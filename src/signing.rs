//! Signing module with integrated improvements
//!
//! This module provides the main signing functions with all improvements:
//! certificate validation, progress indicators, multiple timestamp servers,
//! auto-detection, and configuration support.

use crate::auto_detect::AutoDetection;
use crate::cert_validator::CertificateValidator;
use crate::config::{ConfigManager, SigningConfiguration};
use crate::error::{SigningError, SigningResult};
use crate::progress::{ProgressFactory, ProgressStyle};
use crate::timestamp::{TimestampClient, TimestampConfig};
use crate::{authenticode::AuthenticodeSigner, pe, yubikey_ops::YubiKeyOperations};
use crate::{HashAlgorithm, SigningConfig};
use std::path::Path;
use std::time::Instant;

/// Signing options with all features
#[derive(Debug, Clone)]
pub struct SigningOptions {
    /// Basic signing configuration
    pub config: SigningConfig,
    /// Whether to show progress indicators
    pub show_progress: bool,
    /// Progress style preference
    pub progress_style: Option<ProgressStyle>,
    /// Whether to perform certificate validation before signing
    pub validate_certificate: bool,
    /// Whether to use auto-detection if configured slot is not suitable
    pub auto_detect_fallback: bool,
    /// Whether to use enhanced timestamp client with multiple servers
    pub use_enhanced_timestamps: bool,
    /// Custom timestamp configuration
    pub timestamp_config: Option<TimestampConfig>,
    /// Whether to run in verbose mode
    pub verbose: bool,
}

impl Default for SigningOptions {
    fn default() -> Self {
        // Note: Default implementation requires PIN to be set later
        // This is intentionally using a dummy PIN that will fail if not overridden
        Self {
            config: SigningConfig {
                pin: crate::types::PivPin::new("000000").unwrap(), // Must be overridden with real PIN
                piv_slot: crate::types::PivSlot::new(0x9a).unwrap(),
                timestamp_url: Some(crate::types::TimestampUrl::new("http://ts.ssl.com").unwrap()),
                hash_algorithm: HashAlgorithm::Sha256,
                embed_certificate: true,
            },
            show_progress: true,
            progress_style: None, // Auto-detect
            validate_certificate: true,
            auto_detect_fallback: true,
            use_enhanced_timestamps: true,
            timestamp_config: None, // Use default
            verbose: false,
        }
    }
}

/// Signing details with comprehensive information
#[derive(Debug)]
pub struct SigningDetails {
    /// Whether signing was successful
    pub success: bool,
    /// Time taken for the signing operation
    pub duration: std::time::Duration,
    /// Slot that was actually used for signing
    pub slot_used: crate::types::PivSlot,
    /// Certificate analysis results
    pub certificate_analysis: Option<crate::cert_validator::CertificateAnalysis>,
    /// Timestamp server that was used
    pub timestamp_server_used: Option<String>,
    /// Any warnings generated during signing
    pub warnings: Vec<String>,
    /// Size of the signed file
    pub file_size: u64,
}

/// PE file signer with all improvements
pub struct Signer {
    options: SigningOptions,
    config_manager: Option<ConfigManager>,
}

impl Signer {
    /// Create a new signer with options
    pub fn new(options: SigningOptions) -> Self {
        Self {
            options,
            config_manager: None,
        }
    }

    /// Create a signer from configuration file
    pub fn from_config_file() -> SigningResult<Self> {
        let config_manager = ConfigManager::new()?;
        let signing_config = config_manager.load_or_create_default()?;
        
        let options = Self::convert_config_to_options(signing_config)?;
        
        Ok(Self {
            options,
            config_manager: Some(config_manager),
        })
    }

    /// Convert configuration file format to signing options
    fn convert_config_to_options(config: SigningConfiguration) -> SigningResult<SigningOptions> {
        // Get PIN from environment variable
        let pin = std::env::var("YUBICO_PIN")
            .map_err(|_| SigningError::ConfigurationError(
                "YUBICO_PIN environment variable not set".to_string()
            ))?;

        let signing_config = SigningConfig {
            pin: crate::types::PivPin::new(pin)?,
            piv_slot: crate::types::PivSlot::new(config.default_piv_slot)?,
            timestamp_url: Some(crate::types::TimestampUrl::new(&config.primary_timestamp_server)?),
            hash_algorithm: config.default_hash_algorithm.parse()?,
            embed_certificate: config.embed_certificate,
        };

        // Create timestamp config with fallback servers
        let timestamp_config = TimestampConfig {
            primary_server: crate::types::TimestampUrl::new(&config.primary_timestamp_server)?,
            fallback_servers: config.fallback_timestamp_servers
                .into_iter()
                .map(crate::types::TimestampUrl::new)
                .collect::<Result<Vec<_>, _>>()?,
            timeout: std::time::Duration::from_secs(config.network_timeout_seconds),
            retry_attempts: config.retry_attempts,
            ..Default::default()
        };

        let progress_style = match config.progress_style.as_str() {
            "percentage" => Some(ProgressStyle::Percentage),
            "bar" => Some(ProgressStyle::ProgressBar),
            "spinner" => Some(ProgressStyle::Spinner),
            "silent" => Some(ProgressStyle::Silent),
            _ => None, // Auto-detect
        };

        Ok(SigningOptions {
            config: signing_config,
            show_progress: !config.progress_style.eq("silent"),
            progress_style,
            validate_certificate: config.certificate_validation.require_code_signing_eku || 
                                config.certificate_validation.auto_find_certificates,
            auto_detect_fallback: config.certificate_validation.auto_find_certificates,
            use_enhanced_timestamps: true,
            timestamp_config: Some(timestamp_config),
            verbose: config.verbose,
        })
    }

    /// Sign a PE file with all enhancements
    pub async fn sign_pe_file<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
    ) -> SigningResult<SigningDetails> {
        let start_time = Instant::now();
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        if self.options.verbose {
            log::info!("🚀 Starting PE file signing");
            log::info!("  Input: {}", input_path.display());
            log::info!("  Output: {}", output_path.display());
            log::info!("  Slot: {}", self.options.config.piv_slot);
        }

        // Get file size for progress tracking
        let file_size = std::fs::metadata(input_path)
            .map_err(|e| SigningError::IoError(format!("Failed to get file metadata: {e}")))?
            .len();

        // Set up progress tracking
        let progress_style = self.options.progress_style
            .unwrap_or_else(|| ProgressFactory::suggest_style("signing", file_size));
        
        let mut progress = if self.options.show_progress {
            Some(ProgressFactory::create_file_progress(file_size, progress_style))
        } else {
            None
        };

        if let Some(ref mut p) = progress {
            p.set_message("Reading PE file");
        }

        // Read and validate PE file
        let file_data = std::fs::read(input_path)
            .map_err(|e| SigningError::IoError(format!("Failed to read input file: {e}")))?;

        if let Some(ref mut p) = progress {
            p.update(file_size / 4); // 25% - file read
        }

        // Validate PE format early
        let _ = pe::parse_pe(&file_data)?;

        if let Some(ref mut p) = progress {
            p.set_message("Connecting to YubiKey");
            p.update(file_size / 2); // 50% - PE validated
        }

        // Connect to YubiKey
        let mut yubikey_ops = YubiKeyOperations::connect()?;
        yubikey_ops.authenticate(&self.options.config.pin)?;

        let mut warnings = Vec::new();
        let mut actual_slot = self.options.config.piv_slot;

        // Certificate validation and auto-detection
        if self.options.validate_certificate || self.options.auto_detect_fallback {
            if let Some(ref mut p) = progress {
                p.set_message("Validating certificate");
            }

            let _certificate_analysis = self.validate_and_auto_detect(&mut yubikey_ops, &mut actual_slot, &mut warnings).await?;
            
            if self.options.verbose && !warnings.is_empty() {
                log::warn!("Certificate validation warnings:");
                for warning in &warnings {
                    log::warn!("  ⚠️  {warning}");
                }
            }
        }

        if let Some(ref mut p) = progress {
            p.set_message("Retrieving certificate");
            p.update((file_size * 3) / 4); // 75% - certificate validated
        }

        // Get certificate and create signer
        let certificate = yubikey_ops.get_certificate(actual_slot)?;
        let signer = AuthenticodeSigner::new(certificate.clone(), self.options.config.hash_algorithm);

        if let Some(ref mut p) = progress {
            p.set_message("Computing hash and signing");
        }

        // Compute PE hash for signing
        let pe_hash = signer.compute_pe_hash(&file_data)?;
        let signature = yubikey_ops.sign_hash(&pe_hash, actual_slot)?;

        // Handle timestamping
        let timestamp_server_used = if let Some(ref timestamp_url) = self.options.config.timestamp_url {
            if let Some(ref mut p) = progress {
                p.set_message("Getting timestamp");
            }

            if self.options.use_enhanced_timestamps {
                self.get_enhanced_timestamp(&pe_hash).await?
            } else {
                self.get_basic_timestamp(timestamp_url, &pe_hash).await?
            }
        } else {
            if self.options.verbose {
                log::warn!("No timestamp server configured - signature will not be timestamped");
            }
            warnings.push("No timestamp applied - signature validity limited to certificate lifetime".to_string());
            None
        };

        if let Some(ref mut p) = progress {
            p.set_message("Creating signed PE file");
            p.update(file_size); // 100% - signing complete
        }

        // Create signed PE file
        let signed_data = signer.create_signed_pe(&file_data, &signature, None, self.options.config.embed_certificate)?;

        // Write output file
        std::fs::write(output_path, &signed_data)
            .map_err(|e| SigningError::IoError(format!("Failed to write output file: {e}")))?;

        if let Some(ref mut p) = progress {
            p.finish();
        }

        let duration = start_time.elapsed();

        // Get certificate analysis for the result
        let certificate_analysis = if self.options.validate_certificate {
            Some(CertificateValidator::validate_for_code_signing(&certificate)?)
        } else {
            None
        };

        if self.options.verbose {
            log::info!("✅ Signing completed successfully in {:.2}s", duration.as_secs_f64());
            log::info!("  File size: {file_size} bytes");
            log::info!("  Slot used: {actual_slot}");
            if let Some(ref server) = timestamp_server_used {
                log::info!("  Timestamp server: {server}");
            }
        }

        Ok(SigningDetails {
            success: true,
            duration,
            slot_used: actual_slot,
            certificate_analysis,
            timestamp_server_used,
            warnings,
            file_size,
        })
    }

    /// Validate certificate and perform auto-detection if needed
    async fn validate_and_auto_detect(
        &self,
        yubikey_ops: &mut YubiKeyOperations,
        actual_slot: &mut crate::types::PivSlot,
        warnings: &mut Vec<String>,
    ) -> SigningResult<Option<crate::cert_validator::CertificateAnalysis>> {
        
        if self.options.validate_certificate {
            // Check the configured slot first
            match yubikey_ops.get_certificate(*actual_slot) {
                Ok(certificate) => {
                    let analysis = CertificateValidator::validate_for_code_signing(&certificate)?;
                    
                    if !analysis.is_code_signing_suitable && self.options.auto_detect_fallback {
                        warnings.push(format!("Configured slot {actual_slot} is not suitable for code signing"));
                        
                        if self.options.verbose {
                            log::warn!("🔍 Auto-detecting suitable certificate...");
                        }
                        
                        // Try to find a better slot
                        let discovery = AutoDetection::discover_yubikey_capabilities(yubikey_ops)?;
                        
                        if let Some(recommended_slot) = discovery.recommended_slot {
                            if self.options.verbose {
                                log::info!("✅ Found suitable certificate in slot {recommended_slot}");
                            }
                            
                            warnings.push(format!("Switched to slot {recommended_slot} for better certificate"));
                            *actual_slot = recommended_slot;
                            
                            // Return analysis for the new slot
                            let new_certificate = yubikey_ops.get_certificate(*actual_slot)?;
                            return Ok(Some(CertificateValidator::validate_for_code_signing(&new_certificate)?));
                        } else {
                            warnings.push("No suitable certificate found via auto-detection".to_string());
                        }
                    }
                    
                    return Ok(Some(analysis));
                }
                Err(e) => {
                    if self.options.auto_detect_fallback {
                        warnings.push(format!("Cannot access certificate in slot {actual_slot}: {e}"));
                        
                        if self.options.verbose {
                            log::warn!("🔍 Auto-detecting available certificates...");
                        }
                        
                        let discovery = AutoDetection::discover_yubikey_capabilities(yubikey_ops)?;
                        
                        if let Some(recommended_slot) = discovery.recommended_slot {
                            if self.options.verbose {
                                log::info!("✅ Found suitable certificate in slot {recommended_slot}");
                            }
                            
                            warnings.push(format!("Switched to slot {recommended_slot} due to access issues"));
                            *actual_slot = recommended_slot;
                            
                            let new_certificate = yubikey_ops.get_certificate(*actual_slot)?;
                            return Ok(Some(CertificateValidator::validate_for_code_signing(&new_certificate)?));
                        } else {
                            return Err(SigningError::YubiKeyError(format!(
                                "No accessible certificates found for code signing. Original error: {e}"
                            )));
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Get timestamp using client with multiple servers
    async fn get_enhanced_timestamp(&self, hash_data: &[u8]) -> SigningResult<Option<String>> {
        let timestamp_config = self.options.timestamp_config.clone()
            .unwrap_or_default();
        
        let client = TimestampClient::with_config(timestamp_config);
        
        match client.get_timestamp_with_details(hash_data).await {
            Ok(response) => {
                if self.options.verbose {
                    log::info!("✅ Timestamp obtained from {}", response.authority);
                }
                Ok(Some(response.authority))
            }
            Err(e) => {
                if self.options.verbose {
                    log::error!("❌ Timestamp failed: {e}");
                }
                Err(e)
            }
        }
    }

    /// Get timestamp using basic client (fallback)
    async fn get_basic_timestamp(
        &self,
        timestamp_url: &crate::types::TimestampUrl,
        hash_data: &[u8],
    ) -> SigningResult<Option<String>> {
        let client = crate::timestamp::TimestampClient::new(timestamp_url);
        
        match client.get_timestamp(hash_data).await {
            Ok(_) => {
                if self.options.verbose {
                    log::info!("✅ Basic timestamp obtained from {}", timestamp_url.as_str());
                }
                Ok(Some(timestamp_url.as_str().to_string()))
            }
            Err(e) => {
                if self.options.verbose {
                    log::error!("❌ Basic timestamp failed: {e}");
                }
                Err(e)
            }
        }
    }

    /// Save current options to configuration file
    pub fn save_to_config(&self) -> SigningResult<()> {
        if let Some(ref config_manager) = self.config_manager {
            let signing_config = Self::convert_options_to_config(&self.options)?;
            config_manager.save(&signing_config)?;
            
            if self.options.verbose {
                log::info!("✅ Configuration saved to {}", config_manager.config_path().display());
            }
        } else {
            return Err(SigningError::ConfigurationError(
                "No configuration manager available".to_string()
            ));
        }
        
        Ok(())
    }

    /// Convert signing options back to configuration format
    fn convert_options_to_config(options: &SigningOptions) -> SigningResult<SigningConfiguration> {
        let mut config = SigningConfiguration::default();
        
        config.default_piv_slot = options.config.piv_slot.as_u8();
        config.default_hash_algorithm = options.config.hash_algorithm.as_str().to_string();
        
        if let Some(ref timestamp_url) = options.config.timestamp_url {
            config.primary_timestamp_server = timestamp_url.as_str().to_string();
        }
        
        if let Some(ref timestamp_config) = options.timestamp_config {
            config.fallback_timestamp_servers = timestamp_config.fallback_servers
                .iter()
                .map(|url| url.as_str().to_string())
                .collect();
            config.network_timeout_seconds = timestamp_config.timeout.as_secs();
            config.retry_attempts = timestamp_config.retry_attempts;
        }
        
        config.embed_certificate = options.config.embed_certificate;
        config.verbose = options.verbose;
        
        config.progress_style = match options.progress_style {
            Some(ProgressStyle::Percentage) => "percentage".to_string(),
            Some(ProgressStyle::ProgressBar) => "bar".to_string(),
            Some(ProgressStyle::Spinner) => "spinner".to_string(),
            Some(ProgressStyle::Silent) => "silent".to_string(),
            None => "auto".to_string(),
        };
        
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_options_default() {
        let options = SigningOptions::default();
        assert!(options.show_progress);
        assert!(options.validate_certificate);
        assert!(options.auto_detect_fallback);
        assert!(options.use_enhanced_timestamps);
    }

    #[test]
    fn test_signer_creation() {
        let options = SigningOptions::default();
        let signer = Signer::new(options);
        assert!(signer.config_manager.is_none());
    }
}
