//! High-level signing service orchestrating the complete PE file signing workflow.
//!
//! Provides convenience interfaces for common signing operations including:
//! - Hardware key discovery and selection
//! - Certificate validation and chain building
//! - PE file signing with optional timestamping
//! - Integration with `YubiKey` PIV authentication
//!
//! This service layer bridges between the CLI interface and the lower-level
//! cryptographic components.

use crate::adapters::yubikey::auth_bridge::YubiKeyAuthenticodeBridge;
use crate::adapters::yubikey::ops::YubiKeyOperations;
use crate::domain::crypto::HashAlgorithm;
use crate::domain::pe;
use crate::domain::types::{PivPin, PivSlot, TimestampUrl};
use crate::infra::config::{ConfigManager, SigningConfiguration};
use crate::infra::error::{SigningError, SigningResult};
use crate::infra::progress::{ProgressFactory, ProgressStyle};
use crate::services::auto_detect::AutoDetection;
use crate::services::cert_validator::CertificateValidator;
use crate::services::timestamp::{TimestampClient, TimestampConfig};
use std::path::Path;
use std::time::Instant;

/// Basic signing configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub pin: PivPin,
    pub piv_slot: PivSlot,
    pub timestamp_url: Option<TimestampUrl>,
    pub hash_algorithm: HashAlgorithm,
    pub embed_certificate: bool,
}

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
                pin: PivPin::new("000000").unwrap(), // Must be overridden with real PIN
                piv_slot: PivSlot::new(0x9a).unwrap(),
                timestamp_url: Some(TimestampUrl::new("http://ts.ssl.com").unwrap()),
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
    pub slot_used: PivSlot,
    /// Certificate analysis results
    pub certificate_analysis: Option<crate::services::cert_validator::CertificateAnalysis>,
    /// Timestamp server that was used
    pub timestamp_server_used: Option<String>,
    /// Any warnings generated during signing
    pub warnings: Vec<String>,
    /// Size of the signed file
    pub file_size: u64,
}

/// PE file signer with all improvements
/// Signing service preserving exact behavior
/// while integrating with the new domain/service architecture.
pub struct Signer {
    options: SigningOptions,
}

impl Signer {
    /// Create a new signer with options
    #[must_use]
    pub fn new(options: SigningOptions) -> Self {
        Self { options }
    }

    /// Create a signer from configuration file
    pub fn from_config_file() -> SigningResult<Self> {
        let config_manager = ConfigManager::new()?;
        let signing_config = config_manager.load_or_create_default()?;

        let options = Self::convert_config_to_options(signing_config)?;

        Ok(Self { options })
    }

    /// Convert configuration file format to signing options
    fn convert_config_to_options(config: SigningConfiguration) -> SigningResult<SigningOptions> {
        // Get PIN from environment variable
        let pin = std::env::var("YUBICO_PIN").map_err(|_| {
            SigningError::ConfigurationError("YUBICO_PIN environment variable not set".to_string())
        })?;

        let signing_config = SigningConfig {
            pin: PivPin::new(pin)?,
            piv_slot: PivSlot::new(config.default_piv_slot)?,
            timestamp_url: Some(TimestampUrl::new(&config.primary_timestamp_server)?),
            hash_algorithm: config.default_hash_algorithm.parse()?,
            embed_certificate: config.embed_certificate,
        };

        // Create timestamp config with fallback servers
        let timestamp_config = TimestampConfig {
            primary_server: TimestampUrl::new(&config.primary_timestamp_server)?,
            fallback_servers: config
                .fallback_timestamp_servers
                .into_iter()
                .map(TimestampUrl::new)
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
            validate_certificate: config.certificate_validation.require_code_signing_eku
                || config.certificate_validation.auto_find_certificates,
            auto_detect_fallback: config.certificate_validation.auto_find_certificates,
            use_enhanced_timestamps: true,
            timestamp_config: Some(timestamp_config),
            verbose: config.verbose,
        })
    }

    /// Sign a PE file with comprehensive features
    pub async fn sign_file(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> SigningResult<SigningDetails> {
        let start_time = Instant::now();

        let file_size = std::fs::metadata(input_path)
            .map_err(|e| SigningError::IoError(format!("Failed to get file metadata: {e}")))?
            .len();

        // Initialize progress indicator
        let mut progress = if self.options.show_progress {
            Some(ProgressFactory::create_file_progress(
                file_size,
                self.options
                    .progress_style
                    .unwrap_or(ProgressStyle::ProgressBar),
            ))
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

            let _certificate_analysis = self
                .validate_and_auto_detect(&mut yubikey_ops, &mut actual_slot, &mut warnings)
                .await?;

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

        // Get certificate and create bridge that combines YubiKey ops and OpenSSL signer
        let certificate = yubikey_ops.get_certificate(actual_slot)?;
        let mut bridge = YubiKeyAuthenticodeBridge::new(
            yubikey_ops,
            actual_slot,
            self.options.config.hash_algorithm,
        )?;

        if let Some(ref mut p) = progress {
            p.set_message("Computing hash and signing");
        }

        // Compute PE hash for diagnostics (kept for logs/validation)
        let _pe_hash = bridge.compute_pe_hash(&file_data)?;

        // Prepare timestamp token (RFC3161 TimeStampToken over signature value)
        let mut timestamp_token: Option<Vec<u8>> = None;
        let mut timestamp_server_used: Option<String> = None;

        if let Some(ref timestamp_url) = self.options.config.timestamp_url {
            if self.options.verbose {
                log::info!("⏱  Preparing timestamp (over SignerInfo.signature)");
            }

            // 1) Extract signature bytes for the current TBS (authenticated attributes)
            let signature_bytes = bridge.extract_signature_bytes(&file_data, actual_slot)?;

            if let Some(ref mut p) = progress {
                p.set_message("Requesting timestamp");
            }

            // 3) Request timestamp token
            if self.options.use_enhanced_timestamps {
                let ts_config = self.options.timestamp_config.clone().unwrap_or_default();
                let client = TimestampClient::with_config(ts_config);
                let response = client.get_timestamp_with_details(&signature_bytes).await?;
                timestamp_server_used = Some(response.authority.clone());
                timestamp_token = Some(response.token);
            } else {
                let client = TimestampClient::new(timestamp_url);
                let token = client.get_timestamp(&signature_bytes).await?;
                timestamp_server_used = Some(timestamp_url.as_str().to_string());
                timestamp_token = Some(token);
            }
        } else {
            if self.options.verbose {
                log::warn!("No timestamp server configured - signature will not be timestamped");
            }
            warnings.push(
                "No timestamp applied - signature validity limited to certificate lifetime"
                    .to_string(),
            );
        }

        if let Some(ref mut p) = progress {
            p.set_message("Creating signed PE file");
            p.update(file_size); // 100% - signing complete
        }

        // Create signed PE file using YubiKey bridge
        let signed_data = bridge.sign_pe_file(
            &file_data,
            actual_slot,
            timestamp_token.as_deref(),
            self.options.config.embed_certificate,
        )?;

        // Write output file
        std::fs::write(output_path, &signed_data)
            .map_err(|e| SigningError::IoError(format!("Failed to write output file: {e}")))?;

        if let Some(ref mut p) = progress {
            p.finish();
        }

        let duration = start_time.elapsed();

        // Get certificate analysis for the result
        let certificate_analysis = if self.options.validate_certificate {
            Some(CertificateValidator::validate_for_code_signing(
                &certificate,
            )?)
        } else {
            None
        };

        if self.options.verbose {
            log::info!(
                "✅ Signing completed successfully in {:.2}s",
                duration.as_secs_f64()
            );
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
        actual_slot: &mut PivSlot,
        warnings: &mut Vec<String>,
    ) -> SigningResult<Option<crate::services::cert_validator::CertificateAnalysis>> {
        let mut certificate_analysis = None;

        if self.options.validate_certificate {
            let certificate = yubikey_ops.get_certificate(*actual_slot)?;
            let analysis = CertificateValidator::validate_for_code_signing(&certificate)?;

            // Check if certificate is suitable for code signing (using correct field name)
            if analysis.is_code_signing_suitable {
                certificate_analysis = Some(analysis);
            } else if self.options.auto_detect_fallback {
                if self.options.verbose {
                    log::warn!(
                        "⚠️  Certificate in slot {actual_slot} is not suitable for code signing"
                    );
                    log::info!("🔍 Running auto-detection to find suitable certificate...");
                }

                // Simplified auto-detection - just use discovery capabilities
                let discovery_results = AutoDetection::discover_yubikey_capabilities(yubikey_ops)?;
                if let Some(&suitable_slot) = discovery_results.suitable_slots.first() {
                    if self.options.verbose {
                        log::info!("✅ Found suitable certificate in slot: {suitable_slot}");
                    }
                    *actual_slot = suitable_slot;

                    // Re-validate with the new slot
                    let new_certificate = yubikey_ops.get_certificate(*actual_slot)?;
                    certificate_analysis = Some(CertificateValidator::validate_for_code_signing(
                        &new_certificate,
                    )?);
                } else {
                    warnings.push(format!(
                        "No suitable certificate found for code signing. Using slot {actual_slot} anyway."
                    ));
                    certificate_analysis = Some(analysis);
                }
            } else {
                warnings.push(format!(
                    "Certificate in slot {actual_slot} may not be suitable for code signing"
                ));
                certificate_analysis = Some(analysis);
            }
        }

        Ok(certificate_analysis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_creation() {
        let options = SigningOptions::default();
        let _signer = Signer::new(options);
        // Basic constructor test - should not panic
    }

    #[test]
    fn test_signing_options_default() {
        let options = SigningOptions::default();
        assert!(options.show_progress);
        assert!(options.validate_certificate);
        assert!(options.auto_detect_fallback);
        assert!(options.use_enhanced_timestamps);
        assert!(!options.verbose);
    }
}
