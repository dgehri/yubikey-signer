//! Configuration management infrastructure.
//!
//! This module provides configuration file support, allowing users to save
//! and load signing preferences, server configurations, and other settings.

use crate::domain::types::{PivSlot, TimestampUrl};
use crate::infra::error::{SigningError, SigningResult};
use crate::HashAlgorithm;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Application configuration with all signing preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfiguration {
    /// Default PIV slot to use for signing
    pub default_piv_slot: u8,

    /// Default hash algorithm
    pub default_hash_algorithm: String,

    /// Primary timestamp server
    pub primary_timestamp_server: String,

    /// Fallback timestamp servers
    pub fallback_timestamp_servers: Vec<String>,

    /// Whether to embed certificates in signatures by default
    pub embed_certificate: bool,

    /// Network timeout settings
    pub network_timeout_seconds: u64,

    /// Number of retry attempts for network operations
    pub retry_attempts: usize,

    /// Progress indicator preferences
    pub progress_style: String,

    /// Whether to show verbose output
    pub verbose: bool,

    /// Certificate validation preferences
    pub certificate_validation: CertificateValidationConfig,
}

/// Certificate validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidationConfig {
    /// Whether to require code signing extended key usage
    pub require_code_signing_eku: bool,

    /// Whether to allow self-signed certificates
    pub allow_self_signed: bool,

    /// Minimum days before expiry to warn about
    pub expiry_warning_days: u32,

    /// Whether to automatically find suitable certificates
    pub auto_find_certificates: bool,
}

impl Default for SigningConfiguration {
    fn default() -> Self {
        Self {
            default_piv_slot: 0x9a, // Authentication slot (our new default)
            default_hash_algorithm: "sha384".to_string(), // Match ECC-P384 curve
            primary_timestamp_server: "http://ts.ssl.com".to_string(),
            fallback_timestamp_servers: vec![
                "http://timestamp.digicert.com".to_string(),
                "http://timestamp.sectigo.com".to_string(),
                "http://timestamp.entrust.net".to_string(),
            ],
            embed_certificate: true,
            network_timeout_seconds: 30,
            retry_attempts: 3,
            progress_style: "auto".to_string(),
            verbose: false,
            certificate_validation: CertificateValidationConfig::default(),
        }
    }
}

impl Default for CertificateValidationConfig {
    fn default() -> Self {
        Self {
            require_code_signing_eku: false, // Be flexible by default
            allow_self_signed: true,         // Allow for development/testing
            expiry_warning_days: 30,
            auto_find_certificates: true,
        }
    }
}

/// Configuration manager for handling config files
pub struct ConfigManager {
    config_path: PathBuf,
}

impl ConfigManager {
    /// Create a new configuration manager with default path
    pub fn new() -> SigningResult<Self> {
        let config_path = Self::default_config_path()?;
        Ok(Self { config_path })
    }

    /// Create a configuration manager with custom path
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            config_path: path.as_ref().to_path_buf(),
        }
    }

    /// Get the default configuration file path
    pub fn default_config_path() -> SigningResult<PathBuf> {
        // Try to get the user's config directory
        if let Some(config_dir) = dirs::config_dir() {
            let yubikey_signer_dir = config_dir.join("yubikey-signer");
            Ok(yubikey_signer_dir.join("config.toml"))
        } else {
            // Fallback to current directory
            Ok(PathBuf::from("yubikey-signer-config.toml"))
        }
    }

    /// Load configuration from file, creating default if it doesn't exist
    pub fn load_or_create_default(&self) -> SigningResult<SigningConfiguration> {
        if self.config_path.exists() {
            self.load()
        } else {
            log::info!(
                "Configuration file not found, creating default: {}",
                self.config_path.display()
            );
            let default_config = SigningConfiguration::default();
            self.save(&default_config)?;
            Ok(default_config)
        }
    }

    /// Load configuration from file
    pub fn load(&self) -> SigningResult<SigningConfiguration> {
        log::info!("Loading configuration from: {}", self.config_path.display());

        let content = fs::read_to_string(&self.config_path).map_err(|e| {
            SigningError::ConfigurationError(format!(
                "Failed to read config file {}: {}",
                self.config_path.display(),
                e
            ))
        })?;

        let config: SigningConfiguration = toml::from_str(&content).map_err(|e| {
            SigningError::ConfigurationError(format!("Failed to parse config file: {e}"))
        })?;

        self.validate_config(&config)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self, config: &SigningConfiguration) -> SigningResult<()> {
        log::info!("Saving configuration to: {}", self.config_path.display());

        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                SigningError::ConfigurationError(format!(
                    "Failed to create config directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let content = toml::to_string_pretty(config).map_err(|e| {
            SigningError::ConfigurationError(format!("Failed to serialize config: {e}"))
        })?;

        fs::write(&self.config_path, content).map_err(|e| {
            SigningError::ConfigurationError(format!(
                "Failed to write config file {}: {}",
                self.config_path.display(),
                e
            ))
        })?;

        log::info!("Configuration saved successfully");
        Ok(())
    }

    /// Validate configuration values
    fn validate_config(&self, config: &SigningConfiguration) -> SigningResult<()> {
        // Validate PIV slot
        PivSlot::new(config.default_piv_slot)?;

        // Validate hash algorithm
        config
            .default_hash_algorithm
            .parse::<HashAlgorithm>()
            .map_err(|_| {
                SigningError::ConfigurationError(format!(
                    "Invalid hash algorithm: {}",
                    config.default_hash_algorithm
                ))
            })?;

        // Validate timestamp URLs
        TimestampUrl::new(&config.primary_timestamp_server)?;
        for url in &config.fallback_timestamp_servers {
            TimestampUrl::new(url)?;
        }

        // Validate timeout and retry values
        if config.network_timeout_seconds == 0 {
            return Err(SigningError::ConfigurationError(
                "Network timeout must be greater than 0".to_string(),
            ));
        }

        if config.retry_attempts == 0 {
            return Err(SigningError::ConfigurationError(
                "Retry attempts must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Update a specific configuration value
    pub fn update_value(&self, key: &str, value: &str) -> SigningResult<()> {
        let mut config = self.load()?;

        match key {
            "default_piv_slot" => {
                let slot_value = parse_piv_slot_value(value)?;
                PivSlot::new(slot_value)?; // Validate
                config.default_piv_slot = slot_value;
            }
            "default_hash_algorithm" => {
                value.parse::<HashAlgorithm>().map_err(|_| {
                    SigningError::ConfigurationError(format!("Invalid hash algorithm: {value}"))
                })?;
                config.default_hash_algorithm = value.to_string();
            }
            "primary_timestamp_server" => {
                TimestampUrl::new(value)?; // Validate
                config.primary_timestamp_server = value.to_string();
            }
            "embed_certificate" => {
                config.embed_certificate = value.parse().map_err(|_| {
                    SigningError::ConfigurationError(format!("Invalid boolean value: {value}"))
                })?;
            }
            "verbose" => {
                config.verbose = value.parse().map_err(|_| {
                    SigningError::ConfigurationError(format!("Invalid boolean value: {value}"))
                })?;
            }
            _ => {
                return Err(SigningError::ConfigurationError(format!(
                    "Unknown configuration key: {key}"
                )));
            }
        }

        self.save(&config)
    }

    /// Get the configuration file path
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Export configuration as a portable format
    pub fn export_config(&self, format: ExportFormat) -> SigningResult<String> {
        let config = self.load()?;

        match format {
            ExportFormat::Toml => toml::to_string_pretty(&config)
                .map_err(|e| SigningError::ConfigurationError(format!("TOML export failed: {e}"))),
            ExportFormat::Json => serde_json::to_string_pretty(&config)
                .map_err(|e| SigningError::ConfigurationError(format!("JSON export failed: {e}"))),
            ExportFormat::Yaml => serde_yaml::to_string(&config)
                .map_err(|e| SigningError::ConfigurationError(format!("YAML export failed: {e}"))),
        }
    }

    /// Import configuration from a string
    pub fn import_config(&self, content: &str, format: ExportFormat) -> SigningResult<()> {
        let config: SigningConfiguration = match format {
            ExportFormat::Toml => toml::from_str(content).map_err(|e| {
                SigningError::ConfigurationError(format!("TOML import failed: {e}"))
            })?,
            ExportFormat::Json => serde_json::from_str(content).map_err(|e| {
                SigningError::ConfigurationError(format!("JSON import failed: {e}"))
            })?,
            ExportFormat::Yaml => serde_yaml::from_str(content).map_err(|e| {
                SigningError::ConfigurationError(format!("YAML import failed: {e}"))
            })?,
        };

        self.validate_config(&config)?;
        self.save(&config)
    }
}

/// Configuration export/import formats
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Toml,
    Json,
    Yaml,
}

/// Configuration profile for different environments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: String,
    /// Configuration for this profile
    pub config: SigningConfiguration,
}

/// Profile manager for handling multiple configuration profiles
pub struct ProfileManager {
    profiles_dir: PathBuf,
}

impl ProfileManager {
    /// Create a new profile manager
    pub fn new() -> SigningResult<Self> {
        let profiles_dir = ConfigManager::default_config_path()?
            .parent()
            .unwrap()
            .join("profiles");

        Ok(Self { profiles_dir })
    }

    /// List available profiles
    pub fn list_profiles(&self) -> SigningResult<Vec<String>> {
        if !self.profiles_dir.exists() {
            return Ok(Vec::new());
        }

        let mut profiles = Vec::new();
        let entries = fs::read_dir(&self.profiles_dir).map_err(|e| {
            SigningError::ConfigurationError(format!("Failed to read profiles directory: {e}"))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SigningError::ConfigurationError(format!("Failed to read directory entry: {e}"))
            })?;

            if let Some(name) = entry.file_name().to_str() {
                if std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
                {
                    profiles.push(name.trim_end_matches(".toml").to_string());
                }
            }
        }

        profiles.sort();
        Ok(profiles)
    }

    /// Save a configuration profile
    pub fn save_profile(&self, profile: &ConfigProfile) -> SigningResult<()> {
        fs::create_dir_all(&self.profiles_dir).map_err(|e| {
            SigningError::ConfigurationError(format!("Failed to create profiles directory: {e}"))
        })?;

        let profile_path = self.profiles_dir.join(format!("{}.toml", profile.name));
        let content = toml::to_string_pretty(profile).map_err(|e| {
            SigningError::ConfigurationError(format!("Failed to serialize profile: {e}"))
        })?;

        fs::write(&profile_path, content).map_err(|e| {
            SigningError::ConfigurationError(format!(
                "Failed to write profile {}: {}",
                profile_path.display(),
                e
            ))
        })?;

        log::info!("Profile '{}' saved successfully", profile.name);
        Ok(())
    }

    /// Load a configuration profile
    pub fn load_profile(&self, name: &str) -> SigningResult<ConfigProfile> {
        let profile_path = self.profiles_dir.join(format!("{name}.toml"));

        if !profile_path.exists() {
            return Err(SigningError::ConfigurationError(format!(
                "Profile '{name}' not found"
            )));
        }

        let content = fs::read_to_string(&profile_path).map_err(|e| {
            SigningError::ConfigurationError(format!(
                "Failed to read profile {}: {}",
                profile_path.display(),
                e
            ))
        })?;

        let profile: ConfigProfile = toml::from_str(&content).map_err(|e| {
            SigningError::ConfigurationError(format!("Failed to parse profile: {e}"))
        })?;

        Ok(profile)
    }
}

/// Parse PIV slot value supporting hex (0x9a, 9a) and decimal (154) formats
fn parse_piv_slot_value(slot_str: &str) -> SigningResult<u8> {
    // Handle hex format (0x9a, 9a) and decimal format (154)
    let slot_value = if slot_str.starts_with("0x") || slot_str.starts_with("0X") {
        u8::from_str_radix(&slot_str[2..], 16).map_err(|_| {
            SigningError::ConfigurationError(format!("Invalid hex slot: {slot_str}"))
        })?
    } else if slot_str.len() == 2 && slot_str.chars().all(|c| c.is_ascii_hexdigit()) {
        u8::from_str_radix(slot_str, 16).map_err(|_| {
            SigningError::ConfigurationError(format!("Invalid hex slot: {slot_str}"))
        })?
    } else {
        slot_str
            .parse::<u8>()
            .map_err(|_| SigningError::ConfigurationError(format!("Invalid slot: {slot_str}")))?
    };

    Ok(slot_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_configuration() {
        let config = SigningConfiguration::default();
        assert_eq!(config.default_piv_slot, 0x9a);
        assert_eq!(config.default_hash_algorithm, "sha384");
        assert!(!config.fallback_timestamp_servers.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = SigningConfiguration::default();
        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: SigningConfiguration = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.default_piv_slot, deserialized.default_piv_slot);
        assert_eq!(
            config.primary_timestamp_server,
            deserialized.primary_timestamp_server
        );
    }

    #[test]
    fn test_config_manager_with_temp_path() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        let manager = ConfigManager::with_path(&config_path);

        // Should create default config
        let config = manager.load_or_create_default().unwrap();
        assert!(config_path.exists());

        // Should be able to load it back
        let loaded_config = manager.load().unwrap();
        assert_eq!(config.default_piv_slot, loaded_config.default_piv_slot);
    }
}
