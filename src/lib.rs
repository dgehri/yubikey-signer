//! YubiKey Signer Library
//!
//! A self-contained library for code signing using YubiKey PIV certificates.
//! Supports Authenticode PE signing with RFC 3161 timestamping.

pub mod authenticode;
pub mod error;
pub mod pe;
pub mod timestamp;
pub mod types;
pub mod yubikey_ops;

#[cfg(test)]
mod lib_tests;

#[cfg(test)]
mod yubikey_ops_tests;

use std::path::Path;

pub use authenticode::AuthenticodeSigner;
pub use error::{SigningError, SigningResult};
pub use timestamp::TimestampClient;
pub use types::{HashData, PivPin, PivSlot, SecurePath, TimestampUrl};
pub use yubikey_ops::YubiKeyOperations;

/// Main signing configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// YubiKey PIN for authentication
    pub pin: PivPin,
    /// PIV slot to use for signing (default: 0x9c)
    pub piv_slot: PivSlot,
    /// Timestamp server URL (RFC 3161)
    pub timestamp_url: Option<TimestampUrl>,
    /// Hash algorithm to use
    pub hash_algorithm: HashAlgorithm,
    /// Whether to embed the signing certificate
    pub embed_certificate: bool,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// Main signing function - signs a PE file using YubiKey
pub async fn sign_pe_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    config: SigningConfig,
) -> SigningResult<()> {
    log::info!("Starting PE file signing process");

    // Read input file
    let file_data = std::fs::read(&input_path)
        .map_err(|e| SigningError::IoError(format!("Failed to read input file: {e}")))?;

    // Validate it's a PE file before accessing hardware, so we fail fast
    // with a clear PE parsing error on invalid inputs.
    let _ = pe::parse_pe(&file_data)?;

    // Connect to YubiKey and authenticate
    let mut yubikey_ops = YubiKeyOperations::connect()?;
    yubikey_ops.authenticate(&config.pin)?;

    // Get certificate from YubiKey
    let certificate = yubikey_ops.get_certificate(config.piv_slot)?;
    log::info!("Retrieved certificate from YubiKey");

    // Create Authenticode signer
    let signer = AuthenticodeSigner::new(certificate, config.hash_algorithm);

    // Compute PE hash for signing
    let pe_hash = signer.compute_pe_hash(&file_data)?;
    log::debug!("Computed PE hash: {} bytes", pe_hash.len());

    // Sign the hash using YubiKey
    let signature = yubikey_ops.sign_hash(&pe_hash, config.piv_slot)?;
    log::info!("Created digital signature using YubiKey");

    // Get timestamp if requested
    let timestamp_token = if let Some(ts_url) = &config.timestamp_url {
        log::info!("Requesting timestamp from: {ts_url}");
        let client = TimestampClient::new(ts_url);
        Some(client.get_timestamp(&pe_hash).await?)
    } else {
        None
    };

    // Create signed PE file
    let signed_data = signer.create_signed_pe(
        &file_data,
        &signature,
        timestamp_token.as_deref(),
        config.embed_certificate,
    )?;

    // Write signed file
    std::fs::write(&output_path, signed_data)
        .map_err(|e| SigningError::IoError(format!("Failed to write output file: {e}")))?;

    log::info!("Successfully signed PE file: {:?}", output_path.as_ref());
    Ok(())
}

/// Verify a signed PE file
pub fn verify_pe_file<P: AsRef<Path>>(path: P) -> SigningResult<bool> {
    let file_data = std::fs::read(&path)
        .map_err(|e| SigningError::IoError(format!("Failed to read file: {e}")))?;

    // Parse PE and extract signature
    let pe_info = pe::parse_pe(&file_data)?;

    if let Some(signature_data) = pe_info.certificate_table {
        // Verify the signature
        AuthenticodeSigner::verify_signature(&file_data, &signature_data)
    } else {
        Ok(false) // No signature found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_properties() {
        assert_eq!(HashAlgorithm::Sha256.as_str(), "sha256");
        assert_eq!(HashAlgorithm::Sha256.digest_size(), 32);

        assert_eq!(HashAlgorithm::Sha384.as_str(), "sha384");
        assert_eq!(HashAlgorithm::Sha384.digest_size(), 48);

        assert_eq!(HashAlgorithm::Sha512.as_str(), "sha512");
        assert_eq!(HashAlgorithm::Sha512.digest_size(), 64);
    }

    #[test]
    fn test_signing_config_creation() {
        let config = SigningConfig {
            pin: PivPin::new("123456").unwrap(),
            piv_slot: PivSlot::new(0x9c).unwrap(),
            timestamp_url: Some(TimestampUrl::new("http://ts.ssl.com").unwrap()),
            hash_algorithm: HashAlgorithm::Sha256,
            embed_certificate: true,
        };

        assert_eq!(config.pin.as_str(), "123456");
        assert_eq!(config.piv_slot.as_u8(), 0x9c);
        assert_eq!(
            config.timestamp_url.as_ref().map(|u| u.as_str()),
            Some("http://ts.ssl.com")
        );
        assert_eq!(config.hash_algorithm, HashAlgorithm::Sha256);
        assert!(config.embed_certificate);
    }
}
