// Copyright 2025 Daniel Gehriger
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `YubiKey` Signer Library
//!
//! A self-contained library for code signing using `YubiKey` PIV certificates.
//! Supports Authenticode PE signing with RFC 3161 timestamping.
//! Requires OpenSSL for Windows-compatible Authenticode signatures.

#![allow(
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::match_same_arms,
    clippy::unused_async,
    clippy::missing_panics_doc,
    clippy::unnecessary_debug_formatting,
    clippy::no_effect_underscore_binding,
    clippy::needless_range_loop,
    clippy::float_cmp,
    clippy::items_after_statements,
    clippy::manual_let_else
)]

// Core architectural layers - post-migration structure
pub mod adapters;
pub mod domain;
pub mod infra;
pub mod pipelines;
pub mod services;

// Core domain exports - cryptographic and PE types
pub use crate::domain::crypto::{
    CertChain, CmsSignature, DigestBytes, DigestBytesError, EndEntityCert, IntermediateCert,
};
pub use crate::domain::pe::{PeHashView, PeRaw};
pub use crate::domain::spc::SpcIndirectData;

// Core API exports - maintain backward compatibility
pub use crate::domain::types::{HashData, PivPin, PivSlot, SecurePath, TimestampUrl};
pub use crate::infra::error::{SigningError, SigningResult};
pub use crate::pipelines::sign::SignWorkflow;

// Public API exports - stable interfaces for external use
pub use crate::adapters::yubikey::auth_bridge::{
    sign_pe_file_with_yubikey_openssl, sign_pe_with_yubikey_openssl, YubiKeyAuthenticodeBridge,
};
pub use crate::adapters::yubikey::ops::YubiKeyOperations;
pub use crate::domain::verification::VerificationReport;
pub use crate::services::authenticode::OpenSslAuthenticodeSigner;
pub use crate::services::signing::{Signer, SigningDetails, SigningOptions};
pub use crate::services::timestamp::TimestampClient;

use std::path::Path;
use std::str::FromStr;

/// Main signing configuration
#[derive(Debug, Clone, Default)]
pub struct SigningConfig {
    /// `YubiKey` PIN for authentication
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

// Re-export additional workflows after enum declaration
pub use crate::pipelines::{timestamp::TimestampWorkflow, verify::VerifyWorkflow};

impl HashAlgorithm {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    #[must_use]
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = crate::infra::error::SigningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            _ => Err(crate::infra::error::SigningError::InvalidInput(format!(
                "Invalid hash algorithm: {s}"
            ))),
        }
    }
}

/// Main signing function - signs a PE file using `YubiKey`
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
    let _ = crate::domain::pe::layout::parse_pe(&file_data)?;

    // Connect to YubiKey and authenticate
    let mut yubikey_ops = YubiKeyOperations::connect()?;
    yubikey_ops.authenticate(&config.pin)?;

    // Get certificate DER bytes from YubiKey
    let certificate_der = yubikey_ops.get_certificate_der(config.piv_slot)?;
    log::info!("Retrieved certificate from YubiKey");

    // Create OpenSSL Authenticode signer
    let signer = OpenSslAuthenticodeSigner::new(&certificate_der, config.hash_algorithm)?;

    // Compute PE hash for signing
    let pe_hash = signer.compute_pe_hash(&file_data)?;
    log::debug!("Computed PE hash: {} bytes", pe_hash.len());

    // Don't sign the hash directly - remove this line since bridge will handle it
    // let signature = yubikey_ops.sign_hash(&pe_hash, config.piv_slot)?;
    // log::info!("Created digital signature using YubiKey");

    // Get timestamp if requested
    let timestamp_token = if let Some(ts_url) = &config.timestamp_url {
        log::info!("Requesting timestamp from: {ts_url}");
        let client = TimestampClient::new(ts_url);
        Some(client.get_timestamp(&pe_hash).await?)
    } else {
        None
    };

    // Create signed PE file using YubiKey authenticode bridge
    let mut bridge = crate::adapters::yubikey::auth_bridge::YubiKeyAuthenticodeBridge::new(
        yubikey_ops,
        config.piv_slot,
        config.hash_algorithm,
    )?;

    let signed_data = bridge.sign_pe_file(
        &file_data,
        config.piv_slot,
        timestamp_token.as_deref(),
        config.embed_certificate,
    )?;

    // Write signed file
    std::fs::write(&output_path, signed_data)
        .map_err(|e| SigningError::IoError(format!("Failed to write output file: {e}")))?;

    log::info!("Successfully signed PE file: {:?}", output_path.as_ref());
    Ok(())
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
            config.timestamp_url.as_ref().map(TimestampUrl::as_str),
            Some("http://ts.ssl.com")
        );
        assert_eq!(config.hash_algorithm, HashAlgorithm::Sha256);
        assert!(config.embed_certificate);
    }
}
