//! `YubiKey` + OpenSSL Authenticode bridge adapter.
//!
//! Provides integration between `YubiKey` hardware and OpenSSL-based Authenticode signing.

use crate::domain::pe; // PE validation
use crate::services::timestamp::TimestampClient; // timestamp retrieval
use crate::SigningConfig; // for async file helper
use crate::{
    domain::types::PivSlot, infra::error::SigningResult,
    services::authenticode::OpenSslAuthenticodeSigner, HashAlgorithm,
};
use std::path::Path; // path generics

use super::ops::YubiKeyOperations;

/// Bridge combining OpenSSL PKCS#7 assembly with hardware signing.
pub struct YubiKeyAuthenticodeBridge {
    openssl_signer: OpenSslAuthenticodeSigner,
    yubikey_ops: YubiKeyOperations,
}

impl YubiKeyAuthenticodeBridge {
    /// Instantiate bridge (fetches certificate DER from the `YubiKey`).
    pub fn new(
        mut yubikey_ops: YubiKeyOperations,
        slot: PivSlot,
        hash_algorithm: HashAlgorithm,
    ) -> SigningResult<Self> {
        let cert_der = yubikey_ops.get_certificate_der(slot)?;
        let openssl_signer = OpenSslAuthenticodeSigner::new(&cert_der, hash_algorithm)?;
        Ok(Self {
            openssl_signer,
            yubikey_ops,
        })
    }

    /// Sign a PE file, optionally embedding timestamp & certificate.
    pub fn sign_pe_file(
        &mut self,
        pe_data: &[u8],
        slot: PivSlot,
        timestamp_token: Option<&[u8]>,
        embed_certificate: bool,
    ) -> SigningResult<Vec<u8>> {
        let cb = |data: &[u8]| self.yubikey_ops.sign_hash(data, slot);
        self.openssl_signer.create_signed_pe_openssl(
            pe_data,
            cb,
            timestamp_token,
            embed_certificate,
        )
    }

    /// Compute PE hash via OpenSSL helper.
    pub fn compute_pe_hash(&self, pe_data: &[u8]) -> SigningResult<Vec<u8>> {
        self.openssl_signer.compute_pe_hash(pe_data)
    }

    /// Build SPC `IndirectDataContent` from hash.
    pub fn create_spc_content(&self, pe_hash: &[u8]) -> SigningResult<Vec<u8>> {
        self.openssl_signer.create_spc_content(pe_hash)
    }

    /// Extract only signature bytes for timestamping purposes.
    pub fn extract_signature_bytes(
        &mut self,
        pe_data: &[u8],
        slot: PivSlot,
    ) -> SigningResult<Vec<u8>> {
        self.openssl_signer
            .create_signature_bytes_only(pe_data, |d| self.yubikey_ops.sign_hash(d, slot))
    }

    /// Consume bridge returning underlying `YubiKey` operations.
    #[must_use]
    pub fn into_yubikey_ops(self) -> YubiKeyOperations {
        self.yubikey_ops
    }
}

/// Helper one-shot signing using bridge.
pub fn sign_pe_with_yubikey_openssl(
    pe_data: &[u8],
    yubikey_ops: YubiKeyOperations,
    slot: PivSlot,
    hash_algorithm: HashAlgorithm,
    timestamp_token: Option<&[u8]>,
    embed_certificate: bool,
) -> SigningResult<Vec<u8>> {
    let mut bridge = YubiKeyAuthenticodeBridge::new(yubikey_ops, slot, hash_algorithm)?;
    bridge.sign_pe_file(pe_data, slot, timestamp_token, embed_certificate)
}

// NOTE: Extended path containing phased timestamp rebuild logic stays in root file
// until domain timestamp unsigned attribute injection is integrated.

/// Async helper for CLI compatibility during migration.
/// Signs a PE file located on disk using `YubiKey` + OpenSSL, mirroring previous
/// root-level helper API. Will be replaced by pipeline orchestration in a later phase.
pub async fn sign_pe_file_with_yubikey_openssl<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    config: &SigningConfig,
) -> SigningResult<()> {
    // Read input
    let data = std::fs::read(&input_path).map_err(|e| {
        crate::infra::error::SigningError::IoError(format!("Failed to read input file: {e}"))
    })?;

    // Validate PE early (fail-fast before hardware access)
    let _ = pe::parse_pe(&data)?;

    // Connect + authenticate
    let mut yubikey_ops = YubiKeyOperations::connect()?;
    yubikey_ops.authenticate(&config.pin)?;

    // Build bridge once
    let mut bridge =
        YubiKeyAuthenticodeBridge::new(yubikey_ops, config.piv_slot, config.hash_algorithm)?;

    // Prepare timestamp token using signature bytes (SignerInfo.signature TBS path)
    let timestamp_token = if let Some(url) = &config.timestamp_url {
        // Extract signature bytes (this performs one internal signing round to produce signature value)
        let signature_bytes = bridge.extract_signature_bytes(&data, config.piv_slot)?;
        let client = TimestampClient::new(url);
        Some(client.get_timestamp(&signature_bytes).await?)
    } else {
        None
    };

    let signed = bridge.sign_pe_file(
        &data,
        config.piv_slot,
        timestamp_token.as_deref(),
        config.embed_certificate,
    )?;

    // Write output
    std::fs::write(&output_path, signed).map_err(|e| {
        crate::infra::error::SigningError::IoError(format!("Failed to write output file: {e}"))
    })?;

    Ok(())
}
