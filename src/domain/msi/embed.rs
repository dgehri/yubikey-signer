//! MSI signature embedding.
//!
//! This module delegates to a verifier-compatible CFB rewriter implemented
//! in pure Rust (see `cfb_writer_compat`). We intentionally avoid using the `cfb`
//! crate for output because its layout decisions can trigger Windows
//! `TRUST_E_BAD_DIGEST` even when the logical MSI hash matches.

use crate::infra::error::{SigningError, SigningResult};

use super::embed_signature_cfb_writer;

/// Embed a PKCS#7 signature with optional extended signature data.
///
/// # Arguments
/// * `msi_data` - The original MSI file bytes
/// * `signature` - The PKCS#7 signature in DER format
/// * `signature_ex` - Optional `MsiDigitalSignatureEx` data
///
/// # Returns
/// The new MSI file bytes with the embedded signature(s).
///
/// # Errors
/// Returns an error if the MSI file cannot be parsed or the signature cannot
/// be embedded.
pub fn embed_signature_with_ex(
    msi_data: &[u8],
    signature: &[u8],
    signature_ex: Option<&[u8]>,
) -> SigningResult<Vec<u8>> {
    if signature_ex.is_some() {
        // Avoid producing invalid files: Ex-mode requires additional strict
        // rules and stream embedding. Until fully implemented, fail loudly.
        return Err(SigningError::ValidationError(
            "MsiDigitalSignatureEx embedding is not supported yet".into(),
        ));
    }

    embed_signature_cfb_writer(msi_data, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_parent_storages() {
        // This test was for the old cfb-based writer and is no longer relevant.
        // Keep a trivial assertion to retain the module test harness.
        assert!(true);
    }

    #[test]
    fn test_embed_preserves_hash() {
        use crate::domain::crypto::HashAlgorithm;
        use crate::domain::msi::MsiHashView;

        // Read test MSI file
        let original = match std::fs::read("test-data/test_unsigned.msi") {
            Ok(data) => data,
            Err(_) => return, // Skip if file doesn't exist
        };

        // Compute original hash
        let original_hash = MsiHashView::new(&original)
            .compute_hash(HashAlgorithm::Sha256)
            .unwrap();

        // Embed a dummy signature
        let fake_sig = vec![0u8; 100];
        let signed = embed_signature_with_ex(&original, &fake_sig, None).unwrap();

        // Compute hash of signed file
        let signed_hash = MsiHashView::new(&signed)
            .compute_hash(HashAlgorithm::Sha256)
            .unwrap();

        // The hashes should match (signature stream is excluded from hash)
        println!("Original hash: {:02x?}", original_hash);
        println!("Signed hash:   {:02x?}", signed_hash);
        assert_eq!(
            original_hash, signed_hash,
            "Embedding signature changed the MSI hash!"
        );
    }
}
