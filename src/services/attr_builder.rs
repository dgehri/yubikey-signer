//! Attribute & TBS builder service (delegating implementation).
//!
//! Delegates to proven OpenSSL logic for deterministic DER attribute construction.

use crate::{services::authenticode::OpenSslAuthenticodeSigner, HashAlgorithm, SigningResult};

/// Output of the attribute build process.
pub struct AttributeBuildOutput {
    /// Canonical SET OF authenticated attributes (to be signed) DER.
    pub set_der: Vec<u8>,
    /// The embedding context specific [0] wrapper (A0) DER used inside `SignerInfo`.
    pub embedding_der: Vec<u8>,
    /// Raw individual attribute DER blobs (opaque, ordering matches SET canonical order).
    pub raw_attributes: Vec<(String, Vec<u8>)>,
}

/// Thin facade over OpenSSL-backed implementation.
pub struct AttrBuilderService {
    hash_algorithm: HashAlgorithm,
}

impl AttrBuilderService {
    #[must_use]
    pub fn new(hash_algorithm: HashAlgorithm) -> Self {
        Self { hash_algorithm }
    }

    /// Build authenticated attributes using the OpenSSL-backed implementation.
    #[allow(clippy::used_underscore_binding)]
    pub fn build(
        &self,
        pe_digest: &[u8],
        spc_der: &[u8],
        _cert_der: &[u8],
        _pe_bytes: &[u8],
    ) -> SigningResult<AttributeBuildOutput> {
        let signer = OpenSslAuthenticodeSigner::new_placeholder_for_hash(self.hash_algorithm)?;
        let attrs = signer.create_authenticated_attributes(pe_digest, spc_der, None, _pe_bytes)?;
        let (set_der, a0_der) = signer.build_tbs_and_embedding_data(&attrs)?;
        let raw_attributes = attrs.clone();
        Ok(AttributeBuildOutput {
            set_der,
            embedding_der: a0_der,
            raw_attributes,
        })
    }
}

impl Default for AttrBuilderService {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delegates_basic() {
        let svc = AttrBuilderService::new(HashAlgorithm::Sha256);
        let digest = vec![0x11u8; 32];
        let spc = vec![0x30, 0x00]; // minimal placeholder DER (empty SEQUENCE)
        let out = svc.build(&digest, &spc, &[], &[]).expect("attr build");
        assert!(out.set_der.starts_with(&[0x31]));
        assert!(out.embedding_der.starts_with(&[0xA0]));
        assert!(!out.set_der.is_empty());
        assert!(!out.embedding_der.is_empty());
    }
}
