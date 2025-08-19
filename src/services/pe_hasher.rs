//! `PeHasher` service: produces Authenticode digest via domain `PeRaw` + `PeHashView`.
//!
//! Delegates to proven OpenSSL-based hashing logic for cryptographic correctness.

use crate::{
    domain::pe::{PeHashView, PeRaw},
    services::authenticode::OpenSslAuthenticodeSigner,
    HashAlgorithm, SigningError, SigningResult,
};

pub struct PeHasher {
    algo: HashAlgorithm,
}

impl PeHasher {
    #[must_use]
    pub fn new(algo: HashAlgorithm) -> Self {
        Self { algo }
    }

    pub fn hash(&self, pe_bytes: &[u8]) -> SigningResult<Vec<u8>> {
        let pe_raw =
            PeRaw::parse(pe_bytes).map_err(|e| SigningError::PeParsingError(format!("{e}")))?;
        let view = PeHashView::from_raw(&pe_raw);
        // Reuse existing OpenSSL hashing logic for correctness parity
        let signer = OpenSslAuthenticodeSigner::new_empty(self.algo)?;
        signer.compute_pe_hash_view(&view)
    }
}

// Extension of existing signer to permit hashing reuse without full construction inputs.
impl OpenSslAuthenticodeSigner {
    pub(crate) fn new_empty(algo: HashAlgorithm) -> SigningResult<Self> {
        // Minimal instance with only hash_algorithm set; certificate fields left empty.
        Self::new_placeholder_for_hash(algo)
    }
}
