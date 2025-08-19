//! `SpcBuilderService` constructs `SpcIndirectData` from a PE hash.
//! Thin adapter around `create_spc_content` logic.

use crate::{domain::spc::SpcIndirectData, HashAlgorithm, SigningResult};

pub struct SpcBuilderService {
    hash_algorithm: HashAlgorithm,
}

impl SpcBuilderService {
    #[must_use]
    pub fn new(hash_algorithm: HashAlgorithm) -> Self {
        Self { hash_algorithm }
    }

    /// Build `SpcIndirectData` by delegating to provided DER construction closure.
    /// The closure should produce valid SPC `IndirectData` DER bytes from a PE hash.
    pub fn build<F>(&self, pe_hash: &[u8], der_builder: F) -> SigningResult<SpcIndirectData>
    where
        F: Fn(&[u8]) -> SigningResult<Vec<u8>>,
    {
        SpcIndirectData::from_pe_hash(self.hash_algorithm, pe_hash, der_builder)
    }
}
