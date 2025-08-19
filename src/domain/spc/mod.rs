//! SPC (Software Publisher Certificate) domain module.
//! Provides strongly-typed representation of `SpcIndirectDataContent` used in Authenticode.

pub mod constants;

use std::fmt;

use crate::{HashAlgorithm, SigningResult};

// Re-export SPC constants for convenient access
pub use constants::*;

/// Strongly-typed wrapper around the DER-encoded `SpcIndirectDataContent` structure.
/// Encapsulates the SPC content used in Authenticode signatures.
pub struct SpcIndirectData {
    der: Vec<u8>,
    hash_algorithm: HashAlgorithm,
}

impl SpcIndirectData {
    /// Construct from a precomputed PE hash by delegating to a DER builder function.
    /// The builder function encapsulates the SPC construction logic.
    pub fn from_pe_hash<F>(
        hash_algorithm: HashAlgorithm,
        pe_hash: &[u8],
        der_builder: F,
    ) -> SigningResult<Self>
    where
        F: Fn(&[u8]) -> SigningResult<Vec<u8>>,
    {
        let der = der_builder(pe_hash)?;
        Ok(Self {
            der,
            hash_algorithm,
        })
    }

    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
    #[must_use]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }
}

impl fmt::Debug for SpcIndirectData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpcIndirectData(len={})", self.der.len())
    }
}
