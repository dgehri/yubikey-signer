use std::fmt;

use super::HashAlgorithm;

/// Strongly typed digest bytes paired with the algorithm that produced them.
///
/// Invariant: `bytes.len() == algo.digest_size()`.
#[derive(Clone, Eq, PartialEq)]
pub struct DigestBytes {
    algo: HashAlgorithm,
    bytes: Box<[u8]>,
}

impl DigestBytes {
    pub fn new(algo: HashAlgorithm, bytes: Vec<u8>) -> Result<Self, DigestBytesError> {
        if bytes.len() != algo.digest_size() {
            return Err(DigestBytesError::LengthMismatch {
                expected: algo.digest_size(),
                actual: bytes.len(),
            });
        }
        Ok(Self {
            algo,
            bytes: bytes.into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algo
    }
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes.into()
    }
}

impl fmt::Debug for DigestBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DigestBytes(algo={:?}, len={})",
            self.algo,
            self.bytes.len()
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DigestBytesError {
    #[error("digest length mismatch (expected {expected}, actual {actual})")]
    LengthMismatch { expected: usize, actual: usize },
}
