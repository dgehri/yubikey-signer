use std::fmt;

use super::HashAlgorithm;

/// Wrapper over a CMS/PKCS#7 signature value (raw DER-encoded signature bytes).
/// For ECDSA the bytes are typically the ASN.1 DER encoded Ecdsa-Sig-Value.
#[derive(Clone, Eq, PartialEq)]
pub struct CmsSignature {
    algo: HashAlgorithm, // hash algorithm used for the signed attributes digest
    bytes: Box<[u8]>,
}

impl CmsSignature {
    #[must_use]
    pub fn new(algo: HashAlgorithm, bytes: Vec<u8>) -> Self {
        Self {
            algo,
            bytes: bytes.into_boxed_slice(),
        }
    }
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algo
    }
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for CmsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CmsSignature(algo={:?}, len={})",
            self.algo,
            self.bytes.len()
        )
    }
}
