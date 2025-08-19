//! PKCS#7 `SignedData` domain wrapper.
//! Minimal newtype around DER bytes; will gain structured parsing.

use std::fmt;

pub mod attributes;
pub mod timestamp; // RFC3161 TimestampToken now colocated with PKCS#7 domain

pub struct Pkcs7SignedData {
    der: Vec<u8>,
}

// Incremental component wrappers to decouple assembly steps.
pub struct Pkcs7DigestAlgorithms {
    der: Vec<u8>,
} // SET OF AlgorithmIdentifier
pub struct Pkcs7ContentInfoSpc {
    der: Vec<u8>,
} // EncapsulatedContentInfo for SpcIndirectData
pub struct Pkcs7SignerInfos {
    der: Vec<u8>,
} // SET OF SignerInfo

impl Pkcs7DigestAlgorithms {
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}
impl Pkcs7ContentInfoSpc {
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}
impl Pkcs7SignerInfos {
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl Pkcs7SignedData {
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.der.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.der.is_empty()
    }
}

impl fmt::Debug for Pkcs7SignedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pkcs7SignedData(len={})", self.der.len())
    }
}

pub use attributes::{SignedAttributeLogical, SignedAttributesCanonical};
pub use timestamp::TimestampToken;
