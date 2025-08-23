//! Foundational cryptographic domain types.
//!
//! Provides strongly-typed wrappers for cryptographic artifacts including:
//! - Hash algorithms and digest values with size validation
//! - Certificate representations and chain structures  
//! - Digital signature values with algorithm constraints
//! - Type-safe conversions between raw bytes and semantic types
//!
//! These types ensure cryptographic correctness at compile time and provide
//! clear interfaces for the service layer operations.

mod cert;
mod digest_bytes;
mod hash;
mod signature;

pub use cert::{CertChain, EndEntityCert, IntermediateCert};
pub use digest_bytes::{DigestBytes, DigestBytesError};
pub use hash::HashAlgorithm;
pub use signature::CmsSignature;
