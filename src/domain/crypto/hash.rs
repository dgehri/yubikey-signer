//! Hash algorithm domain type.
//!
//! Provides the core `HashAlgorithm` enumeration supporting SHA-256, SHA-384,
//! and SHA-512 for Authenticode signatures. Includes size validation and
//! OpenSSL integration for cryptographic operations.

pub use crate::HashAlgorithm;
