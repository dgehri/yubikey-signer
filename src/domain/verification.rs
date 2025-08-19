//! Verification domain types for Authenticode signed PE files.
//!
//! Aggregates results from verification steps; cryptographic and structural
//! checks are delegated to existing OpenSSL-backed helpers. This keeps the
//! domain layer free of direct crypto dependencies while providing a stable
//! reporting contract to higher level workflows.

/// Result of verifying a signed PE file.
///
/// This struct aggregates the outcomes of various verification checks
/// performed on an Authenticode-signed PE file, providing a comprehensive
/// view of the signature's validity.
///
/// Each field represents a specific aspect of the verification process:
/// - `hash_ok`: PE hash recomputation matches the messageDigest attribute
/// - `signature_ok`: CMS signature validates over authenticated attributes  
/// - `attrs_ok`: Authenticated attributes structure and ordering are valid
/// - `timestamp_ok`: RFC3161 timestamp (when present) is valid
/// - `chain_ok`: Certificate chain validates according to policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// True if the recomputed PE hash matches the messageDigest attribute.
    pub hash_ok: bool,
    /// True if the CMS signature validates over the authenticated attributes.
    pub signature_ok: bool,
    /// True if the authenticated attributes set structure & ordering are valid.
    pub attrs_ok: bool,
    /// True if an RFC3161 timestamp (when present) is valid.
    pub timestamp_ok: bool,
    /// True if the certificate chain validates according to policy (basic checks only for now).
    pub chain_ok: bool,
}

impl VerificationReport {
    /// Construct a new verification report from component results.
    ///
    /// # Arguments
    ///
    /// * `hash_ok` - Whether PE hash recomputation succeeded
    /// * `signature_ok` - Whether signature validation succeeded  
    /// * `attrs_ok` - Whether authenticated attributes are valid
    /// * `timestamp_ok` - Whether timestamp validation succeeded
    /// * `chain_ok` - Whether certificate chain validation succeeded
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn new(
        hash_ok: bool,
        signature_ok: bool,
        attrs_ok: bool,
        timestamp_ok: bool,
        chain_ok: bool,
    ) -> Self {
        Self {
            hash_ok,
            signature_ok,
            attrs_ok,
            timestamp_ok,
            chain_ok,
        }
    }

    /// Overall success indicator - returns true only if all checks passed.
    ///
    /// This is the primary method for determining if a signed PE file
    /// can be considered fully valid according to Authenticode standards.
    #[must_use]
    pub fn success(&self) -> bool {
        self.hash_ok && self.signature_ok && self.attrs_ok && self.timestamp_ok && self.chain_ok
    }
}
