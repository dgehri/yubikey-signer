//! Protocol definitions for remote `YubiKey` signing.
//!
//! Defines the JSON message format exchanged between client and server
//! for secure remote signing operations.

use serde::{Deserialize, Serialize};

/// API version for protocol compatibility checks.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Request to sign a hash digest using the remote `YubiKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Protocol version for compatibility checking.
    pub version: String,
    /// Base64-encoded hash digest to sign.
    pub digest_b64: String,
    /// PIV slot to use (hex string, e.g. "9c").
    pub slot: String,
    /// Optional nonce for replay protection (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Response containing the signature from the remote `YubiKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Protocol version.
    pub version: String,
    /// Base64-encoded signature bytes.
    pub signature_b64: String,
    /// Echo of the nonce if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Request to retrieve the certificate from a PIV slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCertificateRequest {
    /// Protocol version.
    pub version: String,
    /// PIV slot to retrieve certificate from (hex string).
    pub slot: String,
}

/// Response containing the certificate from the remote `YubiKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCertificateResponse {
    /// Protocol version.
    pub version: String,
    /// Base64-encoded DER certificate bytes.
    pub certificate_der_b64: String,
}

/// Health check / status request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {
    /// Protocol version.
    pub version: String,
}

/// Status response with server and `YubiKey` information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Protocol version.
    pub version: String,
    /// Whether the `YubiKey` is connected and authenticated.
    pub yubikey_ready: bool,
    /// `YubiKey` serial number (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// `YubiKey` firmware version (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
    /// Available PIV slots with certificates.
    pub available_slots: Vec<String>,
    /// Server uptime in seconds.
    pub uptime_seconds: u64,
}

/// Error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Protocol version.
    pub version: String,
    /// Error code for programmatic handling.
    pub error_code: String,
    /// Human-readable error message.
    pub message: String,
}

/// Known error codes returned by the proxy.
pub mod error_codes {
    /// Authentication failed (bad token).
    pub const AUTH_FAILED: &str = "AUTH_FAILED";
    /// `YubiKey` not connected or not responding.
    pub const YUBIKEY_NOT_FOUND: &str = "YUBIKEY_NOT_FOUND";
    /// `YubiKey` not authenticated (PIN not verified).
    pub const NOT_AUTHENTICATED: &str = "NOT_AUTHENTICATED";
    /// Invalid slot specified.
    pub const INVALID_SLOT: &str = "INVALID_SLOT";
    /// Signing operation failed.
    pub const SIGNING_FAILED: &str = "SIGNING_FAILED";
    /// Certificate not found in slot.
    pub const CERT_NOT_FOUND: &str = "CERT_NOT_FOUND";
    /// Protocol version mismatch.
    pub const VERSION_MISMATCH: &str = "VERSION_MISMATCH";
    /// Malformed request.
    pub const BAD_REQUEST: &str = "BAD_REQUEST";
    /// Rate limit exceeded.
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
}

impl SignRequest {
    /// Create a new sign request.
    ///
    /// # Arguments
    /// * `digest` - Raw hash digest bytes to sign
    /// * `slot` - PIV slot identifier (e.g., 0x9c)
    #[must_use]
    pub fn new(digest: &[u8], slot: u8) -> Self {
        use base64::Engine;
        Self {
            version: PROTOCOL_VERSION.to_string(),
            digest_b64: base64::engine::general_purpose::STANDARD.encode(digest),
            slot: format!("{slot:02x}"),
            nonce: None,
        }
    }

    /// Add a nonce for replay protection.
    #[must_use]
    pub fn with_nonce(mut self) -> Self {
        use base64::Engine;
        let mut nonce_bytes = [0u8; 16];
        rand::fill(&mut nonce_bytes);
        self.nonce = Some(base64::engine::general_purpose::STANDARD.encode(nonce_bytes));
        self
    }

    /// Decode the digest from base64.
    ///
    /// # Errors
    /// Returns error if base64 decoding fails.
    pub fn decode_digest(&self) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&self.digest_b64)
    }
}

impl SignResponse {
    /// Create a new sign response.
    ///
    /// # Arguments
    /// * `signature` - Raw signature bytes
    /// * `nonce` - Optional nonce echo from request
    #[must_use]
    pub fn new(signature: &[u8], nonce: Option<String>) -> Self {
        use base64::Engine;
        Self {
            version: PROTOCOL_VERSION.to_string(),
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
            nonce,
        }
    }

    /// Decode the signature from base64.
    ///
    /// # Errors
    /// Returns error if base64 decoding fails.
    pub fn decode_signature(&self) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&self.signature_b64)
    }
}

impl GetCertificateRequest {
    /// Create a new certificate request.
    ///
    /// # Arguments
    /// * `slot` - PIV slot identifier (e.g., 0x9c)
    #[must_use]
    pub fn new(slot: u8) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            slot: format!("{slot:02x}"),
        }
    }
}

impl GetCertificateResponse {
    /// Create a new certificate response.
    ///
    /// # Arguments
    /// * `certificate_der` - DER-encoded certificate bytes
    #[must_use]
    pub fn new(certificate_der: &[u8]) -> Self {
        use base64::Engine;
        Self {
            version: PROTOCOL_VERSION.to_string(),
            certificate_der_b64: base64::engine::general_purpose::STANDARD.encode(certificate_der),
        }
    }

    /// Decode the certificate from base64.
    ///
    /// # Errors
    /// Returns error if base64 decoding fails.
    pub fn decode_certificate(&self) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&self.certificate_der_b64)
    }
}

impl ErrorResponse {
    /// Create a new error response.
    ///
    /// # Arguments
    /// * `code` - Error code from `error_codes` module
    /// * `message` - Human-readable error description
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            error_code: code.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_request_roundtrip() {
        let digest = vec![0xab; 32];
        let request = SignRequest::new(&digest, 0x9c);

        let decoded = request.decode_digest().unwrap();
        assert_eq!(decoded, digest);
        assert_eq!(request.slot, "9c");
    }

    #[test]
    fn test_sign_response_roundtrip() {
        let signature = vec![0xcd; 64];
        let response = SignResponse::new(&signature, Some("test-nonce".to_string()));

        let decoded = response.decode_signature().unwrap();
        assert_eq!(decoded, signature);
        assert_eq!(response.nonce, Some("test-nonce".to_string()));
    }

    #[test]
    fn test_certificate_response_roundtrip() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // Mock DER
        let response = GetCertificateResponse::new(&cert_der);

        let decoded = response.decode_certificate().unwrap();
        assert_eq!(decoded, cert_der);
    }
}
