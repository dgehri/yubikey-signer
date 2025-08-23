//! Error types for `YubiKey` signing operations.
//! Error handling types and result definitions for signing operations.

use thiserror::Error;

/// Result type for signing operations
pub type SigningResult<T> = Result<T, SigningError>;

/// Comprehensive error types for signing operations
#[derive(Error, Debug, miette::Diagnostic)]
pub enum SigningError {
    #[error("YubiKey error: {0}")]
    YubiKeyError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Invalid certificate format: {0}")]
    InvalidCertificate(String),

    #[error("PE file parsing error: {0}")]
    PeParsingError(String),

    #[error("Signature creation error: {0}")]
    SignatureError(String),

    #[error("Timestamp error: {0}")]
    TimestampError(String),

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("ASN.1 encoding/decoding error: {0}")]
    Asn1Error(String),

    #[error("PKCS#7 structure error: {0}")]
    Pkcs7Error(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

impl From<yubikey::Error> for SigningError {
    fn from(error: yubikey::Error) -> Self {
        SigningError::YubiKeyError(error.to_string())
    }
}

impl From<der::Error> for SigningError {
    fn from(error: der::Error) -> Self {
        SigningError::Asn1Error(error.to_string())
    }
}

impl From<reqwest::Error> for SigningError {
    fn from(error: reqwest::Error) -> Self {
        SigningError::NetworkError(error.to_string())
    }
}

impl From<goblin::error::Error> for SigningError {
    fn from(error: goblin::error::Error) -> Self {
        SigningError::PeParsingError(error.to_string())
    }
}

impl From<std::io::Error> for SigningError {
    fn from(error: std::io::Error) -> Self {
        SigningError::IoError(error.to_string())
    }
}

// Note: We intentionally avoid depending on the `rsa` crate directly to
// mitigate security warnings (RUSTSEC-2023-0071). RSA operations are delegated
// to the YubiKey hardware via the `yubikey` crate; any crypto errors are
// reported through higher-level error variants.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = SigningError::YubiKeyError("Test error".to_string());
        assert_eq!(error.to_string(), "YubiKey error: Test error");

        let error = SigningError::InvalidInput("Invalid PIN".to_string());
        assert_eq!(error.to_string(), "Invalid input: Invalid PIN");
    }

    #[test]
    fn test_error_conversion() {
        // Test that our error types can be created and converted
        let error_msg = "Test DER error";
        let signing_error = SigningError::Asn1Error(error_msg.to_string());
        match signing_error {
            SigningError::Asn1Error(msg) => assert_eq!(msg, error_msg),
            _ => panic!("Wrong error type"),
        }
    }
}
