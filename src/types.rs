//! Type-safe wrappers using new-type pattern
//!
//! This module provides type-safe wrappers for various inputs to prevent
//! common errors and improve API safety.

use std::fmt;
use std::str::FromStr;
use crate::error::{SigningError, SigningResult};

/// Type-safe wrapper for timestamp URLs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampUrl(String);

impl TimestampUrl {
    /// Create a new TimestampUrl after validation
    pub fn new(url: impl AsRef<str>) -> SigningResult<Self> {
        let url = url.as_ref();
        Self::validate_url(url)?;
        Ok(TimestampUrl(url.to_string()))
    }

    /// Get the URL as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that the URL is reasonable for timestamping
    fn validate_url(url: &str) -> SigningResult<()> {
        // Must start with http:// or https://
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(SigningError::ValidationError(
                format!("Timestamp URL must start with http:// or https://, got: {}", url)
            ));
        }

        // Must have more content than just the protocol
        if url.len() <= 8 {
            return Err(SigningError::ValidationError(
                "Timestamp URL too short".to_string()
            ));
        }

        // Check for suspicious patterns
        let suspicious_patterns = ["localhost", "127.0.0.1", "javascript:", "file:", "data:"];
        for pattern in &suspicious_patterns {
            if url.contains(pattern) {
                return Err(SigningError::ValidationError(
                    format!("Timestamp URL contains suspicious pattern '{}': {}", pattern, url)
                ));
            }
        }

        // Basic domain validation - must contain at least one dot
        let without_protocol = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap();
        if !without_protocol.contains('.') {
            return Err(SigningError::ValidationError(
                format!("Timestamp URL must contain a valid domain: {}", url)
            ));
        }

        Ok(())
    }
}

impl FromStr for TimestampUrl {
    type Err = SigningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for TimestampUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type-safe wrapper for PIV PINs
#[derive(Debug, Clone)]
pub struct PivPin(String);

impl PivPin {
    /// Create a new PivPin after validation
    pub fn new(pin: impl AsRef<str>) -> SigningResult<Self> {
        let pin = pin.as_ref();
        Self::validate_pin(pin)?;
        Ok(PivPin(pin.to_string()))
    }

    /// Get the PIN as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the PIN as bytes for YubiKey API
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Validate PIV PIN format
    fn validate_pin(pin: &str) -> SigningResult<()> {
        // PIV PINs must be 6-8 characters
        if pin.len() < 6 {
            return Err(SigningError::ValidationError(
                format!("PIV PIN too short: {} characters (minimum 6)", pin.len())
            ));
        }

        if pin.len() > 8 {
            return Err(SigningError::ValidationError(
                format!("PIV PIN too long: {} characters (maximum 8)", pin.len())
            ));
        }

        // PIV PINs are typically numeric, but YubiKey supports alphanumeric
        // We'll be flexible but warn about non-numeric PINs
        if !pin.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(SigningError::ValidationError(
                "PIV PIN must contain only alphanumeric characters".to_string()
            ));
        }

        Ok(())
    }
}

impl FromStr for PivPin {
    type Err = SigningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// Don't implement Display for PivPin to avoid accidental logging
impl fmt::Display for PivPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[PIN REDACTED]")
    }
}

/// Type-safe wrapper for PIV slot IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PivSlot(u8);

impl PivSlot {
    /// Create a new PivSlot after validation
    pub fn new(slot: u8) -> SigningResult<Self> {
        Self::validate_slot(slot)?;
        Ok(PivSlot(slot))
    }

    /// Get the slot ID as u8
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// Get the slot as a YubiKey SlotId enum
    pub fn as_slot_id(&self) -> yubikey::piv::SlotId {
        match self.0 {
            0x9a => yubikey::piv::SlotId::Authentication,
            0x9c => yubikey::piv::SlotId::Signature,
            0x9d => yubikey::piv::SlotId::KeyManagement,
            0x9e => yubikey::piv::SlotId::CardAuthentication,
            _ => yubikey::piv::SlotId::Authentication, // Should never happen due to validation
        }
    }

    /// Get a human-readable description of the slot
    pub fn description(&self) -> &'static str {
        match self.0 {
            0x9a => "Authentication (login/auth certificates)",
            0x9c => "Digital Signature (code signing certificates)",
            0x9d => "Key Management (encryption certificates)",
            0x9e => "Card Authentication (PIV authentication)",
            _ => "Unknown slot", // Should never happen
        }
    }

    /// Validate PIV slot ID
    fn validate_slot(slot: u8) -> SigningResult<()> {
        match slot {
            0x9a | 0x9c | 0x9d | 0x9e => Ok(()),
            _ => Err(SigningError::ValidationError(
                format!("Invalid PIV slot 0x{:02x}. Valid slots: 0x9a (Auth), 0x9c (Sign), 0x9d (KeyMgmt), 0x9e (CardAuth)", slot)
            ))
        }
    }
}

impl FromStr for PivSlot {
    type Err = SigningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let slot = u8::from_str_radix(s, 16)
            .map_err(|_| SigningError::ValidationError(
                format!("Invalid slot format '{}'. Expected hex value (9a, 9c, 9d, or 9e)", s)
            ))?;
        Self::new(slot)
    }
}

impl fmt::Display for PivSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:02x}", self.0)
    }
}

/// Type-safe wrapper for hash data with size validation
#[derive(Debug, Clone)]
pub struct HashData {
    data: Vec<u8>,
    expected_algorithm: Option<crate::HashAlgorithm>,
}

impl HashData {
    /// Create new hash data with algorithm validation
    pub fn new(data: Vec<u8>, algorithm: Option<crate::HashAlgorithm>) -> SigningResult<Self> {
        let hash_data = HashData {
            data,
            expected_algorithm: algorithm,
        };
        hash_data.validate()?;
        Ok(hash_data)
    }

    /// Create hash data without algorithm validation (for raw signing)
    pub fn raw(data: Vec<u8>) -> SigningResult<Self> {
        if data.len() > 1024 {
            return Err(SigningError::ValidationError(
                format!("Hash data too large: {} bytes (maximum 1024)", data.len())
            ));
        }
        Ok(HashData {
            data,
            expected_algorithm: None,
        })
    }

    /// Get the hash data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the hash data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if hash data is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Validate hash data size against expected algorithm
    fn validate(&self) -> SigningResult<()> {
        if let Some(algorithm) = self.expected_algorithm {
            let expected_size = match algorithm {
                crate::HashAlgorithm::Sha256 => 32,
                crate::HashAlgorithm::Sha384 => 48,
                crate::HashAlgorithm::Sha512 => 64,
            };

            if self.data.len() != expected_size {
                return Err(SigningError::ValidationError(
                    format!(
                        "Hash size mismatch: got {} bytes, expected {} bytes for {:?}",
                        self.data.len(),
                        expected_size,
                        algorithm
                    )
                ));
            }
        } else {
            // For raw hash data, check reasonable bounds
            if self.data.is_empty() {
                return Err(SigningError::ValidationError(
                    "Hash data cannot be empty".to_string()
                ));
            }

            if self.data.len() > 1024 {
                return Err(SigningError::ValidationError(
                    format!("Hash data too large: {} bytes (maximum 1024)", self.data.len())
                ));
            }
        }

        Ok(())
    }
}

/// Type-safe wrapper for file paths
#[derive(Debug, Clone)]
pub struct SecurePath(std::path::PathBuf);

impl SecurePath {
    /// Create a new SecurePath after validation
    pub fn new(path: impl AsRef<std::path::Path>) -> SigningResult<Self> {
        let path = path.as_ref().to_path_buf();
        Self::validate_path(&path)?;
        Ok(SecurePath(path))
    }

    /// Get the path as a PathBuf
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }

    /// Validate that the path is reasonable and secure
    fn validate_path(path: &std::path::Path) -> SigningResult<()> {
        // Check for empty path
        if path.as_os_str().is_empty() {
            return Err(SigningError::ValidationError(
                "Path cannot be empty".to_string()
            ));
        }

        // Convert to string for validation
        let path_str = path.to_string_lossy();

        // Check for suspicious patterns
        let suspicious_patterns = ["../", "..\\", "://", "javascript:", "data:"];
        for pattern in &suspicious_patterns {
            if path_str.contains(pattern) {
                return Err(SigningError::ValidationError(
                    format!("Path contains suspicious pattern '{}': {}", pattern, path_str)
                ));
            }
        }

        // Check for excessively long paths
        if path_str.len() > 1000 {
            return Err(SigningError::ValidationError(
                format!("Path too long: {} characters (maximum 1000)", path_str.len())
            ));
        }

        Ok(())
    }
}

impl fmt::Display for SecurePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_url_validation() {
        // Valid URLs
        let valid_urls = vec![
            "https://timestamp.digicert.com",
            "http://timestamp.globalsign.com/advanced",
            "https://tsa.swisssign.net",
        ];

        for url in valid_urls {
            assert!(TimestampUrl::new(url).is_ok(), "URL should be valid: {}", url);
        }

        // Invalid URLs
        let invalid_urls = vec![
            "",
            "ftp://timestamp.com",
            "javascript:alert('xss')",
            "http://localhost/timestamp",
            "https://127.0.0.1/timestamp",
            "not-a-url",
            "http://",
        ];

        for url in invalid_urls {
            assert!(TimestampUrl::new(url).is_err(), "URL should be invalid: {}", url);
        }
    }

    #[test]
    fn test_piv_pin_validation() {
        // Valid PINs
        let valid_pins = vec!["123456", "12345678", "abc123", "000000"];
        for pin in valid_pins {
            assert!(PivPin::new(pin).is_ok(), "PIN should be valid: {}", pin);
        }

        // Invalid PINs
        let invalid_pins = vec!["", "12345", "123456789", "12 34 56", "123-456"];
        for pin in invalid_pins {
            assert!(PivPin::new(pin).is_err(), "PIN should be invalid: {}", pin);
        }
    }

    #[test]
    fn test_piv_slot_validation() {
        // Valid slots
        let valid_slots = vec![0x9a, 0x9c, 0x9d, 0x9e];
        for slot in valid_slots {
            assert!(PivSlot::new(slot).is_ok(), "Slot should be valid: 0x{:02x}", slot);
        }

        // Invalid slots
        let invalid_slots = vec![0x00, 0x99, 0xFF, 0x9b, 0x9f];
        for slot in invalid_slots {
            assert!(PivSlot::new(slot).is_err(), "Slot should be invalid: 0x{:02x}", slot);
        }
    }

    #[test]
    fn test_hash_data_validation() {
        // Valid hash data
        let sha256_hash = vec![0x01; 32];
        assert!(HashData::new(sha256_hash, Some(crate::HashAlgorithm::Sha256)).is_ok());

        // Invalid hash data (wrong size)
        let wrong_size = vec![0x01; 31];
        assert!(HashData::new(wrong_size, Some(crate::HashAlgorithm::Sha256)).is_err());

        // Raw hash data
        let raw_data = vec![0x01; 100];
        assert!(HashData::raw(raw_data).is_ok());

        // Too large raw data
        let too_large = vec![0x01; 2000];
        assert!(HashData::raw(too_large).is_err());
    }

    #[test]
    fn test_secure_path_validation() {
        // Valid paths
        let valid_paths = vec!["test.exe", "C:\\Program Files\\test.exe", "/usr/bin/test"];
        for path in valid_paths {
            assert!(SecurePath::new(path).is_ok(), "Path should be valid: {}", path);
        }

        // Invalid paths
        let invalid_paths = vec!["", "../../../etc/passwd", "javascript:alert('xss')"];
        for path in invalid_paths {
            assert!(SecurePath::new(path).is_err(), "Path should be invalid: {}", path);
        }
    }
}
