//! MSI file parsing and manipulation.
//!
//! Provides types for parsing and modifying MSI files (OLE Compound Documents)
//! for Authenticode digital signature operations.

use crate::infra::error::{SigningError, SigningResult};
use cfb::CompoundFile;
use std::io::{Cursor, Read};

/// Error type for MSI parsing failures.
#[derive(Debug, Clone)]
pub struct MsiParseError(pub String);

impl std::fmt::Display for MsiParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MSI parse error: {}", self.0)
    }
}

impl std::error::Error for MsiParseError {}

/// Represents an unsigned MSI file (no `DigitalSignature` stream present).
///
/// This type ensures the MSI file does not contain an existing signature,
/// making it safe for initial signing operations.
#[derive(Debug)]
pub struct UnsignedMsiFile {
    bytes: Vec<u8>,
}

impl UnsignedMsiFile {
    /// Create a new unsigned MSI file from raw bytes.
    ///
    /// Validates that:
    /// - The file has valid OLE Compound Document structure
    /// - No `DigitalSignature` stream is present
    ///
    /// # Arguments
    /// * `bytes` - Raw MSI file bytes
    ///
    /// # Errors
    /// Returns error if the file is not a valid MSI or already contains a signature.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SigningError> {
        // Check magic
        if bytes.len() < 8 || bytes[..8] != super::MSI_MAGIC {
            return Err(SigningError::MsiParsingError(
                "Not an MSI file (missing OLE magic)".into(),
            ));
        }

        // Try to parse as CFB
        let cursor = Cursor::new(&bytes);
        let cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        // Check for existing signature
        if cfb.exists(super::DIGITAL_SIGNATURE_STREAM) {
            return Err(SigningError::ValidationError(
                "MSI file already contains a digital signature".into(),
            ));
        }

        Ok(Self { bytes })
    }

    /// Get the raw bytes of the MSI file.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Represents a signed MSI file (contains `DigitalSignature` stream).
#[derive(Debug)]
pub struct SignedMsiFile {
    bytes: Vec<u8>,
}

impl SignedMsiFile {
    /// Create a signed MSI file from raw bytes (no validation).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the raw bytes of the signed MSI file.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// High-level MSI file representation for signing operations.
pub struct MsiFile {
    /// The raw bytes of the MSI file
    data: Vec<u8>,
}

impl MsiFile {
    /// Open an MSI file from raw bytes.
    ///
    /// # Arguments
    /// * `data` - Raw MSI file bytes
    ///
    /// # Errors
    /// Returns error if the file is not a valid OLE Compound Document.
    pub fn open(data: Vec<u8>) -> SigningResult<Self> {
        if data.len() < 8 || data[..8] != super::MSI_MAGIC {
            return Err(SigningError::MsiParsingError(
                "Not an MSI file (missing OLE magic)".into(),
            ));
        }

        // Validate structure
        let cursor = Cursor::new(&data);
        CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        Ok(Self { data })
    }

    /// Check if this MSI file already has a digital signature.
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be read.
    pub fn has_signature(&self) -> SigningResult<bool> {
        let cursor = Cursor::new(&self.data);
        let cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;
        Ok(cfb.exists(super::DIGITAL_SIGNATURE_STREAM))
    }

    /// Check if this MSI file has an extended signature (`MsiDigitalSignatureEx`).
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be read.
    pub fn has_extended_signature(&self) -> SigningResult<bool> {
        let cursor = Cursor::new(&self.data);
        let cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;
        Ok(cfb.exists(super::DIGITAL_SIGNATURE_EX_STREAM))
    }

    /// Get the raw file bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Embed a PKCS#7 signature into the MSI file.
    ///
    /// This creates or replaces the `\x05DigitalSignature` stream with
    /// the provided PKCS#7 DER-encoded signature.
    ///
    /// # Arguments
    /// * `pkcs7_der` - The PKCS#7 signature in DER format
    ///
    /// # Returns
    /// A new `SignedMsiFile` with the embedded signature.
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be modified.
    pub fn embed_signature(&self, pkcs7_der: &[u8]) -> SigningResult<SignedMsiFile> {
        self.embed_signature_with_ex(pkcs7_der, None)
    }

    /// Embed a PKCS#7 signature with optional extended signature data.
    ///
    /// This uses a native Rust implementation to embed the signature into the
    /// MSI file. The implementation carefully preserves the existing file structure
    /// to ensure the hash computed during verification matches.
    ///
    /// # Arguments
    /// * `pkcs7_der` - The PKCS#7 signature in DER format
    /// * `msi_digital_signature_ex` - Optional pre-hash for `MsiDigitalSignatureEx`
    ///
    /// # Returns
    /// A new `SignedMsiFile` with the embedded signature(s).
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be modified.
    pub fn embed_signature_with_ex(
        &self,
        pkcs7_der: &[u8],
        msi_digital_signature_ex: Option<&[u8]>,
    ) -> SigningResult<SignedMsiFile> {
        // Use native Rust embedder that rewrites the CFB container in an
        // verifier-compatible way.
        let output =
            super::embed::embed_signature_with_ex(&self.data, pkcs7_der, msi_digital_signature_ex)?;

        log::debug!(
            "Successfully embedded MSI signature ({} bytes -> {} bytes)",
            self.data.len(),
            output.len()
        );

        Ok(SignedMsiFile::from_bytes(output))
    }

    /// List all streams in the MSI file (for debugging).
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be read.
    pub fn list_streams(&self) -> SigningResult<Vec<String>> {
        let cursor = Cursor::new(&self.data);
        let cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        let mut streams = Vec::new();
        for entry in cfb.walk() {
            if entry.is_stream() {
                streams.push(entry.path().display().to_string());
            }
        }
        Ok(streams)
    }

    /// Read a specific stream from the MSI file.
    ///
    /// # Arguments
    /// * `path` - The stream path (e.g., "/`DigitalSignature`")
    ///
    /// # Errors
    /// Returns error if the stream doesn't exist or cannot be read.
    pub fn read_stream(&self, path: &str) -> SigningResult<Vec<u8>> {
        let cursor = Cursor::new(&self.data);
        let mut cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        let mut stream = cfb.open_stream(path).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to open stream '{path}': {e}"))
        })?;

        let mut data = Vec::new();
        stream.read_to_end(&mut data).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to read stream '{path}': {e}"))
        })?;

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_msi_magic() {
        let msi_header = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert!(super::super::is_msi_file(&msi_header));

        let pe_header = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert!(!super::super::is_msi_file(&pe_header));
    }

    #[test]
    fn test_unsigned_msi_rejects_non_msi() {
        let not_msi = vec![0x4D, 0x5A, 0x00, 0x00]; // PE header
        let result = UnsignedMsiFile::new(not_msi);
        assert!(result.is_err());
    }
}
