//! File format detection for signable files.
//!
//! Provides automatic detection and abstraction over different file formats
//! that can be signed with Authenticode signatures (PE, MSI, CAB, etc.).

use crate::domain::msi;
use crate::domain::pe;
use crate::infra::error::{SigningError, SigningResult};

/// Supported file formats for Authenticode signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// Windows Portable Executable (.exe, .dll, .sys, .ocx, .scr)
    Pe,
    /// Windows Installer Package (.msi, .msp, .mst)
    Msi,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pe => write!(f, "PE (Portable Executable)"),
            Self::Msi => write!(f, "MSI (Windows Installer)"),
        }
    }
}

impl FileFormat {
    /// Detect file format from raw bytes.
    ///
    /// Examines magic bytes to determine the file format:
    /// - PE files start with "MZ" (DOS header)
    /// - MSI files start with OLE Compound Document signature
    ///
    /// # Arguments
    /// * `data` - The raw file bytes
    ///
    /// # Returns
    /// The detected file format.
    ///
    /// # Errors
    /// Returns error if the format cannot be determined.
    pub fn detect(data: &[u8]) -> SigningResult<Self> {
        if data.len() < 8 {
            return Err(SigningError::InvalidInput(
                "File too small to determine format".into(),
            ));
        }

        // Check for MSI (OLE Compound Document) first - more specific magic
        if msi::is_msi_file(data) {
            return Ok(Self::Msi);
        }

        // Check for PE (DOS MZ header)
        if data.len() >= 2 && &data[0..2] == b"MZ" {
            return Ok(Self::Pe);
        }

        Err(SigningError::InvalidInput(
            "Unknown file format - expected PE (.exe, .dll) or MSI (.msi)".into(),
        ))
    }

    /// Detect file format from file extension.
    ///
    /// This is a fallback when magic detection fails or as a hint.
    ///
    /// # Arguments
    /// * `path` - The file path
    ///
    /// # Returns
    /// The detected file format based on extension, or None if unknown.
    #[must_use]
    pub fn from_extension(path: &std::path::Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        match ext.as_str() {
            "exe" | "dll" | "sys" | "ocx" | "scr" | "drv" | "efi" => Some(Self::Pe),
            "msi" | "msp" | "mst" => Some(Self::Msi),
            _ => None,
        }
    }

    /// Get the typical file extensions for this format.
    #[must_use]
    pub const fn extensions(&self) -> &'static [&'static str] {
        match self {
            Self::Pe => &["exe", "dll", "sys", "ocx", "scr", "drv", "efi"],
            Self::Msi => &["msi", "msp", "mst"],
        }
    }

    /// Check if this file format supports dual signing.
    ///
    /// Some formats support multiple signatures (nested signatures).
    #[must_use]
    pub const fn supports_nested_signatures(&self) -> bool {
        match self {
            Self::Pe => true,
            Self::Msi => true,
        }
    }
}

/// Information about a signable file.
#[derive(Debug)]
pub struct SignableFile {
    /// The detected file format
    pub format: FileFormat,
    /// Whether the file already has a signature
    pub is_signed: bool,
    /// The raw file data
    data: Vec<u8>,
}

impl SignableFile {
    /// Open and analyze a file for signing.
    ///
    /// # Arguments
    /// * `data` - The raw file bytes
    ///
    /// # Errors
    /// Returns error if the file format is not supported or cannot be parsed.
    pub fn open(data: Vec<u8>) -> SigningResult<Self> {
        let format = FileFormat::detect(&data)?;

        let is_signed = match format {
            FileFormat::Pe => {
                // Check if PE has certificate table
                if let Ok(pe_info) = pe::parse_pe(&data) {
                    pe_info.certificate_table.is_some()
                } else {
                    false
                }
            }
            FileFormat::Msi => {
                // Check if MSI has DigitalSignature stream
                let msi_file = msi::MsiFile::open(data.clone())?;
                msi_file.has_signature()?
            }
        };

        Ok(Self {
            format,
            is_signed,
            data,
        })
    }

    /// Get the raw file data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the raw data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_detection() {
        // Minimal PE header
        let pe_data = b"MZ\x00\x00\x00\x00\x00\x00".to_vec();
        assert_eq!(FileFormat::detect(&pe_data).unwrap(), FileFormat::Pe);
    }

    #[test]
    fn test_msi_detection() {
        // OLE magic
        let msi_data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert_eq!(FileFormat::detect(&msi_data).unwrap(), FileFormat::Msi);
    }

    #[test]
    fn test_unknown_format() {
        let unknown_data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert!(FileFormat::detect(&unknown_data).is_err());
    }

    #[test]
    fn test_extension_detection() {
        use std::path::Path;

        assert_eq!(
            FileFormat::from_extension(Path::new("test.exe")),
            Some(FileFormat::Pe)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("test.msi")),
            Some(FileFormat::Msi)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("test.DLL")),
            Some(FileFormat::Pe)
        );
        assert_eq!(FileFormat::from_extension(Path::new("test.txt")), None);
    }
}
