//! PE (Portable Executable) domain types and operations.
//!
//! Provides structured representations of Windows PE files with:
//! - Validated PE structure parsing and header access
//! - Canonical hash views for Authenticode digest computation
//! - Signed vs unsigned PE file distinctions with type safety
//! - PE signature embedding and checksum management
//!
//! These types ensure correct PE manipulation while preserving
//! the exact binary layout required for Windows compatibility.

mod hash_view;
pub mod layout;
mod parse;
// embedding domain wrappers introduced (minimal invariants)

use crate::SigningError;

mod signed_types {
    use super::SigningError;

    /// Unsigned PE file prior to `WIN_CERTIFICATE` embedding.
    /// minimal wrapper ensuring security directory empty.
    #[derive(Debug)]
    pub struct UnsignedPeFile {
        bytes: Vec<u8>,
    }

    /// Signed PE file (`WIN_CERTIFICATE` present & checksum updated).
    #[derive(Debug)]
    pub struct SignedPeFile {
        bytes: Vec<u8>,
    }

    impl UnsignedPeFile {
        pub fn new(bytes: Vec<u8>) -> Result<Self, SigningError> {
            // Basic PE sanity: must start with MZ and contain PE signature at offset from e_lfanew (byte 60..63)
            if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
                return Err(SigningError::PeParsingError(
                    "Not a PE file (missing MZ)".into(),
                ));
            }
            let pe_off = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
            if pe_off + 4 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
                return Err(SigningError::PeParsingError("Invalid PE signature".into()));
            }
            // Certificate directory entry (Security Directory) location depends on PE32/PE32+
            if pe_off + 24 + 2 > bytes.len() {
                // need magic field
                return Err(SigningError::PeParsingError(
                    "Truncated optional header".into(),
                ));
            }
            let magic = u16::from_le_bytes([bytes[pe_off + 24], bytes[pe_off + 25]]);
            let pe32plus = matches!(magic, 0x20b);
            let cert_dir_offset = pe_off + 24 + if pe32plus { 112 } else { 96 } + (4 * 8); // entry index 4
            if cert_dir_offset + 8 > bytes.len() {
                return Err(SigningError::PeParsingError(
                    "Truncated data directories".into(),
                ));
            }
            let rva = u32::from_le_bytes([
                bytes[cert_dir_offset],
                bytes[cert_dir_offset + 1],
                bytes[cert_dir_offset + 2],
                bytes[cert_dir_offset + 3],
            ]);
            let size = u32::from_le_bytes([
                bytes[cert_dir_offset + 4],
                bytes[cert_dir_offset + 5],
                bytes[cert_dir_offset + 6],
                bytes[cert_dir_offset + 7],
            ]);
            if rva != 0 || size != 0 {
                return Err(SigningError::ValidationError(
                    "PE already contains a certificate table; not UnsignedPeFile".into(),
                ));
            }
            Ok(Self { bytes })
        }
        #[must_use]
        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }
        #[must_use]
        pub fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    impl SignedPeFile {
        #[must_use]
        pub fn from_bytes(bytes: Vec<u8>) -> Self {
            Self { bytes }
        }
        #[must_use]
        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }
        #[must_use]
        pub fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// Locate the security directory table entry offset within a PE buffer.
    ///
    /// Used by verification and replacement embedding features to find the
    /// certificate table location within PE file data directories.
    ///
    /// Returns `None` if the buffer is not a minimally valid PE or directories truncated.
    #[must_use]
    pub fn security_directory_offset(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
            return None;
        }
        let pe_off = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
        if pe_off + 4 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
            return None;
        }
        if pe_off + 24 + 2 > bytes.len() {
            return None;
        }
        let magic = u16::from_le_bytes([bytes[pe_off + 24], bytes[pe_off + 25]]);
        let pe32plus = matches!(magic, 0x20b);
        let cert_dir_offset = pe_off + 24 + if pe32plus { 112 } else { 96 } + 32; // entry index 4 *8
        if cert_dir_offset + 8 > bytes.len() {
            return None;
        }
        Some(cert_dir_offset)
    }

    pub use SignedPeFile as SignedPeFileExport;
    pub use UnsignedPeFile as UnsignedPeFileExport;
}

pub use signed_types::{
    security_directory_offset, SignedPeFileExport as SignedPeFile,
    UnsignedPeFileExport as UnsignedPeFile,
};

pub use hash_view::PeHashView;
pub use layout::{
    calculate_pe_checksum, find_certificate_directory_offset, parse_pe,
    strip_certificate_table_for_resigning, update_pe_checksum, PECertificateDirectory, PeInfo,
    WinCertificate,
};
pub use parse::{PeParseError, PeRaw};
