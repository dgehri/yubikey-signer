//! MSI (Windows Installer) domain types and operations.
//!
//! Provides structured representations of MSI files for Authenticode signing:
//! - OLE Compound Document parsing using the CFB format
//! - MSI-specific hash computation (hashing stream contents in sorted order)
//! - Digital signature embedding in the `\x05DigitalSignature` stream
//! - Optional `MsiDigitalSignatureEx` stream for metadata hashing
//!
//! MSI files are OLE Compound Documents (Microsoft Structured Storage format).
//! Unlike PE files where the signature is appended, MSI signatures are stored
//! as named streams within the compound document structure.

mod cfb_writer;
mod embed;
mod hash;
mod parse;

pub use hash::MsiHashView;
pub use parse::{MsiFile, MsiParseError, SignedMsiFile, UnsignedMsiFile};

pub(crate) use cfb_writer::embed_signature_cfb_writer;

/// MSI file magic bytes (OLE Compound Document signature)
pub const MSI_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Name of the digital signature stream in MSI files
pub const DIGITAL_SIGNATURE_STREAM: &str = "\u{0005}DigitalSignature";

/// Name of the extended digital signature stream (metadata hash)
pub const DIGITAL_SIGNATURE_EX_STREAM: &str = "\u{0005}MsiDigitalSignatureEx";

/// Check if data starts with the MSI/OLE magic signature.
///
/// # Arguments
/// * `data` - The raw file bytes to check
///
/// # Returns
/// `true` if the data starts with the OLE Compound Document magic bytes
#[must_use]
pub fn is_msi_file(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == MSI_MAGIC
}
