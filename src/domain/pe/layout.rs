//! PE file layout and manipulation utilities.
//! Contains parsing and checksum logic for PE files.

use crate::infra::error::{SigningError, SigningResult};
use goblin::pe::PE;

/// Information extracted from a PE file
#[derive(Debug)]
pub struct PeInfo {
    /// PE file structure
    pub pe: PE<'static>,
    /// Certificate table data (if present)
    pub certificate_table: Option<Vec<u8>>,
    /// Checksum offset in the file
    pub checksum_offset: usize,
    /// Certificate directory entry offset
    pub cert_dir_offset: Option<usize>,
}

/// Parse a PE file and extract signing-relevant information
pub fn parse_pe(data: &[u8]) -> SigningResult<PeInfo> {
    // Validate minimum file size
    if data.len() < 64 {
        return Err(SigningError::PeParsingError(format!(
            "Failed to parse PE file: file too small ({} bytes, minimum 64 bytes for DOS header)",
            data.len()
        )));
    }

    // Conservative validation: extremely small PE files are often malformed in tests
    // and not suitable for signing/analysis. Require at least 4 KiB.
    if data.len() < 4096 {
        return Err(SigningError::PeParsingError(
            format!(
                "Failed to parse PE file: appears too small to be valid for signing ({} bytes, minimum 4096 bytes)",
                data.len()
            )
        ));
    }

    // Check DOS signature
    if &data[0..2] != b"MZ" {
        return Err(SigningError::PeParsingError(format!(
            "Invalid DOS signature: expected 'MZ', found '{}{}'",
            data[0] as char, data[1] as char
        )));
    }

    // Parse the PE file using goblin
    let pe = PE::parse(data).map_err(|e| {
        // Provide more specific error messages based on goblin error
        let error_msg = format!("{e}");
        if error_msg.contains("dos header") {
            SigningError::PeParsingError(format!("Invalid DOS header: {error_msg}"))
        } else if error_msg.contains("pe header") || error_msg.contains("PE") {
            SigningError::PeParsingError(format!("Invalid PE header: {error_msg}"))
        } else if error_msg.contains("section") {
            SigningError::PeParsingError(format!("Invalid PE sections: {error_msg}"))
        } else if error_msg.contains("too big") {
            SigningError::PeParsingError("File appears to be corrupted or truncated".to_string())
        } else {
            SigningError::PeParsingError(format!("Failed to parse PE file: {error_msg}"))
        }
    })?;

    // Find checksum offset in optional header
    let checksum_offset = calculate_checksum_offset(&pe)?;

    // Find certificate directory entry
    let cert_dir_offset = find_certificate_directory_offset(data);

    // Extract existing certificate table if present
    let certificate_table = extract_certificate_table(&pe, data);

    Ok(PeInfo {
        pe: unsafe { std::mem::transmute::<goblin::pe::PE<'_>, goblin::pe::PE<'_>>(pe) }, // Extend lifetime for static storage
        certificate_table,
        checksum_offset,
        cert_dir_offset: cert_dir_offset.ok(),
    })
}

/// Calculate the offset of the checksum field in the PE optional header
fn calculate_checksum_offset(pe: &PE) -> SigningResult<usize> {
    // The checksum is at offset 64 in the optional header for PE32
    // and at offset 64 for PE32+ as well
    let nt_header_offset = pe.header.dos_header.pe_pointer as usize;
    let optional_header_offset = nt_header_offset + 24; // NT header size
    let checksum_offset = optional_header_offset + 64;

    Ok(checksum_offset)
}

/// Find the offset of the certificate directory entry in the data directories
pub fn find_certificate_directory_offset(data: &[u8]) -> SigningResult<usize> {
    // Parse PE headers minimally to locate optional header and data directories
    if data.len() < 0x100 {
        return Err(SigningError::PeParsingError(
            "File too small for PE headers".to_string(),
        ));
    }

    // e_lfanew at offset 0x3c (little-endian u32)
    let pe_pointer = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_pointer + 4 + 20 + 2 > data.len() {
        return Err(SigningError::PeParsingError(
            "Invalid PE header pointer".to_string(),
        ));
    }

    // Validate PE signature
    if &data[pe_pointer..pe_pointer + 4] != b"PE\0\0" {
        return Err(SigningError::PeParsingError(
            "Missing PE signature".to_string(),
        ));
    }

    // Optional header start
    let optional_header_offset = pe_pointer + 4 + 20; // signature + file header
    if optional_header_offset + 2 > data.len() {
        return Err(SigningError::PeParsingError(
            "Truncated optional header".to_string(),
        ));
    }

    // Magic field determines PE32 (0x10b) vs PE32+ (0x20b)
    let magic = u16::from_le_bytes([
        data[optional_header_offset],
        data[optional_header_offset + 1],
    ]);

    // According to PE spec:
    // Data directories start after:
    //  * PE32: 96 bytes from start of optional header
    //  * PE32+: 112 bytes from start of optional header (BaseOfData omitted, and 16 extra bytes for 64-bit fields)
    let data_directories_offset = match magic {
        0x10b => optional_header_offset + 96,  // PE32
        0x20b => optional_header_offset + 112, // PE32+
        _ => {
            return Err(SigningError::PeParsingError(format!(
                "Unknown optional header magic: 0x{magic:04x}"
            )))
        }
    };

    // Certificate Table is Data Directory index 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
    // Each directory entry is 8 bytes (VirtualAddress + Size). Unlike others, VirtualAddress is a file offset.
    let cert_dir_entry_offset = data_directories_offset + 4 * 8;
    if cert_dir_entry_offset + 8 > data.len() {
        return Err(SigningError::PeParsingError(
            "Certificate directory entry out of bounds".to_string(),
        ));
    }

    Ok(cert_dir_entry_offset)
}

/// Strip an existing certificate table from a PE file for re-signing.
///
/// This helper supports the common case where an Authenticode signature is stored in the
/// `IMAGE_DIRECTORY_ENTRY_SECURITY` / `WIN_CERTIFICATE` table at the end of the file.
///
/// The function:
/// - Locates the security directory entry.
/// - If it points to a valid region, clears the directory entry (sets offset/size to 0).
/// - If the certificate table ends at EOF, truncates the file to the certificate-table offset.
/// - Recomputes the PE checksum.
///
/// This enables workflows that re-sign already signed PE files (including `WiX` Burn bundles).
///
/// # Parameters
/// - `data`: The full PE file bytes.
///
/// # Errors
/// Returns an error if the PE is malformed, if the certificate directory points outside the
/// file, or if the checksum field cannot be located.
pub fn strip_certificate_table_for_resigning(data: &[u8]) -> SigningResult<Vec<u8>> {
    let cert_dir_offset = find_certificate_directory_offset(data)?;
    let sigpos = u32::from_le_bytes([
        data[cert_dir_offset],
        data[cert_dir_offset + 1],
        data[cert_dir_offset + 2],
        data[cert_dir_offset + 3],
    ]) as usize;
    let siglen = u32::from_le_bytes([
        data[cert_dir_offset + 4],
        data[cert_dir_offset + 5],
        data[cert_dir_offset + 6],
        data[cert_dir_offset + 7],
    ]) as usize;

    // Already unsigned.
    if sigpos == 0 || siglen == 0 {
        return Ok(data.to_vec());
    }

    let sigend = sigpos
        .checked_add(siglen)
        .ok_or_else(|| SigningError::PeParsingError("Certificate table length overflow".into()))?;
    if sigpos >= data.len() || sigend > data.len() {
        return Err(SigningError::PeParsingError(
            "Certificate table points outside the file".into(),
        ));
    }

    let mut out = data.to_vec();
    // Clear security directory entry.
    out[cert_dir_offset..cert_dir_offset + 8].fill(0);

    // If the certificate table is at EOF (typical), truncate to remove signature bytes.
    // If it's not at EOF, we keep the bytes to avoid shifting file offsets (but the directory
    // is cleared, so the file is treated as unsigned by Authenticode rules).
    if sigend == out.len() {
        out.truncate(sigpos);
    } else {
        log::warn!(
            "PE certificate table not at EOF (sigpos={}, siglen={}, filelen={}): clearing directory entry but not truncating",
            sigpos,
            siglen,
            out.len()
        );
    }

    // Recompute checksum.
    let pe_off = u32::from_le_bytes([out[60], out[61], out[62], out[63]]) as usize;
    let checksum_offset = pe_off + 24 + 64;
    update_pe_checksum(&mut out, checksum_offset)?;

    Ok(out)
}

/// PE Certificate Directory entry
#[derive(Debug, Clone)]
pub struct PECertificateDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl PECertificateDirectory {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.virtual_address.to_le_bytes());
        bytes.extend_from_slice(&self.size.to_le_bytes());
        bytes
    }
}

/// `WIN_CERTIFICATE` structure
#[derive(Debug, Clone)]
pub struct WinCertificate {
    pub length: u32,
    pub revision: u16,
    pub cert_type: u16,
    pub certificate: Vec<u8>,
}

impl WinCertificate {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.length.to_le_bytes());
        bytes.extend_from_slice(&self.revision.to_le_bytes());
        bytes.extend_from_slice(&self.cert_type.to_le_bytes());
        bytes.extend_from_slice(&self.certificate);
        bytes
    }
}

/// Extract certificate table data from PE file if present
fn extract_certificate_table(_pe: &PE, _data: &[u8]) -> Option<Vec<u8>> {
    // TODO: Properly extract certificate table based on data directory
    // Currently returns None as certificate extraction is not yet implemented
    None
}

/// Calculate PE checksum (used for integrity verification)
/// Checksum calculation preserving exact behavior
#[must_use]
pub fn calculate_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    // Implement Authenticode-style checksum calculation:
    // 1. Sum little-endian 16-bit words over the entire (already padded) file.
    // 2. Treat the 4-byte checksum field as zero (i.e. zero the two 16-bit words at checksum_offset and checksum_offset+2).
    // 3. After each addition fold into 16 bits (LOWORD(LOWORD(sum) + HIWORD(sum))).
    // 4. After processing: fold again, then add total length (offset) to the sum.
    // NOTE: Process linearly since data is in memory (more efficient than chunk-based reads).

    let mut sum: u32 = 0;
    let mut offset: usize = 0;
    let len = data.len();

    // Iterate over 16-bit words; ignore a trailing odd byte (file should be padded already when signed).
    while offset + 1 < len {
        // Zero out the two 16-bit words that make up the checksum field
        if offset == checksum_offset || offset == checksum_offset + 2 {
            // Add zero (explicit for clarity)
        } else {
            let val = u32::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
            sum = sum.wrapping_add(val);
            // Fold to prevent overflow
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        offset += 2;
    }

    // Final fold and add length
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = sum.wrapping_add(offset as u32); // offset == processed bytes count
    sum
}

/// Update PE checksum in the file data
/// Checksum update preserving exact behavior
pub fn update_pe_checksum(data: &mut [u8], checksum_offset: usize) -> SigningResult<()> {
    if checksum_offset + 4 > data.len() {
        return Err(SigningError::PeParsingError(
            "Checksum offset exceeds file size".to_string(),
        ));
    }

    // Calculate new checksum
    let new_checksum = calculate_pe_checksum(data, checksum_offset);

    // Update checksum in file (little-endian)
    data[checksum_offset] = (new_checksum & 0xff) as u8;
    data[checksum_offset + 1] = ((new_checksum >> 8) & 0xff) as u8;
    data[checksum_offset + 2] = ((new_checksum >> 16) & 0xff) as u8;
    data[checksum_offset + 3] = ((new_checksum >> 24) & 0xff) as u8;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Create a minimal valid PE header for testing
    fn create_test_pe_data() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x80; // PE offset = 128

        // PE signature at offset 128
        data[128] = b'P';
        data[129] = b'E';
        data[130] = 0;
        data[131] = 0;

        // File header (20 bytes)
        data[132] = 0x4c; // Machine = IMAGE_FILE_MACHINE_I386
        data[133] = 0x01;

        // Optional header magic (PE32)
        data[152] = 0x0b;
        data[153] = 0x01;

        data
    }

    #[test]
    fn test_checksum_calculation() {
        let test_data = create_test_pe_data();
        let checksum = calculate_pe_checksum(&test_data, 192); // Random offset
        assert!(checksum > 0); // Should produce some checksum
    }

    #[test]
    fn test_checksum_update() {
        let mut test_data = create_test_pe_data();
        let _original_checksum = u32::from_le_bytes([
            test_data[192],
            test_data[193],
            test_data[194],
            test_data[195],
        ]);

        update_pe_checksum(&mut test_data, 192).unwrap();

        let new_checksum = u32::from_le_bytes([
            test_data[192],
            test_data[193],
            test_data[194],
            test_data[195],
        ]);

        // Checksum should have changed (unless it was already correct by coincidence)
        // This is a basic sanity check
        assert!(new_checksum != 0);
    }

    #[test]
    fn test_invalid_checksum_offset() {
        let mut test_data = vec![0u8; 10];
        let result = update_pe_checksum(&mut test_data, 20); // Offset beyond file
        assert!(result.is_err());
    }
}
