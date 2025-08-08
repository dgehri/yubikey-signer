//! PE file parsing and manipulation utilities

use crate::error::{SigningError, SigningResult};
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
        return Err(SigningError::PeParsingError(
            format!("File too small to be a valid PE file: {} bytes (minimum 64 bytes for DOS header)", data.len())
        ));
    }

    // Check DOS signature
    if &data[0..2] != b"MZ" {
        return Err(SigningError::PeParsingError(
            format!("Invalid DOS signature: expected 'MZ', found '{}{}'", 
                data[0] as char, data[1] as char)
        ));
    }

    // Parse the PE file using goblin
    let pe = PE::parse(data).map_err(|e| {
        // Provide more specific error messages based on goblin error
        let error_msg = format!("{e}");
        if error_msg.contains("dos header") {
            SigningError::PeParsingError(
                format!("Invalid DOS header: {error_msg}")
            )
        } else if error_msg.contains("pe header") || error_msg.contains("PE") {
            SigningError::PeParsingError(
                format!("Invalid PE header: {error_msg}")
            )
        } else if error_msg.contains("section") {
            SigningError::PeParsingError(
                format!("Invalid PE sections: {error_msg}")
            )
        } else if error_msg.contains("too big") {
            SigningError::PeParsingError(
                "File appears to be corrupted or truncated".to_string()
            )
        } else {
            SigningError::PeParsingError(
                format!("Failed to parse PE file: {error_msg}")
            )
        }
    })?;
    
    // Find checksum offset in optional header
    let checksum_offset = calculate_checksum_offset(&pe)?;
    
    // Find certificate directory entry
    let cert_dir_offset = find_certificate_directory_offset(&pe);
    
    // Extract existing certificate table if present
    let certificate_table = extract_certificate_table(&pe, data);
    
    Ok(PeInfo {
        pe: unsafe { std::mem::transmute(pe) }, // Extend lifetime for static storage
        certificate_table,
        checksum_offset,
        cert_dir_offset,
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
fn find_certificate_directory_offset(pe: &PE) -> Option<usize> {
    // Certificate table is data directory entry 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
    // Each data directory entry is 8 bytes (4 bytes VirtualAddress + 4 bytes Size)
    let nt_header_offset = pe.header.dos_header.pe_pointer as usize;
    let optional_header_offset = nt_header_offset + 24;
    
    // Data directories start after the optional header standard fields
    let data_dir_offset = match pe.header.optional_header {
        Some(_) => {
            // Both PE32 and PE32+ have similar layouts for our purposes
            optional_header_offset + 96 // Standard fields size
        }
        None => return None,
    };
    
    // Certificate table is directory entry 4
    Some(data_dir_offset + 4 * 8)
}

/// Extract certificate table data from PE file if present
fn extract_certificate_table(_pe: &PE, _data: &[u8]) -> Option<Vec<u8>> {
    // TODO: Properly extract certificate table based on data directory
    // This is a placeholder implementation
    None
}

/// Calculate PE checksum (used for integrity verification)
pub fn calculate_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut checksum: u64 = 0;
    let mut i = 0;
    
    // Process file in 32-bit chunks, skipping the checksum field
    while i < data.len() {
        if i == checksum_offset {
            // Skip the 4-byte checksum field
            i += 4;
            continue;
        }
        
        // Read 32-bit value (little-endian)
        let mut value = 0u32;
        for j in 0..4 {
            if i + j < data.len() {
                value |= (data[i + j] as u32) << (j * 8);
            }
        }
        
        checksum = (checksum & 0xffffffff) + value as u64 + (checksum >> 32);
        i += 4;
    }
    
    // Finalize checksum
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = checksum + (checksum >> 16);
    checksum &= 0xffff;
    
    (checksum + data.len() as u64) as u32
}

/// Update PE checksum in the file data
pub fn update_pe_checksum(data: &mut [u8], checksum_offset: usize) -> SigningResult<()> {
    if checksum_offset + 4 > data.len() {
        return Err(SigningError::PeParsingError(
            "Checksum offset exceeds file size".to_string()
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
            test_data[192], test_data[193], test_data[194], test_data[195]
        ]);
        
        update_pe_checksum(&mut test_data, 192).unwrap();
        
        let new_checksum = u32::from_le_bytes([
            test_data[192], test_data[193], test_data[194], test_data[195]
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
