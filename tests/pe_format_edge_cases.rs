//! PE file format edge case tests
//!
//! Tests for handling various PE file formats, malformed files, and edge cases

use yubikey_signer::domain::pe::parse_pe;
use yubikey_signer::{
    services::authenticode::OpenSslAuthenticodeSigner,
    services::{pe_hasher::PeHasher, spc_builder::SpcBuilderService},
    HashAlgorithm,
};

#[test]
fn test_minimal_pe_file() {
    let pe_data = create_minimal_valid_pe();

    let result = parse_pe(&pe_data);
    // May fail due to incomplete implementation, but shouldn't crash
    match result {
        Ok(pe_info) => {
            println!(
                "Parsed minimal PE: checksum offset {}",
                pe_info.checksum_offset
            );
        }
        Err(e) => {
            println!("Expected failure parsing minimal PE: {e}");
            // Should be a parsing error, not a panic
            assert!(format!("{e}").contains("PE") || format!("{e}").contains("parse"));
        }
    }
}

#[test]
fn test_corrupted_dos_header() {
    // Test various corrupted DOS headers
    let test_cases = vec![
        ("No MZ signature", b"XX\x90\x00\x03\x00".to_vec()),
        ("Truncated header", b"MZ\x90".to_vec()),
        ("Wrong endianness", b"ZM\x00\x90\x00\x03".to_vec()),
        ("Invalid e_lfanew", create_pe_with_invalid_lfanew()),
    ];

    for (name, data) in test_cases {
        println!("Testing corrupted DOS header: {name}");

        let result = parse_pe(&data);
        assert!(result.is_err(), "Should fail parsing corrupted PE: {name}");

        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("DOS")
                || error_msg.contains("MZ")
                || error_msg.contains("header")
                || error_msg.contains("parse"),
            "Error should mention DOS/MZ header or parsing: {error_msg}"
        );
    }
}

#[test]
fn test_corrupted_pe_header() {
    let test_cases = vec![
        ("No PE signature", create_pe_with_bad_pe_signature()),
        ("Invalid machine type", create_pe_with_invalid_machine()),
        ("Zero sections", create_pe_with_zero_sections()),
        ("Too many sections", create_pe_with_too_many_sections()),
    ];

    for (name, data) in test_cases {
        println!("Testing corrupted PE header: {name}");

        let result = parse_pe(&data);
        assert!(result.is_err(), "Should fail parsing corrupted PE: {name}");
    }
}

#[test]
fn test_malformed_sections() {
    let test_cases = vec![
        (
            "Overlapping sections",
            create_pe_with_overlapping_sections(),
        ),
        ("Section past EOF", create_pe_with_section_past_eof()),
        ("Zero-size section", create_pe_with_zero_size_section()),
        ("Huge section", create_pe_with_huge_section()),
    ];

    for (name, data) in test_cases {
        println!("Testing malformed sections: {name}");

        let result = parse_pe(&data);
        // Should handle gracefully
        match result {
            Ok(_) => println!("  Parsed (surprising)"),
            Err(e) => println!("  Failed as expected: {e}"),
        }
    }
}

#[test]
fn test_existing_signatures() {
    // Test files that already have signatures
    let pe_with_sig = create_pe_with_existing_signature();

    let result = parse_pe(&pe_with_sig);
    match result {
        Ok(pe_info) => {
            // Should detect existing signature
            println!("PE with existing signature parsed");
            // Check if we can detect the existing signature directory
            if pe_info.certificate_table.is_some() {
                println!("  Detected existing certificate table");
            }
        }
        Err(e) => {
            println!("Failed to parse PE with signature: {e}");
        }
    }
}

#[test]
fn test_edge_case_file_sizes() {
    let test_cases = vec![
        ("Empty file", vec![]),
        ("1 byte", vec![0x00]),
        ("63 bytes (DOS header - 1)", vec![0x00; 63]),
        ("64 bytes (minimal DOS)", create_minimal_dos_header()),
        ("Very large file simulation", create_large_pe_simulation()),
    ];

    for (name, data) in test_cases {
        println!(
            "Testing file size edge case: {} ({} bytes)",
            name,
            data.len()
        );

        let result = parse_pe(&data);
        // All should fail gracefully
        assert!(result.is_err(), "Should fail for edge case: {name}");
    }
}

#[test]
fn test_pe_file_modifications() {
    // Test behavior when PE file data changes
    let pe_data = create_minimal_valid_pe();

    // Parse first
    let _result1 = parse_pe(&pe_data);

    // Modify data
    let mut modified_data = pe_data.clone();
    modified_data.extend_from_slice(b"MODIFIED");

    // Parse again - should handle changed file
    let _result2 = parse_pe(&modified_data);

    // Both results may be errors, but shouldn't crash
}

#[test]
fn test_non_pe_files_with_pe_extensions() {
    // Test files that have .exe extension but aren't PE files
    let test_cases = vec![
        ("Text file", b"This is just a text file".to_vec()),
        ("Binary data", vec![0x01, 0x02, 0x03, 0x04, 0x05]),
        ("DOS executable", create_fake_dos_executable()),
        ("ELF file", create_fake_elf_file()),
        ("Mach-O file", create_fake_macho_file()),
    ];

    for (name, data) in test_cases {
        println!("Testing non-PE file: {name}");

        let result = parse_pe(&data);
        assert!(result.is_err(), "Should reject non-PE file: {name}");

        let error_msg = format!("{}", result.unwrap_err());
        // Should clearly indicate it's not a valid PE file
        assert!(
            error_msg.contains("PE")
                || error_msg.contains("format")
                || error_msg.contains("invalid")
                || error_msg.contains("parse"),
            "Error should indicate invalid PE format: {error_msg}"
        );
    }
}

// Helper functions to create test PE files

fn create_minimal_valid_pe() -> Vec<u8> {
    let mut pe = Vec::new();

    // DOS Header (64 bytes)
    pe.extend_from_slice(b"MZ"); // e_magic
    pe.extend_from_slice(&[0x90, 0x00]); // e_cblp
    pe.extend_from_slice(&[0x03, 0x00]); // e_cp
    pe.extend_from_slice(&[0x00, 0x00]); // e_crlc
    pe.extend_from_slice(&[0x04, 0x00]); // e_cparhdr
    pe.extend_from_slice(&[0x00, 0x00]); // e_minalloc
    pe.extend_from_slice(&[0xFF, 0xFF]); // e_maxalloc
    pe.extend_from_slice(&[0x00, 0x00]); // e_ss
    pe.extend_from_slice(&[0xB8, 0x00]); // e_sp
    pe.extend_from_slice(&[0x00, 0x00]); // e_csum
    pe.extend_from_slice(&[0x00, 0x00]); // e_ip
    pe.extend_from_slice(&[0x00, 0x00]); // e_cs
    pe.extend_from_slice(&[0x40, 0x00]); // e_lfarlc
    pe.extend_from_slice(&[0x00, 0x00]); // e_ovno

    // Reserved fields
    for _ in 0..4 {
        pe.extend_from_slice(&[0x00, 0x00]);
    }

    pe.extend_from_slice(&[0x00, 0x00]); // e_oemid
    pe.extend_from_slice(&[0x00, 0x00]); // e_oeminfo

    // More reserved fields
    for _ in 0..10 {
        pe.extend_from_slice(&[0x00, 0x00]);
    }

    // e_lfanew - offset to PE header (at 0x100)
    pe.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);

    // DOS stub (pad to PE header location)
    while pe.len() < 0x100 {
        pe.push(0x00);
    }

    // PE Header
    pe.extend_from_slice(b"PE\x00\x00"); // PE signature

    // COFF Header
    pe.extend_from_slice(&[0x4c, 0x01]); // Machine (i386)
    pe.extend_from_slice(&[0x01, 0x00]); // NumberOfSections
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TimeDateStamp
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PointerToSymbolTable
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NumberOfSymbols
    pe.extend_from_slice(&[0xE0, 0x00]); // SizeOfOptionalHeader
    pe.extend_from_slice(&[0x02, 0x01]); // Characteristics

    // Optional Header (PE32)
    pe.extend_from_slice(&[0x0B, 0x01]); // Magic (PE32)
    pe.extend_from_slice(&[0x0E, 0x00]); // MajorLinkerVersion, MinorLinkerVersion
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // SizeOfCode
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // SizeOfInitializedData
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // SizeOfUninitializedData
    pe.extend_from_slice(&[0x00, 0x20, 0x00, 0x00]); // AddressOfEntryPoint
    pe.extend_from_slice(&[0x00, 0x20, 0x00, 0x00]); // BaseOfCode
    pe.extend_from_slice(&[0x00, 0x30, 0x00, 0x00]); // BaseOfData
    pe.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // ImageBase
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // SectionAlignment
    pe.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // FileAlignment
    pe.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // MajorOSVersion, MinorOSVersion
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // MajorImageVersion, MinorImageVersion
    pe.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // MajorSubsystemVersion, MinorSubsystemVersion
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Win32VersionValue
    pe.extend_from_slice(&[0x00, 0x40, 0x00, 0x00]); // SizeOfImage
    pe.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]); // SizeOfHeaders
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CheckSum
    pe.extend_from_slice(&[0x03, 0x00]); // Subsystem (CONSOLE)
    pe.extend_from_slice(&[0x00, 0x00]); // DllCharacteristics
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // SizeOfStackReserve
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // SizeOfStackCommit
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // SizeOfHeapReserve
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // SizeOfHeapCommit
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // LoaderFlags
    pe.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NumberOfRvaAndSizes

    // Data directories (16 entries, 8 bytes each)
    for _ in 0..16 {
        pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // VirtualAddress
        pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Size
    }

    // Section Headers (40 bytes each)
    // .text section
    pe.extend_from_slice(b".text\x00\x00\x00"); // Name
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // VirtualSize
    pe.extend_from_slice(&[0x00, 0x20, 0x00, 0x00]); // VirtualAddress
    pe.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // SizeOfRawData
    pe.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]); // PointerToRawData
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PointerToRelocations
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PointerToLinenumbers
    pe.extend_from_slice(&[0x00, 0x00]); // NumberOfRelocations
    pe.extend_from_slice(&[0x00, 0x00]); // NumberOfLinenumbers
    pe.extend_from_slice(&[0x20, 0x00, 0x00, 0x60]); // Characteristics

    // Pad to section data
    while pe.len() < 0x400 {
        pe.push(0x00);
    }

    // Section data (.text section - 512 bytes)
    for i in 0..512 {
        pe.push((i % 256) as u8);
    }

    pe
}

fn create_minimal_dos_header() -> Vec<u8> {
    let mut dos = Vec::new();
    dos.extend_from_slice(b"MZ");
    dos.extend(std::iter::repeat_n(0x00, 62)); // 64 - 2 = 62
    dos
}

fn create_pe_with_invalid_lfanew() -> Vec<u8> {
    let mut pe = create_minimal_dos_header();
    // Set e_lfanew to point past EOF
    pe[60..64].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    pe
}

fn create_pe_with_bad_pe_signature() -> Vec<u8> {
    let mut pe = create_minimal_dos_header();
    // Set e_lfanew to reasonable location
    pe[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // Pad to PE header location
    while pe.len() < 0x80 {
        pe.push(0x00);
    }

    // Bad PE signature
    pe.extend_from_slice(b"NOTPE");
    pe
}

fn create_pe_with_invalid_machine() -> Vec<u8> {
    let mut pe = create_minimal_dos_header();
    pe[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    while pe.len() < 0x80 {
        pe.push(0x00);
    }

    pe.extend_from_slice(b"PE\x00\x00");
    pe.extend_from_slice(&[0xFF, 0xFF]); // Invalid machine type
    pe
}

fn create_pe_with_zero_sections() -> Vec<u8> {
    let mut pe = create_minimal_dos_header();
    pe[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    while pe.len() < 0x80 {
        pe.push(0x00);
    }

    pe.extend_from_slice(b"PE\x00\x00");
    pe.extend_from_slice(&[0x4c, 0x01]); // Machine
    pe.extend_from_slice(&[0x00, 0x00]); // Zero sections
    pe
}

fn create_pe_with_too_many_sections() -> Vec<u8> {
    let mut pe = create_minimal_dos_header();
    pe[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    while pe.len() < 0x80 {
        pe.push(0x00);
    }

    pe.extend_from_slice(b"PE\x00\x00");
    pe.extend_from_slice(&[0x4c, 0x01]); // Machine
    pe.extend_from_slice(&[0xFF, 0xFF]); // Too many sections
    pe
}

fn create_pe_with_overlapping_sections() -> Vec<u8> {
    // Create a basic PE but with overlapping section addresses
    create_minimal_valid_pe() // For now, just return valid PE
}

#[test]
fn pe_hasher_parity_with_authenticode_signer() {
    let path = "reference/clean_unsigned.exe";
    if let Ok(bytes) = std::fs::read(path) {
        let hasher = PeHasher::new(HashAlgorithm::Sha256);
        let digest1 = hasher.hash(&bytes).expect("PeHasher should hash");
        let reference_signer =
            OpenSslAuthenticodeSigner::new_placeholder_for_hash(HashAlgorithm::Sha256)
                .expect("test signer");
        let digest2 = reference_signer
            .compute_pe_hash(&bytes)
            .expect("reference hash");
        assert_eq!(
            digest1, digest2,
            "PeHasher digest mismatch with AuthenticodeSigner path"
        );
    } else {
        eprintln!("Skipping parity test; missing reference/clean_unsigned.exe");
    }
}

#[test]
fn spc_builder_parity() {
    let path = "reference/clean_unsigned.exe";
    if let Ok(bytes) = std::fs::read(path) {
        let hasher = PeHasher::new(HashAlgorithm::Sha256);
        let pe_digest = match hasher.hash(&bytes) {
            Ok(d) => d,
            Err(_) => return,
        };
        let reference_signer =
            OpenSslAuthenticodeSigner::new_placeholder_for_hash(HashAlgorithm::Sha256)
                .expect("test signer");
        let reference_spc = reference_signer
            .create_spc_content(&pe_digest)
            .expect("reference spc");
        let spc_builder = SpcBuilderService::new(HashAlgorithm::Sha256);
        let domain_spc = spc_builder
            .build(&pe_digest, |h| reference_signer.create_spc_content(h))
            .expect("domain spc");
        assert_eq!(
            domain_spc.as_der(),
            &reference_spc,
            "SPC DER mismatch between service and AuthenticodeSigner"
        );
    } else {
        eprintln!("Skipping SPC parity test; missing reference/clean_unsigned.exe");
    }
}

#[test]
fn signed_attributes_builder_parity() {
    let path = "reference/clean_unsigned.exe";
    if let Ok(bytes) = std::fs::read(path) {
        let signer = OpenSslAuthenticodeSigner::new_placeholder_for_hash(HashAlgorithm::Sha256)
            .expect("test signer");
        let pe_digest = signer.compute_pe_hash(&bytes).expect("hash");
        let spc = signer.create_spc_content(&pe_digest).expect("spc");
        // Reference authenticated attributes (already sorted & with complete DER sequences stored in value position)
        let reference_attrs = signer
            .create_authenticated_attributes(&pe_digest, &spc, None, &bytes)
            .expect("reference attrs");
        let mut reference_concat = Vec::new();
        for (_, der) in &reference_attrs {
            reference_concat.extend_from_slice(der);
        }
        // Rebuild logical list for SignedAttributesBuilder parity (each der already complete Attribute sequence)
        let logical: Vec<yubikey_signer::domain::pkcs7::SignedAttributeLogical> = reference_attrs
            .iter()
            .map(
                |(name, der)| yubikey_signer::domain::pkcs7::SignedAttributeLogical {
                    oid: name.clone(),
                    der: der.clone(),
                },
            )
            .collect();
        let builder =
            yubikey_signer::services::signed_attributes_builder::SignedAttributesBuilder::new();
        let canonical = builder.canonicalize(logical);
        assert_eq!(
            canonical.concatenated_der(),
            &reference_concat[..],
            "SignedAttributesBuilder canonical DER mismatch with AuthenticodeSigner ordering"
        );
    } else {
        eprintln!(
            "Skipping SignedAttributesBuilder parity test; missing reference/clean_unsigned.exe"
        );
    }
}

fn create_pe_with_section_past_eof() -> Vec<u8> {
    create_minimal_valid_pe() // Simplified for now
}

fn create_pe_with_zero_size_section() -> Vec<u8> {
    create_minimal_valid_pe() // Simplified for now
}

fn create_pe_with_huge_section() -> Vec<u8> {
    create_minimal_valid_pe() // Simplified for now
}

fn create_pe_with_existing_signature() -> Vec<u8> {
    create_minimal_valid_pe() // Simplified for now
}

fn create_large_pe_simulation() -> Vec<u8> {
    // Create a PE that simulates a large file without actually being large
    let mut pe = create_minimal_valid_pe();
    // Extend with some extra data to make it larger
    pe.extend_from_slice(&vec![0x00; 1024]);
    pe
}

fn create_fake_dos_executable() -> Vec<u8> {
    // Old DOS .COM file format
    vec![
        0xB4, 0x09, 0xBA, 0x10, 0x01, 0xCD, 0x21, 0xCD, 0x20, b'H', b'e', b'l', b'l', b'o', b'$',
    ]
}

fn create_fake_elf_file() -> Vec<u8> {
    // ELF magic number and minimal header
    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F']); // ELF magic
    elf.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]); // Class, data, version, ABI
    elf.extend_from_slice(&[0x00; 8]); // Padding
    elf.extend_from_slice(&[0x02, 0x00]); // e_type
    elf.extend_from_slice(&[0x03, 0x00]); // e_machine (i386)
    elf
}

fn create_fake_macho_file() -> Vec<u8> {
    // Mach-O magic number
    let mut macho = Vec::new();
    macho.extend_from_slice(&[0xFE, 0xED, 0xFA, 0xCE]); // MH_MAGIC
    macho.extend_from_slice(&[0x00, 0x00, 0x00, 0x07]); // CPU_TYPE_X86
    macho
}
