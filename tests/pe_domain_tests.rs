use yubikey_signer::PeRaw;

#[test]
fn parse_valid_minimal_like_pe() {
    // Construct minimal PE-like buffer: DOS header (MZ ... e_lfanew at 0x3C), PE signature
    let mut buf = vec![0u8; 0x48]; // space for DOS + e_lfanew + PE sig
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_offset: u32 = 0x44; // place signature at 0x44
    buf[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    buf[0x44..0x48].copy_from_slice(b"PE\0\0");
    let parsed = PeRaw::parse(&buf).expect("should parse");
    assert_eq!(parsed.pe_offset(), 0x44);
    assert!(parsed.bytes().starts_with(b"MZ"));
}

use yubikey_signer::domain::pe::UnsignedPeFile;
use yubikey_signer::domain::pkcs7::Pkcs7SignedData;
use yubikey_signer::services::PeSignatureEmbedderService;

#[test]
fn phase6_embedder_basic_embedding() {
    // Minimal fake unsigned PE (reuse helper if exists else craft)
    let mut pe = vec![0u8; 512];
    pe[0] = b'M';
    pe[1] = b'Z';
    // e_lfanew at 0x80
    pe[60] = 0x80; // PE header offset
                   // PE signature
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;
    // Optional header magic (PE32)
    pe[0x80 + 24] = 0x0b;
    pe[0x80 + 25] = 0x01;
    // Ensure data directories area large enough (write zeros already) certificate directory offset for PE32 = pe_off + 24 + 96 + 32
    let cert_dir_offset = 0x80 + 24 + 96 + 32;
    assert!(cert_dir_offset + 8 <= pe.len());
    // Security directory zero -> qualifies as UnsignedPeFile
    let unsigned = UnsignedPeFile::new(pe.clone()).expect("unsigned");

    // Build tiny fake PKCS#7 (valid minimal SEQUENCE) – using existing builder for digest part
    // For simplicity embed arbitrary bytes shaped like ContentInfo (not parsed later in test)
    let fake_pkcs7 = Pkcs7SignedData::from_der(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    let embedder = PeSignatureEmbedderService::new();
    let original_hash = vec![0u8; 32]; // dummy hash (post validation warning acceptable)
    let signed = embedder
        .embed(&unsigned, &fake_pkcs7, &original_hash)
        .expect("embed");
    let out = signed.bytes();
    // Check security directory populated
    let rva = u32::from_le_bytes([
        out[cert_dir_offset],
        out[cert_dir_offset + 1],
        out[cert_dir_offset + 2],
        out[cert_dir_offset + 3],
    ]) as usize;
    let size = u32::from_le_bytes([
        out[cert_dir_offset + 4],
        out[cert_dir_offset + 5],
        out[cert_dir_offset + 6],
        out[cert_dir_offset + 7],
    ]) as usize;
    assert!(rva > 0 && size >= 8, "certificate directory not updated");
    assert!(rva + size <= out.len());
    // WIN_CERT header present
    assert_eq!(&out[rva + 4..rva + 6], &0x0200u16.to_le_bytes());
}

#[test]
fn phase6_embedder_checksum_verification() {
    // Create PE file with known checksum field
    let mut pe = vec![0u8; 512];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[60] = 0x80; // PE header offset
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;
    // PE32 magic
    pe[0x80 + 24] = 0x0b;
    pe[0x80 + 25] = 0x01;

    // Set initial checksum to known value (will be overwritten)
    let checksum_offset = 0x80 + 88;
    let initial_checksum: u32 = 0x12345678;
    pe[checksum_offset..checksum_offset + 4].copy_from_slice(&initial_checksum.to_le_bytes());

    let unsigned = UnsignedPeFile::new(pe.clone()).expect("unsigned");

    // Extract original checksum for comparison
    let original_checksum = u32::from_le_bytes([
        pe[checksum_offset],
        pe[checksum_offset + 1],
        pe[checksum_offset + 2],
        pe[checksum_offset + 3],
    ]);
    assert_eq!(original_checksum, initial_checksum);

    // Embed signature
    let fake_pkcs7 = Pkcs7SignedData::from_der(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    let embedder = PeSignatureEmbedderService::new();
    let original_hash = vec![0u8; 32];
    let signed = embedder
        .embed(&unsigned, &fake_pkcs7, &original_hash)
        .expect("embed");

    let output_bytes = signed.bytes();

    // Verify checksum was updated (should be different)
    let new_checksum = u32::from_le_bytes([
        output_bytes[checksum_offset],
        output_bytes[checksum_offset + 1],
        output_bytes[checksum_offset + 2],
        output_bytes[checksum_offset + 3],
    ]);

    assert_ne!(
        new_checksum, original_checksum,
        "checksum should have been updated"
    );
    assert_ne!(new_checksum, 0, "checksum should not be zero");
}

#[test]
fn phase6_embedder_padding_alignment() {
    // Test various PKCS#7 sizes to verify padding behavior
    let pe_base = {
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[60] = 0x80;
        pe[0x80] = b'P';
        pe[0x81] = b'E';
        pe[0x82] = 0;
        pe[0x83] = 0;
        pe[0x80 + 24] = 0x0b;
        pe[0x80 + 25] = 0x01;
        pe
    };

    // Test PKCS#7 sizes that require different padding amounts
    let test_cases = vec![
        (vec![0x30, 0x03, 0x02, 0x01, 0x01], "5 bytes (3 pad)"),
        (
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            "8 bytes (0 pad)",
        ),
        (
            vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x01],
            "9 bytes (7 pad)",
        ),
    ];

    for (pkcs7_bytes, description) in test_cases {
        let unsigned = UnsignedPeFile::new(pe_base.clone()).expect("unsigned");
        let fake_pkcs7 = Pkcs7SignedData::from_der(pkcs7_bytes.clone());
        let embedder = PeSignatureEmbedderService::new();
        let original_hash = vec![0u8; 32];

        let signed = embedder
            .embed(&unsigned, &fake_pkcs7, &original_hash)
            .unwrap_or_else(|_| panic!("embed {description}"));

        let output = signed.bytes();

        // Find certificate table
        let cert_dir_offset = 0x80 + 24 + 96 + 32;
        let cert_rva = u32::from_le_bytes([
            output[cert_dir_offset],
            output[cert_dir_offset + 1],
            output[cert_dir_offset + 2],
            output[cert_dir_offset + 3],
        ]) as usize;

        let cert_size = u32::from_le_bytes([
            output[cert_dir_offset + 4],
            output[cert_dir_offset + 5],
            output[cert_dir_offset + 6],
            output[cert_dir_offset + 7],
        ]) as usize;

        // Verify dwLength in WIN_CERTIFICATE header
        let win_cert_length = u32::from_le_bytes([
            output[cert_rva],
            output[cert_rva + 1],
            output[cert_rva + 2],
            output[cert_rva + 3],
        ]);

        // WIN_CERT length should be 8 (header) + PKCS#7 length + padding
        let expected_length = 8 + pkcs7_bytes.len();
        let padding = if expected_length % 8 == 0 {
            0
        } else {
            8 - (expected_length % 8)
        };
        let expected_total = expected_length + padding;

        assert_eq!(
            win_cert_length as usize, expected_total,
            "dwLength mismatch for {description}: expected {expected_total}, got {win_cert_length}"
        );

        // Verify size matches certificate directory entry
        assert_eq!(
            cert_size, expected_total,
            "certificate directory size mismatch for {description}"
        );

        // Verify padding bytes are zero
        if padding > 0 {
            let padding_start = cert_rva + 8 + pkcs7_bytes.len();
            for i in 0..padding {
                assert_eq!(
                    output[padding_start + i],
                    0,
                    "padding byte {i} not zero for {description}"
                );
            }
        }
    }
}

#[test]
fn phase6_embedder_rejects_already_signed() {
    // Create PE file with existing certificate table entry
    let mut pe = vec![0u8; 512];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[60] = 0x80;
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;
    pe[0x80 + 24] = 0x0b;
    pe[0x80 + 25] = 0x01;

    // Set certificate directory to non-zero (simulating already signed)
    let cert_dir_offset = 0x80 + 24 + 96 + 32;
    pe[cert_dir_offset] = 0x01; // Non-zero RVA
    pe[cert_dir_offset + 4] = 0x08; // Non-zero size

    // Should fail to create UnsignedPeFile
    let result = UnsignedPeFile::new(pe);
    assert!(
        result.is_err(),
        "should reject PE with existing certificate table"
    );

    let error_msg = format!("{}", result.unwrap_err());
    assert!(
        error_msg.contains("certificate")
            || error_msg.contains("signature")
            || error_msg.contains("signed"),
        "error should mention certificates/signatures: {error_msg}"
    );
}

#[test]
fn phase6_embedder_preserves_overlay_at_eof() {
    // Construct a small-but-parseable PE32 with a single section, then append an overlay.
    // The overlay simulates formats like WiX Burn bundles that keep an attached container
    // after the PE image.
    fn make_pe32_with_one_section_and_overlay(overlay_len: usize) -> Vec<u8> {
        let pe_off = 0x80usize;
        let size_of_optional_header = 0xE0usize; // PE32
        let section_table_off = pe_off + 24 + size_of_optional_header;
        let section_raw_off = 0x200usize;
        let section_raw_size = 0x200usize;
        let end_of_image = section_raw_off + section_raw_size; // 0x400

        let mut pe = vec![0u8; end_of_image + overlay_len];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

        // COFF header (20 bytes) after signature
        // Machine: 0x014c (Intel 386), NumberOfSections: 1, SizeOfOptionalHeader: 0xE0
        let coff_off = pe_off + 4;
        pe[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        pe[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
        pe[coff_off + 16..coff_off + 18]
            .copy_from_slice(&(size_of_optional_header as u16).to_le_bytes());
        pe[coff_off + 18..coff_off + 20].copy_from_slice(&0x010Fu16.to_le_bytes());

        // Optional header start
        let opt_off = pe_off + 24;
        pe[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32

        // SectionAlignment (optional header offset 32) and FileAlignment (offset 36)
        pe[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt_off + 36..opt_off + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        // SizeOfHeaders (optional header offset 60)
        pe[opt_off + 60..opt_off + 64].copy_from_slice(&0x0200u32.to_le_bytes());
        // NumberOfRvaAndSizes (optional header offset 92)
        pe[opt_off + 92..opt_off + 96].copy_from_slice(&16u32.to_le_bytes());
        // Certificate Table directory entry (index 4) left as 0 for unsigned.

        // Section header (40 bytes)
        pe[section_table_off..section_table_off + 8].copy_from_slice(b".text\0\0\0");
        // VirtualSize
        pe[section_table_off + 8..section_table_off + 12].copy_from_slice(&0x0200u32.to_le_bytes());
        // VirtualAddress
        pe[section_table_off + 12..section_table_off + 16]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData
        pe[section_table_off + 16..section_table_off + 20]
            .copy_from_slice(&(section_raw_size as u32).to_le_bytes());
        // PointerToRawData
        pe[section_table_off + 20..section_table_off + 24]
            .copy_from_slice(&(section_raw_off as u32).to_le_bytes());

        // Fill overlay with a recognizable pattern.
        for b in &mut pe[end_of_image..] {
            *b = 0xAA;
        }
        pe
    }

    // Use an overlay length that makes the file NOT 8-byte aligned.
    // The embedder adds padding AFTER the overlay to reach 8-byte alignment (Windows requires
    // WIN_CERTIFICATE to start at an aligned offset). The overlay bytes themselves remain intact.
    let overlay_len = 123;
    let pe = make_pe32_with_one_section_and_overlay(overlay_len);
    let original_len = pe.len();
    let unsigned = UnsignedPeFile::new(pe.clone()).expect("unsigned");

    let fake_pkcs7 = Pkcs7SignedData::from_der(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    let embedder = PeSignatureEmbedderService::new();
    let original_hash = vec![0u8; 32];
    let signed = embedder
        .embed(&unsigned, &fake_pkcs7, &original_hash)
        .expect("embed");

    let out = signed.bytes();

    // The overlay bytes must remain intact at the same offset (end-of-image = 0x400).
    let end_of_image = 0x400usize;
    assert!(
        out.len() > end_of_image + overlay_len,
        "expected signed file to be larger than unsigned (signature appended)"
    );
    assert!(
        out[end_of_image..end_of_image + overlay_len]
            .iter()
            .all(|b| *b == 0xAA),
        "expected overlay bytes to be unchanged"
    );

    // The certificate table must start at an 8-byte aligned offset.
    // Padding is added after the overlay to achieve this.
    let expected_sig_offset = (original_len + 7) & !7; // Round up to 8-byte boundary
    let cert_dir_offset = 0x80 + 24 + 96 + 32;
    let cert_rva = u32::from_le_bytes([
        out[cert_dir_offset],
        out[cert_dir_offset + 1],
        out[cert_dir_offset + 2],
        out[cert_dir_offset + 3],
    ]) as usize;
    assert_eq!(
        cert_rva, expected_sig_offset,
        "expected signature at 8-byte aligned offset after overlay"
    );
    assert_eq!(
        cert_rva % 8,
        0,
        "certificate table must start at 8-byte aligned offset"
    );
}

#[test]
fn parse_rejects_missing_mz() {
    let buf = vec![0u8; 128];
    let err = PeRaw::parse(&buf).unwrap_err();
    assert_eq!(format!("{err}"), "missing MZ signature");
}
