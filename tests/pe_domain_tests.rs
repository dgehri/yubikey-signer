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
fn parse_rejects_missing_mz() {
    let buf = vec![0u8; 128];
    let err = PeRaw::parse(&buf).unwrap_err();
    assert_eq!(format!("{err}"), "missing MZ signature");
}
