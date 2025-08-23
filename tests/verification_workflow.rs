//! Tests for the new verification workflow.

use yubikey_signer::VerifyWorkflow;

#[test]
fn verify_rejects_invalid_pe() {
    let wf = VerifyWorkflow::new();
    let bogus = b"NOT A PE"; // fails MZ check
    let report = wf.run(bogus).expect("verification should not error");
    assert!(!report.success());
    assert!(!report.hash_ok);
}

#[test]
fn verify_accepts_minimal_like_pe() {
    // Construct buffer meeting minimal size threshold (>=4096) with MZ header and fake PE signature
    let mut data = vec![0u8; 4096];
    data[0] = b'M';
    data[1] = b'Z';
    let pe_off: u32 = 0x200;
    data[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
    data[pe_off as usize..pe_off as usize + 4].copy_from_slice(b"PE\0\0");

    // Add fake certificate table entry (non-zero RVA/size to simulate signed PE)
    let cert_dir_offset = pe_off as usize + 24 + 96 + 32; // PE32 + entry index 4
    if cert_dir_offset + 8 <= data.len() {
        data[cert_dir_offset..cert_dir_offset + 4].copy_from_slice(&1024u32.to_le_bytes()); // fake RVA
        data[cert_dir_offset + 4..cert_dir_offset + 8].copy_from_slice(&256u32.to_le_bytes());
        // fake size
    }

    let wf = VerifyWorkflow::new();
    let report = wf
        .run(&data)
        .expect("verification should succeed structurally");
    // Since we have a certificate table but no actual crypto validation yet,
    // only hash_ok should be true (structural check passes)
    assert!(report.hash_ok);
    assert!(!report.signature_ok); // crypto validation not implemented yet
}
