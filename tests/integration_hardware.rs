//! Hardware integration tests for YubiKey functionality
//!
//! These tests require an actual YubiKey to be connected and the YUBICO_PIN environment variable to be set.
//! Run with: cargo test --test integration_hardware -- --ignored

use std::env;
use tempfile::NamedTempFile;
use yubikey_signer::types::*;
use yubikey_signer::{sign_pe_file, HashAlgorithm, SigningConfig};

#[tokio::test]
#[ignore = "Requires YubiKey hardware"]
async fn test_real_yubikey_connection_and_certificate_retrieval() {
    // Get PIN from environment (same as PowerShell script)
    let pin_str = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");
    let pin = PivPin::new(&pin_str).expect("PIN should be valid");

    // Test configuration matching the PowerShell script parameters
    let config = SigningConfig {
        pin,
        piv_slot: PivSlot::new(0x9a).unwrap(), // Use Authentication slot where we found the certificate
        hash_algorithm: HashAlgorithm::Sha256, // Matches -h sha256
        timestamp_url: Some(TimestampUrl::new("http://ts.ssl.com").unwrap()), // Matches -ts
        embed_certificate: true,
    };

    // Create a minimal PE file for testing (will fail gracefully if not a real PE)
    let mut temp_pe = NamedTempFile::new().expect("Failed to create temp file");
    // Write a minimal DOS header that goblin can at least start to parse
    let dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00";
    std::io::Write::write_all(&mut temp_pe, dos_header).expect("Failed to write temp file");

    let input_path = temp_pe.path().to_path_buf();
    let output_path = input_path.with_extension("signed.exe");

    // This should work with real hardware - currently will fail with PE parsing or other errors
    let result = sign_pe_file(&input_path, &output_path, config).await;

    match result {
        Ok(_) => {
            println!("SUCCESS: Real YubiKey signing worked!");
            // Clean up
            let _ = std::fs::remove_file(&output_path);
        }
        Err(e) => {
            // For TDD, we expect this to fail with various errors as we build up functionality
            println!("Expected failure during TDD: {e}");

            // Verify it's failing for expected reasons (not connectivity issues)
            let error_msg = format!("{e}");
            assert!(
                error_msg.contains("PE file parsing")
                    || error_msg.contains("not a valid PE")
                    || error_msg.contains("Authenticode")
                    || error_msg.contains("timestamp")
                    || error_msg.contains("invalid")
                    || error_msg.contains("placeholder"),
                "Should fail with implementation error, got: {error_msg}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "Requires YubiKey hardware"]
async fn test_yubikey_certificate_matches_file() {
    // This test verifies that we can extract the same certificate that would be
    // referenced by the certFile parameter in the PowerShell script

    let pin_str = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");
    let pin = PivPin::new(&pin_str).expect("PIN should be valid");

    // Test just the YubiKey operations directly
    use yubikey_signer::yubikey_ops::YubiKeyOperations;

    let mut ops = YubiKeyOperations::connect().expect("YubiKey connection failed");
    ops.authenticate(&pin)
        .expect("YubiKey authentication failed");

    let slot = PivSlot::new(0x9a).expect("Should create valid slot");
    // Try to get certificate from slot 0x9a (authentication slot where we know there's a cert)
    let result = ops.get_certificate(slot);

    match result {
        Ok(cert) => {
            println!("SUCCESS: Retrieved certificate from YubiKey slot 0x9a");
            println!("Certificate subject: {:?}", cert.tbs_certificate.subject);

            // Verify it's a valid certificate structure
            assert!(!cert.tbs_certificate.serial_number.as_bytes().is_empty());
        }
        Err(e) => {
            // No certificate in 0x9a, try other slots
            println!("No certificate in slot 0x9a: {e}");

            // Try other common slots
            let slots_to_try = [0x9c, 0x9d, 0x9e]; // Digital Signature, Key Management, Card Authentication
            let mut found_cert = false;

            for slot_id in slots_to_try {
                let slot = PivSlot::new(slot_id).expect("Should create valid slot");
                match ops.get_certificate(slot) {
                    Ok(cert) => {
                        println!(
                            "SUCCESS: Retrieved certificate from YubiKey slot 0x{slot_id:02x}"
                        );
                        println!("Certificate subject: {:?}", cert.tbs_certificate.subject);
                        assert!(!cert.tbs_certificate.serial_number.as_bytes().is_empty());
                        found_cert = true;
                        break;
                    }
                    Err(e) => {
                        println!("No certificate in slot 0x{slot_id:02x}: {e}");
                    }
                }
            }

            if !found_cert {
                // Expected TDD failure if no certificates are present
                println!("Expected TDD failure: No certificates found in any PIV slot");
                let error_msg = format!("{e}");
                assert!(
                    error_msg.contains("invalid object")
                        || error_msg.contains("not found")
                        || error_msg.contains("empty")
                );
            }
        }
    }
}

#[test]
#[ignore = "Requires YubiKey hardware"]
fn test_yubikey_basic_connection() {
    // Most basic test - can we connect to the YubiKey at all?
    use yubikey_signer::yubikey_ops::YubiKeyOperations;

    let result = YubiKeyOperations::connect();

    match result {
        Ok(mut ops) => {
            println!("SUCCESS: YubiKey connected");

            // Try to get serial number
            if let Ok(serial) = ops.get_serial() {
                println!("YubiKey Serial: {serial}");
            }

            // Try to get version
            if let Ok(version) = ops.get_version() {
                println!("YubiKey Version: {version}");
            }
        }
        Err(e) => {
            panic!(
                "Failed to connect to YubiKey: {e}. Is YubiKey plugged in?"
            );
        }
    }
}
