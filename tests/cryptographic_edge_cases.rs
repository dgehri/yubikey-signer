//! Cryptographic edge case tests
//!
//! Tests for various cryptographic scenarios, certificate handling, and signing edge cases

use std::env;
use tempfile::NamedTempFile;
use yubikey_signer::types::{PivPin, PivSlot, TimestampUrl};
use yubikey_signer::yubikey_ops::YubiKeyOperations;
use yubikey_signer::{sign_pe_file, HashAlgorithm, SigningConfig};

/// Test suite for certificate handling edge cases
mod certificate_tests {
    use super::*;

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_certificate_validity_periods() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("Should create valid PIN");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test getting certificate from various slots
        let test_slots = vec![0x9a, 0x9c, 0x9d, 0x9e];

        for slot_id in test_slots {
            println!("Testing certificate in slot 0x{slot_id:02x}");
            let slot = PivSlot::new(slot_id).expect("Should create valid slot");

            match ops.get_certificate(slot) {
                Ok(cert) => {
                    // Extract validity information
                    println!("  Certificate found");

                    // Check certificate validity period
                    // Note: x509_cert crate provides validity info
                    let validity = &cert.tbs_certificate.validity;
                    println!("    Valid from: {:?}", validity.not_before);
                    println!("    Valid until: {:?}", validity.not_after);

                    // Check if certificate is currently valid
                    // (This is basic validation - real implementation would check current time)

                    // Check key usage extensions
                    if let Some(extensions) = &cert.tbs_certificate.extensions {
                        println!("    Extensions: {} found", extensions.len());

                        // Look for key usage and extended key usage
                        for ext in extensions {
                            println!("    Extension OID: {:?}", ext.extn_id);
                        }
                    }
                }
                Err(e) => {
                    println!("  No certificate in slot 0x{slot_id:02x}: {e}");
                }
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_certificate_algorithms() {
        let pin = PivPin::new(env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string()))
            .expect("Valid PIN");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test certificate algorithm compatibility
        let slots_to_test = vec![0x9a, 0x9c];

        for slot in slots_to_test {
            match ops.get_certificate(PivSlot::new(slot).expect("Valid slot")) {
                Ok(cert) => {
                    println!("Testing algorithms for slot 0x{slot:02x}");

                    // Check signature algorithm
                    let sig_alg = &cert.signature_algorithm;
                    println!("  Certificate signature algorithm: {:?}", sig_alg.oid);

                    // Check public key algorithm
                    let pub_key_alg = &cert.tbs_certificate.subject_public_key_info.algorithm;
                    println!("  Public key algorithm: {:?}", pub_key_alg.oid);

                    // Try to determine if this is RSA, ECDSA, etc.
                    // RSA: 1.2.840.113549.1.1.1
                    // ECDSA: 1.2.840.10045.2.1
                    let oid_str = format!("{}", pub_key_alg.oid);
                    match oid_str.as_str() {
                        "1.2.840.113549.1.1.1" => println!("    RSA public key detected"),
                        "1.2.840.10045.2.1" => println!("    ECDSA public key detected"),
                        _ => println!("    ❓ Unknown public key algorithm: {oid_str}"),
                    }

                    // Test signing with different hash sizes for this certificate
                    test_signing_with_various_hashes(&mut ops, slot);
                }
                Err(e) => {
                    println!("No certificate in slot 0x{slot:02x}: {e}");
                }
            }
        }
    }

    fn test_signing_with_various_hashes(ops: &mut YubiKeyOperations, slot: u8) {
        let test_hashes = vec![
            ("SHA256", vec![0x01; 32]),
            ("SHA384", vec![0x02; 48]),
            ("SHA512", vec![0x03; 64]),
            ("Empty", vec![]),
            ("Small (16 bytes)", vec![0x04; 16]),
            ("Large (100 bytes)", vec![0x05; 100]),
        ];

        for (name, hash) in test_hashes {
            match ops.sign_hash(&hash, PivSlot::new(slot).expect("Valid slot")) {
                Ok(signature) => {
                    println!(
                        "    {} hash: {} bytes -> {} byte signature",
                        name,
                        hash.len(),
                        signature.len()
                    );
                }
                Err(e) => {
                    println!("    {name} hash failed: {e}");
                }
            }
        }
    }
}

/// Test suite for algorithm edge cases
mod algorithm_tests {
    use super::*;

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_algorithm_fallback_behavior() {
        let pin = PivPin::new(env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string()))
            .expect("Valid PIN");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test the algorithm fallback chain directly
        // Our implementation tries: ECC-P384 -> ECC-P256 -> RSA-2048

        let test_data = vec![0x12; 32]; // 32-byte hash

        println!("Testing algorithm fallback chain:");

        // The perform_signing method should try different algorithms
        // We can't call it directly as it's private, but sign_hash will use it
        match ops.sign_hash(&test_data, PivSlot::new(0x9a).expect("Valid slot")) {
            Ok(signature) => {
                println!(
                    "Fallback chain succeeded: {} byte signature",
                    signature.len()
                );

                // Signature size can give us clues about which algorithm was used:
                // ECC-P384: ~96-104 bytes
                // ECC-P256: ~70-72 bytes
                // RSA-2048: 256 bytes
                match signature.len() {
                    96..=104 => println!("  Likely ECC-P384 signature"),
                    70..=72 => println!("  Likely ECC-P256 signature"),
                    256 => println!("  Likely RSA-2048 signature"),
                    _ => println!("  Unknown signature type: {} bytes", signature.len()),
                }
            }
            Err(e) => {
                println!("All algorithms in fallback chain failed: {e}");
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_hash_algorithm_combinations() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());

        // Test all hash algorithm configurations
        let hash_algorithms = vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ];

        let slots_to_test = vec![0x9a, 0x9c];

        for hash_alg in hash_algorithms {
            for slot in &slots_to_test {
                println!("Testing {:?} with slot 0x{:02x}", hash_alg, *slot);

                let config = SigningConfig {
                    pin: PivPin::new(&pin_str).expect("Valid PIN"),
                    piv_slot: PivSlot::new(*slot).expect("Valid slot"),
                    hash_algorithm: hash_alg,
                    timestamp_url: None,
                    embed_certificate: true,
                };

                // Create minimal test file
                let temp_file = create_test_pe_file();
                let mut temp_file_obj = NamedTempFile::new().unwrap();
                std::io::Write::write_all(&mut temp_file_obj, &temp_file).unwrap();

                let output_path = temp_file_obj.path().with_extension("signed.exe");

                let result =
                    tokio_test::block_on(sign_pe_file(temp_file_obj.path(), &output_path, config));

                match result {
                    Ok(_) => {
                        println!("  {:?} + slot 0x{:02x} succeeded", hash_alg, *slot);
                        let _ = std::fs::remove_file(&output_path);
                    }
                    Err(e) => {
                        println!("  {:?} + slot 0x{:02x} failed: {}", hash_alg, *slot, e);
                        // This is expected for many combinations
                    }
                }
            }
        }
    }
}

/// Test suite for signature format edge cases
mod signature_format_tests {
    use super::*;

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_signature_consistency() {
        let pin = PivPin::new(env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string()))
            .expect("Valid PIN");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test that the same input produces consistent signatures
        let test_hash = vec![0xAA; 32];
        let iterations = 5;

        let mut signatures = Vec::new();

        for i in 0..iterations {
            match ops.sign_hash(&test_hash, PivSlot::new(0x9a).expect("Valid slot")) {
                Ok(signature) => {
                    println!("Iteration {}: {} byte signature", i + 1, signature.len());
                    signatures.push(signature);
                }
                Err(e) => {
                    println!("Iteration {} failed: {}", i + 1, e);
                    break;
                }
            }
        }

        if signatures.len() >= 2 {
            // Check signature lengths are consistent
            let first_len = signatures[0].len();
            let all_same_length = signatures.iter().all(|s| s.len() == first_len);
            assert!(all_same_length, "Signature lengths should be consistent");
            println!(
                "All signatures have consistent length: {first_len} bytes"
            );

            // For RSA, signatures of the same data should be identical
            // For ECDSA, they will be different due to randomness
            let all_identical = signatures.iter().all(|s| s == &signatures[0]);
            if all_identical {
                println!("All signatures identical (likely RSA)");
            } else {
                println!("Signatures differ (likely ECDSA - expected)");
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_boundary_hash_sizes() {
        let pin = PivPin::new(env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string()))
            .expect("Valid PIN");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test boundary cases for hash sizes
        let boundary_cases = vec![
            ("0 bytes", vec![]),
            ("1 byte", vec![0x01]),
            ("15 bytes", vec![0x02; 15]),
            ("16 bytes", vec![0x03; 16]),
            ("31 bytes", vec![0x04; 31]),
            ("32 bytes (SHA256)", vec![0x05; 32]),
            ("33 bytes", vec![0x06; 33]),
            ("47 bytes", vec![0x07; 47]),
            ("48 bytes (SHA384)", vec![0x08; 48]),
            ("49 bytes", vec![0x09; 49]),
            ("63 bytes", vec![0x0A; 63]),
            ("64 bytes (SHA512)", vec![0x0B; 64]),
            ("65 bytes", vec![0x0C; 65]),
            ("255 bytes", vec![0x0D; 255]),
            ("256 bytes", vec![0x0E; 256]),
            ("257 bytes", vec![0x0F; 257]),
        ];

        for (name, hash) in boundary_cases {
            match ops.sign_hash(&hash, PivSlot::new(0x9a).expect("Valid slot")) {
                Ok(signature) => {
                    println!(
                        "{}: {} bytes -> {} byte signature",
                        name,
                        hash.len(),
                        signature.len()
                    );
                }
                Err(e) => {
                    println!("{name} failed: {e}");
                }
            }
        }
    }
}

/// Test suite for error handling edge cases
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_error_propagation() {
        // Test that errors propagate correctly through the system
        // We'll test with a valid PIN but expect authentication failure
        let invalid_config = SigningConfig {
            pin: PivPin::new("wrong_pin").unwrap_or_else(|_| PivPin::new("123456").unwrap()),
            piv_slot: PivSlot::new(0x9a).unwrap(), // Valid slot but wrong PIN will cause auth failure
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: None,
            embed_certificate: true,
        };

        let temp_file = NamedTempFile::new().unwrap();
        let output_path = temp_file.path().with_extension("signed.exe");

        let result =
            tokio_test::block_on(sign_pe_file(temp_file.path(), &output_path, invalid_config));

        assert!(result.is_err());
        let error = result.unwrap_err();

        // Error should be descriptive
        let error_msg = format!("{error}");
        println!("Error message: {error_msg}");

        // Should contain relevant context
        assert!(!error_msg.is_empty());
    }

    #[test]
    fn test_concurrent_yubikey_access() {
        // Test that concurrent access to YubiKey is handled gracefully
        use std::thread;

        let handles: Vec<_> = (0..5)
            .map(|i| {
                thread::spawn(move || {
                    println!("Thread {i} attempting YubiKey connection");

                    let result = YubiKeyOperations::connect();
                    match result {
                        Ok(_ops) => {
                            println!("Thread {i} connected");
                            true
                        }
                        Err(e) => {
                            println!("Thread {i} failed to connect: {e}");
                            false
                        }
                    }
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // At most one thread should succeed (or all should fail if no hardware)
        let success_count = results.iter().filter(|&&x| x).count();
        println!(
            "Concurrent access: {}/{} threads succeeded",
            success_count,
            results.len()
        );

        // This is hardware dependent, but shouldn't crash
        assert!(
            success_count <= 1,
            "At most one thread should connect to YubiKey"
        );
    }

    #[test]
    fn test_memory_safety_with_large_inputs() {
        // Test memory safety with large inputs
        let large_config = SigningConfig {
            pin: PivPin::new("A".repeat(1000)).unwrap_or_else(|_| PivPin::new("123456").unwrap()), // Very long PIN - will be rejected by PIN validation
            piv_slot: PivSlot::new(0x9a).unwrap(),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some(
                TimestampUrl::new(&("http://".to_string() + &"a".repeat(1000) + ".com"))
                    .unwrap_or_else(|_| {
                        TimestampUrl::new("http://timestamp.digicert.com").unwrap()
                    }),
            ), // Very long URL - will be rejected
            embed_certificate: true,
        };

        let temp_file = NamedTempFile::new().unwrap();
        let output_path = temp_file.path().with_extension("signed.exe");

        let result =
            tokio_test::block_on(sign_pe_file(temp_file.path(), &output_path, large_config));

        // Should fail gracefully, not crash
        assert!(result.is_err());
        println!("Large input test completed without crash");
    }
}

/// Test suite for real-world scenario edge cases
mod real_world_tests {
    use super::*;

    #[test]
    #[ignore = "Requires YubiKey hardware and network"]
    fn test_realistic_signing_workflow() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());

        // Test a complete realistic workflow
        let config = SigningConfig {
            pin: PivPin::new(&pin_str).expect("Valid PIN"),
            piv_slot: PivSlot::new(0x9a).expect("Valid slot"),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some(
                TimestampUrl::new("http://timestamp.digicert.com").expect("Valid URL"),
            ),
            embed_certificate: true,
        };

        // Create a more realistic PE file (larger)
        let realistic_pe = create_realistic_pe_file();
        let mut temp_file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp_file, &realistic_pe).unwrap();

        let output_path = temp_file.path().with_extension("signed.exe");

        let start_time = std::time::Instant::now();

        let result = tokio_test::block_on(sign_pe_file(temp_file.path(), &output_path, config));

        let duration = start_time.elapsed();
        println!("Realistic signing took: {duration:?}");

        match result {
            Ok(_) => {
                println!("Realistic workflow succeeded");

                // Check output file exists and has reasonable size
                if let Ok(metadata) = std::fs::metadata(&output_path) {
                    println!("  Output file size: {} bytes", metadata.len());
                    assert!(
                        metadata.len() > realistic_pe.len() as u64,
                        "Signed file should be larger"
                    );
                }

                // Clean up
                let _ = std::fs::remove_file(&output_path);
            }
            Err(e) => {
                println!("Realistic workflow failed: {e}");
                // This might fail due to network, certificate issues, etc.
                // But it should fail gracefully
            }
        }
    }

    fn create_realistic_pe_file() -> Vec<u8> {
        // Create a more realistic PE file (simplified)
        let mut pe = create_test_pe_file();

        // Add more sections and data to make it more realistic
        pe.extend_from_slice(&vec![0x90; 4096]); // Add some "code"
        pe.extend_from_slice(b"Hello World Program Data");
        pe.extend_from_slice(&vec![0x00; 1024]); // Add some "data"

        pe
    }
}

// Helper function to create a basic test PE file
fn create_test_pe_file() -> Vec<u8> {
    // Create minimal but valid PE structure
    let mut pe = Vec::new();

    // DOS Header (simplified)
    pe.extend_from_slice(b"MZ"); // e_magic
    pe.extend_from_slice(&[0x90, 0x00]); // e_cblp
    pe.extend_from_slice(&[0x03, 0x00]); // e_cp
    pe.extend_from_slice(&[0x00; 54]); // Rest of DOS header
    pe.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew

    // Pad to PE header
    while pe.len() < 0x80 {
        pe.push(0x00);
    }

    // PE Header
    pe.extend_from_slice(b"PE\x00\x00"); // PE signature
    pe.extend_from_slice(&[0x4c, 0x01]); // Machine (i386)
    pe.extend_from_slice(&[0x01, 0x00]); // NumberOfSections
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TimeDateStamp
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PointerToSymbolTable
    pe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NumberOfSymbols
    pe.extend_from_slice(&[0xE0, 0x00]); // SizeOfOptionalHeader
    pe.extend_from_slice(&[0x02, 0x01]); // Characteristics

    // Add minimal optional header
    pe.extend_from_slice(&vec![0x00; 0xE0]); // Optional header (zeros for simplicity)

    // Add minimal section header
    pe.extend_from_slice(&[0x00; 40]); // Section header (zeros for simplicity)

    pe
}

// Add tokio-test to dependencies for blocking async calls in tests
#[cfg(test)]
mod test_dependencies {
    // This would normally be in Cargo.toml:
    // [dev-dependencies]
    // tokio-test = "0.4"
}
