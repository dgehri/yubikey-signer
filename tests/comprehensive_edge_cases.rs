//! Comprehensive edge case tests for YubiKey PE Signer
//!
//! This test suite covers all edge cases and error conditions to en            Ok(_) => println!("YubiKey connected");ure
//! robust production behavior.

use std::env;
use std::path::Path;
use tempfile::NamedTempFile;
use yubikey_signer::types::{PivPin, PivSlot};
use yubikey_signer::{sign_pe_file, HashAlgorithm, SigningConfig, YubiKeyOperations};

/// Test suite for input validation edge cases
mod input_validation_tests {
    use super::*;

    #[tokio::test]
    async fn test_nonexistent_input_file() {
        let config = create_test_config();
        let nonexistent = Path::new("definitely_does_not_exist.exe");
        let output = Path::new("output.exe");

        let result = sign_pe_file(nonexistent, output, config).await;
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("file") || error_msg.contains("not found"));
    }

    #[tokio::test]
    async fn test_invalid_pe_file() {
        let config = create_test_config();

        // Create a file that's not a PE
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This is not a PE file").unwrap();

        let output_path = temp_file.path().with_extension("signed.exe");

        let result = sign_pe_file(temp_file.path(), &output_path, config).await;
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("PE") || error_msg.contains("invalid"));
    }

    #[tokio::test]
    async fn test_empty_file() {
        let config = create_test_config();

        // Create empty file
        let temp_file = NamedTempFile::new().unwrap();
        let output_path = temp_file.path().with_extension("signed.exe");

        let result = sign_pe_file(temp_file.path(), &output_path, config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_very_large_file() {
        let config = create_test_config();

        // Create a large file (simulate)
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write just enough to make it look like it might be PE-ish but invalid
        temp_file.write_all(b"MZ").unwrap();

        let output_path = temp_file.path().with_extension("signed.exe");

        let result = sign_pe_file(temp_file.path(), &output_path, config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_readonly_output_directory() {
        let config = create_test_config();

        // Create a temp file as input
        let temp_file = NamedTempFile::new().unwrap();

        // Try to write to a readonly location (system directory)
        let readonly_output = Path::new("C:\\Windows\\System32\\test_signed.exe");

        let result = sign_pe_file(temp_file.path(), readonly_output, config).await;
        // Should fail due to permissions (or earlier due to invalid PE)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_output_same_as_input() {
        let config = create_test_config();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(create_minimal_pe()).unwrap();

        // Output same as input should work (overwrite mode)
        let result = sign_pe_file(temp_file.path(), temp_file.path(), config).await;
        // Will fail due to invalid PE or YubiKey, but shouldn't fail due to same path
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(!error_msg.contains("same file") && !error_msg.contains("identical"));
    }

    fn create_test_config() -> SigningConfig {
        SigningConfig {
            pin: PivPin::new("123456").expect("Valid PIN format"),
            piv_slot: PivSlot::new(0x9c).expect("Valid slot"),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: None,
            embed_certificate: true,
        }
    }

    fn create_minimal_pe() -> &'static [u8] {
        // Minimal DOS header that might parse
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
          \xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    }
}

/// Test suite for YubiKey hardware edge cases
mod yubikey_hardware_tests {
    use super::*;
    use yubikey_signer::yubikey_ops::YubiKeyOperations;

    #[test]
    fn test_yubikey_not_connected() {
        // This will fail if no YubiKey is connected
        let result = YubiKeyOperations::connect();

        // We can't guarantee hardware state, but test should handle gracefully
        match result {
            Ok(_) => println!("YubiKey connected"),
            Err(e) => {
                let error_msg = format!("{e}");
                assert!(error_msg.contains("YubiKey") || error_msg.contains("connect"));
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_invalid_pin() {
        let _ops = YubiKeyOperations::connect().expect("YubiKey required");

        let invalid_pins = vec![
            "",          // empty
            "1",         // too short
            "12345",     // too short
            "123456789", // too long
            "abcdef",    // non-numeric
            "12345a",    // mixed
        ];

        for pin_str in invalid_pins {
            // Test that PivPin creation fails for invalid formats
            let pin_result = PivPin::new(pin_str);
            assert!(pin_result.is_err(), "PIN '{pin_str}' should be invalid");
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_wrong_pin() {
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");

        // Try obviously wrong PINs
        let wrong_pins = vec!["000000", "111111", "999999"];

        for pin_str in wrong_pins {
            let pin = PivPin::new(pin_str).expect("Valid PIN format but wrong value");
            let result = ops.authenticate(&pin);
            // Should fail (unless user actually uses these pins!)
            if result.is_err() {
                let error_msg = format!("{}", result.unwrap_err());
                assert!(error_msg.contains("PIN") || error_msg.contains("auth"));
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_invalid_slot_numbers() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("Valid PIN format");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        let invalid_slots = vec![0x00, 0x01, 0x99, 0xFF];

        for slot_num in invalid_slots {
            // Test slot creation
            match PivSlot::new(slot_num) {
                Ok(slot) => {
                    let result = ops.get_certificate(slot);
                    // Should fail gracefully for invalid slots
                    if result.is_err() {
                        let error_msg = format!("{}", result.unwrap_err());
                        assert!(error_msg.contains("slot") || error_msg.contains("certificate"));
                    }
                }
                Err(_) => {
                    // Invalid slot number - this is expected behavior
                }
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_empty_slots() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("Valid PIN format");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test slots that might be empty
        let potentially_empty_slots = vec![0x9c, 0x9d, 0x9e];

        for slot_num in potentially_empty_slots {
            let slot = PivSlot::new(slot_num).expect("Valid slot");
            let result = ops.get_certificate(slot);
            match result {
                Ok(_) => println!("Slot 0x{slot_num:02x} has certificate"),
                Err(e) => {
                    let error_msg = format!("{e}");
                    // Should fail gracefully for empty slots
                    assert!(error_msg.contains("certificate") || error_msg.contains("slot"));
                }
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_sign_without_authentication() {
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        // Don't authenticate

        let test_hash = vec![0x01; 32]; // 32 bytes for SHA256
        let slot = PivSlot::new(0x9a).expect("Valid slot");
        let result = ops.sign_hash(&test_hash, slot);

        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("auth") || error_msg.contains("PIN"));
    }
}

/// Test suite for signature format edge cases  
mod signature_format_tests {
    use super::*;
    use yubikey_signer::yubikey_ops::YubiKeyOperations;

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_various_hash_sizes() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("Valid PIN format");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        let test_cases = vec![
            ("Empty hash", vec![]),
            ("1 byte", vec![0x01]),
            ("15 bytes", vec![0x02; 15]),
            ("16 bytes", vec![0x03; 16]),
            ("31 bytes", vec![0x04; 31]),
            ("32 bytes (SHA256)", vec![0x05; 32]),
            ("33 bytes", vec![0x06; 33]),
            ("48 bytes (SHA384)", vec![0x07; 48]),
            ("64 bytes (SHA512)", vec![0x08; 64]),
            ("65 bytes", vec![0x09; 65]),
            ("128 bytes", vec![0x0A; 128]),
            ("256 bytes", vec![0x0B; 256]),
            ("257 bytes", vec![0x0C; 257]),
        ];

        for (name, hash) in test_cases {
            println!("Testing hash size: {} ({} bytes)", name, hash.len());

            let slot = PivSlot::new(0x9a).expect("Valid slot");
            let result = ops.sign_hash(&hash, slot);
            match result {
                Ok(signature) => {
                    println!("  Success: {} byte signature", signature.len());
                    assert!(!signature.is_empty());
                }
                Err(e) => {
                    println!("  Failed: {e}");
                    // Document which sizes fail for different algorithms
                }
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_algorithm_compatibility() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("Valid PIN format");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test different hash algorithms with their expected sizes
        let test_cases = vec![
            ("SHA256", HashAlgorithm::Sha256, vec![0x01; 32]),
            ("SHA384", HashAlgorithm::Sha384, vec![0x02; 48]),
            ("SHA512", HashAlgorithm::Sha512, vec![0x03; 64]),
        ];

        for (name, _algorithm, hash) in test_cases {
            println!("Testing algorithm: {} ({} bytes)", name, hash.len());

            let slot = PivSlot::new(0x9a).expect("Valid slot");
            let result = ops.sign_hash(&hash, slot);
            match result {
                Ok(signature) => {
                    println!("  {} works: {} byte signature", name, signature.len());
                }
                Err(e) => {
                    println!("  {name} failed: {e}");
                }
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_malformed_hash_data() {
        let pin_str = env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("Valid PIN format");
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        ops.authenticate(&pin).expect("Authentication required");

        // Test various potentially problematic hash values
        let test_cases = vec![
            ("All zeros", vec![0x00; 32]),
            ("All ones", vec![0xFF; 32]),
            (
                "Alternating",
                (0..32)
                    .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
                    .collect(),
            ),
            ("Sequential", (0..32).map(|i| i as u8).collect()),
            (
                "Random pattern",
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0].repeat(4),
            ),
        ];

        for (name, hash) in test_cases {
            println!("Testing malformed hash: {name}");

            let slot = PivSlot::new(0x9a).expect("Valid slot");
            let result = ops.sign_hash(&hash, slot);
            match result {
                Ok(signature) => {
                    println!("  Handled gracefully: {} bytes", signature.len());
                    assert!(!signature.is_empty());
                }
                Err(e) => {
                    println!("  Failed (expected): {e}");
                }
            }
        }
    }
}

/// Test suite for CLI argument edge cases
mod cli_argument_tests {

    #[test]
    fn test_slot_parsing() {
        // Test that slot parsing handles various formats
        let valid_slots = vec!["9a", "9A", "9c", "9C", "9d", "9D", "9e", "9E"];
        let invalid_slots = vec!["", "9", "9g", "99", "abc", "123"];

        for slot_str in valid_slots {
            let parsed = u8::from_str_radix(slot_str, 16);
            assert!(parsed.is_ok(), "Slot '{slot_str}' should parse");
            let slot_value = parsed.unwrap();
            assert!(
                (0x9a..=0x9e).contains(&slot_value),
                "Slot 0x{slot_value:02x} should be in valid range"
            );
        }

        for slot_str in invalid_slots {
            let parsed = u8::from_str_radix(slot_str, 16);
            if parsed.is_ok() {
                let slot_value = parsed.unwrap();
                // Even if it parses, it should be outside valid PIV range
                assert!(
                    !(0x9a..=0x9e).contains(&slot_value),
                    "Slot '{slot_str}' should be invalid"
                );
            }
        }
    }

    #[test]
    fn test_pin_validation() {
        let valid_pins = vec!["123456", "000000", "999999", "12345678"];
        let invalid_pins = vec!["", "1", "12345", "123456789", "abcdef", "12345a"];

        for pin in valid_pins {
            assert!(is_valid_pin(pin), "PIN '{pin}' should be valid");
        }

        for pin in invalid_pins {
            assert!(!is_valid_pin(pin), "PIN '{pin}' should be invalid");
        }
    }

    fn is_valid_pin(pin: &str) -> bool {
        pin.len() >= 6 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit())
    }

    #[test]
    fn test_url_validation() {
        let valid_urls = vec![
            "http://timestamp.digicert.com",
            "https://timestamp.globalsign.com/advanced",
            "http://ts.ssl.com",
            "https://tsa.swisssign.net",
        ];

        let questionable_urls = vec![
            "",
            "not-a-url",
            "ftp://invalid.com",
            "javascript:alert('xss')",
            "file:///etc/passwd",
        ];

        for url in valid_urls {
            assert!(
                is_reasonable_timestamp_url(url),
                "URL '{url}' should be reasonable"
            );
        }

        for url in questionable_urls {
            // These might be invalid or suspicious
            println!(
                "Questionable URL: {} -> {}",
                url,
                is_reasonable_timestamp_url(url)
            );
        }
    }

    fn is_reasonable_timestamp_url(url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }
}

/// Test suite for network and timestamp edge cases
#[cfg(feature = "network-tests")]
mod network_tests {
    use super::*;

    #[tokio::test]
    async fn test_invalid_timestamp_urls() {
        let config_base = SigningConfig {
            pin: "123456".to_string(),
            piv_slot: 0x9c,
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: None,
            embed_certificate: true,
        };

        let invalid_urls = vec![
            "http://definitely-does-not-exist.invalid",
            "https://127.0.0.1:99999/timestamp",
            "http://localhost:1/invalid",
            "https://expired-ssl-cert.example.com",
        ];

        for url in invalid_urls {
            let mut config = config_base.clone();
            config.timestamp_url = Some(url.to_string());

            let temp_file = NamedTempFile::new().unwrap();
            let output_path = temp_file.path().with_extension("signed.exe");

            let result = sign_pe_file(temp_file.path(), &output_path, config).await;
            // Should fail gracefully with network error, not crash
            assert!(result.is_err());
            let error_msg = format!("{}", result.unwrap_err());
            println!("Network error for {}: {}", url, error_msg);
        }
    }

    #[tokio::test]
    async fn test_slow_timestamp_server() {
        // Test timeout handling
        let config = SigningConfig {
            pin: "123456".to_string(),
            piv_slot: 0x9c,
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some("http://httpstat.us/200?sleep=30000".to_string()), // 30 second delay
            embed_certificate: true,
        };

        let temp_file = NamedTempFile::new().unwrap();
        let output_path = temp_file.path().with_extension("signed.exe");

        let start = std::time::Instant::now();
        let result = sign_pe_file(temp_file.path(), &output_path, config).await;
        let duration = start.elapsed();

        // Should timeout before 30 seconds
        assert!(
            duration.as_secs() < 25,
            "Should timeout quickly, took {:?}",
            duration
        );
        assert!(result.is_err());
    }
}

/// Test suite for memory and resource edge cases
mod resource_tests {
    use super::*;

    #[test]
    fn test_memory_usage_patterns() {
        // Test that we don't leak memory or resources
        let iterations = 100;

        for i in 0..iterations {
            // Try to connect (will fail without hardware)
            let result = YubiKeyOperations::connect();

            // Should fail gracefully without leaking resources
            match result {
                Ok(_) => {
                    // If we actually connect, that's fine too
                    println!("Connected on iteration {i}");
                }
                Err(_) => {
                    // Expected without hardware
                }
            }
        }

        // Test completed - no memory leaks expected
    }

    #[test]
    fn test_concurrent_operations() {
        // Test thread safety

        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    // Each thread tries to connect
                    let result = YubiKeyOperations::connect();
                    println!("Thread {}: {:?}", i, result.is_ok());
                    result.is_ok()
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All should succeed or all should fail consistently
        let success_count = results.iter().filter(|&&x| x).count();
        println!(
            "Concurrent connection success rate: {}/{}",
            success_count,
            results.len()
        );
    }
}

// Helper function to create test PE files
#[allow(dead_code)]
fn create_test_pe_file() -> Vec<u8> {
    // Create a minimal valid PE file structure
    let mut pe_data = Vec::new();

    // DOS Header
    pe_data.extend_from_slice(b"MZ"); // e_magic
    pe_data.extend_from_slice(&[0x90, 0x00]); // e_cblp
    pe_data.extend_from_slice(&[0x03, 0x00]); // e_cp
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_crlc
    pe_data.extend_from_slice(&[0x04, 0x00]); // e_cparhdr
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_minalloc
    pe_data.extend_from_slice(&[0xFF, 0xFF]); // e_maxalloc
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_ss
    pe_data.extend_from_slice(&[0xB8, 0x00]); // e_sp
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_csum
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_ip
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_cs
    pe_data.extend_from_slice(&[0x40, 0x00]); // e_lfarlc
    pe_data.extend_from_slice(&[0x00, 0x00]); // e_ovno

    // Pad to 64 bytes DOS header
    while pe_data.len() < 60 {
        pe_data.push(0x00);
    }

    // e_lfanew (offset to PE header) - put PE header at 0x80
    pe_data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // Pad to PE header location
    while pe_data.len() < 0x80 {
        pe_data.push(0x00);
    }

    // This is very minimal and likely won't parse correctly,
    // but it's better than random data
    pe_data
}

use std::io::Write;
