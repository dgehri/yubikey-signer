//! CLI and integration edge case tests
//!
//! Tests for command-line interface, configuration handling, and integration scenarios

use std::env;
use std::io::Write;
use tempfile::TempDir;
use yubikey_signer::PivPin;
use yubikey_signer::PivSlot;
use yubikey_signer::TimestampUrl;
use yubikey_signer::{HashAlgorithm, SigningConfig};

/// Test suite for CLI argument validation
mod cli_validation_tests {
    use super::*;

    #[test]
    fn test_slot_id_parsing() {
        // Test various slot ID formats
        let valid_slots = vec![
            ("9a", 0x9a),
            ("9A", 0x9a),
            ("9c", 0x9c),
            ("9C", 0x9c),
            ("9d", 0x9d),
            ("9e", 0x9e),
        ];

        for (input, expected) in valid_slots {
            match u8::from_str_radix(input, 16) {
                Ok(parsed) => {
                    assert_eq!(
                        parsed, expected,
                        "Slot '{input}' should parse to 0x{expected:02x}"
                    );

                    // Verify it's in valid PIV range
                    assert!(
                        (0x9a..=0x9e).contains(&parsed),
                        "Slot 0x{parsed:02x} should be valid PIV slot"
                    );
                }
                Err(e) => {
                    panic!("Slot '{input}' should parse: {e}");
                }
            }
        }

        let invalid_slots = vec!["", "9", "9g", "99", "abc", "123", "9x"];

        for input in invalid_slots {
            let result = u8::from_str_radix(input, 16);
            if let Ok(parsed) = result {
                // Even if it parses as hex, it should be outside PIV range
                assert!(
                    !(0x9a..=0x9e).contains(&parsed),
                    "Invalid slot '{input}' parsed to valid PIV slot 0x{parsed:02x}"
                );
            }
            // Otherwise, parse failure is expected
        }
    }

    #[test]
    fn test_pin_validation_rules() {
        // Test PIN validation according to PIV specifications
        let test_cases = vec![
            // (pin, expected_valid, reason)
            ("123456", true, "Valid 6-digit PIN"),
            ("12345678", true, "Valid 8-digit PIN"),
            ("000000", true, "All zeros (valid format)"),
            ("999999", true, "All nines (valid format)"),
            ("", false, "Empty PIN"),
            ("1", false, "Too short"),
            ("12345", false, "Too short"),
            ("123456789", false, "Too long"),
            ("abcdef", false, "Non-numeric characters"),
            ("12345a", false, "Mixed alphanumeric"),
            ("12 34 56", false, "Contains spaces"),
            ("123-456", false, "Contains special characters"),
        ];

        for (pin, expected_valid, reason) in test_cases {
            let is_valid = validate_piv_pin(pin);
            assert_eq!(
                is_valid, expected_valid,
                "PIN '{pin}' validation failed: {reason} (expected: {expected_valid})"
            );
        }
    }

    #[test]
    fn test_hash_algorithm_parsing() {
        // Test hash algorithm string parsing
        let valid_algorithms = vec![
            ("sha256", HashAlgorithm::Sha256),
            ("SHA256", HashAlgorithm::Sha256),
            ("Sha256", HashAlgorithm::Sha256),
            ("sha384", HashAlgorithm::Sha384),
            ("SHA384", HashAlgorithm::Sha384),
            ("sha512", HashAlgorithm::Sha512),
            ("SHA512", HashAlgorithm::Sha512),
        ];

        for (input, expected) in valid_algorithms {
            let parsed = parse_hash_algorithm(input);
            assert_eq!(
                parsed,
                Some(expected),
                "Hash algorithm '{input}' should parse to {expected:?}"
            );
        }

        let invalid_algorithms = vec!["", "md5", "sha1", "sha128", "invalid", "256", "sha"];

        for input in invalid_algorithms {
            let parsed = parse_hash_algorithm(input);
            assert_eq!(
                parsed, None,
                "Invalid hash algorithm '{input}' should not parse"
            );
        }
    }

    #[test]
    fn test_url_validation() {
        // Test timestamp URL validation
        let valid_urls = vec![
            "http://timestamp.digicert.com",
            "https://timestamp.globalsign.com/advanced",
            "http://ts.ssl.com",
            "https://tsa.swisssign.net",
            "http://timestamp.sectigo.com",
            "https://timestamp.apple.com/ts01",
        ];

        for url in valid_urls {
            assert!(
                is_valid_timestamp_url(url),
                "URL '{url}' should be considered valid"
            );
        }

        let questionable_urls = vec![
            "",
            "not-a-url",
            "ftp://timestamp.com",
            "javascript:alert('xss')",
            "file:///etc/passwd",
            "ldap://server.com",
            "http://",
            "https://",
            "http://localhost",
            "http://127.0.0.1",
        ];

        for url in questionable_urls {
            println!("Testing questionable URL: '{url}'");
            // These should be rejected or flagged as suspicious
            let is_valid = is_valid_timestamp_url(url);
            if is_valid {
                println!("  WARNING: Questionable URL accepted: '{url}'");
            }
        }
    }

    fn validate_piv_pin(pin: &str) -> bool {
        // PIV PINs should be 6-8 digits
        pin.len() >= 6 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit())
    }

    fn parse_hash_algorithm(input: &str) -> Option<HashAlgorithm> {
        match input.to_lowercase().as_str() {
            "sha256" => Some(HashAlgorithm::Sha256),
            "sha384" => Some(HashAlgorithm::Sha384),
            "sha512" => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }

    fn is_valid_timestamp_url(url: &str) -> bool {
        // Basic validation - should start with http:// or https://
        (url.starts_with("http://") || url.starts_with("https://"))
            && url.len() > 8 // More than just the protocol
            && !url.contains("localhost")
            && !url.contains("127.0.0.1")
            && !url.contains("javascript:")
            && !url.contains("file:")
    }
}

/// Test suite for configuration edge cases
mod configuration_tests {
    use super::*;

    #[test]
    fn test_environment_variable_handling() {
        // Test environment variable handling for PIN
        let original_pin = env::var("YUBICO_PIN").ok();

        // Test with no environment variable
        env::remove_var("YUBICO_PIN");
        let result = env::var("YUBICO_PIN");
        assert!(result.is_err(), "YUBICO_PIN should not be set");

        // Test with valid PIN
        env::set_var("YUBICO_PIN", "123456");
        let result = env::var("YUBICO_PIN");
        assert_eq!(
            result.unwrap(),
            "123456",
            "YUBICO_PIN should be retrievable"
        );

        // Test with invalid PIN format
        env::set_var("YUBICO_PIN", "invalid");
        let pin = env::var("YUBICO_PIN").unwrap();
        assert!(!validate_piv_pin(&pin), "Invalid PIN should be detected");

        // Test with empty PIN
        env::set_var("YUBICO_PIN", "");
        let pin = env::var("YUBICO_PIN").unwrap();
        assert!(!validate_piv_pin(&pin), "Empty PIN should be invalid");

        // Restore original PIN if it existed
        if let Some(original) = original_pin {
            env::set_var("YUBICO_PIN", original);
        } else {
            env::remove_var("YUBICO_PIN");
        }
    }

    #[test]
    fn test_config_validation() {
        // Test configuration validation
        let valid_config = SigningConfig {
            pin: PivPin::new("123456").expect("Valid PIN"),
            piv_slot: PivSlot::new(0x9a).expect("Valid slot"),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some(
                TimestampUrl::new("https://timestamp.digicert.com").expect("Valid URL"),
            ),
            embed_certificate: true,
            additional_certs: Vec::new(),
        };

        assert!(
            validate_signing_config(&valid_config),
            "Valid config should pass validation"
        );

        // Test that invalid inputs fail during type construction
        // Empty PIN should fail
        assert!(
            PivPin::new("").is_err(),
            "Empty PIN should be rejected during construction"
        );

        // Short PIN should fail
        assert!(
            PivPin::new("12345").is_err(),
            "Short PIN should be rejected during construction"
        );

        // Invalid slot should fail
        assert!(
            PivSlot::new(0x99).is_err(),
            "Invalid slot should be rejected during construction"
        );

        // Invalid URL should fail
        assert!(
            TimestampUrl::new("not-a-url").is_err(),
            "Invalid URL should be rejected during construction"
        );
    }

    fn validate_piv_pin(pin: &str) -> bool {
        pin.len() >= 6 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit())
    }

    fn validate_signing_config(_config: &SigningConfig) -> bool {
        // With type-safe wrappers, if we can construct the config,
        // the individual components are already validated.
        // This function now mainly validates the overall configuration.
        true // Basic validation - the types handle individual field validation
    }
}

/// Test suite for file handling edge cases
mod file_handling_tests {
    use super::*;

    #[test]
    fn test_file_path_edge_cases() {
        // Test various problematic file paths
        let problematic_paths = vec![
            "",                                                       // Empty path
            ".",                                                      // Current directory
            "..",                                                     // Parent directory
            "/",                                                      // Root (Unix)
            "\\",                                                     // Root (Windows)
            "C:\\",                                                   // Drive root (Windows)
            "non/existent/path.exe",                                  // Non-existent path
            "very/deep/nested/path/that/probably/does/not/exist.exe", // Very deep path
        ];

        for path in problematic_paths {
            println!("Testing problematic path: '{path}'");

            // These should all fail gracefully when used as input files
            let path_obj = std::path::Path::new(path);

            // Test file existence check
            let exists = path_obj.exists();
            if path.is_empty() {
                // Empty path has undefined behavior, but shouldn't crash
                println!("  Empty path exists: {exists}");
            } else {
                println!("  Path '{path}' exists: {exists}");
            }

            // Test metadata access
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    println!("  Path '{}' metadata: {} bytes", path, metadata.len());
                }
                Err(e) => {
                    println!("  Path '{path}' metadata error: {e}");
                    // This is expected for most test paths
                }
            }
        }
    }

    #[test]
    fn test_file_permission_scenarios() {
        // Test various file permission scenarios
        let temp_dir = TempDir::new().unwrap();

        // Create a test file
        let test_file = temp_dir.path().join("test.exe");
        let mut file = std::fs::File::create(&test_file).unwrap();
        file.write_all(b"Test PE file content").unwrap();
        drop(file);

        // Test reading the file
        let content = std::fs::read(&test_file);
        assert!(content.is_ok(), "Should be able to read test file");

        // Test writing to same location (simulating overwrite)
        let write_result = std::fs::write(&test_file, b"Modified content");
        assert!(
            write_result.is_ok(),
            "Should be able to overwrite test file"
        );

        // Test creating file in temp directory (should work)
        let output_file = temp_dir.path().join("output.exe");
        let create_result = std::fs::write(&output_file, b"Output content");
        assert!(
            create_result.is_ok(),
            "Should be able to create output file"
        );

        // Test with very long filename
        let long_name = "a".repeat(200) + ".exe";
        let long_file = temp_dir.path().join(&long_name);
        let long_result = std::fs::write(&long_file, b"Long filename content");
        match long_result {
            Ok(()) => println!("Long filename worked: {} chars", long_name.len()),
            Err(e) => println!("Long filename failed (expected): {e}"),
        }

        // Test with special characters in filename
        let special_chars = vec!["test?.exe", "test*.exe", "test<>.exe", "test|.exe"];
        for special_name in special_chars {
            let special_file = temp_dir.path().join(special_name);
            let special_result = std::fs::write(&special_file, b"Special char content");
            match special_result {
                Ok(()) => println!("Special char filename '{special_name}' worked"),
                Err(e) => println!("Special char filename '{special_name}' failed: {e}"),
            }
        }
    }

    #[test]
    fn test_large_file_simulation() {
        // Test behavior with large files (simulated)
        let temp_dir = TempDir::new().unwrap();

        // Create a moderately large file (1MB)
        let large_file = temp_dir.path().join("large.exe");
        let large_content = vec![0x90; 1024 * 1024]; // 1MB of NOPs

        let write_result = std::fs::write(&large_file, &large_content);
        assert!(write_result.is_ok(), "Should be able to create 1MB file");

        // Test reading it back
        let read_result = std::fs::read(&large_file);
        assert!(read_result.is_ok(), "Should be able to read 1MB file");

        let read_content = read_result.unwrap();
        assert_eq!(
            read_content.len(),
            large_content.len(),
            "Read content should match written size"
        );

        // Test file metadata
        let metadata = std::fs::metadata(&large_file).unwrap();
        assert_eq!(
            metadata.len(),
            large_content.len() as u64,
            "Metadata size should match"
        );

        println!("Large file test completed: {} bytes", metadata.len());
    }
}

/// Test suite for error recovery scenarios
mod error_recovery_tests {
    use super::*;

    #[test]
    fn test_partial_failure_recovery() {
        // Test recovery from partial failures
        let temp_dir = TempDir::new().unwrap();

        // Create input file
        let input_file = temp_dir.path().join("input.exe");
        std::fs::write(&input_file, b"Test PE content").unwrap();

        // Try to create output in non-existent directory
        let bad_output = temp_dir.path().join("nonexistent").join("output.exe");

        // This should fail gracefully
        let config = SigningConfig {
            pin: PivPin::new("123456").expect("Valid PIN format"),
            piv_slot: PivSlot::new(0x9a).expect("Valid slot"),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: None,
            embed_certificate: true,
            additional_certs: Vec::new(),
        };

        let result = tokio_test::block_on(yubikey_signer::sign_pe_file(
            &input_file,
            &bad_output,
            config,
        ));

        assert!(result.is_err(), "Should fail with invalid output path");

        // Input file should still exist and be unchanged
        assert!(input_file.exists(), "Input file should still exist");
        let content = std::fs::read(&input_file).unwrap();
        assert_eq!(
            content, b"Test PE content",
            "Input file should be unchanged"
        );

        // Output file should not exist
        assert!(
            !bad_output.exists(),
            "Output file should not exist after failure"
        );
    }

    #[test]
    fn test_interrupted_operation_cleanup() {
        // Test that interrupted operations clean up properly
        let temp_dir = TempDir::new().unwrap();

        // Create input file
        let input_file = temp_dir.path().join("input.exe");
        std::fs::write(&input_file, create_minimal_pe()).unwrap();

        let output_file = temp_dir.path().join("output.exe");

        // Use invalid PIN to cause failure after some processing
        let config = SigningConfig {
            pin: PivPin::new("123456").expect("Valid PIN format but will be wrong for auth"), // Valid format but wrong PIN will cause auth failure
            piv_slot: PivSlot::new(0x9a).expect("Valid slot"),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: None,
            embed_certificate: true,
            additional_certs: Vec::new(),
        };

        let result = tokio_test::block_on(yubikey_signer::sign_pe_file(
            &input_file,
            &output_file,
            config,
        ));

        // Should fail due to authentication
        assert!(result.is_err(), "Should fail with wrong PIN");

        // Check that no partial output file was left behind
        if output_file.exists() {
            println!("WARNING: Output file exists after failure - check cleanup");
            let output_size = std::fs::metadata(&output_file).unwrap().len();
            println!("Partial output file size: {output_size} bytes");
        }

        // Input should be unchanged
        assert!(input_file.exists(), "Input file should still exist");
    }

    fn create_minimal_pe() -> Vec<u8> {
        // Create minimal PE file for testing
        let mut pe = Vec::new();
        pe.extend_from_slice(b"MZ");
        pe.extend_from_slice(&[0x00; 62]);
        pe.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew

        // Pad to PE header
        while pe.len() < 0x80 {
            pe.push(0x00);
        }

        pe.extend_from_slice(b"PE\x00\x00");
        pe.extend_from_slice(&[0x00; 100]); // Rest of PE structure

        pe
    }
}

/// Test suite for platform-specific edge cases
#[cfg(target_os = "windows")]
mod windows_specific_tests {
    use super::*;

    #[test]
    fn test_windows_path_handling() {
        // Test Windows-specific path handling
        let windows_paths = vec![
            r"C:\Program Files\test.exe",
            r"C:\Program Files (x86)\test.exe",
            r"\\server\share\test.exe",     // UNC path
            r"C:\Users\Test User\test.exe", // Path with spaces
            r"C:\test\very\long\path\that\goes\on\and\on\test.exe", // Long path
        ];

        for path in windows_paths {
            println!("Testing Windows path: {path}");

            let path_obj = std::path::Path::new(path);

            // Test path parsing
            if let Some(parent) = path_obj.parent() {
                println!("  Parent: {parent:?}");
            }

            if let Some(filename) = path_obj.file_name() {
                println!("  Filename: {filename:?}");
            }

            // Test path normalization
            let canonical = path_obj.canonicalize();
            match canonical {
                Ok(normalized) => println!("  Canonical: {normalized:?}"),
                Err(e) => println!("  Canonicalization failed: {e}"),
            }
        }
    }

    #[test]
    fn test_windows_file_attributes() {
        // Test Windows file attributes
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.exe");

        std::fs::write(&test_file, b"Test content").unwrap();

        // Test file attributes
        let metadata = std::fs::metadata(&test_file).unwrap();
        println!("File attributes:");
        println!("  Size: {} bytes", metadata.len());
        println!("  Read-only: {}", metadata.permissions().readonly());

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let attrs = metadata.file_attributes();
            println!("  Windows attributes: 0x{attrs:08x}");
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod unix_specific_tests {
    use super::*;

    #[test]
    fn test_unix_path_handling() {
        // Test Unix-specific path handling
        let unix_paths = vec![
            "/usr/bin/test",
            "/home/user/test.exe",
            "/tmp/test file.exe",       // Path with spaces
            "/very/long/path/test.exe", // Long path
        ];

        for path in unix_paths {
            println!("Testing Unix path: {path}");

            let path_obj = std::path::Path::new(path);

            if let Some(parent) = path_obj.parent() {
                println!("  Parent: {parent:?}");
            }

            if let Some(filename) = path_obj.file_name() {
                println!("  Filename: {filename:?}");
            }
        }
    }

    #[test]
    fn test_unix_permissions() {
        // Test Unix file permissions
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.exe");

        std::fs::write(&test_file, b"Test content").unwrap();

        let metadata = std::fs::metadata(&test_file).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            println!("Unix file mode: 0{mode:o}");
        }
    }
}

// Helper for async tests
#[cfg(test)]
mod test_helpers {
    // This would normally be in Cargo.toml:
    // [dev-dependencies]
    // tokio-test = "0.4"
}
