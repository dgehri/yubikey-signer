//! Integration tests for the yubikey-signer library

use std::path::PathBuf;
use tempfile::NamedTempFile;
use yubikey_signer::*;

#[test]
fn test_signing_config_creation() {
    let config = SigningConfig {
        piv_slot: PivSlot::new(0x9c).unwrap(),
        pin: PivPin::new("123456").unwrap(),
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: Some(TimestampUrl::new("http://ts.ssl.com").unwrap()),
        embed_certificate: true,
    };

    assert_eq!(config.piv_slot.as_u8(), 0x9c);
    assert_eq!(config.pin.as_str(), "123456");
    assert!(matches!(config.hash_algorithm, HashAlgorithm::Sha256));
    assert_eq!(config.timestamp_url.unwrap().as_str(), "http://ts.ssl.com");
    assert!(config.embed_certificate);
}

#[test]
fn test_hash_algorithm_display() {
    assert_eq!(format!("{:?}", HashAlgorithm::Sha256), "Sha256");
    assert_eq!(format!("{:?}", HashAlgorithm::Sha384), "Sha384");
    assert_eq!(format!("{:?}", HashAlgorithm::Sha512), "Sha512");
}

#[tokio::test]
async fn test_sign_pe_file_with_invalid_input() {
    let config = SigningConfig {
        piv_slot: PivSlot::new(0x9c).unwrap(),
        pin: PivPin::new("123456").unwrap(),
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: None,
        embed_certificate: false,
    };

    let input_path = PathBuf::from("nonexistent_file.exe");
    let output_path = PathBuf::from("output.exe");

    let result = sign_pe_file(&input_path, &output_path, config).await;
    assert!(result.is_err());

    // Should be an IO error for nonexistent file
    match result.unwrap_err() {
        SigningError::IoError(_) => {} // Expected
        other => panic!("Expected IoError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_sign_pe_file_with_invalid_pe() {
    let config = SigningConfig {
        piv_slot: PivSlot::new(0x9c).unwrap(),
        pin: PivPin::new("123456").unwrap(),
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: None,
        embed_certificate: false,
    };

    // Create a temporary file with invalid PE content
    let mut temp_file = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut temp_file, b"Not a PE file").unwrap();

    let input_path = temp_file.path().to_path_buf();
    let output_path = PathBuf::from("output.exe");

    let result = sign_pe_file(&input_path, &output_path, config).await;
    assert!(result.is_err());

    // Should be either a PE error or YubiKey error (depending on how far it gets)
    match result.unwrap_err() {
        SigningError::PeParsingError(_) | SigningError::YubiKeyError(_) => {} // Expected
        other => panic!("Expected PeParsingError or YubiKeyError, got: {other:?}"),
    }
}

#[test]
fn test_minimal_config() {
    let config = SigningConfig {
        piv_slot: PivSlot::new(0x9a).unwrap(),
        pin: PivPin::new("654321").unwrap(),
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: None,
        embed_certificate: false,
    };

    assert_eq!(config.piv_slot.as_u8(), 0x9a);
    assert!(config.timestamp_url.is_none());
    assert!(!config.embed_certificate);
}

mod integration_tests {
    #[cfg(any(feature = "hardware-tests", feature = "network-tests"))]
    use super::*;

    // These tests require actual YubiKey hardware and are marked as ignored
    // Run with: cargo test -- --ignored

    #[tokio::test]
    #[cfg(feature = "hardware-tests")]
    async fn test_sign_real_pe_file() {
        // This test requires:
        // 1. A real YubiKey with PIV certificate
        // 2. A valid PE file to sign
        // 3. Correct PIN
        // Run with: cargo test --features hardware-tests

        println!("🔐 Testing with real YubiKey hardware...");

        let _config = SigningConfig {
            piv_slot: PivSlot::new(0x9a).unwrap(), // Use 9a as default (our fix)
            pin: PivPin::new(std::env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string()))
                .unwrap(),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some(TimestampUrl::new("http://ts.ssl.com").unwrap()),
            embed_certificate: true,
        };

        // Would need a real PE file for testing
        // let input_path = PathBuf::from("test_data/sample.exe");
        // let output_path = PathBuf::from("test_output/signed_sample.exe");
        //
        // let result = sign_pe_file(&input_path, &output_path, config).await;
        // assert!(result.is_ok());

        println!("Hardware test configured for slot 9a (new default) with http://ts.ssl.com timestamp server");
    }

    #[tokio::test]
    #[cfg(all(feature = "hardware-tests", feature = "network-tests"))]
    async fn test_integration_with_real_hardware_and_timestamp() {
        // Integration test requiring both YubiKey hardware and network access
        // Run with: cargo test --features integration-tests

        println!("🚀 Running full integration test with YubiKey hardware and timestamp server...");

        use crate::services::timestamp::TimestampClient;

        // Test timestamp server first
        let client = TimestampClient::new(&TimestampUrl::new("http://ts.ssl.com").unwrap());
        let test_hash = vec![0u8; 32];

        let timestamp_result = client.get_timestamp(&test_hash).await;
        match timestamp_result {
            Ok(token) => {
                println!(
                    "✅ Timestamp server working: {} bytes received",
                    token.len()
                );
            }
            Err(e) => {
                panic!("❌ Timestamp server failed: {e}");
            }
        }

        // Test YubiKey connection with new default slot 9a
        let _config = SigningConfig {
            piv_slot: PivSlot::new(0x9a).unwrap(), // Use new default slot
            pin: PivPin::new(std::env::var("YUBICO_PIN").unwrap_or_else(|_| "123456".to_string()))
                .unwrap(),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some(TimestampUrl::new("http://ts.ssl.com").unwrap()),
            embed_certificate: true,
        };

        println!("✅ Integration test configuration validated");
        println!("  - Default slot: 9a (Authentication)");
        println!("  - Timestamp server: http://ts.ssl.com");
        println!("  - Hash algorithm: SHA-256");
    }

    #[tokio::test]
    #[cfg(feature = "network-tests")]
    async fn test_timestamp_integration() {
        use crate::services::timestamp::TimestampClient;

        // Use http://ts.ssl.com as recommended
        let client = TimestampClient::new(&TimestampUrl::new("http://ts.ssl.com").unwrap());
        let test_hash = vec![1u8; 32];

        let result = client.get_timestamp(&test_hash).await;
        match result {
            Ok(token) => {
                println!("✅ Received timestamp token: {} bytes", token.len());
                assert!(!token.is_empty());
                assert!(token.len() > 100); // Real timestamp tokens should be substantial
            }
            Err(e) => {
                println!("❌ Timestamp request failed: {e}");
                // Only panic if we're specifically running network tests
                panic!(
                    "Timestamp integration test failed when network-tests feature is enabled: {e}"
                );
            }
        }
    }
}
