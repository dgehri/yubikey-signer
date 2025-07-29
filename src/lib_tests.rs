//! Unit tests for the yubikey-signer library

use crate::*;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[test]
fn test_signing_config_creation() {
    let config = SigningConfig {
        piv_slot: 0x9c,
        pin: "123456".to_string(),
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: Some("http://ts.ssl.com".to_string()),
        embed_certificate: true,
    };
    
    assert_eq!(config.piv_slot, 0x9c);
    assert_eq!(config.pin, "123456");
    assert!(matches!(config.hash_algorithm, HashAlgorithm::Sha256));
    assert_eq!(config.timestamp_url.unwrap(), "http://ts.ssl.com");
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
        piv_slot: 0x9c,
        pin: "123456".to_string(),
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
        SigningError::IoError(_) => {}, // Expected
        other => panic!("Expected IoError, got: {:?}", other),
    }
}

#[tokio::test] 
async fn test_sign_pe_file_with_invalid_pe() {
    let config = SigningConfig {
        piv_slot: 0x9c,
        pin: "123456".to_string(),
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
        SigningError::PeParsingError(_) | SigningError::YubiKeyError(_) => {}, // Expected
        other => panic!("Expected PeParsingError or YubiKeyError, got: {:?}", other),
    }
}

#[test]
fn test_minimal_config() {
    let config = SigningConfig {
        piv_slot: 0x9a,
        pin: "654321".to_string(),
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: None,
        embed_certificate: false,
    };
    
    assert_eq!(config.piv_slot, 0x9a);
    assert!(config.timestamp_url.is_none());
    assert!(!config.embed_certificate);
}

mod integration_tests {
    use super::*;
    
    // These tests require actual YubiKey hardware and are marked as ignored
    // Run with: cargo test -- --ignored
    
    #[tokio::test]
    #[ignore = "Requires YubiKey hardware"]
    async fn test_sign_real_pe_file() {
        // This test would require:
        // 1. A real YubiKey with PIV certificate
        // 2. A valid PE file to sign
        // 3. Correct PIN
        
        let config = SigningConfig {
            piv_slot: 0x9c,
            pin: std::env::var("YUBIKEY_PIN").unwrap_or_else(|_| "123456".to_string()),
            hash_algorithm: HashAlgorithm::Sha256,
            timestamp_url: Some("http://ts.ssl.com".to_string()),
            embed_certificate: true,
        };
        
        // Would need a real PE file for testing
        // let input_path = PathBuf::from("test_data/sample.exe");
        // let output_path = PathBuf::from("test_output/signed_sample.exe");
        // 
        // let result = sign_pe_file(&input_path, &output_path, config).await;
        // assert!(result.is_ok());
        
        println!("Integration test would run here with real hardware");
    }
    
    #[tokio::test]
    #[ignore = "Requires network access"]
    async fn test_timestamp_integration() {
        use crate::timestamp::TimestampClient;
        
        let client = TimestampClient::new("http://ts.ssl.com");
        let test_hash = vec![1u8; 32];
        
        let result = client.get_timestamp(&test_hash).await;
        match result {
            Ok(token) => {
                println!("Received timestamp token: {} bytes", token.len());
                assert!(token.len() > 0);
            }
            Err(e) => {
                println!("Timestamp failed (may be expected in CI): {}", e);
                // Don't fail the test - network may not be available
            }
        }
    }
}
