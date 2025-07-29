//! End-to-End Signing Integration Tests
//! 
//! These tests validate the complete signing workflow with real YubiKey hardware
//! and real PE files. Run with: cargo test --test end_to_end_signing -- --include-ignored

use std::env;
use std::fs;
use yubikey_signer::{HashAlgorithm, SigningConfig, sign_pe_file};
use tempfile::NamedTempFile;

#[tokio::test]
#[ignore = "Requires YubiKey hardware and real PE file"]
async fn test_complete_signing_workflow() {
    // Get PIN from environment
    let pin = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");
    
    // Configuration that should work with our YubiKey setup
    let config = SigningConfig {
        pin,
        piv_slot: 0x9a, // Use Authentication slot where certificate exists
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: Some("http://ts.ssl.com".to_string()),
        embed_certificate: true,
    };
    
    // Use the real PE file we created
    let input_path = "test_real.exe";
    assert!(fs::metadata(input_path).is_ok(), "test_real.exe must exist");
    
    // Create temporary output file
    let output_file = NamedTempFile::new().expect("Failed to create temp output file");
    let output_path = output_file.path();
    
    // This should complete successfully with real hardware
    let result = sign_pe_file(input_path, output_path.to_str().unwrap(), config).await;
    
    match result {
        Ok(_) => {
            println!("✅ Complete signing workflow successful!");
            
            // Verify the output file was created and has content
            let output_metadata = fs::metadata(output_path).expect("Output file should exist");
            assert!(output_metadata.len() > 0, "Output file should not be empty");
            
            println!("✅ Output file created: {} bytes", output_metadata.len());
        }
        Err(e) => {
            println!("❌ Signing workflow failed: {}", e);
            
            // Let's diagnose what specifically failed
            match &e {
                yubikey_signer::SigningError::YubiKeyError(msg) => {
                    println!("🔍 YubiKey issue: {}", msg);
                }
                yubikey_signer::SigningError::PeParsingError(msg) => {
                    println!("🔍 PE parsing issue: {}", msg);
                }
                yubikey_signer::SigningError::CertificateError(msg) => {
                    println!("🔍 Certificate issue: {}", msg);
                }
                yubikey_signer::SigningError::NetworkError(msg) => {
                    println!("🔍 Network issue: {}", msg);
                }
                yubikey_signer::SigningError::IoError(msg) => {
                    println!("🔍 IO issue: {}", msg);
                }
                yubikey_signer::SigningError::SignatureError(msg) => {
                    println!("🔍 Signature creation issue: {}", msg);
                }
                _ => {
                    println!("🔍 Other error: {}", e);
                }
            }
            
            // For TDD, we expect this to fail initially, then we implement the missing parts
            panic!("Expected signing to succeed, but got: {}", e);
        }
    }
}

#[tokio::test]
#[ignore = "Requires YubiKey hardware"]
async fn test_signing_without_timestamp() {
    // Test signing without timestamp to isolate network issues
    let pin = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");
    
    let config = SigningConfig {
        pin,
        piv_slot: 0x9a,
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: None, // No timestamp
        embed_certificate: true,
    };
    
    let input_path = "test_real.exe";
    let output_file = NamedTempFile::new().expect("Failed to create temp output file");
    let output_path = output_file.path();
    
    let result = sign_pe_file(input_path, output_path.to_str().unwrap(), config).await;
    
    match result {
        Ok(_) => {
            println!("✅ Signing without timestamp successful!");
        }
        Err(e) => {
            println!("❌ Signing without timestamp failed: {}", e);
            panic!("Signing without timestamp should work: {}", e);
        }
    }
}

#[tokio::test]
#[ignore = "Requires YubiKey hardware"]
async fn test_signing_validation_only() {
    // Test just the validation/dry-run functionality
    let pin = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");
    
    let config = SigningConfig {
        pin,
        piv_slot: 0x9a,
        hash_algorithm: HashAlgorithm::Sha256,
        timestamp_url: None,
        embed_certificate: true,
    };
    
    // We'll test just the validation components that should work
    use yubikey_signer::yubikey_ops::YubiKeyOperations;
    
    // Test YubiKey connection
    let mut yubikey_ops = YubiKeyOperations::connect().expect("Should connect to YubiKey");
    yubikey_ops.authenticate(&config.pin).expect("Should authenticate");
    
    // Test certificate retrieval
    let _cert = yubikey_ops.get_certificate(config.piv_slot).expect("Should get certificate");
    
    println!("✅ Validation components working");
}
