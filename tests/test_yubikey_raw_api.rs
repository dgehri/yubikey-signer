//! Test YubiKey PIV signing with different algorithms and slots

use std::env;
use yubikey::{YubiKey, piv::*};

#[test]
#[ignore = "Requires YubiKey hardware"]
fn test_yubikey_raw_signing() {
    // Get PIN from environment
    let pin = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");
    
    // Connect to YubiKey directly
    let mut yubikey = YubiKey::open().expect("Should connect to YubiKey");
    
    // Authenticate with PIN for PIV operations
    yubikey.verify_pin(pin.as_bytes()).expect("Should verify PIN");
    
    // Test different algorithms
    let algorithms = vec![
        (AlgorithmId::Rsa1024, "RSA-1024"),
        (AlgorithmId::Rsa2048, "RSA-2048"), 
        (AlgorithmId::EccP256, "ECC-P256"),
        (AlgorithmId::EccP384, "ECC-P384"),
    ];
    
    let test_data = vec![0x01; 32]; // 32 bytes of test data
    
    for (algorithm, name) in algorithms {
        println!("Testing algorithm: {}", name);
        
        // Try slot 0x9a (Authentication)
        match sign_data(&mut yubikey, &test_data, algorithm, SlotId::Authentication) {
            Ok(signature) => {
                println!("  Slot 0x9a success! Signature: {} bytes", signature.len());
            }
            Err(e) => {
                println!("  Slot 0x9a failed: {}", e);
            }
        }
        
        // Try slot 0x9c (Digital Signature)  
        match sign_data(&mut yubikey, &test_data, algorithm, SlotId::Signature) {
            Ok(signature) => {
                println!("  Slot 0x9c success! Signature: {} bytes", signature.len());
            }
            Err(e) => {
                println!("  Slot 0x9c failed: {}", e);
            }
        }
    }
}
