//! Test YubiKey PIV signing with different data formats

use std::env;
use yubikey_signer::yubikey_ops::YubiKeyOperations;

#[test]
#[ignore = "Requires YubiKey hardware"]
fn test_yubikey_signing_formats() {
    // Get PIN from environment
    let pin = env::var("YUBICO_PIN").expect("YUBICO_PIN environment variable must be set");

    // Connect and authenticate
    let mut yubikey_ops = YubiKeyOperations::connect().expect("Should connect to YubiKey");
    yubikey_ops.authenticate(&pin).expect("Should authenticate");

    // Test different data sizes and formats
    let test_cases = vec![
        ("Empty data", vec![]),
        ("Small data (16 bytes)", vec![0x01; 16]),
        ("SHA256 size (32 bytes)", vec![0x02; 32]),
        ("SHA384 size (48 bytes)", vec![0x03; 48]),
        ("SHA512 size (64 bytes)", vec![0x04; 64]),
        ("Large data (100 bytes)", vec![0x05; 100]),
        ("Max RSA size (256 bytes)", vec![0x06; 256]),
    ];

    for (name, data) in test_cases {
        println!("Testing: {} - {} bytes", name, data.len());

        match yubikey_ops.sign_hash(&data, 0x9a) {
            Ok(signature) => {
                println!("  ✅ Success! Signature: {} bytes", signature.len());
            }
            Err(e) => {
                println!("  ❌ Failed: {}", e);
            }
        }
    }
}
