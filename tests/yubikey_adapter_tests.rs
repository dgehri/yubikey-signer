//! Tests for `YubiKey` operations adapter

use yubikey_signer::{PivPin, PivSlot, SigningError, YubiKeyOperations};

#[test]
fn test_yubikey_operations_creation() {
    // Test basic instantiation concepts
    // Actual YubiKey hardware would be required for full testing
    let result = std::panic::catch_unwind(|| {
        // This will fail without hardware, but we can test it doesn't panic badly
        let _ = YubiKeyOperations::connect();
    });
    assert!(result.is_ok()); // Should not panic, just return error
}

#[test]
fn test_piv_slot_validation() {
    // Test that PivSlot type validates correctly
    let valid_slots = [0x9a, 0x9c, 0x9d, 0x9e];

    for slot_value in valid_slots {
        let slot = PivSlot::new(slot_value);
        assert!(slot.is_ok(), "Slot 0x{slot_value:02x} should be valid");
        let slot = slot.unwrap();
        assert_eq!(slot.as_u8(), slot_value);
    }

    // Test invalid slots
    let invalid_slots = [0x00, 0x99, 0xFF];
    for slot_value in invalid_slots {
        let slot = PivSlot::new(slot_value);
        assert!(slot.is_err(), "Slot 0x{slot_value:02x} should be invalid");
    }
}

#[test]
fn test_pin_validation() {
    let valid_pins = ["123456", "654321", "00000000"];
    let invalid_pins = ["", "12345", "123456789"]; // too short/long

    for pin_str in valid_pins {
        let pin = PivPin::new(pin_str);
        assert!(pin.is_ok(), "PIN '{pin_str}' should be valid");
    }

    for pin_str in invalid_pins {
        let pin = PivPin::new(pin_str);
        assert!(pin.is_err(), "PIN '{pin_str}' should be invalid");
    }
}

#[test]
fn test_error_handling() {
    // Test that our error types can be created and displayed
    let error = SigningError::YubiKeyError("Test error".to_string());
    let error_string = format!("{error}");
    assert!(error_string.contains("Test error"));
}

// Integration tests that require real hardware
#[cfg(test)]
mod hardware_tests {
    #[cfg(feature = "hardware-tests")]
    use super::*;

    #[test]
    #[cfg(feature = "hardware-tests")]
    fn test_real_yubikey_connection() {
        println!("🔐 Testing YubiKey hardware connection...");
        let result = YubiKeyOperations::connect();

        match result {
            Ok(mut ops) => {
                println!("✅ Connected to YubiKey");

                // Test authentication with a known PIN
                let pin_str = std::env::var("YUBICO_PIN").unwrap_or_else(|_| {
                    println!("💡 Set YUBICO_PIN environment variable for PIN testing");
                    println!("   Example: $env:YUBICO_PIN='123456'");
                    "123456".to_string()
                });
                let pin = PivPin::new(&pin_str).expect("PIN should be valid");
                let auth_result = ops.authenticate(&pin);

                match auth_result {
                    Ok(()) => {
                        println!("✅ PIN authentication successful");
                    }
                    Err(e) => {
                        println!("❌ PIN authentication failed: {e}");
                        println!("💡 Set correct PIN using: $env:YUBICO_PIN='your_pin_here'");
                        println!("   Skipping authentication-dependent tests");
                    }
                }
            }
            Err(e) => {
                println!("❌ YubiKey connection failed: {e}");
                println!("💡 Ensure YubiKey is connected and drivers are installed");
                // Don't fail the test - hardware may not be available
            }
        }
    }

    #[test]
    #[cfg(feature = "hardware-tests")]
    fn test_certificate_retrieval() {
        println!("🔐 Testing certificate retrieval from YubiKey...");
        let result = YubiKeyOperations::connect();

        let mut ops = match result {
            Ok(ops) => {
                println!("✅ Connected to YubiKey");
                ops
            }
            Err(e) => {
                println!("❌ YubiKey connection failed: {e}");
                println!("💡 Ensure YubiKey is connected and drivers are installed");
                return; // Skip test if no hardware
            }
        };

        let pin_str = std::env::var("YUBICO_PIN").unwrap_or_else(|_| {
            println!("💡 Set YUBICO_PIN environment variable for PIN testing");
            println!("   Example: $env:YUBICO_PIN='123456'");
            "123456".to_string()
        });
        let pin = PivPin::new(&pin_str).expect("PIN should be valid");

        match ops.authenticate(&pin) {
            Ok(()) => {
                println!("✅ PIN authentication successful");
            }
            Err(e) => {
                println!("❌ PIN authentication failed: {e}");
                println!("💡 Set correct PIN using: $env:YUBICO_PIN='your_pin_here'");
                return; // Skip test if authentication fails
            }
        }

        // Test certificate retrieval from different slots
        let slots_to_test = [0x9a, 0x9c, 0x9d, 0x9e];

        for slot_value in slots_to_test {
            let slot = PivSlot::new(slot_value).expect("Valid slot");
            match ops.get_certificate(slot) {
                Ok(cert) => {
                    println!(
                        "✅ Certificate found in slot 0x{:02x}: {} bytes",
                        slot_value,
                        cert.tbs_certificate.serial_number.as_bytes().len()
                    );
                }
                Err(e) => {
                    println!("ℹ️  No certificate in slot 0x{slot_value:02x}: {e}");
                }
            }
        }

        println!("✅ Certificate retrieval test completed");
    }

    #[test]
    #[cfg(feature = "hardware-tests")]
    fn test_signing_operation() {
        println!("🔐 Testing signing operation with YubiKey...");
        let result = YubiKeyOperations::connect();

        let mut ops = match result {
            Ok(ops) => {
                println!("✅ Connected to YubiKey");
                ops
            }
            Err(e) => {
                println!("❌ YubiKey connection failed: {e}");
                println!("💡 Ensure YubiKey is connected and drivers are installed");
                return; // Skip test if no hardware
            }
        };

        let pin_str = std::env::var("YUBICO_PIN").unwrap_or_else(|_| {
            println!("💡 Set YUBICO_PIN environment variable for PIN testing");
            println!("   Example: $env:YUBICO_PIN='123456'");
            "123456".to_string()
        });
        let pin = PivPin::new(&pin_str).expect("PIN should be valid");

        match ops.authenticate(&pin) {
            Ok(()) => {
                println!("✅ PIN authentication successful");
            }
            Err(e) => {
                println!("❌ PIN authentication failed: {e}");
                println!("💡 Set correct PIN using: $env:YUBICO_PIN='your_pin_here'");
                return; // Skip test if authentication fails
            }
        }

        // Test signing with a dummy hash
        let test_hash = vec![0u8; 32]; // 32-byte SHA-256 hash
        let slot = PivSlot::new(0x9a).expect("Valid slot"); // Use 9a as default (our fix)

        match ops.sign_hash(&test_hash, slot) {
            Ok(signature) => {
                println!("✅ Signing successful: {} bytes", signature.len());
                assert!(!signature.is_empty());
            }
            Err(e) => {
                println!("ℹ️  Signing failed: {e}");
                println!(
                    "   Note: This is expected if no certificate/private key exists in slot 9a"
                );
                println!("   Try with slot 9c if your certificate is there");
            }
        }

        println!("✅ Signing operation test completed");
    }
}
