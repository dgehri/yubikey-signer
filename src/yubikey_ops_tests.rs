//! Tests for YubiKey operations module

use crate::error::SigningError;
use crate::types::*;
use crate::yubikey_ops::*;

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
        assert!(slot.is_ok(), "Slot 0x{:02x} should be valid", slot_value);
        let slot = slot.unwrap();
        assert_eq!(slot.as_u8(), slot_value);
    }

    // Test invalid slots
    let invalid_slots = [0x00, 0x99, 0xFF];
    for slot_value in invalid_slots {
        let slot = PivSlot::new(slot_value);
        assert!(slot.is_err(), "Slot 0x{:02x} should be invalid", slot_value);
    }
}

#[test]
fn test_pin_validation() {
    let valid_pins = ["123456", "654321", "00000000"];
    let invalid_pins = ["", "12345", "123456789"]; // too short/long

    for pin_str in valid_pins {
        let pin = PivPin::new(pin_str);
        assert!(pin.is_ok(), "PIN '{}' should be valid", pin_str);
    }

    for pin_str in invalid_pins {
        let pin = PivPin::new(pin_str);
        assert!(pin.is_err(), "PIN '{}' should be invalid", pin_str);
    }
}

#[test]
fn test_error_handling() {
    // Test that our error types can be created and displayed
    let error = SigningError::YubiKeyError("Test error".to_string());
    let error_string = format!("{}", error);
    assert!(error_string.contains("Test error"));
}

// Integration tests that require real hardware
#[cfg(test)]
mod hardware_tests {
    use super::*;

    #[test]
    #[ignore = "Requires YubiKey hardware"]
    fn test_real_yubikey_connection() {
        let result = YubiKeyOperations::connect();

        match result {
            Ok(mut ops) => {
                println!("Connected to YubiKey");

                // Test authentication with a known PIN
                let pin_str =
                    std::env::var("TEST_YUBIKEY_PIN").unwrap_or_else(|_| "123456".to_string());
                let pin = PivPin::new(&pin_str).expect("PIN should be valid");
                let auth_result = ops.authenticate(&pin);

                match auth_result {
                    Ok(_) => println!("Authentication successful"),
                    Err(e) => println!("Authentication failed: {}", e),
                }
            }
            Err(e) => {
                println!("YubiKey connection failed: {}", e);
                // Don't fail the test - hardware may not be available
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey with certificate"]
    fn test_certificate_retrieval() {
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        let pin_str = std::env::var("TEST_YUBIKEY_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("PIN should be valid");

        ops.authenticate(&pin).expect("Authentication required");

        // Test certificate retrieval from different slots
        let slots_to_test = [0x9a, 0x9c, 0x9d, 0x9e];

        for slot_value in slots_to_test {
            let slot = PivSlot::new(slot_value).expect("Valid slot");
            match ops.get_certificate(slot) {
                Ok(cert) => {
                    println!(
                        "Found certificate in slot 0x{:02x}: {} bytes",
                        slot_value,
                        cert.tbs_certificate.serial_number.as_bytes().len()
                    );
                }
                Err(e) => {
                    println!("No certificate in slot 0x{:02x}: {}", slot_value, e);
                }
            }
        }
    }

    #[test]
    #[ignore = "Requires YubiKey with private key"]
    fn test_signing_operation() {
        let mut ops = YubiKeyOperations::connect().expect("YubiKey required");
        let pin_str = std::env::var("TEST_YUBIKEY_PIN").unwrap_or_else(|_| "123456".to_string());
        let pin = PivPin::new(&pin_str).expect("PIN should be valid");

        ops.authenticate(&pin).expect("Authentication required");

        // Test signing with a dummy hash
        let test_hash = vec![0u8; 32]; // 32-byte SHA-256 hash
        let slot = PivSlot::new(0x9c).expect("Valid slot"); // Digital signature slot

        match ops.sign_hash(&test_hash, slot) {
            Ok(signature) => {
                println!("Signing successful: {} bytes", signature.len());
                assert!(signature.len() > 0);
            }
            Err(e) => {
                println!("Signing failed: {}", e);
                // May fail if no private key in slot
            }
        }
    }
}
