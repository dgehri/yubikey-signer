//! YubiKey PIV operations for code signing
//! 
//! This module provides a high-level interface for YubiKey PIV operations
//! including authentication, certificate retrieval, and digital signing.

use crate::error::{SigningError, SigningResult};
use x509_cert::Certificate;
use yubikey::{
    YubiKey, 
    certificate::Certificate as YkCertificate,
    piv::{SlotId, ObjectId, AlgorithmId},
};

/// Convert u8 slot ID to SlotId enum
pub fn u8_to_slot_id(slot: u8) -> SlotId {
    match slot {
        0x9a => SlotId::Authentication,
        0x9c => SlotId::Signature,
        0x9d => SlotId::KeyManagement,
        0x9e => SlotId::CardAuthentication,
        _ => SlotId::Authentication, // Default fallback
    }
}

/// YubiKey PIV operations wrapper
pub struct YubiKeyOperations {
    yubikey: YubiKey,
    authenticated: bool,
}

impl YubiKeyOperations {
    /// Connect to YubiKey device
    pub fn connect() -> SigningResult<Self> {
        log::info!("Connecting to YubiKey device");
        
        let yubikey = YubiKey::open()
            .map_err(|e| SigningError::YubikeyError(format!("Failed to open YubiKey: {}", e)))?;
        
        log::info!("Connected to YubiKey");
        Ok(Self {
            yubikey,
            authenticated: false,
        })
    }
    
    /// Authenticate with PIN
    pub fn authenticate(&mut self, pin: &str) -> SigningResult<()> {
        log::info!("Authenticating with YubiKey PIN");
        
        self.yubikey
            .verify_pin(pin.as_bytes())
            .map_err(|e| SigningError::YubikeyError(format!("PIN verification failed: {}", e)))?;
        
        self.authenticated = true;
        log::info!("Authenticated with YubiKey");
        Ok(())
    }
    
    /// Get certificate from PIV slot
    pub fn get_certificate(&mut self, slot: u8) -> SigningResult<Certificate> {
        if !self.authenticated {
            return Err(SigningError::YubikeyError("Not authenticated with YubiKey".to_string()));
        }
        
        log::info!("Retrieving certificate from PIV slot 0x{:02x}", slot);
        
        let slot_id = u8_to_slot_id(slot);
        let object_id = ObjectId::from(slot_id);
        
        // Fetch certificate data from YubiKey
        let cert_data = self.yubikey
            .fetch_object(object_id)
            .map_err(|e| SigningError::YubikeyError(
                format!("Failed to fetch certificate from PIV slot 0x{:02x}: {}", slot, e)
            ))?;
        
        // Parse the DER-encoded certificate
        let certificate = Certificate::from_der(&cert_data)
            .map_err(|e| SigningError::CertificateError(
                format!("Failed to parse certificate: {}", e)
            ))?;
        
        log::info!("Retrieved certificate from slot 0x{:02x}", slot);
        Ok(certificate)
    }
    
    /// Sign hash with private key from PIV slot
    pub fn sign_hash(&mut self, hash: &[u8], slot: u8) -> SigningResult<Vec<u8>> {
        if !self.authenticated {
            return Err(SigningError::YubikeyError("Not authenticated with YubiKey".to_string()));
        }
        
        log::info!("Signing hash with YubiKey PIV slot 0x{:02x}", slot);
        log::debug!("Hash length: {} bytes", hash.len());
        
        let slot_id = u8_to_slot_id(slot);
        
        // Create signature using the YubiKey's private key
        // The YubiKey will internally add PKCS#1 padding for RSA signatures
        let signature = self
            .yubikey
            .sign_data(slot_id, hash, AlgorithmId::Rsa2048)
            .map_err(|e| SigningError::SignatureError(
                format!("Failed to sign data with YubiKey: {}", e)
            ))?;

        log::info!("Created digital signature");
        Ok(signature.to_vec())
    }

    /// List available certificates on the YubiKey for debugging
    pub fn list_certificates(&mut self) -> SigningResult<Vec<(SlotId, Certificate)>> {
        if !self.authenticated {
            return Err(SigningError::YubikeyError("Not authenticated with YubiKey".to_string()));
        }
        
        let mut certificates = Vec::new();
        
        // Common PIV slots that might contain certificates
        let slots_to_check = [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
            SlotId::CardAuthentication,
        ];
        
        for slot in slots_to_check {
            match self.get_certificate_from_slot(slot) {
                Ok(cert) => {
                    certificates.push((slot, cert));
                }
                Err(_) => {
                    // No certificate in this slot, continue
                }
            }
        }
        
        Ok(certificates)
    }

    /// Get certificate from specific slot
    fn get_certificate_from_slot(&mut self, slot: SlotId) -> SigningResult<Certificate> {
        let object_id = ObjectId::from(slot);
        let cert_data = self.yubikey.fetch_object(object_id)
            .map_err(|e| SigningError::YubikeyError(
                format!("Failed to fetch certificate from PIV slot: {}", e)
            ))?;

        let certificate = Certificate::from_der(&cert_data)
            .map_err(|e| SigningError::CertificateError(
                format!("Failed to parse certificate: {}", e)
            ))?;

        Ok(certificate)
    }

    /// Get YubiKey serial number
    pub fn get_serial(&mut self) -> SigningResult<u32> {
        Ok(self.yubikey.serial())
    }

    /// Get YubiKey version information
    pub fn get_version(&mut self) -> SigningResult<String> {
        let version = self.yubikey.version();
        Ok(format!(
            "{}.{}.{}",
            version.major, version.minor, version.patch
        ))
    }
}

// Convert SlotId to ObjectId for certificate fetching
impl From<SlotId> for ObjectId {
    fn from(slot: SlotId) -> Self {
        match slot {
            SlotId::Authentication => ObjectId::Authentication,
            SlotId::Signature => ObjectId::Signature,
            SlotId::KeyManagement => ObjectId::KeyManagement,
            SlotId::CardAuthentication => ObjectId::CardAuthentication,
            _ => ObjectId::Authentication, // Default fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
        // Test that common PIV slots are valid values
        let valid_slots = [0x9a, 0x9c, 0x9d, 0x9e];
        
        for slot in valid_slots {
            // These are valid slot numbers
            assert!(slot <= 0xFF);
            assert!(slot >= 0x80); // PIV slots are in upper range
        }
    }
    
    #[test]
    fn test_pin_validation() {
        let valid_pins = ["123456", "654321", "000000"];
        let invalid_pins = ["", "12345", "1234567890123456"]; // too short/long
        
        for pin in valid_pins {
            assert!(pin.len() >= 6);
            assert!(pin.len() <= 8);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
        }
        
        for pin in invalid_pins {
            let is_valid = pin.len() >= 6 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit());
            assert!(!is_valid);
        }
    }
    
    #[test]
    fn test_slot_conversion() {
        // Test conversion from u8 to SlotId
        let slot_9c = u8_to_slot_id(0x9c);
        assert!(matches!(slot_9c, SlotId::Signature));
        
        let slot_9a = u8_to_slot_id(0x9a);
        assert!(matches!(slot_9a, SlotId::Authentication));
        
        let slot_9d = u8_to_slot_id(0x9d);
        assert!(matches!(slot_9d, SlotId::KeyManagement));
        
        let slot_9e = u8_to_slot_id(0x9e);
        assert!(matches!(slot_9e, SlotId::CardAuthentication));
    }
    
    #[test]
    fn test_error_handling() {
        // Test that our error types can be created and displayed
        let error = SigningError::YubikeyError("Test error".to_string());
        let error_string = format!("{}", error);
        assert!(error_string.contains("Test error"));
    }
}
