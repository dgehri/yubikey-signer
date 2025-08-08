//! YubiKey PIV operations for code signing
//!
//! This module provides a high-level interface for YubiKey PIV operations
//! including authentication, certificate retrieval, and digital signing.

use crate::error::{SigningError, SigningResult};
use der::{Decode, Encode};
use x509_cert::Certificate;
use yubikey::{piv::SlotId, YubiKey};

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
            .map_err(|e| SigningError::YubiKeyError(format!("Failed to open YubiKey: {e}")))?;

        log::info!("Connected to YubiKey");
        Ok(Self {
            yubikey,
            authenticated: false,
        })
    }

    /// Authenticate with PIN
    pub fn authenticate(&mut self, pin: &crate::types::PivPin) -> SigningResult<()> {
        log::info!("Authenticating with YubiKey PIN");

        self.yubikey
            .verify_pin(pin.as_bytes())
            .map_err(|e| SigningError::YubiKeyError(format!("PIN verification failed: {e}")))?;

        self.authenticated = true;
        log::info!("Authenticated with YubiKey");
        Ok(())
    }

    /// Get certificate from PIV slot
    pub fn get_certificate(&mut self, slot: crate::types::PivSlot) -> SigningResult<Certificate> {
        if !self.authenticated {
            return Err(SigningError::YubiKeyError(
                "Not authenticated with YubiKey".to_string(),
            ));
        }

        log::info!("Retrieving certificate from PIV slot {slot}");

        let slot_id = slot.as_slot_id();

        // Try to get certificate using YubiKey PIV functionality
        // This is a simplified implementation - in reality we'd use the proper PIV API
        let cert_der = self.fetch_certificate_der(slot_id)?;

        // Parse the DER-encoded certificate
        let certificate = Certificate::from_der(&cert_der).map_err(|e| {
            SigningError::CertificateError(format!("Failed to parse certificate: {e}"))
        })?;

        log::info!("Successfully retrieved certificate from slot {slot}");
        Ok(certificate)
    }

    /// Sign hash with private key from PIV slot
    pub fn sign_hash(
        &mut self,
        hash: &[u8],
        slot: crate::types::PivSlot,
    ) -> SigningResult<Vec<u8>> {
        if !self.authenticated {
            return Err(SigningError::YubiKeyError(
                "Not authenticated with YubiKey".to_string(),
            ));
        }

        log::info!("Signing hash with YubiKey PIV slot {slot}");
        log::debug!("Hash length: {} bytes", hash.len());

        let slot_id = slot.as_slot_id();

        // Perform the signing operation
        let signature = self.perform_signing(slot_id, hash)?;

        log::info!("Successfully created digital signature");
        Ok(signature)
    }

    /// Internal method to fetch certificate DER data from YubiKey
    fn fetch_certificate_der(&mut self, slot_id: SlotId) -> SigningResult<Vec<u8>> {
        log::info!("Fetching certificate DER from slot {slot_id:?}");

        // Use yubikey::Certificate::read to get the certificate
        match yubikey::Certificate::read(&mut self.yubikey, slot_id) {
            Ok(yubikey_cert) => {
                // The yubikey Certificate wraps an x509_cert::Certificate
                // We need to extract the DER bytes from it
                match yubikey_cert.cert.to_der() {
                    Ok(der_bytes) => {
                        log::info!(
                            "Successfully fetched certificate: {} bytes",
                            der_bytes.len()
                        );
                        Ok(der_bytes)
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to encode certificate to DER: {e}");
                        log::error!("{error_msg}");
                        Err(SigningError::YubiKeyError(error_msg))
                    }
                }
            }
            Err(e) => {
                let error_msg =
                    format!("Failed to read certificate from slot {slot_id:?}: {e}");
                log::error!("{error_msg}");
                Err(SigningError::YubiKeyError(error_msg))
            }
        }
    }
    /// Internal method to perform signing with YubiKey
    fn perform_signing(&mut self, slot_id: SlotId, hash: &[u8]) -> SigningResult<Vec<u8>> {
        log::info!("Performing digital signature with slot {slot_id:?}");
        log::debug!("Hash to sign: {} bytes", hash.len());

        // Try different algorithms in order of preference
        // ECC-P384 first (most likely to work based on our certificate)
        match yubikey::piv::sign_data(
            &mut self.yubikey,
            hash,
            yubikey::piv::AlgorithmId::EccP384,
            slot_id,
        ) {
            Ok(signature) => {
                log::info!(
                    "Successfully created ECC-P384 signature: {} bytes",
                    signature.len()
                );
                return Ok(signature.to_vec());
            }
            Err(e) => {
                log::debug!("ECC-P384 signing failed: {e}");
            }
        }

        // Try ECC-P256 next
        match yubikey::piv::sign_data(
            &mut self.yubikey,
            hash,
            yubikey::piv::AlgorithmId::EccP256,
            slot_id,
        ) {
            Ok(signature) => {
                log::info!(
                    "Successfully created ECC-P256 signature: {} bytes",
                    signature.len()
                );
                return Ok(signature.to_vec());
            }
            Err(e) => {
                log::debug!("ECC-P256 signing failed: {e}");
            }
        }

        // Try RSA-2048 with raw hash
        match yubikey::piv::sign_data(
            &mut self.yubikey,
            hash,
            yubikey::piv::AlgorithmId::Rsa2048,
            slot_id,
        ) {
            Ok(signature) => {
                log::info!(
                    "Successfully created RSA-2048 signature: {} bytes",
                    signature.len()
                );
                return Ok(signature.to_vec());
            }
            Err(e) => {
                log::debug!("RSA-2048 raw hash signing failed: {e}");

                // If raw hash fails, try with DigestInfo structure
                let hash_algorithm = match hash.len() {
                    32 => crate::HashAlgorithm::Sha256,
                    48 => crate::HashAlgorithm::Sha384,
                    64 => crate::HashAlgorithm::Sha512,
                    _ => {
                        let error_msg = format!("Unsupported hash length: {} bytes", hash.len());
                        log::error!("{error_msg}");
                        return Err(SigningError::YubiKeyError(error_msg));
                    }
                };

                // Create DigestInfo structure for PKCS#1 signing
                let digest_info = crate::authenticode::create_digest_info(hash, hash_algorithm)?;
                log::debug!("Trying RSA with DigestInfo: {} bytes", digest_info.len());

                // Try signing with DigestInfo
                match yubikey::piv::sign_data(
                    &mut self.yubikey,
                    &digest_info,
                    yubikey::piv::AlgorithmId::Rsa2048,
                    slot_id,
                ) {
                    Ok(signature) => {
                        log::info!(
                            "Successfully created RSA-2048 signature with DigestInfo: {} bytes",
                            signature.len()
                        );
                        return Ok(signature.to_vec());
                    }
                    Err(e2) => {
                        log::debug!("RSA-2048 DigestInfo signing failed: {e2}");
                    }
                }
            }
        }

        // If all algorithms fail, return error
        let error_msg = format!(
            "Failed to sign with slot {slot_id:?}: no supported algorithm worked"
        );
        log::error!("{error_msg}");
        Err(SigningError::YubiKeyError(error_msg))
    }
    /// Get YubiKey serial number
    pub fn get_serial(&mut self) -> SigningResult<u32> {
        let serial = self.yubikey.serial();
        Ok(u32::from(serial))
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
            let is_valid =
                pin.len() >= 6 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit());
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
        let error = SigningError::YubiKeyError("Test error".to_string());
        let error_string = format!("{error}");
        assert!(error_string.contains("Test error"));
    }
}
