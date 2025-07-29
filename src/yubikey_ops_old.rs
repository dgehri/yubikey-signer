//! YubiKey PIV operations for code signing

use crate::error::{SigningError, SigningResult};
use yubikey::{piv::*, YubiKey};
use x509_cert::Certificate;

/// YubiKey operations interface
pub struct YubiKeyOperations {
    yubikey: YubiKey,
    authenticated: bool,
}

impl YubiKeyOperations {
    /// Connect to YubiKey and authenticate with PIN
    pub fn connect(pin: &str) -> SigningResult<Self> {
        log::info!("Connecting to YubiKey...");
        
        let mut yubikey = YubiKey::open()
            .map_err(|e| SigningError::YubiKeyError(
                format!("Failed to connect to YubiKey. Make sure it's inserted and PIV applet is enabled: {}", e)
            ))?;

        log::info!("Authenticating with PIN...");
        
        // Verify PIN - this authenticates for signing operations
        yubikey
            .verify_pin(pin.as_bytes())
            .map_err(|e| SigningError::AuthenticationError(
                format!("Failed to verify PIN: {}", e)
            ))?;

        Ok(Self {
            yubikey,
            authenticated: true,
        })
    }

    /// Get the certificate from the authentication slot (9a)
    pub fn get_certificate(&mut self) -> SigningResult<Certificate> {
        self.ensure_authenticated()?;

        log::debug!("Fetching certificate from YubiKey PIV slot 9a");
        
        // Try to get certificate from slot 9a (authentication)
        let cert_data = self
            .yubikey
            .fetch_object(ObjectId::Authentication)
            .map_err(|e| SigningError::CertificateError(
                format!("Failed to fetch certificate from YubiKey PIV slot 9a: {}", e)
            ))?;

        // Parse the certificate
        let certificate = Certificate::from_der(&cert_data)
            .map_err(|e| SigningError::CertificateError(
                format!("Failed to parse certificate from YubiKey: {}", e)
            ))?;

        log::info!("Successfully retrieved certificate from YubiKey");
        Ok(certificate)
    }

    /// Sign a hash using the private key in the YubiKey
    pub fn sign_hash(&mut self, hash: &[u8]) -> SigningResult<Vec<u8>> {
        self.ensure_authenticated()?;

        log::debug!("Signing hash with YubiKey (hash length: {} bytes)", hash.len());

        // Use slot 9a (authentication) which typically contains the code signing certificate
        let slot = SlotId::Authentication;

        // Create signature using the YubiKey's private key
        // The YubiKey will internally add PKCS#1 padding for RSA signatures
        let signature = self
            .yubikey
            .sign_data(slot, hash, AlgorithmId::Rsa2048)
            .map_err(|e| SigningError::SignatureError(
                format!("Failed to sign data with YubiKey: {}", e)
            ))?;

        log::info!("Successfully created digital signature");
        Ok(signature.to_vec())
    }

    /// List available certificates on the YubiKey for debugging
    pub fn list_certificates(&mut self) -> SigningResult<Vec<(SlotId, Certificate)>> {
        self.ensure_authenticated()?;
        
        let mut certificates = Vec::new();
        
        // Common PIV slots that might contain certificates
        let slots = [
            SlotId::Authentication,
            SlotId::Signature, 
            SlotId::KeyManagement,
            SlotId::CardAuthentication,
        ];

        for slot in slots {
            if let Ok(cert_data) = self.yubikey.fetch_object(ObjectId::from(slot)) {
                if let Ok(certificate) = Certificate::from_der(&cert_data) {
                    certificates.push((slot, certificate));
                }
            }
        }

        Ok(certificates)
    }

    /// Get YubiKey serial number for identification
    pub fn get_serial(&self) -> Option<u32> {
        self.yubikey.serial()
    }

    /// Get YubiKey version information
    pub fn get_version(&self) -> String {
        let version = self.yubikey.version();
        format!("{}.{}.{}", version.major, version.minor, version.patch)
    }

    /// Ensure the YubiKey is authenticated
    fn ensure_authenticated(&self) -> SigningResult<()> {
        if !self.authenticated {
            return Err(SigningError::AuthenticationError(
                "Not authenticated with YubiKey".to_string()
            ));
        }
        Ok(())
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
    fn test_slot_id_conversion() {
        assert_eq!(ObjectId::from(SlotId::Authentication), ObjectId::Authentication);
        assert_eq!(ObjectId::from(SlotId::Signature), ObjectId::Signature);
        assert_eq!(ObjectId::from(SlotId::KeyManagement), ObjectId::KeyManagement);
        assert_eq!(ObjectId::from(SlotId::CardAuthentication), ObjectId::CardAuthentication);
    }

    // Note: These tests require a physical YubiKey, so they're marked as ignored
    // Run with: cargo test -- --ignored
    
    #[test]
    #[ignore]
    fn test_yubikey_connection() {
        // This test requires a YubiKey with PIN "123456"
        let result = YubiKeyOperations::connect("123456");
        match result {
            Ok(mut ops) => {
                let version = ops.get_version();
                println!("YubiKey version: {}", version);
                
                if let Some(serial) = ops.get_serial() {
                    println!("YubiKey serial: {}", serial);
                }
            }
            Err(e) => {
                println!("YubiKey not available or wrong PIN: {}", e);
            }
        }
    }
    
    #[test]
    #[ignore]
    fn test_certificate_retrieval() {
        let mut ops = YubiKeyOperations::connect("123456").unwrap();
        let result = ops.get_certificate();
        
        match result {
            Ok(cert) => {
                println!("Certificate subject: {:?}", cert.tbs_certificate.subject);
            }
            Err(e) => {
                println!("Failed to get certificate: {}", e);
            }
        }
    }
}
            .yubikey
            .fetch_object(ObjectId::Authentication)
            .context("Failed to fetch certificate from YubiKey PIV slot 9a")?;

        // Parse the certificate
        let certificate = x509_cert::Certificate::from_der(&cert_data)
            .context("Failed to parse certificate from YubiKey")?;

        Ok(certificate)
    }

    /// Sign a hash using the private key in the YubiKey
    pub fn sign_hash(&mut self, hash: &[u8]) -> Result<Vec<u8>> {
        if !self.authenticated {
            anyhow::bail!("Not authenticated with YubiKey");
        }

        // Use slot 9a (authentication) which typically contains the code signing certificate
        let slot = SlotId::Authentication;

        // Create signature using the YubiKey's private key
        // The YubiKey will internally add PKCS#1 padding for RSA signatures
        let signature = self
            .yubikey
            .sign_data(slot, hash, AlgorithmId::Rsa2048)
            .context("Failed to sign data with YubiKey")?;

        Ok(signature.to_vec())
    }

    /// List available certificates on the YubiKey for debugging
    pub fn list_certificates(&mut self) -> Result<Vec<(SlotId, x509_cert::Certificate)>> {
        let mut certificates = Vec::new();

        // Common PIV slots that might contain certificates
        let slots = [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
            SlotId::CardAuthentication,
        ];

        for slot in slots {
            if let Ok(cert_data) = self.yubikey.fetch_object(ObjectId::from(slot)) {
                if let Ok(certificate) = x509_cert::Certificate::from_der(&cert_data) {
                    certificates.push((slot, certificate));
                }
            }
        }

        Ok(certificates)
    }

    /// Get YubiKey serial number for identification
    pub fn get_serial(&mut self) -> Result<Option<u32>> {
        Ok(self.yubikey.serial())
    }

    /// Get YubiKey version information
    pub fn get_version(&mut self) -> Result<String> {
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
