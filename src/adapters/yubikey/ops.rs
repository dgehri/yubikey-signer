//! `YubiKey` hardware PIV operations adapter.
//!
//! Provides hardware-specific PIV operations for signing and certificate retrieval.

use der::{Decode, Encode};
use yubikey::{piv::SlotId, YubiKey};

use crate::{
    domain::constants,
    domain::types::{PivPin, PivSlot},
    infra::error::{SigningError, SigningResult},
    services::authenticode, // for DigestInfo helper
    HashAlgorithm,
};

/// Convert u8 slot ID to `SlotId` enum
#[must_use]
pub fn u8_to_slot_id(slot: u8) -> SlotId {
    match slot {
        constants::PIV_SLOT_AUTHENTICATION => SlotId::Authentication,
        constants::PIV_SLOT_SIGNATURE => SlotId::Signature,
        constants::PIV_SLOT_KEY_MANAGEMENT => SlotId::KeyManagement,
        constants::PIV_SLOT_CARD_AUTHENTICATION => SlotId::CardAuthentication,
        _ => SlotId::Authentication, // Fallback
    }
}

/// Low-level `YubiKey` PIV operations.
pub struct YubiKeyOperations {
    yubikey: YubiKey,
    authenticated: bool,
}

impl YubiKeyOperations {
    /// Open a connection to the first available `YubiKey`.
    pub fn connect() -> SigningResult<Self> {
        let yubikey = YubiKey::open()
            .map_err(|e| SigningError::YubiKeyError(format!("Failed to open YubiKey: {e}")))?;
        Ok(Self {
            yubikey,
            authenticated: false,
        })
    }

    /// Verify PIN to unlock private key operations.
    pub fn authenticate(&mut self, pin: &PivPin) -> SigningResult<()> {
        self.yubikey
            .verify_pin(pin.as_bytes())
            .map_err(|e| SigningError::YubiKeyError(format!("PIN verification failed: {e}")))?;
        self.authenticated = true;
        Ok(())
    }

    /// Retrieve parsed X.509 certificate for the given slot.
    pub fn get_certificate(&mut self, slot: PivSlot) -> SigningResult<x509_cert::Certificate> {
        let der = self.get_certificate_der(slot)?;
        x509_cert::Certificate::from_der(&der).map_err(|e| {
            SigningError::CertificateError(format!("Failed to parse certificate: {e}"))
        })
    }

    /// Retrieve raw DER certificate bytes for the given slot.
    pub fn get_certificate_der(&mut self, slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.ensure_authenticated()?;
        self.fetch_certificate_der(slot.as_slot_id())
    }

    /// Sign a hash (or `DigestInfo` for RSA) residing in host memory using private key in slot.
    pub fn sign_hash(&mut self, hash: &[u8], slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.ensure_authenticated()?;
        self.perform_signing(slot.as_slot_id(), hash)
    }

    /// Device serial number.
    pub fn get_serial(&mut self) -> SigningResult<u32> {
        Ok(self.yubikey.serial().into())
    }

    /// Device firmware version string.
    pub fn get_version(&mut self) -> SigningResult<String> {
        let v = self.yubikey.version();
        Ok(format!("{}.{}.{}", v.major, v.minor, v.patch))
    }

    fn ensure_authenticated(&self) -> SigningResult<()> {
        if !self.authenticated {
            return Err(SigningError::YubiKeyError(
                "Not authenticated with YubiKey".into(),
            ));
        }
        Ok(())
    }

    fn fetch_certificate_der(&mut self, slot_id: SlotId) -> SigningResult<Vec<u8>> {
        match yubikey::Certificate::read(&mut self.yubikey, slot_id) {
            Ok(cert) => cert.cert.to_der().map_err(|e| {
                SigningError::YubiKeyError(format!("Failed to encode certificate to DER: {e}"))
            }),
            Err(e) => Err(SigningError::YubiKeyError(format!(
                "Failed to read certificate from slot {slot_id:?}: {e}"
            ))),
        }
    }

    fn perform_signing(&mut self, slot_id: SlotId, hash: &[u8]) -> SigningResult<Vec<u8>> {
        // Try ECDSA P-384
        if let Ok(sig) = yubikey::piv::sign_data(
            &mut self.yubikey,
            hash,
            yubikey::piv::AlgorithmId::EccP384,
            slot_id,
        ) {
            return Ok(sig.to_vec());
        }
        // Try ECDSA P-256
        if let Ok(sig) = yubikey::piv::sign_data(
            &mut self.yubikey,
            hash,
            yubikey::piv::AlgorithmId::EccP256,
            slot_id,
        ) {
            return Ok(sig.to_vec());
        }
        // Try raw RSA 2048
        if let Ok(sig) = yubikey::piv::sign_data(
            &mut self.yubikey,
            hash,
            yubikey::piv::AlgorithmId::Rsa2048,
            slot_id,
        ) {
            return Ok(sig.to_vec());
        }

        // Attempt RSA with DigestInfo wrapper
        let hash_algorithm = match hash.len() {
            32 => HashAlgorithm::Sha256,
            48 => HashAlgorithm::Sha384,
            64 => HashAlgorithm::Sha512,
            l => {
                return Err(SigningError::YubiKeyError(format!(
                    "Unsupported hash length: {l} bytes"
                )))
            }
        };
        let digest_info = authenticode::create_digest_info(hash, hash_algorithm)?;
        if let Ok(sig) = yubikey::piv::sign_data(
            &mut self.yubikey,
            &digest_info,
            yubikey::piv::AlgorithmId::Rsa2048,
            slot_id,
        ) {
            return Ok(sig.to_vec());
        }

        Err(SigningError::YubiKeyError(format!(
            "Failed to sign with slot {slot_id:?}: no supported algorithm worked"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_id_conversion_basic() {
        let s = u8_to_slot_id(constants::PIV_SLOT_SIGNATURE);
        matches!(s, SlotId::Signature);
    }
}
