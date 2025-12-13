//! Unified `YubiKey` backend trait for multiple transport implementations.
//!
//! This module defines a common interface for `YubiKey` operations that can be
//! implemented by different backends:
//! - PC/SC backend (requires pcscd on Linux) - feature `pcsc-backend`
//! - Direct USB/CCID backend (no pcscd required) - feature `direct-usb`

use crate::domain::types::{PivPin, PivSlot};
use crate::infra::error::SigningResult;

// SigningError is only used when no backend features are enabled
#[cfg(not(any(feature = "pcsc-backend", feature = "direct-usb")))]
use crate::infra::error::SigningError;

/// Backend implementation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// PC/SC backend using the `yubikey` crate (requires pcscd).
    #[cfg(feature = "pcsc-backend")]
    Pcsc,
    /// Direct USB backend using CCID protocol (no pcscd required).
    #[cfg(feature = "direct-usb")]
    DirectUsb,
}

impl std::fmt::Display for BackendType {
    #[allow(unreachable_code)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "pcsc-backend")]
        if matches!(self, Self::Pcsc) {
            return write!(f, "PC/SC");
        }
        #[cfg(feature = "direct-usb")]
        if matches!(self, Self::DirectUsb) {
            return write!(f, "Direct USB");
        }
        // This is unreachable when any backend feature is enabled,
        // but needed when building remote-only (no backend features)
        write!(f, "Unknown")
    }
}

/// Unified `YubiKey` operations trait.
///
/// Provides a common interface for `YubiKey` PIV operations regardless of
/// the underlying transport mechanism.
pub trait YubiKeyBackend: Send {
    /// Get the backend type.
    fn backend_type(&self) -> BackendType;

    /// Authenticate with the `YubiKey` using the PIV PIN.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIV PIN
    ///
    /// # Errors
    ///
    /// Returns error if authentication fails.
    fn authenticate(&mut self, pin: &PivPin) -> SigningResult<()>;

    /// Get the raw DER-encoded certificate from a slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot containing the certificate
    ///
    /// # Errors
    ///
    /// Returns error if certificate retrieval fails.
    fn get_certificate_der(&mut self, slot: PivSlot) -> SigningResult<Vec<u8>>;

    /// Sign a hash using the private key in the specified slot.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash bytes to sign
    /// * `slot` - The PIV slot containing the signing key
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    fn sign_hash(&mut self, hash: &[u8], slot: PivSlot) -> SigningResult<Vec<u8>>;

    /// Get the device serial number.
    ///
    /// # Errors
    ///
    /// Returns error if serial cannot be retrieved.
    fn get_serial(&mut self) -> SigningResult<u32>;

    /// Get the device firmware version.
    ///
    /// # Errors
    ///
    /// Returns error if version cannot be retrieved.
    fn get_version(&mut self) -> SigningResult<String>;
}

/// Connect to a `YubiKey` using the best available backend.
///
/// On platforms with direct USB support enabled, this will first try the
/// direct USB backend (no pcscd required), then fall back to PC/SC.
///
/// # Errors
///
/// Returns error if no `YubiKey` can be found with any backend.
pub fn connect_best_backend() -> SigningResult<Box<dyn YubiKeyBackend>> {
    // Try direct USB first if available (preferred - no pcscd needed)
    #[cfg(feature = "direct-usb")]
    {
        log::info!("Trying direct USB backend...");
        match crate::adapters::ccid::DirectPivOperations::connect() {
            Ok(ops) => {
                log::info!("Connected via direct USB (no pcscd required)");
                return Ok(Box::new(DirectUsbBackend(ops)));
            }
            Err(e) => {
                log::debug!("Direct USB failed: {e}");
                #[cfg(feature = "pcsc-backend")]
                {
                    log::debug!("Falling back to PC/SC");
                }
                #[cfg(not(feature = "pcsc-backend"))]
                {
                    return Err(e);
                }
            }
        }
    }

    // Fall back to PC/SC if available
    #[cfg(feature = "pcsc-backend")]
    {
        log::info!("Trying PC/SC backend...");
        let ops = crate::adapters::yubikey::ops::YubiKeyOperations::connect()?;
        log::info!("Connected via PC/SC");
        Ok(Box::new(PcscBackend(ops)))
    }

    #[cfg(not(any(feature = "pcsc-backend", feature = "direct-usb")))]
    {
        Err(SigningError::YubiKeyError(
            "No YubiKey backend available. Enable 'pcsc-backend' or 'direct-usb' feature."
                .to_string(),
        ))
    }
}

/// Connect to a `YubiKey` using a specific backend.
///
/// # Arguments
///
/// * `backend_type` - The backend type to use
///
/// # Errors
///
/// Returns error if connection fails.
#[allow(unreachable_code, unused_variables, clippy::needless_return)]
pub fn connect_with_backend(backend_type: BackendType) -> SigningResult<Box<dyn YubiKeyBackend>> {
    #[cfg(feature = "pcsc-backend")]
    if matches!(backend_type, BackendType::Pcsc) {
        let ops = crate::adapters::yubikey::ops::YubiKeyOperations::connect()?;
        return Ok(Box::new(PcscBackend(ops)));
    }
    #[cfg(feature = "direct-usb")]
    if matches!(backend_type, BackendType::DirectUsb) {
        let ops = crate::adapters::ccid::DirectPivOperations::connect()?;
        return Ok(Box::new(DirectUsbBackend(ops)));
    }
    // Fallback error when no matching backend or no backend features enabled
    #[cfg(not(any(feature = "pcsc-backend", feature = "direct-usb")))]
    return Err(SigningError::YubiKeyError(
        "No YubiKey backend available. Enable 'pcsc-backend' or 'direct-usb' feature.".to_string(),
    ));

    // When a backend feature is enabled but no match (should be unreachable)
    #[cfg(any(feature = "pcsc-backend", feature = "direct-usb"))]
    unreachable!("Invalid backend type for enabled features")
}

/// PC/SC backend wrapper.
#[cfg(feature = "pcsc-backend")]
struct PcscBackend(crate::adapters::yubikey::ops::YubiKeyOperations);

#[cfg(feature = "pcsc-backend")]
impl YubiKeyBackend for PcscBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Pcsc
    }

    fn authenticate(&mut self, pin: &PivPin) -> SigningResult<()> {
        self.0.authenticate(pin)
    }

    fn get_certificate_der(&mut self, slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.0.get_certificate_der(slot)
    }

    fn sign_hash(&mut self, hash: &[u8], slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.0.sign_hash(hash, slot)
    }

    fn get_serial(&mut self) -> SigningResult<u32> {
        self.0.get_serial()
    }

    fn get_version(&mut self) -> SigningResult<String> {
        self.0.get_version()
    }
}

/// Direct USB backend wrapper.
#[cfg(feature = "direct-usb")]
struct DirectUsbBackend(crate::adapters::ccid::DirectPivOperations);

#[cfg(feature = "direct-usb")]
impl YubiKeyBackend for DirectUsbBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::DirectUsb
    }

    fn authenticate(&mut self, pin: &PivPin) -> SigningResult<()> {
        self.0.authenticate(pin)
    }

    fn get_certificate_der(&mut self, slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.0.get_certificate_der(slot)
    }

    fn sign_hash(&mut self, hash: &[u8], slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.0.sign_hash(hash, slot)
    }

    fn get_serial(&mut self) -> SigningResult<u32> {
        self.0.get_serial()
    }

    fn get_version(&mut self) -> SigningResult<String> {
        self.0.get_version()
    }
}
