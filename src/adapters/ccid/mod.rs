//! Direct USB CCID transport for `YubiKey` communication.
//!
//! This module provides direct USB access to `YubiKey` devices using the CCID
//! (Chip Card Interface Device) protocol, eliminating the need for pcscd.
//!
//! # Architecture
//!
//! The CCID protocol uses USB bulk transfers:
//! - Bulk OUT endpoint: Host sends commands (APDUs) to the card
//! - Bulk IN endpoint: Card sends responses back to the host
//!
//! Each CCID message has a 10-byte header followed by optional data.

#[cfg(feature = "direct-usb")]
pub mod transport;

#[cfg(feature = "direct-usb")]
pub mod piv;

#[cfg(feature = "direct-usb")]
pub use transport::CcidTransport;

#[cfg(feature = "direct-usb")]
pub use piv::DirectPivOperations;
