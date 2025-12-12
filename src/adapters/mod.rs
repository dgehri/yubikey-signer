//! Adapter layer modules for external system integration.
//!
//! Provides adapters for:
//! - `YubiKey` hardware operations and PIV authentication
//! - Remote `YubiKey` signing proxy (client and server)
//! - HTTP timestamp authority communication with retry logic
//! - OpenSSL cryptographic operations and certificate handling
//! - System time and random number generation
//! - Direct USB CCID transport (optional, no pcscd required)
//! - Unified backend abstraction for multiple transport types

pub mod backend;

#[cfg(feature = "direct-usb")]
pub mod ccid;

pub mod remote;
pub mod timestamp_http_client;
pub mod yubikey;
