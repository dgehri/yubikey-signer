//! `YubiKey` hardware adapter modules.
//!
//! Provides comprehensive `YubiKey` integration including:
//! - PIV authentication and certificate management
//! - ECDSA signature generation with hardware keys
//! - Slot discovery and automatic configuration
//! - Bridge interfaces for high-level signing operations
//!
//! This module requires the `pcsc-backend` feature (enabled by default).

#[cfg(feature = "pcsc-backend")]
pub mod auth_bridge;

#[cfg(feature = "pcsc-backend")]
pub mod ops;
