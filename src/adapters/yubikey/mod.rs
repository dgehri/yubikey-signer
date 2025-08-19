//! `YubiKey` hardware adapter modules.
//!
//! Provides comprehensive `YubiKey` integration including:
//! - PIV authentication and certificate management
//! - ECDSA signature generation with hardware keys
//! - Slot discovery and automatic configuration
//! - Bridge interfaces for high-level signing operations

pub mod auth_bridge;
pub mod ops;
