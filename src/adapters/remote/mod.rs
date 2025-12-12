//! Remote `YubiKey` signing proxy adapter.
//!
//! Provides the ability to connect to a remote `yubikey-proxy` server
//! that hosts the physical `YubiKey`, allowing signing operations
//! over HTTPS through firewalls and Cloudflare tunnels.

pub mod client;
pub mod protocol;

#[cfg(feature = "proxy-server")]
pub mod server;
