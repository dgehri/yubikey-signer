//! Remote `YubiKey` signing proxy server.
//!
//! Provides an HTTPS server that exposes `YubiKey` signing operations
//! via a REST API. This server runs on the machine with the physical
//! `YubiKey` attached and allows remote clients to request signatures.
//!
//! # Backend Selection
//!
//! The server supports multiple backends:
//! - **Direct USB** (default when available): No pcscd required, ideal for
//!   embedded systems and routers
//! - **PC/SC**: Traditional smart card interface, requires pcscd on Linux

use super::protocol::{
    error_codes, ErrorResponse, GetCertificateRequest, GetCertificateResponse, SignRequest,
    SignResponse, StatusResponse, PROTOCOL_VERSION,
};
use crate::adapters::backend::{connect_best_backend, BackendType, YubiKeyBackend};
use crate::domain::types::{PivPin, PivSlot};
use crate::infra::error::{SigningError, SigningResult};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyServerConfig {
    /// Address to bind to (e.g., "0.0.0.0:8443").
    pub bind_address: String,
    /// Bearer token for client authentication.
    pub auth_token: String,
    /// PIV PIN for `YubiKey` authentication.
    pub pin: PivPin,
    /// Maximum requests per minute per client (rate limiting).
    pub rate_limit_rpm: u32,
    /// TLS certificate path (PEM format).
    pub tls_cert_path: Option<String>,
    /// TLS private key path (PEM format).
    pub tls_key_path: Option<String>,
}

impl ProxyServerConfig {
    /// Create a new proxy server configuration.
    ///
    /// # Arguments
    /// * `bind_address` - Address to bind to
    /// * `auth_token` - Bearer token for authentication
    /// * `pin` - `YubiKey` PIN
    #[must_use]
    pub fn new(
        bind_address: impl Into<String>,
        auth_token: impl Into<String>,
        pin: PivPin,
    ) -> Self {
        Self {
            bind_address: bind_address.into(),
            auth_token: auth_token.into(),
            pin,
            rate_limit_rpm: 60,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    /// Configure TLS with certificate and key paths.
    #[must_use]
    pub fn with_tls(mut self, cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(key_path.into());
        self
    }

    /// Set the rate limit (requests per minute).
    #[must_use]
    pub fn with_rate_limit(mut self, rpm: u32) -> Self {
        self.rate_limit_rpm = rpm;
        self
    }
}

/// Shared state for the proxy server handlers.
pub struct ProxyState {
    /// `YubiKey` backend instance (locked for thread safety).
    backend: Mutex<Box<dyn YubiKeyBackend>>,
    /// Backend type in use.
    backend_type: BackendType,
    /// Expected authentication token.
    auth_token: String,
    /// Server start time for uptime reporting.
    start_time: Instant,
    /// PIV slots with available certificates.
    available_slots: Vec<PivSlot>,
}

impl ProxyState {
    /// Create new proxy state with an authenticated `YubiKey` backend.
    ///
    /// # Arguments
    /// * `backend` - Authenticated `YubiKey` backend
    /// * `auth_token` - Expected bearer token
    /// * `available_slots` - Slots with certificates
    #[must_use]
    pub fn new(
        backend: Box<dyn YubiKeyBackend>,
        auth_token: String,
        available_slots: Vec<PivSlot>,
    ) -> Self {
        let backend_type = backend.backend_type();
        Self {
            backend: Mutex::new(backend),
            backend_type,
            auth_token,
            start_time: Instant::now(),
            available_slots,
        }
    }

    /// Validate the authentication token.
    fn validate_auth(&self, token: &str) -> bool {
        // Constant-time comparison to prevent timing attacks
        use std::cmp::min;
        let expected = self.auth_token.as_bytes();
        let provided = token.as_bytes();

        if expected.len() != provided.len() {
            return false;
        }

        let mut result = 0u8;
        for i in 0..min(expected.len(), provided.len()) {
            result |= expected[i] ^ provided[i];
        }
        result == 0
    }

    /// Get the backend type in use.
    #[must_use]
    pub fn backend_type(&self) -> BackendType {
        self.backend_type
    }
}

/// Handle the status endpoint.
///
/// # Arguments
/// * `state` - Shared proxy state
///
/// # Returns
/// Status response with `YubiKey` and server information.
pub fn handle_status(state: &Arc<ProxyState>) -> StatusResponse {
    let mut backend = state.backend.lock().unwrap();

    let serial = backend.get_serial().ok();
    let firmware_version = backend.get_version().ok();

    StatusResponse {
        version: PROTOCOL_VERSION.to_string(),
        yubikey_ready: true,
        serial,
        firmware_version,
        available_slots: state
            .available_slots
            .iter()
            .map(|s| format!("{s}"))
            .collect(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    }
}

/// Handle the certificate retrieval endpoint.
///
/// # Arguments
/// * `state` - Shared proxy state
/// * `request` - Certificate request
///
/// # Returns
/// Certificate response or error.
pub fn handle_get_certificate(
    state: &Arc<ProxyState>,
    request: &GetCertificateRequest,
) -> Result<GetCertificateResponse, ErrorResponse> {
    // Validate protocol version
    if request.version != PROTOCOL_VERSION {
        return Err(ErrorResponse::new(
            error_codes::VERSION_MISMATCH,
            format!(
                "Protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, request.version
            ),
        ));
    }

    // Parse slot
    let slot = parse_slot(&request.slot)?;

    // Get certificate
    let mut backend = state.backend.lock().unwrap();
    let cert_der = backend.get_certificate_der(slot).map_err(|e| {
        ErrorResponse::new(
            error_codes::CERT_NOT_FOUND,
            format!("Failed to get certificate: {e}"),
        )
    })?;

    Ok(GetCertificateResponse::new(&cert_der))
}

/// Handle the signing endpoint.
///
/// # Arguments
/// * `state` - Shared proxy state
/// * `request` - Sign request
///
/// # Returns
/// Sign response or error.
pub fn handle_sign(
    state: &Arc<ProxyState>,
    request: &SignRequest,
) -> Result<SignResponse, ErrorResponse> {
    // Validate protocol version
    if request.version != PROTOCOL_VERSION {
        return Err(ErrorResponse::new(
            error_codes::VERSION_MISMATCH,
            format!(
                "Protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, request.version
            ),
        ));
    }

    // Parse slot
    let slot = parse_slot(&request.slot)?;

    // Decode digest
    let digest = request.decode_digest().map_err(|e| {
        ErrorResponse::new(
            error_codes::BAD_REQUEST,
            format!("Invalid digest encoding: {e}"),
        )
    })?;

    // Validate digest size
    if digest.len() < 20 || digest.len() > 64 {
        return Err(ErrorResponse::new(
            error_codes::BAD_REQUEST,
            format!(
                "Invalid digest size: {} bytes (expected 20-64)",
                digest.len()
            ),
        ));
    }

    // Perform signing
    let mut backend = state.backend.lock().unwrap();
    let signature = backend.sign_hash(&digest, slot).map_err(|e| {
        ErrorResponse::new(error_codes::SIGNING_FAILED, format!("Signing failed: {e}"))
    })?;

    log::info!(
        "Signature produced: {} bytes, first 4 bytes: {:02X?}",
        signature.len(),
        &signature[..4.min(signature.len())]
    );

    Ok(SignResponse::new(&signature, request.nonce.clone()))
}

/// Parse a slot string to `PivSlot`.
fn parse_slot(slot_str: &str) -> Result<PivSlot, ErrorResponse> {
    let slot_byte = u8::from_str_radix(slot_str, 16).map_err(|_| {
        ErrorResponse::new(
            error_codes::INVALID_SLOT,
            format!("Invalid slot format: {slot_str}"),
        )
    })?;

    PivSlot::new(slot_byte)
        .map_err(|e| ErrorResponse::new(error_codes::INVALID_SLOT, format!("Invalid slot: {e}")))
}

/// Initialize the proxy server.
///
/// This function connects to the `YubiKey` using the best available backend,
/// authenticates with the PIN, and discovers available certificates.
///
/// On systems without pcscd, the direct USB backend will be used automatically
/// if the `direct-usb` feature is enabled.
///
/// # Arguments
/// * `config` - Proxy server configuration
///
/// # Returns
/// Initialized proxy state ready for serving requests.
///
/// # Errors
/// Returns error if `YubiKey` connection or authentication fails.
pub fn initialize_proxy(config: &ProxyServerConfig) -> SigningResult<Arc<ProxyState>> {
    log::info!("Connecting to YubiKey (auto-selecting backend)...");
    let mut backend = connect_best_backend()?;

    log::info!("Using {} backend", backend.backend_type());

    log::info!("Authenticating with PIN...");
    backend.authenticate(&config.pin)?;

    // Discover available slots
    let mut available_slots = Vec::new();
    for slot_id in [0x9a, 0x9c, 0x9d, 0x9e] {
        if let Ok(slot) = PivSlot::new(slot_id) {
            if backend.get_certificate_der(slot).is_ok() {
                available_slots.push(slot);
                log::info!("Found certificate in slot {slot}");
            }
        }
    }

    if available_slots.is_empty() {
        return Err(SigningError::CertificateError(
            "No certificates found in YubiKey PIV slots".to_string(),
        ));
    }

    let serial = backend.get_serial().unwrap_or(0);
    let version = backend.get_version().unwrap_or_default();
    log::info!("YubiKey ready: serial={serial}, firmware={version}");

    Ok(Arc::new(ProxyState::new(
        backend,
        config.auth_token.clone(),
        available_slots,
    )))
}

/// Extract bearer token from Authorization header value.
///
/// # Arguments
/// * `auth_header` - Full Authorization header value
///
/// # Returns
/// The token if present and properly formatted, None otherwise.
#[must_use]
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
}

/// Validate authentication for an incoming request.
///
/// # Arguments
/// * `state` - Shared proxy state
/// * `auth_header` - Authorization header value
///
/// # Returns
/// Ok if authenticated, Err with error response otherwise.
pub fn validate_request_auth(
    state: &Arc<ProxyState>,
    auth_header: Option<&str>,
) -> Result<(), ErrorResponse> {
    let token = auth_header.and_then(extract_bearer_token).ok_or_else(|| {
        ErrorResponse::new(
            error_codes::AUTH_FAILED,
            "Missing or invalid Authorization header",
        )
    })?;

    if !state.validate_auth(token) {
        return Err(ErrorResponse::new(
            error_codes::AUTH_FAILED,
            "Invalid authentication token",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("bearer xyz789"), Some("xyz789"));
        assert_eq!(extract_bearer_token("Basic auth"), None);
        assert_eq!(extract_bearer_token(""), None);
    }

    #[test]
    fn test_parse_slot() {
        assert!(parse_slot("9a").is_ok());
        assert!(parse_slot("9c").is_ok());
        assert!(parse_slot("9d").is_ok());
        assert!(parse_slot("9e").is_ok());
        assert!(parse_slot("ff").is_err());
        assert!(parse_slot("invalid").is_err());
    }
}
