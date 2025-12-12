//! Remote `YubiKey` signing client.
//!
//! Provides a client adapter that connects to a `yubikey-proxy` server
//! over HTTPS to perform signing operations remotely.

use super::protocol::{
    error_codes, ErrorResponse, GetCertificateRequest, GetCertificateResponse, SignRequest,
    SignResponse, StatusRequest, StatusResponse, PROTOCOL_VERSION,
};
use crate::domain::types::PivSlot;
use crate::infra::error::{SigningError, SigningResult};

/// Configuration for connecting to a remote `YubiKey` proxy.
#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    /// Base URL of the proxy server (e.g., `https://yubikey.example.com`).
    pub base_url: String,
    /// Bearer token for authentication.
    pub auth_token: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Whether to verify TLS certificates (should be true in production).
    pub verify_tls: bool,
}

impl RemoteSignerConfig {
    /// Create a new remote signer configuration.
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the proxy server
    /// * `auth_token` - Bearer token for authentication
    #[must_use]
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth_token: auth_token.into(),
            timeout_secs: 30,
            verify_tls: true,
        }
    }

    /// Set the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Disable TLS verification (for testing only!).
    #[must_use]
    pub fn with_insecure_tls(mut self) -> Self {
        self.verify_tls = false;
        self
    }
}

/// Remote `YubiKey` signing client.
///
/// Connects to a `yubikey-proxy` server to perform signing operations
/// on a remote `YubiKey` device.
pub struct RemoteSigner {
    config: RemoteSignerConfig,
    client: reqwest::Client,
}

impl RemoteSigner {
    /// Create a new remote signer client.
    ///
    /// # Arguments
    /// * `config` - Remote signer configuration
    ///
    /// # Errors
    /// Returns error if HTTP client creation fails.
    pub fn new(config: RemoteSignerConfig) -> SigningResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(|e| {
                SigningError::NetworkError(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self { config, client })
    }

    /// Check the status of the remote proxy and `YubiKey`.
    ///
    /// # Errors
    /// Returns error if the server is unreachable or returns an error.
    pub async fn check_status(&self) -> SigningResult<StatusResponse> {
        let url = format!("{}/api/v1/status", self.config.base_url);
        let request = StatusRequest {
            version: PROTOCOL_VERSION.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| SigningError::NetworkError(format!("Failed to connect to proxy: {e}")))?;

        self.handle_response(response).await
    }

    /// Retrieve the certificate from a PIV slot on the remote `YubiKey`.
    ///
    /// # Arguments
    /// * `slot` - PIV slot to retrieve certificate from
    ///
    /// # Errors
    /// Returns error if the certificate cannot be retrieved.
    pub async fn get_certificate(&self, slot: PivSlot) -> SigningResult<Vec<u8>> {
        let url = format!("{}/api/v1/certificate", self.config.base_url);
        let request = GetCertificateRequest::new(slot.as_u8());

        let response = self
            .client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| SigningError::NetworkError(format!("Failed to connect to proxy: {e}")))?;

        let cert_response: GetCertificateResponse = self.handle_response(response).await?;

        cert_response.decode_certificate().map_err(|e| {
            SigningError::CertificateError(format!("Failed to decode certificate: {e}"))
        })
    }

    /// Sign a hash digest using the remote `YubiKey`.
    ///
    /// # Arguments
    /// * `digest` - Hash digest to sign
    /// * `slot` - PIV slot containing the signing key
    ///
    /// # Errors
    /// Returns error if signing fails.
    pub async fn sign_hash(&self, digest: &[u8], slot: PivSlot) -> SigningResult<Vec<u8>> {
        let url = format!("{}/api/v1/sign", self.config.base_url);
        let request = SignRequest::new(digest, slot.as_u8()).with_nonce();

        let response = self
            .client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| SigningError::NetworkError(format!("Failed to connect to proxy: {e}")))?;

        let sign_response: SignResponse = self.handle_response(response).await?;

        sign_response
            .decode_signature()
            .map_err(|e| SigningError::SignatureError(format!("Failed to decode signature: {e}")))
    }

    /// Handle HTTP response and parse JSON body.
    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> SigningResult<T> {
        let status = response.status();

        if status.is_success() {
            response
                .json()
                .await
                .map_err(|e| SigningError::NetworkError(format!("Failed to parse response: {e}")))
        } else {
            // Try to parse error response
            let error_text = response.text().await.unwrap_or_default();

            if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&error_text) {
                Err(Self::map_error_code(&error_response))
            } else {
                Err(SigningError::NetworkError(format!(
                    "Server error {status}: {error_text}"
                )))
            }
        }
    }

    /// Map error codes to appropriate `SigningError` variants.
    fn map_error_code(error: &ErrorResponse) -> SigningError {
        match error.error_code.as_str() {
            error_codes::AUTH_FAILED => SigningError::ConfigurationError(format!(
                "Authentication failed: {}",
                error.message
            )),
            error_codes::YUBIKEY_NOT_FOUND => {
                SigningError::YubiKeyError(format!("YubiKey not found: {}", error.message))
            }
            error_codes::NOT_AUTHENTICATED => {
                SigningError::YubiKeyError(format!("YubiKey not authenticated: {}", error.message))
            }
            error_codes::INVALID_SLOT => {
                SigningError::ValidationError(format!("Invalid slot: {}", error.message))
            }
            error_codes::SIGNING_FAILED => {
                SigningError::SignatureError(format!("Signing failed: {}", error.message))
            }
            error_codes::CERT_NOT_FOUND => {
                SigningError::CertificateError(format!("Certificate not found: {}", error.message))
            }
            error_codes::RATE_LIMITED => {
                SigningError::NetworkError(format!("Rate limited: {}", error.message))
            }
            _ => SigningError::NetworkError(format!(
                "Remote error [{}]: {}",
                error.error_code, error.message
            )),
        }
    }
}

/// Remote `YubiKey` operations adapter.
///
/// Implements the same interface as `YubiKeyOperations` but delegates
/// to a remote proxy server. This allows seamless switching between
/// local and remote `YubiKey` access.
pub struct RemoteYubiKeyOperations {
    client: RemoteSigner,
    slot: PivSlot,
}

impl RemoteYubiKeyOperations {
    /// Create a new remote `YubiKey` operations instance.
    ///
    /// # Arguments
    /// * `config` - Remote signer configuration
    /// * `slot` - Default PIV slot to use
    ///
    /// # Errors
    /// Returns error if client creation fails.
    pub fn new(config: RemoteSignerConfig, slot: PivSlot) -> SigningResult<Self> {
        let client = RemoteSigner::new(config)?;
        Ok(Self { client, slot })
    }

    /// Verify the remote connection and `YubiKey` availability.
    ///
    /// # Errors
    /// Returns error if the proxy is unreachable or `YubiKey` is not ready.
    pub async fn verify_connection(&self) -> SigningResult<()> {
        let status = self.client.check_status().await?;

        if !status.yubikey_ready {
            return Err(SigningError::YubiKeyError(
                "Remote YubiKey is not ready".to_string(),
            ));
        }

        log::info!(
            "Connected to remote YubiKey proxy (serial: {:?}, firmware: {:?})",
            status.serial,
            status.firmware_version
        );

        Ok(())
    }

    /// Get the certificate DER bytes from the remote `YubiKey`.
    ///
    /// # Errors
    /// Returns error if certificate retrieval fails.
    pub async fn get_certificate_der(&self) -> SigningResult<Vec<u8>> {
        self.client.get_certificate(self.slot).await
    }

    /// Sign a hash using the remote `YubiKey`.
    ///
    /// # Arguments
    /// * `hash` - Hash digest to sign
    ///
    /// # Errors
    /// Returns error if signing fails.
    pub async fn sign_hash(&self, hash: &[u8]) -> SigningResult<Vec<u8>> {
        self.client.sign_hash(hash, self.slot).await
    }

    /// Get the configured PIV slot.
    #[must_use]
    pub fn slot(&self) -> PivSlot {
        self.slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = RemoteSignerConfig::new("https://proxy.example.com", "secret-token")
            .with_timeout(60)
            .with_insecure_tls();

        assert_eq!(config.base_url, "https://proxy.example.com");
        assert_eq!(config.auth_token, "secret-token");
        assert_eq!(config.timeout_secs, 60);
        assert!(!config.verify_tls);
    }
}
