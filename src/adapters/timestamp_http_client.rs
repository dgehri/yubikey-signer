//! Timestamp HTTP client adapter.
//! HTTP client adapter for RFC3161 timestamp authority requests.
//! Provides retry and failover over a list of timestamp servers.

use crate::domain::types::TimestampUrl;
use crate::infra::error::{SigningError, SigningResult};
use std::time::Duration;

/// Configuration for timestamp HTTP operations.
#[derive(Debug, Clone)]
pub struct TimestampHttpConfig {
    pub primary: TimestampUrl,
    pub fallbacks: Vec<TimestampUrl>,
    pub timeout: Duration,
    pub retries_per_server: usize,
    pub retry_delay: Duration,
}

impl TimestampHttpConfig {
    #[must_use]
    pub fn servers(&self) -> Vec<&TimestampUrl> {
        std::iter::once(&self.primary)
            .chain(self.fallbacks.iter())
            .collect()
    }
}

impl From<&crate::services::timestamp::TimestampConfig> for TimestampHttpConfig {
    fn from(cfg: &crate::services::timestamp::TimestampConfig) -> Self {
        Self {
            primary: cfg.primary_server.clone(),
            fallbacks: cfg.fallback_servers.clone(),
            timeout: cfg.timeout,
            retries_per_server: cfg.retry_attempts,
            retry_delay: cfg.retry_delay,
        }
    }
}

/// HTTP adapter performing RFC3161 POST exchanges.
pub struct TimestampHttpClient {
    cfg: TimestampHttpConfig,
    http: reqwest::Client,
}

impl TimestampHttpClient {
    /// Create a new client from config.
    #[must_use]
    pub fn new(cfg: TimestampHttpConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .user_agent("yubikey-signer/1.0")
            .build()
            .expect("reqwest client build");
        Self { cfg, http }
    }

    /// Attempt to obtain a timestamp response body for the given request DER.
    pub async fn post_request(&self, ts_request_der: &[u8]) -> SigningResult<Vec<u8>> {
        let mut last_err: Option<SigningError> = None;
        for (idx, server) in self.cfg.servers().iter().enumerate() {
            log::info!("timestamp server attempt {}: {}", idx + 1, server.as_str());
            match self.post_with_retries(server, ts_request_der).await {
                Ok(body) => return Ok(body),
                Err(e) => {
                    log::warn!("server {} failed: {}", server.as_str(), e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| SigningError::TimestampError("All servers failed".into())))
    }

    async fn post_with_retries(
        &self,
        server: &TimestampUrl,
        body: &[u8],
    ) -> SigningResult<Vec<u8>> {
        let mut last_err: Option<SigningError> = None;
        for attempt in 1..=self.cfg.retries_per_server {
            log::debug!(
                "timestamp http attempt {} of {} -> {}",
                attempt,
                self.cfg.retries_per_server,
                server.as_str()
            );
            match self.single_post(server, body).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < self.cfg.retries_per_server {
                        tokio::time::sleep(self.cfg.retry_delay).await;
                    }
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn single_post(&self, server: &TimestampUrl, body: &[u8]) -> SigningResult<Vec<u8>> {
        let resp = self
            .http
            .post(server.as_str())
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| SigningError::TimestampError(format!("HTTP error: {e}")))?;
        if !resp.status().is_success() {
            return Err(SigningError::TimestampError(format!(
                "HTTP {} from {}",
                resp.status(),
                server.as_str()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| SigningError::TimestampError(format!("Read body failed: {e}")))?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_servers_list() {
        let base = crate::services::timestamp::TimestampConfig::default();
        let cfg = TimestampHttpConfig::from(&base);
        assert!(!cfg.servers().is_empty());
    }
}
