//! `TimestampWorkflow`: orchestrates RFC3161 timestamp acquisition and application.
//!
//! Provides timestamp token acquisition and PKCS#7 integration.
//! Steps:
//! 1. Build RFC3161 request from CMS signature bytes (`TimestampRequestBuilder`)
//! 2. Send request via `TimestampClient` (existing multi-server client)
//! 3. Extract `TimeStampToken` (timestamp client already returns raw token bytes)
//! 4. Parse token into domain `TimestampToken`
//! 5. Apply token to existing PKCS#7 (`TimestampApplier`)

use crate::adapters::timestamp_http_client::{TimestampHttpClient, TimestampHttpConfig};
use crate::domain::pkcs7::Pkcs7SignedData;
use crate::services::timestamp::{TimestampClient, TimestampConfig};
use crate::services::{TimestampApplier, TimestampParserService, TimestampRequestBuilder};
use crate::{HashAlgorithm, SigningError, SigningResult};

pub struct TimestampWorkflow {
    hash_algorithm: HashAlgorithm,
    timestamp_client: TimestampClient,
    http_client: TimestampHttpClient,
}

impl TimestampWorkflow {
    #[must_use]
    pub fn new(hash_algorithm: HashAlgorithm, config: Option<&TimestampConfig>) -> Self {
        let (timestamp_client, http_client) = if let Some(c) = config {
            let client = TimestampClient::with_config(c.clone());
            let http_cfg: TimestampHttpConfig = c.into();
            (client, TimestampHttpClient::new(http_cfg))
        } else {
            let default_cfg = TimestampConfig::default();
            let client = TimestampClient::with_config(default_cfg.clone());
            let http_cfg: TimestampHttpConfig = (&default_cfg).into();
            (client, TimestampHttpClient::new(http_cfg))
        };
        Self {
            hash_algorithm,
            timestamp_client,
            http_client,
        }
    }

    #[must_use]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Obtain RFC3161 timestamp for given CMS signature bytes and apply to PKCS#7 structure.
    pub async fn timestamp_pkcs7(
        &self,
        pkcs7: &Pkcs7SignedData,
        cms_signature: &[u8],
    ) -> SigningResult<Pkcs7SignedData> {
        if cms_signature.is_empty() {
            return Err(SigningError::TimestampError(
                "Empty CMS signature for timestamping".into(),
            ));
        }
        // 1. Build request
        let req_builder = TimestampRequestBuilder::new();
        let ts_request = req_builder.build_request(cms_signature, self.hash_algorithm)?;
        log::debug!(
            "TimestampWorkflow: built TSRequest ({} bytes)",
            ts_request.len()
        );

        // 2. Send request via new HTTP adapter first. If it fails, fallback to timestamp client.
        let token_bytes = match self.http_client.post_request(&ts_request).await {
            Ok(resp) => resp,
            Err(e) => {
                log::warn!("HTTP adapter failed ({e}). Falling back to timestamp client");
                self.timestamp_client.get_timestamp(cms_signature).await?
            }
        };

        // 3. Parse & validate token imprint vs signature hash
        use sha2::{Digest, Sha256};
        let signature_hash = Sha256::digest(cms_signature).to_vec();
        let token = TimestampParserService::parse_and_validate(token_bytes, &signature_hash)
            .map_err(|e| {
                SigningError::TimestampError(format!("Failed to parse/validate token: {e}"))
            })?;

        // 4. Apply token
        let applier = TimestampApplier::new();
        let updated = applier
            .apply_timestamp(pkcs7, &token, &signature_hash)
            .map_err(|e| SigningError::TimestampError(format!("Failed to apply timestamp: {e}")))?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_workflow() {
        let wf = TimestampWorkflow::new(HashAlgorithm::Sha256, None);
        assert_eq!(wf.hash_algorithm(), HashAlgorithm::Sha256);
    }
}
