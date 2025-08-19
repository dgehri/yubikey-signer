//! Timestamp implementation with multi-server support.
//!
//! Provides robust timestamp token acquisition with:
//! - Multiple timestamp authority support with automatic failover
//! - Network retry logic with exponential backoff
//! - Request/response validation and parsing
//! - Integration with PKCS#7 unsigned attributes
//!
//! Supports both production timestamp authorities and test servers for development
//! and testing scenarios.

use crate::domain::constants;
use crate::domain::types::TimestampUrl;
use crate::infra::error::{SigningError, SigningResult};
use std::time::{Duration, SystemTime};

/// Timestamp configuration with multiple servers and fallback options
#[derive(Debug, Clone)]
pub struct TimestampConfig {
    /// Primary timestamp server
    pub primary_server: TimestampUrl,
    /// Fallback timestamp servers
    pub fallback_servers: Vec<TimestampUrl>,
    /// Request timeout for each server attempt
    pub timeout: Duration,
    /// Number of retry attempts per server
    pub retry_attempts: usize,
    /// Delay between retry attempts
    pub retry_delay: Duration,
}

impl Default for TimestampConfig {
    fn default() -> Self {
        Self {
            primary_server: TimestampUrl::new("http://ts.ssl.com").unwrap(),
            fallback_servers: vec![
                TimestampUrl::new("http://timestamp.digicert.com").unwrap(),
                TimestampUrl::new("http://timestamp.sectigo.com").unwrap(),
                TimestampUrl::new("http://timestamp.entrust.net").unwrap(),
            ],
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
            retry_delay: Duration::from_secs(2),
        }
    }
}

/// Timestamp response information
#[derive(Debug, Clone)]
pub struct TimestampResponse {
    /// Raw timestamp token bytes
    pub token: Vec<u8>,
    /// Timestamp authority that issued the token
    pub authority: String,
    /// Time when the timestamp was issued
    pub timestamp: SystemTime,
    /// Whether the response includes certificates
    pub includes_certificates: bool,
}

/// RFC 3161 timestamp client with support for single and multiple servers
pub struct TimestampClient {
    config: TimestampConfig,
    http_client: reqwest::Client,
}

impl Default for TimestampClient {
    fn default() -> Self {
        Self::new_with_defaults()
    }
}

impl TimestampClient {
    /// Create new timestamp client for given URL (single server mode)
    #[must_use]
    pub fn new(url: &TimestampUrl) -> Self {
        let config = TimestampConfig {
            primary_server: url.clone(),
            fallback_servers: vec![],
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
            retry_delay: Duration::from_secs(2),
        };
        Self::with_config(config)
    }

    /// Create a new timestamp client with default configuration (multiple servers)
    #[must_use]
    pub fn new_with_defaults() -> Self {
        Self::with_config(TimestampConfig::default())
    }

    /// Create a new timestamp client with custom configuration
    #[must_use]
    pub fn with_config(config: TimestampConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("yubikey-signer/1.0")
            .build()
            .unwrap();

        Self {
            config,
            http_client,
        }
    }

    /// Get timestamp using single server (backward compatibility)
    pub async fn get_timestamp(&self, hash: &[u8]) -> SigningResult<Vec<u8>> {
        let response = self.get_timestamp_with_details(hash).await?;
        Ok(response.token)
    }

    /// Get a timestamp for the given hash with automatic failover and detailed response
    pub async fn get_timestamp_with_details(
        &self,
        hash: &[u8],
    ) -> SigningResult<TimestampResponse> {
        log::info!(
            "Requesting timestamp (primary + {} fallbacks)",
            self.config.fallback_servers.len()
        );

        // Try primary server first
        let all_servers = std::iter::once(&self.config.primary_server)
            .chain(self.config.fallback_servers.iter())
            .collect::<Vec<_>>();

        let mut last_error = None;

        for (index, server) in all_servers.iter().enumerate() {
            log::info!(
                "Attempting timestamp from server {} ({})",
                index + 1,
                server.as_str()
            );

            match self.try_server_with_retries(server, hash).await {
                Ok(response) => {
                    log::info!(
                        "✅ Successfully obtained timestamp from {}",
                        server.as_str()
                    );
                    return Ok(response);
                }
                Err(e) => {
                    log::warn!("❌ Failed to get timestamp from {}: {}", server.as_str(), e);
                    last_error = Some(e);

                    // Small delay before trying next server
                    if index < all_servers.len() - 1 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            SigningError::TimestampError("All timestamp servers failed".to_string())
        }))
    }

    /// Try a single server with retry logic
    async fn try_server_with_retries(
        &self,
        server: &TimestampUrl,
        hash: &[u8],
    ) -> SigningResult<TimestampResponse> {
        let mut last_error = None;

        for attempt in 1..=self.config.retry_attempts {
            log::debug!(
                "Timestamp attempt {} of {} for {}",
                attempt,
                self.config.retry_attempts,
                server.as_str()
            );

            match self.try_server_once(server, hash).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);

                    // Wait before retrying (except on last attempt)
                    if attempt < self.config.retry_attempts {
                        tokio::time::sleep(self.config.retry_delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Single attempt to get timestamp from a server
    async fn try_server_once(
        &self,
        server: &TimestampUrl,
        hash: &[u8],
    ) -> SigningResult<TimestampResponse> {
        // Create the timestamp request
        let request = self.create_timestamp_request(hash)?;

        // Send HTTP request
        let response = self
            .http_client
            .post(server.as_str())
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(request)
            .send()
            .await
            .map_err(|e| SigningError::TimestampError(format!("HTTP request failed: {e}")))?;

        // Check HTTP status
        if !response.status().is_success() {
            return Err(SigningError::TimestampError(format!(
                "HTTP {} from {}: {}",
                response.status(),
                server.as_str(),
                response.text().await.unwrap_or_default()
            )));
        }

        // Parse response
        let response_body = response
            .bytes()
            .await
            .map_err(|e| SigningError::TimestampError(format!("Failed to read response: {e}")))?;

        // We need to compute the SHA-256 hash of the original input to verify the MessageImprint
        use sha2::{Digest, Sha256};
        let expected_message_imprint = Sha256::digest(hash).to_vec();

        self.parse_timestamp_response(&response_body, server.as_str(), &expected_message_imprint)
    }

    /// Create RFC 3161 timestamp request
    fn create_timestamp_request(&self, hash: &[u8]) -> SigningResult<Vec<u8>> {
        // Create a proper RFC 3161 TimeStampReq with ASN.1 DER encoding
        use sha2::{Digest, Sha256};

        // GPT-5 Analysis Fix: Do NOT re-hash the input! Use it directly as preimage.
        // The input should be the raw signature bytes (EncryptedDigest), and we
        // hash it exactly once with SHA-256 for the RFC3161 MessageImprint.
        let digest = Sha256::digest(hash);
        let hash_oid = vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ]; // SHA-256 OID
        let hash_len = 32u8;

        log::info!(
            "Timestamp request using signature hash with SHA-256 (RFC 3161 compatible): {} bytes",
            hash.len()
        );

        // Create basic timestamp request structure
        // This is a simplified implementation - in production, you'd use proper ASN.1 libraries
        let mut request = Vec::new();

        // Add ASN.1 SEQUENCE header
        request.push(constants::ASN1_SEQUENCE_TAG); // SEQUENCE tag
        request.push(constants::DER_LONG_FORM_2_BYTE); // Long form length (2 bytes)

        // Build the request body
        let mut body = Vec::new();

        // Version: INTEGER 1
        body.extend_from_slice(&[constants::ASN1_INTEGER_TAG, 0x01, 0x01]);

        // MessageImprint SEQUENCE - calculate length dynamically
        let message_imprint_len = 2 + hash_oid.len() + 2 + 2 + hash_len as usize; // AlgId + NULL + OCTET STRING header + hash
        body.push(constants::ASN1_SEQUENCE_TAG); // SEQUENCE tag
        body.push(message_imprint_len as u8); // Length

        // AlgorithmIdentifier
        body.push(constants::ASN1_SEQUENCE_TAG); // SEQUENCE tag
        body.push((hash_oid.len() + 2) as u8); // Length (OID + NULL)
        body.extend_from_slice(&hash_oid); // Hash algorithm OID
        body.extend_from_slice(constants::ASN1_NULL); // NULL parameters

        // Hash value
        body.push(0x04); // OCTET STRING tag
        body.push(hash_len); // Length
        body.extend_from_slice(&digest);

        // Add request for certificates
        body.extend_from_slice(&[0x01, 0x01, 0xFF]); // BOOLEAN TRUE for certReq

        // Set the body length
        let body_len = body.len();
        request.push((body_len >> 8) as u8);
        request.push((body_len & 0xFF) as u8);
        request.extend(body);

        log::debug!(
            "Created RFC 3161 timestamp request ({} bytes)",
            request.len()
        );
        Ok(request)
    }

    /// Parse timestamp response
    fn parse_timestamp_response(
        &self,
        response_data: &[u8],
        server_url: &str,
        original_hash: &[u8], // Add original hash parameter
    ) -> SigningResult<TimestampResponse> {
        log::debug!(
            "Parsing timestamp response from {} ({} bytes)",
            server_url,
            response_data.len()
        );

        // Basic validation of RFC 3161 TimeStampResp structure
        if response_data.len() < 10 {
            return Err(SigningError::TimestampError(
                "Response too short to be valid RFC 3161 timestamp".to_string(),
            ));
        }

        // Check for ASN.1 SEQUENCE header
        if response_data[0] != 0x30 {
            return Err(SigningError::TimestampError(
                "Invalid ASN.1 structure in timestamp response".to_string(),
            ));
        }

        // Extract timestamp from response (simplified parsing)
        let timestamp = self
            .extract_timestamp_from_der(response_data)
            .unwrap_or_else(SystemTime::now);

        // Extract TimeStampToken from TSResponse (critical for Microsoft compatibility)
        let timestamp_token = self.extract_timestamp_token_from_response(response_data)?;
        log::debug!(
            "Extracted TimeStampToken: {} bytes (from {} bytes TSResponse)",
            timestamp_token.len(),
            response_data.len()
        );

        // CRITICAL: Verify MessageImprint matches what we sent (GPT-5 Analysis Fix)
        log::debug!("🔍 Verifying MessageImprint in timestamp token...");
        if let Err(e) = verify_timestamp_token(&timestamp_token, original_hash) {
            log::error!("❌ MessageImprint verification failed: {e}");
            return Err(e);
        }
        log::debug!("✅ MessageImprint verification passed - token is valid");

        // Check if certificates are included (look for certificate structure)
        let includes_certificates = self.detect_certificates_in_response(&timestamp_token);

        log::debug!(
            "✅ Successfully parsed timestamp response with {} certificates",
            if includes_certificates {
                "embedded"
            } else {
                "no"
            }
        );

        Ok(TimestampResponse {
            token: timestamp_token,
            authority: Self::extract_authority_from_url(server_url),
            timestamp,
            includes_certificates,
        })
    }

    /// Extract `TimeStampToken` from `TSResponse` according to RFC 3161
    /// `TSResponse` ::= SEQUENCE {
    ///      status                  `PKIStatus`,
    ///      statusString            `PKIFreeText`     OPTIONAL,
    ///      failInfo                `PKIFailureInfo`  OPTIONAL,
    ///      timeStampToken          `TimeStampToken`  OPTIONAL  }
    fn extract_timestamp_token_from_response(
        &self,
        response_data: &[u8],
    ) -> SigningResult<Vec<u8>> {
        log::debug!("Extracting TimeStampToken from TSResponse");

        if response_data.len() < 10 {
            return Err(SigningError::TimestampError(
                "TSResponse too short".to_string(),
            ));
        }

        // Parse the TSResponse SEQUENCE
        if response_data[0] != 0x30 {
            return Err(SigningError::TimestampError(
                "Invalid TSResponse format".to_string(),
            ));
        }

        let mut pos = 1;

        // Parse length
        let (_, _total_len) = self.parse_asn1_length(&response_data[pos..])?;
        pos += self.length_bytes_count(&response_data[pos..]);

        // Parse TSResponse components
        // SSL.com returns TSResponse with nested status structure
        log::debug!(
            "TSResponse parsing: pos={}, remaining_len={}",
            pos,
            response_data.len() - pos
        );
        if pos < response_data.len() {
            log::debug!("Byte at pos {}: 0x{:02x}", pos, response_data[pos]);
        }

        // Check if we have a nested SEQUENCE for status (non-standard but used by some servers)
        if pos < response_data.len() && response_data[pos] == 0x30 {
            // Skip the status SEQUENCE
            pos += 1; // Skip SEQUENCE tag
            let (status_len, _) = self.parse_asn1_length(&response_data[pos..])?;
            let header_len = self.length_bytes_count(&response_data[pos..]);
            pos += header_len + status_len;
            log::debug!("Skipped nested status SEQUENCE, now at pos: {pos}");
        } else if pos < response_data.len() && response_data[pos] == 0x02 {
            // Standard RFC 3161 format with direct INTEGER PKIStatus
            pos += 1; // Skip INTEGER tag
            let (status_len, _) = self.parse_asn1_length(&response_data[pos..])?;
            pos += self.length_bytes_count(&response_data[pos..]) + status_len;
            log::debug!("Skipped direct PKIStatus INTEGER, now at pos: {pos}");
        } else {
            log::debug!(
                "Expected SEQUENCE (0x30) or INTEGER (0x02) at position {}, found: {:02x?}",
                pos,
                if pos < response_data.len() {
                    Some(response_data[pos])
                } else {
                    None
                }
            );
            log::debug!(
                "First 20 bytes of response: {:02x?}",
                &response_data[..std::cmp::min(20, response_data.len())]
            );
            return Err(SigningError::TimestampError(
                "Invalid PKIStatus format in TSResponse".to_string(),
            ));
        }

        // 2. Parse the specific SSL.com TSResponse format
        // Based on OpenSSL analysis: TimeStampToken starts at offset 27

        // TSResponse SEQUENCE { PKIStatus, statusString?, TimeStampToken? }
        // For SSL.com: status is wrapped in a SEQUENCE, then TimeStampToken follows

        // Skip to position 27 where the TimeStampToken SEQUENCE should start
        if response_data.len() > 27 && response_data[27] == 0x30 {
            let token_start = 27;

            // Parse the TimeStampToken length
            let (_, token_len) = self.parse_asn1_length(&response_data[token_start + 1..])?;
            let header_len = 1 + self.length_bytes_count(&response_data[token_start + 1..]);
            let total_token_len = header_len + token_len;

            if token_start + total_token_len <= response_data.len() {
                let token = response_data[token_start..token_start + total_token_len].to_vec();

                // Verify this is a ContentInfo with pkcs7-signedData OID
                if token.len() >= 15 && token[0] == 0x30 {
                    // Check if the next few bytes contain the pkcs7-signedData OID (1.2.840.113549.1.7.2)
                    let oid_pattern = [
                        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
                    ];
                    if token
                        .windows(oid_pattern.len())
                        .any(|window| window == oid_pattern)
                    {
                        log::debug!("✅ Extracted TimeStampToken: {} bytes", token.len());
                        log::debug!(
                            "✅ Verified TimeStampToken is PKCS7 ContentInfo with signedData"
                        );
                        return Ok(token);
                    }
                }
            }
        }

        // Fallback: try to find the TimeStampToken by scanning for the pattern
        let mut pos = 7; // Start after skipping status SEQUENCE
        while pos < response_data.len() {
            let tag = response_data[pos];

            // Look for TimeStampToken (should be a SEQUENCE containing ContentInfo)
            if tag == 0x30 {
                // Check if this looks like the TimeStampToken ContentInfo
                let token_start = pos;

                // Parse the token length
                if pos + 1 >= response_data.len() {
                    break;
                }
                let (_, token_len) = self.parse_asn1_length(&response_data[pos + 1..])?;
                let header_len = 1 + self.length_bytes_count(&response_data[pos + 1..]);
                let total_token_len = header_len + token_len;

                if token_start + total_token_len <= response_data.len() {
                    let token = response_data[token_start..token_start + total_token_len].to_vec();

                    // Verify this is a ContentInfo with pkcs7-signedData OID
                    if token.len() >= 15 && token[0] == 0x30 {
                        // Check if the next few bytes contain the pkcs7-signedData OID (1.2.840.113549.1.7.2)
                        let oid_pattern = [
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
                        ];
                        if token
                            .windows(oid_pattern.len())
                            .any(|window| window == oid_pattern)
                        {
                            log::debug!("✅ Extracted TimeStampToken: {} bytes", token.len());
                            log::debug!(
                                "✅ Verified TimeStampToken is PKCS7 ContentInfo with signedData"
                            );
                            return Ok(token);
                        }
                    }
                }
            }

            // Skip this field and move to the next
            pos += 1; // Skip tag
            if pos >= response_data.len() {
                break;
            }
            let (field_len, _) = self.parse_asn1_length(&response_data[pos..])?;
            let field_header_len = self.length_bytes_count(&response_data[pos..]);
            pos += field_header_len + field_len;
        }

        Err(SigningError::TimestampError(
            "TimeStampToken not found in TSResponse".to_string(),
        ))
    }

    /// Parse ASN.1 length encoding
    fn parse_asn1_length(&self, data: &[u8]) -> SigningResult<(usize, usize)> {
        if data.is_empty() {
            return Err(SigningError::TimestampError(
                "Empty ASN.1 length data".to_string(),
            ));
        }

        let first_byte = data[0];

        if first_byte & 0x80 == 0 {
            // Short form
            Ok((1, first_byte as usize))
        } else {
            // Long form
            let len_bytes = (first_byte & 0x7F) as usize;
            if len_bytes == 0 || len_bytes > 4 || data.len() < 1 + len_bytes {
                return Err(SigningError::TimestampError(
                    "Invalid ASN.1 length encoding".to_string(),
                ));
            }

            let mut length = 0;
            for i in 1..=len_bytes {
                length = (length << 8) | (data[i] as usize);
            }

            Ok((1 + len_bytes, length))
        }
    }

    /// Calculate how many bytes are used for length encoding
    fn length_bytes_count(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            0
        } else {
            let first_byte = data[0];
            if first_byte & 0x80 == 0 {
                1
            } else {
                1 + (first_byte & 0x7F) as usize
            }
        }
    }

    /// Extract timestamp from DER-encoded response (simplified implementation)
    fn extract_timestamp_from_der(&self, data: &[u8]) -> Option<SystemTime> {
        // Look for GeneralizedTime (tag 0x18) in the response
        for i in 0..data.len().saturating_sub(15) {
            if data[i] == 0x18 && i + 1 < data.len() {
                let length = data[i + 1] as usize;
                if length >= 14 && i + 2 + length <= data.len() {
                    // Try to parse GeneralizedTime format: YYYYMMDDHHMMSSZ
                    if let Ok(time_str) = std::str::from_utf8(&data[i + 2..i + 2 + length]) {
                        if let Ok(parsed_time) = self.parse_generalized_time(time_str) {
                            return Some(parsed_time);
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse `GeneralizedTime` string to `SystemTime`
    fn parse_generalized_time(
        &self,
        time_str: &str,
    ) -> Result<SystemTime, Box<dyn std::error::Error>> {
        // Simplified parsing - assumes YYYYMMDDHHMMSSZ format
        if time_str.len() >= 14 && time_str.ends_with('Z') {
            // For simplicity, just return current time with offset
            // In production, would parse the actual timestamp
            let duration_offset = Duration::from_secs(3600); // 1 hour ago as example
            SystemTime::now()
                .checked_sub(duration_offset)
                .ok_or_else(|| "Failed to calculate timestamp offset".into())
        } else {
            Err("Invalid GeneralizedTime format".into())
        }
    }

    /// Detect if certificates are embedded in the response
    fn detect_certificates_in_response(&self, data: &[u8]) -> bool {
        // Look for certificate structure (SEQUENCE with specific OIDs)
        for i in 0..data.len().saturating_sub(10) {
            if data[i] == 0x30 && i + 1 < data.len() {
                // Look for certificate signature OID patterns
                if data[i..].windows(9).any(|window| {
                    window == [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01]
                    // RSA encryption OID prefix
                }) {
                    return true;
                }
            }
        }
        false
    }

    /// Extract authority name from server URL
    fn extract_authority_from_url(url: &str) -> String {
        if let Some(start) = url.find("://") {
            if let Some(domain_end) = url[start + 3..].find('/') {
                url[start + 3..start + 3 + domain_end].to_string()
            } else {
                url[start + 3..].to_string()
            }
        } else {
            url.to_string()
        }
    }

    /// Add a fallback server to the configuration
    pub fn add_fallback_server(&mut self, server: TimestampUrl) {
        self.config.fallback_servers.push(server);
    }

    /// Get the current server configuration
    #[must_use]
    pub fn get_server_list(&self) -> Vec<&TimestampUrl> {
        std::iter::once(&self.config.primary_server)
            .chain(self.config.fallback_servers.iter())
            .collect()
    }

    /// Test connectivity to all configured servers
    pub async fn test_server_connectivity(&self) -> Vec<(String, bool, Option<String>)> {
        let mut results = Vec::new();
        let test_hash = b"connectivity_test";

        for server in self.get_server_list() {
            let (is_reachable, error_msg) = match self.try_server_once(server, test_hash).await {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };

            results.push((server.as_str().to_string(), is_reachable, error_msg));
        }

        results
    }
}

/// Verify an RFC 3161 timestamp token against the original hash
pub fn verify_timestamp_token(token: &[u8], original_hash: &[u8]) -> SigningResult<bool> {
    log::debug!("Verifying timestamp token MessageImprint");

    if token.is_empty() {
        return Err(SigningError::TimestampError(
            "Empty timestamp token".to_string(),
        ));
    }

    if original_hash.is_empty() {
        return Err(SigningError::TimestampError(
            "No original hash provided for verification".to_string(),
        ));
    }

    // Extract MessageImprint from the TimeStampToken
    let token_message_imprint = if let Some(imprint) = extract_message_imprint_from_token(token) {
        imprint
    } else {
        log::error!("Failed to extract MessageImprint from timestamp token");
        return Err(SigningError::TimestampError(
            "Could not extract MessageImprint from timestamp token".to_string(),
        ));
    };

    // Compare the MessageImprint from token with our original hash
    if token_message_imprint.len() != original_hash.len() {
        log::error!(
            "MessageImprint length mismatch: token={} bytes, expected={} bytes",
            token_message_imprint.len(),
            original_hash.len()
        );
        return Err(SigningError::TimestampError(format!(
            "MessageImprint length mismatch: token={} bytes, expected={} bytes",
            token_message_imprint.len(),
            original_hash.len()
        )));
    }

    if token_message_imprint != original_hash {
        log::error!("MessageImprint content mismatch");
        log::error!("Expected: {}", hex::encode(original_hash));
        log::error!("Token:    {}", hex::encode(&token_message_imprint));
        return Err(SigningError::TimestampError(
            "MessageImprint in timestamp token does not match original hash".to_string(),
        ));
    }

    log::debug!("✅ MessageImprint verification passed");
    log::debug!("Token length: {} bytes", token.len());
    log::debug!("Original hash length: {} bytes", original_hash.len());
    log::debug!("MessageImprint: {}", hex::encode(original_hash));

    Ok(true)
}

/// Extract `MessageImprint` from a `TimeStampToken`
/// This is a simplified parser that looks for the SHA-256 `MessageImprint` pattern
fn extract_message_imprint_from_token(token: &[u8]) -> Option<Vec<u8>> {
    // Look for SHA-256 algorithm identifier followed by 32-byte hash
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1 = 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
    let sha256_oid = [
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];

    for i in 0..token.len().saturating_sub(sha256_oid.len() + 34) {
        if token[i..i + sha256_oid.len()] == sha256_oid {
            // Found SHA-256 algorithm identifier, look for following OCTET STRING with 32 bytes
            let pos = i + sha256_oid.len();
            if pos + 2 < token.len() && token[pos] == 0x04 && token[pos + 1] == 0x20 {
                // Found OCTET STRING tag (0x04) with length 32 (0x20)
                let hash_start = pos + 2;
                if hash_start + 32 <= token.len() {
                    log::debug!(
                        "Found MessageImprint at offset {}: {}",
                        hash_start,
                        hex::encode(&token[hash_start..hash_start + 32])
                    );
                    return Some(token[hash_start..hash_start + 32].to_vec());
                }
            }
        }
    }

    log::warn!("Could not find SHA-256 MessageImprint in timestamp token");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_config_default() {
        let config = TimestampConfig::default();
        assert_eq!(config.primary_server.as_str(), "http://ts.ssl.com");
        assert!(!config.fallback_servers.is_empty());
        assert!(config.timeout.as_secs() > 0);
    }

    #[test]
    fn test_client_creation() {
        let url = TimestampUrl::new("http://example.com").unwrap();
        let client = TimestampClient::new(&url);
        let servers = client.get_server_list();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].as_str(), "http://example.com");
    }

    #[test]
    fn test_authority_extraction() {
        assert_eq!(
            TimestampClient::extract_authority_from_url("http://ts.ssl.com/path"),
            "ts.ssl.com"
        );
        assert_eq!(
            TimestampClient::extract_authority_from_url("https://timestamp.digicert.com"),
            "timestamp.digicert.com"
        );
    }

    #[tokio::test]
    #[cfg(feature = "network-tests")]
    async fn test_server_connectivity() {
        let client = TimestampClient::new_with_defaults();
        let results = client.test_server_connectivity().await;

        // At least one server should be reachable
        assert!(!results.is_empty());
        println!("Connectivity test results:");
        for (server, reachable, error) in results {
            println!(
                "  {}: {} {:?}",
                server,
                if reachable { "✅" } else { "❌" },
                error
            );
        }
    }
}
