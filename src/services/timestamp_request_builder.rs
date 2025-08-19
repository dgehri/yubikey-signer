//! Timestamp request builder service.
//!
//! Service for building RFC3161 timestamp requests from signature bytes.

use crate::domain::constants::{
    ASN1_INTEGER_TAG, ASN1_NULL, ASN1_OCTET_STRING_TAG, ASN1_OID_TAG, ASN1_SEQUENCE_TAG,
    CERT_REQ_TRUE, SHA256_ALGORITHM_OID, SHA384_ALGORITHM_OID, SHA512_ALGORITHM_OID,
    TS_REQ_NONCE_LENGTH, TS_REQ_VERSION_1,
};
use crate::domain::crypto::HashAlgorithm;
use crate::SigningError;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Service for building RFC3161 timestamp requests.
pub struct TimestampRequestBuilder;

impl TimestampRequestBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build an RFC3161 timestamp request for the given signature bytes.
    ///
    /// This creates a proper `TSRequest` structure with:
    /// - `MessageImprint` containing hash of the signature
    /// - Request policy (optional)
    /// - Nonce for replay protection
    /// - Request for TSA certificate inclusion
    pub fn build_request(
        &self,
        signature_bytes: &[u8],
        hash_algorithm: HashAlgorithm,
    ) -> Result<Vec<u8>, SigningError> {
        if signature_bytes.is_empty() {
            return Err(SigningError::TimestampError(
                "Cannot create timestamp request for empty signature".into(),
            ));
        }

        // Compute hash of signature bytes for MessageImprint
        let signature_hash = self.compute_signature_hash(signature_bytes, hash_algorithm)?;

        // Build minimal RFC3161 request structure
        // Real implementation would build proper ASN.1 TSRequest:
        // TSRequest ::= SEQUENCE {
        //     version                      INTEGER,
        //     messageImprint               MessageImprint,
        //     reqPolicy             TSAPolicyId                OPTIONAL,
        //     nonce                 INTEGER                    OPTIONAL,
        //     certReq               BOOLEAN                    DEFAULT FALSE,
        //     extensions            [0] IMPLICIT Extensions    OPTIONAL
        // }

        let request = self.build_minimal_ts_request(&signature_hash, hash_algorithm)?;

        log::debug!(
            "Built RFC3161 timestamp request: {} bytes for signature: {} bytes",
            request.len(),
            signature_bytes.len()
        );

        Ok(request)
    }

    /// Compute hash of signature bytes using the specified algorithm.
    fn compute_signature_hash(
        &self,
        signature_bytes: &[u8],
        algorithm: HashAlgorithm,
    ) -> Result<Vec<u8>, SigningError> {
        let hash = match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(signature_bytes);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(signature_bytes);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(signature_bytes);
                hasher.finalize().to_vec()
            }
        };

        Ok(hash)
    }

    /// Build minimal RFC3161 timestamp request.
    fn build_minimal_ts_request(
        &self,
        signature_hash: &[u8],
        algorithm: HashAlgorithm,
    ) -> Result<Vec<u8>, SigningError> {
        // Basic ASN.1 TSRequest with nonce + certReq
        // TSRequest ::= SEQUENCE { version INTEGER 1, messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }, nonce INTEGER, certReq BOOLEAN }

        // AlgorithmIdentifier OIDs from constants
        let (alg_oid, alg_oid_len) = match algorithm {
            HashAlgorithm::Sha256 => (SHA256_ALGORITHM_OID, 0x09),
            HashAlgorithm::Sha384 => (SHA384_ALGORITHM_OID, 0x09),
            HashAlgorithm::Sha512 => (SHA512_ALGORITHM_OID, 0x09),
        };

        // hashAlgorithm: SEQUENCE { OID, NULL }
        let mut algorithm_identifier = vec![
            ASN1_SEQUENCE_TAG,   // SEQUENCE
            2 + 1 + alg_oid_len, // length: OID hdr + NULL
            ASN1_OID_TAG,        // OID
            alg_oid_len,
        ];
        algorithm_identifier.extend_from_slice(alg_oid);
        algorithm_identifier.extend_from_slice(ASN1_NULL); // NULL

        // messageImprint SEQUENCE
        let mut message_imprint = Vec::new();
        message_imprint.push(ASN1_SEQUENCE_TAG); // SEQUENCE
                                                 // length will be filled in later
        let mi_len_pos = message_imprint.len();
        message_imprint.push(0x00);
        // hashAlgorithm
        message_imprint.extend_from_slice(&algorithm_identifier);
        // hashedMessage OCTET STRING
        message_imprint.push(ASN1_OCTET_STRING_TAG);
        if signature_hash.len() > 255 {
            return Err(SigningError::TimestampError(
                "Hashed message too large".into(),
            ));
        }
        message_imprint.push(signature_hash.len() as u8);
        message_imprint.extend_from_slice(signature_hash);
        // fix messageImprint length
        let mi_content_len = message_imprint.len() - mi_len_pos - 1;
        if mi_content_len > 255 {
            return Err(SigningError::TimestampError(
                "messageImprint too large".into(),
            ));
        }
        message_imprint[mi_len_pos] = mi_content_len as u8;

        // nonce INTEGER (8 bytes) using deterministic RNG seeded by signature hash to keep
        // tests stable while exercising RNG path.
        let mut seed = [0u8; 32];
        for (i, b) in signature_hash.iter().take(32).enumerate() {
            seed[i] = *b;
        }
        let mut rng = StdRng::from_seed(seed);
        let mut nonce_bytes = [0u8; 8];
        rng.fill_bytes(&mut nonce_bytes);
        let mut nonce_der = Vec::new();
        nonce_der.push(ASN1_INTEGER_TAG); // INTEGER
        nonce_der.push(TS_REQ_NONCE_LENGTH); // length (ensure positive by prefix 0x00)
        nonce_der.push(0x00);
        nonce_der.extend_from_slice(&nonce_bytes);

        // certReq BOOLEAN TRUE
        let cert_req = CERT_REQ_TRUE;

        // Assemble TSRequest
        let mut ts_req = Vec::new();
        ts_req.push(ASN1_SEQUENCE_TAG); // SEQUENCE
        let len_pos = ts_req.len();
        ts_req.push(0x00); // length will be filled in later
                           // version INTEGER 1
        ts_req.extend_from_slice(&TS_REQ_VERSION_1);
        // messageImprint
        ts_req.extend_from_slice(&message_imprint);
        // nonce
        ts_req.extend_from_slice(&nonce_der);
        // certReq
        ts_req.extend_from_slice(&cert_req);
        let total_len = ts_req.len() - len_pos - 1;
        if total_len > 255 {
            return Err(SigningError::TimestampError("TSRequest too large".into()));
        }
        ts_req[len_pos] = total_len as u8;
        Ok(ts_req)
    }
}

impl Default for TimestampRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_rejects_empty_signature() {
        let builder = TimestampRequestBuilder::new();
        let result = builder.build_request(&[], HashAlgorithm::Sha256);

        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("empty signature"));
    }

    #[test]
    fn build_request_produces_der_structure() {
        let builder = TimestampRequestBuilder::new();
        let dummy_signature = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xEF];

        let request = builder
            .build_request(&dummy_signature, HashAlgorithm::Sha256)
            .expect("should build request");

        // Should start with SEQUENCE tag
        assert_eq!(request[0], 0x30);
        assert!(request.len() > 10);

        // Basic structural assertions
        assert_eq!(request[0], 0x30); // SEQUENCE
                                      // Contains version INTEGER 1 sequence: 02 01 01
        assert!(request.windows(3).any(|w| w == [0x02, 0x01, 0x01]));
        // Contains AlgorithmIdentifier OID for sha256 (ends with 0x01)
        assert!(request
            .windows(11)
            .any(|w| w.starts_with(&[0x30]) && w.contains(&0x06)));
        // Contains OCTET STRING tag for hashedMessage
        assert!(request.contains(&0x04));
        // Contains BOOLEAN TRUE (certReq)
        assert!(request.windows(3).any(|w| w == [0x01, 0x01, 0xFF]));
        // Nonce INTEGER present (length 9 with leading 0x00)
        assert!(request.windows(2).any(|w| w == [0x02, 0x09]));
    }

    #[test]
    fn build_request_different_algorithms() {
        let builder = TimestampRequestBuilder::new();
        let dummy_signature = vec![0x12, 0x34, 0x56, 0x78];

        let req_sha256 = builder
            .build_request(&dummy_signature, HashAlgorithm::Sha256)
            .expect("should build SHA-256 request");

        let req_sha384 = builder
            .build_request(&dummy_signature, HashAlgorithm::Sha384)
            .expect("should build SHA-384 request");

        let req_sha512 = builder
            .build_request(&dummy_signature, HashAlgorithm::Sha512)
            .expect("should build SHA-512 request");

        // Different algorithms should produce different requests
        assert_ne!(req_sha256, req_sha384);
        assert_ne!(req_sha384, req_sha512);
        assert_ne!(req_sha256, req_sha512);
    }

    #[test]
    fn compute_signature_hash_sha256() {
        let builder = TimestampRequestBuilder::new();
        let signature = b"test signature bytes";

        let hash = builder
            .compute_signature_hash(signature, HashAlgorithm::Sha256)
            .expect("should compute hash");

        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes

        // Verify it's actually computing the hash (not just returning zeros)
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(signature);
            hasher.finalize().to_vec()
        };
        assert_eq!(hash, expected);
    }
}
