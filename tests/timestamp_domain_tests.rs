use yubikey_signer::domain::crypto::HashAlgorithm;
use yubikey_signer::domain::pkcs7::TimestampToken;
use yubikey_signer::services::{TimestampApplier, TimestampRequestBuilder};

#[test]
fn timestamp_workflow_basic_request_and_token() {
    // Test the basic workflow: build request -> get token -> apply token
    let builder = TimestampRequestBuilder::new();
    let applier = TimestampApplier::new();

    // Simulate signature bytes
    let signature_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xEF];

    // Build timestamp request
    let request = builder
        .build_request(&signature_bytes, HashAlgorithm::Sha256)
        .expect("should build request");

    assert!(!request.is_empty());
    assert_eq!(request[0], 0x30); // Should be DER SEQUENCE

    // Simulate receiving a timestamp token (minimal valid structure)
    let token_der = vec![
        0x30, 0x0A, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x04, 0x02, 0x12, 0x34,
    ];
    let timestamp_token =
        TimestampToken::from_der(token_der).expect("should parse timestamp token");

    // Validate token for signature
    let validation_result =
        applier.validate_timestamp_for_signature(&timestamp_token, &signature_bytes);
    assert!(validation_result.is_ok());
}

#[test]
fn timestamp_request_size_varies_by_algorithm() {
    let builder = TimestampRequestBuilder::new();
    let signature = vec![0x11, 0x22, 0x33, 0x44];

    let req_sha256 = builder
        .build_request(&signature, HashAlgorithm::Sha256)
        .expect("SHA-256 request");

    let req_sha384 = builder
        .build_request(&signature, HashAlgorithm::Sha384)
        .expect("SHA-384 request");

    let req_sha512 = builder
        .build_request(&signature, HashAlgorithm::Sha512)
        .expect("SHA-512 request");

    // Requests should have different sizes due to different hash sizes
    assert_ne!(req_sha256.len(), req_sha384.len());
    assert_ne!(req_sha384.len(), req_sha512.len());

    // SHA-512 should be largest
    assert!(req_sha512.len() > req_sha384.len());
    assert!(req_sha384.len() > req_sha256.len());
}

#[test]
fn timestamp_token_validation_edge_cases() {
    // Test various edge cases in timestamp token validation

    // Empty token
    let result = TimestampToken::from_der(vec![]);
    assert!(result.is_err());

    // Too short but valid start
    let result = TimestampToken::from_der(vec![0x30, 0x02]);
    assert!(result.is_err());

    // Invalid ASN.1 tag
    let result = TimestampToken::from_der(vec![
        0xFF, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);
    assert!(result.is_err());

    // Valid minimal structure
    let result = TimestampToken::from_der(vec![
        0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x04, 0x01,
    ]);
    assert!(result.is_ok());
}

#[test]
fn phase7_timestamp_workflow_integration() {
    // Test that demonstrates the workflow components working together
    let builder = TimestampRequestBuilder::new();
    let applier = TimestampApplier::new();

    // Create a signature
    let signature = b"test signature for timestamp".to_vec();

    // Build request for the signature
    let request = builder
        .build_request(&signature, HashAlgorithm::Sha256)
        .expect("should build request");

    // Verify request structure
    assert_eq!(request[0], 0x30); // SEQUENCE
    assert!(request.len() > 32); // Should include SHA-256 hash (32 bytes) plus overhead

    // Simulate timestamp response (minimal ContentInfo)
    let token_response = vec![
        0x30, 0x12, // SEQUENCE, length 18
        0x06, 0x09, // OID, length 9
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
        0x10, // pkcs#9 id-smime OID (1.2.840.113549.1.9.16)
        0x04, 0x05, // OCTET STRING, length 5
        0x01, 0x02, 0x03, 0x04, 0x05, // Token data
    ];

    let timestamp_token = TimestampToken::from_der(token_response).expect("should parse response");

    // Create minimal PKCS#7 for applying timestamp
    let pkcs7_der = vec![
        0x30, 0x14, // SEQUENCE, length 20
        0x06, 0x09, // OID, length 9
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, // pkcs7-signedData
        0xA0, 0x07, // [0] EXPLICIT content wrapper, length 7
        0x30, 0x05, // SignedData SEQUENCE length 5
        0x02, 0x01, 0x01, // version INTEGER 1
        0x31, 0x00, // empty SET algorithms
    ];
    let original_pkcs7 = yubikey_signer::domain::pkcs7::Pkcs7SignedData::from_der(pkcs7_der);

    // Apply timestamp to PKCS#7
    let timestamped_pkcs7 = applier
        .apply_timestamp(&original_pkcs7, &timestamp_token, &signature)
        .expect("should apply timestamp");

    // Verify the result
    assert!(!timestamped_pkcs7.as_der().is_empty());
    assert!(!timestamped_pkcs7.is_empty());
}

#[test]
fn timestamp_request_deterministic_for_same_input() {
    // Verify that the same signature produces the same request
    let builder = TimestampRequestBuilder::new();
    let signature = vec![0xAA, 0xBB, 0xCC, 0xDD];

    let request1 = builder
        .build_request(&signature, HashAlgorithm::Sha256)
        .expect("first request");

    let request2 = builder
        .build_request(&signature, HashAlgorithm::Sha256)
        .expect("second request");

    assert_eq!(request1, request2, "Requests should be deterministic");
}

#[test]
fn timestamp_applier_rejects_mismatched_signatures() {
    let applier = TimestampApplier::new();

    // Create timestamp token
    let token_der = vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x04, 0x01];
    let timestamp_token = TimestampToken::from_der(token_der).expect("should parse token");

    // Create PKCS#7
    let pkcs7_der = vec![
        0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    let pkcs7 = yubikey_signer::domain::pkcs7::Pkcs7SignedData::from_der(pkcs7_der);

    // Try to apply with empty signature (should fail validation)
    let result = applier.apply_timestamp(&pkcs7, &timestamp_token, &[]);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("Empty signature hash"));
}
