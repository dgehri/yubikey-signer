//! Centralized constants for commonly repeated DER/OID bytes, tags and masks.
//! Domain constants for cryptographic algorithms and PE structures.
//! Keep this intentionally small; only broadly reused literals should live here.

// === ASN.1 DER Constants ===

/// ASN.1 NULL value (tag + length + null)
pub const ASN1_NULL: &[u8] = &[0x05, 0x00];

/// ASN.1 SEQUENCE tag
pub const ASN1_SEQUENCE_TAG: u8 = 0x30;

/// ASN.1 INTEGER tag
pub const ASN1_INTEGER_TAG: u8 = 0x02;

/// ASN.1 OBJECT IDENTIFIER tag
pub const ASN1_OID_TAG: u8 = 0x06;

/// ASN.1 OCTET STRING tag
pub const ASN1_OCTET_STRING_TAG: u8 = 0x04;

/// ASN.1 BOOLEAN tag
pub const ASN1_BOOLEAN_TAG: u8 = 0x01;

/// DER long form length encoding: 1-byte length follows
pub const DER_LONG_FORM_1_BYTE: u8 = 0x81;

/// DER long form length encoding: 2-byte length follows
pub const DER_LONG_FORM_2_BYTE: u8 = 0x82;

/// DER long form length encoding: 3-byte length follows  
pub const DER_LONG_FORM_3_BYTE: u8 = 0x83;

// === RFC3161 Timestamp Request Constants ===

/// Version 1 for RFC3161 timestamp requests
pub const TS_REQ_VERSION_1: [u8; 3] = [0x02, 0x01, 0x01];

/// BOOLEAN TRUE value for certReq field
pub const CERT_REQ_TRUE: [u8; 3] = [0x01, 0x01, 0xFF];

/// Standard nonce length for RFC3161 requests (8 random bytes + leading zero)
pub const TS_REQ_NONCE_LENGTH: u8 = 9;

// === PKCS#7 DER Structure Length Constants ===

/// Length of `AlgorithmIdentifier` SET in digestAlgorithms (1 sequence of 13 bytes + 2 bytes overhead)
pub const DIGEST_ALGORITHMS_SET_LENGTH: u8 = 0x0f;

/// Length of single `AlgorithmIdentifier` SEQUENCE payload (OID header + 9-byte OID + NULL)
pub const ALGORITHM_IDENTIFIER_SEQUENCE_LENGTH: u8 = 0x0d;

/// Length of SHA-2 family algorithm OIDs (all SHA-256/384/512 OIDs are 9 bytes)
pub const SHA2_ALGORITHM_OID_LENGTH: u8 = 0x09;

// === PKCS#7/CMS OID Constants ===

/// PKCS#7 `SignedData` OID (1.2.840.113549.1.7.2) DER encoding
pub const PKCS7_SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/// PKCS#7 `SignedData` OID with tag and length (complete DER structure)
pub const PKCS7_SIGNED_DATA_OID_COMPLETE: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];

/// PKCS#9 contentType attribute OID (1.2.840.113549.1.9.3) DER encoding
pub const PKCS9_CONTENT_TYPE_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];

/// PKCS#9 messageDigest attribute OID (1.2.840.113549.1.9.4) DER encoding  
pub const PKCS9_MESSAGE_DIGEST_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// PKCS#9 messageDigest OID with tag and length (complete DER structure)
pub const OID_MESSAGE_DIGEST_COMPLETE: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];

/// PKCS#9 contentType OID with tag and length (complete DER structure)
pub const OID_CONTENT_TYPE_COMPLETE: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
];

/// PKCS#9 signingTime attribute OID (1.2.840.113549.1.9.5) DER encoding
pub const PKCS9_SIGNING_TIME_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];

/// Context-specific IMPLICIT tag for unsigned attributes in PKCS#7 `SignerInfo` (tag number 1).
pub const UNSIGNED_ATTRS_CONTEXT_TAG: u8 = 0xA1; // 0b1010_0001

/// ASN.1 SET tag
pub const ASN1_SET_TAG: u8 = 0x31;

/// ASN.1 context-specific tag [0] EXPLICIT  
pub const ASN1_CONTEXT_0_EXPLICIT_TAG: u8 = 0xa0;

/// PKCS#7 version 1 (for backwards compatibility)
pub const PKCS7_VERSION_1: &[u8] = &[0x02, 0x01, 0x01];

// === Hash Algorithm OIDs ===

/// SHA-256 algorithm OID (2.16.840.1.101.3.4.2.1) DER encoding  
pub const SHA256_ALGORITHM_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// SHA-384 algorithm OID (2.16.840.1.101.3.4.2.2) DER encoding
pub const SHA384_ALGORITHM_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// SHA-512 algorithm OID (2.16.840.1.101.3.4.2.3) DER encoding
pub const SHA512_ALGORITHM_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

// === Microsoft Authenticode Constants ===

/// Microsoft RFC3161 timestamp unauthenticated attribute OID (1.3.6.1.4.1.311.3.3.1) DER bytes.
pub const MS_TIMESTAMP_ATTR_OID_DER: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01,
];

// === PE File Constants ===

/// 32-bit checksum mask used in PE checksum calculations.
pub const PE_CHECKSUM_MASK_U32: u64 = 0xFFFF_FFFF;

// === PIV Slot Constants ===

/// PIV Authentication slot (9A)
pub const PIV_SLOT_AUTHENTICATION: u8 = 0x9a;

/// PIV Digital Signature slot (9C) - recommended for code signing
pub const PIV_SLOT_SIGNATURE: u8 = 0x9c;

/// PIV Key Management slot (9D)
pub const PIV_SLOT_KEY_MANAGEMENT: u8 = 0x9d;

/// PIV Card Authentication slot (9E)
pub const PIV_SLOT_CARD_AUTHENTICATION: u8 = 0x9e;

/// All valid PIV slots for certificate operations
pub const VALID_PIV_SLOTS: &[u8] = &[
    PIV_SLOT_AUTHENTICATION,
    PIV_SLOT_SIGNATURE,
    PIV_SLOT_KEY_MANAGEMENT,
    PIV_SLOT_CARD_AUTHENTICATION,
];
