//! SPC-specific constants for Authenticode signing.

/// Microsoft SPC Indirect Data OID (1.3.6.1.4.1.311.2.1.4) - used in Authenticode content type
pub const SPC_INDIRECT_DATA_OBJID: &str = "1.3.6.1.4.1.311.2.1.4";

/// Microsoft Individual Code Signing purpose (ASN.1 encoded SEQUENCE)
pub const PURPOSE_IND: [u8; 14] = [
    0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15,
];
