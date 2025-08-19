//! Tests for the `SpcIndirectData` domain type.

use yubikey_signer::{HashAlgorithm, SpcIndirectData};

#[test]
fn spc_indirect_data_constructs_via_builder_closure() {
    let dummy_hash = vec![0u8; HashAlgorithm::Sha256.digest_size()];
    // Minimal builder closure returning a fake (but structurally plausible) DER SEQUENCE.
    let builder = |hash: &[u8]| -> Result<Vec<u8>, yubikey_signer::SigningError> {
        // SEQUENCE { OCTET STRING <hash> }
        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE
        let inner_len = 2 + hash.len(); // 0x04 + len + data
        der.push(inner_len as u8);
        der.push(0x04); // OCTET STRING
        der.push(hash.len() as u8);
        der.extend_from_slice(hash);
        Ok(der)
    };
    let spc = SpcIndirectData::from_pe_hash(HashAlgorithm::Sha256, &dummy_hash, builder).unwrap();
    assert!(spc.as_der().starts_with(&[0x30]));
    assert_eq!(spc.hash_algorithm(), HashAlgorithm::Sha256);
}
