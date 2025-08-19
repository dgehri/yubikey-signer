use yubikey_signer::{CmsSignature, DigestBytes, DigestBytesError, EndEntityCert, HashAlgorithm};

#[test]
fn digest_bytes_happy_path() {
    let bytes = vec![0xAA; HashAlgorithm::Sha256.digest_size()];
    let d = DigestBytes::new(HashAlgorithm::Sha256, bytes.clone()).expect("valid size");
    assert_eq!(d.as_slice(), &bytes[..]);
    assert_eq!(d.algorithm(), HashAlgorithm::Sha256);
}

#[test]
fn digest_bytes_length_mismatch() {
    let bytes = vec![0xAA; 10];
    let err = DigestBytes::new(HashAlgorithm::Sha256, bytes).unwrap_err();
    assert!(matches!(err, DigestBytesError::LengthMismatch { .. }));
}

#[test]
fn cms_signature_wrapper() {
    let sig = CmsSignature::new(HashAlgorithm::Sha256, vec![1, 2, 3, 4]);
    assert_eq!(sig.as_slice(), &[1, 2, 3, 4]);
    assert_eq!(sig.algorithm(), HashAlgorithm::Sha256);
}

#[test]
fn end_entity_cert_wrapper() {
    // Minimal DER: use empty vector just to test storage (real parsing deferred to later phase)
    let cert = EndEntityCert::from_der(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    assert_eq!(cert.as_der()[0], 0x30);
}
