//! Tests for `Pkcs7SignedData` domain wrapper.

use openssl::x509::X509;
use std::fs;
use std::path::Path;
use yubikey_signer::domain::pkcs7::Pkcs7SignedData;
use yubikey_signer::{
    services::pkcs7::AuthenticodeBuilder, services::Pkcs7BuilderService, HashAlgorithm,
};

// Helper: minimal fake data for comparison (not a valid signature but structurally sufficient)
fn sample_components() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // spc_content (fake SEQUENCE)
    let spc = vec![0x30, 0x03, 0x02, 0x01, 0x01];
    // a0 implicit attrs: [0] tag around SET with empty content
    let attrs = vec![0xA0, 0x00];
    // signature: minimal DER ECDSA-like (r=1,s=1)
    let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    (spc, attrs, sig)
}

#[test]
fn pkcs7_signed_data_wrapper_basic() {
    let sample = vec![0x30, 0x00]; // Minimal invalid but structurally SEQUENCE start for test
    let pk = Pkcs7SignedData::from_der(sample.clone());
    assert_eq!(pk.len(), sample.len());
    assert_eq!(pk.as_der(), &sample[..]);
    assert!(!pk.is_empty());
}

#[test]
#[ignore = "Missing deterministic test certificate"] // This test relies on constructing a valid certificate DER.
                                                     // Ignoring until a deterministic test certificate fixture is added.
fn pkcs7_service_matches_authenticode_builder_no_timestamp() {
    let (spc, attrs, sig) = sample_components();
    // Dummy cert DER (not parsed because embed_certificate=false)
    let cert = vec![0x30, 0x00];
    let reference_pkcs7 = AuthenticodeBuilder::new(cert.clone(), HashAlgorithm::Sha256)
        .build_with_signature_fixed_attrs(&spc, &attrs, &sig, false)
        .expect("reference build ok");
    let service = Pkcs7BuilderService::new(cert, HashAlgorithm::Sha256, false)
        .build_signed(&spc, &attrs, &sig)
        .expect("service build ok");
    assert_eq!(reference_pkcs7, service.as_der());
}

#[test]
fn pkcs7_service_parity_real_cert_dummy_signature() {
    // Load real test certificate (PEM) from reference path
    let pem_path = Path::new("reference").join("cert.pem");
    let pem = fs::read(&pem_path).expect("read cert.pem");
    let cert = X509::from_pem(&pem).expect("parse pem");
    let cert_der = cert.to_der().expect("der");

    // Minimal fake SPC content (valid SEQUENCE wrapper for reproducibility)
    // In real flow this is SpcIndirectDataContent DER.
    let spc = vec![0x30, 0x03, 0x02, 0x01, 0x01];
    // Minimal [0] IMPLICIT signedAttrs containing empty SET (constructed, length 0)
    let attrs = vec![0xA0, 0x00];
    // Deterministic dummy ECDSA signature DER (r=1,s=1)
    let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

    // Reference builder output
    let reference_pkcs7 = AuthenticodeBuilder::new(cert_der.clone(), HashAlgorithm::Sha256)
        .build_with_signature_fixed_attrs(&spc, &attrs, &sig, true)
        .expect("reference ok");

    // New service output (should match for non-timestamp path)
    let service = Pkcs7BuilderService::new(cert_der, HashAlgorithm::Sha256, true)
        .build_signed(&spc, &attrs, &sig)
        .expect("service ok");

    assert_eq!(
        reference_pkcs7,
        service.as_der(),
        "Service PKCS#7 DER must match reference builder for deterministic inputs"
    );
}
