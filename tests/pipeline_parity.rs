//! Pipeline parity tests ensuring rearchitected services produce identical PKCS#7 artifacts
//! to OpenSSL-backed builder paths (dependency & cryptographic behavior stability).
//!
//! These tests purposefully avoid hardware access by using a deterministic dummy signature
//! and certificate DER already present via `YubiKey` operations in other tests. We reuse
//! `YubiKeyOperations::connect` only to fetch the real certificate when available; if that
//! fails (e.g. CI without hardware), the test is ignored.

use yubikey_signer::{
    services::{
        attr_builder::AttrBuilderService, authenticode::OpenSslAuthenticodeSigner,
        pe_hasher::PeHasher, pkcs7_builder::Pkcs7BuilderService, spc_builder::SpcBuilderService,
    },
    HashAlgorithm, PivPin, PivSlot, SigningError, YubiKeyOperations,
};

fn get_cert_der() -> Result<Vec<u8>, SigningError> {
    // Reuse hardware path if available; else return error so test can be ignored.
    let mut ops = match YubiKeyOperations::connect() {
        Ok(o) => o,
        Err(e) => return Err(SigningError::CertificateError(format!("No YubiKey: {e}"))),
    };
    let pin = PivPin::new("4449f111").expect("pin construct");
    ops.authenticate(&pin)?;
    ops.get_certificate_der(PivSlot::AUTHENTICATION)
}

#[test]
fn pkcs7_service_vs_authenticode_parity() {
    let cert_der = if let Ok(c) = get_cert_der() {
        c
    } else {
        eprintln!("Skipping parity test (no YubiKey certificate available)");
        return; // graceful skip
    };

    let algo = HashAlgorithm::Sha256;
    let pe_bytes = include_bytes!("../test-data/test_unsigned.exe");
    let hasher = PeHasher::new(algo);
    let pe_digest = hasher.hash(pe_bytes).expect("hash");

    // AuthenticodeSigner path to derive SPC + attrs
    let reference_signer =
        OpenSslAuthenticodeSigner::new(&cert_der, algo).expect("reference signer");
    let spc_builder = SpcBuilderService::new(algo);
    let spc = spc_builder
        .build(&pe_digest, |h| reference_signer.create_spc_content(h))
        .expect("spc");
    let spc_der = spc.as_der();

    // Service attr builder (delegates to OpenSSL internally)
    let attr_service = AttrBuilderService::new(algo);
    let attr_out = attr_service
        .build(&pe_digest, spc_der, &cert_der, pe_bytes)
        .expect("attr build");

    // Deterministic dummy signature (same length as ECDSA P-256 ~ 70-72 bytes not required for assembly correctness)
    let dummy_sig = vec![0xAA; 64];

    // Service PKCS#7
    let service_pkcs7 = Pkcs7BuilderService::new(cert_der.clone(), algo, true)
        .build_signed(spc_der, &attr_out.embedding_der, &dummy_sig)
        .expect("service pkcs7");

    // Reference PKCS#7 (using existing builder). We mimic path invoked in signing workflow.
    // Use fixed attributes (set_der/embedding) & dummy signature by calling through reference helper.
    let reference_pkcs7 = reference_signer
        .build_pkcs7_from_components(spc_der, &attr_out.embedding_der, &dummy_sig, None, true)
        .expect("reference pkcs7");

    let service_bytes = service_pkcs7.as_der();
    let reference_bytes = reference_pkcs7;

    assert_eq!(
        service_bytes, reference_bytes,
        "PKCS#7 DER mismatch between service and AuthenticodeSigner paths"
    );
}
