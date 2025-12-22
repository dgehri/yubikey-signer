//! MSI Signing Integration Tests
//!
//! Tests for MSI (Windows Installer) file signing functionality.
//! Uses the remote signing proxy for actual signing operations.
//!
//! Run with: `cargo test --test msi_signing_tests -- --include-ignored`
//!
//! Required environment variables:
//! - `YUBIKEY_PROXY_URL`: URL of the YubiKey proxy server
//! - `YUBIKEY_PROXY_TOKEN`: Authentication token for the proxy

use std::env;
use std::fs;
use std::path::PathBuf;
use yubikey_signer::adapters::remote::client::{RemoteSigner, RemoteSignerConfig};
use yubikey_signer::domain::msi::{is_msi_file, MsiFile};
use yubikey_signer::services::msi_signer::MsiSigner;
use yubikey_signer::services::timestamp::TimestampClient;
use yubikey_signer::{HashAlgorithm, PivSlot, TimestampUrl};

/// Get the path to the test MSI file.
fn test_msi_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data/test_unsigned.msi")
}

/// Get remote signer configuration from environment.
fn get_remote_config() -> Option<(String, String)> {
    let url = env::var("YUBIKEY_PROXY_URL").ok()?;
    let token = env::var("YUBIKEY_PROXY_TOKEN").ok()?;
    Some((url, token))
}

#[test]
fn test_msi_file_detection() {
    let msi_path = test_msi_path();

    // Skip if test MSI doesn't exist
    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");

    // Verify it's detected as an MSI file
    assert!(is_msi_file(&data), "Test file should be detected as MSI");

    // Verify magic bytes
    assert_eq!(
        &data[0..8],
        &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "MSI should have OLE magic bytes"
    );

    println!("MSI file detection: OK ({} bytes)", data.len());
}

#[test]
fn test_msi_file_parsing() {
    let msi_path = test_msi_path();

    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");

    // Parse the MSI file
    let msi = MsiFile::open(data.clone());
    assert!(msi.is_ok(), "MSI parsing should succeed: {:?}", msi.err());

    let msi = msi.unwrap();
    assert!(
        !msi.has_signature().expect("Should check signature"),
        "Test MSI should not have a signature"
    );

    println!("MSI file parsing: OK");
}

#[test]
fn test_msi_hash_computation() {
    let msi_path = test_msi_path();

    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");

    // Create a test certificate (self-signed for testing)
    let cert_der = create_test_certificate();

    // Create MSI signer
    let signer = MsiSigner::new(&cert_der, HashAlgorithm::Sha256);
    assert!(
        signer.is_ok(),
        "MSI signer creation should succeed: {:?}",
        signer.err()
    );

    let signer = signer.unwrap();

    // Compute hash
    let hash = signer.compute_msi_hash(&data);
    assert!(
        hash.is_ok(),
        "MSI hash computation should succeed: {:?}",
        hash.err()
    );

    let hash = hash.unwrap();
    assert_eq!(hash.len(), 32, "SHA256 hash should be 32 bytes");

    println!("MSI hash: {}", hex::encode(&hash));
    println!("MSI hash computation: OK");
}

#[test]
fn test_msi_tbs_context_creation() {
    let msi_path = test_msi_path();

    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");
    let cert_der = create_test_certificate();

    let signer = MsiSigner::new(&cert_der, HashAlgorithm::Sha256).expect("Should create signer");

    // Compute TBS context
    let context = signer.compute_tbs_hash_with_context(&data);
    assert!(
        context.is_ok(),
        "TBS context creation should succeed: {:?}",
        context.err()
    );

    let context = context.unwrap();
    assert_eq!(context.tbs_hash().len(), 32, "TBS hash should be 32 bytes");
    assert_eq!(context.msi_hash().len(), 32, "MSI hash should be 32 bytes");

    println!("TBS hash: {}", hex::encode(context.tbs_hash()));
    println!("MSI content hash: {}", hex::encode(context.msi_hash()));
    println!("TBS context creation: OK");
}

#[tokio::test]
#[ignore = "Requires remote signing proxy (set YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN)"]
async fn test_msi_remote_signing() {
    let msi_path = test_msi_path();

    if !msi_path.exists() {
        panic!(
            "Test MSI not found: {}. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
    }

    let (proxy_url, proxy_token) =
        get_remote_config().expect("YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN must be set");

    println!("Using remote proxy: {proxy_url}");

    let data = fs::read(&msi_path).expect("Failed to read test MSI");
    let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

    // Create remote signer client
    let config = RemoteSignerConfig::new(&proxy_url, &proxy_token);
    let client = RemoteSigner::new(config).expect("Should create remote client");

    // Check proxy status
    let status = client.check_status().await.expect("Should check status");
    assert!(status.yubikey_ready, "YubiKey should be ready");
    println!("YubiKey status: ready (serial: {:?})", status.serial);

    // Get certificate from remote YubiKey
    let cert_der = client
        .get_certificate(piv_slot)
        .await
        .expect("Should get certificate");
    println!("Got certificate: {} bytes", cert_der.len());

    // Create MSI signer
    let signer = MsiSigner::new(&cert_der, HashAlgorithm::Sha256).expect("Should create signer");

    // Compute TBS hash
    let context = signer
        .compute_tbs_hash_with_context(&data)
        .expect("Should compute TBS hash");
    println!("TBS hash: {}", hex::encode(context.tbs_hash()));

    // Sign with remote YubiKey
    let signature = client
        .sign_hash(context.tbs_hash(), piv_slot)
        .await
        .expect("Should sign hash");
    println!("Got signature: {} bytes", signature.len());

    // Create signed MSI (no timestamp for this test)
    let signed_msi = signer
        .create_signed_msi_with_context(&data, &context, &signature, None)
        .expect("Should create signed MSI");

    let signed_bytes = signed_msi.into_bytes();
    println!("Signed MSI: {} bytes", signed_bytes.len());

    // Verify the signed MSI is still a valid OLE document
    assert!(
        is_msi_file(&signed_bytes),
        "Signed file should still be MSI"
    );

    // Parse signed MSI and verify signature exists
    let parsed = MsiFile::open(signed_bytes.clone()).expect("Should parse signed MSI");
    assert!(
        parsed.has_signature().expect("Should check signature"),
        "Signed MSI should have signature"
    );

    // Write to temp file for external verification
    let output_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("temp/test_signed.msi");
    fs::write(&output_path, &signed_bytes).expect("Should write signed MSI");
    println!("Signed MSI written to: {}", output_path.display());

    println!("MSI remote signing: OK");
}

#[tokio::test]
#[ignore = "Requires remote signing proxy (set YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN)"]
async fn test_msi_remote_signing_with_timestamp() {
    let msi_path = test_msi_path();

    if !msi_path.exists() {
        panic!(
            "Test MSI not found: {}. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
    }

    let (proxy_url, proxy_token) =
        get_remote_config().expect("YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN must be set");

    println!("Using remote proxy: {proxy_url}");

    let data = fs::read(&msi_path).expect("Failed to read test MSI");
    let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

    // Create remote signer client
    let config = RemoteSignerConfig::new(&proxy_url, &proxy_token);
    let client = RemoteSigner::new(config).expect("Should create remote client");

    // Get certificate from remote YubiKey
    let cert_der = client
        .get_certificate(piv_slot)
        .await
        .expect("Should get certificate");

    // Create MSI signer
    let signer = MsiSigner::new(&cert_der, HashAlgorithm::Sha256).expect("Should create signer");

    // Compute TBS hash
    let context = signer
        .compute_tbs_hash_with_context(&data)
        .expect("Should compute TBS hash");

    // Sign with remote YubiKey
    let signature = client
        .sign_hash(context.tbs_hash(), piv_slot)
        .await
        .expect("Should sign hash");

    // Get timestamp
    let ts_url = TimestampUrl::new("http://ts.ssl.com").expect("Valid timestamp URL");
    let ts_client = TimestampClient::new(&ts_url);
    let timestamp_token = ts_client
        .get_timestamp(&signature)
        .await
        .expect("Should get timestamp");
    println!("Got timestamp token: {} bytes", timestamp_token.len());

    // Create signed MSI with timestamp
    let signed_msi = signer
        .create_signed_msi_with_context(&data, &context, &signature, Some(&timestamp_token))
        .expect("Should create signed MSI with timestamp");

    let signed_bytes = signed_msi.into_bytes();
    println!("Signed MSI with timestamp: {} bytes", signed_bytes.len());

    // Write to temp file for external verification
    let output_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("temp/test_signed_timestamped.msi");
    fs::write(&output_path, &signed_bytes).expect("Should write signed MSI");
    println!("Signed MSI written to: {}", output_path.display());

    println!("MSI remote signing with timestamp: OK");
}

#[tokio::test]
#[ignore = "Requires remote signing proxy and Windows for signature verification"]
async fn test_msi_signature_verification() {
    let msi_path = test_msi_path();

    if !msi_path.exists() {
        panic!(
            "Test MSI not found: {}. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
    }

    let (proxy_url, proxy_token) =
        get_remote_config().expect("YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN must be set");

    let data = fs::read(&msi_path).expect("Failed to read test MSI");
    let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

    // Create remote signer client
    let config = RemoteSignerConfig::new(&proxy_url, &proxy_token);
    let client = RemoteSigner::new(config).expect("Should create remote client");

    // Get certificate and sign
    let cert_der = client
        .get_certificate(piv_slot)
        .await
        .expect("Should get certificate");
    let signer = MsiSigner::new(&cert_der, HashAlgorithm::Sha256).expect("Should create signer");
    let context = signer
        .compute_tbs_hash_with_context(&data)
        .expect("Should compute TBS hash");
    let signature = client
        .sign_hash(context.tbs_hash(), piv_slot)
        .await
        .expect("Should sign hash");

    // Create signed MSI
    let signed_msi = signer
        .create_signed_msi_with_context(&data, &context, &signature, None)
        .expect("Should create signed MSI");

    let signed_bytes = signed_msi.into_bytes();

    // Write to temp file
    let output_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("temp/test_signed_verify.msi");
    fs::write(&output_path, &signed_bytes).expect("Should write signed MSI");

    // Verify using Windows signtool (if available)
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        // Try to find signtool
        let signtool_paths = [
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x86\signtool.exe",
        ];

        let signtool = signtool_paths.iter().find(|p| PathBuf::from(p).exists());

        if let Some(signtool_path) = signtool {
            let output = Command::new(signtool_path)
                .args(["verify", "/pa", output_path.to_str().unwrap()])
                .output()
                .expect("Failed to run signtool");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            println!("signtool stdout: {stdout}");
            println!("signtool stderr: {stderr}");

            assert!(
                output.status.success(),
                "Signature verification should succeed"
            );
            println!("Windows signature verification: PASSED");
        } else {
            println!("signtool not found, skipping Windows verification");
        }
    }

    // Also verify using PowerShell Get-AuthenticodeSignature
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "(Get-AuthenticodeSignature '{}').Status",
                    output_path.display()
                ),
            ])
            .output()
            .expect("Failed to run PowerShell");

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("Get-AuthenticodeSignature status: {status}");

        // Valid statuses: Valid, UnknownError (if cert not trusted), NotTrusted
        assert!(
            status == "Valid" || status == "UnknownError" || status == "NotTrusted",
            "Signature should be structurally valid (got: {status})"
        );
    }

    println!("MSI signature verification: OK");
}

/// Create a self-signed test certificate for unit tests.
fn create_test_certificate() -> Vec<u8> {
    use openssl::bn::BigNum;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let rsa = Rsa::generate(2048).expect("Should generate RSA key");
    let pkey = PKey::from_rsa(rsa).expect("Should create PKey");

    let mut name = X509NameBuilder::new().expect("Should create name builder");
    name.append_entry_by_text("CN", "Test Certificate")
        .expect("Should add CN");
    let name = name.build();

    let mut builder = X509Builder::new().expect("Should create X509 builder");
    builder.set_version(2).expect("Should set version");
    let serial = BigNum::from_u32(1)
        .expect("Should create serial")
        .to_asn1_integer()
        .expect("Should convert serial");
    builder
        .set_serial_number(&serial)
        .expect("Should set serial");
    builder.set_subject_name(&name).expect("Should set subject");
    builder.set_issuer_name(&name).expect("Should set issuer");

    use openssl::asn1::Asn1Time;
    let not_before = Asn1Time::days_from_now(0).expect("Should create not_before");
    let not_after = Asn1Time::days_from_now(1).expect("Should create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Should set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Should set not_after");
    builder.set_pubkey(&pkey).expect("Should set pubkey");
    builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .expect("Should sign");

    builder.build().to_der().expect("Should convert to DER")
}
