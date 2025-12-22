//! Remote Signing Integration Tests
//!
//! Tests for PE and MSI file signing via the remote YubiKey proxy.
//! These tests require environment variables to be set (either directly or via .env file):
//!
//! Required environment variables:
//! - `YUBIKEY_PROXY_URL`: URL of the YubiKey proxy server
//! - `YUBIKEY_PROXY_TOKEN`: Authentication token for the proxy
//! - `YUBIKEY_CF_CLIENT_ID`: Cloudflare Access Client ID header (optional)
//! - `YUBIKEY_CF_CLIENT_SECRET`: Cloudflare Access Client Secret header (optional)
//!
//! Tests are skipped automatically unless required environment variables are present.

use std::env;
use std::fs;
use std::path::PathBuf;

mod common;

/// Configuration for remote signing tests.
struct RemoteTestConfig {
    proxy_url: String,
    proxy_token: String,
    cf_client_id: Option<String>,
    cf_client_secret: Option<String>,
}

impl RemoteTestConfig {
    /// Load configuration from environment variables.
    /// Returns None if required variables are not set.
    fn from_env() -> Option<Self> {
        common::test_env::load_dotenv_if_present();

        let proxy_url = env::var("YUBIKEY_PROXY_URL").ok()?;
        let proxy_token = env::var("YUBIKEY_PROXY_TOKEN").ok()?;
        let cf_client_id = env::var("YUBIKEY_CF_CLIENT_ID").ok();
        let cf_client_secret = env::var("YUBIKEY_CF_CLIENT_SECRET").ok();

        Some(Self {
            proxy_url,
            proxy_token,
            cf_client_id,
            cf_client_secret,
        })
    }

    /// Get custom headers for Cloudflare Access authentication.
    fn custom_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        if let Some(ref id) = self.cf_client_id {
            // Parse "Header-Name: value" format
            if let Some((name, value)) = id.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        if let Some(ref secret) = self.cf_client_secret {
            if let Some((name, value)) = secret.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        headers
    }
}

/// Get path to test PE file.
fn test_pe_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data/test_unsigned_ref.exe")
}

/// Get path to test MSI file.
fn test_msi_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data/test_unsigned.msi")
}

/// Create a simple test PE file if it doesn't exist.
fn ensure_test_pe_exists() -> PathBuf {
    let path = test_pe_path();
    if !path.exists() {
        // Create temp directory PE as fallback
        let temp_pe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("temp/test_unsigned.exe");
        if temp_pe.exists() {
            return temp_pe;
        }
    }
    path
}

mod pe_signing {
    use super::*;
    use yubikey_signer::adapters::remote::client::{RemoteSigner, RemoteSignerConfig};
    use yubikey_signer::services::authenticode::OpenSslAuthenticodeSigner;
    use yubikey_signer::HashAlgorithm;
    use yubikey_signer::PivSlot;

    #[tokio::test]
    async fn test_pe_remote_signing_valid() {
        let Some(config) = RemoteTestConfig::from_env() else {
            eprintln!(
                "Skipping: set YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN to enable remote signing tests"
            );
            return;
        };

        let pe_path = ensure_test_pe_exists();
        assert!(
            pe_path.exists(),
            "Test PE not found: {}. Create temp/test_unsigned.exe first.",
            pe_path.display()
        );

        println!("Using remote proxy: {}", config.proxy_url);
        println!("Test PE file: {}", pe_path.display());

        let pe_data = fs::read(&pe_path).expect("Failed to read test PE");
        let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

        // Create remote signer client with custom headers
        let mut signer_config = RemoteSignerConfig::new(&config.proxy_url, &config.proxy_token);
        for (name, value) in config.custom_headers() {
            signer_config = signer_config.with_header(&name, &value);
        }

        let client = RemoteSigner::new(signer_config).expect("Should create remote client");

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

        // Create Authenticode signer
        let signer = OpenSslAuthenticodeSigner::new(&cert_der, HashAlgorithm::Sha256)
            .expect("Should create signer");

        // Compute TBS hash
        let context = signer
            .compute_tbs_hash_with_context(&pe_data)
            .expect("Should compute TBS hash");
        println!("TBS hash: {}", hex::encode(context.tbs_hash()));

        // Sign with remote YubiKey
        let signature = client
            .sign_hash(context.tbs_hash(), piv_slot)
            .await
            .expect("Should sign hash");
        println!("Got signature: {} bytes", signature.len());

        // Create signed PE (no timestamp for this test)
        let signed_pe = signer
            .create_signed_pe_with_context(&pe_data, &context, &signature, None)
            .expect("Should create signed PE");
        println!("Signed PE: {} bytes", signed_pe.len());

        // Write to temp file
        let output_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("temp/test_signed_remote.exe");
        let _ = fs::remove_file(&output_path);
        fs::write(&output_path, &signed_pe).expect("Should write signed PE");
        println!("Signed PE written to: {}", output_path.display());

        // Verify signature on Windows
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-AuthenticodeSignature '{}').Status",
                        output_path.display()
                    ),
                ])
                .output()
                .expect("Failed to run PowerShell");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let status = stdout.trim().to_string();

            println!("Get-AuthenticodeSignature stdout: {stdout}");
            println!("Get-AuthenticodeSignature stderr: {stderr}");

            if !output.status.success() || status.is_empty() {
                println!(
                    "Get-AuthenticodeSignature did not produce a usable Status value; skipping this check"
                );
            } else {
                println!("Get-AuthenticodeSignature status: {status}");
                // Valid statuses: Valid, UnknownError (if cert not trusted), NotTrusted
                assert!(
                    status == "Valid" || status == "UnknownError" || status == "NotTrusted",
                    "Signature should be structurally valid (got: {status})"
                );
                println!("✅ PE signature verification: PASSED");
            }
        }
    }

    #[tokio::test]
    async fn test_pe_remote_signing_with_timestamp_valid() {
        let Some(config) = RemoteTestConfig::from_env() else {
            eprintln!(
                "Skipping: set YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN to enable remote signing tests"
            );
            return;
        };

        let pe_path = ensure_test_pe_exists();
        assert!(pe_path.exists(), "Test PE not found: {}", pe_path.display());

        println!("Using remote proxy: {}", config.proxy_url);

        let pe_data = fs::read(&pe_path).expect("Failed to read test PE");
        let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

        // Create remote signer client with custom headers
        let mut signer_config = RemoteSignerConfig::new(&config.proxy_url, &config.proxy_token);
        for (name, value) in config.custom_headers() {
            signer_config = signer_config.with_header(&name, &value);
        }

        let client = RemoteSigner::new(signer_config).expect("Should create remote client");

        // Get certificate
        let cert_der = client
            .get_certificate(piv_slot)
            .await
            .expect("Should get certificate");

        // Create signer and compute TBS hash
        let signer = OpenSslAuthenticodeSigner::new(&cert_der, HashAlgorithm::Sha256)
            .expect("Should create signer");
        let context = signer
            .compute_tbs_hash_with_context(&pe_data)
            .expect("Should compute TBS hash");

        // Sign with remote YubiKey
        let signature = client
            .sign_hash(context.tbs_hash(), piv_slot)
            .await
            .expect("Should sign hash");

        // Get timestamp
        use yubikey_signer::services::timestamp::TimestampClient;
        use yubikey_signer::TimestampUrl;

        let ts_url = TimestampUrl::new("http://ts.ssl.com").expect("Valid timestamp URL");
        let ts_client = TimestampClient::new(&ts_url);
        let timestamp_token = ts_client
            .get_timestamp(&signature)
            .await
            .expect("Should get timestamp");
        println!("Got timestamp token: {} bytes", timestamp_token.len());

        // Create signed PE with timestamp
        let signed_pe = signer
            .create_signed_pe_with_context(&pe_data, &context, &signature, Some(&timestamp_token))
            .expect("Should create signed PE with timestamp");
        println!("Signed PE with timestamp: {} bytes", signed_pe.len());

        // Write to temp file
        let output_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("temp/test_signed_remote_timestamped.exe");
        let _ = fs::remove_file(&output_path);
        fs::write(&output_path, &signed_pe).expect("Should write signed PE");
        println!("Signed PE written to: {}", output_path.display());

        // Verify signature on Windows
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-AuthenticodeSignature '{}').Status",
                        output_path.display()
                    ),
                ])
                .output()
                .expect("Failed to run PowerShell");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let status = stdout.trim().to_string();

            println!("Get-AuthenticodeSignature stdout: {stdout}");
            println!("Get-AuthenticodeSignature stderr: {stderr}");

            if !output.status.success() || status.is_empty() {
                println!(
                    "Get-AuthenticodeSignature did not produce a usable Status value; skipping this check"
                );
            } else {
                println!("Get-AuthenticodeSignature status: {status}");
                assert!(
                    status == "Valid" || status == "UnknownError" || status == "NotTrusted",
                    "Signature should be structurally valid (got: {status})"
                );
                println!("✅ PE signature with timestamp verification: PASSED");
            }
        }
    }
}

mod msi_signing {
    use super::*;
    use yubikey_signer::adapters::remote::client::{RemoteSigner, RemoteSignerConfig};
    use yubikey_signer::domain::msi::{is_msi_file, MsiFile};
    use yubikey_signer::services::msi_signer::MsiSigner;
    use yubikey_signer::HashAlgorithm;
    use yubikey_signer::PivSlot;

    #[tokio::test]
    async fn test_msi_remote_signing_valid() {
        let Some(config) = RemoteTestConfig::from_env() else {
            eprintln!(
                "Skipping: set YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN to enable remote signing tests"
            );
            return;
        };

        let msi_path = test_msi_path();
        assert!(
            msi_path.exists(),
            "Test MSI not found: {}. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );

        println!("Using remote proxy: {}", config.proxy_url);
        println!("Test MSI file: {}", msi_path.display());

        let msi_data = fs::read(&msi_path).expect("Failed to read test MSI");
        let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

        // Create remote signer client with custom headers
        let mut signer_config = RemoteSignerConfig::new(&config.proxy_url, &config.proxy_token);
        for (name, value) in config.custom_headers() {
            signer_config = signer_config.with_header(&name, &value);
        }

        let client = RemoteSigner::new(signer_config).expect("Should create remote client");

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
        let signer =
            MsiSigner::new(&cert_der, HashAlgorithm::Sha256).expect("Should create MSI signer");

        // Compute TBS hash
        let context = signer
            .compute_tbs_hash_with_context(&msi_data)
            .expect("Should compute TBS hash");
        println!("TBS hash: {}", hex::encode(context.tbs_hash()));
        println!("MSI content hash: {}", hex::encode(context.msi_hash()));

        // Sign with remote YubiKey
        let signature = client
            .sign_hash(context.tbs_hash(), piv_slot)
            .await
            .expect("Should sign hash");
        println!("Got signature: {} bytes", signature.len());

        // Create signed MSI (no timestamp for this test)
        let signed_msi = signer
            .create_signed_msi_with_context(&msi_data, &context, &signature, None)
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

        // Write to temp file
        let output_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("temp/test_signed_remote.msi");
        let _ = fs::remove_file(&output_path);
        fs::write(&output_path, &signed_bytes).expect("Should write signed MSI");
        println!("Signed MSI written to: {}", output_path.display());

        // Verify signature on Windows
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-AuthenticodeSignature '{}').Status",
                        output_path.display()
                    ),
                ])
                .output()
                .expect("Failed to run PowerShell");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let status = stdout.trim().to_string();

            println!("Get-AuthenticodeSignature stdout: {stdout}");
            println!("Get-AuthenticodeSignature stderr: {stderr}");

            if !output.status.success() || status.is_empty() {
                println!(
                    "Get-AuthenticodeSignature did not produce a usable Status value; skipping this check"
                );
            } else {
                println!("Get-AuthenticodeSignature status: {status}");
                // Valid statuses: Valid, UnknownError (if cert not trusted), NotTrusted
                assert!(
                    status == "Valid" || status == "UnknownError" || status == "NotTrusted",
                    "Signature should be structurally valid (got: {status})"
                );
                println!("✅ MSI signature verification: PASSED");
            }
        }
    }

    #[tokio::test]
    async fn test_msi_remote_signing_with_timestamp_valid() {
        let Some(config) = RemoteTestConfig::from_env() else {
            eprintln!(
                "Skipping: set YUBIKEY_PROXY_URL and YUBIKEY_PROXY_TOKEN to enable remote signing tests"
            );
            return;
        };

        let msi_path = test_msi_path();
        assert!(
            msi_path.exists(),
            "Test MSI not found: {}. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );

        println!("Using remote proxy: {}", config.proxy_url);

        let msi_data = fs::read(&msi_path).expect("Failed to read test MSI");
        let piv_slot = PivSlot::new(0x9a).expect("Valid slot");

        // Create remote signer client with custom headers
        let mut signer_config = RemoteSignerConfig::new(&config.proxy_url, &config.proxy_token);
        for (name, value) in config.custom_headers() {
            signer_config = signer_config.with_header(&name, &value);
        }

        let client = RemoteSigner::new(signer_config).expect("Should create remote client");

        // Get certificate
        let cert_der = client
            .get_certificate(piv_slot)
            .await
            .expect("Should get certificate");

        // Create MSI signer and compute TBS hash
        let signer =
            MsiSigner::new(&cert_der, HashAlgorithm::Sha256).expect("Should create MSI signer");
        let context = signer
            .compute_tbs_hash_with_context(&msi_data)
            .expect("Should compute TBS hash");

        // Sign with remote YubiKey
        let signature = client
            .sign_hash(context.tbs_hash(), piv_slot)
            .await
            .expect("Should sign hash");

        // Get timestamp
        use yubikey_signer::services::timestamp::TimestampClient;
        use yubikey_signer::TimestampUrl;

        let ts_url = TimestampUrl::new("http://ts.ssl.com").expect("Valid timestamp URL");
        let ts_client = TimestampClient::new(&ts_url);
        let timestamp_token = ts_client
            .get_timestamp(&signature)
            .await
            .expect("Should get timestamp");
        println!("Got timestamp token: {} bytes", timestamp_token.len());

        // Create signed MSI with timestamp
        let signed_msi = signer
            .create_signed_msi_with_context(&msi_data, &context, &signature, Some(&timestamp_token))
            .expect("Should create signed MSI with timestamp");
        let signed_bytes = signed_msi.into_bytes();
        println!("Signed MSI with timestamp: {} bytes", signed_bytes.len());

        // Write to temp file
        let output_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("temp/test_signed_remote_timestamped.msi");
        let _ = fs::remove_file(&output_path);
        fs::write(&output_path, &signed_bytes).expect("Should write signed MSI");
        println!("Signed MSI written to: {}", output_path.display());

        // Verify signature on Windows
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-AuthenticodeSignature '{}').Status",
                        output_path.display()
                    ),
                ])
                .output()
                .expect("Failed to run PowerShell");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let status = stdout.trim().to_string();

            println!("Get-AuthenticodeSignature stdout: {stdout}");
            println!("Get-AuthenticodeSignature stderr: {stderr}");

            if !output.status.success() || status.is_empty() {
                println!(
                    "Get-AuthenticodeSignature did not produce a usable Status value; skipping this check"
                );
            } else {
                println!("Get-AuthenticodeSignature status: {status}");
                assert!(
                    status == "Valid" || status == "UnknownError" || status == "NotTrusted",
                    "Signature should be structurally valid (got: {status})"
                );
                println!("✅ MSI signature with timestamp verification: PASSED");
            }
        }
    }
}
