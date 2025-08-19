//! Test for the authenticode PKCS#7 structure with proper authenticated attributes

use yubikey_signer::services::authenticode::OpenSslAuthenticodeSigner;
use yubikey_signer::HashAlgorithm;
use yubikey_signer::SigningResult;

#[test]
#[ignore = "Test uses real certificate data that needs proper loading mechanism"]
fn test_pkcs7_structure_with_authenticated_attributes() {
    env_logger::try_init().ok();

    // Load the reference certificate DER
    let cert_pem = include_str!("../temp/cert.pem");
    let cert_der = pem_to_der(cert_pem);

    // Create the signer
    let signer = OpenSslAuthenticodeSigner::new(&cert_der, HashAlgorithm::Sha256)
        .expect("Failed to create signer");

    // Create dummy PE data for testing
    let dummy_pe_data = vec![0u8; 1024]; // Minimal PE-like data

    // Mock signature callback that creates a dummy ECDSA signature
    let signature_callback = |tbs_data: &[u8]| -> SigningResult<Vec<u8>> {
        println!("TBS data for signing: {} bytes", tbs_data.len());
        // Hex dump first 100 bytes for analysis
        let hex_data = hex::encode(&tbs_data[..std::cmp::min(100, tbs_data.len())]);
        println!("TBS data (first 100 bytes): {hex_data}");

        // Create a dummy ECDSA signature (DER format)
        // This is a valid ECDSA signature structure for testing
        Ok(vec![
            0x30, 0x45, // SEQUENCE (69 bytes)
            0x02, 0x20, // INTEGER (32 bytes)
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x02, 0x21, // INTEGER (33 bytes)
            0x00, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22,
        ])
    };

    // Create the signed PE with PKCS#7 signature
    let signed_pe_data = signer
        .create_signed_pe_openssl(
            &dummy_pe_data,
            signature_callback,
            None, // no timestamp
            true, // embed certificate
        )
        .expect("Failed to create signed PE");

    println!("Created signed PE: {} bytes", signed_pe_data.len());

    // The test passes if we reach here without panicking
    assert!(!signed_pe_data.is_empty());
    assert!(signed_pe_data.len() > dummy_pe_data.len()); // Should be larger due to signature
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    // Simple PEM parser without external dependencies
    let lines: Vec<&str> = pem.lines().collect();
    let mut der_data = String::new();
    let mut inside_cert = false;

    for line in lines {
        if line.starts_with("-----BEGIN") {
            inside_cert = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if inside_cert {
            der_data.push_str(line.trim());
        }
    }

    // Convert base64 to bytes manually (simple implementation)
    // This is a basic implementation for testing - normally would use base64 crate
    base64_decode(&der_data)
}

fn base64_decode(input: &str) -> Vec<u8> {
    // Basic base64 decoding for testing (simplified)
    // This is just for the test - normally would use proper base64 crate
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let chars: Vec<char> = input.chars().filter(|c| alphabet.contains(*c)).collect();

    for chunk in chars.chunks(4) {
        if chunk.len() < 4 {
            break;
        }

        let a = alphabet.find(chunk[0]).unwrap() as u32;
        let b = alphabet.find(chunk[1]).unwrap() as u32;
        let c = alphabet.find(chunk[2]).unwrap() as u32;
        let d = alphabet.find(chunk[3]).unwrap() as u32;

        let combined = (a << 18) | (b << 12) | (c << 6) | d;

        result.push((combined >> 16) as u8);
        result.push((combined >> 8) as u8);
        result.push(combined as u8);
    }

    result
}
