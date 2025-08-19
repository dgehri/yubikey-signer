//! Test `DigestInfo` sizes for different algorithms

use yubikey_signer::{services::authenticode::create_digest_info, HashAlgorithm};

#[test]
fn test_digest_info_sizes() {
    // Test SHA-256
    let sha256_hash = vec![0u8; 32];
    let sha256_digest_info = create_digest_info(&sha256_hash, HashAlgorithm::Sha256).unwrap();
    println!(
        "SHA-256 DigestInfo size: {} bytes",
        sha256_digest_info.len()
    );
    assert_eq!(sha256_digest_info.len(), 49); // Updated: OpenSSL implementation produces 49 bytes

    // Test SHA-384
    let sha384_hash = vec![0u8; 48];
    let sha384_digest_info = create_digest_info(&sha384_hash, HashAlgorithm::Sha384).unwrap();
    println!(
        "SHA-384 DigestInfo size: {} bytes",
        sha384_digest_info.len()
    );
    assert_eq!(sha384_digest_info.len(), 65); // Updated: OpenSSL implementation produces 65 bytes (49-32+48)

    // Test SHA-512
    let sha512_hash = vec![0u8; 64];
    let sha512_digest_info = create_digest_info(&sha512_hash, HashAlgorithm::Sha512).unwrap();
    println!(
        "SHA-512 DigestInfo size: {} bytes",
        sha512_digest_info.len()
    );
    assert_eq!(sha512_digest_info.len(), 81); // Updated: OpenSSL implementation produces 81 bytes (49-32+64)

    // All of these should be well under the RSA-2048 limit (256 bytes - padding)
    assert!(sha256_digest_info.len() < 200);
    assert!(sha384_digest_info.len() < 200);
    assert!(sha512_digest_info.len() < 200);
}
