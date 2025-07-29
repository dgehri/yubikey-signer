//! Quick test to check hash sizes and DigestInfo structure
use sha2::{Digest, Sha256};
use yubikey_signer::{HashAlgorithm, SigningConfig};

#[tokio::test] 
#[ignore = "Debug test"]
async fn debug_hash_sizes() {
    // Check what size hash we're generating
    let test_data = b"Hello, world!";
    let mut hasher = Sha256::new();
    hasher.update(test_data);
    let hash = hasher.finalize();
    
    println!("SHA256 hash size: {} bytes", hash.len());
    println!("SHA256 hash: {:02x?}", hash.as_slice());
    
    // This should be 32 bytes for SHA256
    assert_eq!(hash.len(), 32);
}

#[tokio::test]
#[ignore = "Debug test"] 
async fn debug_digest_info() {
    // Test creating a proper DigestInfo structure for RSA signing
    use yubikey_signer::authenticode::create_digest_info;
    
    let hash = vec![0u8; 32]; // 32-byte SHA256 hash
    let digest_info = create_digest_info(&hash, yubikey_signer::HashAlgorithm::Sha256).unwrap();
    
    println!("DigestInfo size: {} bytes", digest_info.len());
    println!("DigestInfo: {:02x?}", digest_info);
    
    // DigestInfo should be larger than the raw hash
    assert!(digest_info.len() > hash.len());
}
