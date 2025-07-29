//! Demonstration of the new type-safe wrapper types

use yubikey_signer::{PivPin, PivSlot, TimestampUrl, HashData, SecurePath, HashAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 YubiKey Signer - New Type Safety Demo");
    println!("=========================================");
    
    // Demonstrate PivPin validation
    println!("\n📌 PIN Validation:");
    match PivPin::new("123456".to_string()) {
        Ok(pin) => println!("✅ Valid PIN created: {}", pin),
        Err(e) => println!("❌ PIN validation failed: {}", e),
    }
    
    match PivPin::new("12345".to_string()) {
        Ok(pin) => println!("✅ Valid PIN created: {}", pin),
        Err(e) => println!("❌ PIN validation failed: {} (expected - too short)", e),
    }
    
    // Demonstrate PivSlot validation  
    println!("\n🔑 PIV Slot Validation:");
    match PivSlot::new(0x9c) {
        Ok(slot) => println!("✅ Valid slot created: {}", slot.description()),
        Err(e) => println!("❌ Slot validation failed: {}", e),
    }
    
    match PivSlot::new(0xFF) {
        Ok(slot) => println!("✅ Valid slot created: {}", slot.description()),
        Err(e) => println!("❌ Slot validation failed: {} (expected - invalid slot)", e),
    }
    
    // Demonstrate TimestampUrl validation
    println!("\n⏰ Timestamp URL Validation:");
    match TimestampUrl::new("https://timestamp.digicert.com") {
        Ok(url) => println!("✅ Valid URL created: {}", url.as_str()),
        Err(e) => println!("❌ URL validation failed: {}", e),
    }
    
    match TimestampUrl::new("not-a-url") {
        Ok(url) => println!("✅ Valid URL created: {}", url.as_str()),
        Err(e) => println!("❌ URL validation failed: {} (expected - invalid URL)", e),
    }
    
    // Demonstrate SecurePath validation
    println!("\n📁 Secure Path Validation:");
    let temp_path = std::env::temp_dir().join("test.exe");
    match SecurePath::new(temp_path.clone()) {
        Ok(path) => println!("✅ Valid path created: {:?}", path.as_path()),
        Err(e) => println!("❌ Path validation failed: {}", e),
    }
    
    // Demonstrate HashData validation
    println!("\n🔐 Hash Data Validation:");
    let valid_hash = vec![0u8; 32]; // SHA-256 hash
    match HashData::new(valid_hash, Some(HashAlgorithm::Sha256)) {
        Ok(hash) => println!("✅ Valid hash created: {} bytes for SHA-256", 
                           hash.as_bytes().len()),
        Err(e) => println!("❌ Hash validation failed: {}", e),
    }
    
    let invalid_hash = vec![0u8; 16]; // Too short for SHA-256
    match HashData::new(invalid_hash, Some(HashAlgorithm::Sha256)) {
        Ok(hash) => println!("✅ Valid hash created: {} bytes", hash.as_bytes().len()),
        Err(e) => println!("❌ Hash validation failed: {} (expected - wrong size)", e),
    }
    
    println!("\n🎯 All type safety demonstrations completed!");
    println!("The new-type pattern successfully prevents invalid inputs at compile-time");
    println!("and runtime, improving security and reliability.");
    
    Ok(())
}
