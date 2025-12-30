use std::fs;
use yubikey_signer::domain::crypto::HashAlgorithm;
use yubikey_signer::domain::msi::MsiHashView;

fn main() {
    // Hash the original unsigned MSI
    let unsigned_data = fs::read("temp/cadxio-x64-setup.msi").expect("read unsigned");
    let unsigned_view = MsiHashView::new(&unsigned_data);
    let unsigned_hash = unsigned_view
        .compute_hash(HashAlgorithm::Sha256)
        .expect("hash unsigned");
    println!("Unsigned MSI hash: {}", hex::encode(&unsigned_hash));

    // Hash the signed MSI (should be the same since we exclude signature streams)
    let signed_data = fs::read("temp/cadxio_signed.msi").expect("read signed");
    let signed_view = MsiHashView::new(&signed_data);
    let signed_hash = signed_view
        .compute_hash(HashAlgorithm::Sha256)
        .expect("hash signed");
    println!("Signed MSI hash:   {}", hex::encode(&signed_hash));

    if unsigned_hash == signed_hash {
        println!("SUCCESS: Hashes match!");
    } else {
        println!("FAILURE: Hash mismatch!");
    }
}
