use std::fs;
use yubikey_signer::domain::crypto::HashAlgorithm;
use yubikey_signer::domain::msi::MsiHashView;

fn main() {
    let data = fs::read("temp/cadxio-x64-setup.msi").expect("read MSI");
    let hash_view = MsiHashView::new(&data);
    let hash = hash_view
        .compute_hash(HashAlgorithm::Sha256)
        .expect("compute hash");

    println!("Our computed hash: {}", hex::encode(&hash));

    // osslsigncode computed: 53247110f66fc2c5b3eed49aab47938eda87edd7d5fbf287a3b5cf928da091e2
    println!("osslsigncode hash: 53247110f66fc2c5b3eed49aab47938eda87edd7d5fbf287a3b5cf928da091e2");

    let expected =
        hex::decode("53247110f66fc2c5b3eed49aab47938eda87edd7d5fbf287a3b5cf928da091e2").unwrap();
    println!("Match: {}", hash == expected);
}
