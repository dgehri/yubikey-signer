use std::fs;
use yubikey_signer::domain::crypto::HashAlgorithm;
use yubikey_signer::domain::msi::MsiHashView;
use yubikey_signer::services::msi_signer::MsiSigner;

fn create_test_cert() -> Vec<u8> {
    use openssl::bn::BigNum;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Certificate").unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    use openssl::asn1::Asn1Time;
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();

    builder.build().to_der().unwrap()
}

fn main() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    // Hash the original unsigned MSI using our direct method
    let unsigned_data = fs::read("temp/cadxio-x64-setup.msi").expect("read unsigned");
    let unsigned_view = MsiHashView::new(&unsigned_data);
    let direct_hash = unsigned_view
        .compute_hash(HashAlgorithm::Sha256)
        .expect("hash");
    println!(
        "Direct hash (MsiHashView):       {}",
        hex::encode(&direct_hash)
    );

    // Hash using MSI signer
    let cert = create_test_cert();
    let signer = MsiSigner::new(&cert, HashAlgorithm::Sha256).expect("create signer");
    let signer_hash = signer
        .compute_msi_hash(&unsigned_data)
        .expect("signer hash");
    println!(
        "Signer hash (MsiSigner):         {}",
        hex::encode(&signer_hash)
    );

    // Compute TBS context to see what hash gets embedded
    let context = signer
        .compute_tbs_hash_with_context(&unsigned_data)
        .expect("tbs context");
    println!(
        "Context MSI hash:                {}",
        hex::encode(context.msi_hash())
    );

    if direct_hash == signer_hash && signer_hash == context.msi_hash() {
        println!("All hashes match correctly!");
    } else {
        println!("MISMATCH detected!");
    }
}
