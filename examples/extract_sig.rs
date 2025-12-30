use std::fs;
use yubikey_signer::domain::crypto::HashAlgorithm;
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
    let unsigned_data = fs::read("temp/cadxio-x64-setup.msi").expect("read unsigned");

    let cert = create_test_cert();
    let signer = MsiSigner::new(&cert, HashAlgorithm::Sha256).expect("create signer");
    let _context = signer
        .compute_tbs_hash_with_context(&unsigned_data)
        .expect("tbs context");

    // The SPC content is stored in the context, but it's private.
    // Let me extract the hash from the signed MSI instead.

    // Read the signed MSI
    let signed_data = fs::read("temp/cadxio_signed.msi").expect("read signed");

    // Extract the signature stream
    let cursor = std::io::Cursor::new(&signed_data);
    let mut cfb = cfb::CompoundFile::open(cursor).expect("open cfb");

    // Read the DigitalSignature stream
    let path = std::path::Path::new("\u{0005}DigitalSignature");
    let mut sig_stream = cfb.open_stream(path).expect("open sig stream");
    let mut sig_data = Vec::new();
    std::io::Read::read_to_end(&mut sig_stream, &mut sig_data).expect("read sig");

    println!("Signature size: {} bytes", sig_data.len());

    // Write to a temp file for analysis
    fs::write("temp/extracted_sig_debug.der", &sig_data).expect("write sig");
    println!("Written signature to temp/extracted_sig_debug.der");
}
