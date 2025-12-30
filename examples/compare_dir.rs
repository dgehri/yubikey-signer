use cfb::CompoundFile;
use std::fs;
use std::io::Cursor;

fn main() {
    let unsigned_data = fs::read("temp/cadxio-x64-setup.msi").expect("read unsigned");
    let unsigned_cursor = Cursor::new(&unsigned_data);
    let unsigned_cfb = CompoundFile::open(unsigned_cursor).expect("parse unsigned");

    let signed_data = fs::read("temp/cadxio_signed.msi").expect("read signed");
    let signed_cursor = Cursor::new(&signed_data);
    let signed_cfb = CompoundFile::open(signed_cursor).expect("parse signed");

    println!("=== Unsigned MSI directory entries ===");
    let mut unsigned_entries: Vec<_> = unsigned_cfb.walk().collect();
    unsigned_entries.sort_by(|a, b| a.path().cmp(b.path()));
    for entry in &unsigned_entries {
        println!(
            "  {} ({})",
            entry.path().display(),
            if entry.is_stream() {
                "stream"
            } else {
                "storage"
            }
        );
    }

    println!("\n=== Signed MSI directory entries ===");
    let mut signed_entries: Vec<_> = signed_cfb.walk().collect();
    signed_entries.sort_by(|a, b| a.path().cmp(b.path()));
    for entry in &signed_entries {
        println!(
            "  {} ({})",
            entry.path().display(),
            if entry.is_stream() {
                "stream"
            } else {
                "storage"
            }
        );
    }

    println!(
        "\nUnsigned entries: {}, Signed entries: {}",
        unsigned_entries.len(),
        signed_entries.len()
    );
}
