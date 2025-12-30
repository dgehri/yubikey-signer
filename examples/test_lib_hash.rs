//! Direct test of library hash vs manual implementation

use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::io::Read;
use yubikey_signer::domain::msi::MsiHashView;
use yubikey_signer::HashAlgorithm;

fn compute_correct_hash(data: &[u8]) -> Vec<u8> {
    use cfb::CompoundFile;
    use std::io::Cursor;

    fn msi_stream_compare_utf16(a: &[u8], b: &[u8]) -> Ordering {
        let min_len = a.len().min(b.len());
        for i in 0..min_len {
            match a[i].cmp(&b[i]) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        match a.len().cmp(&b.len()) {
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
            Ordering::Equal => Ordering::Equal,
        }
    }

    let cursor = Cursor::new(data);
    let mut cfb = CompoundFile::open(cursor).unwrap();

    let entries: Vec<_> = cfb
        .walk()
        .filter(cfb::Entry::is_stream)
        .map(|e| e.path().to_path_buf())
        .collect();

    let mut streams: Vec<(String, Vec<u8>)> = Vec::new();
    for path in entries {
        let path_str = path.display().to_string();
        if path_str.contains("\u{0005}DigitalSignature")
            || path_str.contains("\u{0005}MsiDigitalSignatureEx")
        {
            continue;
        }
        let mut stream = cfb.open_stream(&path).unwrap();
        let mut content = Vec::new();
        stream.read_to_end(&mut content).unwrap();
        if !content.is_empty() {
            streams.push((path_str, content));
        }
    }

    streams.sort_by(|a, b| {
        let a_bytes: Vec<u16> = a.0.chars().map(|c| c as u16).collect();
        let b_bytes: Vec<u16> = b.0.chars().map(|c| c as u16).collect();
        let a_u8: Vec<u8> = a_bytes.iter().flat_map(|&u| u.to_le_bytes()).collect();
        let b_u8: Vec<u8> = b_bytes.iter().flat_map(|&u| u.to_le_bytes()).collect();
        msi_stream_compare_utf16(&a_u8, &b_u8)
    });

    let sector_size = 1usize << u16::from_le_bytes([data[0x1E], data[0x1F]]) as usize;
    let first_dir_sector =
        u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]) as usize;
    let root_offset = sector_size + first_dir_sector * sector_size;
    let root_clsid = &data[root_offset + 0x50..root_offset + 0x60];

    let mut hasher = Sha256::new();
    for (_, content) in &streams {
        hasher.update(content);
    }
    hasher.update(root_clsid);
    hasher.finalize().to_vec()
}

fn main() {
    let orig_data = std::fs::read("temp/msi-issue/linkcad-x64-setup.msi").unwrap();

    println!("Testing hash computation...");

    let correct_hash = compute_correct_hash(&orig_data);
    println!("Correct hash (cfb crate): {}", hex::encode(&correct_hash));

    let view = MsiHashView::new(&orig_data);
    let lib_hash = view.compute_hash(HashAlgorithm::Sha256).unwrap();
    println!("Library hash:             {}", hex::encode(&lib_hash));

    println!("\nMatch: {}", correct_hash == lib_hash);

    if correct_hash != lib_hash {
        println!("\nHashes differ! Need to investigate...");
    }
}
