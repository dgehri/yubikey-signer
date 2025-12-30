use std::cmp::Ordering;

/// Compare stream names using raw UTF-16LE byte comparison (OUR VERSION).
fn msi_stream_compare_utf16_ours(a: &[u8], b: &[u8]) -> Ordering {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    // If names are equal up to min length, longer name wins (comes first)
    match a.len().cmp(&b.len()) {
        Ordering::Less => Ordering::Greater, // a is shorter, so b wins (a > b)
        Ordering::Greater => Ordering::Less, // a is longer, so a wins (a < b)
        Ordering::Equal => Ordering::Equal,
    }
}

/// osslsigncode version - uses nameLen which INCLUDES the NUL terminator!
fn msi_stream_compare_ossl(a_with_nul: &[u8], b_with_nul: &[u8]) -> Ordering {
    let min_len = a_with_nul.len().min(b_with_nul.len());
    for i in 0..min_len {
        match a_with_nul[i].cmp(&b_with_nul[i]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    // longer wins
    match a_with_nul.len().cmp(&b_with_nul.len()) {
        Ordering::Less => Ordering::Greater,
        Ordering::Greater => Ordering::Less,
        Ordering::Equal => Ordering::Equal,
    }
}

fn main() {
    // Test with example names from MSI (UTF-16LE)
    // Name "abc" = [0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x00, 0x00] with nul
    // Name "ab" = [0x61, 0x00, 0x62, 0x00, 0x00, 0x00] with nul

    let name_abc_with_nul = vec![0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x00, 0x00];
    let name_ab_with_nul = vec![0x61, 0x00, 0x62, 0x00, 0x00, 0x00];

    let name_abc_no_nul = vec![0x61, 0x00, 0x62, 0x00, 0x63, 0x00];
    let name_ab_no_nul = vec![0x61, 0x00, 0x62, 0x00];

    println!("=== Testing sort order ===");
    println!(
        "Our version (no nul): abc vs ab = {:?}",
        msi_stream_compare_utf16_ours(&name_abc_no_nul, &name_ab_no_nul)
    );
    println!(
        "OSSL version (with nul): abc vs ab = {:?}",
        msi_stream_compare_ossl(&name_abc_with_nul, &name_ab_with_nul)
    );

    // Now test with names that share same prefix but have different chars after
    // osslsigncode compares with nul bytes included
    // "ab\0" (len=6) vs "abc\0" (len=8): compare 6 bytes
    // bytes: [61 00 62 00 00 00] vs [61 00 62 00 63 00]
    // At index 4: 00 vs 63 -> 00 < 63, so ab < abc -> ab comes first

    println!("\nosslsigncode MIN(6,8)=6, compare first 6 bytes:");
    println!("  ab\\0: {:02x?}", &name_ab_with_nul);
    println!("  abc\\0: {:02x?}", &name_abc_with_nul[..6]);

    // In osslsigncode:
    // memcmp("ab\0\0", "abc\0", 6) compares:
    // 61 61 -> equal
    // 00 00 -> equal
    // 62 62 -> equal
    // 00 00 -> equal
    // 00 63 -> 00 < 63, return -1 (a < b)

    println!("\nActual byte comparison for osslsigncode:");
    let min_len = name_ab_with_nul.len().min(name_abc_with_nul.len());
    for i in 0..min_len {
        let a = name_ab_with_nul[i];
        let b = name_abc_with_nul[i];
        println!("  idx {}: {:02x} vs {:02x} = {:?}", i, a, b, a.cmp(&b));
        if a != b {
            println!("  -> ab comes BEFORE abc (because 00 < 63)!");
            break;
        }
    }

    println!("\n=== KEY INSIGHT ===");
    println!("osslsigncode sorts ab BEFORE abc (because null byte < 'c')");
    println!("Our code sorts abc BEFORE ab (because longer wins after equal prefix)");
    println!("This causes DIFFERENT hash order!");
}
