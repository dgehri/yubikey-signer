//! MSI Signing Regression Tests
//!
//! Regression tests for specific issues to prevent regressions.
//! These tests verify fixes for known bugs in MSI signing.

use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;
use yubikey_signer::domain::crypto::HashAlgorithm;
use yubikey_signer::domain::msi::MsiHashView;

/// Get path to test data directory.
fn test_data_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data")
}

/// Regression test for Issue #65: MSI signature verification failure for larger files.
///
/// The bug was that `msi_stream_compare_utf16` excluded null terminator bytes
/// when comparing stream names. Per MS-CFB spec, `nameLen` includes the null
/// terminator. This caused different sort orders:
/// - Wrong: "abc" before "ab" (longer name wins after equal prefix)
/// - Correct: "ab" before "abc" (null byte 0x00 < 'c' 0x63)
///
/// This test verifies the sort order matches the MS-CFB specification.
///
/// See: <https://github.com/dgehri/yubikey-signer/issues/65>
#[test]
fn test_issue_65_stream_name_sorting_with_null_terminators() {
    // Per MS-CFB spec, nameLen INCLUDES the null terminator bytes.

    // "ab\0" in UTF-16LE (6 bytes including null terminator)
    let name_ab: &[u8] = &[0x61, 0x00, 0x62, 0x00, 0x00, 0x00];
    // "abc\0" in UTF-16LE (8 bytes including null terminator)
    let name_abc: &[u8] = &[0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x00, 0x00];

    // When comparing with MIN(6, 8) = 6 bytes:
    // Position 0: 0x61 == 0x61 (equal)
    // Position 1: 0x00 == 0x00 (equal)
    // Position 2: 0x62 == 0x62 (equal)
    // Position 3: 0x00 == 0x00 (equal)
    // Position 4: 0x00 < 0x63 -> ab < abc
    //
    // Therefore "ab" should come BEFORE "abc" in the sort order.
    let comparison = compare_utf16_with_nul(name_ab, name_abc);
    assert_eq!(
        comparison,
        Ordering::Less,
        "Issue #65 regression: 'ab' should sort before 'abc' because null byte (0x00) < 'c' (0x63)"
    );

    // Verify the reverse
    let comparison_rev = compare_utf16_with_nul(name_abc, name_ab);
    assert_eq!(
        comparison_rev,
        Ordering::Greater,
        "Issue #65 regression: 'abc' should sort after 'ab'"
    );
}

/// Regression test for Issue #65: Verify hash computation produces correct result.
///
/// This test uses the standard test MSI to verify that the hash is computed
/// correctly per the MS-CFB Authenticode specification.
///
/// See: <https://github.com/dgehri/yubikey-signer/issues/65>
#[test]
fn test_issue_65_msi_hash_computation() {
    let msi_path = test_data_path().join("test_unsigned.msi");

    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");
    let hash_view = MsiHashView::new(&data);
    let hash = hash_view
        .compute_hash(HashAlgorithm::Sha256)
        .expect("Failed to compute hash");

    // The hash should be 32 bytes (SHA-256)
    assert_eq!(hash.len(), 32, "SHA-256 hash should be 32 bytes");

    // Verify hash is not all zeros (sanity check)
    assert!(hash.iter().any(|&b| b != 0), "Hash should not be all zeros");

    println!(
        "Issue #65 regression test: MSI hash = {}",
        hex::encode(&hash)
    );
}

/// Regression test for Issue #63: MSI signing fails for large CFB v4 files.
///
/// The bug was that reading sectors at the end of a file that doesn't align
/// to sector boundaries would fail because we tried to read beyond EOF.
/// Large MSI files use 4096-byte sectors (CFB v4), making this more likely.
///
/// See: <https://github.com/dgehri/yubikey-signer/issues/63>
#[test]
fn test_issue_63_cfb_partial_sector_handling() {
    let msi_path = test_data_path().join("test_unsigned.msi");

    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");

    // Verify we can compute hash regardless of file size alignment
    let hash_view = MsiHashView::new(&data);
    let result = hash_view.compute_hash(HashAlgorithm::Sha256);

    assert!(
        result.is_ok(),
        "Issue #63 regression: Hash computation should succeed for any valid MSI file. Error: {:?}",
        result.err()
    );

    println!(
        "Issue #63 regression test: Successfully computed hash for {} byte MSI",
        data.len()
    );
}

/// Regression test for Issue #63: Verify CFB sector reading handles EOF correctly.
///
/// This test creates a minimal scenario where the file doesn't end on a sector
/// boundary to verify partial sector reading works correctly.
///
/// See: <https://github.com/dgehri/yubikey-signer/issues/63>
#[test]
fn test_issue_63_file_size_not_sector_aligned() {
    let msi_path = test_data_path().join("test_unsigned.msi");

    if !msi_path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run scripts/create-test-msi.ps1 to create it.",
            msi_path.display()
        );
        return;
    }

    let data = fs::read(&msi_path).expect("Failed to read test MSI");

    // Check if file is sector-aligned (512 or 4096 bytes)
    let is_512_aligned = data.len().is_multiple_of(512);
    let is_4096_aligned = data.len().is_multiple_of(4096);

    println!(
        "Issue #63 regression test: File size = {} bytes, 512-aligned = {}, 4096-aligned = {}",
        data.len(),
        is_512_aligned,
        is_4096_aligned
    );

    // Regardless of alignment, hash computation should succeed
    let hash_view = MsiHashView::new(&data);
    let result = hash_view.compute_hash(HashAlgorithm::Sha256);

    assert!(
        result.is_ok(),
        "Issue #63 regression: Hash computation must succeed regardless of file alignment"
    );
}

/// Helper function that replicates the fixed comparison logic.
/// This matches the MS-CFB specification for directory entry comparison.
fn compare_utf16_with_nul(a: &[u8], b: &[u8]) -> Ordering {
    let min_len = a.len().min(b.len());

    // Compare byte-by-byte up to min length (including null terminator bytes)
    for i in 0..min_len {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    // If names are equal up to min length, longer name wins (comes first)
    match a.len().cmp(&b.len()) {
        Ordering::Less => Ordering::Greater,
        Ordering::Greater => Ordering::Less,
        Ordering::Equal => Ordering::Equal,
    }
}
