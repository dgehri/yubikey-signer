//! MSI file hash computation for Authenticode signing.
//!
//! Implements the MSI-specific hash algorithm as used by Windows signing tools.
//! MSI files hash their stream contents in a specific sorted order, excluding
//! the signature streams themselves.
//!
//! The hash algorithm:
//! 1. Traverse the CFB directory tree recursively
//! 2. For each directory, sort children using raw UTF-16LE `memcmp` comparison
//! 3. Hash stream contents in sorted order (skip signature streams at root level)
//! 4. After processing each directory's children, append its 16-byte CLSID

use crate::domain::crypto::HashAlgorithm;
use crate::infra::error::{SigningError, SigningResult};
use cfb::CompoundFile;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::cmp::Ordering;
use std::io::{Cursor, Read};

/// View of an MSI file for hash computation.
///
/// This type provides a canonical view of the MSI file's content streams,
/// sorted according to Microsoft's Authenticode specification for MSI files.
pub struct MsiHashView<'a> {
    data: &'a [u8],
}

/// CFB directory entry structure (128 bytes).
#[repr(C)]
#[derive(Clone)]
struct DirectoryEntry {
    /// Entry name in UTF-16LE (64 bytes, including null terminator)
    name: [u8; 64],
    /// Name length in bytes (including null terminator)
    name_len: u16,
    /// Entry type: 0=invalid, 1=storage, 2=stream, 5=root
    entry_type: u8,
    /// Color: 0=red, 1=black
    color: u8,
    /// Left sibling stream ID
    left_sibling: u32,
    /// Right sibling stream ID
    right_sibling: u32,
    /// Child stream ID (for storage entries)
    child: u32,
    /// CLSID (16 bytes)
    clsid: [u8; 16],
    /// State bits
    state_bits: u32,
    /// Creation time
    create_time: u64,
    /// Modification time
    modify_time: u64,
    /// Starting sector
    start_sector: u32,
    /// Stream size (low 32 bits)
    size_low: u32,
    /// Stream size (high 32 bits, for version 4)
    size_high: u32,
}

impl DirectoryEntry {
    /// Read a directory entry from bytes.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 128 {
            return None;
        }
        let mut name = [0u8; 64];
        name.copy_from_slice(&bytes[0..64]);
        let name_len = u16::from_le_bytes([bytes[64], bytes[65]]);
        let entry_type = bytes[66];
        let color = bytes[67];
        let left_sibling = u32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]);
        let right_sibling = u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]);
        let child = u32::from_le_bytes([bytes[76], bytes[77], bytes[78], bytes[79]]);
        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&bytes[80..96]);
        let state_bits = u32::from_le_bytes([bytes[96], bytes[97], bytes[98], bytes[99]]);
        let create_time = u64::from_le_bytes([
            bytes[100], bytes[101], bytes[102], bytes[103], bytes[104], bytes[105], bytes[106],
            bytes[107],
        ]);
        let modify_time = u64::from_le_bytes([
            bytes[108], bytes[109], bytes[110], bytes[111], bytes[112], bytes[113], bytes[114],
            bytes[115],
        ]);
        let start_sector = u32::from_le_bytes([bytes[116], bytes[117], bytes[118], bytes[119]]);
        let size_low = u32::from_le_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]);
        let size_high = u32::from_le_bytes([bytes[124], bytes[125], bytes[126], bytes[127]]);

        Some(Self {
            name,
            name_len,
            entry_type,
            color,
            left_sibling,
            right_sibling,
            child,
            clsid,
            state_bits,
            create_time,
            modify_time,
            start_sector,
            size_low,
            size_high,
        })
    }

    /// Get the name bytes for sorting (UTF-16LE, **including** null terminator).
    ///
    /// Per the MS-CFB specification, `nameLen` includes the null terminator bytes.
    /// This is critical for correct sort order because shorter names with null
    /// terminators compare less than longer names with additional chars at the same
    /// position (e.g., "ab\0" < "abc" because '\0' < 'c').
    fn name_bytes_with_nul(&self) -> &[u8] {
        if self.name_len > 0 {
            &self.name[..self.name_len as usize]
        } else {
            &[]
        }
    }

    /// Get the name bytes (UTF-16LE, excluding null terminator) for display/matching.
    fn name_bytes(&self) -> &[u8] {
        if self.name_len >= 2 {
            &self.name[..self.name_len as usize - 2]
        } else {
            &[]
        }
    }

    /// Check if this is the `DigitalSignature` stream.
    fn is_digital_signature(&self) -> bool {
        // "\x05DigitalSignature" in UTF-16LE
        const DIGITAL_SIG_NAME: &[u8] = &[
            0x05, 0x00, b'D', 0x00, b'i', 0x00, b'g', 0x00, b'i', 0x00, b't', 0x00, b'a', 0x00,
            b'l', 0x00, b'S', 0x00, b'i', 0x00, b'g', 0x00, b'n', 0x00, b'a', 0x00, b't', 0x00,
            b'u', 0x00, b'r', 0x00, b'e', 0x00,
        ];
        self.name_bytes() == DIGITAL_SIG_NAME
    }

    /// Check if this is the `MsiDigitalSignatureEx` stream.
    fn is_digital_signature_ex(&self) -> bool {
        // "\x05MsiDigitalSignatureEx" in UTF-16LE
        const DIGITAL_SIG_EX_NAME: &[u8] = &[
            0x05, 0x00, b'M', 0x00, b's', 0x00, b'i', 0x00, b'D', 0x00, b'i', 0x00, b'g', 0x00,
            b'i', 0x00, b't', 0x00, b'a', 0x00, b'l', 0x00, b'S', 0x00, b'i', 0x00, b'g', 0x00,
            b'n', 0x00, b'a', 0x00, b't', 0x00, b'u', 0x00, b'r', 0x00, b'e', 0x00, b'E', 0x00,
            b'x', 0x00,
        ];
        self.name_bytes() == DIGITAL_SIG_EX_NAME
    }

    /// Get stream size.
    fn size(&self) -> u64 {
        u64::from(self.size_low) | (u64::from(self.size_high) << 32)
    }
}

/// CFB file parser for MSI hash computation.
struct CfbParser<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    mini_stream_cutoff: u32,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    directory_entries: Vec<DirectoryEntry>,
    mini_stream_data: Vec<u8>,
}

impl<'a> CfbParser<'a> {
    /// Parse a CFB file.
    fn parse(data: &'a [u8]) -> SigningResult<Self> {
        if data.len() < 512 {
            return Err(SigningError::MsiParsingError(
                "File too small for CFB header".into(),
            ));
        }

        // Verify CFB signature
        if data[0..8] != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
            return Err(SigningError::MsiParsingError(
                "Invalid CFB signature".into(),
            ));
        }

        let minor_version = u16::from_le_bytes([data[0x18], data[0x19]]);
        let major_version = u16::from_le_bytes([data[0x1A], data[0x1B]]);
        let sector_size_power = u16::from_le_bytes([data[0x1E], data[0x1F]]);
        let mini_sector_size_power = u16::from_le_bytes([data[0x20], data[0x21]]);

        let sector_size = 1usize << sector_size_power;
        let mini_sector_size = 1usize << mini_sector_size_power;

        let mini_stream_cutoff =
            u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]);
        let first_dir_sector = u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]);
        let first_mini_fat_sector =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
        let _num_fat_sectors = u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]);
        let first_difat_sector =
            u32::from_le_bytes([data[0x44], data[0x45], data[0x46], data[0x47]]);

        log::trace!(
            "CFB version {major_version}.{minor_version}, sector_size={sector_size}, mini_sector_size={mini_sector_size}, cutoff={mini_stream_cutoff}"
        );

        // Read FAT
        let mut fat = Vec::new();
        let mut difat_sectors = Vec::new();

        // First 109 DIFAT entries are in the header
        for i in 0..109 {
            let offset = 0x4C + i * 4;
            if offset + 4 > data.len() {
                break;
            }
            let sector = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if sector < 0xFFFF_FFFA {
                difat_sectors.push(sector);
            }
        }

        // Read additional DIFAT sectors if needed
        let mut current_difat = first_difat_sector;
        while current_difat < 0xFFFF_FFFA {
            let offset = sector_size + current_difat as usize * sector_size;
            if offset + sector_size > data.len() {
                break;
            }
            let entries_per_sector = sector_size / 4 - 1;
            for i in 0..entries_per_sector {
                let entry_offset = offset + i * 4;
                let sector = u32::from_le_bytes([
                    data[entry_offset],
                    data[entry_offset + 1],
                    data[entry_offset + 2],
                    data[entry_offset + 3],
                ]);
                if sector < 0xFFFF_FFFA {
                    difat_sectors.push(sector);
                }
            }
            let next_offset = offset + entries_per_sector * 4;
            current_difat = u32::from_le_bytes([
                data[next_offset],
                data[next_offset + 1],
                data[next_offset + 2],
                data[next_offset + 3],
            ]);
        }

        // Read FAT from DIFAT sectors
        for &fat_sector in &difat_sectors {
            let offset = sector_size + fat_sector as usize * sector_size;
            if offset + sector_size > data.len() {
                continue;
            }
            for i in 0..(sector_size / 4) {
                let entry_offset = offset + i * 4;
                let entry = u32::from_le_bytes([
                    data[entry_offset],
                    data[entry_offset + 1],
                    data[entry_offset + 2],
                    data[entry_offset + 3],
                ]);
                fat.push(entry);
            }
        }

        // Read directory entries
        // IMPORTANT: We must preserve entry indices even for empty entries,
        // because child/sibling pointers reference entries by index.
        let mut directory_entries = Vec::new();
        let mut current_sector = first_dir_sector;
        while current_sector < 0xFFFF_FFFA {
            let offset = sector_size + current_sector as usize * sector_size;
            if offset + sector_size > data.len() {
                break;
            }
            for i in 0..(sector_size / 128) {
                let entry_offset = offset + i * 128;
                if entry_offset + 128 > data.len() {
                    break;
                }
                if let Some(entry) = DirectoryEntry::from_bytes(&data[entry_offset..]) {
                    // Push all entries to preserve index ordering
                    directory_entries.push(entry);
                }
            }
            current_sector = if (current_sector as usize) < fat.len() {
                fat[current_sector as usize]
            } else {
                0xFFFF_FFFE
            };
        }

        // Read mini FAT
        let mut mini_fat = Vec::new();
        let mut current_sector = first_mini_fat_sector;
        while current_sector < 0xFFFF_FFFA {
            let offset = sector_size + current_sector as usize * sector_size;
            if offset + sector_size > data.len() {
                break;
            }
            for i in 0..(sector_size / 4) {
                let entry_offset = offset + i * 4;
                let entry = u32::from_le_bytes([
                    data[entry_offset],
                    data[entry_offset + 1],
                    data[entry_offset + 2],
                    data[entry_offset + 3],
                ]);
                mini_fat.push(entry);
            }
            current_sector = if (current_sector as usize) < fat.len() {
                fat[current_sector as usize]
            } else {
                0xFFFF_FFFE
            };
        }

        // Read mini stream (from root entry)
        let mut mini_stream_data = Vec::new();
        if !directory_entries.is_empty() {
            let root = &directory_entries[0];
            if root.entry_type == 5 {
                // Root entry
                let mut current_sector = root.start_sector;
                while current_sector < 0xFFFF_FFFA {
                    let offset = sector_size + current_sector as usize * sector_size;
                    if offset + sector_size > data.len() {
                        break;
                    }
                    mini_stream_data.extend_from_slice(&data[offset..offset + sector_size]);
                    current_sector = if (current_sector as usize) < fat.len() {
                        fat[current_sector as usize]
                    } else {
                        0xFFFF_FFFE
                    };
                }
            }
        }

        Ok(Self {
            data,
            sector_size,
            mini_sector_size,
            mini_stream_cutoff,
            fat,
            mini_fat,
            directory_entries,
            mini_stream_data,
        })
    }

    /// Read stream content.
    fn read_stream(&self, entry: &DirectoryEntry) -> SigningResult<Vec<u8>> {
        let size = entry.size() as usize;
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut content = Vec::with_capacity(size);

        if size < self.mini_stream_cutoff as usize {
            // Read from mini stream
            let mut current_sector = entry.start_sector;
            while current_sector < 0xFFFF_FFFA && content.len() < size {
                let offset = current_sector as usize * self.mini_sector_size;
                let end = (offset + self.mini_sector_size).min(self.mini_stream_data.len());
                if offset < self.mini_stream_data.len() {
                    let bytes_to_read = (size - content.len()).min(end - offset);
                    content
                        .extend_from_slice(&self.mini_stream_data[offset..offset + bytes_to_read]);
                }
                current_sector = if (current_sector as usize) < self.mini_fat.len() {
                    self.mini_fat[current_sector as usize]
                } else {
                    0xFFFF_FFFE
                };
            }
        } else {
            // Read from regular sectors
            let mut current_sector = entry.start_sector;
            while current_sector < 0xFFFF_FFFA && content.len() < size {
                let offset = self.sector_size + current_sector as usize * self.sector_size;
                // Handle partial sectors at end of file - read what's available.
                if offset < self.data.len() {
                    let available = self.data.len() - offset;
                    // Cap at sector_size to ensure we follow the FAT chain correctly
                    let bytes_to_read = (size - content.len()).min(available).min(self.sector_size);
                    content.extend_from_slice(&self.data[offset..offset + bytes_to_read]);
                }
                current_sector = if (current_sector as usize) < self.fat.len() {
                    self.fat[current_sector as usize]
                } else {
                    0xFFFF_FFFE
                };
            }
        }

        content.truncate(size);
        Ok(content)
    }

    /// Get children of a directory entry by index.
    fn get_children(&self, entry_index: usize) -> Vec<usize> {
        if entry_index >= self.directory_entries.len() {
            return Vec::new();
        }

        let entry = &self.directory_entries[entry_index];
        let child_id = entry.child;
        if child_id == 0xFFFF_FFFF || child_id as usize >= self.directory_entries.len() {
            return Vec::new();
        }

        // Collect all siblings via red-black tree traversal
        let mut children = Vec::new();
        self.collect_tree_entries(child_id as usize, &mut children);
        children
    }

    /// Collect entries from the red-black tree.
    fn collect_tree_entries(&self, entry_index: usize, result: &mut Vec<usize>) {
        if entry_index >= self.directory_entries.len() {
            return;
        }

        let entry = &self.directory_entries[entry_index];

        // Visit left sibling
        if entry.left_sibling != 0xFFFF_FFFF
            && (entry.left_sibling as usize) < self.directory_entries.len()
        {
            self.collect_tree_entries(entry.left_sibling as usize, result);
        }

        // Visit this node
        result.push(entry_index);

        // Visit right sibling
        if entry.right_sibling != 0xFFFF_FFFF
            && (entry.right_sibling as usize) < self.directory_entries.len()
        {
            self.collect_tree_entries(entry.right_sibling as usize, result);
        }
    }

    /// Get the root entry.
    #[allow(dead_code)]
    fn root_entry(&self) -> Option<&DirectoryEntry> {
        self.directory_entries.first()
    }
}

impl<'a> MsiHashView<'a> {
    /// Create a new hash view from MSI file data.
    ///
    /// # Arguments
    /// * `data` - The raw MSI file bytes
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Compute the Authenticode hash of the MSI file.
    ///
    /// The hash is computed according to the MSI hashing rules:
    /// 1. Traverse the CFB directory tree recursively
    /// 2. Sort children using raw UTF-16LE `memcmp` comparison
    /// 3. Hash stream contents in sorted order
    /// 4. After each directory, append its 16-byte CLSID
    /// 5. Skip signature streams at root level only
    ///
    /// # Arguments
    /// * `algorithm` - The hash algorithm to use
    ///
    /// # Returns
    /// The computed hash bytes.
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be parsed.
    pub fn compute_hash(&self, algorithm: HashAlgorithm) -> SigningResult<Vec<u8>> {
        let parser = CfbParser::parse(self.data)?;

        match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hash_directory(&parser, 0, true, &mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hash_directory(&parser, 0, true, &mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hash_directory(&parser, 0, true, &mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
        }
    }
}

/// Hash a directory entry and its children recursively.
///
/// This is a free function to avoid clippy's `self_only_used_in_recursion` lint.
fn hash_directory<D: Digest>(
    parser: &CfbParser,
    entry_index: usize,
    is_root: bool,
    hasher: &mut D,
) -> SigningResult<()> {
    if entry_index >= parser.directory_entries.len() {
        return Ok(());
    }

    let entry = &parser.directory_entries[entry_index];

    // Get and sort children
    // IMPORTANT: Use name_bytes_with_nul() for sorting per MS-CFB spec.
    // The nameLen field includes the null terminator bytes.
    let mut children = parser.get_children(entry_index);
    children.sort_by(|&a, &b| {
        let entry_a = &parser.directory_entries[a];
        let entry_b = &parser.directory_entries[b];
        msi_stream_compare_utf16(entry_a.name_bytes_with_nul(), entry_b.name_bytes_with_nul())
    });

    log::trace!(
        "Processing directory {} with {} children (is_root={})",
        entry_index,
        children.len(),
        is_root
    );

    // Process children in sorted order
    for child_index in children {
        let child = &parser.directory_entries[child_index];

        // Skip signature streams at root level only
        if is_root && (child.is_digital_signature() || child.is_digital_signature_ex()) {
            log::trace!("Skipping signature stream at root level");
            continue;
        }

        match child.entry_type {
            2 => {
                // Stream
                let size = child.size();
                // Skip empty or corrupted streams
                if size == 0 || size >= 0xFFFF_FFFA {
                    continue;
                }
                let content = parser.read_stream(child)?;
                log::trace!(
                    "Hashing stream: entry={}, size={} bytes",
                    child_index,
                    content.len()
                );
                hasher.update(&content);
            }
            1 => {
                // Storage - recurse
                hash_directory(parser, child_index, false, hasher)?;
            }
            _ => {}
        }
    }

    // Append this directory's CLSID (16 bytes)
    log::trace!("Appending CLSID for entry {entry_index}");
    hasher.update(entry.clsid);

    Ok(())
}

impl MsiHashView<'_> {
    /// Compute the extended signature hash (metadata hash).
    ///
    /// This hashes file metadata (names, sizes, timestamps) for use with
    /// `MsiDigitalSignatureEx`. The pre-hash is then included at the start
    /// of the main content hash.
    ///
    /// # Arguments
    /// * `algorithm` - The hash algorithm to use
    ///
    /// # Returns
    /// The pre-hash bytes for `MsiDigitalSignatureEx`.
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be parsed.
    pub fn compute_prehash(&self, algorithm: HashAlgorithm) -> SigningResult<Vec<u8>> {
        let cursor = Cursor::new(self.data);
        let cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        // Collect metadata from all entries
        let mut metadata_parts: Vec<(String, MsiEntryMetadata)> = Vec::new();

        for entry in cfb.walk() {
            let path_str = entry.path().display().to_string();

            // Skip signature streams
            if path_str.contains(super::DIGITAL_SIGNATURE_STREAM)
                || path_str.contains(super::DIGITAL_SIGNATURE_EX_STREAM)
            {
                continue;
            }

            if entry.is_stream() {
                let metadata = MsiEntryMetadata {
                    name: path_str.clone(),
                    size: entry.len() as u32,
                    // CFB crate doesn't expose timestamps directly, use placeholder
                    create_time: 0,
                    modify_time: 0,
                };
                metadata_parts.push((path_str, metadata));
            }
        }

        // Sort by MSI specification
        metadata_parts.sort_by(|a, b| msi_stream_compare(&a.0, &b.0));

        // Hash the metadata
        match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                for (_name, meta) in &metadata_parts {
                    hasher.update(meta.name.as_bytes());
                    hasher.update(meta.size.to_le_bytes());
                    hasher.update(meta.create_time.to_le_bytes());
                    hasher.update(meta.modify_time.to_le_bytes());
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                for (_name, meta) in &metadata_parts {
                    hasher.update(meta.name.as_bytes());
                    hasher.update(meta.size.to_le_bytes());
                    hasher.update(meta.create_time.to_le_bytes());
                    hasher.update(meta.modify_time.to_le_bytes());
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                for (_name, meta) in &metadata_parts {
                    hasher.update(meta.name.as_bytes());
                    hasher.update(meta.size.to_le_bytes());
                    hasher.update(meta.create_time.to_le_bytes());
                    hasher.update(meta.modify_time.to_le_bytes());
                }
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// Compute hash with extended signature support.
    ///
    /// When `use_msi_digital_signature_ex` is true, this computes:
    /// 1. The pre-hash (metadata hash)
    /// 2. The combined hash (pre-hash + content)
    ///
    /// # Arguments
    /// * `algorithm` - The hash algorithm to use
    /// * `use_msi_digital_signature_ex` - Whether to include metadata hash
    ///
    /// # Returns
    /// Tuple of (`content_hash`, optional pre-hash for `MsiDigitalSignatureEx`)
    ///
    /// # Errors
    /// Returns error if the MSI structure cannot be parsed.
    pub fn compute_hash_with_ex(
        &self,
        algorithm: HashAlgorithm,
        use_msi_digital_signature_ex: bool,
    ) -> SigningResult<(Vec<u8>, Option<Vec<u8>>)> {
        if use_msi_digital_signature_ex {
            // Compute pre-hash first
            let prehash = self.compute_prehash(algorithm)?;

            // Compute combined hash: prehash + content
            let content_hash = self.compute_hash_with_prehash(algorithm, &prehash)?;

            Ok((content_hash, Some(prehash)))
        } else {
            // Simple content-only hash
            let hash = self.compute_hash(algorithm)?;
            Ok((hash, None))
        }
    }

    /// Compute hash with a pre-hash prepended.
    fn compute_hash_with_prehash(
        &self,
        algorithm: HashAlgorithm,
        prehash: &[u8],
    ) -> SigningResult<Vec<u8>> {
        let cursor = Cursor::new(self.data);
        let mut cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        // Collect all streams with their paths
        let mut streams: Vec<(String, Vec<u8>)> = Vec::new();

        let entries: Vec<_> = cfb
            .walk()
            .filter(cfb::Entry::is_stream)
            .map(|e| e.path().to_path_buf())
            .collect();

        for path in entries {
            let path_str = path.display().to_string();

            // Skip signature streams
            if path_str.contains(super::DIGITAL_SIGNATURE_STREAM)
                || path_str.contains(super::DIGITAL_SIGNATURE_EX_STREAM)
            {
                continue;
            }

            let mut stream = cfb.open_stream(&path).map_err(|e| {
                SigningError::MsiParsingError(format!("Failed to open stream '{path_str}': {e}"))
            })?;

            let mut content = Vec::new();
            stream.read_to_end(&mut content).map_err(|e| {
                SigningError::MsiParsingError(format!("Failed to read stream '{path_str}': {e}"))
            })?;

            if !content.is_empty() {
                streams.push((path_str, content));
            }
        }

        streams.sort_by(|a, b| msi_stream_compare(&a.0, &b.0));

        // Hash: prehash + sorted stream contents
        match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(prehash);
                for (_name, content) in &streams {
                    hasher.update(content);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(prehash);
                for (_name, content) in &streams {
                    hasher.update(content);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(prehash);
                for (_name, content) in &streams {
                    hasher.update(content);
                }
                Ok(hasher.finalize().to_vec())
            }
        }
    }
}

/// Metadata for an MSI entry used in pre-hash computation.
struct MsiEntryMetadata {
    name: String,
    size: u32,
    create_time: u64,
    modify_time: u64,
}

/// Compare stream names according to MSI specification (legacy, for prehash).
///
/// Streams are sorted by:
/// 1. Length (shorter names first)
/// 2. Case-insensitive Unicode comparison
fn msi_stream_compare(a: &str, b: &str) -> Ordering {
    // First compare by length
    match a.len().cmp(&b.len()) {
        Ordering::Equal => {}
        other => return other,
    }

    // Then compare case-insensitively
    a.to_uppercase().cmp(&b.to_uppercase())
}

/// Compare stream names using raw UTF-16LE byte comparison.
///
/// Per the MS-CFB specification for Authenticode MSI hashing, the comparison rules are:
///
/// 1. Compare bytes using `memcmp` up to the minimum length (including null terminators)
/// 2. If equal up to min length, the **longer name comes first** (wins)
///
/// **IMPORTANT**: The input slices must include the null terminator bytes per the spec.
/// For example, comparing "ab\0\0" vs "abc\0\0" at position 4 gives '\0' < 'c',
/// so "ab" comes before "abc". This is the opposite of what happens when excluding
/// null terminators where "abc" would come first as the longer name.
fn msi_stream_compare_utf16(a: &[u8], b: &[u8]) -> Ordering {
    let min_len = a.len().min(b.len());

    // Compare byte-by-byte up to min length (including null terminator bytes)
    for i in 0..min_len {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    // If names are equal up to min length, longer name wins (comes first)
    // This fallback case only happens when one name is a true prefix of the other
    // and both have identical bytes up to the shorter length.
    match a.len().cmp(&b.len()) {
        Ordering::Less => Ordering::Greater, // a is shorter, so b wins (a > b)
        Ordering::Greater => Ordering::Less, // a is longer, so a wins (a < b)
        Ordering::Equal => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_comparison() {
        assert_eq!(msi_stream_compare("a", "b"), Ordering::Less);
        assert_eq!(msi_stream_compare("ab", "a"), Ordering::Greater);
        assert_eq!(msi_stream_compare("AB", "ab"), Ordering::Equal);
    }

    #[test]
    fn test_utf16_stream_comparison() {
        // Test with null terminators included (per MS-CFB spec)
        // "ab\0\0" vs "abc\0\0" - at byte 4: \0 < 'c', so ab comes first
        let name_ab_with_nul: &[u8] = &[0x61, 0x00, 0x62, 0x00, 0x00, 0x00]; // "ab\0" in UTF-16LE
        let name_abc_with_nul: &[u8] = &[0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x00, 0x00]; // "abc\0" in UTF-16LE

        // "ab" comes BEFORE "abc" because null byte < 'c' (0x00 < 0x63)
        assert_eq!(
            msi_stream_compare_utf16(name_ab_with_nul, name_abc_with_nul),
            Ordering::Less // ab\0 < abc\0 because at position 4: 0x00 < 0x63
        );
        assert_eq!(
            msi_stream_compare_utf16(name_abc_with_nul, name_ab_with_nul),
            Ordering::Greater // abc\0 > ab\0
        );

        // Different bytes (same length)
        assert_eq!(msi_stream_compare_utf16(b"a", b"b"), Ordering::Less);

        // Equal names
        assert_eq!(msi_stream_compare_utf16(b"test", b"test"), Ordering::Equal);

        // True prefix case: when bytes are identical up to shorter length,
        // longer name wins (comes first)
        // This only applies when the shorter name's bytes are a true prefix
        // (without null terminators changing the comparison)
        let name_a: &[u8] = &[0x61, 0x00]; // "a" without null terminator
        let name_ab: &[u8] = &[0x61, 0x00, 0x62, 0x00]; // "ab" without null terminator
        assert_eq!(
            msi_stream_compare_utf16(name_ab, name_a),
            Ordering::Less // ab comes first (longer wins)
        );
    }
}
