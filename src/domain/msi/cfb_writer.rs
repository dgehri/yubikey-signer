//! CFB (Compound File Binary) rewrite for MSI signature embedding.
//!
//! This module implements an MSI rewrite in **pure Rust**.
//!
//! ## Why this exists
//!
//! Windows' MSI SIP verifier is picky about CFB container invariants and (in
//! practice) about the *shape* of the directory table and allocation chains.
//! Some writers reorganize the container in ways that can trigger
//! `TRUST_E_BAD_DIGEST`, even when the logical MSI hashing algorithm matches.
//!
//! To maximize verifier compatibility, we write using a conservative layout:
//!
//! - write order: **large streams → ministream → miniFAT → directory → FAT → header**
//! - directory serialization: `DirEntry::cmp_tree` ordering, with a degenerate
//!   directory structure (all black nodes, left=NOSTREAM, right forms a
//!   table-order linked list)
//! - signature stream is inserted at root and (typically) placed in the
//!   ministream (since it is < 4096 bytes)

use crate::infra::error::{SigningError, SigningResult};

use std::cmp::Ordering;

/// CFB magic (OLE Structured Storage signature).
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The CFB header is always 512 bytes, independent of sector size.
const HEADER_SIZE: usize = 0x200;

/// Size threshold for storing a stream in the mini-stream.
const MINI_STREAM_CUTOFF_SIZE: u32 = 4096;

/// Standard mini-sector size (must be 64 bytes for MSI files).
const MINI_SECTOR_SIZE: u32 = 64;

/// Directory entry size (bytes).
const DIRENT_SIZE: usize = 128;

/// Directory entry name field size (bytes).
const DIRENT_MAX_NAME_SIZE: usize = 64;

/// Special values from MS-CFB.
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FATSECT: u32 = 0xFFFFFFFD;
const DIFSECT: u32 = 0xFFFFFFFC;
const FREESECT: u32 = 0xFFFFFFFF;
const NOSTREAM: u32 = 0xFFFFFFFF;

/// The number of DIFAT entries stored in the header.
const DIFAT_IN_HEADER: usize = 109;

// Header offsets (match reference constants).
const HEADER_MINOR_VER: usize = 0x18;
const HEADER_MAJOR_VER: usize = 0x1A;
const HEADER_BYTE_ORDER: usize = 0x1C;
const HEADER_SECTOR_SHIFT: usize = 0x1E;
const HEADER_MINI_SECTOR_SHIFT: usize = 0x20;
const HEADER_DIR_SECTORS_NUM: usize = 0x28;
const HEADER_FAT_SECTORS_NUM: usize = 0x2C;
const HEADER_DIR_SECTOR_LOC: usize = 0x30;
const HEADER_MINI_STREAM_CUTOFF: usize = 0x38;
const HEADER_MINI_FAT_SECTOR_LOC: usize = 0x3C;
const HEADER_MINI_FAT_SECTORS_NUM: usize = 0x40;
const HEADER_DIFAT_SECTOR_LOC: usize = 0x44;
const HEADER_DIFAT_SECTORS_NUM: usize = 0x48;
const HEADER_DIFAT: usize = 0x4C;

// Directory entry offsets (match reference constants).
const DIRENT_NAME: usize = 0x00;
const DIRENT_NAME_LEN: usize = 0x40;
const DIRENT_TYPE: usize = 0x42;
const DIRENT_COLOUR: usize = 0x43;
const DIRENT_LEFT_SIBLING_ID: usize = 0x44;
const DIRENT_RIGHT_SIBLING_ID: usize = 0x48;
const DIRENT_CHILD_ID: usize = 0x4C;
const DIRENT_CLSID: usize = 0x50;
const DIRENT_STATE_BITS: usize = 0x60;
const DIRENT_CREATE_TIME: usize = 0x64;
const DIRENT_MODIFY_TIME: usize = 0x6C;
const DIRENT_START_SECTOR_LOC: usize = 0x74;
const DIRENT_FILE_SIZE: usize = 0x78;

/// Directory entry types.
const DIR_STORAGE: u8 = 1;
const DIR_STREAM: u8 = 2;
const DIR_ROOT: u8 = 5;

/// Directory entry color values.
const BLACK_COLOR: u8 = 1;

/// The `\x05DigitalSignature` stream name (UTF-16LE incl. NUL).
const DIGITAL_SIGNATURE_NAME_UTF16LE: &[u8] = &[
    0x05, 0x00, // U+0005
    b'D', 0x00, b'i', 0x00, b'g', 0x00, b'i', 0x00, b't', 0x00, b'a', 0x00, b'l', 0x00, b'S', 0x00,
    b'i', 0x00, b'g', 0x00, b'n', 0x00, b'a', 0x00, b't', 0x00, b'u', 0x00, b'r', 0x00, b'e', 0x00,
    0x00, 0x00, // NUL
];

/// Parsed CFB header fields we need.
#[derive(Debug, Clone, Copy)]
struct CfbHeader {
    /// CFB minor version.
    minor_version: u16,
    /// Sector shift (9 for 512-byte sectors, 12 for 4096-byte sectors).
    sector_shift: u16,
    /// Mini-sector shift (should be 6).
    mini_sector_shift: u16,
    /// First directory sector location.
    first_directory_sector_location: u32,
    /// Number of FAT sectors.
    num_fat_sectors: u32,
    /// Mini stream cutoff size (should be 4096).
    mini_stream_cutoff_size: u32,
    /// First miniFAT sector location.
    first_minifat_sector_location: u32,
    /// Number of miniFAT sectors.
    num_minifat_sectors: u32,
    /// First DIFAT sector location.
    first_difat_sector_location: u32,
    /// Number of DIFAT sectors.
    num_difat_sectors: u32,
    /// DIFAT entries stored in the header.
    difat: [u32; DIFAT_IN_HEADER],
}

impl CfbHeader {
    /// Returns the sector size in bytes.
    #[must_use]
    fn sector_size(self) -> usize {
        1usize
            .checked_shl(u32::from(self.sector_shift))
            .unwrap_or(0)
    }

    /// Returns the mini-sector size in bytes.
    #[must_use]
    fn mini_sector_size(self) -> usize {
        1usize
            .checked_shl(u32::from(self.mini_sector_shift))
            .unwrap_or(0)
    }
}

/// A raw directory entry as stored on disk.
#[derive(Debug, Clone)]
struct DirEntry {
    /// Directory entry id (index in directory table).
    id: u32,
    /// Name bytes (UTF-16LE), including NUL terminator. Length is `name_len_bytes`.
    name_utf16le: Vec<u8>,
    /// Name length in bytes (including NUL terminator).
    name_len_bytes: u16,
    /// Object type.
    object_type: u8,
    /// Color flag.
    color_flag: u8,
    /// Left sibling id.
    left_sibling_id: u32,
    /// Right sibling id.
    right_sibling_id: u32,
    /// Child id.
    child_id: u32,
    /// CLSID bytes.
    clsid: [u8; 16],
    /// State bits.
    state_bits: [u8; 4],
    /// Creation time (FILETIME raw bytes).
    creation_time: [u8; 8],
    /// Modification time (FILETIME raw bytes).
    modified_time: [u8; 8],
    /// Start sector location.
    start_sector_location: u32,
    /// Stream size.
    stream_size: u64,
}

impl DirEntry {
    /// Returns true if this is a stream entry.
    #[must_use]
    fn is_stream(&self) -> bool {
        self.object_type == DIR_STREAM
    }

    /// Returns true if this is a storage entry.
    #[must_use]
    fn is_storage(&self) -> bool {
        self.object_type == DIR_STORAGE || self.object_type == DIR_ROOT
    }

    /// Returns true if this is the root entry.
    #[must_use]
    fn is_root(&self) -> bool {
        self.object_type == DIR_ROOT
    }

    /// Compares this entry's name to another using the reference tree comparator.
    ///
    /// This is *not* the hashing comparator.
    #[must_use]
    fn cmp_tree(&self, other: &Self) -> Ordering {
        // The reference comparator compares nameLen first.
        match self.name_len_bytes.cmp(&other.name_len_bytes) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Compare codepoints (u16), excluding the trailing NUL (nameLen-2).
        let limit = usize::from(self.name_len_bytes.saturating_sub(2));
        let mut i = 0;
        while i + 1 < limit {
            let a = u16::from_le_bytes([self.name_utf16le[i], self.name_utf16le[i + 1]]);
            let b = u16::from_le_bytes([other.name_utf16le[i], other.name_utf16le[i + 1]]);
            if a != b {
                return a.cmp(&b);
            }
            i += 2;
        }
        Ordering::Equal
    }

    /// Returns true if this entry name matches `\x05DigitalSignature`.
    #[must_use]
    fn is_digital_signature(&self) -> bool {
        self.name_utf16le == DIGITAL_SIGNATURE_NAME_UTF16LE
    }
}

/// A simplified MSI directory tree representation used for rewriting.
#[derive(Debug, Clone)]
struct MsiDirentTree {
    /// Root entry id.
    root_id: u32,
    /// Per-entry children list in the same order as the reference writer builds it.
    children: Vec<Vec<u32>>,
}

/// Parsed input MSI as a CFB container.
#[derive(Debug)]
struct ParsedMsi {
    /// Header fields.
    header: CfbHeader,
    /// Directory entries.
    entries: Vec<DirEntry>,
    /// FAT entries (one u32 per sector).
    fat: Vec<u32>,
    /// `MiniFAT` entries (one u32 per mini-sector) – may be empty.
    minifat: Vec<u32>,
    /// The root storage's mini-stream bytes.
    ministream: Vec<u8>,
    /// Directory tree children order.
    tree: MsiDirentTree,
    /// Raw file bytes.
    data: Vec<u8>,
}

/// Embed a PKCS#7 signature into an MSI by rewriting the CFB container.
///
/// # Arguments
/// * `msi_data` - The original MSI bytes.
/// * `signature_pkcs7_der` - DER-encoded PKCS#7 `SignedData` to embed.
///
/// # Errors
/// Returns an error if the input MSI cannot be parsed as a CFB file, or if
/// rewriting fails.
pub fn embed_signature_cfb_writer(
    msi_data: &[u8],
    signature_pkcs7_der: &[u8],
) -> SigningResult<Vec<u8>> {
    let parsed = parse_msi_cfb(msi_data)?;
    write_msi_with_signature(&parsed, signature_pkcs7_der)
}

fn parse_msi_cfb(msi_data: &[u8]) -> SigningResult<ParsedMsi> {
    if msi_data.len() < HEADER_SIZE {
        return Err(SigningError::MsiParsingError(
            "MSI file too small to contain CFB header".into(),
        ));
    }

    if msi_data[0..8] != CFB_MAGIC {
        return Err(SigningError::MsiParsingError(
            "Invalid CFB magic (not an MSI/OLE compound file)".into(),
        ));
    }

    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes.copy_from_slice(&msi_data[0..HEADER_SIZE]);

    let header = parse_header(&header_bytes)?;
    let sector_size = header.sector_size();

    if sector_size != 512 && sector_size != 4096 {
        return Err(SigningError::MsiParsingError(format!(
            "Unsupported sector size {sector_size}"
        )));
    }

    if header.mini_sector_size() != usize::try_from(MINI_SECTOR_SIZE).unwrap() {
        return Err(SigningError::MsiParsingError(format!(
            "Unsupported mini-sector size {} (expected 64)",
            header.mini_sector_size()
        )));
    }

    if header.mini_stream_cutoff_size != MINI_STREAM_CUTOFF_SIZE {
        return Err(SigningError::MsiParsingError(format!(
            "Unexpected mini-stream cutoff {} (expected 4096)",
            header.mini_stream_cutoff_size
        )));
    }

    let difat_sectors = collect_difat_sector_ids(&header)?;
    let fat_sector_ids = collect_fat_sector_ids(&header, &difat_sectors, msi_data)?;
    let fat = read_fat(&fat_sector_ids, sector_size, msi_data)?;

    let dir_bytes = read_sector_chain(
        header.first_directory_sector_location,
        &fat,
        sector_size,
        msi_data,
    )?;
    let entries = parse_directory_entries(&dir_bytes)?;

    let root_id = entries
        .iter()
        .find(|e| e.is_root())
        .map(|e| e.id)
        .ok_or_else(|| {
            SigningError::MsiParsingError("Failed to find CFB root directory entry".into())
        })?;

    let (ministream, minifat) =
        read_ministream_and_minifat(&header, &entries, &fat, sector_size, msi_data)?;

    let tree = build_children_order(&entries, root_id)?;

    Ok(ParsedMsi {
        header,
        entries,
        fat,
        minifat,
        ministream,
        tree,
        data: msi_data.to_vec(),
    })
}

fn parse_header(header_bytes: &[u8; HEADER_SIZE]) -> SigningResult<CfbHeader> {
    let minor_version = u16::from_le_bytes([
        header_bytes[HEADER_MINOR_VER],
        header_bytes[HEADER_MINOR_VER + 1],
    ]);
    let major_version = u16::from_le_bytes([
        header_bytes[HEADER_MAJOR_VER],
        header_bytes[HEADER_MAJOR_VER + 1],
    ]);
    let byte_order = u16::from_le_bytes([
        header_bytes[HEADER_BYTE_ORDER],
        header_bytes[HEADER_BYTE_ORDER + 1],
    ]);
    let sector_shift = u16::from_le_bytes([
        header_bytes[HEADER_SECTOR_SHIFT],
        header_bytes[HEADER_SECTOR_SHIFT + 1],
    ]);
    let mini_sector_shift = u16::from_le_bytes([
        header_bytes[HEADER_MINI_SECTOR_SHIFT],
        header_bytes[HEADER_MINI_SECTOR_SHIFT + 1],
    ]);

    // The directory sector count (header field) is only used for version 4 and
    // is not required for our parsing logic (we follow the FAT chain).
    let _num_directory_sectors = u32::from_le_bytes([
        header_bytes[HEADER_DIR_SECTORS_NUM],
        header_bytes[HEADER_DIR_SECTORS_NUM + 1],
        header_bytes[HEADER_DIR_SECTORS_NUM + 2],
        header_bytes[HEADER_DIR_SECTORS_NUM + 3],
    ]);
    let num_fat_sectors = u32::from_le_bytes([
        header_bytes[HEADER_FAT_SECTORS_NUM],
        header_bytes[HEADER_FAT_SECTORS_NUM + 1],
        header_bytes[HEADER_FAT_SECTORS_NUM + 2],
        header_bytes[HEADER_FAT_SECTORS_NUM + 3],
    ]);
    let first_directory_sector_location = u32::from_le_bytes([
        header_bytes[HEADER_DIR_SECTOR_LOC],
        header_bytes[HEADER_DIR_SECTOR_LOC + 1],
        header_bytes[HEADER_DIR_SECTOR_LOC + 2],
        header_bytes[HEADER_DIR_SECTOR_LOC + 3],
    ]);
    let mini_stream_cutoff_size = u32::from_le_bytes([
        header_bytes[HEADER_MINI_STREAM_CUTOFF],
        header_bytes[HEADER_MINI_STREAM_CUTOFF + 1],
        header_bytes[HEADER_MINI_STREAM_CUTOFF + 2],
        header_bytes[HEADER_MINI_STREAM_CUTOFF + 3],
    ]);
    let first_minifat_sector_location = u32::from_le_bytes([
        header_bytes[HEADER_MINI_FAT_SECTOR_LOC],
        header_bytes[HEADER_MINI_FAT_SECTOR_LOC + 1],
        header_bytes[HEADER_MINI_FAT_SECTOR_LOC + 2],
        header_bytes[HEADER_MINI_FAT_SECTOR_LOC + 3],
    ]);
    let num_minifat_sectors = u32::from_le_bytes([
        header_bytes[HEADER_MINI_FAT_SECTORS_NUM],
        header_bytes[HEADER_MINI_FAT_SECTORS_NUM + 1],
        header_bytes[HEADER_MINI_FAT_SECTORS_NUM + 2],
        header_bytes[HEADER_MINI_FAT_SECTORS_NUM + 3],
    ]);
    let first_difat_sector_location = u32::from_le_bytes([
        header_bytes[HEADER_DIFAT_SECTOR_LOC],
        header_bytes[HEADER_DIFAT_SECTOR_LOC + 1],
        header_bytes[HEADER_DIFAT_SECTOR_LOC + 2],
        header_bytes[HEADER_DIFAT_SECTOR_LOC + 3],
    ]);
    let num_difat_sectors = u32::from_le_bytes([
        header_bytes[HEADER_DIFAT_SECTORS_NUM],
        header_bytes[HEADER_DIFAT_SECTORS_NUM + 1],
        header_bytes[HEADER_DIFAT_SECTORS_NUM + 2],
        header_bytes[HEADER_DIFAT_SECTORS_NUM + 3],
    ]);

    let mut difat = [FREESECT; DIFAT_IN_HEADER];
    for i in 0..DIFAT_IN_HEADER {
        let off = HEADER_DIFAT + i * 4;
        difat[i] = u32::from_le_bytes([
            header_bytes[off],
            header_bytes[off + 1],
            header_bytes[off + 2],
            header_bytes[off + 3],
        ]);
    }

    // Basic sanity checks.
    if !(major_version == 3 || major_version == 4) {
        return Err(SigningError::MsiParsingError(format!(
            "Unsupported CFB major version {major_version}"
        )));
    }

    if byte_order != 0xFFFE {
        return Err(SigningError::MsiParsingError(format!(
            "Unexpected CFB byte order 0x{byte_order:04X} (expected 0xFFFE)"
        )));
    }

    if mini_sector_shift != 6 {
        return Err(SigningError::MsiParsingError(format!(
            "Unexpected mini sector shift {mini_sector_shift} (expected 6)"
        )));
    }

    Ok(CfbHeader {
        minor_version,
        sector_shift,
        mini_sector_shift,
        first_directory_sector_location,
        num_fat_sectors,
        mini_stream_cutoff_size,
        first_minifat_sector_location,
        num_minifat_sectors,
        first_difat_sector_location,
        num_difat_sectors,
        difat,
    })
}

fn collect_difat_sector_ids(header: &CfbHeader) -> SigningResult<Vec<u32>> {
    if header.num_difat_sectors == 0 {
        return Ok(Vec::new());
    }

    // DIFAT is a sector chain starting at first_difat_sector_location.
    // We'll follow it later when parsing FAT sector ids; for now we just
    // validate the starting location.
    if header.first_difat_sector_location == ENDOFCHAIN
        || header.first_difat_sector_location == FREESECT
    {
        return Err(SigningError::MsiParsingError(
            "DIFAT sector count is non-zero but first DIFAT sector location is invalid".into(),
        ));
    }

    Ok(vec![header.first_difat_sector_location])
}

fn collect_fat_sector_ids(
    header: &CfbHeader,
    _difat_sectors: &[u32],
    msi_data: &[u8],
) -> SigningResult<Vec<u32>> {
    // First 109 DIFAT entries are stored in the header. Any additional FAT
    // sector locations live in DIFAT sectors, but MSI files are typically small.
    let mut fat_sector_ids = Vec::new();

    for &sid in &header.difat {
        if sid == FREESECT {
            continue;
        }
        if sid == ENDOFCHAIN {
            continue;
        }
        fat_sector_ids.push(sid);
    }

    // If there are DIFAT sectors, parse them to get additional FAT sector ids.
    if header.num_difat_sectors > 0 {
        let sector_size = header.sector_size();
        let entries_per_sector = (sector_size / 4).saturating_sub(1);
        let mut next = header.first_difat_sector_location;
        let mut remaining = header.num_difat_sectors;

        while remaining > 0 && next != ENDOFCHAIN && next != FREESECT {
            let sector = read_sector(msi_data, sector_size, next)?;
            // All but last u32 are FAT sector locations.
            for i in 0..entries_per_sector {
                let off = i * 4;
                let sid = u32::from_le_bytes([
                    sector[off],
                    sector[off + 1],
                    sector[off + 2],
                    sector[off + 3],
                ]);
                if sid == FREESECT {
                    continue;
                }
                fat_sector_ids.push(sid);
            }
            let link_off = sector_size - 4;
            next = u32::from_le_bytes([
                sector[link_off],
                sector[link_off + 1],
                sector[link_off + 2],
                sector[link_off + 3],
            ]);
            remaining -= 1;
        }
    }

    // `num_fat_sectors` is authoritative; trim if header had extra FREESECT gaps.
    if header.num_fat_sectors as usize <= fat_sector_ids.len() {
        fat_sector_ids.truncate(header.num_fat_sectors as usize);
    }

    if fat_sector_ids.len() != header.num_fat_sectors as usize {
        return Err(SigningError::MsiParsingError(format!(
            "FAT sector id list length mismatch (expected {}, got {})",
            header.num_fat_sectors,
            fat_sector_ids.len()
        )));
    }

    Ok(fat_sector_ids)
}

fn read_fat(
    fat_sector_ids: &[u32],
    sector_size: usize,
    msi_data: &[u8],
) -> SigningResult<Vec<u32>> {
    let mut fat = Vec::new();
    for &sid in fat_sector_ids {
        let sec = read_sector(msi_data, sector_size, sid)?;
        for chunk in sec.chunks_exact(4) {
            fat.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
    }
    Ok(fat)
}

fn read_ministream_and_minifat(
    header: &CfbHeader,
    entries: &[DirEntry],
    fat: &[u32],
    sector_size: usize,
    msi_data: &[u8],
) -> SigningResult<(Vec<u8>, Vec<u32>)> {
    // Root entry holds the ministream location and size.
    let root = entries
        .iter()
        .find(|e| e.is_root())
        .ok_or_else(|| SigningError::MsiParsingError("Missing root directory entry".into()))?;

    let ministream_len = usize::try_from(root.stream_size)
        .map_err(|_| SigningError::MsiParsingError("Root ministream size too large".into()))?;

    let ministream_bytes = if root.start_sector_location == NOSTREAM || ministream_len == 0 {
        Vec::new()
    } else {
        read_sector_chain_bytes(
            root.start_sector_location,
            fat,
            sector_size,
            msi_data,
            ministream_len,
        )?
    };

    let minifat =
        if header.num_minifat_sectors == 0 || header.first_minifat_sector_location == ENDOFCHAIN {
            Vec::new()
        } else {
            let minifat_bytes = read_sector_chain(
                header.first_minifat_sector_location,
                fat,
                sector_size,
                msi_data,
            )?;
            minifat_bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        };

    Ok((ministream_bytes, minifat))
}

fn parse_directory_entries(dir_bytes: &[u8]) -> SigningResult<Vec<DirEntry>> {
    if !dir_bytes.len().is_multiple_of(DIRENT_SIZE) {
        return Err(SigningError::MsiParsingError(
            "Directory stream length is not a multiple of 128".into(),
        ));
    }

    let mut entries = Vec::new();
    for (i, chunk) in dir_bytes.chunks_exact(DIRENT_SIZE).enumerate() {
        let name_len_bytes =
            u16::from_le_bytes([chunk[DIRENT_NAME_LEN], chunk[DIRENT_NAME_LEN + 1]]);
        let object_type = chunk[DIRENT_TYPE];
        let color_flag = chunk[DIRENT_COLOUR];
        let left_sibling_id = u32::from_le_bytes([
            chunk[DIRENT_LEFT_SIBLING_ID],
            chunk[DIRENT_LEFT_SIBLING_ID + 1],
            chunk[DIRENT_LEFT_SIBLING_ID + 2],
            chunk[DIRENT_LEFT_SIBLING_ID + 3],
        ]);
        let right_sibling_id = u32::from_le_bytes([
            chunk[DIRENT_RIGHT_SIBLING_ID],
            chunk[DIRENT_RIGHT_SIBLING_ID + 1],
            chunk[DIRENT_RIGHT_SIBLING_ID + 2],
            chunk[DIRENT_RIGHT_SIBLING_ID + 3],
        ]);
        let child_id = u32::from_le_bytes([
            chunk[DIRENT_CHILD_ID],
            chunk[DIRENT_CHILD_ID + 1],
            chunk[DIRENT_CHILD_ID + 2],
            chunk[DIRENT_CHILD_ID + 3],
        ]);

        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&chunk[DIRENT_CLSID..DIRENT_CLSID + 16]);

        let mut state_bits = [0u8; 4];
        state_bits.copy_from_slice(&chunk[DIRENT_STATE_BITS..DIRENT_STATE_BITS + 4]);

        let mut creation_time = [0u8; 8];
        creation_time.copy_from_slice(&chunk[DIRENT_CREATE_TIME..DIRENT_CREATE_TIME + 8]);

        let mut modified_time = [0u8; 8];
        modified_time.copy_from_slice(&chunk[DIRENT_MODIFY_TIME..DIRENT_MODIFY_TIME + 8]);

        let start_sector_location = u32::from_le_bytes([
            chunk[DIRENT_START_SECTOR_LOC],
            chunk[DIRENT_START_SECTOR_LOC + 1],
            chunk[DIRENT_START_SECTOR_LOC + 2],
            chunk[DIRENT_START_SECTOR_LOC + 3],
        ]);

        let stream_size_lo = u32::from_le_bytes([
            chunk[DIRENT_FILE_SIZE],
            chunk[DIRENT_FILE_SIZE + 1],
            chunk[DIRENT_FILE_SIZE + 2],
            chunk[DIRENT_FILE_SIZE + 3],
        ]);
        let stream_size_hi = u32::from_le_bytes([
            chunk[DIRENT_FILE_SIZE + 4],
            chunk[DIRENT_FILE_SIZE + 5],
            chunk[DIRENT_FILE_SIZE + 6],
            chunk[DIRENT_FILE_SIZE + 7],
        ]);
        let stream_size = (u64::from(stream_size_hi) << 32) | u64::from(stream_size_lo);

        let name_len_usize = usize::from(name_len_bytes);
        let name_len_usize = name_len_usize.min(DIRENT_MAX_NAME_SIZE);
        let mut name_utf16le = vec![0u8; name_len_usize];
        name_utf16le.copy_from_slice(&chunk[DIRENT_NAME..DIRENT_NAME + name_len_usize]);

        entries.push(DirEntry {
            id: u32::try_from(i).unwrap_or(0),
            name_utf16le,
            name_len_bytes,
            object_type,
            color_flag,
            left_sibling_id,
            right_sibling_id,
            child_id,
            clsid,
            state_bits,
            creation_time,
            modified_time,
            start_sector_location,
            stream_size,
        });
    }
    Ok(entries)
}

fn build_children_order(entries: &[DirEntry], root_id: u32) -> SigningResult<MsiDirentTree> {
    let mut children: Vec<Vec<u32>> = vec![Vec::new(); entries.len()];
    let mut visited = vec![false; entries.len()];

    fn recurse(
        entries: &[DirEntry],
        children: &mut [Vec<u32>],
        visited: &mut [bool],
        entry_id: u32,
        parent_id: Option<u32>,
    ) -> SigningResult<()> {
        if entry_id == NOSTREAM {
            return Ok(());
        }
        let idx = usize::try_from(entry_id).map_err(|_| {
            SigningError::MsiParsingError(format!("Invalid directory entry id {entry_id}"))
        })?;
        if idx >= entries.len() {
            return Err(SigningError::MsiParsingError(format!(
                "Directory entry id {entry_id} out of range"
            )));
        }
        if visited[idx] {
            return Err(SigningError::MsiParsingError(format!(
                "Directory entry cycle detected at id {entry_id}"
            )));
        }
        visited[idx] = true;

        if let Some(pid) = parent_id {
            let pidx = usize::try_from(pid).map_err(|_| {
                SigningError::MsiParsingError(format!("Invalid parent directory entry id {pid}"))
            })?;
            if pidx >= children.len() {
                return Err(SigningError::MsiParsingError(format!(
                    "Parent directory entry id {pid} out of range"
                )));
            }
            children[pidx].push(entry_id);
        }

        let entry = &entries[idx];
        // Match reference order: left sibling, right sibling, then child.
        recurse(entries, children, visited, entry.left_sibling_id, parent_id)?;
        recurse(
            entries,
            children,
            visited,
            entry.right_sibling_id,
            parent_id,
        )?;
        recurse(entries, children, visited, entry.child_id, Some(entry_id))?;

        Ok(())
    }

    // Root itself is not inserted into any parent list.
    let root_idx = usize::try_from(root_id).map_err(|_| {
        SigningError::MsiParsingError(format!("Invalid root directory entry id {root_id}"))
    })?;
    if root_idx >= entries.len() {
        return Err(SigningError::MsiParsingError(
            "Root directory entry id out of range".into(),
        ));
    }

    // Mark root as visited and build its child list from its child tree.
    visited[root_idx] = true;
    let root_child = entries[root_idx].child_id;
    recurse(
        entries,
        &mut children,
        &mut visited,
        root_child,
        Some(root_id),
    )?;

    Ok(MsiDirentTree { root_id, children })
}

fn read_sector(msi_data: &[u8], sector_size: usize, sector_id: u32) -> SigningResult<Vec<u8>> {
    // In CFB, sector numbering starts *after* the header sector.
    // File offset for sector N is: (N + 1) * sector_size.
    // (The header itself is always 512 bytes, but occupies one full sector.)
    let offset = sector_size
        .checked_add(
            sector_size
                .checked_mul(sector_id as usize)
                .ok_or_else(|| SigningError::MsiParsingError("Sector offset overflow".into()))?,
        )
        .ok_or_else(|| SigningError::MsiParsingError("Sector offset overflow".into()))?;

    // Check if sector starts within the file.
    if offset >= msi_data.len() {
        return Err(SigningError::MsiParsingError(format!(
            "Sector read out of bounds: sector_id={sector_id}, offset={offset}, file_len={}",
            msi_data.len()
        )));
    }

    // Handle partial sectors at the end of file.
    // CFB files may not be padded to a full sector boundary, so the last sector
    // can be truncated. We read what's available and zero-pad to sector_size.
    let available = msi_data.len() - offset;
    if available >= sector_size {
        // Full sector available.
        Ok(msi_data[offset..offset + sector_size].to_vec())
    } else {
        // Partial sector at end of file - read available bytes and zero-pad.
        log::debug!(
            "Reading partial sector {sector_id}: {available} bytes available, padding to {sector_size}"
        );
        let mut sector = vec![0u8; sector_size];
        sector[..available].copy_from_slice(&msi_data[offset..]);
        Ok(sector)
    }
}

fn read_sector_chain(
    start_sector: u32,
    fat: &[u32],
    sector_size: usize,
    msi_data: &[u8],
) -> SigningResult<Vec<u8>> {
    // Read full chain.
    if start_sector == NOSTREAM || start_sector == ENDOFCHAIN || start_sector == FREESECT {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut cur = start_sector;
    let mut visited = vec![false; fat.len()];

    while cur != ENDOFCHAIN && cur != FREESECT {
        let idx = cur as usize;
        if idx >= fat.len() {
            return Err(SigningError::MsiParsingError(
                "FAT sector index out of range".into(),
            ));
        }

        if visited[idx] {
            return Err(SigningError::MsiParsingError(format!(
                "FAT chain cycle detected (start={start_sector}, at={cur})"
            )));
        }
        visited[idx] = true;

        out.extend_from_slice(&read_sector(msi_data, sector_size, cur)?);
        cur = fat[idx];
    }

    Ok(out)
}

fn read_sector_chain_bytes(
    start_sector: u32,
    fat: &[u32],
    sector_size: usize,
    msi_data: &[u8],
    byte_len: usize,
) -> SigningResult<Vec<u8>> {
    let mut bytes = read_sector_chain(start_sector, fat, sector_size, msi_data)?;
    bytes.truncate(byte_len);
    Ok(bytes)
}

fn read_stream_bytes(parsed: &ParsedMsi, entry: &DirEntry) -> SigningResult<Vec<u8>> {
    if !entry.is_stream() {
        return Err(SigningError::MsiParsingError(
            "Attempted to read bytes for a non-stream directory entry".into(),
        ));
    }

    let len = usize::try_from(entry.stream_size)
        .map_err(|_| SigningError::MsiParsingError("Stream size too large".into()))?;

    if len == 0 {
        return Ok(Vec::new());
    }

    if entry.stream_size < u64::from(MINI_STREAM_CUTOFF_SIZE) {
        // Mini-stream.
        let start = entry.start_sector_location;
        if start == NOSTREAM {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(len);
        let mut cur = start;
        let mini_sector_size = parsed.header.mini_sector_size();
        let mut guard = 0usize;

        while cur != ENDOFCHAIN && cur != FREESECT {
            let idx = cur as usize;
            if idx >= parsed.minifat.len() {
                return Err(SigningError::MsiParsingError(
                    "MiniFAT index out of range".into(),
                ));
            }
            let off = idx.checked_mul(mini_sector_size).ok_or_else(|| {
                SigningError::MsiParsingError("Mini-sector offset overflow".into())
            })?;
            let end = off + mini_sector_size;
            if end > parsed.ministream.len() {
                return Err(SigningError::MsiParsingError(
                    "Mini-stream read out of bounds".into(),
                ));
            }
            out.extend_from_slice(&parsed.ministream[off..end]);
            cur = parsed.minifat[idx];
            guard += 1;
            if guard > parsed.minifat.len() {
                return Err(SigningError::MsiParsingError(
                    "MiniFAT chain appears cyclic".into(),
                ));
            }
        }

        out.truncate(len);
        Ok(out)
    } else {
        // Regular stream.
        let start = entry.start_sector_location;
        if start == NOSTREAM {
            return Ok(Vec::new());
        }
        read_sector_chain_bytes(
            start,
            &parsed.fat,
            parsed.header.sector_size(),
            &parsed.data,
            len,
        )
    }
}

/// Output context similar to the reference writer's output context.
#[derive(Debug)]
struct MsiOut {
    /// Sector size.
    sector_size: usize,
    /// Current output sector number (relative to first sector after the header).
    sector_num: u32,
    /// Current mini-sector number.
    mini_sector_num: u32,

    /// Header bytes (512 bytes).
    header: [u8; HEADER_SIZE],

    /// Accumulated ministream bytes.
    ministream: Vec<u8>,
    /// `MiniFAT` entries.
    minifat_entries: Vec<u32>,
    /// FAT entries (one per sector, later extended with FATSECT/DIFSECT and padding).
    fat_entries: Vec<u32>,

    /// Directory sectors count (used for v4).
    dirtree_sectors_count: u32,
    /// `MiniFAT` sectors count.
    minifat_sectors_count: u32,
    /// FAT sectors count.
    fat_sectors_count: u32,
    /// DIFAT sectors count.
    difat_sectors_count: u32,
}

/// A rewrite node containing an entry and its children.
#[derive(Debug, Clone)]
struct RewriteNode {
    /// Directory entry.
    entry: DirEntry,
    /// Children in reference discovery order (for stream write).
    children: Vec<RewriteNode>,
}

fn clone_rewrite_tree(parsed: &ParsedMsi, entry_id: u32) -> SigningResult<RewriteNode> {
    let idx = entry_id as usize;
    if idx >= parsed.entries.len() {
        return Err(SigningError::MsiParsingError(
            "Directory entry id out of range while cloning".into(),
        ));
    }

    let entry = parsed.entries[idx].clone();
    let mut node = RewriteNode {
        entry,
        children: Vec::new(),
    };

    if node.entry.is_storage() {
        let kids = parsed.tree.children[idx].clone();
        for kid in kids {
            let kid_idx = kid as usize;
            if kid_idx >= parsed.entries.len() {
                return Err(SigningError::MsiParsingError(
                    "Child entry id out of range".into(),
                ));
            }
            // Skip existing signature streams in root; we always embed our own.
            if parsed.entries[kid_idx].is_stream()
                && parsed.entries[kid_idx].is_digital_signature()
                && node.entry.is_root()
            {
                continue;
            }
            node.children.push(clone_rewrite_tree(parsed, kid)?);
        }
    }

    Ok(node)
}

fn write_msi_with_signature(parsed: &ParsedMsi, signature: &[u8]) -> SigningResult<Vec<u8>> {
    let sector_size = parsed.header.sector_size();

    // Build a reference-like header (fresh, not copied).
    let mut out = MsiOut {
        sector_size,
        sector_num: 0,
        mini_sector_num: 0,
        header: header_new(&parsed.header, sector_size)?,
        ministream: Vec::new(),
        minifat_entries: Vec::new(),
        fat_entries: Vec::new(),
        dirtree_sectors_count: 0,
        minifat_sectors_count: 0,
        fat_sectors_count: 0,
        difat_sectors_count: 0,
    };

    // Clone the tree from the parsed MSI and insert our signature stream at root.
    let mut root = clone_rewrite_tree(parsed, parsed.tree.root_id)?;

    // Insert DigitalSignature stream at end (reference writer pushes).
    root.children.push(new_signature_dirent());

    // Write: reserve the first sector (header + padding).
    let mut output = vec![0u8; sector_size];

    // Write streams (large streams directly, small streams into ministream).
    stream_handle(parsed, &mut root, signature, &mut output, &mut out, true)?;

    // Save ministream container (root entry points to its regular-sector chain).
    ministream_save(&mut root, &mut output, &mut out)?;

    // Save miniFAT stream.
    minifat_save(&mut output, &mut out)?;

    // Save directory tree.
    dirtree_save(&mut root, &mut output, &mut out)?;

    // Save FAT (+ optional DIFAT).
    fat_save(&mut output, &mut out)?;

    // Write header sector (512 bytes header + zero padding to sector size).
    header_save(&mut output[..], &out);

    Ok(output)
}

fn new_signature_dirent() -> RewriteNode {
    let entry = DirEntry {
        id: 0,
        name_utf16le: DIGITAL_SIGNATURE_NAME_UTF16LE.to_vec(),
        name_len_bytes: u16::try_from(DIGITAL_SIGNATURE_NAME_UTF16LE.len()).unwrap_or(0),
        object_type: DIR_STREAM,
        color_flag: BLACK_COLOR,
        left_sibling_id: NOSTREAM,
        right_sibling_id: NOSTREAM,
        child_id: NOSTREAM,
        clsid: [0u8; 16],
        state_bits: [0u8; 4],
        creation_time: [0u8; 8],
        modified_time: [0u8; 8],
        start_sector_location: NOSTREAM,
        stream_size: 0,
    };

    RewriteNode {
        entry,
        children: Vec::new(),
    }
}

fn header_new(input: &CfbHeader, sector_size: usize) -> SigningResult<[u8; HEADER_SIZE]> {
    let mut hdr = [0u8; HEADER_SIZE];

    hdr[0..8].copy_from_slice(&CFB_MAGIC);

    // CLSID is reserved/unused.
    for b in &mut hdr[0x08..0x18] {
        *b = 0;
    }

    hdr[HEADER_MINOR_VER..HEADER_MINOR_VER + 2].copy_from_slice(&input.minor_version.to_le_bytes());

    let major = if sector_size == 4096 {
        0x0004u16
    } else {
        0x0003u16
    };
    hdr[HEADER_MAJOR_VER..HEADER_MAJOR_VER + 2].copy_from_slice(&major.to_le_bytes());

    // Byte order is required to be 0xFFFE.
    hdr[HEADER_BYTE_ORDER..HEADER_BYTE_ORDER + 2].copy_from_slice(&0xFFFEu16.to_le_bytes());

    let sector_shift = if sector_size == 4096 {
        0x000Cu16
    } else {
        0x0009u16
    };
    hdr[HEADER_SECTOR_SHIFT..HEADER_SECTOR_SHIFT + 2].copy_from_slice(&sector_shift.to_le_bytes());

    hdr[HEADER_MINI_SECTOR_SHIFT..HEADER_MINI_SECTOR_SHIFT + 2]
        .copy_from_slice(&input.mini_sector_shift.to_le_bytes());

    // Reserved (6 bytes) and directory sectors num (4 bytes) already zero.

    // Filled later.
    hdr[HEADER_FAT_SECTORS_NUM..HEADER_FAT_SECTORS_NUM + 4].copy_from_slice(&0u32.to_le_bytes());
    hdr[HEADER_DIR_SECTOR_LOC..HEADER_DIR_SECTOR_LOC + 4].copy_from_slice(&0u32.to_le_bytes());

    // Transaction signature (reserved).
    hdr[0x34..0x38].copy_from_slice(&[0u8; 4]);

    hdr[HEADER_MINI_STREAM_CUTOFF..HEADER_MINI_STREAM_CUTOFF + 4]
        .copy_from_slice(&MINI_STREAM_CUTOFF_SIZE.to_le_bytes());

    // Filled later.
    hdr[HEADER_MINI_FAT_SECTOR_LOC..HEADER_MINI_FAT_SECTOR_LOC + 4]
        .copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    hdr[HEADER_MINI_FAT_SECTORS_NUM..HEADER_MINI_FAT_SECTORS_NUM + 4]
        .copy_from_slice(&0u32.to_le_bytes());

    // DIFAT start sector = ENDOFCHAIN, DIFAT sectors = 0.
    hdr[HEADER_DIFAT_SECTOR_LOC..HEADER_DIFAT_SECTOR_LOC + 4]
        .copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    hdr[HEADER_DIFAT_SECTORS_NUM..HEADER_DIFAT_SECTORS_NUM + 4]
        .copy_from_slice(&0u32.to_le_bytes());

    // DIFAT in header: filled later.
    for i in 0..DIFAT_IN_HEADER {
        let off = HEADER_DIFAT + i * 4;
        hdr[off..off + 4].copy_from_slice(&FREESECT.to_le_bytes());
    }

    Ok(hdr)
}

fn stream_handle(
    parsed: &ParsedMsi,
    dirent: &mut RewriteNode,
    signature: &[u8],
    output: &mut Vec<u8>,
    out: &mut MsiOut,
    is_root: bool,
) -> SigningResult<()> {
    // Recurse children in discovery order (unsorted), matching the reference writer.
    for child in &mut dirent.children {
        if child.entry.object_type == DIR_STORAGE {
            stream_handle(parsed, child, signature, output, out, false)?;
            continue;
        }

        if child.entry.object_type != DIR_STREAM {
            continue;
        }

        let mut data = if is_root && child.entry.is_digital_signature() {
            signature.to_vec()
        } else {
            // Existing stream content.
            read_stream_bytes(parsed, &child.entry)?
        };

        if data.is_empty() {
            // Skip null streams.
            child.entry.stream_size = 0;
            child.entry.start_sector_location = NOSTREAM;
            continue;
        }

        // Update entry size.
        child.entry.stream_size = u64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));

        if data.len() < MINI_STREAM_CUTOFF_SIZE as usize {
            // Store in ministream.
            child.entry.start_sector_location = out.mini_sector_num;

            let start = out.mini_sector_num;
            let mini_count = (data.len() as u32).div_ceil(MINI_SECTOR_SIZE);

            // Append data and pad to mini-sector boundary.
            out.ministream.extend_from_slice(&data);
            let pad = (MINI_SECTOR_SIZE as usize - (data.len() % MINI_SECTOR_SIZE as usize))
                % MINI_SECTOR_SIZE as usize;
            if pad != 0 {
                out.ministream.extend(std::iter::repeat_n(0u8, pad));
            }

            // MiniFAT chain.
            for i in 0..mini_count {
                let next = if i + 1 == mini_count {
                    ENDOFCHAIN
                } else {
                    start + i + 1
                };
                out.minifat_entries.push(next);
            }

            out.mini_sector_num = out.mini_sector_num.checked_add(mini_count).ok_or_else(|| {
                SigningError::MsiParsingError("Mini-sector counter overflow".into())
            })?;
        } else {
            // Store as regular sectors.
            child.entry.start_sector_location = out.sector_num;

            // Write data to output, padded to sector boundary.
            output.extend_from_slice(&data);
            let pad = (out.sector_size - (data.len() % out.sector_size)) % out.sector_size;
            if pad != 0 {
                output.extend(std::iter::repeat_n(0u8, pad));
            }

            let sectors = (data.len() as u32).div_ceil(out.sector_size as u32);
            for i in 0..sectors {
                let next = if i + 1 == sectors {
                    ENDOFCHAIN
                } else {
                    out.sector_num + i + 1
                };
                out.fat_entries.push(next);
            }

            out.sector_num = out
                .sector_num
                .checked_add(sectors)
                .ok_or_else(|| SigningError::MsiParsingError("Sector counter overflow".into()))?;
        }

        // Match reference behavior: free temp buffer.
        data.clear();
    }

    Ok(())
}

fn ministream_save(
    root: &mut RewriteNode,
    output: &mut Vec<u8>,
    out: &mut MsiOut,
) -> SigningResult<()> {
    if out.ministream.is_empty() {
        // No mini-stream container.
        root.entry.start_sector_location = NOSTREAM;
        return Ok(());
    }

    // Root points to the first sector of the ministream container.
    root.entry.start_sector_location = out.sector_num;

    // Write ministream bytes and pad to sector boundary.
    output.extend_from_slice(&out.ministream);
    let pad = (out.sector_size - (out.ministream.len() % out.sector_size)) % out.sector_size;
    if pad != 0 {
        output.extend(std::iter::repeat_n(0u8, pad));
    }

    let sectors = (out.ministream.len() as u32).div_ceil(out.sector_size as u32);

    // FAT chain for the ministream container sectors.
    for i in 0..sectors {
        let next = if i + 1 == sectors {
            ENDOFCHAIN
        } else {
            out.sector_num + i + 1
        };
        out.fat_entries.push(next);
    }

    out.sector_num = out
        .sector_num
        .checked_add(sectors)
        .ok_or_else(|| SigningError::MsiParsingError("Sector counter overflow".into()))?;

    Ok(())
}

fn minifat_save(output: &mut Vec<u8>, out: &mut MsiOut) -> SigningResult<()> {
    if out.minifat_entries.is_empty() {
        // No miniFAT.
        out.header[HEADER_MINI_FAT_SECTOR_LOC..HEADER_MINI_FAT_SECTOR_LOC + 4]
            .copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        out.header[HEADER_MINI_FAT_SECTORS_NUM..HEADER_MINI_FAT_SECTORS_NUM + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        out.minifat_sectors_count = 0;
        return Ok(());
    }

    // Set miniFAT start sector in header.
    out.header[HEADER_MINI_FAT_SECTOR_LOC..HEADER_MINI_FAT_SECTOR_LOC + 4]
        .copy_from_slice(&out.sector_num.to_le_bytes());

    // Serialize miniFAT entries.
    for e in &out.minifat_entries {
        output.extend_from_slice(&e.to_le_bytes());
    }

    // Pad remainder of last miniFAT sector with FREESECT.
    let used = out.minifat_entries.len();
    let entries_per_sector = out.sector_size / 4;
    let padded_entries = used.div_ceil(entries_per_sector) * entries_per_sector;
    for _ in used..padded_entries {
        output.extend_from_slice(&FREESECT.to_le_bytes());
    }

    out.minifat_sectors_count = u32::try_from(padded_entries / entries_per_sector).unwrap_or(0);

    // FAT chain for miniFAT sectors.
    for i in 0..out.minifat_sectors_count {
        let next = if i + 1 == out.minifat_sectors_count {
            ENDOFCHAIN
        } else {
            out.sector_num + i + 1
        };
        out.fat_entries.push(next);
    }

    out.sector_num = out
        .sector_num
        .checked_add(out.minifat_sectors_count)
        .ok_or_else(|| SigningError::MsiParsingError("Sector counter overflow".into()))?;

    Ok(())
}

fn dirtree_save(
    root: &mut RewriteNode,
    output: &mut Vec<u8>,
    out: &mut MsiOut,
) -> SigningResult<()> {
    // Directory starting sector location in header.
    out.header[HEADER_DIR_SECTOR_LOC..HEADER_DIR_SECTOR_LOC + 4]
        .copy_from_slice(&out.sector_num.to_le_bytes());

    // Root stream size = ministream length.
    root.entry.stream_size = u64::from(u32::try_from(out.ministream.len()).unwrap_or(u32::MAX));

    // Serialize directory entries using a degenerate directory structure **per storage**:
    // - all nodes BLACK
    // - left sibling = NOSTREAM
    // - right sibling = next sibling within the parent (linked list)
    // - child id = first child of each storage (or NOSTREAM)
    //
    // Note: Sibling/child pointers are *not* a global linked list. They form a (red-black)
    // binary search tree per storage. Some parsers (including the `cfb` crate) validate the
    // tree invariants, so we must keep pointers scoped to the correct parent.
    #[derive(Debug, Clone)]
    struct FlatNode {
        entry: DirEntry,
        children: Vec<usize>,
    }

    fn flatten(node: &RewriteNode, out: &mut Vec<FlatNode>) -> SigningResult<usize> {
        let idx = out.len();
        out.push(FlatNode {
            entry: node.entry.clone(),
            children: Vec::new(),
        });

        // Children must be ordered using the tree comparator.
        let mut kids: Vec<&RewriteNode> = node.children.iter().collect();
        kids.sort_by(|a, b| a.entry.cmp_tree(&b.entry));

        let mut child_idxs = Vec::with_capacity(kids.len());
        for child in kids {
            let child_idx = flatten(child, out)?;
            child_idxs.push(child_idx);
        }
        out[idx].children = child_idxs;
        Ok(idx)
    }

    let mut flat: Vec<FlatNode> = Vec::new();
    let root_idx = flatten(root, &mut flat)?;
    if flat.is_empty() {
        return Err(SigningError::MsiParsingError(
            "Unexpected empty directory table".into(),
        ));
    }

    // Assign ids and default pointers.
    for (idx, node) in flat.iter_mut().enumerate() {
        node.entry.id = u32::try_from(idx).unwrap_or(0);
        node.entry.color_flag = BLACK_COLOR;
        node.entry.left_sibling_id = NOSTREAM;
        node.entry.right_sibling_id = NOSTREAM;
        node.entry.child_id = NOSTREAM;
    }

    // Build per-storage child trees as a degenerate right-leaning chain in sorted order.
    // Root itself must not have siblings.
    for idx in 0..flat.len() {
        let children = flat[idx].children.clone();
        if !flat[idx].entry.is_storage() || children.is_empty() {
            continue;
        }

        flat[idx].entry.child_id = u32::try_from(children[0]).unwrap_or(NOSTREAM);

        for (pos, &child_idx) in children.iter().enumerate() {
            flat[child_idx].entry.left_sibling_id = NOSTREAM;
            flat[child_idx].entry.right_sibling_id = if pos + 1 < children.len() {
                u32::try_from(children[pos + 1]).unwrap_or(NOSTREAM)
            } else {
                NOSTREAM
            };
        }
    }

    // Ensure the root entry has no siblings.
    if root_idx < flat.len() {
        flat[root_idx].entry.left_sibling_id = NOSTREAM;
        flat[root_idx].entry.right_sibling_id = NOSTREAM;
    }

    let mut dir_bytes = Vec::new();
    for node in &flat {
        dir_bytes.extend_from_slice(&serialize_dirent(&node.entry));
    }

    // Pad directory to sector boundary with unused entries.
    if dir_bytes.len() % out.sector_size != 0 {
        let mut remain = out.sector_size - (dir_bytes.len() % out.sector_size);
        while remain > 0 {
            dir_bytes.extend_from_slice(&unused_dirent_bytes());
            remain = remain.saturating_sub(DIRENT_SIZE);
        }
    }

    output.extend_from_slice(&dir_bytes);

    out.dirtree_sectors_count =
        u32::try_from(dir_bytes.len().div_ceil(out.sector_size)).unwrap_or(0);

    // FAT chain for directory sectors.
    for i in 0..out.dirtree_sectors_count {
        let next = if i + 1 == out.dirtree_sectors_count {
            ENDOFCHAIN
        } else {
            out.sector_num + i + 1
        };
        out.fat_entries.push(next);
    }

    out.sector_num = out
        .sector_num
        .checked_add(out.dirtree_sectors_count)
        .ok_or_else(|| SigningError::MsiParsingError("Sector counter overflow".into()))?;

    Ok(())
}

fn unused_dirent_bytes() -> [u8; DIRENT_SIZE] {
    let mut data = [0u8; DIRENT_SIZE];

    data[DIRENT_LEFT_SIBLING_ID..DIRENT_LEFT_SIBLING_ID + 4]
        .copy_from_slice(&NOSTREAM.to_le_bytes());
    data[DIRENT_RIGHT_SIBLING_ID..DIRENT_RIGHT_SIBLING_ID + 4]
        .copy_from_slice(&NOSTREAM.to_le_bytes());
    data[DIRENT_CHILD_ID..DIRENT_CHILD_ID + 4].copy_from_slice(&NOSTREAM.to_le_bytes());

    data
}

fn serialize_dirent(entry: &DirEntry) -> [u8; DIRENT_SIZE] {
    let mut data = [0u8; DIRENT_SIZE];

    // Name bytes.
    let name_len = usize::from(entry.name_len_bytes).min(DIRENT_MAX_NAME_SIZE);
    data[DIRENT_NAME..DIRENT_NAME + name_len].copy_from_slice(&entry.name_utf16le[..name_len]);

    data[DIRENT_NAME_LEN..DIRENT_NAME_LEN + 2].copy_from_slice(&entry.name_len_bytes.to_le_bytes());
    data[DIRENT_TYPE] = entry.object_type;
    data[DIRENT_COLOUR] = entry.color_flag;

    data[DIRENT_LEFT_SIBLING_ID..DIRENT_LEFT_SIBLING_ID + 4]
        .copy_from_slice(&entry.left_sibling_id.to_le_bytes());
    data[DIRENT_RIGHT_SIBLING_ID..DIRENT_RIGHT_SIBLING_ID + 4]
        .copy_from_slice(&entry.right_sibling_id.to_le_bytes());
    data[DIRENT_CHILD_ID..DIRENT_CHILD_ID + 4].copy_from_slice(&entry.child_id.to_le_bytes());

    data[DIRENT_CLSID..DIRENT_CLSID + 16].copy_from_slice(&entry.clsid);
    data[DIRENT_STATE_BITS..DIRENT_STATE_BITS + 4].copy_from_slice(&entry.state_bits);
    data[DIRENT_CREATE_TIME..DIRENT_CREATE_TIME + 8].copy_from_slice(&entry.creation_time);
    data[DIRENT_MODIFY_TIME..DIRENT_MODIFY_TIME + 8].copy_from_slice(&entry.modified_time);

    data[DIRENT_START_SECTOR_LOC..DIRENT_START_SECTOR_LOC + 4]
        .copy_from_slice(&entry.start_sector_location.to_le_bytes());

    let size_lo = (entry.stream_size & 0xFFFF_FFFF) as u32;
    let size_hi = (entry.stream_size >> 32) as u32;
    data[DIRENT_FILE_SIZE..DIRENT_FILE_SIZE + 4].copy_from_slice(&size_lo.to_le_bytes());
    data[DIRENT_FILE_SIZE + 4..DIRENT_FILE_SIZE + 8].copy_from_slice(&size_hi.to_le_bytes());

    data
}

fn fat_save(output: &mut Vec<u8>, out: &mut MsiOut) -> SigningResult<()> {
    // Determine required FAT/DIFAT sectors iteratively.
    let entries_per_sector = out.sector_size / 4;
    let difat_entries_per_sector = entries_per_sector.saturating_sub(1);

    let num_sectors_before_fat = out.sector_num;

    let mut fat_sectors = 0u32;
    let mut difat_sectors = 0u32;

    for _ in 0..8 {
        let total_sectors = num_sectors_before_fat
            .checked_add(fat_sectors)
            .and_then(|v| v.checked_add(difat_sectors))
            .ok_or_else(|| SigningError::MsiParsingError("Sector count overflow".into()))?;

        let required_fat_sectors = div_ceil_u32(
            total_sectors,
            u32::try_from(entries_per_sector).unwrap_or(1),
        );
        let required_difat_sectors = if required_fat_sectors as usize > DIFAT_IN_HEADER {
            let extra = required_fat_sectors - u32::try_from(DIFAT_IN_HEADER).unwrap_or(0);
            div_ceil_u32(extra, u32::try_from(difat_entries_per_sector).unwrap_or(1))
        } else {
            0
        };

        if required_fat_sectors == fat_sectors && required_difat_sectors == difat_sectors {
            break;
        }
        fat_sectors = required_fat_sectors;
        difat_sectors = required_difat_sectors;
    }

    out.fat_sectors_count = fat_sectors;
    out.difat_sectors_count = difat_sectors;

    // Fill header DIFAT table with FAT sector numbers.
    let fat_start = num_sectors_before_fat;
    for i in 0..DIFAT_IN_HEADER {
        let off = HEADER_DIFAT + i * 4;
        let v = if i < fat_sectors as usize {
            fat_start + u32::try_from(i).unwrap_or(0)
        } else {
            FREESECT
        };
        out.header[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // If we need DIFAT sectors, set DIFAT start and count.
    if difat_sectors > 0 {
        let difat_start = fat_start
            .checked_add(fat_sectors)
            .ok_or_else(|| SigningError::MsiParsingError("Sector count overflow".into()))?;
        out.header[HEADER_DIFAT_SECTOR_LOC..HEADER_DIFAT_SECTOR_LOC + 4]
            .copy_from_slice(&difat_start.to_le_bytes());
        out.header[HEADER_DIFAT_SECTORS_NUM..HEADER_DIFAT_SECTORS_NUM + 4]
            .copy_from_slice(&difat_sectors.to_le_bytes());
    } else {
        out.header[HEADER_DIFAT_SECTOR_LOC..HEADER_DIFAT_SECTOR_LOC + 4]
            .copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        out.header[HEADER_DIFAT_SECTORS_NUM..HEADER_DIFAT_SECTORS_NUM + 4]
            .copy_from_slice(&0u32.to_le_bytes());
    }

    // Extend FAT entries with FATSECT and DIFSECT.
    for _ in 0..fat_sectors {
        out.fat_entries.push(FATSECT);
    }
    for _ in 0..difat_sectors {
        out.fat_entries.push(DIFSECT);
    }

    // Pad FAT entries to full FAT sectors.
    let required_entries = (fat_sectors as usize) * entries_per_sector;
    while out.fat_entries.len() < required_entries {
        out.fat_entries.push(FREESECT);
    }

    // Serialize FAT sectors.
    for e in &out.fat_entries {
        output.extend_from_slice(&e.to_le_bytes());
    }

    // Serialize DIFAT sectors if needed.
    if difat_sectors > 0 {
        let mut remaining_fat_ids = (fat_sectors as usize).saturating_sub(DIFAT_IN_HEADER);
        let mut next_fat_id = fat_start + u32::try_from(DIFAT_IN_HEADER).unwrap_or(0);
        let mut difat_sector_index = fat_start + fat_sectors;

        for i in 0..difat_sectors {
            let mut sector = vec![0u8; out.sector_size];
            for j in 0..difat_entries_per_sector {
                let sid = if remaining_fat_ids > 0 {
                    remaining_fat_ids -= 1;
                    let v = next_fat_id;
                    next_fat_id += 1;
                    v
                } else {
                    FREESECT
                };
                let off = j * 4;
                sector[off..off + 4].copy_from_slice(&sid.to_le_bytes());
            }
            // Link to next DIFAT sector or ENDOFCHAIN.
            let link = if i + 1 == difat_sectors {
                ENDOFCHAIN
            } else {
                difat_sector_index + 1
            };
            sector[out.sector_size - 4..out.sector_size].copy_from_slice(&link.to_le_bytes());
            output.extend_from_slice(&sector);
            difat_sector_index += 1;
        }
    }

    // Update header counts.
    out.header[HEADER_FAT_SECTORS_NUM..HEADER_FAT_SECTORS_NUM + 4]
        .copy_from_slice(&fat_sectors.to_le_bytes());
    out.header[HEADER_MINI_FAT_SECTORS_NUM..HEADER_MINI_FAT_SECTORS_NUM + 4]
        .copy_from_slice(&out.minifat_sectors_count.to_le_bytes());

    if out.sector_size == 4096 {
        out.header[HEADER_DIR_SECTORS_NUM..HEADER_DIR_SECTORS_NUM + 4]
            .copy_from_slice(&out.dirtree_sectors_count.to_le_bytes());
    }

    Ok(())
}

fn header_save(output: &mut [u8], out: &MsiOut) {
    // Overwrite the first 512 bytes.
    output[0..HEADER_SIZE].copy_from_slice(&out.header);
    // The remainder of the first sector stays zeroed.
}

fn div_ceil_u32(a: u32, b: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    (a / b) + u32::from(!a.is_multiple_of(b))
}
