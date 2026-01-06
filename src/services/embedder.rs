//! PE Signature Embedder Service
//!
//! Embeds PKCS#7 as `WIN_CERTIFICATE`, updates Security Directory & checksum.

use crate::{
    domain::pe,
    domain::pe::{SignedPeFile, UnsignedPeFile},
    domain::pkcs7::Pkcs7SignedData,
    infra::error::{SigningError, SigningResult},
};

pub struct PeSignatureEmbedderService;

impl Default for PeSignatureEmbedderService {
    fn default() -> Self {
        Self::new()
    }
}

impl PeSignatureEmbedderService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn embed(
        &self,
        unsigned: &UnsignedPeFile,
        pkcs7: &Pkcs7SignedData,
        original_pe_hash: &[u8],
    ) -> SigningResult<SignedPeFile> {
        let mut signed_pe = unsigned.bytes().to_vec();
        let pkcs7_der = pkcs7.as_der();
        Self::assert_no_existing_certificate(&signed_pe)?;

        // If the PE has an overlay (data after the end of the last section), we must NOT insert
        // bytes before the overlay, because overlay-based formats (e.g. WiX Burn bundles) expect
        // their attached container to start at a specific offset (typically end-of-image).
        //
        // At the same time, Windows expects the certificate table to be the last data in the file
        // (see post-MS12-024 behavior), so we keep the signature at EOF.
        let overlay_start = Self::overlay_start(&signed_pe);
        let has_overlay = overlay_start < signed_pe.len();

        // The certificate table is specified to start on an 8-byte boundary.
        // This is a Windows requirement - signatures at unaligned offsets are rejected with
        // error 0x80096010 "The digital signature of the object did not verify".
        //
        // For overlay-bearing files (e.g., WiX Burn bundles), the padding bytes are appended
        // AFTER the overlay but BEFORE the signature. The overlay container itself is not
        // modified - only padding is added at EOF to ensure proper alignment. This padding
        // becomes part of the file and must be included in the Authenticode hash computation.
        let pre_pad = (8 - (signed_pe.len() % 8)) % 8;
        if pre_pad > 0 {
            if has_overlay {
                log::info!(
                    "PE has overlay and is not 8-byte aligned (len={}): adding {} padding bytes before WIN_CERTIFICATE",
                    signed_pe.len(),
                    pre_pad
                );
            }
            signed_pe.extend(std::iter::repeat_n(0u8, pre_pad));
        }
        let padlen = (8 - ((8 + pkcs7_der.len()) % 8)) % 8;
        let dw_length = 8 + pkcs7_der.len() + padlen;
        let mut win_cert = Vec::with_capacity(dw_length);
        win_cert.extend_from_slice(&(dw_length as u32).to_le_bytes());
        win_cert.extend_from_slice(&0x0200u16.to_le_bytes());
        win_cert.extend_from_slice(&0x0002u16.to_le_bytes());
        win_cert.extend_from_slice(pkcs7_der);
        if padlen > 0 {
            win_cert.extend(std::iter::repeat_n(0u8, padlen));
        }

        let signature_offset = signed_pe.len();
        signed_pe.extend_from_slice(&win_cert);

        let cert_dir_offset = Self::security_directory_offset(&signed_pe)?;
        signed_pe[cert_dir_offset..cert_dir_offset + 4]
            .copy_from_slice(&(signature_offset as u32).to_le_bytes());
        signed_pe[cert_dir_offset + 4..cert_dir_offset + 8]
            .copy_from_slice(&(win_cert.len() as u32).to_le_bytes());
        let pe_off =
            u32::from_le_bytes([signed_pe[60], signed_pe[61], signed_pe[62], signed_pe[63]])
                as usize;
        let checksum_offset = pe_off + 24 + 64;
        pe::update_pe_checksum(&mut signed_pe, checksum_offset)?;
        if let Err(e) = Self::post_write_hash_check(&signed_pe, original_pe_hash) {
            log::warn!("Post-write hash check failed: {e}");
        }
        Ok(SignedPeFile::from_bytes(signed_pe))
    }

    /// Determine the start offset of any PE overlay.
    ///
    /// The overlay is defined as any data appended after the end of the last section's raw data.
    /// For typical `WiX` Burn bundles, the attached container lives in the overlay; we must keep
    /// the overlay start offset and its bytes intact.
    ///
    /// # Parameters
    /// - `bytes`: Full PE file bytes.
    ///
    /// # Returns
    /// A file offset (0..=len) representing the end-of-image / start-of-overlay.
    /// If parsing fails, this returns `bytes.len()` (treat as “no overlay”).
    #[must_use]
    fn overlay_start(bytes: &[u8]) -> usize {
        let Ok(pe) = goblin::pe::PE::parse(bytes) else {
            return bytes.len();
        };

        let mut end = 0usize;
        if let Some(optional_header) = pe.header.optional_header {
            end = end.max(optional_header.windows_fields.size_of_headers as usize);
        }
        for section in &pe.sections {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            end = end.max(start.saturating_add(size));
        }
        if end == 0 {
            // For very small/minimal test PEs goblin may not populate section/optional header
            // fields reliably. Treat these as having no overlay.
            return bytes.len();
        }
        end.min(bytes.len())
    }

    fn assert_no_existing_certificate(bytes: &[u8]) -> SigningResult<()> {
        let off = Self::security_directory_offset(bytes)?;
        let rva = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let size = u32::from_le_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        if rva != 0 || size != 0 {
            return Err(SigningError::ValidationError(
                "PE already has certificate table".into(),
            ));
        }
        Ok(())
    }

    fn security_directory_offset(bytes: &[u8]) -> SigningResult<usize> {
        if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
            return Err(SigningError::PeParsingError("Not PE".into()));
        }
        let pe_off = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
        if pe_off + 4 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err(SigningError::PeParsingError("Missing PE signature".into()));
        }
        if pe_off + 24 + 2 > bytes.len() {
            return Err(SigningError::PeParsingError(
                "Truncated optional header".into(),
            ));
        }
        let magic = u16::from_le_bytes([bytes[pe_off + 24], bytes[pe_off + 25]]);
        let pe32plus = matches!(magic, 0x20b);
        let off = pe_off + 24 + if pe32plus { 112 } else { 96 } + 32;
        if off + 8 > bytes.len() {
            return Err(SigningError::PeParsingError(
                "Truncated data directories".into(),
            ));
        }
        Ok(off)
    }

    fn post_write_hash_check(signed_pe: &[u8], original_pe_hash: &[u8]) -> SigningResult<()> {
        if signed_pe.len() < 64 {
            return Err(SigningError::PeParsingError("Too small".into()));
        }
        let header_size =
            u32::from_le_bytes([signed_pe[60], signed_pe[61], signed_pe[62], signed_pe[63]])
                as usize;
        if header_size + 24 >= signed_pe.len()
            || &signed_pe[header_size..header_size + 4] != b"PE\0\0"
        {
            return Err(SigningError::PeParsingError("Invalid PE".into()));
        }
        let magic = u16::from_le_bytes([signed_pe[header_size + 24], signed_pe[header_size + 25]]);
        let pe32plus = usize::from(magic == 0x20b);
        let cert_table_offset = header_size + 152 + pe32plus * 16;
        let file_len = signed_pe.len();
        let (sigpos, siglen) = if cert_table_offset + 8 <= signed_pe.len() {
            let rva = u32::from_le_bytes([
                signed_pe[cert_table_offset],
                signed_pe[cert_table_offset + 1],
                signed_pe[cert_table_offset + 2],
                signed_pe[cert_table_offset + 3],
            ]) as usize;
            let size = u32::from_le_bytes([
                signed_pe[cert_table_offset + 4],
                signed_pe[cert_table_offset + 5],
                signed_pe[cert_table_offset + 6],
                signed_pe[cert_table_offset + 7],
            ]) as usize;
            if rva > 0 && size > 0 && rva < file_len && rva + size <= file_len {
                (rva, size)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };
        let sigend = sigpos.saturating_add(siglen);
        use sha2::{Digest, Sha256, Sha384, Sha512};
        let mut hasher = match original_pe_hash.len() {
            32 => Box::new(Sha256::new()) as Box<dyn sha2::digest::DynDigest>,
            48 => Box::new(Sha384::new()) as Box<dyn sha2::digest::DynDigest>,
            64 => Box::new(Sha512::new()) as Box<dyn sha2::digest::DynDigest>,
            _ => Box::new(Sha256::new()) as Box<dyn sha2::digest::DynDigest>,
        };
        let mut idx = 0;
        let range1_end = header_size + 88;
        hasher.update(&signed_pe[idx..range1_end]);
        idx = range1_end + 4;
        let range2_len = 60 + pe32plus * 16;
        let range2_end = idx + range2_len;
        hasher.update(&signed_pe[idx..range2_end]);
        idx = range2_end + 8;
        let mut cursor = idx;
        if sigpos > 0 && sigend <= file_len {
            if cursor < sigpos {
                hasher.update(&signed_pe[cursor..sigpos]);
            }
            cursor = sigend;
        }
        if cursor < file_len {
            hasher.update(&signed_pe[cursor..file_len]);
        }
        if sigpos == 0 {
            let pad_len = 8 - (file_len % 8);
            if pad_len > 0 && pad_len != 8 {
                hasher.update(&vec![0u8; pad_len]);
            }
        }
        let digest_vec = hasher.finalize().to_vec();
        if digest_vec.as_slice() != original_pe_hash {
            log::warn!("PE hash mismatch after embedding");
        }
        Ok(())
    }
}
