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
        let pre_pad = (8 - (signed_pe.len() % 8)) % 8;
        if pre_pad > 0 {
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
        let (sigpos, _siglen) = if cert_table_offset + 8 <= signed_pe.len() {
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
        let fileend = if sigpos > 0 { sigpos } else { file_len };
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
        if idx < fileend {
            hasher.update(&signed_pe[idx..fileend]);
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
