//! MSI file hash computation for Authenticode signing.
//!
//! Implements the MSI-specific hash algorithm as used by signtool/osslsigncode.
//! MSI files hash their stream contents in a specific sorted order, excluding
//! the signature streams themselves.

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
    /// The hash is computed over all streams in sorted order, excluding:
    /// - `\x05DigitalSignature` stream
    /// - `\x05MsiDigitalSignatureEx` stream
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
        let cursor = Cursor::new(self.data);
        let mut cfb = CompoundFile::open(cursor).map_err(|e| {
            SigningError::MsiParsingError(format!("Failed to parse MSI structure: {e}"))
        })?;

        // Collect all streams with their paths
        let mut streams: Vec<(String, Vec<u8>)> = Vec::new();

        // Get list of all entries first
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
                log::debug!("Skipping signature stream: {path_str}");
                continue;
            }

            // Read stream content
            let mut stream = cfb.open_stream(&path).map_err(|e| {
                SigningError::MsiParsingError(format!("Failed to open stream '{path_str}': {e}"))
            })?;

            let mut content = Vec::new();
            stream.read_to_end(&mut content).map_err(|e| {
                SigningError::MsiParsingError(format!("Failed to read stream '{path_str}': {e}"))
            })?;

            // Only include non-empty streams
            if !content.is_empty() {
                streams.push((path_str, content));
            }
        }

        // Sort streams by name according to MSI specification
        // The sort order is case-insensitive and length-based (shorter names first)
        streams.sort_by(|a, b| msi_stream_compare(&a.0, &b.0));

        log::debug!(
            "Computing MSI hash over {} streams with {:?}",
            streams.len(),
            algorithm
        );

        // Compute hash over sorted stream contents
        match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                for (name, content) in &streams {
                    log::trace!("Hashing stream '{}': {} bytes", name, content.len());
                    hasher.update(content);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                for (name, content) in &streams {
                    log::trace!("Hashing stream '{}': {} bytes", name, content.len());
                    hasher.update(content);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                for (name, content) in &streams {
                    log::trace!("Hashing stream '{}': {} bytes", name, content.len());
                    hasher.update(content);
                }
                Ok(hasher.finalize().to_vec())
            }
        }
    }

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

/// Compare stream names according to MSI specification.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_comparison() {
        assert_eq!(msi_stream_compare("a", "b"), Ordering::Less);
        assert_eq!(msi_stream_compare("ab", "a"), Ordering::Greater);
        assert_eq!(msi_stream_compare("AB", "ab"), Ordering::Equal);
    }
}
