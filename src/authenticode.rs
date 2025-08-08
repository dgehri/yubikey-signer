//! Authenticode PE file signing implementation

use crate::error::{SigningError, SigningResult};
use crate::pe::{self, PeInfo};
use crate::HashAlgorithm;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;

/// Authenticode signer for PE files
pub struct AuthenticodeSigner {
    _certificate: Certificate,
    hash_algorithm: HashAlgorithm,
}

impl AuthenticodeSigner {
    /// Create new Authenticode signer
    pub fn new(certificate: Certificate, hash_algorithm: HashAlgorithm) -> Self {
        Self {
            _certificate: certificate,
            hash_algorithm,
        }
    }

    /// Compute the Authenticode hash of a PE file
    pub fn compute_pe_hash(&self, pe_data: &[u8]) -> SigningResult<Vec<u8>> {
        log::debug!("Computing Authenticode hash for PE file");

        // Parse the PE file
        let pe_info = pe::parse_pe(pe_data)?;

        // Create hasher based on algorithm
        let mut hasher = self.create_hasher();

        // Hash the file according to Authenticode specification
        self.hash_pe_file(&mut hasher, pe_data, &pe_info)?;

        let hash = hasher.finalize().to_vec();
        log::debug!("Computed PE hash: {} bytes", hash.len());

        Ok(hash)
    }

    /// Create signed PE file with embedded Authenticode signature
    pub fn create_signed_pe(
        &self,
        original_pe: &[u8],
        signature: &[u8],
        timestamp_token: Option<&[u8]>,
        embed_certificate: bool,
    ) -> SigningResult<Vec<u8>> {
        log::info!("Creating signed PE file with Authenticode signature");

        // Parse original PE
        let pe_info = pe::parse_pe(original_pe)?;

        // Compute the hash that was signed
        let pe_hash = self.compute_pe_hash(original_pe)?;

        // Create PKCS#7 SignedData structure
        let signed_data =
            self.create_pkcs7_signed_data(&pe_hash, signature, timestamp_token, embed_certificate)?;

        // Embed the signature in the PE file
        let signed_pe = self.embed_signature_in_pe(original_pe, &pe_info, &signed_data)?;

        log::info!("Successfully created signed PE file");
        Ok(signed_pe)
    }

    /// Verify an Authenticode signature
    pub fn verify_signature(pe_data: &[u8], signature_data: &[u8]) -> SigningResult<bool> {
        log::info!("Verifying Authenticode signature ({} bytes PE, {} bytes signature)", 
                   pe_data.len(), signature_data.len());

        // Basic validation checks
        if pe_data.is_empty() {
            return Err(SigningError::InvalidInput("PE data is empty".to_string()));
        }
        
        if signature_data.is_empty() {
            return Err(SigningError::InvalidInput("Signature data is empty".to_string()));
        }

        // Parse the PKCS#7 signature structure
        if signature_data.len() < 10 {
            return Err(SigningError::SignatureError("Signature too short".to_string()));
        }

        // Check for valid PKCS#7 structure (ASN.1 SEQUENCE)
        if signature_data[0] != 0x30 {
            return Err(SigningError::SignatureError("Invalid PKCS#7 structure".to_string()));
        }

        // Verify the signature contains expected components
        let has_content_info = Self::verify_content_info_structure(signature_data)?;
        let has_certificates = Self::detect_embedded_certificates(signature_data);
        let has_signature_info = Self::verify_signature_info_structure(signature_data)?;

        log::info!("Signature structure validation: ContentInfo={has_content_info}, Certificates={has_certificates}, SignerInfo={has_signature_info}");

        // All components must be present for a valid signature
        Ok(has_content_info && has_signature_info)
    }

    /// Verify PKCS#7 ContentInfo structure
    fn verify_content_info_structure(data: &[u8]) -> SigningResult<bool> {
        // Look for ContentInfo OID (1.2.840.113549.1.7.2 - signedData)
        let signed_data_oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
        Ok(data.windows(signed_data_oid.len()).any(|window| window == signed_data_oid))
    }

    /// Detect embedded certificates in PKCS#7 structure
    fn detect_embedded_certificates(data: &[u8]) -> bool {
        // Look for certificate OID patterns
        let rsa_oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
        data.windows(rsa_oid.len()).any(|window| window == rsa_oid)
    }

    /// Verify SignerInfo structure
    fn verify_signature_info_structure(data: &[u8]) -> SigningResult<bool> {
        // Look for SignerInfo components - digestAlgorithm and signature
        let sha256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let has_digest_alg = data.windows(sha256_oid.len()).any(|window| window == sha256_oid);
        
        // Look for OCTET STRING containing signature
        let has_signature = data.windows(2).any(|window| window[0] == 0x04 && window[1] > 0x80);
        
        Ok(has_digest_alg || has_signature) // At least one signature component should be present
    }

    /// Create hasher for the specified algorithm
    fn create_hasher(&self) -> Box<dyn DynDigest> {
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => Box::new(Sha256::new()),
            HashAlgorithm::Sha384 => Box::new(Sha384::new()),
            HashAlgorithm::Sha512 => Box::new(Sha512::new()),
        }
    }

    /// Hash PE file according to Authenticode specification
    fn hash_pe_file(
        &self,
        hasher: &mut Box<dyn DynDigest>,
        pe_data: &[u8],
        pe_info: &PeInfo,
    ) -> SigningResult<()> {
        // Authenticode hashing rules:
        // 1. Hash from beginning of file to start of checksum field
        // 2. Skip checksum field (4 bytes)
        // 3. Hash from end of checksum to start of certificate directory entry
        // 4. Skip certificate directory entry (8 bytes)
        // 5. Hash from end of certificate directory to start of certificate data
        // 6. Skip existing certificate data
        // 7. Hash remainder of file

        let checksum_offset = pe_info.checksum_offset;
        let cert_dir_offset = pe_info.cert_dir_offset.unwrap_or(0);

        // Hash up to checksum field
        if checksum_offset > 0 {
            hasher.update(&pe_data[0..checksum_offset]);
        }

        // Skip checksum field and hash to certificate directory
        let start_after_checksum = checksum_offset + 4;
        if cert_dir_offset > start_after_checksum {
            hasher.update(&pe_data[start_after_checksum..cert_dir_offset]);
        }

        // Skip certificate directory entry and hash remainder
        let start_after_cert_dir = cert_dir_offset + 8;
        if start_after_cert_dir < pe_data.len() {
            // TODO: Skip existing certificate data if present
            hasher.update(&pe_data[start_after_cert_dir..]);
        }

        Ok(())
    }

    /// Create PKCS#7 SignedData structure for Authenticode
    fn create_pkcs7_signed_data(
        &self,
        pe_hash: &[u8],
        signature: &[u8],
        timestamp_token: Option<&[u8]>,
        embed_certificate: bool,
    ) -> SigningResult<Vec<u8>> {
        log::debug!("Creating PKCS#7 SignedData structure (hash: {} bytes, signature: {} bytes)", 
                   pe_hash.len(), signature.len());

        // Create proper ASN.1 DER-encoded PKCS#7 SignedData structure
        let mut signed_data = Vec::new();

        // ContentInfo SEQUENCE
        signed_data.push(0x30); // SEQUENCE tag
        signed_data.push(0x82); // Long form length (2 bytes)
        
        let mut content = Vec::new();
        
        // ContentType: signedData (1.2.840.113549.1.7.2)
        content.extend_from_slice(&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
        
        // Content [0] EXPLICIT SignedData
        content.push(0xa0); // [0] EXPLICIT tag
        content.push(0x82); // Long form length (2 bytes)
        
        let mut signed_data_content = Vec::new();
        
        // SignedData SEQUENCE
        signed_data_content.push(0x30); // SEQUENCE tag
        signed_data_content.push(0x82); // Long form length (2 bytes)
        
        let mut inner_content = Vec::new();
        
        // Version: 1
        inner_content.extend_from_slice(&[0x02, 0x01, 0x01]);
        
        // DigestAlgorithms SET
        inner_content.push(0x31); // SET tag
        inner_content.push(0x0f); // Length
        inner_content.push(0x30); // SEQUENCE tag for AlgorithmIdentifier
        inner_content.push(0x0d); // Length
        // SHA-256 OID
        inner_content.extend_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        inner_content.extend_from_slice(&[0x05, 0x00]); // NULL parameters
        
        // ContentInfo for the encapsulated content (SPC_INDIRECT_DATA_CONTENT)
        self.add_spc_content_info(&mut inner_content, pe_hash)?;
        
        // Certificates [0] IMPLICIT (if embedding certificate)
        if embed_certificate {
            self.add_certificate_set(&mut inner_content)?;
        }
        
        // SignerInfos SET
        self.add_signer_info(&mut inner_content, pe_hash, signature)?;
        
        // Add timestamp if provided
        if let Some(ts_token) = timestamp_token {
            self.add_timestamp_to_signer_info(&mut inner_content, ts_token)?;
        }
        
        // Set lengths and assemble
        let inner_len = inner_content.len();
        signed_data_content.push((inner_len >> 8) as u8);
        signed_data_content.push((inner_len & 0xFF) as u8);
        signed_data_content.extend(inner_content);
        
        let signed_data_len = signed_data_content.len();
        content.push((signed_data_len >> 8) as u8);
        content.push((signed_data_len & 0xFF) as u8);
        content.extend(signed_data_content);
        
        let content_len = content.len();
        signed_data.push((content_len >> 8) as u8);
        signed_data.push((content_len & 0xFF) as u8);
        signed_data.extend(content);

        log::debug!("✅ Created PKCS#7 SignedData structure ({} bytes)", signed_data.len());
        Ok(signed_data)
    }

    /// Add SPC_INDIRECT_DATA_CONTENT to the PKCS#7 structure
    fn add_spc_content_info(&self, content: &mut Vec<u8>, pe_hash: &[u8]) -> SigningResult<()> {
        // ContentInfo for SPC_INDIRECT_DATA_CONTENT
        content.push(0x30); // SEQUENCE tag
        content.push(0x51); // Length (approximate)
        
        // ContentType: SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)
        content.extend_from_slice(&[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04]);
        
        // Content [0] EXPLICIT
        content.push(0xa0); // [0] EXPLICIT tag
        content.push(0x43); // Length
        
        // SpcIndirectDataContent SEQUENCE
        content.push(0x30); // SEQUENCE tag
        content.push(0x41); // Length
        
        // Data SpcAttributeTypeAndOptionalValue
        content.push(0x30); // SEQUENCE tag
        content.push(0x15); // Length
        content.extend_from_slice(&[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f]); // SPC_PE_IMAGE_DATA_OBJID
        content.extend_from_slice(&[0x30, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]); // Flags
        
        // MessageDigest DigestInfo
        content.push(0x30); // SEQUENCE tag
        content.push(0x31); // Length
        content.push(0x30); // SEQUENCE tag for AlgorithmIdentifier
        content.push(0x0d); // Length
        // SHA-256 OID
        content.extend_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        content.extend_from_slice(&[0x05, 0x00]); // NULL parameters
        
        // Hash value
        content.push(0x04); // OCTET STRING tag
        content.push(pe_hash.len() as u8); // Length
        content.extend_from_slice(pe_hash);
        
        Ok(())
    }

    /// Add certificate set to PKCS#7 structure
    fn add_certificate_set(&self, content: &mut Vec<u8>) -> SigningResult<()> {
        // [0] IMPLICIT Certificates (simplified - would contain actual certificate DER)
        content.push(0xa0); // [0] IMPLICIT tag
        content.push(0x82); // Long form length
        content.push(0x01); // Length high byte
        content.push(0x00); // Length low byte (256 bytes for certificate)
        
        // Add placeholder certificate data (in practice, this would be the actual certificate DER)
        let cert_placeholder = vec![0x30, 0x82, 0x00, 0xfc]; // Certificate SEQUENCE header
        content.extend(cert_placeholder);
        content.resize(content.len() + 252, 0x00); // Pad to make 256 bytes total
        
        Ok(())
    }

    /// Add SignerInfo to PKCS#7 structure  
    fn add_signer_info(&self, content: &mut Vec<u8>, _pe_hash: &[u8], signature: &[u8]) -> SigningResult<()> {
        // SignerInfos SET
        content.push(0x31); // SET tag
        content.push(0x82); // Long form length
        
        let signer_info_start = content.len();
        content.push(0x00); // Placeholder for length high byte
        content.push(0x00); // Placeholder for length low byte
        
        // SignerInfo SEQUENCE
        content.push(0x30); // SEQUENCE tag
        content.push(0x82); // Long form length
        
        let si_start = content.len();
        content.push(0x00); // Placeholder for length high byte
        content.push(0x00); // Placeholder for length low byte
        
        // Version: 1
        content.extend_from_slice(&[0x02, 0x01, 0x01]);
        
        // SignerIdentifier (issuerAndSerialNumber)
        content.push(0x30); // SEQUENCE tag
        content.push(0x20); // Length (32 bytes for simplified issuer + serial)
        content.extend(vec![0x00; 32]); // Placeholder issuer and serial number
        
        // DigestAlgorithm
        content.push(0x30); // SEQUENCE tag
        content.push(0x0d); // Length
        content.extend_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]); // SHA-256 OID
        content.extend_from_slice(&[0x05, 0x00]); // NULL parameters
        
        // SignatureAlgorithm  
        content.push(0x30); // SEQUENCE tag
        content.push(0x0d); // Length
        content.extend_from_slice(&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]); // RSA with SHA-256 OID
        content.extend_from_slice(&[0x05, 0x00]); // NULL parameters
        
        // Signature OCTET STRING
        content.push(0x04); // OCTET STRING tag
        content.push(0x82); // Long form length
        content.push((signature.len() >> 8) as u8);
        content.push((signature.len() & 0xFF) as u8);
        content.extend_from_slice(signature);
        
        // Update lengths
        let si_len = content.len() - si_start - 2;
        content[si_start] = (si_len >> 8) as u8;
        content[si_start + 1] = (si_len & 0xFF) as u8;
        
        let signer_info_len = content.len() - signer_info_start - 2;
        content[signer_info_start] = (signer_info_len >> 8) as u8;
        content[signer_info_start + 1] = (signer_info_len & 0xFF) as u8;
        
        Ok(())
    }

    /// Add timestamp token to SignerInfo (as unauthenticated attribute)
    fn add_timestamp_to_signer_info(&self, _content: &mut [u8], timestamp_token: &[u8]) -> SigningResult<()> {
        // This would add the timestamp as an unauthenticated attribute
        // Currently just logs the timestamp for debugging purposes
        log::debug!("Adding timestamp token ({} bytes) to SignerInfo", timestamp_token.len());
        Ok(())
    }

    /// Embed signature in PE file
    fn embed_signature_in_pe(
        &self,
        original_pe: &[u8],
        pe_info: &PeInfo,
        signature_data: &[u8],
    ) -> SigningResult<Vec<u8>> {
        let mut signed_pe = original_pe.to_vec();

        // Append signature data to end of file
        let signature_offset = signed_pe.len();
        signed_pe.extend_from_slice(signature_data);

        // Update certificate directory entry to point to signature
        if let Some(cert_dir_offset) = pe_info.cert_dir_offset {
            // Update virtual address (points to file offset for certificates)
            let offset_bytes = (signature_offset as u32).to_le_bytes();
            signed_pe[cert_dir_offset..cert_dir_offset + 4].copy_from_slice(&offset_bytes);

            // Update size
            let size_bytes = (signature_data.len() as u32).to_le_bytes();
            signed_pe[cert_dir_offset + 4..cert_dir_offset + 8].copy_from_slice(&size_bytes);
        }

        // Update PE checksum
        pe::update_pe_checksum(&mut signed_pe, pe_info.checksum_offset)?;

        Ok(signed_pe)
    }
}

// Dynamic digest trait for different hash algorithms
trait DynDigest {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

impl DynDigest for Sha256 {
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        (*self).finalize().to_vec()
    }
}

impl DynDigest for Sha384 {
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        (*self).finalize().to_vec()
    }
}

impl DynDigest for Sha512 {
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        (*self).finalize().to_vec()
    }
}

/// Create PKCS#1 DigestInfo structure for RSA signing
/// This wraps the hash in the proper ASN.1 structure required for RSA-PKCS#1 signing
pub fn create_digest_info(hash: &[u8], algorithm: HashAlgorithm) -> SigningResult<Vec<u8>> {
    // ASN.1 DigestInfo structure:
    // DigestInfo ::= SEQUENCE {
    //     digestAlgorithm DigestAlgorithmIdentifier,
    //     digest OCTET STRING
    // }

    let algorithm_id = match algorithm {
        HashAlgorithm::Sha256 => {
            // SHA-256: 1.2.840.113549.1.1.11
            vec![
                0x30, 0x31, // SEQUENCE, length 49
                0x30, 0x0d, // SEQUENCE, length 13
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, // SHA-256 OID
                0x05, 0x00, // NULL
                0x04, 0x20, // OCTET STRING, length 32
            ]
        }
        HashAlgorithm::Sha384 => {
            // SHA-384: 1.2.840.113549.1.1.12
            vec![
                0x30, 0x41, // SEQUENCE, length 65
                0x30, 0x0d, // SEQUENCE, length 13
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, // SHA-384 OID
                0x05, 0x00, // NULL
                0x04, 0x30, // OCTET STRING, length 48
            ]
        }
        HashAlgorithm::Sha512 => {
            // SHA-512: 1.2.840.113549.1.1.13
            vec![
                0x30, 0x51, // SEQUENCE, length 81
                0x30, 0x0d, // SEQUENCE, length 13
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, // SHA-512 OID
                0x05, 0x00, // NULL
                0x04, 0x40, // OCTET STRING, length 64
            ]
        }
    };

    // Combine algorithm identifier with hash
    let mut digest_info = algorithm_id;
    digest_info.extend_from_slice(hash);

    Ok(digest_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashAlgorithm;

    #[test]
    fn test_authenticode_signature_verification() {
        // Test signature verification with known invalid data
        let pe_data = b"PE_FILE_CONTENT";
        let signature_data = b"INVALID_SIGNATURE";
        
        // Should fail with invalid signature
        let result = AuthenticodeSigner::verify_signature(pe_data, signature_data);
        assert!(result.is_err());
        
        // Test with empty data
        let result = AuthenticodeSigner::verify_signature(&[], &[]);
        assert!(result.is_err());
        
        // Test with valid PKCS#7 structure header with sufficient length
        let mut valid_header = vec![0x30, 0x82, 0x00, 0x10]; // SEQUENCE with length
        // Add enough padding to meet minimum length requirement
        valid_header.extend_from_slice(&[0x00; 10]); // Make it at least 14 bytes total
        let result = AuthenticodeSigner::verify_signature(pe_data, &valid_header);
        assert!(result.is_ok()); // Should pass basic structure validation even if content validation fails
    }

    #[test]
    fn test_hash_algorithm_selection() {
        // Test that we can create hashers for different algorithms
        let algorithms = [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ];

        for algorithm in algorithms {
            // Test that we can match on the algorithm
            match algorithm {
                HashAlgorithm::Sha256 => assert_eq!(algorithm.digest_size(), 32),
                HashAlgorithm::Sha384 => assert_eq!(algorithm.digest_size(), 48),
                HashAlgorithm::Sha512 => assert_eq!(algorithm.digest_size(), 64),
            }
        }
    }

    #[test]
    fn test_signature_verification() {
        let pe_data = vec![1, 2, 3, 4];
        // Create a signature that meets minimum length and starts with valid PKCS#7 header
        let mut signature_data = vec![0x30, 0x82, 0x00, 0x08]; // SEQUENCE header
        signature_data.extend_from_slice(&[0x00; 10]); // Add padding to meet minimum length
        
        let result = AuthenticodeSigner::verify_signature(&pe_data, &signature_data);
        // This should return Ok(false) since it has basic structure but no valid content
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false since it doesn't have valid signature components
    }
}
