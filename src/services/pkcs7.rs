//! PKCS#7 `SignedData` construction and manipulation for Authenticode signatures.
//!
//! Provides comprehensive PKCS#7 operations including:
//! - `SignedData` structure assembly with proper ASN.1 encoding
//! - Certificate chain embedding and validation
//! - Timestamp token integration as unsigned attributes
//! - Authenticode-specific attribute handling and ordering
//!
//! This module handles the cryptographic container format that wraps
//! the actual digital signature and associated metadata.

use crate::domain::constants;
use crate::domain::crypto::HashAlgorithm;
use crate::infra::error::{SigningError, SigningResult};
use openssl::x509::X509;

/// Consolidated PKCS#7 builder for Authenticode signatures
pub struct AuthenticodeBuilder {
    certificate_der: Vec<u8>,
    additional_certs: Vec<Vec<u8>>,
    hash_algorithm: HashAlgorithm,
}

impl AuthenticodeBuilder {
    /// Create a new PKCS#7 builder with certificate and hash algorithm
    #[must_use]
    pub fn new(certificate_der: Vec<u8>, hash_algorithm: HashAlgorithm) -> Self {
        Self {
            certificate_der,
            additional_certs: Vec::new(),
            hash_algorithm,
        }
    }

    /// Set additional certificates to include in the signature.
    ///
    /// These certificates (typically intermediate CAs) will be embedded in the
    /// PKCS#7 `SignedData` certificates field alongside the signing certificate.
    ///
    /// # Arguments
    /// * `certs` - Vector of DER-encoded certificate bytes
    #[must_use]
    pub fn with_additional_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.additional_certs = certs;
        self
    }

    /// Encode ASN.1 length field correctly (short form vs long form)
    fn encode_length_bytes(&self, length: usize) -> Vec<u8> {
        if length < 128 {
            // Short form: one byte
            vec![length as u8]
        } else if length < 256 {
            // Long form: 0x81 + length
            vec![constants::DER_LONG_FORM_1_BYTE, length as u8]
        } else if length < 65536 {
            // Long form: 0x82 + two length bytes
            vec![
                constants::DER_LONG_FORM_2_BYTE,
                (length >> 8) as u8,
                (length & 0xFF) as u8,
            ]
        } else {
            // Very long form: 0x83 + three length bytes
            vec![
                constants::DER_LONG_FORM_3_BYTE,
                ((length >> 16) & 0xFF) as u8,
                ((length >> 8) & 0xFF) as u8,
                (length & 0xFF) as u8,
            ]
        }
    }

    /// Build PKCS#7 `SignedData` with pre-encoded [0] IMPLICIT attributes (fixes cryptographic mismatch)
    pub fn build_with_signature_fixed_attrs(
        &self,
        spc_content: &[u8],
        a0_implicit_attrs: &[u8], // Pre-encoded [0] IMPLICIT DER
        signature: &[u8],
        embed_certificate: bool,
    ) -> SigningResult<Vec<u8>> {
        // Build SignedData inner content first
        let mut signed_data_content = Vec::new();

        // version INTEGER (1 for PKCS#7 v1.5)
        signed_data_content.push(0x02); // INTEGER
        signed_data_content.push(0x01); // Length
        signed_data_content.push(0x01); // Version 1
        log::debug!(
            "DEBUG_SIGNEDDATA: version: {} bytes",
            signed_data_content.len()
        );

        // digestAlgorithms SET
        let digest_algs = self.build_digest_algorithms()?;
        signed_data_content.extend_from_slice(&digest_algs);
        log::debug!(
            "DEBUG_SIGNEDDATA: + digestAlgorithms: {} bytes (total: {})",
            digest_algs.len(),
            signed_data_content.len()
        );

        // contentInfo (SPC Indirect Data Content)
        let content_info = self.build_content_info(spc_content)?;
        signed_data_content.extend_from_slice(&content_info);
        log::debug!(
            "DEBUG_SIGNEDDATA: + contentInfo: {} bytes (total: {})",
            content_info.len(),
            signed_data_content.len()
        );

        // certificates [0] IMPLICIT (optional)
        if embed_certificate {
            let certificates = self.build_certificates()?;
            signed_data_content.extend_from_slice(&certificates);
            log::debug!(
                "DEBUG_SIGNEDDATA: + certificates: {} bytes (total: {})",
                certificates.len(),
                signed_data_content.len()
            );
        }

        // signerInfos SET
        let signer_infos = self.build_signer_info_fixed_attrs(a0_implicit_attrs, signature)?;
        signed_data_content.extend_from_slice(&signer_infos);
        log::debug!(
            "DEBUG_SIGNEDDATA: + signerInfos: {} bytes (total: {})",
            signer_infos.len(),
            signed_data_content.len()
        );
        log::debug!(
            "DEBUG_SIGNEDDATA: Final SignedData content before SEQUENCE wrapping: {} bytes",
            signed_data_content.len()
        );

        // Wrap SignedData content in SEQUENCE with minimal DER length
        let mut signed_data_seq = Vec::new();
        signed_data_seq.push(constants::ASN1_SEQUENCE_TAG); // SEQUENCE
        let signed_data_length_bytes = self.encode_length_bytes(signed_data_content.len());
        log::debug!(
            "DEBUG_SIGNEDDATA: SignedData content length: {} bytes",
            signed_data_content.len()
        );
        log::debug!("DEBUG_SIGNEDDATA: SignedData length encoding: {signed_data_length_bytes:?}");
        signed_data_seq.extend_from_slice(&signed_data_length_bytes);
        signed_data_seq.extend_from_slice(&signed_data_content);
        log::debug!(
            "DEBUG_SIGNEDDATA: Final SignedData SEQUENCE: {} bytes",
            signed_data_seq.len()
        );

        // Build ContentInfo for SignedData: OID + [0] EXPLICIT { SignedData }
        let mut ci_body = Vec::new();
        // contentType OID: signedData (1.2.840.113549.1.7.2)
        ci_body.push(constants::ASN1_OID_TAG); // OBJECT IDENTIFIER
        ci_body.push(0x09); // Length
        ci_body.extend_from_slice(constants::PKCS7_SIGNED_DATA_OID);
        // content [0] EXPLICIT
        ci_body.push(0xa0);
        let explicit_length_bytes = self.encode_length_bytes(signed_data_seq.len());
        log::debug!(
            "DEBUG_LENGTH: SignedData SEQUENCE size: {} bytes",
            signed_data_seq.len()
        );
        log::debug!("DEBUG_LENGTH: [0] EXPLICIT length encoding: {explicit_length_bytes:?}");
        ci_body.extend_from_slice(&explicit_length_bytes);
        ci_body.extend_from_slice(&signed_data_seq);
        log::debug!(
            "DEBUG_LENGTH: Total ContentInfo body size: {} bytes",
            ci_body.len()
        );

        // Outer ContentInfo SEQUENCE with minimal DER length
        let mut pkcs7 = Vec::new();
        pkcs7.push(0x30); // SEQUENCE
        let outer_length_bytes = self.encode_length_bytes(ci_body.len());
        log::debug!("DEBUG_LENGTH: Outer SEQUENCE length encoding: {outer_length_bytes:?}");
        pkcs7.extend_from_slice(&outer_length_bytes);
        pkcs7.extend_from_slice(&ci_body);
        log::debug!(
            "DEBUG_LENGTH: Final PKCS#7 size before trimming: {} bytes",
            pkcs7.len()
        );

        // Final guard: ensure no stray bytes beyond top-level DER length
        let total = Self::der_total_length(&pkcs7)?;
        if pkcs7.len() > total {
            log::warn!(
                "Trimming PKCS#7 trailing bytes: built={} declared={} (-{})",
                pkcs7.len(),
                total,
                pkcs7.len() - total
            );
            let mut trimmed = pkcs7;
            trimmed.truncate(total);
            log::debug!(
                "Built Authenticode PKCS#7 with fixed attributes: {} bytes (trimmed)",
                trimmed.len()
            );
            return Ok(trimmed);
        }
        log::debug!(
            "Built Authenticode PKCS#7 with fixed attributes: {} bytes",
            pkcs7.len()
        );
        Ok(pkcs7)
    }

    /// Build PKCS#7 with timestamp using pre-encoded [0] IMPLICIT attributes  
    pub fn build_with_signature_and_timestamp_fixed_attrs(
        &self,
        spc_content: &[u8],
        a0_implicit_attrs: &[u8], // Pre-encoded [0] IMPLICIT DER
        signature: &[u8],
        embed_certificate: bool,
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<Vec<u8>> {
        // If no timestamp provided, reuse the non-timestamp path
        if let Some(ts_token) = timestamp_token {
            log::warn!("[*] Using rebuild approach that changes signedAttrs");
            log::warn!("[*] This will cause Windows validation issues - surgical approach needed");

            // Build complete PKCS#7 with timestamp - similar to build_with_signature_fixed_attrs
            // but using the timestamp-enabled SignerInfo builder

            log::info!("[+] PKCS7::build_with_signature_and_timestamp_fixed_attrs CALLED");

            // Build SignedData inner content first
            let mut signed_data_content = Vec::new();

            // Version (INTEGER 1)
            signed_data_content.push(constants::ASN1_INTEGER_TAG); // INTEGER
            signed_data_content.push(0x01); // Length
            signed_data_content.push(0x01); // Version 1            // digestAlgorithms SET
            let digest_algs = self.build_digest_algorithms()?;
            signed_data_content.extend_from_slice(&digest_algs);

            // contentInfo (SPC Indirect Data Content)
            let content_info = self.build_content_info(spc_content)?;
            signed_data_content.extend_from_slice(&content_info);

            // certificates [0] IMPLICIT (optional)
            if embed_certificate {
                let certificates = self.build_certificates()?;
                signed_data_content.extend_from_slice(&certificates);
            }

            // signerInfos SET (with timestamp)
            let signer_infos = self.build_signer_info_fixed_attrs_with_timestamp(
                a0_implicit_attrs,
                signature,
                ts_token,
            )?;
            signed_data_content.extend_from_slice(&signer_infos);

            // Wrap SignedData content in SEQUENCE
            let mut signed_data_seq = Vec::new();
            signed_data_seq.push(0x30); // SEQUENCE
            let signed_data_length_bytes = self.encode_length_bytes(signed_data_content.len());
            signed_data_seq.extend_from_slice(&signed_data_length_bytes);
            signed_data_seq.extend_from_slice(&signed_data_content);

            // Build ContentInfo for SignedData: OID + [0] EXPLICIT { SignedData }
            let mut ci_body = Vec::new();
            // contentType OID: signedData (1.2.840.113549.1.7.2)
            ci_body.push(0x06); // OBJECT IDENTIFIER
            ci_body.push(0x09); // Length
            ci_body.extend_from_slice(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
            // content [0] EXPLICIT
            ci_body.push(0xa0);
            let explicit_length_bytes = self.encode_length_bytes(signed_data_seq.len());
            ci_body.extend_from_slice(&explicit_length_bytes);
            ci_body.extend_from_slice(&signed_data_seq);

            // Outer ContentInfo SEQUENCE
            let mut pkcs7 = Vec::new();
            pkcs7.push(0x30); // SEQUENCE
            let outer_length_bytes = self.encode_length_bytes(ci_body.len());
            pkcs7.extend_from_slice(&outer_length_bytes);
            pkcs7.extend_from_slice(&ci_body);

            // Final guard: ensure no stray bytes beyond top-level DER length
            let total = Self::der_total_length(&pkcs7)?;
            if pkcs7.len() > total {
                let mut trimmed = pkcs7;
                trimmed.truncate(total);
                log::debug!(
                    "Built PKCS#7 with timestamp: {} bytes (trimmed)",
                    trimmed.len()
                );
                return Ok(trimmed);
            }
            log::debug!("Built PKCS#7 with timestamp: {} bytes", pkcs7.len());
            Ok(pkcs7)
        } else {
            self.build_with_signature_fixed_attrs(
                spc_content,
                a0_implicit_attrs,
                signature,
                embed_certificate,
            )
        }
    }

    /// Build digestAlgorithms SET
    fn build_digest_algorithms(&self) -> SigningResult<Vec<u8>> {
        let mut algs = vec![
            0x31, // SET
            0x0f, // Length (15 bytes)
            0x30, // SEQUENCE
            0x0d, // Length (13 bytes)
            0x06, // OBJECT IDENTIFIER
            0x09, // Length
        ];

        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                algs.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
                // SHA-256
            }
            HashAlgorithm::Sha384 => {
                algs.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
                // SHA-384
            }
            HashAlgorithm::Sha512 => {
                algs.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
                // SHA-512
            }
        }

        // NULL parameters
        algs.push(0x05); // NULL
        algs.push(0x00); // Length

        Ok(algs)
    }

    /// Build contentInfo for SPC Indirect Data
    fn build_content_info(&self, spc_content: &[u8]) -> SigningResult<Vec<u8>> {
        let mut content_body = Vec::new();

        // contentType OID: SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)
        content_body.push(0x06); // OBJECT IDENTIFIER
        content_body.push(0x0a); // Length
        content_body
            .extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04]);

        // encapContentInfo.content [0] EXPLICIT containing raw SpcIndirectDataContent
        // The eContent should contain the raw ASN.1 structure, not wrapped in OCTET STRING
        content_body.push(0xA0); // [0] EXPLICIT
        content_body.extend_from_slice(&self.encode_length_bytes(spc_content.len()));
        content_body.extend_from_slice(spc_content);

        // Now build the complete ContentInfo with correct minimal DER length
        let mut content_info = Vec::new();
        content_info.push(0x30); // SEQUENCE
        content_info.extend_from_slice(&self.encode_length_bytes(content_body.len()));
        content_info.extend_from_slice(&content_body);

        Ok(content_info)
    }

    /// Build certificates [0] IMPLICIT
    ///
    /// Includes the signing certificate and any additional certificates
    /// (e.g., intermediate CAs) configured via `with_additional_certs()`.
    fn build_certificates(&self) -> SigningResult<Vec<u8>> {
        let mut field = Vec::new();

        // Calculate total length of all certificates
        let mut total_len = self.certificate_der.len();
        for cert in &self.additional_certs {
            total_len += cert.len();
        }

        // certificates [0] IMPLICIT ExtendedCertificatesAndCertificates
        // IMPLICIT tagging means we DO NOT include the SET tag (0x31); content is the concatenation
        // of Certificate DER encodings.
        field.push(0xA0); // [0] IMPLICIT, constructed

        // Encode length of all certificates
        field.extend_from_slice(&self.encode_length_bytes(total_len));

        // Append end-entity cert first
        field.extend_from_slice(&self.certificate_der);

        // Append additional certificates (intermediates, etc.)
        for cert in &self.additional_certs {
            field.extend_from_slice(cert);
        }

        Ok(field)
    }

    /// Build issuerAndSerialNumber from certificate
    fn build_issuer_and_serial_number(&self) -> SigningResult<Vec<u8>> {
        // Parse certificate to extract issuer and serial number
        let cert = X509::from_der(&self.certificate_der).map_err(|e| {
            SigningError::CertificateError(format!("Failed to parse certificate: {e}"))
        })?;

        // Issuer (X509 Name) DER as produced by OpenSSL
        let issuer_der = cert.issuer_name().to_der().map_err(|e| {
            SigningError::CertificateError(format!("Failed to get issuer DER: {e}"))
        })?;

        // Serial number as ASN.1 INTEGER DER: big-endian, minimal, prepend 0x00 if high bit set
        let serial_bn = cert.serial_number().to_bn().map_err(|e| {
            SigningError::CertificateError(format!("Failed to get serial number: {e}"))
        })?;
        let mut serial_bytes = serial_bn.to_vec();
        if serial_bytes.is_empty() {
            serial_bytes.push(0);
        }
        if serial_bytes[0] & 0x80 != 0 {
            // Prepend 0x00 to keep it positive in two's complement
            serial_bytes.insert(0, 0x00);
        }
        let mut serial_der = Vec::new();
        serial_der.push(0x02); // INTEGER
        serial_der.extend_from_slice(&self.encode_length_bytes(serial_bytes.len()));
        serial_der.extend_from_slice(&serial_bytes);

        // Build IssuerAndSerialNumber SEQUENCE
        let mut issuer_serial = Vec::new();
        issuer_serial.push(0x30); // SEQUENCE

        // Content = issuer Name (DER) + serialNumber (DER)
        let content_len = issuer_der.len() + serial_der.len();
        let length_bytes = self.encode_length_bytes(content_len);
        issuer_serial.extend_from_slice(&length_bytes);
        issuer_serial.extend_from_slice(&issuer_der);
        issuer_serial.extend_from_slice(&serial_der);

        Ok(issuer_serial)
    }

    /// Build digest algorithm identifier
    /// Include NULL parameters for SHA-2 algorithms per RFC 3370 requirement
    fn build_digest_algorithm_identifier(&self) -> SigningResult<Vec<u8>> {
        let mut alg = vec![
            0x30, // SEQUENCE
            0x0d, // Length (13 bytes) - includes NULL parameters per RFC 3370
            0x06, // OBJECT IDENTIFIER
            0x09, // Length
        ];

        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                alg.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
                // SHA-256
            }
            HashAlgorithm::Sha384 => {
                alg.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
                // SHA-384
            }
            HashAlgorithm::Sha512 => {
                alg.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
                // SHA-512
            }
        }

        // Add NULL parameters per RFC 3370 requirement
        alg.extend_from_slice(constants::ASN1_NULL); // NULL

        Ok(alg)
    }

    /// Build signature algorithm identifier (ECDSA with SHA)
    fn build_signature_algorithm_identifier(&self) -> SigningResult<Vec<u8>> {
        let mut alg = vec![
            0x30, // SEQUENCE
            0x0a, // Length (10 bytes) - NO NULL parameters per ECDSA specification
            0x06, // OBJECT IDENTIFIER
            0x08, // Length
        ];

        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                alg.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
                // ecdsa-with-SHA256
            }
            HashAlgorithm::Sha384 => {
                alg.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
                // ecdsa-with-SHA384
            }
            HashAlgorithm::Sha512 => {
                alg.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);
                // ecdsa-with-SHA512
            }
        }

        // DO NOT add NULL parameters for ECDSA signature algorithms per RFC 3279
        // alg.extend_from_slice(&[0x05, 0x00]); // NULL

        Ok(alg)
    }

    /// Build `SignerInfo` with pre-encoded [0] IMPLICIT attributes (fixes cryptographic mismatch)
    fn build_signer_info_fixed_attrs(
        &self,
        a0_implicit_attrs: &[u8], // Pre-encoded [0] IMPLICIT DER
        signature: &[u8],
    ) -> SigningResult<Vec<u8>> {
        log::info!(
            "🔧 PKCS7: build_signer_info_fixed_attrs called with signature length: {}",
            signature.len()
        );
        // Build SignerInfo content (without the outer SEQUENCE header)
        let mut si_content = Vec::new();

        // version INTEGER (1) — must be inside the SignerInfo SEQUENCE
        si_content.push(0x02); // INTEGER
        si_content.push(0x01); // Length
        si_content.push(0x01); // Version 1

        // issuerAndSerialNumber
        let issuer_and_serial = self.build_issuer_and_serial_number()?;
        si_content.extend_from_slice(&issuer_and_serial);

        // digestAlgorithm
        let digest_alg = self.build_digest_algorithm_identifier()?;
        si_content.extend_from_slice(&digest_alg);

        // authenticatedAttributes [0] IMPLICIT - use pre-encoded data directly
        log::debug!(
            "Adding pre-encoded [0] IMPLICIT attributes: {} bytes",
            a0_implicit_attrs.len()
        );
        si_content.extend_from_slice(a0_implicit_attrs);

        // digestEncryptionAlgorithm (signature algorithm)
        let sig_alg = self.build_signature_algorithm_identifier()?;
        si_content.extend_from_slice(&sig_alg);

        // encryptedDigest (signature) as OCTET STRING
        let clean_sig = Self::sanitize_ecdsa_signature(signature)?;
        log::info!(
            "🔧 PKCS7: Encoding encryptedDigest as OCTET STRING (0x04), sig_in={} -> sig_out={} bytes",
            signature.len(),
            clean_sig.len()
        );
        si_content.push(0x04); // OCTET STRING
        si_content.extend_from_slice(&self.encode_length_bytes(clean_sig.len()));
        si_content.extend_from_slice(&clean_sig);

        // Wrap content in SEQUENCE with minimal DER length
        let mut si_seq = Vec::new();
        si_seq.push(0x30); // SEQUENCE
        si_seq.extend_from_slice(&self.encode_length_bytes(si_content.len()));
        si_seq.extend_from_slice(&si_content);

        // Wrap SignerInfo SEQUENCE in signerInfos SET
        let mut signer_infos = Vec::new();
        signer_infos.push(0x31); // SET
        signer_infos.extend_from_slice(&self.encode_length_bytes(si_seq.len()));
        signer_infos.extend_from_slice(&si_seq);

        log::debug!(
            "Built SignerInfo with fixed attributes: {} bytes",
            signer_infos.len()
        );
        Ok(signer_infos)
    }

    /// Build `SignerInfo` including unauthenticated attributes [1] IMPLICIT with RFC3161 token
    /// FIXED: This preserves the exact authenticated attributes from the original signature
    fn build_signer_info_fixed_attrs_with_timestamp(
        &self,
        a0_implicit_attrs: &[u8], // Pre-encoded [0] IMPLICIT DER
        signature: &[u8],
        timestamp_token: &[u8],
    ) -> SigningResult<Vec<u8>> {
        log::info!(
            "🔧 FIXED_TIMESTAMP: Preserving original signedAttrs, only adding timestamp attribute"
        );

        // 🔧 FIX: Build the exact same SignerInfo as the non-timestamp version,
        // then append the [1] IMPLICIT unauthenticated attributes

        // First, build the base SignerInfo content (identical to non-timestamp version)
        let mut si_content = Vec::new();

        // version INTEGER (1)
        si_content.push(0x02); // INTEGER
        si_content.push(0x01);
        si_content.push(0x01);

        // issuerAndSerialNumber
        let issuer_and_serial = self.build_issuer_and_serial_number()?;
        si_content.extend_from_slice(&issuer_and_serial);

        // digestAlgorithm
        let digest_alg = self.build_digest_algorithm_identifier()?;
        si_content.extend_from_slice(&digest_alg);

        // authenticatedAttributes [0] IMPLICIT - use EXACT same bytes as non-timestamp version
        log::debug!(
            "🔧 FIXED_TIMESTAMP: Using IDENTICAL authenticated attributes: {} bytes",
            a0_implicit_attrs.len()
        );
        si_content.extend_from_slice(a0_implicit_attrs);

        // digestEncryptionAlgorithm (signature algorithm)
        let sig_alg = self.build_signature_algorithm_identifier()?;
        si_content.extend_from_slice(&sig_alg);

        // encryptedDigest (signature) as OCTET STRING - use EXACT same signature
        let clean_sig = Self::sanitize_ecdsa_signature(signature)?;
        log::debug!(
            "🔧 FIXED_TIMESTAMP: Using IDENTICAL signature: {} bytes",
            clean_sig.len()
        );
        si_content.push(0x04); // OCTET STRING
        si_content.extend_from_slice(&self.encode_length_bytes(clean_sig.len()));
        si_content.extend_from_slice(&clean_sig);

        // 🔧 NEW: Add unauthenticatedAttributes [1] IMPLICIT with timestamp
        let ts_attr = Self::build_rfc3161_timestamp_attribute(timestamp_token);

        // Wrap timestamp attribute in [1] IMPLICIT SET for unauthenticatedAttributes
        // ASN.1: [1] IMPLICIT SET OF Attribute
        si_content.push(constants::UNSIGNED_ATTRS_CONTEXT_TAG);
        si_content.extend_from_slice(&self.encode_length_bytes(ts_attr.len()));
        si_content.extend_from_slice(&ts_attr);

        log::debug!(
            "🔧 FIXED_TIMESTAMP: Added [1] IMPLICIT unauthenticated attributes: {} bytes total",
            2 + self.encode_length_bytes(ts_attr.len()).len() + ts_attr.len()
        );

        // Wrap content in SEQUENCE with minimal DER length
        let mut si_seq = Vec::new();
        si_seq.push(0x30); // SEQUENCE
        si_seq.extend_from_slice(&self.encode_length_bytes(si_content.len()));
        si_seq.extend_from_slice(&si_content);

        // Wrap SignerInfo SEQUENCE in signerInfos SET
        let mut signer_infos = Vec::new();
        signer_infos.push(0x31); // SET
        signer_infos.extend_from_slice(&self.encode_length_bytes(si_seq.len()));
        signer_infos.extend_from_slice(&si_seq);

        log::debug!(
            "🔧 FIXED_TIMESTAMP: Built SignerInfo with preserved signedAttrs + timestamp: {} bytes",
            signer_infos.len()
        );
        Ok(signer_infos)
    }

    /// Build a single RFC3161 timestamp Attribute SEQUENCE as used by Authenticode
    /// OID: 1.3.6.1.4.1.311.3.3.1, value: SET { `TimeStampToken` as `ContentInfo` }
    ///
    /// Note: Per Microsoft specification analysis, the `TimeStampToken` should be embedded
    /// directly in the SET, not wrapped in an OCTET STRING. This matches the Microsoft
    /// specification where the timestamp attribute value is the `TimeStampToken` itself.
    fn build_rfc3161_timestamp_attribute(timestamp_token: &[u8]) -> Vec<u8> {
        // Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF AttributeValue }
        let mut attr = Vec::new();
        // We'll assemble the body first to compute SEQUENCE length
        let mut body = Vec::new();

        // OID (1.3.6.1.4.1.311.3.3.1)
        body.push(0x06); // OBJECT IDENTIFIER
        body.push(0x0a); // length 10
        body.extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01]);

        // SET { TimeStampToken (ContentInfo SEQUENCE) }
        // RFC 3161 Analysis: TimeStampToken is already a DER-encoded ContentInfo (SEQUENCE)
        // Microsoft spec requires direct inclusion in the SET as ASN.1 SEQUENCE, not wrapped in OCTET STRING
        // This follows the X509_ATTRIBUTE structure where value is the raw TimeStampToken
        let mut set_content = Vec::new();
        set_content.extend_from_slice(timestamp_token); // Direct inclusion, no OCTET STRING wrapper

        body.push(0x31); // SET
        if set_content.len() < 128 {
            body.push(set_content.len() as u8);
        } else if set_content.len() < 256 {
            body.push(0x81);
            body.push(set_content.len() as u8);
        } else {
            body.push(0x82);
            body.push(((set_content.len() >> 8) & 0xFF) as u8);
            body.push((set_content.len() & 0xFF) as u8);
        }
        body.extend_from_slice(&set_content);

        // Now SEQUENCE wrapper
        attr.push(0x30); // SEQUENCE
        if body.len() < 128 {
            attr.push(body.len() as u8);
        } else {
            attr.push(0x82);
            attr.push(((body.len() >> 8) & 0xFF) as u8);
            attr.push((body.len() & 0xFF) as u8);
        }
        attr.extend_from_slice(&body);

        attr
    }

    /// Ensure ECDSA signature is DER-encoded SEQUENCE(INTEGER r, INTEGER s) with exact length.
    /// - If input starts with 0x30, treat as DER and trim any trailing bytes beyond declared length.
    /// - If input length equals 64/96 (P-256/P-384 raw r||s), convert to DER.
    fn sanitize_ecdsa_signature(sig: &[u8]) -> SigningResult<Vec<u8>> {
        if sig.is_empty() {
            return Err(SigningError::Pkcs7Error(
                "Empty signature bytes".to_string(),
            ));
        }
        // DER path
        if sig[0] == 0x30 {
            // Parse and canonicalize r and s INTEGERs to ensure minimal DER encoding
            if sig.len() < 2 {
                return Err(SigningError::Pkcs7Error(
                    "Truncated DER signature".to_string(),
                ));
            }
            let (seq_hdr_len, seq_len) = match sig[1] {
                l @ 0x00..=0x7F => (2usize, l as usize),
                0x81 => {
                    if sig.len() < 3 {
                        return Err(SigningError::Pkcs7Error(
                            "Truncated DER length (0x81)".to_string(),
                        ));
                    }
                    (3usize, sig[2] as usize)
                }
                0x82 => {
                    if sig.len() < 4 {
                        return Err(SigningError::Pkcs7Error(
                            "Truncated DER length (0x82)".to_string(),
                        ));
                    }
                    (4usize, ((sig[2] as usize) << 8) | (sig[3] as usize))
                }
                _ => {
                    return Err(SigningError::Pkcs7Error(format!(
                        "Unsupported DER length form: 0x{:02X}",
                        sig[1]
                    )));
                }
            };
            let total = seq_hdr_len + seq_len;
            if total > sig.len() {
                return Err(SigningError::Pkcs7Error(format!(
                    "DER signature shorter than declared: {} < {}",
                    sig.len(),
                    total
                )));
            }

            // Now parse the two INTEGERs
            let mut p = seq_hdr_len; // start of content
            if p + 2 > total || sig[p] != 0x02 {
                return Err(SigningError::Pkcs7Error(
                    "DER signature: expected INTEGER for r".to_string(),
                ));
            }
            let r_len = match sig[p + 1] {
                l @ 0x00..=0x7F => {
                    let l = l as usize;
                    p += 2;
                    l
                }
                0x81 => {
                    if p + 3 > total {
                        return Err(SigningError::Pkcs7Error(
                            "DER signature: truncated r length (0x81)".to_string(),
                        ));
                    }
                    let l = sig[p + 2] as usize;
                    p += 3;
                    l
                }
                0x82 => {
                    if p + 4 > total {
                        return Err(SigningError::Pkcs7Error(
                            "DER signature: truncated r length (0x82)".to_string(),
                        ));
                    }
                    let l = ((sig[p + 2] as usize) << 8) | (sig[p + 3] as usize);
                    p += 4;
                    l
                }
                other => {
                    return Err(SigningError::Pkcs7Error(format!(
                        "DER signature: unsupported r length form 0x{other:02X}"
                    )));
                }
            };
            if p + r_len > total {
                return Err(SigningError::Pkcs7Error(
                    "DER signature: r overruns sequence".to_string(),
                ));
            }
            let r_bytes = &sig[p..p + r_len];
            p += r_len;

            if p + 2 > total || sig[p] != 0x02 {
                return Err(SigningError::Pkcs7Error(
                    "DER signature: expected INTEGER for s".to_string(),
                ));
            }
            let s_len = match sig[p + 1] {
                l @ 0x00..=0x7F => {
                    let l = l as usize;
                    p += 2;
                    l
                }
                0x81 => {
                    if p + 3 > total {
                        return Err(SigningError::Pkcs7Error(
                            "DER signature: truncated s length (0x81)".to_string(),
                        ));
                    }
                    let l = sig[p + 2] as usize;
                    p += 3;
                    l
                }
                0x82 => {
                    if p + 4 > total {
                        return Err(SigningError::Pkcs7Error(
                            "DER signature: truncated s length (0x82)".to_string(),
                        ));
                    }
                    let l = ((sig[p + 2] as usize) << 8) | (sig[p + 3] as usize);
                    p += 4;
                    l
                }
                other => {
                    return Err(SigningError::Pkcs7Error(format!(
                        "DER signature: unsupported s length form 0x{other:02X}"
                    )));
                }
            };
            if p + s_len > total {
                return Err(SigningError::Pkcs7Error(
                    "DER signature: s overruns sequence".to_string(),
                ));
            }
            let s_bytes = &sig[p..p + s_len];

            // Re-encode r and s with minimal DER INTEGER encoding
            let r_der = Self::encode_der_integer(r_bytes);
            let s_der = Self::encode_der_integer(s_bytes);
            let content_len = r_der.len() + s_der.len();
            let mut out = Vec::with_capacity(2 + content_len + 3);
            out.push(0x30);
            if content_len < 128 {
                out.push(content_len as u8);
            } else if content_len < 256 {
                out.push(0x81);
                out.push(content_len as u8);
            } else {
                out.push(0x82);
                out.push(((content_len >> 8) & 0xFF) as u8);
                out.push((content_len & 0xFF) as u8);
            }
            out.extend_from_slice(&r_der);
            out.extend_from_slice(&s_der);
            Ok(out)
        } else {
            // Possibly raw r||s (fixed width). Convert to DER.
            let half = sig.len() / 2;
            if sig.len() != 64 && sig.len() != 96 && sig.len() != 132 {
                return Err(SigningError::Pkcs7Error(format!(
                    "Unexpected ECDSA signature length {}; not DER and not raw r||s",
                    sig.len()
                )));
            }
            let (r_raw, s_raw) = sig.split_at(half);
            let r = Self::encode_der_integer(r_raw);
            let s = Self::encode_der_integer(s_raw);
            let content_len = r.len() + s.len();
            let mut out = Vec::with_capacity(2 + content_len + 3);
            out.push(0x30);
            if content_len < 128 {
                out.push(content_len as u8);
            } else if content_len < 256 {
                out.push(0x81);
                out.push(content_len as u8);
            } else {
                out.push(0x82);
                out.push(((content_len >> 8) & 0xFF) as u8);
                out.push((content_len & 0xFF) as u8);
            }
            out.extend_from_slice(&r);
            out.extend_from_slice(&s);
            Ok(out)
        }
    }

    /// Encode a big-endian unsigned integer as DER INTEGER with conservative padding.
    /// Uses RFC 3280 compliant encoding approach for non-negative integers.
    fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
        // Strip leading zeros
        let mut i = 0;
        while i < bytes.len() && bytes[i] == 0 {
            i += 1;
        }
        let mut v = if i == bytes.len() {
            vec![0]
        } else {
            bytes[i..].to_vec()
        };

        // DER rule: if the high bit is set, prepend 0x00 to keep INTEGER positive.
        // Previous heuristic skipped padding for some ECDSA sizes causing a 1-byte shorter signature.
        if !v.is_empty() && (v[0] & 0x80) != 0 {
            v.insert(0, 0x00);
            log::debug!(
                "DER_INTEGER: added leading 0x00 sign padding (len now {})",
                v.len()
            );
        }

        let mut out = Vec::with_capacity(2 + v.len());
        out.push(0x02); // INTEGER
        if v.len() < 128 {
            out.push(v.len() as u8);
        } else {
            out.push(0x81);
            out.push(v.len() as u8);
        }
        out.extend_from_slice(&v);
        out
    }

    /// Compute total length (header + content) of a DER-encoded SEQUENCE at data[0].
    /// Returns an error if data is too short or not a SEQUENCE or if length is inconsistent.
    fn der_total_length(data: &[u8]) -> SigningResult<usize> {
        if data.len() < 2 {
            return Err(SigningError::Pkcs7Error(
                "DER too short for top-level SEQUENCE".to_string(),
            ));
        }
        if data[0] != 0x30 {
            return Err(SigningError::Pkcs7Error(format!(
                "Expected SEQUENCE (0x30) at start, got 0x{:02X}",
                data[0]
            )));
        }
        let (hdr_len, declared_len) = match data[1] {
            l @ 0x00..=0x7F => (2usize, l as usize),
            0x81 => {
                if data.len() < 3 {
                    return Err(SigningError::Pkcs7Error(
                        "DER length uses 0x81 but missing byte".to_string(),
                    ));
                }
                (3usize, data[2] as usize)
            }
            0x82 => {
                if data.len() < 4 {
                    return Err(SigningError::Pkcs7Error(
                        "DER length uses 0x82 but missing bytes".to_string(),
                    ));
                }
                (4usize, ((data[2] as usize) << 8) | (data[3] as usize))
            }
            0x83 => {
                if data.len() < 5 {
                    return Err(SigningError::Pkcs7Error(
                        "DER length uses 0x83 but missing bytes".to_string(),
                    ));
                }
                (
                    5usize,
                    ((data[2] as usize) << 16) | ((data[3] as usize) << 8) | (data[4] as usize),
                )
            }
            other => {
                return Err(SigningError::Pkcs7Error(format!(
                    "Unsupported DER length form: 0x{other:02X}"
                )));
            }
        };
        let total = hdr_len + declared_len;
        if total > data.len() {
            return Err(SigningError::Pkcs7Error(format!(
                "DER declared length {} exceeds available {}",
                total,
                data.len()
            )));
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_builder_creation() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // Dummy certificate DER
        let builder = AuthenticodeBuilder::new(cert_der.clone(), HashAlgorithm::Sha384);
        assert_eq!(builder.certificate_der, cert_der);
        assert_eq!(builder.hash_algorithm, HashAlgorithm::Sha384);
    }

    #[test]
    fn test_length_encoding() {
        let builder = AuthenticodeBuilder::new(vec![], HashAlgorithm::Sha256);

        // Short form
        assert_eq!(builder.encode_length_bytes(127), vec![127]);

        // Long form 1 byte
        assert_eq!(builder.encode_length_bytes(128), vec![0x81, 128]);
        assert_eq!(builder.encode_length_bytes(255), vec![0x81, 255]);

        // Long form 2 bytes
        assert_eq!(builder.encode_length_bytes(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(builder.encode_length_bytes(65535), vec![0x82, 0xFF, 0xFF]);

        // Long form 3 bytes
        assert_eq!(
            builder.encode_length_bytes(65536),
            vec![0x83, 0x01, 0x00, 0x00]
        );
    }
}
