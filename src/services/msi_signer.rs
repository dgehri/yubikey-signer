//! MSI file signing service.
//!
//! Provides Authenticode signing for MSI (Windows Installer) files.
//! Uses the same PKCS#7 signature format as PE signing but with
//! MSI-specific hash computation and signature embedding.

use crate::domain::crypto::HashAlgorithm;
use crate::domain::msi::{MsiFile, MsiHashView, SignedMsiFile};
use crate::domain::spc;
use crate::infra::error::{SigningError, SigningResult};
use crate::services::Pkcs7BuilderService;
use openssl::x509::X509;

/// Context for remote MSI signing that preserves authenticated attributes.
///
/// This struct holds all the data computed during `compute_tbs_hash_with_context()`
/// that needs to be reused when calling `create_signed_msi_with_context()`.
#[derive(Clone)]
pub struct MsiTbsContext {
    /// The hash that needs to be signed (hash of authenticated attributes SET).
    pub tbs_hash: Vec<u8>,
    /// The MSI content hash.
    msi_hash: Vec<u8>,
    /// The SPC indirect data content (DER-encoded).
    spc_content: Vec<u8>,
    /// The authenticated attributes for embedding ([0] IMPLICIT tagged).
    a0_der: Vec<u8>,
    /// Optional pre-hash for `MsiDigitalSignatureEx`.
    msi_ex_hash: Option<Vec<u8>>,
}

impl MsiTbsContext {
    /// Get the TBS hash that should be sent to the remote signer.
    #[must_use]
    pub fn tbs_hash(&self) -> &[u8] {
        &self.tbs_hash
    }

    /// Get the MSI content hash.
    #[must_use]
    pub fn msi_hash(&self) -> &[u8] {
        &self.msi_hash
    }
}

/// MSI file signer using Authenticode format.
pub struct MsiSigner {
    certificate: X509,
    hash_algorithm: HashAlgorithm,
    use_msi_digital_signature_ex: bool,
}

impl MsiSigner {
    /// Create a new MSI signer.
    ///
    /// # Arguments
    /// * `cert_der` - Certificate in DER format
    /// * `hash_algorithm` - Hash algorithm to use
    ///
    /// # Errors
    /// Returns error if the certificate cannot be parsed.
    pub fn new(cert_der: &[u8], hash_algorithm: HashAlgorithm) -> SigningResult<Self> {
        let certificate = X509::from_der(cert_der).map_err(|e| {
            SigningError::CertificateError(format!("Failed to parse certificate: {e}"))
        })?;

        log::info!("Created MSI signer with hash algorithm: {hash_algorithm:?}");

        Ok(Self {
            certificate,
            hash_algorithm,
            use_msi_digital_signature_ex: false,
        })
    }

    /// Enable or disable `MsiDigitalSignatureEx` (metadata hashing).
    ///
    /// When enabled, the signature includes a hash of file metadata
    /// in addition to file content, providing stronger integrity guarantees.
    #[must_use]
    pub fn with_extended_signature(mut self, enabled: bool) -> Self {
        self.use_msi_digital_signature_ex = enabled;
        self
    }

    /// Get the configured hash algorithm.
    #[must_use]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Compute the MSI content hash.
    ///
    /// # Arguments
    /// * `msi_data` - The raw MSI file bytes
    ///
    /// # Errors
    /// Returns error if hash computation fails.
    pub fn compute_msi_hash(&self, msi_data: &[u8]) -> SigningResult<Vec<u8>> {
        let view = MsiHashView::new(msi_data);
        view.compute_hash(self.hash_algorithm)
    }

    /// Compute the "to-be-signed" hash and context for remote signing.
    ///
    /// # Arguments
    /// * `msi_data` - The raw MSI file bytes
    ///
    /// # Returns
    /// A context containing the hash and all data needed for embedding.
    ///
    /// # Errors
    /// Returns error if hash computation fails.
    pub fn compute_tbs_hash_with_context(&self, msi_data: &[u8]) -> SigningResult<MsiTbsContext> {
        let view = MsiHashView::new(msi_data);
        let (msi_hash, msi_ex_hash) =
            view.compute_hash_with_ex(self.hash_algorithm, self.use_msi_digital_signature_ex)?;

        log::debug!(
            "Computed MSI hash: {} bytes, extended: {}, hash: {:02x?}",
            msi_hash.len(),
            msi_ex_hash.is_some(),
            &msi_hash
        );

        // Build SPC indirect data
        let spc_content = self.create_spc_content(&msi_hash)?;

        // Build authenticated attributes
        let authenticated_attrs = self.create_authenticated_attributes(&msi_hash, &spc_content)?;
        let (set_der, a0_der) = self.build_tbs_and_embedding_data(&authenticated_attrs)?;

        // Hash the authenticated attributes
        let tbs_hash = self.hash_data(&set_der)?;

        log::debug!(
            "Computed TBS hash for MSI: {} bytes (MSI hash was {} bytes), TBS: {:02x?}",
            tbs_hash.len(),
            msi_hash.len(),
            &tbs_hash
        );
        log::debug!(
            "set_der: {} bytes, first 30: {:02x?}",
            set_der.len(),
            &set_der[..std::cmp::min(set_der.len(), 30)]
        );

        Ok(MsiTbsContext {
            tbs_hash,
            msi_hash,
            spc_content,
            a0_der,
            msi_ex_hash,
        })
    }

    /// Create a signed MSI file using a pre-computed context and raw signature.
    ///
    /// # Arguments
    /// * `msi_data` - The original MSI file bytes
    /// * `context` - The TBS context from `compute_tbs_hash_with_context()`
    /// * `raw_signature` - The raw signature bytes from the signer
    /// * `timestamp_token` - Optional timestamp token
    ///
    /// # Returns
    /// The signed MSI file.
    ///
    /// # Errors
    /// Returns error if PKCS7 assembly or MSI embedding fails.
    pub fn create_signed_msi_with_context(
        &self,
        msi_data: &[u8],
        context: &MsiTbsContext,
        raw_signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<SignedMsiFile> {
        // Build PKCS7 with the signature
        let cert_der = self.certificate.to_der().map_err(|e| {
            SigningError::CryptographicError(format!("Failed to get cert DER: {e}"))
        })?;

        let pkcs7_service = Pkcs7BuilderService::new(
            cert_der,
            self.hash_algorithm,
            true, /* embed_certificate */
        );

        let pkcs7_der = pkcs7_service
            .build_signed_with_timestamp(
                &context.spc_content,
                &context.a0_der,
                raw_signature,
                timestamp_token,
            )?
            .as_der()
            .to_vec();

        // Trim any trailing bytes from PKCS7
        let pkcs7_trimmed = Self::trim_top_level_der(&pkcs7_der)?;

        log::debug!("Built PKCS#7 for MSI: {} bytes", pkcs7_trimmed.len());

        // Embed signature in MSI
        let msi_file = MsiFile::open(msi_data.to_vec())?;
        let signed =
            msi_file.embed_signature_with_ex(&pkcs7_trimmed, context.msi_ex_hash.as_deref())?;

        Ok(signed)
    }

    /// Sign an MSI file using a callback for signature generation.
    ///
    /// # Arguments
    /// * `msi_data` - The raw MSI file bytes
    /// * `signature_callback` - Callback that signs the TBS hash
    /// * `timestamp_token` - Optional timestamp token
    ///
    /// # Returns
    /// The signed MSI file bytes.
    ///
    /// # Errors
    /// Returns error if signing fails.
    pub fn sign_msi(
        &self,
        msi_data: &[u8],
        mut signature_callback: impl FnMut(&[u8]) -> SigningResult<Vec<u8>>,
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<Vec<u8>> {
        let context = self.compute_tbs_hash_with_context(msi_data)?;
        let signature = signature_callback(&context.tbs_hash)?;
        let signed =
            self.create_signed_msi_with_context(msi_data, &context, &signature, timestamp_token)?;
        Ok(signed.into_bytes())
    }

    /// Create SPC indirect data content for MSI.
    fn create_spc_content(&self, msi_hash: &[u8]) -> SigningResult<Vec<u8>> {
        // MSI uses SPC_SIPINFO_OBJID (1.3.6.1.4.1.311.2.1.30) for the data blob type
        // The structure is SpcSipInfo:
        // SpcSipInfo ::= SEQUENCE {
        //    version             INTEGER,
        //    uuid                OCTET STRING,
        //    reserved1           INTEGER,
        //    reserved2           INTEGER,
        //    reserved3           INTEGER,
        //    reserved4           INTEGER,
        //    reserved5           INTEGER
        // }
        let mut content = Vec::new();

        // Build SpcAttributeTypeAndOptionalValue for MSI
        let mut spc_attribute = Vec::new();

        // OID for SPC_SIPINFO_OBJID
        spc_attribute.push(0x06); // OID tag
        spc_attribute.push(0x0a); // length
        spc_attribute
            .extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1e]);

        // SpcSipInfo structure
        let mut spc_sip_info = Vec::new();

        // version: INTEGER 1
        // MSI SpcSipInfo uses version=1.
        spc_sip_info.extend_from_slice(&[0x02, 0x01, 0x01]);

        // uuid: OCTET STRING (MSI GUID: {000C10F1-0000-0000-C000-000000000046})
        // Note: The GUID is stored as bytes, but typically GUIDs are little-endian in Windows structures.
        // However, in ASN.1 it is usually an OCTET STRING.
        // The subagent reported: F1 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46
        // This matches the little-endian representation of the first 3 parts of the GUID.
        spc_sip_info.extend_from_slice(&[
            0x04, 0x10, 0xF1, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x46,
        ]);

        // reserved1-5: INTEGER 0
        for _ in 0..5 {
            spc_sip_info.extend_from_slice(&[0x02, 0x01, 0x00]);
        }

        // Wrap in SEQUENCE
        let mut spc_sip_info_complete = Vec::new();
        spc_sip_info_complete.push(0x30);
        spc_sip_info_complete.extend(self.encode_length(spc_sip_info.len()));
        spc_sip_info_complete.extend_from_slice(&spc_sip_info);

        spc_attribute.extend_from_slice(&spc_sip_info_complete);

        // Wrap SpcAttributeTypeAndOptionalValue in SEQUENCE
        let mut spc_attribute_complete = Vec::new();
        spc_attribute_complete.push(0x30);
        spc_attribute_complete.extend(self.encode_length(spc_attribute.len()));
        spc_attribute_complete.extend_from_slice(&spc_attribute);

        // DigestInfo
        let mut digest_info = vec![0x30, 0x0d, 0x06, 0x09];
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                digest_info
                    .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
            }
            HashAlgorithm::Sha384 => {
                digest_info
                    .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
            }
            HashAlgorithm::Sha512 => {
                digest_info
                    .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
            }
        }
        digest_info.push(0x05); // NULL
        digest_info.push(0x00);
        digest_info.push(0x04); // OCTET STRING
        digest_info.extend(self.encode_length(msi_hash.len()));
        digest_info.extend_from_slice(msi_hash);

        // Wrap DigestInfo in SEQUENCE
        let mut digest_info_complete = Vec::new();
        digest_info_complete.push(0x30);
        digest_info_complete.extend(self.encode_length(digest_info.len()));
        digest_info_complete.extend_from_slice(&digest_info);

        // Final SpcIndirectDataContent SEQUENCE
        content.push(0x30);
        let total_length = spc_attribute_complete.len() + digest_info_complete.len();
        content.extend(self.encode_length(total_length));
        content.extend_from_slice(&spc_attribute_complete);
        content.extend_from_slice(&digest_info_complete);

        Ok(content)
    }

    /// Create authenticated attributes for signing.
    fn create_authenticated_attributes(
        &self,
        _msi_hash: &[u8],
        spc_content: &[u8],
    ) -> SigningResult<Vec<(String, Vec<u8>)>> {
        let mut attrs: Vec<(String, Vec<u8>)> = Vec::new();

        // contentType attribute
        let content_type_oid = self.encode_oid(spc::SPC_INDIRECT_DATA_OBJID)?;
        let content_type_attr = self.encode_attr_content_type(&content_type_oid)?;
        attrs.push(("contentType".to_string(), content_type_attr));

        // messageDigest attribute - hash of SPC content
        let message_digest = if let Some(contents) = self.strip_outer_sequence_header(spc_content) {
            log::debug!(
                "Hashing SPC content for messageDigest: {} bytes: {:02x?}",
                contents.len(),
                &contents[..std::cmp::min(contents.len(), 50)]
            );
            use sha2::Digest;
            match self.hash_algorithm {
                HashAlgorithm::Sha256 => {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(contents);
                    let digest = hasher.finalize().to_vec();
                    log::debug!("messageDigest: {:02x?}", &digest);
                    digest
                }
                HashAlgorithm::Sha384 => {
                    let mut hasher = sha2::Sha384::new();
                    hasher.update(contents);
                    hasher.finalize().to_vec()
                }
                HashAlgorithm::Sha512 => {
                    let mut hasher = sha2::Sha512::new();
                    hasher.update(contents);
                    hasher.finalize().to_vec()
                }
            }
        } else {
            return Err(SigningError::CryptographicError(
                "Failed to extract SPC content for message digest".into(),
            ));
        };
        let message_digest_attr = self.encode_attr_message_digest(&message_digest)?;
        attrs.push(("messageDigest".to_string(), message_digest_attr));

        // signingTime attribute
        let signing_time = self.encode_signing_time()?;
        let signing_time_attr = self.encode_attr_signing_time(&signing_time)?;
        attrs.push(("signingTime".to_string(), signing_time_attr));

        // spcStatementType attribute
        let statement_type_attr = self.encode_attr_statement_type(&spc::PURPOSE_IND)?;
        attrs.push(("spcStatementType".to_string(), statement_type_attr));

        // Sort attributes for canonical encoding
        let mut attrs_with_der: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
        for (name, value) in &attrs {
            let mut complete = Vec::new();
            complete.push(0x30);
            complete.extend(self.encode_length(value.len()));
            complete.extend_from_slice(value);
            attrs_with_der.push((name.clone(), value.clone(), complete));
        }

        // Use the SignedAttributesBuilder for canonical sorting
        let builder = crate::services::SignedAttributesBuilder::new();
        let logical: Vec<crate::domain::pkcs7::SignedAttributeLogical> = attrs_with_der
            .iter()
            .map(
                |(name, _value, complete)| crate::domain::pkcs7::SignedAttributeLogical {
                    oid: name.clone(),
                    der: complete.clone(),
                },
            )
            .collect();

        let canonical = builder.canonicalize(logical);
        let sorted: Vec<(String, Vec<u8>)> = canonical
            .ordered()
            .iter()
            .map(|sa| {
                let (name, value, _) = attrs_with_der
                    .iter()
                    .find(|(_, _, complete)| *complete == sa.der)
                    .expect("Canonical attribute must match");
                (name.clone(), value.clone())
            })
            .collect();

        Ok(sorted)
    }

    /// Build TBS data and embedding data from authenticated attributes.
    fn build_tbs_and_embedding_data(
        &self,
        attrs: &[(String, Vec<u8>)],
    ) -> SigningResult<(Vec<u8>, Vec<u8>)> {
        let mut total_len = 0;
        for (_, attr_data) in attrs {
            total_len += attr_data.len();
        }

        // SET OF for hashing
        let mut set_der = Vec::new();
        set_der.push(0x31);
        set_der.extend(self.encode_length(total_len));
        for (_, attr_data) in attrs {
            set_der.extend_from_slice(attr_data);
        }

        // [0] IMPLICIT for embedding
        let mut a0_der = Vec::new();
        a0_der.push(0xa0);
        a0_der.extend(self.encode_length(total_len));
        for (_, attr_data) in attrs {
            a0_der.extend_from_slice(attr_data);
        }

        Ok((set_der, a0_der))
    }

    /// Hash data using the configured algorithm.
    fn hash_data(&self, data: &[u8]) -> SigningResult<Vec<u8>> {
        use sha2::Digest;
        Ok(match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        })
    }

    /// Encode ASN.1 length.
    fn encode_length(&self, length: usize) -> Vec<u8> {
        if length < 128 {
            vec![length as u8]
        } else if length < 256 {
            vec![0x81, length as u8]
        } else if length < 65536 {
            vec![0x82, (length >> 8) as u8, (length & 0xFF) as u8]
        } else {
            vec![
                0x83,
                (length >> 16) as u8,
                (length >> 8) as u8,
                (length & 0xFF) as u8,
            ]
        }
    }

    /// Encode an OID string to DER.
    fn encode_oid(&self, oid_str: &str) -> SigningResult<Vec<u8>> {
        use openssl::asn1::Asn1Object;
        let oid_obj = Asn1Object::from_str(oid_str)
            .map_err(|e| SigningError::CryptographicError(format!("Invalid OID {oid_str}: {e}")))?;
        Ok(oid_obj.as_slice().to_vec())
    }

    /// Encode signing time as `UTCTime`.
    fn encode_signing_time(&self) -> SigningResult<Vec<u8>> {
        let now = std::time::SystemTime::now();
        let duration = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SigningError::CryptographicError(format!("Time error: {e}")))?;

        let total_seconds = duration.as_secs();
        let days_since_epoch = total_seconds / 86400;
        let mut year = 1970;
        let mut remaining_days = days_since_epoch;

        while remaining_days >= 365 {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }

        let month = ((remaining_days / 30) + 1).min(12);
        let day = ((remaining_days % 30) + 1).min(31);
        let seconds_today = total_seconds % 86400;
        let hour = seconds_today / 3600;
        let minute = (seconds_today % 3600) / 60;
        let second = seconds_today % 60;
        let yy = year % 100;

        let time_str = format!("{yy:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        let mut time_der = Vec::new();
        time_der.push(0x17); // UTCTime tag
        time_der.push(0x0d); // length
        time_der.extend_from_slice(time_str.as_bytes());

        Ok(time_der)
    }

    /// Encode contentType attribute.
    fn encode_attr_content_type(&self, oid_der: &[u8]) -> SigningResult<Vec<u8>> {
        use crate::domain::constants;

        let mut attr = Vec::new();
        attr.push(0x30);

        let oid_part = 11;
        let complete_oid_len = 1 + self.encode_length(oid_der.len()).len() + oid_der.len();
        let set_len = 1 + self.encode_length(complete_oid_len).len() + complete_oid_len;
        let content_len = oid_part + set_len;

        attr.extend(self.encode_length(content_len));
        attr.push(0x06);
        attr.push(0x09);
        attr.extend_from_slice(constants::PKCS9_CONTENT_TYPE_OID);
        attr.push(0x31);
        attr.extend(self.encode_length(complete_oid_len));
        attr.push(0x06);
        attr.extend(self.encode_length(oid_der.len()));
        attr.extend_from_slice(oid_der);

        Ok(attr)
    }

    /// Encode signingTime attribute.
    fn encode_attr_signing_time(&self, time_der: &[u8]) -> SigningResult<Vec<u8>> {
        use crate::domain::constants;

        let mut attr = Vec::new();
        attr.push(0x30);

        let oid_part = 11;
        let set_header_len = 1 + self.encode_length(time_der.len()).len();
        let content_len = oid_part + set_header_len + time_der.len();

        attr.extend(self.encode_length(content_len));
        attr.push(0x06);
        attr.push(0x09);
        attr.extend_from_slice(constants::PKCS9_SIGNING_TIME_OID);
        attr.push(0x31);
        attr.extend(self.encode_length(time_der.len()));
        attr.extend_from_slice(time_der);

        Ok(attr)
    }

    /// Encode messageDigest attribute.
    fn encode_attr_message_digest(&self, digest: &[u8]) -> SigningResult<Vec<u8>> {
        use crate::domain::constants;

        let mut attr = Vec::new();
        attr.push(0x30);

        let oid_part = 11;
        let octet_string_len = 1 + self.encode_length(digest.len()).len() + digest.len();
        let set_len = 1 + self.encode_length(octet_string_len).len() + octet_string_len;
        let content_len = oid_part + set_len;

        attr.extend(self.encode_length(content_len));
        attr.push(0x06);
        attr.push(0x09);
        attr.extend_from_slice(constants::PKCS9_MESSAGE_DIGEST_OID);
        attr.push(0x31);
        attr.extend(self.encode_length(octet_string_len));
        attr.push(0x04);
        attr.extend(self.encode_length(digest.len()));
        attr.extend_from_slice(digest);

        Ok(attr)
    }

    /// Encode spcStatementType attribute.
    fn encode_attr_statement_type(&self, purpose: &[u8]) -> SigningResult<Vec<u8>> {
        let mut attr = Vec::new();
        attr.push(0x30);

        let oid_part = 12;
        let set_len = 1 + self.encode_length(purpose.len()).len() + purpose.len();
        let content_len = oid_part + set_len;

        attr.extend(self.encode_length(content_len));
        attr.push(0x06);
        attr.push(0x0a);
        attr.extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b]);
        attr.push(0x31);
        attr.extend(self.encode_length(purpose.len()));
        attr.extend_from_slice(purpose);

        Ok(attr)
    }

    /// Strip outer SEQUENCE header from DER data.
    fn strip_outer_sequence_header<'a>(&self, der_data: &'a [u8]) -> Option<&'a [u8]> {
        if der_data.len() < 2 || der_data[0] != 0x30 {
            return None;
        }

        let len_byte = der_data[1] as usize;
        let (header_len, content_len) = if (len_byte & 0x80) == 0 {
            (2, len_byte)
        } else {
            let n = len_byte & 0x7f;
            if 2 + n > der_data.len() || n > 4 {
                return None;
            }
            let mut length = 0usize;
            for i in 0..n {
                length = (length << 8) | der_data[2 + i] as usize;
            }
            (2 + n, length)
        };

        if header_len + content_len > der_data.len() {
            return None;
        }

        Some(&der_data[header_len..header_len + content_len])
    }

    /// Trim DER to declared length.
    fn trim_top_level_der(data: &[u8]) -> SigningResult<Vec<u8>> {
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
                "DER declared length {total} exceeds available {}",
                data.len()
            )));
        }

        if total == data.len() {
            return Ok(data.to_vec());
        }

        Ok(data[..total].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cert() -> Vec<u8> {
        // Create a minimal self-signed test certificate
        use openssl::bn::BigNum;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Test Certificate").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();

        use openssl::asn1::Asn1Time;
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();

        builder.build().to_der().unwrap()
    }

    #[test]
    fn test_msi_signer_creation() {
        let cert = create_test_cert();
        let signer = MsiSigner::new(&cert, HashAlgorithm::Sha256);
        assert!(signer.is_ok());
    }
}
