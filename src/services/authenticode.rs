//! OpenSSL-based Authenticode PKCS#7 implementation.
//!
//! Provides core cryptographic operations for Authenticode signing including:
//! - PE hash computation using canonical Authenticode algorithm
//! - SPC (Software Publisher Certificate) indirect data structure creation
//! - PKCS#7 signed data assembly with proper authenticated attributes
//! - `YubiKey` hardware integration for signature generation
//!
//! This module serves as the foundational cryptographic layer for the signing pipeline.

use crate::domain::constants;
use crate::domain::pe::{self as pe, PeInfo};
use crate::domain::spc;
use crate::infra::error::{SigningError, SigningResult};
use crate::services::PeSignatureEmbedderService; // embedder integration
use crate::HashAlgorithm;
use openssl::asn1::Asn1Object;
use openssl::x509::X509;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Context for remote signing that preserves authenticated attributes.
///
/// This struct holds all the data computed during `compute_tbs_hash_with_context()`
/// that needs to be reused when calling `create_signed_pe_with_context()`.
/// This ensures the signingTime and other attributes are identical between
/// hash computation and signature embedding.
#[derive(Clone)]
pub struct TbsContext {
    /// The hash that needs to be signed (hash of authenticated attributes SET).
    pub tbs_hash: Vec<u8>,
    /// The PE hash.
    pe_hash: Vec<u8>,
    /// The SPC indirect data content (DER-encoded).
    spc_content: Vec<u8>,
    /// The authenticated attributes for embedding ([0] IMPLICIT tagged).
    a0_der: Vec<u8>,
}

impl TbsContext {
    /// Get the TBS hash that should be sent to the remote signer.
    #[must_use]
    pub fn tbs_hash(&self) -> &[u8] {
        &self.tbs_hash
    }
}

/// OpenSSL-based Authenticode signer implementation
pub struct OpenSslAuthenticodeSigner {
    certificate: X509,
    additional_certs: Vec<Vec<u8>>,
    hash_algorithm: HashAlgorithm,
}

impl OpenSslAuthenticodeSigner {
    /// Create new OpenSSL-based Authenticode signer
    pub fn new(cert_der: &[u8], requested_hash_algorithm: HashAlgorithm) -> SigningResult<Self> {
        let certificate = X509::from_der(cert_der).map_err(|e| {
            SigningError::CertificateError(format!("Failed to parse certificate: {e}"))
        })?;

        // Auto-detect appropriate hash algorithm based on certificate key curve
        let hash_algorithm = Self::select_hash_for_cert(&certificate, requested_hash_algorithm)?;

        log::info!(
            "Created OpenSSL-based Authenticode signer with hash algorithm: {hash_algorithm:?}"
        );
        Ok(Self {
            certificate,
            additional_certs: Vec::new(),
            hash_algorithm,
        })
    }

    /// Set additional certificates to include in the signature.
    ///
    /// These certificates (typically intermediate CAs) will be embedded in the
    /// PKCS#7 `SignedData` certificates field alongside the signing certificate.
    /// This enables Windows to build the full certificate chain without needing
    /// to fetch intermediates from the network or local stores.
    ///
    /// # Arguments
    /// * `certs` - Vector of DER-encoded certificate bytes
    #[must_use]
    pub fn with_additional_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.additional_certs = certs;
        self
    }

    /// Get the additional certificates configured for this signer.
    #[must_use]
    pub fn additional_certs(&self) -> &[Vec<u8>] {
        &self.additional_certs
    }

    /// Get the hash algorithm selected for this signer
    #[must_use]
    pub fn get_hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Select appropriate hash algorithm based on certificate key type and user preference
    fn select_hash_for_cert(cert: &X509, requested: HashAlgorithm) -> SigningResult<HashAlgorithm> {
        // Get the public key from the certificate
        let pub_key = cert.public_key().map_err(|e| {
            SigningError::CertificateError(format!("Failed to get public key: {e}"))
        })?;

        // Check if it's an EC key and get the curve
        if let Ok(ec_key) = pub_key.ec_key() {
            let group = ec_key.group();
            let curve_name = group.curve_name();

            match curve_name {
                Some(openssl::nid::Nid::SECP384R1) => {
                    log::info!(
                        "Detected P-384 certificate, using requested hash algorithm: {requested:?} (NIST P-384 standard)"
                    );
                    Ok(requested)
                }
                Some(openssl::nid::Nid::X9_62_PRIME256V1) => {
                    log::info!(
                        "Detected P-256 certificate, using requested hash algorithm: {requested:?}"
                    );
                    Ok(requested)
                }
                _ => {
                    log::info!("Unknown EC curve, using requested hash algorithm: {requested:?}");
                    Ok(requested)
                }
            }
        } else {
            log::info!("Non-EC certificate, using requested hash algorithm: {requested:?}");
            Ok(requested)
        }
    }

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

    pub fn compute_pe_hash(&self, pe_data: &[u8]) -> SigningResult<Vec<u8>> {
        let pe_raw = crate::domain::pe::PeRaw::parse(pe_data)
            .map_err(|e| SigningError::PeParsingError(format!("{e}")))?;
        let view = crate::domain::pe::PeHashView::from_raw(&pe_raw);
        self.compute_pe_hash_view(&view)
    }

    /// Compute the "to-be-signed" hash for remote signing.
    ///
    /// This is the hash of the authenticated attributes SET, which is what
    /// actually gets signed in Authenticode. This is NOT the PE hash.
    ///
    /// The workflow for remote signing is:
    /// 1. Call `compute_tbs_hash()` to get the hash that needs to be signed
    /// 2. Send this hash to the remote `YubiKey` proxy for signing
    /// 3. Use the returned signature with `create_signed_pe_with_raw_signature()`
    ///
    /// # Arguments
    /// * `pe_data` - The original PE file bytes
    ///
    /// # Returns
    /// The hash of the authenticated attributes SET (the "to-be-signed" data)
    ///
    /// # Errors
    /// Returns error if PE parsing or hash computation fails.
    #[deprecated(
        since = "0.5.1",
        note = "Use compute_tbs_hash_with_context() for remote signing to ensure consistent signingTime"
    )]
    pub fn compute_tbs_hash(&self, pe_data: &[u8]) -> SigningResult<Vec<u8>> {
        Ok(self.compute_tbs_hash_with_context(pe_data)?.tbs_hash)
    }

    /// Compute the "to-be-signed" hash and context for remote signing.
    ///
    /// This method returns both the hash and a context object that must be
    /// passed to `create_signed_pe_with_context()` to ensure the authenticated
    /// attributes (including signingTime) are identical between hash computation
    /// and signature embedding.
    ///
    /// # Arguments
    /// * `pe_data` - The original PE file bytes
    ///
    /// # Returns
    /// A `TbsContext` containing the hash and all data needed for embedding
    ///
    /// # Errors
    /// Returns error if PE parsing or hash computation fails.
    pub fn compute_tbs_hash_with_context(&self, pe_data: &[u8]) -> SigningResult<TbsContext> {
        let pe_hash = self.compute_pe_hash(pe_data)?;
        let spc_content_domain = self.build_spc_indirect_data(&pe_hash)?;
        let spc_content = spc_content_domain.as_der();
        let authenticated_attrs =
            self.create_authenticated_attributes(&pe_hash, spc_content, None, pe_data)?;
        let (set_der, a0_der) = self.build_tbs_and_embedding_data(&authenticated_attrs)?;
        let tbs_hash = self.hash_data(&set_der)?;
        log::debug!(
            "Computed TBS hash: {} bytes (PE hash was {} bytes)",
            tbs_hash.len(),
            pe_hash.len()
        );
        Ok(TbsContext {
            tbs_hash,
            pe_hash,
            spc_content: spc_content.to_vec(),
            a0_der,
        })
    }

    fn build_spc_indirect_data(&self, pe_hash: &[u8]) -> SigningResult<crate::SpcIndirectData> {
        let builder = crate::services::SpcBuilderService::new(self.hash_algorithm);
        builder.build(pe_hash, |h| self.create_spc_content(h))
    }

    pub(crate) fn compute_pe_hash_view(
        &self,
        view: &crate::domain::pe::PeHashView,
    ) -> SigningResult<Vec<u8>> {
        log::debug!("Computing Authenticode hash via PeHashView");
        let pe_info = pe::parse_pe(view.as_bytes())?;
        let mut hasher = self.create_hasher();
        self.hash_pe_file_for_spc_creation(&mut hasher, view.as_bytes(), &pe_info)?;
        let hash = hasher.finalize().clone();
        log::debug!("Computed PE hash: {} bytes", hash.len());
        Ok(hash)
    }

    /// Creates a test signer with a self-signed certificate for testing purposes.
    ///
    /// This generates a test RSA key pair and self-signed certificate,
    /// suitable for testing the signing pipeline without requiring a real `YubiKey`
    /// or production certificate.
    ///
    /// # Arguments
    /// * `algo` - The hash algorithm to configure for this test signer
    ///
    /// # Returns
    /// A configured `OpenSslAuthenticodeSigner` with a test certificate
    pub fn new_placeholder_for_hash(algo: HashAlgorithm) -> SigningResult<Self> {
        use openssl::{bn::BigNum, pkey::PKey, rsa::Rsa, x509::X509Builder, x509::X509NameBuilder};
        let rsa = Rsa::generate(2048)
            .map_err(|e| SigningError::CertificateError(format!("RSA gen failed: {e}")))?;
        let pkey = PKey::from_rsa(rsa)
            .map_err(|e| SigningError::CertificateError(format!("PKey failed: {e}")))?;
        let mut name = X509NameBuilder::new()
            .map_err(|e| SigningError::CertificateError(format!("Name builder: {e}")))?;
        name.append_entry_by_text("CN", "Test Certificate")
            .map_err(|e| SigningError::CertificateError(format!("Name entry: {e}")))?;
        let name = name.build();
        let mut builder = X509Builder::new()
            .map_err(|e| SigningError::CertificateError(format!("X509 builder: {e}")))?;
        builder
            .set_version(2)
            .map_err(|e| SigningError::CertificateError(format!("Set version: {e}")))?;
        let serial = BigNum::from_u32(1)
            .map_err(|e| SigningError::CertificateError(format!("BigNum from_u32: {e}")))?;
        let serial = serial
            .to_asn1_integer()
            .map_err(|e| SigningError::CertificateError(format!("ASN1 int: {e}")))?;
        builder
            .set_serial_number(&serial)
            .map_err(|e| SigningError::CertificateError(format!("Set serial: {e}")))?;
        builder
            .set_subject_name(&name)
            .map_err(|e| SigningError::CertificateError(format!("Set subj: {e}")))?;
        builder
            .set_issuer_name(&name)
            .map_err(|e| SigningError::CertificateError(format!("Set issuer: {e}")))?;
        use openssl::asn1::Asn1Time;
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| SigningError::CertificateError(format!("not_before: {e}")))?;
        let not_after = Asn1Time::days_from_now(1)
            .map_err(|e| SigningError::CertificateError(format!("not_after: {e}")))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| SigningError::CertificateError(format!("Set not_before: {e}")))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| SigningError::CertificateError(format!("Set not_after: {e}")))?;
        builder
            .set_pubkey(&pkey)
            .map_err(|e| SigningError::CertificateError(format!("Set pubkey: {e}")))?;
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .map_err(|e| SigningError::CertificateError(format!("Sign test cert: {e}")))?;
        let certificate = builder.build();
        Ok(Self {
            certificate,
            additional_certs: Vec::new(),
            hash_algorithm: algo,
        })
    }

    pub fn create_signed_pe_openssl(
        &self,
        original_pe: &[u8],
        mut signature_callback: impl FnMut(&[u8]) -> SigningResult<Vec<u8>>,
        timestamp_token: Option<&[u8]>,
        embed_certificate: bool,
    ) -> SigningResult<Vec<u8>> {
        let _pe_info = pe::parse_pe(original_pe)?;
        let pe_hash = self.compute_pe_hash(original_pe)?;
        let spc_content_domain = self.build_spc_indirect_data(&pe_hash)?;
        let spc_content = spc_content_domain.as_der();
        let pkcs7_der = self.create_pkcs7_with_timestamp(
            &pe_hash,
            spc_content,
            &mut signature_callback,
            timestamp_token,
            embed_certificate,
            original_pe,
        )?;
        let pkcs7_domain = crate::services::Pkcs7BuilderService::new(
            self.certificate.to_der().unwrap_or_default(),
            self.hash_algorithm,
            embed_certificate,
        )
        .wrap(pkcs7_der.clone())?;
        let unsigned = crate::domain::pe::UnsignedPeFile::new(original_pe.to_vec())?;
        let embedder = PeSignatureEmbedderService::new();
        let signed_pe_domain = embedder.embed(&unsigned, &pkcs7_domain, &pe_hash)?;
        Ok(signed_pe_domain.into_bytes())
    }

    pub fn create_signature_bytes_only(
        &self,
        original_pe: &[u8],
        mut signature_callback: impl FnMut(&[u8]) -> SigningResult<Vec<u8>>,
    ) -> SigningResult<Vec<u8>> {
        let pe_hash = self.compute_pe_hash(original_pe)?;
        let spc_content_domain = self.build_spc_indirect_data(&pe_hash)?;
        let spc_content = spc_content_domain.as_der();
        let authenticated_attrs =
            self.create_authenticated_attributes(&pe_hash, spc_content, None, original_pe)?;
        let (set_der, _a0_der) = self.build_tbs_and_embedding_data(&authenticated_attrs)?;
        let tbs_hash = self.hash_data(&set_der)?;
        let signature_bytes = signature_callback(&tbs_hash)?;
        Ok(signature_bytes)
    }

    /// Create a signed PE file using a pre-computed raw signature.
    ///
    /// This method is used for remote signing where the signature is computed
    /// on a different machine (via yubikey-proxy) and sent back.
    ///
    /// # Arguments
    /// * `original_pe` - The original PE file bytes
    /// * `raw_signature` - The raw signature bytes from the remote signer
    /// * `timestamp_token` - Optional timestamp token
    ///
    /// # Returns
    /// The signed PE file bytes
    ///
    /// # Errors
    /// Returns error if PKCS7 assembly or PE embedding fails.
    #[deprecated(
        since = "0.5.1",
        note = "Use create_signed_pe_with_context() for remote signing to ensure consistent signingTime"
    )]
    pub fn create_signed_pe_with_raw_signature(
        &self,
        original_pe: &[u8],
        raw_signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<Vec<u8>> {
        // This regenerates authenticated attributes, which causes signingTime mismatch!
        // Use create_signed_pe_with_context() instead.
        let _pe_info = pe::parse_pe(original_pe)?;
        let pe_hash = self.compute_pe_hash(original_pe)?;
        let spc_content_domain = self.build_spc_indirect_data(&pe_hash)?;
        let spc_content = spc_content_domain.as_der();

        // Build authenticated attributes
        let authenticated_attrs = self.create_authenticated_attributes(
            &pe_hash,
            spc_content,
            timestamp_token,
            original_pe,
        )?;
        let (_set_der, a0_der) = self.build_tbs_and_embedding_data(&authenticated_attrs)?;

        self.build_signed_pe_internal(
            original_pe,
            &pe_hash,
            spc_content,
            &a0_der,
            raw_signature,
            timestamp_token,
        )
    }

    /// Create a signed PE file using a pre-computed context and raw signature.
    ///
    /// This method uses the context from `compute_tbs_hash_with_context()` to ensure
    /// the authenticated attributes (including signingTime) are identical to those
    /// that were hashed and signed.
    ///
    /// # Arguments
    /// * `original_pe` - The original PE file bytes
    /// * `context` - The TBS context from `compute_tbs_hash_with_context()`
    /// * `raw_signature` - The raw signature bytes from the remote signer
    /// * `timestamp_token` - Optional timestamp token
    ///
    /// # Returns
    /// The signed PE file bytes
    ///
    /// # Errors
    /// Returns error if PKCS7 assembly or PE embedding fails.
    pub fn create_signed_pe_with_context(
        &self,
        original_pe: &[u8],
        context: &TbsContext,
        raw_signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<Vec<u8>> {
        self.build_signed_pe_internal(
            original_pe,
            &context.pe_hash,
            &context.spc_content,
            &context.a0_der,
            raw_signature,
            timestamp_token,
        )
    }

    /// Internal method to build the signed PE with provided components.
    fn build_signed_pe_internal(
        &self,
        original_pe: &[u8],
        pe_hash: &[u8],
        spc_content: &[u8],
        a0_der: &[u8],
        raw_signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<Vec<u8>> {
        // Build PKCS7 with the provided raw signature
        let cert_der = self.certificate.to_der().map_err(|e| {
            SigningError::CryptographicError(format!("Failed to get cert DER: {e}"))
        })?;
        let pkcs7_service = crate::services::Pkcs7BuilderService::new(
            cert_der,
            self.hash_algorithm,
            true, // embed_certificate
        )
        .with_additional_certs(self.additional_certs.clone());

        let pkcs7_der = pkcs7_service
            .build_signed_with_timestamp(spc_content, a0_der, raw_signature, timestamp_token)?
            .as_der()
            .to_vec();
        let pkcs7_trimmed = Self::trim_top_level_der(&pkcs7_der)?;

        // Wrap for domain layer
        let pkcs7_domain = crate::services::Pkcs7BuilderService::new(
            self.certificate.to_der().unwrap_or_default(),
            self.hash_algorithm,
            true,
        )
        .wrap(pkcs7_trimmed.clone())?;

        // Embed signature in PE
        let unsigned = crate::domain::pe::UnsignedPeFile::new(original_pe.to_vec())?;
        let embedder = PeSignatureEmbedderService::new();
        let signed_pe_domain = embedder.embed(&unsigned, &pkcs7_domain, pe_hash)?;
        Ok(signed_pe_domain.into_bytes())
    }

    fn create_pkcs7_with_timestamp(
        &self,
        pe_hash: &[u8],
        spc_content: &[u8],
        mut signature_callback: impl FnMut(&[u8]) -> SigningResult<Vec<u8>>,
        timestamp_token: Option<&[u8]>,
        embed_certificate: bool,
        original_pe: &[u8],
    ) -> SigningResult<Vec<u8>> {
        let cert_der = self.certificate.to_der().map_err(|e| {
            SigningError::CryptographicError(format!("Failed to get cert DER: {e}"))
        })?;
        let pkcs7_service = crate::services::Pkcs7BuilderService::new(
            cert_der,
            self.hash_algorithm,
            embed_certificate,
        )
        .with_additional_certs(self.additional_certs.clone());
        let authenticated_attrs = self.create_authenticated_attributes(
            pe_hash,
            spc_content,
            timestamp_token,
            original_pe,
        )?;
        let (set_der, a0_der) = self.build_tbs_and_embedding_data(&authenticated_attrs)?;
        let tbs_hash = self.hash_data(&set_der)?;
        let yubikey_signature = signature_callback(&tbs_hash)?;
        self.export_signature_components_for_debugging(
            pe_hash,
            spc_content,
            &authenticated_attrs,
            &set_der,
            &tbs_hash,
            &yubikey_signature,
        )?;
        let pkcs7_der = pkcs7_service
            .build_signed_with_timestamp(spc_content, &a0_der, &yubikey_signature, timestamp_token)?
            .as_der()
            .to_vec();
        Self::trim_top_level_der(&pkcs7_der)
    }

    pub fn build_pkcs7_from_components(
        &self,
        spc_content: &[u8],
        a0_implicit_attrs: &[u8],
        signature: &[u8],
        timestamp_token: Option<&[u8]>,
        embed_certificate: bool,
    ) -> SigningResult<Vec<u8>> {
        let cert_der = self.certificate.to_der().map_err(|e| {
            SigningError::CryptographicError(format!("Failed to get cert DER: {e}"))
        })?;
        let pkcs7_service = crate::services::Pkcs7BuilderService::new(
            cert_der,
            self.hash_algorithm,
            embed_certificate,
        )
        .with_additional_certs(self.additional_certs.clone());
        let pkcs7 = pkcs7_service
            .build_signed_with_timestamp(
                spc_content,
                a0_implicit_attrs,
                signature,
                timestamp_token,
            )?
            .as_der()
            .to_vec();
        let der = Self::trim_top_level_der(&pkcs7)?;
        let _pkcs7_domain = crate::services::Pkcs7BuilderService::new(
            vec![0x30, 0x00],
            self.hash_algorithm,
            embed_certificate,
        )
        .wrap(der.clone())?;
        Ok(der)
    }

    pub fn create_authenticated_attributes(
        &self,
        pe_hash: &[u8],
        spc_content: &[u8],
        _timestamp_token: Option<&[u8]>,
        _pe_data: &[u8],
    ) -> SigningResult<Vec<(String, Vec<u8>)>> {
        let mut attrs_unsorted: Vec<(String, Vec<u8>)> = Vec::new();
        let content_type_attr =
            self.encode_attr_content_type(&self.encode_oid(spc::SPC_INDIRECT_DATA_OBJID)?)?;
        attrs_unsorted.push(("contentType".to_string(), content_type_attr));
        let message_digest_hash =
            if let Some(spc_contents) = self.strip_outer_sequence_header(spc_content) {
                let mut hasher = self.create_hasher();
                hasher.update(spc_contents);
                let hash_result = hasher.finalize();
                hash_result.clone()
            } else {
                pe_hash.to_vec()
            };
        let message_digest_attr = self.encode_attr_message_digest(&message_digest_hash)?;
        attrs_unsorted.push(("messageDigest".to_string(), message_digest_attr));
        let signing_time_attr = self.encode_attr_signing_time(&self.encode_signing_time()?)?;
        attrs_unsorted.push(("signingTime".to_string(), signing_time_attr));
        let statement_type_attr = self.encode_attr_statement_type(&spc::PURPOSE_IND)?;
        attrs_unsorted.push(("spcStatementType".to_string(), statement_type_attr));
        let mut attrs_with_complete_der: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
        for (name, attr_value) in &attrs_unsorted {
            let mut complete_attr = Vec::new();
            complete_attr.push(0x30);
            let length_bytes = if attr_value.len() < 128 {
                vec![attr_value.len() as u8]
            } else if attr_value.len() < 256 {
                vec![0x81, attr_value.len() as u8]
            } else {
                vec![
                    0x82,
                    (attr_value.len() >> 8) as u8,
                    (attr_value.len() & 0xFF) as u8,
                ]
            };
            complete_attr.extend_from_slice(&length_bytes);
            complete_attr.extend_from_slice(attr_value);
            attrs_with_complete_der.push((name.clone(), attr_value.clone(), complete_attr));
        }
        let builder = crate::services::SignedAttributesBuilder::new();
        let logical: Vec<crate::domain::pkcs7::SignedAttributeLogical> = attrs_with_complete_der
            .iter()
            .map(
                |(name, _value, complete)| crate::domain::pkcs7::SignedAttributeLogical {
                    oid: name.clone(),
                    der: complete.clone(),
                },
            )
            .collect();
        let canonical = builder.canonicalize(logical);
        let sorted_attrs: Vec<(String, Vec<u8>)> = canonical
            .ordered()
            .iter()
            .map(|sa| {
                let (name, value, _) = attrs_with_complete_der
                    .iter()
                    .find(|(_, _, complete)| *complete == sa.der)
                    .expect("Canonical attribute must match original");
                (name.clone(), value.clone())
            })
            .collect();
        Ok(sorted_attrs)
    }

    pub fn build_tbs_and_embedding_data(
        &self,
        authenticated_attrs: &[(String, Vec<u8>)],
    ) -> SigningResult<(Vec<u8>, Vec<u8>)> {
        let mut total_len = 0;
        for (_, attr_data) in authenticated_attrs {
            total_len += attr_data.len();
        }
        let mut set_der = Vec::new();
        set_der.push(0x31);
        if total_len < 128 {
            set_der.push(total_len as u8);
        } else if total_len < 256 {
            set_der.push(0x81);
            set_der.push(total_len as u8);
        } else {
            set_der.push(0x82);
            set_der.push((total_len >> 8) as u8);
            set_der.push((total_len & 0xFF) as u8);
        }
        for (_, attr_data) in authenticated_attrs {
            set_der.extend_from_slice(attr_data);
        }
        let mut a0_der = Vec::new();
        a0_der.push(0xa0);
        if total_len < 128 {
            a0_der.push(total_len as u8);
        } else if total_len < 256 {
            a0_der.push(0x81);
            a0_der.push(total_len as u8);
        } else {
            a0_der.push(0x82);
            a0_der.push((total_len >> 8) as u8);
            a0_der.push((total_len & 0xFF) as u8);
        }
        for (_, attr_data) in authenticated_attrs {
            a0_der.extend_from_slice(attr_data);
        }
        if a0_der.len() < 2 {
            return Err(SigningError::CryptographicError(
                "Invalid a0_der length".to_string(),
            ));
        }
        let mut reconstructed_set = Vec::new();
        reconstructed_set.push(0x31);
        reconstructed_set.extend_from_slice(&a0_der[1..]);
        if reconstructed_set != set_der {
            return Err(SigningError::CryptographicError(
                "SET DER and [0] IMPLICIT DER content mismatch".to_string(),
            ));
        }
        Ok((set_der, a0_der))
    }

    fn encode_oid(&self, oid_str: &str) -> SigningResult<Vec<u8>> {
        let oid_obj = Asn1Object::from_str(oid_str)
            .map_err(|e| SigningError::CryptographicError(format!("Invalid OID {oid_str}: {e}")))?;
        Ok(oid_obj.as_slice().to_vec())
    }
    fn encode_signing_time(&self) -> SigningResult<Vec<u8>> {
        let mut time_der = Vec::new();
        time_der.push(0x17);
        time_der.push(0x0d);
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
        time_der.extend_from_slice(time_str.as_bytes());
        Ok(time_der)
    }
    fn hash_data(&self, data: &[u8]) -> SigningResult<Vec<u8>> {
        let hash = match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                Digest::update(&mut hasher, data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                Digest::update(&mut hasher, data);
                hasher.finalize().to_vec()
            }
        };
        Ok(hash)
    }
    fn encode_attr_content_type(&self, oid_der: &[u8]) -> SigningResult<Vec<u8>> {
        let mut attr = Vec::new();
        attr.push(0x30);
        let oid_part = 11;
        let complete_oid_len = 1 + self.encode_length(oid_der.len()).len() + oid_der.len();
        let set_len = 1 + self.encode_length(complete_oid_len).len() + complete_oid_len;
        let content_len = oid_part + set_len;
        let length_bytes = self.encode_length(content_len);
        attr.extend_from_slice(&length_bytes);
        attr.push(0x06);
        attr.push(0x09);
        attr.extend_from_slice(constants::PKCS9_CONTENT_TYPE_OID);
        attr.push(0x31);
        let set_length_bytes = self.encode_length(complete_oid_len);
        attr.extend_from_slice(&set_length_bytes);
        attr.push(0x06);
        let oid_length_bytes = self.encode_length(oid_der.len());
        attr.extend_from_slice(&oid_length_bytes);
        attr.extend_from_slice(oid_der);
        Ok(attr)
    }
    fn encode_attr_signing_time(&self, time_der: &[u8]) -> SigningResult<Vec<u8>> {
        let mut attr = Vec::new();
        attr.push(0x30);
        let oid_part = 11;
        let set_header_len = 1 + self.encode_length(time_der.len()).len();
        let content_len = oid_part + set_header_len + time_der.len();
        let length_bytes = self.encode_length(content_len);
        attr.extend_from_slice(&length_bytes);
        attr.push(0x06);
        attr.push(0x09);
        attr.extend_from_slice(constants::PKCS9_SIGNING_TIME_OID);
        attr.push(0x31);
        let set_length_bytes = self.encode_length(time_der.len());
        attr.extend_from_slice(&set_length_bytes);
        attr.extend_from_slice(time_der);
        Ok(attr)
    }
    fn encode_attr_message_digest(&self, digest: &[u8]) -> SigningResult<Vec<u8>> {
        let mut attr = Vec::new();
        attr.push(0x30);
        let oid_part = 11;
        let octet_string_len = 1 + self.encode_length(digest.len()).len() + digest.len();
        let set_len = 1 + self.encode_length(octet_string_len).len() + octet_string_len;
        let content_len = oid_part + set_len;
        let length_bytes = self.encode_length(content_len);
        attr.extend_from_slice(&length_bytes);
        attr.push(0x06);
        attr.push(0x09);
        attr.extend_from_slice(constants::PKCS9_MESSAGE_DIGEST_OID);
        attr.push(0x31);
        let set_length_bytes = self.encode_length(octet_string_len);
        attr.extend_from_slice(&set_length_bytes);
        attr.push(0x04);
        let octet_length_bytes = self.encode_length(digest.len());
        attr.extend_from_slice(&octet_length_bytes);
        attr.extend_from_slice(digest);
        Ok(attr)
    }
    pub fn create_spc_content(&self, pe_hash: &[u8]) -> SigningResult<Vec<u8>> {
        let mut spc_attribute = Vec::new();
        spc_attribute.push(0x06);
        spc_attribute.push(0x0a);
        spc_attribute
            .extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f]);
        let mut spc_pe_image_data = vec![0x03, 0x02, 0x07, 0x80];
        let spc_string = vec![
            0x80, 0x1c, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62, 0x00, 0x73, 0x00,
            0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00,
            0x3e, 0x00,
        ];
        let mut spc_link = vec![0xa2, 0x1e];
        spc_link.extend_from_slice(&spc_string);
        let mut spc_link_wrapper = vec![0xa0, 0x20];
        spc_link_wrapper.extend_from_slice(&spc_link);
        spc_pe_image_data.extend_from_slice(&spc_link_wrapper);
        let mut spc_pe_data_complete = Vec::new();
        spc_pe_data_complete.push(0x30);
        let spc_pe_length_bytes = self.encode_length(spc_pe_image_data.len());
        spc_pe_data_complete.extend_from_slice(&spc_pe_length_bytes);
        spc_pe_data_complete.extend_from_slice(&spc_pe_image_data);
        spc_attribute.extend_from_slice(&spc_pe_data_complete);
        let mut spc_attribute_complete = Vec::new();
        spc_attribute_complete.push(0x30);
        let spc_attr_length_bytes = self.encode_length(spc_attribute.len());
        spc_attribute_complete.extend_from_slice(&spc_attr_length_bytes);
        spc_attribute_complete.extend_from_slice(&spc_attribute);
        let mut digest_info = vec![0x30, 0x0d, 0x06, 0x09];
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => digest_info
                .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
            HashAlgorithm::Sha384 => digest_info
                .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
            HashAlgorithm::Sha512 => digest_info
                .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
        }
        digest_info.push(0x05);
        digest_info.push(0x00);
        digest_info.push(0x04);
        let hash_length_bytes = self.encode_length(pe_hash.len());
        digest_info.extend_from_slice(&hash_length_bytes);
        digest_info.extend_from_slice(pe_hash);
        let mut digest_info_complete = Vec::new();
        digest_info_complete.push(0x30);
        let digest_length_bytes = self.encode_length(digest_info.len());
        digest_info_complete.extend_from_slice(&digest_length_bytes);
        digest_info_complete.extend_from_slice(&digest_info);
        let mut content = Vec::new();
        content.push(0x30);
        let total_length = spc_attribute_complete.len() + digest_info_complete.len();
        let total_length_bytes = self.encode_length(total_length);
        content.extend_from_slice(&total_length_bytes);
        content.extend_from_slice(&spc_attribute_complete);
        content.extend_from_slice(&digest_info_complete);
        Ok(content)
    }
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
    fn encode_attr_statement_type(&self, purpose: &[u8]) -> SigningResult<Vec<u8>> {
        let mut attr = Vec::new();
        attr.push(0x30);
        let oid_part = 12;
        let set_len = 1 + self.encode_length(purpose.len()).len() + purpose.len();
        let content_len = oid_part + set_len;
        let length_bytes = self.encode_length(content_len);
        attr.extend_from_slice(&length_bytes);
        attr.push(0x06);
        attr.push(0x0a);
        attr.extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b]);
        attr.push(0x31);
        let set_length_bytes = self.encode_length(purpose.len());
        attr.extend_from_slice(&set_length_bytes);
        attr.extend_from_slice(purpose);
        Ok(attr)
    }
    fn create_hasher(&self) -> Box<dyn DynDigest> {
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => Box::new(Sha256::new()),
            HashAlgorithm::Sha384 => Box::new(Sha384::new()),
            HashAlgorithm::Sha512 => Box::new(Sha512::new()),
        }
    }
    /// Hash a PE file for Authenticode SPC indirect data content.
    ///
    /// Authenticode hashing follows specific rules:
    /// - Skip the checksum field (4 bytes at header + 88)
    /// - Skip the certificate table directory entry (8 bytes at header + 152 or +168 for PE32+)
    /// - For signed files: skip the certificate table bytes themselves
    /// - For unsigned files: hash up to end-of-image and pad with zeros to 8-byte boundary
    ///
    /// **Important for overlay-bearing files** (e.g., `WiX` Burn bundles):
    /// The Authenticode hash covers only the PE image proper, not the overlay.
    /// The end-of-image is defined as the maximum of (`SizeOfHeaders`, `section_end`) for all sections.
    ///
    /// # Parameters
    /// - `hasher`: A mutable boxed hasher to accumulate the hash.
    /// - `pe_data`: The full PE file bytes (may include overlay).
    /// - `pe_info`: Parsed PE information (currently unused but reserved for future).
    ///
    /// # Errors
    /// Returns an error if the PE structure is malformed or too small.
    fn hash_pe_file_for_spc_creation(
        &self,
        hasher: &mut Box<dyn DynDigest>,
        pe_data: &[u8],
        pe_info: &PeInfo,
    ) -> SigningResult<()> {
        if pe_data.len() < 64 {
            return Err(SigningError::PeParsingError("File too small for PE".into()));
        }
        let header_size =
            u32::from_le_bytes([pe_data[60], pe_data[61], pe_data[62], pe_data[63]]) as usize;
        if header_size + 24 >= pe_data.len() || &pe_data[header_size..header_size + 4] != b"PE\0\0"
        {
            return Err(SigningError::PeParsingError("Invalid PE signature".into()));
        }
        let magic = u16::from_le_bytes([pe_data[header_size + 24], pe_data[header_size + 24 + 1]]);
        let pe32plus = usize::from(magic == 0x20B);
        let cert_table_offset = header_size + 152 + pe32plus * 16;
        let file_len = pe_data.len();
        let (sigpos, siglen) = if cert_table_offset + 8 <= pe_data.len() {
            let rva = u32::from_le_bytes([
                pe_data[cert_table_offset],
                pe_data[cert_table_offset + 1],
                pe_data[cert_table_offset + 2],
                pe_data[cert_table_offset + 3],
            ]) as usize;
            let size = u32::from_le_bytes([
                pe_data[cert_table_offset + 4],
                pe_data[cert_table_offset + 5],
                pe_data[cert_table_offset + 6],
                pe_data[cert_table_offset + 7],
            ]) as usize;
            if rva > 0 && size > 0 && rva < file_len && rva + size <= file_len {
                (rva, size)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        // NOTE: The reference implementation hashes the full file for unsigned files,
        // INCLUDING any overlay data. The overlay is NOT excluded from the hash.
        // This is because Windows verifies by hashing from 0 to sigpos (the signature offset),
        // and for unsigned files, the signature will be appended at EOF (after the overlay).
        let _ = pe_info;

        log::debug!(
            "PE hash params: file_len={file_len}, sigpos={sigpos}, siglen={siglen}, pe32plus={pe32plus}"
        );

        let mut idx = 0;
        let range1_end = header_size + 88;
        hasher.update(&pe_data[idx..range1_end]);
        idx = range1_end + 4;
        let range2_len = 60 + pe32plus * 16;
        let range2_end = idx + range2_len;
        hasher.update(&pe_data[idx..range2_end]);
        idx = range2_end + 8;

        // For unsigned files: hash up to EOF (file_len), including any overlay.
        // For signed files: hash up to sigpos, skip certificate table.
        // The hash_end is always file_len because:
        // - Unsigned files: we hash the full file including overlay
        // - Signed files: we hash up to sigpos, then skip signature, then continue to EOF
        let hash_end = file_len;
        log::debug!("PE hash: hash_end={hash_end}, idx={idx}");

        let mut cursor = idx;
        if sigpos > 0 {
            let sigend = sigpos.saturating_add(siglen);
            if sigend <= file_len {
                if cursor < sigpos {
                    hasher.update(&pe_data[cursor..sigpos]);
                }
                cursor = sigend;
            }
        }
        if cursor < hash_end {
            hasher.update(&pe_data[cursor..hash_end]);
        }

        // Pad unsigned files to 8-byte boundary, but ONLY if the file has no overlay.
        //
        // Per Authenticode spec, unsigned PE files are padded to 8-byte boundary before
        // the signature is appended. The hash must match what Windows will compute over
        // the signed file content [0..sigpos].
        //
        // The padding applies to ALL unsigned files, including those with overlays.
        // The embedder will add padding after the overlay but before the signature.
        // Windows requires the WIN_CERTIFICATE to start at an 8-byte aligned offset,
        // so both the embedder and the hash must account for this padding.
        if sigpos == 0 {
            let pad_len = (8 - (file_len % 8)) % 8;
            if pad_len > 0 {
                log::debug!("Adding {pad_len} bytes of padding to hash (file_len={file_len})");
                hasher.update(&vec![0u8; pad_len]);
            }
        }
        Ok(())
    }

    /// Compute the end-of-image offset (start of overlay, if any).
    ///
    /// The end-of-image is defined as the maximum of:
    /// - `SizeOfHeaders` from the optional header
    /// - `PointerToRawData + SizeOfRawData` for each section
    ///
    /// This corresponds to the last byte of actual PE image data before any overlay.
    ///
    /// # Parameters
    /// - `pe_data`: The full PE file bytes.
    /// - `_pe_info`: Parsed PE info (sections available via goblin).
    ///
    /// # Returns
    /// The file offset where the PE image ends (and overlay begins, if present).
    #[allow(dead_code)]
    fn compute_end_of_image(pe_data: &[u8], _pe_info: &PeInfo) -> usize {
        // Parse sections to find end of raw data. We reparse here since pe_info.pe lifetime
        // is 'static transmuted and we want fresh parsing for safety.
        let Ok(pe) = goblin::pe::PE::parse(pe_data) else {
            log::warn!("Failed to parse PE for overlay detection, using file length");
            return pe_data.len();
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

        // Fallback for minimal/test PEs
        if end == 0 {
            log::warn!("PE has no sections or headers, using file length for hash boundary");
            return pe_data.len();
        }

        end.min(pe_data.len())
    }
    fn export_signature_components_for_debugging(
        &self,
        pe_hash: &[u8],
        spc_content: &[u8],
        authenticated_attrs: &[(String, Vec<u8>)],
        set_der: &[u8],
        tbs_hash: &[u8],
        yubikey_signature: &[u8],
    ) -> SigningResult<()> {
        use std::fs;
        let temp_dir = std::path::Path::new("temp");
        if !temp_dir.exists() {
            fs::create_dir_all(temp_dir).map_err(|e| {
                SigningError::Pkcs7Error(format!("Failed to create temp directory: {e}"))
            })?;
        }
        fs::write("temp/our_pe_hash.bin", pe_hash)
            .map_err(|e| SigningError::Pkcs7Error(format!("Failed to write PE hash: {e}")))?;
        fs::write("temp/our_spc_content.der", spc_content)
            .map_err(|e| SigningError::Pkcs7Error(format!("Failed to write SPC content: {e}")))?;
        fs::write("temp/our_set_der.bin", set_der)
            .map_err(|e| SigningError::Pkcs7Error(format!("Failed to write SET DER: {e}")))?;
        fs::write("temp/our_tbs_hash.bin", tbs_hash)
            .map_err(|e| SigningError::Pkcs7Error(format!("Failed to write TBS hash: {e}")))?;
        fs::write("temp/our_yubikey_signature.bin", yubikey_signature).map_err(|e| {
            SigningError::Pkcs7Error(format!("Failed to write YubiKey signature: {e}"))
        })?;
        let cert_der = self.certificate.to_der().map_err(|e| {
            SigningError::CryptographicError(format!("Failed to get cert DER: {e}"))
        })?;
        fs::write("temp/our_certificate.der", &cert_der)
            .map_err(|e| SigningError::Pkcs7Error(format!("Failed to write certificate: {e}")))?;
        let mut all_attrs = Vec::new();
        for (name, data) in authenticated_attrs {
            all_attrs.extend_from_slice(data);
            fs::write(format!("temp/our_attr_{name}.der"), data).map_err(|e| {
                SigningError::Pkcs7Error(format!("Failed to write attribute {name}: {e}"))
            })?;
        }
        fs::write("temp/our_all_attrs.der", &all_attrs).map_err(|e| {
            SigningError::Pkcs7Error(format!("Failed to write all attributes: {e}"))
        })?;
        Ok(())
    }
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
                "DER declared length {} exceeds available {}",
                total,
                data.len()
            )));
        }
        if total == data.len() {
            return Ok(data.to_vec());
        }
        Ok(data[..total].to_vec())
    }
}

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

pub fn create_digest_info(hash: &[u8], hash_algorithm: HashAlgorithm) -> SigningResult<Vec<u8>> {
    use der::{asn1::ObjectIdentifier, Encode};
    use spki::AlgorithmIdentifier;
    let algorithm_id = match hash_algorithm {
        HashAlgorithm::Sha256 => ObjectIdentifier::new("2.16.840.1.101.3.4.2.1")
            .map_err(|e| SigningError::CryptographicError(format!("Invalid SHA-256 OID: {e}")))?,
        HashAlgorithm::Sha384 => ObjectIdentifier::new("2.16.840.1.101.3.4.2.2")
            .map_err(|e| SigningError::CryptographicError(format!("Invalid SHA-384 OID: {e}")))?,
        HashAlgorithm::Sha512 => ObjectIdentifier::new("2.16.840.1.101.3.4.2.3")
            .map_err(|e| SigningError::CryptographicError(format!("Invalid SHA-512 OID: {e}")))?,
    };
    let mut digest_info = Vec::new();
    digest_info.push(0x30);
    let alg_id_bytes = AlgorithmIdentifier::<der::asn1::AnyRef> {
        oid: algorithm_id,
        parameters: None,
    }
    .to_der()
    .map_err(|e| SigningError::CryptographicError(format!("Failed to encode algorithm ID: {e}")))?;
    let hash_octet_string = der::asn1::OctetString::new(hash)
        .map_err(|e| {
            SigningError::CryptographicError(format!("Failed to create octet string: {e}"))
        })?
        .to_der()
        .map_err(|e| {
            SigningError::CryptographicError(format!("Failed to encode octet string: {e}"))
        })?;
    let total_len = alg_id_bytes.len() + hash_octet_string.len();
    if total_len < 128 {
        digest_info.push(total_len as u8);
    } else {
        let len_bytes = total_len.to_be_bytes();
        let mut start_idx = 0;
        while start_idx < len_bytes.len() && len_bytes[start_idx] == 0 {
            start_idx += 1;
        }
        digest_info.push(0x80 | (len_bytes.len() - start_idx) as u8);
        digest_info.extend_from_slice(&len_bytes[start_idx..]);
    }
    digest_info.extend_from_slice(&alg_id_bytes);
    digest_info.extend_from_slice(&hash_octet_string);
    Ok(digest_info)
}
pub fn create_digest_info_from_digest(
    digest: &crate::domain::crypto::DigestBytes,
) -> SigningResult<Vec<u8>> {
    create_digest_info(digest.as_slice(), digest.algorithm())
}
