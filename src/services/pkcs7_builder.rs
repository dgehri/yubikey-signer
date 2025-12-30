//! PKCS#7 builder service with inline component assembly.
//! Implements PKCS#7 `SignedData` construction for Authenticode signatures.
//!
//! Assembles the final CMS container that includes certificates, signed attributes,
//! and signature data. Some DER assembly logic adapted from `pkcs7.rs`.
//! NEXT(phase6): Replace manual DER concatenation with structured DER writers & remove duplication.

use crate::{
    domain::{
        constants,
        pkcs7::{Pkcs7ContentInfoSpc, Pkcs7DigestAlgorithms, Pkcs7SignedData, Pkcs7SignerInfos},
    },
    services::pkcs7::AuthenticodeBuilder,
    HashAlgorithm, SigningError, SigningResult,
};

pub struct Pkcs7BuilderService {
    cert_der: Vec<u8>,
    additional_certs: Vec<Vec<u8>>,
    hash_algorithm: HashAlgorithm,
    embed_certificate: bool,
}

impl Pkcs7BuilderService {
    /// create service from raw certificate DER & chosen hash algorithm.
    #[must_use]
    pub fn new(cert_der: Vec<u8>, hash_algorithm: HashAlgorithm, embed_certificate: bool) -> Self {
        Self {
            cert_der,
            additional_certs: Vec::new(),
            hash_algorithm,
            embed_certificate,
        }
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

    /// Build full PKCS#7 without timestamp using pre-encoded signed attributes + signature.
    /// This implements the `SignedData` assembly logic
    /// with fixed authenticated attributes for consistency.
    pub fn build_signed(
        &self,
        spc_content: &[u8],
        a0_implicit_attrs: &[u8],
        signature: &[u8],
    ) -> SigningResult<Pkcs7SignedData> {
        // version INTEGER (1)
        let mut signed_data_content = Vec::new();
        signed_data_content.extend_from_slice(constants::PKCS7_VERSION_1);

        // digestAlgorithms
        signed_data_content.extend_from_slice(self.build_digest_algorithms_component()?.as_der());

        // encapContentInfo
        signed_data_content.extend_from_slice(self.build_content_info_spc(spc_content)?.as_der());

        // certificates [0] IMPLICIT (optional)
        if self.embed_certificate {
            signed_data_content.extend_from_slice(&self.build_certificates_component()?);
        }

        // signerInfos
        signed_data_content.extend_from_slice(
            self.build_signer_infos(a0_implicit_attrs, signature)?
                .as_der(),
        );

        // Wrap SignedData content in SEQUENCE
        let mut signed_data_seq = vec![constants::ASN1_SEQUENCE_TAG];
        let len_bytes = self.encode_len(signed_data_content.len());
        signed_data_seq.extend_from_slice(&len_bytes);
        signed_data_seq.extend_from_slice(&signed_data_content);

        // Build outer ContentInfo: OID signedData + [0] EXPLICIT SignedData
        let mut ci_body = Vec::new();
        ci_body.extend_from_slice(constants::PKCS7_SIGNED_DATA_OID_COMPLETE);
        ci_body.push(constants::ASN1_CONTEXT_0_EXPLICIT_TAG); // [0] EXPLICIT
        ci_body.extend_from_slice(&self.encode_len(signed_data_seq.len()));
        ci_body.extend_from_slice(&signed_data_seq);

        // Outer SEQUENCE
        let mut pkcs7 = vec![constants::ASN1_SEQUENCE_TAG];
        pkcs7.extend_from_slice(&self.encode_len(ci_body.len()));
        pkcs7.extend_from_slice(&ci_body);

        Ok(Pkcs7SignedData::from_der(pkcs7))
    }

    /// Build digestAlgorithms (SET of one) component.
    pub fn build_digest_algorithms_component(&self) -> SigningResult<Pkcs7DigestAlgorithms> {
        let mut der = vec![
            constants::ASN1_SET_TAG,
            constants::DIGEST_ALGORITHMS_SET_LENGTH,
            constants::ASN1_SEQUENCE_TAG,
            constants::ALGORITHM_IDENTIFIER_SEQUENCE_LENGTH,
            constants::ASN1_OID_TAG,
            constants::SHA2_ALGORITHM_OID_LENGTH,
        ];
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                der.extend_from_slice(constants::SHA256_ALGORITHM_OID);
            }
            HashAlgorithm::Sha384 => {
                der.extend_from_slice(constants::SHA384_ALGORITHM_OID);
            }
            HashAlgorithm::Sha512 => {
                der.extend_from_slice(constants::SHA512_ALGORITHM_OID);
            }
        }
        der.extend_from_slice(constants::ASN1_NULL);
        Ok(Pkcs7DigestAlgorithms::from_der(der))
    }

    /// Build `ContentInfo` (encapContentInfo) for SPC Indirect Data.
    pub fn build_content_info_spc(&self, spc_content: &[u8]) -> SigningResult<Pkcs7ContentInfoSpc> {
        let mut body = vec![
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04, 0xA0,
        ];
        body.extend_from_slice(&self.encode_len(spc_content.len()));
        body.extend_from_slice(spc_content);
        let mut ci = vec![0x30];
        ci.extend_from_slice(&self.encode_len(body.len()));
        ci.extend_from_slice(&body);
        Ok(Pkcs7ContentInfoSpc::from_der(ci))
    }

    /// Build signerInfos (single `SignerInfo`) from implicit signed attributes + raw signature.
    pub fn build_signer_infos(
        &self,
        a0_implicit_attrs: &[u8],
        signature: &[u8],
    ) -> SigningResult<Pkcs7SignerInfos> {
        fn enc_len(len: usize) -> Vec<u8> {
            if len < 128 {
                vec![len as u8]
            } else if len < 256 {
                vec![0x81, len as u8]
            } else {
                vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
            }
        }
        let cert = openssl::x509::X509::from_der(&self.cert_der).map_err(|e| {
            SigningError::CertificateError(format!("Failed to parse certificate: {e}"))
        })?;
        let issuer_der = cert.issuer_name().to_der().map_err(|e| {
            SigningError::CertificateError(format!("Failed to get issuer DER: {e}"))
        })?;
        let serial_bn = cert.serial_number().to_bn().map_err(|e| {
            SigningError::CertificateError(format!("Failed to get serial number: {e}"))
        })?;
        let mut serial_bytes = serial_bn.to_vec();
        if serial_bytes.is_empty() {
            serial_bytes.push(0);
        }
        if serial_bytes[0] & 0x80 != 0 {
            serial_bytes.insert(0, 0);
        }
        let mut serial_der = vec![0x02];
        serial_der.extend_from_slice(&enc_len(serial_bytes.len()));
        serial_der.extend_from_slice(&serial_bytes);
        let mut issuer_serial = vec![0x30];
        issuer_serial.extend_from_slice(&enc_len(issuer_der.len() + serial_der.len()));
        issuer_serial.extend_from_slice(&issuer_der);
        issuer_serial.extend_from_slice(&serial_der);
        let mut digest_alg = vec![0x30, 0x0d, 0x06, 0x09];
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => digest_alg
                .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
            HashAlgorithm::Sha384 => digest_alg
                .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
            HashAlgorithm::Sha512 => digest_alg
                .extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
        }
        digest_alg.extend_from_slice(&[0x05, 0x00]); // NULL params
        let mut sig_alg = vec![0x30, 0x0a, 0x06, 0x08];
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                sig_alg.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
            }
            HashAlgorithm::Sha384 => {
                sig_alg.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
            }
            HashAlgorithm::Sha512 => {
                sig_alg.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);
            }
        }
        let clean_sig = signature; // assume canonical DER already
        let mut si_content = Vec::new();
        si_content.extend_from_slice(&[0x02, 0x01, 0x01]);
        si_content.extend_from_slice(&issuer_serial);
        si_content.extend_from_slice(&digest_alg);
        si_content.extend_from_slice(a0_implicit_attrs);
        si_content.extend_from_slice(&sig_alg);
        si_content.push(0x04);
        si_content.extend_from_slice(&enc_len(clean_sig.len()));
        si_content.extend_from_slice(clean_sig);
        let mut si_seq = vec![0x30];
        si_seq.extend_from_slice(&enc_len(si_content.len()));
        si_seq.extend_from_slice(&si_content);
        let mut signer_infos = vec![0x31];
        signer_infos.extend_from_slice(&enc_len(si_seq.len()));
        signer_infos.extend_from_slice(&si_seq);
        Ok(Pkcs7SignerInfos::from_der(signer_infos))
    }

    /// Build certificates [0] IMPLICIT block (end-entity + additional certs).
    ///
    /// Includes the signing certificate and any additional certificates
    /// (e.g., intermediate CAs) configured via `with_additional_certs()`.
    pub fn build_certificates_component(&self) -> SigningResult<Vec<u8>> {
        // Calculate total length of all certificates
        let mut total_len = self.cert_der.len();
        for cert in &self.additional_certs {
            total_len += cert.len();
        }

        let mut field = Vec::new();
        field.push(0xA0); // [0] IMPLICIT constructed
        field.extend_from_slice(&self.encode_len(total_len));

        // Add end-entity certificate first
        field.extend_from_slice(&self.cert_der);

        // Add additional certificates (intermediates, etc.)
        for cert in &self.additional_certs {
            field.extend_from_slice(cert);
        }

        Ok(field)
    }

    fn encode_len(&self, len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    /// Build PKCS#7 with optional timestamp token (existing signed attrs preserved).
    pub fn build_signed_with_timestamp(
        &self,
        spc_content: &[u8],
        a0_implicit_attrs: &[u8],
        signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> SigningResult<Pkcs7SignedData> {
        // timestamp path still delegates to authenticode builder.
        if timestamp_token.is_some() {
            let builder = AuthenticodeBuilder::new(self.cert_der.clone(), self.hash_algorithm)
                .with_additional_certs(self.additional_certs.clone());
            let der = builder.build_with_signature_and_timestamp_fixed_attrs(
                spc_content,
                a0_implicit_attrs,
                signature,
                self.embed_certificate,
                timestamp_token,
            )?;
            return Ok(Pkcs7SignedData::from_der(der));
        }
        // Fallback: reuse no-timestamp assembly (defensive)
        self.build_signed(spc_content, a0_implicit_attrs, signature)
    }

    /// Wrap raw DER (used by tests / transitional code paths).
    pub fn wrap(&self, der: Vec<u8>) -> SigningResult<Pkcs7SignedData> {
        if der.is_empty() {
            return Err(SigningError::Pkcs7Error("Empty PKCS#7 blob".into()));
        }
        Ok(Pkcs7SignedData::from_der(der))
    }
}
