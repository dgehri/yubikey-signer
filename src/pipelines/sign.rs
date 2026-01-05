//! `SignWorkflow` orchestrates core signing steps.
//!
//! Provides both timestamped and non-timestamped signing workflows.
//! Uses service layer components for modular, testable signing pipeline.

use crate::{
    domain::pe, // for parsing early
    domain::{crypto::HashAlgorithm, pe::UnsignedPeFile},
    services::{
        attr_builder::AttrBuilderService, authenticode::OpenSslAuthenticodeSigner,
        embedder::PeSignatureEmbedderService, pe_hasher::PeHasher,
        pkcs7_builder::Pkcs7BuilderService, spc_builder::SpcBuilderService,
    },
    SigningConfig,
    SigningError,
    SigningResult,
    YubiKeyOperations,
};
use std::path::Path;

pub struct SignWorkflow {
    hash_algorithm: HashAlgorithm,
}

impl SignWorkflow {
    #[must_use]
    pub fn new(hash_algorithm: HashAlgorithm) -> Self {
        Self { hash_algorithm }
    }

    #[must_use]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Sign a PE file.
    ///
    /// Handles both timestamped and non-timestamped signing using appropriate workflow.
    pub async fn sign_pe_file<P: AsRef<Path>>(
        &self,
        input: P,
        output: P,
        config: SigningConfig,
    ) -> SigningResult<()> {
        let input_path = input.as_ref();
        let output_path = output.as_ref();
        let file_data = std::fs::read(input_path)
            .map_err(|e| SigningError::IoError(format!("Failed to read input file: {e}")))?;
        // If the input is already signed, strip the existing certificate table before hashing.
        // This allows re-signing build artifacts without requiring a separate "unsign" step.
        let file_data = pe::strip_certificate_table_for_resigning(&file_data)?;
        let _ = pe::parse_pe(&file_data)?; // validate early

        let mut yubikey_ops = YubiKeyOperations::connect()?;
        yubikey_ops.authenticate(&config.pin)?;

        let want_timestamp = config.timestamp_url.is_some();
        log::info!(
            "Phase8: executing service pipeline{}",
            if want_timestamp {
                " (with timestamp)"
            } else {
                ""
            }
        );
        // 1. Compute Authenticode hash
        let pe_hasher = PeHasher::new(self.hash_algorithm);
        let pe_digest = pe_hasher.hash(&file_data)?;
        // 2. SPC indirect data
        let cert_der = yubikey_ops.get_certificate_der(config.piv_slot)?;
        let ossl_signer = OpenSslAuthenticodeSigner::new(&cert_der, self.hash_algorithm)?;
        let spc_builder = SpcBuilderService::new(self.hash_algorithm);
        let spc = spc_builder.build(&pe_digest, |h| ossl_signer.create_spc_content(h))?;
        let spc_der = spc.as_der();
        // 3. Authenticated attributes + TBS via bridging AttrBuilderService
        let attr_service = AttrBuilderService::new(self.hash_algorithm);
        let attr_output = attr_service.build(&pe_digest, spc_der, &cert_der, &file_data)?;
        let set_der = attr_output.set_der;
        let a0_der = attr_output.embedding_der;
        // 5. Hash of TBS SET
        use sha2::{Digest, Sha256, Sha384, Sha512};
        let tbs_hash = match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                h.update(&set_der);
                h.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut h = Sha384::new();
                h.update(&set_der);
                h.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut h = Sha512::new();
                h.update(&set_der);
                h.finalize().to_vec()
            }
        };
        // 6. Hardware signature
        let signature = yubikey_ops.sign_hash(&tbs_hash, config.piv_slot)?;
        // 7. PKCS#7 assembly
        let pkcs7 = if want_timestamp {
            // Use authenticode path for timestamped signing until TimestampApplier
            // can properly inject into existing PKCS#7 structures
            log::info!("Using authenticode path for timestamped signing");

            // Get timestamp token first
            use crate::services::timestamp::{TimestampClient, TimestampConfig};
            let ts_config = TimestampConfig::default();
            let timestamp_client = TimestampClient::with_config(ts_config);
            let timestamp_token = timestamp_client.get_timestamp(&signature).await?;

            let authenticode_signer =
                OpenSslAuthenticodeSigner::new(&cert_der, self.hash_algorithm)?;
            let pkcs7_der = authenticode_signer.build_pkcs7_from_components(
                spc_der,
                &a0_der,
                &signature,
                Some(&timestamp_token),
                config.embed_certificate,
            )?;
            crate::domain::pkcs7::Pkcs7SignedData::from_der(pkcs7_der)
        } else {
            // No timestamp: use service pipeline
            let pkcs7_builder = Pkcs7BuilderService::new(
                cert_der.clone(),
                self.hash_algorithm,
                config.embed_certificate,
            );
            pkcs7_builder.build_signed(spc_der, &a0_der, &signature)?
        };

        // 8. Embed into PE
        let unsigned = UnsignedPeFile::new(file_data.clone())?;
        let embedder = PeSignatureEmbedderService::new();
        let signed_pe = embedder.embed(&unsigned, &pkcs7, &pe_digest)?;
        std::fs::write(output_path, signed_pe.bytes())
            .map_err(|e| SigningError::IoError(format!("Failed to write output file: {e}")))?;
        Ok(())
    }
}

// (parity helper removed post cutover)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_workflow() {
        let wf = SignWorkflow::new(HashAlgorithm::Sha256);
        assert!(matches!(wf.hash_algorithm, HashAlgorithm::Sha256));
    }

    // Integration tests with hardware are in tests/ directory
}
