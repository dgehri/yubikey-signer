//! Service layer module root.
//! Contains cryptographic services and signing implementations.

pub mod attr_builder;
pub mod authenticode;
#[cfg(feature = "pcsc-backend")]
pub mod auto_detect;
pub mod cert_validator;
pub mod embedder;
pub mod pe_hasher;
pub mod pkcs7;
pub mod pkcs7_builder;
pub mod signed_attributes_builder;
#[cfg(feature = "pcsc-backend")]
pub mod signing;
pub mod spc_builder;
pub mod timestamp;
pub mod timestamp_applier;
pub mod timestamp_parser;
pub mod timestamp_request_builder;
pub mod verification;

pub use attr_builder::AttrBuilderService;
pub use authenticode::{
    create_digest_info, create_digest_info_from_digest, OpenSslAuthenticodeSigner, TbsContext,
};
#[cfg(feature = "pcsc-backend")]
pub use auto_detect::{
    AutoDetection, DiscoveryResults, RecommendationLevel, SlotInfo, SlotRecommendation,
};
pub use cert_validator::{CertificateAnalysis, CertificateValidator};
pub use embedder::PeSignatureEmbedderService;
pub use pkcs7::AuthenticodeBuilder;
pub use pkcs7_builder::Pkcs7BuilderService;
pub use signed_attributes_builder::SignedAttributesBuilder;
#[cfg(feature = "pcsc-backend")]
pub use signing::{Signer, SigningConfig, SigningDetails, SigningOptions};
pub use spc_builder::SpcBuilderService;
pub use timestamp::{verify_timestamp_token, TimestampClient, TimestampConfig, TimestampResponse};
pub use timestamp_applier::TimestampApplier;
pub use timestamp_parser::TimestampParserService;
pub use timestamp_request_builder::TimestampRequestBuilder;
pub use verification::VerificationService;
