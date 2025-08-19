//! Service for constructing and canonicalizing signed attributes.
//! Wraps existing attribute construction in authenticode.rs.

use crate::domain::pkcs7::{SignedAttributeLogical, SignedAttributesCanonical};

pub struct SignedAttributesBuilder; // stateless

impl Default for SignedAttributesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SignedAttributesBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build canonical attributes given already assembled Attribute SEQUENCE DER blobs.
    #[must_use]
    pub fn canonicalize(
        &self,
        raw_attributes: Vec<SignedAttributeLogical>,
    ) -> SignedAttributesCanonical {
        SignedAttributesCanonical::new(raw_attributes)
    }
}
