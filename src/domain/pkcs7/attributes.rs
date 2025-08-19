//! Signed attributes domain types (relocated under pkcs7/ per architecture).
//! Will gain richer semantics & strong OID typing.

use std::fmt;

#[derive(Clone)]
pub struct SignedAttributeLogical {
    pub oid: String,  // e.g. "1.2.840.113549.1.9.3"
    pub der: Vec<u8>, // Complete Attribute SEQUENCE bytes
}

impl fmt::Debug for SignedAttributeLogical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedAttributeLogical(oid={}, len={})",
            self.oid,
            self.der.len()
        )
    }
}

/// Canonically ordered, concatenated DER of all attributes (without outer SET tag).
pub struct SignedAttributesCanonical {
    ordered: Vec<SignedAttributeLogical>,
    concatenated_der: Vec<u8>, // concatenation of attribute DER sequences
}

impl SignedAttributesCanonical {
    #[must_use]
    pub fn new(mut attrs: Vec<SignedAttributeLogical>) -> Self {
        attrs.sort_by(|a, b| a.der.cmp(&b.der)); // DER SET ordering
        let mut concatenated = Vec::new();
        for a in &attrs {
            concatenated.extend_from_slice(&a.der);
        }
        Self {
            ordered: attrs,
            concatenated_der: concatenated,
        }
    }
    #[must_use]
    pub fn concatenated_der(&self) -> &[u8] {
        &self.concatenated_der
    }
    #[must_use]
    pub fn ordered(&self) -> &[SignedAttributeLogical] {
        &self.ordered
    }
}

impl fmt::Debug for SignedAttributesCanonical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedAttributesCanonical(count={}, total_len={})",
            self.ordered.len(),
            self.concatenated_der.len()
        )
    }
}
