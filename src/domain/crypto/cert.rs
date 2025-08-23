use std::fmt;

/// End-entity code signing certificate wrapper.
#[derive(Clone)]
pub struct EndEntityCert {
    der: Box<[u8]>,
}

/// Intermediate certificate wrapper.
#[derive(Clone)]
pub struct IntermediateCert {
    der: Box<[u8]>,
}

/// Simple ordered certificate chain (leaf first, then intermediates). Root excluded.
#[derive(Clone)]
pub struct CertChain {
    leaf: EndEntityCert,
    intermediates: Vec<IntermediateCert>,
}

impl EndEntityCert {
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self {
            der: der.into_boxed_slice(),
        }
    }
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl IntermediateCert {
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self {
            der: der.into_boxed_slice(),
        }
    }
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl CertChain {
    #[must_use]
    pub fn new(leaf: EndEntityCert) -> Self {
        Self {
            leaf,
            intermediates: Vec::new(),
        }
    }
    #[must_use]
    pub fn with_intermediates(mut self, list: Vec<IntermediateCert>) -> Self {
        self.intermediates = list;
        self
    }
    #[must_use]
    pub fn leaf(&self) -> &EndEntityCert {
        &self.leaf
    }
    #[must_use]
    pub fn intermediates(&self) -> &[IntermediateCert] {
        &self.intermediates
    }
}

impl fmt::Debug for EndEntityCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndEntityCert(len={})", self.der.len())
    }
}
impl fmt::Debug for IntermediateCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntermediateCert(len={})", self.der.len())
    }
}
impl fmt::Debug for CertChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertChain(leaf_len={}, intermediates={})",
            self.leaf.der.len(),
            self.intermediates.len()
        )
    }
}
