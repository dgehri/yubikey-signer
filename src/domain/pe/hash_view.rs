use super::PeRaw;

/// Thin wrapper providing access to PE bytes for canonical Authenticode hashing.
#[derive(Clone, Debug)]
pub struct PeHashView<'a> {
    raw: &'a PeRaw,
}

impl<'a> PeHashView<'a> {
    #[must_use]
    pub fn from_raw(raw: &'a PeRaw) -> Self {
        Self { raw }
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.raw.bytes()
    }
}
