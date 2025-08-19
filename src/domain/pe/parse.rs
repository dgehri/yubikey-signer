use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct PeRaw {
    bytes: Arc<[u8]>,
    pe_offset: usize,
}

impl PeRaw {
    pub fn parse(data: &[u8]) -> Result<Self, PeParseError> {
        if data.len() < 64 {
            return Err(PeParseError::TooShort);
        }
        if &data[0..2] != b"MZ" {
            return Err(PeParseError::MissingMz);
        }
        // e_lfanew at offset 0x3C (60)
        let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        if pe_offset + 4 > data.len() {
            return Err(PeParseError::OutOfRangePeHeader);
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(PeParseError::MissingPe);
        }
        Ok(PeRaw {
            bytes: Arc::from(data.to_owned().into_boxed_slice()),
            pe_offset,
        })
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn pe_offset(&self) -> usize {
        self.pe_offset
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeParseError {
    #[error("file too short for DOS header")]
    TooShort,
    #[error("missing MZ signature")]
    MissingMz,
    #[error("PE header pointer out of range")]
    OutOfRangePeHeader,
    #[error("missing PE signature")]
    MissingPe,
}
