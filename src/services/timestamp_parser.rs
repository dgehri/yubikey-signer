//! Timestamp token parser & validator service.
//! Timestamp token parsing service with structural validation.

use crate::domain::pkcs7::timestamp::TimestampToken;
use crate::{infra::error::SigningError, infra::error::SigningResult};

/// Service responsible for parsing raw timestamp response bytes and validating
/// the message imprint against the provided signature hash.
pub struct TimestampParserService;

impl TimestampParserService {
    /// Parse a timestamp token DER and validate the message imprint hash.
    pub fn parse_and_validate(
        token_der: Vec<u8>,
        signature_hash: &[u8],
    ) -> SigningResult<TimestampToken> {
        let token = TimestampToken::from_der(token_der)?;
        token
            .validate_message_imprint(signature_hash)
            .map_err(|e| SigningError::TimestampError(format!("imprint validation failed: {e}")))?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_der() {
        let res = TimestampParserService::parse_and_validate(vec![0x30], &[1, 2, 3]);
        assert!(res.is_err());
    }
}
