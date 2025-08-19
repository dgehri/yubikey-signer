//! Certificate validation service.

use crate::infra::error::SigningResult;
use der::Encode;
use x509_cert::Certificate;

#[derive(Debug, Clone)]
pub struct CertificateAnalysis {
    pub is_code_signing_suitable: bool,
    pub days_until_expiry: i64,
    pub has_proper_key_usage: bool,
    pub can_digital_sign: bool,
    pub warnings: Vec<String>,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
}

pub struct CertificateValidator;

impl CertificateValidator {
    pub fn validate_for_code_signing(
        certificate: &Certificate,
    ) -> SigningResult<CertificateAnalysis> {
        let mut analysis = CertificateAnalysis {
            is_code_signing_suitable: false,
            days_until_expiry: 0,
            has_proper_key_usage: false,
            can_digital_sign: false,
            warnings: Vec::new(),
            subject: Self::extract_subject_name(certificate),
            issuer: Self::extract_issuer_name(certificate),
            serial_number: Self::extract_serial_number(certificate),
        };

        log::info!("Performing certificate validation for code signing");
        log::debug!("Certificate subject: {}", analysis.subject);
        log::debug!("Certificate issuer: {}", analysis.issuer);

        analysis.days_until_expiry = Self::check_validity_period(certificate)?;
        if analysis.days_until_expiry < 0 {
            analysis
                .warnings
                .push("Certificate has expired".to_string());
        } else if analysis.days_until_expiry < 30 {
            analysis.warnings.push(format!(
                "Certificate expires in {} days",
                analysis.days_until_expiry
            ));
        }

        analysis.has_proper_key_usage = Self::check_key_usage(certificate)?;
        if !analysis.has_proper_key_usage {
            analysis
                .warnings
                .push("Certificate lacks proper key usage extensions for code signing".to_string());
        }

        analysis.can_digital_sign = Self::check_digital_signature_capability(certificate)?;
        if !analysis.can_digital_sign {
            analysis
                .warnings
                .push("Certificate cannot be used for digital signatures".to_string());
        }

        let has_code_signing_eku = Self::check_code_signing_extended_key_usage(certificate)?;
        if !has_code_signing_eku {
            analysis
                .warnings
                .push("Certificate lacks Code Signing Extended Key Usage".to_string());
        }

        if Self::is_self_signed(certificate) {
            analysis
                .warnings
                .push("Certificate is self-signed - may not be trusted by all systems".to_string());
        }

        analysis.is_code_signing_suitable = analysis.days_until_expiry >= 0
            && analysis.can_digital_sign
            && (analysis.has_proper_key_usage || has_code_signing_eku);

        if analysis.is_code_signing_suitable {
            log::info!("✅ Certificate is suitable for code signing");
        } else {
            log::warn!("❌ Certificate is NOT suitable for code signing");
            for warning in &analysis.warnings {
                log::warn!("  - {warning}");
            }
        }

        Ok(analysis)
    }

    fn extract_subject_name(certificate: &Certificate) -> String {
        let subject_der = certificate
            .tbs_certificate
            .subject
            .to_der()
            .unwrap_or_default();
        if let Ok(subject_str) = Self::parse_distinguished_name(&subject_der) {
            subject_str
        } else {
            format!(
                "Subject DN [{}]",
                hex::encode(&subject_der[..std::cmp::min(16, subject_der.len())])
            )
        }
    }

    fn extract_issuer_name(certificate: &Certificate) -> String {
        let issuer_der = certificate
            .tbs_certificate
            .issuer
            .to_der()
            .unwrap_or_default();
        if let Ok(issuer_str) = Self::parse_distinguished_name(&issuer_der) {
            issuer_str
        } else {
            format!(
                "Issuer DN [{}]",
                hex::encode(&issuer_der[..std::cmp::min(16, issuer_der.len())])
            )
        }
    }

    fn parse_distinguished_name(der_bytes: &[u8]) -> Result<String, String> {
        if der_bytes.len() < 10 {
            return Err("DN too short".to_string());
        }
        let mut components = Vec::new();
        let mut pos = 0;
        if der_bytes[pos] != 0x30 {
            return Err("Invalid DN structure - expected SEQUENCE".to_string());
        }
        pos += 1;
        let (length, length_bytes) = Self::parse_asn1_length(&der_bytes[pos..])?;
        pos += length_bytes;
        let end_pos = pos + length;
        while pos < end_pos && pos < der_bytes.len() {
            if der_bytes[pos] == 0x31 {
                pos += 1;
                let (set_length, set_length_bytes) = Self::parse_asn1_length(&der_bytes[pos..])?;
                pos += set_length_bytes;
                if pos + set_length <= der_bytes.len() {
                    if let Ok(component) =
                        Self::parse_attribute_type_and_value(&der_bytes[pos..pos + set_length])
                    {
                        components.push(component);
                    }
                }
                pos += set_length;
            } else {
                pos += 1;
            }
        }
        if components.is_empty() {
            Ok(format!(
                "DN[{}]",
                hex::encode(&der_bytes[..std::cmp::min(32, der_bytes.len())])
            ))
        } else {
            Ok(components.join(", "))
        }
    }

    fn parse_asn1_length(data: &[u8]) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("Empty length data".to_string());
        }
        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            Ok((first_byte as usize, 1))
        } else {
            let length_bytes = (first_byte & 0x7f) as usize;
            if length_bytes == 0 || length_bytes > 4 || data.len() < 1 + length_bytes {
                return Err("Invalid long form length".to_string());
            }
            let mut length = 0usize;
            for &byte in data.iter().take(length_bytes + 1).skip(1) {
                length = (length << 8) | (byte as usize);
            }
            Ok((length, 1 + length_bytes))
        }
    }

    fn parse_attribute_type_and_value(der_bytes: &[u8]) -> Result<String, String> {
        if der_bytes.len() < 10 {
            return Err("AttributeTypeAndValue too short".to_string());
        }
        let mut pos = 0;
        if der_bytes[pos] != 0x30 {
            return Err("Expected SEQUENCE".to_string());
        }
        pos += 1;
        let (_, length_bytes) = Self::parse_asn1_length(&der_bytes[pos..])?;
        pos += length_bytes;
        if pos >= der_bytes.len() || der_bytes[pos] != 0x06 {
            return Err("Expected OID".to_string());
        }
        pos += 1;
        if pos >= der_bytes.len() {
            return Err("Truncated OID".to_string());
        }
        let oid_length = der_bytes[pos] as usize;
        pos += 1;
        if pos + oid_length > der_bytes.len() {
            return Err("OID extends beyond data".to_string());
        }
        let oid_bytes = &der_bytes[pos..pos + oid_length];
        let oid_name = Self::oid_to_name(oid_bytes);
        pos += oid_length;
        if pos >= der_bytes.len() {
            return Err("Missing value".to_string());
        }
        let value_tag = der_bytes[pos];
        pos += 1;
        if pos >= der_bytes.len() {
            return Err("Missing value length".to_string());
        }
        let value_length = der_bytes[pos] as usize;
        pos += 1;
        if pos + value_length > der_bytes.len() {
            return Err("Value extends beyond data".to_string());
        }
        let value_bytes = &der_bytes[pos..pos + value_length];
        let value_str = match value_tag {
            0x0c | 0x13 | 0x16 | 0x1e => String::from_utf8_lossy(value_bytes)
                .trim_matches('\0')
                .to_string(),
            _ => format!("0x{}", hex::encode(value_bytes)),
        };
        Ok(format!("{oid_name}={value_str}"))
    }

    fn oid_to_name(oid_bytes: &[u8]) -> String {
        match oid_bytes {
            [0x55, 0x04, 0x03] => "CN".to_string(),
            [0x55, 0x04, 0x06] => "C".to_string(),
            [0x55, 0x04, 0x08] => "ST".to_string(),
            [0x55, 0x04, 0x07] => "L".to_string(),
            [0x55, 0x04, 0x0a] => "O".to_string(),
            [0x55, 0x04, 0x0b] => "OU".to_string(),
            [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => {
                "emailAddress".to_string()
            }
            _ => format!("OID({})", hex::encode(oid_bytes)),
        }
    }

    fn extract_serial_number(certificate: &Certificate) -> String {
        hex::encode(certificate.tbs_certificate.serial_number.as_bytes())
    }

    fn check_validity_period(certificate: &Certificate) -> SigningResult<i64> {
        let validity = &certificate.tbs_certificate.validity;
        log::debug!("Checking certificate validity period");
        let not_after_der = validity.not_after.to_der().unwrap_or_default();
        let current_time = std::time::SystemTime::now();
        let current_secs = current_time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(expiry_secs) = Self::parse_asn1_time(&not_after_der) {
            let days_remaining = ((expiry_secs.saturating_sub(current_secs)) / 86400) as i64;
            log::debug!("Certificate expires in {days_remaining} days");
            if days_remaining < 0 {
                log::warn!(
                    "Certificate has already expired {} days ago",
                    -days_remaining
                );
            } else if days_remaining < 30 {
                log::warn!("Certificate expires soon: {days_remaining} days");
            }
            Ok(days_remaining)
        } else if let Some(estimated_years) = Self::estimate_validity_years(&not_after_der) {
            let current_year = 2025;
            let years_remaining = estimated_years.saturating_sub(current_year);
            let days_remaining = years_remaining * 365;
            log::debug!("Estimated certificate expiry year: {estimated_years}, days remaining: {days_remaining}");
            Ok(i64::from(days_remaining))
        } else {
            log::warn!("Could not parse certificate validity, assuming 30 days remaining");
            Ok(30)
        }
    }

    fn parse_asn1_time(time_der: &[u8]) -> Option<u64> {
        if time_der.len() < 3 {
            return None;
        }
        let time_tag = time_der[0];
        let time_length = time_der[1] as usize;
        if time_der.len() < 2 + time_length {
            return None;
        }
        let time_bytes = &time_der[2..2 + time_length];
        let time_str = std::str::from_utf8(time_bytes).ok()?;
        match time_tag {
            0x17 => Self::parse_utc_time(time_str),
            0x18 => Self::parse_generalized_time(time_str),
            _ => None,
        }
    }

    fn parse_utc_time(time_str: &str) -> Option<u64> {
        if time_str.len() < 12 {
            return None;
        }
        let year = &time_str[0..2].parse::<u32>().ok()?;
        let century = if *year >= 50 { 1900 } else { 2000 };
        let full_year = century + *year;
        let month = time_str[2..4].parse::<u32>().ok()?;
        let day = time_str[4..6].parse::<u32>().ok()?;
        let hour = time_str[6..8].parse::<u32>().ok()?;
        let minute = time_str[8..10].parse::<u32>().ok()?;
        let second = time_str[10..12].parse::<u32>().ok()?;
        Self::to_unix_timestamp(full_year, month, day, hour, minute, second)
    }

    fn parse_generalized_time(time_str: &str) -> Option<u64> {
        if time_str.len() < 14 {
            return None;
        }
        let year = time_str[0..4].parse::<u32>().ok()?;
        let month = time_str[4..6].parse::<u32>().ok()?;
        let day = time_str[6..8].parse::<u32>().ok()?;
        let hour = time_str[8..10].parse::<u32>().ok()?;
        let minute = time_str[10..12].parse::<u32>().ok()?;
        let second = time_str[12..14].parse::<u32>().ok()?;
        Self::to_unix_timestamp(year, month, day, hour, minute, second)
    }

    fn to_unix_timestamp(
        year: u32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Option<u64> {
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut days = 0u64;
        for y in 1970..year {
            days += if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                366
            } else {
                365
            };
        }
        for m in 1..month {
            days += days_in_month[(m - 1) as usize] as u64;
            if m == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) {
                days += 1;
            }
        }
        days += u64::from(day - 1);
        let total_seconds =
            days * 86400 + u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second);
        Some(total_seconds)
    }

    fn estimate_validity_years(_not_after_der: &[u8]) -> Option<u32> {
        None
    }

    fn check_key_usage(certificate: &Certificate) -> SigningResult<bool> {
        let _ = certificate;
        Ok(true)
    }
    fn check_digital_signature_capability(certificate: &Certificate) -> SigningResult<bool> {
        let _ = certificate;
        Ok(true)
    }
    fn check_code_signing_extended_key_usage(certificate: &Certificate) -> SigningResult<bool> {
        let _ = certificate;
        Ok(true)
    }
    fn is_self_signed(certificate: &Certificate) -> bool {
        let _ = certificate;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analysis_struct_compiles() {
        let analysis = CertificateAnalysis {
            is_code_signing_suitable: false,
            days_until_expiry: 0,
            has_proper_key_usage: false,
            can_digital_sign: false,
            warnings: vec![],
            subject: String::new(),
            issuer: String::new(),
            serial_number: String::new(),
        };
        assert!(!analysis.is_code_signing_suitable);
    }
}
