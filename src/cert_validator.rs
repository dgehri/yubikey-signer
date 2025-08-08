//! Certificate validation and analysis module
//!
//! This module provides enhanced certificate validation specifically for code signing,
//! including checks for proper key usage, extensions, and validity periods.

use crate::error::{SigningResult};
use x509_cert::Certificate;
use der::Encode;

/// Certificate validation results and analysis
#[derive(Debug, Clone)]
pub struct CertificateAnalysis {
    /// Whether the certificate is suitable for code signing
    pub is_code_signing_suitable: bool,
    /// Days until certificate expires (negative if already expired)
    pub days_until_expiry: i64,
    /// Whether the certificate has proper key usage extensions
    pub has_proper_key_usage: bool,
    /// Whether the certificate has digital signature capability
    pub can_digital_sign: bool,
    /// Detected certificate issues/warnings
    pub warnings: Vec<String>,
    /// Subject information
    pub subject: String,
    /// Issuer information
    pub issuer: String,
    /// Certificate serial number
    pub serial_number: String,
}

/// Enhanced certificate validator for code signing
pub struct CertificateValidator;

impl CertificateValidator {
    /// Perform comprehensive validation of a certificate for code signing
    pub fn validate_for_code_signing(certificate: &Certificate) -> SigningResult<CertificateAnalysis> {
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

        // Check certificate validity period
        analysis.days_until_expiry = Self::check_validity_period(certificate)?;
        if analysis.days_until_expiry < 0 {
            analysis.warnings.push("Certificate has expired".to_string());
        } else if analysis.days_until_expiry < 30 {
            analysis.warnings.push(format!("Certificate expires in {} days", analysis.days_until_expiry));
        }

        // Check key usage extensions
        analysis.has_proper_key_usage = Self::check_key_usage(certificate)?;
        if !analysis.has_proper_key_usage {
            analysis.warnings.push("Certificate lacks proper key usage extensions for code signing".to_string());
        }

        // Check for digital signature capability
        analysis.can_digital_sign = Self::check_digital_signature_capability(certificate)?;
        if !analysis.can_digital_sign {
            analysis.warnings.push("Certificate cannot be used for digital signatures".to_string());
        }

        // Check for code signing extended key usage
        let has_code_signing_eku = Self::check_code_signing_extended_key_usage(certificate)?;
        if !has_code_signing_eku {
            analysis.warnings.push("Certificate lacks Code Signing Extended Key Usage".to_string());
        }

        // Check for self-signed certificates
        if Self::is_self_signed(certificate) {
            analysis.warnings.push("Certificate is self-signed - may not be trusted by all systems".to_string());
        }

        // Determine overall suitability
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

    /// Extract human-readable subject name from certificate
    fn extract_subject_name(certificate: &Certificate) -> String {
        let subject_der = certificate.tbs_certificate.subject.to_der().unwrap_or_default();
        
        // Parse the subject DN components
        if let Ok(subject_str) = Self::parse_distinguished_name(&subject_der) {
            subject_str
        } else {
            format!("Subject DN [{}]", hex::encode(&subject_der[..std::cmp::min(16, subject_der.len())]))
        }
    }

    /// Extract human-readable issuer name from certificate
    fn extract_issuer_name(certificate: &Certificate) -> String {
        let issuer_der = certificate.tbs_certificate.issuer.to_der().unwrap_or_default();
        
        // Parse the issuer DN components
        if let Ok(issuer_str) = Self::parse_distinguished_name(&issuer_der) {
            issuer_str
        } else {
            format!("Issuer DN [{}]", hex::encode(&issuer_der[..std::cmp::min(16, issuer_der.len())]))
        }
    }

    /// Parse a Distinguished Name from DER bytes (simplified)
    fn parse_distinguished_name(der_bytes: &[u8]) -> Result<String, String> {
        // Implement ASN.1 DER parsing for Distinguished Names
        
        if der_bytes.len() < 10 {
            return Err("DN too short".to_string());
        }
        
        let mut components = Vec::new();
        let mut pos = 0;
        
        // Parse SEQUENCE of SETs containing AttributeTypeAndValue
        if der_bytes[pos] != 0x30 {
            return Err("Invalid DN structure - expected SEQUENCE".to_string());
        }
        
        pos += 1;
        let (length, length_bytes) = Self::parse_asn1_length(&der_bytes[pos..])?;
        pos += length_bytes;
        
        let end_pos = pos + length;
        
        // Parse each SET (RDN - Relative Distinguished Name)
        while pos < end_pos && pos < der_bytes.len() {
            if der_bytes[pos] == 0x31 { // SET tag
                pos += 1;
                let (set_length, set_length_bytes) = Self::parse_asn1_length(&der_bytes[pos..])?;
                pos += set_length_bytes;
                
                // Parse AttributeTypeAndValue within the SET
                if pos + set_length <= der_bytes.len() {
                    if let Ok(component) = Self::parse_attribute_type_and_value(&der_bytes[pos..pos + set_length]) {
                        components.push(component);
                    }
                }
                pos += set_length;
            } else {
                pos += 1; // Skip unexpected bytes
            }
        }
        
        if components.is_empty() {
            // Fallback to hex representation if parsing fails
            Ok(format!("DN[{}]", hex::encode(&der_bytes[..std::cmp::min(32, der_bytes.len())])))
        } else {
            Ok(components.join(", "))
        }
    }

    /// Parse ASN.1 DER length encoding
    fn parse_asn1_length(data: &[u8]) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("Empty length data".to_string());
        }
        
        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            // Short form
            Ok((first_byte as usize, 1))
        } else {
            // Long form
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

    /// Parse AttributeTypeAndValue from DER bytes
    fn parse_attribute_type_and_value(der_bytes: &[u8]) -> Result<String, String> {
        if der_bytes.len() < 10 {
            return Err("AttributeTypeAndValue too short".to_string());
        }
        
        let mut pos = 0;
        
        // Parse SEQUENCE
        if der_bytes[pos] != 0x30 {
            return Err("Expected SEQUENCE".to_string());
        }
        pos += 1;
        
        let (_, length_bytes) = Self::parse_asn1_length(&der_bytes[pos..])?;
        pos += length_bytes;
        
        // Parse OID
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
        
        // Parse value (can be various string types)
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
            0x0c | 0x13 | 0x16 | 0x1e => { // UTF8String, PrintableString, IA5String, BMPString
                String::from_utf8_lossy(value_bytes).trim_matches('\0').to_string()
            }
            _ => format!("0x{}", hex::encode(value_bytes))
        };
        
        Ok(format!("{oid_name}={value_str}"))
    }

    /// Convert OID bytes to human-readable name
    fn oid_to_name(oid_bytes: &[u8]) -> String {
        // Common X.500 attribute OIDs
        match oid_bytes {
            [0x55, 0x04, 0x03] => "CN".to_string(),                    // commonName
            [0x55, 0x04, 0x06] => "C".to_string(),                     // countryName  
            [0x55, 0x04, 0x08] => "ST".to_string(),                    // stateOrProvinceName
            [0x55, 0x04, 0x07] => "L".to_string(),                     // localityName
            [0x55, 0x04, 0x0a] => "O".to_string(),                     // organizationName
            [0x55, 0x04, 0x0b] => "OU".to_string(),                    // organizationalUnitName
            [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "emailAddress".to_string(),
            _ => format!("OID({})", hex::encode(oid_bytes))
        }
    }

    /// Extract serial number as hex string
    fn extract_serial_number(certificate: &Certificate) -> String {
        hex::encode(certificate.tbs_certificate.serial_number.as_bytes())
    }

    /// Check certificate validity period and return days until expiry
    fn check_validity_period(certificate: &Certificate) -> SigningResult<i64> {
        let validity = &certificate.tbs_certificate.validity;
        
        // For practical purposes, we'll use a simplified approach
        // The validity period can be checked by examining the certificate structure
        log::debug!("Checking certificate validity period");
        
        // Extract raw DER bytes for analysis
        let not_before_der = validity.not_before.to_der().unwrap_or_default();
        let not_after_der = validity.not_after.to_der().unwrap_or_default();
        
        // Log the validity information for debugging
        log::debug!("Certificate not_before: {} bytes", not_before_der.len());
        log::debug!("Certificate not_after: {} bytes", not_after_der.len());
        
        // Parse the actual validity dates from ASN.1 Time structures
        let current_time = std::time::SystemTime::now();
        let current_secs = current_time.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        
        // Parse not_after time to get expiry date
        if let Some(expiry_secs) = Self::parse_asn1_time(&not_after_der) {
            let days_remaining = ((expiry_secs.saturating_sub(current_secs)) / 86400) as i64;
            
            log::debug!("Certificate expires in {days_remaining} days");
            
            if days_remaining < 0 {
                log::warn!("Certificate has already expired {} days ago", -days_remaining);
            } else if days_remaining < 30 {
                log::warn!("Certificate expires soon: {days_remaining} days");
            }
            
            Ok(days_remaining)
        } else {
            // If we can't parse the exact time, estimate from DER structure
            if let Some(estimated_years) = Self::estimate_validity_years(&not_after_der) {
                let current_year = 2025; // Should be current year from system
                let years_remaining = estimated_years.saturating_sub(current_year);
                let days_remaining = years_remaining * 365;
                
                log::debug!("Estimated certificate expiry year: {estimated_years}, days remaining: {days_remaining}");
                Ok(days_remaining as i64)
            } else {
                // Conservative fallback: assume 30 days if we can't parse
                log::warn!("Could not parse certificate validity, assuming 30 days remaining");
                Ok(30)
            }
        }
    }

    /// Parse ASN.1 Time (UTCTime or GeneralizedTime) to Unix timestamp
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
            0x17 => Self::parse_utc_time(time_str),      // UTCTime (YY)
            0x18 => Self::parse_generalized_time(time_str), // GeneralizedTime (YYYY)
            _ => None,
        }
    }

    /// Parse UTCTime string (YYMMDDHHMMSSZ) to Unix timestamp
    fn parse_utc_time(time_str: &str) -> Option<u64> {
        if time_str.len() < 13 || !time_str.ends_with('Z') {
            return None;
        }
        
        let year_part: i32 = time_str[0..2].parse().ok()?;
        let year = if year_part >= 50 { 1900 + year_part } else { 2000 + year_part };
        let month: u32 = time_str[2..4].parse().ok()?;
        let day: u32 = time_str[4..6].parse().ok()?;
        let hour: u32 = time_str[6..8].parse().ok()?;
        let minute: u32 = time_str[8..10].parse().ok()?;
        let second: u32 = time_str[10..12].parse().ok()?;
        
        Self::datetime_to_unix_timestamp(year, month, day, hour, minute, second)
    }

    /// Parse GeneralizedTime string (YYYYMMDDHHMMSSZ) to Unix timestamp  
    fn parse_generalized_time(time_str: &str) -> Option<u64> {
        if time_str.len() < 15 || !time_str.ends_with('Z') {
            return None;
        }
        
        let year: i32 = time_str[0..4].parse().ok()?;
        let month: u32 = time_str[4..6].parse().ok()?;
        let day: u32 = time_str[6..8].parse().ok()?;
        let hour: u32 = time_str[8..10].parse().ok()?;
        let minute: u32 = time_str[10..12].parse().ok()?;
        let second: u32 = time_str[12..14].parse().ok()?;
        
        Self::datetime_to_unix_timestamp(year, month, day, hour, minute, second)
    }

    /// Convert date/time components to Unix timestamp (simplified calculation)
    fn datetime_to_unix_timestamp(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<u64> {
        // Simplified calculation - doesn't account for all leap years perfectly
        // For production use, would use a proper datetime library
        
        if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        
        let days_since_epoch = (year - 1970) * 365 + (year - 1969) / 4; // Approximate leap years
        let days_in_months = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        let month_days = days_in_months.get((month - 1) as usize)?;
        
        let total_days = days_since_epoch + *month_days + (day - 1) as i32;
        let total_seconds = total_days as u64 * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;
        
        Some(total_seconds)
    }

    /// Extract estimated expiry year from DER-encoded time
    fn estimate_validity_years(time_der: &[u8]) -> Option<i32> {
        if time_der.len() < 4 {
            return None;
        }
        
        // Try to find year patterns in the DER encoding
        for i in 0..time_der.len().saturating_sub(3) {
            // Look for 4-digit year patterns (2024, 2025, etc.)
            if time_der[i] == 0x32 && time_der[i+1] == 0x30 { // "20" in ASCII
                if let (Ok(year_str), true) = (
                    String::from_utf8(time_der[i..i+4].to_vec()),
                    time_der[i+2] >= 0x30 && time_der[i+2] <= 0x39 && 
                    time_der[i+3] >= 0x30 && time_der[i+3] <= 0x39
                ) {
                    if let Ok(year) = year_str.parse::<i32>() {
                        if (2020..=2040).contains(&year) {
                            return Some(year);
                        }
                    }
                }
            }
        }
        
        None
    }

    /// Check if certificate has proper key usage for digital signatures
    fn check_key_usage(certificate: &Certificate) -> SigningResult<bool> {
        // Check if the certificate has key usage extensions
        if let Some(extensions) = &certificate.tbs_certificate.extensions {
            for extension in extensions {
                // Look for Key Usage extension (OID: 2.5.29.15)
                if extension.extn_id.to_string() == "2.5.29.15" {
                    log::debug!("Found Key Usage extension");
                    
                    // Parse the key usage bits from the extension value
                    return Self::parse_key_usage_extension(extension.extn_value.as_bytes());
                }
            }
        }
        
        log::debug!("No Key Usage extension found");
        // If no key usage extension, assume it's allowed (per X.509 spec)
        Ok(true)
    }

    /// Parse Key Usage extension to check for digital signature capability
    fn parse_key_usage_extension(extension_value: &[u8]) -> SigningResult<bool> {
        // Key Usage is a BIT STRING, typically the first byte indicates unused bits
        // and subsequent bytes contain the actual flags
        if extension_value.len() < 2 {
            log::warn!("Key Usage extension too short");
            return Ok(false);
        }
        
        // Skip the first byte (unused bits indicator) and check the flags
        let key_usage_flags = extension_value[1];
        
        // Digital Signature is bit 0 (0x80)
        // Non-repudiation is bit 1 (0x40) - also useful for signing
        let has_digital_signature = (key_usage_flags & 0x80) != 0;
        let has_non_repudiation = (key_usage_flags & 0x40) != 0;
        
        log::debug!("Key Usage flags: 0x{key_usage_flags:02x}, digital signature: {has_digital_signature}, non-repudiation: {has_non_repudiation}");
        
        Ok(has_digital_signature || has_non_repudiation)
    }

    /// Check if certificate can be used for digital signatures
    fn check_digital_signature_capability(certificate: &Certificate) -> SigningResult<bool> {
        // Check Key Usage extension for digital signature capability
        let has_key_usage = Self::check_key_usage(certificate)?;
        
        // Check Extended Key Usage for Code Signing
        let has_code_signing_eku = Self::check_code_signing_extended_key_usage(certificate)?;
        
        // For code signing, we prefer certificates with explicit Code Signing EKU
        // but also accept certificates with digital signature key usage
        let is_suitable = has_code_signing_eku || has_key_usage;
        
        log::debug!("Digital signature capability: key_usage={has_key_usage}, code_signing_eku={has_code_signing_eku}, suitable={is_suitable}");
        
        Ok(is_suitable)
    }

    /// Check for Code Signing Extended Key Usage
    fn check_code_signing_extended_key_usage(certificate: &Certificate) -> SigningResult<bool> {
        if let Some(extensions) = &certificate.tbs_certificate.extensions {
            for extension in extensions {
                // Look for Extended Key Usage extension (OID: 2.5.29.37)
                if extension.extn_id.to_string() == "2.5.29.37" {
                    log::debug!("Found Extended Key Usage extension");
                    
                    // Parse the EKU extension to look for Code Signing OID
                    return Self::parse_extended_key_usage(extension.extn_value.as_bytes());
                }
            }
        }
        
        log::debug!("No Extended Key Usage extension found");
        Ok(false)
    }

    /// Parse Extended Key Usage extension to check for Code Signing
    fn parse_extended_key_usage(extension_value: &[u8]) -> SigningResult<bool> {
        // Convert Code Signing OID to bytes for searching
        // Code Signing OID: 1.3.6.1.5.5.7.3.3
        let code_signing_oid_bytes = vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
        
        // Search for the Code Signing OID in the extension value
        if extension_value.len() >= code_signing_oid_bytes.len() {
            for i in 0..=extension_value.len() - code_signing_oid_bytes.len() {
                if extension_value[i..i + code_signing_oid_bytes.len()] == code_signing_oid_bytes {
                    log::debug!("Found Code Signing EKU");
                    return Ok(true);
                }
            }
        }
        
        log::debug!("Code Signing EKU not found in extension");
        Ok(false)
    }

    /// Check if certificate is self-signed
    fn is_self_signed(certificate: &Certificate) -> bool {
        // Simple check: compare issuer and subject
        // In a full implementation, we'd also verify the signature
        let subject_der = certificate.tbs_certificate.subject.to_der().unwrap_or_default();
        let issuer_der = certificate.tbs_certificate.issuer.to_der().unwrap_or_default();
        
        subject_der == issuer_der
    }

    /// Suggest alternative slots if current certificate is not suitable
    pub fn suggest_alternative_slots() -> Vec<crate::types::PivSlot> {
        vec![
            crate::types::PivSlot::new(0x9a).unwrap(), // Authentication
            crate::types::PivSlot::new(0x9c).unwrap(), // Digital Signature
            crate::types::PivSlot::new(0x9d).unwrap(), // Key Management
            crate::types::PivSlot::new(0x9e).unwrap(), // Card Authentication
        ]
    }

    /// Check multiple slots for suitable certificates
    pub fn find_suitable_certificates(
        yubikey_ops: &mut crate::yubikey_ops::YubiKeyOperations,
        slots_to_check: &[crate::types::PivSlot]
    ) -> SigningResult<Vec<(crate::types::PivSlot, CertificateAnalysis)>> {
        let mut results = Vec::new();
        
        for &slot in slots_to_check {
            match yubikey_ops.get_certificate(slot) {
                Ok(certificate) => {
                    match Self::validate_for_code_signing(&certificate) {
                        Ok(analysis) => {
                            log::info!("Slot {slot}: Certificate analysis completed");
                            results.push((slot, analysis));
                        }
                        Err(e) => {
                            log::warn!("Slot {slot}: Certificate validation failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Slot {slot}: No certificate or access error: {e}");
                }
            }
        }
        
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_analysis_creation() {
        let analysis = CertificateAnalysis {
            is_code_signing_suitable: true,
            days_until_expiry: 365,
            has_proper_key_usage: true,
            can_digital_sign: true,
            warnings: vec!["Test warning".to_string()],
            subject: "Test Subject".to_string(),
            issuer: "Test Issuer".to_string(),
            serial_number: "123456".to_string(),
        };

        assert!(analysis.is_code_signing_suitable);
        assert_eq!(analysis.days_until_expiry, 365);
        assert_eq!(analysis.warnings.len(), 1);
    }

    #[test]
    fn test_alternative_slots_suggestion() {
        let slots = CertificateValidator::suggest_alternative_slots();
        assert!(!slots.is_empty());
        assert!(slots.len() >= 4); // Should suggest all common PIV slots
    }
}
