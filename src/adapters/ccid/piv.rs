//! PIV (Personal Identity Verification) operations over direct USB CCID.
//!
//! Implements the PIV application commands for authentication, certificate
//! retrieval, and signing using the direct CCID transport.
//!
//! # PIV Application
//!
//! The PIV application on `YubiKey` is identified by AID `A0 00 00 03 08`.
//! It provides:
//! - PIN verification for access control
//! - Certificate storage in various slots
//! - Asymmetric key operations (signing, decryption)

use super::CcidTransport;
use crate::domain::types::{PivPin, PivSlot};
use crate::infra::error::{SigningError, SigningResult};
use crate::services::authenticode;
use crate::HashAlgorithm;

/// PIV Application ID.
const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// PIV instruction codes.
mod ins {
    /// SELECT application.
    pub const SELECT: u8 = 0xA4;
    /// VERIFY PIN.
    pub const VERIFY: u8 = 0x20;
    /// GET DATA (read object).
    pub const GET_DATA: u8 = 0xCB;
    /// GENERAL AUTHENTICATE (sign/decrypt).
    pub const GENERAL_AUTHENTICATE: u8 = 0x87;
}

/// PIV object IDs for certificates in each slot.
fn slot_to_object_id(slot: PivSlot) -> &'static [u8] {
    match slot.as_u8() {
        0x9A => &[0x5F, 0xC1, 0x05], // PIV Authentication
        0x9C => &[0x5F, 0xC1, 0x0A], // Digital Signature
        0x9D => &[0x5F, 0xC1, 0x0B], // Key Management
        0x9E => &[0x5F, 0xC1, 0x01], // Card Authentication
        _ => &[0x5F, 0xC1, 0x05],    // Default to 9A
    }
}

/// PIV algorithm IDs.
mod algorithm {
    /// 3DES (for management key).
    #[allow(dead_code)]
    pub const TDES: u8 = 0x03;
    /// RSA 1024.
    #[allow(dead_code)]
    pub const RSA1024: u8 = 0x06;
    /// RSA 2048.
    pub const RSA2048: u8 = 0x07;
    /// ECC P-256.
    pub const ECCP256: u8 = 0x11;
    /// ECC P-384.
    pub const ECCP384: u8 = 0x14;
}

/// Direct PIV operations using CCID transport.
///
/// Provides high-level PIV operations (authentication, certificate retrieval,
/// signing) over a direct USB connection to the `YubiKey`.
pub struct DirectPivOperations {
    /// CCID transport layer.
    transport: CcidTransport,
    /// Whether PIN has been verified.
    authenticated: bool,
}

impl DirectPivOperations {
    /// Create a new PIV operations instance.
    ///
    /// Opens a direct USB connection to the `YubiKey` and selects the PIV
    /// application.
    ///
    /// # Errors
    ///
    /// Returns error if no `YubiKey` is found or PIV selection fails.
    pub fn connect() -> SigningResult<Self> {
        let mut transport = CcidTransport::open()?;

        // Select PIV application
        let mut select_cmd = vec![0x00, ins::SELECT, 0x04, 0x00, PIV_AID.len() as u8];
        select_cmd.extend_from_slice(PIV_AID);

        let response = transport.transmit(&select_cmd)?;
        Self::check_status(&response, "SELECT PIV")?;

        log::info!("PIV application selected successfully (direct USB)");

        Ok(Self {
            transport,
            authenticated: false,
        })
    }

    /// Verify PIN to unlock private key operations.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIV PIN (6-8 digits)
    ///
    /// # Errors
    ///
    /// Returns error if PIN verification fails.
    pub fn authenticate(&mut self, pin: &PivPin) -> SigningResult<()> {
        let pin_bytes = pin.as_bytes();

        // VERIFY command: CLA=0x00, INS=0x20, P1=0x00, P2=0x80 (PIV PIN)
        let mut verify_cmd = vec![0x00, ins::VERIFY, 0x00, 0x80, pin_bytes.len() as u8];
        verify_cmd.extend_from_slice(pin_bytes);

        let response = self.transport.transmit(&verify_cmd)?;
        Self::check_status(&response, "VERIFY PIN")?;

        self.authenticated = true;
        log::info!("PIN verified successfully");
        Ok(())
    }

    /// Retrieve raw DER certificate bytes from a slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot containing the certificate
    ///
    /// # Errors
    ///
    /// Returns error if certificate cannot be read.
    pub fn get_certificate_der(&mut self, slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.ensure_authenticated()?;

        let object_id = slot_to_object_id(slot);

        // Build GET DATA command
        // The data object is specified in a TLV with tag 0x5C
        let mut data_field = vec![0x5C];
        data_field.push(object_id.len() as u8);
        data_field.extend_from_slice(object_id);

        // GET DATA: CLA=0x00, INS=0xCB, P1=0x3F, P2=0xFF
        let mut get_data_cmd = vec![0x00, ins::GET_DATA, 0x3F, 0xFF, data_field.len() as u8];
        get_data_cmd.extend_from_slice(&data_field);
        get_data_cmd.push(0x00); // Le = 0 (expect max response)

        let mut full_response = Vec::new();

        // Handle response chaining
        loop {
            let response = self.transport.transmit(&get_data_cmd)?;

            if response.len() < 2 {
                return Err(SigningError::YubiKeyError("Response too short".to_string()));
            }

            let sw1 = response[response.len() - 2];
            let sw2 = response[response.len() - 1];

            // Append data (excluding status bytes)
            full_response.extend_from_slice(&response[..response.len() - 2]);

            if sw1 == 0x90 && sw2 == 0x00 {
                // Success, no more data
                break;
            } else if sw1 == 0x61 {
                // More data available, GET RESPONSE
                get_data_cmd = vec![0x00, 0xC0, 0x00, 0x00, sw2];
            } else {
                return Err(SigningError::YubiKeyError(format!(
                    "GET DATA failed: SW={sw1:02X}{sw2:02X}"
                )));
            }
        }

        // Parse the certificate from the response
        // Response format: 53 LL [cert TLV] [compress TLV] [LRC TLV]
        // We need to extract the certificate (tag 0x70 or 0x71)
        Self::extract_certificate(&full_response)
    }

    /// Sign a hash using the private key in the specified slot.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash bytes to sign (SHA-256, SHA-384, or SHA-512)
    /// * `slot` - The PIV slot containing the signing key
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    pub fn sign_hash(&mut self, hash: &[u8], slot: PivSlot) -> SigningResult<Vec<u8>> {
        self.ensure_authenticated()?;

        // Determine algorithm based on hash length and try different algorithms
        // First try ECDSA, then RSA

        // Try ECC P-384
        if let Ok(sig) = self.try_sign(hash, slot, algorithm::ECCP384) {
            return Ok(sig);
        }

        // Try ECC P-256
        if let Ok(sig) = self.try_sign(hash, slot, algorithm::ECCP256) {
            return Ok(sig);
        }

        // Try RSA 2048 with DigestInfo
        let hash_algorithm = match hash.len() {
            32 => HashAlgorithm::Sha256,
            48 => HashAlgorithm::Sha384,
            64 => HashAlgorithm::Sha512,
            _ => {
                return Err(SigningError::YubiKeyError(format!(
                    "Unsupported hash length: {} bytes",
                    hash.len()
                )));
            }
        };

        let digest_info = authenticode::create_digest_info(hash, hash_algorithm)?;
        if let Ok(sig) = self.try_sign(&digest_info, slot, algorithm::RSA2048) {
            return Ok(sig);
        }

        Err(SigningError::YubiKeyError(format!(
            "Failed to sign with slot {slot}: no supported algorithm worked"
        )))
    }

    /// Try signing with a specific algorithm.
    fn try_sign(&mut self, data: &[u8], slot: PivSlot, alg: u8) -> SigningResult<Vec<u8>> {
        // Build GENERAL AUTHENTICATE command
        // Dynamic Object Template (tag 0x7C):
        //   Response tag 0x82 (empty - request signature)
        //   Challenge tag 0x81 (hash/data to sign)

        let mut dyn_auth = vec![0x7C];

        // Calculate inner TLV length
        let challenge_tlv_len = 1 + Self::len_bytes(data.len()).len() + data.len();
        let response_tlv_len = 2; // 0x82 0x00
        let inner_len = challenge_tlv_len + response_tlv_len;

        // Encode outer length
        dyn_auth.extend(Self::len_bytes(inner_len));

        // Response placeholder: 82 00
        dyn_auth.extend_from_slice(&[0x82, 0x00]);

        // Challenge: 81 LL <data>
        dyn_auth.push(0x81);
        dyn_auth.extend(Self::len_bytes(data.len()));
        dyn_auth.extend_from_slice(data);

        // Build command
        // CLA=0x00, INS=0x87, P1=algorithm, P2=slot
        let mut cmd = vec![0x00, ins::GENERAL_AUTHENTICATE, alg, slot.as_u8()];

        // Handle extended length if needed
        if dyn_auth.len() > 255 {
            // Extended APDU
            cmd.push(0x00); // Extended length marker
            cmd.push(((dyn_auth.len() >> 8) & 0xFF) as u8);
            cmd.push((dyn_auth.len() & 0xFF) as u8);
        } else {
            cmd.push(dyn_auth.len() as u8);
        }

        cmd.extend_from_slice(&dyn_auth);

        // Le
        if dyn_auth.len() > 255 {
            cmd.extend_from_slice(&[0x00, 0x00]); // Extended Le
        } else {
            cmd.push(0x00);
        }

        let mut full_response = Vec::new();

        // Send and handle chaining
        let mut current_cmd = cmd;
        loop {
            let response = self.transport.transmit(&current_cmd)?;

            if response.len() < 2 {
                return Err(SigningError::YubiKeyError("Response too short".to_string()));
            }

            let sw1 = response[response.len() - 2];
            let sw2 = response[response.len() - 1];

            full_response.extend_from_slice(&response[..response.len() - 2]);

            if sw1 == 0x90 && sw2 == 0x00 {
                break;
            } else if sw1 == 0x61 {
                // More data, GET RESPONSE
                current_cmd = vec![0x00, 0xC0, 0x00, 0x00, sw2];
            } else {
                return Err(SigningError::YubiKeyError(format!(
                    "GENERAL AUTHENTICATE failed: SW={sw1:02X}{sw2:02X}"
                )));
            }
        }

        // Parse signature from response
        // Response: 7C LL 82 LL <signature>
        Self::extract_signature(&full_response)
    }

    /// Get the device serial number.
    ///
    /// # Errors
    ///
    /// Returns error if serial cannot be retrieved.
    pub fn get_serial(&mut self) -> SigningResult<u32> {
        self.transport.serial()
    }

    /// Get the device firmware version.
    ///
    /// # Errors
    ///
    /// Returns error if version cannot be retrieved.
    pub fn get_version(&mut self) -> SigningResult<String> {
        self.transport.version()
    }

    /// Check if authenticated.
    fn ensure_authenticated(&self) -> SigningResult<()> {
        if !self.authenticated {
            return Err(SigningError::YubiKeyError(
                "Not authenticated with YubiKey".to_string(),
            ));
        }
        Ok(())
    }

    /// Check APDU status words.
    fn check_status(response: &[u8], operation: &str) -> SigningResult<()> {
        if response.len() < 2 {
            return Err(SigningError::YubiKeyError(format!(
                "{operation}: Response too short"
            )));
        }

        let sw1 = response[response.len() - 2];
        let sw2 = response[response.len() - 1];

        if sw1 == 0x90 && sw2 == 0x00 {
            Ok(())
        } else if sw1 == 0x63 && (sw2 & 0xC0) == 0xC0 {
            let retries = sw2 & 0x0F;
            Err(SigningError::YubiKeyError(format!(
                "{operation}: Wrong PIN ({retries} retries remaining)"
            )))
        } else if sw1 == 0x69 && sw2 == 0x83 {
            Err(SigningError::YubiKeyError(format!(
                "{operation}: PIN blocked"
            )))
        } else {
            Err(SigningError::YubiKeyError(format!(
                "{operation}: Failed with SW={sw1:02X}{sw2:02X}"
            )))
        }
    }

    /// Encode length in ASN.1/BER format.
    fn len_bytes(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]
        }
    }

    /// Extract certificate from GET DATA response.
    fn extract_certificate(data: &[u8]) -> SigningResult<Vec<u8>> {
        // The response is: 53 LL <contents>
        // Contents: 70/71 LL <certificate> [optional 71 01 00] [FE LRC]
        if data.is_empty() {
            return Err(SigningError::CertificateError(
                "Empty certificate response".to_string(),
            ));
        }

        let mut pos = 0;

        // Skip outer tag 0x53 if present
        if pos < data.len() && data[pos] == 0x53 {
            pos += 1;
            pos += Self::skip_length(&data[pos..])?;
        }

        // Find certificate tag (0x70 = uncompressed, 0x71 = compressed)
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;

            if pos >= data.len() {
                break;
            }

            let (len, len_size) = Self::parse_length(&data[pos..])?;
            pos += len_size;

            if tag == 0x70 {
                // Uncompressed certificate
                if pos + len > data.len() {
                    return Err(SigningError::CertificateError(
                        "Certificate data truncated".to_string(),
                    ));
                }
                return Ok(data[pos..pos + len].to_vec());
            } else if tag == 0x71 {
                // Compressed certificate - not supported for now
                return Err(SigningError::CertificateError(
                    "Compressed certificates not supported".to_string(),
                ));
            }

            // Skip this TLV
            pos += len;
        }

        Err(SigningError::CertificateError(
            "Certificate not found in response".to_string(),
        ))
    }

    /// Extract signature from GENERAL AUTHENTICATE response.
    fn extract_signature(data: &[u8]) -> SigningResult<Vec<u8>> {
        // Response: 7C LL 82 LL <signature>
        if data.len() < 4 {
            return Err(SigningError::YubiKeyError(
                "Signature response too short".to_string(),
            ));
        }

        let mut pos = 0;

        // Check for Dynamic Authentication Template tag 0x7C
        if data[pos] != 0x7C {
            return Err(SigningError::YubiKeyError(format!(
                "Expected tag 0x7C, got 0x{:02X}",
                data[pos]
            )));
        }
        pos += 1;

        // Skip length
        let (_, len_size) = Self::parse_length(&data[pos..])?;
        pos += len_size;

        // Check for signature tag 0x82
        if pos >= data.len() || data[pos] != 0x82 {
            return Err(SigningError::YubiKeyError(format!(
                "Expected tag 0x82, got 0x{:02X}",
                data.get(pos).copied().unwrap_or(0)
            )));
        }
        pos += 1;

        // Get signature length
        let (sig_len, len_size) = Self::parse_length(&data[pos..])?;
        pos += len_size;

        if pos + sig_len > data.len() {
            return Err(SigningError::YubiKeyError(
                "Signature data truncated".to_string(),
            ));
        }

        Ok(data[pos..pos + sig_len].to_vec())
    }

    /// Parse BER length encoding.
    fn parse_length(data: &[u8]) -> SigningResult<(usize, usize)> {
        if data.is_empty() {
            return Err(SigningError::YubiKeyError(
                "Missing length byte".to_string(),
            ));
        }

        if data[0] < 128 {
            Ok((data[0] as usize, 1))
        } else if data[0] == 0x81 {
            if data.len() < 2 {
                return Err(SigningError::YubiKeyError(
                    "Truncated length encoding".to_string(),
                ));
            }
            Ok((data[1] as usize, 2))
        } else if data[0] == 0x82 {
            if data.len() < 3 {
                return Err(SigningError::YubiKeyError(
                    "Truncated length encoding".to_string(),
                ));
            }
            let len = ((data[1] as usize) << 8) | (data[2] as usize);
            Ok((len, 3))
        } else {
            Err(SigningError::YubiKeyError(format!(
                "Unsupported length encoding: 0x{:02X}",
                data[0]
            )))
        }
    }

    /// Skip over a BER length field.
    fn skip_length(data: &[u8]) -> SigningResult<usize> {
        let (_, len_size) = Self::parse_length(data)?;
        Ok(len_size)
    }
}
