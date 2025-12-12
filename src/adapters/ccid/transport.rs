//! USB CCID transport layer for direct `YubiKey` communication.
//!
//! Implements the USB CCID (Chip Card Interface Device) protocol for sending
//! APDUs directly to the `YubiKey` without requiring pcscd.
//!
//! # Protocol Overview
//!
//! CCID messages consist of a 10-byte header followed by optional data:
//!
//! ```text
//! Offset  Size  Description
//! 0       1     Message type (0x6F = XfrBlock, 0x80 = DataBlock)
//! 1       4     Data length (little-endian)
//! 5       1     Slot number (always 0 for YubiKey)
//! 6       1     Sequence number
//! 7       3     Type-specific parameters
//! 10      N     Data payload (APDU for XfrBlock, response for DataBlock)
//! ```

use crate::infra::error::{SigningError, SigningResult};
use rusb::{Context, DeviceHandle, UsbContext};
use std::time::Duration;

/// `YubiKey` USB Vendor ID.
const YUBIKEY_VID: u16 = 0x1050;

/// Known `YubiKey` Product IDs (CCID-capable devices).
const YUBIKEY_PIDS: &[u16] = &[
    0x0407, // YubiKey 5 NFC
    0x0406, // YubiKey 5 Nano
    0x0405, // YubiKey 5C
    0x0404, // YubiKey 5C Nano
    0x0402, // YubiKey 4
    0x0403, // YubiKey 4 Nano
    0x0410, // YubiKey 5 NFC FIDO
    0x0411, // YubiKey 5C NFC
    0x0401, // YubiKey NEO OTP+CCID
    0x0116, // YubiKey NEO OTP+U2F+CCID
    0x0112, // YubiKey NEO CCID
];

/// CCID message types.
mod message_type {
    /// PC to Reader: Transfer block (send APDU).
    pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
    /// PC to Reader: ICC power on.
    pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
    /// PC to Reader: ICC power off.
    pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
    /// Reader to PC: Data block (APDU response).
    pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
    /// Reader to PC: Slot status.
    pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
}

/// CCID slot status codes.
mod slot_status {
    /// Card present and active.
    pub const ICC_PRESENT_ACTIVE: u8 = 0x00;
    /// Card present but inactive.
    #[allow(dead_code)]
    pub const ICC_PRESENT_INACTIVE: u8 = 0x01;
    /// No card present.
    #[allow(dead_code)]
    pub const ICC_NOT_PRESENT: u8 = 0x02;
}

/// CCID header size in bytes.
const CCID_HEADER_SIZE: usize = 10;

/// Maximum response size (should be enough for any PIV operation).
const MAX_RESPONSE_SIZE: usize = 4096;

/// USB timeout for operations.
const USB_TIMEOUT: Duration = Duration::from_secs(30);

/// Direct USB CCID transport for `YubiKey` communication.
///
/// Provides low-level APDU exchange with a `YubiKey` device over USB,
/// bypassing the need for pcscd or any smart card middleware.
pub struct CcidTransport {
    /// USB device handle.
    handle: DeviceHandle<Context>,
    /// Bulk OUT endpoint address.
    endpoint_out: u8,
    /// Bulk IN endpoint address.
    endpoint_in: u8,
    /// CCID sequence number (increments with each command).
    sequence: u8,
    /// Device serial number.
    serial: u32,
    /// Device firmware version.
    version: String,
    /// Whether the interface has been claimed.
    interface_claimed: bool,
    /// The interface number we claimed.
    interface_number: u8,
}

impl CcidTransport {
    /// Open a connection to the first available `YubiKey`.
    ///
    /// Scans USB devices for a `YubiKey` with CCID interface and opens it.
    ///
    /// # Errors
    ///
    /// Returns error if no `YubiKey` is found or USB operations fail.
    pub fn open() -> SigningResult<Self> {
        let context = Context::new().map_err(|e| {
            SigningError::YubiKeyError(format!("Failed to create USB context: {e}"))
        })?;

        // Find YubiKey device
        let devices = context.devices().map_err(|e| {
            SigningError::YubiKeyError(format!("Failed to enumerate USB devices: {e}"))
        })?;

        for device in devices.iter() {
            let desc = match device.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };

            if desc.vendor_id() == YUBIKEY_VID && YUBIKEY_PIDS.contains(&desc.product_id()) {
                log::debug!(
                    "Found YubiKey: VID={:04x} PID={:04x}",
                    desc.vendor_id(),
                    desc.product_id()
                );

                // Find CCID interface and endpoints
                let config = device.active_config_descriptor().map_err(|e| {
                    SigningError::YubiKeyError(format!("Failed to get config descriptor: {e}"))
                })?;

                for interface in config.interfaces() {
                    for desc in interface.descriptors() {
                        // CCID class is 0x0B (Smart Card)
                        if desc.class_code() == 0x0B {
                            let interface_number = desc.interface_number();

                            // Find bulk endpoints
                            let mut endpoint_in = None;
                            let mut endpoint_out = None;

                            for endpoint in desc.endpoint_descriptors() {
                                if endpoint.transfer_type() == rusb::TransferType::Bulk {
                                    if endpoint.direction() == rusb::Direction::In {
                                        endpoint_in = Some(endpoint.address());
                                    } else {
                                        endpoint_out = Some(endpoint.address());
                                    }
                                }
                            }

                            if let (Some(ep_in), Some(ep_out)) = (endpoint_in, endpoint_out) {
                                log::debug!(
                                    "CCID interface {interface_number} found: IN=0x{ep_in:02x} OUT=0x{ep_out:02x}"
                                );

                                let handle = device.open().map_err(|e| {
                                    SigningError::YubiKeyError(format!(
                                        "Failed to open USB device: {e}"
                                    ))
                                })?;

                                // Detach kernel driver if necessary (Linux)
                                #[cfg(target_os = "linux")]
                                {
                                    if handle
                                        .kernel_driver_active(interface_number)
                                        .unwrap_or(false)
                                    {
                                        handle.detach_kernel_driver(interface_number).map_err(
                                            |e| {
                                                SigningError::YubiKeyError(format!(
                                                    "Failed to detach kernel driver: {e}"
                                                ))
                                            },
                                        )?;
                                    }
                                }

                                // Claim the interface
                                handle.claim_interface(interface_number).map_err(|e| {
                                    SigningError::YubiKeyError(format!(
                                        "Failed to claim USB interface: {e}"
                                    ))
                                })?;

                                let mut transport = Self {
                                    handle,
                                    endpoint_out: ep_out,
                                    endpoint_in: ep_in,
                                    sequence: 0,
                                    serial: 0,
                                    version: String::new(),
                                    interface_claimed: true,
                                    interface_number,
                                };

                                // Power on the card
                                transport.power_on()?;

                                return Ok(transport);
                            }
                        }
                    }
                }
            }
        }

        Err(SigningError::YubiKeyError(
            "No YubiKey with CCID interface found".to_string(),
        ))
    }

    /// Power on the ICC (Integrated Circuit Card).
    ///
    /// Sends `PC_to_RDR_IccPowerOn` to activate the smart card interface.
    fn power_on(&mut self) -> SigningResult<Vec<u8>> {
        let mut cmd = [0u8; CCID_HEADER_SIZE];
        cmd[0] = message_type::PC_TO_RDR_ICC_POWER_ON;
        // dwLength = 0 (no data)
        cmd[5] = 0; // bSlot
        cmd[6] = self.next_sequence();
        cmd[7] = 0; // bPowerSelect: automatic voltage selection

        self.send_raw(&cmd)?;
        self.receive_response()
    }

    /// Send an APDU command and receive the response.
    ///
    /// # Arguments
    ///
    /// * `apdu` - The APDU command bytes to send
    ///
    /// # Returns
    ///
    /// The response data including status words (SW1, SW2).
    ///
    /// # Errors
    ///
    /// Returns error if USB transfer fails or response is malformed.
    pub fn transmit(&mut self, apdu: &[u8]) -> SigningResult<Vec<u8>> {
        // Build PC_to_RDR_XfrBlock message
        let data_len = apdu.len();
        let mut cmd = vec![0u8; CCID_HEADER_SIZE + data_len];

        cmd[0] = message_type::PC_TO_RDR_XFR_BLOCK;
        // dwLength (little-endian)
        cmd[1] = (data_len & 0xFF) as u8;
        cmd[2] = ((data_len >> 8) & 0xFF) as u8;
        cmd[3] = ((data_len >> 16) & 0xFF) as u8;
        cmd[4] = ((data_len >> 24) & 0xFF) as u8;
        cmd[5] = 0; // bSlot
        cmd[6] = self.next_sequence();
        cmd[7] = 0; // bBWI (Block Waiting Time Integer)
        cmd[8] = 0; // wLevelParameter
        cmd[9] = 0;

        // Copy APDU data
        cmd[CCID_HEADER_SIZE..].copy_from_slice(apdu);

        log::trace!("CCID TX: {:02x?}", &cmd);

        self.send_raw(&cmd)?;
        self.receive_response()
    }

    /// Send raw bytes to the bulk OUT endpoint.
    fn send_raw(&self, data: &[u8]) -> SigningResult<()> {
        let written = self.handle.write_bulk(self.endpoint_out, data, USB_TIMEOUT);

        match written {
            Ok(n) if n == data.len() => Ok(()),
            Ok(n) => Err(SigningError::YubiKeyError(format!(
                "Incomplete USB write: {n}/{} bytes",
                data.len()
            ))),
            Err(e) => Err(SigningError::YubiKeyError(format!("USB write failed: {e}"))),
        }
    }

    /// Receive and parse a CCID response.
    fn receive_response(&mut self) -> SigningResult<Vec<u8>> {
        let mut buf = vec![0u8; MAX_RESPONSE_SIZE];

        let read = self
            .handle
            .read_bulk(self.endpoint_in, &mut buf, USB_TIMEOUT)
            .map_err(|e| SigningError::YubiKeyError(format!("USB read failed: {e}")))?;

        if read < CCID_HEADER_SIZE {
            return Err(SigningError::YubiKeyError(format!(
                "Response too short: {read} bytes"
            )));
        }

        log::trace!("CCID RX: {:02x?}", &buf[..read]);

        let msg_type = buf[0];
        let data_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let slot_status = buf[7];
        let error_code = buf[8];

        // Check for errors
        if error_code != 0 {
            return Err(SigningError::YubiKeyError(format!(
                "CCID error: status=0x{slot_status:02x} error=0x{error_code:02x}"
            )));
        }

        match msg_type {
            message_type::RDR_TO_PC_DATA_BLOCK => {
                // Verify slot status
                if (slot_status & 0x03) != slot_status::ICC_PRESENT_ACTIVE {
                    return Err(SigningError::YubiKeyError(format!(
                        "Card not active: status=0x{slot_status:02x}"
                    )));
                }

                // Extract response data
                let response_start = CCID_HEADER_SIZE;
                let response_end = response_start + data_len;

                if response_end > read {
                    return Err(SigningError::YubiKeyError(format!(
                        "Response data truncated: expected {data_len} bytes, got {}",
                        read - CCID_HEADER_SIZE
                    )));
                }

                Ok(buf[response_start..response_end].to_vec())
            }
            message_type::RDR_TO_PC_SLOT_STATUS => {
                // Slot status response (from power on)
                // Return ATR if present
                let response_start = CCID_HEADER_SIZE;
                let response_end = response_start + data_len;
                Ok(buf[response_start..response_end].to_vec())
            }
            _ => Err(SigningError::YubiKeyError(format!(
                "Unexpected CCID message type: 0x{msg_type:02x}"
            ))),
        }
    }

    /// Get the next sequence number.
    fn next_sequence(&mut self) -> u8 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Get the device serial number (cached after first retrieval).
    ///
    /// # Errors
    ///
    /// Returns error if serial number cannot be retrieved.
    pub fn serial(&mut self) -> SigningResult<u32> {
        if self.serial == 0 {
            self.fetch_device_info()?;
        }
        Ok(self.serial)
    }

    /// Get the device firmware version (cached after first retrieval).
    ///
    /// # Errors
    ///
    /// Returns error if version cannot be retrieved.
    pub fn version(&mut self) -> SigningResult<String> {
        if self.version.is_empty() {
            self.fetch_device_info()?;
        }
        Ok(self.version.clone())
    }

    /// Fetch device info (serial and version) from the `YubiKey`.
    fn fetch_device_info(&mut self) -> SigningResult<()> {
        // Select PIV application first
        let select_piv = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
        let _ = self.transmit(&select_piv)?;

        // Get version (INS 0xFD)
        let get_version = [0x00, 0xFD, 0x00, 0x00, 0x00];
        let version_resp = self.transmit(&get_version)?;
        if version_resp.len() >= 5 {
            self.version = format!(
                "{}.{}.{}",
                version_resp[0], version_resp[1], version_resp[2]
            );
        }

        // Get serial (INS 0xF8)
        let get_serial = [0x00, 0xF8, 0x00, 0x00, 0x00];
        let serial_resp = self.transmit(&get_serial)?;
        if serial_resp.len() >= 6 {
            self.serial = u32::from_be_bytes([
                serial_resp[0],
                serial_resp[1],
                serial_resp[2],
                serial_resp[3],
            ]);
        }

        Ok(())
    }
}

impl Drop for CcidTransport {
    fn drop(&mut self) {
        // Power off the card
        let mut cmd = [0u8; CCID_HEADER_SIZE];
        cmd[0] = message_type::PC_TO_RDR_ICC_POWER_OFF;
        cmd[5] = 0; // bSlot
        cmd[6] = self.next_sequence();

        let _ = self.send_raw(&cmd);

        // Release the interface
        if self.interface_claimed {
            let _ = self.handle.release_interface(self.interface_number);
        }
    }
}
