use anyhow::{Context, Result};
use clap::{Arg, Command};
use std::env;
use std::path::PathBuf;
use yubikey::{YubiKey, piv::*};

mod authenticode;
mod timestamp;
mod yubikey_ops;
mod types;

use crate::yubikey_ops::YubiKeyOperations;
use crate::types::{PivPin, PivSlot, TimestampUrl, SecurePath};

#[derive(Debug)]
pub struct SigningOptions {
    pub input_file: SecurePath,
    pub output_file: SecurePath,
    pub pin: PivPin,
    pub slot: PivSlot,
    pub timestamp_url: Option<TimestampUrl>,
    pub hash_algorithm: HashAlgorithm,
    pub dry_run: bool,
}

#[derive(Debug)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
        }
    }
}

fn main() -> Result<()> {
    let matches = Command::new("yubikey-signer")
        .version("0.1.0")
        .about("Self-contained YubiKey code signing utility")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Input file to sign")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output signed file (defaults to input file)"),
        )
        .arg(
            Arg::new("pin")
                .short('p')
                .long("pin")
                .value_name("PIN")
                .help("YubiKey PIN (can also use YUBICO_PIN env var)"),
        )
        .arg(
            Arg::new("timestamp-url")
                .short('t')
                .long("timestamp-url")
                .value_name("URL")
                .help("RFC 3161 timestamp server URL")
                .default_value("http://ts.ssl.com"),
        )
        .arg(
            Arg::new("hash")
                .short('h')
                .long("hash")
                .value_name("ALGORITHM")
                .help("Hash algorithm")
                .default_value("sha256"),
        )
        .arg(
            Arg::new("slot")
                .short('s')
                .long("slot")
                .value_name("SLOT")
                .help("PIV slot for certificate and signing (9a=Authentication, 9c=Signature)")
                .default_value("9a"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Perform dry run without writing output file")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let input_path = PathBuf::from(matches.get_one::<String>("input").unwrap());
    let output_path = matches
        .get_one::<String>("output")
        .map(PathBuf::from)
        .unwrap_or_else(|| input_path.clone());

    // Validate and create secure paths
    let input_file = SecurePath::new(input_path)
        .context("Invalid input file path")?;
    let output_file = SecurePath::new(output_path)
        .context("Invalid output file path")?;

    // Get PIN from command line or environment
    let pin_str = matches
        .get_one::<String>("pin")
        .map(String::from)
        .or_else(|| env::var("YUBICO_PIN").ok())
        .context("PIN must be provided via --pin argument or YUBICO_PIN environment variable")?;
    
    let pin = PivPin::new(pin_str)
        .context("Invalid PIN format")?;

    let timestamp_url = if let Some(url_str) = matches.get_one::<String>("timestamp-url") {
        Some(TimestampUrl::new(url_str)
            .with_context(|| format!("Invalid timestamp URL: {}", url_str))?)
    } else {
        None
    };
    
    let hash_algorithm = match matches.get_one::<String>("hash").unwrap().as_str() {
        "sha256" => HashAlgorithm::Sha256,
        other => anyhow::bail!("Unsupported hash algorithm: {}", other),
    };

    // Parse slot (hex string to PivSlot)
    let slot_str = matches.get_one::<String>("slot").unwrap();
    let slot_id = u8::from_str_radix(slot_str, 16)
        .with_context(|| format!("Invalid slot '{}'. Expected hex value like '9a' or '9c'", slot_str))?;
    let slot = PivSlot::new(slot_id)
        .with_context(|| format!("Invalid PIV slot: 0x{:02x}", slot_id))?;

    let dry_run = matches.get_flag("dry-run");

    let options = SigningOptions {
        input_file,
        output_file,
        pin,
        slot,
        timestamp_url,
        hash_algorithm,
        dry_run,
    };

    sign_file(options)?;
    
    Ok(())
}

#[tokio::main]
async fn sign_file(options: SigningOptions) -> Result<()> {
    println!("Connecting to YubiKey...");
    
    // Connect to YubiKey
    let mut yubikey = YubiKey::open()
        .context("Failed to connect to YubiKey. Make sure it's inserted and PIV applet is enabled.")?;

    println!("Authenticating with PIN...");
    
    // Verify PIN and get signing capability
    let yubikey_ops = YubiKeyOperations::new(&mut yubikey, &options.pin)
        .context("Failed to authenticate with YubiKey")?;

    println!("Reading certificate from YubiKey slot {}...", options.slot.description());
    
    // Get certificate from YubiKey PIV slot
    let certificate = yubikey_ops.get_certificate(&options.slot)
        .context("Failed to read certificate from YubiKey")?;

    println!("Reading input file: {:?}", options.input_file.as_path());
    
    // Read the file to be signed
    let file_data = std::fs::read(options.input_file.as_path())
        .with_context(|| format!("Failed to read input file: {:?}", options.input_file.as_path()))?;

    println!("Computing file hash...");
    
    // Create Authenticode signature
    let mut authenticode_signer = authenticode::AuthenticodeSigner::new(certificate);
    let file_hash = authenticode_signer.compute_pe_hash(&file_data)?;

    println!("Signing with YubiKey...");
    
    // Sign the hash using YubiKey
    let signature = yubikey_ops.sign_hash(&file_hash, &options.slot)
        .context("Failed to sign hash with YubiKey")?;

    // Get timestamp if requested
    let timestamp_token = if let Some(ts_url) = &options.timestamp_url {
        println!("Requesting timestamp from: {}", ts_url.as_str());
        Some(timestamp::get_timestamp(&file_hash, ts_url).await
            .context("Failed to get timestamp")?)
    } else {
        None
    };

    println!("Creating Authenticode signature...");
    
    // Create the complete Authenticode signature
    let signed_data = authenticode_signer.create_signed_pe(&file_data, &signature, timestamp_token.as_ref())
        .context("Failed to create signed PE file")?;

    if options.dry_run {
        println!("🔍 Dry run completed successfully - no file written");
        println!("✅ File would be signed and written to: {:?}", options.output_file.as_path());
    } else {
        println!("Writing signed file: {:?}", options.output_file.as_path());
        
        // Write signed file
        std::fs::write(options.output_file.as_path(), signed_data)
            .with_context(|| format!("Failed to write signed file: {:?}", options.output_file.as_path()))?;

        println!("✅ Successfully signed: {:?}", options.output_file.as_path());
    }
    
    Ok(())
}
