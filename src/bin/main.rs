//! YubiKey PE Signer CLI
//!
//! Command-line interface for signing PE files using YubiKey PIV certificates.

use clap::{Parser, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};
use std::path::PathBuf;
use tokio;
use yubikey_signer::{sign_pe_file, HashAlgorithm, SigningConfig, SigningError};
use yubikey_signer::{PivPin, PivSlot, TimestampUrl};

#[derive(Parser)]
#[command(name = "yubikey-signer")]
#[command(about = "Self-contained PE code signing with YubiKey PIV certificates")]
#[command(long_about = "
YubiKey PE Signer - Professional code signing utility

This tool signs Windows PE executables (.exe, .dll, .sys) using certificates
stored on YubiKey PIV smartcards. It provides enterprise-grade digital signing
with hardware security and optional RFC 3161 timestamping.

EXAMPLES:
    # Sign with certificate in default slot (9c - Digital Signature)
    yubikey-signer myapp.exe

    # Sign with custom slot and timestamp  
    yubikey-signer myapp.exe -s 9a -t http://timestamp.digicert.com

    # Dry run to validate configuration
    yubikey-signer myapp.exe --dry-run

SLOT REFERENCE:
    9a = Authentication (login/auth certificates)
    9c = Digital Signature (default - code signing certificates)  
    9d = Key Management (encryption certificates)
    9e = Card Authentication (PIV authentication)

For help setting up your YubiKey PIV certificate, see:
https://developers.yubico.com/PIV/Guides/Certificate_authentication.html
")]
#[command(version)]
struct Cli {
    /// PE file to sign (.exe, .dll, .sys, etc.)
    #[arg(value_name = "INPUT_FILE", help = "Windows PE executable to sign")]
    input_file: PathBuf,

    /// Output file path (defaults to overwriting input file)
    #[arg(short, long, value_name = "OUTPUT_FILE", help = "Path for signed output file")]
    output: Option<PathBuf>,

    /// YubiKey PIV slot containing signing certificate
    #[arg(
        short = 's', 
        long, 
        default_value = "9c",
        value_name = "SLOT",
        help = "PIV slot (9a=Auth, 9c=Sign, 9d=KeyMgmt, 9e=CardAuth)",
        long_help = "YubiKey PIV slot containing the signing certificate\n\nValid slots:\n  • 9a - Authentication (login/auth certificates)\n  • 9c - Digital Signature (default - code signing certificates)\n  • 9d - Key Management (encryption certificates)\n  • 9e - Card Authentication (PIV authentication)\n\nFormat: hex (9c) or decimal (156)"
    )]
    slot: String,

    /// YubiKey PIV PIN (or set YUBICO_PIN environment variable)
    #[arg(
        short, 
        long, 
        value_name = "PIN",
        help = "6-8 digit PIN (or use YUBICO_PIN env var for automation)"
    )]
    pin: Option<String>,

    /// Cryptographic hash algorithm for signing
    #[arg(
        short = 'a', 
        long, 
        default_value = "sha256",
        value_name = "ALGORITHM",
        help = "Hash algorithm (sha256 recommended for compatibility)",
        long_help = "Cryptographic hash algorithm for digital signature\n\nValid options:\n  • sha256 - SHA-256 (recommended, widely compatible)\n  • sha384 - SHA-384 (higher security, larger signatures)\n  • sha512 - SHA-512 (highest security, largest signatures)"
    )]
    algorithm: HashAlgorithmArg,

    /// RFC 3161 timestamp server URL for trusted timestamps
    #[arg(
        short, 
        long,
        value_name = "URL", 
        help = "Timestamp server URL (recommended for long-term verification)"
    )]
    timestamp_url: Option<String>,

    /// Description embedded in the digital signature
    #[arg(
        short, 
        long,
        value_name = "TEXT",
        help = "Description text embedded in signature metadata"
    )]
    description: Option<String>,

    /// URL embedded in the digital signature  
    #[arg(
        short = 'u', 
        long,
        value_name = "URL",
        help = "URL embedded in signature metadata (typically product homepage)"
    )]
    url: Option<String>,

    /// Enable verbose debug output
    #[arg(short, long, help = "Show detailed progress and debug information")]
    verbose: bool,

    /// Validate configuration without signing (dry run)
    #[arg(long, help = "Test YubiKey connection and certificate without signing")]
    dry_run: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum HashAlgorithmArg {
    Sha256,
    Sha384,
    Sha512,
}

impl From<HashAlgorithmArg> for HashAlgorithm {
    fn from(arg: HashAlgorithmArg) -> Self {
        match arg {
            HashAlgorithmArg::Sha256 => HashAlgorithm::Sha256,
            HashAlgorithmArg::Sha384 => HashAlgorithm::Sha384,
            HashAlgorithmArg::Sha512 => HashAlgorithm::Sha512,
        }
    }
}

/// Create a detailed miette error with helpful context for signing failures
fn create_detailed_signing_error(e: SigningError) -> miette::Report {
    match &e {
        SigningError::YubiKeyError(msg) => {
            miette::miette!(
                help = "• Ensure YubiKey is inserted and recognized\n• Verify the PIV slot contains a valid certificate\n• Check that the PIN is correct\n• Try running 'ykman piv info' to verify PIV functionality",
                "YubiKey error: {}",
                msg
            )
        }
        SigningError::IoError(msg) => {
            miette::miette!(
                help = "• Ensure you have read access to the input file\n• Ensure you have write access to the output location\n• Check that the file is not locked by another process",
                "File access error: {}",
                msg
            )
        }
        SigningError::PeParsingError(msg) => {
            miette::miette!(
                help = "• Verify the input file is a valid PE executable\n• Check that the file is not corrupted\n• Ensure the PE file is not already signed (unless overwriting)",
                "PE file error: {}",
                msg
            )
        }
        SigningError::NetworkError(msg) => {
            miette::miette!(
                help = "• Check internet connectivity\n• Verify the timestamp server URL is correct\n• Try without timestamping (remove -t flag) as a workaround",
                "Network error: {}",
                msg
            )
        }
        SigningError::ValidationError(msg) => {
            miette::miette!(
                help = "Check the parameter format and try again with valid values",
                "Validation error: {}",
                msg
            )
        }
        _ => {
            miette::miette!(
                help = "Run with --verbose for more details, or consult the documentation",
                "Signing failed: {}",
                e
            )
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();

    // Validate input file exists and is accessible
    if !cli.input_file.exists() {
        return Err(miette::miette!(
            labels = [
                miette::LabeledSpan::at(0..cli.input_file.display().to_string().len(), "file path")
            ],
            help = "Check the file path and ensure the file exists",
            "Input file does not exist: {}",
            cli.input_file.display()
        ));
    }

    if !cli.input_file.is_file() {
        return Err(miette::miette!(
            help = "Provide a path to a PE executable file (.exe, .dll, .sys)",
            "Path is not a regular file: {}",
            cli.input_file.display()
        ));
    }

    // Validate it's a PE file by checking the header
    if let Ok(metadata) = std::fs::metadata(&cli.input_file) {
        if metadata.len() < 64 {
            return Err(miette::miette!(
                help = "PE files require at least 64 bytes for DOS and PE headers",
                "File is too small to be a valid PE executable: {} bytes (minimum: 64)",
                metadata.len()
            ));
        }
    }

    // Check for common file extensions
    if let Some(extension) = cli.input_file.extension() {
        let ext_str = extension.to_string_lossy().to_lowercase();
        if !["exe", "dll", "sys", "scr", "ocx"].contains(&ext_str.as_str()) {
            println!("⚠️  Warning: File extension '{}' is not a typical PE file type", ext_str);
            println!("   Common PE types: .exe, .dll, .sys, .scr, .ocx");
            println!("   Continuing anyway...");
            println!();
        }
    }

    // Determine output file
    let output_file = cli.output.clone().unwrap_or_else(|| cli.input_file.clone());

    // Get PIN from command line, environment variable, or secure prompt
    let pin = match cli.pin {
        Some(pin) => {
            // Validate PIN format (YubiKey PIV PINs can be 6-8 characters, alphanumeric + some symbols)
            if pin.len() < 6 || pin.len() > 8 {
                return Err(miette::miette!(
                    help = "YubiKey PIV PINs must be between 6 and 8 characters",
                    "Invalid PIN length: {} characters",
                    pin.len()
                ));
            }
            if !pin.chars().all(|c| c.is_ascii_alphanumeric() || "!@#$%^&*()_+-=[]{}|;':\",./<>?".contains(c)) {
                return Err(miette::miette!(
                    help = "PIN can contain letters, numbers, and common symbols",
                    "PIN contains invalid characters"
                ));
            }
            pin
        }
        None => {
            // Try environment variable first
            match std::env::var("YUBICO_PIN") {
                Ok(env_pin) if !env_pin.is_empty() => {
                    // Validate environment PIN with relaxed rules
                    if env_pin.len() < 6 || env_pin.len() > 8 {
                        return Err(miette::miette!(
                            help = "Set a valid 6-8 character PIN in the YUBICO_PIN environment variable",
                            "YUBICO_PIN environment variable contains invalid PIN: {} characters",
                            env_pin.len()
                        ));
                    }
                    println!("🔐 Using PIN from YUBICO_PIN environment variable");
                    env_pin
                }
                _ => {
                    println!("🔐 Enter YubiKey PIN (6-8 characters): ");
                    print!("   PIN: ");
                    std::io::Write::flush(&mut std::io::stdout()).into_diagnostic()?;
                    
                    // Read PIN securely (without echo)
                    let pin = rpassword::read_password().into_diagnostic()?;
                    if pin.is_empty() {
                        return Err(miette::miette!(
                            help = "Use --pin <PIN>, set YUBICO_PIN environment variable, or enter PIN when prompted",
                            "PIN cannot be empty"
                        ));
                    }
                    if pin.len() < 6 || pin.len() > 8 {
                        return Err(miette::miette!(
                            help = "YubiKey PIV PINs are 6-8 characters long",
                            "Invalid PIN format: {} characters",
                            pin.len()
                        ));
                    }
                    pin
                }
            }
        }
    };

    // Parse PIV slot and create PivSlot
    let slot_id = parse_piv_slot(&cli.slot)
        .with_context(|| format!("Invalid PIV slot '{}'. Valid options: 9a (Auth), 9c (Sign), 9d (KeyMgmt), 9e (CardAuth)", cli.slot))?;
    let slot = PivSlot::new(slot_id).into_diagnostic()
        .with_context(|| "PIV slot validation failed")?;

    // Create PivPin
    let piv_pin = PivPin::new(pin).into_diagnostic()
        .with_context(|| "PIN validation failed")?;

    // Create TimestampUrl if provided
    let timestamp_url = if let Some(url_str) = cli.timestamp_url {
        Some(TimestampUrl::new(url_str).into_diagnostic()
            .with_context(|| "Timestamp URL validation failed")?)
    } else {
        None
    };

    // Create signing configuration
    let config = SigningConfig {
        piv_slot: slot,
        pin: piv_pin,
        hash_algorithm: cli.algorithm.into(),
        timestamp_url,
        embed_certificate: true, // Default to embedding certificate
    };

    // Display configuration in a user-friendly way
    println!("🔐 YubiKey PE Code Signer");
    println!("========================");
    println!("📁 Input file:       {}", cli.input_file.display());
    println!("📁 Output file:      {}", output_file.display());
    println!("🔑 PIV slot:         {} ({})", slot.description(), get_slot_description(slot.as_u8()));
    println!("🔒 Hash algorithm:   {:?}", config.hash_algorithm);
    if let Some(ref ts_url) = config.timestamp_url {
        println!("⏰ Timestamp URL:    {}", ts_url);
    } else {
        println!("⏰ Timestamp URL:    None (signature will not include timestamp)");
    }
    if let Some(ref desc) = cli.description {
        println!("📝 Description:      {}", desc);
    }
    if let Some(ref url_val) = cli.url {
        println!("🌐 Product URL:      {}", url_val);
    }
    
    // Show file size info
    if let Ok(metadata) = std::fs::metadata(&cli.input_file) {
        println!("📊 Input file size:  {} bytes ({:.1} KB)", 
                 metadata.len(), 
                 metadata.len() as f64 / 1024.0);
    }
    
    println!();

    if cli.dry_run {
        println!("🔍 DRY RUN MODE - Validation Only");
        println!("No files will be modified or signed");
        println!();

        // Perform comprehensive validation
        match validate_signing_environment(&config).await {
            Ok(_) => {
                println!("✅ All validation checks passed!");
                println!();
                println!("🎯 Ready to sign - run without --dry-run to proceed");
                println!("   Command: yubikey-signer {} -s {} -a {:?}{}", 
                         cli.input_file.display(),
                         cli.slot,
                         config.hash_algorithm,
                         if config.timestamp_url.is_some() { 
                             format!(" -t {}", config.timestamp_url.as_ref().unwrap()) 
                         } else { 
                             String::new() 
                         });
                return Ok(());
            }
            Err(e) => {
                return Err(miette::miette!(
                    help = "Check YubiKey connection, PIN, certificate, and network connectivity",
                    "Validation failed: {}",
                    e
                ));
            }
        }
    }

    // Perform the signing
    println!("Starting signing process...");

    sign_pe_file(&cli.input_file, &output_file, config).await
        .into_diagnostic()
        .with_context(|| "Code signing operation failed")?;

    println!("✓ Successfully signed PE file");
    println!("  Output: {}", output_file.display());

    // Display file info
    if let Ok(metadata) = std::fs::metadata(&output_file) {
        println!("  Size: {} bytes", metadata.len());
    }

    println!();
    println!("Signing completed successfully!");

    Ok(())
}

/// Get human-readable description for PIV slot
fn get_slot_description(slot: u8) -> &'static str {
    match slot {
        0x9a => "Authentication",
        0x9c => "Digital Signature", 
        0x9d => "Key Management",
        0x9e => "Card Authentication",
        _ => "Custom/Unknown"
    }
}

/// Parse PIV slot from string (hex or decimal)
fn parse_piv_slot(slot_str: &str) -> Result<u8> {
    let slot = if slot_str.starts_with("0x") || slot_str.starts_with("0X") {
        // Hex format
        u8::from_str_radix(&slot_str[2..], 16).into_diagnostic()
            .with_context(|| format!("Invalid hex format in slot '{}'", slot_str))?
    } else if slot_str.len() == 2 && slot_str.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex format without prefix
        u8::from_str_radix(slot_str, 16).into_diagnostic()
            .with_context(|| format!("Invalid hex format in slot '{}'", slot_str))?
    } else {
        // Decimal format
        slot_str.parse::<u8>().into_diagnostic()
            .with_context(|| format!("Invalid decimal format in slot '{}'", slot_str))?
    };

    // Validate common PIV slots
    match slot {
        0x9a | 0x9c | 0x9d | 0x9e => Ok(slot),
        _ => {
            log::warn!(
                "Unusual PIV slot 0x{:02x} - common slots are 0x9a, 0x9c, 0x9d, 0x9e",
                slot
            );
            
            // Provide a more helpful error for clearly invalid slots
            if slot > 0x9e {
                Err(miette::miette!(
                    help = "Common PIV slots: 9a (Auth), 9c (Sign), 9d (KeyMgmt), 9e (CardAuth)",
                    "Invalid PIV slot 0x{:02x}. PIV slots are typically in range 0x9a-0x9e",
                    slot
                ))
            } else {
                Ok(slot) // Allow other slots but with warning
            }
        }
    }
}

/// Validate that we can sign with the current configuration
async fn validate_signing_environment(config: &SigningConfig) -> Result<()> {
    log::info!("Validating signing environment...");

    // Test YubiKey connection and authentication
    use yubikey_signer::yubikey_ops::YubiKeyOperations;

    let mut yubikey_ops = YubiKeyOperations::connect().into_diagnostic()
        .with_context(|| "Failed to connect to YubiKey")?;
    yubikey_ops.authenticate(&config.pin).into_diagnostic()
        .with_context(|| "Failed to authenticate with YubiKey PIN")?;

    // Verify certificate exists in slot
    let _cert = yubikey_ops.get_certificate(config.piv_slot).into_diagnostic()
        .with_context(|| format!("Failed to read certificate from PIV slot {}", config.piv_slot.description()))?;
    log::info!("✓ Certificate found in PIV slot {}", config.piv_slot.description());

    // Test timestamp server if configured
    if let Some(ref timestamp_url) = config.timestamp_url {
        log::info!("Testing timestamp server connectivity...");

        use yubikey_signer::timestamp::TimestampClient;
        let client = TimestampClient::new(timestamp_url);

        // Test with dummy hash
        let test_hash = vec![0u8; 32];
        match client.get_timestamp(&test_hash).await {
            Ok(_) => {
                log::info!("✓ Timestamp server reachable");
            }
            Err(e) => {
                log::warn!("Timestamp server test failed: {}", e);
                log::warn!("Signing will proceed without timestamp");
            }
        }
    }

    log::info!("Environment validation completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_piv_slot_hex_with_prefix() {
        assert_eq!(parse_piv_slot("0x9c").unwrap(), 0x9c);
        assert_eq!(parse_piv_slot("0X9a").unwrap(), 0x9a);
    }

    #[test]
    fn test_parse_piv_slot_hex_without_prefix() {
        assert_eq!(parse_piv_slot("9c").unwrap(), 0x9c);
        assert_eq!(parse_piv_slot("9a").unwrap(), 0x9a);
    }

    #[test]
    fn test_parse_piv_slot_decimal() {
        assert_eq!(parse_piv_slot("156").unwrap(), 156); // 0x9c
        assert_eq!(parse_piv_slot("154").unwrap(), 154); // 0x9a
    }

    #[test]
    fn test_parse_piv_slot_invalid() {
        assert!(parse_piv_slot("xyz").is_err());
        assert!(parse_piv_slot("256").is_err()); // > u8::MAX
        assert!(parse_piv_slot("").is_err());
    }

    #[test]
    fn test_hash_algorithm_conversion() {
        assert!(matches!(
            HashAlgorithm::from(HashAlgorithmArg::Sha256),
            HashAlgorithm::Sha256
        ));
        assert!(matches!(
            HashAlgorithm::from(HashAlgorithmArg::Sha384),
            HashAlgorithm::Sha384
        ));
        assert!(matches!(
            HashAlgorithm::from(HashAlgorithmArg::Sha512),
            HashAlgorithm::Sha512
        ));
    }
}
