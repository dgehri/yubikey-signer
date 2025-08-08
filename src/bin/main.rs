//! Enhanced YubiKey PE Signer CLI with all improvements
//!
//! Command-line interface with certificate validation, auto-detection,
//! multiple timestamp servers, progress indicators, and configuration support.

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};
use std::path::PathBuf;
use yubikey_signer::{
    auto_detect::AutoDetection,
    config::{ConfigManager, ExportFormat},
    error::SigningError,
    progress::ProgressStyle,
    signing::{Signer, SigningOptions},
    HashAlgorithm, PivPin, PivSlot, SigningConfig, TimestampUrl,
};

#[derive(Parser)]
#[command(name = "yubikey-signer")]
#[command(about = "Enhanced PE code signing with YubiKey PIV certificates")]
#[command(long_about = "
YubiKey PE Signer - Code signing utility with advanced features

EXAMPLES:
    # Basic signing (auto-detects best certificate)
    yubikey-signer sign myapp.exe

    # Sign with specific slot and progress bar
    yubikey-signer sign myapp.exe -s 9c --progress bar

    # Discover available certificates
    yubikey-signer discover

    # Create configuration profile
    yubikey-signer config create-profile development

    # Test timestamp servers
    yubikey-signer test-timestamps

SLOT REFERENCE:
    9a = Authentication (default - most certificates stored here)
    9c = Digital Signature (code signing specific)  
    9d = Key Management (encryption, sometimes signing)
    9e = Card Authentication (PIV authentication)

ENVIRONMENT VARIABLES:
    YUBICO_PIN      YubiKey PIN (required)
    RUST_LOG        Logging level (debug, info, warn, error)
")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a PE file with enhanced features
    Sign {
        /// PE file to sign (.exe, .dll, .sys, etc.)
        #[arg(value_name = "INPUT_FILE")]
        input_file: PathBuf,

        /// Output file path (defaults to overwriting input file)
        #[arg(short, long, value_name = "OUTPUT_FILE")]
        output: Option<PathBuf>,

        /// PIV slot to use for signing
        #[arg(short, long, value_name = "SLOT_ID", default_value = "9a")]
        slot: String,

        /// Timestamp server URL (overrides config)
        #[arg(short, long, value_name = "URL")]
        timestamp_url: Option<String>,

        /// Hash algorithm to use
        #[arg(long, value_enum, default_value = "sha256")]
        hash: HashAlgorithmArg,

        /// Progress indicator style
        #[arg(long, value_enum)]
        progress: Option<ProgressStyleArg>,

        /// Disable progress indicators
        #[arg(long)]
        no_progress: bool,

        /// Skip certificate validation
        #[arg(long)]
        skip_validation: bool,

        /// Disable auto-detection fallback
        #[arg(long)]
        no_auto_detect: bool,

        /// Use basic timestamp client (disable enhanced features)
        #[arg(long)]
        basic_timestamps: bool,

        /// Dry run - validate configuration without signing
        #[arg(long)]
        dry_run: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Discover available YubiKey certificates and slots
    Discover {
        /// Show detailed certificate information
        #[arg(short, long)]
        detailed: bool,

        /// Test signing capability (requires PIN)
        #[arg(short, long)]
        test_signing: bool,
    },

    /// Test timestamp server connectivity
    TestTimestamps {
        /// Test specific server URL
        #[arg(short, long)]
        url: Option<String>,

        /// Show response details
        #[arg(short, long)]
        verbose: bool,
    },

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Verify signature of a signed PE file (uses PowerShell Get-AuthenticodeSignature)
    Verify {
        /// Signed PE file to verify
        #[arg(value_name = "SIGNED_FILE")]
        file: PathBuf,

        /// Show detailed signature information
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Create default configuration file
    Init,

    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },

    /// Export configuration
    Export {
        /// Export format
        #[arg(short, long, value_enum, default_value = "toml")]
        format: ExportFormatArg,
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import configuration
    Import {
        /// Configuration file to import
        file: PathBuf,
        /// Import format
        #[arg(short, long, value_enum, default_value = "toml")]
        format: ExportFormatArg,
    },

    /// Create a configuration profile
    CreateProfile {
        /// Profile name
        name: String,
        /// Profile description
        #[arg(short, long)]
        description: Option<String>,
    },

    /// List available profiles
    ListProfiles,

    /// Load a configuration profile
    LoadProfile {
        /// Profile name
        name: String,
    },
}

#[derive(ValueEnum, Clone)]
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

#[derive(ValueEnum, Clone)]
enum ProgressStyleArg {
    Percentage,
    Bar,
    Spinner,
    Silent,
}

impl From<ProgressStyleArg> for ProgressStyle {
    fn from(arg: ProgressStyleArg) -> Self {
        match arg {
            ProgressStyleArg::Percentage => ProgressStyle::Percentage,
            ProgressStyleArg::Bar => ProgressStyle::ProgressBar,
            ProgressStyleArg::Spinner => ProgressStyle::Spinner,
            ProgressStyleArg::Silent => ProgressStyle::Silent,
        }
    }
}

#[derive(ValueEnum, Clone)]
enum ExportFormatArg {
    Toml,
    Json,
    Yaml,
}

impl From<ExportFormatArg> for ExportFormat {
    fn from(arg: ExportFormatArg) -> Self {
        match arg {
            ExportFormatArg::Toml => ExportFormat::Toml,
            ExportFormatArg::Json => ExportFormat::Json,
            ExportFormatArg::Yaml => ExportFormat::Yaml,
        }
    }
}

/// Parameters for the sign command
struct SignCommandArgs {
    input_file: PathBuf,
    output: Option<PathBuf>,
    slot: String,
    timestamp_url: Option<String>,
    hash: HashAlgorithmArg,
    progress: Option<ProgressStyleArg>,
    no_progress: bool,
    skip_validation: bool,
    no_auto_detect: bool,
    basic_timestamps: bool,
    dry_run: bool,
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Sign {
            input_file,
            output,
            slot,
            timestamp_url,
            hash,
            progress,
            no_progress,
            skip_validation,
            no_auto_detect,
            basic_timestamps,
            dry_run,
            verbose,
        } => {
            let args = SignCommandArgs {
                input_file,
                output,
                slot,
                timestamp_url,
                hash,
                progress,
                no_progress,
                skip_validation,
                no_auto_detect,
                basic_timestamps,
                dry_run,
                verbose,
            };
            handle_sign_command(args).await?;
        }

        Commands::Discover {
            detailed,
            test_signing,
        } => {
            handle_discover_command(detailed, test_signing).await?;
        }

        Commands::TestTimestamps { url, verbose } => {
            handle_test_timestamps_command(url, verbose).await?;
        }

        Commands::Config(config_cmd) => {
            handle_config_command(config_cmd).await?;
        }

        Commands::Verify { file, verbose } => {
            handle_verify_command(file, verbose).await?;
        }
    }

    Ok(())
}

async fn handle_sign_command(args: SignCommandArgs) -> Result<()> {
    // Check if YUBICO_PIN is set
    let pin = std::env::var("YUBICO_PIN")
        .into_diagnostic()
        .context("YUBICO_PIN environment variable not set")?;

    // Parse slot
    let piv_slot = parse_piv_slot(&args.slot)
        .into_diagnostic()
        .context("Invalid PIV slot")?;

    // Determine output path
    let output_path = args.output.unwrap_or_else(|| args.input_file.clone());

    // Build signing configuration
    let mut options = if let Ok(_signer) = Signer::from_config_file() {
        if args.verbose {
            println!("📋 Loaded configuration from file");
        }
        // Override with command line arguments
        // Create enhanced signing options
        let mut opts = SigningOptions::default();
        opts.config.pin = PivPin::new(pin).into_diagnostic()?;
        opts.config.piv_slot = piv_slot;
        opts.config.hash_algorithm = args.hash.into();
        opts.verbose = args.verbose;
        opts
    } else {
        // Create default options
        let signing_config = SigningConfig {
            pin: PivPin::new(pin).into_diagnostic()?,
            piv_slot,
            timestamp_url: args
                .timestamp_url
                .as_ref()
                .map(|url| TimestampUrl::new(url.clone()).into_diagnostic())
                .transpose()?,
            hash_algorithm: args.hash.into(),
            embed_certificate: true,
        };

        SigningOptions {
            config: signing_config,
            show_progress: !args.no_progress,
            progress_style: args.progress.map(|p| p.into()),
            validate_certificate: !args.skip_validation,
            auto_detect_fallback: !args.no_auto_detect,
            use_enhanced_timestamps: !args.basic_timestamps,
            timestamp_config: None,
            verbose: args.verbose,
        }
    };

    // Override timestamp URL if provided
    if let Some(url) = &args.timestamp_url {
        options.config.timestamp_url = Some(TimestampUrl::new(url.clone()).into_diagnostic()?);
    }

    if args.dry_run {
        println!("🔍 Dry run mode - validating configuration");
        println!("  Input file: {}", args.input_file.display());
        println!("  Output file: {}", output_path.display());
        println!("  PIV slot: {}", options.config.piv_slot);
        println!(
            "  Hash algorithm: {}",
            options.config.hash_algorithm.as_str()
        );
        if let Some(ts_url) = &options.config.timestamp_url {
            println!("  Timestamp URL: {}", ts_url.as_str());
        }
        println!(
            "  Certificate validation: {}",
            if options.validate_certificate {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "  Auto-detection: {}",
            if options.auto_detect_fallback {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!("✅ Configuration is valid");
        return Ok(());
    }

    // Perform the signing
    let signer = Signer::new(options);

    match signer.sign_pe_file(&args.input_file, &output_path).await {
        Ok(result) => {
            println!("✅ File signed successfully!");
            println!("  Duration: {:.2}s", result.duration.as_secs_f64());
            println!("  File size: {} bytes", result.file_size);
            println!("  Slot used: {}", result.slot_used);

            if let Some(ref server) = result.timestamp_server_used {
                println!("  Timestamp server: {server}");
            }

            if !result.warnings.is_empty() {
                println!("\n⚠️  Warnings:");
                for warning in &result.warnings {
                    println!("  - {warning}");
                }
            }

            if args.verbose {
                if let Some(ref analysis) = result.certificate_analysis {
                    println!("\n📜 Certificate Analysis:");
                    println!("  Subject: {}", analysis.subject);
                    println!("  Issuer: {}", analysis.issuer);
                    println!("  Days until expiry: {}", analysis.days_until_expiry);
                    println!(
                        "  Code signing suitable: {}",
                        analysis.is_code_signing_suitable
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Signing failed: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn handle_discover_command(detailed: bool, test_signing: bool) -> Result<()> {
    println!("🔍 Discovering YubiKey certificates and capabilities...");

    // Check if YUBICO_PIN is set for authentication
    let pin = if test_signing {
        Some(
            std::env::var("YUBICO_PIN")
                .into_diagnostic()
                .context("YUBICO_PIN environment variable required for testing")?,
        )
    } else {
        std::env::var("YUBICO_PIN").ok()
    };

    // Connect to YubiKey
    let mut yubikey_ops = yubikey_signer::YubiKeyOperations::connect()
        .into_diagnostic()
        .context("Failed to connect to YubiKey")?;

    if let Some(pin_str) = pin {
        let piv_pin = PivPin::new(pin_str).into_diagnostic()?;
        yubikey_ops
            .authenticate(&piv_pin)
            .into_diagnostic()
            .context("Failed to authenticate with YubiKey")?;

        // Perform discovery
        let discovery = AutoDetection::discover_yubikey_capabilities(&mut yubikey_ops)
            .into_diagnostic()
            .context("Failed to discover YubiKey capabilities")?;

        println!("\n📊 Discovery Results:");
        println!(
            "  Total certificates found: {}",
            discovery.certificate_count
        );
        println!(
            "  Suitable for code signing: {}",
            discovery.suitable_slots.len()
        );

        if let Some(recommended) = discovery.recommended_slot {
            println!("  🏆 Recommended slot: {recommended}");
        }

        println!("\n📋 Slot Analysis:");
        for slot_info in &discovery.slots {
            print!("  Slot {}: ", slot_info.slot);

            if slot_info.has_certificate {
                if let Some(ref analysis) = slot_info.certificate_analysis {
                    if analysis.is_code_signing_suitable {
                        println!("✅ Suitable for code signing");
                        if detailed {
                            println!("    Subject: {}", analysis.subject);
                            println!("    Days until expiry: {}", analysis.days_until_expiry);
                            if !analysis.warnings.is_empty() {
                                for warning in &analysis.warnings {
                                    println!("    ⚠️  {warning}");
                                }
                            }
                        }
                    } else {
                        println!("❌ Not suitable for code signing");
                        if detailed {
                            for warning in &analysis.warnings {
                                println!("    - {warning}");
                            }
                        }
                    }
                } else {
                    println!("❓ Certificate analysis failed");
                }
            } else {
                println!("⭕ No certificate");
            }
        }

        if !discovery.warnings.is_empty() {
            println!("\n⚠️  Discovery Warnings:");
            for warning in &discovery.warnings {
                println!("  - {warning}");
            }
        }
    } else {
        println!("ℹ️  Set YUBICO_PIN environment variable for full discovery with authentication");
        println!("   Basic slot enumeration only (no certificate analysis):");

        // Basic enumeration without PIN
        let slots = [0x9a, 0x9c, 0x9d, 0x9e];
        for &slot_id in &slots {
            let slot = PivSlot::new(slot_id).unwrap();
            println!("  Slot {slot}: Present (authentication required for analysis)");
        }
    }

    Ok(())
}

async fn handle_test_timestamps_command(url: Option<String>, verbose: bool) -> Result<()> {
    println!("🌐 Testing timestamp server connectivity...");

    if let Some(url) = url {
        // Test specific URL
        let timestamp_url = TimestampUrl::new(url).into_diagnostic()?;
        let client = yubikey_signer::timestamp::TimestampClient::new(&timestamp_url);

        print!("Testing {}: ", timestamp_url.as_str());

        let test_data = b"timestamp_connectivity_test";
        match client.get_timestamp(test_data).await {
            Ok(_) => println!("✅ Success"),
            Err(e) => {
                println!("❌ Failed");
                if verbose {
                    println!("  Error: {e}");
                }
            }
        }
    } else {
        // Test all configured servers
        let client = yubikey_signer::timestamp::TimestampClient::default();
        let results = client.test_server_connectivity().await;

        println!("\n📊 Server Connectivity Results:");
        for (server, reachable, error) in results {
            print!("  {server}: ");
            if reachable {
                println!("✅ Reachable");
            } else {
                println!("❌ Failed");
                if verbose {
                    if let Some(err) = error {
                        println!("    Error: {err}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_config_command(config_cmd: ConfigCommands) -> Result<()> {
    let config_manager = ConfigManager::new().into_diagnostic()?;

    match config_cmd {
        ConfigCommands::Show => match config_manager.load() {
            Ok(config) => {
                println!("📋 Current Configuration:");
                println!("  Default PIV slot: 0x{:02x}", config.default_piv_slot);
                println!("  Hash algorithm: {}", config.default_hash_algorithm);
                println!(
                    "  Primary timestamp server: {}",
                    config.primary_timestamp_server
                );
                println!(
                    "  Fallback servers: {}",
                    config.fallback_timestamp_servers.len()
                );
                println!("  Embed certificate: {}", config.embed_certificate);
                println!("  Progress style: {}", config.progress_style);
                println!(
                    "  Configuration file: {}",
                    config_manager.config_path().display()
                );
            }
            Err(_) => {
                println!("📋 No configuration file found. Use 'config init' to create one.");
            }
        },

        ConfigCommands::Init => {
            let _config = config_manager.load_or_create_default().into_diagnostic()?;
            println!(
                "✅ Configuration initialized: {}",
                config_manager.config_path().display()
            );
            println!("   Edit the file to customize settings, or use 'config set' commands.");
        }

        ConfigCommands::Set { key, value } => {
            config_manager
                .update_value(&key, &value)
                .into_diagnostic()?;
            println!("✅ Configuration updated: {key} = {value}");
        }

        ConfigCommands::Export { format, output } => {
            let content = config_manager
                .export_config(format.into())
                .into_diagnostic()?;

            if let Some(output_path) = output {
                std::fs::write(&output_path, content).into_diagnostic()?;
                println!("✅ Configuration exported to: {}", output_path.display());
            } else {
                println!("{content}");
            }
        }

        ConfigCommands::Import { file, format } => {
            let content = std::fs::read_to_string(&file).into_diagnostic()?;
            config_manager
                .import_config(&content, format.into())
                .into_diagnostic()?;
            println!("✅ Configuration imported from: {}", file.display());
        }

        ConfigCommands::CreateProfile {
            name: _,
            description: _,
        } => {
            // This would require profile manager implementation
            println!("📁 Profile management not yet implemented in this demo");
        }

        ConfigCommands::ListProfiles => {
            println!("📁 Profile management not yet implemented in this demo");
        }

        ConfigCommands::LoadProfile { name: _ } => {
            println!("📁 Profile management not yet implemented in this demo");
        }
    }

    Ok(())
}

async fn handle_verify_command(file: PathBuf, verbose: bool) -> Result<()> {
    println!("🔍 Verifying signature using PowerShell Get-AuthenticodeSignature...");

    // Build PowerShell command
    let script_path = std::env::current_exe()
        .into_diagnostic()?
        .parent()
        .unwrap()
        .join("scripts")
        .join("verify_signature.ps1");

    if !script_path.exists() {
        println!(
            "❌ Verification script not found: {}",
            script_path.display()
        );
        println!(
            "   You can manually verify using: Get-AuthenticodeSignature '{}'",
            file.display()
        );
        return Ok(());
    }

    let mut cmd = std::process::Command::new("pwsh");
    cmd.arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path)
        .arg("-FilePath")
        .arg(&file);

    if verbose {
        cmd.arg("-Verbose");
    }

    let output = cmd.output().into_diagnostic()?;

    if output.status.success() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        eprintln!("❌ Verification failed:");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(1);
    }

    Ok(())
}

fn parse_piv_slot(slot_str: &str) -> Result<PivSlot, SigningError> {
    // Handle hex format (0x9a, 9a) and decimal format (154)
    let slot_value = if slot_str.starts_with("0x") || slot_str.starts_with("0X") {
        u8::from_str_radix(&slot_str[2..], 16)
            .map_err(|_| SigningError::ValidationError(format!("Invalid hex slot: {slot_str}")))?
    } else if slot_str.len() == 2 && slot_str.chars().all(|c| c.is_ascii_hexdigit()) {
        u8::from_str_radix(slot_str, 16)
            .map_err(|_| SigningError::ValidationError(format!("Invalid hex slot: {slot_str}")))?
    } else {
        slot_str
            .parse::<u8>()
            .map_err(|_| SigningError::ValidationError(format!("Invalid slot: {slot_str}")))?
    };

    PivSlot::new(slot_value)
}
