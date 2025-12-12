// Copyright 2025 Daniel Gehriger
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::match_same_arms,
    clippy::unused_async,
    clippy::missing_panics_doc,
    clippy::unnecessary_debug_formatting,
    clippy::no_effect_underscore_binding,
    clippy::needless_range_loop,
    clippy::float_cmp,
    clippy::items_after_statements,
    clippy::manual_let_else
)]
//!
//! Command-line interface with certificate validation, auto-detection,
//! multiple timestamp servers, progress indicators, and configuration support.

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};
use std::path::PathBuf;
use yubikey_signer::{
    adapters::remote::client::{RemoteSigner, RemoteSignerConfig},
    infra::config::{ConfigManager, ExportFormat},
    infra::error::SigningError,
    pipelines::sign::SignWorkflow,
    services::authenticode::OpenSslAuthenticodeSigner,
    services::auto_detect::AutoDetection,
    services::timestamp::TimestampClient,
    HashAlgorithm, PivPin, PivSlot, SigningConfig, TimestampUrl,
};

#[derive(Parser)]
#[command(name = "yubikey-signer")]
#[command(about = "Enhanced PE code signing with YubiKey PIV certificates")]
#[command(long_about = "
YubiKey PE Signer - Simple code signing utility

EXAMPLES:
    # Sign in-place (default behavior)
    yubikey-signer sign myapp.exe

    # Sign to different output file
    yubikey-signer sign myapp.exe -o myapp-signed.exe

    # Sign with specific slot
    yubikey-signer sign myapp.exe -s 9c

    # Sign with timestamp
    yubikey-signer sign myapp.exe -t http://timestamp.digicert.com

    # Sign with default timestamp server
    yubikey-signer sign myapp.exe -t

    # Discover available certificates
    yubikey-signer discover

    # Dry run to validate configuration
    yubikey-signer sign myapp.exe --dry-run

SLOT REFERENCE:
    9a = Authentication (default - most certificates stored here)
    9c = Digital Signature (code signing specific)  
    9d = Key Management (encryption, sometimes signing)
    9e = Card Authentication (PIV authentication)

    Valid formats: 0x9a, 9a, 154 (all refer to the same slot)

REMOTE SIGNING:
    For signing with a YubiKey on a remote machine (via yubikey-proxy):
    
    yubikey-signer sign myapp.exe --remote https://yubikey.example.com
    
    Set YUBIKEY_PROXY_TOKEN env var for authentication.

ENVIRONMENT VARIABLES:
    YUBICO_PIN          YubiKey PIN (required for local signing)
    YUBIKEY_PROXY_TOKEN Authentication token for remote proxy
")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a PE file
    Sign {
        /// PE file to sign (.exe, .dll, .sys, etc.)
        #[arg(value_name = "INPUT_FILE")]
        input_file: PathBuf,

        /// Output file path (defaults to overwriting input file)
        #[arg(short, long, value_name = "OUTPUT_FILE")]
        output: Option<PathBuf>,

        /// PIV slot to use for signing (hex: 0x9a, 9a; decimal: 154)
        #[arg(short, long, value_name = "SLOT", default_value = "9a")]
        slot: String,

        /// Timestamp server URL (use without value for default server)
        #[arg(short, long, value_name = "URL", num_args = 0..=1, default_missing_value = "http://ts.ssl.com")]
        timestamp: Option<String>,

        /// Remote `YubiKey` proxy URL (e.g., <https://yubikey.example.com>)
        #[arg(long, value_name = "URL", env = "YUBIKEY_PROXY_URL")]
        remote: Option<String>,

        /// Custom HTTP header for remote requests (can be repeated).
        /// Format: "Header-Name: value"
        /// Example: --header "CF-Access-Client-Id: xxx" --header "CF-Access-Client-Secret: yyy"
        #[arg(long = "header", value_name = "HEADER", action = clap::ArgAction::Append)]
        headers: Vec<String>,

        /// Dry run - validate configuration without signing
        #[arg(long)]
        dry_run: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Discover available `YubiKey` certificates and slots
    Discover {
        /// Show detailed certificate information
        #[arg(short, long)]
        detailed: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),
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
    timestamp: Option<String>,
    remote: Option<String>,
    headers: Vec<String>,
    dry_run: bool,
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbose flag
    let log_level = match &cli.command {
        Commands::Sign { verbose, .. } | Commands::Discover { verbose, .. } if *verbose => "debug",
        _ => "off", // No logging by default for clean output
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    match cli.command {
        Commands::Sign {
            input_file,
            output,
            slot,
            timestamp,
            remote,
            headers,
            dry_run,
            verbose,
        } => {
            let args = SignCommandArgs {
                input_file,
                output,
                slot,
                timestamp,
                remote,
                headers,
                dry_run,
                verbose,
            };
            handle_sign_command(args).await?;
        }

        Commands::Discover { detailed, verbose } => {
            handle_discover_command(detailed, verbose).await?;
        }

        Commands::Config(config_cmd) => {
            handle_config_command(config_cmd).await?;
        }
    }

    Ok(())
}

async fn handle_sign_command(args: SignCommandArgs) -> Result<()> {
    // Parse slot
    let piv_slot = parse_piv_slot(&args.slot)
        .into_diagnostic()
        .context("Invalid PIV slot")?;

    // Determine output path - default to in-place
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| args.input_file.clone());

    // Check if we're using remote signing (only if URL is non-empty)
    if let Some(ref remote_url) = args.remote {
        if !remote_url.is_empty() {
            return handle_remote_sign(&args, piv_slot, output_path, remote_url).await;
        }
    }

    // Local signing: Check if YUBICO_PIN is set
    let pin = std::env::var("YUBICO_PIN")
        .into_diagnostic()
        .context("YUBICO_PIN environment variable not set (required for local signing)")?;

    // Signing configuration
    let signing_config = SigningConfig {
        pin: PivPin::new(pin).into_diagnostic()?,
        piv_slot,
        timestamp_url: args
            .timestamp
            .map(TimestampUrl::new)
            .transpose()
            .into_diagnostic()?,
        hash_algorithm: HashAlgorithm::Sha256, // Auto-detected, this is just a default
        embed_certificate: true,
    };

    if args.dry_run {
        println!("🔍 Dry run mode - validating configuration");
        println!("  Input file: {}", args.input_file.display());
        println!("  Output file: {}", output_path.display());
        println!("  PIV slot: {}", signing_config.piv_slot);
        if let Some(ref ts_url) = signing_config.timestamp_url {
            println!("  Timestamp server: {}", ts_url.as_str());
        } else {
            println!("  Timestamp: disabled");
        }
        println!("✅ Configuration is valid");
        return Ok(());
    }

    if args.verbose {
        println!(
            "🔐 Signing {} with YubiKey slot {}",
            args.input_file.display(),
            signing_config.piv_slot
        );
    }

    let start_time = std::time::Instant::now();

    let workflow = SignWorkflow::new(signing_config.hash_algorithm);
    let config_clone = signing_config.clone();
    match workflow
        .sign_pe_file(&args.input_file, &output_path, signing_config)
        .await
    {
        Ok(()) => {
            let duration = start_time.elapsed();
            println!("✅ File signed successfully!");
            if args.verbose {
                println!("  Duration: {:.2}s", duration.as_secs_f64());
                let file_size = std::fs::metadata(&output_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                println!("  File size: {file_size} bytes");
                println!("  Slot used: {}", config_clone.piv_slot);
                if let Some(ref ts_url) = config_clone.timestamp_url {
                    println!("  Timestamp server: {}", ts_url.as_str());
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

async fn handle_discover_command(detailed: bool, verbose: bool) -> Result<()> {
    if verbose {
        println!("🔍 Discovering YubiKey certificates and capabilities...");
    }

    // Check if YUBICO_PIN is set for authentication
    let pin = std::env::var("YUBICO_PIN").ok();

    if let Some(pin_str) = pin {
        // Connect to YubiKey
        let mut yubikey_ops = yubikey_signer::YubiKeyOperations::connect()
            .into_diagnostic()
            .context("Failed to connect to YubiKey")?;

        let piv_pin = PivPin::new(pin_str).into_diagnostic()?;
        yubikey_ops
            .authenticate(&piv_pin)
            .into_diagnostic()
            .context("Failed to authenticate with YubiKey")?;

        // Perform discovery
        let discovery = AutoDetection::discover_yubikey_capabilities(&mut yubikey_ops)
            .into_diagnostic()
            .context("Failed to discover YubiKey capabilities")?;

        println!("📊 Discovery Results:");
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

        if !discovery.warnings.is_empty() && verbose {
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

/// Parse HTTP headers from command-line arguments.
///
/// Expected format: "Header-Name: value" or "Header-Name:value"
///
/// # Arguments
/// * `headers` - Vector of header strings from CLI
///
/// # Returns
/// Vector of (name, value) tuples
///
/// # Errors
/// Returns error if a header is malformed (missing colon).
fn parse_headers(headers: &[String]) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|h| {
            let parts: Vec<&str> = h.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(miette::miette!(
                    "Invalid header format: '{}'. Expected 'Header-Name: value'",
                    h
                ));
            }
            Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
        })
        .collect()
}

/// Handle remote signing via yubikey-proxy server.
///
/// This function connects to a remote yubikey-proxy server to perform
/// signing operations when the `YubiKey` is not locally attached.
///
/// # Arguments
/// * `args` - Sign command arguments
/// * `piv_slot` - Parsed PIV slot
/// * `output_path` - Output file path
/// * `remote_url` - Remote proxy URL
///
/// # Errors
/// Returns error if remote signing fails.
async fn handle_remote_sign(
    args: &SignCommandArgs,
    piv_slot: PivSlot,
    output_path: PathBuf,
    remote_url: &str,
) -> Result<()> {
    // Get proxy authentication token
    let auth_token = std::env::var("YUBIKEY_PROXY_TOKEN")
        .into_diagnostic()
        .context(
            "YUBIKEY_PROXY_TOKEN environment variable not set (required for remote signing)",
        )?;

    // Parse extra headers (format: "Header-Name: value")
    let extra_headers = parse_headers(&args.headers)?;

    if args.verbose {
        println!("🌐 Remote signing via {remote_url}");
        println!("  Input file: {}", args.input_file.display());
        println!("  Output file: {}", output_path.display());
        println!("  PIV slot: {piv_slot}");
        if !extra_headers.is_empty() {
            println!("  Custom headers: {}", extra_headers.len());
        }
    }

    if args.dry_run {
        println!("🔍 Dry run mode - validating remote configuration");
        println!("  Remote URL: {remote_url}");
        println!("  PIV slot: {piv_slot}");

        // Check remote connection
        let config =
            RemoteSignerConfig::new(remote_url, &auth_token).with_extra_headers(extra_headers);
        let client = RemoteSigner::new(config).into_diagnostic()?;
        let status = client.check_status().await.into_diagnostic()?;

        println!("  YubiKey ready: {}", status.yubikey_ready);
        if let Some(serial) = status.serial {
            println!("  Serial: {serial}");
        }
        println!("✅ Remote configuration is valid");
        return Ok(());
    }

    let start_time = std::time::Instant::now();

    // Read input file
    let pe_data = std::fs::read(&args.input_file)
        .into_diagnostic()
        .context("Failed to read input file")?;

    // Create remote signer client
    let config = RemoteSignerConfig::new(remote_url, &auth_token).with_extra_headers(extra_headers);
    let client = RemoteSigner::new(config).into_diagnostic()?;

    // Get certificate from remote YubiKey
    if args.verbose {
        println!("📜 Fetching certificate from remote YubiKey...");
    }
    let cert_der = client.get_certificate(piv_slot).await.into_diagnostic()?;

    // Create OpenSSL signer with remote certificate
    let openssl_signer = OpenSslAuthenticodeSigner::new(&cert_der, HashAlgorithm::Sha256)
        .into_diagnostic()
        .context("Failed to create signer with remote certificate")?;

    // Compute TBS (to-be-signed) hash locally with context
    // This computes the authenticated attributes and preserves them for later embedding.
    // Using context ensures the signingTime is identical in hash computation and final PKCS7.
    if args.verbose {
        println!("🔢 Computing TBS hash (authenticated attributes)...");
    }
    let tbs_context = openssl_signer
        .compute_tbs_hash_with_context(&pe_data)
        .into_diagnostic()?;

    // Sign TBS hash remotely
    if args.verbose {
        println!("✍️  Signing TBS hash remotely...");
    }
    let signature = client
        .sign_hash(&tbs_context.tbs_hash, piv_slot)
        .await
        .into_diagnostic()?;

    // Build PKCS7 locally with remote signature
    if args.verbose {
        println!("📦 Building PKCS7 structure...");
    }

    // Get timestamp if requested
    let timestamp_token = if let Some(ref ts_url) = args.timestamp {
        if args.verbose {
            println!("⏱️  Fetching timestamp from {ts_url}...");
        }
        let ts_url_typed = TimestampUrl::new(ts_url).into_diagnostic()?;
        let ts_client = TimestampClient::new(&ts_url_typed);
        Some(
            ts_client
                .get_timestamp(&signature)
                .await
                .into_diagnostic()?,
        )
    } else {
        None
    };

    // Create signed PE using preserved context (ensures signingTime matches)
    let signed_pe = openssl_signer
        .create_signed_pe_with_context(
            &pe_data,
            &tbs_context,
            &signature,
            timestamp_token.as_deref(),
        )
        .into_diagnostic()
        .context("Failed to create signed PE")?;

    // Write output
    std::fs::write(&output_path, &signed_pe)
        .into_diagnostic()
        .context("Failed to write output file")?;

    let duration = start_time.elapsed();
    println!("✅ File signed successfully (remote)!");
    if args.verbose {
        println!("  Duration: {:.2}s", duration.as_secs_f64());
        println!("  File size: {} bytes", signed_pe.len());
    }

    Ok(())
}
