# YubiKey Signer

A Rust library and CLI tool for code signing PE executables using YubiKey PIV certificates, with support for RFC 3161 timestamping.

## Features

- **YubiKey PIV Integration**: Direct communication with YubiKey devices via PIV protocol
- **Authenticode PE Signing**: Full support for Microsoft Authenticode PE signature format
- **RFC 3161 Timestamping**: Automatic timestamping with configurable timestamp authorities
- **Self-Contained**: No external dependencies on Windows SDK or other signing tools
- **Cross-Platform**: Works on Windows, Linux, and macOS with automated builds

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases page](../../releases):

- **Windows**: `yubikey-signer-x86_64-pc-windows-msvc.exe`
- **Linux**: `yubikey-signer-x86_64-unknown-linux-gnu`
- **macOS (Intel)**: `yubikey-signer-x86_64-apple-darwin`
- **macOS (Apple Silicon)**: `yubikey-signer-aarch64-apple-darwin`

### Build from Source

```bash
# Prerequisites
- YubiKey with PIV-enabled firmware
- Valid code signing certificate loaded in PIV slot (typically 0x9c)
- Rust toolchain (1.70+)

# Clone and build
git clone <repository>
cd yubikey-signer
cargo build --release

# The binary will be available at target/release/yubikey-signer
```

## Quick Start

```bash
# Sign a PE file with PIN prompt
yubikey-signer sign --input myapp.exe --output myapp-signed.exe --slot 9c

# Sign with timestamp server (recommended for production)
yubikey-signer sign --input myapp.exe --output myapp-signed.exe --slot 9c --timestamp-url http://timestamp.digicert.com

# Sign with PIN from environment variable (secure)
export YUBICO_PIN="123456"
yubikey-signer sign --input myapp.exe --output myapp-signed.exe --slot 9c

# Get help with valid options
yubikey-signer sign --help

# Verify system is ready
yubikey-signer --version
```

## Library Usage

```rust
use yubikey_signer::{
    sign_pe_file, 
    types::{PivSlot, PivPin, TimestampUrl, SecurePath, HashData},
    error::SigningError
};

#[tokio::main]
async fn main() -> Result<(), SigningError> {
    // Type-safe parameter construction with validation
    let input = SecurePath::new("myapp.exe")?;
    let output = SecurePath::new("myapp_signed.exe")?;
    let slot = PivSlot::DigitalSignature; // 0x9c
    let pin = PivPin::new("123456")?;
    let timestamp_url = TimestampUrl::new("http://timestamp.digicert.com")?;
    
    // Sign the PE file
    sign_pe_file(
        &input,
        &output,
        slot,
        &pin,
        Some(&timestamp_url)
    ).await?;
    
    println!("PE file signed successfully");
    Ok(())
}
```

## Command Line Interface

```bash
yubikey-signer sign [OPTIONS]

Options:
  -i, --input <INPUT>                Input PE file to sign [required]
  -o, --output <OUTPUT>              Output signed PE file [required]
  -s, --slot <SLOT>                  PIV slot containing the signing certificate
                                     [default: 9c] [possible values: 9a, 9c, 9d, 9e]
  -p, --pin <PIN>                    PIV PIN (alternatively use YUBICO_PIN env var)
  -t, --timestamp-url <URL>          RFC 3161 timestamp server URL
                                     Examples: http://timestamp.digicert.com,
                                              http://ts.ssl.com,
                                              http://timestamp.comodoca.com
  -a, --hash-algorithm <ALGORITHM>   Hash algorithm for signing
                                     [default: sha256] [possible values: sha256, sha384, sha512]
  -v, --verbose                      Enable verbose output
  -h, --help                         Print help information
  -V, --version                      Print version information

Global Options:
      --color <WHEN>                 When to use colors [default: auto] [possible values: always, auto, never]

Examples:
  # Basic signing with PIN prompt
  yubikey-signer sign -i app.exe -o app-signed.exe -s 9c

  # With timestamp server (recommended)
  yubikey-signer sign -i app.exe -o app-signed.exe -s 9c -t http://timestamp.digicert.com

  # Using environment variable for PIN (secure)
  YUBICO_PIN=123456 yubikey-signer sign -i app.exe -o app-signed.exe -s 9c
```

## PIV Slots

Common YubiKey PIV slots for code signing:

- `0x9c` (156): Digital Signature - Primary slot for code signing
- `0x9a` (154): Authentication - Can be used for signing
- `0x9d` (157): Key Management - Alternative signing slot
- `0x9e` (158): Card Authentication - Alternative signing slot
