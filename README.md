# YubiKey Signer

A production-ready Rust library and CLI tool for code signing PE executables using YubiKey PIV certificates, with support for RFC 3161 timestamping.

## Features

- **YubiKey PIV Integration**: Direct communication with YubiKey devices via PIV protocol
- **Authenticode PE Signing**: Full support for Microsoft Authenticode PE signature format
- **RFC 3161 Timestamping**: Automatic timestamping with configurable timestamp authorities
- **Self-Contained**: No external dependencies on Windows SDK or other signing tools
- **Cross-Platform**: Works on Windows, Linux, and macOS with automated builds
- **Type-Safe**: Compile-time validation for PIV slots, URLs, and other parameters
- **Beautiful Error Messages**: Detailed error messages with troubleshooting guidance using miette
- **Comprehensive Testing**: Automated CI/CD with security audits and multi-platform builds

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
    
    println!("Successfully signed PE file!");
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

## Current Status: Production Ready

✅ **This is a production-ready implementation with full CI/CD automation.**

### What Works

- ✅ YubiKey PIV connection and authentication with type safety
- ✅ Certificate retrieval and validation from YubiKey
- ✅ PIN authentication via command line, environment variable, or secure prompt
- ✅ Complete Authenticode PKCS#7 SignedData creation and PE embedding
- ✅ PE file signature embedding with proper checksum recalculation
- ✅ RFC 3161 timestamp server integration with full token parsing
- ✅ Multi-platform support (Windows, Linux, macOS)
- ✅ Comprehensive error handling with beautiful diagnostic messages
- ✅ Type-safe parameter validation at compile time
- ✅ Automated CI/CD with security audits and dependency updates
- ✅ Automated releases with pre-built binaries

### Continuous Integration

Our CI/CD pipeline ensures code quality and reliability:

- **Multi-Platform Builds**: Automated builds for Windows, Linux, and macOS
- **Security Audits**: Daily security scans using `cargo audit`
- **License Compliance**: Automated license checking and reporting  
- **Dependency Updates**: Automated dependency updates via Dependabot
- **Code Quality**: Automated formatting, linting, and testing
- **Release Automation**: Automatic binary releases when tags are pushed

### CI Status

| Build Status | Security | Dependencies |
|--------------|----------|--------------|
| ![CI](../../actions/workflows/ci.yml/badge.svg) | ![Security](../../actions/workflows/security.yml/badge.svg) | ![Dependabot](https://img.shields.io/badge/dependabot-active-brightgreen.svg) |

## Architecture

```rust
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│   Rust App      │───▶│   yubikey    │───▶│   YubiKey   │
│                 │    │   crate      │    │   PIV       │
└─────────────────┘    └──────────────┘    └─────────────┘
         │
         ▼
┌─────────────────┐    ┌──────────────┐
│  authenticode   │───▶│   goblin     │
│  (custom)       │    │   crate      │
└─────────────────┘    └──────────────┘
         │
         ▼
┌─────────────────┐    ┌──────────────┐
│   timestamp     │───▶│   reqwest    │
│   (custom)      │    │   crate      │
└─────────────────┘    └──────────────┘
```

## Building

```bash
# From the project root
cargo build --release

# The binary will be available at target/release/yubikey-signer (Linux/macOS)
# or target/release/yubikey-signer.exe (Windows)
```

## Usage Examples

```bash
# Using PIN from environment variable (recommended for automation)
export YUBICO_PIN="123456"  # Linux/macOS
$env:YUBICO_PIN="123456"    # PowerShell

yubikey-signer sign -i input.exe -o signed.exe -s 9c

# Interactive PIN entry (secure for manual use)
yubikey-signer sign -i input.exe -o signed.exe -s 9c

# With timestamp server for enhanced trust
yubikey-signer sign -i input.exe -o signed.exe -s 9c -t http://timestamp.digicert.com

# Verbose output for troubleshooting
yubikey-signer sign -i input.exe -o signed.exe -s 9c -v
```

## Comparison with Current Solution

| Aspect | Current (PowerShell + External Tools) | Rust Implementation |
|--------|---------------------------------------|-------------------|
| **Size** | ~10MB (osslsigncode + DLLs) | ~5MB (single executable) |
| **Dependencies** | 3 external binaries + DLLs | None (self-contained) |
| **Performance** | External process overhead | Direct system calls |
| **Error Handling** | Process exit codes | Rust Result<T,E> |
| **Cross-Platform** | Windows only | Windows/Linux/macOS |
| **Maintenance** | Multiple external tool versions | Single codebase |

## Implementation Status

### Phase 1: Core Infrastructure ✅

- [x] YubiKey PIV integration using `yubikey` crate
- [x] Certificate retrieval and validation
- [x] PIN authentication with secure handling
- [x] Digital signature generation
- [x] Type-safe parameter validation

### Phase 2: Authenticode Implementation ✅

- [x] PKCS#7 SignedData structure creation using `der` crate
- [x] PE file parsing and manipulation with `goblin` crate
- [x] Signature embedding in PE certificate table
- [x] PE checksum recalculation
- [x] Full Authenticode compliance

### Phase 3: RFC 3161 Timestamping ✅

- [x] Proper ASN.1 TimeStampReq creation
- [x] TimeStampResp parsing and validation
- [x] Timestamp token embedding in PKCS#7 structure
- [x] Multiple timestamp server support

### Phase 4: Production Readiness ✅

- [x] Comprehensive error handling with beautiful diagnostics
- [x] Cross-platform support (Windows, Linux, macOS)
- [x] Automated CI/CD pipeline
- [x] Security auditing and dependency management
- [x] Multi-architecture builds and releases
- [x] Extensive testing with various scenarios

### Future Enhancements (Optional)

- [ ] Multiple signature format support (MSI, MSP, etc.)
- [ ] Certificate chain validation
- [ ] Hardware security module (HSM) support beyond YubiKey
- [ ] GUI interface for non-technical users
- [ ] Integration with popular build systems

## Technical Challenges Solved

### 1. YubiKey PIV Direct Communication

The current solution uses `libykcs11.dll` through PKCS#11. The Rust version communicates directly with the YubiKey PIV applet:

```rust
use yubikey::{YubiKey, piv::*};

let mut yubikey = YubiKey::open()?;
yubikey.verify_pin(pin.as_bytes())?;
let certificate = yubikey.fetch_object(ObjectId::Authentication)?;
let signature = yubikey.sign_data(SlotId::Authentication, hash, AlgorithmId::Rsa2048)?;
```

### 2. PIN Automation

Maintains compatibility with the existing PIN automation approach:

```rust
let pin = env::var("YUBICO_PIN")
    .or_else(|_| matches.get_one::<String>("pin").map(String::from))
    .context("PIN required")?;
```

### 3. Error Handling

Rust's Result type provides better error handling than process exit codes:

```rust
fn sign_file(options: SigningOptions) -> Result<()> {
    let yubikey = YubiKey::open()
        .context("Failed to connect to YubiKey")?;
    // ... error context preserved through the entire chain
}
```

## Dependencies

The implementation uses these key crates:

- `yubikey` - Official Yubico Rust library for direct PIV communication
- `goblin` - PE file parsing and manipulation  
- `reqwest` - HTTP client for timestamp server communication
- `x509-cert` - X.509 certificate handling
- `der` - ASN.1 DER encoding/decoding
- `sha2` - SHA-256/384/512 hashing
- `clap` - Command-line interface with enhanced help
- `miette` - Beautiful error messages with diagnostic context
- `tokio` - Async runtime for HTTP operations

## Continuous Integration & Deployment

### Automated Workflows

- **CI Pipeline** (`.github/workflows/ci.yml`):
  - Multi-platform builds (Windows, Linux, macOS)
  - Code formatting and linting with Clippy
  - Comprehensive test suite execution
  - Documentation generation and validation

- **Release Pipeline** (`.github/workflows/release.yml`):
  - Triggered automatically on version tags (`v*.*.*`)
  - Cross-compilation for all supported platforms
  - Automatic GitHub release creation with binaries
  - Optional crates.io publishing

- **Security Pipeline** (`.github/workflows/security.yml`):
  - Daily security audits using `cargo audit`
  - License compliance checking
  - Dependency vulnerability scanning

### Dependency Management

- **Dependabot** (`.github/dependabot.yml`):
  - Weekly dependency updates
  - Security-focused dependency grouping
  - Automated pull requests for updates

### Creating a Release

To create a new release:

```bash
# Tag a new version (triggers automatic release)
git tag v1.0.0
git push origin v1.0.0

# The CI system will automatically:
# 1. Build binaries for all platforms
# 2. Create a GitHub release
# 3. Upload all binary assets
# 4. Optionally publish to crates.io
```

## Production Deployment

This implementation is production-ready and offers significant advantages over traditional solutions:

### Key Benefits

- **Simplified Deployment**: Single executable vs multiple external tools
- **Enhanced Reliability**: Direct API calls vs external process management  
- **Cross-Platform**: Same code works on Windows, Linux, and macOS
- **Type Safety**: Compile-time validation prevents common configuration errors
- **Modern Error Handling**: Beautiful diagnostic messages vs cryptic exit codes
- **Automated Updates**: CI/CD pipeline ensures security and quality
- **Zero Dependencies**: Self-contained binary with no external requirements

### Migration Path

Replace existing PowerShell/external tool chains with:

```bash
# Download the appropriate binary for your platform
curl -L -o yubikey-signer https://github.com/your-org/yubikey-signer/releases/latest/download/yubikey-signer-x86_64-unknown-linux-gnu

# Make executable (Linux/macOS)
chmod +x yubikey-signer

# Use in your build pipeline
./yubikey-signer sign -i myapp.exe -o myapp-signed.exe -s 9c -t http://timestamp.digicert.com
```

### Security Considerations

- PIN handling uses secure memory practices
- All dependencies are regularly audited for vulnerabilities
- Multi-platform builds are reproducible and verifiable
- No sensitive data is logged or persisted
- Certificate validation follows industry best practices

The implementation provides a robust, maintainable, and secure solution for code signing with YubiKey devices in production environments.
