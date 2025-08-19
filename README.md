
# YubiKey Signer

Code signing utility for PE executables using YubiKey PIV certificates with OpenSSL-based Authenticode signatures.

## Requirements

1. YubiKey with certificate in PIV slot
2. Windows: PC/SC Smart Card service enabled
3. Linux: pcscd service running (`sudo systemctl start pcscd`)
4. macOS: No additional setup required

## Usage

### Basic Signing

Sign a file in-place (replaces the original):

```bash
yubikey-signer sign myapp.exe
```

Save signed file to a different location:

```bash
yubikey-signer sign myapp.exe -o myapp-signed.exe
```

### Timestamping

With timestamp server:

```bash
yubikey-signer sign myapp.exe --timestamp http://timestamp.digicert.com
```

Without timestamping (not recommended for production):

```bash
yubikey-signer sign myapp.exe --timestamp ""
```

### PIV Slot Selection

Specify a specific PIV slot:

```bash
yubikey-signer sign myapp.exe --slot 0x9c
```

### Discovery

Find suitable certificates on your YubiKey:

```bash
yubikey-signer discover
```

Get detailed certificate information:

```bash
yubikey-signer discover --detailed
```

### Configuration

View current configuration:

```bash
yubikey-signer config show
```

Initialize default configuration:

```bash
yubikey-signer config init
```

Set configuration values:

```bash
yubikey-signer config set default_piv_slot 0x9c
```

### Authentication

Set PIN via environment variable (recommended):

```bash
export YUBICO_PIN=123456  # Linux/macOS
$env:YUBICO_PIN = "123456"  # Windows PowerShell
```

## Installation

### Download Pre-built Binaries

Download from [GitHub Releases](https://github.com/dgehri/yubikey-signer/releases):

- **Windows**: `yubikey-signer-x86_64-pc-windows-msvc.exe`
- **Linux**: `yubikey-signer-x86_64-unknown-linux-gnu`
- **macOS (Intel)**: `yubikey-signer-x86_64-apple-darwin`
- **macOS (Apple Silicon)**: `yubikey-signer-aarch64-apple-darwin`

### Build from Source

#### Windows (Recommended: Automatic Setup)

```powershell
# Run the automated setup script (PowerShell as Administrator)
.\setup-windows-build.ps1

# Or use the batch file
.\setup-windows-build.bat

# Then build normally
cargo build --release
```

The setup script will automatically:

- Install vcpkg if not present (respects existing `VCPKG_ROOT`)
- Install OpenSSL via vcpkg
- Configure the build environment

#### Manual Windows Setup

If you already have vcpkg:

```bash
# Install OpenSSL via your existing vcpkg
vcpkg install openssl:x64-windows

# Set environment variable (if not already set)
set VCPKG_ROOT=C:\your\vcpkg\path

# Build normally
cargo build --release
```

#### Linux/macOS

```bash
# Uses system OpenSSL or vendored if system not available
cargo build --release

# Force vendored OpenSSL (requires dependencies)
cargo build --release --features vendored-openssl
```

## Verification

**Windows PowerShell** (optional):

```powershell
Get-AuthenticodeSignature myapp-signed.exe
```

## Command Line Interface

The CLI provides three main commands:

- `sign` - Sign PE executables with YubiKey certificates
- `discover` - Find and analyze certificates on your YubiKey  
- `config` - Manage application configuration

### Sign Command

```text
yubikey-signer sign [OPTIONS] <FILE>

Arguments:
  <FILE>  PE executable file to sign

Options:
  -o, --output <FILE>       Output file (default: sign in-place)
  -s, --slot <SLOT>         PIV slot (hex: 0x9c, 9c, or decimal: 156)
  -t, --timestamp [<URL>]   Timestamp server URL (default: http://ts.ssl.com)
      --dry-run             Preview signing without making changes
  -v, --verbose             Enable verbose output
  -h, --help                Print help
```

### Discover Command

```text
yubikey-signer discover [OPTIONS]

Options:
      --detailed   Show detailed certificate information
  -v, --verbose    Enable verbose output  
  -h, --help       Print help
```

### Config Command

```text
yubikey-signer config <SUBCOMMAND>

Subcommands:
  show      Display current configuration
  init      Create default configuration file
  set       Set configuration value
  export    Export configuration
  import    Import configuration
  help      Print help
```

## PIV Slots

Common YubiKey PIV slots for code signing:

- `0x9c` (156): Digital Signature - Primary slot for code signing
- `0x9a` (154): Authentication - Can be used for signing  
- `0x9d` (157): Key Management - Alternative signing slot
- `0x9e` (158): Card Authentication - Alternative signing slot

## CI and Release

CI builds and releases are tested for:

- `x86_64-pc-windows-msvc`
- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

## Security & License Compliance

Automated dependency scanning and license compliance is handled by `cargo-deny`, configured via `deny.toml`.

### Run Locally

```bash
cargo install cargo-deny

# Complete dependency compliance check (licenses, advisories, bans, sources)
cargo deny check

# Individual checks
cargo deny check licenses
cargo deny check advisories  
cargo deny check bans
cargo deny check sources
```

Ignored advisories are documented with justification and expiry inside `deny.toml`. Remove or update entries once upstream crates patch vulnerabilities.

CI GitHub Actions workflow runs these checks on pushes, pull requests, and a daily schedule; any new unignored vulnerability or disallowed license will fail the workflow.

## License

This project is licensed under the Apache License, Version 2.0. See the `LICENSE` file for details.

### Third-Party Components

This software includes third-party components under their respective licenses:

- **OpenSSL** (when using `--use-openssl` option): Apache License 2.0
  - Full license text in `LICENSE-OpenSSL`
  - Copyright and attribution notices in `THIRD-PARTY-NOTICES.md`
- **Other Rust dependencies**: Various permissive licenses
  - Run `cargo license` for a complete list

See `THIRD-PARTY-NOTICES.md` for complete attribution and license information for all third-party components.
