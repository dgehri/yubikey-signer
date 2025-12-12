
# YubiKey Signer

Code signing utility for PE executables using YubiKey PIV certificates with OpenSSL-based Authenticode signatures. Supports local signing with a directly connected YubiKey or remote signing via an HTTP proxy server.

## Requirements

### Local Signing

- YubiKey with certificate in PIV slot
- Windows: PC/SC Smart Card service enabled
- Linux: pcscd service running (`sudo systemctl start pcscd`)
- macOS: No additional setup required

### Remote Signing

- Network access to a running `yubikey-proxy` server
- Authentication token matching the proxy configuration

## Usage

### Local Signing

Sign a file in-place (replaces the original):

```bash
yubikey-signer sign myapp.exe
```

Save signed file to a different location:

```bash
yubikey-signer sign myapp.exe -o myapp-signed.exe
```

### Remote Signing

Sign using a remote YubiKey proxy server:

```bash
yubikey-signer sign myapp.exe -o signed.exe --remote http://192.168.1.100:18443
```

With authentication token:

```bash
export YUBIKEY_PROXY_TOKEN="your-secret-token"
yubikey-signer sign myapp.exe -o signed.exe --remote http://proxy:18443
```

With custom HTTP headers (for reverse proxies like Cloudflare Access):

```bash
yubikey-signer sign myapp.exe -o signed.exe \
  --remote https://sign.example.com \
  --header "CF-Access-Client-Id: your-client-id.access" \
  --header "CF-Access-Client-Secret: your-client-secret"
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

**Local signing** - Set YubiKey PIN via environment variable:

```bash
export YUBICO_PIN=123456  # Linux/macOS
$env:YUBICO_PIN = "123456"  # Windows PowerShell
```

**Remote signing** - Set proxy authentication token:

```bash
export YUBIKEY_PROXY_TOKEN="your-secret-token"  # Linux/macOS
$env:YUBIKEY_PROXY_TOKEN = "your-secret-token"  # Windows PowerShell
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

The CLI provides four main commands:

- `sign` - Sign PE executables with YubiKey certificates (local or remote)
- `proxy` - Run a signing proxy server for remote signing
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
  -r, --remote <URL>        Remote signing proxy URL
      --header <HEADER>     Custom HTTP header (format: "Name: Value"), repeatable
      --dry-run             Preview signing without making changes
  -v, --verbose             Enable verbose output
  -h, --help                Print help
```

### Proxy Command

Start a signing proxy server (requires YubiKey connected to the host):

```text
yubikey-signer proxy [OPTIONS]

Options:
  -b, --bind <ADDR>   Bind address (default: 127.0.0.1:18443)
  -v, --verbose       Enable verbose output
  -h, --help          Print help

Environment:
  YUBICO_PIN            YubiKey PIN for signing operations
  YUBIKEY_PROXY_TOKEN   Required authentication token for clients
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

- `0x9a` (154): Authentication - Default slot for signing
- `0x9c` (156): Digital Signature - Primary slot for code signing
- `0x9d` (157): Key Management - Alternative signing slot
- `0x9e` (158): Card Authentication - Alternative signing slot

## Remote Signing Architecture

Remote signing allows code signing from machines without a directly connected YubiKey. The YubiKey remains connected to a secure server running the proxy.

```text
┌─────────────────┐         ┌─────────────────┐         ┌─────────────┐
│  Build Machine  │  HTTPS  │  Proxy Server   │   USB   │   YubiKey   │
│                 │ ──────► │  (yubikey-proxy)│ ──────► │             │
│  yubikey-signer │         │                 │         │  PIV Cert   │
│  --remote URL   │ ◄────── │  Port 18443     │ ◄────── │  Private Key│
└─────────────────┘         └─────────────────┘         └─────────────┘
```

### Proxy Server Setup

1. Connect YubiKey to the server
2. Set environment variables:

   ```bash
   export YUBICO_PIN="your-yubikey-pin"
   export YUBIKEY_PROXY_TOKEN="$(openssl rand -base64 36)"
   ```

3. Start the proxy:

   ```bash
   yubikey-signer proxy --bind 0.0.0.0:18443
   ```

4. For production, place behind a TLS-terminating reverse proxy (nginx, Caddy, Cloudflare Tunnel)

### Proxy API Endpoints

The proxy exposes these endpoints:

| Method | Path                  | Description                   |
| ------ | --------------------- | ----------------------------- |
| POST   | `/api/v1/status`      | Server and YubiKey status     |
| POST   | `/api/v1/certificate` | Get certificate from PIV slot |
| POST   | `/api/v1/sign`        | Sign a hash digest            |

All endpoints require the `Authorization: Bearer <token>` header.

### Security Considerations

- The proxy does not handle TLS directly; use a reverse proxy for HTTPS
- Generate a strong random token (minimum 32 bytes)
- Restrict network access to trusted clients
- The YubiKey PIN is stored server-side; clients only need the proxy token
- Consider additional authentication layers (VPN, Cloudflare Access, mTLS)

## CI and Release

CI builds and releases are tested for:

- `x86_64-pc-windows-msvc`
- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `aarch64-unknown-linux-musl` (proxy binary with direct USB support for embedded Linux)

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
