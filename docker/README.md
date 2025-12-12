# Cross-Compilation Docker Setup

This directory contains Docker configuration for cross-compiling yubikey-signer binaries.

## Quick Start

```bash
# Build portable x86_64 Linux binaries (yubikey-signer + yubikey-proxy)
docker compose -f docker/docker-compose.yml run --rm build-x86_64-musl

# Build aarch64 proxy for ASUS routers (direct USB, no pcscd required)
docker compose -f docker/docker-compose.yml run --rm build-aarch64-direct-usb
```

Output binaries: `target-docker/<target>/release/`

## Available Dockerfiles

| Dockerfile                      | Target                          | Output          | Use Case                                      |
| ------------------------------- | ------------------------------- | --------------- | --------------------------------------------- |
| `Dockerfile.x86_64-musl`        | x86_64-unknown-linux-musl       | signer + proxy  | Portable Linux (works across distros)         |
| `Dockerfile.aarch64-direct-usb` | aarch64-unknown-linux-musl      | proxy only      | ASUS routers, embedded ARM64 (no pcscd)       |

## Architecture

### x86_64-musl (Linux portable)

- Base: `messense/rust-musl-cross:x86_64-musl`
- Links against musl libc for portability across Linux distributions
- Uses vendored OpenSSL (no system dependency)
- Requires `libpcsclite.so` (pcscd) at runtime for YubiKey access
- **Used in CI and release workflows**

### aarch64-direct-usb (Routers/Embedded)

- Base: `messense/rust-musl-cross:aarch64-musl`
- Cross-compiles libusb for direct USB communication
- **No pcscd required** - talks directly to YubiKey via USB CCID protocol
- Fully statically linked (except musl libc)
- **Used in CI and release workflows**

## Deployment to Router

See [docs/remote-signing.md](../docs/remote-signing.md) for complete deployment instructions.

### Quick Deploy (aarch64 direct-usb)

```powershell
# Build
docker compose -f docker/docker-compose.yml run --rm build-aarch64-direct-usb

# Deploy to router
$binary = Get-Content "target-docker/aarch64-unknown-linux-musl/release/yubikey-proxy" -Raw -AsByteStream
[Convert]::ToBase64String($binary) | ssh user@router "base64 -d > /jffs/yubikey-proxy && chmod +x /jffs/yubikey-proxy"
```

### Runtime Requirements (aarch64 direct-usb)

- Alpine's musl dynamic linker (`ld-musl-aarch64.so.1`) on the router
- USB access to YubiKey (no pcscd needed!)
- Environment variables:
  - `YUBIKEY_PROXY_TOKEN`: Bearer token for API authentication
  - `YUBICO_PIN`: PIN for YubiKey (or pass per-request)

## Troubleshooting

### Binary doesn't run on router

```bash
# Run with Alpine's musl linker
LD_LIBRARY_PATH=/jffs /jffs/ld-musl-aarch64.so.1 /jffs/yubikey-proxy --help
```

### "cannot find -lpcsclite" (x86_64-musl build)

The Dockerfile creates a stub library for linking. If you see this error, the Docker image wasn't built correctly. Try rebuilding:

```bash
docker compose -f docker/docker-compose.yml build --no-cache build-x86_64-musl
```
