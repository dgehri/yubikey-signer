# Cross-Compilation for aarch64-unknown-linux-musl

This directory contains Docker configuration for cross-compiling `yubikey-proxy` to run on ARM64 Linux systems (like ASUS routers with Entware).

## Quick Start

```powershell
# From the repository root - builds with pcsc-lite 2.3.3 for Entware compatibility
docker compose -f docker/docker-compose.yml run --rm build-aarch64-static-v2
```

The binary will be at: `target-docker/aarch64-unknown-linux-musl/release/yubikey-proxy`

## Available Build Targets

| Target                    | Command                      | Use Case                  |
| ------------------------- | ---------------------------- | ------------------------- |
| `build-aarch64`           | Basic musl with stub library | Generic deployment        |
| `build-aarch64-static-v2` | pcsc-lite 2.3.3 for Entware  | ASUS routers with Entware |
| `build-aarch64-gnu`       | glibc build                  | Systems with glibc 2.34+  |

## Architecture

The build uses `messense/rust-musl-cross:aarch64-musl` as the base image, which provides:

- Rust toolchain configured for aarch64-unknown-linux-musl
- musl cross-compiler (aarch64-unknown-linux-musl-gcc)
- OpenSSL will be built from source via `vendored-openssl` feature

### PCSC Library Handling

The `pcsc-sys` crate requires `libpcsclite` at compile time. We have two approaches:

**Stub library (build-aarch64):**
Creates a minimal stub that satisfies the linker. Requires runtime library.

**Real pcsc-lite (build-aarch64-static-v2):**
Cross-compiles pcsc-lite 2.3.3 with meson, matching Entware's version exactly.
The socket path is hardcoded to `/tmp/mnt/entware/entware/var/run/pcscd`.

## Deployment to Router

See [docs/remote-signing.md](../docs/remote-signing.md) for complete deployment instructions.

### Quick Deploy

```powershell
# Build
docker compose -f docker/docker-compose.yml run --rm build-aarch64-static-v2

# Deploy (requires Alpine musl runtime on router)
$binary = Get-Content "target-docker/aarch64-unknown-linux-musl/release/yubikey-proxy" -Raw -AsByteStream
[Convert]::ToBase64String($binary) | ssh user@router "base64 -d > /jffs/yubikey-proxy && chmod +x /jffs/yubikey-proxy"
```

### Runtime Requirements

The musl binary needs:

- Alpine's musl dynamic linker (`ld-musl-aarch64.so.1`)
- `libpcsclite.so.1` and `libpcsclite_real.so.1` (musl-compatible)
- `libgcc_s.so.1` (from Alpine)
- Running `pcscd` daemon (Entware: `opkg install pcscd ccid`)

## Environment Variables

The proxy requires these environment variables:

- `YUBICO_PIN`: PIN for the YubiKey (⚠️ should move to per-request)
- `YUBIKEY_PROXY_TOKEN`: Bearer token for API authentication
- `LD_LIBRARY_PATH`: Must include path to musl libraries (e.g., `/jffs`)

## Troubleshooting

### "cannot find -lpcsclite"

The Dockerfile creates a stub library. If you see this error, the Dockerfile wasn't built correctly.

### "Smart card resource manager has shut down"

Library version mismatch. Use `build-aarch64-static-v2` which builds pcsc-lite 2.3.3
to match Entware's pcscd version.

### Binary doesn't run on router

```bash
# Run with Alpine's musl linker
/jffs/ld-musl-aarch64.so.1.alpine /jffs/yubikey-proxy --help

# Check pcscd
pgrep pcscd || /opt/sbin/pcscd
```
