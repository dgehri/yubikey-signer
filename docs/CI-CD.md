# CI/CD Documentation

This document explains the continuous integration and deployment setup for the YubiKey Signer project.

## Overview

The project uses GitHub Actions for CI/CD with three main workflows:

1. **CI Pipeline** (`ci.yml`) - Build, test, and quality checks
2. **Release Pipeline** (`release.yml`) - Automated releases on tags
3. **Security Pipeline** (`security.yml`) - Daily security audits

## Workflows Detail

### CI Pipeline (`.github/workflows/ci.yml`)

**Triggers:**

- Push to `main` or `develop` branches
- Pull requests to `main` branch

**Jobs:**

1. **Test Suite**
   - Runs on Ubuntu Latest
   - Formatting check with `cargo fmt`
   - Linting with `cargo clippy`
   - Unit/integration tests with `cargo test`
   - Documentation generation check

2. **Multi-Platform Build**
   - Matrix builds across Windows, Linux, macOS
   - Cross-compilation for different architectures
   - System dependency installation (PC/SC libraries)
   - Binary artifact upload for testing

3. **Security Audit**
   - Daily dependency vulnerability scanning
   - Uses `cargo audit` for security analysis
   - Results uploaded as artifacts

**Caching:**

- Rust toolchain and dependencies cached using `Swatinem/rust-cache@v2`
- Separate cache keys per platform and job type

### Release Pipeline (`.github/workflows/release.yml`)

**Triggers:**

- Git tags matching `v*.*.*` pattern (e.g., `v1.0.0`)

**Process:**

1. **Create Release**
   - Creates GitHub release with changelog
   - Provides download instructions for each platform

2. **Cross-Platform Binary Build**
   - Builds optimized release binaries for:
     - Windows (x86_64-pc-windows-msvc)
     - Linux (x86_64-unknown-linux-gnu)
     - macOS Intel (x86_64-apple-darwin)
     - macOS Apple Silicon (aarch64-apple-darwin)

3. **Asset Upload**
   - Uploads platform-specific binaries to GitHub release
   - Named with target triple for easy identification

4. **Crates.io Publishing** (Optional)
   - Publishes to Rust package registry
   - Requires `CARGO_REGISTRY_TOKEN` secret
   - Continues on error (won't fail release if publishing fails)

### Security Pipeline (`.github/workflows/security.yml`)

**Triggers:**

- Daily at 9 AM UTC
- Push/PR to main branch

**Features:**

1. **Security Audit**
   - Scans for known vulnerabilities in dependencies
   - Generates JSON reports for analysis
   - Uploads results as artifacts

2. **License Compliance**
   - Scans all dependencies for license compatibility
   - Generates license report
   - Helps ensure legal compliance

## Dependency Management

### Dependabot (`.github/dependabot.yml`)

**Configuration:**

- Weekly updates on Mondays at 9 AM
- Separate groups for security, development, and testing dependencies
- Automatic PR creation with reviewers assigned
- GitHub Actions dependencies also managed

**Groups:**

- `security`: OpenSSL, rustls, crypto-related dependencies
- `dev-dependencies`: Development-only dependencies
- `testing`: Test framework and assertion libraries

## Creating a Release

### Manual Process

1. **Prepare the Release**

   ```bash
   # Ensure you're on main and up to date
   git checkout main
   git pull origin main
   
   # Update version in Cargo.toml if needed
   # Update CHANGELOG.md with new features
   ```

2. **Create and Push Tag**

   ```bash
   # Create annotated tag
   git tag -a v1.0.0 -m "Release version 1.0.0"
   
   # Push tag to trigger release
   git push origin v1.0.0
   ```

3. **Monitor the Release**
   - GitHub Actions will automatically:
     - Build binaries for all platforms
     - Create GitHub release
     - Upload assets
     - Publish to crates.io (if configured)

### Automated Process

The release workflow handles:

- Cross-compilation for all supported platforms
- Binary optimization and verification
- Release notes generation
- Asset naming and upload
- Optional crates.io publishing

## Platform-Specific Notes

### Windows

- Uses MSVC toolchain for compatibility
- Requires no additional runtime dependencies
- Smart Card service automatically available

### Linux

- Installs PC/SC development libraries
- Builds against system OpenSSL
- Requires `pcscd` service at runtime

### macOS

- Builds for both Intel and Apple Silicon
- Uses Homebrew for system dependencies
- Built-in PC/SC support

## Security Considerations

### Secrets Management

Required secrets (configure in repository settings):

- `CARGO_REGISTRY_TOKEN`: For crates.io publishing
- `GITHUB_TOKEN`: Automatically provided by GitHub

### Dependency Security

- Daily automated security scans
- Vulnerability reports uploaded as artifacts
- Dependabot automatically creates PRs for security updates
- License compliance checking prevents problematic dependencies

### Build Security

- Reproducible builds using pinned dependency versions
- Multi-platform builds verify portability
- Artifact verification before upload
- No secrets or sensitive data in build logs

## Troubleshooting

### Build Failures

1. **System Dependencies**
   - Linux: Ensure `pkg-config`, `libssl-dev`, `libpcsclite-dev` available
   - macOS: Ensure Homebrew packages install correctly
   - Windows: MSVC toolchain issues

2. **Cross-Compilation Issues**
   - Target not installed: `rustup target add <target>`
   - Missing system libraries for target platform
   - Architecture-specific code issues

3. **Test Failures**
   - Currently tests are allowed to fail while migration to new type system is completed
   - See TODO.md for test suite migration status
   - Integration tests may require hardware that's not available in CI

### Release Issues

1. **Tag Creation Problems**
   - Ensure tag follows `v*.*.*` pattern
   - Check that tag is pushed to origin
   - Verify repository permissions

2. **Asset Upload Failures**
   - Check binary was built successfully
   - Verify GitHub token permissions
   - Ensure release was created properly

3. **Crates.io Publishing**
   - Token expired or invalid
   - Version already exists
   - Package metadata issues

## Monitoring and Maintenance

### Regular Tasks

- Review Dependabot PRs weekly
- Monitor security audit results
- Update CI workflows for new Rust versions
- Review and merge dependency updates

### Performance Monitoring

- Build times tracked across platforms
- Cache hit rates for dependencies
- Artifact sizes and download statistics

### Quality Metrics

- Test coverage reports (future enhancement)
- Code quality metrics via Clippy
- Documentation coverage
- Security vulnerability counts

## Future Enhancements

- [ ] Add test coverage reporting
- [ ] Implement semantic versioning automation
- [ ] Add performance benchmarking
- [ ] Container-based builds for consistency
- [ ] Codesigning for Windows binaries
- [ ] Integration with security scanning services
