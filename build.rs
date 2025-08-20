use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // OpenSSL is required for Windows-compatible Authenticode signatures
    detect_and_configure_openssl();

    println!(
        "cargo:warning=Building with OpenSSL support for Windows-compatible Authenticode signatures"
    );
}

fn detect_and_configure_openssl() {
    // For Windows, always prioritize vcpkg OpenSSL as it's the most reliable
    if cfg!(target_os = "windows") {
        // Try vcpkg first - this is mandatory for Windows builds
        if try_vcpkg_openssl() {
            return;
        }

        // Only try other methods as fallback if vcpkg completely fails
        println!("cargo:warning=vcpkg OpenSSL setup failed, trying fallback methods...");

        // Try system OpenSSL as fallback
        if try_system_openssl() {
            return;
        }

        // Try to download and use prebuilt OpenSSL
        if try_prebuilt_openssl() {
            return;
        }
    } else {
        // For Unix systems, try system OpenSSL first
        if try_system_openssl() {
            return;
        }
    }

    // As last resort, show installation instructions and prevent vendored build
    // to avoid Perl dependency issues
    env::set_var("OPENSSL_NO_VENDOR", "1");
    println!("cargo:warning=OpenSSL not found and auto-installation failed");
    println!(
        "cargo:warning=For Windows, please install vcpkg and OpenSSL (see instructions below)"
    );
    setup_prebuilt_openssl().unwrap_or_else(|e| {
        println!("cargo:warning=Failed to create setup script: {e}");
    });
}

fn try_system_openssl() -> bool {
    // Try to find system OpenSSL without forcing OPENSSL_NO_VENDOR

    if cfg!(target_os = "windows") {
        // Check common Windows OpenSSL locations
        let windows_paths = [
            "C:\\OpenSSL-Win64",
            "C:\\Program Files\\OpenSSL-Win64",
            "C:\\Program Files\\OpenSSL",
            "C:\\OpenSSL",
            // vcpkg locations
            "C:\\vcpkg\\installed\\x64-windows",
            "C:\\tools\\vcpkg\\installed\\x64-windows",
            // Chocolatey locations
            "C:\\ProgramData\\chocolatey\\lib\\openssl\\tools\\openssl-win64",
            // MSYS2 locations
            "C:\\msys64\\mingw64",
            "C:\\msys64\\usr",
            // Git for Windows OpenSSL
            "C:\\Program Files\\Git\\mingw64",
            // Strawberry Perl OpenSSL (often bundled)
            "C:\\Strawberry\\c",
        ];

        for path in &windows_paths {
            let include_path = Path::new(path).join("include");

            // Also check for alternative lib directory names
            let alt_lib_paths = [
                Path::new(path).join("lib"),
                Path::new(path).join("lib64"),
                Path::new(path).join("libs"),
            ];

            for lib_path in &alt_lib_paths {
                if lib_path.exists() && include_path.exists() {
                    // Verify we have the actual OpenSSL files
                    let ssl_lib = lib_path.join("libssl.lib").exists()
                        || lib_path.join("ssl.lib").exists()
                        || lib_path.join("libssl.a").exists();
                    let crypto_lib = lib_path.join("libcrypto.lib").exists()
                        || lib_path.join("crypto.lib").exists()
                        || lib_path.join("libcrypto.a").exists();

                    if ssl_lib && crypto_lib {
                        println!("cargo:warning=Found OpenSSL at {path}");
                        env::set_var("OPENSSL_DIR", path);
                        env::set_var("OPENSSL_LIB_DIR", lib_path);
                        env::set_var("OPENSSL_INCLUDE_DIR", &include_path);
                        return true;
                    }
                }
            }
        }

        // Check if we have a working pkg-config setup (MSYS2, etc)
        if Command::new("pkg-config")
            .args(["--exists", "openssl"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            println!("cargo:warning=Found OpenSSL via pkg-config");
            return true;
        }

        false
    } else {
        // On Linux/macOS, try pkg-config first
        if Command::new("pkg-config")
            .args(["--exists", "openssl"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            println!("cargo:warning=Found OpenSSL via pkg-config");
            return true;
        }

        // Check common Linux/macOS system paths
        let unix_paths = [
            "/usr/include/openssl",
            "/usr/local/include/openssl",
            "/opt/homebrew/include/openssl",          // macOS ARM
            "/usr/local/opt/openssl/include/openssl", // macOS Intel
            "/usr/local/ssl/include/openssl",         // Custom builds
            "/opt/local/include/openssl",             // MacPorts
        ];

        for path in &unix_paths {
            if Path::new(path).exists() {
                let parent = Path::new(path).parent().unwrap().parent().unwrap();
                let lib_path = parent.join("lib");
                let lib64_path = parent.join("lib64");

                // Check if we have the library files
                if lib_path.exists() || lib64_path.exists() {
                    println!("cargo:warning=Found OpenSSL at {}", parent.display());
                    env::set_var("OPENSSL_DIR", parent);
                    return true;
                }
            }
        }

        false
    }
}

fn try_prebuilt_openssl() -> bool {
    if cfg!(target_os = "windows") {
        try_download_windows_openssl()
    } else {
        false // On Unix, rely on system OpenSSL or manual installation
    }
}

fn try_download_windows_openssl() -> bool {
    println!("cargo:warning=Attempting to setup OpenSSL via vcpkg...");

    // Try to use vcpkg to install OpenSSL automatically
    if try_vcpkg_openssl() {
        return true;
    }

    // If vcpkg fails, show manual installation instructions
    show_openssl_installation_instructions();
    false
}

fn try_vcpkg_openssl() -> bool {
    println!("cargo:warning=Attempting to use vcpkg OpenSSL (required for Windows builds)...");

    // First, find vcpkg installation (respecting existing VCPKG_ROOT)
    let vcpkg_root = if let Some(root) = get_vcpkg_root() {
        println!("cargo:warning=Found vcpkg at: {}", root.display());
        root
    } else {
        println!("cargo:warning=No vcpkg installation found, attempting automatic setup...");
        // Auto-install vcpkg if not found (only in development, not CI)
        if env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok() {
            println!("cargo:warning=CI environment - please install vcpkg manually");
            show_vcpkg_installation_instructions();
            return false;
        }
        match auto_install_vcpkg() {
            Ok(root) => {
                println!(
                    "cargo:warning=Successfully installed vcpkg at: {}",
                    root.display()
                );
                root
            }
            Err(e) => {
                println!("cargo:warning=Failed to auto-install vcpkg: {e}");
                show_vcpkg_installation_instructions();
                return false;
            }
        }
    };

    // Check if OpenSSL is already installed in vcpkg
    // Use static OpenSSL for all builds to avoid DLL dependencies
    let is_release = env::var("PROFILE").unwrap_or_default() == "release";
    let force_static = env::var("CARGO_FEATURE_STATIC_OPENSSL").is_ok();

    // Always prefer static linking now
    let use_static = true; // Changed from: is_release || force_static
    if use_static {
        if force_static {
            println!(
                "cargo:warning=static-openssl feature enabled - forcing static OpenSSL libraries"
            );
        } else if is_release {
            println!("cargo:warning=Release build detected - using static OpenSSL libraries");
        } else {
            println!(
                "cargo:warning=Debug build - using static OpenSSL libraries to avoid DLL dependencies"
            );
        }

        // Try static version first
        let static_openssl_dir = vcpkg_root.join("installed").join("x64-windows-static-md");
        if verify_vcpkg_openssl(&static_openssl_dir) {
            println!("cargo:warning=Found static vcpkg OpenSSL installation");
            configure_vcpkg_openssl(&static_openssl_dir);
            return true;
        }

        // Also try x64-windows-static variant
        let static_openssl_dir2 = vcpkg_root.join("installed").join("x64-windows-static");
        if verify_vcpkg_openssl(&static_openssl_dir2) {
            println!("cargo:warning=Found static vcpkg OpenSSL installation (x64-windows-static)");
            configure_vcpkg_openssl(&static_openssl_dir2);
            return true;
        }
    }

    // Check standard OpenSSL installation
    let openssl_dir = vcpkg_root.join("installed").join("x64-windows");
    if verify_vcpkg_openssl(&openssl_dir) {
        if is_release || force_static {
            println!("cargo:warning=Only dynamic OpenSSL found, but this may cause DLL dependencies in release builds");
        } else {
            println!("cargo:warning=Found existing vcpkg OpenSSL installation");
        }
        configure_vcpkg_openssl(&openssl_dir);
        return true;
    }

    // OpenSSL not found - try to install it
    println!("cargo:warning=vcpkg found but OpenSSL not installed, installing OpenSSL...");
    if install_openssl_in_vcpkg(&vcpkg_root) {
        // After installation, try to find the best version again
        if is_release || force_static {
            let static_openssl_dir = vcpkg_root.join("installed").join("x64-windows-static-md");
            if verify_vcpkg_openssl(&static_openssl_dir) {
                println!("cargo:warning=Successfully installed static OpenSSL via vcpkg");
                configure_vcpkg_openssl(&static_openssl_dir);
                return true;
            }
        }

        // Fallback to standard version
        let openssl_dir = vcpkg_root.join("installed").join("x64-windows");
        if verify_vcpkg_openssl(&openssl_dir) {
            println!("cargo:warning=Successfully installed OpenSSL via vcpkg");
            configure_vcpkg_openssl(&openssl_dir);
            return true;
        }
    }

    println!("cargo:warning=Failed to install OpenSSL in vcpkg");
    false
}

fn get_vcpkg_root() -> Option<std::path::PathBuf> {
    // MUST respect existing VCPKG_ROOT environment variable first
    if let Ok(vcpkg_root) = env::var("VCPKG_ROOT") {
        let path = Path::new(&vcpkg_root);
        if path.exists() && path.join("vcpkg.exe").exists() {
            println!(
                "cargo:warning=Using VCPKG_ROOT from environment: {}",
                path.display()
            );
            return Some(path.to_path_buf());
        }
        println!("cargo:warning=VCPKG_ROOT is set but invalid: {vcpkg_root}");
    }

    // Check CI-specific environment variables
    if let Ok(vcpkg_installation_root) = env::var("VCPKG_INSTALLATION_ROOT") {
        let path = Path::new(&vcpkg_installation_root);
        if path.exists() && path.join("vcpkg.exe").exists() {
            println!(
                "cargo:warning=Using VCPKG_INSTALLATION_ROOT: {}",
                path.display()
            );
            return Some(path.to_path_buf());
        }
    }

    // Check common installation locations
    let common_paths = [
        "C:\\vcpkg",
        "C:\\tools\\vcpkg",
        "C:\\dev\\vcpkg",
        &format!("{}\\vcpkg", env::var("USERPROFILE").unwrap_or_default()),
        "D:\\vcpkg", // Alternative drive
        "E:\\vcpkg", // Alternative drive
    ];

    for path_str in &common_paths {
        let path = Path::new(path_str);
        if path.exists() && path.join("vcpkg.exe").exists() {
            println!(
                "cargo:warning=Found vcpkg at common location: {}",
                path.display()
            );
            return Some(path.to_path_buf());
        }
    }

    None
}

fn auto_install_vcpkg() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    println!("cargo:warning=Auto-installing vcpkg for Windows OpenSSL support...");

    let vcpkg_dir = Path::new("C:\\vcpkg");

    // Install vcpkg if it doesn't exist
    if !vcpkg_dir.exists() {
        println!("cargo:warning=Cloning vcpkg repository...");
        let status = Command::new("git")
            .args([
                "clone",
                "https://github.com/Microsoft/vcpkg.git",
                "C:\\vcpkg",
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to clone vcpkg repository".into());
        }

        println!("cargo:warning=Bootstrapping vcpkg...");
        let status = Command::new("C:\\vcpkg\\bootstrap-vcpkg.bat")
            .current_dir(vcpkg_dir)
            .status()?;

        if !status.success() {
            return Err("Failed to bootstrap vcpkg".into());
        }
    }

    // Set VCPKG_ROOT for this build and future builds
    env::set_var("VCPKG_ROOT", "C:\\vcpkg");

    Ok(vcpkg_dir.to_path_buf())
}

fn install_openssl_in_vcpkg(vcpkg_root: &Path) -> bool {
    println!("cargo:warning=Installing OpenSSL via vcpkg (this may take several minutes)...");

    let vcpkg_exe = vcpkg_root.join("vcpkg.exe");

    // First ensure vcpkg is integrated for MSBuild (helps with some issues)
    let _ = Command::new(&vcpkg_exe)
        .args(["integrate", "install"])
        .current_dir(vcpkg_root)
        .status();

    // Always prioritize static linking to avoid DLL dependencies
    let is_release = env::var("PROFILE").unwrap_or_default() == "release";
    let force_static = env::var("CARGO_FEATURE_STATIC_OPENSSL").is_ok();

    // Always use static linking now
    let use_static = true; // Changed from: is_release || force_static
    if use_static {
        if force_static {
            println!("cargo:warning=static-openssl feature enabled - installing static OpenSSL libraries");
        } else if is_release {
            println!("cargo:warning=Release build detected - installing static OpenSSL libraries");
        } else {
            println!("cargo:warning=Debug build - installing static OpenSSL libraries to avoid DLL dependencies");
        }

        // Install static version first for all builds
        let status_static = Command::new(&vcpkg_exe)
            .args(["install", "openssl:x64-windows-static-md"])
            .current_dir(vcpkg_root)
            .status();

        match status_static {
            Ok(status) if status.success() => {
                println!("cargo:warning=Successfully installed static OpenSSL via vcpkg");
                return true;
            }
            Ok(_) => {
                println!("cargo:warning=Static OpenSSL install failed, trying alternatives...");
            }
            Err(e) => println!("cargo:warning=Failed to install static OpenSSL: {e}"),
        }
    }

    // Install both standard and static-md for compatibility
    let status1 = Command::new(&vcpkg_exe)
        .args(["install", "openssl:x64-windows"])
        .current_dir(vcpkg_root)
        .status();

    let status2 = Command::new(&vcpkg_exe)
        .args(["install", "openssl:x64-windows-static-md"])
        .current_dir(vcpkg_root)
        .status();

    match (status1, status2) {
        (Ok(s1), Ok(s2)) if s1.success() || s2.success() => {
            println!("cargo:warning=Successfully installed OpenSSL via vcpkg");
            true
        }
        (Ok(s1), Ok(s2)) => {
            println!(
                "cargo:warning=vcpkg install failed - x64-windows: {}, x64-windows-static-md: {}",
                s1.success(),
                s2.success()
            );
            false
        }
        (Err(e1), _) => {
            println!("cargo:warning=Failed to run vcpkg install x64-windows: {e1}");
            false
        }
        (_, Err(e2)) => {
            println!("cargo:warning=Failed to run vcpkg install x64-windows-static-md: {e2}");
            false
        }
    }
}

fn show_vcpkg_installation_instructions() {
    println!("cargo:warning=");
    println!("cargo:warning=============================================================");
    println!("cargo:warning=vcpkg + OpenSSL Installation Required");
    println!("cargo:warning=============================================================");
    println!("cargo:warning=");
    println!("cargo:warning=For Windows builds, vcpkg + OpenSSL is required.");
    println!("cargo:warning=");
    println!("cargo:warning=Quick Installation:");
    println!("cargo:warning=  1. Install vcpkg:");
    println!("cargo:warning=     git clone https://github.com/Microsoft/vcpkg.git C:\\vcpkg");
    println!("cargo:warning=     C:\\vcpkg\\bootstrap-vcpkg.bat");
    println!("cargo:warning=");
    println!("cargo:warning=  2. Install OpenSSL:");
    println!("cargo:warning=     C:\\vcpkg\\vcpkg install openssl:x64-windows");
    println!("cargo:warning=");
    println!("cargo:warning=  3. Set environment variable (optional):");
    println!("cargo:warning=     set VCPKG_ROOT=C:\\vcpkg");
    println!("cargo:warning=");
    println!("cargo:warning=Alternative: Use existing VCPKG_ROOT if you have vcpkg elsewhere");
    println!("cargo:warning=============================================================");
}

fn verify_vcpkg_openssl(vcpkg_installed_dir: &Path) -> bool {
    let lib_dir = vcpkg_installed_dir.join("lib");
    let include_dir = vcpkg_installed_dir.join("include").join("openssl");

    // Check for OpenSSL libraries
    let has_libs = lib_dir.exists()
        && ((lib_dir.join("libssl.lib").exists() && lib_dir.join("libcrypto.lib").exists())
            || (lib_dir.join("ssl.lib").exists() && lib_dir.join("crypto.lib").exists()));

    let has_headers = include_dir.exists() && include_dir.join("opensslv.h").exists();

    has_libs && has_headers
}

fn configure_vcpkg_openssl(openssl_dir: &Path) {
    let lib_dir = openssl_dir.join("lib");
    let include_dir = openssl_dir.join("include");

    println!("cargo:warning=Successfully configured vcpkg OpenSSL:");
    println!("cargo:warning=  OPENSSL_DIR={}", openssl_dir.display());
    println!("cargo:warning=  OPENSSL_LIB_DIR={}", lib_dir.display());
    println!(
        "cargo:warning=  OPENSSL_INCLUDE_DIR={}",
        include_dir.display()
    );

    // Set OpenSSL environment variables for the build
    env::set_var("OPENSSL_DIR", openssl_dir);
    env::set_var("OPENSSL_LIB_DIR", &lib_dir);
    env::set_var("OPENSSL_INCLUDE_DIR", &include_dir);

    // Disable vendored build since we have vcpkg OpenSSL
    env::set_var("OPENSSL_NO_VENDOR", "1");

    // Determine if this is a static build based on the path
    let is_static = openssl_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("static"));

    // Ensure VCPKG_ROOT is set for this build (but don't override existing)
    if env::var("VCPKG_ROOT").is_err() {
        if let Some(vcpkg_root) = openssl_dir.parent().and_then(|p| p.parent()) {
            println!(
                "cargo:warning=  Setting VCPKG_ROOT={}",
                vcpkg_root.display()
            );
            env::set_var("VCPKG_ROOT", vcpkg_root);
        }
    } else {
        println!(
            "cargo:warning=  Using existing VCPKG_ROOT={}",
            env::var("VCPKG_ROOT").unwrap()
        );
    }

    // Tell Cargo to link against the vcpkg OpenSSL libraries
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    if is_static {
        println!("cargo:warning=  Configuring STATIC OpenSSL linking");
        println!("cargo:rustc-link-lib=static=libssl");
        println!("cargo:rustc-link-lib=static=libcrypto");

        // Required system libraries for static OpenSSL on Windows
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=user32");

        // Additional libraries required for static linking
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ncrypt");
    } else {
        println!(
            "cargo:warning=  Configuring DYNAMIC OpenSSL linking (may cause DLL dependencies)"
        );
        println!("cargo:rustc-link-lib=libssl");
        println!("cargo:rustc-link-lib=libcrypto");
    }
}

fn show_openssl_installation_instructions() {
    println!("cargo:warning=");
    println!("cargo:warning======================================================");
    println!("cargo:warning=OpenSSL Installation Required");
    println!("cargo:warning======================================================");
    println!("cargo:warning=");
    println!("cargo:warning=The yubikey-signer requires OpenSSL for Windows-compatible");
    println!("cargo:warning=Authenticode signatures. Auto-installation failed.");
    println!("cargo:warning=");
    println!("cargo:warning=OPTION 1: Manual vcpkg installation (RECOMMENDED)");
    println!("cargo:warning=  1. Open PowerShell as Administrator");
    println!("cargo:warning=  2. Run: git clone https://github.com/Microsoft/vcpkg.git C:\\vcpkg");
    println!("cargo:warning=  3. Run: C:\\vcpkg\\bootstrap-vcpkg.bat");
    println!("cargo:warning=  4. Run: C:\\vcpkg\\vcpkg install openssl:x64-windows");
    println!("cargo:warning=  5. Set: $env:VCPKG_ROOT = \"C:\\vcpkg\"");
    println!("cargo:warning=  6. Rebuild with: cargo build --release");
    println!("cargo:warning=");
    println!("cargo:warning=OPTION 2: Prebuilt OpenSSL from Shining Light Productions");
    println!("cargo:warning=  1. Visit: https://slproweb.com/products/Win32OpenSSL.html");
    println!("cargo:warning=  2. Download 'Win64 OpenSSL v3.x.x' (NOT the Light version)");
    println!("cargo:warning=  3. Install to default location (C:\\OpenSSL-Win64)");
    println!("cargo:warning=  4. Rebuild with: cargo build --release");
    println!("cargo:warning=");
    println!("cargo:warning=OPTION 3: Use vendored OpenSSL (requires Perl)");
    println!("cargo:warning=  1. Install Strawberry Perl from https://strawberryperl.com/");
    println!("cargo:warning=  2. Rebuild with: cargo build --release --features vendored-openssl");
    println!("cargo:warning=");
    println!("cargo:warning=After OpenSSL installation, the build will automatically");
    println!("cargo:warning=detect it and enable Windows-compatible signatures.");
    println!("cargo:warning=");
}

fn setup_prebuilt_openssl() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let target_dir = Path::new(&out_dir);

    if cfg!(target_os = "windows") {
        setup_windows_openssl(target_dir)?;
    } else {
        setup_unix_openssl(target_dir)?;
    }
    Ok(())
}

fn setup_windows_openssl(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:warning=OpenSSL not found on Windows system");
    println!("cargo:warning=");
    println!("cargo:warning=To enable OpenSSL support, please install OpenSSL using one of these methods:");
    println!("cargo:warning=");
    println!("cargo:warning=Method 1 - Download from Shining Light Productions (Recommended):");
    println!("cargo:warning=  1. Visit: https://slproweb.com/products/Win32OpenSSL.html");
    println!("cargo:warning=  2. Download 'Win64 OpenSSL v3.x.x' (NOT the Light version)");
    println!("cargo:warning=  3. Install to default location (C:\\OpenSSL-Win64)");
    println!("cargo:warning=  4. Rebuild with: cargo build --features openssl-authenticode");
    println!("cargo:warning=");
    println!("cargo:warning=Method 2 - Using vcpkg:");
    println!("cargo:warning=  1. Install vcpkg: git clone https://github.com/Microsoft/vcpkg.git");
    println!("cargo:warning=  2. Run: .\\vcpkg\\bootstrap-vcpkg.bat");
    println!("cargo:warning=  3. Install: .\\vcpkg\\vcpkg install openssl:x64-windows");
    println!("cargo:warning=  4. Set: $env:VCPKG_ROOT = 'C:\\vcpkg'");
    println!("cargo:warning=  5. Rebuild with: cargo build --features openssl-authenticode");
    println!("cargo:warning=");
    println!("cargo:warning=Method 3 - Using MSYS2:");
    println!("cargo:warning=  1. Install MSYS2 from https://www.msys2.org/");
    println!("cargo:warning=  2. Run: pacman -S mingw-w64-x86_64-openssl");
    println!("cargo:warning=  3. Add C:\\msys64\\mingw64\\bin to PATH");
    println!("cargo:warning=  4. Rebuild with: cargo build --features openssl-authenticode");
    println!("cargo:warning=");
    println!(
        "cargo:warning=After installation, the build system will automatically detect OpenSSL"
    );
    println!("cargo:warning=and build with proper Windows-compatible Authenticode signatures.");

    // Create the target directory structure so the build doesn't fail completely
    let lib_dir = target_dir.join("lib");
    let include_dir = target_dir.join("include");
    let bin_dir = target_dir.join("bin");

    fs::create_dir_all(&lib_dir)?;
    fs::create_dir_all(&include_dir)?;
    fs::create_dir_all(&bin_dir)?;

    // Create empty stub files so the compilation can proceed
    // (This will cause link-time errors, but at least shows clear next steps)
    fs::write(lib_dir.join("libssl.lib"), b"")?;
    fs::write(lib_dir.join("libcrypto.lib"), b"")?;
    fs::create_dir_all(include_dir.join("openssl"))?;
    fs::write(
        include_dir.join("openssl").join("opensslv.h"),
        b"#define OPENSSL_VERSION_TEXT \"OpenSSL 3.0.0 (stub - please install real OpenSSL)\"\n",
    )?;

    // Also create a helper script for easy installation
    create_windows_setup_script(target_dir)?;

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn create_windows_setup_script(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let script_content = r#"# OpenSSL Setup Helper for Windows
# This script helps install OpenSSL for the YubiKey Signer project

Write-Host "YubiKey Signer - OpenSSL Setup Helper" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

Write-Host "Choose an installation method:" -ForegroundColor Yellow
Write-Host "1. Download from Shining Light Productions (Manual - most reliable)"
Write-Host "2. Install via vcpkg (Automatic)"
Write-Host "3. Install via MSYS2 (if already installed)"
Write-Host "4. Check existing OpenSSL installations"
Write-Host

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host "Opening download page..." -ForegroundColor Green
        Start-Process "https://slproweb.com/products/Win32OpenSSL.html"
        Write-Host
        Write-Host "Instructions:" -ForegroundColor Yellow
        Write-Host "1. Download 'Win64 OpenSSL v3.x.x' (NOT the Light version)"
        Write-Host "2. Run the installer as Administrator"
        Write-Host "3. Install to the default location (C:\OpenSSL-Win64)"
        Write-Host "4. After installation, run: cargo build --features openssl-authenticode"
    }
    
    "2" {
        if (-not $isAdmin) {
            Write-Error "vcpkg installation requires Administrator privileges"
            Write-Host "Please run this script as Administrator or choose option 1"
            exit 1
        }
        
        Write-Host "Installing via vcpkg..." -ForegroundColor Green
        
        # Check if vcpkg exists
        $vcpkgPath = "C:\vcpkg\vcpkg.exe"
        if (-not (Test-Path $vcpkgPath)) {
            Write-Host "Installing vcpkg..." -ForegroundColor Yellow
            Set-Location C:\
            git clone https://github.com/Microsoft/vcpkg.git
            Set-Location C:\vcpkg
            .\bootstrap-vcpkg.bat
        }
        
        # Install OpenSSL
        Write-Host "Installing OpenSSL..." -ForegroundColor Yellow
        & $vcpkgPath install openssl:x64-windows
        
        # Set environment variable
        [Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", "User")
        $env:VCPKG_ROOT = "C:\vcpkg"
        
        Write-Host "vcpkg installation complete!" -ForegroundColor Green
        Write-Host "You may need to restart your terminal for environment changes to take effect."
    }
    
    "3" {
        $msys2Path = "C:\msys64\usr\bin\pacman.exe"
        if (-not (Test-Path $msys2Path)) {
            Write-Error "MSYS2 not found at C:\msys64"
            Write-Host "Please install MSYS2 from https://www.msys2.org/ first"
            exit 1
        }
        
        Write-Host "Installing OpenSSL via MSYS2..." -ForegroundColor Green
        & $msys2Path -S mingw-w64-x86_64-openssl --noconfirm
        
        # Add to PATH if not already there
        $mingwBin = "C:\msys64\mingw64\bin"
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($currentPath -notlike "*$mingwBin*") {
            [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$mingwBin", "User")
            Write-Host "Added MSYS2 to PATH. You may need to restart your terminal."
        }
        
        Write-Host "MSYS2 OpenSSL installation complete!" -ForegroundColor Green
    }
    
    "4" {
        Write-Host "Checking for existing OpenSSL installations..." -ForegroundColor Green
        
        $locations = @(
            "C:\OpenSSL-Win64",
            "C:\Program Files\OpenSSL-Win64",
            "C:\Program Files\OpenSSL",
            "C:\vcpkg\installed\x64-windows",
            "C:\msys64\mingw64"
        )
        
        $found = $false
        foreach ($location in $locations) {
            if (Test-Path $location) {
                $libPath = Join-Path $location "lib"
                $includePath = Join-Path $location "include"
                
                if ((Test-Path $libPath) -and (Test-Path $includePath)) {
                    Write-Host "✓ Found OpenSSL at: $location" -ForegroundColor Green
                    $found = $true
                    
                    # Check for library files
                    $sslLib = @(
                        Join-Path $libPath "libssl.lib",
                        Join-Path $libPath "ssl.lib",
                        Join-Path $libPath "libssl.a"
                    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
                    
                    $cryptoLib = @(
                        Join-Path $libPath "libcrypto.lib",
                        Join-Path $libPath "crypto.lib", 
                        Join-Path $libPath "libcrypto.a"
                    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
                    
                    if ($sslLib -and $cryptoLib) {
                        Write-Host "  SSL Library: $sslLib" -ForegroundColor Gray
                        Write-Host "  Crypto Library: $cryptoLib" -ForegroundColor Gray
                    } else {
                        Write-Host "  ⚠️ Missing library files" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        if (-not $found) {
            Write-Host "❌ No OpenSSL installations found" -ForegroundColor Red
            Write-Host "Please choose option 1 or 2 to install OpenSSL"
        } else {
            Write-Host
            Write-Host "Now run: cargo build --features openssl-authenticode" -ForegroundColor Green
        }
    }
    
    default {
        Write-Host "Invalid choice. Please run the script again." -ForegroundColor Red
        exit 1
    }
}

Write-Host
Write-Host "After OpenSSL is installed, you can test with:" -ForegroundColor Cyan
Write-Host "  cargo build --features openssl-authenticode" -ForegroundColor White
Write-Host "  yubikey-signer sign myapp.exe --use-openssl" -ForegroundColor White
"#;

    let script_path = target_dir
        .parent()
        .unwrap()
        .join("setup-openssl-windows.ps1");
    fs::write(&script_path, script_content)?;

    println!("cargo:warning=");
    println!(
        "cargo:warning=Created helper script: {}",
        script_path.display()
    );
    println!("cargo:warning=Run this script for guided OpenSSL installation");

    Ok(())
}

fn setup_unix_openssl(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // For Unix systems, try to build a minimal static OpenSSL
    println!("cargo:warning=Setting up OpenSSL for Unix...");

    let lib_dir = target_dir.join("lib");
    let include_dir = target_dir.join("include");

    fs::create_dir_all(&lib_dir)?;
    fs::create_dir_all(&include_dir)?;

    // Check if we can build from source
    if Command::new("which")
        .arg("make")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        println!("cargo:warning=Building OpenSSL from source...");
        build_openssl_from_source(target_dir)?;
    } else {
        println!("cargo:warning=Please install OpenSSL development packages:");
        if cfg!(target_os = "linux") {
            println!("cargo:warning=  Ubuntu/Debian: sudo apt-get install libssl-dev");
            println!("cargo:warning=  RHEL/CentOS: sudo yum install openssl-devel");
            println!("cargo:warning=  Arch: sudo pacman -S openssl");
        } else if cfg!(target_os = "macos") {
            println!("cargo:warning=  Homebrew: brew install openssl");
        }

        // Create stub files so build continues
        fs::create_dir_all(include_dir.join("openssl"))?;
        fs::write(
            include_dir.join("openssl").join("opensslv.h"),
            b"#define OPENSSL_VERSION_TEXT \"OpenSSL 3.0.0\"\n",
        )?;
    }

    Ok(())
}

fn build_openssl_from_source(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let openssl_version = "3.0.15";
    let url = format!(
        "https://github.com/openssl/openssl/releases/download/openssl-{openssl_version}/openssl-{openssl_version}.tar.gz"
    );

    // Download
    let response = ureq::get(&url).call()?;
    let mut tar_data = Vec::new();
    std::io::copy(&mut response.into_reader(), &mut tar_data)?;

    // Extract
    let tar_path = target_dir.parent().unwrap().join("openssl.tar.gz");
    fs::write(&tar_path, tar_data)?;

    let status = Command::new("tar")
        .args(["xzf", tar_path.to_str().unwrap()])
        .current_dir(target_dir.parent().unwrap())
        .status()?;

    if !status.success() {
        return Err("Failed to extract OpenSSL".into());
    }

    let source_dir = target_dir
        .parent()
        .unwrap()
        .join(format!("openssl-{openssl_version}"));

    // Configure
    let status = Command::new("./config")
        .args([
            &format!("--prefix={}", target_dir.display()),
            "no-shared",
            "no-tests",
            "-fPIC",
        ])
        .current_dir(&source_dir)
        .status()?;

    if !status.success() {
        return Err("Failed to configure OpenSSL".into());
    }

    // Build
    let status = Command::new("make")
        .args(["-j", &num_cpus::get().to_string()])
        .current_dir(&source_dir)
        .status()?;

    if !status.success() {
        return Err("Failed to build OpenSSL".into());
    }

    // Install
    let status = Command::new("make")
        .arg("install_sw")
        .current_dir(&source_dir)
        .status()?;

    if !status.success() {
        return Err("Failed to install OpenSSL".into());
    }

    // Clean up
    let _ = fs::remove_file(&tar_path);
    let _ = fs::remove_dir_all(&source_dir);

    Ok(())
}

// Build dependencies
// We'll add these as build-dependencies in Cargo.toml
