# Windows Build Environment Setup for YubiKey Signer
# Automatically installs vcpkg and OpenSSL

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "YubiKey Signer - Windows Build Environment Setup" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Warning: Not running as administrator. Some operations may fail." -ForegroundColor Yellow
    Write-Host "Consider running PowerShell as Administrator for best results." -ForegroundColor Yellow
    Write-Host ""
}

# Function to find vcpkg installation
function Find-VcpkgInstallation {
    # Check VCPKG_ROOT environment variable first
    $vcpkgRoot = $env:VCPKG_ROOT
    if ($vcpkgRoot -and (Test-Path "$vcpkgRoot\vcpkg.exe")) {
        Write-Host "Using existing VCPKG_ROOT: $vcpkgRoot" -ForegroundColor Green
        return $vcpkgRoot
    }
    
    # Check common locations
    $commonPaths = @(
        "C:\vcpkg",
        "C:\tools\vcpkg", 
        "C:\dev\vcpkg",
        "$env:USERPROFILE\vcpkg"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path "$path\vcpkg.exe") {
            Write-Host "Found existing vcpkg at: $path" -ForegroundColor Green
            return $path
        }
    }
    
    return $null
}

# Function to install vcpkg
function Install-Vcpkg {
    param([string]$InstallPath = "C:\vcpkg")
    
    Write-Host "Installing vcpkg to $InstallPath..." -ForegroundColor Yellow
    
    try {
        # Clone vcpkg repository
        Write-Host "Cloning vcpkg repository..."
        git clone https://github.com/Microsoft/vcpkg.git $InstallPath
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to clone vcpkg repository"
        }
        
        # Bootstrap vcpkg
        Write-Host "Bootstrapping vcpkg..."
        & "$InstallPath\bootstrap-vcpkg.bat"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to bootstrap vcpkg"
        }
        
        Write-Host "vcpkg installed successfully!" -ForegroundColor Green
        return $InstallPath
    }
    catch {
        Write-Host "Error installing vcpkg: $_" -ForegroundColor Red
        return $null
    }
}

# Function to check if OpenSSL is installed in vcpkg
function Test-OpenSSLInstalled {
    param([string]$VcpkgPath)
    
    $opensslLib = "$VcpkgPath\installed\x64-windows\lib\libssl.lib"
    $opensslHeaders = "$VcpkgPath\installed\x64-windows\include\openssl\opensslv.h"
    
    return (Test-Path $opensslLib) -and (Test-Path $opensslHeaders)
}

# Function to install OpenSSL via vcpkg
function Install-OpenSSL {
    param([string]$VcpkgPath)
    
    Write-Host "Installing OpenSSL via vcpkg (this may take several minutes)..." -ForegroundColor Yellow
    
    try {
        # First integrate vcpkg (helps with some installation issues)
        & "$VcpkgPath\vcpkg.exe" integrate install
        
        # Install OpenSSL for both standard and MSVC static-md triplets
        # The rust openssl-sys crate looks for x64-windows-static-md specifically
        & "$VcpkgPath\vcpkg.exe" install openssl:x64-windows
        if ($LASTEXITCODE -ne 0) {
            throw "vcpkg install openssl:x64-windows failed"
        }
        
        & "$VcpkgPath\vcpkg.exe" install openssl:x64-windows-static-md
        if ($LASTEXITCODE -ne 0) {
            throw "vcpkg install openssl:x64-windows-static-md failed"
        }
        
        Write-Host "OpenSSL installed successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error installing OpenSSL: $_" -ForegroundColor Red
        return $false
    }
}

# Main setup process
try {
    # Find or install vcpkg
    $vcpkgPath = Find-VcpkgInstallation
    
    if (-not $vcpkgPath) {
        Write-Host "No vcpkg installation found. Installing..." -ForegroundColor Yellow
        $vcpkgPath = Install-Vcpkg
        
        if (-not $vcpkgPath) {
            throw "Failed to install vcpkg"
        }
    }
    
    # Check for OpenSSL
    Write-Host ""
    Write-Host "Checking for OpenSSL installation..."
    
    if (Test-OpenSSLInstalled -VcpkgPath $vcpkgPath) {
        Write-Host "OpenSSL is already installed in vcpkg" -ForegroundColor Green
    }
    else {
        Write-Host "OpenSSL not found. Installing..." -ForegroundColor Yellow
        $success = Install-OpenSSL -VcpkgPath $vcpkgPath
        
        if (-not $success) {
            throw "Failed to install OpenSSL"
        }
    }
    
    # Configure environment
    Write-Host ""
    Write-Host "Setting up environment..." -ForegroundColor Yellow
    
    # Set VCPKG_ROOT for current session
    $env:VCPKG_ROOT = $vcpkgPath
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "Setup Complete!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "VCPKG_ROOT: $vcpkgPath" -ForegroundColor Cyan
    Write-Host "OpenSSL: $vcpkgPath\installed\x64-windows" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "You can now build the project with:" -ForegroundColor White
    Write-Host "  cargo build" -ForegroundColor Gray
    Write-Host "  cargo run" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To make VCPKG_ROOT permanent, run:" -ForegroundColor White
    Write-Host "  [Environment]::SetEnvironmentVariable('VCPKG_ROOT', '$vcpkgPath', 'User')" -ForegroundColor Gray
    Write-Host ""
    
    # Test the build
    $testBuild = Read-Host "Would you like to test the build now? (y/N)"
    if ($testBuild -eq 'y' -or $testBuild -eq 'Y') {
        Write-Host ""
        Write-Host "Testing build..." -ForegroundColor Yellow
        cargo check
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Build test successful!" -ForegroundColor Green
        }
        else {
            Write-Host "Build test failed. Please check the output above." -ForegroundColor Red
        }
    }
}
catch {
    Write-Host ""
    Write-Host "Setup failed: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Manual setup instructions:" -ForegroundColor Yellow
    Write-Host "1. Install vcpkg: git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg" -ForegroundColor Gray
    Write-Host "2. Bootstrap: C:\vcpkg\bootstrap-vcpkg.bat" -ForegroundColor Gray
    Write-Host "3. Install OpenSSL: C:\vcpkg\vcpkg install openssl:x64-windows" -ForegroundColor Gray
    Write-Host "4. Set environment: set VCPKG_ROOT=C:\vcpkg" -ForegroundColor Gray
    exit 1
}
