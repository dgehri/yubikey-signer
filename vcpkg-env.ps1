# vcpkg OpenSSL Environment Configuration
# Source this script before building: . .\vcpkg-env.ps1

# Only define VCPKG_ROOT if not yet defined
if (-not $env:VCPKG_ROOT) {
    $env:VCPKG_ROOT = "C:\vcpkg"
}
$env:OPENSSL_DIR = "$env:VCPKG_ROOT\installed\x64-windows"
$env:OPENSSL_LIB_DIR = "$env:OPENSSL_DIR\lib"
$env:OPENSSL_INCLUDE_DIR = "$env:OPENSSL_DIR\include"
$env:OPENSSL_NO_VENDOR = "1"

# Add vcpkg bin directory to PATH for runtime DLL loading
$vcpkgBin = "$env:OPENSSL_DIR\bin"
if ($env:PATH -notlike "*$vcpkgBin*") {
    $env:PATH = "$vcpkgBin;$env:PATH"
}

Write-Host "vcpkg OpenSSL environment configured" -ForegroundColor Green
