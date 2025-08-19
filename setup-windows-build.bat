@echo off
REM Setup script for Windows development environment
REM This script automatically installs vcpkg and OpenSSL for YubiKey Signer

echo.
echo ================================================================
echo YubiKey Signer - Windows Build Environment Setup
echo ================================================================
echo.

REM Check if vcpkg is already available
if defined VCPKG_ROOT (
    echo Using existing VCPKG_ROOT: %VCPKG_ROOT%
    if exist "%VCPKG_ROOT%\vcpkg.exe" (
        set VCPKG_PATH=%VCPKG_ROOT%
        goto check_openssl
    ) else (
        echo Warning: VCPKG_ROOT is set but vcpkg.exe not found
        echo Continuing with automatic installation...
    )
)

REM Check common vcpkg locations
if exist "C:\vcpkg\vcpkg.exe" (
    echo Found existing vcpkg installation at C:\vcpkg
    set VCPKG_PATH=C:\vcpkg
    goto check_openssl
)

if exist "C:\tools\vcpkg\vcpkg.exe" (
    echo Found existing vcpkg installation at C:\tools\vcpkg
    set VCPKG_PATH=C:\tools\vcpkg
    goto check_openssl
)

echo.
echo No vcpkg installation found. Installing to C:\vcpkg...
echo.

REM Install vcpkg
echo Cloning vcpkg repository...
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
if errorlevel 1 (
    echo Error: Failed to clone vcpkg repository
    echo Please ensure git is installed and you have internet access
    pause
    exit /b 1
)

echo.
echo Bootstrapping vcpkg...
call C:\vcpkg\bootstrap-vcpkg.bat
if errorlevel 1 (
    echo Error: Failed to bootstrap vcpkg
    pause
    exit /b 1
)

set VCPKG_PATH=C:\vcpkg

:check_openssl
echo.
echo Checking for OpenSSL installation...

if exist "%VCPKG_PATH%\installed\x64-windows\lib\libssl.lib" (
    echo OpenSSL is already installed in vcpkg
    goto configure
)

echo.
echo Installing OpenSSL via vcpkg (this may take several minutes)...
"%VCPKG_PATH%\vcpkg.exe" install openssl:x64-windows
if errorlevel 1 (
    echo Error: Failed to install OpenSSL:x64-windows via vcpkg
    pause
    exit /b 1
)

"%VCPKG_PATH%\vcpkg.exe" install openssl:x64-windows-static-md
if errorlevel 1 (
    echo Error: Failed to install OpenSSL:x64-windows-static-md via vcpkg
    pause
    exit /b 1
)

:configure
echo.
echo Setting up environment...

REM Set VCPKG_ROOT for current session
set VCPKG_ROOT=%VCPKG_PATH%

REM Integrate vcpkg with MSBuild
"%VCPKG_PATH%\vcpkg.exe" integrate install

echo.
echo ================================================================
echo Setup Complete!
echo ================================================================
echo.
echo VCPKG_ROOT: %VCPKG_ROOT%
echo OpenSSL: %VCPKG_PATH%\installed\x64-windows
echo.
echo You can now build the project with:
echo   cargo build
echo   cargo run
echo.
echo To make VCPKG_ROOT permanent, add this to your environment variables:
echo   VCPKG_ROOT=%VCPKG_PATH%
echo.
pause
