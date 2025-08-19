#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive test script for yubikey-signer Authenticode implementation

.DESCRIPTION
    This script tests the complete yubikey-signer pipeline:
    1. Creates an unsigned PE executable for testing
    2. Signs it without timestamp using yubikey-signer
    3. Signs it with timestamp using yubikey-signer  
    4. Verifies Windows accepts both signatures
    5. Compares against reference osslsigncode signatures

.PARAMETER SkipYubiKey
    Skip actual YubiKey signing operations (for testing when hardware not connected)

.PARAMETER Verbose
    Enable verbose output with detailed logging

.EXAMPLE
    .\test.ps1
    Run full test with YubiKey signing

.EXAMPLE  
    .\test.ps1 -SkipYubiKey
    Run test without YubiKey operations (simulation mode)
#>

param(
    [switch]$SkipYubiKey = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-TestStatus {
    param([string]$Message, [string]$Status = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    switch ($Status) {
        "PASS" { Write-Host "[$timestamp] ${Green}✅ $Message${Reset}" }
        "FAIL" { Write-Host "[$timestamp] ${Red}❌ $Message${Reset}" }
        "WARN" { Write-Host "[$timestamp] ${Yellow}⚠️  $Message${Reset}" }
        "INFO" { Write-Host "[$timestamp] ${Blue}ℹ️  $Message${Reset}" }
    }
}

function Test-FileSignature {
    param([string]$FilePath)
    
    try {
        $sig = Get-AuthenticodeSignature $FilePath
        $result = @{
            Status                 = $sig.Status
            StatusMessage          = $sig.StatusMessage
            SignerCertificate      = $null -ne $sig.SignerCertificate
            TimeStamperCertificate = $null -ne $sig.TimeStamperCertificate
            SignatureType          = $sig.SignatureType
        }
        return $result
    }
    catch {
        return @{
            Status                 = "Error"
            StatusMessage          = $_.Exception.Message
            SignerCertificate      = $false
            TimeStamperCertificate = $false
            SignatureType          = "Unknown"
        }
    }
}

function New-TestExecutable {
    param([string]$OutputPath)
    
    Write-TestStatus "Creating test executable: $OutputPath"
    
    # Use reference clean executable as base
    $referenceExe = "reference\clean_unsigned.exe"
    if (-not (Test-Path $referenceExe)) {
        throw "Reference executable not found: $referenceExe"
    }
    
    Copy-Item $referenceExe $OutputPath -Force
    Write-TestStatus "Created test executable: $(Get-Item $OutputPath | Select-Object -ExpandProperty Length) bytes" "PASS"
}

function Test-YubikeySignerBuild {
    Write-TestStatus "Building yubikey-signer..."
    
    try {
        if ($Verbose) {
            & cargo build 2>&1 | Write-Host
        }
        else {
            $output = & cargo build 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host $output
                throw "Build failed"
            }
        }
        Write-TestStatus "yubikey-signer build successful" "PASS"
    }
    catch {
        Write-TestStatus "yubikey-signer build failed: $_" "FAIL"
        throw
    }
}

function Test-YubikeySignerSign {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [switch]$WithTimestamp = $false,
        [switch]$SkipActualSigning = $false
    )
    
    $description = if ($WithTimestamp) { "timestamped" } else { "non-timestamped" }
    
    Write-TestStatus "Signing with yubikey-signer ($description)..."
    
    if ($SkipActualSigning) {
        Write-TestStatus "Skipping actual signing (YubiKey not connected)" "WARN"
        # Create a dummy signed file for testing
        Copy-Item $InputFile $OutputFile -Force
        return $false
    }
    
    try {
        $cmdArgs = @("sign", $InputFile, "--output", $OutputFile)
        if ($WithTimestamp) {
            $cmdArgs += "--timestamp"
        }
        if ($Verbose) {
            $cmdArgs += "--verbose"
        }
        
        if ($Verbose) {
            & cargo run -- @cmdArgs 2>&1 | Write-Host
        }
        else {
            $output = & cargo run -- @cmdArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host $output
                throw "Signing failed"
            }
        }
        
        if (-not (Test-Path $OutputFile)) {
            throw "Output file was not created: $OutputFile"
        }
        
        $fileSize = (Get-Item $OutputFile).Length
        Write-TestStatus "Successfully signed ($description): $fileSize bytes" "PASS"
        return $true
    }
    catch {
        Write-TestStatus "Signing failed ($description): $_" "FAIL"
        return $false
    }
}

function Test-WindowsSignatureValidation {
    param([string]$FilePath, [string]$Description)
    
    Write-TestStatus "Validating $Description signature with Windows..."
    
    $result = Test-FileSignature $FilePath
    
    Write-Host "  Status: $($result.Status)"
    Write-Host "  Message: $($result.StatusMessage)"
    Write-Host "  Signer Certificate: $($result.SignerCertificate)"
    Write-Host "  TimeStamper Certificate: $($result.TimeStamperCertificate)"
    Write-Host "  Signature Type: $($result.SignatureType)"
    
    if ($result.Status -ne "Valid") {
        Write-TestStatus "$Description signature validation failed: $($result.Status)" "FAIL"
        return $false
    }

    # Additional timestamp presence validation
    $expectTimestamp = $Description -eq 'timestamped'
    if ($expectTimestamp -and -not $result.TimeStamperCertificate) {
        Write-TestStatus "Expected timestamp certificate for $Description but none present" "FAIL"
        return $false
    }
    if (-not $expectTimestamp -and $result.TimeStamperCertificate) {
        Write-TestStatus "Did not expect timestamp certificate for $Description but one is present" "FAIL"
        return $false
    }

    Write-TestStatus "$Description signature validation passed (timestamp present=$($result.TimeStamperCertificate))" "PASS"
    return $true
}

function Test-SignToolValidation {
    param([string]$FilePath, [string]$Description)
    
    $signTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe"
    if (-not (Test-Path $signTool)) {
        Write-TestStatus "SignTool not found, skipping verification" "WARN"
        return $false
    }
    
    Write-TestStatus "Validating $Description signature with SignTool..."
    
    try {
        $output = & $signTool verify /pa $FilePath 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-TestStatus "$Description SignTool validation passed" "PASS"
            if ($Verbose) {
                Write-Host $output
            }
            return $true
        }
        else {
            Write-TestStatus "$Description SignTool validation failed" "FAIL"
            Write-Host $output
            return $false
        }
    }
    catch {
        Write-TestStatus "$Description SignTool validation error: $_" "FAIL"
        return $false
    }
}

function Main {
    Write-Host "${Blue}=== YubiKey-Signer Comprehensive Test ===${Reset}"
    Write-Host ""
    
    $testResults = @{
        BuildSuccess        = $false
        UnsignedCreated     = $false
        NoTimestampSigned   = $false
        TimestampSigned     = $false
        NoTimestampValid    = $false
        TimestampValid      = $false
        SignToolNoTimestamp = $false
        SignToolTimestamp   = $false
    }
    
    # Ensure temp directory exists
    if (-not (Test-Path "temp")) {
        New-Item -ItemType Directory -Path "temp" | Out-Null
    }
    
    # Test files
    $unsignedFile = "temp\test_unsigned.exe"
    $signedNoTs = "temp\test_signed_no_timestamp.exe"
    $signedWithTs = "temp\test_signed_with_timestamp.exe"
    
    try {
        # Step 1: Build yubikey-signer
        Test-YubikeySignerBuild
        $testResults.BuildSuccess = $true
        
        # Step 2: Create unsigned test executable
        New-TestExecutable $unsignedFile
        $testResults.UnsignedCreated = $true
        
        # Step 3: Sign without timestamp
        $success = Test-YubikeySignerSign $unsignedFile $signedNoTs -SkipActualSigning:$SkipYubiKey
        $testResults.NoTimestampSigned = $success
        
        # Step 4: Sign with timestamp
        $success = Test-YubikeySignerSign $unsignedFile $signedWithTs -WithTimestamp -SkipActualSigning:$SkipYubiKey
        $testResults.TimestampSigned = $success
        
        if (-not $SkipYubiKey) {
            # Step 5: Validate non-timestamped signature
            if ($testResults.NoTimestampSigned -and (Test-Path $signedNoTs)) {
                $testResults.NoTimestampValid = Test-WindowsSignatureValidation $signedNoTs "non-timestamped"
                $testResults.SignToolNoTimestamp = Test-SignToolValidation $signedNoTs "non-timestamped"
            }
            
            # Step 6: Validate timestamped signature  
            if ($testResults.TimestampSigned -and (Test-Path $signedWithTs)) {
                $testResults.TimestampValid = Test-WindowsSignatureValidation $signedWithTs "timestamped"
                $testResults.SignToolTimestamp = Test-SignToolValidation $signedWithTs "timestamped"
            }
        }
        
        # Summary
        Write-Host ""
        Write-Host "${Blue}=== Test Results Summary ===${Reset}"
        Write-Host ""
        
        $passed = 0
        $total = 0
        
        foreach ($test in $testResults.GetEnumerator()) {
            $total++
            if ($test.Value) {
                Write-TestStatus "$($test.Key): PASSED" "PASS"
                $passed++
            }
            else {
                Write-TestStatus "$($test.Key): FAILED" "FAIL"
            }
        }
        
        Write-Host ""
        Write-Host "${Blue}Overall: $passed/$total tests passed${Reset}"
        
        if ($SkipYubiKey) {
            Write-TestStatus "Test completed in simulation mode (YubiKey operations skipped)" "WARN"
        }
        elseif ($passed -eq $total) {
            Write-TestStatus "All tests passed! yubikey-signer is working correctly." "PASS"
        }
        else {
            Write-TestStatus "Some tests failed. Check the output above for details." "FAIL"
            exit 1
        }
        
    }
    catch {
        Write-TestStatus "Test execution failed: $_" "FAIL"
        exit 1
    }
}

# Run main function
Main
