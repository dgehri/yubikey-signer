#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Verifies Authenticode signatures using PowerShell's Get-AuthenticodeSignature

.DESCRIPTION
    This script verifies that signed PE files have valid signatures and timestamps.
    It checks both the signature validity and timestamp information.

.PARAMETER FilePath
    Path to the signed PE file to verify

.PARAMETER Verbose
    Show detailed signature information

.EXAMPLE
    .\verify_signature.ps1 -FilePath "signed_file.exe"
    
.EXAMPLE
    .\verify_signature.ps1 -FilePath "signed_file.exe" -Verbose
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    
    [switch]$Verbose
)

# Check if file exists
if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

Write-Host "🔍 Verifying Authenticode signature for: $FilePath" -ForegroundColor Cyan

try {
    # Get the signature information
    $signature = Get-AuthenticodeSignature -FilePath $FilePath
    
    # Check signature status
    Write-Host "`n📋 Signature Status: " -NoNewline
    switch ($signature.Status) {
        "Valid" { 
            Write-Host "✅ VALID" -ForegroundColor Green
        }
        "HashMismatch" { 
            Write-Host "❌ HASH MISMATCH" -ForegroundColor Red
        }
        "NotSigned" { 
            Write-Host "❌ NOT SIGNED" -ForegroundColor Red
        }
        "UnknownError" { 
            Write-Host "❌ UNKNOWN ERROR" -ForegroundColor Red
        }
        "Incompatible" { 
            Write-Host "❌ INCOMPATIBLE" -ForegroundColor Red
        }
        default { 
            Write-Host "❌ $($signature.Status)" -ForegroundColor Red
        }
    }
    
    # Show certificate information
    if ($signature.SignerCertificate) {
        Write-Host "`n📜 Certificate Information:"
        Write-Host "   Subject: $($signature.SignerCertificate.Subject)" -ForegroundColor Yellow
        Write-Host "   Issuer: $($signature.SignerCertificate.Issuer)" -ForegroundColor Yellow
        Write-Host "   Thumbprint: $($signature.SignerCertificate.Thumbprint)" -ForegroundColor Yellow
        Write-Host "   Not Before: $($signature.SignerCertificate.NotBefore)" -ForegroundColor Yellow
        Write-Host "   Not After: $($signature.SignerCertificate.NotAfter)" -ForegroundColor Yellow
        
        # Check if certificate is still valid
        $now = Get-Date
        if ($signature.SignerCertificate.NotBefore -le $now -and $signature.SignerCertificate.NotAfter -ge $now) {
            Write-Host "   Validity: ✅ Certificate is currently valid" -ForegroundColor Green
        }
        else {
            Write-Host "   Validity: ❌ Certificate is expired or not yet valid" -ForegroundColor Red
        }
    }
    
    # Check for timestamp
    Write-Host "`n⏰ Timestamp Information:"
    if ($signature.TimeStamperCertificate) {
        Write-Host "   Status: ✅ File is timestamped" -ForegroundColor Green
        Write-Host "   Timestamp Authority: $($signature.TimeStamperCertificate.Subject)" -ForegroundColor Yellow
        Write-Host "   Timestamp Issuer: $($signature.TimeStamperCertificate.Issuer)" -ForegroundColor Yellow
        Write-Host "   Timestamp: $($signature.TimeStamperCertificate.NotBefore)" -ForegroundColor Yellow
        
        # Check timestamp certificate validity
        $now = Get-Date
        if ($signature.TimeStamperCertificate.NotBefore -le $now -and $signature.TimeStamperCertificate.NotAfter -ge $now) {
            Write-Host "   TSA Cert Validity: ✅ Timestamp authority certificate is valid" -ForegroundColor Green
        }
        else {
            Write-Host "   TSA Cert Validity: ❌ Timestamp authority certificate is expired" -ForegroundColor Red
        }
    }
    else {
        Write-Host "   Status: ❌ File is not timestamped" -ForegroundColor Red
        Write-Host "   Note: Without timestamp, signature will become invalid when signing certificate expires" -ForegroundColor Yellow
    }
    
    # Show verbose information if requested
    if ($Verbose) {
        Write-Host "`n🔍 Detailed Information:" -ForegroundColor Cyan
        $signature | Format-List *
    }
    
    # Overall result
    Write-Host "`n🎯 Overall Result: " -NoNewline
    if ($signature.Status -eq "Valid" -and $signature.TimeStamperCertificate) {
        Write-Host "✅ SIGNATURE VALID AND TIMESTAMPED" -ForegroundColor Green
        exit 0
    }
    elseif ($signature.Status -eq "Valid") {
        Write-Host "⚠️  SIGNATURE VALID BUT NOT TIMESTAMPED" -ForegroundColor Yellow
        exit 0
    }
    else {
        Write-Host "❌ SIGNATURE INVALID OR MISSING" -ForegroundColor Red
        exit 1
    }
    
}
catch {
    Write-Error "Error verifying signature: $($_.Exception.Message)"
    exit 1
}
