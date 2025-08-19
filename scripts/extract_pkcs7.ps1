#!/usr/bin/env pwsh
<#
    PE PKCS#7 Extractor (padding-aware)

    - Extracts the WIN_CERTIFICATE PKCS#7 blob from a PE file
    - Trims trailing 8-byte alignment padding by parsing ASN.1 DER length
    - Outputs a clean PKCS#7 DER file suitable for certutil -asn / OpenSSL tools
#>
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$PEFile,
    [Parameter(Mandatory = $true, Position = 1)][string]$OutputFile
)

function Get-Asn1TotalLength {
    param([byte[]]$Data)

    if ($Data.Length -lt 4) { throw "Data too short to be ASN.1 DER" }
    if ($Data[0] -ne 0x30) { throw "Expected SEQUENCE (0x30) at start of PKCS#7" }

    $lenByte = $Data[1]
    switch ($lenByte) {
        { $_ -lt 0x80 } { return 2 + $_ }
        0x81 { return 3 + [int]$Data[2] }
        0x82 { return 4 + ([int]$Data[2] -shl 8) + [int]$Data[3] }
        0x83 { return 5 + ([int]$Data[2] -shl 16) + ([int]$Data[3] -shl 8) + [int]$Data[4] }
        default { throw "Unsupported or non-minimal DER length form: 0x$($lenByte.ToString('X2'))" }
    }
}

function Extract-PKCS7FromPE {
    param([string]$FilePath, [string]$OutputPath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)

    # Find DOS header and PE signature
    $peOffset = [System.BitConverter]::ToUInt32($bytes, 0x3C)
    Write-Host "PE offset: 0x$($peOffset.ToString('X'))"

    # Skip PE signature (4 bytes) and COFF header (20 bytes)
    $optionalHeaderOffset = $peOffset + 24

    # Read optional header magic to determine if PE32 or PE32+
    $magic = [System.BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)

    if ($magic -eq 0x10b) {
        # PE32
        $certTableOffset = $optionalHeaderOffset + 128
    }
    elseif ($magic -eq 0x20b) {
        # PE32+
        $certTableOffset = $optionalHeaderOffset + 144
    }
    else {
        throw "Unknown PE format"
    }

    # Read certificate table directory entry (8 bytes: RVA + Size)
    $certTableRva = [System.BitConverter]::ToUInt32($bytes, $certTableOffset)
    $certTableSize = [System.BitConverter]::ToUInt32($bytes, $certTableOffset + 4)

    Write-Host "Certificate table RVA: 0x$($certTableRva.ToString('X'))"
    Write-Host "Certificate table size: $certTableSize bytes"

    if ($certTableRva -eq 0 -or $certTableSize -eq 0) {
        Write-Host "No certificate table found"
        return
    }

    # In PE files, certificate table RVA is actually a file offset (not RVA)
    $certOffset = $certTableRva

    # Read WIN_CERTIFICATE header
    $certLength = [System.BitConverter]::ToUInt32($bytes, $certOffset)
    $certRevision = [System.BitConverter]::ToUInt16($bytes, $certOffset + 4)
    $certType = [System.BitConverter]::ToUInt16($bytes, $certOffset + 6)

    Write-Host "Certificate length: $certLength"
    Write-Host "Certificate type: $certType (2=PKCS#7)"

    # PKCS#7 data starts after 8-byte WIN_CERTIFICATE header
    $pkcs7Offset = $certOffset + 8
    $pkcs7Size = $certLength - 8

    Write-Host "PKCS#7 offset: 0x$($pkcs7Offset.ToString('X'))"
    Write-Host "PKCS#7 size (incl. padding): $pkcs7Size bytes"

    # Extract raw PKCS#7 (may include padding)
    $raw = New-Object byte[] $pkcs7Size
    [System.Array]::Copy($bytes, $pkcs7Offset, $raw, 0, $pkcs7Size)

    # Trim padding by parsing ASN.1 total length
    $asn1Total = Get-Asn1TotalLength -Data $raw
    if ($asn1Total -lt $raw.Length) {
        Write-Host "Trimming padding: ASN.1=$asn1Total, raw=$($raw.Length) (-$($raw.Length - $asn1Total) bytes)"
        $pkcs7Data = $raw[0..($asn1Total - 1)]
    }
    else {
        $pkcs7Data = $raw
    }

    # Write to output file
    [System.IO.File]::WriteAllBytes($OutputPath, $pkcs7Data)

    Write-Host "Extracted PKCS#7 to: $OutputPath ($($pkcs7Data.Length) bytes)"
    $previewLen = [Math]::Min(31, $pkcs7Data.Length - 1)
    if ($previewLen -ge 0) {
        Write-Host "First 32 bytes: $([System.BitConverter]::ToString($pkcs7Data[0..$previewLen]) -replace '-', ' ')"
    }
}

Extract-PKCS7FromPE -FilePath $PEFile -OutputPath $OutputFile
