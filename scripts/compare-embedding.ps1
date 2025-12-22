<#
Compare two MSI files at a byte level.

This is intentionally a lightweight helper that does not build or invoke any
external signing tools.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$FileA,

    [Parameter(Mandatory = $true)]
    [string]$FileB,

    [int]$DiffWindowBytes = 16
)

$ErrorActionPreference = "Stop"

Write-Host "=== MSI file comparison ===" -ForegroundColor Cyan
Write-Host "A: $FileA"
Write-Host "B: $FileB"

if (-not (Test-Path $FileA)) { throw "File not found: $FileA" }
if (-not (Test-Path $FileB)) { throw "File not found: $FileB" }

$aBytes = [System.IO.File]::ReadAllBytes($FileA)
$bBytes = [System.IO.File]::ReadAllBytes($FileB)

Write-Host "Size A: $($aBytes.Length) bytes"
Write-Host "Size B: $($bBytes.Length) bytes"

try {
    $aSig = Get-AuthenticodeSignature $FileA
    $bSig = Get-AuthenticodeSignature $FileB
    Write-Host "Signature A: $($aSig.Status)" -ForegroundColor $(if ($aSig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
    Write-Host "Signature B: $($bSig.Status)" -ForegroundColor $(if ($bSig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
} catch {
    Write-Host "Signature check skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

$firstDiff = -1
for ($i = 0; $i -lt [Math]::Min($aBytes.Length, $bBytes.Length); $i++) {
    if ($aBytes[$i] -ne $bBytes[$i]) {
        $firstDiff = $i
        break
    }
}

if ($firstDiff -lt 0 -and $aBytes.Length -eq $bBytes.Length) {
    Write-Host "Files are identical." -ForegroundColor Green
    exit 0
}

if ($firstDiff -lt 0) {
    Write-Host "No differing bytes in the shared prefix; file sizes differ." -ForegroundColor Yellow
    exit 0
}

Write-Host "First difference at offset 0x$($firstDiff.ToString('X'))" -ForegroundColor Yellow
$endA = [Math]::Min($firstDiff + $DiffWindowBytes - 1, $aBytes.Length - 1)
$endB = [Math]::Min($firstDiff + $DiffWindowBytes - 1, $bBytes.Length - 1)
Write-Host "A: $([BitConverter]::ToString($aBytes[$firstDiff..$endA]))"
Write-Host "B: $([BitConverter]::ToString($bBytes[$firstDiff..$endB]))"

Write-Host "=== Done ===" -ForegroundColor Cyan
