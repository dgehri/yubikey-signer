# Script to create a minimal test MSI file for signing tests
# Uses the Windows Installer COM API

param(
    [string]$OutputPath = "test-data\test_unsigned.msi"
)

$ErrorActionPreference = "Stop"

# Create Windows Installer COM object
$installer = New-Object -ComObject WindowsInstaller.Installer

# Resolve output path
$fullPath = Join-Path $PSScriptRoot "..\$OutputPath" -Resolve -ErrorAction SilentlyContinue
if (-not $fullPath) {
    $fullPath = Join-Path $PSScriptRoot "..\$OutputPath"
}

# Remove existing file if it exists
if (Test-Path $fullPath) {
    Remove-Item $fullPath -Force
}

Write-Host "Creating minimal MSI at: $fullPath"

# Create a new MSI database
$database = $installer.OpenDatabase($fullPath, 3) # msiOpenDatabaseModeCreate = 3

# Create required tables
# Property table (required)
$database.OpenView("CREATE TABLE Property (Property CHAR(72) NOT NULL, Value CHAR NOT NULL LOCALIZABLE PRIMARY KEY Property)").Execute() | Out-Null

# Add minimal required properties
$view = $database.OpenView("INSERT INTO Property (Property, Value) VALUES ('ProductName', 'Test MSI')")
$view.Execute() | Out-Null
$view.Close()

$view = $database.OpenView("INSERT INTO Property (Property, Value) VALUES ('ProductCode', '{00000000-0000-0000-0000-000000000001}')")
$view.Execute() | Out-Null
$view.Close()

$view = $database.OpenView("INSERT INTO Property (Property, Value) VALUES ('ProductVersion', '1.0.0')")
$view.Execute() | Out-Null
$view.Close()

$view = $database.OpenView("INSERT INTO Property (Property, Value) VALUES ('Manufacturer', 'Test')")
$view.Execute() | Out-Null
$view.Close()

$view = $database.OpenView("INSERT INTO Property (Property, Value) VALUES ('ProductLanguage', '1033')")
$view.Execute() | Out-Null
$view.Close()

# Set summary information
$summary = $database.SummaryInformation(20)
$summary.Property(2) = "Test MSI"           # PID_TITLE
$summary.Property(3) = "Test MSI Package"   # PID_SUBJECT
$summary.Property(4) = "Test"               # PID_AUTHOR
$summary.Property(6) = ""                   # PID_COMMENTS
$summary.Property(7) = ";1033"              # PID_TEMPLATE
$summary.Property(9) = "{00000000-0000-0000-0000-000000000001}" # PID_REVNUMBER
$summary.Property(14) = 200                 # PID_PAGECOUNT (minimum MSI version)
$summary.Property(15) = 2                   # PID_WORDCOUNT
$summary.Persist()

# Commit the database
$database.Commit()

# Release COM objects to unlock the file
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($summary) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Write-Host "Created minimal MSI successfully: $fullPath"
Write-Host "File size: $((Get-Item $fullPath).Length) bytes"

# Verify it's a valid OLE file
$bytes = [System.IO.File]::ReadAllBytes($fullPath)
$magic = [BitConverter]::ToString($bytes[0..7]).Replace("-", " ")
Write-Host "Magic bytes: $magic"
if ($magic -eq "D0 CF 11 E0 A1 B1 1A E1") {
    Write-Host "Valid OLE Compound Document signature confirmed"
} else {
    Write-Host "WARNING: Invalid magic bytes!"
}
