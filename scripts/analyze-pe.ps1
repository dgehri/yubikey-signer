# PE Section Analysis Tool
param([string]$PEFile)

function Analyze-PESections {
    param([string]$FilePath)
    
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    Write-Host "File size: $($bytes.Length) bytes (0x$($bytes.Length.ToString('X')))"
    
    # Get PE offset
    $peOffset = [System.BitConverter]::ToUInt32($bytes, 0x3C)
    Write-Host "PE offset: 0x$($peOffset.ToString('X'))"
    
    # Get number of sections
    $numberOfSections = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)
    Write-Host "Number of sections: $numberOfSections"
    
    # Get optional header size
    $optionalHeaderSize = [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
    Write-Host "Optional header size: $optionalHeaderSize"
    
    # Section table starts after COFF header (24 bytes) + optional header
    $sectionTableOffset = $peOffset + 24 + $optionalHeaderSize
    Write-Host "Section table offset: 0x$($sectionTableOffset.ToString('X'))"
    
    $lastSectionEnd = 0
    $lastRawDataEnd = 0
    
    # Parse each section
    for ($i = 0; $i -lt $numberOfSections; $i++) {
        $sectionOffset = $sectionTableOffset + ($i * 40)
        
        # Read section name (8 bytes)
        $nameBytes = $bytes[$sectionOffset..($sectionOffset + 7)]
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
        
        # Read section data
        $virtualSize = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 8)
        $virtualAddress = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 12)
        $rawSize = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 16)
        $rawOffset = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 20)
        
        Write-Host "Section $($i+1): '$name'"
        Write-Host "  Virtual Size: 0x$($virtualSize.ToString('X'))"
        Write-Host "  Virtual Address: 0x$($virtualAddress.ToString('X'))"
        Write-Host "  Raw Size: 0x$($rawSize.ToString('X'))"
        Write-Host "  Raw Offset: 0x$($rawOffset.ToString('X'))"
        Write-Host "  Raw End: 0x$(($rawOffset + $rawSize).ToString('X'))"
        
        $sectionEnd = $rawOffset + $rawSize
        if ($sectionEnd -gt $lastRawDataEnd) {
            $lastRawDataEnd = $sectionEnd
        }
    }
    
    Write-Host ""
    Write-Host "Last section raw data ends at: 0x$($lastRawDataEnd.ToString('X')) ($lastRawDataEnd bytes)"
    Write-Host "File size: 0x$($bytes.Length.ToString('X')) ($($bytes.Length) bytes)"
    Write-Host "Overlay data size: $(($bytes.Length - $lastRawDataEnd)) bytes"
}

Analyze-PESections $PEFile
