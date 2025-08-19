# Scripts Table of Contents

This directory contains utility scripts and tools for analyzing, debugging, and testing Authenticode signatures with YubiKey PIV hardware.

## 🔍 PE File Analysis Tools

### `analyze-pe.ps1`

**Purpose**: Analyze PE file sections, headers, and certificate table structure  
**Usage**: `.\analyze-pe.ps1 <file.exe>`  
**Agent Use**: Use when investigating PE structure issues or certificate table placement problems.

### `extract_pkcs7.ps1` ⭐ **Essential Tool**

**Purpose**: Extract PKCS#7 signatures from signed PE files (PE32/PE32+ aware)  
**Usage**: `.\extract_pkcs7.ps1 <signed.exe> <output.p7s>`  
**Agent Use**: **Essential for all PKCS#7 analysis workflows**. Extracts embedded signatures for comparison with analyzers. Handles multiple certificates and WIN_CERTIFICATE structures correctly.

## 🧪 Testing and Validation Tools

### `test.ps1` ⭐ **Comprehensive Test Script**

**Purpose**: Complete end-to-end testing of yubikey-signer implementation  
**Usage**: `.\test.ps1` or `.\test.ps1 -SkipYubiKey` (simulation mode)  
**Agent Use**: **Primary testing tool** for validating the complete signing pipeline. Creates unsigned PE, signs with/without timestamp, and verifies Windows accepts both signatures.
