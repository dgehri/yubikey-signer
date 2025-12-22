# MSI Signing Technical Documentation

This document describes the technical implementation of MSI (Windows Installer) file signing in yubikey-signer.

## Overview

MSI files are OLE Compound Documents (also known as Compound File Binary format or CFB). Signing an MSI file involves:

1. Computing a hash of the file contents in a specific order
2. Creating a PKCS#7 signature containing that hash
3. Embedding the signature into the MSI file as a special stream

## Implementation Architecture

yubikey-signer implements MSI signing in pure Rust without external dependencies:

| Component           | File                           | Purpose                          |
| ------------------- | ------------------------------ | -------------------------------- |
| Hash computation    | `src/domain/msi/hash.rs`       | Authenticode-compatible MSI hash |
| CFB parsing         | `src/domain/msi/parse.rs`      | Read MSI structure               |
| CFB writing         | `src/domain/msi/cfb_writer.rs` | Rewrite MSI CFB container        |
| Signature embedding | `src/domain/msi/embed.rs`      | Embed PKCS#7 into MSI            |
| MSI signer service  | `src/services/msi_signer.rs`   | High-level signing API           |

### The Solution: Custom CFB Writer

The critical insight was that Windows validates not just the signature content, but also expects a specific CFB container structure. The standard Rust `cfb` crate reorganizes the file in ways that break Windows validation.

Our solution (`cfb_writer.rs`) implements a complete CFB file rewriter:

1. **Sector order**: streams → ministream → miniFAT → directory → FAT
2. **Directory tree**: Per-storage degenerate red-black trees using right siblings
3. **Stream order**: Sorted by `dirent_cmp_tree` (length-first, then codepoint)

## Compound File Binary (CFB) Format

MSI files use the Microsoft Compound File Binary format, which is essentially a file system within a file:

- **Sectors**: Fixed-size blocks (512 or 4096 bytes)
- **Mini-sectors**: Small blocks (64 bytes) for streams under 4096 bytes
- **FAT**: File Allocation Table tracking sector chains
- **Mini FAT**: FAT for the mini-stream
- **Directory Entries**: Metadata for each stream/storage organized as a red-black tree

### Key Constants

```
MINI_STREAM_CUTOFF_SIZE = 4096 bytes
MINI_SECTOR_SIZE = 64 bytes
SECTOR_SIZE = 512 or 4096 bytes (v3 or v4)
ENDOFCHAIN = 0xFFFFFFFE
NOSTREAM = 0xFFFFFFFF
```

## Signature Streams

Two streams are involved in MSI signing:

1. **`\x05DigitalSignature`**: The PKCS#7 signature (DER-encoded)
2. **`\x05MsiDigitalSignatureEx`** (optional): Extended signature that includes metadata hash

The `\x05` prefix indicates these are special system streams.

## Hash Computation Algorithm

The hash algorithm works as follows:

### Stream Content Hash

1. Get all children of the current directory entry
2. **Sort children** using raw UTF-16LE byte comparison (`memcmp`)
   - If bytes match up to the minimum length, the **longer name wins** (comes first)
3. For each child in sorted order:
   - **Skip** signature streams (`\x05DigitalSignature` and `\x05MsiDigitalSignatureEx`) at root level only
   - If stream: read and hash the stream content
   - If storage: recursively process subdirectory
4. After processing all children, **append the directory's 16-byte CLSID**

### UTF-16LE Name Comparison

```rust
fn msi_stream_compare_utf16(a: &[u8], b: &[u8]) -> Ordering {
    let min_len = a.len().min(b.len());
    
    // Compare byte-by-byte
    for i in 0..min_len {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    
    // Longer name wins (comes first!)
    match a.len().cmp(&b.len()) {
        Ordering::Less => Ordering::Greater,    // a shorter → a comes after
        Ordering::Greater => Ordering::Less,    // a longer → a comes first
        Ordering::Equal => Ordering::Equal,
    }
}
```

### MsiDigitalSignatureEx (Extended Signature)

When present, the hash includes metadata:

1. Compute a "pre-hash" of metadata (names, sizes, timestamps)
2. The final hash = Hash(pre-hash + content-hash-input)
3. Store pre-hash in `MsiDigitalSignatureEx` stream

## SpcSipInfo Structure

MSI signatures use `SpcSipInfo` instead of `SpcPeImageData`:

```rust
// SpcSipInfo for MSI files
SpcSipInfo {
    a: 1,  // CRITICAL: Version must be 1, not 2!
    b: 0,
    c: 0,
    d: 0,
    e: 0,
    f: 0,
    uuid: MSI_UUID  // f1100c00-0000-0000-c000-000000000046
}
```

**Note**: The version field (`a`) must be `1`. Using version 2 causes Windows to reject the signature.

## Signature Embedding

### CFB Directory Tree Structure

The key to Windows compatibility is the directory tree structure. Our implementation builds per-storage degenerate red-black trees:

```
Root Entry (no siblings)
└── child → child1.right_sibling → child2.right_sibling → ...
    
Storage Entry
└── child → subchild1.right_sibling → subchild2.right_sibling → ...
```

**Critical rules**:

- Root entry has NO siblings (`left_sibling = right_sibling = NOSTREAM`)
- Each storage's children are linked only via `right_sibling`
- Children are sorted using `dirent_cmp_tree` (length-first, then codepoint)
- All nodes have `left_sibling = NOSTREAM` (degenerate tree)

### File Writing Order

The CFB writer produces sectors in this order:

```
Offset 0x000: Header (512 bytes for v3)
Sector 0+:    Large streams (> 4096 bytes)
Sector N:     Mini-stream container (root entry data)
Sector M:     Mini FAT
Sector D:     Directory entries
Sector F:     FAT
```

### Sorting Functions

```rust
// For hashing (content order):
dirent_cmp_hash: memcmp on UTF-16LE bytes, longer name wins (comes first)

// For directory tree (entry order):  
dirent_cmp_tree: length first, then codepoint comparison
```

## Usage

### Command Line

```bash
# Sign MSI without timestamp
yubikey-signer sign input.msi --output signed.msi

# Sign MSI with timestamp
yubikey-signer sign input.msi --output signed.msi --timestamp

# Remote signing (via YubiKey proxy server)
yubikey-signer sign input.msi --output signed.msi \
    --remote "https://sign.example.com" \
    --header "CF-Access-Client-Id: ..." \
    --header "CF-Access-Client-Secret: ..."
```

## Verification

To verify a signed MSI file:

```powershell
Get-AuthenticodeSignature "path\to\file.msi"
```

## Testing

The test script (`scripts/test.ps1`) includes MSI signing tests:

```powershell
.\scripts\test.ps1
```

Output includes:

```
✅ MsiSigned: PASSED
✅ MsiValid: PASSED
```

Integration tests in `tests/msi_signing_tests.rs`:

- `test_msi_remote_signing` - Signs MSI via remote server
- `test_msi_remote_signing_with_timestamp` - Signs MSI with RFC 3161 timestamp
- `test_msi_signature_verification` - Verifies Windows accepts signature

## Debugging Tools

### Inspecting MSI Structure

```powershell
# Read CFB header fields (v3 = 512-byte sectors)
$data = [IO.File]::ReadAllBytes("file.msi")
$dirSector = [BitConverter]::ToUInt32($data, 0x30)
$dirOffset = ($dirSector + 1) * 512

# Read directory entries
for ($i = 0; $i -lt 8; $i++) {
    $off = $dirOffset + $i * 128
    $nameLen = [BitConverter]::ToUInt16($data, $off + 0x40)
    if ($nameLen -gt 0) {
        $name = [Text.Encoding]::Unicode.GetString($data, $off, $nameLen - 2)
        $left = [BitConverter]::ToInt32($data, $off + 0x44)
        $right = [BitConverter]::ToInt32($data, $off + 0x48)
        $child = [BitConverter]::ToInt32($data, $off + 0x4C)
        Write-Host "[$i] '$name' L=$left R=$right C=$child"
    }
}
```

### Verifying with SignTool

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe" `
    verify /pa /debug "file.msi"
```

## References

- [MS-CFB: Compound File Binary Format](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/)
- [Authenticode specification](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx)
