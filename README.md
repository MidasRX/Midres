# 🔥 Midres

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <b>Position-Independent Shellcode Generator - Donut Compatible</b>
</p>

---

## ⚠️ DISCLAIMER

> **FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY**
>
> This tool is designed for security professionals, penetration testers, and researchers conducting **authorized** security assessments. Unauthorized access to computer systems is **illegal**.
>
> The author is not responsible for any misuse or damage caused by this tool.

---

## 📋 Table of Contents

- [What is Midres?](#-what-is-midres)
- [How It Works](#-how-it-works)
- [Features](#-features)
- [Building](#-building)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Examples](#-examples)
- [Technical Deep Dive](#-technical-deep-dive)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## 🎯 What is Midres?

Midres is a **shellcode generator** written in Rust that converts Windows executables (PE files) into position-independent shellcode. It's compatible with the [Donut](https://github.com/TheWover/donut) loader format.

### What does it do?

1. Takes a Windows executable (.exe or .dll)
2. Converts it into raw shellcode
3. The shellcode can be injected into any process and will run the original program

### Why is this useful?

- **Red Team Operations**: Execute payloads in memory without touching disk
- **Security Research**: Study in-memory execution techniques
- **Malware Analysis**: Understand shellcode generation and injection
- **Penetration Testing**: Test endpoint detection capabilities

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         MIDRES FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐      ┌──────────────┐      ┌──────────────────┐  │
│   │  Input   │      │   Process    │      │     Output       │  │
│   │   .exe   │ ───► │  & Encrypt   │ ───► │   Shellcode      │  │
│   │   .dll   │      │  & Compress  │      │                  │  │
│   └──────────┘      └──────────────┘      └──────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

                    SHELLCODE STRUCTURE
┌─────────────────────────────────────────────────────────────────┐
│  Call Stub  │  DONUT_INSTANCE  │  Encrypted Payload  │  Loader  │
│   5 bytes   │    4752 bytes    │     Variable        │  ~13 KB  │
└─────────────────────────────────────────────────────────────────┘
```

### The Magic Behind Shellcode

**Position-Independent Code (PIC)** is code that can execute at any memory address without modification. Midres achieves this by:

1. **No Absolute Addresses**: All jumps and calls use relative offsets
2. **Dynamic API Resolution**: Windows APIs are found at runtime using PEB walking
3. **Self-Contained**: Everything needed is embedded in the shellcode

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Encryption** | Chaskey block cipher in CTR mode |
| 📦 **Compression** | LZ4 (fast) or Zstd (better ratio) |
| 🛡️ **AMSI Bypass** | Bypasses Antimalware Scan Interface |
| 🎯 **Multi-Arch** | x86, x64, or both combined |
| 📝 **Multiple Formats** | Binary, C, Rust, Python, PowerShell, etc. |
| ⚡ **.NET Support** | Full support for .NET Framework assemblies |

### Supported Input Types

| Type | Architecture | Status |
|------|-------------|--------|
| Native EXE | x86/x64 | ✅ |
| Native DLL | x86/x64 | ✅ |
| .NET EXE | Any | ✅ |
| .NET DLL | Any | ✅ |
| VBScript | Any | ✅ |
| JScript | Any | ✅ |

---

## 🔨 Building

### Prerequisites

- **Rust 1.70+** - Install from [rustup.rs](https://rustup.rs)
- **Windows 10/11** - Required for building
- **Visual Studio Build Tools** - For MSVC linker

### Build Commands

```powershell
# Clone the repository
git clone https://github.com/MidasRX/NovaLite.git
cd midres

# Build release binaries (optimized)
cargo build --release

# Binaries will be in:
# ./target/release/midres.exe     (shellcode generator)
# ./target/release/injector.exe   (process injector)
```

### Build Options

```powershell
# Debug build (faster compile, slower execution)
cargo build

# Release build with full optimization
cargo build --release

# Clean and rebuild
cargo clean; cargo build --release
```

---

## 📖 Usage

### Basic Usage

```powershell
# Generate shellcode from an executable
midres.exe -i payload.exe -o shellcode.bin

# With verbose output
midres.exe -i payload.exe -o shellcode.bin -v
```

### Inject Shellcode

```powershell
# Inject into a process by name
injector.exe --shellcode shellcode.bin -n notepad.exe

# Inject into a process by PID
injector.exe --shellcode shellcode.bin -p 1234
```

### All Options

```
midres.exe [OPTIONS] --input <INPUT> --output <OUTPUT>

OPTIONS:
  -i, --input <INPUT>       Input PE/DLL/EXE file
  -o, --output <OUTPUT>     Output file path
  -a, --arch <ARCH>         Architecture [default: x64]
                            Values: x86, x64, x84 (both)
  -f, --format <FORMAT>     Output format [default: binary]
                            Values: binary, base64, c, rust, python,
                                    powershell, csharp, hex, uuid
  -e, --encrypt             Enable encryption
  -c, --compress <TYPE>     Compression [default: lz4]
                            Values: none, lz4, zstd
  -x, --exit <EXIT>         Exit behavior [default: thread]
                            Values: thread, process, block
  -b, --bypass <BYPASS>     AMSI/ETW bypass [default: continue]
                            Values: none, abort, continue
      --class <CLASS>       .NET class name
      --method <METHOD>     .NET method or DLL export
      --args <ARGS>         Arguments for payload
      --domain <DOMAIN>     .NET AppDomain name
      --runtime <RUNTIME>   .NET runtime (v2.0.50727, v4.0.30319)
      --thread              Run EXE entrypoint as thread
      --entropy <ENTROPY>   Entropy level [default: 3]
                            1=none, 2=random, 3=full
  -v, --verbose             Verbose output
  -h, --help                Print help
```

---

## 📄 Output Formats

Midres can output shellcode in multiple formats for easy integration:

### Binary (Default)
Raw bytes, ready for injection.

### C/C++
```c
unsigned char midres_shellcode[1234] = {
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    // ...
};
unsigned int midres_shellcode_len = 1234;
```

### Rust
```rust
const MIDRES_SHELLCODE: [u8; 1234] = [
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    // ...
];
```

### Python
```python
midres_shellcode = b""
midres_shellcode += b"\x4d\x5a\x90\x00\x03\x00\x00\x00"
# ...
midres_shellcode_len = 1234
```

### PowerShell
```powershell
[Byte[]] $MidresShellcode = @(
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00
    # ...
)
```

### C#
```csharp
byte[] midresShellcode = new byte[1234] {
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    // ...
};
```

---

## 💡 Examples

### Example 1: Basic .NET Console App

```powershell
# Create shellcode from a .NET console application
midres.exe -i MyApp.exe -o payload.bin -v

# Output:
# [*] Initializing configuration...
# [+] Loaded input file: 12345 bytes
# [+] Module type: .NET EXE, Architecture: x64
# [+] Compressed: 12345 -> 8765 bytes (71.0%)
# [+] Generated shellcode: 25678 bytes
# [+] Written to: payload.bin
```

### Example 2: .NET DLL with Entry Point

```powershell
# Specify class and method for a .NET DLL
midres.exe -i MyLibrary.dll -o payload.bin \
    --class "MyNamespace.MyClass" \
    --method "Execute" \
    --args "arg1 arg2"
```

### Example 3: Native DLL

```powershell
# Generate shellcode from native DLL
midres.exe -i native.dll -o payload.bin --method "DllMain"
```

### Example 4: Generate PowerShell Loader

```powershell
# Output as PowerShell script
midres.exe -i payload.exe -o loader.ps1 -f powershell
```

### Example 5: No Encryption (Testing)

```powershell
# Disable encryption for debugging
midres.exe -i payload.exe -o debug.bin --entropy 1 -c none -v
```

---

## 🔬 Technical Deep Dive

### Shellcode Structure

```
+------------------+------------------------------------------+
| COMPONENT        | DESCRIPTION                              |
+------------------+------------------------------------------+
| Call Stub        | 5-byte relative call to loader           |
|                  | E8 XX XX XX XX                           |
+------------------+------------------------------------------+
| DONUT_INSTANCE   | 4752 bytes - Configuration & metadata    |
|   - Encryption   | Chaskey keys, IV, counter                |
|   - API Hashes   | MARU hashes for dynamic resolution       |
|   - Config       | Compression, bypass, exit options        |
|   - Module       | Embedded DONUT_MODULE (1328 bytes)       |
+------------------+------------------------------------------+
| Payload Data     | Compressed + Encrypted PE/DLL            |
+------------------+------------------------------------------+
| Loader Code      | ~13KB position-independent loader        |
+------------------+------------------------------------------+
```

### API Hashing (MARU)

Midres uses MARU hash for API resolution - a modified DJB2 with 64-bit output:

```rust
fn maru_hash(input: &[u8], iv: u64) -> u64 {
    let mut h: u64 = iv;
    for &byte in input {
        h = h ^ (byte as u64);
        h = h.wrapping_mul(0x5bd1e995);
        h = h ^ (h >> 15);
    }
    h
}
```

### Encryption (Chaskey)

- **Algorithm**: Chaskey lightweight block cipher
- **Mode**: CTR (Counter)
- **Key Size**: 128 bits (16 bytes)
- **Block Size**: 128 bits (16 bytes)

### Exit Behavior

| Mode | Description |
|------|-------------|
| `thread` | Exit current thread only (stealthy) |
| `process` | Terminate entire process |
| `block` | Block forever (for persistent payloads) |

---

## 🔧 Troubleshooting

### "Thread exited with code: 0"
- **Cause**: Payload executed but returned immediately
- **Fix**: Ensure payload has staying power (loop, wait, or service)

### ".NET Assembly fails to load"
- **Cause**: Missing dependencies or wrong runtime
- **Fix**: 
  - Use `--runtime v4.0.30319` explicitly
  - Merge dependencies with ILMerge or Costura.Fody

### "Access denied during injection"
- **Cause**: Insufficient privileges or protected process
- **Fix**: Run as Administrator or target different process

### Debug Mode

Generate unencrypted shellcode for analysis:

```powershell
midres.exe -i payload.exe -o debug.bin --entropy 1 -c none -v
```

---

## 📁 Project Structure

```
midres/
├── Cargo.toml           # Workspace configuration
├── midres-gen/          # Main shellcode generator
│   └── src/
│       ├── main.rs           # CLI entry point
│       ├── donut_instance.rs # Core structures
│       ├── pe.rs             # PE file parsing
│       ├── crypto.rs         # Chaskey encryption
│       ├── compress.rs       # LZ4/Zstd compression
│       ├── output.rs         # Format generation
│       └── bundle.rs         # .NET bundle extraction
├── midres-common/       # Shared types & constants
│   └── src/lib.rs
└── map-injector/        # Process injection tool
    └── src/main.rs
```

---

## 📚 References

- [Donut](https://github.com/TheWover/donut) - Original project by TheWover & odzhan
- [CLR Injection](https://blog.xpnsec.com/) - .NET in-memory techniques
- [PEB Walking](https://www.ired.team/) - Dynamic API resolution

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

```
MIT License

Copyright (c) 2024-2026 MidasRX

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

<p align="center">
  <b>⭐ Star this repo if you find it useful! ⭐</b>
</p>

<p align="center">
  Made with 🦀 by MidasRX
</p>
