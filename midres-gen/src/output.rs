//! Output formatting for shellcode

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;
use midres_common::OutputFormat;

/// Format shellcode for output
pub fn format_output(data: &[u8], format: OutputFormat) -> Result<Vec<u8>> {
    let formatted = match format {
        OutputFormat::Binary => data.to_vec(),
        OutputFormat::Base64 => format_base64(data),
        OutputFormat::C => format_c(data),
        OutputFormat::Rust => format_rust(data),
        OutputFormat::Python => format_python(data),
        OutputFormat::PowerShell => format_powershell(data),
        OutputFormat::CSharp => format_csharp(data),
        OutputFormat::Hex => format_hex(data),
        OutputFormat::Uuid => format_uuid(data),
    };
    
    Ok(formatted)
}

fn format_base64(data: &[u8]) -> Vec<u8> {
    BASE64.encode(data).into_bytes()
}

fn format_hex(data: &[u8]) -> Vec<u8> {
    hex::encode(data).into_bytes()
}

fn format_c(data: &[u8]) -> Vec<u8> {
    let mut output = String::new();
    
    output.push_str("// Midres shellcode - Generated payload\n");
    output.push_str(&format!("// Size: {} bytes\n\n", data.len()));
    output.push_str(&format!("unsigned char midres_shellcode[{}] = {{\n", data.len()));
    
    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str("    ");
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("0x{:02x}", byte));
            if i * 16 + j < data.len() - 1 {
                output.push_str(", ");
            }
        }
        output.push('\n');
    }
    
    output.push_str("};\n\n");
    output.push_str(&format!("unsigned int midres_shellcode_len = {};\n", data.len()));
    
    output.into_bytes()
}

fn format_rust(data: &[u8]) -> Vec<u8> {
    let mut output = String::new();
    
    output.push_str("// Midres shellcode - Generated payload\n");
    output.push_str(&format!("// Size: {} bytes\n\n", data.len()));
    output.push_str(&format!("const midres_SHELLCODE: [u8; {}] = [\n", data.len()));
    
    for chunk in data.chunks(16) {
        output.push_str("    ");
        for byte in chunk {
            output.push_str(&format!("0x{:02x}, ", byte));
        }
        output.push('\n');
    }
    
    output.push_str("];\n");
    
    output.into_bytes()
}

fn format_python(data: &[u8]) -> Vec<u8> {
    let mut output = String::new();
    
    output.push_str("# Midres shellcode - Generated payload\n");
    output.push_str(&format!("# Size: {} bytes\n\n", data.len()));
    output.push_str("midres_shellcode = b\"\"\n");
    
    for chunk in data.chunks(16) {
        output.push_str("midres_shellcode += b\"");
        for byte in chunk {
            output.push_str(&format!("\\x{:02x}", byte));
        }
        output.push_str("\"\n");
    }
    
    output.push_str(&format!("\nmidres_shellcode_len = {}\n", data.len()));
    
    output.into_bytes()
}

fn format_powershell(data: &[u8]) -> Vec<u8> {
    let mut output = String::new();
    
    output.push_str("# Midres shellcode - Generated payload\n");
    output.push_str(&format!("# Size: {} bytes\n\n", data.len()));
    
    // Base64 encoded version
    let b64 = BASE64.encode(data);
    output.push_str(&format!("$VenomBase64 = \"{}\"\n\n", b64));
    
    // Byte array version
    output.push_str("[Byte[]] $VenomShellcode = @(\n");
    
    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str("    ");
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("0x{:02X}", byte));
            if i * 16 + j < data.len() - 1 {
                output.push_str(", ");
            }
        }
        output.push('\n');
    }
    
    output.push_str(")\n");
    
    output.into_bytes()
}

fn format_csharp(data: &[u8]) -> Vec<u8> {
    let mut output = String::new();
    
    output.push_str("// Midres shellcode - Generated payload\n");
    output.push_str(&format!("// Size: {} bytes\n\n", data.len()));
    output.push_str(&format!("byte[] venomShellcode = new byte[{}] {{\n", data.len()));
    
    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str("    ");
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("0x{:02x}", byte));
            if i * 16 + j < data.len() - 1 {
                output.push_str(", ");
            }
        }
        output.push('\n');
    }
    
    output.push_str("};\n");
    
    output.into_bytes()
}

fn format_uuid(data: &[u8]) -> Vec<u8> {
    let mut output = String::new();
    
    output.push_str("// Midres shellcode - UUID formatted\n");
    output.push_str(&format!("// Size: {} bytes ({} UUIDs)\n\n", data.len(), (data.len() + 15) / 16));
    output.push_str("const char* midres_uuids[] = {\n");
    
    // Pad data to multiple of 16 bytes
    let mut padded = data.to_vec();
    while padded.len() % 16 != 0 {
        padded.push(0x00);
    }
    
    for chunk in padded.chunks(16) {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(chunk);
        
        // Create UUID from bytes
        let uuid = Uuid::from_bytes(bytes);
        output.push_str(&format!("    \"{}\",\n", uuid));
    }
    
    output.push_str("};\n");
    output.push_str(&format!("int midres_uuid_count = {};\n", (data.len() + 15) / 16));
    
    output.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_hex() {
        let data = &[0xde, 0xad, 0xbe, 0xef];
        let result = format_output(data, OutputFormat::Hex).unwrap();
        assert_eq!(&result, b"deadbeef");
    }
    
    #[test]
    fn test_format_base64() {
        let data = &[0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let result = format_output(data, OutputFormat::Base64).unwrap();
        assert_eq!(&result, b"SGVsbG8=");
    }
    
    #[test]
    fn test_format_c() {
        let data = &[0x90, 0x90, 0xcc];
        let result = format_output(data, OutputFormat::C).unwrap();
        let result_str = String::from_utf8(result).unwrap();
        
        assert!(result_str.contains("unsigned char midres_shellcode[3]"));
        assert!(result_str.contains("0x90, 0x90, 0xcc"));
    }
}
