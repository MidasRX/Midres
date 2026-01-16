//! .NET Single-File Bundle extraction
//! 
//! .NET 5+ apps built with PublishSingleFile bundle everything into one native stub.
//! This module detects and extracts the main assembly from such bundles.

/// Bundle header signature for .NET single-file apps (SHA-256 of ".net core bundle")
/// This signature is located 8 bytes AFTER the header offset field
const BUNDLE_SIGNATURE: &[u8] = &[
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
    0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
];

/// Information about extracted assembly
pub struct SingleFileInfo {
    pub data: Vec<u8>,
    pub version: String,
    pub name: String,
}

/// File type in bundle
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum BundleFileType {
    Unknown = 0,
    Assembly = 1,
    NativeLibrary = 2,
    DepsJson = 3,
    RuntimeConfigJson = 4,
    Symbols = 5,
}

/// Bundle file entry
#[derive(Debug)]
pub struct BundleEntry {
    pub offset: u64,
    pub size: u64,
    pub compressed_size: u64,
    pub file_type: u8,
    pub relative_path: String,
}

/// Find the bundle marker signature in the file
fn find_bundle_signature(data: &[u8]) -> Option<usize> {
    // Search in the whole file - the marker is at a fixed location
    // compiled into the apphost, typically in the .rdata section
    for i in 0..data.len().saturating_sub(BUNDLE_SIGNATURE.len()) {
        if &data[i..i+32] == BUNDLE_SIGNATURE {
            return Some(i);
        }
    }
    None
}

/// Check if a file is a .NET single-file bundle
pub fn is_single_file_bundle(data: &[u8]) -> bool {
    find_bundle_signature(data).is_some()
}

/// Read a 7-bit encoded length (LEB128-like)
fn read_path_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }
    
    let first_byte = data[*pos];
    *pos += 1;
    
    if (first_byte & 0x80) == 0 {
        Some(first_byte as usize)
    } else {
        if *pos >= data.len() {
            return None;
        }
        let second_byte = data[*pos];
        *pos += 1;
        Some(((second_byte as usize) << 7) | ((first_byte & 0x7f) as usize))
    }
}

/// Parse bundle manifest and extract entries
fn parse_bundle_entries(data: &[u8], header_offset: u64) -> Option<(u32, Vec<BundleEntry>)> {
    let header_pos = header_offset as usize;
    
    if header_pos + 12 > data.len() {
        return None;
    }
    
    // Read fixed header
    let major_version = u32::from_le_bytes(data[header_pos..header_pos+4].try_into().ok()?);
    let minor_version = u32::from_le_bytes(data[header_pos+4..header_pos+8].try_into().ok()?);
    let num_files = i32::from_le_bytes(data[header_pos+8..header_pos+12].try_into().ok()?);
    
    let mut pos = header_pos + 12;
    
    // Read bundle ID (length-prefixed string)
    let id_len = read_path_length(data, &mut pos)?;
    pos += id_len; // Skip bundle ID
    
    // For v2+ bundles, skip additional fixed fields
    if major_version >= 2 {
        pos += 8;  // deps_json_offset
        pos += 8;  // deps_json_size
        pos += 8;  // runtimeconfig_offset
        pos += 8;  // runtimeconfig_size
        pos += 8;  // flags
    }
    
    let mut entries = Vec::new();
    
    for _ in 0..num_files {
        if pos + 25 > data.len() {
            break;
        }
        
        let offset = u64::from_le_bytes(data[pos..pos+8].try_into().ok()?);
        pos += 8;
        let size = u64::from_le_bytes(data[pos..pos+8].try_into().ok()?);
        pos += 8;
        
        // For v6+, read compressed size
        let compressed_size = if major_version >= 6 {
            let cs = u64::from_le_bytes(data[pos..pos+8].try_into().ok()?);
            pos += 8;
            cs
        } else {
            size
        };
        
        let file_type = data[pos];
        pos += 1;
        
        // Read path (length-prefixed)
        let path_len = read_path_length(data, &mut pos)?;
        
        if pos + path_len > data.len() {
            break;
        }
        
        let relative_path = String::from_utf8_lossy(&data[pos..pos+path_len]).to_string();
        pos += path_len;
        
        entries.push(BundleEntry {
            offset,
            size,
            compressed_size,
            file_type,
            relative_path,
        });
    }
    
    Some((major_version, entries))
}

/// Extract the main assembly from a .NET single-file bundle
/// Returns the extracted assembly data, or None if not a bundle
pub fn extract_main_assembly(data: &[u8]) -> Option<SingleFileInfo> {
    // Find the bundle signature
    let sig_offset = find_bundle_signature(data)?;
    
    // Header offset is 8 bytes BEFORE the signature
    if sig_offset < 8 {
        return None;
    }
    
    let header_offset = u64::from_le_bytes(
        data[sig_offset-8..sig_offset].try_into().ok()?
    );
    
    // Header offset of 0 means this is not a bundled app
    if header_offset == 0 {
        return None;
    }
    
    let (version, entries) = parse_bundle_entries(data, header_offset)?;
    
    // Find the main assembly - type 1 (Assembly) with .dll extension
    // The first Assembly type entry is usually the main one
    let main_entry = entries.iter()
        .find(|e| e.file_type == 1 && e.relative_path.ends_with(".dll"))?;
    
    let start = main_entry.offset as usize;
    let end = start + main_entry.size as usize;
    
    if end > data.len() {
        return None;
    }
    
    let assembly_data = data[start..end].to_vec();
    
    // Verify it's a valid PE file
    if assembly_data.len() < 64 || &assembly_data[0..2] != b"MZ" {
        return None;
    }
    
    Some(SingleFileInfo {
        data: assembly_data,
        version: format!("{}.0", version),
        name: main_entry.relative_path.clone(),
    })
}
