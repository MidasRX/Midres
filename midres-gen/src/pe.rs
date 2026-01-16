//! PE file analysis and parsing

use anyhow::{Result, bail, Context};
use goblin::pe::PE;
use goblin::pe::header::*;
use midres_common::*;

use crate::config::Config;

/// COFF characteristic flag for DLL
const COFF_CHARACTERISTIC_DLL: u16 = 0x2000;

/// Information extracted from PE analysis
pub struct PeInfo {
    /// Module type detected
    pub module_type: ModuleType,
    /// Architecture
    pub arch: Architecture,
    /// Is .NET assembly
    pub is_dotnet: bool,
    /// .NET runtime version if applicable
    pub runtime_version: Option<String>,
    /// Entry point RVA
    pub entry_point: u32,
    /// Image base
    pub image_base: u64,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Is DLL
    pub is_dll: bool,
    /// Export names (for DLLs)
    pub exports: Vec<String>,
    /// Import DLLs
    pub imports: Vec<String>,
    /// Has TLS callbacks
    pub has_tls: bool,
    /// Has relocations
    pub has_relocs: bool,
    /// CLR header if .NET
    pub clr_header: Option<ClrHeader>,
}

/// CLR/COR header information
pub struct ClrHeader {
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub flags: u32,
    pub entry_point_token: u32,
}

impl PeInfo {
    pub fn module_type_str(&self) -> &'static str {
        match self.module_type {
            ModuleType::NetDll => ".NET DLL",
            ModuleType::NetExe => ".NET EXE",
            ModuleType::NativeDll => "Native DLL",
            ModuleType::NativeExe => "Native EXE",
            ModuleType::Vbs => "VBScript",
            ModuleType::Js => "JavaScript",
        }
    }
    
    pub fn arch_str(&self) -> &'static str {
        match self.arch {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::X84 => "x84",
            Architecture::Any => "any",
        }
    }
}

/// Analyze a PE file and extract relevant information
pub fn analyze(data: &[u8], config: &Config) -> Result<PeInfo> {
    // Check for script files first
    if is_vbscript(data) {
        return Ok(PeInfo {
            module_type: ModuleType::Vbs,
            arch: Architecture::Any,
            is_dotnet: false,
            runtime_version: None,
            entry_point: 0,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            size_of_image: 0,
            size_of_headers: 0,
            subsystem: 0,
            dll_characteristics: 0,
            is_dll: false,
            exports: Vec::new(),
            imports: Vec::new(),
            has_tls: false,
            has_relocs: false,
            clr_header: None,
        });
    }
    
    if is_javascript(data) {
        return Ok(PeInfo {
            module_type: ModuleType::Js,
            arch: Architecture::Any,
            is_dotnet: false,
            runtime_version: None,
            entry_point: 0,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            size_of_image: 0,
            size_of_headers: 0,
            subsystem: 0,
            dll_characteristics: 0,
            is_dll: false,
            exports: Vec::new(),
            imports: Vec::new(),
            has_tls: false,
            has_relocs: false,
            clr_header: None,
        });
    }
    
    // Parse as PE
    let pe = PE::parse(data).context("Failed to parse PE file")?;
    
    // Determine architecture from PE header
    let pe_arch = match pe.header.coff_header.machine {
        COFF_MACHINE_X86 => Architecture::X86,
        COFF_MACHINE_X86_64 => Architecture::X64,
        _ => bail!("Unsupported architecture: {:#x}", pe.header.coff_header.machine),
    };
    
    let is_dll = pe.header.coff_header.characteristics & COFF_CHARACTERISTIC_DLL != 0;
    
    // Check for .NET
    let (is_dotnet, clr_header, runtime_version) = check_dotnet(&pe, data)?;
    
    // For .NET IL-only assemblies, the PE architecture doesn't matter
    // CLR can load x86 PE as 64-bit process if IL-only
    // Check CLR flags: bit 1 = COMIMAGE_FLAGS_32BITREQUIRED
    let is_il_only = clr_header.as_ref()
        .map(|h| (h.flags & 0x1) != 0 && (h.flags & 0x2) == 0)  // IL-only and NOT 32-bit required
        .unwrap_or(false);
    
    // Use config arch for .NET IL-only assemblies, otherwise use PE arch
    let arch = if is_dotnet && is_il_only {
        // .NET IL-only can run as any architecture
        if config.arch == Architecture::Any || config.arch == Architecture::X84 {
            pe_arch  // Use PE arch if config doesn't specify
        } else {
            config.arch  // Use whatever arch the user specified
        }
    } else {
        // For native code or 32-bit required .NET, validate architecture
        if config.arch != Architecture::Any && config.arch != Architecture::X84 && config.arch != pe_arch {
            bail!(
                "Architecture mismatch: PE is {:?}, config specifies {:?}",
                pe_arch, config.arch
            );
        }
        pe_arch
    };
    
    // Determine module type
    let module_type = if is_dotnet {
        if is_dll { ModuleType::NetDll } else { ModuleType::NetExe }
    } else {
        if is_dll { ModuleType::NativeDll } else { ModuleType::NativeExe }
    };
    
    // Extract optional header info
    let (entry_point, image_base, section_alignment, file_alignment, 
         size_of_image, size_of_headers, subsystem, dll_characteristics) = 
        match pe.header.optional_header {
            Some(ref opt) => {
                let std = &opt.standard_fields;
                let win = &opt.windows_fields;
                (
                    std.address_of_entry_point,
                    win.image_base,
                    win.section_alignment,
                    win.file_alignment,
                    win.size_of_image,
                    win.size_of_headers,
                    win.subsystem,
                    win.dll_characteristics,
                )
            }
            None => bail!("PE file has no optional header"),
        };
    
    // Get exports
    let exports: Vec<String> = pe.exports.iter()
        .filter_map(|e| e.name.map(|s| s.to_string()))
        .collect();
    
    // Get imports
    let imports: Vec<String> = pe.imports.iter()
        .map(|i| i.dll.to_string())
        .collect();
    
    // Check for TLS
    let has_tls = pe.header.optional_header
        .as_ref()
        .and_then(|opt| opt.data_directories.get_tls_table())
        .map(|t| t.virtual_address != 0)
        .unwrap_or(false);
    
    // Check for relocations
    let has_relocs = pe.header.optional_header
        .as_ref()
        .and_then(|opt| opt.data_directories.get_base_relocation_table())
        .map(|r| r.virtual_address != 0)
        .unwrap_or(false);
    
    Ok(PeInfo {
        module_type,
        arch,
        is_dotnet,
        runtime_version,
        entry_point: entry_point as u32,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        subsystem,
        dll_characteristics,
        is_dll,
        exports,
        imports,
        has_tls,
        has_relocs,
        clr_header,
    })
}

fn check_dotnet(pe: &PE, data: &[u8]) -> Result<(bool, Option<ClrHeader>, Option<String>)> {
    // Check COM descriptor / CLR header
    let clr_dir = pe.header.optional_header
        .as_ref()
        .and_then(|opt| opt.data_directories.get_clr_runtime_header());
    
    match clr_dir {
        Some(dir) if dir.virtual_address != 0 && dir.size >= 72 => {
            // Find the CLR header in the file
            if let Some(offset) = rva_to_offset(pe, dir.virtual_address) {
                if offset + 72 <= data.len() {
                    let clr_data = &data[offset..];
                    
                    // Parse CLR header
                    let major = u16::from_le_bytes([clr_data[4], clr_data[5]]);
                    let minor = u16::from_le_bytes([clr_data[6], clr_data[7]]);
                    let flags = u32::from_le_bytes([clr_data[16], clr_data[17], clr_data[18], clr_data[19]]);
                    let entry_token = u32::from_le_bytes([clr_data[20], clr_data[21], clr_data[22], clr_data[23]]);
                    
                    // Try to get runtime version from metadata
                    let runtime_version = detect_runtime_version(pe, data);
                    
                    return Ok((true, Some(ClrHeader {
                        major_runtime_version: major,
                        minor_runtime_version: minor,
                        flags,
                        entry_point_token: entry_token,
                    }), runtime_version));
                }
            }
        }
        _ => {}
    }
    
    Ok((false, None, None))
}

fn detect_runtime_version(pe: &PE, data: &[u8]) -> Option<String> {
    // Look for runtime version in metadata
    // The version string is typically at a fixed offset in the metadata header
    
    // Check for mscoree.dll import which indicates .NET
    let has_mscoree = pe.imports.iter().any(|i| i.dll.eq_ignore_ascii_case("mscoree.dll"));
    
    if has_mscoree {
        // Try to find the version string in the file
        // Look for "v4.0" or "v2.0" patterns
        let data_str = String::from_utf8_lossy(data);
        
        if data_str.contains("v4.0.30319") {
            return Some("v4.0.30319".to_string());
        } else if data_str.contains("v2.0.50727") {
            return Some("v2.0.50727".to_string());
        }
        
        // Default to v4 for modern assemblies
        return Some("v4.0.30319".to_string());
    }
    
    None
}

fn rva_to_offset(pe: &PE, rva: u32) -> Option<usize> {
    for section in &pe.sections {
        let section_rva = section.virtual_address;
        let section_size = section.virtual_size;
        
        if rva >= section_rva && rva < section_rva + section_size {
            let offset = section.pointer_to_raw_data + (rva - section_rva);
            return Some(offset as usize);
        }
    }
    None
}

fn is_vbscript(data: &[u8]) -> bool {
    // Check for common VBScript patterns
    let header = String::from_utf8_lossy(&data[..data.len().min(1024)]).to_lowercase();
    
    header.contains("dim ") || 
    header.contains("sub ") || 
    header.contains("function ") ||
    header.contains("wscript.") ||
    header.contains("createobject(")
}

fn is_javascript(data: &[u8]) -> bool {
    // Check for common JavaScript patterns
    let header = String::from_utf8_lossy(&data[..data.len().min(1024)]).to_lowercase();
    
    header.contains("var ") || 
    header.contains("function ") || 
    header.contains("new activexobject(") ||
    header.contains("wscript.") ||
    (header.contains("{") && header.contains("}") && header.contains("(") && header.contains(")"))
}

/// Calculate the size needed to map the PE in memory
pub fn calculate_image_size(pe_info: &PeInfo) -> usize {
    pe_info.size_of_image as usize
}

/// Get list of required DLLs for the loader
pub fn get_required_dlls(pe_info: &PeInfo) -> Vec<&'static str> {
    let mut dlls = vec!["ntdll.dll", "kernel32.dll"];
    
    if pe_info.is_dotnet {
        dlls.extend(&["mscoree.dll", "ole32.dll", "oleaut32.dll"]);
    }
    
    match pe_info.module_type {
        ModuleType::Vbs | ModuleType::Js => {
            dlls.extend(&["ole32.dll", "oleaut32.dll"]);
        }
        _ => {}
    }
    
    dlls
}
