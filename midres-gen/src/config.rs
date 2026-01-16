//! Configuration management for Midres generator

use anyhow::{Result, bail};
use midres_common::*;

/// Generator configuration
pub struct Config {
    /// Target architecture
    pub arch: Architecture,
    /// Output format
    pub format: OutputFormat,
    /// Enable encryption
    pub encrypt: bool,
    /// Compression type
    pub compression: CompressionType,
    /// Exit behavior
    pub exit_opt: ExitOption,
    /// Bypass level
    pub bypass: BypassLevel,
    /// Class name for .NET
    pub class_name: Option<String>,
    /// Method name
    pub method_name: Option<String>,
    /// Arguments
    pub args: Option<String>,
    /// AppDomain name
    pub domain: Option<String>,
    /// Runtime version
    pub runtime: Option<String>,
    /// Run as thread
    pub thread: bool,
    /// Remote URL for staging
    pub url: Option<String>,
    /// Entropy level
    pub entropy: EntropyLevel,
    /// Header option
    pub headers: HeaderOption,
}

impl Config {
    pub fn from_args(args: &super::Args) -> Result<Self> {
        let arch = match args.arch.to_lowercase().as_str() {
            "x86" | "32" => Architecture::X86,
            "x64" | "64" => Architecture::X64,
            "x84" | "both" => Architecture::X84,
            "any" => Architecture::Any,
            _ => bail!("Invalid architecture: {}. Use: x86, x64, x84, any", args.arch),
        };
        
        let format = match args.format.to_lowercase().as_str() {
            "binary" | "bin" | "raw" => OutputFormat::Binary,
            "base64" | "b64" => OutputFormat::Base64,
            "c" | "h" => OutputFormat::C,
            "rust" | "rs" => OutputFormat::Rust,
            "python" | "py" => OutputFormat::Python,
            "powershell" | "ps1" => OutputFormat::PowerShell,
            "csharp" | "cs" => OutputFormat::CSharp,
            "hex" => OutputFormat::Hex,
            "uuid" => OutputFormat::Uuid,
            _ => bail!("Invalid format: {}. Use: binary, base64, c, rust, python, powershell, csharp, hex, uuid", args.format),
        };
        
        let compression = match args.compress.to_lowercase().as_str() {
            "none" | "no" => CompressionType::None,
            "lz4" => CompressionType::Lz4,
            "zstd" | "zst" => CompressionType::Zstd,
            "lznt1" => CompressionType::Lznt1,
            "xpress" => CompressionType::Xpress,
            _ => bail!("Invalid compression: {}. Use: none, lz4, zstd", args.compress),
        };
        
        let exit_opt = match args.exit.to_lowercase().as_str() {
            "thread" | "t" => ExitOption::Thread,
            "process" | "p" => ExitOption::Process,
            "block" | "b" => ExitOption::Block,
            _ => bail!("Invalid exit option: {}. Use: thread, process, block", args.exit),
        };
        
        let bypass = match args.bypass.to_lowercase().as_str() {
            "none" | "no" => BypassLevel::None,
            "abort" | "a" => BypassLevel::Abort,
            "continue" | "c" | "yes" => BypassLevel::Continue,
            _ => bail!("Invalid bypass option: {}. Use: none, abort, continue", args.bypass),
        };
        
        let entropy = match args.entropy {
            1 => EntropyLevel::None,
            2 => EntropyLevel::Random,
            3 => EntropyLevel::Full,
            _ => bail!("Invalid entropy level: {}. Use: 1 (none), 2 (random), 3 (full)", args.entropy),
        };
        
        Ok(Config {
            arch,
            format,
            encrypt: args.encrypt,
            compression,
            exit_opt,
            bypass,
            class_name: args.class.clone(),
            method_name: args.method.clone(),
            args: args.args.clone(),
            domain: args.domain.clone(),
            runtime: args.runtime.clone(),
            thread: args.thread,
            url: args.url.clone(),
            entropy,
            headers: HeaderOption::Overwrite,
        })
    }
    
    pub fn arch_str(&self) -> &'static str {
        match self.arch {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::X84 => "x84 (both)",
            Architecture::Any => "any",
        }
    }
    
    pub fn format_str(&self) -> &'static str {
        match self.format {
            OutputFormat::Binary => "binary",
            OutputFormat::Base64 => "base64",
            OutputFormat::C => "C header",
            OutputFormat::Rust => "Rust",
            OutputFormat::Python => "Python",
            OutputFormat::PowerShell => "PowerShell",
            OutputFormat::CSharp => "C#",
            OutputFormat::Hex => "hex",
            OutputFormat::Uuid => "UUID",
        }
    }
    
    pub fn compress_str(&self) -> &'static str {
        match self.compression {
            CompressionType::None => "none",
            CompressionType::Lz4 => "LZ4",
            CompressionType::Zstd => "ZSTD",
            CompressionType::Lznt1 => "LZNT1",
            CompressionType::Xpress => "XPRESS",
        }
    }
    
    pub fn is_staged(&self) -> bool {
        self.url.is_some()
    }
}
