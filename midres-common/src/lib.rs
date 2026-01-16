//! Midres Common - Shared types and constants between generator and loader

#![no_std]

/// Maximum length for names (domain, class, method, etc.)
pub const MAX_NAME_LEN: usize = 256;
/// Maximum number of DLLs supported
pub const MAX_DLL_COUNT: usize = 8;
/// Signature length for verification
pub const SIG_LEN: usize = 16;
/// Key length for encryption
pub const KEY_LEN: usize = 32;
/// Nonce length for ChaCha20
pub const NONCE_LEN: usize = 12;
/// Block length
pub const BLOCK_LEN: usize = 16;
/// Maximum API count
pub const MAX_API_COUNT: usize = 96;
/// Domain name length
pub const DOMAIN_LEN: usize = 8;
/// Version string length
pub const VERSION_LEN: usize = 32;

/// Target architecture
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    /// Any architecture (for scripts)
    Any = 0,
    /// x86 32-bit
    X86 = 1,
    /// x86-64 64-bit
    X64 = 2,
    /// Both x86 and x64
    X84 = 3,
}

/// Module type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleType {
    /// .NET DLL
    NetDll = 1,
    /// .NET EXE
    NetExe = 2,
    /// Native DLL
    NativeDll = 3,
    /// Native EXE
    NativeExe = 4,
    /// VBScript
    Vbs = 5,
    /// JavaScript
    Js = 6,
}

/// Output format
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Binary = 1,
    Base64 = 2,
    C = 3,
    Rust = 4,
    Python = 5,
    PowerShell = 6,
    CSharp = 7,
    Hex = 8,
    Uuid = 9,
}

/// Compression algorithm
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionType {
    None = 0,
    Lz4 = 1,
    Zstd = 2,
    Lznt1 = 3,
    Xpress = 4,
}

/// Entropy/encryption level
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyLevel {
    /// No entropy
    None = 1,
    /// Random names only
    Random = 2,
    /// Full encryption + random names
    Full = 3,
}

/// Exit behavior
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitOption {
    /// Exit via thread
    Thread = 1,
    /// Exit entire process
    Process = 2,
    /// Block indefinitely
    Block = 3,
}

/// Instance type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceType {
    /// Module embedded in instance
    Embedded = 1,
    /// Module downloaded via HTTP
    Http = 2,
    /// Module downloaded via DNS
    Dns = 3,
}

/// Bypass behavior
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BypassLevel {
    /// No bypass attempts
    None = 1,
    /// Abort if bypass fails
    Abort = 2,
    /// Continue even if bypass fails
    Continue = 3,
}

/// Header preservation
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderOption {
    /// Overwrite PE headers
    Overwrite = 1,
    /// Keep PE headers
    Keep = 2,
}

/// Cryptographic keys for encryption
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoKeys {
    /// Master key (256-bit for ChaCha20)
    pub master_key: [u8; KEY_LEN],
    /// Nonce for ChaCha20
    pub nonce: [u8; NONCE_LEN],
    /// Counter
    pub counter: u32,
}

/// GUID structure compatible with Windows
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
    }
}

/// Module header - contains information about the payload
#[repr(C)]
pub struct ModuleHeader {
    /// Module type
    pub mod_type: ModuleType,
    /// Run as thread
    pub thread: u32,
    /// Compression type used
    pub compression: CompressionType,
    /// Runtime version for .NET
    pub runtime: [u8; MAX_NAME_LEN],
    /// AppDomain name
    pub domain: [u8; MAX_NAME_LEN],
    /// Class name for .NET
    pub class_name: [u8; MAX_NAME_LEN],
    /// Method name
    pub method: [u8; MAX_NAME_LEN],
    /// Arguments
    pub args: [u8; MAX_NAME_LEN],
    /// Unicode flag
    pub unicode: u32,
    /// Verification signature
    pub signature: [u8; SIG_LEN],
    /// MAC for verification
    pub mac: u64,
    /// Compressed length
    pub compressed_len: u32,
    /// Original length
    pub original_len: u32,
    // Payload data follows...
}

/// Instance header - runtime configuration for the loader
#[repr(C)]
pub struct InstanceHeader {
    /// Total instance length
    pub total_len: u32,
    /// Encryption keys
    pub crypto: CryptoKeys,
    /// Initialization vector for hashing
    pub hash_iv: u64,
    /// API hashes (up to MAX_API_COUNT)
    pub api_hashes: [u64; MAX_API_COUNT],
    /// Exit option
    pub exit_opt: ExitOption,
    /// Entropy level
    pub entropy: EntropyLevel,
    /// Original entry point (for OEP hijacking)
    pub oep: u32,
    /// API count
    pub api_count: u32,
    /// DLL names (semicolon separated)
    pub dll_names: [u8; MAX_NAME_LEN],
    /// Bypass level
    pub bypass: BypassLevel,
    /// Header preservation
    pub headers: HeaderOption,
    /// Instance type
    pub instance_type: InstanceType,
    /// Remote server URL
    pub server: [u8; MAX_NAME_LEN],
    /// Verification signature
    pub signature: [u8; MAX_NAME_LEN],
    /// MAC for instance verification
    pub mac: u64,
    /// Module encryption keys
    pub mod_crypto: CryptoKeys,
    /// Module length
    pub mod_len: u64,
    // Module data follows for embedded type...
}

/// API identifiers for hash lookup
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiId {
    // kernel32.dll
    LoadLibraryA = 0,
    GetProcAddress = 1,
    GetModuleHandleA = 2,
    VirtualAlloc = 3,
    VirtualFree = 4,
    VirtualQuery = 5,
    VirtualProtect = 6,
    Sleep = 7,
    MultiByteToWideChar = 8,
    GetUserDefaultLCID = 9,
    WaitForSingleObject = 10,
    CreateThread = 11,
    CreateFileA = 12,
    GetFileSizeEx = 13,
    GetThreadContext = 14,
    GetCurrentThread = 15,
    GetCurrentProcess = 16,
    GetCommandLineA = 17,
    GetCommandLineW = 18,
    HeapAlloc = 19,
    HeapReAlloc = 20,
    HeapFree = 21,
    GetProcessHeap = 22,
    GetLastError = 23,
    CloseHandle = 24,
    
    // shell32.dll
    CommandLineToArgvW = 25,
    
    // oleaut32.dll
    SafeArrayCreate = 26,
    SafeArrayCreateVector = 27,
    SafeArrayPutElement = 28,
    SafeArrayDestroy = 29,
    SafeArrayGetLBound = 30,
    SafeArrayGetUBound = 31,
    SysAllocString = 32,
    SysFreeString = 33,
    LoadTypeLib = 34,
    
    // wininet.dll
    InternetCrackUrlA = 35,
    InternetOpenA = 36,
    InternetConnectA = 37,
    InternetSetOptionA = 38,
    InternetReadFile = 39,
    InternetQueryDataAvailable = 40,
    InternetCloseHandle = 41,
    HttpOpenRequestA = 42,
    HttpSendRequestA = 43,
    HttpQueryInfoA = 44,
    
    // mscoree.dll
    CorBindToRuntime = 45,
    CLRCreateInstance = 46,
    
    // ole32.dll
    CoInitializeEx = 47,
    CoCreateInstance = 48,
    CoUninitialize = 49,
    
    // ntdll.dll
    RtlEqualUnicodeString = 50,
    RtlEqualString = 51,
    RtlUnicodeStringToAnsiString = 52,
    RtlInitUnicodeString = 53,
    RtlExitUserThread = 54,
    RtlExitUserProcess = 55,
    RtlCreateUnicodeString = 56,
    RtlGetCompressionWorkSpaceSize = 57,
    RtlDecompressBuffer = 58,
    NtContinue = 59,
    NtCreateSection = 60,
    NtMapViewOfSection = 61,
    NtUnmapViewOfSection = 62,
    NtAllocateVirtualMemory = 63,
    NtFreeVirtualMemory = 64,
    NtProtectVirtualMemory = 65,
    NtFlushInstructionCache = 66,
    LdrLoadDll = 67,
    LdrGetProcedureAddress = 68,
    
    // Count
    MaxApi = 69,
}

/// Well-known GUIDs for COM interfaces
pub mod guids {
    use super::Guid;
    
    pub const IID_IUNKNOWN: Guid = Guid::new(
        0x00000000, 0x0000, 0x0000,
        [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
    );
    
    pub const IID_IDISPATCH: Guid = Guid::new(
        0x00020400, 0x0000, 0x0000,
        [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
    );
    
    pub const CLSID_CLRMETAHOST: Guid = Guid::new(
        0x9280188d, 0x0e8e, 0x4867,
        [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde]
    );
    
    pub const IID_ICLRMETAHOST: Guid = Guid::new(
        0xD332DB9E, 0xB9B3, 0x4125,
        [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16]
    );
    
    pub const IID_ICLRRUNTIMEINFO: Guid = Guid::new(
        0xBD39D1D2, 0xBA2F, 0x486a,
        [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91]
    );
    
    pub const CLSID_CORRUNTIMEHOST: Guid = Guid::new(
        0xcb2f6723, 0xab3a, 0x11d2,
        [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e]
    );
    
    pub const IID_ICORRUNTIMEHOST: Guid = Guid::new(
        0xcb2f6722, 0xab3a, 0x11d2,
        [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e]
    );
    
    pub const IID_APPDOMAIN: Guid = Guid::new(
        0x05F696DC, 0x2B29, 0x3663,
        [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13]
    );
}

/// Runtime version strings
pub mod runtime {
    pub const NET2: &[u8] = b"v2.0.50727\0";
    pub const NET4: &[u8] = b"v4.0.30319\0";
}

/// Magic values
pub const INSTANCE_MAGIC: u32 = 0x564E4D52; // "VNMR"
pub const MODULE_MAGIC: u32 = 0x4D4F4456; // "MODV"
