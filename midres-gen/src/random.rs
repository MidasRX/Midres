//! Random name generation and entropy

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rand::distributions::Alphanumeric;
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use midres_common::*;

use crate::config::Config;
use crate::crypto::CryptoContext;

/// Context holding all random values for payload generation
pub struct RandomContext {
    /// Initialization vector for API hashing
    hash_iv: u64,
    /// Random AppDomain name
    domain_name: String,
    /// Random class name
    class_name: String,
    /// Random method name
    method_name: String,
    /// Random module name
    module_name: String,
    /// Random signature
    signature: [u8; SIG_LEN],
    /// Instance encryption key
    instance_key: CryptoContext,
    /// Module encryption key
    module_key: CryptoContext,
    /// Random DLL names for decoys
    decoy_dlls: Vec<String>,
    /// Random variable names
    var_names: Vec<String>,
    /// Entropy level
    entropy: EntropyLevel,
}

impl RandomContext {
    pub fn new(config: &Config) -> Self {
        let entropy = config.entropy;
        
        // Generate random IV for hashing
        let hash_iv = if entropy != EntropyLevel::None {
            OsRng.next_u64()
        } else {
            0x4D6152552D484153 // Fixed IV for no-entropy mode: "MaRU-HAS"
        };
        
        // Generate random names
        let (domain_name, class_name, method_name, module_name) = if entropy == EntropyLevel::None {
            // Use fixed names for no-entropy mode
            (
                "MidresDomain".to_string(),
                "MidresClass".to_string(), 
                "Execute".to_string(),
                "venom.mod".to_string(),
            )
        } else {
            (
                config.domain.clone().unwrap_or_else(|| generate_random_name(8)),
                config.class_name.clone().unwrap_or_else(|| generate_class_name()),
                config.method_name.clone().unwrap_or_else(|| generate_method_name()),
                generate_random_name(12),
            )
        };
        
        // Generate signature
        let mut signature = [0u8; SIG_LEN];
        if entropy != EntropyLevel::None {
            OsRng.fill_bytes(&mut signature);
        } else {
            signature.copy_from_slice(b"VENOM-SIGNATURE!");
        }
        
        // Generate encryption keys
        let instance_key = if entropy == EntropyLevel::Full {
            CryptoContext::new()
        } else {
            // Fixed key for non-encrypted mode
            let key = [0x56u8; KEY_LEN]; // 'V' repeated
            let nonce = [0x4Eu8; NONCE_LEN]; // 'N' repeated
            CryptoContext::from_key(key, nonce)
        };
        
        let module_key = if entropy == EntropyLevel::Full {
            CryptoContext::new()
        } else {
            let key = [0x4Du8; KEY_LEN]; // 'M' repeated
            let nonce = [0x4Fu8; NONCE_LEN]; // 'O' repeated
            CryptoContext::from_key(key, nonce)
        };
        
        // Generate decoy DLL names
        let decoy_dlls = if entropy != EntropyLevel::None {
            generate_decoy_dll_names(5)
        } else {
            vec!["helper.dll".to_string()]
        };
        
        // Generate random variable names
        let var_names = if entropy != EntropyLevel::None {
            (0..20).map(|_| generate_random_name(6)).collect()
        } else {
            (0..20).map(|i| format!("var{}", i)).collect()
        };
        
        Self {
            hash_iv,
            domain_name,
            class_name,
            method_name,
            module_name,
            signature,
            instance_key,
            module_key,
            decoy_dlls,
            var_names,
            entropy,
        }
    }
    
    pub fn hash_iv(&self) -> u64 {
        self.hash_iv
    }
    
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }
    
    pub fn class_name(&self) -> &str {
        &self.class_name
    }
    
    pub fn method_name(&self) -> &str {
        &self.method_name
    }
    
    pub fn module_name(&self) -> &str {
        &self.module_name
    }
    
    pub fn signature(&self) -> &[u8; SIG_LEN] {
        &self.signature
    }
    
    pub fn instance_key(&self) -> &CryptoContext {
        &self.instance_key
    }
    
    pub fn module_key(&self) -> &CryptoContext {
        &self.module_key
    }
    
    pub fn decoy_dlls(&self) -> &[String] {
        &self.decoy_dlls
    }
    
    pub fn var_name(&self, index: usize) -> &str {
        &self.var_names[index % self.var_names.len()]
    }
    
    pub fn symbol_count(&self) -> usize {
        self.var_names.len() + self.decoy_dlls.len() + 4 // 4 for domain, class, method, module
    }
    
    pub fn is_encrypted(&self) -> bool {
        self.entropy == EntropyLevel::Full
    }
}

/// Generate a random alphanumeric name
fn generate_random_name(len: usize) -> String {
    let mut rng = StdRng::from_entropy();
    
    // First character must be a letter
    let first: char = if rng.gen_bool(0.5) {
        rng.gen_range(b'A'..=b'Z') as char
    } else {
        rng.gen_range(b'a'..=b'z') as char
    };
    
    let rest: String = (0..len - 1)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    
    format!("{}{}", first, rest)
}

/// Generate a realistic-looking class name
fn generate_class_name() -> String {
    let prefixes = [
        "Runtime", "Internal", "Native", "System", "Core", "Base",
        "Helper", "Util", "Manager", "Handler", "Provider", "Factory",
        "Service", "Context", "Loader", "Executor", "Worker", "Processor",
    ];
    
    let suffixes = [
        "Impl", "Ex", "Base", "Core", "Helper", "Wrapper", "Proxy",
        "Adapter", "Bridge", "Handler", "Service", "Module", "Component",
    ];
    
    let mut rng = StdRng::from_entropy();
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    let suffix = suffixes[rng.gen_range(0..suffixes.len())];
    
    format!("{}{}{}", prefix, generate_random_name(4), suffix)
}

/// Generate a realistic-looking method name
fn generate_method_name() -> String {
    let verbs = [
        "Execute", "Process", "Handle", "Run", "Invoke", "Call",
        "Initialize", "Start", "Load", "Begin", "Perform", "Do",
        "Apply", "Dispatch", "Trigger", "Fire", "Launch", "Activate",
    ];
    
    let nouns = [
        "Task", "Action", "Operation", "Request", "Command", "Job",
        "Work", "Item", "Data", "Payload", "Content", "Module",
        "Component", "Handler", "Routine", "Procedure", "Function",
    ];
    
    let mut rng = StdRng::from_entropy();
    let verb = verbs[rng.gen_range(0..verbs.len())];
    let noun = nouns[rng.gen_range(0..nouns.len())];
    
    if rng.gen_bool(0.5) {
        format!("{}{}", verb, noun)
    } else {
        verb.to_string()
    }
}

/// Generate decoy DLL names that look legitimate
fn generate_decoy_dll_names(count: usize) -> Vec<String> {
    let templates = [
        ("api-ms-win-", "-l1-1-0.dll"),
        ("ext-ms-win-", "-l1-1-0.dll"),
        ("", "base.dll"),
        ("", "core.dll"),
        ("", "util.dll"),
        ("", "helper.dll"),
        ("", "runtime.dll"),
        ("", "native.dll"),
        ("win", ".dll"),
        ("ms", ".dll"),
    ];
    
    let mut rng = StdRng::from_entropy();
    let mut names = Vec::with_capacity(count);
    
    for _ in 0..count {
        let (prefix, suffix) = templates[rng.gen_range(0..templates.len())];
        let middle = generate_random_name(6).to_lowercase();
        names.push(format!("{}{}{}", prefix, middle, suffix));
    }
    
    names
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate random padding that looks like code
pub fn generate_code_padding(len: usize) -> Vec<u8> {
    let mut rng = StdRng::from_entropy();
    let mut padding = Vec::with_capacity(len);
    
    // Common x86/x64 NOP-like patterns that look like real code
    let patterns: &[&[u8]] = &[
        &[0x90],                         // NOP
        &[0x66, 0x90],                   // 66 NOP
        &[0x0F, 0x1F, 0x00],             // NOP DWORD PTR [RAX]
        &[0x0F, 0x1F, 0x40, 0x00],       // NOP DWORD PTR [RAX+00]
        &[0x0F, 0x1F, 0x44, 0x00, 0x00], // NOP DWORD PTR [RAX+RAX*1+00]
        &[0x48, 0x89, 0xC0],             // MOV RAX, RAX
        &[0x48, 0x87, 0xC0],             // XCHG RAX, RAX
        &[0x48, 0x8D, 0x00],             // LEA RAX, [RAX]
        &[0x87, 0xDB],                   // XCHG EBX, EBX
        &[0x87, 0xC9],                   // XCHG ECX, ECX
    ];
    
    while padding.len() < len {
        let pattern = patterns[rng.gen_range(0..patterns.len())];
        let remaining = len - padding.len();
        
        if pattern.len() <= remaining {
            padding.extend_from_slice(pattern);
        } else {
            // Fill remaining with single-byte NOPs
            padding.resize(len, 0x90);
            break;
        }
    }
    
    padding
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_random_name() {
        let name = generate_random_name(10);
        assert_eq!(name.len(), 10);
        assert!(name.chars().next().unwrap().is_alphabetic());
    }
    
    #[test]
    fn test_generate_class_name() {
        let name = generate_class_name();
        assert!(!name.is_empty());
        assert!(name.chars().next().unwrap().is_uppercase());
    }
    
    #[test]
    fn test_random_context_entropy() {
        let config = Config {
            arch: Architecture::X64,
            format: OutputFormat::Binary,
            encrypt: true,
            compression: CompressionType::None,
            exit_opt: ExitOption::Thread,
            bypass: BypassLevel::Continue,
            class_name: None,
            method_name: None,
            args: None,
            domain: None,
            runtime: None,
            thread: false,
            url: None,
            entropy: EntropyLevel::Full,
            headers: HeaderOption::Overwrite,
        };
        
        let ctx1 = RandomContext::new(&config);
        let ctx2 = RandomContext::new(&config);
        
        // With full entropy, IVs should be different
        assert_ne!(ctx1.hash_iv(), ctx2.hash_iv());
    }
}
