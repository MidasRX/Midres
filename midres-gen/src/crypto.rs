//! Cryptographic operations for payload encryption

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use midres_common::*;

use crate::random::RandomContext;

/// Encryption context with keys and nonce
pub struct CryptoContext {
    pub key: [u8; KEY_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl CryptoContext {
    /// Generate new random encryption context
    pub fn new() -> Self {
        let mut key = [0u8; KEY_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        
        Self { key, nonce }
    }
    
    /// Create from existing key material
    pub fn from_key(key: [u8; KEY_LEN], nonce: [u8; NONCE_LEN]) -> Self {
        Self { key, nonce }
    }
}

/// Encrypt data using ChaCha20-Poly1305
pub fn encrypt(data: &[u8], ctx: &CryptoContext) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&ctx.key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    
    let nonce = Nonce::from_slice(&ctx.nonce);
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    Ok(ciphertext)
}

/// Encrypt instance with structured header
pub fn encrypt_instance(instance: &[u8], random_ctx: &RandomContext) -> Result<Vec<u8>> {
    // Instance structure:
    // [4 bytes: total_len (unencrypted)]
    // [32 bytes: key (unencrypted)]
    // [12 bytes: nonce (unencrypted)]
    // [4 bytes: counter (unencrypted)]
    // [8 bytes: hash_iv (unencrypted)]
    // [... encrypted data ...]
    
    let ctx = random_ctx.instance_key();
    
    // Calculate header size (unencrypted portion)
    let header_size = 4 + KEY_LEN + NONCE_LEN + 4 + 8; // total_len + key + nonce + counter + iv
    
    if instance.len() < header_size {
        return Err(anyhow::anyhow!("Instance too small"));
    }
    
    // Extract header (keep unencrypted)
    let header = &instance[..header_size];
    let payload = &instance[header_size..];
    
    // Encrypt the payload portion
    let encrypted_payload = encrypt(payload, &ctx)?;
    
    // Combine header with encrypted payload
    let mut result = Vec::with_capacity(header.len() + encrypted_payload.len());
    result.extend_from_slice(header);
    result.extend_from_slice(&encrypted_payload);
    
    // Update total length in header
    let total_len = result.len() as u32;
    result[0..4].copy_from_slice(&total_len.to_le_bytes());
    
    Ok(result)
}

/// Chaskey block cipher implementation (for compatibility)
/// Used for API hash obfuscation
pub fn chaskey_encrypt(key: &[u8; 16], block: &mut [u8; 16]) {
    let k: [u32; 4] = [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    ];
    
    let mut w: [u32; 4] = [
        u32::from_le_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_le_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_le_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
    ];
    
    // Add key
    for i in 0..4 {
        w[i] ^= k[i];
    }
    
    // 16 rounds of permutation
    for _ in 0..16 {
        w[0] = w[0].wrapping_add(w[1]);
        w[1] = w[1].rotate_right(27) ^ w[0];
        w[2] = w[2].wrapping_add(w[3]);
        w[3] = w[3].rotate_right(24) ^ w[2];
        w[2] = w[2].wrapping_add(w[1]);
        w[0] = w[0].rotate_right(16).wrapping_add(w[3]);
        w[3] = w[3].rotate_right(19) ^ w[0];
        w[1] = w[1].rotate_right(25) ^ w[2];
        w[2] = w[2].rotate_right(16);
    }
    
    // Add key
    for i in 0..4 {
        w[i] ^= k[i];
    }
    
    // Write back
    block[0..4].copy_from_slice(&w[0].to_le_bytes());
    block[4..8].copy_from_slice(&w[1].to_le_bytes());
    block[8..12].copy_from_slice(&w[2].to_le_bytes());
    block[12..16].copy_from_slice(&w[3].to_le_bytes());
}

/// Counter-mode encryption using Chaskey (for backward compatibility)
pub fn chaskey_ctr_encrypt(key: &[u8; 16], ctr: &mut [u8; 16], data: &mut [u8]) {
    let mut pos = 0;
    
    while pos < data.len() {
        let mut block = *ctr;
        chaskey_encrypt(key, &mut block);
        
        let remaining = data.len() - pos;
        let to_process = remaining.min(16);
        
        for i in 0..to_process {
            data[pos + i] ^= block[i];
        }
        
        pos += to_process;
        
        // Increment counter
        for i in (0..16).rev() {
            ctr[i] = ctr[i].wrapping_add(1);
            if ctr[i] != 0 {
                break;
            }
        }
    }
}

/// Generate a random signature for verification
pub fn generate_signature() -> [u8; SIG_LEN] {
    let mut sig = [0u8; SIG_LEN];
    OsRng.fill_bytes(&mut sig);
    sig
}

/// Generate MAC for verification
pub fn generate_mac(data: &[u8], iv: u64) -> u64 {
    use crate::hash::maru_hash;
    maru_hash(data, iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chaskey_encrypt() {
        let key: [u8; 16] = [
            0x56, 0x09, 0xe9, 0x68, 0x5f, 0x58, 0xe3, 0x29,
            0x40, 0xec, 0xec, 0x98, 0xc5, 0x22, 0x98, 0x2f,
        ];
        
        let mut block: [u8; 16] = [
            0xb8, 0x23, 0x28, 0x26, 0xfd, 0x5e, 0x40, 0x5e,
            0x69, 0xa3, 0x01, 0xa9, 0x78, 0xea, 0x7a, 0xd8,
        ];
        
        let expected: [u8; 16] = [
            0xd5, 0x60, 0x8d, 0x4d, 0xa2, 0xbf, 0x34, 0x7b,
            0xab, 0xf8, 0x77, 0x2f, 0xdf, 0xed, 0xde, 0x07,
        ];
        
        chaskey_encrypt(&key, &mut block);
        assert_eq!(block, expected);
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let ctx = CryptoContext::new();
        let plaintext = b"Hello, Venom!";
        
        let ciphertext = encrypt(plaintext, &ctx).unwrap();
        
        // Verify ciphertext is different
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        
        // Decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&ctx.key).unwrap();
        let nonce = Nonce::from_slice(&ctx.nonce);
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}
