//! Compression algorithms for payload size reduction

use anyhow::Result;
use midres_common::CompressionType;

/// Compress data using the specified algorithm
pub fn compress(data: &[u8], algorithm: CompressionType) -> Result<Vec<u8>> {
    match algorithm {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Lz4 => compress_lz4(data),
        CompressionType::Zstd => compress_zstd(data),
        CompressionType::Lznt1 => {
            // LZNT1 is Windows-specific, use LZ4 as fallback for generation
            compress_lz4(data)
        }
        CompressionType::Xpress => {
            // XPRESS is Windows-specific, use LZ4 as fallback for generation
            compress_lz4(data)
        }
    }
}

/// Decompress data using the specified algorithm
pub fn decompress(data: &[u8], algorithm: CompressionType, original_size: usize) -> Result<Vec<u8>> {
    match algorithm {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Lz4 => decompress_lz4(data, original_size),
        CompressionType::Zstd => decompress_zstd(data),
        CompressionType::Lznt1 | CompressionType::Xpress => {
            // These are decompressed by the loader using Windows APIs
            Err(anyhow::anyhow!("LZNT1/XPRESS decompression requires Windows APIs"))
        }
    }
}

fn compress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    Ok(lz4_flex::compress_prepend_size(data))
}

fn decompress_lz4(data: &[u8], _original_size: usize) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| anyhow::anyhow!("LZ4 decompression failed: {}", e))
}

fn compress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    // Use compression level 19 for maximum compression
    zstd::encode_all(data, 19)
        .map_err(|e| anyhow::anyhow!("ZSTD compression failed: {}", e))
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| anyhow::anyhow!("ZSTD decompression failed: {}", e))
}

/// Calculate compression ratio
pub fn compression_ratio(original: usize, compressed: usize) -> f64 {
    if original == 0 {
        return 0.0;
    }
    (compressed as f64 / original as f64) * 100.0
}

/// Determine best compression algorithm for the data
pub fn auto_select_algorithm(data: &[u8]) -> CompressionType {
    // For small payloads, LZ4 is faster and good enough
    if data.len() < 1024 * 10 {
        return CompressionType::Lz4;
    }
    
    // For larger payloads, try both and pick the smaller result
    let lz4_result = compress_lz4(data);
    let zstd_result = compress_zstd(data);
    
    match (lz4_result, zstd_result) {
        (Ok(lz4), Ok(zstd)) => {
            if zstd.len() < lz4.len() {
                CompressionType::Zstd
            } else {
                CompressionType::Lz4
            }
        }
        (Ok(_), Err(_)) => CompressionType::Lz4,
        (Err(_), Ok(_)) => CompressionType::Zstd,
        (Err(_), Err(_)) => CompressionType::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lz4_roundtrip() {
        let data = b"Hello, World! This is a test string that should compress well. \
                     Hello, World! This is a test string that should compress well.";
        
        let compressed = compress(data, CompressionType::Lz4).unwrap();
        let decompressed = decompress(&compressed, CompressionType::Lz4, data.len()).unwrap();
        
        assert_eq!(data.as_slice(), decompressed.as_slice());
        assert!(compressed.len() < data.len());
    }
    
    #[test]
    fn test_zstd_roundtrip() {
        let data = b"Hello, World! This is a test string that should compress well. \
                     Hello, World! This is a test string that should compress well.";
        
        let compressed = compress(data, CompressionType::Zstd).unwrap();
        let decompressed = decompress(&compressed, CompressionType::Zstd, data.len()).unwrap();
        
        assert_eq!(data.as_slice(), decompressed.as_slice());
        assert!(compressed.len() < data.len());
    }
    
    #[test]
    fn test_no_compression() {
        let data = b"Test data";
        
        let result = compress(data, CompressionType::None).unwrap();
        assert_eq!(data.as_slice(), result.as_slice());
    }
}
