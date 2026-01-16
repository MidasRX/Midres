//! Error types for Midres generator

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MidresError {
    #[error("Input file not found: {0}")]
    InputNotFound(String),
    
    #[error("Invalid PE file format: {0}")]
    InvalidPeFormat(String),
    
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    
    #[error("Output write failed: {0}")]
    OutputWriteFailed(String),
    
    #[error("Loader not found for architecture: {0}")]
    LoaderNotFound(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Module building failed: {0}")]
    ModuleBuildFailed(String),
    
    #[error("Instance building failed: {0}")]
    InstanceBuildFailed(String),
}

impl From<std::io::Error> for MidresError {
    fn from(e: std::io::Error) -> Self {
        MidresError::OutputWriteFailed(e.to_string())
    }
}
