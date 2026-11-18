//! Error types for the encrypted vault engine.

use std::io;
use std::path::PathBuf;

/// Errors produced by vault cryptographic and storage operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,

    #[error("vault is not initialized at {}", path.display())]
    NotInitialized { path: PathBuf },

    #[error("invalid master password or corrupted key slot")]
    InvalidPassword,

    #[error("invalid BIP-39 recovery mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("SM4-GCM encryption failed")]
    EncryptionFailed,

    #[error("SM4-GCM authentication or decryption failed (wrong key or tampered data)")]
    DecryptionFailed,

    #[error("record integrity mismatch: {0}")]
    IntegrityMismatch(String),

    #[error("unsupported vault or record protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("key derivation failed: {0}")]
    KdfFailed(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("config error: {0}")]
    Config(#[from] rooste_core::config::ConfigError),

    #[error("I/O error at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
