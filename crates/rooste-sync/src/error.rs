//! Error types for the async vault sync engine.

use rooste_vault::VaultError;

/// Errors returned by remote sync backends and the incremental merge engine.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync backend is not configured or disabled")]
    NotConfigured,

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("optimistic lock conflict (remote changed concurrently): {0}")]
    Conflict(String),

    #[error("remote resource not found: {0}")]
    NotFound(String),

    #[error("network or HTTP error: {0}")]
    Network(String),

    #[error("remote backend rejected request (HTTP {status}): {body}")]
    HttpStatus { status: u16, body: String },

    #[error("invalid endpoint configuration: {0}")]
    InvalidConfig(String),

    #[error("referential integrity check failed: {0}")]
    Integrity(String),

    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
}
