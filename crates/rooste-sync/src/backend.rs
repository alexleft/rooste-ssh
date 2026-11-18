//! Unified asynchronous remote storage backend trait (`SyncBackend`) and in-memory test backend.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rooste_core::{SyncBackendKind, SyncConfig};
use rooste_vault::{LocalSyncCredentials, sha256_hex};

use crate::error::SyncError;
use crate::github::GitHubBackend;
use crate::s3::S3Backend;
use crate::webdav::WebDavBackend;

/// Ensure `rustls` has the `ring` crypto provider installed before creating any `reqwest` client.
pub fn init_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a configured async `reqwest::Client` (rustls + ring, sane timeouts, no UI thread blocking).
pub fn build_http_client() -> Result<reqwest::Client, SyncError> {
    init_tls_provider();
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("rooste-ssh/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SyncError::Network(e.to_string()))
}

/// Build a concrete [`SyncBackend`] from `SyncConfig` + decrypted `LocalSyncCredentials`.
pub fn build_backend(
    cfg: &SyncConfig,
    creds: &LocalSyncCredentials,
) -> Result<Arc<dyn SyncBackend>, SyncError> {
    match cfg.backend {
        SyncBackendKind::None => Err(SyncError::NotConfigured),
        SyncBackendKind::GitHub => Ok(Arc::new(GitHubBackend::new(cfg, creds)?)),
        SyncBackendKind::S3 => Ok(Arc::new(S3Backend::new(cfg, creds)?)),
        SyncBackendKind::WebDav => Ok(Arc::new(WebDavBackend::new(cfg, creds)?)),
    }
}

/// Asynchronous remote blob storage backend for encrypted vault synchronization.
#[async_trait]
pub trait SyncBackend: Send + Sync + std::fmt::Debug {
    /// Fetch a remote blob (e.g. `"vault.json"`, `"manifest.enc"`, `"keys/<sha256>.enc"`)
    /// along with its remote version token (ETag or Git SHA).
    async fn get_blob(&self, relative_path: &str) -> Result<Option<(Vec<u8>, String)>, SyncError>;

    /// Conditionally write a remote blob using optimistic locking (`If-Match: <etag>` or Git SHA).
    async fn put_blob(
        &self,
        relative_path: &str,
        data: &[u8],
        expected_etag: Option<&str>,
    ) -> Result<String, SyncError>;

    /// Atomically commit a batch of puts and deletes (GitHub uses a single Git Commit;
    /// object stores upload blobs first then conditionally update `manifest.enc` last).
    async fn commit_batch(
        &self,
        puts: Vec<(String, Vec<u8>)>,
        deletes: Vec<String>,
        manifest_bytes: Vec<u8>,
        expected_manifest_etag: Option<&str>,
    ) -> Result<String, SyncError> {
        for (path, data) in puts {
            self.put_blob(&path, &data, None).await?;
        }
        let new_etag = self
            .put_blob("manifest.enc", &manifest_bytes, expected_manifest_etag)
            .await?;
        for path in deletes {
            let _ = self.delete_blob(&path).await;
        }
        Ok(new_etag)
    }

    /// Delete an expired tombstone blob from the remote store.
    async fn delete_blob(&self, relative_path: &str) -> Result<(), SyncError>;

    /// Verify connectivity and authentication credentials against the remote backend.
    async fn test_connection(&self) -> Result<(), SyncError> {
        let _ = self.get_blob("vault.json").await?;
        Ok(())
    }
}

/// In-memory [`SyncBackend`] for deterministic unit and integration testing.
#[derive(Debug, Default, Clone)]
pub struct MemoryBackend {
    inner: Arc<Mutex<MemoryBackendInner>>,
}

#[derive(Debug, Default)]
struct MemoryBackendInner {
    blobs: BTreeMap<String, (Vec<u8>, String)>,
    /// Optional number of upcoming manifest writes that should fail with `SyncError::Conflict`.
    inject_conflicts: usize,
    /// Optional relative path whose `get_blob` should fail with a simulated network error.
    fail_get_path: Option<String>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Force the next `count` `manifest.enc` writes to return `SyncError::Conflict`
    /// to test exponential backoff & re-merge retry logic.
    pub fn inject_manifest_conflicts(&self, count: usize) {
        self.inner.lock().unwrap().inject_conflicts = count;
    }

    /// Force `get_blob` for `path` to fail with a network error (tests referential integrity).
    pub fn fail_get(&self, path: Option<String>) {
        self.inner.lock().unwrap().fail_get_path = path;
    }

    /// Inspect all stored paths in memory.
    pub fn list_paths(&self) -> Vec<String> {
        self.inner.lock().unwrap().blobs.keys().cloned().collect()
    }
}

#[async_trait]
impl SyncBackend for MemoryBackend {
    async fn get_blob(&self, relative_path: &str) -> Result<Option<(Vec<u8>, String)>, SyncError> {
        let guard = self.inner.lock().unwrap();
        if guard.fail_get_path.as_deref() == Some(relative_path) {
            return Err(SyncError::Network(format!(
                "simulated drop while downloading {relative_path}"
            )));
        }
        Ok(guard.blobs.get(relative_path).cloned())
    }

    async fn put_blob(
        &self,
        relative_path: &str,
        data: &[u8],
        expected_etag: Option<&str>,
    ) -> Result<String, SyncError> {
        let mut guard = self.inner.lock().unwrap();
        if relative_path == "manifest.enc" && guard.inject_conflicts > 0 {
            guard.inject_conflicts -= 1;
            return Err(SyncError::Conflict(
                "simulated HTTP 412 Precondition Failed".into(),
            ));
        }
        if let Some(expected) = expected_etag {
            let current = guard.blobs.get(relative_path).map(|(_, e)| e.as_str());
            if current != Some(expected) {
                return Err(SyncError::Conflict(format!(
                    "ETag mismatch on {relative_path}: expected `{expected}`, got `{current:?}`"
                )));
            }
        }
        let etag = sha256_hex(data);
        guard
            .blobs
            .insert(relative_path.to_owned(), (data.to_vec(), etag.clone()));
        Ok(etag)
    }

    async fn delete_blob(&self, relative_path: &str) -> Result<(), SyncError> {
        self.inner.lock().unwrap().blobs.remove(relative_path);
        Ok(())
    }
}
