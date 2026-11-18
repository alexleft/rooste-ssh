//! Machine-local state (`local.toml`) that is strictly excluded from remote sync.
//!
//! Stores the device UUID, monotonic SM4-GCM nonce counter, local filesystem paths
//! (with portable relative-path resolution), auto-lock timeout, and remote sync endpoint
//! metadata (never credentials; those live encrypted in `local_secrets.enc`).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ConfigError;
use crate::expand_tilde;

/// File name of the machine-local state file next to `config.toml`.
pub const LOCAL_FILE_NAME: &str = "local.toml";
/// File name of the DEK-encrypted local sync credentials file.
pub const LOCAL_SECRETS_FILE_NAME: &str = "local_secrets.enc";

/// Supported remote synchronization backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncBackendKind {
    #[default]
    None,
    GitHub,
    S3,
    WebDav,
}

impl SyncBackendKind {
    pub const ALL: [Self; 4] = [Self::None, Self::GitHub, Self::S3, Self::WebDav];

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "Disabled",
            Self::GitHub => "GitHub (Private Repo)",
            Self::S3 => "S3 Compatible",
            Self::WebDav => "WebDAV",
        }
    }
}

/// Non-secret remote synchronization configuration persisted in `local.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    pub enabled: bool,
    pub backend: SyncBackendKind,
    /// API base / repository URL / S3 endpoint URL / WebDAV root URL.
    pub endpoint: String,
    /// Git branch name for GitHub backend (default: `main`).
    pub branch: String,
    /// Optional prefix inside bucket or WebDAV directory (e.g. `rooste-vault`).
    pub prefix: String,
    /// Background auto-sync interval in seconds (0 disables periodic sync).
    pub auto_sync_interval_secs: u64,
    /// Hex-encoded SHA-256 of the last synced `manifest.enc` ciphertext.
    pub last_synced_manifest_hash: String,
    /// Last synced manifest sequence number.
    pub last_synced_sequence: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: SyncBackendKind::None,
            endpoint: String::new(),
            branch: "main".to_owned(),
            prefix: String::new(),
            auto_sync_interval_secs: 300,
            last_synced_manifest_hash: String::new(),
            last_synced_sequence: 0,
        }
    }
}

/// Machine-local runtime state stored in `<ROOSTE_ROOT>/local.toml`.
///
/// Strictly excluded from `vault/` synchronization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalConfig {
    /// Stable per-device UUIDv4 used to namespace deterministic SM4-GCM nonces.
    pub device_id: String,
    /// Human-readable device label.
    pub device_name: String,
    /// Strictly monotonic SM4-GCM nonce counter for this device.
    pub nonce_counter: u64,
    /// Local folder for SFTP downloads (empty means OS Downloads; relative allowed in portable mode).
    pub download_dir: String,
    /// Last folder picked via "Download to…".
    pub last_download_to: String,
    /// Local folder for automatic session text logs.
    pub log_dir: String,
    /// Release tag skipped by the user.
    pub skipped_version: String,
    /// Idle auto-lock timeout in seconds (0 = lock only on exit or manual lock).
    pub auto_lock_timeout_secs: u64,
    /// Remote synchronization endpoint settings (non-secret).
    pub sync: SyncConfig,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            device_name: default_device_name(),
            nonce_counter: 0,
            download_dir: String::new(),
            last_download_to: String::new(),
            log_dir: String::new(),
            skipped_version: String::new(),
            auto_lock_timeout_secs: 1800,
            sync: SyncConfig::default(),
        }
    }
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Rooste-Device".to_owned())
}

impl LocalConfig {
    /// Load `local.toml` from `path`. Missing file yields a fresh default config.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut cfg: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
                    path: path.to_owned(),
                    source: Box::new(source),
                })?;
                if cfg.device_id.trim().is_empty() {
                    cfg.device_id = Uuid::new_v4().to_string();
                }
                Ok(cfg)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// Atomically persist `local.toml` to `path` via a temporary file + rename.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let write_error = |source| ConfigError::Write {
            path: path.to_owned(),
            source,
        };
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(write_error)?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| write_error(io::Error::other(e)))?;
        atomic_write_bytes(path, text.as_bytes()).map_err(write_error)
    }

    /// Increment `nonce_counter` strictly monotonically and persist immediately.
    ///
    /// Returns the newly allocated counter value for constructing a deterministic
    /// 12-byte SM4-GCM nonce.
    pub fn allocate_nonce_counter(&mut self, path: &Path) -> Result<u64, ConfigError> {
        let next = self
            .nonce_counter
            .checked_add(1)
            .ok_or_else(|| ConfigError::Write {
                path: path.to_owned(),
                source: io::Error::other("nonce counter exhausted; rotate device_id"),
            })?;
        self.nonce_counter = next;
        self.save(path)?;
        Ok(next)
    }

    /// Rotate `device_id` to a brand-new UUIDv4 and reset `nonce_counter` to 0.
    ///
    /// Used after disaster recovery / wipe-and-resync so nonce prefixes never collide
    /// with prior encryptions under the same DEK.
    pub fn rotate_device_id(&mut self) {
        self.device_id = Uuid::new_v4().to_string();
        self.nonce_counter = 0;
    }

    /// Resolve a user-configured path (`download_dir`, `log_dir`, etc.) with support
    /// for portable relative paths and graceful fallback if a removable drive letter
    /// or mount point is unavailable.
    pub fn resolve_local_path(
        raw: &str,
        root_dir: &Path,
        portable: bool,
        fallback: impl FnOnce() -> PathBuf,
    ) -> PathBuf {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return fallback();
        }
        let expanded = expand_tilde(trimmed);
        let candidate = if expanded.is_relative() {
            root_dir.join(expanded)
        } else {
            expanded
        };
        if portable {
            // If an absolute path points to a disconnected drive/root (e.g. Windows USB letter changed),
            // check whether the ancestor root exists; fall back cleanly if unreachable.
            if let Some(prefix_root) = candidate.ancestors().last()
                && !prefix_root.as_os_str().is_empty()
                && !prefix_root.exists()
            {
                return fallback();
            }
        }
        candidate
    }
}

/// Write bytes atomically by writing to a sibling `.tmp` file and renaming over `path`.
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rooste");
    let tmp_name = format!(".{file_name}.{}.tmp", Uuid::new_v4().simple());
    let tmp_path = path.with_file_name(tmp_name);
    std::fs::write(&tmp_path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        // On Windows, rename over an existing file can fail if target exists; remove then rename.
        #[cfg(windows)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(path);
                if std::fs::rename(&tmp_path, path).is_ok() {
                    return Ok(());
                }
            }
        }
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_config_round_trips_and_allocates_monotonic_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCAL_FILE_NAME);
        let mut cfg = LocalConfig::load(&path).unwrap();
        assert_eq!(cfg.nonce_counter, 0);
        assert!(!cfg.device_id.is_empty());

        let c1 = cfg.allocate_nonce_counter(&path).unwrap();
        let c2 = cfg.allocate_nonce_counter(&path).unwrap();
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);

        let reloaded = LocalConfig::load(&path).unwrap();
        assert_eq!(reloaded.device_id, cfg.device_id);
        assert_eq!(reloaded.nonce_counter, 2);
    }

    #[test]
    fn rotate_device_id_resets_counter() {
        let mut cfg = LocalConfig {
            nonce_counter: 99,
            ..LocalConfig::default()
        };
        let old = cfg.device_id.clone();
        cfg.rotate_device_id();
        assert_ne!(cfg.device_id, old);
        assert_eq!(cfg.nonce_counter, 0);
    }

    #[test]
    fn portable_relative_path_resolves_against_root() {
        let root = PathBuf::from("/tmp/rooste-usb");
        let resolved = LocalConfig::resolve_local_path("./downloads", &root, true, || {
            PathBuf::from("/fallback")
        });
        assert_eq!(resolved, root.join("./downloads"));
    }
}
