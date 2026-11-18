//! Vault plaintext data models, SSH key SHA-256 normalization/deduplication,
//! global incremental manifest, and encrypted local sync credentials.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::sha256_hex;
use crate::record::RecordKind;

/// Tombstone retention period: 90 days in milliseconds.
pub const TOMBSTONE_RETENTION_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Managed SSH private key stored in `vault/keys/<sha256>.enc`.
///
/// Treated as a **first-class independent asset**: never garbage-collected automatically
/// when profiles are deleted; only removed when explicitly deleted by the user.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultSshKey {
    /// Lowercase 64-character SHA-256 hex digest of the normalized `private_key_pem`.
    pub sha256: String,
    /// Human-readable label shown in the Keys Manager and profile key selector.
    pub label: String,
    /// Public key fingerprint (e.g. `SHA256:...`).
    pub fingerprint: String,
    /// OpenSSH formatted public key (`ssh-ed25519 AAAA...`).
    pub public_key: String,
    /// Normalized OpenSSH PEM private key text (zeroized on drop).
    pub private_key_pem: Zeroizing<String>,
    /// Optional stored passphrase. Always `None` when `require_passphrase_prompt` is `true`.
    pub passphrase: Option<Zeroizing<String>>,
    /// High-security mode: prompt for the key passphrase on every SSH connection.
    #[serde(default)]
    pub require_passphrase_prompt: bool,
}

impl fmt::Debug for VaultSshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSshKey")
            .field("sha256", &self.sha256)
            .field("label", &self.label)
            .field("fingerprint", &self.fingerprint)
            .field("public_key", &self.public_key)
            .field("private_key_pem", &"<redacted>")
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("require_passphrase_prompt", &self.require_passphrase_prompt)
            .finish()
    }
}

/// Session login password stored in `vault/passwords/<profile-uuid>.enc`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultPassword {
    pub profile_id: String,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultPassword")
            .field("profile_id", &self.profile_id)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Encrypted Rhai automation script stored in `vault/scripts/<script-uuid>.enc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultScript {
    pub id: String,
    pub name: String,
    pub content: String,
}

/// Encrypted trusted SSH server host keys stored in `vault/known_hosts.enc`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKnownHosts {
    pub lines: Vec<String>,
}

/// Remote synchronization backend credentials encrypted inside `<ROOSTE_ROOT>/local_secrets.enc`
/// (strictly excluded from remote sync; replaces OS Keyring for standard & portable modes).
///
/// Every secret field is wrapped in `Zeroizing<String>` so it is automatically zeroized on drop.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
#[serde(default)]
pub struct LocalSyncCredentials {
    /// GitHub Personal Access Token (fine-grained or classic `repo` scope).
    pub github_pat: Option<Zeroizing<String>>,
    /// S3-compatible Access Key ID.
    pub s3_access_key: Option<Zeroizing<String>>,
    /// S3-compatible Secret Access Key.
    pub s3_secret_key: Option<Zeroizing<String>>,
    /// S3 Region (e.g. `us-east-1`, `auto` for Cloudflare R2).
    pub s3_region: String,
    /// S3 Bucket name.
    pub s3_bucket: String,
    /// WebDAV HTTP Basic Auth username.
    pub webdav_user: Option<Zeroizing<String>>,
    /// WebDAV HTTP Basic Auth password.
    pub webdav_password: Option<Zeroizing<String>>,
}

impl fmt::Debug for LocalSyncCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSyncCredentials")
            .field(
                "github_pat",
                &self.github_pat.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "s3_access_key",
                &self.s3_access_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "s3_secret_key",
                &self.s3_secret_key.as_ref().map(|_| "<redacted>"),
            )
            .field("s3_region", &self.s3_region)
            .field("s3_bucket", &self.s3_bucket)
            .field(
                "webdav_user",
                &self.webdav_user.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "webdav_password",
                &self.webdav_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Global incremental index stored in `vault/manifest.enc`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    /// Monotonically increasing manifest sequence number across syncs.
    pub sequence: u64,
    /// UTC millisecond timestamp of the last manifest update.
    pub updated_at: u64,
    /// Map of `"<kind>/<id>"` -> [`ManifestEntry`].
    pub entries: BTreeMap<String, ManifestEntry>,
}

/// Per-record sync metadata inside [`VaultManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: String,
    pub kind: RecordKind,
    /// Strictly monotonic logical revision counter (immune to wall-clock skew).
    pub revision: u64,
    /// UTC millisecond timestamp (auxiliary display & deterministic tie-breaker).
    pub updated_at: u64,
    /// Device ID that produced this revision (final deterministic tie-breaker).
    #[serde(default)]
    pub updated_by: String,
    /// SHA-256 of the current `.enc` file bytes.
    pub rev_hash: [u8; 32],
    /// SHA-256 of the previous `.enc` file bytes (`None` on creation).
    pub prev_hash: Option<[u8; 32]>,
    /// Soft-delete tombstone flag (only set by explicit user deletion; retained for 90 days).
    pub deleted: bool,
}

impl VaultManifest {
    /// Prune tombstones older than [`TOMBSTONE_RETENTION_MS`] relative to `now_ms`,
    /// returning the relative paths of records whose remote blobs can be physically deleted.
    pub fn prune_expired_tombstones(&mut self, now_ms: u64) -> Vec<String> {
        let mut expired_keys = Vec::new();
        let mut expired_paths = Vec::new();
        for (key, entry) in &self.entries {
            if entry.deleted && now_ms.saturating_sub(entry.updated_at) >= TOMBSTONE_RETENTION_MS {
                expired_keys.push(key.clone());
                expired_paths.push(entry.kind.relative_path(&entry.id));
            }
        }
        for key in expired_keys {
            self.entries.remove(&key);
        }
        expired_paths
    }
}

/// Normalize an OpenSSH PEM private key text (LF line endings, trailing newline, trimmed outer whitespace)
/// and compute its lowercase 64-character SHA-256 content-addressing hash for global deduplication.
pub fn normalize_and_hash_ssh_key(raw_pem: &str) -> (String, Zeroizing<String>) {
    let mut normalized = raw_pem
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_owned();
    normalized.push('\n');
    let sha256 = sha256_hex(normalized.as_bytes());
    (sha256, Zeroizing::new(normalized))
}
