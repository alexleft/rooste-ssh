//! Single-file SM4-GCM ciphertext envelope (`.enc`) with Canonical AAD binding.
//!
//! Prevents tampering and file-substitution / rename attacks by binding `version`, `kind`,
//! `vault_id`, `id`, `revision`, `updated_at`, and `base_hash` into the GCM AAD and verifying
//! on decryption that the record metadata matches the expected file path and vault ID.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{open_sm4_gcm, seal_sm4_gcm};
use crate::error::VaultError;

/// Current `.enc` envelope protocol version.
pub const RECORD_VERSION: u8 = 1;

/// Logical category of an encrypted vault record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RecordKind {
    Manifest = 1,
    KnownHosts = 2,
    Profile = 3,
    Password = 4,
    SshKey = 5,
    Script = 6,
}

impl RecordKind {
    /// Numeric tag byte used inside the Canonical AAD.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Relative path inside `vault/` for a given record `id`.
    pub fn relative_path(self, id: &str) -> String {
        match self {
            Self::Manifest => "manifest.enc".to_owned(),
            Self::KnownHosts => "known_hosts.enc".to_owned(),
            Self::Profile => format!("profiles/{id}.enc"),
            Self::Password => format!("passwords/{id}.enc"),
            Self::SshKey => format!("keys/{id}.enc"),
            Self::Script => format!("scripts/{id}.enc"),
        }
    }

    /// Manifest key format `"<kind>/<id>"`.
    pub fn manifest_key(self, id: &str) -> String {
        match self {
            Self::Manifest => "manifest".to_owned(),
            Self::KnownHosts => "known_hosts".to_owned(),
            Self::Profile => format!("profiles/{id}"),
            Self::Password => format!("passwords/{id}"),
            Self::SshKey => format!("keys/{id}"),
            Self::Script => format!("scripts/{id}"),
        }
    }

    /// Topological sync priority: dependencies (keys, passwords, scripts, known_hosts)
    /// MUST be downloaded & verified before profiles are activated.
    pub fn dependency_order(self) -> u8 {
        match self {
            Self::KnownHosts => 0,
            Self::SshKey => 1,
            Self::Password => 2,
            Self::Script => 3,
            Self::Profile => 4,
            Self::Manifest => 5,
        }
    }
}

/// On-disk JSON envelope stored in every `.enc` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecord {
    /// Envelope version (currently `1`).
    pub version: u8,
    /// Owning vault UUID (prevents cross-vault file injection).
    pub vault_id: String,
    /// Record identifier (UUID, or 64-char lowercase SHA-256 hex for `SshKey`).
    pub id: String,
    pub kind: RecordKind,
    /// Strictly monotonic logical revision counter for clock-skew-free conflict resolution.
    pub revision: u64,
    /// Last modification UTC millisecond timestamp (auxiliary display & tie-breaker).
    pub updated_at: u64,
    /// SHA-256 of the prior `.enc` version (all-zeros for initial creation).
    pub base_hash: [u8; 32],
    /// Deterministic composite 12-byte SM4-GCM nonce.
    pub nonce: [u8; 12],
    /// SM4-GCM ciphertext + 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Metadata required to seal a new `EncryptedRecord`.
#[derive(Debug, Clone)]
pub struct SealMeta<'a> {
    pub vault_id: &'a str,
    pub id: &'a str,
    pub kind: RecordKind,
    pub revision: u64,
    pub updated_at: u64,
    pub base_hash: [u8; 32],
    pub nonce: [u8; 12],
}

impl EncryptedRecord {
    /// Build the canonical binary AAD bound to this record's header metadata:
    /// `version(1B) || kind(1B) || vault_id_len(2B BE) || vault_id || id_len(2B BE) || id
    ///  || revision(8B BE) || updated_at(8B BE) || base_hash(32B)`
    pub fn canonical_aad(&self) -> Result<Vec<u8>, VaultError> {
        build_canonical_aad(
            self.version,
            self.kind,
            &self.vault_id,
            &self.id,
            self.revision,
            self.updated_at,
            &self.base_hash,
        )
    }

    /// Seal `plaintext` into a new `EncryptedRecord` using SM4-GCM and Canonical AAD.
    pub fn seal(meta: SealMeta<'_>, dek: &[u8; 16], plaintext: &[u8]) -> Result<Self, VaultError> {
        let aad = build_canonical_aad(
            RECORD_VERSION,
            meta.kind,
            meta.vault_id,
            meta.id,
            meta.revision,
            meta.updated_at,
            &meta.base_hash,
        )?;
        let ciphertext = seal_sm4_gcm(dek, &meta.nonce, &aad, plaintext)?;
        Ok(Self {
            version: RECORD_VERSION,
            vault_id: meta.vault_id.to_owned(),
            id: meta.id.to_owned(),
            kind: meta.kind,
            revision: meta.revision,
            updated_at: meta.updated_at,
            base_hash: meta.base_hash,
            nonce: meta.nonce,
            ciphertext,
        })
    }

    /// Authenticate and decrypt this record, enforcing strict identity binding against
    /// `expected_vault_id`, `expected_kind`, and `expected_id` (derived from filename).
    pub fn open(
        &self,
        expected_vault_id: &str,
        expected_kind: RecordKind,
        expected_id: &str,
        dek: &[u8; 16],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if self.version != RECORD_VERSION {
            return Err(VaultError::UnsupportedVersion(self.version));
        }
        if self.vault_id != expected_vault_id {
            return Err(VaultError::IntegrityMismatch(format!(
                "vault_id mismatch: expected `{expected_vault_id}`, found `{}`",
                self.vault_id
            )));
        }
        if self.kind != expected_kind {
            return Err(VaultError::IntegrityMismatch(format!(
                "record kind mismatch: expected `{expected_kind:?}`, found `{:?}`",
                self.kind
            )));
        }
        if self.id != expected_id {
            return Err(VaultError::IntegrityMismatch(format!(
                "record id mismatch (possible file substitution): expected `{expected_id}`, found `{}`",
                self.id
            )));
        }
        let aad = self.canonical_aad()?;
        open_sm4_gcm(dek, &self.nonce, &aad, &self.ciphertext)
    }

    /// Serialize this envelope to canonical JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|e| VaultError::Serialization(e.to_string()))
    }

    /// Parse an envelope from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        serde_json::from_slice(bytes).map_err(|e| VaultError::Serialization(e.to_string()))
    }
}

fn build_canonical_aad(
    version: u8,
    kind: RecordKind,
    vault_id: &str,
    id: &str,
    revision: u64,
    updated_at: u64,
    base_hash: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    let vault_id_bytes = vault_id.as_bytes();
    let id_bytes = id.as_bytes();
    let vault_id_len = u16::try_from(vault_id_bytes.len())
        .map_err(|_| VaultError::IntegrityMismatch("vault_id exceeds u16 length".into()))?;
    let id_len = u16::try_from(id_bytes.len())
        .map_err(|_| VaultError::IntegrityMismatch("record id exceeds u16 length".into()))?;

    let mut aad =
        Vec::with_capacity(1 + 1 + 2 + vault_id_bytes.len() + 2 + id_bytes.len() + 8 + 8 + 32);
    aad.push(version);
    aad.push(kind.as_byte());
    aad.extend_from_slice(&vault_id_len.to_be_bytes());
    aad.extend_from_slice(vault_id_bytes);
    aad.extend_from_slice(&id_len.to_be_bytes());
    aad.extend_from_slice(id_bytes);
    aad.extend_from_slice(&revision.to_be_bytes());
    aad.extend_from_slice(&updated_at.to_be_bytes());
    aad.extend_from_slice(base_hash);
    Ok(aad)
}
