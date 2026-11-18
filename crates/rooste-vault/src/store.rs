//! File-backed encrypted Vault Store (`<ROOSTE_ROOT>/vault/` + `<ROOSTE_ROOT>/local_secrets.enc`).
//!
//! Manages:
//! - Initialization (`vault.json` dual-slot header + empty `manifest.enc`)
//! - Password & 24-word BIP-39 mnemonic unlocking, in-memory `Zeroizing` DEK, and locking
//! - Password reset without re-encrypting `.enc` data files
//! - Full Vault Re-keying (new DEK + new mnemonic + atomic staging swap)
//! - Wipe & Re-sync safety staging (`vault.reset_backup/`)
//! - First-class SHA-256 deduplicated SSH keys, profiles, passwords, scripts, known_hosts,
//!   and DEK-encrypted `local_secrets.enc` (zero OS Keyring dependency).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rooste_core::{ConfigLocation, LocalConfig, Profile, atomic_write_bytes};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{
    Argon2Params, derive_local_secrets_key, deterministic_nonce, open_sm4_gcm, seal_sm4_gcm,
    sha256_bytes, sha256_hex,
};
use crate::error::VaultError;
use crate::header::VaultHeader;
use crate::models::{
    LocalSyncCredentials, ManifestEntry, VaultKnownHosts, VaultManifest, VaultPassword,
    VaultScript, VaultSshKey, normalize_and_hash_ssh_key,
};
use crate::record::{EncryptedRecord, RecordKind, SealMeta};

const VAULT_HEADER_FILE: &str = "vault.json";
const LOCAL_SECRETS_AAD: &[u8] = b"rooste-local-secrets:v1";

/// Encrypted envelope for `<ROOSTE_ROOT>/local_secrets.enc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalSecretsEnvelope {
    version: u8,
    device_id: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Result returned when initializing or re-keying a vault.
#[derive(Clone)]
pub struct InitializedVault {
    /// 24-word English BIP-39 recovery mnemonic (zeroized on drop).
    pub mnemonic: Zeroizing<String>,
    /// Vault UUID.
    pub vault_id: String,
}

impl fmt::Debug for InitializedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitializedVault")
            .field("vault_id", &self.vault_id)
            .field("mnemonic", &"<redacted>")
            .finish()
    }
}

/// Summary metadata extracted from a remote or local vault header + manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSummary {
    pub vault_id: String,
    pub sequence: u64,
    pub updated_at: u64,
    pub profile_count: usize,
    pub key_count: usize,
    pub script_count: usize,
}

/// File-backed end-to-end encrypted Vault Store.
pub struct VaultStore {
    location: ConfigLocation,
    local: LocalConfig,
    header: Option<VaultHeader>,
    dek: Option<Zeroizing<[u8; 16]>>,
    manifest: VaultManifest,
    kdf_params: Argon2Params,
}

impl fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultStore")
            .field("vault_dir", &self.vault_dir())
            .field("portable", &self.location.portable)
            .field("initialized", &self.header.is_some())
            .field("unlocked", &self.dek.is_some())
            .field("manifest_sequence", &self.manifest.sequence)
            .finish()
    }
}

impl VaultStore {
    /// Open a vault handle anchored at `location`. Does not unlock the vault.
    pub fn open(location: ConfigLocation) -> Result<Self, VaultError> {
        let local = LocalConfig::load(&location.local_path())?;
        let header_path = location.vault_dir().join(VAULT_HEADER_FILE);
        let header = if header_path.exists() {
            let bytes = read_file_bytes(&header_path)?;
            let h: VaultHeader = serde_json::from_slice(&bytes)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            h.check_version()?;
            Some(h)
        } else {
            None
        };
        Ok(Self {
            location,
            local,
            header,
            dek: None,
            manifest: VaultManifest::default(),
            kdf_params: Argon2Params::default(),
        })
    }

    /// Override Argon2id parameters (primarily for fast unit/GUI tests).
    pub fn with_kdf_params(mut self, kdf_params: Argon2Params) -> Self {
        self.kdf_params = kdf_params;
        self
    }

    pub fn location(&self) -> &ConfigLocation {
        &self.location
    }

    pub fn vault_dir(&self) -> PathBuf {
        self.location.vault_dir()
    }

    pub fn local_config(&self) -> &LocalConfig {
        &self.local
    }

    pub fn local_config_mut(&mut self) -> &mut LocalConfig {
        &mut self.local
    }

    pub fn save_local_config(&self) -> Result<(), VaultError> {
        self.local.save(&self.location.local_path())?;
        Ok(())
    }

    pub fn header(&self) -> Option<&VaultHeader> {
        self.header.as_ref()
    }

    pub fn is_initialized(&self) -> bool {
        self.header.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some() && self.header.is_some()
    }

    pub fn manifest(&self) -> &VaultManifest {
        &self.manifest
    }

    /// Expose a reference to the unlocked 16-byte DEK (for sync engine operations).
    pub fn dek(&self) -> Result<&[u8; 16], VaultError> {
        self.dek.as_deref().ok_or(VaultError::Locked)
    }

    /// Lock the vault immediately, zeroizing the in-memory DEK.
    pub fn lock(&mut self) {
        self.dek = None;
        self.manifest = VaultManifest::default();
    }

    /// Initialize a brand-new encrypted vault with `master_password`.
    ///
    /// Creates `vault/vault.json` and an initial empty encrypted `vault/manifest.enc`.
    /// Leaves the store in the unlocked state and returns the 24-word BIP-39 mnemonic.
    pub fn initialize(&mut self, master_password: &str) -> Result<InitializedVault, VaultError> {
        let (header, dek, mnemonic) = VaultHeader::create(master_password, self.kdf_params)?;
        ensure_vault_dirs(&self.vault_dir())?;
        write_header(&self.vault_dir(), &header)?;

        let vault_id = header.vault_id.clone();
        self.header = Some(header);
        self.dek = Some(dek);
        self.manifest = VaultManifest {
            sequence: 1,
            updated_at: now_utc_ms(),
            entries: Default::default(),
        };
        self.save_local_config()?;
        self.save_manifest()?;

        Ok(InitializedVault { mnemonic, vault_id })
    }

    /// Unlock an existing vault using the user's master password.
    pub fn unlock_with_password(&mut self, master_password: &str) -> Result<(), VaultError> {
        let header = self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?;
        let dek = header.unlock_with_password(master_password)?;
        self.dek = Some(dek);
        self.load_manifest_if_present()?;
        Ok(())
    }

    /// Re-verify the user's master password without modifying store state.
    ///
    /// Used as a step-up authentication gate before sensitive operations such as
    /// exporting a decrypted SSH private key to disk.
    pub fn verify_master_password(&self, master_password: &str) -> Result<(), VaultError> {
        let header = self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?;
        let candidate_dek = header.unlock_with_password(master_password)?;
        if let Some(active_dek) = self.dek.as_ref()
            && *candidate_dek != **active_dek
        {
            return Err(VaultError::InvalidPassword);
        }
        Ok(())
    }

    /// Unlock an existing vault using its 24-word BIP-39 recovery mnemonic.
    pub fn unlock_with_mnemonic(&mut self, phrase: &str) -> Result<(), VaultError> {
        let header = self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?;
        let dek = header.unlock_with_mnemonic(phrase)?;
        self.dek = Some(dek);
        self.load_manifest_if_present()?;
        Ok(())
    }

    /// Reset `password_slot` to `new_master_password` while keeping the existing DEK.
    /// Does not re-encrypt any `.enc` data records.
    pub fn reset_master_password(&mut self, new_master_password: &str) -> Result<(), VaultError> {
        let dek = *self.dek()?;
        let vault_dir = self.vault_dir();
        let kdf_params = self.kdf_params;
        let header = self
            .header
            .as_mut()
            .ok_or_else(|| VaultError::NotInitialized {
                path: vault_dir.clone(),
            })?;
        header.reset_password_slot(&dek, new_master_password, kdf_params)?;
        write_header(&vault_dir, header)?;
        Ok(())
    }

    /// Perform a full **Vault Re-keying**:
    /// generates a fresh DEK and fresh 24-word BIP-39 mnemonic, re-encrypts every active
    /// `.enc` record into a staging directory, atomically swaps it over `vault/`, and
    /// re-encrypts `local_secrets.enc` if present.
    pub fn rekey(&mut self, new_master_password: &str) -> Result<InitializedVault, VaultError> {
        let _old_dek = *self.dek()?;
        let old_vault_id = self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?
            .vault_id
            .clone();

        // Snapshot all decrypted data before rotating keys.
        let profiles = self.list_profiles()?;
        let keys = self.list_ssh_keys()?;
        let scripts = self.list_scripts()?;
        let known_hosts = self.load_known_hosts()?;
        let mut passwords = Vec::new();
        for p in &profiles {
            if let Some(pw) = self.load_password(&p.id)? {
                passwords.push(pw);
            }
        }
        let local_creds = self.load_local_credentials()?;

        let (new_header, new_dek, new_mnemonic) = VaultHeader::create_for_rekey(
            old_vault_id.clone(),
            new_master_password,
            self.kdf_params,
        )?;

        // Rotate device_id so deterministic nonces start cleanly under the new DEK.
        self.local.rotate_device_id();

        // Build fresh vault in a sibling staging directory.
        let staging_root = self
            .location
            .root_dir()
            .join(format!(".vault.rekey.{}", uuid::Uuid::new_v4().simple()));
        let staging_loc = ConfigLocation::for_root(staging_root.clone(), self.location.portable);
        ensure_vault_dirs(&staging_loc.vault_dir())?;
        write_header(&staging_loc.vault_dir(), &new_header)?;

        let mut staged = VaultStore {
            location: staging_loc.clone(),
            local: self.local.clone(),
            header: Some(new_header.clone()),
            dek: Some(new_dek.clone()),
            manifest: VaultManifest {
                sequence: self.manifest.sequence.saturating_add(1),
                updated_at: now_utc_ms(),
                entries: Default::default(),
            },
            kdf_params: self.kdf_params,
        };
        staged.save_local_config()?;

        if !known_hosts.lines.is_empty() {
            staged.save_known_hosts(&known_hosts)?;
        }
        for key in &keys {
            staged.save_ssh_key(key)?;
        }
        for script in &scripts {
            staged.save_script(script)?;
        }
        for profile in &profiles {
            staged.save_profile(profile)?;
        }
        for pw in &passwords {
            staged.save_password(&pw.profile_id, &pw.password)?;
        }
        staged.save_manifest()?;

        // Swap staging vault/ over live vault/ with backup rollback safety.
        let backup = self.begin_reset_backup()?;
        if let Err(err) = std::fs::rename(staging_loc.vault_dir(), self.vault_dir()) {
            let _ = self.rollback_reset(&backup);
            let _ = std::fs::remove_dir_all(&staging_root);
            return Err(VaultError::Io {
                path: self.vault_dir(),
                source: err,
            });
        }
        let _ = std::fs::remove_dir_all(&staging_root);
        self.commit_reset(&backup);

        // Adopt new state and re-encrypt local_secrets.enc.
        self.local = staged.local;
        self.header = Some(new_header);
        self.dek = Some(new_dek);
        self.manifest = staged.manifest;
        self.save_local_config()?;
        if let Some(creds) = local_creds {
            self.save_local_credentials(&creds)?;
        }

        Ok(InitializedVault {
            mnemonic: new_mnemonic,
            vault_id: old_vault_id,
        })
    }

    // -------------------------------------------------------------------------
    // Local Sync Credentials (`local_secrets.enc` — zero OS Keyring dependency)
    // -------------------------------------------------------------------------

    /// Encrypt and persist machine-local sync backend credentials (`local_secrets.enc`)
    /// using a subkey derived from `DEK` + `device_id`.
    pub fn save_local_credentials(
        &mut self,
        creds: &LocalSyncCredentials,
    ) -> Result<(), VaultError> {
        let dek = *self.dek()?;
        let key = derive_local_secrets_key(&dek, &self.local.device_id)?;
        let nonce = self.allocate_nonce()?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(creds).map_err(|e| VaultError::Serialization(e.to_string()))?,
        );
        let ciphertext = seal_sm4_gcm(&key, &nonce, LOCAL_SECRETS_AAD, &plaintext)?;
        let env = LocalSecretsEnvelope {
            version: 1,
            device_id: self.local.device_id.clone(),
            nonce,
            ciphertext,
        };
        let bytes = serde_json::to_vec_pretty(&env)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        let path = self.location.local_secrets_path();
        atomic_write_bytes(&path, &bytes).map_err(|source| VaultError::Io { path, source })?;
        Ok(())
    }

    /// Load and decrypt machine-local sync backend credentials (`local_secrets.enc`).
    /// Returns `Ok(None)` if no credentials file exists yet.
    pub fn load_local_credentials(&self) -> Result<Option<LocalSyncCredentials>, VaultError> {
        let dek = *self.dek()?;
        let path = self.location.local_secrets_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_file_bytes(&path)?;
        let env: LocalSecretsEnvelope =
            serde_json::from_slice(&bytes).map_err(|e| VaultError::Serialization(e.to_string()))?;
        if env.version != 1 {
            return Err(VaultError::UnsupportedVersion(env.version));
        }
        let key = derive_local_secrets_key(&dek, &env.device_id)?;
        let plaintext = open_sm4_gcm(&key, &env.nonce, LOCAL_SECRETS_AAD, &env.ciphertext)?;
        let creds: LocalSyncCredentials = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(Some(creds))
    }

    // -------------------------------------------------------------------------
    // Profile CRUD (`vault/profiles/<uuid>.enc`)
    // -------------------------------------------------------------------------

    pub fn save_profile(&mut self, profile: &Profile) -> Result<(), VaultError> {
        let bytes =
            serde_json::to_vec(profile).map_err(|e| VaultError::Serialization(e.to_string()))?;
        if self.write_encrypted_record_if_changed(RecordKind::Profile, &profile.id, &bytes)? {
            self.save_manifest()?;
        }
        Ok(())
    }

    pub fn load_profile(&self, id: &str) -> Result<Option<Profile>, VaultError> {
        let Some(plain) = self.read_encrypted_record(RecordKind::Profile, id)? else {
            return Ok(None);
        };
        let profile: Profile =
            serde_json::from_slice(&plain).map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(Some(profile))
    }

    pub fn list_profiles(&self) -> Result<Vec<Profile>, VaultError> {
        let _ = self.dek()?;
        let mut out = Vec::new();
        for entry in self.manifest.entries.values() {
            if entry.kind == RecordKind::Profile
                && !entry.deleted
                && let Some(p) = self.load_profile(&entry.id)?
            {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// Delete a profile (marks profile + its password record as tombstones).
    ///
    /// **Important**: Associated SSH keys (`vault/keys/<sha256>.enc`) are first-class
    /// assets and are NEVER automatically deleted when a profile is removed.
    pub fn delete_profile(&mut self, id: &str) -> Result<(), VaultError> {
        self.mark_deleted(RecordKind::Profile, id)?;
        let pw_key = RecordKind::Password.manifest_key(id);
        if self.manifest.entries.contains_key(&pw_key) {
            self.mark_deleted(RecordKind::Password, id)?;
        }
        self.save_manifest()
    }

    // -------------------------------------------------------------------------
    // Password CRUD (`vault/passwords/<profile-uuid>.enc`)
    // -------------------------------------------------------------------------

    pub fn save_password(&mut self, profile_id: &str, password: &str) -> Result<(), VaultError> {
        let record = VaultPassword {
            profile_id: profile_id.to_owned(),
            password: Zeroizing::new(password.to_owned()),
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&record).map_err(|e| VaultError::Serialization(e.to_string()))?,
        );
        if self.write_encrypted_record_if_changed(RecordKind::Password, profile_id, &bytes)? {
            self.save_manifest()?;
        }
        Ok(())
    }

    pub fn load_password(&self, profile_id: &str) -> Result<Option<VaultPassword>, VaultError> {
        let Some(plain) = self.read_encrypted_record(RecordKind::Password, profile_id)? else {
            return Ok(None);
        };
        let pw: VaultPassword =
            serde_json::from_slice(&plain).map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(Some(pw))
    }

    pub fn delete_password(&mut self, profile_id: &str) -> Result<(), VaultError> {
        self.mark_deleted(RecordKind::Password, profile_id)?;
        self.save_manifest()
    }

    // -------------------------------------------------------------------------
    // First-Class SSH Key CRUD (`vault/keys/<sha256>.enc`)
    // -------------------------------------------------------------------------

    /// Import or deduplicate an SSH private key into the vault as a first-class asset.
    ///
    /// Normalizes the PEM content, computes its SHA-256 hex digest, and reuses any existing
    /// non-deleted key with the same digest (returns `(sha256, deduplicated)`).
    pub fn import_ssh_key(
        &mut self,
        label: String,
        fingerprint: String,
        public_key: String,
        raw_private_key_pem: &str,
        passphrase: Option<String>,
        require_passphrase_prompt: bool,
    ) -> Result<(String, bool), VaultError> {
        let (sha256, normalized_pem) = normalize_and_hash_ssh_key(raw_private_key_pem);
        let mkey = RecordKind::SshKey.manifest_key(&sha256);
        if let Some(existing) = self.manifest.entries.get(&mkey)
            && !existing.deleted
            && self.record_path(RecordKind::SshKey, &sha256).exists()
        {
            return Ok((sha256, true));
        }

        let stored_passphrase = if require_passphrase_prompt {
            None
        } else {
            passphrase.map(Zeroizing::new)
        };
        let key = VaultSshKey {
            sha256: sha256.clone(),
            label,
            fingerprint,
            public_key,
            private_key_pem: normalized_pem,
            passphrase: stored_passphrase,
            require_passphrase_prompt,
        };
        self.save_ssh_key(&key)?;
        Ok((sha256, false))
    }

    pub fn save_ssh_key(&mut self, key: &VaultSshKey) -> Result<(), VaultError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(key).map_err(|e| VaultError::Serialization(e.to_string()))?,
        );
        if self.write_encrypted_record_if_changed(RecordKind::SshKey, &key.sha256, &bytes)? {
            self.save_manifest()?;
        }
        Ok(())
    }

    pub fn load_ssh_key(&self, sha256: &str) -> Result<Option<VaultSshKey>, VaultError> {
        let Some(plain) = self.read_encrypted_record(RecordKind::SshKey, sha256)? else {
            return Ok(None);
        };
        let key: VaultSshKey =
            serde_json::from_slice(&plain).map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(Some(key))
    }

    pub fn list_ssh_keys(&self) -> Result<Vec<VaultSshKey>, VaultError> {
        let _ = self.dek()?;
        let mut out = Vec::new();
        for entry in self.manifest.entries.values() {
            if entry.kind == RecordKind::SshKey
                && !entry.deleted
                && let Some(k) = self.load_ssh_key(&entry.id)?
            {
                out.push(k);
            }
        }
        Ok(out)
    }

    /// Explicitly delete a first-class SSH key asset (only called on explicit user action).
    pub fn delete_ssh_key(&mut self, sha256: &str) -> Result<(), VaultError> {
        self.mark_deleted(RecordKind::SshKey, sha256)?;
        self.save_manifest()
    }

    // -------------------------------------------------------------------------
    // Scripts & KnownHosts CRUD
    // -------------------------------------------------------------------------

    pub fn save_script(&mut self, script: &VaultScript) -> Result<(), VaultError> {
        let bytes =
            serde_json::to_vec(script).map_err(|e| VaultError::Serialization(e.to_string()))?;
        if self.write_encrypted_record_if_changed(RecordKind::Script, &script.id, &bytes)? {
            self.save_manifest()?;
        }
        Ok(())
    }

    pub fn load_script(&self, id: &str) -> Result<Option<VaultScript>, VaultError> {
        let Some(plain) = self.read_encrypted_record(RecordKind::Script, id)? else {
            return Ok(None);
        };
        let script: VaultScript =
            serde_json::from_slice(&plain).map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(Some(script))
    }

    pub fn list_scripts(&self) -> Result<Vec<VaultScript>, VaultError> {
        let _ = self.dek()?;
        let mut out = Vec::new();
        for entry in self.manifest.entries.values() {
            if entry.kind == RecordKind::Script
                && !entry.deleted
                && let Some(s) = self.load_script(&entry.id)?
            {
                out.push(s);
            }
        }
        Ok(out)
    }

    pub fn delete_script(&mut self, id: &str) -> Result<(), VaultError> {
        self.mark_deleted(RecordKind::Script, id)?;
        self.save_manifest()
    }

    pub fn save_known_hosts(&mut self, kh: &VaultKnownHosts) -> Result<(), VaultError> {
        let bytes = serde_json::to_vec(kh).map_err(|e| VaultError::Serialization(e.to_string()))?;
        if self.write_encrypted_record_if_changed(RecordKind::KnownHosts, "known_hosts", &bytes)? {
            self.save_manifest()?;
        }
        Ok(())
    }

    pub fn load_known_hosts(&self) -> Result<VaultKnownHosts, VaultError> {
        let Some(plain) = self.read_encrypted_record(RecordKind::KnownHosts, "known_hosts")? else {
            return Ok(VaultKnownHosts::default());
        };
        let kh: VaultKnownHosts =
            serde_json::from_slice(&plain).map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(kh)
    }

    // -------------------------------------------------------------------------
    // Sync & Disaster Recovery (Wipe & Re-sync) Helpers
    // -------------------------------------------------------------------------

    /// Read raw bytes of any relative path inside `vault/` (for sync upload).
    pub fn read_raw_blob(&self, relative_path: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let path = self.vault_dir().join(relative_path);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(read_file_bytes(&path)?))
    }

    /// Write raw bytes to a relative path inside `vault/` atomically (for sync download).
    pub fn write_raw_blob(&self, relative_path: &str, bytes: &[u8]) -> Result<(), VaultError> {
        let path = self.vault_dir().join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| VaultError::Io {
                path: parent.to_owned(),
                source,
            })?;
        }
        atomic_write_bytes(&path, bytes).map_err(|source| VaultError::Io { path, source })?;
        Ok(())
    }

    /// Remove a local `.enc` file if it exists (when applying a remote tombstone).
    pub fn remove_raw_blob(&self, relative_path: &str) -> Result<(), VaultError> {
        let path = self.vault_dir().join(relative_path);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|source| VaultError::Io { path, source })?;
        }
        Ok(())
    }

    /// Replace the in-memory manifest and persist encrypted `manifest.enc`.
    pub fn set_manifest_and_save(&mut self, manifest: VaultManifest) -> Result<String, VaultError> {
        self.manifest = manifest;
        self.save_manifest()?;
        let raw = self.read_raw_blob("manifest.enc")?.unwrap_or_default();
        Ok(sha256_hex(&raw))
    }

    /// Replace the in-memory manifest and on-disk `manifest.enc` with exact remote bytes
    /// (used on pull-only syncs so local manifest hash & sequence stay identical to remote).
    pub fn replace_manifest_from_remote(
        &mut self,
        manifest: VaultManifest,
        raw_bytes: &[u8],
    ) -> Result<String, VaultError> {
        self.write_raw_blob("manifest.enc", raw_bytes)?;
        self.manifest = manifest;
        Ok(sha256_hex(raw_bytes))
    }

    /// Compute SHA-256 hex of the on-disk `vault/manifest.enc` bytes.
    pub fn manifest_file_hash(&self) -> Result<Option<String>, VaultError> {
        Ok(self.read_raw_blob("manifest.enc")?.map(|b| sha256_hex(&b)))
    }

    /// Produce a human-readable summary of the unlocked vault.
    pub fn summary(&self) -> Option<VaultSummary> {
        let vault_id = self.header.as_ref()?.vault_id.clone();
        let mut profile_count = 0;
        let mut key_count = 0;
        let mut script_count = 0;
        for entry in self.manifest.entries.values() {
            if entry.deleted {
                continue;
            }
            match entry.kind {
                RecordKind::Profile => profile_count += 1,
                RecordKind::SshKey => key_count += 1,
                RecordKind::Script => script_count += 1,
                _ => {}
            }
        }
        Some(VaultSummary {
            vault_id,
            sequence: self.manifest.sequence,
            updated_at: self.manifest.updated_at,
            profile_count,
            key_count,
            script_count,
        })
    }

    /// Move existing `vault/` into `vault.reset_backup/` before wiping and re-syncing from remote
    /// (Scene D safety net). Returns the backup path.
    pub fn begin_reset_backup(&mut self) -> Result<PathBuf, VaultError> {
        let vault_dir = self.vault_dir();
        let backup = self.location.root_dir().join("vault.reset_backup");
        if backup.exists() {
            std::fs::remove_dir_all(&backup).map_err(|source| VaultError::Io {
                path: backup.clone(),
                source,
            })?;
        }
        if vault_dir.exists() {
            std::fs::rename(&vault_dir, &backup).map_err(|source| VaultError::Io {
                path: vault_dir,
                source,
            })?;
        }
        self.header = None;
        self.dek = None;
        self.manifest = VaultManifest::default();
        Ok(backup)
    }

    /// Finalize a successful reset by deleting `vault.reset_backup/`.
    pub fn commit_reset(&self, backup: &Path) {
        if backup.exists() {
            let _ = std::fs::remove_dir_all(backup);
        }
    }

    /// Roll back a failed reset by restoring `vault.reset_backup/` back to `vault/`.
    pub fn rollback_reset(&mut self, backup: &Path) -> Result<(), VaultError> {
        let vault_dir = self.vault_dir();
        if vault_dir.exists() {
            let _ = std::fs::remove_dir_all(&vault_dir);
        }
        if backup.exists() {
            std::fs::rename(backup, &vault_dir).map_err(|source| VaultError::Io {
                path: vault_dir.clone(),
                source,
            })?;
            let header_path = vault_dir.join(VAULT_HEADER_FILE);
            if header_path.exists() {
                let bytes = read_file_bytes(&header_path)?;
                let h: VaultHeader = serde_json::from_slice(&bytes)
                    .map_err(|e| VaultError::Serialization(e.to_string()))?;
                self.header = Some(h);
            }
        }
        Ok(())
    }

    /// Install a freshly pulled remote header and unlock it with `dek`, rotating `device_id`
    /// so subsequent writes start with a fresh deterministic nonce namespace.
    pub fn install_recovered_vault(
        &mut self,
        header: VaultHeader,
        dek: Zeroizing<[u8; 16]>,
        manifest: VaultManifest,
    ) -> Result<(), VaultError> {
        ensure_vault_dirs(&self.vault_dir())?;
        write_header(&self.vault_dir(), &header)?;
        self.local.rotate_device_id();
        self.header = Some(header);
        self.dek = Some(dek);
        self.manifest = manifest;
        self.save_local_config()?;
        Ok(())
    }

    /// Decrypt and validate an `EncryptedRecord` blob against this vault's DEK and vault_id.
    pub fn decrypt_external_record(
        &self,
        kind: RecordKind,
        id: &str,
        bytes: &[u8],
    ) -> Result<(EncryptedRecord, Zeroizing<Vec<u8>>), VaultError> {
        let dek = self.dek()?;
        let vault_id = &self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?
            .vault_id;
        let rec = EncryptedRecord::from_bytes(bytes)?;
        let plain = rec.open(vault_id, kind, id, dek)?;
        Ok((rec, plain))
    }

    // -------------------------------------------------------------------------
    // Internal Encryption & Manifest Persistence
    // -------------------------------------------------------------------------

    fn allocate_nonce(&mut self) -> Result<[u8; 12], VaultError> {
        let counter = self
            .local
            .allocate_nonce_counter(&self.location.local_path())?;
        Ok(deterministic_nonce(&self.local.device_id, counter))
    }

    fn record_path(&self, kind: RecordKind, id: &str) -> PathBuf {
        self.vault_dir().join(kind.relative_path(id))
    }

    /// Write an encrypted record only if it does not yet exist, is currently marked deleted,
    /// or its plaintext differs from the currently stored active record.
    ///
    /// Returns `Ok(true)` if a new revision was written, or `Ok(false)` on a no-op save
    /// (preventing spurious revision increments and false sync conflicts).
    fn write_encrypted_record_if_changed(
        &mut self,
        kind: RecordKind,
        id: &str,
        plaintext: &[u8],
    ) -> Result<bool, VaultError> {
        let _ = self.dek()?;
        let mkey = kind.manifest_key(id);
        if let Some(existing) = self.manifest.entries.get(&mkey)
            && !existing.deleted
            && let Ok(Some(current_plain)) = self.read_encrypted_record(kind, id)
            && current_plain.as_slice() == plaintext
        {
            return Ok(false);
        }
        self.write_encrypted_record(kind, id, plaintext)?;
        Ok(true)
    }

    fn write_encrypted_record(
        &mut self,
        kind: RecordKind,
        id: &str,
        plaintext: &[u8],
    ) -> Result<ManifestEntry, VaultError> {
        let dek = *self.dek()?;
        let vault_id = self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?
            .vault_id
            .clone();

        let mkey = kind.manifest_key(id);
        let prev_entry = self.manifest.entries.get(&mkey).cloned();
        let revision = prev_entry
            .as_ref()
            .map_or(1, |e| e.revision.saturating_add(1));
        let base_hash = prev_entry.as_ref().map_or([0u8; 32], |e| e.rev_hash);
        let updated_at = now_utc_ms();
        let nonce = self.allocate_nonce()?;

        let record = EncryptedRecord::seal(
            SealMeta {
                vault_id: &vault_id,
                id,
                kind,
                revision,
                updated_at,
                base_hash,
                nonce,
            },
            &dek,
            plaintext,
        )?;
        let bytes = record.to_bytes()?;
        let rev_hash = sha256_bytes(&bytes);
        let path = self.record_path(kind, id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| VaultError::Io {
                path: parent.to_owned(),
                source,
            })?;
        }
        atomic_write_bytes(&path, &bytes).map_err(|source| VaultError::Io { path, source })?;

        let entry = ManifestEntry {
            id: id.to_owned(),
            kind,
            revision,
            updated_at,
            updated_by: self.local.device_id.clone(),
            rev_hash,
            prev_hash: prev_entry.map(|e| e.rev_hash),
            deleted: false,
        };
        self.manifest.entries.insert(mkey, entry.clone());
        Ok(entry)
    }

    fn read_encrypted_record(
        &self,
        kind: RecordKind,
        id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let dek = self.dek()?;
        let vault_id = &self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?
            .vault_id;
        let path = self.record_path(kind, id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_file_bytes(&path)?;
        let record = EncryptedRecord::from_bytes(&bytes)?;
        let plain = record.open(vault_id, kind, id, dek)?;
        Ok(Some(plain))
    }

    fn mark_deleted(&mut self, kind: RecordKind, id: &str) -> Result<(), VaultError> {
        let _ = self.dek()?;
        let mkey = kind.manifest_key(id);
        let prev = self.manifest.entries.get(&mkey).cloned();
        let revision = prev.as_ref().map_or(1, |e| e.revision.saturating_add(1));
        let entry = ManifestEntry {
            id: id.to_owned(),
            kind,
            revision,
            updated_at: now_utc_ms(),
            updated_by: self.local.device_id.clone(),
            rev_hash: [0u8; 32],
            prev_hash: prev.map(|e| e.rev_hash),
            deleted: true,
        };
        self.manifest.entries.insert(mkey, entry);
        let path = self.record_path(kind, id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|source| VaultError::Io { path, source })?;
        }
        Ok(())
    }

    fn save_manifest(&mut self) -> Result<(), VaultError> {
        let dek = *self.dek()?;
        let vault_id = self
            .header
            .as_ref()
            .ok_or_else(|| VaultError::NotInitialized {
                path: self.vault_dir(),
            })?
            .vault_id
            .clone();

        self.manifest.sequence = self.manifest.sequence.saturating_add(1);
        self.manifest.updated_at = now_utc_ms();

        let path = self.record_path(RecordKind::Manifest, "manifest");
        let base_hash = if path.exists() {
            sha256_bytes(&read_file_bytes(&path)?)
        } else {
            [0u8; 32]
        };
        let nonce = self.allocate_nonce()?;
        let plaintext = serde_json::to_vec(&self.manifest)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        let record = EncryptedRecord::seal(
            SealMeta {
                vault_id: &vault_id,
                id: "manifest",
                kind: RecordKind::Manifest,
                revision: self.manifest.sequence,
                updated_at: self.manifest.updated_at,
                base_hash,
                nonce,
            },
            &dek,
            &plaintext,
        )?;
        let bytes = record.to_bytes()?;
        atomic_write_bytes(&path, &bytes).map_err(|source| VaultError::Io { path, source })?;
        Ok(())
    }

    fn load_manifest_if_present(&mut self) -> Result<(), VaultError> {
        if let Some(plain) = self.read_encrypted_record(RecordKind::Manifest, "manifest")? {
            self.manifest = serde_json::from_slice(&plain)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
        } else {
            self.manifest = VaultManifest::default();
        }
        Ok(())
    }
}

/// Current UTC timestamp in milliseconds.
pub fn now_utc_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn ensure_vault_dirs(vault_dir: &Path) -> Result<(), VaultError> {
    for sub in ["", "profiles", "passwords", "keys", "scripts"] {
        let dir = if sub.is_empty() {
            vault_dir.to_owned()
        } else {
            vault_dir.join(sub)
        };
        std::fs::create_dir_all(&dir).map_err(|source| VaultError::Io { path: dir, source })?;
    }
    Ok(())
}

fn write_header(vault_dir: &Path, header: &VaultHeader) -> Result<(), VaultError> {
    let path = vault_dir.join(VAULT_HEADER_FILE);
    let bytes =
        serde_json::to_vec_pretty(header).map_err(|e| VaultError::Serialization(e.to_string()))?;
    atomic_write_bytes(&path, &bytes).map_err(|source| VaultError::Io { path, source })?;
    Ok(())
}

fn read_file_bytes(path: &Path) -> Result<Vec<u8>, VaultError> {
    std::fs::read(path).map_err(|source| VaultError::Io {
        path: path.to_owned(),
        source,
    })
}

/// Parse a `VaultHeader` directly from raw JSON bytes (e.g. pulled from remote backend).
pub fn parse_header_bytes(bytes: &[u8]) -> Result<VaultHeader, VaultError> {
    let h: VaultHeader =
        serde_json::from_slice(bytes).map_err(|e| VaultError::Serialization(e.to_string()))?;
    h.check_version()?;
    Ok(h)
}

/// Decrypt a raw `manifest.enc` blob using `header.vault_id` and `dek`.
pub fn decrypt_manifest_bytes(
    vault_id: &str,
    dek: &[u8; 16],
    bytes: &[u8],
) -> Result<VaultManifest, VaultError> {
    let rec = EncryptedRecord::from_bytes(bytes)?;
    let plain = rec.open(vault_id, RecordKind::Manifest, "manifest", dek)?;
    serde_json::from_slice(&plain).map_err(|e| VaultError::Serialization(e.to_string()))
}

#[allow(dead_code)]
fn _assert_io_error_send(_e: io::Error) {}
