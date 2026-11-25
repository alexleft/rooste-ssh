//! Encrypted Vault & Multi-Backend Sync UI controller (`Phase 4`).
//!
//! Implements:
//! - Scene A: New Vault / Legacy Migration Onboarding with 4×6 BIP-39 mnemonic & mandatory 3-word quiz
//! - Scene B: New Device Remote Recovery (Master Password or 24-word Mnemonic)
//! - Scene C: Forgot Master Password lossless reset (`password_slot` only)
//! - Scene D: Wipe Local Vault & Force Re-sync from Remote (with `RESET` confirmation & rollback safety)
//! - Lock Screen & idle auto-lock (`auto_lock_timeout_secs`)
//! - Full Vault Re-keying (rotate DEK & 24-word mnemonic)
//! - First-Class Managed SSH Keys Manager (SHA-256 dedup, mandatory Passphrase double-entry confirmation)
//! - Async Sync Settings & Status Bar (GitHub / S3 / WebDAV, zero OS Keyring via `local_secrets.enc`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Color32, RichText, Ui};
use rooste_core::{
    Config, ConfigLocation, Profile, SecretStore, SyncBackendKind, SyncConfig, backup_legacy_config,
};
use rooste_keys::{KeyInspection, KeyType};
use rooste_protocols::ssh::load_private_key_from_pem;
use rooste_sync::{
    RemoteVaultSnapshot, SyncActorHandle, SyncCommand, SyncEvent, SyncProgress, SyncReport,
};
use rooste_vault::{
    LocalSyncCredentials, VaultSshKey, VaultStore, normalize_and_hash_ssh_key,
    password_strength_score, suggest_mnemonic_words,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::picker::{PickId, PickKind, Picker};
use crate::theme;

/// Cached non-secret summary of a managed SSH key for fast 60 FPS UI rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedKeySummary {
    pub sha256: String,
    pub label: String,
    pub fingerprint: String,
    pub public_key: String,
    pub has_saved_passphrase: bool,
    pub require_passphrase_prompt: bool,
}

/// Live synchronization status shown in the status bar & settings dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Disabled,
    Idle,
    Syncing(SyncProgress),
    Synced(String),
    Error(String),
}

/// Actions emitted by `VaultController::ui` for `RoosteApp` to apply cleanly.
#[derive(Debug)]
pub enum VaultUiAction {
    /// Vault was unlocked or synced; reload `config.profiles` from the decrypted vault.
    ReloadProfiles(Vec<Profile>),
    /// Vault was locked; clear decrypted profiles from memory immediately.
    VaultLocked,
    /// Legacy `config.toml` profiles were migrated into the new encrypted vault.
    LegacyMigrated {
        profiles: Vec<Profile>,
        warnings: Vec<String>,
    },
    /// Show a notification banner in `RoosteApp`.
    Notify { text: String, error: bool },
}

/// Active vault modal dialog.
#[derive(Debug)]
pub enum VaultModal {
    LockScreen(LockScreenState),
    Onboarding(OnboardingState),
    RemoteRecovery(RemoteRecoveryState),
    ForgotPassword(ForgotPasswordState),
    ForceWipeConfirm(ForceWipeState),
    SyncSettings(SyncSettingsState),
    KeysManager(KeysManagerState),
    Rekey(RekeyState),
}

#[derive(Debug)]
pub struct LockScreenState {
    pub password: Zeroizing<String>,
    pub error: Option<String>,
    pub needs_focus: bool,
}

impl Default for LockScreenState {
    fn default() -> Self {
        Self {
            password: Zeroizing::new(String::new()),
            error: None,
            needs_focus: true,
        }
    }
}

#[derive(Debug)]
pub enum OnboardingStep {
    ChooseMode,
    SetPassword,
    ShowMnemonic {
        mnemonic: Zeroizing<String>,
        revealed: bool,
        copied_at: Option<Instant>,
    },
    VerifyMnemonic {
        mnemonic: Zeroizing<String>,
        /// 0-based word indices (e.g. [2, 10, 19]) the user MUST fill accurately.
        quiz_indices: [usize; 3],
        answers: [String; 3],
    },
    OptionalSync,
}

#[derive(Debug)]
pub struct OnboardingState {
    pub step: OnboardingStep,
    pub migrating_legacy: bool,
    pub password: Zeroizing<String>,
    pub confirm_password: Zeroizing<String>,
    pub sync_form: SyncFormState,
    pub error: Option<String>,
}

impl OnboardingState {
    pub fn new(migrating_legacy: bool) -> Self {
        Self {
            step: if migrating_legacy {
                OnboardingStep::SetPassword
            } else {
                OnboardingStep::ChooseMode
            },
            migrating_legacy,
            password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            sync_form: SyncFormState::default(),
            error: None,
        }
    }
}

#[derive(Debug)]
pub struct RemoteRecoveryState {
    pub wipe_existing: bool,
    pub sync_form: SyncFormState,
    pub snapshot: Option<RemoteVaultSnapshot>,
    pub use_mnemonic: bool,
    pub password: Zeroizing<String>,
    pub mnemonic_input: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
    pub confirm_new_password: Zeroizing<String>,
    pub busy: bool,
    pub error: Option<String>,
}

impl RemoteRecoveryState {
    pub fn new(wipe_existing: bool, sync_form: SyncFormState) -> Self {
        Self {
            wipe_existing,
            sync_form,
            snapshot: None,
            use_mnemonic: wipe_existing,
            password: Zeroizing::new(String::new()),
            mnemonic_input: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            confirm_new_password: Zeroizing::new(String::new()),
            busy: false,
            error: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct ForgotPasswordState {
    pub mnemonic_input: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
    pub confirm_password: Zeroizing<String>,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct ForceWipeState {
    pub confirm_word: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SyncFormState {
    pub backend: SyncBackendKind,
    pub endpoint: String,
    pub branch: String,
    pub prefix: String,
    pub auto_sync_interval_secs: u64,
    pub auto_lock_timeout_secs: u64,
    pub github_pat: Zeroizing<String>,
    pub s3_access_key: Zeroizing<String>,
    pub s3_secret_key: Zeroizing<String>,
    pub s3_region: String,
    pub s3_bucket: String,
    pub webdav_user: Zeroizing<String>,
    pub webdav_password: Zeroizing<String>,
}

impl Default for SyncFormState {
    fn default() -> Self {
        Self {
            backend: SyncBackendKind::GitHub,
            endpoint: String::new(),
            branch: "main".into(),
            prefix: String::new(),
            auto_sync_interval_secs: 300,
            auto_lock_timeout_secs: 1800,
            github_pat: Zeroizing::new(String::new()),
            s3_access_key: Zeroizing::new(String::new()),
            s3_secret_key: Zeroizing::new(String::new()),
            s3_region: "auto".into(),
            s3_bucket: String::new(),
            webdav_user: Zeroizing::new(String::new()),
            webdav_password: Zeroizing::new(String::new()),
        }
    }
}

impl SyncFormState {
    pub fn from_config(
        cfg: &SyncConfig,
        auto_lock_secs: u64,
        creds: Option<&LocalSyncCredentials>,
    ) -> Self {
        let mut s = Self {
            backend: cfg.backend,
            endpoint: cfg.endpoint.clone(),
            branch: if cfg.branch.is_empty() {
                "main".into()
            } else {
                cfg.branch.clone()
            },
            prefix: cfg.prefix.clone(),
            auto_sync_interval_secs: cfg.auto_sync_interval_secs,
            auto_lock_timeout_secs: auto_lock_secs,
            ..Self::default()
        };
        if let Some(c) = creds {
            if let Some(ref v) = c.github_pat {
                s.github_pat = v.clone();
            }
            if let Some(ref v) = c.s3_access_key {
                s.s3_access_key = v.clone();
            }
            if let Some(ref v) = c.s3_secret_key {
                s.s3_secret_key = v.clone();
            }
            if !c.s3_region.is_empty() {
                s.s3_region = c.s3_region.clone();
            }
            s.s3_bucket = c.s3_bucket.clone();
            if let Some(ref v) = c.webdav_user {
                s.webdav_user = v.clone();
            }
            if let Some(ref v) = c.webdav_password {
                s.webdav_password = v.clone();
            }
        }
        s
    }

    pub fn to_sync_config(&self, existing: &SyncConfig) -> SyncConfig {
        SyncConfig {
            enabled: self.backend != SyncBackendKind::None,
            backend: self.backend,
            endpoint: self.endpoint.trim().to_owned(),
            branch: if self.branch.trim().is_empty() {
                "main".into()
            } else {
                self.branch.trim().to_owned()
            },
            prefix: self.prefix.trim().to_owned(),
            auto_sync_interval_secs: self.auto_sync_interval_secs,
            last_synced_manifest_hash: existing.last_synced_manifest_hash.clone(),
            last_synced_sequence: existing.last_synced_sequence,
            last_synced_entries: existing.last_synced_entries.clone(),
        }
    }

    pub fn to_credentials(&self) -> LocalSyncCredentials {
        LocalSyncCredentials {
            github_pat: (!self.github_pat.trim().is_empty())
                .then(|| Zeroizing::new(self.github_pat.trim().to_owned())),
            s3_access_key: (!self.s3_access_key.trim().is_empty())
                .then(|| Zeroizing::new(self.s3_access_key.trim().to_owned())),
            s3_secret_key: (!self.s3_secret_key.trim().is_empty())
                .then(|| Zeroizing::new(self.s3_secret_key.trim().to_owned())),
            s3_region: self.s3_region.trim().to_owned(),
            s3_bucket: self.s3_bucket.trim().to_owned(),
            webdav_user: (!self.webdav_user.trim().is_empty())
                .then(|| Zeroizing::new(self.webdav_user.trim().to_owned())),
            webdav_password: (!self.webdav_password.is_empty())
                .then(|| self.webdav_password.clone()),
        }
    }
}

#[derive(Debug)]
pub struct SyncSettingsState {
    pub form: SyncFormState,
    pub testing: bool,
    pub test_result: Option<Result<String, String>>,
    pub error: Option<String>,
}

/// Active right-hand view inside the Managed SSH Keys window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysPane {
    Detail(String),
    Import,
    Generate,
}

/// Source tab inside the Import Key view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ImportSourceTab {
    #[default]
    File,
    DiscoverSshDir,
    PastePem,
}

/// A local private key file discovered inside `~/.ssh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredLocalKey {
    pub path: PathBuf,
    pub file_name: String,
    pub algorithm: String,
    pub is_encrypted: bool,
    pub is_ppk: bool,
    pub sha256_preview: String,
}

#[derive(Debug)]
pub struct KeysManagerState {
    pub pane: KeysPane,
    pub search_query: String,

    // Detail pane editing state (loaded when selecting a key).
    pub detail_loaded_sha: Option<String>,
    pub detail_label: String,
    pub detail_require_prompt: bool,
    pub detail_new_passphrase: Zeroizing<String>,
    pub detail_confirm_passphrase: Zeroizing<String>,
    pub detail_copied_pub: bool,
    pub detail_copied_fp: bool,
    pub pending_delete_sha: Option<String>,
    pub pending_export_private_sha: Option<String>,
    pub export_private_authorized_sha: Option<String>,
    pub export_vault_password: Zeroizing<String>,

    // Import pane state.
    pub import_tab: ImportSourceTab,
    pub import_label: String,
    pub import_path: String,
    pub import_pem: Zeroizing<String>,
    pub import_inspected_source: String,
    pub import_inspection: Option<Result<KeyInspection, String>>,
    pub import_passphrase: Zeroizing<String>,
    pub import_confirm_passphrase: Zeroizing<String>,
    pub import_require_prompt: bool,
    pub discovered_keys: Vec<DiscoveredLocalKey>,

    // Generate pane state.
    pub gen_label: String,
    pub gen_type: KeyType,
    pub gen_comment: String,
    pub gen_passphrase: Zeroizing<String>,
    pub gen_confirm_passphrase: Zeroizing<String>,
    pub gen_require_prompt: bool,

    // Feedback banner.
    pub error: Option<String>,
    pub status: Option<String>,
}

impl KeysManagerState {
    pub fn open(existing_keys: &[ManagedKeySummary]) -> Self {
        let pane = existing_keys
            .first()
            .map(|k| KeysPane::Detail(k.sha256.clone()))
            .unwrap_or(KeysPane::Import);
        let default_comment = default_key_comment();
        Self {
            pane,
            search_query: String::new(),
            detail_loaded_sha: None,
            detail_label: String::new(),
            detail_require_prompt: false,
            detail_new_passphrase: Zeroizing::new(String::new()),
            detail_confirm_passphrase: Zeroizing::new(String::new()),
            detail_copied_pub: false,
            detail_copied_fp: false,
            pending_delete_sha: None,
            pending_export_private_sha: None,
            export_private_authorized_sha: None,
            export_vault_password: Zeroizing::new(String::new()),
            import_tab: ImportSourceTab::File,
            import_label: String::new(),
            import_path: String::new(),
            import_pem: Zeroizing::new(String::new()),
            import_inspected_source: String::new(),
            import_inspection: None,
            import_passphrase: Zeroizing::new(String::new()),
            import_confirm_passphrase: Zeroizing::new(String::new()),
            import_require_prompt: false,
            discovered_keys: scan_local_ssh_dir(),
            gen_label: "my-ed25519".into(),
            gen_type: KeyType::Ed25519,
            gen_comment: default_comment,
            gen_passphrase: Zeroizing::new(String::new()),
            gen_confirm_passphrase: Zeroizing::new(String::new()),
            gen_require_prompt: false,
            error: None,
            status: None,
        }
    }

    pub fn select_detail(&mut self, sha256: String) {
        self.pane = KeysPane::Detail(sha256);
        self.pending_delete_sha = None;
        self.pending_export_private_sha = None;
        self.export_private_authorized_sha = None;
        self.export_vault_password.clear();
        self.detail_copied_pub = false;
        self.detail_copied_fp = false;
        self.error = None;
    }
}

#[derive(Debug)]
pub struct RekeyState {
    pub new_password: Zeroizing<String>,
    pub confirm_password: Zeroizing<String>,
    pub new_mnemonic: Option<Zeroizing<String>>,
    pub quiz_indices: [usize; 3],
    pub answers: [String; 3],
    pub verified: bool,
    pub error: Option<String>,
}

impl Default for RekeyState {
    fn default() -> Self {
        Self {
            new_password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            new_mnemonic: None,
            quiz_indices: [2, 10, 19],
            answers: Default::default(),
            verified: false,
            error: None,
        }
    }
}

/// Top-level vault & async sync controller embedded inside `RoosteApp`.
pub struct VaultController {
    pub store: Arc<Mutex<VaultStore>>,
    pub actor: SyncActorHandle,
    pub modal: Option<VaultModal>,
    pub status: SyncStatus,
    pub managed_keys: Vec<ManagedKeySummary>,
    pub last_activity: Instant,
    pub last_auto_sync: Instant,
    clipboard_clear_at: Option<Instant>,
    /// True only when an on-disk vault is active for this app instance.
    pub enabled: bool,
    pub unlocked: bool,
    pub auto_lock_timeout_secs: u64,
    pub auto_sync_interval_secs: u64,
    pub sync_enabled: bool,
}

impl std::fmt::Debug for VaultController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultController")
            .field("enabled", &self.enabled)
            .field("unlocked", &self.unlocked)
            .field("status", &self.status)
            .field("managed_keys_count", &self.managed_keys.len())
            .finish_non_exhaustive()
    }
}

impl VaultController {
    /// Attach a `VaultController` anchored at `location`, spawning its background async sync actor.
    pub fn new(
        location: ConfigLocation,
        runtime: &tokio::runtime::Handle,
        wake_ui: Arc<dyn Fn() + Send + Sync>,
    ) -> Option<Self> {
        let store = VaultStore::open(location).ok()?;
        let initialized = store.is_initialized();
        let auto_lock_timeout_secs = store.local_config().auto_lock_timeout_secs;
        let auto_sync_interval_secs = store.local_config().sync.auto_sync_interval_secs;
        let sync_enabled = store.local_config().sync.enabled
            && store.local_config().sync.backend != SyncBackendKind::None;
        let store = Arc::new(Mutex::new(store));
        let actor = SyncActorHandle::spawn(runtime, Arc::clone(&store), wake_ui);

        let modal = if initialized {
            Some(VaultModal::LockScreen(LockScreenState::default()))
        } else {
            None
        };

        Some(Self {
            store,
            actor,
            modal,
            status: if sync_enabled {
                SyncStatus::Idle
            } else {
                SyncStatus::Disabled
            },
            managed_keys: Vec::new(),
            last_activity: Instant::now(),
            last_auto_sync: Instant::now(),
            clipboard_clear_at: None,
            enabled: initialized,
            unlocked: false,
            auto_lock_timeout_secs,
            auto_sync_interval_secs,
            sync_enabled,
        })
    }

    pub fn is_locked_blocking_ui(&self) -> bool {
        self.enabled && !self.unlocked
    }

    /// Open onboarding / migration wizard (Scene A).
    pub fn open_onboarding(&mut self, migrating_legacy: bool) {
        self.modal = Some(VaultModal::Onboarding(OnboardingState::new(
            migrating_legacy,
        )));
    }

    /// Open Managed SSH Keys Manager (first-class asset view).
    pub fn open_keys_manager(&mut self) {
        if !self.enabled {
            self.open_onboarding(false);
            return;
        }
        if !self.unlocked {
            self.modal = Some(VaultModal::LockScreen(LockScreenState::default()));
            return;
        }
        self.refresh_managed_keys();
        self.modal = Some(VaultModal::KeysManager(KeysManagerState::open(
            &self.managed_keys,
        )));
    }

    /// Open Vault & Sync Settings modal.
    pub fn open_sync_settings(&mut self) {
        if !self.enabled {
            self.open_onboarding(false);
            return;
        }
        if !self.unlocked {
            self.modal = Some(VaultModal::LockScreen(LockScreenState::default()));
            return;
        }
        let form = if let Ok(guard) = self.store.try_lock() {
            let creds = guard.load_local_credentials().ok().flatten();
            SyncFormState::from_config(
                &guard.local_config().sync,
                guard.local_config().auto_lock_timeout_secs,
                creds.as_ref(),
            )
        } else {
            SyncFormState::default()
        };
        self.modal = Some(VaultModal::SyncSettings(SyncSettingsState {
            form,
            testing: false,
            test_result: None,
            error: None,
        }));
    }

    /// Immediately lock the vault, zeroizing the in-memory DEK.
    pub fn lock_now(&mut self) -> VaultUiAction {
        if let Ok(mut guard) = self.store.try_lock() {
            guard.lock();
        }
        self.unlocked = false;
        self.managed_keys.clear();
        self.modal = Some(VaultModal::LockScreen(LockScreenState::default()));
        VaultUiAction::VaultLocked
    }

    /// Trigger an immediate non-blocking background sync cycle.
    pub fn trigger_sync_now(&mut self) {
        if !self.unlocked {
            return;
        }
        let Ok(guard) = self.store.try_lock() else {
            return;
        };
        let cfg = guard.local_config().sync.clone();
        if !cfg.enabled || cfg.backend == SyncBackendKind::None {
            return;
        }
        let Ok(Some(creds)) = guard.load_local_credentials() else {
            self.status = SyncStatus::Error("Missing sync credentials in local_secrets.enc".into());
            return;
        };
        drop(guard);
        self.status = SyncStatus::Syncing(SyncProgress {
            stage: "Starting sync…".into(),
            done: 0,
            total: 1,
        });
        self.last_auto_sync = Instant::now();
        self.actor.send(SyncCommand::SyncNow { config: cfg, creds });
    }

    /// Save a profile into the unlocked vault (non-blocking local atomic encrypt).
    pub fn save_profile(&self, profile: &Profile) -> Result<(), String> {
        if !self.unlocked {
            return Ok(());
        }
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault is currently syncing; try again shortly".to_owned())?;
        guard.save_profile(profile).map_err(|e| e.to_string())
    }

    /// Delete a profile from the unlocked vault (associated SSH keys survive as first-class assets).
    pub fn delete_profile(&self, id: &str) -> Result<(), String> {
        if !self.unlocked {
            return Ok(());
        }
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault is currently syncing; try again shortly".to_owned())?;
        guard.delete_profile(id).map_err(|e| e.to_string())
    }

    /// Save a profile's SSH password into `vault/passwords/<id>.enc`.
    pub fn save_password(&self, profile_id: &str, password: &str) -> Result<(), String> {
        if !self.unlocked {
            return Ok(());
        }
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault is currently syncing".to_owned())?;
        guard
            .save_password(profile_id, password)
            .map_err(|e| e.to_string())
    }

    /// Load a profile's decrypted password from `vault/passwords/<id>.enc`.
    pub fn load_password(&self, profile_id: &str) -> Option<String> {
        if !self.unlocked {
            return None;
        }
        let guard = self.store.try_lock().ok()?;
        guard
            .load_password(profile_id)
            .ok()
            .flatten()
            .map(|p| p.password.as_str().to_owned())
    }

    /// Decrypt a managed SSH key on demand right before SSH handshake.
    pub fn load_ssh_key(&self, sha256: &str) -> Option<VaultSshKey> {
        if !self.unlocked {
            return None;
        }
        let guard = self.store.try_lock().ok()?;
        guard.load_ssh_key(sha256).ok().flatten()
    }

    /// Re-verify the user's vault master password before sensitive operations
    /// (e.g. exporting a decrypted private key to disk).
    pub fn verify_master_password(&self, password: &str) -> Result<(), String> {
        if !self.unlocked {
            return Err("Vault is locked.".into());
        }
        if password.is_empty() {
            return Err("Please enter your vault master password.".into());
        }
        let guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        guard
            .verify_master_password(password)
            .map_err(|_| "Incorrect vault master password.".to_owned())
    }

    /// Refresh cached managed key metadata list from the unlocked vault.
    pub fn refresh_managed_keys(&mut self) {
        if !self.unlocked {
            self.managed_keys.clear();
            return;
        }
        if let Ok(guard) = self.store.try_lock()
            && let Ok(keys) = guard.list_ssh_keys()
        {
            self.managed_keys = keys
                .into_iter()
                .map(|k| {
                    let (fp, pub_key) = if k.public_key.is_empty()
                        && let Ok(info) = rooste_keys::inspect_key_text(k.private_key_pem.as_str())
                    {
                        let fp = if k.fingerprint.is_empty() || k.fingerprint.contains("encrypted")
                        {
                            info.fingerprint
                        } else {
                            k.fingerprint.clone()
                        };
                        (fp, info.public_key)
                    } else {
                        (k.fingerprint.clone(), k.public_key.clone())
                    };
                    ManagedKeySummary {
                        sha256: k.sha256.clone(),
                        label: k.label.clone(),
                        fingerprint: fp,
                        public_key: pub_key,
                        has_saved_passphrase: k.passphrase.is_some(),
                        require_passphrase_prompt: k.require_passphrase_prompt,
                    }
                })
                .collect();
        }
    }

    /// Poll background sync events, idle auto-lock timer, periodic auto-sync, and 30s clipboard clear.
    pub fn poll(&mut self, ctx: &egui::Context) -> Vec<VaultUiAction> {
        let mut actions = Vec::new();

        // Track user input for idle auto-lock.
        let had_input = ctx.input(|i| !i.events.is_empty() || i.pointer.any_down());
        if had_input {
            self.last_activity = Instant::now();
        }
        if self.unlocked
            && self.auto_lock_timeout_secs > 0
            && self.last_activity.elapsed() >= Duration::from_secs(self.auto_lock_timeout_secs)
        {
            actions.push(self.lock_now());
            actions.push(VaultUiAction::Notify {
                text: "Vault auto-locked due to inactivity (DEK cleared from memory).".into(),
                error: false,
            });
            return actions;
        }

        // Clear mnemonic from clipboard after 30 seconds.
        if let Some(clear_at) = self.clipboard_clear_at
            && Instant::now() >= clear_at
        {
            self.clipboard_clear_at = None;
            ctx.copy_text(String::new());
        }

        // Periodic background sync.
        if self.unlocked
            && self.sync_enabled
            && self.auto_sync_interval_secs > 0
            && !matches!(self.status, SyncStatus::Syncing(_))
            && self.last_auto_sync.elapsed() >= Duration::from_secs(self.auto_sync_interval_secs)
        {
            self.trigger_sync_now();
        }

        // Drain async events from SyncActor.
        for ev in self.actor.poll() {
            match ev {
                SyncEvent::Progress(p) => {
                    self.status = SyncStatus::Syncing(p);
                }
                SyncEvent::ConnectionTested(res) => {
                    if let Some(VaultModal::SyncSettings(st)) = &mut self.modal {
                        st.testing = false;
                        st.test_result =
                            Some(res.map(|()| "Connection & credentials verified.".to_owned()));
                    }
                }
                SyncEvent::RemoteInspected(res) => {
                    if let Some(VaultModal::RemoteRecovery(st)) = &mut self.modal {
                        st.busy = false;
                        match res {
                            Ok(snap) => {
                                st.snapshot = Some(snap);
                                st.error = None;
                            }
                            Err(err) => {
                                st.error = Some(err);
                            }
                        }
                    }
                }
                SyncEvent::Recovered { result } => match result {
                    Ok((report, _summary)) => {
                        self.enabled = true;
                        self.unlocked = true;
                        self.sync_enabled = true;
                        self.modal = None;
                        self.status = SyncStatus::Synced(format!(
                            "Recovered {} items (seq {})",
                            report.pulled, report.manifest_sequence
                        ));
                        self.refresh_managed_keys();
                        if let Ok(guard) = self.store.try_lock()
                            && let Ok(profiles) = guard.list_profiles()
                        {
                            actions.push(VaultUiAction::ReloadProfiles(profiles));
                        }
                        actions.push(VaultUiAction::Notify {
                            text: format!(
                                "Vault recovered cleanly from remote ({} records).",
                                report.pulled
                            ),
                            error: false,
                        });
                    }
                    Err(err) => {
                        if let Some(VaultModal::RemoteRecovery(st)) = &mut self.modal {
                            st.busy = false;
                            st.error = Some(err.clone());
                        }
                        actions.push(VaultUiAction::Notify {
                            text: format!("Remote recovery failed (rolled back): {err}"),
                            error: true,
                        });
                    }
                },
                SyncEvent::Synced(res) => match res {
                    Ok(report) => {
                        self.status = SyncStatus::Synced(format_sync_report(&report));
                        self.refresh_managed_keys();
                        if !report.up_to_date
                            && let Ok(guard) = self.store.try_lock()
                            && let Ok(profiles) = guard.list_profiles()
                        {
                            actions.push(VaultUiAction::ReloadProfiles(profiles));
                        }
                        if !report.conflicts.is_empty() {
                            let names: Vec<&str> = report
                                .conflicts
                                .iter()
                                .map(|c| c.backup_name.as_str())
                                .collect();
                            actions.push(VaultUiAction::Notify {
                                text: format!(
                                    "Sync conflict resolved; backup(s) created: {}",
                                    names.join(", ")
                                ),
                                error: false,
                            });
                        }
                    }
                    Err(err) => {
                        self.status = SyncStatus::Error(err.clone());
                        actions.push(VaultUiAction::Notify {
                            text: format!("Vault sync error: {err}"),
                            error: true,
                        });
                    }
                },
                SyncEvent::HeaderPushed(res) => {
                    if let Err(err) = res {
                        actions.push(VaultUiAction::Notify {
                            text: format!(
                                "Updated local vault.json, but remote header push failed: {err}"
                            ),
                            error: true,
                        });
                    }
                }
            }
        }

        actions
    }

    /// Render the compact Vault & Sync status widget for the toolbar / status bar.
    pub fn toolbar_ui(&mut self, ui: &mut Ui) -> Vec<VaultUiAction> {
        let mut actions = Vec::new();
        if !self.enabled {
            if ui
                .button("🔒 Enable Vault")
                .on_hover_text("Initialize SM4-GCM encrypted vault & multi-device sync")
                .clicked()
            {
                self.open_onboarding(false);
            }
            return actions;
        }
        if !self.unlocked {
            if theme::primary_button(ui, "🔒 Unlock Vault").clicked() {
                self.modal = Some(VaultModal::LockScreen(LockScreenState::default()));
            }
            return actions;
        }

        // Sync status badge & quick controls.
        match &self.status {
            SyncStatus::Syncing(p) => {
                ui.spinner();
                ui.label(RichText::new(&p.stage).small().color(theme::DAWN_GOLD));
            }
            SyncStatus::Synced(summary) => {
                if ui.button("⟳ Sync").on_hover_text(summary).clicked() {
                    self.trigger_sync_now();
                }
            }
            SyncStatus::Error(err) => {
                if ui
                    .button(RichText::new("⚠ Sync Error").color(theme::DAWN_GOLD))
                    .on_hover_text(err)
                    .clicked()
                {
                    self.open_sync_settings();
                }
            }
            SyncStatus::Idle => {
                if ui.button("⟳ Sync").clicked() {
                    self.trigger_sync_now();
                }
            }
            SyncStatus::Disabled => {}
        }

        if ui
            .button("🔒 Lock")
            .on_hover_text("Lock vault and zeroize DEK in memory immediately")
            .clicked()
        {
            actions.push(self.lock_now());
        }
        actions
    }

    /// Render any active vault modal dialog.
    pub fn modal_ui(
        &mut self,
        ctx: &egui::Context,
        legacy_config: &Config,
        legacy_config_path: Option<&Path>,
        legacy_secrets: &dyn SecretStore,
        picker: &mut Picker,
    ) -> Vec<VaultUiAction> {
        let mut actions = Vec::new();
        let Some(mut modal) = self.modal.take() else {
            return actions;
        };

        let mut keep_open = true;
        let mut next_modal: Option<VaultModal> = None;

        match &mut modal {
            VaultModal::LockScreen(state) => {
                egui::Modal::new(egui::Id::unique("vault-lock-screen"))
                    .frame(theme::dialog_frame(ctx))
                    .show(ctx, |ui| {
                        ui.heading("🔒 Unlock Rooste Vault");
                        ui.add_space(6.0);
                        ui.label("Enter your master password to decrypt the local SM4-GCM vault.");
                        ui.add_space(6.0);
                        let edit = ui.add(
                            egui::TextEdit::singleline(&mut *state.password)
                                .id_salt("vault_lock_screen_password")
                                .password(true)
                                .hint_text("Master password")
                                .desired_width(theme::FIELD_WIDTH),
                        );
                        if state.needs_focus {
                            if edit.has_focus() {
                                state.needs_focus = false;
                            } else {
                                edit.request_focus();
                            }
                        }
                        disable_ime_for_password_field(ui, &edit, state.needs_focus);
                        let enter =
                            edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if let Some(ref err) = state.error {
                            ui.colored_label(ui.visuals().error_fg_color, err);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if theme::primary_button(ui, "Unlock").clicked() || enter {
                                match self.unlock_with_password(&state.password) {
                                    Ok(profiles) => {
                                        keep_open = false;
                                        actions.push(VaultUiAction::ReloadProfiles(profiles));
                                        self.trigger_sync_now();
                                    }
                                    Err(err) => {
                                        state.error = Some(err);
                                        state.needs_focus = true;
                                    }
                                }
                            }
                            if ui.button("Forgot Password (24-Word Recovery)…").clicked() {
                                next_modal = Some(VaultModal::ForgotPassword(
                                    ForgotPasswordState::default(),
                                ));
                            }
                            if ui.button("Reset & Re-sync…").clicked() {
                                next_modal =
                                    Some(VaultModal::ForceWipeConfirm(ForceWipeState::default()));
                            }
                        });
                    });
            }

            VaultModal::Onboarding(state) => {
                self.render_onboarding(
                    ctx,
                    state,
                    legacy_config,
                    legacy_config_path,
                    legacy_secrets,
                    &mut keep_open,
                    &mut next_modal,
                    &mut actions,
                );
            }

            VaultModal::RemoteRecovery(state) => {
                self.render_remote_recovery(ctx, state, &mut keep_open);
            }

            VaultModal::ForgotPassword(state) => {
                self.render_forgot_password(
                    ctx,
                    state,
                    &mut keep_open,
                    &mut next_modal,
                    &mut actions,
                );
            }

            VaultModal::ForceWipeConfirm(state) => {
                egui::Window::new("⚠ Reset Local Vault & Force Re-sync")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                    .frame(theme::dialog_frame(ctx))
                    .show(ctx, |ui| {
                        ui.colored_label(
                            theme::DAWN_GOLD,
                            "Warning: This discards all unpushed local changes, wipes local vault/ \
                             (temporarily backed up until recovery succeeds), and pulls a fresh \
                             snapshot from your remote backend using your 24-word mnemonic or master password.",
                        );
                        ui.add_space(8.0);
                        ui.label("Type RESET to confirm:");
                        ui.text_edit_singleline(&mut state.confirm_word);
                        if let Some(ref err) = state.error {
                            ui.colored_label(ui.visuals().error_fg_color, err);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                                if self.enabled && !self.unlocked {
                                    next_modal =
                                        Some(VaultModal::LockScreen(LockScreenState::default()));
                                }
                            }
                            let ready = state.confirm_word.trim() == "RESET";
                            ui.add_enabled_ui(ready, |ui| {
                                if theme::danger_button(ui, "Wipe & Re-sync from Remote").clicked()
                                {
                                    let form = self.current_sync_form();
                                    next_modal = Some(VaultModal::RemoteRecovery(
                                        RemoteRecoveryState::new(true, form),
                                    ));
                                }
                            });
                        });
                    });
            }

            VaultModal::SyncSettings(state) => {
                self.render_sync_settings(
                    ctx,
                    state,
                    &mut keep_open,
                    &mut next_modal,
                    &mut actions,
                );
            }

            VaultModal::KeysManager(state) => {
                self.render_keys_manager(
                    ctx,
                    state,
                    legacy_config,
                    picker,
                    &mut keep_open,
                    &mut actions,
                );
            }

            VaultModal::Rekey(state) => {
                self.render_rekey(ctx, state, &mut keep_open, &mut actions);
            }
        }

        if let Some(replacement) = next_modal {
            self.modal = Some(replacement);
        } else if keep_open {
            self.modal = Some(modal);
        }

        actions
    }

    // -------------------------------------------------------------------------
    // Internal UI Renderers & State Transitions
    // -------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn render_onboarding(
        &mut self,
        ctx: &egui::Context,
        state: &mut OnboardingState,
        legacy_config: &Config,
        legacy_config_path: Option<&Path>,
        legacy_secrets: &dyn SecretStore,
        keep_open: &mut bool,
        next_modal: &mut Option<VaultModal>,
        actions: &mut Vec<VaultUiAction>,
    ) {
        let title = if state.migrating_legacy {
            "🔒 Upgrade to Encrypted Vault (Legacy Migration)"
        } else {
            "🔒 Initialize Rooste Encrypted Vault"
        };
        let mut next_step: Option<OnboardingStep> = None;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| match &mut state.step {
                OnboardingStep::ChooseMode => {
                    ui.label("Choose how to set up your SM4-GCM end-to-end encrypted vault:");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if theme::primary_button(ui, "Create New Vault").clicked() {
                            next_step = Some(OnboardingStep::SetPassword);
                        }
                        if ui.button("Recover from Remote Cloud…").clicked() {
                            *next_modal = Some(VaultModal::RemoteRecovery(
                                RemoteRecoveryState::new(false, SyncFormState::default()),
                            ));
                        }
                        if ui.button("Cancel").clicked() {
                            *keep_open = false;
                        }
                    });
                }

                OnboardingStep::SetPassword => {
                    ui.label("Step 1/3: Set a strong Master Password (Argon2id + SM4-GCM).");
                    if state.migrating_legacy {
                        ui.label(
                            RichText::new(format!(
                                "Will migrate {} existing profile(s), deduplicate SSH keys, and back up config.toml.",
                                legacy_config.profiles.len()
                            ))
                            .small()
                            .color(theme::DAWN_GOLD),
                        );
                    }
                    ui.add_space(6.0);
                    ui.label("Master Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.password)
                            .password(true)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    let score = password_strength_score(&state.password);
                    let (label, color) = match score {
                        0 => ("", Color32::GRAY),
                        1 => ("Strength: Weak", Color32::from_rgb(220, 70, 70)),
                        2 => ("Strength: Fair", theme::DAWN_GOLD),
                        3 => ("Strength: Good", theme::TERMINAL_CYAN),
                        _ => ("Strength: Strong", Color32::from_rgb(80, 200, 120)),
                    };
                    if !label.is_empty() {
                        ui.colored_label(color, label);
                    }
                    ui.label("Confirm Master Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.confirm_password)
                            .password(true)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    if let Some(ref err) = state.error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            *keep_open = false;
                        }
                        if theme::primary_button(ui, "Generate 24-Word Mnemonic →").clicked() {
                            if state.password.len() < 8 {
                                state.error =
                                    Some("Master password must be at least 8 characters.".into());
                            } else if *state.password != *state.confirm_password {
                                state.error = Some("Master passwords do not match.".into());
                            } else {
                                match rooste_vault::generate_mnemonic() {
                                    Ok((_, mnemonic)) => {
                                        state.error = None;
                                        next_step = Some(OnboardingStep::ShowMnemonic {
                                            mnemonic,
                                            revealed: true,
                                            copied_at: None,
                                        });
                                    }
                                    Err(e) => state.error = Some(e.to_string()),
                                }
                            }
                        }
                    });
                }

                OnboardingStep::ShowMnemonic {
                    mnemonic,
                    revealed,
                    copied_at,
                } => {
                    ui.label(
                        "Step 2/3: Write down your 24-word BIP-39 Recovery Mnemonic offline.",
                    );
                    ui.colored_label(
                        theme::DAWN_GOLD,
                        "This is the ONLY way to recover your vault if you forget your master password.",
                    );
                    ui.add_space(8.0);
                    let words: Vec<&str> = mnemonic.split_whitespace().collect();
                    egui::Grid::new("mnemonic_4x6_grid")
                        .num_columns(4)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            for row in 0..6 {
                                for col in 0..4 {
                                    let idx = row * 4 + col;
                                    let word = words.get(idx).copied().unwrap_or("");
                                    let display = if *revealed {
                                        format!("{:>2}. {word}", idx + 1)
                                    } else {
                                        format!("{:>2}. ••••••", idx + 1)
                                    };
                                    ui.monospace(display);
                                }
                                ui.end_row();
                            }
                        });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let toggle = if *revealed { "Hide Words" } else { "Show Words" };
                        if ui.button(toggle).clicked() {
                            *revealed = !*revealed;
                        }
                        if ui.button("Copy (Auto-clears in 30s)").clicked() {
                            ctx.copy_text(mnemonic.as_str().to_owned());
                            *copied_at = Some(Instant::now());
                            self.clipboard_clear_at = Some(Instant::now() + Duration::from_secs(30));
                        }
                        if copied_at.is_some() {
                            ui.label(RichText::new("Copied!").small().color(theme::TERMINAL_CYAN));
                        }
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("← Back").clicked() {
                            next_step = Some(OnboardingStep::SetPassword);
                        }
                        if theme::primary_button(ui, "I Have Written It Down → Verify").clicked() {
                            let phrase = mnemonic.clone();
                            let quiz_indices = pick_three_quiz_indices();
                            next_step = Some(OnboardingStep::VerifyMnemonic {
                                mnemonic: phrase,
                                quiz_indices,
                                answers: Default::default(),
                            });
                        }
                    });
                }

                OnboardingStep::VerifyMnemonic {
                    mnemonic,
                    quiz_indices,
                    answers,
                } => {
                    ui.label("Step 3/3: Mandatory Backup Verification (cannot skip).");
                    ui.label("Enter the requested words from your 24-word mnemonic:");
                    ui.add_space(6.0);
                    let words: Vec<&str> = mnemonic.split_whitespace().collect();
                    egui::Grid::new("mnemonic_verify_grid")
                        .num_columns(2)
                        .spacing(theme::FORM_SPACING)
                        .show(ui, |ui| {
                            for (slot, &word_idx) in quiz_indices.iter().enumerate() {
                                ui.label(format!("Word #{}", word_idx + 1));
                                ui.add(
                                    egui::TextEdit::singleline(&mut answers[slot])
                                        .desired_width(180.0),
                                );
                                ui.end_row();
                            }
                        });
                    if let Some(ref err) = state.error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("← Review Words").clicked() {
                            let phrase = mnemonic.clone();
                            state.error = None;
                            next_step = Some(OnboardingStep::ShowMnemonic {
                                mnemonic: phrase,
                                revealed: true,
                                copied_at: None,
                            });
                        }
                        if theme::primary_button(ui, "Verify & Create Vault").clicked() {
                            let all_match = quiz_indices.iter().enumerate().all(|(slot, &idx)| {
                                words
                                    .get(idx)
                                    .is_some_and(|w| w.eq_ignore_ascii_case(answers[slot].trim()))
                            });
                            if !all_match {
                                state.error = Some(
                                    "One or more verification words do not match. Please double-check your backup."
                                        .into(),
                                );
                            } else {
                                match self.finalize_initialization(
                                    &state.password,
                                    mnemonic,
                                    state.migrating_legacy,
                                    legacy_config,
                                    legacy_config_path,
                                    legacy_secrets,
                                ) {
                                    Ok((profiles, warnings)) => {
                                        state.error = None;
                                        if state.migrating_legacy {
                                            actions.push(VaultUiAction::LegacyMigrated {
                                                profiles,
                                                warnings,
                                            });
                                        } else {
                                            actions.push(VaultUiAction::ReloadProfiles(profiles));
                                        }
                                        next_step = Some(OnboardingStep::OptionalSync);
                                    }
                                    Err(e) => state.error = Some(e),
                                }
                            }
                        }
                    });
                }

                OnboardingStep::OptionalSync => {
                    ui.label("Vault initialized & unlocked! Optionally configure cloud sync:");
                    ui.add_space(6.0);
                    render_sync_form_fields(ui, &mut state.sync_form);
                    if let Some(ref err) = state.error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Skip for Now").clicked() {
                            *keep_open = false;
                        }
                        if theme::primary_button(ui, "Save & Initial Sync").clicked() {
                            match self.save_sync_form(&state.sync_form) {
                                Ok(()) => {
                                    *keep_open = false;
                                    self.trigger_sync_now();
                                }
                                Err(e) => state.error = Some(e),
                            }
                        }
                    });
                }
            });
        if let Some(step) = next_step {
            state.step = step;
        }
    }

    fn render_remote_recovery(
        &mut self,
        ctx: &egui::Context,
        state: &mut RemoteRecoveryState,
        keep_open: &mut bool,
    ) {
        let title = if state.wipe_existing {
            "⟳ Wipe & Recover Vault from Remote"
        } else {
            "☁ Recover Existing Vault from Remote"
        };
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                if state.snapshot.is_none() {
                    ui.label("Step 1/2: Connect to your remote sync backend to fetch vault.json:");
                    ui.add_space(6.0);
                    render_sync_form_fields(ui, &mut state.sync_form);
                    if let Some(ref err) = state.error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            *keep_open = false;
                        }
                        ui.add_enabled_ui(!state.busy, |ui| {
                            if theme::primary_button(ui, "Connect & Inspect Remote").clicked() {
                                state.busy = true;
                                state.error = None;
                                let cfg = state.sync_form.to_sync_config(&SyncConfig::default());
                                let creds = state.sync_form.to_credentials();
                                self.actor
                                    .send(SyncCommand::InspectRemote { config: cfg, creds });
                            }
                        });
                        if state.busy {
                            ui.spinner();
                        }
                    });
                } else {
                    let vault_id = state
                        .snapshot
                        .as_ref()
                        .map(|s| s.header.vault_id.clone())
                        .unwrap_or_default();
                    ui.label(
                        RichText::new(format!("Remote Vault Detected: {vault_id}"))
                            .color(theme::TERMINAL_CYAN),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut state.use_mnemonic,
                            false,
                            "Unlock with Master Password",
                        );
                        ui.selectable_value(
                            &mut state.use_mnemonic,
                            true,
                            "Recover with 24-Word Mnemonic",
                        );
                    });
                    ui.add_space(6.0);
                    if !state.use_mnemonic {
                        ui.label("Master Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut *state.password)
                                .password(true)
                                .desired_width(theme::FIELD_WIDTH),
                        );
                    } else {
                        render_mnemonic_input_with_suggestions(ui, &mut state.mnemonic_input);
                        ui.add_space(4.0);
                        ui.label(
                            "Set New Master Password (optional; leave blank to keep current):",
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut *state.new_password)
                                .password(true)
                                .desired_width(theme::FIELD_WIDTH),
                        );
                        if !state.new_password.is_empty() {
                            ui.label("Confirm New Master Password:");
                            ui.add(
                                egui::TextEdit::singleline(&mut *state.confirm_new_password)
                                    .password(true)
                                    .desired_width(theme::FIELD_WIDTH),
                            );
                        }
                    }

                    if let Some(ref err) = state.error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("← Back").clicked() {
                            state.snapshot = None;
                            state.error = None;
                        }
                        ui.add_enabled_ui(!state.busy, |ui| {
                            if theme::primary_button(ui, "Decrypt & Pull Vault").clicked() {
                                let Some(snap) = state.snapshot.clone() else {
                                    return;
                                };
                                let dek_res = if state.use_mnemonic {
                                    snap.header.unlock_with_mnemonic(&state.mnemonic_input)
                                } else {
                                    snap.header.unlock_with_password(&state.password)
                                };
                                let new_pw = if state.use_mnemonic && !state.new_password.is_empty()
                                {
                                    if state.new_password.len() < 8 {
                                        state.error = Some(
                                            "New password must be at least 8 characters.".into(),
                                        );
                                        return;
                                    }
                                    if *state.new_password != *state.confirm_new_password {
                                        state.error = Some("New passwords do not match.".into());
                                        return;
                                    }
                                    Some(state.new_password.clone())
                                } else {
                                    None
                                };
                                match dek_res {
                                    Ok(dek) => {
                                        state.busy = true;
                                        state.error = None;
                                        let cfg =
                                            state.sync_form.to_sync_config(&SyncConfig::default());
                                        let creds = state.sync_form.to_credentials();
                                        self.actor.send(SyncCommand::RecoverFromRemote {
                                            config: cfg,
                                            creds,
                                            snapshot: Box::new(snap),
                                            dek,
                                            new_master_password: new_pw,
                                            wipe_existing: state.wipe_existing,
                                        });
                                    }
                                    Err(e) => state.error = Some(e.to_string()),
                                }
                            }
                        });
                        if state.busy {
                            ui.spinner();
                        }
                    });
                }
            });
    }

    fn render_forgot_password(
        &mut self,
        ctx: &egui::Context,
        state: &mut ForgotPasswordState,
        keep_open: &mut bool,
        next_modal: &mut Option<VaultModal>,
        actions: &mut Vec<VaultUiAction>,
    ) {
        egui::Window::new("🔑 Reset Master Password via 24-Word Mnemonic")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.label("Unlocks your DEK via recovery_slot and updates password_slot without re-encrypting data.");
                ui.add_space(6.0);
                render_mnemonic_input_with_suggestions(ui, &mut state.mnemonic_input);
                ui.add_space(6.0);
                ui.label("New Master Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *state.new_password)
                        .password(true)
                        .desired_width(theme::FIELD_WIDTH),
                );
                ui.label("Confirm New Master Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *state.confirm_password)
                        .password(true)
                        .desired_width(theme::FIELD_WIDTH),
                );
                if let Some(ref err) = state.error {
                    ui.colored_label(ui.visuals().error_fg_color, err);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        *next_modal = Some(VaultModal::LockScreen(LockScreenState::default()));
                    }
                    if theme::primary_button(ui, "Reset Password & Unlock").clicked() {
                        if state.new_password.len() < 8 {
                            state.error = Some("New password must be at least 8 characters.".into());
                        } else if *state.new_password != *state.confirm_password {
                            state.error = Some("New passwords do not match.".into());
                        } else {
                            match self.recover_and_reset_password(
                                &state.mnemonic_input,
                                &state.new_password,
                            ) {
                                Ok(profiles) => {
                                    *keep_open = false;
                                    actions.push(VaultUiAction::ReloadProfiles(profiles));
                                    actions.push(VaultUiAction::Notify {
                                        text: "Master password reset successfully via 24-word mnemonic."
                                            .into(),
                                        error: false,
                                    });
                                }
                                Err(e) => state.error = Some(e),
                            }
                        }
                    }
                });
            });
    }

    fn render_sync_settings(
        &mut self,
        ctx: &egui::Context,
        state: &mut SyncSettingsState,
        keep_open: &mut bool,
        next_modal: &mut Option<VaultModal>,
        actions: &mut Vec<VaultUiAction>,
    ) {
        egui::Window::new("☁ Vault Security & Sync Settings")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                render_sync_form_fields(ui, &mut state.form);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Auto-lock idle timeout (secs, 0=off):");
                    ui.add(egui::DragValue::new(&mut state.form.auto_lock_timeout_secs).range(0..=86400));
                });
                if let Some(ref res) = state.test_result {
                    match res {
                        Ok(msg) => ui.colored_label(Color32::from_rgb(80, 200, 120), msg),
                        Err(err) => ui.colored_label(ui.visuals().error_fg_color, err),
                    };
                }
                if let Some(ref err) = state.error {
                    ui.colored_label(ui.visuals().error_fg_color, err);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Test Connection").clicked() && !state.testing {
                        state.testing = true;
                        state.test_result = None;
                        let cfg = state.form.to_sync_config(&SyncConfig::default());
                        let creds = state.form.to_credentials();
                        self.actor
                            .send(SyncCommand::TestConnection { config: cfg, creds });
                    }
                    if state.testing {
                        ui.spinner();
                    }
                    if ui.button("Rotate DEK (Re-key Vault)…").clicked() {
                        *next_modal = Some(VaultModal::Rekey(RekeyState::default()));
                    }
                    if theme::danger_button(ui, "Wipe & Force Re-sync…").clicked() {
                        *next_modal = Some(VaultModal::ForceWipeConfirm(ForceWipeState::default()));
                    }
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Close").clicked() {
                        *keep_open = false;
                    }
                    if theme::primary_button(ui, "Save & Sync Now").clicked() {
                        match self.save_sync_form(&state.form) {
                            Ok(()) => {
                                *keep_open = false;
                                self.trigger_sync_now();
                                actions.push(VaultUiAction::Notify {
                                    text: "Sync settings saved to local.toml & encrypted local_secrets.enc."
                                        .into(),
                                    error: false,
                                });
                            }
                            Err(e) => state.error = Some(e),
                        }
                    }
                });
            });
    }

    fn render_keys_manager(
        &mut self,
        ctx: &egui::Context,
        state: &mut KeysManagerState,
        config: &Config,
        picker: &mut Picker,
        keep_open: &mut bool,
        actions: &mut Vec<VaultUiAction>,
    ) {
        let viewport = ctx.content_rect().size();
        let win_w = (viewport.x - 64.0).clamp(560.0, 840.0);
        let win_h = (viewport.y - 80.0).clamp(380.0, 520.0);

        let dark = ctx.global_style().visuals.dark_mode;
        let left_fill = if dark {
            Color32::from_rgb(18, 24, 36)
        } else {
            Color32::from_gray(236)
        };
        let right_fill = if dark {
            Color32::from_rgb(24, 30, 44)
        } else {
            Color32::WHITE
        };
        let border_color = if dark {
            Color32::from_rgb(56, 66, 86)
        } else {
            Color32::from_gray(200)
        };

        let modal_resp = egui::Modal::new(egui::Id::unique("vault-keys-manager"))
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.set_min_size(egui::vec2(win_w, win_h));
                ui.set_max_size(egui::vec2(win_w, win_h));

                // Title header bar.
                ui.horizontal(|ui| {
                    ui.heading("🔑 Managed SSH Keys (Vault)");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("×").on_hover_text("Close").clicked() {
                            *keep_open = false;
                        }
                    });
                });
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "First-class SSH key assets deduplicated by SHA-256 and synced end-to-end via SM4-GCM. Deleting a profile never deletes its key.",
                        )
                        .small()
                        .weak(),
                    )
                    .wrap(),
                );
                ui.add_space(8.0);

                let total_w = win_w;
                let left_w = (total_w * 0.30).clamp(200.0, 245.0);
                let divider_space = 16.0;
                let right_w = (total_w - left_w - divider_space).max(280.0);
                let body_h = (win_h - 102.0).max(220.0);

                ui.horizontal_top(|ui| {
                    // =========================================================
                    // LEFT PANE: Explicit Top-Down Recessed Sidebar
                    // =========================================================
                    ui.allocate_ui_with_layout(
                        egui::vec2(left_w, body_h),
                        egui::Layout::top_down(egui::Align::LEFT),
                        |ui| {
                            egui::Frame::NONE
                                .fill(left_fill)
                                .stroke(egui::Stroke::new(1.0, border_color))
                                .corner_radius(6.0)
                                .inner_margin(8.0)
                                .show(ui, |ui| {
                                    let inner_w = (left_w - 18.0).max(160.0);
                                    let inner_h = (body_h - 18.0).max(180.0);
                                    ui.set_min_size(egui::vec2(inner_w, inner_h));
                                    ui.set_max_size(egui::vec2(inner_w, inner_h));

                                    ui.horizontal(|ui| {
                                        let btn_w = (inner_w - 8.0) * 0.5;
                                        let import_selected = matches!(state.pane, KeysPane::Import);
                                        if ui
                                            .add_sized(
                                                [btn_w, 26.0],
                                                egui::Button::selectable(
                                                    import_selected,
                                                    "+ Import",
                                                ),
                                            )
                                            .on_hover_text(
                                                "Import an existing SSH key from disk or PEM",
                                            )
                                            .clicked()
                                        {
                                            state.pane = KeysPane::Import;
                                            state.discovered_keys = scan_local_ssh_dir();
                                            state.error = None;
                                            state.status = None;
                                        }
                                        let gen_selected = matches!(state.pane, KeysPane::Generate);
                                        if ui
                                            .add_sized(
                                                [btn_w, 26.0],
                                                egui::Button::selectable(
                                                    gen_selected,
                                                    "+ Generate",
                                                ),
                                            )
                                            .on_hover_text(
                                                "Generate a new SSH key pair inside the vault",
                                            )
                                            .clicked()
                                        {
                                            state.pane = KeysPane::Generate;
                                            state.error = None;
                                            state.status = None;
                                        }
                                    });
                                    ui.add_space(6.0);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut state.search_query)
                                            .hint_text("Filter keys…")
                                            .desired_width(inner_w),
                                    );
                                    ui.add_space(6.0);
                                    ui.separator();

                                    let query = state.search_query.trim().to_ascii_lowercase();
                                    let keys_snapshot = self.managed_keys.clone();
                                    egui::ScrollArea::vertical()
                                        .id_salt("vault_keys_list_scroll")
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            if keys_snapshot.is_empty() {
                                                ui.add_space(12.0);
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new("No SSH keys in vault yet.")
                                                            .weak(),
                                                    )
                                                    .wrap(),
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(
                                                            "Use \"+ Import\" or \"+ Generate\" above.",
                                                        )
                                                        .small()
                                                        .weak(),
                                                    )
                                                    .wrap(),
                                                );
                                                return;
                                            }
                                            let mut any_shown = false;
                                            for key in &keys_snapshot {
                                                if !query.is_empty()
                                                    && !key
                                                        .label
                                                        .to_ascii_lowercase()
                                                        .contains(&query)
                                                    && !key
                                                        .fingerprint
                                                        .to_ascii_lowercase()
                                                        .contains(&query)
                                                    && !key
                                                        .sha256
                                                        .to_ascii_lowercase()
                                                        .contains(&query)
                                                {
                                                    continue;
                                                }
                                                any_shown = true;
                                                let is_selected = matches!(
                                                    &state.pane,
                                                    KeysPane::Detail(sha) if sha == &key.sha256
                                                );
                                                let ref_count = config
                                                    .profiles
                                                    .iter()
                                                    .filter(|p| {
                                                        p.key_sha256.as_deref()
                                                            == Some(key.sha256.as_str())
                                                    })
                                                    .count();
                                                let fp_short = if key.fingerprint.is_empty() {
                                                    format!(
                                                        "sha:{}",
                                                        &key.sha256[..10.min(key.sha256.len())]
                                                    )
                                                } else {
                                                    let max = 16.min(key.fingerprint.len());
                                                    format!("{}…", &key.fingerprint[..max])
                                                };
                                                let badge = if key.require_passphrase_prompt {
                                                    " 🔒"
                                                } else {
                                                    ""
                                                };
                                                let title = format!(
                                                    "{}{badge}\n{fp_short} · {ref_count}x",
                                                    key.label
                                                );
                                                let resp = ui.add_sized(
                                                    [ui.available_width(), 42.0],
                                                    egui::Button::selectable(is_selected, title),
                                                );
                                                if resp.clicked() {
                                                    state.select_detail(key.sha256.clone());
                                                }
                                            }
                                            if !any_shown {
                                                ui.weak("No keys match your filter.");
                                            }
                                        });
                                });
                        },
                    );

                    // Explicit vertical divider separating Key List and Work Area.
                    let (sep_rect, _) =
                        ui.allocate_exact_size(egui::vec2(8.0, body_h), egui::Sense::hover());
                    ui.painter().vline(
                        sep_rect.center().x,
                        sep_rect.y_range(),
                        egui::Stroke::new(1.5, border_color),
                    );

                    // =========================================================
                    // RIGHT PANE: Explicit Top-Down Framed Work Area
                    // =========================================================
                    ui.allocate_ui_with_layout(
                        egui::vec2(right_w, body_h),
                        egui::Layout::top_down(egui::Align::LEFT),
                        |ui| {
                            egui::Frame::NONE
                                .fill(right_fill)
                                .stroke(egui::Stroke::new(1.0, border_color))
                                .corner_radius(6.0)
                                .inner_margin(12.0)
                                .show(ui, |ui| {
                                    let inner_w = (right_w - 26.0).max(240.0);
                                    let inner_h = (body_h - 26.0).max(180.0);
                                    ui.set_min_size(egui::vec2(inner_w, inner_h));
                                    ui.set_max_size(egui::vec2(inner_w, inner_h));

                                    match state.pane.clone() {
                                        KeysPane::Detail(sha) => {
                                            let footer_h = if state.pending_delete_sha.as_deref()
                                                == Some(sha.as_str())
                                                || state.pending_export_private_sha.as_deref()
                                                    == Some(sha.as_str())
                                            {
                                                64.0
                                            } else {
                                                38.0
                                            };
                                            let scroll_h = (inner_h - footer_h).max(120.0);
                                            egui::ScrollArea::vertical()
                                                .id_salt("vault_keys_detail_scroll")
                                                .max_height(scroll_h)
                                                .auto_shrink([false, false])
                                                .show(ui, |ui| {
                                                    ui.set_width(ui.available_width());
                                                    self.render_key_detail_pane(
                                                        ui, ctx, state, &sha, config, picker,
                                                    );
                                                });
                                            self.render_key_detail_footer(
                                                ui, ctx, state, &sha, config, picker, actions,
                                            );
                                        }
                                        KeysPane::Import => {
                                            egui::ScrollArea::vertical()
                                                .id_salt("vault_keys_import_scroll")
                                                .auto_shrink([false, false])
                                                .show(ui, |ui| {
                                                    ui.set_width(ui.available_width());
                                                    self.render_key_import_pane(ui, state, picker);
                                                });
                                        }
                                        KeysPane::Generate => {
                                            egui::ScrollArea::vertical()
                                                .id_salt("vault_keys_generate_scroll")
                                                .auto_shrink([false, false])
                                                .show(ui, |ui| {
                                                    ui.set_width(ui.available_width());
                                                    self.render_key_generate_pane(
                                                        ui, state, actions,
                                                    );
                                                });
                                        }
                                    }
                                });
                        },
                    );
                });

                ui.add_space(6.0);
                ui.separator();
                ui.horizontal(|ui| {
                    let close_reserve = 76.0;
                    let msg_w = (win_w - close_reserve).max(120.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(msg_w, 24.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            if let Some(ref err) = state.error {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(err).color(ui.visuals().error_fg_color),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(err);
                            } else if let Some(ref msg) = state.status {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(msg).color(Color32::from_rgb(80, 200, 120)),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(msg);
                            }
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Close").clicked() {
                            *keep_open = false;
                        }
                    });
                });
            });

        if modal_resp.should_close() {
            *keep_open = false;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn render_key_detail_pane(
        &mut self,
        ui: &mut Ui,
        ctx: &egui::Context,
        state: &mut KeysManagerState,
        sha: &str,
        config: &Config,
        picker: &mut Picker,
    ) {
        let Some(summary) = self.managed_keys.iter().find(|k| k.sha256 == sha).cloned() else {
            state.pane = KeysPane::Import;
            return;
        };

        // Sync editable detail fields whenever selection changes.
        if state.detail_loaded_sha.as_deref() != Some(sha) {
            state.detail_loaded_sha = Some(sha.to_owned());
            state.detail_label = summary.label.clone();
            state.detail_require_prompt = summary.require_passphrase_prompt;
            state.detail_new_passphrase.clear();
            state.detail_confirm_passphrase.clear();
            state.detail_copied_pub = false;
            state.detail_copied_fp = false;
            state.pending_delete_sha = None;
            state.pending_export_private_sha = None;
            state.export_private_authorized_sha = None;
            state.export_vault_password.clear();
        }

        // Handle pending export file dialog results.
        if let Some(export_path) = picker.take(PickId::VaultKeyExportPublic) {
            if summary.public_key.is_empty() {
                state.error = Some("No OpenSSH public key available for this entry.".into());
            } else {
                match std::fs::write(&export_path, format!("{}\n", summary.public_key)) {
                    Ok(()) => {
                        state.error = None;
                        state.status =
                            Some(format!("Exported public key to {}", export_path.display()));
                    }
                    Err(e) => state.error = Some(format!("Failed to export .pub: {e}")),
                }
            }
        }
        if let Some(export_path) = picker.take(PickId::VaultKeyExportPrivate) {
            if state.export_private_authorized_sha.take().as_deref() != Some(sha) {
                state.error = Some(
                    "Vault master password verification required before exporting private key."
                        .into(),
                );
            } else if let Some(full_key) = self.load_ssh_key(sha) {
                match rooste_keys::write_private(&export_path, full_key.private_key_pem.as_bytes())
                {
                    Ok(()) => {
                        state.error = None;
                        state.status = Some(format!(
                            "Exported private key (0600) to {}",
                            export_path.display()
                        ));
                    }
                    Err(e) => state.error = Some(format!("Failed to export private key: {e}")),
                }
            } else {
                state.error = Some("Could not decrypt key for export.".into());
            }
        }

        ui.heading(&summary.label);
        ui.add_space(4.0);

        // Label rename row.
        ui.horizontal(|ui| {
            ui.label("Label:");
            ui.add(
                egui::TextEdit::singleline(&mut state.detail_label)
                    .margin(theme::FIELD_MARGIN)
                    .desired_width(200.0),
            );
            let changed =
                state.detail_label.trim() != summary.label && !state.detail_label.trim().is_empty();
            if ui
                .add_enabled(changed, egui::Button::new("Rename"))
                .clicked()
            {
                match self.update_managed_key_meta(
                    sha,
                    Some(state.detail_label.trim().to_owned()),
                    None,
                    None,
                ) {
                    Ok(()) => {
                        state.error = None;
                        state.status = Some("Key renamed.".into());
                    }
                    Err(e) => state.error = Some(e),
                }
            }
        });
        ui.add_space(4.0);

        // Metadata info.
        egui::Grid::new("key_detail_meta_grid")
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                ui.weak("Fingerprint:");
                ui.horizontal(|ui| {
                    let fp_text = if summary.fingerprint.is_empty() {
                        "(unavailable)"
                    } else {
                        summary.fingerprint.as_str()
                    };
                    let copy_reserve = if summary.fingerprint.is_empty() {
                        0.0
                    } else {
                        96.0
                    };
                    let max_fp_w = (ui.available_width() - copy_reserve).max(120.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(max_fp_w, 18.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add(egui::Label::new(RichText::new(fp_text).monospace()).truncate())
                                .on_hover_text(fp_text);
                        },
                    );
                    if !summary.fingerprint.is_empty() && ui.small_button("Copy").clicked() {
                        ctx.copy_text(summary.fingerprint.clone());
                        state.detail_copied_fp = true;
                    }
                    if state.detail_copied_fp {
                        ui.label(RichText::new("Copied").small().color(theme::TERMINAL_CYAN));
                    }
                });
                ui.end_row();

                ui.weak("Vault SHA-256:");
                ui.add(
                    egui::Label::new(
                        RichText::new(&summary.sha256[..24.min(summary.sha256.len())]).monospace(),
                    )
                    .truncate(),
                )
                .on_hover_text(&summary.sha256);
                ui.end_row();

                ui.weak("Used by:");
                let used_by: Vec<String> = config
                    .profiles
                    .iter()
                    .filter(|p| p.key_sha256.as_deref() == Some(sha))
                    .map(|p| p.display_name())
                    .collect();
                if used_by.is_empty() {
                    ui.add(
                        egui::Label::new(
                            RichText::new("Independent key (not linked to any session yet)").weak(),
                        )
                        .wrap(),
                    );
                } else {
                    ui.add(egui::Label::new(used_by.join(", ")).wrap());
                }
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.strong("Public Key (OpenSSH authorized_keys)");
        if summary.public_key.is_empty() {
            ui.weak("Public key line unavailable (legacy PEM format).");
        } else {
            let mut pub_preview = summary.public_key.clone();
            egui::ScrollArea::vertical()
                .id_salt("vault_pubkey_preview_scroll")
                .max_height(68.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut pub_preview)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if theme::primary_button(ui, "📋 Copy Public Key").clicked() {
                    ctx.copy_text(summary.public_key.clone());
                    state.detail_copied_pub = true;
                }
                if ui.button("💾 Export .pub…").clicked() {
                    let default_name = format!("{}.pub", summary.label);
                    picker.open(
                        ctx,
                        PickId::VaultKeyExportPublic,
                        PickKind::SaveFile,
                        &default_name,
                    );
                }
                if state.detail_copied_pub {
                    ui.label(
                        RichText::new("Copied to clipboard!")
                            .small()
                            .color(theme::TERMINAL_CYAN),
                    );
                }
            });
        }

        ui.add_space(8.0);
        ui.separator();
        ui.strong("Passphrase & Connection Security");
        ui.checkbox(
            &mut state.detail_require_prompt,
            "Prompt for passphrase on every SSH connection (high-security)",
        );
        if !state.detail_require_prompt {
            let pw_status = if summary.has_saved_passphrase {
                "Stored passphrase: configured (encrypted in vault)"
            } else {
                "Stored passphrase: none"
            };
            ui.label(RichText::new(pw_status).small());
            egui::Grid::new("key_detail_pass_grid")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Set/Update Passphrase:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.detail_new_passphrase)
                            .password(true)
                            .hint_text("Leave blank to keep unchanged")
                            .desired_width(200.0),
                    );
                    ui.end_row();
                    if !state.detail_new_passphrase.is_empty() {
                        ui.label("Confirm Passphrase:");
                        ui.add(
                            egui::TextEdit::singleline(&mut *state.detail_confirm_passphrase)
                                .password(true)
                                .desired_width(200.0),
                        );
                        ui.end_row();
                    }
                });
        }
        ui.horizontal(|ui| {
            if ui.button("Save Security Settings").clicked() {
                if !state.detail_require_prompt
                    && !state.detail_new_passphrase.is_empty()
                    && *state.detail_new_passphrase != *state.detail_confirm_passphrase
                {
                    state.error = Some("Passphrase confirmation does not match.".into());
                } else {
                    let pass_update = if state.detail_require_prompt {
                        Some(None)
                    } else if !state.detail_new_passphrase.is_empty() {
                        Some(Some(state.detail_new_passphrase.as_str().to_owned()))
                    } else {
                        None
                    };
                    match self.update_managed_key_meta(
                        sha,
                        None,
                        Some(state.detail_require_prompt),
                        pass_update,
                    ) {
                        Ok(()) => {
                            state.detail_new_passphrase.clear();
                            state.detail_confirm_passphrase.clear();
                            state.error = None;
                            state.status = Some("Key security settings updated.".into());
                        }
                        Err(e) => state.error = Some(e),
                    }
                }
            }
            if summary.has_saved_passphrase
                && !state.detail_require_prompt
                && ui.button("Clear Stored Passphrase").clicked()
            {
                match self.update_managed_key_meta(sha, None, None, Some(None)) {
                    Ok(()) => {
                        state.error = None;
                        state.status = Some("Stored passphrase cleared.".into());
                    }
                    Err(e) => state.error = Some(e),
                }
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn render_key_detail_footer(
        &mut self,
        ui: &mut Ui,
        ctx: &egui::Context,
        state: &mut KeysManagerState,
        sha: &str,
        config: &Config,
        picker: &mut Picker,
        actions: &mut Vec<VaultUiAction>,
    ) {
        let Some(summary) = self.managed_keys.iter().find(|k| k.sha256 == sha).cloned() else {
            return;
        };

        ui.add_space(4.0);
        ui.separator();
        ui.add_space(2.0);
        if state.pending_delete_sha.as_deref() == Some(sha) {
            let affected: Vec<String> = config
                .profiles
                .iter()
                .filter(|p| p.key_sha256.as_deref() == Some(sha))
                .map(|p| p.display_name())
                .collect();
            ui.colored_label(
                theme::DAWN_GOLD,
                if affected.is_empty() {
                    format!("Permanently delete managed key \"{}\"?", summary.label)
                } else {
                    format!(
                        "Warning: \"{}\" is used by [{}]. Delete anyway?",
                        summary.label,
                        affected.join(", ")
                    )
                },
            );
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    state.pending_delete_sha = None;
                }
                if theme::danger_button(ui, "Confirm Delete Key").clicked() {
                    let del_res = self
                        .store
                        .try_lock()
                        .map_err(|_| "Vault store busy".to_owned())
                        .and_then(|mut guard| guard.delete_ssh_key(sha).map_err(|e| e.to_string()));
                    match del_res {
                        Ok(()) => {
                            state.pending_delete_sha = None;
                            state.detail_loaded_sha = None;
                            self.refresh_managed_keys();
                            state.pane = self
                                .managed_keys
                                .first()
                                .map(|k| KeysPane::Detail(k.sha256.clone()))
                                .unwrap_or(KeysPane::Import);
                            actions.push(VaultUiAction::Notify {
                                text: format!("Deleted managed SSH key \"{}\".", summary.label),
                                error: false,
                            });
                        }
                        Err(e) => state.error = Some(e),
                    }
                }
            });
        } else if state.pending_export_private_sha.as_deref() == Some(sha) {
            ui.colored_label(
                theme::DAWN_GOLD,
                "Verify vault master password to export private key:",
            );
            ui.horizontal(|ui| {
                let pw_resp = ui.add(
                    egui::TextEdit::singleline(&mut *state.export_vault_password)
                        .id_salt("vault_export_priv_pw")
                        .password(true)
                        .hint_text("Vault master password")
                        .desired_width(220.0),
                );
                let enter_submit = pw_resp.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    && !state.export_vault_password.is_empty();
                if ui.button("Cancel").clicked() {
                    state.pending_export_private_sha = None;
                    state.export_vault_password.clear();
                    state.error = None;
                }
                let can_submit = !state.export_vault_password.is_empty();
                let clicked = ui
                    .add_enabled(can_submit, egui::Button::new("🔒 Verify & Export…"))
                    .clicked();
                if clicked || enter_submit {
                    let verify_res =
                        self.verify_master_password(state.export_vault_password.as_str());
                    state.export_vault_password.clear();
                    match verify_res {
                        Ok(()) => {
                            state.pending_export_private_sha = None;
                            state.export_private_authorized_sha = Some(sha.to_owned());
                            state.error = None;
                            picker.open(
                                ctx,
                                PickId::VaultKeyExportPrivate,
                                PickKind::SaveFile,
                                &summary.label,
                            );
                        }
                        Err(e) => {
                            state.error = Some(e);
                        }
                    }
                }
            });
        } else {
            ui.horizontal(|ui| {
                if ui.button("💾 Export Private Key…").clicked() {
                    state.pending_delete_sha = None;
                    state.pending_export_private_sha = Some(sha.to_owned());
                    state.export_private_authorized_sha = None;
                    state.export_vault_password.clear();
                    state.error = None;
                    state.status = None;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::danger_button(ui, "🗑 Delete Key").clicked() {
                        state.pending_export_private_sha = None;
                        state.export_vault_password.clear();
                        state.pending_delete_sha = Some(sha.to_owned());
                    }
                });
            });
        }
    }

    fn render_key_import_pane(
        &mut self,
        ui: &mut Ui,
        state: &mut KeysManagerState,
        picker: &mut Picker,
    ) {
        ui.heading("Import SSH Key into Vault");
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.selectable_value(&mut state.import_tab, ImportSourceTab::File, "📁 From File");
            ui.selectable_value(
                &mut state.import_tab,
                ImportSourceTab::DiscoverSshDir,
                format!("🔍 Discover ~/.ssh ({})", state.discovered_keys.len()),
            );
            ui.selectable_value(
                &mut state.import_tab,
                ImportSourceTab::PastePem,
                "📋 Paste PEM",
            );
        });
        ui.add_space(6.0);

        match state.import_tab {
            ImportSourceTab::File => {
                ui.label("Key file:");
                let row_w = ui.available_width();
                ui.allocate_ui_with_layout(
                    egui::vec2(row_w, ui.spacing().interact_size.y),
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        let picked = picker.button(
                            ui,
                            PickId::VaultKeyImport,
                            PickKind::OpenFile,
                            &state.import_path,
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut state.import_path)
                                .margin(theme::FIELD_MARGIN)
                                .hint_text("~/.ssh/id_ed25519 or click Browse…")
                                .desired_width(f32::INFINITY),
                        );
                        if let Some(path) = picked {
                            state.import_path = path.display().to_string();
                        }
                    },
                );
                // Auto-inspect file whenever the path changes (including after Browse… returns).
                let trimmed = state.import_path.trim().to_owned();
                if trimmed != state.import_inspected_source {
                    state.import_inspected_source = trimmed.clone();
                    if trimmed.is_empty() {
                        state.import_inspection = None;
                    } else {
                        let expanded = rooste_core::expand_tilde(&trimmed);
                        if state.import_label.trim().is_empty()
                            && let Some(fname) = expanded.file_name().and_then(|n| n.to_str())
                        {
                            state.import_label = fname.to_owned();
                        }
                        state.import_inspection = Some(match std::fs::read_to_string(&expanded) {
                            Ok(text) => {
                                rooste_keys::inspect_key_text(&text).map_err(|e| e.to_string())
                            }
                            Err(e) => Err(format!("Cannot read file: {e}")),
                        });
                    }
                }
            }
            ImportSourceTab::DiscoverSshDir => {
                ui.horizontal(|ui| {
                    ui.weak("Local private keys found in ~/.ssh:");
                    if ui.small_button("⟳ Rescan").clicked() {
                        state.discovered_keys = scan_local_ssh_dir();
                    }
                });
                ui.add_space(4.0);
                if state.discovered_keys.is_empty() {
                    ui.weak(
                        "No private keys detected in ~/.ssh. Use \"From File\" → Browse… instead.",
                    );
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt("discovered_ssh_keys_scroll")
                        .max_height(130.0)
                        .show(ui, |ui| {
                            for item in state.discovered_keys.clone() {
                                let already = self
                                    .managed_keys
                                    .iter()
                                    .any(|k| k.sha256 == item.sha256_preview);
                                ui.horizontal(|ui| {
                                    ui.strong(&item.file_name);
                                    ui.weak(&item.algorithm);
                                    if item.is_encrypted {
                                        ui.colored_label(theme::DAWN_GOLD, "🔒 encrypted");
                                    }
                                    if already {
                                        ui.colored_label(
                                            Color32::from_rgb(80, 200, 120),
                                            "✓ In Vault",
                                        );
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.button("Select").clicked() {
                                                state.import_path = item.path.display().to_string();
                                                state.import_label = item.file_name.clone();
                                                state.import_inspected_source.clear();
                                                state.import_tab = ImportSourceTab::File;
                                                state.error = None;
                                            }
                                        },
                                    );
                                });
                            }
                        });
                }
            }
            ImportSourceTab::PastePem => {
                ui.label("Paste OpenSSH private key PEM or PuTTY .ppk text:");
                ui.add(
                    egui::TextEdit::multiline(&mut *state.import_pem)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(5)
                        .desired_width(f32::INFINITY),
                );
                let marker = format!("pem:{}", state.import_pem.len());
                if marker != state.import_inspected_source {
                    state.import_inspected_source = marker;
                    if state.import_pem.trim().is_empty() {
                        state.import_inspection = None;
                    } else {
                        state.import_inspection = Some(
                            rooste_keys::inspect_key_text(state.import_pem.as_str())
                                .map_err(|e| e.to_string()),
                        );
                    }
                }
            }
        }

        // Live validation badge.
        let source_is_encrypted = match &state.import_inspection {
            Some(Ok(info)) => {
                let kind_note = if info.is_ppk {
                    " (will convert .ppk → OpenSSH PEM)"
                } else if info.needs_normalization {
                    " (will normalize PEM → OpenSSH)"
                } else {
                    ""
                };
                if info.is_encrypted {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "🔒 Encrypted {} key detected{kind_note} — enter its passphrase to verify & import.",
                                info.algorithm
                            ))
                            .color(theme::DAWN_GOLD),
                        )
                        .wrap(),
                    );
                } else {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "✔ Valid {} key{kind_note}\n{}",
                                info.algorithm, info.fingerprint
                            ))
                            .color(Color32::from_rgb(80, 200, 120)),
                        )
                        .wrap(),
                    );
                }
                info.is_encrypted
            }
            Some(Err(msg)) => {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("✖ {msg}")).color(ui.visuals().error_fg_color),
                    )
                    .wrap(),
                );
                false
            }
            None => false,
        };

        ui.add_space(6.0);
        egui::Grid::new("vault_key_import_meta_grid")
            .num_columns(2)
            .spacing(theme::FORM_SPACING)
            .show(ui, |ui| {
                ui.label("Label:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.import_label)
                        .hint_text("e.g. prod-ed25519")
                        .desired_width(240.0),
                );
                ui.end_row();

                let pass_label = if source_is_encrypted {
                    "Key Passphrase:"
                } else {
                    "Protect w/ Passphrase (optional):"
                };
                ui.label(pass_label);
                ui.add(
                    egui::TextEdit::singleline(&mut *state.import_passphrase)
                        .password(true)
                        .desired_width(240.0),
                );
                ui.end_row();

                if !state.import_passphrase.is_empty() {
                    ui.label("Confirm Passphrase:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.import_confirm_passphrase)
                            .password(true)
                            .desired_width(240.0),
                    );
                    ui.end_row();
                }
            });

        ui.checkbox(
            &mut state.import_require_prompt,
            "Prompt for passphrase on every SSH connection (do not store passphrase in vault)",
        );
        ui.add_space(8.0);
        if theme::primary_button(ui, "Import & Deduplicate into Vault").clicked() {
            match self.handle_import_key(state) {
                Ok((sha, dedup)) => {
                    state.error = None;
                    state.status = Some(if dedup {
                        format!(
                            "Reused existing vault key ({}…).",
                            &sha[..12.min(sha.len())]
                        )
                    } else {
                        format!("Imported new vault key ({}…).", &sha[..12.min(sha.len())])
                    });
                    state.import_pem.clear();
                    state.import_path.clear();
                    state.import_label.clear();
                    state.import_inspected_source.clear();
                    state.import_inspection = None;
                    state.import_passphrase.clear();
                    state.import_confirm_passphrase.clear();
                    self.refresh_managed_keys();
                    state.select_detail(sha);
                }
                Err(e) => state.error = Some(e),
            }
        }
    }

    fn render_key_generate_pane(
        &mut self,
        ui: &mut Ui,
        state: &mut KeysManagerState,
        actions: &mut Vec<VaultUiAction>,
    ) {
        ui.heading("Generate New SSH Key in Vault");
        ui.label(
            RichText::new(
                "Generates a fresh key pair directly inside the SM4-GCM vault (never touches unencrypted disk).",
            )
            .small(),
        );
        ui.add_space(8.0);

        egui::Grid::new("vault_key_gen_grid")
            .num_columns(2)
            .spacing(theme::FORM_SPACING)
            .show(ui, |ui| {
                ui.label("Label:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.gen_label)
                        .hint_text("e.g. prod-ed25519")
                        .desired_width(240.0),
                );
                ui.end_row();

                ui.label("Key Type:");
                egui::ComboBox::from_id_salt("vault_key_gen_type")
                    .selected_text(state.gen_type.label())
                    .show_ui(ui, |ui| {
                        for kind in KeyType::ALL {
                            ui.selectable_value(&mut state.gen_type, kind, kind.label());
                        }
                    });
                ui.end_row();

                ui.label("Comment:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.gen_comment)
                        .hint_text("user@host")
                        .desired_width(240.0),
                );
                ui.end_row();

                ui.label("Passphrase (optional):");
                ui.add(
                    egui::TextEdit::singleline(&mut *state.gen_passphrase)
                        .password(true)
                        .desired_width(240.0),
                );
                ui.end_row();

                if !state.gen_passphrase.is_empty() {
                    ui.label("Confirm Passphrase:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.gen_confirm_passphrase)
                            .password(true)
                            .desired_width(240.0),
                    );
                    ui.end_row();
                }
            });

        ui.checkbox(
            &mut state.gen_require_prompt,
            "Prompt for passphrase on every SSH connection (high-security)",
        );
        ui.add_space(8.0);
        if theme::primary_button(ui, "✨ Generate & Save to Vault").clicked() {
            match self.handle_generate_key(state) {
                Ok(sha) => {
                    state.error = None;
                    state.status = Some(
                        "New SSH key generated & saved to vault! Copy its public key on the right."
                            .into(),
                    );
                    state.gen_passphrase.clear();
                    state.gen_confirm_passphrase.clear();
                    self.refresh_managed_keys();
                    state.select_detail(sha);
                    actions.push(VaultUiAction::Notify {
                        text: "Generated new managed SSH key in encrypted vault.".into(),
                        error: false,
                    });
                }
                Err(e) => state.error = Some(e),
            }
        }
    }

    fn render_rekey(
        &mut self,
        ctx: &egui::Context,
        state: &mut RekeyState,
        keep_open: &mut bool,
        actions: &mut Vec<VaultUiAction>,
    ) {
        egui::Window::new("🔄 Rotate Vault DEK & Mnemonic (Re-key)")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                if let Some(ref mnemonic) = state.new_mnemonic {
                    ui.colored_label(
                        theme::DAWN_GOLD,
                        "Vault re-encrypted with a brand-new DEK! Write down your NEW 24-word mnemonic now:",
                    );
                    let words: Vec<&str> = mnemonic.split_whitespace().collect();
                    egui::Grid::new("rekey_mnemonic_grid")
                        .num_columns(4)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            for row in 0..6 {
                                for col in 0..4 {
                                    let idx = row * 4 + col;
                                    ui.monospace(format!(
                                        "{:>2}. {}",
                                        idx + 1,
                                        words.get(idx).copied().unwrap_or("")
                                    ));
                                }
                                ui.end_row();
                            }
                        });
                    ui.add_space(6.0);
                    if ui.button("Copy New Mnemonic (30s auto-clear)").clicked() {
                        ctx.copy_text(mnemonic.as_str().to_owned());
                        self.clipboard_clear_at = Some(Instant::now() + Duration::from_secs(30));
                    }
                    ui.add_space(6.0);
                    if theme::primary_button(ui, "Done & Sync Rotated Vault").clicked() {
                        *keep_open = false;
                        self.trigger_sync_now();
                    }
                } else {
                    ui.label(
                        "Generates a brand-new SM4 DEK & 24-word mnemonic, re-encrypting every record and invalidating old keys.",
                    );
                    ui.label("New Master Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.new_password)
                            .password(true)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.label("Confirm New Master Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *state.confirm_password)
                            .password(true)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    if let Some(ref err) = state.error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            *keep_open = false;
                        }
                        if theme::danger_button(ui, "Rotate Keys Now").clicked() {
                            if state.new_password.len() < 8 {
                                state.error = Some("Password must be at least 8 characters.".into());
                            } else if *state.new_password != *state.confirm_password {
                                state.error = Some("Passwords do not match.".into());
                            } else if let Ok(mut guard) = self.store.try_lock() {
                                match guard.rekey(&state.new_password) {
                                    Ok(init) => {
                                        state.new_mnemonic = Some(init.mnemonic);
                                        state.error = None;
                                        actions.push(VaultUiAction::Notify {
                                            text: "Vault DEK rotated and all records re-encrypted."
                                                .into(),
                                            error: false,
                                        });
                                    }
                                    Err(e) => state.error = Some(e.to_string()),
                                }
                            }
                        }
                    });
                }
            });
    }

    fn unlock_with_password(&mut self, password: &str) -> Result<Vec<Profile>, String> {
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        guard
            .unlock_with_password(password)
            .map_err(|e| e.to_string())?;
        let profiles = guard.list_profiles().map_err(|e| e.to_string())?;
        self.auto_lock_timeout_secs = guard.local_config().auto_lock_timeout_secs;
        self.auto_sync_interval_secs = guard.local_config().sync.auto_sync_interval_secs;
        self.sync_enabled = guard.local_config().sync.enabled
            && guard.local_config().sync.backend != SyncBackendKind::None;
        drop(guard);
        self.unlocked = true;
        self.last_activity = Instant::now();
        self.refresh_managed_keys();
        Ok(profiles)
    }

    fn recover_and_reset_password(
        &mut self,
        mnemonic: &str,
        new_password: &str,
    ) -> Result<Vec<Profile>, String> {
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        guard
            .unlock_with_mnemonic(mnemonic)
            .map_err(|e| e.to_string())?;
        guard
            .reset_master_password(new_password)
            .map_err(|e| e.to_string())?;
        let profiles = guard.list_profiles().map_err(|e| e.to_string())?;
        let cfg = guard.local_config().sync.clone();
        let creds = guard.load_local_credentials().ok().flatten();
        drop(guard);

        self.unlocked = true;
        self.last_activity = Instant::now();
        self.refresh_managed_keys();
        if cfg.enabled
            && cfg.backend != SyncBackendKind::None
            && let Some(creds) = creds
        {
            self.actor
                .send(SyncCommand::PushHeader { config: cfg, creds });
        }
        Ok(profiles)
    }

    fn finalize_initialization(
        &mut self,
        password: &str,
        verified_mnemonic: &str,
        migrating_legacy: bool,
        legacy_config: &Config,
        legacy_config_path: Option<&Path>,
        legacy_secrets: &dyn SecretStore,
    ) -> Result<(Vec<Profile>, Vec<String>), String> {
        // Initialize vault using the exact verified mnemonic entropy so the written words match!
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        let entropy = rooste_vault::parse_mnemonic(verified_mnemonic).map_err(|e| e.to_string())?;
        let dek = rooste_vault::crypto::generate_dek();
        let kdf = rooste_vault::Argon2Params::default();
        let pw_salt = rooste_vault::crypto::generate_salt();
        let pw_nonce = rooste_vault::crypto::generate_slot_nonce();
        let pw_kek = rooste_vault::crypto::derive_password_kek(password, &pw_salt, kdf)
            .map_err(|e| e.to_string())?;
        let pw_wrapped = rooste_vault::crypto::seal_sm4_gcm(
            &pw_kek,
            &pw_nonce,
            b"password_slot:v1",
            dek.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        let rec_salt = rooste_vault::crypto::generate_salt();
        let rec_nonce = rooste_vault::crypto::generate_slot_nonce();
        let rec_kek = rooste_vault::crypto::derive_mnemonic_kek(&entropy, &rec_salt)
            .map_err(|e| e.to_string())?;
        let rec_wrapped = rooste_vault::crypto::seal_sm4_gcm(
            &rec_kek,
            &rec_nonce,
            b"recovery_slot:v1",
            dek.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        let header = rooste_vault::VaultHeader {
            version: rooste_vault::VAULT_HEADER_VERSION,
            vault_id: rooste_core::profile::new_id(),
            kdf,
            password_slot: rooste_vault::KeySlot {
                salt: pw_salt,
                nonce: pw_nonce,
                wrapped_dek: pw_wrapped,
            },
            recovery_slot: rooste_vault::KeySlot {
                salt: rec_salt,
                nonce: rec_nonce,
                wrapped_dek: rec_wrapped,
            },
        };
        guard
            .install_recovered_vault(
                header,
                dek,
                rooste_vault::VaultManifest {
                    sequence: 1,
                    updated_at: rooste_vault::now_utc_ms(),
                    entries: Default::default(),
                },
            )
            .map_err(|e| e.to_string())?;
        let initial_manifest = guard.manifest().clone();
        let _ = guard
            .set_manifest_and_save(initial_manifest)
            .map_err(|e| e.to_string())?;

        let mut warnings = Vec::new();
        let mut migrated_profiles = Vec::new();
        if migrating_legacy {
            for mut p in legacy_config.profiles.clone() {
                if let Some(ref key_path) = p.key_file.clone() {
                    let expanded = rooste_core::expand_tilde(&key_path.to_string_lossy());
                    match std::fs::read_to_string(&expanded) {
                        Ok(pem) => {
                            let label = expanded
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("migrated-key")
                                .to_owned();
                            let (fp, pub_key, req_prompt) =
                                match rooste_keys::inspect_key_text(&pem) {
                                    Ok(info) => {
                                        let fp = if info.fingerprint.is_empty() {
                                            extract_key_fingerprint(&label, &pem, None)
                                        } else {
                                            info.fingerprint
                                        };
                                        (fp, info.public_key, info.is_encrypted)
                                    }
                                    Err(_) => (
                                        extract_key_fingerprint(&label, &pem, None),
                                        String::new(),
                                        false,
                                    ),
                                };
                            match guard.import_ssh_key(label, fp, pub_key, &pem, None, req_prompt) {
                                Ok((sha, _)) => {
                                    p.key_sha256 = Some(sha);
                                    p.key_file = None;
                                }
                                Err(e) => warnings.push(format!(
                                    "Could not import key {} for {}: {e}",
                                    expanded.display(),
                                    p.display_name()
                                )),
                            }
                        }
                        Err(e) => warnings.push(format!(
                            "Key file {} for {} unreadable ({e}); kept legacy path.",
                            expanded.display(),
                            p.display_name()
                        )),
                    }
                }
                if p.save_password
                    && let Some(pw) = legacy_secrets.get(&p.id)
                {
                    let _ = guard.save_password(&p.id, &pw);
                }
                guard.save_profile(&p).map_err(|e| e.to_string())?;
                migrated_profiles.push(p);
            }
            if let Some(cfg_path) = legacy_config_path {
                let _ = backup_legacy_config(cfg_path);
                let mut stripped = legacy_config.clone();
                stripped.profiles.clear();
                let _ = stripped.save(cfg_path);
            }
        }
        drop(guard);

        self.enabled = true;
        self.unlocked = true;
        self.last_activity = Instant::now();
        self.refresh_managed_keys();
        Ok((migrated_profiles, warnings))
    }

    fn save_sync_form(&mut self, form: &SyncFormState) -> Result<(), String> {
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        let new_sync = form.to_sync_config(&guard.local_config().sync);
        guard.local_config_mut().sync = new_sync.clone();
        guard.local_config_mut().auto_lock_timeout_secs = form.auto_lock_timeout_secs;
        guard.save_local_config().map_err(|e| e.to_string())?;
        let creds = form.to_credentials();
        guard
            .save_local_credentials(&creds)
            .map_err(|e| e.to_string())?;
        drop(guard);

        self.auto_lock_timeout_secs = form.auto_lock_timeout_secs;
        self.auto_sync_interval_secs = new_sync.auto_sync_interval_secs;
        self.sync_enabled = new_sync.enabled && new_sync.backend != SyncBackendKind::None;
        if !self.sync_enabled {
            self.status = SyncStatus::Disabled;
        } else if matches!(self.status, SyncStatus::Disabled) {
            self.status = SyncStatus::Idle;
        }
        Ok(())
    }

    fn current_sync_form(&self) -> SyncFormState {
        if let Ok(guard) = self.store.try_lock() {
            let creds = guard.load_local_credentials().ok().flatten();
            SyncFormState::from_config(
                &guard.local_config().sync,
                guard.local_config().auto_lock_timeout_secs,
                creds.as_ref(),
            )
        } else {
            SyncFormState::default()
        }
    }

    fn handle_import_key(&mut self, state: &KeysManagerState) -> Result<(String, bool), String> {
        // Mandatory double-entry confirmation whenever a passphrase is entered!
        if !state.import_passphrase.is_empty()
            && *state.import_passphrase != *state.import_confirm_passphrase
        {
            return Err("Passphrase confirmation does not match.".into());
        }
        let raw_text = match state.import_tab {
            ImportSourceTab::PastePem => {
                if state.import_pem.trim().is_empty() {
                    return Err("Paste an OpenSSH PEM or PuTTY .ppk private key.".into());
                }
                state.import_pem.as_str().to_owned()
            }
            ImportSourceTab::File | ImportSourceTab::DiscoverSshDir => {
                if state.import_path.trim().is_empty() {
                    return Err("Click Browse… (or pick a key from ~/.ssh) first.".into());
                }
                let expanded = rooste_core::expand_tilde(state.import_path.trim());
                std::fs::read_to_string(&expanded)
                    .map_err(|e| format!("Failed to read {}: {e}", expanded.display()))?
            }
        };

        let inspection = rooste_keys::inspect_key_text(&raw_text).map_err(|e| e.to_string())?;
        let pass_opt =
            (!state.import_passphrase.is_empty()).then(|| state.import_passphrase.as_str());

        let label = if !state.import_label.trim().is_empty() {
            state.import_label.trim().to_owned()
        } else if !state.import_path.trim().is_empty() {
            Path::new(state.import_path.trim())
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("ssh-key")
                .to_owned()
        } else {
            format!("imported-{}", inspection.algorithm.to_ascii_lowercase())
        };

        // Decrypt/verify the key (OpenSSH, PKCS#1 RSA, PKCS#8, SEC1, legacy encrypted PEM, PuTTY .ppk)
        // and normalize to canonical OpenSSH PEM + extract real public key & fingerprint.
        let (normalized_pem, fingerprint, public_key) = if inspection.is_encrypted {
            if let Some(pass) = pass_opt {
                let parsed = decode_any_private_key(&label, &raw_text, Some(pass))
                    .map_err(|e| format!("Key verification failed: {e}"))?;
                let pub_key = parsed.public_key();
                let fp = rooste_keys::fingerprint(pub_key);
                let pub_line = rooste_keys::public_line(pub_key);
                let pem = if inspection.needs_normalization {
                    rooste_keys::to_openssh_pem(&parsed, Some(pass))
                        .map_err(|e| e.to_string())?
                        .as_str()
                        .to_owned()
                } else {
                    raw_text
                };
                (pem, fp, pub_line)
            } else if state.import_require_prompt && !inspection.needs_normalization {
                // Allow importing an already-encrypted OpenSSH key without decrypting it right now
                // when the user explicitly chose prompt-on-every-connection!
                (raw_text, inspection.fingerprint, inspection.public_key)
            } else {
                return Err(
                    "This private key is encrypted. Enter its passphrase to verify & import (or check 'Prompt on every connection' for OpenSSH keys)."
                        .into(),
                );
            }
        } else {
            let parsed = decode_any_private_key(&label, &raw_text, None)
                .map_err(|e| format!("Invalid private key: {e}"))?;
            let pub_key = parsed.public_key();
            let fp = rooste_keys::fingerprint(pub_key);
            let pub_line = rooste_keys::public_line(pub_key);
            let pem = if inspection.needs_normalization || pass_opt.is_some() {
                rooste_keys::to_openssh_pem(&parsed, pass_opt)
                    .map_err(|e| e.to_string())?
                    .as_str()
                    .to_owned()
            } else {
                raw_text
            };
            (pem, fp, pub_line)
        };

        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        guard
            .import_ssh_key(
                label,
                fingerprint,
                public_key,
                &normalized_pem,
                pass_opt.map(ToOwned::to_owned),
                state.import_require_prompt,
            )
            .map_err(|e| e.to_string())
    }

    fn handle_generate_key(&mut self, state: &KeysManagerState) -> Result<String, String> {
        let label = state.gen_label.trim();
        if label.is_empty() {
            return Err("Enter a label for the new SSH key.".into());
        }
        if !state.gen_passphrase.is_empty()
            && *state.gen_passphrase != *state.gen_confirm_passphrase
        {
            return Err("Passphrase confirmation does not match.".into());
        }
        let pass_opt = (!state.gen_passphrase.is_empty()).then(|| state.gen_passphrase.as_str());
        let key = rooste_keys::generate(state.gen_type, state.gen_comment.trim())
            .map_err(|e| format!("Key generation failed: {e}"))?;
        let pub_key = key.public_key();
        let fingerprint = rooste_keys::fingerprint(pub_key);
        let public_key = rooste_keys::public_line(pub_key);
        let pem = rooste_keys::to_openssh_pem(&key, pass_opt).map_err(|e| e.to_string())?;

        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        let (sha, _) = guard
            .import_ssh_key(
                label.to_owned(),
                fingerprint,
                public_key,
                pem.as_str(),
                pass_opt.map(ToOwned::to_owned),
                state.gen_require_prompt,
            )
            .map_err(|e| e.to_string())?;
        Ok(sha)
    }

    fn update_managed_key_meta(
        &mut self,
        sha: &str,
        new_label: Option<String>,
        new_require_prompt: Option<bool>,
        new_passphrase: Option<Option<String>>,
    ) -> Result<(), String> {
        let mut guard = self
            .store
            .try_lock()
            .map_err(|_| "Vault store busy".to_owned())?;
        let mut key = guard
            .load_ssh_key(sha)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Managed key not found in vault".to_owned())?;
        if let Some(label) = new_label {
            key.label = label;
        }
        if let Some(req) = new_require_prompt {
            key.require_passphrase_prompt = req;
            if req {
                key.passphrase = None;
            }
        }
        if let Some(pass) = new_passphrase {
            key.passphrase = pass.map(Zeroizing::new);
        }
        guard.save_ssh_key(&key).map_err(|e| e.to_string())?;
        drop(guard);
        self.refresh_managed_keys();
        Ok(())
    }
}

/// Scan `~/.ssh/` for candidate OpenSSH / PuTTY private keys so users can import them in one click.
fn scan_local_ssh_dir() -> Vec<DiscoveredLocalKey> {
    let Some(home) = std::env::home_dir() else {
        return Vec::new();
    };
    let ssh_dir = home.join(".ssh");
    let Ok(entries) = std::fs::read_dir(&ssh_dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if file_name.ends_with(".pub")
            || file_name.starts_with("known_hosts")
            || file_name == "config"
            || file_name == "authorized_keys"
            || file_name.starts_with('.')
        {
            continue;
        }
        // Skip oversized files (> 64 KiB) to stay snappy.
        if entry.metadata().is_ok_and(|m| m.len() > 64 * 1024) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(info) = rooste_keys::inspect_key_text(&text) {
            let (sha256_preview, _) = normalize_and_hash_ssh_key(&text);
            found.push(DiscoveredLocalKey {
                path,
                file_name,
                algorithm: info.algorithm,
                is_encrypted: info.is_encrypted,
                is_ppk: info.is_ppk,
                sha256_preview,
            });
        }
    }
    found.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    found
}

fn default_key_comment() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into());
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "rooste".into());
    format!("{user}@{host}")
}

fn render_sync_form_fields(ui: &mut Ui, form: &mut SyncFormState) {
    egui::Grid::new("vault_sync_form_grid")
        .num_columns(2)
        .spacing(theme::FORM_SPACING)
        .show(ui, |ui| {
            ui.label("Backend:");
            egui::ComboBox::from_id_salt("sync_backend_combo")
                .selected_text(form.backend.label())
                .show_ui(ui, |ui| {
                    for kind in SyncBackendKind::ALL {
                        ui.selectable_value(&mut form.backend, kind, kind.label());
                    }
                });
            ui.end_row();

            match form.backend {
                SyncBackendKind::None => {}
                SyncBackendKind::GitHub => {
                    ui.label("Repository (owner/repo or URL):");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.endpoint)
                            .hint_text("alexleft/rooste-vault-private")
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                    ui.label("Branch:");
                    ui.text_edit_singleline(&mut form.branch);
                    ui.end_row();
                    ui.label("GitHub PAT:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *form.github_pat)
                            .password(true)
                            .hint_text("ghp_... or github_pat_...")
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                }
                SyncBackendKind::S3 => {
                    ui.label("S3 Endpoint URL:");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.endpoint)
                            .hint_text("https://<account>.r2.cloudflarestorage.com")
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                    ui.label("Bucket:");
                    ui.text_edit_singleline(&mut form.s3_bucket);
                    ui.end_row();
                    ui.label("Region:");
                    ui.text_edit_singleline(&mut form.s3_region);
                    ui.end_row();
                    ui.label("Access Key ID:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *form.s3_access_key)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                    ui.label("Secret Access Key:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *form.s3_secret_key)
                            .password(true)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                }
                SyncBackendKind::WebDav => {
                    ui.label("WebDAV Root URL:");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.endpoint)
                            .hint_text("https://nas.local/remote.php/dav/files/user/rooste")
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                    ui.label("Username:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *form.webdav_user)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *form.webdav_password)
                            .password(true)
                            .desired_width(theme::FIELD_WIDTH),
                    );
                    ui.end_row();
                }
            }

            if form.backend != SyncBackendKind::None {
                ui.label("Optional Sub-prefix:");
                ui.text_edit_singleline(&mut form.prefix);
                ui.end_row();

                ui.label("Auto-sync interval (secs):");
                ui.add(egui::DragValue::new(&mut form.auto_sync_interval_secs).range(0..=86400));
                ui.end_row();
            }
        });
}

fn render_mnemonic_input_with_suggestions(ui: &mut Ui, input: &mut Zeroizing<String>) {
    let count = input.split_whitespace().count();
    ui.label(format!(
        "24-Word BIP-39 Recovery Mnemonic ({count}/24 words):"
    ));
    ui.add(
        egui::TextEdit::multiline(&mut **input)
            .desired_rows(3)
            .hint_text("Paste or type all 24 space-separated English BIP-39 words…")
            .desired_width(theme::FIELD_WIDTH),
    );
    // Live BIP-39 autocomplete suggestions for the word currently being typed.
    if !input.ends_with(char::is_whitespace)
        && let Some(last) = input.split_whitespace().last().map(ToOwned::to_owned)
        && last.len() >= 2
    {
        let suggestions = suggest_mnemonic_words(&last);
        if !suggestions.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.weak("Suggestions:");
                for word in suggestions {
                    if ui.small_button(word).clicked()
                        && let Some(pos) = input.rfind(&last)
                    {
                        input.truncate(pos);
                        input.push_str(word);
                        input.push(' ');
                    }
                }
            });
        }
    }
}

fn pick_three_quiz_indices() -> [usize; 3] {
    let mut picked = Vec::with_capacity(3);
    let mut seed = usize::try_from(rooste_vault::now_utc_ms()).unwrap_or(7);
    while picked.len() < 3 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (seed >> 8) % 24;
        if !picked.contains(&idx) {
            picked.push(idx);
        }
    }
    picked.sort_unstable();
    [picked[0], picked[1], picked[2]]
}

fn decode_any_private_key(
    label: &str,
    raw_text: &str,
    passphrase: Option<&str>,
) -> Result<rooste_keys::PrivateKey, String> {
    match rooste_keys::load(raw_text, passphrase) {
        Ok(pk) => Ok(pk),
        Err(first_err) => load_private_key_from_pem(label, raw_text, passphrase)
            .map_err(|_| first_err.to_string()),
    }
}

fn extract_key_fingerprint(label: &str, pem: &str, passphrase: Option<&str>) -> String {
    match load_private_key_from_pem(label, pem, passphrase) {
        Ok(pk) => pk.fingerprint(Default::default()).to_string(),
        Err(_) => "SHA256:(encrypted-key)".to_owned(),
    }
}

fn disable_ime_for_password_field(ui: &egui::Ui, edit: &egui::Response, needs_focus: bool) {
    if edit.has_focus() || needs_focus {
        ui.output_mut(|o| o.ime = None);
    }
}

fn format_sync_report(report: &SyncReport) -> String {
    if report.up_to_date {
        format!("Up to date (seq {})", report.manifest_sequence)
    } else if report.deleted_local > 0 {
        format!(
            "Synced: ↓{} ↑{} 🗑{} (seq {})",
            report.pulled, report.pushed, report.deleted_local, report.manifest_sequence
        )
    } else {
        format!(
            "Synced: ↓{} ↑{} (seq {})",
            report.pulled, report.pushed, report.manifest_sequence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_screen_password_disables_ime() {
        let ctx = egui::Context::default();
        let mut pw = String::new();
        let mut needs_focus = true;
        let screen = Some(egui::Rect::from_min_size(
            egui::pos2(0.0, 0.0),
            egui::vec2(600.0, 400.0),
        ));

        // Frame 1: request focus on the password field.
        let mut full = ctx.run_ui(
            egui::RawInput {
                screen_rect: screen,
                ..Default::default()
            },
            |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut pw)
                            .id_salt("vault_lock_screen_password")
                            .password(true),
                    );
                    if needs_focus {
                        if edit.has_focus() {
                            needs_focus = false;
                        } else {
                            edit.request_focus();
                        }
                    }
                    disable_ime_for_password_field(ui, &edit, needs_focus);
                });
            },
        );
        full.textures_delta.clear();
        assert!(full.platform_output.ime.is_none());

        // Frame 2: focused password field keeps IME disabled and still accepts ASCII text.
        let mut full = ctx.run_ui(
            egui::RawInput {
                screen_rect: screen,
                events: vec![egui::Event::Text("Abc123!".into())],
                ..Default::default()
            },
            |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut pw)
                            .id_salt("vault_lock_screen_password")
                            .password(true),
                    );
                    assert!(edit.has_focus());
                    disable_ime_for_password_field(ui, &edit, false);
                });
            },
        );
        full.textures_delta.clear();
        assert!(full.platform_output.ime.is_none());
        assert_eq!(pw, "Abc123!");
    }
}
