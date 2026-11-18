//! Incremental three-way merge sync engine with:
//! - Logical revision (`revision`) conflict resolution (immune to wall-clock skew)
//! - Two-phase topological staging download (guarantees referential integrity for keys/passwords/scripts -> profiles)
//! - Optimistic concurrency lock retry with exponential backoff + jitter (HTTP 412 / Git push conflict)
//! - Remote vault inspection & full recovery / wipe-and-resync (Scene B & Scene D)

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use rooste_core::Profile;
use rooste_vault::{
    ManifestEntry, RecordKind, VaultHeader, VaultManifest, VaultStore, VaultSummary,
    decrypt_manifest_bytes, now_utc_ms, parse_header_bytes, sha256_hex,
};
use zeroize::Zeroizing;

use crate::backend::SyncBackend;
use crate::error::SyncError;

/// Maximum optimistic-lock retry attempts on concurrent remote pushes.
pub const MAX_CONFLICT_RETRIES: usize = 3;

/// Summary of a profile conflict that was auto-forked into a backup entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConflict {
    pub original_id: String,
    pub backup_id: String,
    pub backup_name: String,
    pub winner_is_remote: bool,
}

/// Detailed result returned after a sync cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub deleted_local: usize,
    pub pruned_remote: usize,
    pub retries: usize,
    pub up_to_date: bool,
    pub conflicts: Vec<SyncConflict>,
    pub manifest_sequence: u64,
}

/// Progress update emitted during long-running sync or remote recovery operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncProgress {
    pub stage: String,
    pub done: usize,
    pub total: usize,
}

/// Remote vault header and raw encrypted manifest fetched prior to unlock (Scene B / Scene D).
#[derive(Debug, Clone)]
pub struct RemoteVaultSnapshot {
    pub header: VaultHeader,
    pub header_bytes: Vec<u8>,
    pub manifest_bytes: Option<Vec<u8>>,
    pub manifest_etag: Option<String>,
}

/// Configurable sync engine (allows short retry delays in tests).
#[derive(Debug, Clone)]
pub struct SyncEngine {
    pub base_retry_delay: Duration,
    pub max_retries: usize,
}

impl Default for SyncEngine {
    fn default() -> Self {
        Self {
            base_retry_delay: Duration::from_secs(1),
            max_retries: MAX_CONFLICT_RETRIES,
        }
    }
}

impl SyncEngine {
    /// Fast retry timings for automated tests.
    pub fn fast_for_tests() -> Self {
        Self {
            base_retry_delay: Duration::from_millis(5),
            max_retries: MAX_CONFLICT_RETRIES,
        }
    }

    /// Fetch remote `vault.json` (and optional `manifest.enc`) without requiring local unlock yet.
    pub async fn inspect_remote(
        &self,
        backend: &dyn SyncBackend,
    ) -> Result<RemoteVaultSnapshot, SyncError> {
        let Some((header_bytes, _)) = backend.get_blob("vault.json").await? else {
            return Err(SyncError::NotFound(
                "no vault.json found on remote backend".into(),
            ));
        };
        let header = parse_header_bytes(&header_bytes)?;
        let (manifest_bytes, manifest_etag) = match backend.get_blob("manifest.enc").await? {
            Some((bytes, etag)) => (Some(bytes), Some(etag)),
            None => (None, None),
        };
        Ok(RemoteVaultSnapshot {
            header,
            header_bytes,
            manifest_bytes,
            manifest_etag,
        })
    }

    /// Preview a remote vault's statistics once the user has unlocked `dek` from `snapshot.header`.
    pub fn summarize_remote(
        snapshot: &RemoteVaultSnapshot,
        dek: &[u8; 16],
    ) -> Result<VaultSummary, SyncError> {
        let manifest = match &snapshot.manifest_bytes {
            Some(bytes) => decrypt_manifest_bytes(&snapshot.header.vault_id, dek, bytes)?,
            None => VaultManifest::default(),
        };
        let mut profile_count = 0;
        let mut key_count = 0;
        let mut script_count = 0;
        for entry in manifest.entries.values() {
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
        Ok(VaultSummary {
            vault_id: snapshot.header.vault_id.clone(),
            sequence: manifest.sequence,
            updated_at: manifest.updated_at,
            profile_count,
            key_count,
            script_count,
        })
    }

    /// Recover a complete vault from remote into `store` (used by Scene B New Device Setup and
    /// Scene D Wipe & Re-sync). If `reset_backup` is provided and recovery fails mid-flight,
    /// `store` automatically rolls back to the backup so the user never loses local data.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_from_remote(
        &self,
        store: &mut VaultStore,
        backend: &dyn SyncBackend,
        snapshot: RemoteVaultSnapshot,
        dek: Zeroizing<[u8; 16]>,
        new_master_password: Option<&str>,
        reset_backup: Option<&Path>,
        mut on_progress: impl FnMut(SyncProgress),
    ) -> Result<SyncReport, SyncError> {
        let result = self
            .recover_inner(
                store,
                backend,
                snapshot,
                dek,
                new_master_password,
                &mut on_progress,
            )
            .await;
        match result {
            Ok(report) => {
                if let Some(backup) = reset_backup {
                    store.commit_reset(backup);
                }
                Ok(report)
            }
            Err(err) => {
                if let Some(backup) = reset_backup {
                    let _ = store.rollback_reset(backup);
                }
                Err(err)
            }
        }
    }

    async fn recover_inner(
        &self,
        store: &mut VaultStore,
        backend: &dyn SyncBackend,
        mut snapshot: RemoteVaultSnapshot,
        dek: Zeroizing<[u8; 16]>,
        new_master_password: Option<&str>,
        on_progress: &mut impl FnMut(SyncProgress),
    ) -> Result<SyncReport, SyncError> {
        let manifest = match &snapshot.manifest_bytes {
            Some(bytes) => decrypt_manifest_bytes(&snapshot.header.vault_id, &dek, bytes)?,
            None => VaultManifest::default(),
        };

        // Collect all active entries in strict topological dependency order.
        let mut active: Vec<ManifestEntry> = manifest
            .entries
            .values()
            .filter(|e| !e.deleted)
            .cloned()
            .collect();
        active.sort_by_key(|e| e.kind.dependency_order());

        // Stage all downloads in memory & verify SM4-GCM authentication + referential integrity.
        let total = active.len();
        let mut staged: Vec<(String, Vec<u8>)> = Vec::with_capacity(total);
        let mut verified_keys = std::collections::HashSet::new();

        for (idx, entry) in active.iter().enumerate() {
            on_progress(SyncProgress {
                stage: format!("Downloading {}", entry.kind.relative_path(&entry.id)),
                done: idx,
                total,
            });
            let rel = entry.kind.relative_path(&entry.id);
            let Some((bytes, _)) = backend.get_blob(&rel).await? else {
                return Err(SyncError::Integrity(format!(
                    "remote manifest references missing blob `{rel}`"
                )));
            };
            let rec = rooste_vault::EncryptedRecord::from_bytes(&bytes)?;
            let plain = rec.open(&snapshot.header.vault_id, entry.kind, &entry.id, &dek)?;
            match entry.kind {
                RecordKind::SshKey => {
                    verified_keys.insert(entry.id.clone());
                }
                RecordKind::Profile => {
                    let profile: Profile = serde_json::from_slice(&plain)
                        .map_err(|e| SyncError::Integrity(format!("invalid profile JSON: {e}")))?;
                    if let Some(ref key_sha) = profile.key_sha256
                        && !verified_keys.contains(key_sha)
                    {
                        return Err(SyncError::Integrity(format!(
                            "profile `{}` references missing SSH key `{key_sha}`",
                            profile.id
                        )));
                    }
                }
                _ => {}
            }
            staged.push((rel, bytes));
        }

        // If user recovered via mnemonic and set a new master password, update header & push header.
        if let Some(new_pw) = new_master_password {
            snapshot
                .header
                .reset_password_slot(&dek, new_pw, snapshot.header.kdf)?;
            let new_header_bytes = serde_json::to_vec_pretty(&snapshot.header).map_err(|e| {
                SyncError::Vault(rooste_vault::VaultError::Serialization(e.to_string()))
            })?;
            backend
                .put_blob("vault.json", &new_header_bytes, None)
                .await?;
        }

        // Install recovered header + rotate device_id + write verified blobs atomically.
        store.install_recovered_vault(snapshot.header, dek, manifest.clone())?;
        for (rel, bytes) in &staged {
            store.write_raw_blob(rel, bytes)?;
        }
        let manifest_hash = if let Some(ref mbytes) = snapshot.manifest_bytes {
            store.write_raw_blob("manifest.enc", mbytes)?;
            sha256_hex(mbytes)
        } else {
            store.set_manifest_and_save(manifest.clone())?
        };
        store.local_config_mut().sync.last_synced_manifest_hash = manifest_hash;
        store.local_config_mut().sync.last_synced_sequence = manifest.sequence;
        store.save_local_config()?;

        on_progress(SyncProgress {
            stage: "Recovery complete".into(),
            done: total,
            total,
        });

        Ok(SyncReport {
            pulled: staged.len(),
            pushed: 0,
            deleted_local: 0,
            pruned_remote: 0,
            retries: 0,
            up_to_date: false,
            conflicts: Vec::new(),
            manifest_sequence: manifest.sequence,
        })
    }

    /// Execute one incremental three-way sync cycle with automatic optimistic-lock retries.
    pub async fn sync(
        &self,
        store: &mut VaultStore,
        backend: &dyn SyncBackend,
        mut on_progress: impl FnMut(SyncProgress),
    ) -> Result<SyncReport, SyncError> {
        let mut retries = 0usize;
        loop {
            match self.sync_once(store, backend, &mut on_progress).await {
                Ok(mut report) => {
                    report.retries = retries;
                    return Ok(report);
                }
                Err(SyncError::Conflict(msg)) if retries < self.max_retries => {
                    retries += 1;
                    let shift = u32::try_from(retries - 1).unwrap_or(0).min(4);
                    let factor = 1u32 << shift;
                    let jitter_ms: u64 = u64::from(rand::random::<u8>()) % 150;
                    let delay = self.base_retry_delay * factor + Duration::from_millis(jitter_ms);
                    on_progress(SyncProgress {
                        stage: format!(
                            "Conflict ({msg}), retrying ({retries}/{})…",
                            self.max_retries
                        ),
                        done: 0,
                        total: 1,
                    });
                    tokio::time::sleep(delay).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn sync_once(
        &self,
        store: &mut VaultStore,
        backend: &dyn SyncBackend,
        on_progress: &mut impl FnMut(SyncProgress),
    ) -> Result<SyncReport, SyncError> {
        let dek = *store.dek()?;
        let vault_id = store
            .header()
            .ok_or_else(|| {
                SyncError::Vault(rooste_vault::VaultError::NotInitialized {
                    path: store.vault_dir(),
                })
            })?
            .vault_id
            .clone();

        on_progress(SyncProgress {
            stage: "Checking remote manifest…".into(),
            done: 0,
            total: 1,
        });

        let remote_manifest_opt = backend.get_blob("manifest.enc").await?;
        let local_manifest_hash = store.manifest_file_hash()?.unwrap_or_default();
        let last_synced_hash = store.local_config().sync.last_synced_manifest_hash.clone();

        // Short-circuit: remote manifest matches last synced hash AND local has no unpushed changes.
        if let Some((ref remote_bytes, _)) = remote_manifest_opt {
            let remote_hash = sha256_hex(remote_bytes);
            if !last_synced_hash.is_empty()
                && remote_hash == last_synced_hash
                && local_manifest_hash == last_synced_hash
            {
                return Ok(SyncReport {
                    up_to_date: true,
                    manifest_sequence: store.manifest().sequence,
                    ..SyncReport::default()
                });
            }
        }

        // First-time push if remote vault is completely empty.
        let (remote_manifest, remote_etag, need_push_header) = match &remote_manifest_opt {
            Some((bytes, etag)) => {
                let m = decrypt_manifest_bytes(&vault_id, &dek, bytes)?;
                // Also ensure vault.json exists remotely.
                let has_header = backend.get_blob("vault.json").await?.is_some();
                (m, Some(etag.clone()), !has_header)
            }
            None => (VaultManifest::default(), None, true),
        };

        let local_manifest = store.manifest().clone();

        // Three-way merge on logical revisions & hashes.
        let mut merged_entries: BTreeMap<String, ManifestEntry> = BTreeMap::new();
        let mut to_pull: Vec<ManifestEntry> = Vec::new();
        let mut to_push: Vec<ManifestEntry> = Vec::new();
        let mut to_delete_local: Vec<ManifestEntry> = Vec::new();
        let mut conflict_forks: Vec<(ManifestEntry, bool /* winner_is_remote */)> = Vec::new();

        let all_keys: std::collections::BTreeSet<String> = local_manifest
            .entries
            .keys()
            .chain(remote_manifest.entries.keys())
            .cloned()
            .collect();

        for key in all_keys {
            match (
                local_manifest.entries.get(&key),
                remote_manifest.entries.get(&key),
            ) {
                (Some(local), None) => {
                    merged_entries.insert(key, local.clone());
                    if !local.deleted {
                        to_push.push(local.clone());
                    }
                }
                (None, Some(remote)) => {
                    merged_entries.insert(key, remote.clone());
                    if !remote.deleted {
                        to_pull.push(remote.clone());
                    }
                }
                (Some(local), Some(remote)) => {
                    if local.rev_hash == remote.rev_hash && local.deleted == remote.deleted {
                        let keep = if compare_entries(remote, local) == Ordering::Greater {
                            remote.clone()
                        } else {
                            local.clone()
                        };
                        merged_entries.insert(key, keep);
                        continue;
                    }

                    // Clean fast-forward from local -> remote.
                    if remote.prev_hash == Some(local.rev_hash) {
                        merged_entries.insert(key, remote.clone());
                        if remote.deleted {
                            to_delete_local.push(remote.clone());
                        } else {
                            to_pull.push(remote.clone());
                        }
                        continue;
                    }

                    // Clean fast-forward from remote -> local.
                    if local.prev_hash == Some(remote.rev_hash) {
                        merged_entries.insert(key, local.clone());
                        if !local.deleted {
                            to_push.push(local.clone());
                        }
                        continue;
                    }

                    // Concurrent divergence! Resolve deterministically by logical (revision, updated_at, updated_by).
                    let remote_wins = compare_entries(remote, local) == Ordering::Greater;
                    if remote_wins {
                        merged_entries.insert(key, remote.clone());
                        if !local.deleted && !remote.deleted && local.kind == RecordKind::Profile {
                            conflict_forks.push((local.clone(), true));
                        }
                        if remote.deleted {
                            to_delete_local.push(remote.clone());
                        } else {
                            to_pull.push(remote.clone());
                        }
                    } else {
                        merged_entries.insert(key, local.clone());
                        if !local.deleted && !remote.deleted && remote.kind == RecordKind::Profile {
                            conflict_forks.push((remote.clone(), false));
                        }
                        if !local.deleted {
                            to_push.push(local.clone());
                        }
                    }
                }
                (None, None) => {}
            }
        }

        // Phase 1 (Download): Two-phase topological staging so dependencies exist before profiles activate.
        to_pull.sort_by_key(|e| e.kind.dependency_order());
        let pull_total = to_pull.len();
        let mut staged_pulls: Vec<(ManifestEntry, Vec<u8>)> = Vec::with_capacity(pull_total);
        let mut staged_key_shas = std::collections::HashSet::new();

        for (idx, entry) in to_pull.iter().enumerate() {
            let rel = entry.kind.relative_path(&entry.id);
            on_progress(SyncProgress {
                stage: format!("Pulling {rel}"),
                done: idx,
                total: pull_total.max(1),
            });
            let Some((bytes, _)) = backend.get_blob(&rel).await? else {
                return Err(SyncError::Integrity(format!(
                    "remote blob `{rel}` missing during pull"
                )));
            };
            let (_, plain) = store.decrypt_external_record(entry.kind, &entry.id, &bytes)?;
            match entry.kind {
                RecordKind::SshKey => {
                    staged_key_shas.insert(entry.id.clone());
                }
                RecordKind::Profile => {
                    let profile: Profile = serde_json::from_slice(&plain).map_err(|e| {
                        SyncError::Integrity(format!("corrupt remote profile: {e}"))
                    })?;
                    if let Some(ref key_sha) = profile.key_sha256 {
                        let key_path = store
                            .vault_dir()
                            .join(RecordKind::SshKey.relative_path(key_sha));
                        if !staged_key_shas.contains(key_sha) && !key_path.exists() {
                            return Err(SyncError::Integrity(format!(
                                "profile `{}` references missing SSH key `{key_sha}`; aborting pull before activation",
                                profile.id
                            )));
                        }
                    }
                }
                _ => {}
            }
            staged_pulls.push((entry.clone(), bytes));
        }

        // Handle profile conflict forks BEFORE overwriting local files so loser data is preserved!
        let mut conflicts = Vec::new();
        let date_tag = Utc::now().format("%Y-%m-%d").to_string();
        for (loser_entry, winner_is_remote) in conflict_forks {
            let loser_profile_opt = if winner_is_remote {
                store.load_profile(&loser_entry.id)?
            } else {
                let rel = RecordKind::Profile.relative_path(&loser_entry.id);
                if let Some((bytes, _)) = backend.get_blob(&rel).await? {
                    let (_, plain) = store.decrypt_external_record(
                        RecordKind::Profile,
                        &loser_entry.id,
                        &bytes,
                    )?;
                    serde_json::from_slice::<Profile>(&plain).ok()
                } else {
                    None
                }
            };
            if let Some(mut backup_profile) = loser_profile_opt {
                let original_id = backup_profile.id.clone();
                backup_profile.id = rooste_core::profile::new_id();
                backup_profile.name =
                    format!("{} (冲突备份 - {date_tag})", backup_profile.display_name());
                let backup_id = backup_profile.id.clone();
                let backup_name = backup_profile.name.clone();
                store.save_profile(&backup_profile)?;
                let bkey = RecordKind::Profile.manifest_key(&backup_id);
                if let Some(new_entry) = store.manifest().entries.get(&bkey).cloned() {
                    merged_entries.insert(bkey, new_entry.clone());
                    to_push.push(new_entry);
                }
                conflicts.push(SyncConflict {
                    original_id,
                    backup_id,
                    backup_name,
                    winner_is_remote,
                });
            }
        }

        // Phase 2 (Activate): Commit verified pulls & tombstones to local disk in topological order.
        for (entry, bytes) in &staged_pulls {
            store.write_raw_blob(&entry.kind.relative_path(&entry.id), bytes)?;
        }
        let deleted_local = to_delete_local.len();
        for entry in &to_delete_local {
            store.remove_raw_blob(&entry.kind.relative_path(&entry.id))?;
        }

        // Assemble merged manifest & prune tombstones older than 90 days.
        let mut merged_manifest = VaultManifest {
            sequence: local_manifest.sequence.max(remote_manifest.sequence),
            updated_at: now_utc_ms(),
            entries: merged_entries,
        };
        let pruned_paths = merged_manifest.prune_expired_tombstones(now_utc_ms());

        let has_remote_writes = need_push_header
            || !to_push.is_empty()
            || !pruned_paths.is_empty()
            || !conflicts.is_empty();

        // If we only pulled and nothing needs pushing, simply persist remote manifest & return.
        if !has_remote_writes {
            if let Some((ref remote_bytes, _)) = remote_manifest_opt {
                store.write_raw_blob("manifest.enc", remote_bytes)?;
                let hash = sha256_hex(remote_bytes);
                let _ = store.set_manifest_and_save(merged_manifest.clone());
                // Keep exact remote manifest bytes so hash matches remote without needless churn.
                store.write_raw_blob("manifest.enc", remote_bytes)?;
                store.local_config_mut().sync.last_synced_manifest_hash = hash;
                store.local_config_mut().sync.last_synced_sequence = remote_manifest.sequence;
                store.save_local_config()?;
            }
            return Ok(SyncReport {
                pulled: staged_pulls.len(),
                pushed: 0,
                deleted_local,
                pruned_remote: 0,
                retries: 0,
                up_to_date: staged_pulls.is_empty() && deleted_local == 0,
                conflicts,
                manifest_sequence: remote_manifest.sequence,
            });
        }

        // Persist updated local manifest & prepare upload batch.
        let new_manifest_hash = store.set_manifest_and_save(merged_manifest)?;
        let manifest_bytes = store
            .read_raw_blob("manifest.enc")?
            .ok_or_else(|| SyncError::Integrity("local manifest.enc missing after save".into()))?;

        // Sort pushes in topological order (keys/passwords/scripts before profiles).
        to_push.sort_by_key(|e| e.kind.dependency_order());
        let mut puts: Vec<(String, Vec<u8>)> = Vec::with_capacity(to_push.len() + 1);
        if need_push_header {
            let header_bytes = store
                .read_raw_blob("vault.json")?
                .ok_or_else(|| SyncError::Integrity("local vault.json missing".into()))?;
            puts.push(("vault.json".to_owned(), header_bytes));
        }
        for entry in &to_push {
            let rel = entry.kind.relative_path(&entry.id);
            if let Some(bytes) = store.read_raw_blob(&rel)? {
                puts.push((rel, bytes));
            }
        }

        on_progress(SyncProgress {
            stage: format!("Pushing {} item(s)…", puts.len()),
            done: 0,
            total: puts.len().max(1),
        });

        let pushed_count = to_push.len();
        let pruned_count = pruned_paths.len();
        backend
            .commit_batch(puts, pruned_paths, manifest_bytes, remote_etag.as_deref())
            .await?;

        store.local_config_mut().sync.last_synced_manifest_hash = new_manifest_hash;
        store.local_config_mut().sync.last_synced_sequence = store.manifest().sequence;
        store.save_local_config()?;

        Ok(SyncReport {
            pulled: staged_pulls.len(),
            pushed: pushed_count,
            deleted_local,
            pruned_remote: pruned_count,
            retries: 0,
            up_to_date: false,
            conflicts,
            manifest_sequence: store.manifest().sequence,
        })
    }
}

/// Deterministic conflict winner ordering:
/// 1. Higher logical `revision` (immune to wall-clock skew)
/// 2. Higher `updated_at` UTC ms (tie-breaker when revisions equal)
/// 3. Lexicographically greater `updated_by` device_id (guarantees convergence across all nodes)
fn compare_entries(a: &ManifestEntry, b: &ManifestEntry) -> Ordering {
    a.revision
        .cmp(&b.revision)
        .then_with(|| a.updated_at.cmp(&b.updated_at))
        .then_with(|| a.updated_by.cmp(&b.updated_by))
}
