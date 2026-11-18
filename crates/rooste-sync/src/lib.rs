//! Asynchronous multi-backend incremental sync engine (`crates/rooste-sync`).
//!
//! Supports GitHub (atomic single-commit Git Database REST API), S3-compatible object stores
//! (pure Safe Rust AWS SigV4 + `If-Match` optimistic locking), and WebDAV (`.tmp` + atomic `MOVE`),
//! driven by a three-way logical-revision merge engine and a non-blocking `tokio` actor.

pub mod actor;
pub mod backend;
pub mod engine;
pub mod error;
pub mod github;
pub mod s3;
pub mod webdav;

pub use actor::{SyncActorHandle, SyncCommand, SyncEvent};
pub use backend::{
    MemoryBackend, SyncBackend, build_backend, build_http_client, init_tls_provider,
};
pub use engine::{
    MAX_CONFLICT_RETRIES, RemoteVaultSnapshot, SyncConflict, SyncEngine, SyncProgress, SyncReport,
};
pub use error::SyncError;
pub use github::{GitHubBackend, normalize_github_repo_url};
pub use s3::S3Backend;
pub use webdav::WebDavBackend;

#[cfg(test)]
mod tests {
    use rooste_core::{ConfigLocation, Profile};
    use rooste_vault::{Argon2Params, RecordKind, VaultStore};

    use super::*;

    fn new_store(dir: &tempfile::TempDir) -> VaultStore {
        let loc = ConfigLocation::for_root(dir.path().to_path_buf(), true);
        VaultStore::open(loc)
            .unwrap()
            .with_kdf_params(Argon2Params::fast_for_tests())
    }

    #[tokio::test]
    async fn two_devices_sync_keys_profiles_and_short_circuit() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        // Device A initializes vault, adds an SSH key + profile + password, and pushes.
        let mut dev_a = new_store(&dir_a);
        let init = dev_a.initialize("shared-master-pw!").unwrap();
        let (key_sha, _) = dev_a
            .import_ssh_key(
                "prod-key".into(),
                "SHA256:prod".into(),
                "ssh-ed25519 AAAA".into(),
                "-----BEGIN OPENSSH PRIVATE KEY-----\nkeybody\n-----END OPENSSH PRIVATE KEY-----\n",
                None,
                false,
            )
            .unwrap();
        let profile = Profile {
            name: "Gateway".into(),
            host: "gw.example.com".into(),
            user: "admin".into(),
            key_sha256: Some(key_sha.clone()),
            save_password: true,
            ..Profile::default()
        };
        dev_a.save_profile(&profile).unwrap();
        dev_a.save_password(&profile.id, "pw-123").unwrap();

        let report_push = engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();
        assert_eq!(report_push.pushed, 3);
        assert_eq!(report_push.pulled, 0);

        // Second sync with no changes short-circuits cleanly.
        let report_noop = engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();
        assert!(report_noop.up_to_date);

        // Device B recovers from remote using the 24-word mnemonic (Scene B).
        let mut dev_b = new_store(&dir_b);
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_mnemonic(&init.mnemonic).unwrap();
        let summary = SyncEngine::summarize_remote(&snap, &dek).unwrap();
        assert_eq!(summary.profile_count, 1);
        assert_eq!(summary.key_count, 1);

        let rec_report = engine
            .recover_from_remote(&mut dev_b, &remote, snap, dek, None, None, |_| {})
            .await
            .unwrap();
        assert_eq!(rec_report.pulled, 3);
        assert_eq!(
            dev_b.load_profile(&profile.id).unwrap().unwrap().name,
            "Gateway"
        );
        assert_eq!(
            dev_b.load_ssh_key(&key_sha).unwrap().unwrap().label,
            "prod-key"
        );
        assert_eq!(
            dev_b
                .load_password(&profile.id)
                .unwrap()
                .unwrap()
                .password
                .as_str(),
            "pw-123"
        );
    }

    #[tokio::test]
    async fn concurrent_profile_edits_resolve_by_revision_and_fork_conflict_backup() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut dev_a = new_store(&dir_a);
        dev_a.initialize("pw-sync-1").unwrap();
        let mut profile = Profile {
            name: "App Server".into(),
            host: "app.internal".into(),
            ..Profile::default()
        };
        dev_a.save_profile(&profile).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        // Recover onto Device B so both share revision 1.
        let mut dev_b = new_store(&dir_b);
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_password("pw-sync-1").unwrap();
        engine
            .recover_from_remote(&mut dev_b, &remote, snap, dek, None, None, |_| {})
            .await
            .unwrap();

        // Device A edits twice (reaches revision 3) and pushes.
        profile.notes = "A edit 1".into();
        dev_a.save_profile(&profile).unwrap();
        profile.notes = "A edit 2 (rev 3)".into();
        dev_a.save_profile(&profile).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        // Offline Device B edits once (revision 2) -> diverges from Device A!
        let mut prof_b = dev_b.load_profile(&profile.id).unwrap().unwrap();
        prof_b.notes = "B offline edit (rev 2)".into();
        dev_b.save_profile(&prof_b).unwrap();

        // Sync Device B: Device A's revision 3 wins; Device B's edit is preserved as conflict backup.
        let report = engine.sync(&mut dev_b, &remote, |_| {}).await.unwrap();
        assert_eq!(report.conflicts.len(), 1);
        assert!(report.conflicts[0].winner_is_remote);
        assert!(report.conflicts[0].backup_name.contains("conflict"));

        let winner = dev_b.load_profile(&profile.id).unwrap().unwrap();
        assert_eq!(winner.notes, "A edit 2 (rev 3)");
        let backup = dev_b
            .load_profile(&report.conflicts[0].backup_id)
            .unwrap()
            .unwrap();
        assert_eq!(backup.notes, "B offline edit (rev 2)");
    }

    #[tokio::test]
    async fn optimistic_lock_412_retries_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut store = new_store(&dir);
        store.initialize("retry-pw").unwrap();
        store
            .save_profile(&Profile {
                name: "Node 1".into(),
                host: "node1.local".into(),
                ..Profile::default()
            })
            .unwrap();

        // Inject 2 consecutive 412 conflicts; engine should retry and succeed on attempt 3.
        remote.inject_manifest_conflicts(2);
        let report = engine.sync(&mut store, &remote, |_| {}).await.unwrap();
        assert_eq!(report.retries, 2);
        assert_eq!(report.pushed, 1);
    }

    #[tokio::test]
    async fn network_drop_on_ssh_key_aborts_before_activating_profile() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut dev_a = new_store(&dir_a);
        dev_a.initialize("integrity-pw").unwrap();
        let (key_sha, _) = dev_a
            .import_ssh_key(
                "db-key".into(),
                "SHA256:db".into(),
                "ssh-ed25519 AAAA".into(),
                "-----BEGIN OPENSSH PRIVATE KEY-----\ndbkey\n-----END OPENSSH PRIVATE KEY-----\n",
                None,
                false,
            )
            .unwrap();
        let p = Profile {
            name: "DB".into(),
            host: "db.local".into(),
            key_sha256: Some(key_sha.clone()),
            ..Profile::default()
        };
        dev_a.save_profile(&p).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        // Simulate network failure specifically when Device B tries to fetch the SSH key blob.
        let key_rel = RecordKind::SshKey.relative_path(&key_sha);
        remote.fail_get(Some(key_rel));

        let mut dev_b = new_store(&dir_b);
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_password("integrity-pw").unwrap();
        let err = engine
            .recover_from_remote(&mut dev_b, &remote, snap, dek, None, None, |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::Network(_)));
        // Crucially, Device B must NOT have activated a broken profile missing its SSH key!
        assert!(!dev_b.is_initialized());
    }

    #[tokio::test]
    async fn scene_d_wipe_and_resync_rolls_back_on_error_and_succeeds_when_healthy() {
        let dir_a = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut dev = new_store(&dir_a);
        let init = dev.initialize("pw-orig").unwrap();
        let p_clean = Profile {
            name: "Clean Remote".into(),
            host: "clean.example.com".into(),
            ..Profile::default()
        };
        dev.save_profile(&p_clean).unwrap();
        engine.sync(&mut dev, &remote, |_| {}).await.unwrap();

        // Make an unwanted local edit (not pushed).
        let p_dirty = Profile {
            name: "Unwanted Local".into(),
            host: "dirty.local".into(),
            ..Profile::default()
        };
        dev.save_profile(&p_dirty).unwrap();

        // First simulate a failed wipe-and-resync -> must roll back local backup intact!
        remote.fail_get(Some(RecordKind::Profile.relative_path(&p_clean.id)));
        let backup = dev.begin_reset_backup().unwrap();
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_mnemonic(&init.mnemonic).unwrap();
        assert!(
            engine
                .recover_from_remote(&mut dev, &remote, snap, dek, None, Some(&backup), |_| {})
                .await
                .is_err()
        );
        dev.unlock_with_password("pw-orig").unwrap();
        assert!(dev.load_profile(&p_dirty.id).unwrap().is_some());

        // Now clear network fault and perform clean wipe-and-resync with mnemonic + new password!
        remote.fail_get(None);
        let backup2 = dev.begin_reset_backup().unwrap();
        let snap2 = engine.inspect_remote(&remote).await.unwrap();
        let dek2 = snap2.header.unlock_with_mnemonic(&init.mnemonic).unwrap();
        engine
            .recover_from_remote(
                &mut dev,
                &remote,
                snap2,
                dek2,
                Some("pw-reset-new"),
                Some(&backup2),
                |_| {},
            )
            .await
            .unwrap();
        assert!(!backup2.exists());
        assert!(dev.load_profile(&p_dirty.id).unwrap().is_none());
        assert_eq!(
            dev.load_profile(&p_clean.id).unwrap().unwrap().name,
            "Clean Remote"
        );
        // Verify new password works on re-open.
        dev.lock();
        dev.unlock_with_password("pw-reset-new").unwrap();
    }

    #[tokio::test]
    async fn multi_edit_fast_forward_never_creates_false_conflict() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut dev_a = new_store(&dir_a);
        dev_a.initialize("pw-sync-ff").unwrap();
        let mut profile = Profile {
            name: "sz-aliyun".into(),
            host: "1.2.3.4".into(),
            ..Profile::default()
        };
        dev_a.save_profile(&profile).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        // Device B (Windows) recovers at revision 1 and never edits `sz-aliyun`.
        let mut dev_b = new_store(&dir_b);
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_password("pw-sync-ff").unwrap();
        engine
            .recover_from_remote(&mut dev_b, &remote, snap, dek, None, None, |_| {})
            .await
            .unwrap();

        // Device A edits `sz-aliyun` 3 times before Device B syncs (rev 1 -> 2 -> 3 -> 4).
        for i in 2..=4 {
            profile.notes = format!("edit {i}");
            dev_a.save_profile(&profile).unwrap();
        }
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        // Device B syncs: must cleanly fast-forward with ZERO conflict backups!
        let report = engine.sync(&mut dev_b, &remote, |_| {}).await.unwrap();
        assert!(report.conflicts.is_empty());
        assert_eq!(report.pulled, 1);
        assert_eq!(report.pushed, 0);
        assert_eq!(dev_b.list_profiles().unwrap().len(), 1);
        assert_eq!(
            dev_b.load_profile(&profile.id).unwrap().unwrap().notes,
            "edit 4"
        );

        // Also test legacy upgrade path (empty `last_synced_entries` on Device B) after 2 more edits on A.
        dev_b.local_config_mut().sync.last_synced_entries.clear();
        for i in 5..=6 {
            profile.notes = format!("edit {i}");
            dev_a.save_profile(&profile).unwrap();
        }
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();
        let report2 = engine.sync(&mut dev_b, &remote, |_| {}).await.unwrap();
        assert!(report2.conflicts.is_empty());
        assert_eq!(dev_b.list_profiles().unwrap().len(), 1);
        assert_eq!(
            dev_b.load_profile(&profile.id).unwrap().unwrap().notes,
            "edit 6"
        );
    }

    #[tokio::test]
    async fn noop_save_and_identical_concurrent_edits_never_create_conflict() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut dev_a = new_store(&dir_a);
        dev_a.initialize("pw-sync-noop").unwrap();
        let mut profile = Profile {
            name: "sz-aliyun".into(),
            host: "1.2.3.4".into(),
            ..Profile::default()
        };
        dev_a.save_profile(&profile).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        let mut dev_b = new_store(&dir_b);
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_password("pw-sync-noop").unwrap();
        engine
            .recover_from_remote(&mut dev_b, &remote, snap, dek, None, None, |_| {})
            .await
            .unwrap();

        // 1. No-op save on Device B must NOT bump revision or dirty the manifest.
        let mkey = rooste_vault::RecordKind::Profile.manifest_key(&profile.id);
        let before_rev = dev_b.manifest().entries[&mkey].revision;
        let unchanged = dev_b.load_profile(&profile.id).unwrap().unwrap();
        dev_b.save_profile(&unchanged).unwrap();
        let after_rev = dev_b.manifest().entries[&mkey].revision;
        assert_eq!(before_rev, after_rev);

        // 2. Both devices independently make the exact same edit offline.
        profile.allow_legacy = true;
        dev_a.save_profile(&profile).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        let mut prof_b = dev_b.load_profile(&profile.id).unwrap().unwrap();
        prof_b.allow_legacy = true;
        dev_b.save_profile(&prof_b).unwrap();

        // Syncing must detect identical decrypted content and create ZERO conflict backup!
        let report = engine.sync(&mut dev_b, &remote, |_| {}).await.unwrap();
        assert!(report.conflicts.is_empty());
        assert_eq!(dev_b.list_profiles().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn delete_profile_propagates_tombstone_across_devices() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let remote = MemoryBackend::new();
        let engine = SyncEngine::fast_for_tests();

        let mut dev_a = new_store(&dir_a);
        dev_a.initialize("pw-del-sync").unwrap();
        let keep_p = Profile {
            name: "sz-aliyun".into(),
            host: "1.2.3.4".into(),
            ..Profile::default()
        };
        let drop_p = Profile {
            name: "sz-aliyun (conflict - 2026-11-18)".into(),
            host: "1.2.3.4".into(),
            ..Profile::default()
        };
        dev_a.save_profile(&keep_p).unwrap();
        dev_a.save_profile(&drop_p).unwrap();
        engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();

        // Device B (Windows) recovers both profiles.
        let mut dev_b = new_store(&dir_b);
        let snap = engine.inspect_remote(&remote).await.unwrap();
        let dek = snap.header.unlock_with_password("pw-del-sync").unwrap();
        engine
            .recover_from_remote(&mut dev_b, &remote, snap, dek, None, None, |_| {})
            .await
            .unwrap();
        assert_eq!(dev_b.list_profiles().unwrap().len(), 2);

        // Device A (Mac) deletes the conflict backup profile and syncs.
        dev_a.delete_profile(&drop_p.id).unwrap();
        let push_rep = engine.sync(&mut dev_a, &remote, |_| {}).await.unwrap();
        assert!(!push_rep.up_to_date);
        assert_eq!(push_rep.pushed, 1);
        assert!(
            remote
                .get_blob(&rooste_vault::RecordKind::Profile.relative_path(&drop_p.id))
                .await
                .unwrap()
                .is_none()
        );

        // Device B (Windows) syncs and MUST delete the profile locally!
        let pull_rep = engine.sync(&mut dev_b, &remote, |_| {}).await.unwrap();
        assert!(!pull_rep.up_to_date);
        assert_eq!(pull_rep.deleted_local, 1);
        let remaining = dev_b.list_profiles().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, keep_p.id);
        assert!(
            !dev_b
                .vault_dir()
                .join(rooste_vault::RecordKind::Profile.relative_path(&drop_p.id))
                .exists()
        );

        // Next sync on Device B is cleanly up to date.
        let noop_rep = engine.sync(&mut dev_b, &remote, |_| {}).await.unwrap();
        assert!(noop_rep.up_to_date);
    }

    #[test]
    fn github_url_normalization_handles_common_forms() {
        assert_eq!(
            normalize_github_repo_url("alexleft/rooste-vault").unwrap(),
            "https://api.github.com/repos/alexleft/rooste-vault"
        );
        assert_eq!(
            normalize_github_repo_url("https://github.com/alexleft/rooste-vault.git").unwrap(),
            "https://api.github.com/repos/alexleft/rooste-vault"
        );
        assert_eq!(
            normalize_github_repo_url("https://api.github.com/repos/alexleft/rooste-vault")
                .unwrap(),
            "https://api.github.com/repos/alexleft/rooste-vault"
        );
    }
}
