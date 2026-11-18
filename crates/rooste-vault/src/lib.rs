//! End-to-end encrypted file vault for Rooste SSH (`crates/rooste-vault`).
//!
//! - National standard **SM4-GCM** authenticated encryption with **deterministic composite 96-bit Nonce**
//! - Canonical AAD binding protecting against metadata tampering and file substitution attacks
//! - Dual-slot `vault.json` envelope (`Argon2id` master password + 24-word English BIP-39 recovery mnemonic)
//! - First-class SSH private key storage with SHA-256 content deduplication
//! - Zero OS Keyring dependency via DEK-derived `local_secrets.enc`

pub mod crypto;
pub mod error;
pub mod header;
pub mod models;
pub mod record;
pub mod store;

pub use crypto::{
    Argon2Params, Sm4Gcm, derive_local_secrets_key, deterministic_nonce, generate_mnemonic,
    parse_mnemonic, password_strength_score, sha256_bytes, sha256_hex, suggest_mnemonic_words,
};
pub use error::VaultError;
pub use header::{KeySlot, VAULT_HEADER_VERSION, VaultHeader};
pub use models::{
    LocalSyncCredentials, ManifestEntry, TOMBSTONE_RETENTION_MS, VaultKnownHosts, VaultManifest,
    VaultPassword, VaultScript, VaultSshKey, normalize_and_hash_ssh_key,
};
pub use record::{EncryptedRecord, RECORD_VERSION, RecordKind, SealMeta};
pub use store::{
    InitializedVault, VaultStore, VaultSummary, decrypt_manifest_bytes, now_utc_ms,
    parse_header_bytes,
};

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rooste_core::{ConfigLocation, Profile};
    use zeroize::Zeroizing;

    use super::*;

    fn test_store(dir: &tempfile::TempDir) -> VaultStore {
        let loc = ConfigLocation::for_root(dir.path().to_path_buf(), true);
        VaultStore::open(loc)
            .unwrap()
            .with_kdf_params(Argon2Params::fast_for_tests())
    }

    #[test]
    fn dual_slot_init_unlock_and_password_reset_preserve_data() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = test_store(&dir);
        let init = store.initialize("Correct-Horse-Battery-1!").unwrap();
        assert_eq!(init.mnemonic.split_whitespace().count(), 24);

        let mut profile = Profile {
            name: "Prod Bastion".into(),
            host: "10.0.0.1".into(),
            user: "ops".into(),
            save_password: true,
            ..Profile::default()
        };
        store.save_profile(&profile).unwrap();
        store.save_password(&profile.id, "super-secret-pw").unwrap();

        // Lock clears DEK.
        store.lock();
        assert!(!store.is_unlocked());
        assert!(matches!(store.list_profiles(), Err(VaultError::Locked)));

        // Wrong password fails.
        assert!(matches!(
            store.unlock_with_password("wrong-password"),
            Err(VaultError::InvalidPassword)
        ));

        // Unlock with 24-word mnemonic & reset master password without re-encrypting records.
        store.unlock_with_mnemonic(&init.mnemonic).unwrap();
        store
            .reset_master_password("Brand-New-Password-2@")
            .unwrap();
        store.lock();

        // Old password no longer works; new password unlocks existing data intact.
        assert!(
            store
                .unlock_with_password("Correct-Horse-Battery-1!")
                .is_err()
        );
        store.unlock_with_password("Brand-New-Password-2@").unwrap();
        let loaded = store.load_profile(&profile.id).unwrap().unwrap();
        assert_eq!(loaded.name, "Prod Bastion");
        let pw = store.load_password(&profile.id).unwrap().unwrap();
        assert_eq!(pw.password.as_str(), "super-secret-pw");

        // Update profile to verify monotonic revision increments.
        profile.notes = "Updated".into();
        store.save_profile(&profile).unwrap();
        let entry = store
            .manifest()
            .entries
            .get(&RecordKind::Profile.manifest_key(&profile.id))
            .unwrap();
        assert_eq!(entry.revision, 2);
    }

    #[test]
    fn canonical_aad_blocks_file_substitution_and_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = test_store(&dir);
        store.initialize("master-pass-123").unwrap();

        let p1 = Profile {
            name: "Server A".into(),
            host: "a.example.com".into(),
            ..Profile::default()
        };
        let p2 = Profile {
            name: "Server B".into(),
            host: "b.example.com".into(),
            ..Profile::default()
        };
        store.save_profile(&p1).unwrap();
        store.save_profile(&p2).unwrap();

        // Substitution attack: copy Server A's ciphertext file over Server B's path.
        let path_a = store
            .vault_dir()
            .join(RecordKind::Profile.relative_path(&p1.id));
        let path_b = store
            .vault_dir()
            .join(RecordKind::Profile.relative_path(&p2.id));
        std::fs::copy(&path_a, &path_b).unwrap();

        // Loading Server B MUST fail with IntegrityMismatch!
        let err = store.load_profile(&p2.id).unwrap_err();
        assert!(matches!(err, VaultError::IntegrityMismatch(_)));

        // Metadata tamper attack: modify updated_at in Server A's JSON header.
        let mut raw_rec = EncryptedRecord::from_bytes(&std::fs::read(&path_a).unwrap()).unwrap();
        raw_rec.updated_at += 1;
        std::fs::write(&path_a, raw_rec.to_bytes().unwrap()).unwrap();
        let err = store.load_profile(&p1.id).unwrap_err();
        assert!(matches!(err, VaultError::DecryptionFailed));
    }

    #[test]
    fn ssh_keys_deduplicate_by_sha256_and_survive_profile_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = test_store(&dir);
        store.initialize("master-pass-123").unwrap();

        let pem_crlf = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc123\r\n-----END OPENSSH PRIVATE KEY-----\r\n";
        let pem_lf =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\n";

        let (sha1, dedup1) = store
            .import_ssh_key(
                "work-key".into(),
                "SHA256:testfp".into(),
                "ssh-ed25519 AAAA test".into(),
                pem_crlf,
                Some("key-pass".into()),
                false,
            )
            .unwrap();
        assert!(!dedup1);

        let (sha2, dedup2) = store
            .import_ssh_key(
                "work-key-copy".into(),
                "SHA256:testfp".into(),
                "ssh-ed25519 AAAA test".into(),
                pem_lf,
                None,
                true,
            )
            .unwrap();
        assert!(dedup2);
        assert_eq!(sha1, sha2);

        // Attach to profile, then delete profile -> key MUST remain intact (first-class asset).
        let profile = Profile {
            name: "Web 1".into(),
            host: "web1.internal".into(),
            key_sha256: Some(sha1.clone()),
            ..Profile::default()
        };
        store.save_profile(&profile).unwrap();
        store.delete_profile(&profile.id).unwrap();

        assert!(store.load_profile(&profile.id).unwrap().is_none());
        let key = store.load_ssh_key(&sha1).unwrap().unwrap();
        assert_eq!(key.label, "work-key");
        assert_eq!(
            key.passphrase.as_deref().map(String::as_str),
            Some("key-pass")
        );

        // Only explicit user deletion removes the key.
        store.delete_ssh_key(&sha1).unwrap();
        assert!(store.load_ssh_key(&sha1).unwrap().is_none());
    }

    #[test]
    fn local_sync_credentials_round_trip_without_os_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = test_store(&dir);
        store.initialize("portable-pass!").unwrap();

        let creds = LocalSyncCredentials {
            github_pat: Some(Zeroizing::new("ghp_secret_token_12345".into())),
            s3_region: "auto".into(),
            s3_bucket: "rooste-backup".into(),
            ..LocalSyncCredentials::default()
        };
        store.save_local_credentials(&creds).unwrap();

        // Ensure plaintext token is NOT written to disk.
        let disk_text = std::fs::read_to_string(store.location().local_secrets_path()).unwrap();
        assert!(!disk_text.contains("ghp_secret_token_12345"));

        // Re-open in a fresh VaultStore instance (simulating plugging USB into another PC).
        let mut reopened = test_store(&dir);
        reopened.unlock_with_password("portable-pass!").unwrap();
        let loaded = reopened.load_local_credentials().unwrap().unwrap();
        assert_eq!(
            loaded.github_pat.as_deref().map(String::as_str),
            Some("ghp_secret_token_12345")
        );
        assert_eq!(loaded.s3_bucket, "rooste-backup");
    }

    #[test]
    fn full_rekey_rotates_dek_and_invalidates_old_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = test_store(&dir);
        let init1 = store.initialize("old-pw-111").unwrap();

        let profile = Profile {
            name: "Core DB".into(),
            host: "db.internal".into(),
            ..Profile::default()
        };
        store.save_profile(&profile).unwrap();
        store.save_password(&profile.id, "db-secret").unwrap();
        store
            .save_local_credentials(&LocalSyncCredentials {
                github_pat: Some(Zeroizing::new("ghp_pat".into())),
                ..LocalSyncCredentials::default()
            })
            .unwrap();

        let init2 = store.rekey("new-pw-222").unwrap();
        assert_ne!(init1.mnemonic.as_str(), init2.mnemonic.as_str());
        assert_eq!(init1.vault_id, init2.vault_id);

        // Re-open cleanly: old credentials fail, new credentials decrypt everything.
        let mut reopened = test_store(&dir);
        assert!(reopened.unlock_with_password("old-pw-111").is_err());
        assert!(reopened.unlock_with_mnemonic(&init1.mnemonic).is_err());

        reopened.unlock_with_password("new-pw-222").unwrap();
        assert_eq!(
            reopened.load_profile(&profile.id).unwrap().unwrap().name,
            "Core DB"
        );
        assert_eq!(
            reopened
                .load_password(&profile.id)
                .unwrap()
                .unwrap()
                .password
                .as_str(),
            "db-secret"
        );
        assert_eq!(
            reopened
                .load_local_credentials()
                .unwrap()
                .unwrap()
                .github_pat
                .as_deref()
                .map(String::as_str),
            Some("ghp_pat")
        );
    }

    #[test]
    fn deterministic_nonce_is_distinct_across_devices_and_counters() {
        let n1 = deterministic_nonce("device-a", 1);
        let n2 = deterministic_nonce("device-a", 2);
        let n3 = deterministic_nonce("device-b", 1);
        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_eq!(&n1[..4], &n2[..4]);
        assert_ne!(&n1[..4], &n3[..4]);
    }

    proptest! {
        #[test]
        fn sm4_gcm_record_round_trips_arbitrary_payload(
            payload in prop::collection::vec(any::<u8>(), 0..1024),
            counter in 1u64..100_000,
        ) {
            let dek = crypto::generate_dek();
            let nonce = deterministic_nonce("prop-device", counter);
            let rec = EncryptedRecord::seal(
                SealMeta {
                    vault_id: "vault-prop",
                    id: "rec-1",
                    kind: RecordKind::Profile,
                    revision: counter,
                    updated_at: 1_700_000_000_000,
                    base_hash: [0u8; 32],
                    nonce,
                },
                &dek,
                &payload,
            ).unwrap();
            let opened = rec.open("vault-prop", RecordKind::Profile, "rec-1", &dek).unwrap();
            prop_assert_eq!(opened.as_slice(), payload.as_slice());
        }
    }
}
