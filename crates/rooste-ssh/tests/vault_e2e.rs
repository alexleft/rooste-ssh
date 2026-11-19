//! End-to-end GUI & visual verification tests for the Vault Managed SSH Keys UI.

use std::path::PathBuf;
use std::sync::Arc;

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use rooste_core::{Config, ConfigLocation, MemoryStore};
use rooste_keys::{KeyType, generate, to_openssh_pem};
use rooste_ssh::RoosteApp;
use rooste_ssh::vault_ui::{KeysPane, VaultModal};
use rooste_vault::Argon2Params;

fn settle(harness: &mut Harness<'_, RoosteApp>) {
    for _ in 0..4 {
        harness.step();
    }
}

fn screenshot_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/screenshots");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn e2e_managed_ssh_keys_import_browse_detail_generate_rename_delete() {
    let dir = tempfile::tempdir().unwrap();
    let loc = ConfigLocation::for_root(dir.path().to_path_buf(), true);

    // Pre-initialize a real SM4-GCM vault with fast KDF so the E2E test runs quickly.
    {
        let mut store = rooste_vault::VaultStore::open(loc.clone())
            .unwrap()
            .with_kdf_params(Argon2Params::fast_for_tests());
        store.initialize("Test-Master-Pass-1!").unwrap();
    }

    // Create a realistic local private key file on disk to pick via "Browse…".
    let disk_key = generate(KeyType::Ed25519, "alex@qcloud").unwrap();
    let disk_key_pem = to_openssh_pem(&disk_key, None).unwrap();
    let disk_key_path = dir.path().join("qcloud_kapros");
    std::fs::write(&disk_key_path, disk_key_pem.as_str()).unwrap();

    let app = RoosteApp::with_config(
        Config::default(),
        Some(loc.path.clone()),
        Arc::new(MemoryStore::default()),
    )
    .with_vault(loc);

    let mut harness = Harness::builder()
        .with_size([960.0, 620.0])
        .build_ui_state(|ui, app: &mut RoosteApp| app.show(ui), app);
    rooste_ssh::fonts::install(&harness.ctx);
    settle(&mut harness);

    // 1. Unlock the vault via Lock Screen modal by typing directly without clicking
    //    (verifies the master password input receives keyboard focus automatically on startup!).
    harness.event(egui::Event::Text("Test-Master-Pass-1!".into()));
    harness.key_press(egui::Key::Enter);
    settle(&mut harness);
    assert!(harness.state().vault.as_ref().unwrap().unlocked);

    // 2. Open Managed SSH Keys via toolbar button ("🔑 Keys").
    harness.get_by_label("🔑 Keys").click();
    settle(&mut harness);

    // Since vault has 0 keys initially, right pane starts on Import.
    assert!(matches!(
        harness.state().vault.as_ref().unwrap().modal,
        Some(VaultModal::KeysManager(ref km)) if matches!(km.pane, KeysPane::Import)
    ));

    // 3. Use "Browse…" native file picker inside the KeysManager modal to choose the local key file.
    harness.state_mut().picker.fake_answer = Some(disk_key_path.clone());
    harness.get_all_by_label("Browse…").last().unwrap().click();
    settle(&mut harness);

    // Verify Browse… populated path, auto-filled label, and live-validated the key.
    {
        let modal = harness
            .state()
            .vault
            .as_ref()
            .unwrap()
            .modal
            .as_ref()
            .unwrap();
        let VaultModal::KeysManager(km) = modal else {
            panic!("expected KeysManager");
        };
        assert_eq!(km.import_path, disk_key_path.display().to_string());
        assert_eq!(km.import_label, "qcloud_kapros");
        assert!(matches!(km.import_inspection, Some(Ok(_))));
    }

    // Render Import view screenshot if wgpu is available.
    if let Ok(img) = harness.render() {
        let _ = img.save(screenshot_dir().join("vault_keys_import.png"));
    }

    // 4. Click "Import & Deduplicate into Vault".
    harness
        .get_by_label("Import & Deduplicate into Vault")
        .click();
    settle(&mut harness);

    // Verify key is in managed_keys with real fingerprint & public key, and Detail pane opened.
    let imported_sha = {
        let vault = harness.state().vault.as_ref().unwrap();
        assert_eq!(vault.managed_keys.len(), 1);
        let k = &vault.managed_keys[0];
        assert_eq!(k.label, "qcloud_kapros");
        assert!(k.fingerprint.starts_with("SHA256:"));
        assert!(k.public_key.starts_with("ssh-ed25519 "));
        assert!(matches!(
            vault.modal,
            Some(VaultModal::KeysManager(ref km)) if matches!(km.pane, KeysPane::Detail(ref s) if s == &k.sha256)
        ));
        k.sha256.clone()
    };

    // Render Detail view screenshot!
    if let Ok(img) = harness.render() {
        let _ = img.save(screenshot_dir().join("vault_keys_detail.png"));
    }

    // 5. Switch to "+ Generate", verify passphrase mismatch check, then generate a new key.
    harness.get_by_label("+ Generate").click();
    settle(&mut harness);
    if let Ok(img) = harness.render() {
        let _ = img.save(screenshot_dir().join("vault_keys_generate.png"));
    }
    {
        let Some(VaultModal::KeysManager(ref mut km)) =
            harness.state_mut().vault.as_mut().unwrap().modal
        else {
            panic!("expected KeysManager");
        };
        km.gen_label = "prod-bastion-ed25519".into();
        *km.gen_passphrase = "secret-pass".into();
        *km.gen_confirm_passphrase = "mismatch".into();
    }
    settle(&mut harness);
    harness.get_by_label("✨ Generate & Save to Vault").click();
    settle(&mut harness);
    {
        let Some(VaultModal::KeysManager(ref mut km)) =
            harness.state_mut().vault.as_mut().unwrap().modal
        else {
            panic!("expected KeysManager");
        };
        assert!(km.error.as_deref().unwrap_or("").contains("match"));
        *km.gen_confirm_passphrase = "secret-pass".into();
        km.gen_require_prompt = true;
    }
    settle(&mut harness);
    harness.get_by_label("✨ Generate & Save to Vault").click();
    settle(&mut harness);

    assert_eq!(
        harness.state().vault.as_ref().unwrap().managed_keys.len(),
        2
    );

    // Render Detail view with 2 keys in the left sidebar!
    if let Ok(img) = harness.render() {
        let _ = img.save(screenshot_dir().join("vault_keys_detail_two.png"));
    }

    // 6. Export .pub via native SaveFile picker.
    let export_pub_path = dir.path().join("exported.pub");
    harness.state_mut().picker.fake_answer = Some(export_pub_path.clone());
    harness.get_by_label("💾 Export .pub…").click();
    settle(&mut harness);
    assert!(export_pub_path.exists());
    assert!(
        std::fs::read_to_string(&export_pub_path)
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );

    // 7. Rename the generated key and verify the sidebar updates.
    {
        let Some(VaultModal::KeysManager(ref mut km)) =
            harness.state_mut().vault.as_mut().unwrap().modal
        else {
            panic!("expected KeysManager");
        };
        km.detail_label = "prod-bastion-renamed".into();
    }
    settle(&mut harness);
    harness.get_by_label("Rename").click();
    settle(&mut harness);
    assert!(
        harness
            .state()
            .vault
            .as_ref()
            .unwrap()
            .managed_keys
            .iter()
            .any(|k| k.label == "prod-bastion-renamed")
    );

    // 8. Export private key: must require vault master password verification first!
    let export_priv_path = dir.path().join("exported_private_key");
    harness.state_mut().picker.fake_answer = Some(export_priv_path.clone());
    harness.get_by_label("💾 Export Private Key…").click();
    settle(&mut harness);
    // File MUST NOT be written before verifying the master password.
    assert!(!export_priv_path.exists());
    // Render screenshot of the step-up password verification prompt.
    if let Ok(img) = harness.render() {
        let _ = img.save(screenshot_dir().join("vault_keys_export_auth.png"));
    }

    // Wrong password must fail and NOT export the key.
    {
        let Some(VaultModal::KeysManager(ref mut km)) =
            harness.state_mut().vault.as_mut().unwrap().modal
        else {
            panic!("expected KeysManager");
        };
        *km.export_vault_password = "Wrong-Master-Pass!".into();
    }
    settle(&mut harness);
    harness.get_by_label("🔒 Verify & Export…").click();
    settle(&mut harness);
    assert!(!export_priv_path.exists());
    {
        let Some(VaultModal::KeysManager(ref mut km)) =
            harness.state_mut().vault.as_mut().unwrap().modal
        else {
            panic!("expected KeysManager");
        };
        assert!(
            km.error
                .as_deref()
                .unwrap_or("")
                .contains("Incorrect vault master password")
        );
        assert!(km.export_vault_password.is_empty());
        // Now supply the real vault master password.
        *km.export_vault_password = "Test-Master-Pass-1!".into();
    }
    settle(&mut harness);
    harness.get_by_label("🔒 Verify & Export…").click();
    settle(&mut harness);
    assert!(export_priv_path.exists());
    let exported_pem = std::fs::read_to_string(&export_priv_path).unwrap();
    assert!(exported_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&export_priv_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // 9. Switch back to the first imported key and delete it with confirmation.
    {
        let Some(VaultModal::KeysManager(ref mut km)) =
            harness.state_mut().vault.as_mut().unwrap().modal
        else {
            panic!("expected KeysManager");
        };
        km.select_detail(imported_sha);
    }
    settle(&mut harness);
    harness.get_by_label("🗑 Delete Key").click();
    settle(&mut harness);
    if let Ok(img) = harness.render() {
        let _ = img.save(screenshot_dir().join("vault_keys_delete_confirm.png"));
    }
    harness.get_by_label("Confirm Delete Key").click();
    settle(&mut harness);
    assert_eq!(
        harness.state().vault.as_ref().unwrap().managed_keys.len(),
        1
    );
}
