//! Headless vault unlocking for `rooste-cli`.
//!
//! Priority order (zero OS Keyring dependency):
//! 1. `ROOSTE_VAULT_PASSWORD` environment variable (CI / scripting).
//! 2. `--vault-password-file <path>` (enforces `0600` permissions on Unix).
//! 3. Interactive hidden TTY prompt via `rpassword`.

use std::path::Path;

use anyhow::{Context, bail};
use rooste_core::{ConfigLocation, Profile};
use rooste_vault::{VaultSshKey, VaultStore};
use zeroize::Zeroizing;

/// Environment variable checked first for non-interactive vault unlocking.
pub const ENV_VAULT_PASSWORD: &str = "ROOSTE_VAULT_PASSWORD";

/// Resolved profile and optional managed SSH key / password loaded from the encrypted vault.
#[derive(Debug)]
pub struct UnlockedVaultProfile {
    pub profile: Profile,
    pub ssh_key: Option<VaultSshKey>,
    pub password: Option<Zeroizing<String>>,
}

/// Unlock the local encrypted vault and locate a saved profile by exact name or UUID.
pub fn load_vault_profile(
    profile_query: &str,
    password_file: Option<&Path>,
) -> anyhow::Result<UnlockedVaultProfile> {
    let location = ConfigLocation::detect();
    let mut store = VaultStore::open(location).context("failed to open vault")?;
    if !store.is_initialized() {
        bail!(
            "no encrypted vault initialized at {}; launch rooste-ssh GUI to create or recover one",
            store.vault_dir().display()
        );
    }

    let master_pw = read_master_password(password_file)?;
    store
        .unlock_with_password(&master_pw)
        .context("failed to unlock vault with master password")?;

    let profiles = store
        .list_profiles()
        .context("failed to list vault profiles")?;
    let profile = profiles
        .into_iter()
        .find(|p| p.id == profile_query || p.name.eq_ignore_ascii_case(profile_query))
        .with_context(|| format!("no saved profile named `{profile_query}` found in vault"))?;

    let ssh_key = match &profile.key_sha256 {
        Some(sha) => store
            .load_ssh_key(sha)
            .with_context(|| format!("failed to decrypt managed SSH key `{sha}`"))?,
        None => None,
    };
    let password = if profile.save_password {
        store
            .load_password(&profile.id)
            .context("failed to decrypt saved profile password")?
            .map(|p| p.password.clone())
    } else {
        None
    };

    store.lock();
    Ok(UnlockedVaultProfile {
        profile,
        ssh_key,
        password,
    })
}

fn read_master_password(password_file: Option<&Path>) -> anyhow::Result<Zeroizing<String>> {
    if let Ok(pw) = std::env::var(ENV_VAULT_PASSWORD)
        && !pw.is_empty()
    {
        return Ok(Zeroizing::new(pw));
    }
    if let Some(path) = password_file {
        check_password_file_permissions(path)?;
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("could not read vault password file {}", path.display()))?;
        let trimmed = raw.trim_end_matches(['\r', '\n']).to_owned();
        if trimmed.is_empty() {
            bail!("vault password file {} is empty", path.display());
        }
        return Ok(Zeroizing::new(trimmed));
    }
    let entered = rpassword::prompt_password("Vault master password: ")
        .context("failed to read vault master password from terminal")?;
    Ok(Zeroizing::new(entered))
}

#[cfg(unix)]
fn check_password_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .with_context(|| format!("could not stat vault password file {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "vault password file {} has insecure permissions {:04o}; set chmod 600",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_password_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
