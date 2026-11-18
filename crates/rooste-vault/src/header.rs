//! Dual-slot key envelope (`vault/vault.json`):
//! - Slot 1 (`password_slot`): Argon2id KEK wrapping the 16-byte SM4 DEK.
//! - Slot 2 (`recovery_slot`): BIP-39 24-word mnemonic entropy -> HKDF-SHA256 KEK wrapping the same DEK.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{
    Argon2Params, derive_mnemonic_kek, derive_password_kek, generate_dek, generate_mnemonic,
    generate_salt, generate_slot_nonce, open_sm4_gcm, parse_mnemonic, seal_sm4_gcm,
};
use crate::error::VaultError;

/// Current `vault.json` header format version.
pub const VAULT_HEADER_VERSION: u8 = 1;

const PASSWORD_SLOT_AAD: &[u8] = b"password_slot:v1";
const RECOVERY_SLOT_AAD: &[u8] = b"recovery_slot:v1";

/// Public key-wrapping header stored at `vault/vault.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Protocol version (currently `1`).
    pub version: u8,
    /// Stable unique identifier of this vault, bound into every record's Canonical AAD.
    pub vault_id: String,
    /// Persisted Argon2id parameters for `password_slot`.
    pub kdf: Argon2Params,
    /// Slot 1: Master password KEK wrapping `DEK`.
    pub password_slot: KeySlot,
    /// Slot 2: 24-word BIP-39 recovery mnemonic KEK wrapping `DEK`.
    pub recovery_slot: KeySlot,
}

/// Encrypted key-wrapping slot inside `vault.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlot {
    pub salt: [u8; 16],
    /// SM4-GCM 12-byte nonce.
    pub nonce: [u8; 12],
    /// 16-byte DEK encrypted with SM4-GCM + 16-byte GCM authentication tag (32 bytes total).
    pub wrapped_dek: Vec<u8>,
}

/// Newly initialized vault header together with its unlocked DEK and 24-word mnemonic.
pub type CreatedVaultHeader = (VaultHeader, Zeroizing<[u8; 16]>, Zeroizing<String>);

impl VaultHeader {
    /// Initialize a brand-new vault header with a random 16-byte DEK and a fresh 24-word English BIP-39 mnemonic.
    ///
    /// Returns `(header, dek, mnemonic_phrase)`.
    pub fn create(
        master_password: &str,
        kdf: Argon2Params,
    ) -> Result<CreatedVaultHeader, VaultError> {
        let dek = generate_dek();
        let (entropy, phrase) = generate_mnemonic()?;

        let password_slot = wrap_password_slot(master_password, &dek, kdf)?;
        let recovery_slot = wrap_recovery_slot(&entropy, &dek)?;

        let header = Self {
            version: VAULT_HEADER_VERSION,
            vault_id: Uuid::new_v4().to_string(),
            kdf,
            password_slot,
            recovery_slot,
        };
        Ok((header, dek, phrase))
    }

    /// Re-key an existing vault ID with a brand-new DEK and brand-new 24-word mnemonic.
    pub fn create_for_rekey(
        vault_id: String,
        master_password: &str,
        kdf: Argon2Params,
    ) -> Result<CreatedVaultHeader, VaultError> {
        let (mut header, dek, phrase) = Self::create(master_password, kdf)?;
        header.vault_id = vault_id;
        Ok((header, dek, phrase))
    }

    /// Validate version compatibility.
    pub fn check_version(&self) -> Result<(), VaultError> {
        if self.version != VAULT_HEADER_VERSION {
            return Err(VaultError::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    /// Unlock `DEK` using the user's master password via `password_slot`.
    pub fn unlock_with_password(
        &self,
        master_password: &str,
    ) -> Result<Zeroizing<[u8; 16]>, VaultError> {
        self.check_version()?;
        let kek = derive_password_kek(master_password, &self.password_slot.salt, self.kdf)?;
        let raw = open_sm4_gcm(
            &kek,
            &self.password_slot.nonce,
            PASSWORD_SLOT_AAD,
            &self.password_slot.wrapped_dek,
        )
        .map_err(|_| VaultError::InvalidPassword)?;
        bytes_to_dek(&raw)
    }

    /// Unlock `DEK` using the 24-word BIP-39 recovery mnemonic via `recovery_slot`.
    pub fn unlock_with_mnemonic(&self, phrase: &str) -> Result<Zeroizing<[u8; 16]>, VaultError> {
        self.check_version()?;
        let entropy = parse_mnemonic(phrase)?;
        let kek = derive_mnemonic_kek(&entropy, &self.recovery_slot.salt)?;
        let raw = open_sm4_gcm(
            &kek,
            &self.recovery_slot.nonce,
            RECOVERY_SLOT_AAD,
            &self.recovery_slot.wrapped_dek,
        )
        .map_err(|_| VaultError::InvalidMnemonic("mnemonic does not match this vault".into()))?;
        bytes_to_dek(&raw)
    }

    /// Replace `password_slot` with a new master password wrapping the existing `DEK`.
    /// No `.enc` data files need to be re-encrypted.
    pub fn reset_password_slot(
        &mut self,
        dek: &[u8; 16],
        new_master_password: &str,
        kdf: Argon2Params,
    ) -> Result<(), VaultError> {
        self.check_version()?;
        self.password_slot = wrap_password_slot(new_master_password, dek, kdf)?;
        self.kdf = kdf;
        Ok(())
    }
}

fn wrap_password_slot(
    password: &str,
    dek: &[u8; 16],
    kdf: Argon2Params,
) -> Result<KeySlot, VaultError> {
    let salt = generate_salt();
    let nonce = generate_slot_nonce();
    let kek = derive_password_kek(password, &salt, kdf)?;
    let wrapped_dek = seal_sm4_gcm(&kek, &nonce, PASSWORD_SLOT_AAD, dek)?;
    Ok(KeySlot {
        salt,
        nonce,
        wrapped_dek,
    })
}

fn wrap_recovery_slot(entropy: &[u8; 32], dek: &[u8; 16]) -> Result<KeySlot, VaultError> {
    let salt = generate_salt();
    let nonce = generate_slot_nonce();
    let kek = derive_mnemonic_kek(entropy, &salt)?;
    let wrapped_dek = seal_sm4_gcm(&kek, &nonce, RECOVERY_SLOT_AAD, dek)?;
    Ok(KeySlot {
        salt,
        nonce,
        wrapped_dek,
    })
}

fn bytes_to_dek(raw: &[u8]) -> Result<Zeroizing<[u8; 16]>, VaultError> {
    if raw.len() != 16 {
        return Err(VaultError::IntegrityMismatch(format!(
            "unwrapped DEK length must be 16 bytes, got {}",
            raw.len()
        )));
    }
    let mut dek = Zeroizing::new([0u8; 16]);
    dek.copy_from_slice(raw);
    Ok(dek)
}
