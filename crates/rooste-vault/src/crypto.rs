//! Cryptographic primitives for Rooste Vault:
//! - National standard **SM4-GCM** (`aes-gcm::AesGcm<sm4::Sm4, U12>`)
//! - **Deterministic composite 96-bit Nonce** (`SHA-256(device_id)[0..4] || u64_be(counter)`)
//! - **Argon2id** (`m = 64 MiB, t = 3, p = 4`) for master password KEK derivation
//! - **HKDF-SHA256** for BIP-39 mnemonic recovery KEK and local sync credentials subkey
//! - **BIP-39** standard 24-word English mnemonic generation, validation, and word lookup

use aes_gcm::{AeadInOut, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sm4::Sm4;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// National standard SM4 block cipher in GCM authenticated encryption mode (128-bit key, 96-bit nonce, 128-bit tag).
pub type Sm4Gcm = aes_gcm::AesGcm<Sm4, aes_gcm::aead::consts::U12>;

const RECOVERY_HKDF_INFO: &[u8] = b"rooste-vault-recovery-v1";
const LOCAL_SECRETS_HKDF_INFO: &[u8] = b"rooste-ssh-local-secrets-v1";

/// Persisted Argon2id parameters stored in `vault.json` so parameters can be upgraded smoothly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 65536 = 64 MiB).
    pub m_cost: u32,
    /// Iteration count (default: 3).
    pub t_cost: u32,
    /// Parallelism lanes (default: 4).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl Argon2Params {
    /// Lightweight preset for unit/GUI tests so test suites complete rapidly.
    pub fn fast_for_tests() -> Self {
        Self {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// Generate a random 16-byte (128-bit) SM4 Data Encryption Key (DEK).
pub fn generate_dek() -> Zeroizing<[u8; 16]> {
    Zeroizing::new(rand::random::<[u8; 16]>())
}

/// Generate a random 16-byte salt.
pub fn generate_salt() -> [u8; 16] {
    rand::random::<[u8; 16]>()
}

/// Generate a random 12-byte nonce (used strictly for one-shot KEK slot wrapping where each KEK has a fresh random salt).
pub fn generate_slot_nonce() -> [u8; 12] {
    rand::random::<[u8; 12]>()
}

/// Build the deterministic composite 12-byte SM4-GCM nonce:
/// `SHA-256(device_id)[0..4] || u64_be(monotonic_counter)`.
///
/// Guarantees uniqueness across both offline multi-device concurrent writes and sequential
/// local encryptions under the same DEK.
pub fn deterministic_nonce(device_id: &str, counter: u64) -> [u8; 12] {
    let prefix = Sha256::digest(device_id.as_bytes());
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix[..4]);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Compute raw 32-byte SHA-256 digest.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Compute lowercase 64-character hexadecimal SHA-256 digest.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_bytes(data))
}

/// Derive a 16-byte KEK from the user's master password using Argon2id.
pub fn derive_password_kek(
    password: &str,
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 16]>, VaultError> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(16))
        .map_err(|e| VaultError::KdfFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = Zeroizing::new([0u8; 16]);
    argon2
        .hash_password_into(password.as_bytes(), salt, kek.as_mut())
        .map_err(|e| VaultError::KdfFailed(e.to_string()))?;
    Ok(kek)
}

/// Derive a 16-byte recovery KEK from 32-byte BIP-39 raw entropy via HKDF-SHA256.
pub fn derive_mnemonic_kek(
    entropy_32: &[u8; 32],
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 16]>, VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), entropy_32);
    let mut kek = Zeroizing::new([0u8; 16]);
    hk.expand(RECOVERY_HKDF_INFO, kek.as_mut())
        .map_err(|e| VaultError::KdfFailed(e.to_string()))?;
    Ok(kek)
}

/// Derive the machine-local subkey `K_local` from `DEK` and `device_id` to encrypt
/// `<ROOSTE_ROOT>/local_secrets.enc` (replacing OS Keyring cleanly in standard & portable modes).
pub fn derive_local_secrets_key(
    dek: &[u8; 16],
    device_id: &str,
) -> Result<Zeroizing<[u8; 16]>, VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(device_id.as_bytes()), dek);
    let mut key = Zeroizing::new([0u8; 16]);
    hk.expand(LOCAL_SECRETS_HKDF_INFO, key.as_mut())
        .map_err(|e| VaultError::KdfFailed(e.to_string()))?;
    Ok(key)
}

/// Encrypt `plaintext` using SM4-GCM with `key`, 12-byte `nonce`, and associated authenticated data `aad`.
pub fn seal_sm4_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = Sm4Gcm::new(key.into());
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce.into(), aad, &mut buffer)
        .map_err(|_| VaultError::EncryptionFailed)?;
    Ok(buffer)
}

/// Authenticate and decrypt `ciphertext` (which includes the 16-byte GCM tag) using SM4-GCM.
pub fn open_sm4_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let cipher = Sm4Gcm::new(key.into());
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(nonce.into(), aad, &mut *buffer)
        .map_err(|_| VaultError::DecryptionFailed)?;
    Ok(buffer)
}

/// Generate 32 bytes (256-bit) of fresh entropy and encode it as a standard 24-word English BIP-39 mnemonic.
pub fn generate_mnemonic() -> Result<(Zeroizing<[u8; 32]>, Zeroizing<String>), VaultError> {
    let entropy = Zeroizing::new(rand::random::<[u8; 32]>());
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
        .map_err(|e| VaultError::InvalidMnemonic(e.to_string()))?;
    let phrase = Zeroizing::new(mnemonic.to_string());
    Ok((entropy, phrase))
}

/// Parse, checksum-verify, and decode a 24-word English BIP-39 mnemonic back into its 32-byte raw entropy.
pub fn parse_mnemonic(phrase: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let normalized: String = phrase
        .split_whitespace()
        .map(|w| w.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map_err(|e| VaultError::InvalidMnemonic(e.to_string()))?;
    let raw = mnemonic.to_entropy();
    if raw.len() != 32 {
        return Err(VaultError::InvalidMnemonic(format!(
            "expected 24-word mnemonic (32 bytes entropy), got {} bytes",
            raw.len()
        )));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Return BIP-39 English dictionary suggestions matching `prefix` (for recovery UI autocomplete).
pub fn suggest_mnemonic_words(prefix: &str) -> Vec<&'static str> {
    let lower = prefix.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Vec::new();
    }
    Language::English
        .words_by_prefix_iter(&lower)
        .take(6)
        .collect()
}

/// Estimate password strength on a 0..=4 scale for onboarding UI feedback.
pub fn password_strength_score(password: &str) -> u8 {
    let len = password.chars().count();
    if len == 0 {
        return 0;
    }
    let mut classes = 0u8;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace())
    {
        classes += 1;
    }
    match (len, classes) {
        (0..=5, _) => 1,
        (6..=9, 0..=1) => 1,
        (6..=9, _) => 2,
        (10..=11, 0..=2) => 2,
        (10..=11, _) => 3,
        (12..=15, 0..=1) => 2,
        (12..=15, 2) => 3,
        (12..=15, _) => 4,
        (_, 0..=1) => 3,
        _ => 4,
    }
}
