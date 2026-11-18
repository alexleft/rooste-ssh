//! SSH keys: generating them, converting to and from PuTTY's `.ppk` format,
//! and a built-in SSH agent.

pub mod agent;
mod generation;
pub mod ppk;

pub use agent::Agent;
pub use generation::{KeyType, generate, public_line, save_openssh, to_openssh_pem, write_private};
pub use russh::keys::{PrivateKey, PublicKey};

/// Non-secret metadata discovered by inspecting a private key text before decrypting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInspection {
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub is_encrypted: bool,
    pub is_ppk: bool,
    /// True when the source is not already in OpenSSH private key format (e.g. `.ppk`, PKCS#1 RSA, PKCS#8, SEC1).
    pub needs_normalization: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{0}")]
    Key(#[from] russh::keys::ssh_key::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("the key is encrypted; enter its passphrase")]
    Encrypted,
    #[error("wrong passphrase or damaged key file")]
    BadPassphrase,
    #[error("not a supported key: {0}")]
    Unsupported(String),
}

/// SHA-256 fingerprint in OpenSSH format.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
}

/// Inspect a private key string (OpenSSH or PuTTY `.ppk`) without requiring its passphrase.
///
/// Rejects public-key files and unrecognized text with clear errors.
pub fn inspect_key_text(text: &str) -> Result<KeyInspection, KeyError> {
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return Err(KeyError::Unsupported("empty key content".into()));
    }
    if trimmed.starts_with("ssh-")
        || trimmed.starts_with("ecdsa-")
        || trimmed.starts_with("sk-")
        || trimmed.starts_with("---- BEGIN SSH2 PUBLIC KEY")
    {
        return Err(KeyError::Unsupported(
            "this is a public key file; select the private key instead".into(),
        ));
    }
    if trimmed.starts_with("PuTTY-User-Key-File-") {
        let is_encrypted = !trimmed
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("Encryption: none"));
        let algorithm = trimmed
            .lines()
            .next()
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "PuTTY PPK".to_owned());
        if !is_encrypted && let Ok(key) = ppk::import(text, None) {
            let pub_key = key.public_key();
            return Ok(KeyInspection {
                algorithm: pub_key.algorithm().to_string(),
                fingerprint: fingerprint(pub_key),
                public_key: public_line(pub_key),
                is_encrypted: false,
                is_ppk: true,
                needs_normalization: true,
            });
        }
        return Ok(KeyInspection {
            algorithm,
            fingerprint: String::new(),
            public_key: String::new(),
            is_encrypted,
            is_ppk: true,
            needs_normalization: true,
        });
    }
    if !text.contains("PRIVATE KEY-----") {
        return Err(KeyError::Unsupported(
            "file does not look like an OpenSSH, PEM, or PuTTY private key".into(),
        ));
    }
    if let Ok(key) = PrivateKey::from_openssh(text) {
        let pub_key = key.public_key();
        return Ok(KeyInspection {
            algorithm: pub_key.algorithm().to_string(),
            fingerprint: fingerprint(pub_key),
            public_key: public_line(pub_key),
            is_encrypted: key.is_encrypted(),
            is_ppk: false,
            needs_normalization: false,
        });
    }
    // Traditional PEM formats: PKCS#1 (`BEGIN RSA PRIVATE KEY`), SEC1 (`BEGIN EC PRIVATE KEY`),
    // PKCS#8 (`BEGIN PRIVATE KEY` / `BEGIN ENCRYPTED PRIVATE KEY`).
    let is_encrypted = text.contains("BEGIN ENCRYPTED PRIVATE KEY")
        || text.contains("Proc-Type: 4,ENCRYPTED")
        || text.contains("DEK-Info:");
    if !is_encrypted && let Ok(key) = russh::keys::decode_secret_key(text, None) {
        let pub_key = key.public_key();
        return Ok(KeyInspection {
            algorithm: pub_key.algorithm().to_string(),
            fingerprint: fingerprint(pub_key),
            public_key: public_line(pub_key),
            is_encrypted: false,
            is_ppk: false,
            needs_normalization: true,
        });
    }
    let algorithm = if text.contains("BEGIN RSA PRIVATE KEY") {
        "RSA PEM".to_owned()
    } else if text.contains("BEGIN EC PRIVATE KEY") {
        "ECDSA PEM".to_owned()
    } else {
        "PKCS#8 PEM".to_owned()
    };
    Ok(KeyInspection {
        algorithm,
        fingerprint: String::new(),
        public_key: String::new(),
        is_encrypted,
        is_ppk: false,
        needs_normalization: true,
    })
}

/// Load a private key in OpenSSH, traditional PEM (PKCS#1 / PKCS#8 / SEC1), or PuTTY `.ppk` format.
pub fn load(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyError> {
    if text.trim_start().starts_with("PuTTY-User-Key-File-") {
        return ppk::import(text, passphrase);
    }
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        let key = PrivateKey::from_openssh(text)?;
        if !key.is_encrypted() {
            return Ok(key);
        }
        let passphrase = passphrase.ok_or(KeyError::Encrypted)?;
        return key.decrypt(passphrase).map_err(|_| KeyError::BadPassphrase);
    }
    russh::keys::decode_secret_key(text, passphrase).map_err(|e| match e {
        russh::keys::Error::KeyIsEncrypted => {
            if passphrase.is_some() {
                KeyError::BadPassphrase
            } else {
                KeyError::Encrypted
            }
        }
        other => KeyError::Unsupported(other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_and_load_reject_public_key_and_accept_openssh_and_pkcs8() {
        let key = generate(KeyType::Ed25519, "test@unit").unwrap();
        let pub_line = public_line(key.public_key());
        assert!(inspect_key_text(&pub_line).is_err());

        let openssh = to_openssh_pem(&key, None).unwrap();
        let info = inspect_key_text(&openssh).unwrap();
        assert!(!info.is_encrypted);
        assert!(!info.needs_normalization);
        assert_eq!(info.public_key, pub_line);
        let loaded = load(&openssh, None).unwrap();
        assert_eq!(
            fingerprint(loaded.public_key()),
            fingerprint(key.public_key())
        );

        let encrypted = to_openssh_pem(&key, Some("secret-pw")).unwrap();
        let enc_info = inspect_key_text(&encrypted).unwrap();
        assert!(enc_info.is_encrypted);
        assert!(matches!(load(&encrypted, None), Err(KeyError::Encrypted)));
        assert!(matches!(
            load(&encrypted, Some("wrong")),
            Err(KeyError::BadPassphrase)
        ));
        let decrypted = load(&encrypted, Some("secret-pw")).unwrap();
        assert_eq!(
            fingerprint(decrypted.public_key()),
            fingerprint(key.public_key())
        );
    }
}
