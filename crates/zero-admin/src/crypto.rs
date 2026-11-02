//! Cryptographic primitives for the admin backend.
//!
//! - Panel password: argon2id (OWASP params via [`Argon2::default()`]).
//! - Credential secrets at rest: XChaCha20-Poly1305 with the per-install
//!   data key from `/etc/zeronet-admin/db.key`.
//! - Engine identity join: `HMAC-SHA256(usage_salt, credential_identity)`.
//! - Tokens: 256-bit CSPRNG; stored as SHA-256 hashes.

use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password hashing failed: {0}")]
    Argon(String),
    #[error("encryption failed")]
    Seal,
    #[error("decryption failed")]
    Open,
    #[error("bad key length")]
    KeyLength,
}

/// Hash a panel password with argon2id (OWASP parameters).
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    // Argon2::default() = Argon2id, m=19 MiB, t=2, p=1 (OWASP).
    // The salt is generated internally (password-hash 0.6 API).
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| CryptoError::Argon(e.to_string()))
}

/// Verify a panel password. Wrong passwords get a generic failure; the
/// caller must not distinguish "unknown user" from "bad password".
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Seal `plaintext` with XChaCha20-Poly1305. Output: `nonce(24) || ciphertext`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = Vec::with_capacity(24 + plaintext.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(
        &cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Seal)?,
    );
    Ok(out)
}

/// Open a blob produced by [`seal`].
pub fn open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 24 + 16 {
        return Err(CryptoError::Open);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(&blob[..24]);
    cipher
        .decrypt(nonce, &blob[24..])
        .map_err(|_| CryptoError::Open)
}

/// `HMAC-SHA256(usage_salt, credential_identity)`, hex-encoded.
///
/// This is the join key between engine-reported usage (`GET /usage?detail=1`
/// reports `h`) and `credentials.identity_hash` in the admin DB. The raw
/// identity never crosses the engine→admin boundary in a reversible way.
pub fn identity_hash(usage_salt: &[u8; 32], identity: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(usage_salt).expect("HMAC accepts any key length");
    mac.update(identity.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// 256-bit random token, hex-encoded (admin/collector/panel-session tokens).
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 of a token, hex. Tokens are stored hashed, never plaintext.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// 256-bit random data key (for `/etc/zeronet-admin/db.key`).
pub fn new_data_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// 256-bit random usage salt (per-install, shared with the engine config).
pub fn new_usage_salt() -> [u8; 32] {
    new_data_key()
}

/// Derive a backup-encryption key from a passphrase with argon2id.
/// Returns `(key, salt)`; the salt is stored in the backup header.
pub fn backup_kdf(passphrase: &str) -> Result<([u8; 32], [u8; 16]), CryptoError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = backup_kdf_with_salt(passphrase, &salt)?;
    Ok((key, salt))
}

pub fn backup_kdf_with_salt(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Argon(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
        assert!(!verify_password(
            "correct horse battery staple",
            "not-a-hash"
        ));
    }

    #[test]
    fn seal_open_round_trip() {
        let key = new_data_key();
        let pt = b"credential secret payload";
        let blob = seal(&key, pt).unwrap();
        assert!(blob.len() > pt.len());
        let back = open(&key, &blob).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn open_rejects_tampered_and_wrong_key() {
        let key = new_data_key();
        let other = new_data_key();
        let mut blob = seal(&key, b"data").unwrap();
        assert!(open(&other, &blob).is_err());
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(open(&key, &blob).is_err());
        assert!(open(&key, b"too short").is_err());
    }

    #[test]
    fn identity_hash_is_deterministic_and_salted() {
        let salt = new_usage_salt();
        let other = new_usage_salt();
        let a = identity_hash(&salt, "some-uuid");
        let b = identity_hash(&salt, "some-uuid");
        let c = identity_hash(&other, "some-uuid");
        let d = identity_hash(&salt, "other-uuid");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 64);
        // The raw identity is not recoverable from the hash.
        assert!(!a.contains("some-uuid"));
    }

    #[test]
    fn token_hash_is_one_way() {
        let t = new_token();
        assert_eq!(t.len(), 64);
        let h = token_hash(&t);
        assert_eq!(h.len(), 64);
        assert_ne!(h, t);
        assert!(!h.contains(&t[..8]));
    }

    #[test]
    fn backup_kdf_round_trip() {
        let (key, salt) = backup_kdf("my backup passphrase").unwrap();
        let key2 = backup_kdf_with_salt("my backup passphrase", &salt).unwrap();
        assert_eq!(key, key2);
        let wrong = backup_kdf_with_salt("wrong passphrase", &salt).unwrap();
        assert_ne!(key, wrong);
    }
}
