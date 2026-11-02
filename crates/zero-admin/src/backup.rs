//! Encrypted backup & restore.
//!
//! Format: `ZABK1\0\0\0` (8-byte magic) || salt(16) || nonce(24) ||
//! XChaCha20-Poly1305(DB bytes), key = argon2id(passphrase, salt).
//! Wrong passphrase → clean error, no partial restore. The token URL hashes
//! are backed up; the plaintext tokens are not (they only ever live in
//! 0600 files, never in the DB).

use crate::crypto::{backup_kdf, backup_kdf_with_salt, open, seal, CryptoError};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad backup: {0}")]
    BadBackup(String),
    #[error("wrong passphrase or corrupted backup")]
    WrongPassphrase,
}

const MAGIC: &[u8; 8] = b"ZABK1\0\0\0";

/// Create an encrypted backup of the DB file at `db_path`.
pub fn create_backup(db_path: &Path, passphrase: &str) -> Result<Vec<u8>, BackupError> {
    if passphrase.len() < 8 {
        return Err(BackupError::BadBackup(
            "passphrase must be at least 8 characters".to_string(),
        ));
    }
    let db_bytes = std::fs::read(db_path)?;
    let (key, salt) = backup_kdf(passphrase)?;
    let sealed = seal(&key, &db_bytes)?;
    // sealed = nonce(24) || ct; split them for the header layout.
    let mut out = Vec::with_capacity(8 + 16 + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decrypt a backup blob; returns the raw DB bytes. Does not touch disk.
pub fn decrypt_backup(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    if blob.len() < 8 + 16 + 24 + 16 || &blob[..8] != MAGIC {
        return Err(BackupError::BadBackup(
            "not a zray-admin backup".to_string(),
        ));
    }
    let salt: [u8; 16] = blob[8..24].try_into().unwrap();
    let key = backup_kdf_with_salt(passphrase, &salt).map_err(|_| BackupError::WrongPassphrase)?;
    open(&key, &blob[24..]).map_err(|_| BackupError::WrongPassphrase)
}

/// Verify decrypted bytes look like a SQLite database.
pub fn looks_like_sqlite(db_bytes: &[u8]) -> bool {
    db_bytes.len() > 100 && &db_bytes[..16] == b"SQLite format 3\0"
}

/// Restore: decrypt → sanity-check → atomic replace of the DB file.
/// Returns the number of DB bytes restored.
pub fn restore_backup(db_path: &Path, blob: &[u8], passphrase: &str) -> Result<usize, BackupError> {
    let db_bytes = decrypt_backup(blob, passphrase)?;
    if !looks_like_sqlite(&db_bytes) {
        return Err(BackupError::BadBackup(
            "decrypted payload is not a SQLite database".to_string(),
        ));
    }
    // Keep one pre-restore copy.
    if db_path.exists() {
        let prev = db_path.with_extension("db.pre-restore");
        std::fs::copy(db_path, prev)?;
    }
    let tmp = db_path.with_extension("db.restore-tmp");
    std::fs::write(&tmp, &db_bytes)?;
    std::fs::rename(&tmp, db_path)?;
    Ok(db_bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    // Simpler: return path + a cleanup closure is awkward; use a struct.
    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn backup_round_trip() {
        let dir = TempDir(crate::test_temp_dir("zero-admin-backup"));
        let path = dir.0.join("admin.db");
        {
            let conn = db::open(&path).unwrap();
            crate::store::create_user(
                &conn,
                &crate::store::User {
                    id: "u1".into(),
                    name: "Backup User".into(),
                    note: String::new(),
                    created_at: 1,
                    expires_at: None,
                    revoked: false,
                    quota_bytes: None,
                    quota_mbps: None,
                    max_devices: 8,
                },
            )
            .unwrap();
        }
        let blob = create_backup(&path, "correct-passphrase").unwrap();
        assert_eq!(&blob[..8], MAGIC);
        // The plaintext user name must not appear in the blob.
        assert!(!blob.windows(11).any(|w| w == b"Backup User"));

        let db_bytes = decrypt_backup(&blob, "correct-passphrase").unwrap();
        assert!(looks_like_sqlite(&db_bytes));

        // Wrong passphrase: clean error.
        assert!(matches!(
            decrypt_backup(&blob, "wrong-passphrase").unwrap_err(),
            BackupError::WrongPassphrase
        ));
        // Garbage: bad backup error.
        assert!(matches!(
            decrypt_backup(b"garbage", "correct-passphrase").unwrap_err(),
            BackupError::BadBackup(_)
        ));
        // Short passphrase refused.
        assert!(create_backup(&path, "short").is_err());

        // Restore round-trip: wipe the DB, restore, user is back.
        std::fs::write(&path, b"junk").unwrap();
        let n = restore_backup(&path, &blob, "correct-passphrase").unwrap();
        assert!(n > 100);
        let conn = db::open(&path).unwrap();
        let u = crate::store::get_user(&conn, "u1").unwrap();
        assert_eq!(u.name, "Backup User");
    }
}
