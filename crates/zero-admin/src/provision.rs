//! Provisioning helpers: the contract the provisioning agent (A1) uses to
//! install `zray-admin`.
//!
//! - [`default_paths`]: canonical on-disk layout.
//! - [`ensure_layout`]: create dirs (0700) and secret files (0600), generating
//!   tokens/keys that are missing. Never prints secrets.
//! - [`unit_file`]: the hardened systemd unit text for `zeronet-admin.service`.
//! - [`migrate_db`]: run schema migrations (re-export of [`crate::db::migrate`]).

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AdminPaths {
    pub etc_dir: PathBuf,   // /etc/zeronet-admin
    pub var_dir: PathBuf,   // /var/lib/zeronet-admin
    pub users_dir: PathBuf, // /etc/zray/users
}

impl AdminPaths {
    pub fn db_path(&self) -> PathBuf {
        self.var_dir.join("admin.db")
    }
    pub fn db_key_path(&self) -> PathBuf {
        self.etc_dir.join("db.key")
    }
    pub fn admin_token_path(&self) -> PathBuf {
        self.etc_dir.join("admin.token")
    }
    pub fn collector_token_path(&self) -> PathBuf {
        self.etc_dir.join("collector.token")
    }
    pub fn config_path(&self) -> PathBuf {
        self.etc_dir.join("config.json")
    }
}

pub fn default_paths() -> AdminPaths {
    AdminPaths {
        etc_dir: PathBuf::from("/etc/zeronet-admin"),
        var_dir: PathBuf::from("/var/lib/zeronet-admin"),
        users_dir: PathBuf::from("/etc/zray/users"),
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Create the on-disk layout. Idempotent: existing secrets are kept.
pub fn ensure_layout(paths: &AdminPaths) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for dir in [&paths.etc_dir, &paths.var_dir, &paths.users_dir] {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if !paths.admin_token_path().exists() {
        write_secret_file(
            &paths.admin_token_path(),
            crate::crypto::new_token().as_bytes(),
        )?;
    }
    if !paths.collector_token_path().exists() {
        write_secret_file(
            &paths.collector_token_path(),
            crate::crypto::new_token().as_bytes(),
        )?;
    }
    if !paths.db_key_path().exists() {
        write_secret_file(&paths.db_key_path(), &crate::crypto::new_data_key())?;
    }
    Ok(())
}

/// Hardened systemd unit for `zeronet-admin.service`.
/// Binary path and user are filled in by the caller.
pub fn unit_file(binary: &str, user: &str) -> String {
    format!(
        r#"[Unit]
Description=ZeroNet admin backend (zray-admin)
After=network-online.target zray.service
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
ExecStart={binary} serve
Restart=on-failure
RestartSec=5

# Hardening (Design C section 8)
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/zeronet-admin /etc/zray/users

[Install]
WantedBy=multi-user.target
"#
    )
}

pub fn migrate_db(db_path: &Path) -> Result<(), crate::db::DbError> {
    let conn = crate::db::open(db_path)?;
    drop(conn);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_idempotent_and_600() {
        let root = crate::test_temp_dir("zero-admin-layout");
        let paths = AdminPaths {
            etc_dir: root.join("etc"),
            var_dir: root.join("var"),
            users_dir: root.join("users"),
        };
        ensure_layout(&paths).unwrap();
        let token1 = std::fs::read(paths.admin_token_path()).unwrap();
        ensure_layout(&paths).unwrap();
        let token2 = std::fs::read(paths.admin_token_path()).unwrap();
        assert_eq!(token1, token2, "existing secrets must be kept");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.admin_token_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let mode = std::fs::metadata(&paths.var_dir)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unit_file_has_hardening() {
        let u = unit_file("/usr/local/bin/zray-admin", "zray-admin");
        for directive in [
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "PrivateTmp=true",
            "UMask=0077",
            "MemoryDenyWriteExecute=true",
        ] {
            assert!(u.contains(directive), "missing {directive}");
        }
        assert!(u.contains("ExecStart=/usr/local/bin/zray-admin serve"));
    }
}
