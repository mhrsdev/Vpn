//! Admin service configuration.
//!
//! On a provisioned server this is read from `/etc/zeronet-admin/config.json`
//! (written by the provisioning agent). Tests use [`AdminConfig::test`].

use crate::secrets::SecretString;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerRole {
    Gateway,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminMode {
    /// Authoritative DB, panel enabled.
    Primary,
    /// Forwards aggregates to the primary; panel disabled.
    Collector,
}

impl std::fmt::Display for ServerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerRole::Gateway => write!(f, "gateway"),
            ServerRole::Exit => write!(f, "exit"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub role: ServerRole,
    pub mode: AdminMode,
    /// Loopback API + panel listener. Never a public address for the API.
    pub listen: SocketAddr,
    /// Optional public subscription listener (`GET /s/{token}` only).
    /// Default off.
    pub sub_listen: Option<SocketAddr>,
    pub db_path: PathBuf,
    pub db_key: [u8; 32],
    pub admin_token: SecretString,
    pub collector_token: Option<SecretString>,
    /// Where `/etc/zray/users/<tag>.json` files are written.
    pub users_dir: PathBuf,
    /// Engine loopback management API.
    pub engine_mgmt: SocketAddr,
    pub engine_token: SecretString,
    /// Per-install salt shared with the engine for identity HMACs.
    pub usage_salt: [u8; 32],
    /// Gateway mode: where to POST aggregates (`http://<exit>:18081`).
    pub collector_target: Option<String>,
    pub poll_interval_secs: u64,
    pub install_id: String,
    /// Public host used in personal subscription URLs.
    pub exit_host: Option<String>,
    pub sub_port: u16,
    pub version: String,
    pub started_at: u64,
}

impl AdminConfig {
    /// Test configuration: temp paths, ephemeral ports, fixed secrets.
    /// Available to integration tests as well (never used in production paths).
    pub fn test(dir: &std::path::Path) -> Self {
        use crate::crypto::{new_data_key, new_token};
        Self {
            role: ServerRole::Exit,
            mode: AdminMode::Primary,
            listen: "127.0.0.1:0".parse().unwrap(),
            sub_listen: None,
            db_path: dir.join("admin.db"),
            db_key: new_data_key(),
            admin_token: SecretString::new(new_token()),
            collector_token: Some(SecretString::new(new_token())),
            users_dir: dir.join("users"),
            engine_mgmt: "127.0.0.1:1".parse().unwrap(),
            engine_token: SecretString::new(new_token()),
            usage_salt: new_data_key(),
            collector_target: None,
            poll_interval_secs: 60,
            install_id: "test-install".to_string(),
            exit_host: Some("203.0.113.7".to_string()),
            sub_port: 18443,
            version: "0.1.0-test".to_string(),
            started_at: 1798765400,
        }
    }

    /// On-disk shape written by provisioning (`/etc/zeronet-admin/config.json`).
    /// Secrets live in separate 0600 files, never in this JSON.
    pub fn on_disk(&self) -> OnDiskConfig {
        OnDiskConfig {
            role: self.role,
            mode: self.mode,
            listen: self.listen,
            sub_listen: self.sub_listen,
            engine_mgmt: self.engine_mgmt,
            collector_target: self.collector_target.clone(),
            poll_interval_secs: self.poll_interval_secs,
            install_id: self.install_id.clone(),
            exit_host: self.exit_host.clone(),
            sub_port: self.sub_port,
            usage_salt_hex: hex::encode(self.usage_salt),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskConfig {
    pub role: ServerRole,
    pub mode: AdminMode,
    pub listen: SocketAddr,
    pub sub_listen: Option<SocketAddr>,
    pub engine_mgmt: SocketAddr,
    pub collector_target: Option<String>,
    pub poll_interval_secs: u64,
    pub install_id: String,
    pub exit_host: Option<String>,
    pub sub_port: u16,
    pub usage_salt_hex: String,
}
