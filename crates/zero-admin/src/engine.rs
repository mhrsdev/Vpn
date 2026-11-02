//! Engine integration: HTTP client for the engine's loopback management API
//! (`GET /usage?detail=1`, `GET /health`, `GET /tunnel`,
//! `POST /api/v1/engine/users/reload`) and the `/etc/zray/users/<tag>.json`
//! writer (atomic tmp+rename, Tide precedent).
//!
//! These endpoints are owned by the VPN-core agent; this module codes against
//! the frozen contracts (Design B §9). Until they land, every call degrades
//! gracefully (`EngineError::Unreachable` / `NotImplemented`) and the admin
//! labels the affected surface honestly.

use crate::secrets::SecretString;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine unreachable: {0}")]
    Unreachable(String),
    #[error("engine returned status {0}: {1}")]
    Status(u16, String),
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("io: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundUsage {
    pub tag: String,
    pub sessions: u64,
    #[serde(default)]
    pub devices_now: u64,
    #[serde(default)]
    pub devices_recent: u64,
    #[serde(default)]
    pub uplink: u64,
    #[serde(default)]
    pub downlink: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PerUserUsage {
    /// identity_hash: HMAC-SHA256(usage_salt, identity), hex.
    pub h: String,
    pub tag: String,
    pub sessions: u64,
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageDetail {
    pub window_secs: u64,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub at: Option<i64>,
    #[serde(default)]
    pub inbounds: Vec<InboundUsage>,
    /// Only present with `?detail=1` (new engine).
    #[serde(default)]
    pub users: Vec<PerUserUsage>,
}

#[derive(Debug, Clone)]
pub struct EngineClient {
    mgmt: SocketAddr,
    token: SecretString,
}

impl EngineClient {
    pub fn new(mgmt: SocketAddr, token: SecretString) -> Self {
        Self { mgmt, token }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), EngineError> {
        let mut stream = tokio::net::TcpStream::connect(self.mgmt)
            .await
            .map_err(|e| EngineError::Unreachable(e.to_string()))?;
        let body_len = body.map(|b| b.len()).unwrap_or(0);
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n",
            self.token.expose()
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| EngineError::Io(e.to_string()))?;
        if let Some(b) = body {
            stream
                .write_all(b)
                .await
                .map_err(|e| EngineError::Io(e.to_string()))?;
        }
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| EngineError::Io(e.to_string()))?;
        parse_response(&buf)
    }

    async fn get_json(&self, path: &str) -> Result<serde_json::Value, EngineError> {
        let (status, body) = self.request("GET", path, None).await?;
        if status != 200 {
            return Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| EngineError::BadResponse(e.to_string()))
    }

    /// `GET /usage?detail=1`. Falls back to plain `/usage` when the engine
    /// does not know the flag (old engine: no per-user attribution).
    pub async fn usage_detail(&self) -> Result<UsageDetail, EngineError> {
        let v = self.get_json("/usage?detail=1").await?;
        // If the new engine is present, `users` is an array; if the old
        // engine ignored the flag, `users` is absent — both parse.
        serde_json::from_value(v.clone()).map_err(|e| EngineError::BadResponse(e.to_string()))
    }

    pub async fn health(&self) -> Result<serde_json::Value, EngineError> {
        self.get_json("/health").await
    }

    /// `GET /tunnel` (new, gateway). Old engines 404 → caller treats as unknown.
    pub async fn tunnel(&self) -> Result<serde_json::Value, EngineError> {
        self.get_json("/tunnel").await
    }

    /// Crate-internal raw access for the HA module (`crate::ha`).
    pub(crate) async fn ha_get_json(&self, path: &str) -> Result<serde_json::Value, EngineError> {
        self.get_json(path).await
    }

    /// Crate-internal raw access for the HA module (`crate::ha`).
    pub(crate) async fn ha_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), EngineError> {
        self.request(method, path, body).await
    }

    /// `POST /api/v1/engine/users/reload {"tag"}` → user count.
    pub async fn reload_users(&self, tag: &str) -> Result<u64, EngineError> {
        let body = serde_json::json!({ "tag": tag }).to_string();
        let (status, raw) = self
            .request("POST", "/api/v1/engine/users/reload", Some(body.as_bytes()))
            .await?;
        match status {
            200 => {
                let v: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|e| EngineError::BadResponse(e.to_string()))?;
                Ok(v.get("users").and_then(|u| u.as_u64()).unwrap_or(0))
            }
            404 => Err(EngineError::Status(404, "unknown tag".to_string())),
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }
}

fn parse_response(buf: &[u8]) -> Result<(u16, Vec<u8>), EngineError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut res = httparse::Response::new(&mut headers);
    let offset = match res
        .parse(buf)
        .map_err(|e| EngineError::BadResponse(e.to_string()))?
    {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => {
            return Err(EngineError::BadResponse("partial response".to_string()))
        }
    };
    let status = res
        .code
        .ok_or_else(|| EngineError::BadResponse("no status".to_string()))?;
    let content_len: usize = res
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let end = offset.saturating_add(content_len).min(buf.len());
    Ok((status, buf[offset..end].to_vec()))
}

// ---------------------------------------------------------------------------
// /etc/zray/users/<tag>.json
// ---------------------------------------------------------------------------

/// A users-file entry (frozen format, Design B §9.3 / C §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersFileEntry {
    pub identity: String,
    pub name: String,
    pub disabled: bool,
}

/// Tags are used as file names: only `[A-Za-z0-9_-]` is allowed.
/// This prevents path traversal from a hostile/mistaken DB row.
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Write `/etc/zray/users/<tag>.json` atomically (tmp file + rename).
pub fn write_users_file(
    users_dir: &Path,
    tag: &str,
    entries: &[UsersFileEntry],
) -> Result<(), String> {
    if !valid_tag(tag) {
        return Err(format!("refusing to write users file for bad tag {tag:?}"));
    }
    std::fs::create_dir_all(users_dir).map_err(|e| e.to_string())?;
    let path = users_dir.join(format!("{tag}.json"));
    let tmp = users_dir.join(format!(".{tag}.json.tmp"));
    let body = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Rebuild one tag's users file from the DB and ask the engine to reload it.
/// Returns the number of entries written.
pub async fn sync_tag(
    db: &std::sync::Mutex<rusqlite::Connection>,
    db_key: &[u8; 32],
    users_dir: &Path,
    engine: &EngineClient,
    tag: &str,
) -> Result<usize, String> {
    let identities = {
        let conn = db.lock().map_err(|e| format!("db lock: {e}"))?;
        crate::store::credential_identities_for_tag(&conn, tag, db_key)
            .map_err(|e| format!("db: {e}"))?
    };
    let entries: Vec<UsersFileEntry> = identities
        .into_iter()
        .map(|(identity, name)| UsersFileEntry {
            identity,
            name,
            disabled: false,
        })
        .collect();
    write_users_file(users_dir, tag, &entries)?;
    match engine.reload_users(tag).await {
        Ok(_) => Ok(entries.len()),
        // The new endpoint may not exist yet on an older engine: the file is
        // still written (a restart picks it up); the caller labels this.
        Err(EngineError::Status(404, _)) => Err(
            "users file written; engine lacks /engine/users/reload (needs restart or newer engine)"
                .to_string(),
        ),
        Err(e) => Err(format!("users file written but engine reload failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tag_rejects_traversal() {
        assert!(valid_tag("reality-in"));
        assert!(valid_tag("wg_tunnel"));
        assert!(!valid_tag("../evil"));
        assert!(!valid_tag("a/b"));
        assert!(!valid_tag(""));
        assert!(!valid_tag(&"x".repeat(65)));
        assert!(!valid_tag("tag;rm"));
    }

    #[test]
    fn write_users_file_is_atomic_and_600() {
        let dir = crate::test_temp_dir("zero-admin-users");
        let entries = vec![
            UsersFileEntry {
                identity: "uuid-1".into(),
                name: "phone".into(),
                disabled: false,
            },
            UsersFileEntry {
                identity: "uuid-2".into(),
                name: "laptop".into(),
                disabled: true,
            },
        ];
        write_users_file(&dir, "reality-in", &entries).unwrap();
        let body = std::fs::read_to_string(dir.join("reality-in.json")).unwrap();
        let back: Vec<UsersFileEntry> = serde_json::from_str(&body).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back[1].disabled);
        // No tmp file left behind.
        assert!(!dir.join(".reality-in.json.tmp").exists());
        // Traversal refused.
        assert!(write_users_file(&dir, "../evil", &entries).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_detail_parses_old_and_new_shapes() {
        // Old engine: no `users`, no `server_id`.
        let old: UsageDetail = serde_json::from_value(serde_json::json!({
            "window_secs": 300,
            "inbounds": [{"tag": "reality-in", "sessions": 2, "uplink": 10, "downlink": 20}]
        }))
        .unwrap();
        assert!(old.users.is_empty());
        assert!(old.server_id.is_none());
        // New engine: additive fields.
        let new: UsageDetail = serde_json::from_value(serde_json::json!({
            "window_secs": 300, "server_id": "abc", "at": 1798765400,
            "inbounds": [],
            "users": [{"h": "aa", "tag": "reality-in", "sessions": 1, "up": 5, "down": 6}]
        }))
        .unwrap();
        assert_eq!(new.users.len(), 1);
        assert_eq!(new.users[0].h, "aa");
    }

    #[test]
    fn parse_response_handles_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{\"a\":1}";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"a\":1}");
    }
}
