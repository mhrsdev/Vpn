//! End-to-end API tests: spawn the real HTTP server on an ephemeral
//! loopback port and exercise the frozen REST contract over raw TCP.
//!
//! Covers: auth (401/403/429), CSRF, user/device lifecycle, credential
//! issuance (secrets returned once), reissue rotation, revoke/restore,
//! personal + external subscriptions, quotas, events, backup/restore
//! round-trip, collector auth, and the no-GeoIP assertion.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use zero_admin::api::{self, AppState};
use zero_admin::config::AdminConfig;

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Unique temp dir per test: pid + nanos + atomic counter. Two tests
/// starting in the same nanosecond (real on a busy VM) must not share one
/// directory — `create_dir_all` is idempotent, so a bare-nanos name collides
/// and tests end up sharing one SQLite file.
fn unique_test_dir(prefix: &str) -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let dir = TempDir(std::env::temp_dir().join(format!(
        "{}-{}-{}-{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        CTR.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir_all(&dir.0).unwrap();
    dir
}

/// Read one full HTTP/1.1 request: head until `\r\n\r\n`, then the body per
/// Content-Length. A single `read()` is not enough — under memory pressure
/// the kernel may split even a small loopback write into several segments,
/// and closing a socket with unread received data makes the peer observe
/// RST, which surfaced here as flaky 502s from the engine client.
async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 65536 {
            break;
        }
    }
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let content_len: usize = String::from_utf8_lossy(&buf[..head_end])
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + content_len && buf.len() < 2 * 1024 * 1024 {
        let n = stream.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

struct Client {
    addr: SocketAddr,
    token: String,
}

impl Client {
    fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        auth: bool,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        let mut stream =
            TcpStream::connect_timeout(&self.addr, Duration::from_secs(5)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut head =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        if auth {
            head.push_str(&format!("Authorization: Bearer {}\r\n", self.token));
        }
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\n\r\n",
            body.map(|b| b.len()).unwrap_or(0)
        ));
        stream.write_all(head.as_bytes()).unwrap();
        if let Some(b) = body {
            stream.write_all(b).unwrap();
        }
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        parse(&buf)
    }

    fn get(&self, path: &str) -> (u16, serde_json::Value) {
        let (s, _, b) = self.request("GET", path, &[], None, true);
        (
            s,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }
    fn post(&self, path: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let raw = serde_json::to_vec(body).unwrap();
        let (s, _, b) = self.request(
            "POST",
            path,
            &[("Content-Type", "application/json")],
            Some(&raw),
            true,
        );
        (
            s,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }
    fn noauth(&self, method: &str, path: &str) -> (u16, Vec<u8>) {
        let (s, _, b) = self.request(method, path, &[], None, false);
        (s, b)
    }
    fn put(&self, path: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let raw = serde_json::to_vec(body).unwrap();
        let (s, _, b) = self.request(
            "PUT",
            path,
            &[("Content-Type", "application/json")],
            Some(&raw),
            true,
        );
        (
            s,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }
    fn delete(&self, path: &str) -> (u16, serde_json::Value) {
        let (s, _, b) = self.request("DELETE", path, &[], None, true);
        (
            s,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }
}

fn parse(buf: &[u8]) -> (u16, HashMap<String, String>, Vec<u8>) {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&buf[..head_end]);
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut headers = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    (status, headers, buf[head_end..].to_vec())
}

async fn spawn_server() -> (TempDir, Arc<AppState>, Client) {
    let dir = unique_test_dir("zero-admin-api-test");
    let mut config = AdminConfig::test(&dir.0);
    // Seed one inbound so issuance works.
    let state = AppState::new(config.clone()).unwrap();
    {
        let conn = state.db.lock().unwrap();
        zero_admin::store::upsert_inbound(
            &conn,
            &zero_admin::store::Inbound {
                tag: "reality-in".to_string(),
                protocol: "vless-reality".to_string(),
                server_role: "exit".to_string(),
                host: "203.0.113.7".to_string(),
                port: 443,
                params: serde_json::json!({
                    "sni": "www.example.com",
                    "pbk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                    "sid": "a1b2c3d4",
                }),
                enabled: true,
            },
        )
        .unwrap();
    }
    let token = config.admin_token.expose().to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    config.listen = addr;
    tokio::spawn(api::serve(state.clone(), listener, false));
    // Give the accept loop a moment.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (dir, state, Client { addr, token })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_rejects_missing_and_wrong_tokens() {
    let (_dir, _state, c) = spawn_server().await;
    let (s, _) = c.noauth("GET", "/api/v1/status");
    assert_eq!(s, 401);
    let (s, _, _) = c.request("GET", "/api/v1/status", &[], None, false);
    assert_eq!(s, 401);
    // Wrong token, right shape.
    let mut bad = c.token.clone();
    bad.push('x');
    let bad_client = Client {
        addr: c.addr,
        token: bad,
    };
    let (s, _) = bad_client.get("/api/v1/status");
    assert_eq!(s, 401);
    // Right token works.
    let (s, v) = c.get("/api/v1/status");
    assert_eq!(s, 200);
    assert_eq!(v["role"], "exit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn csrf_blocks_origin_posts() {
    let (_dir, _state, c) = spawn_server().await;
    let (s, _, _) = c.request(
        "POST",
        "/api/v1/users",
        &[
            ("Origin", "https://evil.example"),
            ("Content-Type", "application/json"),
        ],
        Some(br#"{"name":"x"}"#),
        true,
    );
    assert_eq!(s, 403);
    // No Origin: fine.
    let (s, _) = c.post("/api/v1/users", &serde_json::json!({"name": "csrf-ok"}));
    assert_eq!(s, 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_device_credential_lifecycle() {
    let (_dir, state, c) = spawn_server().await;
    // Create user.
    let (s, v) = c.post(
        "/api/v1/users",
        &serde_json::json!({"name": "Ali", "quota_bytes": 1073741824}),
    );
    assert_eq!(s, 201);
    let user_id = v["user"]["id"].as_str().unwrap().to_string();

    // Issue device: secrets come back exactly once.
    let (s, v) = c.post(
        &format!("/api/v1/users/{user_id}/devices"),
        &serde_json::json!({"label": "phone"}),
    );
    assert_eq!(s, 201, "{v}");
    let device_id = v["device"]["id"].as_str().unwrap().to_string();
    let creds = v["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    let link = creds[0]["link"].as_str().unwrap();
    assert!(link.starts_with("vless://"), "{link}");
    assert!(zero_config::parse_link(link).is_ok());
    assert!(creds[0]["qr_svg"].as_str().unwrap().starts_with("<svg"));

    // The users file was written (engine reload fails gracefully: no engine).
    let users_file = state.config.users_dir.join("reality-in.json");
    assert!(users_file.exists(), "users file must be written");
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&users_file).unwrap()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["disabled"], false);

    // GET device metadata: no secrets.
    let (s, v) = c.get(&format!("/api/v1/devices/{device_id}"));
    assert_eq!(s, 200);
    assert!(v["device"].get("secret").is_none());

    // Re-render configs: links again, same identity.
    let (s, v2) = c.get(&format!("/api/v1/devices/{device_id}/configs"));
    assert_eq!(s, 200);
    assert_eq!(
        v2["credentials"][0]["link"].as_str().unwrap(),
        link,
        "re-render must be deterministic"
    );

    // Revoke device: users file rewritten empty, engine reload attempted.
    let (s, _) = c.post(
        &format!("/api/v1/devices/{device_id}/revoke"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&users_file).unwrap()).unwrap();
    assert!(
        entries.is_empty(),
        "revoked device must leave the users file"
    );

    // Restore + reissue rotation.
    let (s, _) = c.post(
        &format!("/api/v1/devices/{device_id}/restore"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let (s, v3) = c.post(
        &format!("/api/v1/devices/{device_id}/reissue"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let link2 = v3["credentials"][0]["link"].as_str().unwrap();
    assert_ne!(link2, link, "reissue must rotate the credential");

    // Revoke the user: cascades to the device.
    let (s, _) = c.post(
        &format!("/api/v1/users/{user_id}/revoke"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let (s, v) = c.get(&format!("/api/v1/devices/{device_id}"));
    assert_eq!(s, 200);
    assert_eq!(v["device"]["revoked"], true);

    // Delete (forget): purges secrets.
    let (s, _, _) = c.request(
        "DELETE",
        &format!("/api/v1/devices/{device_id}"),
        &[],
        None,
        true,
    );
    assert_eq!(s, 200);
    let (s, _) = c.get(&format!("/api/v1/devices/{device_id}"));
    assert_eq!(s, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issuance_refuses_non_issuable_protocol() {
    let (_dir, state, c) = spawn_server().await;
    {
        let conn = state.db.lock().unwrap();
        zero_admin::store::upsert_inbound(
            &conn,
            &zero_admin::store::Inbound {
                tag: "juicity-in".to_string(),
                protocol: "juicity".to_string(), // no server side
                server_role: "exit".to_string(),
                host: "203.0.113.7".to_string(),
                port: 8443,
                params: serde_json::json!({}),
                enabled: true,
            },
        )
        .unwrap();
    }
    let (s, v) = c.post("/api/v1/users", &serde_json::json!({"name": "Bob"}));
    assert_eq!(s, 201);
    let user_id = v["user"]["id"].as_str().unwrap();
    // Explicit request for the non-issuable inbound: honest 400, no fake link.
    let (s, v) = c.post(
        &format!("/api/v1/users/{user_id}/devices"),
        &serde_json::json!({"label": "x", "inbounds": ["juicity-in"]}),
    );
    assert_eq!(s, 400, "{v}");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no server side"));
    // Unknown inbound tag: 400 as well.
    let (s, _) = c.post(
        &format!("/api/v1/users/{user_id}/devices"),
        &serde_json::json!({"label": "x", "inbounds": ["nope"]}),
    );
    assert_eq!(s, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscriptions_personal_and_external() {
    let (_dir, _state, c) = spawn_server().await;
    let (_s, v) = c.post("/api/v1/users", &serde_json::json!({"name": "Cara"}));
    let user_id = v["user"]["id"].as_str().unwrap();
    let (s, v) = c.post(
        &format!("/api/v1/users/{user_id}/devices"),
        &serde_json::json!({"label": "laptop"}),
    );
    assert_eq!(s, 201);
    let device_id = v["device"]["id"].as_str().unwrap();

    // Personal subscription: URL + QR, token shown once.
    let (s, v) = c.post(
        "/api/v1/subscriptions/personal",
        &serde_json::json!({"device_id": device_id}),
    );
    assert_eq!(s, 200, "{v}");
    let sub_id = v["subscription"]["id"].as_str().unwrap().to_string();
    let url = v["url"].as_str().unwrap().to_string();
    assert!(url.contains("/s/"));
    assert!(v["qr_svg"].as_str().unwrap().starts_with("<svg"));
    let token = url.rsplit('/').next().unwrap().to_string();

    // The token URL serves the body (loopback listener also serves /s/).
    let (s, _, body) = c.request("GET", &format!("/s/{token}"), &[], None, false);
    assert_eq!(s, 200);
    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body).unwrap(),
    )
    .unwrap();
    assert!(decoded.starts_with("vless://"), "{decoded}");

    // Rotate: old token 404s.
    let (s, v) = c.post(
        &format!("/api/v1/subscriptions/{sub_id}/rotate"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let (s, _, _) = c.request("GET", &format!("/s/{token}"), &[], None, false);
    assert_eq!(s, 404);
    let new_token = v["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let (s, _, _) = c.request("GET", &format!("/s/{new_token}"), &[], None, false);
    assert_eq!(s, 200);

    // Revoke: 404.
    let (s, _) = c.post(
        &format!("/api/v1/subscriptions/{sub_id}/revoke"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let (s, _, _) = c.request("GET", &format!("/s/{new_token}"), &[], None, false);
    assert_eq!(s, 404);

    // External subscription: parsed, stored encrypted, unmanaged.
    let (s, v) = c.post(
        "/api/v1/subscriptions/external",
        &serde_json::json!({
            "name": "Vendor",
            "source_url": "https://vendor.example/sub",
            "body_text": "vless://11111111-2222-4333-8444-555555555555@203.0.113.9:443?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=abc&sid=12&type=tcp#x\n",
        }),
    );
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["subscription"]["managed"], false);
    assert!(v["unmanaged_note"].as_str().unwrap().contains("unmanaged"));
    let ext_id = v["subscription"]["id"].as_str().unwrap().to_string();
    // The stored body must be encrypted (not the plaintext link).
    {
        let conn = _state.db.lock().unwrap();
        let sub = zero_admin::store::get_subscription(&conn, &ext_id).unwrap();
        let blob = sub.body_crypt.unwrap();
        assert!(!blob.windows(6).any(|w| w == b"vless:"));
    }
    // List never exposes token hashes or bodies.
    let (s, v) = c.get("/api/v1/subscriptions");
    assert_eq!(s, 200);
    for s in v["subscriptions"].as_array().unwrap() {
        assert!(s.get("token_hash").is_none());
        assert!(s.get("body_crypt").is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quotas_events_backup_restore() {
    let (_dir, state, c) = spawn_server().await;
    // Quota status lists the user near/over quota.
    let (s, _v) = c.post(
        "/api/v1/users",
        &serde_json::json!({"name": "Dan", "quota_bytes": 1000}),
    );
    assert_eq!(s, 201);
    let (s, v) = c.get("/api/v1/quotas/status");
    assert_eq!(s, 200);
    assert_eq!(v["users"].as_array().unwrap().len(), 1);

    // Events: issue logs show up.
    let (s, v) = c.get("/api/v1/events?kind=issue&limit=5");
    assert_eq!(s, 200);
    assert!(v["events"].is_array());

    // Backup with a passphrase; restore round-trip.
    let (s, _, blob) = c.request(
        "POST",
        "/api/v1/backup",
        &[("Content-Type", "application/json")],
        Some(br#"{"passphrase":"backup-secret-1"}"#.as_slice()),
        true,
    );
    assert_eq!(s, 200);
    assert_eq!(&blob[..8], b"ZABK1\0\0\0");
    let blob_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);
    let (s, v) = c.post(
        "/api/v1/restore",
        &serde_json::json!({"passphrase": "backup-secret-1", "blob": blob_b64}),
    );
    assert_eq!(s, 200, "{v}");
    // Wrong passphrase: clean 401, no partial restore.
    let (s, _) = c.post(
        "/api/v1/restore",
        &serde_json::json!({"passphrase": "wrong", "blob": blob_b64}),
    );
    assert_eq!(s, 401);
    // DB still works after restore.
    let (s, _) = c.get("/api/v1/users");
    assert_eq!(s, 200);
    let _ = state;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collector_requires_collector_token() {
    let (_dir, _state, c) = spawn_server().await;
    // Admin token is NOT accepted on the collector endpoint.
    let (s, _, _) = c.request(
        "POST",
        "/api/v1/collector/usage",
        &[("Content-Type", "application/json")],
        Some(br#"{"day":"2026-11-01","rows":[]}"#.as_slice()),
        true,
    );
    assert_eq!(s, 401);
    // No token at all: 401.
    let (s, _, _) = c.request(
        "POST",
        "/api/v1/collector/usage",
        &[("Content-Type", "application/json")],
        Some(br#"{"day":"2026-11-01","rows":[]}"#.as_slice()),
        false,
    );
    assert_eq!(s, 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_geoip_dependency_in_closure() {
    // Hard rule: the admin crate must never gain a GeoIP *dependency*, and
    // GeoIP must never feed tariffs/costs. The one authorized use is the
    // string "geoip" as a split-routing RULE KIND (owner EXPANDED prompt v2:
    // "GeoIP is the ROUTING mechanism" — never for costs).
    let manifest = include_str!("../Cargo.toml");
    for bad in ["geoip", "maxmind", "ip2location", "ipgeolocation"] {
        assert!(
            !manifest.to_lowercase().contains(bad),
            "Cargo.toml must not mention {bad}"
        );
    }
    // Whole dependency closure: no geoip-ish crate may sneak in transitively.
    let lock = include_str!("../../../Cargo.lock");
    for bad in ["geoip", "maxmind", "ip2location"] {
        assert!(
            !lock.to_lowercase().contains(bad),
            "Cargo.lock must not mention {bad}"
        );
    }
    // GeoIP database/lookup machinery is banned everywhere: maxmind-style
    // crates, mmdb readers, ip2location — in ANY source file.
    let sources = [
        include_str!("../src/api.rs"),
        include_str!("../src/store.rs"),
        include_str!("../src/subs.rs"),
        include_str!("../src/poller.rs"),
        include_str!("../src/panel.rs"),
        include_str!("../src/engine.rs"),
        include_str!("../src/backup.rs"),
        include_str!("../src/config.rs"),
        include_str!("../src/crypto.rs"),
        include_str!("../src/db.rs"),
        include_str!("../src/provision.rs"),
        include_str!("../src/secrets.rs"),
        include_str!("../src/main.rs"),
        include_str!("../src/routing.rs"),
        include_str!("../src/routing_panel.rs"),
        include_str!("../src/triple.rs"),
        include_str!("../src/triple_panel.rs"),
        include_str!("../src/ha.rs"),
        include_str!("../src/ha_panel.rs"),
        include_str!("../src/modem.rs"),
        include_str!("../src/huawei_panel.rs"),
    ];
    for src in sources {
        let lower = src.to_lowercase();
        for bad in [
            "maxmind",
            "ip2location",
            "geo_lite",
            "geo-lite",
            "geoip2",
            ".mmdb",
        ] {
            assert!(!lower.contains(bad), "source must not mention {bad}");
        }
    }
    // The bare word "geoip" may appear ONLY as the routing rule-kind literal
    // (and its direct documentation). It must never appear in cost/tariff,
    // subscription, or engine code paths.
    for src in [
        include_str!("../src/subs.rs"),
        include_str!("../src/poller.rs"),
        include_str!("../src/engine.rs"),
        include_str!("../src/backup.rs"),
        include_str!("../src/config.rs"),
        include_str!("../src/crypto.rs"),
        include_str!("../src/db.rs"),
        include_str!("../src/provision.rs"),
        include_str!("../src/secrets.rs"),
        include_str!("../src/main.rs"),
    ] {
        assert!(
            !src.to_lowercase().contains("geoip"),
            "non-routing source must not mention geoip"
        );
    }
    // And the tariff hard rule: costs default to "unknown".
    let (_dir, _state, c) = spawn_server().await;
    let (s, v) = c.post(
        "/api/v1/settings/costs",
        &serde_json::json!({"kind": "data_package", "label": "pack", "amount": 10}),
    );
    assert_eq!(s, 201);
    assert_eq!(v["cost"]["tariff_note"], "unknown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panel_login_flow() {
    let (_dir, state, c) = spawn_server().await;
    // Set a panel password directly in the DB.
    {
        let conn = state.db.lock().unwrap();
        let hash = zero_admin::crypto::hash_password("panel-pass-1").unwrap();
        zero_admin::store::set_setting(&conn, "panel.password_hash", &hash).unwrap();
    }
    // Login page renders.
    let (s, _, body) = c.request("GET", "/panel/login", &[], None, false);
    assert_eq!(s, 200);
    assert!(String::from_utf8_lossy(&body).contains("Admin password"));
    // Wrong password: 200 with error text (no token leak).
    let (s, _, body) = c.request(
        "POST",
        "/panel/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(b"password=nope"),
        false,
    );
    assert_eq!(s, 200);
    assert!(String::from_utf8_lossy(&body).contains("invalid credentials"));
    // Right password: 303 + HttpOnly SameSite=Strict cookie.
    let (s, headers, _) = c.request(
        "POST",
        "/panel/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(b"password=panel-pass-1"),
        false,
    );
    assert_eq!(s, 303);
    let cookie = headers.get("set-cookie").cloned().unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let token = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("zadmin=")
        .unwrap();
    // Dashboard with the cookie.
    let (s, _, body) = c.request(
        "GET",
        "/panel/",
        &[("Cookie", &format!("zadmin={token}"))],
        None,
        false,
    );
    assert_eq!(s, 200);
    assert!(String::from_utf8_lossy(&body).contains("Dashboard"));
    // No cookie: redirect to login.
    let (s, _, _) = c.request("GET", "/panel/", &[], None, false);
    assert_eq!(s, 303);
    // XSS: a hostile user name must be escaped in the panel.
    let (s, _) = c.post(
        "/api/v1/users",
        &serde_json::json!({"name": "<script>alert(1)</script>"}),
    );
    assert_eq!(s, 201);
    let (s, _, body) = c.request(
        "GET",
        "/panel/users",
        &[("Cookie", &format!("zadmin={token}"))],
        None,
        false,
    );
    assert_eq!(s, 200);
    let html = String::from_utf8_lossy(&body).into_owned();
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
}

// ---------------------------------------------------------------------------
// Modem endpoints (Design G, frozen app contract per RouterApi.kt)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn modem_capabilities_guide_security() {
    let (_dir, _state, c) = spawn_server().await;
    let (s, v) = c.get("/api/v1/modem/capabilities");
    assert_eq!(s, 200);
    assert_eq!(v["model"], "Huawei H158-381 (5G CPE Pro 5)");
    let protos = v["vpn_client"]["protocols"].as_array().unwrap();
    assert_eq!(
        protos.len(),
        1,
        "PPTP is refused — never listed as offerable"
    );
    assert_eq!(protos[0], "l2tp");
    let fields = v["vpn_client"]["fields"].as_array().unwrap();
    let ids: Vec<&str> = fields.iter().map(|f| f["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        vec![
            "connection_type",
            "lns_address",
            "hostname",
            "tunnel_password",
            "ppp_username",
            "ppp_password"
        ]
    );

    let (s, v) = c.get("/api/v1/modem/guide?protocol=l2tp");
    assert_eq!(s, 200);
    assert!(v["steps"].as_array().unwrap().len() >= 10);
    assert_eq!(v["steps"][0]["title"], "Step 1");
    let (s, _) = c.get("/api/v1/modem/guide?protocol=pptp");
    assert_eq!(s, 400);

    let (s, v) = c.get("/api/v1/modem/security?protocol=l2tp");
    assert_eq!(s, 200);
    let findings = v["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|f| f["id"] == "pptp-refused" && f["severity"] == "insecure"));
    assert!(findings
        .iter()
        .any(|f| f["id"] == "l2tp-weak" && f["severity"] == "untrustworthy"));
    assert!(findings.iter().any(|f| f["id"] == "no-kill-switch"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn modem_lifecycle_consent_gate() {
    let (_dir, _state, c) = spawn_server().await;
    // Create WITHOUT consent: no credentials.
    let (s, v) = c.post(
        "/api/v1/modem/accounts",
        &serde_json::json!({"name": "home-5g", "lns_address": "203.0.113.1"}),
    );
    assert_eq!(s, 201);
    let id = v["account"]["id"].as_str().unwrap().to_string();
    assert_eq!(v["consent_required"], true);
    assert_eq!(v["credentials"].as_array().unwrap().len(), 0);
    let username = v["account"]["username"].as_str().unwrap().to_string();
    assert!(username.starts_with("h158-") && username.len() == 13);

    // List: app shape, no secrets.
    let (s, v) = c.get("/api/v1/modem/accounts");
    assert_eq!(s, 200);
    let acc = &v["accounts"][0];
    assert_eq!(acc["name"], "home-5g");
    assert_eq!(acc["username"], username);
    assert!(acc.get("ppp_password").is_none());

    // GET before consent: empty credentials + consent_required.
    let (s, v) = c.get(&format!("/api/v1/modem/accounts/{id}"));
    assert_eq!(s, 200);
    assert_eq!(v["credentials"].as_array().unwrap().len(), 0);
    assert_eq!(v["consent_required"], true);

    // Reveal before consent: 403.
    let (s, _) = c.post(
        &format!("/api/v1/modem/accounts/{id}/reveal"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 403);

    // Consent requires acknowledged:true.
    let (s, _) = c.post(
        &format!("/api/v1/modem/accounts/{id}/consent"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post(
        &format!("/api/v1/modem/accounts/{id}/consent"),
        &serde_json::json!({"acknowledged": true}),
    );
    assert_eq!(s, 200);

    // Now GET returns credentials in firmware field order.
    let (s, v) = c.get(&format!("/api/v1/modem/accounts/{id}"));
    assert_eq!(s, 200);
    let creds = v["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 6);
    let ids: Vec<&str> = creds
        .iter()
        .map(|x| x["field_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "connection_type",
            "lns_address",
            "hostname",
            "tunnel_password",
            "ppp_username",
            "ppp_password"
        ]
    );
    assert_eq!(creds[0]["value"], "L2TP VPN client");
    assert_eq!(creds[4]["value"], username);
    assert!(!creds[5]["value"].as_str().unwrap().is_empty());
    let old_ppp = creds[5]["value"].as_str().unwrap().to_string();

    // Rotate: new password, different from the old one.
    let (s, v) = c.post(
        &format!("/api/v1/modem/accounts/{id}/rotate"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    let new_ppp = v["credentials"].as_array().unwrap()[5]["value"]
        .as_str()
        .unwrap();
    assert_ne!(new_ppp, old_ppp);

    // Protocol selection is refused.
    let (s, _) = c.post(
        "/api/v1/modem/accounts",
        &serde_json::json!({"name": "x", "protocol": "pptp"}),
    );
    assert_eq!(s, 400);

    // DELETE revokes.
    let (s, v) = c.delete(&format!("/api/v1/modem/accounts/{id}"));
    assert_eq!(s, 200);
    assert_eq!(v["ok"], true);
    let (s, _) = c.post(
        &format!("/api/v1/modem/accounts/{id}/reveal"),
        &serde_json::json!({}),
    );
    assert_eq!(s, 409);

    // Status + usage endpoints.
    let (s, v) = c.get(&format!("/api/v1/modem/accounts/{id}/status"));
    assert_eq!(s, 200);
    assert_eq!(v["username"], username);
    let (s, v) = c.get(&format!("/api/v1/modem/accounts/{id}/usage"));
    assert_eq!(s, 200);
    assert_eq!(v["data_used"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn modem_consent_at_create_returns_credentials_once() {
    let (_dir, _state, c) = spawn_server().await;
    let (s, v) = c.post(
        "/api/v1/modem/accounts",
        &serde_json::json!({"name": "shop-5g", "lns_address": "203.0.113.1", "consent": true}),
    );
    assert_eq!(s, 201);
    assert_eq!(v["credentials"].as_array().unwrap().len(), 6);
    assert!(v.get("consent_required").is_none());
}

// ---------------------------------------------------------------------------
// HA endpoints (frozen app contract per HaApi.kt)
// ---------------------------------------------------------------------------

/// Minimal stub of the engine's HA surface (contract test double — the real
/// machinery belongs to the routing agent).
async fn spawn_stub_engine() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req = read_http_request(&mut stream).await;
                let line = req.lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET /ha ") {
                    serde_json::json!({
                        "tunnels": [
                            {"id":"A","protocol":"wireguard","transport_family":"wireguard",
                             "state":"up","rtt_ms":42,"loss_pct":0.5,"jitter_ms":3,
                             "keepalive_ok":true,"last_heartbeat_at":1730412345000i64,
                             "bytes_up":100,"bytes_down":200},
                            {"id":"B","protocol":"hysteria2","transport_family":"quic",
                             "state":"weird-state","rtt_ms":88,"loss_pct":1.0,
                             "keepalive_ok":false}
                        ],
                        "primary":"A","mode":"hot_standby","available_modes":["hot_standby"],
                        "auto_recovery":true,"heartbeat_interval_s":3,"failover_threshold_missed":3,
                        "last_failover_at":1730410000000i64,"failover_count":1,
                        "total_downtime_s":1.5,
                        "exit":{"ip":"203.0.113.9","healthy":true,
                                "checked_at":1730412345000i64,"ip_stable":true}
                    })
                    .to_string()
                } else if line.starts_with("POST /ha/primary ")
                    || line.starts_with("POST /ha/mode ")
                    || line.starts_with("POST /ha/settings ")
                {
                    r#"{"ok":true}"#.to_string()
                } else {
                    String::new()
                };
                let status = if body.is_empty() {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

async fn spawn_server_with_engine(engine_mgmt: SocketAddr) -> (TempDir, Arc<AppState>, Client) {
    let dir = unique_test_dir("zero-admin-ha-test");
    let mut config = AdminConfig::test(&dir.0);
    config.engine_mgmt = engine_mgmt;
    let state = AppState::new(config.clone()).unwrap();
    let token = config.admin_token.expose().to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(state.clone(), listener, false));
    tokio::time::sleep(Duration::from_millis(100)).await;
    (dir, state, Client { addr, token })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ha_engine_down_is_honest() {
    // Default test config: engine_mgmt = 127.0.0.1:1 (unreachable).
    let (_dir, _state, c) = spawn_server().await;
    let (s, _) = c.get("/api/v1/ha/status");
    assert_eq!(s, 502);
    let (s, _) = c.post("/api/v1/ha/primary", &serde_json::json!({"tunnel": "C"}));
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/ha/settings",
        &serde_json::json!({"heartbeat_interval_s": 99}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post("/api/v1/ha/settings", &serde_json::json!({"nope": 1}));
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/ha/mode",
        &serde_json::json!({"mode": "active_active"}),
    );
    assert_eq!(s, 502); // snapshot fetch fails before the mode check
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ha_status_frozen_shape_with_stub_engine() {
    let engine_addr = spawn_stub_engine().await;
    let (_dir, _state, c) = spawn_server_with_engine(engine_addr).await;
    let (s, v) = c.get("/api/v1/ha/status");
    assert_eq!(s, 200);
    assert_eq!(v["supported"], true);
    assert_eq!(v["tunnels"].as_array().unwrap().len(), 2);
    // Fail-closed: the engine's "weird-state" surfaces as down.
    assert_eq!(v["tunnels"][0]["state"], "up");
    assert_eq!(v["tunnels"][1]["state"], "down");
    assert_eq!(v["tunnels"][0]["transport_family"], "wireguard");
    assert_eq!(v["tunnels"][0]["rtt_ms"], 42);
    assert_eq!(v["tunnels"][0]["jitter_ms"], 3);
    assert_eq!(v["tunnels"][0]["keepalive_ok"], true);
    assert_eq!(v["tunnels"][0]["last_heartbeat_at"], 1730412345000i64);
    assert_eq!(v["tunnels"][0]["bytes_up"], 100);
    assert_eq!(v["primary"], "A");
    assert_eq!(v["mode"], "hot_standby");
    assert_eq!(v["available_modes"], serde_json::json!(["hot_standby"]));
    assert_eq!(v["auto_recovery"], true);
    assert_eq!(v["heartbeat_interval_s"], 3);
    assert_eq!(v["failover_threshold_missed"], 3);
    assert_eq!(v["last_failover_at"], 1730410000000i64);
    assert_eq!(v["failover_count"], 1);
    assert_eq!(v["total_downtime_s"], 1.5);
    assert_eq!(v["downtime_measured"], true);
    // No GeoIP in the admin crate.
    assert_eq!(v["exit"]["country"], "unknown");
    assert_eq!(v["exit"]["ip"], "203.0.113.9");
    assert_eq!(v["exit"]["healthy"], true);
    assert_eq!(v["exit"]["ip_stable"], true);
    assert_eq!(v["exit"]["ip_stable_across_failovers"], true);
    assert!(v["honesty"]
        .as_str()
        .unwrap()
        .contains("NOT claimed without measured proof"));

    // Manual primary selection → frozen {ok, primary}.
    let (s, v) = c.post("/api/v1/ha/primary", &serde_json::json!({"tunnel": "B"}));
    assert_eq!(s, 200);
    assert_eq!(v, serde_json::json!({"ok": true, "primary": "B"}));

    // Mode switch: only engine-offered modes.
    let (s, v) = c.post(
        "/api/v1/ha/mode",
        &serde_json::json!({"mode": "hot_standby"}),
    );
    assert_eq!(s, 200);
    assert_eq!(v, serde_json::json!({"ok": true, "mode": "hot_standby"}));
    let (s, _) = c.post(
        "/api/v1/ha/mode",
        &serde_json::json!({"mode": "active_active"}),
    );
    assert_eq!(s, 409);

    // Settings.
    let (s, v) = c.post(
        "/api/v1/ha/settings",
        &serde_json::json!({"heartbeat_interval_s": 5, "auto_recovery": false}),
    );
    assert_eq!(s, 200);
    assert_eq!(v["ok"], true);

    // /ha is an alias of /ha/status.
    let (s, v2) = c.get("/api/v1/ha");
    assert_eq!(s, 200);
    assert_eq!(v2["supported"], true);
    assert_eq!(v2["primary"], "A"); // stub engine is stateless; always reports A
    assert_eq!(v2["tunnels"].as_array().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Routing endpoints (frozen app contract per RouterApi.kt)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_crud_versioning_and_test() {
    let (_dir, _state, c) = spawn_server().await;
    // Seeded v1 active, empty.
    let (s, v) = c.get("/api/v1/routing/rules");
    assert_eq!(s, 200);
    assert_eq!(v["version"], 1);
    assert_eq!(v["rules"].as_array().unwrap().len(), 0);

    // Create a valid rule.
    let (s, v) = c.post(
        "/api/v1/routing/rules",
        &serde_json::json!({"kind": "domain", "value": "bank.ir", "action": "iran", "priority": 10}),
    );
    assert_eq!(s, 201);
    let id = v["rule"]["id"].as_str().unwrap().to_string();
    assert_eq!(v["rule"]["action"], "iran");
    assert_eq!(v["conflicts"].as_array().unwrap().len(), 0);

    // A conflicting rule warns but is stored (priority decides).
    let (s, v) = c.post(
        "/api/v1/routing/rules",
        &serde_json::json!({"kind": "domain", "value": "bank.ir", "action": "usa", "priority": 20}),
    );
    assert_eq!(s, 201);
    assert!(!v["conflicts"].as_array().unwrap().is_empty());
    let id2 = v["rule"]["id"].as_str().unwrap().to_string();

    // Fail-closed validation.
    let (s, _) = c.post(
        "/api/v1/routing/rules",
        &serde_json::json!({"kind": "domain", "value": "not a domain!", "action": "iran"}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/routing/rules",
        &serde_json::json!({"kind": "asn", "value": "123", "action": "iran"}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/routing/rules",
        &serde_json::json!({"kind": "cidr", "value": "5.6.0.0/33", "action": "iran"}),
    );
    assert_eq!(s, 400);

    // Update.
    let (s, v) = c.put(
        &format!("/api/v1/routing/rules/{id}"),
        &serde_json::json!({"priority": 5}),
    );
    assert_eq!(s, 200);
    assert_eq!(v["rule"]["priority"], 5);

    // Delete.
    let (s, _) = c.delete(&format!("/api/v1/routing/rules/{id2}"));
    assert_eq!(s, 200);
    let (s, _) = c.delete(&format!("/api/v1/routing/rules/{id2}"));
    assert_eq!(s, 404);

    // Snapshot → v2 (inactive); rollback = activate v1.
    let (s, v) = c.post(
        "/api/v1/routing/rulesets",
        &serde_json::json!({"note": "pre-change"}),
    );
    assert_eq!(s, 201);
    assert_eq!(v["ruleset"]["version"], 2);
    assert_eq!(v["ruleset"]["active"], false);
    let (s, v) = c.get("/api/v1/routing/rulesets");
    assert_eq!(s, 200);
    assert_eq!(v["rulesets"].as_array().unwrap().len(), 2);
    let (s, v) = c.post(
        "/api/v1/routing/rulesets/1/activate",
        &serde_json::json!({}),
    );
    assert_eq!(s, 200);
    assert_eq!(v["version"], 1);
    let (s, _) = c.post(
        "/api/v1/routing/rulesets/99/activate",
        &serde_json::json!({}),
    );
    assert_eq!(s, 404);

    // Push pending (no engine) → engine_synced:false, honestly reported.
    let (s, v) = c.get("/api/v1/routing/rules");
    assert_eq!(s, 200);
    assert_eq!(v["engine_synced"], false);

    // Tester: no engine classifier → 502, never a guessed answer.
    let (s, _) = c.post(
        "/api/v1/routing/test",
        &serde_json::json!({"target": "example.com"}),
    );
    assert_eq!(s, 502);
    let (s, _) = c.post("/api/v1/routing/test", &serde_json::json!({"target": ""}));
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Panel sections for the new groups
// ---------------------------------------------------------------------------

async fn panel_login(state: &AppState, c: &Client) -> String {
    // The test server provisions no panel password; set one like the
    // panel_login_flow test does.
    {
        let conn = state.db.lock().unwrap();
        let hash = zero_admin::crypto::hash_password("panel-pass-1").unwrap();
        zero_admin::store::set_setting(&conn, "panel.password_hash", &hash).unwrap();
    }
    let (s, headers, _) = c.request(
        "POST",
        "/panel/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(b"password=panel-pass-1"),
        false,
    );
    assert_eq!(s, 303);
    let cookie = headers.get("set-cookie").cloned().unwrap();
    cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("zadmin=")
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panel_new_sections_render() {
    // The HA page needs live engine data for the honesty disclosure;
    // use the HA stub engine.
    let engine_addr = spawn_stub_engine().await;
    let (_dir, _state, c) = spawn_server_with_engine(engine_addr).await;
    let token = panel_login(&_state, &c).await;
    let cookie = format!("zadmin={token}");
    for path in ["/panel/huawei", "/panel/ha"] {
        let (s, headers, body) = c.request("GET", path, &[("Cookie", &cookie)], None, false);
        assert_eq!(s, 200, "{path}");
        let html = String::from_utf8_lossy(&body).into_owned();
        // CSP is a response header; the panel has no inline script.
        let csp = headers
            .get("content-security-policy")
            .cloned()
            .unwrap_or_default();
        assert!(csp.contains("default-src"), "{path} missing CSP header");
        assert!(!html.contains("<script"));
    }
    let (_, _, body) = c.request("GET", "/panel/huawei", &[("Cookie", &cookie)], None, false);
    let html = String::from_utf8_lossy(&body).into_owned();
    assert!(html.contains("⚠️ WEAK+"));
    assert!(html.contains("192.168.8.1"));
    let (_, _, body) = c.request("GET", "/panel/ha", &[("Cookie", &cookie)], None, false);
    let html = String::from_utf8_lossy(&body).into_owned();
    assert!(html.contains("Inter-Server High Availability"));
    assert!(html.contains("NOT claimed without measured proof"));
}

// ---------------------------------------------------------------------------
// Triple tunnel / dual-stack / sticky exit (frozen contracts)
// ---------------------------------------------------------------------------

/// Stub engine for the triple-tunnel surface (contract test double).
async fn spawn_triple_stub_engine() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req = read_http_request(&mut stream).await;
                let line = req.lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET /tunnels ") {
                    serde_json::json!({
                        "tunnels": [
                            {"id":"A","family":"ipv4","protocol":"wireguard",
                             "transport_family":"wireguard","state":"up",
                             "rtt_ms":42,"loss_pct":0.5,"jitter_ms":3,
                             "keepalive_ok":true,"last_heartbeat_at":1730412345000i64,
                             "traffic":{"payload_up":1000,"payload_down":2000,
                                        "keepalive_bytes":100,"health_bytes":50,
                                        "overhead_bytes":30},
                             "active_sessions":7,"failover_count":1,"recovery_time_s":1.2},
                            {"id":"B","family":"ipv4","protocol":"hysteria2",
                             "transport_family":"quic","state":"standby",
                             "rtt_ms":88,"keepalive_ok":true,
                             "traffic":{"payload_up":0,"payload_down":0,
                                        "keepalive_bytes":40,"health_bytes":20,
                                        "overhead_bytes":10}},
                            {"id":"C","family":"ipv6","protocol":"wireguard",
                             "transport_family":"wireguard","state":"unavailable"}
                        ],
                        "primary":"A","mode":"hot_standby","available_modes":["hot_standby"],
                        "probe_budget":"balanced",
                        "probe_budget_options":["low","balanced","aggressive","custom"]
                    })
                    .to_string()
                } else if line.starts_with("GET /egress ") && !line.contains("/decisions") {
                    serde_json::json!({
                        "static_ipv4":"203.0.113.9","static_ipv6":"2001:db8::9",
                        "v4":{"connected":true,"success_rate":0.99},
                        "v6":{"connected":false,"success_rate":0.0},
                        "sticky":{"exit_ip":"203.0.113.9","exit_family":"ipv4",
                                  "session_started_at":1730410000000i64,
                                  "last_reroute_at":1730411000000i64,
                                  "last_reroute_reason":"tunnel A recovered, policy auto"}
                    })
                    .to_string()
                } else if line.starts_with("GET /egress/decisions") {
                    serde_json::json!({
                        "domain":"bank.ir","family":"ipv4",
                        "policy":"prefer_stable_ipv4",
                        "reason":"stored sticky policy prefer_stable_ipv4 for bank.ir",
                        "exit_ip":"203.0.113.9"
                    })
                    .to_string()
                } else if line.starts_with("POST /tests/") {
                    let kind = line.split_whitespace().nth(1).unwrap_or("");
                    let kind = kind.strip_prefix("/tests/").unwrap_or(kind);
                    serde_json::json!({
                        "kind": kind, "ok": true,
                        "results":[{"name":"connectivity","ok":true,
                                    "detail":"3/3 probes ok","duration_ms":120}],
                        "measured_at":1730412345000i64
                    })
                    .to_string()
                } else if line.starts_with("POST /tunnels/probe-budget ")
                    || line.starts_with("POST /sticky-policies ")
                {
                    r#"{"ok":true}"#.to_string()
                } else {
                    String::new()
                };
                let status = if body.is_empty() {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn triple_engine_down_is_honest() {
    let (_dir, _state, c) = spawn_server().await;
    let (s, _) = c.get("/api/v1/tunnels/status");
    assert_eq!(s, 502);
    let (s, _) = c.post(
        "/api/v1/tunnels/primary",
        &serde_json::json!({"tunnel": "D"}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/tunnels/probe-budget",
        &serde_json::json!({"budget": "extreme"}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.get("/api/v1/egress/status");
    assert_eq!(s, 502);
    let (s, _) = c.get("/api/v1/egress/decisions");
    assert_eq!(s, 400);
    let (s, _) = c.post("/api/v1/tests/ipv4", &serde_json::json!({}));
    assert_eq!(s, 502);
    let (s, _) = c.post("/api/v1/tests/bogus", &serde_json::json!({}));
    assert_eq!(s, 400);
    // Failover test requires explicit confirmation.
    let (s, _) = c.post("/api/v1/tests/failover", &serde_json::json!({}));
    assert_eq!(s, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn triple_tunnels_frozen_shape_with_stub_engine() {
    let engine_addr = spawn_triple_stub_engine().await;
    let (_dir, _state, c) = spawn_server_with_engine(engine_addr).await;

    let (s, v) = c.get("/api/v1/tunnels/status");
    assert_eq!(s, 200);
    assert_eq!(v["supported"], true);
    let tunnels = v["tunnels"].as_array().unwrap();
    assert_eq!(tunnels.len(), 3);
    assert_eq!(tunnels[0]["id"], "A");
    assert_eq!(tunnels[0]["family"], "ipv4");
    assert_eq!(tunnels[0]["state"], "up");
    assert_eq!(tunnels[0]["traffic"]["payload_up"], 1000);
    assert_eq!(tunnels[0]["traffic"]["overhead_bytes"], 30);
    assert_eq!(tunnels[0]["active_sessions"], 7);
    assert_eq!(tunnels[0]["recovery_time_s"], 1.2);
    // Tunnel C: explicit "unavailable" passes through (never fake-connected).
    assert_eq!(tunnels[2]["id"], "C");
    assert_eq!(tunnels[2]["family"], "ipv6");
    assert_eq!(tunnels[2]["state"], "unavailable");
    assert_eq!(v["primary"], "A");
    assert_eq!(v["probe_budget"], "balanced");
    assert_eq!(v["probe_budget_options"].as_array().unwrap().len(), 4);

    // Probe budget: admin setting stored; engine push best-effort.
    let (s, v) = c.post(
        "/api/v1/tunnels/probe-budget",
        &serde_json::json!({"budget": "low"}),
    );
    assert_eq!(s, 200);
    assert_eq!(v["budget"], "low");
    assert_eq!(v["engine_applied"], true);
    let (s, v) = c.get("/api/v1/tunnels/probe-budget");
    assert_eq!(s, 200);
    assert_eq!(v["budget"], "low");

    // Egress.
    let (s, v) = c.get("/api/v1/egress/status");
    assert_eq!(s, 200);
    assert_eq!(v["supported"], true);
    assert_eq!(v["static_ipv4"], "203.0.113.9");
    assert_eq!(v["static_ipv6"], "2001:db8::9");
    assert_eq!(v["v4"]["connected"], true);
    assert_eq!(v["v6"]["connected"], false);
    assert_eq!(v["sticky"]["exit_ip"], "203.0.113.9");
    assert_eq!(
        v["sticky"]["last_reroute_reason"],
        "tunnel A recovered, policy auto"
    );

    // Per-destination decision.
    let (s, v) = c.get("/api/v1/egress/decisions?domain=bank.ir");
    assert_eq!(s, 200);
    assert_eq!(v["domain"], "bank.ir");
    assert_eq!(v["family"], "ipv4");
    assert_eq!(v["policy"], "prefer_stable_ipv4");
    assert!(!v["reason"].as_str().unwrap().is_empty());

    // Manual tests: real results.
    let (s, v) = c.post("/api/v1/tests/ipv4", &serde_json::json!({}));
    assert_eq!(s, 200);
    assert_eq!(v["kind"], "ipv4");
    assert_eq!(v["ok"], true);
    assert_eq!(v["results"][0]["name"], "connectivity");
    assert_eq!(v["measured_at"], 1730412345000i64);
    let (s, v) = c.post(
        "/api/v1/tests/failover",
        &serde_json::json!({"confirm": true}),
    );
    assert_eq!(s, 200);
    assert_eq!(v["kind"], "failover");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sticky_policies_crud_and_effective() {
    let (_dir, _state, c) = spawn_server().await;
    // Create.
    let (s, v) = c.post(
        "/api/v1/sticky-policies",
        &serde_json::json!({"scope": "domain", "target": "Bank.IR",
                            "policy": "prefer_stable_ipv4", "affinity_secs": 3600}),
    );
    assert_eq!(s, 201);
    let id = v["policy"]["id"].as_str().unwrap().to_string();
    assert_eq!(v["policy"]["target"], "bank.ir"); // normalized lowercase
    assert_eq!(v["policy"]["policy"], "prefer_stable_ipv4");

    // Fail-closed validation.
    let (s, _) = c.post(
        "/api/v1/sticky-policies",
        &serde_json::json!({"scope": "asn", "target": "x", "policy": "auto"}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/sticky-policies",
        &serde_json::json!({"scope": "domain", "target": "x", "policy": "prefer-ipv4"}),
    );
    assert_eq!(s, 400);
    let (s, _) = c.post(
        "/api/v1/sticky-policies",
        &serde_json::json!({"scope": "domain", "target": "", "policy": "auto"}),
    );
    assert_eq!(s, 400);

    // List + engine_synced:false (push pending, no engine).
    let (s, v) = c.get("/api/v1/sticky-policies");
    assert_eq!(s, 200);
    assert_eq!(v["policies"].as_array().unwrap().len(), 1);
    assert_eq!(v["engine_synced"], false);
    assert_eq!(v["defaults"]["policy"], "auto");

    // Effective: domain policy matches.
    let (s, v) = c.get("/api/v1/sticky-policies/effective?domain=bank.ir");
    assert_eq!(s, 200);
    assert_eq!(v["source"], "stored");
    assert_eq!(v["policy"]["policy"], "prefer_stable_ipv4");

    // Device policy wins over domain policy.
    let (s, _) = c.post(
        "/api/v1/sticky-policies",
        &serde_json::json!({"scope": "device", "target": "dev-1", "policy": "force_ipv6"}),
    );
    assert_eq!(s, 201);
    let (s, v) = c.get("/api/v1/sticky-policies/effective?domain=bank.ir&device=dev-1");
    assert_eq!(s, 200);
    assert_eq!(v["policy"]["policy"], "force_ipv6");

    // No match → default, never 404.
    let (s, v) = c.get("/api/v1/sticky-policies/effective?domain=other.example");
    assert_eq!(s, 200);
    assert_eq!(v["source"], "default");
    assert_eq!(v["policy"]["policy"], "auto");

    // Update.
    let (s, v) = c.put(
        &format!("/api/v1/sticky-policies/{id}"),
        &serde_json::json!({"policy": "force_ipv4"}),
    );
    assert_eq!(s, 200);
    assert_eq!(v["policy"]["policy"], "force_ipv4");
    let (s, _) = c.put(
        &format!("/api/v1/sticky-policies/{id}"),
        &serde_json::json!({"policy": "bogus"}),
    );
    assert_eq!(s, 400);

    // Delete.
    let (s, _) = c.delete(&format!("/api/v1/sticky-policies/{id}"));
    assert_eq!(s, 200);
    let (s, _) = c.delete(&format!("/api/v1/sticky-policies/{id}"));
    assert_eq!(s, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panel_triple_and_sticky_render() {
    let (_dir, _state, c) = spawn_server().await;
    let token = panel_login(&_state, &c).await;
    let cookie = format!("zadmin={token}");
    for (path, marker) in [
        ("/panel/triple", "Triple Tunnel &amp; Dual-Stack Monitor"),
        ("/panel/sticky", "Sticky Exit Policies"),
    ] {
        let (s, _, body) = c.request("GET", path, &[("Cookie", &cookie)], None, false);
        assert_eq!(s, 200, "{path}");
        let html = String::from_utf8_lossy(&body).into_owned();
        assert!(html.contains(marker), "{path} missing marker");
        assert!(!html.contains("<script"));
    }
}
