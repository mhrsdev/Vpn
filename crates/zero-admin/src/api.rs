//! REST API `/api/v1` + panel + public subscription listener.
//!
//! Hand-rolled HTTP/1.1 (httparse), following the `zero-runtime/src/api.rs`
//! precedent: 2 MiB cap, 30 s read timeout, loopback-only bind, bearer auth
//! with **constant-time** compare, CSRF Origin rule, per-IP rate limiting.
//!
//! The admin never fetches user-supplied URLs (SSRF-safe by design); the only
//! outbound HTTPS the admin performs is the exit-IP check against a fixed
//! compiled-in endpoint, and the gateway→exit collector POST to a
//! provision-time address.

use crate::config::{AdminConfig, AdminMode, ServerRole};
use crate::crypto::{self, token_hash};
use crate::engine::{self, EngineClient};
use crate::secrets::SecretString;
use crate::store::{self, StoreError};
use crate::subs::{self, IssuedSecret};
use rusqlite::Connection;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_REQUEST: usize = 2 * 1024 * 1024;
const API_RATE_PER_MIN: f64 = 60.0;
const AUTH_RATE_PER_MIN: f64 = 10.0;
const SUB_RATE_PER_MIN: f64 = 30.0;

/// Compiled-in exit-IP check endpoint (single-purpose IP echo). Fixed at
/// build time — never user-controlled (SSRF-safe).
const EXIT_IP_URL: &str = "https://api.ipify.org";

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn today_utc() -> String {
    // Days since epoch -> YYYY-MM-DD via a small civil-date conversion.
    let days = now_secs().div_euclid(86400);
    civil_from_days(days)
}

fn civil_from_days(z: i64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", y + if m <= 2 { 1 } else { 0 }, m, d)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExitIpState {
    pub ip: String,
    pub checked_at: i64,
}

pub struct RateBucket {
    tokens: f64,
    last: Instant,
    last_hit: Option<Instant>,
}

impl RateBucket {
    fn new(per_min: f64) -> Self {
        Self {
            tokens: per_min,
            last: Instant::now(),
            last_hit: None,
        }
    }
}

pub struct AppState {
    pub config: AdminConfig,
    pub db: Arc<Mutex<Connection>>,
    pub engine: EngineClient,
    pub rate: Mutex<HashMap<(IpAddr, &'static str), RateBucket>>,
    pub exit_ip: Mutex<Option<ExitIpState>>,
    /// Last per-identity counters seen: "h|tag" -> (up, down).
    pub last_counters: Mutex<HashMap<String, (u64, u64)>>,
    /// Last per-modem-account counters seen from the session monitor:
    /// account id -> (up, down).
    pub last_modem_counters: Mutex<HashMap<String, (u64, u64)>>,
    /// Last HA snapshot seen (for failover-event detection).
    pub last_ha: Mutex<Option<crate::ha::HaSnapshot>>,
    /// Last switch events seen from engine /health (dedup for events).
    pub last_switch_at: Mutex<Option<i64>>,
}

impl AppState {
    pub fn new(config: AdminConfig) -> Result<Arc<Self>, String> {
        let conn = crate::db::open(&config.db_path).map_err(|e| e.to_string())?;
        let engine = EngineClient::new(config.engine_mgmt, config.engine_token.clone());
        Ok(Arc::new(Self {
            config,
            db: Arc::new(Mutex::new(conn)),
            engine,
            rate: Mutex::new(HashMap::new()),
            exit_ip: Mutex::new(None),
            last_counters: Mutex::new(HashMap::new()),
            last_modem_counters: Mutex::new(HashMap::new()),
            last_ha: Mutex::new(None),
            last_switch_at: Mutex::new(None),
        }))
    }

    fn db_lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, HttpResponse> {
        self.db
            .lock()
            .map_err(|_| err_json("internal", "db lock poisoned", 500))
    }
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub extra: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

pub(crate) fn resp(status: u16, content_type: &'static str, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status,
        content_type,
        extra: Vec::new(),
        body,
    }
}

pub fn ok_json(v: serde_json::Value) -> HttpResponse {
    resp(200, "application/json", serde_json::to_vec(&v).unwrap())
}

pub fn err_json(code: &str, message: &str, status: u16) -> HttpResponse {
    resp(
        status,
        "application/json",
        serde_json::to_vec(&serde_json::json!({"error": {"code": code, "message": message}}))
            .unwrap(),
    )
}

pub(crate) async fn write_response(stream: &mut tokio::net::TcpStream, r: HttpResponse) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    for (k, v) in &r.extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&r.body).await;
}

pub(crate) fn parse_query(q: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        m.insert(percent_decode(k), percent_decode(v));
    }
    m
}

pub(crate) fn percent_decode(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h: String = chars.by_ref().take(2).collect();
            if let Ok(b) = u8::from_str_radix(&h, 16) {
                out.push(b as char);
                continue;
            }
            out.push('%');
            out.push_str(&h);
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) async fn read_request(
    stream: &mut tokio::net::TcpStream,
    peer: SocketAddr,
) -> Result<HttpRequest, HttpResponse> {
    let mut data = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    // Read headers.
    let head_end = loop {
        if data.len() > MAX_REQUEST {
            return Err(resp(413, "text/plain", b"request too large".to_vec()));
        }
        if let Some(i) = find_subslice(&data, b"\r\n\r\n") {
            break i + 4;
        }
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| resp(400, "text/plain", b"request timed out".to_vec()))?
            .map_err(|_| resp(400, "text/plain", b"read error".to_vec()))?;
        if n == 0 {
            return Err(resp(400, "text/plain", b"truncated request".to_vec()));
        }
    };
    let mut headers_arr = [httparse::EMPTY_HEADER; 48];
    let mut req = httparse::Request::new(&mut headers_arr);
    req.parse(&data[..head_end])
        .map_err(|_| resp(400, "text/plain", b"bad request".to_vec()))?;
    let method = req.method.unwrap_or("").to_string();
    let full_path = req.path.unwrap_or("/").to_string();
    let (path, query) = match full_path.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (full_path, HashMap::new()),
    };
    let mut headers = HashMap::new();
    for h in req.headers.iter() {
        headers.insert(
            h.name.to_ascii_lowercase(),
            String::from_utf8_lossy(h.value).into_owned(),
        );
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    if content_length > MAX_REQUEST - head_end {
        return Err(resp(413, "text/plain", b"request too large".to_vec()));
    }
    while data.len() < head_end + content_length {
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| resp(400, "text/plain", b"body timed out".to_vec()))?
            .map_err(|_| resp(400, "text/plain", b"read error".to_vec()))?;
        if n == 0 {
            return Err(resp(400, "text/plain", b"truncated body".to_vec()));
        }
    }
    data.truncate(head_end + content_length);
    let body = data[head_end..].to_vec();
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
        peer,
    })
}

pub(crate) fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Auth, rate limiting, CSRF
// ---------------------------------------------------------------------------

pub(crate) fn bearer_of(req: &HttpRequest) -> Option<&str> {
    req.headers
        .get("authorization")?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Constant-time bearer comparison. Never `!=` on secrets.
pub(crate) fn bearer_valid(presented: Option<&str>, expected: &SecretString) -> bool {
    match presented {
        Some(p) => bool::from(p.as_bytes().ct_eq(expected.expose().as_bytes())),
        None => false,
    }
}

pub(crate) fn check_rate(
    state: &AppState,
    ip: IpAddr,
    bucket: &'static str,
    per_min: f64,
    min_spacing_secs: Option<u64>,
) -> Result<(), u64> {
    let mut rate = state.rate.lock().unwrap();
    let b = rate
        .entry((ip, bucket))
        .or_insert_with(|| RateBucket::new(per_min));
    let now = Instant::now();
    let elapsed = now.duration_since(b.last).as_secs_f64();
    b.tokens = (b.tokens + elapsed * per_min / 60.0).min(per_min);
    b.last = now;
    if let Some(spacing) = min_spacing_secs {
        if let Some(last_hit) = b.last_hit {
            if now.duration_since(last_hit).as_secs() < spacing {
                return Err(spacing);
            }
        }
    }
    if b.tokens < 1.0 {
        return Err((60.0 / per_min).ceil() as u64);
    }
    b.tokens -= 1.0;
    b.last_hit = Some(now);
    Ok(())
}

pub(crate) fn rate_limited_response(retry_after: u64) -> HttpResponse {
    let mut r = err_json("rate_limited", "too many requests", 429);
    r.extra
        .push(("Retry-After".to_string(), retry_after.to_string()));
    r
}

/// API auth: bearer required on every /api/v1 route. Rate limited 60/min/IP.
pub(crate) fn api_auth(state: &AppState, req: &HttpRequest) -> Result<(), HttpResponse> {
    if let Err(retry) = check_rate(state, req.peer.ip(), "api", API_RATE_PER_MIN, None) {
        return Err(rate_limited_response(retry));
    }
    if !bearer_valid(bearer_of(req), &state.config.admin_token) {
        return Err(err_json("unauthorized", "bad or missing bearer token", 401));
    }
    // CSRF: state-changing verbs carrying an Origin header are refused
    // (api.rs:136 precedent). API clients don't send Origin; browsers do.
    if !matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS")
        && req.headers.contains_key("origin")
    {
        return Err(err_json("forbidden", "cross-origin request refused", 403));
    }
    Ok(())
}

pub(crate) fn session_of(state: &AppState, req: &HttpRequest) -> Option<String> {
    let cookie = req.headers.get("cookie")?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("zadmin=") {
            let h = token_hash(token);
            let now = now_secs();
            let conn = state.db.lock().ok()?;
            // IP binding: mismatch = logout.
            if let Ok(Some(ip)) = store::get_session(&conn, &h, now) {
                if ip == req.peer.ip().to_string() {
                    return Some(h);
                }
                let _ = store::delete_session(&conn, &h);
            }
            return None;
        }
    }
    None
}

/// Panel auth: session cookie required. Same-origin CSRF check for
/// state-changing verbs (the panel is browser-driven, unlike the API).
pub(crate) fn panel_auth(state: &AppState, req: &HttpRequest) -> Result<(), HttpResponse> {
    if session_of(state, req).is_none() {
        return Err(resp(
            401,
            "text/html",
            b"<h1>401</h1><p><a href=\"/panel/login\">login</a></p>".to_vec(),
        ));
    }
    if !matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        if let Some(origin) = req.headers.get("origin") {
            let host = req.headers.get("host").map(String::as_str).unwrap_or("");
            // Same-origin only: http(s)://host must match the Host header.
            let ok = origin == &format!("http://{host}") || origin == &format!("https://{host}");
            if !ok {
                return Err(err_json("forbidden", "cross-origin request refused", 403));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Serve forever. `public_only` = the optional public subscription listener:
/// only `GET /s/{token}` is served, everything else 404s.
pub async fn serve(state: Arc<AppState>, listener: tokio::net::TcpListener, public_only: bool) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let req = match read_request(&mut stream, peer).await {
                Ok(r) => r,
                Err(e) => {
                    write_response(&mut stream, e).await;
                    return;
                }
            };
            let resp = handle(&state, &req, public_only).await;
            write_response(&mut stream, resp).await;
        });
    }
}

async fn handle(state: &AppState, req: &HttpRequest, public_only: bool) -> HttpResponse {
    // Public subscription listener: exactly one route.
    if public_only {
        let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
        if req.method == "GET" && segs.len() == 2 && segs[0] == "s" {
            if let Err(retry) = check_rate(state, req.peer.ip(), "sub", SUB_RATE_PER_MIN, None) {
                return rate_limited_response(retry);
            }
            return serve_subscription(state, segs[1]).await;
        }
        return err_json("not_found", "not found", 404);
    }

    let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["api", "v1", "status"] if req.method == "GET" => {
            authed(api_auth(state, req), h_status(state).await)
        }
        ["api", "v1", "auth", "login"] if req.method == "POST" => h_auth_login(state, req).await,
        ["api", "v1", "auth", "logout"] if req.method == "POST" => {
            authed(api_auth(state, req), h_auth_logout(state, req).await)
        }
        ["api", "v1", "health"] if req.method == "GET" => {
            authed(api_auth(state, req), h_health(state).await)
        }
        ["api", "v1", "servers"] if req.method == "GET" => {
            authed(api_auth(state, req), h_servers(state).await)
        }
        ["api", "v1", "servers", role, "health"] if req.method == "GET" => {
            authed(api_auth(state, req), h_server_health(state, role).await)
        }
        ["api", "v1", "servers", role, "probe"] if req.method == "POST" => {
            authed(api_auth(state, req), h_server_probe(state, role).await)
        }
        ["api", "v1", "users"] if req.method == "GET" => {
            authed(api_auth(state, req), h_users_list(state).await)
        }
        ["api", "v1", "users"] if req.method == "POST" => {
            authed(api_auth(state, req), h_user_create(state, req).await)
        }
        ["api", "v1", "users", id] if req.method == "GET" => {
            authed(api_auth(state, req), h_user_get(state, id).await)
        }
        ["api", "v1", "users", id] if req.method == "PATCH" => {
            authed(api_auth(state, req), h_user_patch(state, id, req).await)
        }
        ["api", "v1", "users", id, "revoke"] if req.method == "POST" => {
            authed(api_auth(state, req), h_user_revoke(state, id, true).await)
        }
        ["api", "v1", "users", id, "restore"] if req.method == "POST" => {
            authed(api_auth(state, req), h_user_revoke(state, id, false).await)
        }
        ["api", "v1", "users", id, "devices"] if req.method == "GET" => {
            authed(api_auth(state, req), h_devices_list(state, id).await)
        }
        ["api", "v1", "users", id, "devices"] if req.method == "POST" => {
            authed(api_auth(state, req), h_device_issue(state, id, req).await)
        }
        ["api", "v1", "devices", id] if req.method == "GET" => {
            authed(api_auth(state, req), h_device_get(state, id).await)
        }
        ["api", "v1", "devices", id] if req.method == "DELETE" => {
            authed(api_auth(state, req), h_device_delete(state, id).await)
        }
        ["api", "v1", "devices", id, "reissue"] if req.method == "POST" => {
            authed(api_auth(state, req), h_device_reissue(state, id).await)
        }
        ["api", "v1", "devices", id, "revoke"] if req.method == "POST" => {
            authed(api_auth(state, req), h_device_revoke(state, id, true).await)
        }
        ["api", "v1", "devices", id, "restore"] if req.method == "POST" => authed(
            api_auth(state, req),
            h_device_revoke(state, id, false).await,
        ),
        ["api", "v1", "devices", id, "configs"] if req.method == "GET" => {
            authed(api_auth(state, req), h_device_configs(state, id).await)
        }
        ["api", "v1", "subscriptions"] if req.method == "GET" => {
            authed(api_auth(state, req), h_subs_list(state).await)
        }
        ["api", "v1", "subscriptions", "personal"] if req.method == "POST" => {
            authed(api_auth(state, req), h_sub_personal(state, req).await)
        }
        ["api", "v1", "subscriptions", id, "rotate"] if req.method == "POST" => {
            authed(api_auth(state, req), h_sub_rotate(state, id).await)
        }
        ["api", "v1", "subscriptions", "external"] if req.method == "POST" => {
            authed(api_auth(state, req), h_sub_external(state, req).await)
        }
        ["api", "v1", "subscriptions", "external", id, "refresh"] if req.method == "POST" => {
            authed(
                api_auth(state, req),
                h_sub_external_refresh(state, id, req).await,
            )
        }
        ["api", "v1", "subscriptions", id, "revoke"] if req.method == "POST" => {
            authed(api_auth(state, req), h_sub_revoke(state, id).await)
        }
        // Modem accounts (Design G) — /api/v1/modem/* group (frozen contract §3.2m).
        // Frozen app contract (shapes per the Android agent's RouterApi.kt).
        ["api", "v1", "modem", "capabilities"] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_capabilities(state).await)
        }
        ["api", "v1", "modem", "guide"] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_guide(state, req).await)
        }
        ["api", "v1", "modem", "security"] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_security(state, req).await)
        }
        ["api", "v1", "modem", "accounts"] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_list(state).await)
        }
        ["api", "v1", "modem", "accounts"] if req.method == "POST" => {
            authed(api_auth(state, req), h_modem_create(state, req).await)
        }
        ["api", "v1", "modem", "accounts", id] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_get(state, id).await)
        }
        ["api", "v1", "modem", "accounts", id] if req.method == "DELETE" => {
            authed(api_auth(state, req), h_modem_revoke(state, id, true).await)
        }
        ["api", "v1", "modem", "accounts", id, "consent"] if req.method == "POST" => {
            authed(api_auth(state, req), h_modem_consent(state, id, req).await)
        }
        ["api", "v1", "modem", "accounts", id, "reveal"] if req.method == "POST" => {
            authed(api_auth(state, req), h_modem_reveal(state, id).await)
        }
        ["api", "v1", "modem", "accounts", id, "rotate"] if req.method == "POST" => {
            authed(api_auth(state, req), h_modem_rotate(state, id).await)
        }
        ["api", "v1", "modem", "accounts", id, "revoke"] if req.method == "POST" => {
            authed(api_auth(state, req), h_modem_revoke(state, id, true).await)
        }
        ["api", "v1", "modem", "accounts", id, "restore"] if req.method == "POST" => {
            authed(api_auth(state, req), h_modem_revoke(state, id, false).await)
        }
        ["api", "v1", "modem", "accounts", id, "usage"] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_usage(state, id, req).await)
        }
        ["api", "v1", "modem", "accounts", id, "status"] if req.method == "GET" => {
            authed(api_auth(state, req), h_modem_status(state, id).await)
        }
        // Inter-server High Availability (owner addendum) — /api/v1/ha/* (§3.2h).
        // Frozen app contract (shapes per the Android agent's HaApi.kt).
        ["api", "v1", "ha", "status"] if req.method == "GET" => {
            authed(api_auth(state, req), h_ha_status(state).await)
        }
        ["api", "v1", "ha"] if req.method == "GET" => {
            authed(api_auth(state, req), h_ha_status(state).await)
        }
        ["api", "v1", "ha", "tunnels"] if req.method == "GET" => {
            authed(api_auth(state, req), h_ha_tunnels(state).await)
        }
        ["api", "v1", "ha", "primary"] if req.method == "POST" => {
            authed(api_auth(state, req), h_ha_primary(state, req).await)
        }
        ["api", "v1", "ha", "mode"] if req.method == "POST" => {
            authed(api_auth(state, req), h_ha_mode(state, req).await)
        }
        ["api", "v1", "ha", "settings"] if req.method == "GET" => {
            authed(api_auth(state, req), h_ha_settings_get(state).await)
        }
        ["api", "v1", "ha", "settings"] if req.method == "POST" => {
            authed(api_auth(state, req), h_ha_settings_post(state, req).await)
        }
        ["api", "v1", "ha", "settings"] if req.method == "PUT" => {
            authed(api_auth(state, req), h_ha_settings_post(state, req).await)
        }
        // Triple tunnel / dual-stack / sticky exit — frozen app contract.
        ["api", "v1", "tunnels", "status"] if req.method == "GET" => {
            authed(api_auth(state, req), h_tunnels_status(state).await)
        }
        ["api", "v1", "tunnels", "primary"] if req.method == "POST" => {
            authed(api_auth(state, req), h_tunnels_primary(state, req).await)
        }
        ["api", "v1", "tunnels", "probe-budget"] if req.method == "GET" => {
            authed(api_auth(state, req), h_probe_budget_get(state).await)
        }
        ["api", "v1", "tunnels", "probe-budget"] if req.method == "POST" => {
            authed(api_auth(state, req), h_probe_budget_post(state, req).await)
        }
        ["api", "v1", "egress", "status"] if req.method == "GET" => {
            authed(api_auth(state, req), h_egress_status(state).await)
        }
        ["api", "v1", "egress", "decisions"] if req.method == "GET" => {
            authed(api_auth(state, req), h_egress_decision(state, req).await)
        }
        ["api", "v1", "sticky-policies"] if req.method == "GET" => {
            authed(api_auth(state, req), h_sticky_list(state).await)
        }
        ["api", "v1", "sticky-policies"] if req.method == "POST" => {
            authed(api_auth(state, req), h_sticky_create(state, req).await)
        }
        ["api", "v1", "sticky-policies", "effective"] if req.method == "GET" => {
            authed(api_auth(state, req), h_sticky_effective(state, req).await)
        }
        ["api", "v1", "sticky-policies", id] if req.method == "PUT" => {
            authed(api_auth(state, req), h_sticky_update(state, id, req).await)
        }
        ["api", "v1", "sticky-policies", id] if req.method == "DELETE" => {
            authed(api_auth(state, req), h_sticky_delete(state, id).await)
        }
        ["api", "v1", "tests", kind] if req.method == "POST" => {
            authed(api_auth(state, req), h_test_run(state, kind, req).await)
        }
        ["s", token] if req.method == "GET" => {
            // Also served on the main listener (loopback): same handler.
            if let Err(retry) = check_rate(state, req.peer.ip(), "sub", SUB_RATE_PER_MIN, None) {
                return rate_limited_response(retry);
            }
            serve_subscription(state, token).await
        }
        ["api", "v1", "usage", "summary"] if req.method == "GET" => {
            authed(api_auth(state, req), h_usage_summary(state).await)
        }
        ["api", "v1", "usage", "devices"] if req.method == "GET" => {
            authed(api_auth(state, req), h_usage_devices(state, req).await)
        }
        ["api", "v1", "usage", "inbounds"] if req.method == "GET" => {
            authed(api_auth(state, req), h_usage_inbounds(state).await)
        }
        ["api", "v1", "inbounds"] if req.method == "GET" => {
            authed(api_auth(state, req), h_inbounds_list(state).await)
        }
        ["api", "v1", "quotas", "status"] if req.method == "GET" => {
            authed(api_auth(state, req), h_quotas_status(state).await)
        }
        ["api", "v1", "settings", "dns"] if req.method == "GET" => {
            authed(api_auth(state, req), h_dns_get(state).await)
        }
        ["api", "v1", "settings", "dns"] if req.method == "PUT" => {
            authed(api_auth(state, req), h_dns_put(state, req).await)
        }
        ["api", "v1", "settings", "costs"] if req.method == "GET" => {
            authed(api_auth(state, req), h_costs_list(state).await)
        }
        ["api", "v1", "settings", "costs"] if req.method == "POST" => {
            authed(api_auth(state, req), h_cost_create(state, req).await)
        }
        ["api", "v1", "settings", "costs", id] if req.method == "DELETE" => {
            authed(api_auth(state, req), h_cost_delete(state, id).await)
        }
        ["api", "v1", "settings", "costs", "report"] if req.method == "GET" => {
            authed(api_auth(state, req), h_costs_report(state).await)
        }
        ["api", "v1", "settings"] if req.method == "GET" => {
            authed(api_auth(state, req), h_settings_all(state).await)
        }
        ["api", "v1", "events"] if req.method == "GET" => {
            authed(api_auth(state, req), h_events(state, req).await)
        }
        ["api", "v1", "backup"] if req.method == "POST" => {
            authed(api_auth(state, req), h_backup(state, req).await)
        }
        ["api", "v1", "restore"] if req.method == "POST" => {
            authed(api_auth(state, req), h_restore(state, req).await)
        }
        ["api", "v1", "net", "exit-ip"] if req.method == "GET" => {
            authed(api_auth(state, req), h_exit_ip(state).await)
        }
        ["api", "v1", "collector", "usage"] if req.method == "POST" => {
            h_collector_usage(state, req).await
        }
        // Smart split-routing — /api/v1/routing/* (frozen app contract).
        ["api", "v1", "routing", "rules"] if req.method == "GET" => {
            authed(api_auth(state, req), h_routing_rules_get(state).await)
        }
        ["api", "v1", "routing", "rules"] if req.method == "POST" => authed(
            api_auth(state, req),
            h_routing_rule_create(state, req).await,
        ),
        ["api", "v1", "routing", "rules", id] if req.method == "PUT" => authed(
            api_auth(state, req),
            h_routing_rule_update(state, id, req).await,
        ),
        ["api", "v1", "routing", "rules", id] if req.method == "DELETE" => {
            authed(api_auth(state, req), h_routing_rule_delete(state, id).await)
        }
        ["api", "v1", "routing", "rulesets"] if req.method == "GET" => {
            authed(api_auth(state, req), h_routing_rulesets_list(state).await)
        }
        ["api", "v1", "routing", "rulesets"] if req.method == "POST" => authed(
            api_auth(state, req),
            h_routing_ruleset_snapshot(state, req).await,
        ),
        ["api", "v1", "routing", "rulesets", version, "activate"] if req.method == "POST" => {
            match version.parse::<i64>() {
                Ok(v) => authed(
                    api_auth(state, req),
                    h_routing_ruleset_activate(state, v).await,
                ),
                Err(_) => err_json("bad_request", "version must be an integer", 400),
            }
        }
        ["api", "v1", "routing", "test"] if req.method == "POST" => {
            authed(api_auth(state, req), h_routing_test(state, req).await)
        }
        ["panel", ..] => crate::panel::handle_panel(state, req).await,
        _ => err_json("not_found", "not found", 404),
    }
}

/// Apply an auth check to a handler response: auth failure wins.
fn authed(auth: Result<(), HttpResponse>, resp: HttpResponse) -> HttpResponse {
    match auth {
        Ok(()) => resp,
        Err(e) => e,
    }
}

pub(crate) fn json_body<T: serde::de::DeserializeOwned>(
    req: &HttpRequest,
) -> Result<T, HttpResponse> {
    serde_json::from_slice(&req.body)
        .map_err(|e| err_json("bad_request", &format!("invalid JSON: {e}"), 400))
}

pub(crate) fn store_err(e: StoreError) -> HttpResponse {
    match e {
        StoreError::NotFound(m) => err_json("not_found", &m, 404),
        StoreError::Conflict(m) => err_json("conflict", &m, 409),
        StoreError::BadEventKey(k) => err_json("bad_request", &format!("bad event key {k}"), 400),
        StoreError::Sqlite(e) => err_json("internal", &format!("db error: {e}"), 500),
    }
}

// ---------------------------------------------------------------------------
// Status & auth
// ---------------------------------------------------------------------------

async fn h_status(state: &AppState) -> HttpResponse {
    let engine_reachable = state.engine.health().await.is_ok();
    let db_ok = state.db_lock().is_ok();
    ok_json(serde_json::json!({
        "role": state.config.role.to_string(),
        "mode": format!("{:?}", state.config.mode).to_lowercase(),
        "version": state.config.version,
        "started_at": state.config.started_at,
        "engine": { "reachable": engine_reachable },
        "db": { "ok": db_ok },
    }))
}

async fn h_health(_state: &AppState) -> HttpResponse {
    ok_json(serde_json::json!({"ok": true}))
}

async fn h_auth_login(state: &AppState, req: &HttpRequest) -> HttpResponse {
    if let Err(retry) = check_rate(state, req.peer.ip(), "auth", AUTH_RATE_PER_MIN, Some(1)) {
        return rate_limited_response(retry);
    }
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let hash = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        match store::get_setting(&conn, "panel.password_hash") {
            Ok(Some(h)) => h,
            Ok(None) => {
                return err_json(
                    "conflict",
                    "panel password not set (provision must set it)",
                    409,
                )
            }
            Err(e) => return store_err(e),
        }
    };
    if !crypto::verify_password(password, &hash) {
        // Generic failure; the rate limiter + 1s spacing tarpit brute force.
        return err_json("unauthorized", "invalid credentials", 401);
    }
    let token = crypto::new_token();
    let h = token_hash(&token);
    let now = now_secs();
    {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        if let Err(e) =
            store::create_session(&conn, &h, now, now + 12 * 3600, &req.peer.ip().to_string())
        {
            return store_err(e);
        }
        let _ = store::log_event(
            &conn,
            now,
            "login",
            "panel",
            &serde_json::json!({"ip": req.peer.ip().to_string()}),
        );
    }
    let mut r = ok_json(serde_json::json!({"ok": true}));
    r.extra.push((
        "Set-Cookie".to_string(),
        format!("zadmin={token}; HttpOnly; SameSite=Strict; Path=/panel; Max-Age=43200"),
    ));
    r
}

async fn h_auth_logout(state: &AppState, req: &HttpRequest) -> HttpResponse {
    if let Some(h) = session_of(state, req) {
        if let Ok(conn) = state.db_lock() {
            let _ = store::delete_session(&conn, &h);
        }
    }
    let mut r = ok_json(serde_json::json!({"ok": true}));
    r.extra.push((
        "Set-Cookie".to_string(),
        "zadmin=; HttpOnly; SameSite=Strict; Path=/panel; Max-Age=0".to_string(),
    ));
    r
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

fn other_role(role: ServerRole) -> ServerRole {
    match role {
        ServerRole::Gateway => ServerRole::Exit,
        ServerRole::Exit => ServerRole::Gateway,
    }
}

async fn h_servers(state: &AppState) -> HttpResponse {
    let role = state.config.role;
    let engine_reachable = state.engine.health().await.is_ok();
    let tunnel_state = match state.engine.tunnel().await {
        Ok(v) => v.get("tunnels").cloned().unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    };
    let mut servers = vec![serde_json::json!({
        "role": role.to_string(),
        "host": state.config.exit_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
        "engine_reachable": engine_reachable,
        "tunnel": tunnel_state,
        "note": "local server (this zray-admin)",
    })];
    // Peer: only what the provision-time config tells us; no live facts.
    if let Some(target) = &state.config.collector_target {
        servers.push(serde_json::json!({
            "role": other_role(role).to_string(),
            "host": target,
            "engine_reachable": false,
            "note": "peer server: live facts unavailable from this node (provision-time address only)",
        }));
    }
    ok_json(serde_json::json!({ "servers": servers }))
}

async fn h_server_health(state: &AppState, role: &str) -> HttpResponse {
    let want: ServerRole = match role {
        "gateway" => ServerRole::Gateway,
        "exit" => ServerRole::Exit,
        _ => return err_json("not_found", "unknown server role", 404),
    };
    if want != state.config.role {
        return err_json(
            "not_found",
            "peer server health is not proxied by this node",
            404,
        );
    }
    match state.engine.health().await {
        Ok(v) => ok_json(v),
        Err(e) => err_json("bad_request", &format!("engine unreachable: {e}"), 502),
    }
}

async fn h_server_probe(state: &AppState, role: &str) -> HttpResponse {
    let want: ServerRole = match role {
        "gateway" => ServerRole::Gateway,
        "exit" => ServerRole::Exit,
        _ => return err_json("not_found", "unknown server role", 404),
    };
    if want != state.config.role {
        return err_json(
            "not_found",
            "peer server probing is not supported from this node",
            404,
        );
    }
    let health = state.engine.health().await.ok();
    let tunnel = state.engine.tunnel().await.ok();
    ok_json(serde_json::json!({
        "role": role,
        "at": now_secs(),
        "engine_reachable": health.is_some(),
        "health": health.unwrap_or(serde_json::Value::Null),
        "tunnel": tunnel.unwrap_or(serde_json::Value::Null),
    }))
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

async fn h_users_list(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_users(&conn) {
        Ok(users) => ok_json(serde_json::json!({ "users": users })),
        Err(e) => store_err(e),
    }
}

async fn h_user_create(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() || name.len() > 128 {
        return err_json("bad_request", "name is required (max 128 chars)", 400);
    }
    let now = now_secs();
    let user = store::User {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        note: body
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        created_at: now,
        expires_at: body.get("expires_at").and_then(|v| v.as_i64()),
        revoked: false,
        quota_bytes: body.get("quota_bytes").and_then(|v| v.as_i64()),
        quota_mbps: body.get("quota_mbps").and_then(|v| v.as_i64()),
        max_devices: body
            .get("max_devices")
            .and_then(|v| v.as_i64())
            .unwrap_or(8)
            .clamp(1, 64),
    };
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = store::create_user(&conn, &user) {
        return store_err(e);
    }
    let _ = store::log_event(
        &conn,
        now,
        "user_create",
        "api",
        &serde_json::json!({"user_id": user.id}),
    );
    let mut r = ok_json(serde_json::json!({ "user": user }));
    r.status = 201;
    r
}

async fn h_user_get(state: &AppState, id: &str) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::get_user(&conn, id) {
        Ok(u) => ok_json(serde_json::json!({ "user": u })),
        Err(e) => store_err(e),
    }
}

async fn h_user_patch(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // Optional-nullable fields: present+null clears, absent keeps.
    let opt_i64 = |k: &str| {
        if body.get(k).is_some() {
            Some(body.get(k).and_then(|v| v.as_i64()))
        } else {
            None
        }
    };
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::patch_user(
        &conn,
        id,
        body.get("name").and_then(|v| v.as_str()),
        body.get("note").and_then(|v| v.as_str()),
        opt_i64("quota_bytes"),
        opt_i64("quota_mbps"),
        opt_i64("expires_at"),
    ) {
        Ok(u) => ok_json(serde_json::json!({ "user": u })),
        Err(e) => store_err(e),
    }
}

/// Revoke (or restore) a user: flips the flag on the user + all their
/// devices, rewrites every affected users file, reloads the engine.
async fn h_user_revoke(state: &AppState, id: &str, revoked: bool) -> HttpResponse {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        if let Err(e) = store::set_user_revoked(&conn, id, revoked) {
            return store_err(e);
        }
        let devices = match store::list_user_devices(&conn, id) {
            Ok(d) => d,
            Err(e) => return store_err(e),
        };
        for d in &devices {
            if let Err(e) = store::set_device_revoked(&conn, &d.id, revoked) {
                return store_err(e);
            }
        }
        let mut tags = std::collections::HashSet::new();
        for d in &devices {
            if let Ok(creds) = store::list_device_credentials(&conn, &d.id) {
                for c in creds {
                    tags.insert(c.inbound_tag.clone());
                }
            }
        }
        let _ = store::log_event(
            &conn,
            now,
            if revoked { "revoke" } else { "restore" },
            "api",
            &serde_json::json!({"user_id": id}),
        );
        tags.into_iter().collect()
    };
    let reload = sync_tags(state, &tags).await;
    ok_json(serde_json::json!({
        "ok": true, "revoked": revoked,
        "engine_reload": reload,
    }))
}

// ---------------------------------------------------------------------------
// Devices & credential lifecycle
// ---------------------------------------------------------------------------

/// Rewrite users files + engine reload for a set of tags.
/// Returns per-tag outcomes; a 404 from the engine means "file written,
/// engine needs restart or is older" — reported honestly, not as failure.
pub(crate) async fn sync_tags(state: &AppState, tags: &[String]) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for tag in tags {
        let r = engine::sync_tag(
            &state.db,
            &state.config.db_key,
            &state.config.users_dir,
            &state.engine,
            tag,
        )
        .await;
        out.insert(
            tag.clone(),
            match r {
                Ok(n) => serde_json::json!({"ok": true, "entries": n}),
                Err(msg) => serde_json::json!({"ok": false, "note": msg}),
            },
        );
    }
    serde_json::Value::Object(out)
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct IssuedConfigOut {
    pub(crate) inbound_tag: String,
    pub(crate) protocol: String,
    pub(crate) link: String,
    pub(crate) qr_svg: Option<String>,
    pub(crate) singbox: serde_json::Value,
    pub(crate) mihomo: String,
}

/// Render configs for a device's active credentials (decrypts server-side).
pub(crate) fn render_device_configs(
    state: &AppState,
    device: &store::Device,
) -> Result<Vec<IssuedConfigOut>, HttpResponse> {
    let conn = state.db_lock()?;
    let creds = store::active_device_credentials(&conn, &device.id).map_err(store_err)?;
    let inbounds: HashMap<String, store::Inbound> = store::list_inbounds(&conn)
        .map_err(store_err)?
        .into_iter()
        .map(|i| (i.tag.clone(), i))
        .collect();
    let mut out = Vec::new();
    for cred in creds {
        let ib = match inbounds.get(&cred.inbound_tag) {
            Some(ib) => ib,
            None => continue,
        };
        let pt = crypto::open(&state.config.db_key, &cred.secret)
            .map_err(|_| err_json("internal", "credential undecryptable", 500))?;
        let secret: IssuedSecret = serde_json::from_slice(&pt)
            .map_err(|_| err_json("internal", "credential corrupt", 500))?;
        let Some(link) = subs::render_link(ib, &secret, &device.label) else {
            continue;
        };
        let tag = format!("{}-{}", device.label, cred.inbound_tag);
        let ob = subs::singbox_outbound(ib, &secret, &tag);
        out.push(IssuedConfigOut {
            inbound_tag: cred.inbound_tag.clone(),
            protocol: cred.protocol.clone(),
            qr_svg: subs::qr_svg(&link),
            singbox: ob
                .as_ref()
                .map(|o| serde_json::to_value(o).unwrap())
                .unwrap_or(serde_json::Value::Null),
            mihomo: ob.as_ref().and_then(subs::mihomo_proxy).unwrap_or_default(),
            link,
        });
    }
    Ok(out)
}

/// Issue a device: create the device row, generate per-inbound credentials,
/// seal them, write users files, reload the engine.
/// Returns the device + the rendered configs — the ONLY call that ever
/// returns secrets, once.
pub(crate) async fn issue_device(
    state: &AppState,
    user_id: &str,
    label: &str,
    inbound_tags: Option<Vec<String>>,
    expires_at: Option<i64>,
    now: i64,
) -> Result<(store::Device, Vec<IssuedConfigOut>), HttpResponse> {
    let device = store::Device {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        label: label.to_string(),
        created_at: now,
        expires_at,
        revoked: false,
        last_seen_at: None,
    };
    let tags: Vec<String> = {
        let conn = state.db_lock()?;
        let user = store::get_user(&conn, user_id).map_err(store_err)?;
        if user.revoked {
            return Err(err_json("conflict", "user is revoked", 409));
        }
        let existing = store::list_user_devices(&conn, user_id).map_err(store_err)?;
        if existing.len() as i64 >= user.max_devices {
            return Err(err_json("conflict", "user device limit reached", 409));
        }
        let all = store::enabled_inbounds(&conn).map_err(store_err)?;
        let wanted: Vec<store::Inbound> = match &inbound_tags {
            Some(tags) => {
                let mut v = Vec::new();
                for t in tags {
                    match all.iter().find(|i| &i.tag == t) {
                        Some(ib) => v.push(ib.clone()),
                        None => {
                            return Err(err_json(
                                "bad_request",
                                &format!("unknown or disabled inbound {t}"),
                                400,
                            ))
                        }
                    }
                }
                v
            }
            None => all,
        };
        // Refuse non-issuable protocols honestly, before creating anything.
        for ib in &wanted {
            if !subs::issuable(&ib.protocol) {
                return Err(err_json(
                    "bad_request",
                    &format!(
                        "inbound {} uses protocol {} which has no server side; not issued",
                        ib.tag, ib.protocol
                    ),
                    400,
                ));
            }
        }
        store::create_device(&conn, &device).map_err(store_err)?;
        for ib in &wanted {
            let material = subs::generate_material(&ib.protocol, &ib.params).ok_or_else(|| {
                err_json(
                    "bad_request",
                    &format!("cannot generate material for {}", ib.protocol),
                    400,
                )
            })?;
            let identity_hash = crypto::identity_hash(&state.config.usage_salt, &material.identity);
            let sealed = crypto::seal(
                &state.config.db_key,
                &serde_json::to_vec(&material).unwrap(),
            )
            .map_err(|_| err_json("internal", "seal failed", 500))?;
            let cred = store::Credential {
                id: uuid::Uuid::new_v4().to_string(),
                device_id: device.id.clone(),
                inbound_tag: ib.tag.clone(),
                protocol: ib.protocol.clone(),
                identity_hash,
                secret: sealed,
                created_at: now,
                revoked: false,
            };
            // Skip inbounds whose link can't be rendered (missing params):
            // honest skip, not a fake credential. But still store the
            // credential so the engine authenticates it; the panel shows
            // "no link builder output".
            store::create_credential(&conn, &cred).map_err(store_err)?;
        }
        let _ = store::log_event(
            &conn,
            now,
            "issue",
            "api",
            &serde_json::json!({"device_id": device.id, "user_id": user_id}),
        );
        wanted.into_iter().map(|i| i.tag).collect()
    };
    let _reload = sync_tags(state, &tags).await;
    let configs = render_device_configs(state, &device)?;
    Ok((device, configs))
}

async fn h_devices_list(state: &AppState, user_id: &str) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    // Metadata only — never secrets.
    let devices = match store::list_user_devices(&conn, user_id) {
        Ok(d) => d,
        Err(e) => return store_err(e),
    };
    let devices: Vec<serde_json::Value> = devices
        .into_iter()
        .map(|d| {
            let creds = store::list_device_credentials(&conn, &d.id).unwrap_or_default();
            let creds: Vec<_> = creds
                .into_iter()
                .map(|c| {
                    serde_json::json!({
                        "inbound_tag": c.inbound_tag, "protocol": c.protocol,
                        "revoked": c.revoked, "created_at": c.created_at,
                    })
                })
                .collect();
            serde_json::json!({
                "id": d.id, "user_id": d.user_id, "label": d.label,
                "created_at": d.created_at, "expires_at": d.expires_at,
                "revoked": d.revoked, "last_seen_at": d.last_seen_at,
                "credentials": creds,
            })
        })
        .collect();
    ok_json(serde_json::json!({ "devices": devices }))
}

async fn h_device_issue(state: &AppState, user_id: &str, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if label.is_empty() || label.len() > 128 {
        return err_json("bad_request", "label is required (max 128 chars)", 400);
    }
    let inbound_tags = body.get("inbounds").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    });
    let now = now_secs();
    match issue_device(
        state,
        user_id,
        label,
        inbound_tags,
        body.get("expires_at").and_then(|v| v.as_i64()),
        now,
    )
    .await
    {
        Ok((device, configs)) => {
            let mut r = ok_json(serde_json::json!({ "device": device, "credentials": configs }));
            r.status = 201;
            r
        }
        Err(e) => e,
    }
}

async fn h_device_get(state: &AppState, id: &str) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::get_device(&conn, id) {
        Ok(d) => ok_json(serde_json::json!({ "device": d })),
        Err(e) => store_err(e),
    }
}

async fn h_device_revoke(state: &AppState, id: &str, revoked: bool) -> HttpResponse {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let device = match store::get_device(&conn, id) {
            Ok(d) => d,
            Err(e) => return store_err(e),
        };
        if let Err(e) = store::set_device_revoked(&conn, id, revoked) {
            return store_err(e);
        }
        let tags: Vec<String> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| c.inbound_tag).collect())
            .unwrap_or_default();
        let _ = store::log_event(
            &conn,
            now,
            if revoked { "revoke" } else { "restore" },
            "api",
            &serde_json::json!({"device_id": id, "user_id": device.user_id}),
        );
        tags
    };
    let reload = sync_tags(state, &tags).await;
    ok_json(serde_json::json!({ "ok": true, "revoked": revoked, "engine_reload": reload }))
}

async fn h_device_reissue(state: &AppState, id: &str) -> HttpResponse {
    // Rotate: revoke old credentials atomically with new issuance.
    let now = now_secs();
    let (user_id, label, expires_at, inbound_tags) = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let device = match store::get_device(&conn, id) {
            Ok(d) => d,
            Err(e) => return store_err(e),
        };
        if device.revoked {
            return err_json("conflict", "device is revoked; restore it first", 409);
        }
        let old: Vec<String> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| c.id).collect())
            .unwrap_or_default();
        let tags: Vec<String> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| c.inbound_tag).collect())
            .unwrap_or_default();
        // Mark old revoked (keep rows for history; secrets stay sealed).
        for cid in &old {
            let _ = conn.execute(
                "UPDATE credentials SET revoked=1 WHERE id=?1",
                rusqlite::params![cid],
            );
        }
        (device.user_id, device.label, device.expires_at, tags)
    };
    let tags_opt = if inbound_tags.is_empty() {
        None
    } else {
        Some(inbound_tags)
    };
    // Issue a fresh device row would change the device id; instead we add new
    // credentials to the SAME device (old ones revoked above).
    let new_device_id = id.to_string();
    let configs = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let all = match store::enabled_inbounds(&conn) {
            Ok(v) => v,
            Err(e) => return store_err(e),
        };
        let wanted: Vec<store::Inbound> = match &tags_opt {
            Some(tags) => all.into_iter().filter(|i| tags.contains(&i.tag)).collect(),
            None => all,
        };
        let mut tags_out = Vec::new();
        for ib in &wanted {
            let Some(material) = subs::generate_material(&ib.protocol, &ib.params) else {
                continue;
            };
            let identity_hash = crypto::identity_hash(&state.config.usage_salt, &material.identity);
            let sealed = match crypto::seal(
                &state.config.db_key,
                &serde_json::to_vec(&material).unwrap(),
            ) {
                Ok(s) => s,
                Err(_) => return err_json("internal", "seal failed", 500),
            };
            // Replace the (device, tag) row: delete revoked old, insert new.
            let _ = conn.execute(
                "DELETE FROM credentials WHERE device_id=?1 AND inbound_tag=?2 AND revoked=1",
                rusqlite::params![new_device_id, ib.tag],
            );
            let cred = store::Credential {
                id: uuid::Uuid::new_v4().to_string(),
                device_id: new_device_id.clone(),
                inbound_tag: ib.tag.clone(),
                protocol: ib.protocol.clone(),
                identity_hash,
                secret: sealed,
                created_at: now,
                revoked: false,
            };
            if let Err(e) = store::create_credential(&conn, &cred) {
                return store_err(e);
            }
            tags_out.push(ib.tag.clone());
        }
        let _ = store::log_event(
            &conn,
            now,
            "reissue",
            "api",
            &serde_json::json!({"device_id": new_device_id}),
        );
        tags_out
    };
    let _reload = sync_tags(state, &configs).await;
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let device = match store::get_device(&conn, id) {
        Ok(d) => d,
        Err(e) => return store_err(e),
    };
    drop(conn);
    let _ = (user_id, label, expires_at);
    match render_device_configs(state, &device) {
        Ok(configs) => ok_json(serde_json::json!({ "device": device, "credentials": configs })),
        Err(e) => e,
    }
}

async fn h_device_configs(state: &AppState, id: &str) -> HttpResponse {
    let device = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        match store::get_device(&conn, id) {
            Ok(d) => d,
            Err(e) => return store_err(e),
        }
    };
    match render_device_configs(state, &device) {
        Ok(configs) => ok_json(serde_json::json!({ "device": device, "credentials": configs })),
        Err(e) => e,
    }
}

async fn h_device_delete(state: &AppState, id: &str) -> HttpResponse {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let tags: Vec<String> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| c.inbound_tag).collect())
            .unwrap_or_default();
        if let Err(e) = store::delete_device(&conn, id) {
            return store_err(e);
        }
        let _ = store::log_event(
            &conn,
            now,
            "delete",
            "api",
            &serde_json::json!({"device_id": id}),
        );
        tags
    };
    let reload = sync_tags(state, &tags).await;
    ok_json(serde_json::json!({ "ok": true, "engine_reload": reload }))
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

pub(crate) fn subscription_public_url(state: &AppState, token: &str) -> Option<String> {
    let host = state.config.exit_host.as_ref()?;
    Some(format!(
        "https://{host}:{}/s/{token}",
        state.config.sub_port
    ))
}

async fn h_subs_list(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_subscriptions(&conn) {
        Ok(subs) => {
            // Never expose token hashes or encrypted bodies in the list.
            let subs: Vec<serde_json::Value> = subs
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id, "kind": s.kind, "name": s.name,
                        "device_id": s.device_id, "source_url": s.source_url,
                        "imported_at": s.imported_at, "config_count": s.config_count,
                        "managed": s.managed, "expires_at": s.expires_at,
                        "revoked": s.revoked, "created_at": s.created_at,
                    })
                })
                .collect();
            ok_json(serde_json::json!({ "subscriptions": subs }))
        }
        Err(e) => store_err(e),
    }
}

async fn h_sub_personal(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let device_id = body.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
    let now = now_secs();
    let (sub, token) = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let device = match store::get_device(&conn, device_id) {
            Ok(d) => d,
            Err(e) => return store_err(e),
        };
        if device.revoked {
            return err_json("conflict", "device is revoked", 409);
        }
        let token = crypto::new_token();
        let sub = store::Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            kind: "personal".to_string(),
            name: format!("{} — personal", device.label),
            device_id: Some(device.id.clone()),
            token_hash: Some(token_hash(&token)),
            source_url: None,
            imported_at: None,
            body_crypt: None,
            config_count: 0,
            managed: true,
            expires_at: body.get("expires_at").and_then(|v| v.as_i64()),
            revoked: false,
            created_at: now,
        };
        if let Err(e) = store::create_subscription(&conn, &sub) {
            return store_err(e);
        }
        let _ = store::log_event(
            &conn,
            now,
            "sub_issue",
            "api",
            &serde_json::json!({"subscription_id": sub.id, "device_id": device.id}),
        );
        (sub, token)
    };
    let url = subscription_public_url(state, &token);
    ok_json(serde_json::json!({
        "subscription": { "id": sub.id, "kind": sub.kind, "name": sub.name,
                          "device_id": sub.device_id, "managed": true,
                          "expires_at": sub.expires_at, "revoked": false },
        "url": url,
        "note": url.as_ref().map(|_| "fetchable only when the opt-in public sub listener is enabled; otherwise use the QR / copy flow"),
        "qr_svg": url.as_deref().and_then(subs::qr_svg),
    }))
}

async fn h_sub_rotate(state: &AppState, id: &str) -> HttpResponse {
    let now = now_secs();
    let token = crypto::new_token();
    {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        if let Err(e) = store::rotate_subscription_token(&conn, id, &token_hash(&token)) {
            return store_err(e);
        }
        let _ = store::log_event(
            &conn,
            now,
            "sub_rotate",
            "api",
            &serde_json::json!({"subscription_id": id}),
        );
    }
    let url = subscription_public_url(state, &token);
    ok_json(serde_json::json!({
        "ok": true,
        "url": url,
        "qr_svg": url.as_deref().and_then(subs::qr_svg),
    }))
}

async fn h_sub_external(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let body_text = body.get("body_text").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return err_json("bad_request", "name is required", 400);
    }
    // Parse only — the app fetched the URL; the server never fetches it.
    let parsed = zero_config::parse_subscription(body_text);
    let count = parsed.iter().filter(|r| r.is_ok()).count() as i64;
    let now = now_secs();
    let sealed = match crypto::seal(&state.config.db_key, body_text.as_bytes()) {
        Ok(s) => s,
        Err(_) => return err_json("internal", "seal failed", 500),
    };
    let sub = store::Subscription {
        id: uuid::Uuid::new_v4().to_string(),
        kind: "external".to_string(),
        name: name.to_string(),
        device_id: None,
        token_hash: None,
        source_url: body
            .get("source_url")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        imported_at: Some(now),
        body_crypt: Some(sealed),
        config_count: count,
        managed: false,
        expires_at: None,
        revoked: false,
        created_at: now,
    };
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = store::create_subscription(&conn, &sub) {
        return store_err(e);
    }
    let _ = store::log_event(
        &conn,
        now,
        "sub_import",
        "api",
        &serde_json::json!({"subscription_id": sub.id, "config_count": count}),
    );
    let mut r = ok_json(serde_json::json!({
        "subscription": { "id": sub.id, "kind": "external", "name": sub.name,
                          "config_count": count, "managed": false },
        "unmanaged_note": "unmanaged — usage, quotas and revocation unavailable; exit IP unknown",
    }));
    r.status = 201;
    r
}

async fn h_sub_external_refresh(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let body_text = body.get("body_text").and_then(|v| v.as_str()).unwrap_or("");
    let parsed = zero_config::parse_subscription(body_text);
    let count = parsed.iter().filter(|r| r.is_ok()).count() as i64;
    let now = now_secs();
    let sealed = match crypto::seal(&state.config.db_key, body_text.as_bytes()) {
        Ok(s) => s,
        Err(_) => return err_json("internal", "seal failed", 500),
    };
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let old = match store::get_subscription(&conn, id) {
        Ok(s) => s,
        Err(e) => return store_err(e),
    };
    if let Err(e) = store::update_external_body(&conn, id, &sealed, count, now) {
        return store_err(e);
    }
    let _ = store::log_event(
        &conn,
        now,
        "sub_refresh",
        "api",
        &serde_json::json!({
            "subscription_id": id,
            "old_config_count": old.config_count,
            "new_config_count": count,
        }),
    );
    ok_json(serde_json::json!({ "ok": true, "config_count": count }))
}

async fn h_sub_revoke(state: &AppState, id: &str) -> HttpResponse {
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = store::set_subscription_revoked(&conn, id, true) {
        return store_err(e);
    }
    let _ = store::log_event(
        &conn,
        now,
        "sub_revoke",
        "api",
        &serde_json::json!({"subscription_id": id}),
    );
    ok_json(serde_json::json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Modem accounts (Design G) — /api/v1/modem/* (frozen contract §3.2m)
//
// Frozen app contract (shapes per the Android agent's RouterApi.kt):
// - GET    /api/v1/modem/capabilities       → {model, firmware?, vpn_client:{protocols, fields}, note?}
// - GET    /api/v1/modem/guide?protocol=l2tp → {steps:[{title, body}]}
// - GET    /api/v1/modem/security?protocol=l2tp → {findings:[{id, severity, title, detail}]}
// - GET    /api/v1/modem/accounts           → {accounts:[ModemAccount]}
// - POST   /api/v1/modem/accounts           {name,...} → {account, credentials:[ModemCredential]}
// - GET    /api/v1/modem/accounts/{id}      → {account, credentials:[ModemCredential]}
// - POST   /api/v1/modem/accounts/{id}/consent → {ok, consent_at}
// - POST   /api/v1/modem/accounts/{id}/reveal  → {credentials:[...]}
// - POST   /api/v1/modem/accounts/{id}/rotate  → {credentials:[...]}
// - DELETE /api/v1/modem/accounts/{id}      → {ok:true}
// (+ POST .../revoke, .../restore, GET .../usage, .../status for the web panel)
//
// ModemCredential: {field_id, label, value, sensitive} — field ids follow the
// H158-381 form order (Design G §c): connection_type, lns_address, hostname,
// tunnel_password, ppp_username, ppp_password.
// ModemAccount: {id, name, username, status, last_seen, data_used}.
// The informed-consent gate (Design G §d, owner-confirmed) still applies:
// credentials are returned only after consent is recorded; otherwise the
// response carries credentials:[] + consent_required:true.
// ---------------------------------------------------------------------------

/// The `usage_daily.device_id` key for a modem account's rollups.
fn modem_usage_key(account_id: &str) -> String {
    format!("modem:{account_id}")
}

fn modem_data_used(conn: &rusqlite::Connection, account_id: &str) -> i64 {
    let key = modem_usage_key(account_id);
    conn.query_row(
        "SELECT COALESCE(SUM(bytes_up + bytes_down), 0) FROM usage_daily WHERE device_id=?1",
        rusqlite::params![key],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

/// App-facing account view (frozen shape). Extra keys are ignored by the app.
fn modem_account_view(conn: &rusqlite::Connection, m: &store::ModemAccount) -> serde_json::Value {
    // App status vocabulary: connected | last_seen | never (raw "unknown"
    // passes through honestly when the session monitor never reported).
    let status = match m.status.as_str() {
        "disconnected" => "last_seen",
        s => s,
    };
    serde_json::json!({
        "id": m.id,
        "name": m.label,
        "username": m.username,
        "status": status,
        "last_seen": m.last_seen_at.map(|t| t.to_string()),
        "data_used": modem_data_used(conn, &m.id),
        // Internal extras (app ignores unknown keys):
        "label": m.label,
        "hostname": m.hostname,
        "lns_address": m.lns_address,
        "connection_type": crate::modem::CONNECTION_TYPE,
        "consent_at": m.consent_at,
        "can_reveal": m.consent_at.is_some() && !m.revoked,
        "created_at": m.created_at,
        "revoked": m.revoked,
    })
}

/// Decrypt the sealed passwords of a modem account. Only called after the
/// informed-consent gate has been verified.
fn modem_open_secrets(
    state: &AppState,
    m: &store::ModemAccount,
) -> Result<(String, String), HttpResponse> {
    let tunnel = crypto::open(&state.config.db_key, &m.tunnel_secret)
        .map_err(|_| err_json("internal", "cannot decrypt tunnel password", 500))?;
    let ppp = crypto::open(&state.config.db_key, &m.ppp_secret)
        .map_err(|_| err_json("internal", "cannot decrypt PPP password", 500))?;
    let tunnel = String::from_utf8(tunnel)
        .map_err(|_| err_json("internal", "tunnel password is not valid UTF-8", 500))?;
    let ppp = String::from_utf8(ppp)
        .map_err(|_| err_json("internal", "PPP password is not valid UTF-8", 500))?;
    Ok((tunnel, ppp))
}

/// The "Huawei H158-381 native VPN parameters" output: native modem fields in
/// firmware form order (Design G §c), never a v2ray subscription link.
fn modem_credentials(
    m: &store::ModemAccount,
    tunnel_password: &str,
    ppp_password: &str,
) -> serde_json::Value {
    let field = |id: &str, label: &str, value: &str, sensitive: bool| {
        serde_json::json!({
            "field_id": id,
            "label": label,
            "value": value,
            "sensitive": sensitive,
        })
    };
    serde_json::json!([
        field(
            "connection_type",
            "Connection type",
            crate::modem::CONNECTION_TYPE,
            false
        ),
        field("lns_address", "LNS address", &m.lns_address, false),
        field("hostname", "Hostname", &m.hostname, false),
        field("tunnel_password", "Tunnel password", tunnel_password, true),
        field("ppp_username", "PPP user name", &m.username, false),
        field("ppp_password", "PPP password", ppp_password, true),
    ])
}

/// Input for modem account issuance (shared by the REST handler and the panel).
pub(crate) struct ModemCreateInput {
    pub label: String,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub lns_address: Option<String>,
    pub consent: bool,
}

pub(crate) struct ModemIssueOut {
    pub account: store::ModemAccount,
    /// Present only when `consent` was given (one-time issuance).
    pub credentials: Option<serde_json::Value>,
}

/// Issue a modem account (Design G §e). Shared by `POST /api/v1/modem/accounts`
/// and the panel form. Protocol is fixed (L2TP VPN client); PPTP is refused.
pub(crate) async fn modem_issue(
    state: &AppState,
    input: ModemCreateInput,
) -> Result<ModemIssueOut, HttpResponse> {
    let label = input.label.trim();
    if label.is_empty() || label.len() > 128 {
        return Err(err_json(
            "bad_request",
            "label is required (max 128 chars)",
            400,
        ));
    }
    let username = match input.username.as_deref().map(str::trim) {
        Some(u) if !u.is_empty() => {
            if let Err(e) = crate::modem::validate_username(u) {
                return Err(err_json("bad_request", &e.to_string(), 400));
            }
            u.to_string()
        }
        _ => crate::modem::generate_username(),
    };
    let hostname = match input.hostname.as_deref().map(str::trim) {
        Some(h) if !h.is_empty() => {
            if h.len() > 253 {
                return Err(err_json("bad_request", "hostname too long (max 253)", 400));
            }
            h.to_string()
        }
        _ => crate::modem::generate_hostname(),
    };
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return Err(e),
    };
    let lns_address = match input.lns_address.as_deref().map(str::trim) {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => match store::get_setting(&conn, "modem.lns_address") {
            Ok(Some(a)) if !a.trim().is_empty() => a,
            _ => {
                return Err(err_json(
                    "conflict",
                    "LNS address is not configured: set modem.lns_address or pass lns_address",
                    409,
                ))
            }
        },
    };
    if store::get_modem_account_by_username(&conn, &username)
        .map_err(store_err)
        .map(|o| o.is_some())
        .unwrap_or(false)
    {
        return Err(err_json("conflict", "modem username already exists", 409));
    }
    let ppp_password = crate::modem::generate_ppp_password();
    let tunnel_password = crate::modem::generate_tunnel_password();
    let tunnel_sealed = match crypto::seal(&state.config.db_key, tunnel_password.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Err(err_json("internal", "cannot seal tunnel password", 500)),
    };
    let ppp_sealed = match crypto::seal(&state.config.db_key, ppp_password.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Err(err_json("internal", "cannot seal PPP password", 500)),
    };
    let now = now_secs();
    let account = store::ModemAccount {
        id: uuid::Uuid::new_v4().to_string(),
        label: label.to_string(),
        username: username.clone(),
        hostname,
        lns_address,
        tunnel_secret: tunnel_sealed,
        ppp_secret: ppp_sealed,
        consent_at: if input.consent { Some(now) } else { None },
        consent_note: if input.consent {
            "consent given at creation".to_string()
        } else {
            String::new()
        },
        status: "never".to_string(),
        last_seen_at: None,
        created_at: now,
        revoked: false,
    };
    if let Err(e) = store::create_modem_account(&conn, &account) {
        return Err(store_err(e));
    }
    let _ = store::log_event(
        &conn,
        now,
        "modem_create",
        "api",
        &serde_json::json!({"account_id": account.id, "label": label, "username": username, "consent": input.consent}),
    );
    let credentials = if input.consent {
        // One-time issuance: the owner confirmed the ⚠️ WEAK+ label first.
        Some(modem_credentials(&account, &tunnel_password, &ppp_password))
    } else {
        None
    };
    Ok(ModemIssueOut {
        account,
        credentials,
    })
}

async fn h_modem_create(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // Protocol is fixed: the firmware offers only L2TP (+PPTP, which we
    // refuse). There is deliberately no `protocol` field to select.
    if body.get("protocol").is_some() {
        return err_json(
            "bad_request",
            "protocol selection is not offered for modem accounts (L2TP VPN client only; PPTP refused)",
            400,
        );
    }
    // The app sends {name}; accept label as an alias.
    let label = body
        .get("label")
        .or_else(|| body.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let input = ModemCreateInput {
        label,
        username: body
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        hostname: body
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        lns_address: body
            .get("lns_address")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        consent: body
            .get("consent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    };
    match modem_issue(state, input).await {
        Ok(out) => {
            let conn = match state.db_lock() {
                Ok(c) => c,
                Err(e) => return e,
            };
            let mut body =
                serde_json::json!({ "account": modem_account_view(&conn, &out.account) });
            match out.credentials {
                Some(credentials) => body["credentials"] = credentials,
                None => {
                    body["credentials"] = serde_json::json!([]);
                    body["consent_required"] = serde_json::json!(true);
                    body["consent_text"] = serde_json::json!(crate::modem::CONSENT_TEXT);
                }
            }
            let mut r = ok_json(body);
            r.status = 201;
            r
        }
        Err(e) => e,
    }
}

async fn h_modem_list(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_modem_accounts(&conn) {
        Ok(accounts) => ok_json(serde_json::json!({
            "accounts": accounts.iter().map(|m| modem_account_view(&conn, m)).collect::<Vec<_>>(),
        })),
        Err(e) => store_err(e),
    }
}

/// Reveal the credentials array. Requires recorded consent; every reveal is
/// logged. Used by `GET /accounts/{id}` and `POST .../reveal`.
pub(crate) async fn modem_reveal_credentials(
    state: &AppState,
    id: &str,
) -> Result<serde_json::Value, HttpResponse> {
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return Err(e),
    };
    let account = match store::get_modem_account(&conn, id) {
        Ok(m) => m,
        Err(e) => return Err(store_err(e)),
    };
    if account.revoked {
        return Err(err_json("conflict", "account is revoked", 409));
    }
    if account.consent_at.is_none() {
        return Err(err_json(
            "forbidden",
            "informed consent is required before credentials are shown (POST .../consent)",
            403,
        ));
    }
    let (tunnel_password, ppp_password) = modem_open_secrets(state, &account)?;
    let _ = store::log_event(
        &conn,
        now,
        "modem_reveal",
        "api",
        &serde_json::json!({"account_id": id}),
    );
    Ok(modem_credentials(&account, &tunnel_password, &ppp_password))
}

async fn h_modem_get(state: &AppState, id: &str) -> HttpResponse {
    let account_view = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        match store::get_modem_account(&conn, id) {
            Ok(m) => modem_account_view(&conn, &m),
            Err(e) => return store_err(e),
        }
    };
    // Credentials only after consent; the reveal is logged. Without consent
    // the shape stays {account, credentials:[]} + consent_required.
    match modem_reveal_credentials(state, id).await {
        Ok(credentials) => {
            ok_json(serde_json::json!({ "account": account_view, "credentials": credentials }))
        }
        Err(e) if e.status == 403 => ok_json(serde_json::json!({
            "account": account_view,
            "credentials": [],
            "consent_required": true,
            "consent_text": crate::modem::CONSENT_TEXT,
        })),
        Err(e) => e,
    }
}

/// Record informed consent (Design G §d). Mandatory before any secret is shown.
async fn h_modem_consent(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if body.get("acknowledged").and_then(|v| v.as_bool()) != Some(true) {
        return err_json(
            "bad_request",
            "acknowledged:true is required — the ⚠️ WEAK+ limitations must be accepted before credentials are shown",
            400,
        );
    }
    let note = body
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if note.len() > 500 {
        return err_json("bad_request", "note too long (max 500)", 400);
    }
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let account = match store::get_modem_account(&conn, id) {
        Ok(m) => m,
        Err(e) => return store_err(e),
    };
    if account.revoked {
        return err_json("conflict", "account is revoked", 409);
    }
    if let Err(e) = store::record_modem_consent(&conn, id, now, note) {
        return store_err(e);
    }
    let _ = store::log_event(
        &conn,
        now,
        "modem_consent",
        "api",
        &serde_json::json!({"account_id": id}),
    );
    ok_json(serde_json::json!({ "ok": true, "consent_at": now }))
}

async fn h_modem_reveal(state: &AppState, id: &str) -> HttpResponse {
    match modem_reveal_credentials(state, id).await {
        Ok(credentials) => ok_json(serde_json::json!({ "credentials": credentials })),
        Err(e) => e,
    }
}

/// Rotate passwords and return the new credentials array once (consent
/// required). Shared by the REST handler and the panel.
pub(crate) async fn modem_rotate_credentials(
    state: &AppState,
    id: &str,
) -> Result<serde_json::Value, HttpResponse> {
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return Err(e),
    };
    let account = match store::get_modem_account(&conn, id) {
        Ok(m) => m,
        Err(e) => return Err(store_err(e)),
    };
    if account.revoked {
        return Err(err_json("conflict", "account is revoked", 409));
    }
    if account.consent_at.is_none() {
        return Err(err_json(
            "forbidden",
            "informed consent is required before credentials are shown (POST .../consent)",
            403,
        ));
    }
    let ppp_password = crate::modem::generate_ppp_password();
    let tunnel_password = crate::modem::generate_tunnel_password();
    let tunnel_sealed = match crypto::seal(&state.config.db_key, tunnel_password.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Err(err_json("internal", "cannot seal tunnel password", 500)),
    };
    let ppp_sealed = match crypto::seal(&state.config.db_key, ppp_password.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Err(err_json("internal", "cannot seal PPP password", 500)),
    };
    if let Err(e) = store::rotate_modem_secrets(&conn, id, &tunnel_sealed, &ppp_sealed) {
        return Err(store_err(e));
    }
    let _ = store::log_event(
        &conn,
        now,
        "modem_rotate",
        "api",
        &serde_json::json!({"account_id": id}),
    );
    let account = match store::get_modem_account(&conn, id) {
        Ok(m) => m,
        Err(e) => return Err(store_err(e)),
    };
    Ok(modem_credentials(&account, &tunnel_password, &ppp_password))
}

async fn h_modem_rotate(state: &AppState, id: &str) -> HttpResponse {
    match modem_rotate_credentials(state, id).await {
        Ok(credentials) => ok_json(serde_json::json!({ "credentials": credentials })),
        Err(e) => e,
    }
}

async fn h_modem_revoke(state: &AppState, id: &str, revoked: bool) -> HttpResponse {
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = store::set_modem_revoked(&conn, id, revoked) {
        return store_err(e);
    }
    let kind = if revoked {
        "modem_revoke"
    } else {
        "modem_restore"
    };
    let _ = store::log_event(
        &conn,
        now,
        kind,
        "api",
        &serde_json::json!({"account_id": id}),
    );
    ok_json(serde_json::json!({ "ok": true }))
}

/// Per-modem usage: rollup rows keyed `modem:<account_id>` (ingested by the
/// poller from the provisioner's session monitor, Design G §g.8) plus the
/// live snapshot from the status file when available.
async fn h_modem_usage(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let from = req
        .query
        .get("from")
        .cloned()
        .unwrap_or_else(|| "2000-01-01".to_string());
    let to = req.query.get("to").cloned().unwrap_or_else(today_utc);
    let key = modem_usage_key(id);
    let (username, rows) = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        // 404 for unknown accounts so usage can't be probed by id guessing.
        let username = match store::get_modem_account(&conn, id) {
            Ok(m) => m.username,
            Err(e) => return store_err(e),
        };
        let rows = match store::usage_range(&conn, &from, &to) {
            Ok(r) => r,
            Err(e) => return store_err(e),
        };
        (username, rows)
    };
    let rows: Vec<&store::UsageRow> = rows
        .iter()
        .filter(|r| r.device_id.as_deref() == Some(key.as_str()))
        .collect();
    let total_up: i64 = rows.iter().map(|r| r.bytes_up).sum();
    let total_down: i64 = rows.iter().map(|r| r.bytes_down).sum();
    let mut out = serde_json::json!({
        "account_id": id,
        "from": from,
        "to": to,
        "total_up": total_up,
        "total_down": total_down,
        "data_used": total_up + total_down,
        "days": rows.iter().map(|r| serde_json::json!({
            "day": r.day, "bytes_up": r.bytes_up, "bytes_down": r.bytes_down,
        })).collect::<Vec<_>>(),
    });
    if let Some(live) = modem_live_snapshot(state, &username).await {
        out["live"] = live;
    }
    ok_json(out)
}

/// Connection status = session up + recent activity (Design G §g.8).
/// Source: the provisioner's session-monitor status file
/// (`modem.status_path` setting). Absent file → stored status, never invented.
async fn h_modem_status(state: &AppState, id: &str) -> HttpResponse {
    // Scope the DB guard: it must not be alive across the await below.
    let (username, stored_status, stored_seen) = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        match store::get_modem_account(&conn, id) {
            Ok(m) => (m.username, m.status, m.last_seen_at),
            Err(e) => return store_err(e),
        }
    };
    let live = modem_live_snapshot(state, &username).await;
    let (status, last_seen_at, source) = match &live {
        Some(s) => {
            let up = s
                .get("session_up")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let seen = s.get("last_seen").and_then(|v| v.as_i64());
            if up {
                ("connected".to_string(), seen, "session_monitor")
            } else if seen.is_some() {
                ("disconnected".to_string(), seen, "session_monitor")
            } else {
                ("unknown".to_string(), stored_seen, "session_monitor")
            }
        }
        None => (stored_status.clone(), stored_seen, "database"),
    };
    ok_json(serde_json::json!({
        "account_id": id,
        "username": username,
        "status": status,
        "last_seen_at": last_seen_at,
        "source": source,
        "note": "Status = L2TP session up + recent activity (provisioner session monitor, Design G §g.8). The modem has no kill switch: on drop, traffic falls back to direct until it reconnects.",
    }))
}

/// Live snapshot for one modem account (by PPP username) from the
/// session-monitor status file.
async fn modem_live_snapshot(state: &AppState, username: &str) -> Option<serde_json::Value> {
    let path = {
        let conn = state.db_lock().ok()?;
        let p = store::get_setting(&conn, "modem.status_path")
            .ok()
            .flatten();
        p.unwrap_or_else(|| "/var/lib/zeronet-admin/modem-status.json".to_string())
    };
    let accounts = crate::modem::read_status_file(&path)?;
    let snap = accounts.get(username)?;
    Some(serde_json::json!({
        "session_up": snap.session_up,
        "last_seen": snap.last_seen,
        "bytes_up": snap.bytes_up,
        "bytes_down": snap.bytes_down,
    }))
}

// ---------------------------------------------------------------------------
// Modem capabilities / guide / security findings (frozen app contract)
// ---------------------------------------------------------------------------

/// `GET /api/v1/modem/capabilities` — data-driven VPN-client description.
/// The UI renders ONLY the fields declared here (Design G §c).
async fn h_modem_capabilities(_state: &AppState) -> HttpResponse {
    let field =
        |id: &str, label: &str, kind: &str, options: Vec<&str>, required: bool, sensitive: bool| {
            serde_json::json!({
                "id": id,
                "label": label,
                "kind": kind,
                "options": options,
                "required": required,
                "sensitive": sensitive,
            })
        };
    ok_json(serde_json::json!({
        "model": "Huawei H158-381 (5G CPE Pro 5)",
        "firmware": serde_json::Value::Null,
        "vpn_client": {
            // PPTP is refused on principle — not listed as offerable.
            "protocols": ["l2tp"],
            "fields": [
                field("connection_type", "Connection type", "choice", vec!["L2TP VPN client"], true, false),
                field("lns_address", "LNS address", "text", vec![], true, false),
                field("hostname", "Hostname", "text", vec![], false, false),
                field("tunnel_password", "Tunnel password", "password", vec![], false, true),
                field("ppp_username", "PPP user name", "text", vec![], true, false),
                field("ppp_password", "PPP password", "password", vec![], true, true),
            ],
        },
        "note": "Stock firmware offers L2TP + PPTP (Huawei doc en-us00761349). PPTP is refused on principle — not listed. Plain L2TP is WEAK without IPsec; the server mandates MPPE-128 fail-closed and the panel requires informed consent before showing credentials. The modem link is never called secure without the ⚠️ qualifier.",
    }))
}

/// `GET /api/v1/modem/guide?protocol=l2tp` — Design G §f, English source of
/// truth (Persian translation is the app team's job).
async fn h_modem_guide(_state: &AppState, req: &HttpRequest) -> HttpResponse {
    let protocol = req
        .query
        .get("protocol")
        .map(String::as_str)
        .unwrap_or("l2tp");
    if protocol != "l2tp" {
        return err_json(
            "bad_request",
            "only protocol=l2tp is supported (PPTP refused)",
            400,
        );
    }
    let mut steps: Vec<serde_json::Value> = crate::modem::GUIDE_STEPS
        .iter()
        .enumerate()
        .map(|(i, s)| {
            // Strip the leading "N. " — the app numbers steps itself.
            let body = s.split_once(". ").map(|(_, rest)| rest).unwrap_or(s);
            serde_json::json!({ "title": format!("Step {}", i + 1), "body": body })
        })
        .collect();
    for item in crate::modem::GUIDE_TROUBLESHOOTING {
        steps.push(serde_json::json!({ "title": "Troubleshooting", "body": item }));
    }
    steps.push(
        serde_json::json!({ "title": "IPv6 notice", "body": crate::modem::GUIDE_IPV6_NOTICE }),
    );
    ok_json(serde_json::json!({ "protocol": "l2tp", "steps": steps }))
}

/// `GET /api/v1/modem/security?protocol=l2tp` — honesty findings. Severity is
/// the backend's word; the UI never upgrades it.
async fn h_modem_security(_state: &AppState, req: &HttpRequest) -> HttpResponse {
    let protocol = req
        .query
        .get("protocol")
        .map(String::as_str)
        .unwrap_or("l2tp");
    if protocol != "l2tp" {
        return err_json(
            "bad_request",
            "only protocol=l2tp is supported (PPTP refused)",
            400,
        );
    }
    let finding = |id: &str, severity: &str, title: &str, detail: &str| serde_json::json!({ "id": id, "severity": severity, "title": title, "detail": detail });
    ok_json(serde_json::json!({
        "protocol": "l2tp",
        "findings": [
            finding("pptp-refused", "insecure",
                "PPTP refused — not offered",
                "PPTP's encryption (MPPE/RC4 with MS-CHAPv2) is broken and can be decrypted by a determined attacker. This panel does not generate PPTP credentials."),
            finding("l2tp-weak", "untrustworthy",
                "L2TP without IPsec is weak",
                "L2TP by itself provides no encryption. With the mandatory MPPE-128 setting, traffic between the modem and the server gets RC4-based encryption: it defeats casual snooping but NOT a determined network observer. It is not modern-VPN-grade. The server refuses connections that do not negotiate 128-bit MPPE, so the link can never silently fall back to plaintext. Informed consent is required before credentials are shown."),
            finding("no-kill-switch", "warning",
                "No kill switch on the modem",
                "If the L2TP session drops, the modem routes traffic directly over the mobile network until it reconnects. The panel shows live connection status; it cannot prevent the fallback."),
            finding("full-tunnel-unverified", "warning",
                "Full-tunnel behavior unverified",
                "Whether ALL LAN-device traffic uses the tunnel must be tested on the real unit (connect → IP check from a LAN device). Do not claim success before the test."),
            finding("ipv6-bypass", "warning",
                "IPv6 bypass risk",
                "If the mobile plan uses IPv6, set the modem's APN to IPv4-only while the VPN is active. Otherwise IPv6 traffic may bypass the VPN."),
            finding("weak-leg-scope", "warning",
                "Weak leg is modem→gateway only",
                "The Iran↔USA tunnel and everything past the gateway keep full modern crypto. The weak leg is only the modem→gateway hop."),
        ],
    }))
}
// ---------------------------------------------------------------------------
// Inter-server High Availability (owner addendum) — /api/v1/ha/* (§3.2h)
//
// Frozen app contract (shapes per the Android agent's HaApi.kt):
// - GET  /api/v1/ha/status   → full status (canonical)
// - GET  /api/v1/ha          → alias of /status
// - POST /api/v1/ha/primary  {tunnel:"A"|"B"} → {ok, primary}
// - POST /api/v1/ha/mode     {mode} → {ok, mode} (only offered modes)
// - POST /api/v1/ha/settings {heartbeat_interval_s?, failover_threshold_missed?,
//                             auto_recovery?} → {ok, ...}
// The routing agent owns the failover machinery; these endpoints are the
// admin's read/control surface over the engine's HA contract
// (`GET /ha`, `POST /ha/primary`, `POST /ha/mode`, `POST /ha/settings`).
//
// Binding honesty rules: tunnel state unknown/missing → "down" (fail-closed);
// downtime values MEASURED only, never estimated; modes are offered only as
// the engine declares them (active_active only when really implemented).
// ---------------------------------------------------------------------------

fn engine_err(e: crate::engine::EngineError) -> HttpResponse {
    use crate::engine::EngineError as E;
    match e {
        E::Unreachable(m) => err_json("bad_gateway", &format!("engine unreachable: {m}"), 502),
        E::Status(404, _) => err_json(
            "not_supported",
            "engine does not implement the HA contract (predates it)",
            502,
        ),
        E::Status(s, m) => err_json("bad_gateway", &format!("engine status {s}: {m}"), 502),
        E::BadResponse(m) => err_json("bad_gateway", &format!("engine bad response: {m}"), 502),
        E::Io(m) => err_json("bad_gateway", &format!("engine io: {m}"), 502),
    }
}

/// Build the frozen `GET /api/v1/ha/status` view. `failover_events` are the
/// admin's own `ha_failover` events (real observed transitions).
/// `exit_ip_fallback` is the admin's cached exit-IP check (used only when the
/// engine reports no exit IP).
fn ha_status_view(
    snap: &crate::ha::HaSnapshot,
    failover_events: &[store::Event],
    exit_ip_fallback: Option<&str>,
) -> serde_json::Value {
    use crate::ha::tunnel_state_of;
    let tunnels: Vec<serde_json::Value> = snap
        .tunnels
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "protocol": t.protocol,
                "transport_family": t.transport_family,
                // Fail-closed: unknown/missing → "down". No "unknown" state.
                "state": tunnel_state_of(t.state.as_deref()).as_str(),
                "rtt_ms": t.rtt_ms,
                "loss_pct": t.loss_pct,
                "jitter_ms": t.jitter_ms,
                "keepalive_ok": t.keepalive_ok.unwrap_or(false),
                "last_heartbeat_at": t.last_heartbeat_at.unwrap_or(0),
                "bytes_up": t.bytes_up,
                "bytes_down": t.bytes_down,
            })
        })
        .collect();
    let recent: Vec<serde_json::Value> = failover_events
        .iter()
        .map(|e| {
            let downtime_s = e
                .detail
                .get("last_downtime_ms")
                .and_then(|v| v.as_u64())
                .map(|ms| ms as f64 / 1000.0);
            let from = e.detail.get("from").and_then(|v| v.as_str());
            let to = e.detail.get("to").and_then(|v| v.as_str());
            let reason = match (from, to) {
                (Some(f), Some(t)) if f != t => format!("primary changed {f} → {t}"),
                _ => "failover counter increased".to_string(),
            };
            serde_json::json!({
                "at": e.at * 1000,
                "from": from,
                "to": to,
                "reason": reason,
                "downtime_s": downtime_s,
                // Not measured by the admin — null, never invented.
                "sessions_preserved_pct": serde_json::Value::Null,
            })
        })
        .collect();
    // Downtime is MEASURED only. Absent measurement → 0.0 with
    // downtime_measured:false; the panel says "not measured".
    // Top-level contract fields win; the nested `failovers` object is a
    // fallback for engines that nest them.
    let total_downtime_s = snap.total_downtime_s.or(snap.failovers.total_downtime_s);
    let downtime_measured = total_downtime_s.is_some();
    let last_failover_at = snap
        .last_failover_at
        .or_else(|| snap.failovers.last_at.map(|t| t * 1000))
        .unwrap_or(0);
    let failover_count = snap.failover_count.unwrap_or(snap.failovers.count);
    let exit_ip = snap
        .exit
        .ip
        .clone()
        .or_else(|| exit_ip_fallback.map(str::to_string));
    let ip_stable = snap.exit.ip_stable.unwrap_or(true);
    serde_json::json!({
        "supported": snap.supported(),
        "tunnels": tunnels,
        "primary": snap.primary,
        "mode": snap.mode_view(),
        "available_modes": snap.offered_modes(),
        "auto_recovery": snap.auto_recovery.unwrap_or(true),
        "heartbeat_interval_s": snap.heartbeat_interval_s.unwrap_or(3),
        "failover_threshold_missed": snap.failover_threshold_missed.unwrap_or(3),
        "last_failover_at": last_failover_at,
        "failover_count": failover_count,
        "total_downtime_s": total_downtime_s.unwrap_or(0.0),
        "downtime_measured": downtime_measured,
        "recent_failovers": recent,
        "exit": {
            "ip": exit_ip,
            // No GeoIP anywhere in the admin crate: country stays unknown.
            "country": "unknown",
            "healthy": snap.exit.healthy.unwrap_or(false),
            "checked_at": snap.exit.checked_at.map(|t| t * 1000).unwrap_or(0),
            "ip_stable": ip_stable,
            "ip_stable_across_failovers": ip_stable,
        },
        "honesty": crate::ha::HA_HONESTY,
    })
}

async fn h_ha_status(state: &AppState) -> HttpResponse {
    let snap = match state.engine.ha_snapshot().await {
        Ok(s) => s,
        Err(e) => return engine_err(e),
    };
    let events = match state.db_lock() {
        Ok(conn) => store::list_events(&conn, Some("ha_failover"), None, 10).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let exit_ip_cached = state.exit_ip.lock().unwrap().clone().map(|e| e.ip);
    let mut v = ha_status_view(&snap, &events, exit_ip_cached.as_deref());
    if !snap.supported() {
        v["note"] = serde_json::json!(
            "engine predates the HA contract: no tunnel/failover data. States are fail-closed to down; downtime is not measured."
        );
    }
    ok_json(v)
}

async fn h_ha_tunnels(state: &AppState) -> HttpResponse {
    match state.engine.ha_snapshot().await {
        Ok(snap) => {
            let v = ha_status_view(&snap, &[], None);
            ok_json(serde_json::json!({
                "supported": v["supported"],
                "primary": v["primary"],
                "tunnels": v["tunnels"],
            }))
        }
        Err(e) => engine_err(e),
    }
}

/// Manual primary selection (shared by REST + panel). Validates, forwards to
/// the engine, logs the event. Response: {ok, primary} (frozen shape).
pub(crate) async fn ha_select_primary(
    state: &AppState,
    tunnel: &str,
    actor: &str,
) -> Result<serde_json::Value, HttpResponse> {
    if !matches!(tunnel, "A" | "B") {
        return Err(err_json(
            "bad_request",
            "tunnel must be \"A\" or \"B\"",
            400,
        ));
    }
    let now = now_secs();
    match state.engine.ha_set_primary(tunnel).await {
        Ok(_) => {
            let conn = state.db_lock()?;
            let _ = store::log_event(
                &conn,
                now,
                "ha_primary_change",
                actor,
                &serde_json::json!({"tunnel": tunnel}),
            );
            Ok(serde_json::json!({ "ok": true, "primary": tunnel }))
        }
        Err(e) => Err(engine_err(e)),
    }
}

async fn h_ha_primary(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let tunnel = body.get("tunnel").and_then(|v| v.as_str()).unwrap_or("");
    match ha_select_primary(state, tunnel, "api").await {
        Ok(v) => ok_json(v),
        Err(e) => e,
    }
}

/// Mode switch (shared by REST + panel). Only modes the engine declares in
/// `available_modes` are offered — active_active only when really implemented.
pub(crate) async fn ha_select_mode(
    state: &AppState,
    mode: &str,
    actor: &str,
) -> Result<serde_json::Value, HttpResponse> {
    let snap = match state.engine.ha_snapshot().await {
        Ok(s) => s,
        Err(e) => return Err(engine_err(e)),
    };
    if !snap.supported() {
        return Err(engine_err(crate::engine::EngineError::Status(
            404,
            "no HA contract".to_string(),
        )));
    }
    let offered = snap.offered_modes();
    if !offered.iter().any(|m| m == mode) {
        return Err(err_json(
            "conflict",
            &format!(
                "mode {mode:?} is not offered by this engine (available: {})",
                offered.join(", ")
            ),
            409,
        ));
    }
    let now = now_secs();
    match state.engine.ha_set_mode(mode).await {
        Ok(_) => {
            let conn = state.db_lock()?;
            let _ = store::log_event(
                &conn,
                now,
                "ha_mode_change",
                actor,
                &serde_json::json!({"mode": mode}),
            );
            Ok(serde_json::json!({ "ok": true, "mode": mode }))
        }
        Err(e) => Err(engine_err(e)),
    }
}

async fn h_ha_mode(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    match ha_select_mode(state, mode, "api").await {
        Ok(v) => ok_json(v),
        Err(e) => e,
    }
}

/// Validate HA settings body → forwarded engine body (shared by REST + panel).
/// Frozen keys: heartbeat_interval_s, failover_threshold_missed, auto_recovery.
/// The legacy `heartbeat_interval_secs` spelling is accepted and normalized.
pub(crate) fn validate_ha_settings(
    body: &serde_json::Value,
) -> Result<serde_json::Value, HttpResponse> {
    let mut fwd = serde_json::Map::new();
    let hb = body
        .get("heartbeat_interval_s")
        .or_else(|| body.get("heartbeat_interval_secs"))
        .and_then(|v| v.as_u64());
    if let Some(hb) = hb {
        // Owner addendum: heartbeat 2–5s configurable; accept 1–30.
        if !(1..=30).contains(&hb) {
            return Err(err_json(
                "bad_request",
                "heartbeat_interval_s must be 1..=30",
                400,
            ));
        }
        fwd.insert("heartbeat_interval_s".to_string(), serde_json::json!(hb));
    }
    if let Some(m) = body
        .get("failover_threshold_missed")
        .and_then(|v| v.as_u64())
    {
        if !(1..=10).contains(&m) {
            return Err(err_json(
                "bad_request",
                "failover_threshold_missed must be 1..=10",
                400,
            ));
        }
        fwd.insert(
            "failover_threshold_missed".to_string(),
            serde_json::json!(m),
        );
    }
    if let Some(ar) = body.get("auto_recovery").and_then(|v| v.as_bool()) {
        fwd.insert("auto_recovery".to_string(), serde_json::json!(ar));
    }
    if fwd.is_empty() {
        return Err(err_json(
            "bad_request",
            "no recognized HA settings in body",
            400,
        ));
    }
    Ok(serde_json::Value::Object(fwd))
}

/// Apply HA settings (shared by REST + panel). Validates, forwards to the
/// engine, logs the event.
pub(crate) async fn ha_apply_settings(
    state: &AppState,
    body: &serde_json::Value,
    actor: &str,
) -> Result<serde_json::Value, HttpResponse> {
    let fwd_value = validate_ha_settings(body)?;
    let now = now_secs();
    match state.engine.ha_post_settings(&fwd_value).await {
        Ok(v) => {
            let conn = state.db_lock()?;
            let _ = store::log_event(
                &conn,
                now,
                "ha_settings_change",
                actor,
                &serde_json::json!({"settings": fwd_value}),
            );
            Ok(serde_json::json!({ "ok": true, "engine": v }))
        }
        Err(e) => Err(engine_err(e)),
    }
}

async fn h_ha_settings_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match ha_apply_settings(state, &body, "api").await {
        Ok(v) => ok_json(v),
        Err(e) => e,
    }
}

async fn h_ha_settings_get(state: &AppState) -> HttpResponse {
    match state.engine.ha_snapshot().await {
        Ok(snap) => ok_json(serde_json::json!({
            "supported": snap.supported(),
            "mode": snap.mode_view(),
            "available_modes": snap.offered_modes(),
            "heartbeat_interval_s": snap.heartbeat_interval_s.unwrap_or(3),
            "failover_threshold_missed": snap.failover_threshold_missed.unwrap_or(3),
            "auto_recovery": snap.auto_recovery.unwrap_or(true),
        })),
        Err(e) => engine_err(e),
    }
}

// ---------------------------------------------------------------------------
// Smart split-routing (owner prompt v2 / LEAD DELTA) — /api/v1/routing/*
//
// Frozen app contract (shapes per the Android agent's RouterApi.kt):
// - GET    /api/v1/routing/rules            → {version, rules, engine_synced}
// - POST   /api/v1/routing/rules            {kind,value,action,priority?,enabled?,note?} → {rule, conflicts}
// - PUT    /api/v1/routing/rules/{id}       {…} → {rule, conflicts}
// - DELETE /api/v1/routing/rules/{id}       → {ok:true}
// - GET    /api/v1/routing/rulesets         → {rulesets:[...]}
// - POST   /api/v1/routing/rulesets         {note?} → {ruleset} (snapshot, inactive)
// - POST   /api/v1/routing/rulesets/{version}/activate → {ok, version}
// - POST   /api/v1/routing/test             {target} → {route, matched_rule?, exit_country?, dns_policy?, confidence, reason}
//
// The admin is the authoritative rule store. The ACTIVE version is pushed to
// the engine by the poller (`routing.push_pending`); `engine_synced` reports
// the last push outcome honestly. The tester proxies the engine's CLASSIFY
// API — 502 when the engine has no classifier, never a guessed answer.
// ---------------------------------------------------------------------------

fn mark_routing_push_pending(conn: &rusqlite::Connection) {
    let _ = store::set_setting(conn, "routing.push_pending", "1");
}

fn routing_engine_synced(conn: &rusqlite::Connection) -> (bool, Option<String>) {
    let pending = store::get_setting(conn, "routing.push_pending")
        .ok()
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(false);
    let err = store::get_setting(conn, "routing.push_error")
        .ok()
        .flatten();
    (!pending, err)
}

fn rule_json(r: &store::SplitRule) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "kind": r.kind,
        "value": r.value,
        "action": r.action,
        "priority": r.priority,
        "enabled": r.enabled,
        "note": r.note,
    })
}

async fn h_routing_rules_get(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (version, rules) = match store::active_rules(&conn) {
        Ok(v) => v,
        Err(e) => return store_err(e),
    };
    let (synced, push_error) = routing_engine_synced(&conn);
    let mut out = serde_json::json!({
        "version": version,
        "rules": rules.iter().map(rule_json).collect::<Vec<_>>(),
        "engine_synced": synced,
    });
    if let Some(err) = push_error {
        out["push_error"] = serde_json::json!(err);
    }
    ok_json(out)
}

async fn h_routing_rule_create(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let value = body.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let priority = body.get("priority").and_then(|v| v.as_i64()).unwrap_or(100);
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    let valid = match crate::routing::validate_rule(kind, value, action, priority, note) {
        Ok(v) => v,
        Err(e) => return err_json("bad_request", &e.to_string(), 400),
    };
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let version = match store::active_ruleset_version(&conn) {
        Ok(v) => v,
        Err(e) => return store_err(e),
    };
    let existing = store::list_rules(&conn, version).unwrap_or_default();
    let conflicts = crate::routing::check_conflicts(&valid, &existing, None);
    let rule = store::SplitRule {
        id: uuid::Uuid::new_v4().to_string(),
        version,
        kind: valid.kind,
        value: valid.value,
        action: valid.action,
        priority: valid.priority,
        enabled,
        note: valid.note,
    };
    if let Err(e) = store::create_rule(&conn, &rule) {
        return store_err(e);
    }
    mark_routing_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "routing_rule_create",
        "api",
        &serde_json::json!({"rule_id": rule.id, "version": version}),
    );
    let mut r = ok_json(serde_json::json!({ "rule": rule_json(&rule), "conflicts": conflicts }));
    r.status = 201;
    r
}

async fn h_routing_rule_update(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut rule = match store::get_rule(&conn, id) {
        Ok(r) => r,
        Err(e) => return store_err(e),
    };
    let kind = body
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or(&rule.kind);
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or(&rule.value);
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or(&rule.action);
    let priority = body
        .get("priority")
        .and_then(|v| v.as_i64())
        .unwrap_or(rule.priority);
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(rule.enabled);
    let note = body
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or(&rule.note);
    let valid = match crate::routing::validate_rule(kind, value, action, priority, note) {
        Ok(v) => v,
        Err(e) => return err_json("bad_request", &e.to_string(), 400),
    };
    rule.kind = valid.kind.clone();
    rule.value = valid.value.clone();
    rule.action = valid.action.clone();
    rule.priority = valid.priority;
    rule.enabled = enabled;
    rule.note = valid.note.clone();
    let existing = store::list_rules(&conn, rule.version).unwrap_or_default();
    let conflicts = crate::routing::check_conflicts(&valid, &existing, Some(id));
    if let Err(e) = store::update_rule(&conn, &rule) {
        return store_err(e);
    }
    mark_routing_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "routing_rule_update",
        "api",
        &serde_json::json!({"rule_id": id, "version": rule.version}),
    );
    ok_json(serde_json::json!({ "rule": rule_json(&rule), "conflicts": conflicts }))
}

async fn h_routing_rule_delete(state: &AppState, id: &str) -> HttpResponse {
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let rule = match store::get_rule(&conn, id) {
        Ok(r) => r,
        Err(e) => return store_err(e),
    };
    if let Err(e) = store::delete_rule(&conn, id) {
        return store_err(e);
    }
    mark_routing_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "routing_rule_delete",
        "api",
        &serde_json::json!({"rule_id": id, "version": rule.version}),
    );
    ok_json(serde_json::json!({ "ok": true }))
}

async fn h_routing_rulesets_list(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_rulesets(&conn) {
        Ok(rs) => ok_json(serde_json::json!({ "rulesets": rs })),
        Err(e) => store_err(e),
    }
}

/// Snapshot the active version's rules into a NEW (inactive) version.
/// Rollback = activate an older version.
async fn h_routing_ruleset_snapshot(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    if note.len() > 500 {
        return err_json("bad_request", "note too long (max 500)", 400);
    }
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let from = match store::active_ruleset_version(&conn) {
        Ok(v) => v,
        Err(e) => return store_err(e),
    };
    let to = match store::next_ruleset_version(&conn) {
        Ok(v) => v,
        Err(e) => return store_err(e),
    };
    if let Err(e) = store::create_ruleset(&conn, to, note, now) {
        return store_err(e);
    }
    let copied = match store::snapshot_ruleset(&conn, from, to) {
        Ok(n) => n,
        Err(e) => return store_err(e),
    };
    let _ = store::log_event(
        &conn,
        now,
        "routing_ruleset_snapshot",
        "api",
        &serde_json::json!({"from_version": from, "to_version": to, "rules": copied}),
    );
    let mut r = ok_json(serde_json::json!({
        "ruleset": { "version": to, "note": note, "created_at": now, "active": false, "rule_count": copied },
    }));
    r.status = 201;
    r
}

async fn h_routing_ruleset_activate(state: &AppState, version: i64) -> HttpResponse {
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = store::activate_ruleset(&conn, version) {
        return store_err(e);
    }
    mark_routing_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "routing_ruleset_activate",
        "api",
        &serde_json::json!({"version": version}),
    );
    ok_json(serde_json::json!({ "ok": true, "version": version }))
}

/// Rule tester: proxies the engine's CLASSIFY API. 502 when the engine has
/// no classifier — never a guessed answer.
async fn h_routing_test(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = body
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if target.is_empty() || target.len() > 253 {
        return err_json("bad_request", "target is required (max 253 chars)", 400);
    }
    match state.engine.classify(target).await {
        Ok(t) => ok_json(serde_json::json!({
            "route": t.route,
            "matched_rule": t.matched_rule,
            "exit_country": t.exit_country,
            "dns_policy": t.dns_policy,
            "confidence": t.confidence,
            "reason": t.reason,
        })),
        Err(e) => engine_err(e),
    }
}

// ---------------------------------------------------------------------------
// Triple tunnel / dual-stack / sticky exit (owner addendum, binding)
// /api/v1/tunnels/*, /api/v1/egress/*, /api/v1/sticky-policies/*,
// /api/v1/tests/* — frozen app contract.
// ---------------------------------------------------------------------------

fn triple_tunnel_json(t: &crate::triple::TripleTunnel) -> serde_json::Value {
    serde_json::json!({
        "id": t.id,
        "family": t.family_view(),
        "protocol": t.protocol,
        "transport_family": t.transport_family,
        "state": t.state_view(),
        "rtt_ms": t.rtt_ms,
        "loss_pct": t.loss_pct,
        "jitter_ms": t.jitter_ms,
        "keepalive_ok": t.keepalive_ok,
        "last_heartbeat_at": t.last_heartbeat_at,
        "traffic": {
            "payload_up": t.traffic.payload_up,
            "payload_down": t.traffic.payload_down,
            "keepalive_bytes": t.traffic.keepalive_bytes,
            "health_bytes": t.traffic.health_bytes,
            "overhead_bytes": t.traffic.overhead_bytes,
        },
        "active_sessions": t.active_sessions,
        "failover_count": t.failover_count,
        "recovery_time_s": t.recovery_time_s,
    })
}

async fn h_tunnels_status(state: &AppState) -> HttpResponse {
    match state.engine.tunnels_snapshot().await {
        Ok(snap) => {
            let tunnels: Vec<serde_json::Value> = snap
                .ordered_tunnels()
                .iter()
                .map(triple_tunnel_json)
                .collect();
            ok_json(serde_json::json!({
                "supported": snap.supported(),
                "tunnels": tunnels,
                "primary": snap.primary,
                "mode": snap.mode,
                "available_modes": snap.available_modes,
                "probe_budget": snap.probe_budget_view(),
                "probe_budget_options": snap.budget_options(),
                "note": if snap.supported() { "live engine data" } else { "engine has no /tunnels surface (routing agent implements it)" },
            }))
        }
        Err(e) => engine_err(e),
    }
}

async fn h_tunnels_primary(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let tunnel = body
        .get("tunnel")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_uppercase();
    if !crate::triple::TUNNEL_IDS.contains(&tunnel.as_str()) {
        return err_json("bad_request", "tunnel must be A, B or C", 400);
    }
    match state.engine.ha_set_primary(&tunnel).await {
        Ok(_) => ok_json(serde_json::json!({ "ok": true, "primary": tunnel })),
        Err(e) => engine_err(e),
    }
}

async fn h_probe_budget_get(state: &AppState) -> HttpResponse {
    let (engine_budget, options) = match state.engine.tunnels_snapshot().await {
        Ok(snap) => (snap.probe_budget_view().to_string(), snap.budget_options()),
        Err(_) => (
            "balanced".to_string(),
            crate::triple::PROBE_BUDGETS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
    };
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    let admin_budget = store::get_setting(&conn, "tunnels.probe_budget")
        .ok()
        .flatten()
        .unwrap_or_else(|| engine_budget.clone());
    ok_json(serde_json::json!({
        "budget": admin_budget,
        "engine_budget": engine_budget,
        "options": options,
    }))
}

async fn h_probe_budget_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let budget = body.get("budget").and_then(|v| v.as_str()).unwrap_or("");
    if !crate::triple::PROBE_BUDGETS.contains(&budget) {
        return err_json(
            "bad_request",
            "budget must be low | balanced | aggressive | custom",
            400,
        );
    }
    // Best-effort engine push (like routing rules); the admin setting is
    // authoritative and stored regardless.
    let engine_err_msg = match state.engine.set_probe_budget(budget).await {
        Ok(()) => None,
        Err(e) => Some(e.to_string()),
    };
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    let now = now_secs();
    let _ = store::set_setting(&conn, "tunnels.probe_budget", budget);
    let _ = store::log_event(
        &conn,
        now,
        "probe_budget_set",
        "api",
        &serde_json::json!({"budget": budget, "engine_error": engine_err_msg}),
    );
    ok_json(serde_json::json!({
        "ok": true,
        "budget": budget,
        "engine_applied": engine_err_msg.is_none(),
        "engine_error": engine_err_msg,
    }))
}

async fn h_egress_status(state: &AppState) -> HttpResponse {
    match state.engine.egress_snapshot().await {
        Ok(snap) => ok_json(serde_json::json!({
            "supported": snap.supported(),
            "static_ipv4": snap.static_ipv4,
            "static_ipv6": snap.static_ipv6,
            "v4": {"connected": snap.v4.connected, "success_rate": snap.v4.success_rate},
            "v6": {"connected": snap.v6.connected, "success_rate": snap.v6.success_rate},
            "sticky": {
                "exit_ip": snap.sticky.exit_ip,
                "exit_family": snap.sticky.exit_family,
                "session_started_at": snap.sticky.session_started_at,
                "last_reroute_at": snap.sticky.last_reroute_at,
                "last_reroute_reason": snap.sticky.last_reroute_reason,
            },
            "note": if snap.supported() { "live engine data" } else { "engine has no /egress surface (routing agent implements it)" },
        })),
        Err(e) => engine_err(e),
    }
}

async fn h_egress_decision(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let domain = req.query.get("domain").map(|s| s.trim()).unwrap_or("");
    if domain.is_empty() || domain.len() > 253 {
        return err_json(
            "bad_request",
            "domain query parameter is required (max 253)",
            400,
        );
    }
    match state.engine.egress_decision(domain).await {
        Ok(d) => ok_json(serde_json::json!({
            "domain": d.domain,
            "family": d.family,
            "policy": d.policy,
            "reason": d.reason,
            "exit_ip": d.exit_ip,
        })),
        Err(e) => engine_err(e),
    }
}

fn sticky_policy_json(p: &store::StickyPolicy) -> serde_json::Value {
    serde_json::json!({
        "id": p.id, "scope": p.scope, "target": p.target, "policy": p.policy,
        "affinity_secs": p.affinity_secs, "note": p.note, "created_at": p.created_at,
    })
}

fn mark_sticky_push_pending(conn: &rusqlite::Connection) {
    let _ = store::set_setting(conn, "sticky.push_pending", "1");
}

async fn h_sticky_list(state: &AppState) -> HttpResponse {
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    match store::list_sticky_policies(&conn) {
        Ok(policies) => {
            let pending = store::get_setting(&conn, "sticky.push_pending")
                .ok()
                .flatten()
                .map(|v| v == "1")
                .unwrap_or(false);
            ok_json(serde_json::json!({
                "policies": policies.iter().map(sticky_policy_json).collect::<Vec<_>>(),
                "engine_synced": !pending,
                "defaults": {"policy": "auto", "sticky_session": true, "sensitive_sites": "prefer_stable_ipv4"},
            }))
        }
        Err(e) => store_err(e),
    }
}

async fn h_sticky_create(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("");
    let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let policy = body.get("policy").and_then(|v| v.as_str()).unwrap_or("");
    let affinity_secs = body
        .get("affinity_secs")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    let valid =
        match crate::triple::validate_sticky_policy(scope, target, policy, affinity_secs, note) {
            Ok(v) => v,
            Err(e) => return err_json("bad_request", &e.to_string(), 400),
        };
    let now = now_secs();
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    let p = store::StickyPolicy {
        id: format!("sp-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        scope: valid.scope,
        target: valid.target,
        policy: valid.policy,
        affinity_secs: valid.affinity_secs,
        note: valid.note,
        created_at: now,
    };
    if let Err(e) = store::create_sticky_policy(&conn, &p) {
        return store_err(e);
    }
    mark_sticky_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "sticky_policy_create",
        "api",
        &serde_json::json!({"id": p.id, "scope": p.scope, "target": p.target, "policy": p.policy}),
    );
    let mut r = ok_json(serde_json::json!({ "policy": sticky_policy_json(&p) }));
    r.status = 201;
    r
}

async fn h_sticky_update(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let now = now_secs();
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    let mut p =
        match store::list_sticky_policies(&conn).map(|ps| ps.into_iter().find(|x| x.id == id)) {
            Ok(Some(p)) => p,
            Ok(None) => return err_json("not_found", "sticky policy not found", 404),
            Err(e) => return store_err(e),
        };
    if let Some(policy) = body.get("policy").and_then(|v| v.as_str()) {
        let valid = match crate::triple::validate_sticky_policy(
            &p.scope,
            &p.target,
            policy,
            p.affinity_secs,
            &p.note,
        ) {
            Ok(v) => v,
            Err(e) => return err_json("bad_request", &e.to_string(), 400),
        };
        p.policy = valid.policy;
    }
    if let Some(a) = body.get("affinity_secs").and_then(|v| v.as_i64()) {
        if !(0..=86400).contains(&a) {
            return err_json("bad_request", "affinity_secs must be 0..=86400", 400);
        }
        p.affinity_secs = a;
    }
    if let Some(note) = body.get("note").and_then(|v| v.as_str()) {
        if note.len() > 500 {
            return err_json("bad_request", "note too long (max 500)", 400);
        }
        p.note = note.to_string();
    }
    if let Err(e) = store::update_sticky_policy(&conn, &p) {
        return store_err(e);
    }
    mark_sticky_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "sticky_policy_update",
        "api",
        &serde_json::json!({"id": p.id, "policy": p.policy}),
    );
    ok_json(serde_json::json!({ "policy": sticky_policy_json(&p) }))
}

async fn h_sticky_delete(state: &AppState, id: &str) -> HttpResponse {
    let now = now_secs();
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    if let Err(e) = store::delete_sticky_policy(&conn, id) {
        return store_err(e);
    }
    mark_sticky_push_pending(&conn);
    let _ = store::log_event(
        &conn,
        now,
        "sticky_policy_delete",
        "api",
        &serde_json::json!({"id": id}),
    );
    ok_json(serde_json::json!({ "ok": true }))
}

async fn h_sticky_effective(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let domain = req.query.get("domain").map(|s| s.as_str());
    let device = req.query.get("device").map(|s| s.as_str());
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return err_json("db", "database unavailable", 500),
    };
    match store::effective_sticky_policy(&conn, domain, device) {
        Ok(Some(p)) => ok_json(serde_json::json!({
            "policy": sticky_policy_json(&p),
            "source": "stored",
        })),
        Ok(None) => ok_json(serde_json::json!({
            "policy": {"scope": "default", "policy": "auto", "sticky_session": true},
            "source": "default",
            "note": "no stored policy for this domain/device — engine default: Auto + Sticky Session",
        })),
        Err(e) => store_err(e),
    }
}

async fn h_test_run(state: &AppState, kind: &str, req: &HttpRequest) -> HttpResponse {
    if !crate::triple::TEST_KINDS.contains(&kind) {
        return err_json(
            "bad_request",
            "test kind must be ipv4 | ipv6 | both | exit-ip | failover",
            400,
        );
    }
    // Failover tests are destructive-ish: require explicit confirmation.
    if kind == "failover" {
        let body: serde_json::Value = match json_body(req) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if body.get("confirm").and_then(|v| v.as_bool()) != Some(true) {
            return err_json(
                "bad_request",
                "failover test requires {\"confirm\": true}",
                400,
            );
        }
    }
    let now = now_secs();
    match state.engine.run_test(kind).await {
        Ok(t) => {
            let conn = match state.db.lock() {
                Ok(c) => c,
                Err(_) => return err_json("db", "database unavailable", 500),
            };
            let _ = store::log_event(
                &conn,
                now,
                "manual_test",
                "api",
                &serde_json::json!({"kind": kind, "ok": t.ok, "steps": t.results.len()}),
            );
            ok_json(serde_json::json!({
                "kind": t.kind,
                "ok": t.ok,
                "results": t.results,
                "measured_at": t.measured_at,
            }))
        }
        Err(e) => engine_err(e),
    }
}

/// `GET /s/{token}` — personal subscription body. Only on the opt-in public
/// listener (or loopback). Token IS the auth; 404 for anything else.
async fn serve_subscription(state: &AppState, token: &str) -> HttpResponse {
    if token.len() > 256 {
        return err_json("not_found", "not found", 404);
    }
    let now = now_secs();
    let sub = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        match store::find_subscription_by_token_hash(&conn, &token_hash(token)) {
            Ok(s) => s,
            Err(_) => return err_json("not_found", "not found", 404),
        }
    };
    if sub.revoked || sub.kind != "personal" {
        return err_json("not_found", "not found", 404);
    }
    if let Some(exp) = sub.expires_at {
        if exp < now {
            return err_json("not_found", "not found", 404);
        }
    }
    let device_id = match &sub.device_id {
        Some(d) => d.clone(),
        None => return err_json("not_found", "not found", 404),
    };
    let device = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        match store::get_device(&conn, &device_id) {
            Ok(d) => d,
            Err(_) => return err_json("not_found", "not found", 404),
        }
    };
    if device.revoked {
        return err_json("not_found", "not found", 404);
    }
    match render_device_configs(state, &device) {
        Ok(configs) => {
            let links: Vec<String> = configs.into_iter().map(|c| c.link).collect();
            let body = subs::subscription_body(&links);
            resp(200, "text/plain; charset=utf-8", body.into_bytes())
        }
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Inbounds (for the device-issue wizard)
// ---------------------------------------------------------------------------

async fn h_inbounds_list(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_inbounds(&conn) {
        Ok(inbounds) => {
            let inbounds: Vec<serde_json::Value> = inbounds
                .into_iter()
                .map(|i| {
                    serde_json::json!({
                        "tag": i.tag, "protocol": i.protocol,
                        "server_role": i.server_role, "host": i.host, "port": i.port,
                        "enabled": i.enabled,
                        "issuable": subs::issuable(&i.protocol),
                        // Never expose inbound params blindly: they may carry
                        // server keys. The panel shows them only to admins.
                    })
                })
                .collect();
            ok_json(serde_json::json!({ "inbounds": inbounds }))
        }
        Err(e) => store_err(e),
    }
}

// ---------------------------------------------------------------------------
// Usage & quotas
// ---------------------------------------------------------------------------

async fn h_usage_summary(state: &AppState) -> HttpResponse {
    let today = today_utc();
    let (db_up, db_down, devices) = {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let rows = store::usage_range(&conn, &today, &today).unwrap_or_default();
        let up: i64 = rows.iter().map(|r| r.bytes_up).sum();
        let down: i64 = rows.iter().map(|r| r.bytes_down).sum();
        let devices: i64 = rows.iter().map(|r| r.sessions_peak).sum();
        (up, down, devices)
    };
    // Live "devices now" from the engine (degraded: 0 when unreachable).
    let live = state.engine.usage_detail().await.ok();
    let devices_now: u64 = live
        .as_ref()
        .map(|u| u.inbounds.iter().map(|i| i.devices_now).sum())
        .unwrap_or(0);
    ok_json(serde_json::json!({
        "window_secs": 86400,
        "day": today,
        "totals": { "bytes_up": db_up, "bytes_down": db_down },
        "devices_now": devices_now,
        "sessions_peak_today": devices,
        "engine_live": live.is_some(),
    }))
}

async fn h_usage_devices(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let from = req.query.get("from").cloned().unwrap_or_else(today_utc);
    let to = req.query.get("to").cloned().unwrap_or_else(today_utc);
    if from.len() != 10 || to.len() != 10 {
        return err_json("bad_request", "from/to must be YYYY-MM-DD", 400);
    }
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let rows = match store::usage_range(&conn, &from, &to) {
        Ok(r) => r,
        Err(e) => return store_err(e),
    };
    // Attach device labels.
    let rows: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let label = r
                .device_id
                .as_deref()
                .and_then(|id| store::get_device(&conn, id).ok())
                .map(|d| d.label);
            serde_json::json!({
                "day": r.day, "device_id": r.device_id, "device_label": label,
                "server_role": r.server_role, "bytes_up": r.bytes_up,
                "bytes_down": r.bytes_down, "sessions_peak": r.sessions_peak,
            })
        })
        .collect();
    ok_json(serde_json::json!({ "from": from, "to": to, "rows": rows }))
}

async fn h_usage_inbounds(state: &AppState) -> HttpResponse {
    // Admin-aggregated current per-inbound counters from the engine.
    let detail = match state.engine.usage_detail().await {
        Ok(d) => d,
        Err(e) => {
            return err_json(
                "bad_request",
                &format!("engine unreachable (degraded mode): {e}"),
                502,
            )
        }
    };
    let inbounds: Vec<serde_json::Value> = detail
        .inbounds
        .into_iter()
        .map(|i| {
            serde_json::json!({
                "tag": i.tag, "sessions": i.sessions,
                "devices_now": i.devices_now, "devices_recent": i.devices_recent,
                "uplink": i.uplink, "downlink": i.downlink,
            })
        })
        .collect();
    ok_json(serde_json::json!({
        "at": detail.at, "server_id": detail.server_id,
        "inbounds": inbounds,
        "per_user_detail": !detail.users.is_empty(),
    }))
}

async fn h_quotas_status(state: &AppState) -> HttpResponse {
    let today = today_utc();
    let month_start = format!("{}-01", &today[..7]);
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let users = match store::list_users(&conn) {
        Ok(u) => u,
        Err(e) => return store_err(e),
    };
    let mut out = Vec::new();
    for u in users {
        let Some(quota) = u.quota_bytes else { continue };
        let (up, down) =
            store::user_usage_bytes(&conn, &u.id, &month_start, &today).unwrap_or((0, 0));
        let used = up + down;
        let pct = if quota > 0 {
            used as f64 / quota as f64 * 100.0
        } else {
            0.0
        };
        out.push(serde_json::json!({
            "user_id": u.id, "name": u.name,
            "quota_bytes": quota, "used_bytes": used,
            "percent": (pct * 10.0).round() / 10.0,
            "over": used >= quota,
            "revoked": u.revoked,
        }));
    }
    ok_json(serde_json::json!({ "month": &today[..7], "users": out }))
}

// ---------------------------------------------------------------------------
// Settings: DNS, costs, all
// ---------------------------------------------------------------------------

async fn h_dns_get(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mode = store::get_setting(&conn, "dns.mode")
        .unwrap_or(None)
        .unwrap_or_else(|| "\"strict\"".to_string());
    let resolvers = store::get_setting(&conn, "dns.resolvers")
        .unwrap_or(None)
        .unwrap_or_else(|| "[]".to_string());
    let note = store::get_setting(&conn, "dns.note")
        .unwrap_or(None)
        .unwrap_or_else(|| "\"\"".to_string());
    ok_json(serde_json::json!({
        "mode": serde_json::from_str::<serde_json::Value>(&mode).unwrap_or(serde_json::Value::Null),
        "resolvers": serde_json::from_str::<serde_json::Value>(&resolvers).unwrap_or(serde_json::Value::Null),
        "note": serde_json::from_str::<serde_json::Value>(&note).unwrap_or(serde_json::Value::Null),
        // Honest: the admin stores DNS policy; enforcement lives in the
        // engine config (provision/core wire it). No silent claims.
        "engine_applied": false,
    }))
}

async fn h_dns_put(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mode = body
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("strict");
    if !matches!(mode, "strict" | "auto") {
        return err_json("bad_request", "mode must be strict or auto", 400);
    }
    // Scope the DB guard so it is dropped before the await below
    // (std::sync::MutexGuard<Connection> is !Send; the handler future must be Send).
    {
        let conn = match state.db_lock() {
            Ok(c) => c,
            Err(e) => return e,
        };
        let _ = store::set_setting(&conn, "dns.mode", &serde_json::json!(mode).to_string());
        let _ = store::set_setting(
            &conn,
            "dns.resolvers",
            &body
                .get("resolvers")
                .cloned()
                .unwrap_or(serde_json::json!([]))
                .to_string(),
        );
        let _ = store::set_setting(
            &conn,
            "dns.note",
            &body
                .get("note")
                .cloned()
                .unwrap_or(serde_json::json!(""))
                .to_string(),
        );
        let _ = store::log_event(
            &conn,
            now_secs(),
            "dns_change",
            "api",
            &serde_json::json!({"mode": mode}),
        );
    }
    h_dns_get(state).await
}

async fn h_costs_list(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_costs(&conn) {
        Ok(costs) => ok_json(serde_json::json!({ "costs": costs })),
        Err(e) => store_err(e),
    }
}

async fn h_cost_create(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(kind, "server" | "data_package" | "baseline") {
        return err_json(
            "bad_request",
            "kind must be server, data_package or baseline",
            400,
        );
    }
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if label.is_empty() {
        return err_json("bad_request", "label is required", 400);
    }
    // HARD RULE: tariff is never inferred. The owner may record a verified
    // tariff explicitly; otherwise it stays "unknown".
    let tariff_note = body
        .get("tariff_note")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let now = now_secs();
    let cost = store::Cost {
        id: uuid::Uuid::new_v4().to_string(),
        kind: kind.to_string(),
        label: label.to_string(),
        amount: body.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0),
        currency: body
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("IRR")
            .to_string(),
        period: body
            .get("period")
            .and_then(|v| v.as_str())
            .unwrap_or("monthly")
            .to_string(),
        volume_mb: body.get("volume_mb").and_then(|v| v.as_i64()),
        operator: body
            .get("operator")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        tariff_note,
        recorded_at: now,
    };
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = store::create_cost(&conn, &cost) {
        return store_err(e);
    }
    let mut r = ok_json(serde_json::json!({ "cost": cost }));
    r.status = 201;
    r
}

async fn h_cost_delete(state: &AppState, id: &str) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::delete_cost(&conn, id) {
        Ok(()) => ok_json(serde_json::json!({ "ok": true })),
        Err(e) => store_err(e),
    }
}

async fn h_costs_report(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let costs = match store::list_costs(&conn) {
        Ok(c) => c,
        Err(e) => return store_err(e),
    };
    let monthly_servers: f64 = costs
        .iter()
        .filter(|c| c.kind == "server" && c.period == "monthly")
        .map(|c| c.amount)
        .sum();
    let monthly_packages: f64 = costs
        .iter()
        .filter(|c| c.kind == "data_package" && c.period == "monthly")
        .map(|c| c.amount)
        .sum();
    let baseline: f64 = costs
        .iter()
        .filter(|c| c.kind == "baseline")
        .map(|c| c.amount)
        .sum();
    let total = monthly_servers + monthly_packages;
    ok_json(serde_json::json!({
        "currency": "IRR",
        "monthly_server_costs": monthly_servers,
        "monthly_data_package_costs": monthly_packages,
        "monthly_total": total,
        "baseline_monthly": baseline,
        "estimated_monthly_savings": baseline - total,
        "caveat": "Savings = baseline minus recorded server + package costs. \
                   Whether your carrier bills this traffic at a domestic tariff is \
                   unknown — verify with your operator. Tariff is never inferred from IP geolocation.",
    }))
}

async fn h_settings_all(state: &AppState) -> HttpResponse {
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_settings(&conn) {
        Ok(settings) => {
            // Never expose the password hash.
            let settings: Vec<(String, String)> = settings
                .into_iter()
                .filter(|(k, _)| k != "panel.password_hash")
                .collect();
            ok_json(serde_json::json!({ "settings": settings }))
        }
        Err(e) => store_err(e),
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

async fn h_events(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let kind = req.query.get("kind").map(String::as_str);
    let from = req.query.get("from").and_then(|v| v.parse::<i64>().ok());
    let limit = req
        .query
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match store::list_events(&conn, kind, from, limit) {
        Ok(events) => ok_json(serde_json::json!({ "events": events })),
        Err(e) => store_err(e),
    }
}

// ---------------------------------------------------------------------------
// Backup / restore
// ---------------------------------------------------------------------------

async fn h_backup(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let passphrase = body
        .get("passphrase")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match crate::backup::create_backup(&state.config.db_path, passphrase) {
        Ok(blob) => {
            let now = now_secs();
            if let Ok(conn) = state.db_lock() {
                let _ = store::log_event(&conn, now, "backup", "api", &serde_json::json!({}));
            }
            let mut r = resp(200, "application/octet-stream", blob);
            r.extra.push((
                "Content-Disposition".to_string(),
                format!("attachment; filename=\"zray-admin-backup-{now}.zabk\""),
            ));
            r
        }
        Err(e) => err_json("bad_request", &e.to_string(), 400),
    }
}

async fn h_restore(state: &AppState, req: &HttpRequest) -> HttpResponse {
    // JSON body {passphrase, blob(base64)}; or multipart with fields
    // `passphrase` (text) and `file` (backup bytes).
    let (passphrase, blob): (String, Vec<u8>) = {
        let ct = req
            .headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if ct.starts_with("multipart/form-data") {
            match parse_multipart_backup(req) {
                Ok(v) => v,
                Err(e) => return e,
            }
        } else {
            let body: serde_json::Value = match json_body(req) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let passphrase = body
                .get("passphrase")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let blob_b64 = body.get("blob").and_then(|v| v.as_str()).unwrap_or("");
            let blob = match base64::engine::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                blob_b64,
            ) {
                Ok(b) => b,
                Err(_) => return err_json("bad_request", "blob is not valid base64", 400),
            };
            (passphrase, blob)
        }
    };
    match crate::backup::restore_backup(&state.config.db_path, &blob, &passphrase) {
        Ok(n) => {
            // Re-open the DB against the replaced file.
            match crate::db::open(&state.config.db_path) {
                Ok(new_conn) => {
                    if let Ok(mut guard) = state.db.lock() {
                        *guard = new_conn;
                    }
                    if let Ok(conn) = state.db_lock() {
                        let _ = store::log_event(
                            &conn,
                            now_secs(),
                            "restore",
                            "api",
                            &serde_json::json!({"bytes": n}),
                        );
                    }
                    ok_json(serde_json::json!({ "ok": true, "bytes": n }))
                }
                Err(e) => err_json(
                    "internal",
                    &format!("restored but re-open failed: {e}"),
                    500,
                ),
            }
        }
        Err(crate::backup::BackupError::WrongPassphrase) => {
            err_json("unauthorized", "wrong passphrase or corrupted backup", 401)
        }
        Err(e) => err_json("bad_request", &e.to_string(), 400),
    }
}

/// Minimal multipart parser: enough for {passphrase: text, file: bytes}.
fn parse_multipart_backup(req: &HttpRequest) -> Result<(String, Vec<u8>), HttpResponse> {
    let ct = req.headers.get("content-type").cloned().unwrap_or_default();
    let boundary = ct
        .split("boundary=")
        .nth(1)
        .ok_or_else(|| err_json("bad_request", "multipart missing boundary", 400))?;
    let boundary = format!("--{boundary}");
    let body = &req.body;
    let mut passphrase = String::new();
    let mut file: Option<Vec<u8>> = None;
    for part in split_multipart(body, boundary.as_bytes()) {
        let (headers, data) = match split_part(part) {
            Some(v) => v,
            None => continue,
        };
        let disp = headers
            .iter()
            .find(|(k, _)| k == "content-disposition")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let name = disp
            .split("name=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("");
        match name {
            "passphrase" => passphrase = String::from_utf8_lossy(data).into_owned(),
            "file" => file = Some(data.to_vec()),
            _ => {}
        }
    }
    match file {
        Some(f) => Ok((passphrase, f)),
        None => Err(err_json("bad_request", "multipart missing file field", 400)),
    }
}

fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(i) = find_subslice(&body[start..], boundary) {
        let abs = start + i;
        if abs > start {
            parts.push(&body[start..abs]);
        }
        start = abs + boundary.len();
    }
    parts
}

/// Parsed multipart section: headers + body.
type PartSection<'a> = (Vec<(String, String)>, &'a [u8]);

fn split_part(part: &[u8]) -> Option<PartSection<'_>> {
    let i = find_subslice(part, b"\r\n\r\n")?;
    let mut headers = Vec::new();
    for line in part[..i].split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let mut data = &part[i + 4..];
    // Strip the trailing CRLF before the next boundary.
    if data.ends_with(b"\r\n") {
        data = &data[..data.len() - 2];
    }
    Some((headers, data))
}

// ---------------------------------------------------------------------------
// Exit IP (fixed compiled-in check; country always "unknown")
// ---------------------------------------------------------------------------

async fn h_exit_ip(state: &AppState) -> HttpResponse {
    let now = now_secs();
    {
        let cache = state.exit_ip.lock().unwrap();
        if let Some(cached) = cache.as_ref() {
            if now - cached.checked_at < 3600 {
                return ok_json(serde_json::json!({
                    "ip": cached.ip, "country": "unknown", "checked_at": cached.checked_at,
                    "cached": true,
                }));
            }
        }
    }
    match https_get_ip().await {
        Ok(ip) => {
            *state.exit_ip.lock().unwrap() = Some(ExitIpState {
                ip: ip.clone(),
                checked_at: now,
            });
            ok_json(serde_json::json!({
                "ip": ip, "country": "unknown", "checked_at": now, "cached": false,
            }))
        }
        Err(e) => err_json("bad_request", &format!("exit-IP check failed: {e}"), 502),
    }
}

/// Minimal HTTPS GET to the compiled-in IP-echo endpoint. No proxy, no
/// redirects, 15 s timeout. The URL is fixed at build time (never user input).
async fn https_get_ip() -> Result<String, String> {
    use rustls_pki_types::ServerName;
    let host = EXIT_IP_URL.strip_prefix("https://").unwrap_or(EXIT_IP_URL);
    let addr = format!("{host}:443");
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host)
        .map_err(|e| format!("server name: {e}"))?
        .to_owned();
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| "tls handshake timed out".to_string())?
    .map_err(|e| format!("tls: {e}"))?;
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tls.read_to_end(&mut buf),
    )
    .await
    .map_err(|_| "read timed out".to_string())?
    .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    if body.parse::<std::net::IpAddr>().is_ok() {
        Ok(body.to_string())
    } else {
        Err("unexpected response body".to_string())
    }
}

// ---------------------------------------------------------------------------
// Collector (gateway -> exit aggregates)
// ---------------------------------------------------------------------------

async fn h_collector_usage(state: &AppState, req: &HttpRequest) -> HttpResponse {
    // Collector-token auth (constant-time), separate from the admin token.
    let expected = match &state.config.collector_token {
        Some(t) => t,
        None => return err_json("forbidden", "collector not configured", 403),
    };
    if let Err(retry) = check_rate(state, req.peer.ip(), "api", API_RATE_PER_MIN, None) {
        return rate_limited_response(retry);
    }
    if !bearer_valid(bearer_of(req), expected) {
        return err_json("unauthorized", "bad collector token", 401);
    }
    if state.config.mode != AdminMode::Primary {
        return err_json("forbidden", "this node is not primary", 403);
    }
    let body: serde_json::Value = match json_body(req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let day = body
        .get("day")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if day.len() != 10 {
        return err_json("bad_request", "day must be YYYY-MM-DD", 400);
    }
    let rows = body
        .get("rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let now = now_secs();
    let conn = match state.db_lock() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut applied = 0;
    for row in rows {
        // Rows carry identity_hashes; the primary joins them to devices.
        let h = row.get("h").and_then(|v| v.as_str()).unwrap_or("");
        let up = row.get("up").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let down = row.get("down").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let sessions = row.get("sessions").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let device_id: Option<String> = conn
            .query_row(
                "SELECT device_id FROM credentials WHERE identity_hash=?1 LIMIT 1",
                rusqlite::params![h],
                |r| r.get::<_, String>(0),
            )
            .ok();
        // The gateway's role for these rows is always "gateway".
        if store::upsert_usage(
            &conn,
            &day,
            device_id.as_deref(),
            "gateway",
            up,
            down,
            sessions,
        )
        .is_ok()
        {
            applied += 1;
        }
    }
    let _ = store::log_event(
        &conn,
        now,
        "collector",
        "gateway",
        &serde_json::json!({"rows": applied, "day": day}),
    );
    ok_json(serde_json::json!({ "ok": true, "applied": applied }))
}
