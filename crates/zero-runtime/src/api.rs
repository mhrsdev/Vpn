//! Small loopback management API.
//!
//! The API is intentionally separate from proxy listeners. It exposes only
//! bounded statistics and an authenticated whole-generation reload endpoint;
//! it never accepts arbitrary outbound destinations or executes config JSON
//! incrementally.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Server;

const MAX_REQUEST: usize = 2 * 1024 * 1024;
/// How long a client may take to deliver its request. Only reading is
/// bounded: handling (a forced asset refresh downloads rule sets) must not be
/// cancelled half-way by a deadline meant for slow senders.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ManagementConfig {
    pub listen: SocketAddr,
    pub bearer_token: Option<Arc<str>>,
}

impl ManagementConfig {
    pub fn validate(&self) -> Result<(), String> {
        let loopback = self.listen.ip().is_loopback();
        if !loopback && self.bearer_token.as_deref().is_none_or(str::is_empty) {
            return Err("management API requires a bearer token off loopback".into());
        }
        Ok(())
    }
}

pub struct ManagementServer {
    config: ManagementConfig,
}

impl ManagementServer {
    pub fn new(config: ManagementConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self { config })
    }

    pub async fn run(self, server: Arc<Server>) -> std::io::Result<()> {
        let addr = self.config.listen;
        let listener = zero_net::prepare_listener(addr)?;
        let mut backoff_ms = 10u64;
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => {
                    backoff_ms = 10;
                    accepted
                }
                // Descriptor exhaustion and aborted handshakes are transient;
                // returning here would take the management API down for good.
                Err(error) => {
                    tracing::warn!(%error, backoff_ms, "management accept failed");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(1000);
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let config = self.config.clone();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, peer, config, server).await {
                    tracing::debug!(%peer, %error, "management request failed");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: ManagementConfig,
    server: Arc<Server>,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + REQUEST_READ_TIMEOUT;
    let mut data = Vec::with_capacity(1024);
    let head_end;
    // Only the bytes that arrived since the last pass (plus three, for a
    // terminator split across reads) need scanning; rescanning the whole
    // buffer per read is quadratic in a trickled request.
    let mut scanned = 0usize;
    loop {
        let from = scanned.saturating_sub(3);
        if let Some(end) = data[from..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            head_end = from + end + 4;
            break;
        }
        scanned = data.len();
        if data.len() >= MAX_REQUEST {
            return write_response(&mut stream, 413, "request too large", b"").await;
        }
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| "request head timed out".to_string())?
            .map_err(|error| format!("reading request: {error}"))?;
        if n == 0 {
            return Ok(());
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut request = httparse::Request::new(&mut headers);
    request
        .parse(&data[..head_end])
        .map_err(|error| format!("malformed request: {error}"))?;
    let method = request.method.unwrap_or("").to_string();
    let path = request.path.unwrap_or("").to_string();
    let authorization = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::to_owned);
    // Copied out of the borrow of `data` below, which the rest of the handler
    // needs mutably while it reads the body.
    let origin = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("origin"))
        .map(|header| header.value.len());
    let content_length = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| {
            std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if content_length > MAX_REQUEST - head_end {
        return write_response(&mut stream, 413, "request too large", b"").await;
    }
    while data.len() < head_end + content_length {
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| "request body timed out".to_string())?
            .map_err(|error| format!("reading request body: {error}"))?;
        if n == 0 {
            return write_response(&mut stream, 400, "truncated body", b"").await;
        }
    }

    if let Some(expected) = config.bearer_token.as_deref() {
        let actual = authorization
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "));
        if actual != Some(expected) {
            return write_response(&mut stream, 401, "unauthorized", b"").await;
        }
    } else if !peer.ip().is_loopback() {
        return write_response(&mut stream, 403, "forbidden", b"").await;
    }

    // Cross-site requests. `POST /reload` installs a whole replacement
    // configuration, so a page open in the user's browser must not be able to
    // trigger it: without this, any site could send a form post to
    // `127.0.0.1` and rewrite the proxy. Every state-changing verb is checked
    // rather than just `/reload`, so the rule cannot be forgotten when an
    // endpoint is added.
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") && origin.is_some() {
        return write_response(&mut stream, 403, "cross-origin request refused", b"").await;
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/stats") => {
            let body = serde_json::to_vec(&server.stats.snapshot())
                .map_err(|error| format!("encoding stats: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", path) if path == "/stats/traffic" || path.starts_with("/stats/traffic?") => {
            // Xray-compatible per-tag counters. `?reset=true` zeroes each
            // counter as it is read, matching Xray's QueryStats reset.
            let reset = path
                .split_once('?')
                .map(|(_, query)| {
                    query
                        .split('&')
                        .any(|pair| matches!(pair, "reset=true" | "reset=1" | "reset"))
                })
                .unwrap_or(false);
            let stat = server
                .stats
                .traffic_counters(reset)
                .into_iter()
                .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
                .collect::<Vec<_>>();
            let body = serde_json::to_vec(&serde_json::json!({ "stat": stat }))
                .map_err(|error| format!("encoding traffic stats: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/usage") => {
            // Counts only: sessions and devices per inbound, plus its byte
            // totals. See `crate::usage` for why nothing here can name a user.
            let snapshot = server.stats.usage.snapshot();
            let traffic: std::collections::HashMap<String, u64> =
                server.stats.traffic_counters(false).into_iter().collect();
            let bytes = |tag: &str, way: &str| {
                traffic
                    .get(&format!("inbound>>>{tag}>>>traffic>>>{way}"))
                    .copied()
                    .unwrap_or(0)
            };
            let inbounds: Vec<_> = snapshot
                .inbounds
                .iter()
                .map(|usage| {
                    serde_json::json!({
                        "tag": usage.tag,
                        "sessions": usage.sessions,
                        "devices_now": usage.devices_now,
                        "devices_recent": usage.devices_recent,
                        "uplink": bytes(&usage.tag, "uplink"),
                        "downlink": bytes(&usage.tag, "downlink"),
                    })
                })
                .collect();
            let body = serde_json::to_vec(&serde_json::json!({
                "window_secs": snapshot.window_secs,
                "inbounds": inbounds,
            }))
            .map_err(|error| format!("encoding usage: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/health") => {
            let body = serde_json::to_vec(&server.health_snapshot())
                .map_err(|error| format!("encoding health: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/clean-ip") => {
            let body = serde_json::to_vec(&server.clean_ip_snapshot())
                .map_err(|error| format!("encoding clean-ip results: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/assets") => {
            let body = serde_json::to_vec(&server.asset_snapshot())
                .map_err(|error| format!("encoding asset status: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/assets/refresh") => {
            // Forced because an operator asking for a refresh is doing so
            // precisely when the TTL says nothing needs doing.
            let report = server.refresh_assets_now().await;
            let body = serde_json::to_vec(&report)
                .map_err(|error| format!("encoding refresh report: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/reload") => {
            let body = &data[head_end..head_end + content_length];
            let value: serde_json::Value = serde_json::from_slice(body)
                .map_err(|error| format!("reload body is not JSON: {error}"))?;
            let next = server.current_generation().0.saturating_add(1);
            let (generation, diagnostics) =
                zero_config::compile_config(&value, zero_core::GenerationId(next))
                    .map_err(|error| format!("reload config rejected: {error}"))?;
            server
                .reload(Arc::clone(&generation.config), generation.id)
                .map_err(|error| format!("reload rejected: {error}"))?;
            let body = serde_json::json!({
                "generation": next,
                "diagnostics": diagnostics.diagnostics.len()
            });
            let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/classify") => {
            // Engine side of the admin's Rule Tester
            // (`POST /api/v1/routing/test` → admin `EngineClient::classify`).
            // 404 when the engine has no split classifier — the admin maps
            // this to its honest 502, never a guessed answer.
            let body = &data[head_end..head_end + content_length];
            let value: serde_json::Value = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(error) => {
                    let msg = format!("classify body is not JSON: {error}");
                    return write_response(&mut stream, 400, "bad request", msg.as_bytes()).await;
                }
            };
            let target = match value.get("target").and_then(serde_json::Value::as_str) {
                Some(target) => target,
                None => {
                    return write_response(
                        &mut stream,
                        400,
                        "bad request",
                        b"classify needs a string \"target\"",
                    )
                    .await
                }
            };
            match server.classify_target(target) {
                Some(result) => {
                    let body = serde_json::to_vec(&result.to_json())
                        .map_err(|error| format!("encoding classify result: {error}"))?;
                    write_response(&mut stream, 200, "ok", &body).await
                }
                None => write_response(&mut stream, 404, "no split classifier", b"").await,
            }
        }
        ("POST", "/ruleset") => {
            // Engine side of the admin's rule push
            // (`EngineClient::push_ruleset`). Fail-closed: a rejected push
            // keeps the previous version; the error text goes back to the
            // admin, which keeps `push_pending` set.
            let body = &data[head_end..head_end + content_length];
            let value: serde_json::Value = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(error) => {
                    let msg = format!("ruleset body is not JSON: {error}");
                    return write_response(&mut stream, 400, "bad request", msg.as_bytes()).await;
                }
            };
            let version = match value.get("version").and_then(serde_json::Value::as_i64) {
                Some(version) => version,
                None => {
                    return write_response(
                        &mut stream,
                        400,
                        "bad request",
                        b"ruleset needs an integer \"version\"",
                    )
                    .await
                }
            };
            let rules = match value.get("rules").and_then(serde_json::Value::as_array) {
                Some(rules) => rules.clone(),
                None => {
                    return write_response(
                        &mut stream,
                        400,
                        "bad request",
                        b"ruleset needs a \"rules\" array",
                    )
                    .await
                }
            };
            match server.apply_pushed_ruleset(version, rules) {
                Ok(applied) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "version": version,
                        "applied": applied,
                    });
                    let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
                    write_response(&mut stream, 200, "ok", &body).await
                }
                Err(error) => {
                    let body = serde_json::json!({ "ok": false, "error": error });
                    let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
                    write_response(&mut stream, 400, "bad ruleset", &body).await
                }
            }
        }
        _ => write_response(&mut stream, 404, "not found", b"").await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| format!("writing response: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("writing response body: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_management_listeners_require_authentication() {
        let config = ManagementConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            bearer_token: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn loopback_management_listener_can_be_private() {
        let config = ManagementConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            bearer_token: None,
        };
        assert!(config.validate().is_ok());
    }

    /// A page in the user's browser must not be able to drive the API.
    ///
    /// `POST /reload` installs a whole replacement configuration, and with
    /// only a loopback check a form post from any site reached it: a JSON
    /// body sent as `text/plain` is not preflighted, so the browser issued
    /// the request and the API parsed it happily.
    #[tokio::test]
    async fn a_cross_origin_post_is_refused() {
        use tokio::io::AsyncWriteExt;

        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let config = ManagementConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            bearer_token: None,
        };

        // One request per call, served by the real handler, so the check is
        // exercised where a browser's request would land.
        let post = |origin: Option<&str>| {
            let mut request = String::from(
                "POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\
Content-Length: 2\r\n",
            );
            if let Some(origin) = origin {
                request.push_str(&format!("Origin: {origin}\r\n"));
            }
            request.push_str("\r\n{}");
            let server = std::sync::Arc::clone(&server);
            let config = config.clone();
            async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let serving = {
                    let server = std::sync::Arc::clone(&server);
                    let config = config.clone();
                    async move {
                        let (accepted, peer) = listener.accept().await.unwrap();
                        handle_connection(accepted, peer, config, server).await
                    }
                };
                let client = async {
                    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
                    stream.write_all(request.as_bytes()).await.unwrap();
                    let mut reply = Vec::new();
                    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut reply)
                        .await
                        .unwrap();
                    String::from_utf8_lossy(&reply).into_owned()
                };
                let (reply, served) = tokio::join!(client, serving);
                // The handler reports a refusal as an error after it has
                // answered, so that is not a failure of the test.
                let _ = served;
                reply
            }
        };

        let crossed = post(Some("https://evil.example")).await;
        assert!(
            crossed.starts_with("HTTP/1.1 403"),
            "a browser could still rewrite the config: {crossed}"
        );

        // Same request without the header — a local tool, not a page — is
        // untouched, so nothing that legitimately drives the API breaks.
        let direct = post(None).await;
        assert!(
            !direct.starts_with("HTTP/1.1 403"),
            "a local client was refused: {direct}"
        );
    }

    /// `/usage` reports counts and byte totals per inbound and nothing that
    /// could name a client: not the address a session came from, not the key
    /// the tracker made from it.
    #[tokio::test]
    async fn usage_reports_counts_and_no_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let tag: std::sync::Arc<str> = std::sync::Arc::from("reality-in");
        let address: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let _a = server.stats.usage.open(&tag, address);
        let _b = server.stats.usage.open(&tag, address);
        let _c = server
            .stats
            .usage
            .open(&tag, "198.51.100.4".parse().unwrap());
        server.stats.record_tag_traffic(
            "reality-in",
            None,
            &crate::relay::Transferred {
                uploaded: 11,
                downloaded: 22,
            },
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let config = ManagementConfig {
            listen,
            bearer_token: Some("t0ken".into()),
        };
        let serving = {
            let server = std::sync::Arc::clone(&server);
            async move {
                let (accepted, peer) = listener.accept().await.unwrap();
                handle_connection(accepted, peer, config, server).await
            }
        };
        let client = async {
            let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
            stream
                .write_all(b"GET /usage HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0ken\r\n\r\n")
                .await
                .unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            String::from_utf8_lossy(&reply).into_owned()
        };
        let (reply, _) = tokio::join!(client, serving);
        let body = reply.split("\r\n\r\n").nth(1).expect("a body");
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON");
        let usage = &json["inbounds"][0];
        assert_eq!(usage["tag"], "reality-in");
        assert_eq!(usage["sessions"], 3);
        assert_eq!(usage["devices_now"], 2);
        assert_eq!(usage["devices_recent"], 2);
        assert_eq!(usage["uplink"], 11);
        assert_eq!(usage["downlink"], 22);
        assert!(!reply.contains("203.0.113.9") && !reply.contains("198.51.100.4"));
    }

    #[test]
    fn traffic_counters_accumulate_per_tag_and_reset_on_demand() {
        use crate::relay::Transferred;
        use crate::server::Stats;

        let stats = Stats::default();
        stats.record_tag_traffic(
            "socks-in",
            Some("proxy"),
            &Transferred {
                uploaded: 100,
                downloaded: 250,
            },
        );
        stats.record_tag_traffic(
            "socks-in",
            Some("proxy"),
            &Transferred {
                uploaded: 5,
                downloaded: 7,
            },
        );

        let counters = stats.traffic_counters(false);
        let find = |name: &str| {
            counters
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, value)| *value)
        };
        assert_eq!(find("inbound>>>socks-in>>>traffic>>>uplink"), Some(105));
        assert_eq!(find("inbound>>>socks-in>>>traffic>>>downlink"), Some(257));
        assert_eq!(find("outbound>>>proxy>>>traffic>>>uplink"), Some(105));
        assert_eq!(find("outbound>>>proxy>>>traffic>>>downlink"), Some(257));

        // A read with reset returns the accumulated values, then zeroes them.
        let reset = stats.traffic_counters(true);
        assert_eq!(
            reset
                .iter()
                .find(|(n, _)| n == "inbound>>>socks-in>>>traffic>>>uplink")
                .map(|(_, v)| *v),
            Some(105)
        );
        let after = stats.traffic_counters(false);
        assert!(
            after.iter().all(|(_, value)| *value == 0),
            "reset should have zeroed every counter: {after:?}"
        );
    }

    #[test]
    fn a_zero_byte_session_records_no_counter() {
        use crate::relay::Transferred;
        use crate::server::Stats;

        let stats = Stats::default();
        stats.record_tag_traffic(
            "socks-in",
            None,
            &Transferred {
                uploaded: 0,
                downloaded: 0,
            },
        );
        assert!(stats.traffic_counters(false).is_empty());
    }

    /// Build a `Server` for management-API tests, optionally with a
    /// `splitRouting` block.
    fn split_test_server(with_split: bool) -> std::sync::Arc<crate::Server> {
        let split = if with_split {
            r#","splitRouting": {"tunnelOnly": false, "lanAsIran": true}"#
        } else {
            ""
        };
        let config_json = format!(
            r#"{{"inbounds": [], "outbounds": [{{"tag": "direct", "protocol": "freedom"}}]{split}}}"#
        );
        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(&config_json)
                .expect("a config the engine accepts")
                .remove(0)
                .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }))
    }

    /// Drive one raw HTTP request through the real management handler.
    async fn mgmt_roundtrip(server: std::sync::Arc<crate::Server>, request: &str) -> String {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = ManagementConfig {
            listen: address,
            bearer_token: None,
        };
        let serving = async move {
            let (accepted, peer) = listener.accept().await.unwrap();
            handle_connection(accepted, peer, config, server).await
        };
        let client = async move {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut reply)
                .await
                .unwrap();
            String::from_utf8_lossy(&reply).into_owned()
        };
        let (reply, _) = tokio::join!(client, serving);
        reply
    }

    fn post(path: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// `POST /classify` answers through the real split engine; without a
    /// `splitRouting` block it 404s (the admin maps this to its honest 502).
    #[tokio::test]
    async fn classify_endpoint_classifies_and_404s_without_split() {
        let server = split_test_server(true);
        let reply =
            mgmt_roundtrip(server, &post("/classify", r#"{"target": "example.com"}"#)).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "unexpected: {reply}");
        let body = reply.split("\r\n\r\n").nth(1).expect("a body");
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON");
        // example.com is foreign → USA tunnel.
        assert_eq!(json["route"], "usa");
        assert_eq!(json["exit_country"], "US");
        assert_eq!(json["dns_policy"], "tunnel");
        assert!(json["confidence"].as_f64().unwrap() > 0.0);
        assert!(!json["reason"].as_str().unwrap().is_empty());
        assert!(!json["matched_rule"].as_str().unwrap().is_empty());

        // No split engine → 404, never a guessed answer.
        let plain = split_test_server(false);
        let reply = mgmt_roundtrip(plain, &post("/classify", r#"{"target": "example.com"}"#)).await;
        assert!(
            reply.starts_with("HTTP/1.1 404"),
            "expected 404 without splitRouting: {reply}"
        );

        // Malformed body → 400, not a panic.
        let server = split_test_server(true);
        let reply = mgmt_roundtrip(server, &post("/classify", r#"{"nope": 1}"#)).await;
        assert!(
            reply.starts_with("HTTP/1.1 400"),
            "expected 400 for missing target: {reply}"
        );
    }

    /// `POST /ruleset` applies the admin's pushed rules; a rejected push
    /// keeps the previous version (fail closed); classify reflects pushes.
    #[tokio::test]
    async fn ruleset_push_applies_and_rejects_bad() {
        let server = split_test_server(true);

        // Push a rule sending example.com to Iran.
        let push = serde_json::json!({
            "version": 7,
            "rules": [
                {"id": "r1", "kind": "domain", "value": "example.com",
                 "action": "iran", "priority": 10, "enabled": true, "note": ""}
            ]
        })
        .to_string();
        let reply = mgmt_roundtrip(std::sync::Arc::clone(&server), &post("/ruleset", &push)).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "unexpected: {reply}");
        let body = reply.split("\r\n\r\n").nth(1).expect("a body");
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(json["ok"], true);
        assert_eq!(json["version"], 7);
        assert_eq!(json["applied"], 1);

        // The pushed rule now governs classification.
        let reply = mgmt_roundtrip(
            std::sync::Arc::clone(&server),
            &post("/classify", r#"{"target": "example.com"}"#),
        )
        .await;
        let body = reply.split("\r\n\r\n").nth(1).expect("a body");
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(json["route"], "iran");
        assert_eq!(json["matched_rule"], "pushed:r1");
        assert_eq!(json["exit_country"], "IR");
        assert_eq!(json["dns_policy"], "direct");

        // A bad push is rejected whole: 400, previous version kept.
        let bad = serde_json::json!({
            "version": 8,
            "rules": [
                {"id": "r9", "kind": "bogus", "value": "x",
                 "action": "iran", "priority": 1, "enabled": true, "note": ""}
            ]
        })
        .to_string();
        let reply = mgmt_roundtrip(std::sync::Arc::clone(&server), &post("/ruleset", &bad)).await;
        assert!(
            reply.starts_with("HTTP/1.1 400"),
            "expected 400 for bad ruleset: {reply}"
        );
        assert_eq!(server.pushed_ruleset_version(), Some(7));

        // Malformed JSON → 400.
        let reply = mgmt_roundtrip(
            std::sync::Arc::clone(&server),
            &post("/ruleset", "not json"),
        )
        .await;
        assert!(reply.starts_with("HTTP/1.1 400"), "unexpected: {reply}");
    }
}
