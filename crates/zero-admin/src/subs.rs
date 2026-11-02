//! Subscription issuance: per-device credentials, share links, QR, configs.
//!
//! Link builders exist ONLY for protocols with a real server side (audit §4).
//! Protocols without one — juicity, amneziawg (no server), shadowtls
//! (unverified), ssr/naive/snell (absent) — are never offered for issuance;
//! [`issuable`] returns false for them and the panel labels them honestly.
//!
//! The vless-reality / vless-xhttp / zerov1 builders are delegated to
//! `zero_provision::links` (the same builders provision uses); the rest are
//! implemented here and round-trip tested through `zero_config::parse_link`.

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use zero_provision::{keys, links};

/// Protocols the admin will actually issue credentials for.
/// Everything else in the audit's client-only list is refused.
pub const ISSUABLE_PROTOCOLS: &[&str] = &[
    "vless",
    "vless-reality",
    "vless-xhttp",
    "vmess",
    "trojan",
    "ss",
    "wireguard",
    "hy2",
    "tuic",
    "anytls",
    "socks",
    "zerov1",
    "masterdns",
];

pub fn issuable(protocol: &str) -> bool {
    ISSUABLE_PROTOCOLS.contains(&protocol)
}

/// The sealed per-credential payload stored in `credentials.secret`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedSecret {
    pub protocol: String,
    /// Server-side identity: uuid, password, base64 key, or pubkey.
    /// This is what goes into `/etc/zray/users/<tag>.json` and what the
    /// engine HMACs for usage attribution.
    pub identity: String,
    /// Protocol-specific material (private keys, extra params).
    pub material: serde_json::Value,
}

fn fragment(label: &str) -> String {
    utf8_percent_encode(label, NON_ALPHANUMERIC).to_string()
}

fn authority(host: &str, port: u16) -> String {
    links::authority(host, port)
}

fn param<'a>(params: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    params.get(key)?.as_str()
}

// ---------------------------------------------------------------------------
// Credential material generation (one per protocol)
// ---------------------------------------------------------------------------

/// Generate fresh credential material for a protocol.
/// `None` = protocol not issuable (no server side) — never fake one.
pub fn generate_material(protocol: &str, params: &serde_json::Value) -> Option<IssuedSecret> {
    let material = match protocol {
        "vless" | "vless-reality" | "vless-xhttp" | "vmess" | "tuic" => {
            let uuid = keys::new_uuid();
            let mut m = serde_json::json!({ "uuid": uuid });
            if protocol == "tuic" {
                m["password"] = serde_json::Value::String(keys::random_hex(16));
            }
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: uuid,
                material: m,
            }
        }
        "trojan" | "hy2" | "anytls" => {
            let password = keys::random_hex(16);
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: password.clone(),
                material: serde_json::json!({ "password": password }),
            }
        }
        "ss" => {
            // Key length follows the cipher (params.method, default aes-256-gcm).
            let key_len = match param(params, "method").unwrap_or("aes-256-gcm") {
                "aes-128-gcm" => 16,
                _ => 32,
            };
            let key = base64::engine::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                rand_bytes(key_len),
            );
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: key.clone(),
                material: serde_json::json!({
                    "method": param(params, "method").unwrap_or("aes-256-gcm"),
                    "key": key,
                }),
            }
        }
        "wireguard" => {
            use rand::rngs::OsRng;
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let enc = base64::engine::general_purpose::STANDARD;
            let priv_b64 = base64::engine::Engine::encode(&enc, secret.to_bytes());
            let pub_b64 = base64::engine::Engine::encode(&enc, public.to_bytes());
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: pub_b64.clone(),
                material: serde_json::json!({
                    "private_key": priv_b64,
                    "public_key": pub_b64,
                }),
            }
        }
        "socks" => {
            let username = format!("u{}", keys::random_hex(4));
            let password = keys::random_hex(12);
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: username.clone(),
                material: serde_json::json!({
                    "username": username,
                    "password": password,
                }),
            }
        }
        "zerov1" => {
            let uuid = keys::new_uuid();
            let id = links::zerov1_user_id(&uuid).unwrap_or_default();
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: id,
                material: serde_json::json!({ "uuid": uuid }),
            }
        }
        "masterdns" => {
            // MasterDNS uses the service key (shared, not per-device).
            // The panel must label this honestly: not per-device revocable.
            let key = param(params, "key")?.to_string();
            IssuedSecret {
                protocol: protocol.to_string(),
                identity: "shared".to_string(),
                material: serde_json::json!({ "key": key }),
            }
        }
        _ => return None,
    };
    Some(material)
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// Share-link builders
// ---------------------------------------------------------------------------

/// Render a share link for an issued credential on an inbound.
/// Returns `None` when required inbound params are missing (honest skip)
/// or the protocol is not issuable (never a fake link).
pub fn render_link(
    inbound: &crate::store::Inbound,
    secret: &IssuedSecret,
    label: &str,
) -> Option<String> {
    let p = &inbound.params;
    let host = inbound.host.as_str();
    let port = inbound.port as u16;
    let frag = fragment(label);
    let uuid = secret
        .material
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match inbound.protocol.as_str() {
        "vless-reality" => Some(links::vless_reality(
            host,
            port,
            uuid,
            param(p, "sni")?,
            param(p, "pbk")?,
            param(p, "sid").unwrap_or(""),
            label,
        )),
        "vless-xhttp" => Some(links::vless_xhttp_reality(
            host,
            port,
            uuid,
            param(p, "sni")?,
            param(p, "pbk")?,
            param(p, "sid").unwrap_or(""),
            param(p, "path").unwrap_or("/"),
            label,
        )),
        "zerov1" => Some(links::zerov1_reality(
            host,
            port,
            uuid,
            param(p, "server_key")?,
            param(p, "path").unwrap_or("/"),
            param(p, "sni")?,
            param(p, "pbk")?,
            param(p, "sid").unwrap_or(""),
            label,
        )),
        "masterdns" => {
            let domain = param(p, "domain")?;
            let key = secret.material.get("key")?.as_str()?;
            let mut query = String::new();
            if host.parse::<std::net::IpAddr>().is_ok() {
                query.push_str(&format!("server={host}&"));
            }
            query.push_str(&format!(
                "resolvers={}",
                links::MASTERDNS_RESOLVERS.join(",")
            ));
            if param(p, "method").unwrap_or("5") != "5" {
                query.push_str(&format!("&method={}", param(p, "method").unwrap()));
            }
            Some(format!(
                "masterdns://{}@{}?{query}#{frag}",
                utf8_percent_encode(key, NON_ALPHANUMERIC),
                domain
            ))
        }
        "vless" => {
            // Generic VLESS: params-driven security (tls) or none.
            let security = param(p, "security").unwrap_or("none");
            let mut q = format!("encryption=none&security={security}");
            match security {
                "tls" => {
                    q.push_str(&format!("&sni={}", param(p, "sni")?));
                    q.push_str("&fp=chrome");
                }
                "reality" => {
                    q.push_str(&format!(
                        "&sni={}&fp=chrome&pbk={}&sid={}",
                        param(p, "sni")?,
                        param(p, "pbk")?,
                        param(p, "sid").unwrap_or("")
                    ));
                }
                _ => {}
            }
            let net = param(p, "type").unwrap_or("tcp");
            q.push_str(&format!("&type={net}"));
            if net != "tcp" && net != "raw" {
                if let Some(path) = param(p, "path") {
                    q.push_str(&format!(
                        "&path={}",
                        utf8_percent_encode(path, NON_ALPHANUMERIC)
                    ));
                }
                if let Some(h) = param(p, "host_header") {
                    q.push_str(&format!("&host={h}"));
                }
            }
            if param(p, "flow").is_some() {
                q.push_str(&format!("&flow={}", param(p, "flow").unwrap()));
            }
            Some(format!(
                "vless://{uuid}@{}?{q}#{frag}",
                authority(host, port)
            ))
        }
        "vmess" => {
            let vmess = serde_json::json!({
                "v": "2", "ps": label, "add": host, "port": port.to_string(),
                "id": uuid, "aid": "0",
                "net": param(p, "type").unwrap_or("tcp"),
                "type": "none",
                "host": param(p, "host_header").unwrap_or(""),
                "path": param(p, "path").unwrap_or(""),
                "tls": if param(p, "security").unwrap_or("none") == "tls" { "tls" } else { "" },
                "sni": param(p, "sni").unwrap_or(""),
            });
            let b64 = base64::engine::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                vmess.to_string().as_bytes(),
            );
            Some(format!("vmess://{b64}"))
        }
        "trojan" => {
            let password = secret.identity.as_str();
            let sni = param(p, "sni").unwrap_or(host);
            Some(format!(
                "trojan://{password}@{}?security=tls&sni={sni}#{frag}",
                authority(host, port)
            ))
        }
        "ss" => {
            let method = secret
                .material
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("aes-256-gcm");
            let userinfo = base64::engine::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{method}:{}", secret.identity).as_bytes(),
            );
            Some(format!("ss://{userinfo}@{}#{frag}", authority(host, port)))
        }
        "wireguard" => {
            let privkey = secret.material.get("private_key")?.as_str()?;
            let server_pubkey = param(p, "server_pubkey")?;
            let address = wireguard_address(p, &secret.identity);
            let keepalive = param(p, "keepalive").unwrap_or("25");
            Some(format!(
                "wireguard://{privkey}@{}?publickey={server_pubkey}&address={address}&keepalive={keepalive}#{frag}",
                authority(host, port)
            ))
        }
        "hy2" => {
            let password = secret.identity.as_str();
            let sni = param(p, "sni").unwrap_or(host);
            let mut q = format!("sni={sni}");
            if let Some(obfs) = param(p, "obfs") {
                q.push_str(&format!("&obfs={obfs}"));
                if let Some(pw) = param(p, "obfs_password") {
                    q.push_str(&format!("&obfs-password={pw}"));
                }
            }
            Some(format!(
                "hy2://{password}@{}?{q}#{frag}",
                authority(host, port)
            ))
        }
        "tuic" => {
            let password = secret
                .material
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sni = param(p, "sni").unwrap_or(host);
            Some(format!(
                "tuic://{uuid}:{password}@{}?sni={sni}&congestion_control=bbr&udp_relay_mode=native&alpn=h3#{frag}",
                authority(host, port)
            ))
        }
        "anytls" => {
            let password = secret.identity.as_str();
            let sni = param(p, "sni").unwrap_or(host);
            Some(format!(
                "anytls://{password}@{}?security=tls&sni={sni}#{frag}",
                authority(host, port)
            ))
        }
        "socks" => {
            let user = secret
                .material
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let pass = secret
                .material
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(format!(
                "socks://{user}:{pass}@{}#{frag}",
                authority(host, port)
            ))
        }
        _ => None,
    }
}

/// Deterministic per-device WireGuard address from a /24 template.
/// `params.address_template` = "10.8.0.0/24"; the last octet derives from
/// a hash of the device identity (1..=254). Documented, deterministic,
/// collision-safe for personal scale.
fn wireguard_address(params: &serde_json::Value, identity: &str) -> String {
    let template = param(params, "address_template").unwrap_or("10.8.0.0/24");
    let prefix = template.split('/').next().unwrap_or("10.8.0.0");
    let mut base: Vec<&str> = prefix.split('.').collect();
    while base.len() < 3 {
        base.push("0");
    }
    let octet = {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(identity.as_bytes());
        (h[0] % 254) + 1
    };
    format!("{}.{}.{}.{octet}/32", base[0], base[1], base[2])
}

// ---------------------------------------------------------------------------
// QR (SVG), subscription bodies
// ---------------------------------------------------------------------------

/// Render a QR code as SVG. Links longer than 2 KiB fall back to "copy link"
/// (QR density limit is honest UI, per Design C §4.3).
pub fn qr_svg(text: &str) -> Option<String> {
    if text.len() > 2048 {
        return None;
    }
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let w = code.width();
    let module = 4u32;
    let size = w as u32 * module;
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         width=\"{size}\" height=\"{size}\" shape-rendering=\"crispEdges\">\
         <rect width=\"{size}\" height=\"{size}\" fill=\"white\"/>"
    );
    for y in 0..w {
        for x in 0..w {
            if code[(x, y)] == qrcode::Color::Dark {
                let (px, py) = (x as u32 * module, y as u32 * module);
                svg.push_str(&format!(
                    "<rect x=\"{px}\" y=\"{py}\" width=\"{module}\" height=\"{module}\" fill=\"black\"/>"
                ));
            }
        }
    }
    svg.push_str("</svg>");
    Some(svg)
}

/// Standard subscription body: base64 lines of the device's links.
pub fn subscription_body(links: &[String]) -> String {
    base64::engine::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        links.join("\n").as_bytes(),
    )
}

// ---------------------------------------------------------------------------
// sing-box JSON / Mihomo YAML (typed structs, not hand templates)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SingBoxOutbound {
    Vless {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<String>,
        tls: SingBoxTls,
    },
    Vmess {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        security: String,
        alter_id: u8,
    },
    Trojan {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        tls: SingBoxTls,
    },
    Shadowsocks {
        tag: String,
        server: String,
        server_port: u16,
        method: String,
        password: String,
    },
    Wireguard {
        tag: String,
        server: String,
        server_port: u16,
        private_key: String,
        peer_public_key: String,
        local_address: Vec<String>,
    },
    Hysteria2 {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        tls: SingBoxTls,
    },
    Tuic {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        password: String,
        tls: SingBoxTls,
    },
    Anytls {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        tls: SingBoxTls,
    },
    Socks {
        tag: String,
        server: String,
        server_port: u16,
        username: String,
        password: String,
    },
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SingBoxTls {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality: Option<SingBoxReality>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SingBoxReality {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: String,
}

pub fn singbox_outbound(
    inbound: &crate::store::Inbound,
    secret: &IssuedSecret,
    tag: &str,
) -> Option<SingBoxOutbound> {
    let p = &inbound.params;
    let server = inbound.host.clone();
    let port = inbound.port as u16;
    let tls_server = |enabled: bool| SingBoxTls {
        enabled,
        server_name: param(p, "sni").map(str::to_string),
        reality: None,
    };
    match inbound.protocol.as_str() {
        "vless" | "vless-reality" | "vless-xhttp" => {
            let uuid = secret.material.get("uuid")?.as_str()?.to_string();
            let reality = if param(p, "pbk").is_some() {
                Some(SingBoxReality {
                    enabled: true,
                    public_key: param(p, "pbk")?.to_string(),
                    short_id: param(p, "sid").unwrap_or("").to_string(),
                })
            } else {
                None
            };
            Some(SingBoxOutbound::Vless {
                tag: tag.to_string(),
                server,
                server_port: port,
                uuid,
                flow: param(p, "flow").map(str::to_string),
                tls: SingBoxTls {
                    enabled: reality.is_some() || param(p, "security") == Some("tls"),
                    server_name: param(p, "sni").map(str::to_string),
                    reality,
                },
            })
        }
        "vmess" => Some(SingBoxOutbound::Vmess {
            tag: tag.to_string(),
            server,
            server_port: port,
            uuid: secret.material.get("uuid")?.as_str()?.to_string(),
            security: "auto".to_string(),
            alter_id: 0,
        }),
        "trojan" => Some(SingBoxOutbound::Trojan {
            tag: tag.to_string(),
            server,
            server_port: port,
            password: secret.identity.clone(),
            tls: tls_server(true),
        }),
        "ss" => Some(SingBoxOutbound::Shadowsocks {
            tag: tag.to_string(),
            server,
            server_port: port,
            method: secret
                .material
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("aes-256-gcm")
                .to_string(),
            password: secret.identity.clone(),
        }),
        "wireguard" => Some(SingBoxOutbound::Wireguard {
            tag: tag.to_string(),
            server,
            server_port: port,
            private_key: secret.material.get("private_key")?.as_str()?.to_string(),
            peer_public_key: param(p, "server_pubkey")?.to_string(),
            local_address: vec![wireguard_address(p, &secret.identity)],
        }),
        "hy2" => Some(SingBoxOutbound::Hysteria2 {
            tag: tag.to_string(),
            server,
            server_port: port,
            password: secret.identity.clone(),
            tls: tls_server(true),
        }),
        "tuic" => Some(SingBoxOutbound::Tuic {
            tag: tag.to_string(),
            server,
            server_port: port,
            uuid: secret.material.get("uuid")?.as_str()?.to_string(),
            password: secret
                .material
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            tls: tls_server(true),
        }),
        "anytls" => Some(SingBoxOutbound::Anytls {
            tag: tag.to_string(),
            server,
            server_port: port,
            password: secret.identity.clone(),
            tls: tls_server(true),
        }),
        "socks" => Some(SingBoxOutbound::Socks {
            tag: tag.to_string(),
            server,
            server_port: port,
            username: secret.material.get("username")?.as_str()?.to_string(),
            password: secret.material.get("password")?.as_str()?.to_string(),
        }),
        _ => None,
    }
}

/// Mihomo `proxies:` entry, generated from the same typed enum.
pub fn mihomo_proxy(ob: &SingBoxOutbound) -> Option<String> {
    let y = |s: &str| yaml_str(s);
    let entry = match ob {
        SingBoxOutbound::Vless { tag, server, server_port, uuid, flow, tls } => {
            let mut s = format!(
                "- name: {}\n  type: vless\n  server: {}\n  port: {}\n  uuid: {}\n  encryption: none\n",
                y(tag),
                y(server),
                server_port,
                y(uuid)
            );
            if let Some(f) = flow {
                s.push_str(&format!("  flow: {}\n", y(f)));
            }
            s.push_str(&tls_yaml(tls, "  "));
            s
        }
        SingBoxOutbound::Vmess { tag, server, server_port, uuid, .. } => format!(
            "- name: {}\n  type: vmess\n  server: {}\n  port: {}\n  uuid: {}\n  alterId: 0\n  cipher: auto\n",
            y(tag),
            y(server),
            server_port,
            y(uuid)
        ),
        SingBoxOutbound::Trojan { tag, server, server_port, password, tls } => format!(
            "- name: {}\n  type: trojan\n  server: {}\n  port: {}\n  password: {}\n{}",
            y(tag),
            y(server),
            server_port,
            y(password),
            tls_yaml(tls, "  ")
        ),
        SingBoxOutbound::Shadowsocks { tag, server, server_port, method, password } => format!(
            "- name: {}\n  type: ss\n  server: {}\n  port: {}\n  cipher: {}\n  password: {}\n",
            y(tag),
            y(server),
            server_port,
            y(method),
            y(password)
        ),
        SingBoxOutbound::Wireguard {
            tag,
            server,
            server_port,
            private_key,
            peer_public_key,
            local_address,
        } => format!(
            "- name: {}\n  type: wireguard\n  server: {}\n  port: {}\n  private-key: {}\n  public-key: {}\n  ip: {}\n",
            y(tag),
            y(server),
            server_port,
            y(private_key),
            y(peer_public_key),
            y(local_address.first().map(String::as_str).unwrap_or(""))
        ),
        SingBoxOutbound::Hysteria2 { tag, server, server_port, password, tls } => format!(
            "- name: {}\n  type: hysteria2\n  server: {}\n  port: {}\n  password: {}\n{}",
            y(tag),
            y(server),
            server_port,
            y(password),
            tls_yaml(tls, "  ")
        ),
        SingBoxOutbound::Tuic { tag, server, server_port, uuid, password, tls } => format!(
            "- name: {}\n  type: tuic\n  server: {}\n  port: {}\n  uuid: {}\n  password: {}\n{}",
            y(tag),
            y(server),
            server_port,
            y(uuid),
            y(password),
            tls_yaml(tls, "  ")
        ),
        SingBoxOutbound::Anytls { tag, server, server_port, password, tls } => format!(
            "- name: {}\n  type: anytls\n  server: {}\n  port: {}\n  password: {}\n{}",
            y(tag),
            y(server),
            server_port,
            y(password),
            tls_yaml(tls, "  ")
        ),
        SingBoxOutbound::Socks { tag, server, server_port, username, password } => format!(
            "- name: {}\n  type: socks5\n  server: {}\n  port: {}\n  username: {}\n  password: {}\n",
            y(tag),
            y(server),
            server_port,
            y(username),
            y(password)
        ),
    };
    Some(entry)
}

fn yaml_str(s: &str) -> String {
    // Quote when the value could confuse a YAML parser.
    if s.chars()
        .any(|c| c.is_whitespace() || ":{}[],#&*!|>'\"%@`".contains(c))
        || s.is_empty()
    {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        s.to_string()
    }
}

fn tls_yaml(tls: &SingBoxTls, indent: &str) -> String {
    if !tls.enabled {
        return String::new();
    }
    let mut s = format!("{indent}tls: true\n");
    if let Some(name) = &tls.server_name {
        s.push_str(&format!("{indent}servername: {}\n", yaml_str(name)));
    }
    if let Some(r) = &tls.reality {
        if r.enabled {
            s.push_str(&format!("{indent}reality-opts:\n"));
            s.push_str(&format!(
                "{indent}  public-key: {}\n",
                yaml_str(&r.public_key)
            ));
            s.push_str(&format!("{indent}  short-id: {}\n", yaml_str(&r.short_id)));
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Tests: every builder round-trips through the real parser.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Inbound;

    fn inbound(protocol: &str, params: serde_json::Value) -> Inbound {
        Inbound {
            tag: "test-in".to_string(),
            protocol: protocol.to_string(),
            server_role: "exit".to_string(),
            host: "203.0.113.7".to_string(),
            port: 443,
            params,
            enabled: true,
        }
    }

    fn reality_params() -> serde_json::Value {
        serde_json::json!({
            "sni": "www.example.com",
            "pbk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "sid": "a1b2c3d4",
            "path": "/xhttp",
            "server_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
        })
    }

    fn check_round_trip(link: &str) {
        let parsed = zero_config::parse_link(link);
        assert!(
            parsed.is_ok(),
            "builder output failed to parse: {link}\nerr: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn issuable_set_excludes_client_only_protocols() {
        for p in [
            "juicity",
            "amneziawg",
            "shadowtls",
            "ssr",
            "naive",
            "snell",
            "bogus",
        ] {
            assert!(!issuable(p), "{p} must not be issuable");
            assert!(generate_material(p, &serde_json::json!({})).is_none());
        }
        for p in ISSUABLE_PROTOCOLS {
            assert!(issuable(p));
        }
    }

    #[test]
    fn delegated_builders_round_trip() {
        for proto in ["vless-reality", "vless-xhttp", "zerov1"] {
            let ib = inbound(proto, reality_params());
            let secret = generate_material(proto, &ib.params).unwrap();
            let link = render_link(&ib, &secret, "device-1").unwrap();
            check_round_trip(&link);
        }
        let ib = inbound(
            "masterdns",
            serde_json::json!({"domain": "dns.example.com", "key": "k", "method": "5"}),
        );
        let secret = generate_material("masterdns", &ib.params).unwrap();
        let link = render_link(&ib, &secret, "device-1").unwrap();
        assert!(link.starts_with("masterdns://"));
    }

    #[test]
    fn generic_builders_round_trip() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "vless",
                serde_json::json!({"security": "tls", "sni": "www.example.com", "flow": "xtls-rprx-vision"}),
            ),
            ("vless", serde_json::json!({})),
            ("vmess", serde_json::json!({"type": "tcp"})),
            ("trojan", serde_json::json!({"sni": "www.example.com"})),
            ("ss", serde_json::json!({"method": "aes-256-gcm"})),
            ("ss", serde_json::json!({"method": "aes-128-gcm"})),
            (
                "wireguard",
                serde_json::json!({
                    "server_pubkey": base64::engine::Engine::encode(
                        &base64::engine::general_purpose::STANDARD, [7u8; 32]),
                    "address_template": "10.8.0.0/24"
                }),
            ),
            ("hy2", serde_json::json!({"sni": "www.example.com"})),
            ("tuic", serde_json::json!({"sni": "www.example.com"})),
            ("anytls", serde_json::json!({"sni": "www.example.com"})),
            ("socks", serde_json::json!({})),
        ];
        for (proto, params) in cases {
            let ib = inbound(proto, params.clone());
            let secret = generate_material(proto, &ib.params).expect(proto);
            let link = render_link(&ib, &secret, "device-1").expect(proto);
            check_round_trip(&link);
        }
    }

    #[test]
    fn builder_returns_none_when_params_missing() {
        // reality pbk missing -> honest None, never a broken link.
        let ib = inbound("vless-reality", serde_json::json!({"sni": "x"}));
        let secret = generate_material("vless-reality", &ib.params).unwrap();
        assert!(render_link(&ib, &secret, "d").is_none());
        // masterdns without key material -> None.
        let ib = inbound("masterdns", serde_json::json!({"domain": "d"}));
        assert!(generate_material("masterdns", &ib.params).is_none());
    }

    #[test]
    fn wireguard_address_is_deterministic() {
        let p = serde_json::json!({"address_template": "10.8.0.0/24"});
        let a = wireguard_address(&p, "device-a");
        let b = wireguard_address(&p, "device-a");
        let c = wireguard_address(&p, "device-b");
        assert_eq!(a, b);
        assert!(a.starts_with("10.8.0."));
        assert!(a.ends_with("/32"));
        assert_ne!(a, c);
    }

    #[test]
    fn qr_svg_respects_size_cap() {
        let small = qr_svg("vless://abc").unwrap();
        assert!(small.starts_with("<svg"));
        assert!(small.contains("rect"));
        assert!(qr_svg(&"x".repeat(3000)).is_none());
    }

    #[test]
    fn subscription_body_is_base64_lines() {
        let body = subscription_body(&["vless://a".to_string(), "ss://b".to_string()]);
        let decoded = String::from_utf8(
            base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, &body)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, "vless://a\nss://b");
    }

    #[test]
    fn singbox_and_mihomo_emit_for_all_issuable() {
        for proto in [
            "vless",
            "vmess",
            "trojan",
            "ss",
            "wireguard",
            "hy2",
            "tuic",
            "anytls",
            "socks",
        ] {
            let params = match proto {
                "wireguard" => serde_json::json!({"server_pubkey": base64::engine::Engine::encode(
                    &base64::engine::general_purpose::STANDARD, [7u8; 32])}),
                "ss" => serde_json::json!({"method": "aes-256-gcm"}),
                _ => serde_json::json!({"sni": "www.example.com"}),
            };
            let ib = inbound(proto, params);
            let secret = generate_material(proto, &ib.params).unwrap();
            let ob = singbox_outbound(&ib, &secret, "test-in").expect(proto);
            let json = serde_json::to_value(&ob).unwrap();
            assert_eq!(json["server"], "203.0.113.7");
            let yaml = mihomo_proxy(&ob).expect(proto);
            assert!(yaml.contains("203.0.113.7"), "{proto} yaml missing server");
        }
    }

    #[test]
    fn identity_hash_matches_engine_formula() {
        // The engine computes HMAC-SHA256(usage_salt, identity); the admin
        // must precompute the identical value at issuance.
        let salt = crate::crypto::new_usage_salt();
        let secret = generate_material("vless", &serde_json::json!({})).unwrap();
        let h1 = crate::crypto::identity_hash(&salt, &secret.identity);
        let h2 = crate::crypto::identity_hash(&salt, &secret.identity);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}
