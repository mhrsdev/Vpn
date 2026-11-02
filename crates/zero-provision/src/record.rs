//! What the app remembers about a server it set up.
//!
//! The record lives on the user's own device and is the only place the app
//! keeps anything about the server. It holds what is needed to come back and to
//! rebuild the client links: the address, how to log in (the app's own SSH key
//! once it is installed), the pinned host key, and the public facts of each
//! service. The server's private keys (REALITY's) are *not* here: they exist
//! only in the server's config file.
//!
//! `ssh_key` is a secret that opens the server; apps store the record in
//! private storage only and show a "remove access" action that deletes the key
//! on both ends.

use serde::{Deserialize, Serialize};

use crate::links;
use crate::ssh::HostKey;

/// The record's format version, for the day it changes.
pub const VERSION: u32 = 2;

/// Which side of a pair a server is on. `Single` is what the older one-server
/// installs read as: it is the serde default, so a version-1 record still
/// parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Gateway,
    Exit,
    #[default]
    Single,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reality {
    pub tag: String,
    pub port: u16,
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    pub users: Vec<User>,
}

/// VLESS over XHTTP, wrapped in REALITY like [`Reality`] and sharing its keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xhttp {
    pub tag: String,
    pub port: u16,
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    /// The request path the server answers on; a client must use the same one.
    pub path: String,
    pub users: Vec<User>,
}

/// ZeroV1 wrapped in REALITY like [`Reality`], sharing its keys and its user
/// list: a user's ZeroV1 id is their VLESS UUID's sixteen bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zerov1 {
    pub tag: String,
    pub port: u16,
    pub sni: String,
    /// REALITY's public key (the private half stays in the server's config).
    pub public_key: String,
    pub short_id: String,
    /// ZeroV1's own public key, which every link carries.
    pub server_key: String,
    /// The path the server answers ZeroV1 requests on.
    pub path: String,
    pub users: Vec<User>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterDns {
    /// The tunnel domain, delegated to the server.
    pub domain: String,
    /// The name server host that domain points to (`ns.example.com`).
    pub ns_host: String,
    /// The program's encryption method id (5 = AES-256-GCM).
    pub method: u8,
    /// The shared key. A client secret: it goes into the client's config.
    pub key: String,
    /// The release of the upstream server that was installed.
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Service {
    Reality(Reality),
    Xhttp(Xhttp),
    Zerov1(Zerov1),
    MasterDns(MasterDns),
}

impl Service {
    /// The inbound tag the usage figures are reported under.
    pub fn tag(&self) -> &str {
        match self {
            Service::Reality(r) => &r.tag,
            Service::Xhttp(x) => &x.tag,
            Service::Zerov1(z) => &z.tag,
            Service::MasterDns(_) => "masterdns",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Service::Reality(_) => "VLESS + REALITY",
            Service::Xhttp(_) => "VLESS + XHTTP + REALITY",
            Service::Zerov1(_) => "ZeroV1 + REALITY",
            Service::MasterDns(_) => "MasterDnsVPN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRecord {
    pub version: u32,
    pub id: String,
    pub name: String,
    /// The address the person typed: an IP or a domain.
    pub host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub host_key: HostKey,
    /// The app's own key, once installed on the server. Secret.
    pub ssh_key: Option<String>,
    pub os: String,
    pub zray_version: String,
    /// Loopback port of the management API on the server.
    pub management_port: u16,
    /// Whether the downloaded program was checked against the signed list.
    pub verified_download: bool,
    pub services: Vec<Service>,
    pub created: u64,
    /// Which side of a pair this server is; `Single` for older records.
    #[serde(default)]
    pub role: Role,
    /// The pair's WireGuard tunnel UDP port, set on the exit side (and on the
    /// gateway side when it opened one). Used to clean up firewall rules.
    #[serde(default)]
    pub tunnel_port: Option<u16>,
}

/// A file a client program reads, ready to save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct File {
    pub name: String,
    pub text: String,
}

/// One config a person can hand to a client: a link an app imports, and for
/// MasterDNS also the files the upstream client program reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientConfig {
    pub service: &'static str,
    /// Who it is for (`Main`, `Ali`, ...).
    pub user: String,
    pub link: Option<String>,
    pub files: Vec<File>,
}

/// Where a pair install stopped, for crash recovery: the app offers
/// "Continue" (re-run) or "Remove" (rollback) for a pair left `Installing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairState {
    Installing,
    Ready,
    Failed,
}

/// The inter-server tunnel. Public keys only: the private halves live in each
/// server's tunnel config and never in this record, never in logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRecord {
    /// The tunnel mechanism; always `"wireguard"` in this version.
    #[serde(rename = "type")]
    pub kind: String,
    /// The UDP port on the exit server the gateway dials.
    pub port: u16,
    /// What the gateway dials: `host:port` of the exit server.
    pub exit_endpoint: String,
    pub gateway_public_key: String,
    pub exit_public_key: String,
    /// Reserved for a future pre-shared key; `None` until key rotation lands.
    #[serde(default)]
    pub psk: Option<String>,
    pub mtu: u16,
    /// The gateway's `PersistentKeepalive`, in seconds.
    pub keepalive_secs: u16,
    /// Unix seconds of the last verified handshake; 0 when never verified.
    pub established: u64,
    /// Tunnel B (VLESS+REALITY over TCP 443): the second transport family to
    /// the same exit server. `None` on records written before Tunnel B
    /// existed; re-link fills it in.
    #[serde(default)]
    pub b: Option<RealityTunnelRecord>,
    /// Tunnel C (WireGuard over an IPv6 underlay) to the same exit server:
    /// the third transport, always-on hot standby. `None` when IPv6 was not
    /// really usable at provisioning (see `PairRecord.ipv6_status`) — never
    /// faked.
    #[serde(default)]
    pub c: Option<TunnelCRecord>,
    /// Which tunnel the gateway's catch-all routing rule points at.
    #[serde(default)]
    pub active: TransportId,
}

/// Tunnel C's record: its own WireGuard keypair (public halves only — the
/// private halves live in each server's `tunnel-c.conf`, never here), the
/// exit's `[ipv6]:port` endpoint, and the gateway's IPv6 egress address the
/// exit's firewall rule was opened for (needed for teardown).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelCRecord {
    /// The UDP port on the exit server the gateway dials (IPv6).
    pub port: u16,
    /// What the gateway dials: `[ipv6]:port` of the exit server.
    pub exit_endpoint: String,
    pub gateway_public_key: String,
    pub exit_public_key: String,
    /// The gateway's public IPv6 the exit's firewall rule trusts.
    pub gateway_ipv6: String,
    pub mtu: u16,
    /// The gateway's `PersistentKeepalive`, in seconds (same as Tunnel A).
    pub keepalive_secs: u16,
    /// Unix seconds of the last verified handshake; 0 when never verified.
    pub established: u64,
}

/// The outcome of the real end-to-end IPv6 verification on both servers.
/// `Untested` for records written before Tunnel C existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Status {
    #[default]
    Untested,
    Verified,
    Unavailable,
}

/// Tunnel B's record: the exit's REALITY public key (only), the short id
/// the gateway presents, and the tunnel's VLESS UUID (a credential, stored
/// like the client user UUIDs). The REALITY private key lives only in the
/// exit's tunnel-rt config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityTunnelRecord {
    pub exit_public_key: String,
    pub short_id: String,
    pub user_id: String,
    /// What the gateway dials: the exit's host (Tunnel B is always 443).
    pub exit_host: String,
}

/// One of the two always-on inter-server transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportId {
    /// Tunnel A: WireGuard over UDP (primary at install).
    #[default]
    A,
    /// Tunnel B: VLESS+REALITY over TCP 443.
    B,
}

impl TransportId {
    /// The gateway outbound tag carrying this transport's traffic.
    pub fn outbound_tag(self) -> &'static str {
        match self {
            TransportId::A => crate::layout::WG_TUNNEL_TAG,
            TransportId::B => crate::layout::REALITY_TUNNEL_TAG,
        }
    }
}

/// The Huawei modem L2TP server on the gateway (Design G). Account
/// credentials are never stored here: usernames are read live from the
/// server's chap-secrets by `modem_status`, passwords live only in
/// chap-secrets and the admin credential store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModemRecord {
    pub pool_cidr: String,
    pub server_ip: String,
    pub dns_primary: String,
    pub dns_secondary: String,
    /// The LNS hostname the panel tells the user to paste into the modem's
    /// Hostname field.
    pub hostname: String,
    /// The gateway address the modem dials (LNS address for the panel).
    pub lns_address: String,
    /// The Zray TUN device the modem pool will be policy-routed into once
    /// the routing agent confirms the inbound contract (Design G Q2).
    pub tun_device: String,
    /// True until the TUN handoff contract lands; while true the pool guard
    /// drops forwarded modem traffic (fail-closed).
    pub handoff_pending: bool,
}

/// A provisioned server pair: an Iran-side gateway and a USA-side exit joined
/// by a WireGuard tunnel. This is the version-2 record; a version-1
/// [`ServerRecord`] still parses on its own (its `role` reads as `Single`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRecord {
    pub version: u32,
    pub id: String,
    pub name: String,
    pub created: u64,
    pub state: PairState,
    pub gateway: ServerRecord,
    pub exit: ServerRecord,
    pub tunnel: TunnelRecord,
    /// The modem L2TP server on the gateway; `None` when the pair was
    /// installed without it (opt-in per install).
    #[serde(default)]
    pub modem: Option<ModemRecord>,
    /// The real end-to-end IPv6 verdict on both servers. `Untested` on
    /// records written before Tunnel C existed; `Unavailable` means Tunnel
    /// C was honestly not provisioned (A+B work normally).
    #[serde(default)]
    pub ipv6_status: Ipv6Status,
}

impl std::fmt::Debug for PairRecord {
    // The servers' login keys never print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairRecord")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("name", &self.name)
            .field("created", &self.created)
            .field("state", &self.state)
            .field("gateway_host", &self.gateway.host)
            .field("exit_host", &self.exit.host)
            .field("tunnel", &self.tunnel)
            .finish_non_exhaustive()
    }
}

impl PairRecord {
    /// Every client config of the pair. Clients always talk to the gateway;
    /// the tunnel and the exit are invisible to client apps.
    pub fn client_configs(&self) -> Vec<ClientConfig> {
        self.gateway.client_configs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(id: &str, role: Role, host: &str) -> ServerRecord {
        ServerRecord {
            version: VERSION,
            id: id.into(),
            name: format!("{id} server"),
            host: host.into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            host_key: HostKey {
                fingerprint: "SHA256:x".into(),
                algorithm: "ssh-ed25519".into(),
            },
            ssh_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
            os: "Debian 12".into(),
            zray_version: "v0.4.1".into(),
            management_port: 41203,
            verified_download: true,
            services: Vec::new(),
            created: 1798765432,
            role,
            tunnel_port: None,
        }
    }

    fn pair() -> PairRecord {
        PairRecord {
            version: VERSION,
            id: "9f2c1a".into(),
            name: "My pair".into(),
            created: 1798765432,
            state: PairState::Ready,
            gateway: server("9f2c1a-gw", Role::Gateway, "203.0.113.7"),
            exit: server("9f2c1a-ex", Role::Exit, "198.51.100.23"),
            tunnel: TunnelRecord {
                kind: "wireguard".into(),
                port: 51823,
                exit_endpoint: "198.51.100.23:51823".into(),
                gateway_public_key: "gw-pub".into(),
                exit_public_key: "ex-pub".into(),
                psk: None,
                mtu: 1380,
                keepalive_secs: 25,
                established: 1798765500,
                b: Some(RealityTunnelRecord {
                    exit_public_key: "rt-pub".into(),
                    short_id: "0123456789abcdef".into(),
                    user_id: "00000000-0000-0000-0000-000000000000".into(),
                    exit_host: "198.51.100.23".into(),
                }),
                c: Some(TunnelCRecord {
                    port: 51827,
                    exit_endpoint: "[2001:db8::23]:51827".into(),
                    gateway_public_key: "gw-c-pub".into(),
                    exit_public_key: "ex-c-pub".into(),
                    gateway_ipv6: "2001:db8::7".into(),
                    mtu: 1360,
                    keepalive_secs: 25,
                    established: 1798765600,
                }),
                active: TransportId::A,
            },
            modem: Some(ModemRecord {
                pool_cidr: "10.88.0.0/24".into(),
                server_ip: "10.88.0.1".into(),
                dns_primary: "10.88.0.1".into(),
                dns_secondary: "10.88.0.1".into(),
                hostname: "lns-abcdef12".into(),
                lns_address: "203.0.113.7".into(),
                tun_device: "zray-tun".into(),
                handoff_pending: true,
            }),
            ipv6_status: Ipv6Status::Verified,
        }
    }

    /// The frozen version-2 schema round-trips byte for byte.
    #[test]
    fn a_pair_record_round_trips() {
        let record = pair();
        let text = serde_json::to_string(&record).unwrap();
        let back: PairRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(back, record);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["tunnel"]["type"], "wireguard");
        assert_eq!(value["tunnel"]["mtu"], 1380);
        assert_eq!(value["tunnel"]["keepalive_secs"], 25);
        assert_eq!(value["tunnel"]["active"], "a");
        assert_eq!(value["tunnel"]["b"]["exit_host"], "198.51.100.23");
        assert_eq!(
            value["tunnel"]["c"]["exit_endpoint"],
            "[2001:db8::23]:51827"
        );
        assert_eq!(value["tunnel"]["c"]["mtu"], 1360);
        assert_eq!(value["ipv6_status"], "verified");
        assert_eq!(value["gateway"]["role"], "gateway");
        assert_eq!(value["exit"]["role"], "exit");
        assert_eq!(value["modem"]["pool_cidr"], "10.88.0.0/24");
        assert!(value["modem"]["handoff_pending"].as_bool().unwrap());
    }

    /// A version-2 record written before Tunnels B/C and the modem role
    /// existed still parses: the new fields default (no Tunnel B/C, no
    /// modem, Tunnel A active, IPv6 untested).
    #[test]
    fn a_pair_without_tunnel_b_or_modem_still_parses() {
        let mut value = serde_json::to_value(pair()).unwrap();
        value["tunnel"].as_object_mut().unwrap().remove("b");
        value["tunnel"].as_object_mut().unwrap().remove("c");
        value["tunnel"].as_object_mut().unwrap().remove("active");
        value.as_object_mut().unwrap().remove("modem");
        value.as_object_mut().unwrap().remove("ipv6_status");
        let back: PairRecord = serde_json::from_value(value).unwrap();
        assert_eq!(back.tunnel.b, None);
        assert_eq!(back.tunnel.c, None);
        assert_eq!(back.tunnel.active, TransportId::A);
        assert_eq!(back.modem, None);
        assert_eq!(back.ipv6_status, Ipv6Status::Untested);
    }

    /// A version-1 server record still parses: its role reads as `single` and
    /// it carries no tunnel port.
    #[test]
    fn a_version_1_server_record_still_parses() {
        let text = r#"{"version":1,"id":"a","name":"n","host":"203.0.113.7","ssh_port":22,
            "ssh_user":"root","host_key":{"fingerprint":"SHA256:x","algorithm":"a"},
            "ssh_key":null,"os":"x","zray_version":"1","management_port":1,
            "verified_download":true,"services":[],"created":0}"#;
        let record: ServerRecord = serde_json::from_str(text).unwrap();
        assert_eq!(record.role, Role::Single);
        assert_eq!(record.tunnel_port, None);
    }

    /// Unknown fields are ignored, so a newer writer does not break this reader.
    #[test]
    fn unknown_fields_are_ignored() {
        let mut value = serde_json::to_value(pair()).unwrap();
        value["future_field"] = serde_json::json!("whatever");
        value["gateway"]["also_new"] = serde_json::json!(1);
        let back: PairRecord = serde_json::from_value(value).unwrap();
        assert_eq!(back, pair());
    }

    /// Client configs come from the gateway only: their links name the
    /// gateway's host, never the exit's.
    #[test]
    fn client_configs_point_at_the_gateway() {
        let mut record = pair();
        record.gateway.services = vec![Service::Reality(Reality {
            tag: "reality-in".into(),
            port: 443,
            sni: "www.microsoft.com".into(),
            public_key: "JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA".into(),
            short_id: "0123456789abcdef".into(),
            users: vec![User {
                name: "Main".into(),
                id: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            }],
        })];
        let configs = record.client_configs();
        assert_eq!(configs.len(), 1);
        let link = configs[0].link.as_ref().unwrap();
        assert!(link.contains("@203.0.113.7:443"), "{link}");
        assert!(!link.contains("198.51.100.23"), "{link}");
    }

    /// The private keys never appear in the pair's debug text.
    #[test]
    fn the_login_keys_never_print() {
        let text = format!("{:?}", pair());
        assert!(!text.contains("BEGIN OPENSSH"));
        assert!(text.contains("203.0.113.7"));
    }

    /// The wire format matches the frozen contract's field names.
    #[test]
    fn the_tunnel_block_matches_the_contract() {
        let value = serde_json::to_value(pair()).unwrap();
        let tunnel = &value["tunnel"];
        for field in [
            "type",
            "port",
            "exit_endpoint",
            "gateway_public_key",
            "exit_public_key",
            "psk",
            "mtu",
            "keepalive_secs",
            "established",
        ] {
            assert!(tunnel.get(field).is_some(), "missing {field}");
        }
        assert!(value["gateway"].get("role").is_some());
        assert!(value.get("state").is_some());
    }
}

impl ServerRecord {
    /// Every client config of every service, ready to show, copy or scan.
    pub fn client_configs(&self) -> Vec<ClientConfig> {
        let mut out = Vec::new();
        for service in &self.services {
            match service {
                Service::Reality(r) => {
                    for user in &r.users {
                        out.push(ClientConfig {
                            service: "reality",
                            user: user.name.clone(),
                            link: Some(links::vless_reality(
                                &self.host,
                                r.port,
                                &user.id,
                                &r.sni,
                                &r.public_key,
                                &r.short_id,
                                &format!("{} · {}", self.name, user.name),
                            )),
                            files: Vec::new(),
                        });
                    }
                }
                Service::Xhttp(x) => {
                    for user in &x.users {
                        out.push(ClientConfig {
                            service: "xhttp",
                            user: user.name.clone(),
                            link: Some(links::vless_xhttp_reality(
                                &self.host,
                                x.port,
                                &user.id,
                                &x.sni,
                                &x.public_key,
                                &x.short_id,
                                &x.path,
                                &format!("{} · XHTTP · {}", self.name, user.name),
                            )),
                            files: Vec::new(),
                        });
                    }
                }
                Service::Zerov1(z) => {
                    for user in &z.users {
                        out.push(ClientConfig {
                            service: "zerov1",
                            user: user.name.clone(),
                            link: Some(links::zerov1_reality(
                                &self.host,
                                z.port,
                                &user.id,
                                &z.server_key,
                                &z.path,
                                &z.sni,
                                &z.public_key,
                                &z.short_id,
                                &format!("{} · ZeroV1 · {}", self.name, user.name),
                            )),
                            files: Vec::new(),
                        });
                    }
                }
                Service::MasterDns(m) => out.push(ClientConfig {
                    service: "masterdns",
                    user: "Main".to_string(),
                    link: Some(links::masterdns(
                        &self.host,
                        m,
                        &format!("{} · MasterDNS", self.name),
                    )),
                    files: links::masterdns_client_files(m),
                }),
            }
        }
        out
    }
}
