//! Where everything lives on the server, and the files the installer writes.
//!
//! One place for the paths, so the installer, the status check and the
//! uninstaller cannot disagree about what is theirs. Everything the installer
//! creates is under these names; nothing else on the server is touched.

use serde_json::{json, Value};

/// GitHub project the server program is downloaded from.
pub const REPO: &str = "mhrsdev/Vpn";

pub const ZRAY_DIR: &str = "/opt/zray";
pub const ZRAY_BIN: &str = "/opt/zray/zray";
pub const ZRAY_ETC: &str = "/etc/zray";
pub const ZRAY_CONFIG: &str = "/etc/zray/server.json";
pub const ZRAY_TOKEN: &str = "/etc/zray/management.token";
pub const ZRAY_UNIT: &str = "/etc/systemd/system/zray.service";
pub const ZRAY_SERVICE: &str = "zray";
/// The unprivileged account the server runs as.
pub const ZRAY_USER: &str = "zray";
/// The tunnel's key material: each server's own WireGuard private key and its
/// public half. Written by key generation on the server itself, mode 640
/// `root:zray`; the private key never crosses the SSH channel.
pub const ZRAY_TUNNEL_CONF: &str = "/etc/zray/tunnel.conf";
/// Scratch space for downloads, removed when the install ends.
pub const WORK_DIR: &str = "/tmp/zray-setup";

pub const MASTERDNS_DIR: &str = "/opt/masterdns";
pub const MASTERDNS_BIN: &str = "/opt/masterdns/masterdns-server";
pub const MASTERDNS_ETC: &str = "/etc/masterdns";
pub const MASTERDNS_CONFIG: &str = "/etc/masterdns/server_config.toml";
pub const MASTERDNS_KEY: &str = "/etc/masterdns/encrypt_key.txt";
pub const MASTERDNS_UNIT: &str = "/etc/systemd/system/masterdns.service";
pub const MASTERDNS_SERVICE: &str = "masterdns";
pub const MASTERDNS_USER: &str = "masterdns";

/// The MasterDnsVPN server release the installer deploys: a pinned tag and the
/// SHA-256 of each archive, so what is installed is exactly what was reviewed.
/// (Upstream's release hashes, re-checked by downloading the archives.) Moving
/// to a newer release is a deliberate change to these three lines.
pub const MASTERDNS_REPO: &str = "masterking32/MasterDnsVPN";
pub const MASTERDNS_TAG: &str = "v2026.06.13.234407-7de2476";
pub const MASTERDNS_SHA256_AMD64: &str =
    "597bdc510b896a3b4ac89865ee7cefa73191025c64093f5e0f85c76a70430de9";
pub const MASTERDNS_SHA256_ARM64: &str =
    "4f3d0e8afac0381e5a47e3064e07d0bac27c56b5f1a4fd8df8013f157168cbbf";

/// The archive name and hash for a CPU (`x64` or `ARM64`, as in `Facts`).
pub fn masterdns_asset(arch: &str) -> Option<(&'static str, &'static str)> {
    match arch {
        "x64" => Some((
            "MasterDnsVPN_Server_Linux_AMD64.tar.gz",
            MASTERDNS_SHA256_AMD64,
        )),
        "ARM64" => Some((
            "MasterDnsVPN_Server_Linux_ARM64.tar.gz",
            MASTERDNS_SHA256_ARM64,
        )),
        _ => None,
    }
}

/// The systemd unit for the MasterDNS server. It binds port 53 as its own user
/// with only that one privilege, like the Zray unit.
pub fn masterdns_unit() -> String {
    format!(
        "[Unit]\n\
         Description=MasterDnsVPN server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         User={MASTERDNS_USER}\n\
         Group={MASTERDNS_USER}\n\
         ExecStart={MASTERDNS_BIN} -config {MASTERDNS_CONFIG} -nowait\n\
         Restart=always\n\
         RestartSec=2\n\
         LimitNOFILE=1048576\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// What the MasterDNS server needs to know.
pub struct MasterDnsServer<'a> {
    /// The tunnel domain, delegated to this server.
    pub domain: &'a str,
    /// The address to bind: the machine's own address, or `0.0.0.0`.
    pub bind: &'a str,
    /// AES-256-GCM, the one authenticated method (see `zero-masterdns`).
    pub method: u8,
}

/// The server's `server_config.toml`. Only what differs from the program's own
/// defaults is written, so a later release's new defaults apply untouched. It
/// answers as a SOCKS5 proxy; the program itself refuses private targets.
pub fn masterdns_config(server: &MasterDnsServer) -> String {
    format!(
        "DOMAIN = [\"{}\"]\n\
         PROTOCOL_TYPE = \"SOCKS5\"\n\
         UDP_HOST = \"{}\"\n\
         UDP_PORT = 53\n\
         DATA_ENCRYPTION_METHOD = {}\n\
         ENCRYPTION_KEY_FILE = \"{MASTERDNS_KEY}\"\n\
         LOG_LEVEL = \"INFO\"\n",
        server.domain, server.bind, server.method
    )
}

/// The key length the server insists on for a method (it silently replaces any
/// other key with one of its own). AES-256-GCM, method 5, takes 32 characters.
pub const MASTERDNS_KEY_LEN: usize = 32;

/// The comment on the app's SSH key for server `id`. Unique per server and per
/// install, so removing one server's access never touches another's.
pub fn key_comment(id: &str) -> String {
    format!("zray-{id}")
}

/// The comment on the app's SSH key for one side of a pair. Unique per pair
/// and per side, so removing the gateway's access never touches the exit's.
pub fn pair_key_comment(pair_id: &str, role: crate::record::Role) -> String {
    let side = match role {
        crate::record::Role::Gateway => "gw",
        crate::record::Role::Exit => "ex",
        crate::record::Role::Single => "single",
    };
    format!("zray-{pair_id}-{side}")
}

/// The systemd unit for the Zray server.
///
/// It runs as its own user with only the right to bind low ports, a read-only
/// view of the system and no way to gain privileges, so a flaw in the server
/// does not hand over the machine. `management_port` is the loopback port of
/// the management API the usage figures come from.
pub fn zray_unit(management_port: u16) -> String {
    format!(
        "[Unit]\n\
         Description=Zray server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         User={ZRAY_USER}\n\
         Group={ZRAY_USER}\n\
         ExecStart={ZRAY_BIN} run {ZRAY_CONFIG} --management 127.0.0.1:{management_port} \
         --management-token-file {ZRAY_TOKEN}\n\
         Restart=always\n\
         RestartSec=2\n\
         LimitNOFILE=1048576\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         StateDirectory=zray\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Inbound tags the usage figures are reported under.
pub const VISION_TAG: &str = "reality-in";
pub const XHTTP_TAG: &str = "xhttp-in";
pub const ZEROV1_TAG: &str = "zerov1-in";

/// The ZeroV1 inbound: its port, the path it answers on and its secret key.
/// Its users are the REALITY users, by the sixteen bytes of their UUIDs.
pub struct Zerov1Inbound<'a> {
    pub port: u16,
    pub path: &'a str,
    pub secret_key: &'a str,
}

/// The resolver block both server configs share: the machine's own resolver
/// (the hosting provider's DNS is the one always reachable from its own
/// network), never a built-in public default.
fn dns_block(ipv6: bool) -> Value {
    json!({
        "servers": ["localhost"],
        "leakPolicy": "fallback",
        "queryStrategy": if ipv6 { "UseIP" } else { "UseIPv4" },
    })
}

/// The client-facing inbounds of a REALITY setup: VLESS + Vision, XHTTP and
/// ZeroV1, sharing one key pair, short id and user list. Shared by the
/// single-server config and the pair gateway config.
fn reality_inbounds(reality: &RealityInbound) -> Vec<Value> {
    let clients = |flow: &str| -> Vec<Value> {
        reality
            .users
            .iter()
            .map(|(name, id)| json!({"id": id, "flow": flow, "email": name}))
            .collect()
    };
    let security = json!({
        "security": "reality",
        "realitySettings": {
            "show": false,
            "dest": format!("{}:443", reality.sni),
            "xver": 0,
            "serverNames": [reality.sni],
            "privateKey": reality.private_key,
            "shortIds": [reality.short_id],
        },
    });
    // Both inbounds share the REALITY settings; only the carrier differs. XHTTP
    // carries its own framing, so it takes no Vision flow.
    let inbound = |tag: &str, port: u16, flow: &str, network: Value| {
        let mut stream = security.clone();
        for (key, value) in network.as_object().expect("an object") {
            stream[key] = value.clone();
        }
        json!({
            "tag": tag,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": clients(flow), "decryption": "none"},
            "streamSettings": stream,
        })
    };
    let mut inbounds = Vec::new();
    if let Some(port) = reality.vision_port {
        inbounds.push(inbound(
            VISION_TAG,
            port,
            "xtls-rprx-vision",
            json!({"network": "tcp"}),
        ));
    }
    if let Some((port, path)) = reality.xhttp {
        inbounds.push(inbound(
            XHTTP_TAG,
            port,
            "",
            json!({"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"}}),
        ));
    }
    if let Some(zerov1) = &reality.zerov1 {
        let users: Vec<Value> = reality
            .users
            .iter()
            .filter_map(|(name, id)| {
                crate::links::zerov1_user_id(id).map(|id| json!({"id": id, "name": name}))
            })
            .collect();
        let mut stream = security.clone();
        stream["network"] = json!("tcp");
        inbounds.push(json!({
            "tag": ZEROV1_TAG,
            "listen": "0.0.0.0",
            "port": zerov1.port,
            "protocol": "zerov1",
            "settings": {"path": zerov1.path, "secretKey": zerov1.secret_key, "users": users},
            "streamSettings": stream,
        }));
    }
    inbounds
}

/// What the REALITY inbounds need. One key pair, short id and user list are
/// shared by both inbounds, so a person can hold either config.
pub struct RealityInbound<'a> {
    /// The real site the server relays to anyone who is not a client.
    pub sni: &'a str,
    pub private_key: &'a str,
    pub short_id: &'a str,
    /// `(name, uuid)` pairs.
    pub users: &'a [(String, String)],
    /// Port of the VLESS + Vision inbound on TCP, when it is installed.
    pub vision_port: Option<u16>,
    /// Port and request path of the XHTTP inbound, when it is installed.
    pub xhttp: Option<(u16, &'a str)>,
    /// The ZeroV1 inbound, when it is installed.
    pub zerov1: Option<Zerov1Inbound<'a>>,
}

/// The server's whole configuration. Clients may reach any public address and
/// nothing private: the rule at the top sends traffic aimed at the server's own
/// network (loopback, LAN, link-local, cloud metadata) to a black hole, so a
/// client cannot use the server to reach services that trust it.
///
/// `ipv6` says whether the machine can actually reach the IPv6 internet; when
/// it cannot, names are resolved to IPv4 only, because a destination whose
/// IPv6 address is tried first on a machine without IPv6 stalls until the
/// dial times out.
pub fn zray_config(reality: &RealityInbound, ipv6: bool) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        // The machine's own resolver: the hosting provider's DNS is the one
        // that is always reachable from its own network, which a built-in
        // default (a public DNS-over-HTTPS service) is not everywhere.
        "dns": dns_block(ipv6),
        "inbounds": reality_inbounds(reality),
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
        ]},
    })
}

/// Tag of the WireGuard outbound on the gateway that carries client sessions
/// to the exit server.
pub const WG_TUNNEL_TAG: &str = "wg-tunnel";
/// Tag of the gateway's Iran-egress outbound: `freedom` for destinations
/// classified as Iranian. Iranian-classified traffic exiting via Iran is by
/// design (smart split routing); it is not a leak. Foreign and unknown
/// destinations always take the tunnel — there is no unclassified direct
/// egress on the gateway.
pub const IRAN_DIRECT_TAG: &str = "iran-direct";
/// Tag of the WireGuard inbound on the exit server that the gateway dials.
pub const TUNNEL_IN_TAG: &str = "tunnel-in";
/// Tag of the gateway's Tunnel C outbound: WireGuard over an IPv6 underlay
/// to the same exit server. Always-on hot standby; no routing rule points
/// at it until the routing agent clears it for active use.
pub const TUNNEL_C_TAG: &str = "tunnel-c";
/// Tag of the WireGuard-over-IPv6 inbound on the exit server that
/// terminates Tunnel C. Never client-facing: its only client is the gateway.
pub const TUNNEL_C_IN_TAG: &str = "tunnel-c-in";
/// Where the Tunnel C WireGuard private keys live (600, root:root),
/// mirroring [`ZRAY_TUNNEL_CONF`] for Tunnel A. One keypair per tunnel:
/// keys are never shared between tunnels.
pub const ZRAY_TUNNEL_C_CONF: &str = "/etc/zray/tunnel-c.conf";
/// Placeholder the on-server tunnel step replaces with the Tunnel C private
/// key from [`ZRAY_TUNNEL_C_CONF`].
pub const TUNNEL_C_KEY_PLACEHOLDER: &str = "@TUNNEL_C_PRIVATE_KEY@";
/// Tunnel C MTU: Tunnel A's 1380 minus 20 for the larger IPv6 underlay
/// header (40 vs 20). Conservative for Iran↔USA paths.
pub const TUNNEL_C_MTU: u16 = 1360;
/// Tunnel C interface addresses: its own /24, apart from Tunnel A's
/// 10.8.0.0/24, so the two WireGuard interfaces never share an address.
pub const GATEWAY_TUNNEL_C_IP: &str = "10.8.1.1";
pub const EXIT_TUNNEL_C_IP: &str = "10.8.1.2";
/// Tag of the VLESS+REALITY outbound on the gateway: Tunnel B, the second
/// transport family (TCP 443 with TLS camouflage) to the same exit server.
pub const REALITY_TUNNEL_TAG: &str = "reality-tunnel";
/// Tag of the VLESS+REALITY inbound on the exit server that terminates
/// Tunnel B. Never client-facing: its only client is the gateway.
pub const TUNNEL_RT_IN_TAG: &str = "tunnel-rt-in";
/// Tunnel B's port on the exit: TCP 443, the camouflage port.
pub const TUNNEL_RT_PORT: u16 = 443;
/// The real site Tunnel B's REALITY relays to anyone who is not the gateway.
pub const TUNNEL_RT_SNI: &str = "www.microsoft.com";
/// Where the exit's Tunnel B REALITY private key lives (640, root:zray),
/// mirroring [`ZRAY_TUNNEL_CONF`] for Tunnel A.
pub const ZRAY_TUNNEL_RT_CONF: &str = "/etc/zray/tunnel-rt.conf";
/// The tunnel interface MTU: conservative for the paths between Iran and the
/// USA (PPPoE and mobile links).
pub const TUNNEL_MTU: u16 = 1380;
/// `PersistentKeepalive` on the gateway side, so the NAT mapping on the
/// Iranian side stays open. The exit learns the gateway's endpoint from the
/// authenticated handshake and sets none.
pub const TUNNEL_KEEPALIVE_SECS: u16 = 25;
/// Tunnel IPs: the gateway takes `.1`, the exit `.2`.
pub const GATEWAY_TUNNEL_IP: &str = "10.8.0.1";
pub const EXIT_TUNNEL_IP: &str = "10.8.0.2";

/// What the gateway's `wg-tunnel` outbound needs. `private_key` is the
/// gateway's own WireGuard private key, or [`TUNNEL_KEY_PLACEHOLDER`] when the
/// object is a merge fragment for the on-server step (the key never crosses
/// the SSH channel).
pub struct GatewayTunnel<'a> {
    /// What the gateway dials: the exit's `host:port`.
    pub exit_endpoint: &'a str,
    pub exit_public_key: &'a str,
    pub private_key: &'a str,
    /// The gateway's address inside the tunnel, `10.8.0.1`.
    pub address: &'a str,
    pub keepalive: u16,
}

/// What the exit's `tunnel-in` inbound needs. `private_key` is the exit's own
/// WireGuard private key, or [`TUNNEL_KEY_PLACEHOLDER`] for a merge fragment.
pub struct ExitTunnel<'a> {
    pub port: u16,
    pub gateway_public_key: &'a str,
    pub private_key: &'a str,
    pub mtu: u16,
}

/// Placeholder the on-server tunnel step replaces with the private key from
/// [`ZRAY_TUNNEL_CONF`].
pub const TUNNEL_KEY_PLACEHOLDER: &str = "@TUNNEL_PRIVATE_KEY@";
/// Placeholder the on-server tunnel step replaces with the REALITY private
/// key from [`ZRAY_TUNNEL_RT_CONF`].
pub const TUNNEL_RT_KEY_PLACEHOLDER: &str = "@REALITY_PRIVATE_KEY@";

/// What the gateway's `reality-tunnel` outbound (Tunnel B) needs.
/// `exit_public_key` is the exit's REALITY public key (URL-safe base64,
/// no pad, as `zray x25519` prints it); `short_id` is the gateway's
/// client short id on the exit's inbound; `user_id` is the tunnel's VLESS
/// UUID, the credential the exit authenticates.
pub struct RealityTunnel<'a> {
    /// What the gateway dials: the exit's host (no port; always 443).
    pub exit_host: &'a str,
    pub exit_public_key: &'a str,
    pub short_id: &'a str,
    pub user_id: &'a str,
}

/// What the exit's `tunnel-rt-in` inbound (Tunnel B) needs. `private_key` is
/// the exit's own REALITY private key, or [`TUNNEL_RT_KEY_PLACEHOLDER`] for
/// a merge fragment.
pub struct RtInbound<'a> {
    pub private_key: &'a str,
    pub short_id: &'a str,
    pub user_id: &'a str,
}

fn reality_tunnel_outbound(tunnel: &RealityTunnel) -> Value {
    json!({
        "tag": REALITY_TUNNEL_TAG,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": tunnel.exit_host,
                "port": TUNNEL_RT_PORT,
                "users": [{"id": tunnel.user_id, "flow": "xtls-rprx-vision", "encryption": "none"}],
            }],
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "fingerprint": "chrome",
                "serverName": TUNNEL_RT_SNI,
                "publicKey": tunnel.exit_public_key,
                "shortId": tunnel.short_id,
                "spiderX": "/",
            },
        },
    })
}

fn tunnel_rt_in_inbound(tunnel: &RtInbound) -> Value {
    json!({
        "tag": TUNNEL_RT_IN_TAG,
        "listen": "0.0.0.0",
        "port": TUNNEL_RT_PORT,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": tunnel.user_id, "flow": "xtls-rprx-vision", "email": "tunnel-b"}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": format!("{}:443", TUNNEL_RT_SNI),
                "xver": 0,
                "serverNames": [TUNNEL_RT_SNI],
                "privateKey": tunnel.private_key,
                "shortIds": [tunnel.short_id],
            },
        },
    })
}

fn wg_tunnel_outbound(tunnel: &GatewayTunnel) -> Value {
    wg_tunnel_outbound_with_tag(tunnel, WG_TUNNEL_TAG)
}

/// A WireGuard outbound under an arbitrary tag: Tunnel A uses
/// [`WG_TUNNEL_TAG`], Tunnel C [`TUNNEL_C_TAG`]. The endpoint may be a
/// `host:port` pair (IPv4) or a bracketed `[ipv6]:port` pair.
fn wg_tunnel_outbound_with_tag(tunnel: &GatewayTunnel, tag: &str) -> Value {
    json!({
        "tag": tag,
        "protocol": "wireguard",
        "settings": {
            "secretKey": tunnel.private_key,
            "endpoint": tunnel.exit_endpoint,
            "address": tunnel.address,
            "keepAlive": tunnel.keepalive,
            "peers": [{"publicKey": tunnel.exit_public_key,
                       "allowedIPs": ["0.0.0.0/0", "::/0"]}],
        },
    })
}

fn tunnel_in_inbound(tunnel: &ExitTunnel) -> Value {
    tunnel_in_inbound_with_tag(tunnel, TUNNEL_IN_TAG, "0.0.0.0")
}

/// A WireGuard inbound under an arbitrary tag and listen address: Tunnel A
/// listens on `0.0.0.0`, Tunnel C on `::` (its underlay is IPv6).
fn tunnel_in_inbound_with_tag(tunnel: &ExitTunnel, tag: &str, listen: &str) -> Value {
    json!({
        "tag": tag,
        "listen": listen,
        "port": tunnel.port,
        "protocol": "wireguard",
        "settings": {
            "secretKey": tunnel.private_key,
            "mtu": tunnel.mtu,
            "peers": [{"publicKey": tunnel.gateway_public_key,
                       "allowedIPs": ["0.0.0.0/0", "::/0"]}],
        },
    })
}

/// The gateway's whole configuration: the client-facing inbounds behind a
/// smart split router, plus the two always-on inter-server tunnels to the
/// same exit server — Tunnel A (`wg-tunnel`, WireGuard/UDP, primary) and
/// Tunnel B (`reality-tunnel`, VLESS+REALITY/TCP-443, the second transport
/// family). Both outbounds are always configured; the split router's
/// catch-all points at the active one (Tunnel A at install; `tunnel_switch`
/// flips it). Destinations classified as Iranian exit via the `iran-direct`
/// freedom outbound — by design, not a leak. Everything else — foreign and
/// unknown — takes the active tunnel (unknown defaults to the tunnel).
/// Private addresses are blackholed first. There is no other
/// `freedom`/`direct` outbound: when the tunnels are down, foreign dials
/// fail and traffic blackholes (fail-closed). Unclassified traffic can never
/// reach the Iran egress.
pub fn gateway_config(
    reality: &RealityInbound,
    tunnel: &GatewayTunnel,
    rt: &RealityTunnel,
    ipv6: bool,
) -> Value {
    let inbounds = reality_inbounds(reality);
    let tags: Vec<Value> = inbounds.iter().map(|i| i["tag"].clone()).collect();
    // Classification atoms are the routing agent's vocabulary, shared from
    // zero-config::presets so the gateway and the client presets classify
    // "Iranian" identically. geoip:private is deliberately excluded here: on
    // the gateway it stays blackholed (first rule), it must not exit direct.
    let iran_domains: Vec<Value> = zero_config::presets::IRAN_DIRECT_DOMAINS
        .iter()
        .map(|d| Value::String((*d).to_owned()))
        .collect();
    json!({
        "log": {"loglevel": "warning"},
        "dns": dns_block(ipv6),
        "inbounds": inbounds,
        "outbounds": [
            wg_tunnel_outbound(tunnel),
            reality_tunnel_outbound(rt),
            {"tag": IRAN_DIRECT_TAG, "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "domain": iran_domains, "outboundTag": IRAN_DIRECT_TAG},
            {"type": "field", "ip": ["geoip:ir"], "outboundTag": IRAN_DIRECT_TAG},
            {"type": "field", "inboundTag": tags, "outboundTag": WG_TUNNEL_TAG},
        ]},
    })
}

/// The exit's whole configuration: the two tunnel inbounds the gateway dials
/// (Tunnel A WireGuard `tunnel-in`, Tunnel B VLESS+REALITY `tunnel-rt-in`),
/// and a `freedom` egress for what comes out of the tunnels. By policy the
/// exit exposes no client-facing inbound: the only way in is the tunnels.
pub fn exit_config(tunnel: &ExitTunnel, rt: &RtInbound, ipv6: bool) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "dns": dns_block(ipv6),
        "inbounds": [tunnel_in_inbound(tunnel), tunnel_rt_in_inbound(rt)],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "inboundTag": [TUNNEL_IN_TAG, TUNNEL_RT_IN_TAG], "outboundTag": "direct"},
        ]},
    })
}

/// The merge fragment the tunnel step hands to the on-server merge: the
/// finished `wg-tunnel` outbound. The server replaces the outbound with the
/// same tag in its config.
pub fn tunnel_gateway_fragment(tunnel: &GatewayTunnel) -> Value {
    json!({"kind": "outbound", "object": wg_tunnel_outbound(tunnel)})
}

/// The merge fragment for the exit side: the finished `tunnel-in` inbound.
pub fn tunnel_exit_fragment(tunnel: &ExitTunnel) -> Value {
    json!({"kind": "inbound", "object": tunnel_in_inbound(tunnel)})
}

/// The merge fragment the tunnel step hands to the on-server merge: the
/// finished `reality-tunnel` outbound (Tunnel B). The server replaces the
/// outbound with the same tag in its config.
pub fn tunnel_rt_gateway_fragment(tunnel: &RealityTunnel) -> Value {
    json!({"kind": "outbound", "object": reality_tunnel_outbound(tunnel)})
}

/// The merge fragment for the exit side: the finished `tunnel-rt-in`
/// inbound (Tunnel B).
pub fn tunnel_rt_exit_fragment(tunnel: &RtInbound) -> Value {
    json!({"kind": "inbound", "object": tunnel_rt_in_inbound(tunnel)})
}

/// The merge fragment for the gateway side: the finished `tunnel-c`
/// outbound (Tunnel C, WireGuard over IPv6). Appended when absent; no
/// routing rule references it — it is hot standby until the routing agent
/// clears it for active use.
pub fn tunnel_c_gateway_fragment(tunnel: &GatewayTunnel) -> Value {
    json!({"kind": "outbound", "object": wg_tunnel_outbound_with_tag(tunnel, TUNNEL_C_TAG)})
}

/// The merge fragment for the exit side: the finished `tunnel-c-in`
/// inbound (Tunnel C). `route_to` tells the on-server merge to add the
/// inbound's tag to the exit's tunnel→direct routing rule, so what comes
/// out of Tunnel C egresses like the other tunnels.
pub fn tunnel_c_exit_fragment(tunnel: &ExitTunnel) -> Value {
    json!({"kind": "inbound", "object": tunnel_in_inbound_with_tag(tunnel, TUNNEL_C_IN_TAG, "::"), "route_to": "direct"})
}

/// A routing-switch fragment: `{"kind": "routetag", "tag": <outbound tag>}`
/// retargets the gateway's client-inbounds catch-all rule at the named
/// tunnel outbound. The on-server merge finds the rule with `inboundTag`
/// and no domain/ip selectors and rewrites its `outboundTag`.
pub fn tunnel_switch_fragment(tag: &str) -> Value {
    json!({"kind": "routetag", "tag": tag})
}

// ---------------------------------------------------------------------------
// Huawei modem L2TP server (Iran gateway role, Design G).
//
// The H158-381's stock firmware is an L2TP *client* only: the gateway runs
// the LNS with Ubuntu's maintained xl2tpd+ppp packages. No L2TP/PPP wire
// code lives in this tree; these are config templates plus the account
// file helpers. Security posture: the server mandates 128-bit MPPE and
// refuses PAP, so a client that will not negotiate MPPE-128 fails closed
// rather than falling back to plaintext (Design G section d: WEAK+).
// ---------------------------------------------------------------------------

/// The modem pool: the /24 pppd hands out. The provisioner's choice,
/// documented in the pair record.
pub const MODEM_POOL_CIDR: &str = "10.88.0.0/24";
/// The gateway's own address on the modem pool (pppd `localip`).
pub const MODEM_POOL_SERVER_IP: &str = "10.88.0.1";
/// The modem pool range pppd offers (pppd `remoteip`).
pub const MODEM_POOL_RANGE: &str = "10.88.0.2-10.88.0.254";
/// L2TP listens here; the modem's form takes no port (Design G section b).
pub const MODEM_L2TP_PORT: u16 = 1701;
/// xl2tpd's config and the pppd options file it points at.
pub const XL2TPD_CONF: &str = "/etc/xl2tpd/xl2tpd.conf";
pub const PPP_OPTIONS_MODEM: &str = "/etc/ppp/options.xl2tpd.zray";
/// PPP account database. One line per modem account; mode 600, root-owned.
pub const PPP_CHAP_SECRETS: &str = "/etc/ppp/chap-secrets";
/// The chap-secrets "server" field for accounts this provisioner manages.
/// Teardown removes exactly these lines, leaving foreign entries alone.
pub const MODEM_CHAP_SERVER: &str = "zray-modem";

/// What the modem L2TP server needs. DNS is pushed via PPP (`ms-dns`)
/// because the modem's L2TP form has no DNS fields (Design G section c).
/// There is deliberately no tunnel password: xl2tpd's LNS side does not
/// verify L2TP tunnel authentication, so claiming to set one would be
/// theater — the panel guide tells the user to enter any value, exactly as
/// Huawei's own documentation does. The real authentication is PPP
/// MS-CHAPv2 with mandatory MPPE-128.
pub struct ModemServer<'a> {
    /// Public IP xl2tpd binds (`listen-addr`).
    pub listen_ip: &'a str,
    /// LNS hostname: the value the panel tells the user to paste into the
    /// modem's Hostname field (not verified server-side, Design G section c).
    pub hostname: &'a str,
    /// In-tunnel DNS pushed to the modem.
    pub dns_primary: &'a str,
    pub dns_secondary: &'a str,
}

/// `xl2tpd.conf`: listen on the gateway's public IP, one LNS, no IPsec
/// (plain L2TP — the modem offers no IPsec; Design G section b).
pub fn xl2tpd_config(m: &ModemServer) -> String {
    format!(
        "[global]\n\
         listen-addr = {listen_ip}\n\
         port = {port}\n\
         \n\
         [lns default]\n\
         ip range = {range}\n\
         local ip = {server_ip}\n\
         require chap = yes\n\
         refuse pap = yes\n\
         require authentication = yes\n\
         name = {hostname}\n\
         pppoptfile = {pppopt}\n\
         tunnel rws = 8\n\
         flow bit = yes\n\
         exclusive = no\n\
         hidden bit = no\n\
         length bit = yes\n\
         sequence bit = no\n\
         ipsec saref = no\n",
        listen_ip = m.listen_ip,
        port = MODEM_L2TP_PORT,
        range = MODEM_POOL_RANGE,
        server_ip = MODEM_POOL_SERVER_IP,
        hostname = m.hostname,
        pppopt = PPP_OPTIONS_MODEM,
    )
}

/// The pppd options file xl2tpd uses for modem sessions. The security
/// posture is fail-closed: `require-mppe-128` refuses any client that will
/// not negotiate 128-bit MPPE, `refuse-pap` keeps reusable credentials off
/// the wire, and `nodefaultroute` keeps the server's own routing untouched.
/// MS-CHAPv2 is the only auth allowed (MPPE keys derive from it); the
/// server's PPP name is [`MODEM_CHAP_SERVER`], so chap-secrets lookups and
/// teardown match exactly our lines. IP assignment comes from xl2tpd's own
/// `ip range`/`local ip`, not from here.
///
/// DNS uses the repeatable `ms-dns` option (first = primary, second =
/// secondary): modern pppd (2.4.9+/2.5.x, as Ubuntu ships) no longer
/// accepts the old `ms-dns1`/`ms-dns2` spellings — verified against the
/// real pppd binary, which rejects them as unrecognized options.
pub fn modem_ppp_options(m: &ModemServer) -> String {
    format!(
        "# pppd options for Huawei modem L2TP sessions (managed by zray).\n\
         name {server}\n\
         auth\n\
         refuse-pap\n\
         refuse-chap\n\
         refuse-mschap\n\
         require-mschap-v2\n\
         require-mppe-128\n\
         ms-dns {dns1}\n\
         ms-dns {dns2}\n\
         netmask 255.255.255.0\n\
         nobsdcomp\n\
         novj\n\
         nodefaultroute\n\
         lock\n",
        server = MODEM_CHAP_SERVER,
        dns1 = m.dns_primary,
        dns2 = m.dns_secondary,
    )
}

/// One PPP account: `user server password allowed-ip`, whitespace-separated.
/// Passwords are generated alphanumeric (see `keys::new_modem_password`),
/// so they never contain whitespace or `#`.
pub struct ChapEntry {
    pub user: String,
    pub server: String,
    pub password: String,
    pub allowed_ip: String,
}

impl ChapEntry {
    pub fn new(user: &str, password: &str) -> Self {
        ChapEntry {
            user: user.to_string(),
            server: MODEM_CHAP_SERVER.to_string(),
            password: password.to_string(),
            allowed_ip: "*".to_string(),
        }
    }

    fn render(&self) -> String {
        format!(
            "{} {} {} {}",
            self.user, self.server, self.password, self.allowed_ip
        )
    }
}

/// Split chap-secrets into our managed entries and the verbatim lines we
/// must not touch (comments, blanks, foreign accounts). A managed line has
/// exactly four whitespace-separated fields with the server field equal to
/// [`MODEM_CHAP_SERVER`].
pub fn parse_chap_secrets(text: &str) -> (Vec<ChapEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut other = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            other.push(line.to_string());
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() == 4 && fields[1] == MODEM_CHAP_SERVER {
            entries.push(ChapEntry {
                user: fields[0].to_string(),
                server: fields[1].to_string(),
                password: fields[2].to_string(),
                allowed_ip: fields[3].to_string(),
            });
        } else {
            other.push(line.to_string());
        }
    }
    (entries, other)
}

/// Render chap-secrets: our entries first, then the untouched lines.
/// Round-trips through [`parse_chap_secrets`] (foreign lines keep their
/// exact bytes, including comments).
pub fn render_chap_secrets(entries: &[ChapEntry], other: &[String]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&entry.render());
        out.push('\n');
    }
    for line in other {
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(users: &[(String, String)]) -> RealityInbound<'_> {
        RealityInbound {
            sni: "www.microsoft.com",
            private_key: "uJLQY8ZQJjlg2Bld0RFcuTJsGZSnBeZyGP2yR4xCxFM",
            short_id: "0123456789abcdef",
            users,
            vision_port: Some(443),
            xhttp: None,
            zerov1: None,
        }
    }

    /// The server config must be one the engine itself accepts, or the service
    /// would fail to start on a stranger's machine.
    #[test]
    fn the_server_config_compiles_in_the_engine() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let config = zray_config(&inbound(&users), false);
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts the generated server config");
        assert_eq!(generation.config.inbounds.len(), 1);
        assert_eq!(&*generation.config.inbounds[0].tag, VISION_TAG);
    }

    /// XHTTP rides the same REALITY keys on its own port, takes no Vision
    /// flow, and the engine accepts the result.
    #[test]
    fn the_xhttp_inbound_shares_the_reality_keys_and_compiles() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let mut both = inbound(&users);
        both.xhttp = Some((8443, "/a1b2c3d4"));
        let config = zray_config(&both, false);
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        let (vision, xhttp) = (&inbounds[0], &inbounds[1]);
        assert_eq!(vision["tag"], VISION_TAG);
        assert_eq!(vision["settings"]["clients"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(xhttp["tag"], XHTTP_TAG);
        assert_eq!(xhttp["port"], 8443);
        assert_eq!(xhttp["settings"]["clients"][0]["flow"], "");
        assert_eq!(xhttp["streamSettings"]["network"], "xhttp");
        assert_eq!(
            xhttp["streamSettings"]["xhttpSettings"]["path"],
            "/a1b2c3d4"
        );
        assert_eq!(
            xhttp["streamSettings"]["realitySettings"],
            vision["streamSettings"]["realitySettings"]
        );
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts both inbounds");
        assert_eq!(generation.config.inbounds.len(), 2);

        let mut only = inbound(&users);
        only.vision_port = None;
        only.xhttp = Some((443, "/p"));
        let config = zray_config(&only, false);
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("XHTTP alone is accepted");
    }

    /// VLESS, XHTTP and ZeroV1 on one server: three inbounds, one REALITY
    /// setup and one user list, each user's ZeroV1 id being their UUID's bytes.
    #[test]
    fn zerov1_sits_beside_vless_and_xhttp_on_the_same_keys_and_users() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let (secret, _) = zero_protocol::tide::generate_keypair();
        let secret = zero_protocol::tide::encode_key(&secret);
        let mut all = inbound(&users);
        all.xhttp = Some((8443, "/a1b2c3d4"));
        all.zerov1 = Some(Zerov1Inbound {
            port: 2083,
            path: "/static/9f8e7d",
            secret_key: &secret,
        });
        let config = zray_config(&all, false);
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        let zerov1 = &inbounds[2];
        assert_eq!(zerov1["tag"], ZEROV1_TAG);
        assert_eq!(zerov1["protocol"], "zerov1");
        assert_eq!(zerov1["port"], 2083);
        assert_eq!(
            zerov1["streamSettings"]["realitySettings"],
            inbounds[0]["streamSettings"]["realitySettings"],
            "one REALITY setup for all of them"
        );
        let id = crate::links::zerov1_user_id(&users[0].1).unwrap();
        assert_eq!(zerov1["settings"]["users"][0]["id"], id);
        assert_eq!(zerov1["settings"]["users"][0]["name"], "Main");
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts all three inbounds");
        assert_eq!(generation.config.inbounds.len(), 3);

        let mut only = inbound(&users);
        only.vision_port = None;
        only.zerov1 = Some(Zerov1Inbound {
            port: 443,
            path: "/static/9f8e7d",
            secret_key: &secret,
        });
        let config = zray_config(&only, false);
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("ZeroV1 alone is accepted");
    }

    #[test]
    fn a_machine_without_ipv6_resolves_to_ipv4_only() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        assert_eq!(
            zray_config(&inbound(&users), false)["dns"]["queryStrategy"],
            "UseIPv4"
        );
        assert_eq!(
            zray_config(&inbound(&users), true)["dns"]["queryStrategy"],
            "UseIP"
        );
    }

    #[test]
    fn private_networks_are_blocked_before_anything_else() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let config = zray_config(&inbound(&users), false);
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["ip"][0], "geoip:private");
        assert_eq!(rules[0]["outboundTag"], "block");
    }

    #[test]
    fn the_masterdns_config_is_what_the_server_expects() {
        let text = masterdns_config(&MasterDnsServer {
            domain: "t.example.com",
            bind: "203.0.113.7",
            method: 5,
        });
        assert!(text.contains("DOMAIN = [\"t.example.com\"]"));
        assert!(text.contains("UDP_HOST = \"203.0.113.7\""));
        assert!(text.contains("UDP_PORT = 53"));
        assert!(text.contains("DATA_ENCRYPTION_METHOD = 5"));
        assert!(text.contains("ENCRYPTION_KEY_FILE = \"/etc/masterdns/encrypt_key.txt\""));
    }

    #[test]
    fn the_pinned_masterdns_archives_are_known_for_both_cpus() {
        assert_eq!(masterdns_asset("x64").unwrap().1.len(), 64);
        assert_eq!(masterdns_asset("ARM64").unwrap().1.len(), 64);
        assert!(masterdns_asset("riscv").is_none());
        assert!(masterdns_unit().contains("-config /etc/masterdns/server_config.toml"));
    }

    #[test]
    fn the_unit_binds_low_ports_and_nothing_more() {
        let unit = zray_unit(20123);
        assert!(unit.contains("--management 127.0.0.1:20123"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(!unit.contains("User=root"));
    }

    fn gateway_test_config() -> Value {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        gateway_config(
            &inbound(&users),
            &GatewayTunnel {
                exit_endpoint: "198.51.100.23:51823",
                exit_public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                address: GATEWAY_TUNNEL_IP,
                keepalive: TUNNEL_KEEPALIVE_SECS,
            },
            &RealityTunnel {
                exit_host: "198.51.100.23",
                exit_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                short_id: "0000000000000000",
                user_id: "00000000-0000-0000-0000-000000000000",
            },
            false,
        )
    }

    fn rt_inbound() -> RtInbound<'static> {
        RtInbound {
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            short_id: "0000000000000000",
            user_id: "00000000-0000-0000-0000-000000000000",
        }
    }

    /// The gateway runs a smart split router: Iranian-classified destinations
    /// exit via Iran (the `iran-direct` freedom outbound — by design, not a
    /// leak); foreign and unknown traffic takes the WireGuard tunnel. The
    /// fail-closed contract is now: no UNCLASSIFIED traffic may reach a
    /// direct egress, and there is exactly one freedom outbound, the Iranian
    /// one. If a future protocol adds an inbound, it must land in the
    /// catch-all tunnel rule or the engine's compile — and this test — will
    /// catch the gap.
    #[test]
    fn the_gateway_config_splits_iranian_traffic_and_tunnels_the_rest() {
        use zero_config::presets::IRAN_DIRECT_DOMAINS;
        let config = gateway_test_config();
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts the gateway config");
        // Exactly one freedom outbound on the gateway, and it is the Iranian
        // egress. No unclassified direct egress exists.
        let freedoms: Vec<&str> = generation
            .config
            .outbounds
            .iter()
            .filter(|o| matches!(o.protocol, zero_config::OutboundProtocol::Freedom { .. }))
            .map(|o| &*o.tag)
            .collect();
        assert_eq!(
            freedoms,
            [IRAN_DIRECT_TAG],
            "the only freedom outbound is the Iranian egress, got {freedoms:?}"
        );
        let tags: Vec<&str> = generation
            .config
            .outbounds
            .iter()
            .map(|o| &*o.tag)
            .collect();
        assert!(tags.contains(&WG_TUNNEL_TAG));
        assert!(tags.contains(&"block"));
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(
            rules[0]["outboundTag"], "block",
            "private nets still blackholed first"
        );
        assert_eq!(
            rules[0]["ip"].as_array().unwrap().len(),
            1,
            "the block rule stays a narrow private-nets rule"
        );
        // Every rule that sends to iran-direct must carry ONLY Iranian
        // classification selectors: its domains must be the known Iranian
        // domain list and its IPs geoip:ir. No wildcard, no port-only rule,
        // no empty selector may point at the Iran egress.
        for rule in rules {
            if rule["outboundTag"] != IRAN_DIRECT_TAG {
                continue;
            }
            let has_domain = rule
                .get("domain")
                .and_then(|d| d.as_array())
                .is_some_and(|d| !d.is_empty());
            let has_ip = rule
                .get("ip")
                .and_then(|d| d.as_array())
                .is_some_and(|d| !d.is_empty());
            assert!(
                has_domain || has_ip,
                "iran-direct rule has no classification selector: {rule}"
            );
            if let Some(domains) = rule.get("domain").and_then(|d| d.as_array()) {
                for d in domains {
                    let d = d.as_str().unwrap();
                    assert!(
                        IRAN_DIRECT_DOMAINS.contains(&d),
                        "non-Iranian domain {d} routed to the Iran egress"
                    );
                }
            }
            if let Some(ips) = rule.get("ip").and_then(|d| d.as_array()) {
                for ip in ips {
                    assert_eq!(
                        ip.as_str().unwrap(),
                        "geoip:ir",
                        "non-Iranian IP selector routed to the Iran egress: {ip}"
                    );
                }
            }
        }
        // The catch-all: a rule with no domain/ip selector that covers every
        // client inbound must point at the tunnel. Unknown defaults to the
        // tunnel — never to the Iran egress.
        let inbounds: Vec<&str> = config["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["tag"].as_str().unwrap())
            .collect();
        let mut catch_all = 0;
        for rule in rules {
            let unclassified = rule.get("domain").is_none() && rule.get("ip").is_none();
            if !unclassified || rule["outboundTag"] == "block" {
                continue;
            }
            catch_all += 1;
            assert_eq!(
                rule["outboundTag"], WG_TUNNEL_TAG,
                "unclassified traffic must take the tunnel, got {rule}"
            );
            let routed: Vec<&str> = rule["inboundTag"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap())
                .collect();
            assert_eq!(
                routed.len(),
                inbounds.len(),
                "every client inbound ({inbounds:?}) must be covered by the tunnel catch-all"
            );
            for tag in &inbounds {
                assert!(routed.contains(tag), "{tag} is not routed to the tunnel");
            }
        }
        assert_eq!(catch_all, 1, "exactly one unclassified catch-all rule");
        let settings = &config["outbounds"][0]["settings"];
        assert_eq!(settings["keepAlive"], TUNNEL_KEEPALIVE_SECS);
        assert_eq!(settings["address"], GATEWAY_TUNNEL_IP);
    }

    /// A tunnel switch retargets the gateway catch-all at the named tunnel
    /// outbound. The fragment carries the target tag and nothing else; the
    /// on-server merge rewrites the catch-all's `outboundTag` in place and
    /// refuses to touch rules with classification selectors.
    #[test]
    fn the_tunnel_switch_fragment_carries_only_the_target_tag() {
        for tag in [WG_TUNNEL_TAG, REALITY_TUNNEL_TAG] {
            let fragment = tunnel_switch_fragment(tag);
            assert_eq!(fragment["kind"], "routetag");
            assert_eq!(fragment["tag"], tag);
            assert_eq!(
                fragment.as_object().unwrap().len(),
                2,
                "the fragment must carry no selectors of its own"
            );
        }
        // The target must be a tunnel outbound the gateway config defines.
        let config = gateway_test_config();
        let tags: Vec<&str> = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect();
        assert!(tags.contains(&REALITY_TUNNEL_TAG));
        assert!(tags.contains(&WG_TUNNEL_TAG));
    }

    /// Tunnel C's fragments: the gateway's `tunnel-c` outbound (WireGuard
    /// over a bracketed IPv6 endpoint, its own /24) and the exit's
    /// `tunnel-c-in` inbound (listening on `::`), both accepted by the
    /// engine. The exit fragment carries `route_to: direct` so the merge
    /// egresses Tunnel C like the other tunnels.
    #[test]
    fn the_tunnel_c_fragments_compile_and_carry_the_egress_hint() {
        // The fragment as the installer builds it carries the placeholder;
        // the on-server merge substitutes the real key before `zray check`.
        let gw = tunnel_c_gateway_fragment(&GatewayTunnel {
            exit_endpoint: "[2001:db8::23]:51827",
            exit_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            private_key: TUNNEL_C_KEY_PLACEHOLDER,
            address: GATEWAY_TUNNEL_C_IP,
            keepalive: TUNNEL_KEEPALIVE_SECS,
        });
        assert_eq!(gw["kind"], "outbound");
        let obj = &gw["object"];
        assert_eq!(obj["tag"], TUNNEL_C_TAG);
        assert_eq!(obj["protocol"], "wireguard");
        assert_eq!(obj["settings"]["endpoint"], "[2001:db8::23]:51827");
        assert_eq!(obj["settings"]["address"], GATEWAY_TUNNEL_C_IP);
        assert_eq!(obj["settings"]["secretKey"], TUNNEL_C_KEY_PLACEHOLDER);
        assert_ne!(
            GATEWAY_TUNNEL_C_IP, GATEWAY_TUNNEL_IP,
            "Tunnel C must not share Tunnel A's interface address"
        );
        assert_eq!(obj["settings"]["keepAlive"], TUNNEL_KEEPALIVE_SECS);

        let ex = tunnel_c_exit_fragment(&ExitTunnel {
            port: 51827,
            gateway_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            private_key: TUNNEL_C_KEY_PLACEHOLDER,
            mtu: TUNNEL_C_MTU,
        });
        assert_eq!(ex["kind"], "inbound");
        assert_eq!(ex["route_to"], "direct");
        let obj = &ex["object"];
        assert_eq!(obj["tag"], TUNNEL_C_IN_TAG);
        assert_eq!(obj["listen"], "::");
        assert_eq!(obj["settings"]["mtu"], TUNNEL_C_MTU);

        // Both objects are engine-accepted inside a real config: build them
        // with a dummy key (as the on-server merge would) and compile.
        let mut gw_obj = gw["object"].clone();
        gw_obj["settings"]["secretKey"] =
            serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let mut config = gateway_test_config();
        config["outbounds"].as_array_mut().unwrap().push(gw_obj);
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts the gateway config with Tunnel C");
        let tags: Vec<&str> = generation
            .config
            .outbounds
            .iter()
            .map(|o| &*o.tag)
            .collect();
        assert!(tags.contains(&TUNNEL_C_TAG));
        // Hot standby: no routing rule may point at Tunnel C.
        let rules = config["routing"]["rules"].as_array().unwrap();
        for rule in rules {
            assert_ne!(
                rule["outboundTag"], TUNNEL_C_TAG,
                "no routing rule may reference the standby tunnel: {rule}"
            );
        }
    }

    /// The exit exposes no client-facing inbound: the only way in is the
    /// tunnels, and what comes out of them goes to freedom.
    #[test]
    fn the_exit_config_has_no_client_inbounds() {
        let config = exit_config(
            &ExitTunnel {
                port: 51823,
                gateway_public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                mtu: TUNNEL_MTU,
            },
            &rt_inbound(),
            false,
        );
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts the exit config");
        let inbounds: Vec<&str> = generation.config.inbounds.iter().map(|i| &*i.tag).collect();
        assert_eq!(
            inbounds,
            [TUNNEL_IN_TAG, TUNNEL_RT_IN_TAG],
            "the exit's only inbounds are the two tunnels, got {inbounds:?}"
        );
        let rules = config["routing"]["rules"].as_array().unwrap();
        let tunnel_rule = rules
            .iter()
            .find(|r| r["inboundTag"][0] == TUNNEL_IN_TAG)
            .expect("the tunnels feed the egress");
        assert_eq!(tunnel_rule["outboundTag"], "direct");
        // Both tunnel inbounds route to the egress, nothing else does.
        let routed: Vec<&str> = tunnel_rule["inboundTag"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        assert!(routed.contains(&TUNNEL_RT_IN_TAG));
        assert_eq!(config["inbounds"][0]["settings"]["mtu"], TUNNEL_MTU);
        // Tunnel B's REALITY terminates TLS camouflage on 443, for the
        // gateway only.
        assert_eq!(config["inbounds"][1]["port"], TUNNEL_RT_PORT);
        assert_eq!(config["inbounds"][1]["protocol"], "vless");
    }

    /// The tunnel fragments carry the finished objects under the tags the
    /// on-server merge replaces, with the key placeholder intact.
    #[test]
    fn the_tunnel_fragments_carry_tagged_objects() {
        let fragment = tunnel_gateway_fragment(&GatewayTunnel {
            exit_endpoint: "198.51.100.23:51823",
            exit_public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            private_key: TUNNEL_KEY_PLACEHOLDER,
            address: GATEWAY_TUNNEL_IP,
            keepalive: TUNNEL_KEEPALIVE_SECS,
        });
        assert_eq!(fragment["kind"], "outbound");
        assert_eq!(fragment["object"]["tag"], WG_TUNNEL_TAG);
        assert_eq!(
            fragment["object"]["settings"]["secretKey"],
            TUNNEL_KEY_PLACEHOLDER
        );
        let fragment = tunnel_exit_fragment(&ExitTunnel {
            port: 51823,
            gateway_public_key: "pub",
            private_key: TUNNEL_KEY_PLACEHOLDER,
            mtu: TUNNEL_MTU,
        });
        assert_eq!(fragment["kind"], "inbound");
        assert_eq!(fragment["object"]["tag"], TUNNEL_IN_TAG);
        assert_eq!(fragment["object"]["port"], 51823);
        assert_eq!(
            fragment["object"]["settings"]["secretKey"],
            TUNNEL_KEY_PLACEHOLDER
        );
    }

    #[test]
    fn pair_key_comments_name_the_pair_and_the_side() {
        assert_eq!(
            pair_key_comment("9f2c1a", crate::record::Role::Gateway),
            "zray-9f2c1a-gw"
        );
        assert_eq!(
            pair_key_comment("9f2c1a", crate::record::Role::Exit),
            "zray-9f2c1a-ex"
        );
    }

    /// Tunnel B's fragments carry the tagged REALITY objects with the key
    /// placeholder intact, and the gateway's Tunnel B outbound compiles in
    /// the engine.
    #[test]
    fn the_tunnel_b_fragments_carry_tagged_reality_objects() {
        let rt = RealityTunnel {
            exit_host: "198.51.100.23",
            exit_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            short_id: "0123456789abcdef",
            user_id: "00000000-0000-0000-0000-000000000000",
        };
        let fragment = tunnel_rt_gateway_fragment(&rt);
        assert_eq!(fragment["kind"], "outbound");
        assert_eq!(fragment["object"]["tag"], REALITY_TUNNEL_TAG);
        assert_eq!(fragment["object"]["protocol"], "vless");
        assert_eq!(
            fragment["object"]["settings"]["vnext"][0]["port"],
            TUNNEL_RT_PORT
        );
        let stream = &fragment["object"]["streamSettings"];
        assert_eq!(stream["security"], "reality");
        assert_eq!(
            stream["realitySettings"]["publicKey"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        let fragment = tunnel_rt_exit_fragment(&RtInbound {
            private_key: TUNNEL_RT_KEY_PLACEHOLDER,
            short_id: "0123456789abcdef",
            user_id: "00000000-0000-0000-0000-000000000000",
        });
        assert_eq!(fragment["kind"], "inbound");
        assert_eq!(fragment["object"]["tag"], TUNNEL_RT_IN_TAG);
        assert_eq!(fragment["object"]["port"], TUNNEL_RT_PORT);
        assert_eq!(
            fragment["object"]["streamSettings"]["realitySettings"]["privateKey"],
            TUNNEL_RT_KEY_PLACEHOLDER
        );
        // The gateway config with both tunnels is one the engine accepts.
        let config = gateway_test_config();
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts the dual-tunnel gateway config");
        let tags: Vec<&str> = generation
            .config
            .outbounds
            .iter()
            .map(|o| &*o.tag)
            .collect();
        assert!(tags.contains(&WG_TUNNEL_TAG));
        assert!(tags.contains(&REALITY_TUNNEL_TAG));
    }

    /// The routing-switch fragment names the tunnel outbound the catch-all
    /// rule must point at.
    #[test]
    fn the_tunnel_switch_fragment_names_a_tunnel_outbound() {
        let fragment = tunnel_switch_fragment(REALITY_TUNNEL_TAG);
        assert_eq!(fragment["kind"], "routetag");
        assert_eq!(fragment["tag"], REALITY_TUNNEL_TAG);
    }

    fn modem_server() -> ModemServer<'static> {
        ModemServer {
            listen_ip: "198.51.100.7",
            hostname: "lns-abcdef12",
            dns_primary: "10.88.0.1",
            dns_secondary: "10.88.0.1",
        }
    }

    /// xl2tpd listens on UDP 1701 on the gateway's public IP, with no IPsec:
    /// plain L2TP is all the modem's stock firmware offers.
    #[test]
    fn the_xl2tpd_config_listens_on_1701_without_ipsec() {
        let conf = xl2tpd_config(&modem_server());
        assert!(conf.contains("listen-addr = 198.51.100.7"), "{conf}");
        assert!(conf.contains("port = 1701"), "{conf}");
        assert!(conf.contains("[lns default]"), "{conf}");
        assert!(conf.contains("ipsec saref = no"), "{conf}");
        assert!(
            conf.contains(&format!("pppoptfile = {PPP_OPTIONS_MODEM}")),
            "{conf}"
        );
        assert!(
            conf.contains(&format!("local ip = {MODEM_POOL_SERVER_IP}")),
            "{conf}"
        );
    }

    /// The pppd options mandate 128-bit MPPE: a client that will not
    /// negotiate it cannot connect, full stop.
    #[test]
    fn the_modem_ppp_options_require_mppe_128() {
        let opts = modem_ppp_options(&modem_server());
        assert!(
            opts.lines().any(|l| l.trim() == "require-mppe-128"),
            "require-mppe-128 missing:\n{opts}"
        );
    }

    /// Negative: nothing in the options may let a session fall back to
    /// plaintext. PAP (reusable cleartext credentials) is refused, only
    /// MS-CHAPv2 is accepted (MPPE keys derive from it), and no `nomppe`
    /// variant may appear.
    #[test]
    fn the_modem_ppp_options_refuse_plaintext_fallback() {
        let opts = modem_ppp_options(&modem_server());
        let lines: Vec<&str> = opts.lines().map(str::trim).collect();
        for banned in ["nomppe", "nomppe-40", "nomppe-56", "+pap", "require-pap"] {
            assert!(
                !lines.contains(&banned),
                "{banned} would allow plaintext, in:\n{opts}"
            );
        }
        // A bare `require-mppe` (without -128) would accept 40/56-bit keys.
        for line in &lines {
            if line.starts_with("require-mppe") {
                assert_eq!(*line, "require-mppe-128", "weak MPPE allowed: {line}");
            }
        }
        assert!(
            lines.contains(&"refuse-pap"),
            "PAP must be refused:\n{opts}"
        );
        assert!(
            lines.contains(&"require-mschap-v2"),
            "only MS-CHAPv2 may authenticate:\n{opts}"
        );
        assert!(
            lines.contains(&"nodefaultroute"),
            "the server's own routing stays untouched:\n{opts}"
        );
    }

    /// The modem's L2TP form has no DNS fields, so PPP must push ours —
    /// with the repeatable `ms-dns` spelling modern pppd accepts.
    #[test]
    fn the_modem_ppp_options_push_the_configured_dns() {
        let opts = modem_ppp_options(&modem_server());
        assert!(opts.contains("ms-dns 10.88.0.1"), "{opts}");
        assert!(
            !opts.contains("ms-dns1"),
            "old spelling rejected by pppd:\n{opts}"
        );
    }

    /// The real pppd binary parses the generated options file: it must get
    /// past option parsing (no "unrecognized option"). This caught a real
    /// bug — `ms-dns1`/`ms-dns2` are rejected by the pppd Ubuntu ships.
    /// Skips where pppd is not installed.
    #[test]
    fn pppd_accepts_the_generated_options_file() {
        use std::process::Command;
        if Command::new("pppd").arg("--version").output().is_err() {
            eprintln!("pppd not installed: skipping pppd option-parse check");
            return;
        }
        let dir = std::env::temp_dir().join(format!("zray-pppd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("options.zray-test");
        std::fs::write(&path, modem_ppp_options(&modem_server())).unwrap();
        let out = Command::new("pppd")
            .arg("file")
            .arg(&path)
            .output()
            .expect("failed to run pppd");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("unrecognized option"),
            "pppd rejects our options file:\n{stderr}"
        );
        // Past option parsing, pppd must fail only for want of a device or
        // kernel PPP — never on the options themselves.
        assert!(
            stderr.contains("no device specified") || stderr.contains("/dev/ppp"),
            "unexpected pppd failure:\n{stderr}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// chap-secrets round-trips: our entries parse back, foreign lines
    /// (comments, other accounts) keep their exact bytes.
    #[test]
    fn the_chap_secrets_round_trip_preserves_foreign_lines() {
        let original = "# managed by something else\npeer1 * secret1 *\n";
        let (mut entries, other) = parse_chap_secrets(original);
        assert!(entries.is_empty());
        entries.push(ChapEntry::new(
            "h158-abcdef12",
            "s3cr3tpassword000000000001",
        ));
        let rendered = render_chap_secrets(&entries, &other);
        assert!(rendered.contains("h158-abcdef12 zray-modem s3cr3tpassword000000000001 *"));
        assert!(rendered.contains("# managed by something else"));
        assert!(rendered.contains("peer1 * secret1 *"));
        let (entries2, other2) = parse_chap_secrets(&rendered);
        assert_eq!(entries2.len(), 1);
        assert_eq!(entries2[0].user, "h158-abcdef12");
        assert_eq!(entries2[0].password, "s3cr3tpassword000000000001");
        assert_eq!(other2, other);
        // Revocation is removing the entry and re-rendering.
        let rendered = render_chap_secrets(&[], &other2);
        let (entries3, _) = parse_chap_secrets(&rendered);
        assert!(entries3.is_empty());
        assert!(rendered.contains("peer1 * secret1 *"));
    }

    /// Positive MPPE proof, live: two real pppd processes (authenticator +
    /// supplicant) negotiate PPP over a pty pair using the generated
    /// options file; the server log must show `MPPE 128-bit` actually
    /// enabled. This is the complement of the negative config test: it
    /// proves encryption is really negotiated, not merely required.
    ///
    /// Needs root (pppd touches /etc/ppp/chap-secrets, backed up and
    /// restored), pppd, python3 (pty driver), and a PPP-capable kernel
    /// (/dev/ppp). Ignored by default; run on a capable machine with
    /// `cargo test -p zero-provision -- --ignored pppd_mppe_128`.
    #[test]
    #[ignore = "needs root, pppd, python3 and a PPP-capable kernel (/dev/ppp)"]
    fn pppd_mppe_128_negotiates_on_a_real_session() {
        use std::io::{BufRead, BufReader};
        use std::process::{Child, Command, Stdio};

        assert_eq!(
            libc_getuid(),
            0,
            "this test must run as root (chap-secrets backup)"
        );
        assert!(
            std::path::Path::new("/dev/ppp").exists(),
            "this machine has no /dev/ppp: run on a PPP-capable kernel"
        );
        assert!(
            Command::new("pppd").arg("--version").output().is_ok(),
            "pppd is not installed"
        );
        assert!(
            Command::new("python3").arg("--version").output().is_ok(),
            "python3 is not installed (pty driver)"
        );

        let dir = std::env::temp_dir().join(format!("zray-pppd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Server options: our exact generated file, plus test addressing.
        let mut server_opts = modem_ppp_options(&modem_server());
        server_opts.push_str("10.99.0.1:10.99.0.2\n");
        std::fs::write(dir.join("options.server"), &server_opts).unwrap();
        // Client options: authenticate as the test account, demand MPPE-128.
        std::fs::write(
            dir.join("options.client"),
            "user h158-test0001\npassword testpassword000000000001\n\
             refuse-pap\nrefuse-chap\nrefuse-mschap\nrequire-mschap-v2\n\
             require-mppe-128\nnobsdcomp\nnovj\nnodefaultroute\nnoipdefault\n",
        )
        .unwrap();

        // chap-secrets is hardcoded in pppd: back it up, install the test
        // account, restore afterwards no matter what.
        let secrets_path = std::path::Path::new("/etc/ppp/chap-secrets");
        let backup = std::fs::read(secrets_path).ok();
        struct Restore {
            backup: Option<Vec<u8>>,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                let path = std::path::Path::new("/etc/ppp/chap-secrets");
                match &self.backup {
                    Some(bytes) => {
                        std::fs::write(path, bytes).ok();
                    }
                    None => {
                        std::fs::remove_file(path).ok();
                    }
                }
            }
        }
        let _restore = Restore { backup };
        let secrets = render_chap_secrets(
            &[ChapEntry::new("h158-test0001", "testpassword000000000001")],
            &[],
        );
        std::fs::write(secrets_path, &secrets).unwrap();
        std::os::unix::fs::PermissionsExt::set_mode(
            &mut std::fs::metadata(secrets_path).unwrap().permissions(),
            0o600,
        );

        // A pty pair stands in for the L2TP transport; python cross-connects
        // the masters and prints the slave device paths.
        let driver = "import os,pty,threading,time,sys\n\
            m1,s1=pty.openpty();m2,s2=pty.openpty()\n\
            print(os.ttyname(s1),flush=True);print(os.ttyname(s2),flush=True)\n\
            def f(a,b):\n\twhile True:\n\t d=os.read(a,2048)\n\t if not d:break\n\t os.write(b,d)\n\
            threading.Thread(target=f,args=(m1,m2),daemon=True).start()\n\
            threading.Thread(target=f,args=(m2,m1),daemon=True).start()\n\
            time.sleep(60)\n";
        let mut driver = Command::new("python3")
            .arg("-c")
            .arg(driver)
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to start pty driver");
        let stdout = driver.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let tty_server = lines.next().expect("no tty from driver").unwrap();
        let tty_client = lines.next().expect("no tty from driver").unwrap();

        let mut server: Child = Command::new("pppd")
            .arg(&tty_server)
            .arg("115200")
            .arg("file")
            .arg(dir.join("options.server"))
            .arg("nodetach")
            .arg("logfile")
            .arg(dir.join("server.log"))
            .spawn()
            .expect("failed to start server pppd");
        let mut client: Child = Command::new("pppd")
            .arg(&tty_client)
            .arg("115200")
            .arg("file")
            .arg(dir.join("options.client"))
            .arg("nodetach")
            .arg("logfile")
            .arg(dir.join("client.log"))
            .spawn()
            .expect("failed to start client pppd");

        std::thread::sleep(std::time::Duration::from_secs(12));
        let _ = server.kill();
        let _ = client.kill();
        let _ = driver.kill();
        // Reap the children so they do not linger as zombies.
        let _ = server.wait();
        let _ = client.wait();
        let _ = driver.wait();

        let log = std::fs::read_to_string(dir.join("server.log")).unwrap_or_default();
        assert!(
            log.contains("MPPE 128-bit"),
            "server never negotiated MPPE-128; server log:\n{log}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Minimal libc binding for the root check in the live pppd test.
    /// (Avoids a new dependency for one call in an ignored test.)
    fn libc_getuid() -> u32 {
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() }
    }
}
