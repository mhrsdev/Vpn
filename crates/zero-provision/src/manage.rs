//! Coming back to a server the app set up: read its usage, remove it.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::layout;
use crate::record::{ServerRecord, Service};
use crate::scripts;
use crate::ssh::{self, Auth, Connection, Login};

/// Log in with the app's own key. Fails when the record kept no key (the
/// person declined it), in which case the caller asks for the password again.
pub async fn connect(record: &ServerRecord) -> Result<Connection, ssh::Error> {
    let key = record.ssh_key.clone().ok_or(ssh::Error::AuthFailed)?;
    let login = Login {
        host: record.host.clone(),
        port: record.ssh_port,
        user: record.ssh_user.clone(),
        auth: Auth::Key(key),
    };
    ssh::connect(&login, &record.host_key.fingerprint).await
}

/// One inbound's live figures, exactly as the server reports them: counts and
/// byte totals, nothing that names a person (see `zero_runtime::usage`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundUsage {
    pub tag: String,
    pub sessions: u64,
    pub devices_now: u64,
    pub devices_recent: u64,
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub window_secs: u64,
    pub inbounds: Vec<InboundUsage>,
}

impl Usage {
    pub fn devices_now(&self) -> u64 {
        self.inbounds.iter().map(|i| i.devices_now).sum()
    }
}

/// Why the usage could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    Ssh(ssh::Error),
    /// The server program is up but too old to report usage.
    Unsupported,
    /// The server is not running.
    Down,
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsageError::Ssh(e) => e.fmt(f),
            UsageError::Unsupported => f.write_str(
                "This server's program is too old to report who is connected. Update it from the \
                 server's menu.",
            ),
            UsageError::Down => f.write_str(
                "The server program is not running. Open the server's menu and restart it.",
            ),
        }
    }
}

/// Ask the server how many people are connected.
///
/// The Zray server reports it itself (see `zero_runtime::usage`). The MasterDNS
/// server keeps no such figure, so it is worked out from the session lines in
/// its log: sessions created, less those closed or expired. That can lag by up
/// to five minutes (a client that vanishes is only noticed when its session
/// times out) and reports no byte counts.
pub async fn usage(conn: &Connection, record: &ServerRecord) -> Result<Usage, UsageError> {
    let mut usage = Usage {
        window_secs: crate::manage::WINDOW,
        inbounds: Vec::new(),
    };
    if record.services.iter().any(|s| {
        matches!(
            s,
            Service::Reality(_) | Service::Xhttp(_) | Service::Zerov1(_)
        )
    }) {
        let port = record.management_port.to_string();
        let env = [
            ("TOKEN_FILE", layout::ZRAY_TOKEN),
            ("MANAGEMENT_PORT", port.as_str()),
        ];
        let out = conn
            .script(&env, scripts::USAGE, Duration::from_secs(20))
            .await
            .map_err(UsageError::Ssh)?;
        if !out.ok() {
            // curl: 22 is an HTTP error (a 404 is an older program), the rest
            // mean nothing answered.
            return Err(match out.status {
                22 => UsageError::Unsupported,
                _ => UsageError::Down,
            });
        }
        let zray: Usage = serde_json::from_str(&out.stdout).map_err(|_| UsageError::Unsupported)?;
        usage.window_secs = zray.window_secs;
        usage.inbounds = zray.inbounds;
    }
    if record
        .services
        .iter()
        .any(|s| matches!(s, Service::MasterDns(_)))
    {
        let env = [("SERVICE", layout::MASTERDNS_SERVICE)];
        let out = conn
            .script(&env, scripts::MASTERDNS_LOG, Duration::from_secs(20))
            .await
            .map_err(UsageError::Ssh)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        usage.inbounds.push(masterdns_usage(&out.stdout, now));
    }
    Ok(usage)
}

/// Seconds of recent activity the usage figures speak about.
pub const WINDOW: u64 = 300;

/// The MasterDNS figure from its journal lines (`journalctl -o short-unix`).
fn masterdns_usage(log: &str, now: u64) -> InboundUsage {
    let (mut created, mut closed, mut expired, mut recent) = (0u64, 0u64, 0u64, 0u64);
    for line in log.lines() {
        let at: u64 = line
            .split_whitespace()
            .next()
            .and_then(|t| t.split('.').next())
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        if line.contains("Session Created") {
            created += 1;
            if at + WINDOW >= now {
                recent += 1;
            }
        } else if line.contains("Session Closed") {
            closed += 1;
        } else if let Some(rest) = line.split("Expired Sessions Cleaned, Count:").nth(1) {
            expired += rest
                .trim()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    let now_open = created.saturating_sub(closed + expired);
    InboundUsage {
        tag: "masterdns".into(),
        sessions: now_open,
        devices_now: now_open,
        devices_recent: now_open.max(recent),
        uplink: 0,
        downlink: 0,
    }
}

/// What [`remove`] reports as it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removed {
    Services,
    Files,
    Firewall,
    Access,
}

fn ports_of(record: &ServerRecord) -> (Vec<u16>, Vec<u16>) {
    let (mut tcp, mut udp) = (Vec::new(), Vec::new());
    for service in &record.services {
        match service {
            Service::Reality(r) => tcp.push(r.port),
            Service::Xhttp(x) => tcp.push(x.port),
            Service::Zerov1(z) => tcp.push(z.port),
            Service::MasterDns(_) => udp.push(53),
        }
    }
    // The pair's tunnel port (the exit side): its firewall rule is
    // source-restricted, so it is removed separately below.
    if let Some(port) = record.tunnel_port {
        udp.push(port);
    }
    (tcp, udp)
}

const REMOVE: &str = r#"
for svc in $SERVICES; do systemctl disable --now "$svc" >/dev/null 2>&1 || true; done
echo "step=services"
rm -f "$ZRAY_UNIT" "$MASTERDNS_UNIT" "$TUNNEL_CONF" "$TUNNEL_RT_CONF" "$TUNNEL_C_CONF"
systemctl daemon-reload >/dev/null 2>&1 || true
rm -rf "$ZRAY_DIR" "$ZRAY_ETC" /var/lib/zray "$MASTERDNS_DIR" "$MASTERDNS_ETC"
id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" >/dev/null 2>&1 || true
getent group "$SVC_USER" >/dev/null 2>&1 && groupdel "$SVC_USER" >/dev/null 2>&1 || true
echo "step=files"
# The modem L2TP server (gateway role; harmless elsewhere): stop xl2tpd,
# drop its configs, remove only our chap-secrets lines, close UDP 1701,
# and lift the pool guard.
systemctl disable --now xl2tpd >/dev/null 2>&1 || true
rm -f "$XL2TPD_CONF" "$PPP_OPTIONS"
if [ -f "$CHAP_SECRETS" ]; then
  grep -v " $CHAP_SERVER " "$CHAP_SECRETS" > "$CHAP_SECRETS.zray" || true
  cat "$CHAP_SECRETS.zray" > "$CHAP_SECRETS" 2>/dev/null || true
  rm -f "$CHAP_SECRETS.zray"
fi
if command -v iptables >/dev/null 2>&1; then
  while iptables -C FORWARD -s "$MODEM_POOL" -j DROP >/dev/null 2>&1; do
    iptables -D FORWARD -s "$MODEM_POOL" -j DROP >/dev/null 2>&1 || break
  done
fi
tcp=$(echo "$TCP" | tr ',' ' '); udp=$(echo "$UDP" | tr ',' ' ')
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  for p in $tcp; do [ "$p" = none ] || ufw delete allow "$p/tcp" >/dev/null 2>&1 || true; done
  for p in $udp; do [ "$p" = none ] || ufw delete allow "$p/udp" >/dev/null 2>&1 || true; done
  ufw delete allow 1701/udp >/dev/null 2>&1 || true
  if [ "$TUNNEL_PORT" != none ]; then
    ufw delete allow from "$GW_IP" to any port "$TUNNEL_PORT" proto udp >/dev/null 2>&1 || true
  fi
  if [ "$GW_IP" != none ]; then
    ufw delete allow from "$GW_IP" to any port "$RT_PORT" proto tcp >/dev/null 2>&1 || true
  fi
  if [ "$C_PORT" != none ]; then
    ufw delete allow from "$GW6" to any port "$C_PORT" proto udp >/dev/null 2>&1 || true
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  for p in $tcp; do [ "$p" = none ] || firewall-cmd --permanent --remove-port="$p/tcp" >/dev/null 2>&1 || true; done
  for p in $udp; do [ "$p" = none ] || firewall-cmd --permanent --remove-port="$p/udp" >/dev/null 2>&1 || true; done
  firewall-cmd --permanent --remove-port=1701/udp >/dev/null 2>&1 || true
  if [ "$TUNNEL_PORT" != none ]; then
    firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$GW_IP port port=$TUNNEL_PORT protocol=udp accept" >/dev/null 2>&1 || true
  fi
  if [ "$GW_IP" != none ]; then
    firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$GW_IP port port=$RT_PORT protocol=tcp accept" >/dev/null 2>&1 || true
  fi
  if [ "$C_PORT" != none ]; then
    firewall-cmd --permanent --remove-rich-rule="rule family=ipv6 source address=$GW6 port port=$C_PORT protocol=udp accept" >/dev/null 2>&1 || true
  fi
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
echo "step=firewall"
home=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
if [ -n "$home" ] && [ -f "$home/.ssh/authorized_keys" ]; then
  grep -vF " $KEY_COMMENT" "$home/.ssh/authorized_keys" > "$home/.ssh/authorized_keys.zray" || true
  cat "$home/.ssh/authorized_keys.zray" > "$home/.ssh/authorized_keys"
  rm -f "$home/.ssh/authorized_keys.zray"
fi
echo "step=access"
"#;

/// Take everything the installer put on the server away again: the services,
/// their files and account, the firewall ports it opened, and the app's own SSH
/// key. Nothing else on the server is touched. The connection must have been
/// made with the app's key or the password; the key is removed last.
pub async fn remove(
    conn: &Connection,
    record: &ServerRecord,
    on: &(dyn Fn(Removed) + Sync),
) -> Result<(), ssh::Error> {
    remove_inner(conn, record, None, None, on).await
}

/// `remove`, plus the tunnel's source-restricted firewall rule: `tunnel_gw_ip`
/// is the address the exit's rule was opened for (`None` skips it).
async fn remove_inner(
    conn: &Connection,
    record: &ServerRecord,
    tunnel_gw_ip: Option<&str>,
    tunnel_c: Option<(&str, u16)>,
    on: &(dyn Fn(Removed) + Sync),
) -> Result<(), ssh::Error> {
    let (tcp, udp) = ports_of(record);
    let list = |ports: &[u16]| {
        if ports.is_empty() {
            "none".to_string()
        } else {
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    };
    let (tcp, udp) = (list(&tcp), list(&udp));
    let comment = layout::key_comment(&record.id);
    // The tunnel's source-restricted firewall rule (exit side) is removed by
    // address+port; a plain server record has no gateway address, so it skips.
    let tunnel_port = record
        .tunnel_port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "none".to_string());
    let gw_ip = tunnel_gw_ip.unwrap_or("none").to_string();
    let (gw6, c_port) = match tunnel_c {
        Some((ip, port)) => (ip.to_string(), port.to_string()),
        None => ("none".to_string(), "none".to_string()),
    };
    let env = [
        ("SERVICES", "zray masterdns"),
        ("ZRAY_UNIT", layout::ZRAY_UNIT),
        ("MASTERDNS_UNIT", layout::MASTERDNS_UNIT),
        ("TUNNEL_CONF", layout::ZRAY_TUNNEL_CONF),
        ("TUNNEL_RT_CONF", layout::ZRAY_TUNNEL_RT_CONF),
        ("ZRAY_DIR", layout::ZRAY_DIR),
        ("ZRAY_ETC", layout::ZRAY_ETC),
        ("MASTERDNS_DIR", layout::MASTERDNS_DIR),
        ("MASTERDNS_ETC", layout::MASTERDNS_ETC),
        ("XL2TPD_CONF", layout::XL2TPD_CONF),
        ("PPP_OPTIONS", layout::PPP_OPTIONS_MODEM),
        ("CHAP_SECRETS", layout::PPP_CHAP_SECRETS),
        ("CHAP_SERVER", layout::MODEM_CHAP_SERVER),
        ("MODEM_POOL", layout::MODEM_POOL_CIDR),
        ("SVC_USER", layout::ZRAY_USER),
        ("TCP", tcp.as_str()),
        ("UDP", udp.as_str()),
        ("TUNNEL_PORT", tunnel_port.as_str()),
        ("RT_PORT", "443"),
        ("GW_IP", gw_ip.as_str()),
        ("TUNNEL_C_CONF", layout::ZRAY_TUNNEL_C_CONF),
        ("C_PORT", c_port.as_str()),
        ("GW6", gw6.as_str()),
        ("LOGIN_USER", record.ssh_user.as_str()),
        ("KEY_COMMENT", comment.as_str()),
    ];
    let out = conn.script(&env, REMOVE, Duration::from_secs(120)).await?;
    for line in out.stdout.lines() {
        match line.strip_prefix("step=") {
            Some("services") => on(Removed::Services),
            Some("files") => on(Removed::Files),
            Some("firewall") => on(Removed::Firewall),
            Some("access") => on(Removed::Access),
            _ => {}
        }
    }
    if out.ok() {
        Ok(())
    } else {
        Err(ssh::Error::Protocol(format!(
            "removal stopped part-way: {}",
            out.stderr.trim()
        )))
    }
}

/// `remove`, but the exit side also drops the tunnel's source-restricted
/// firewall rule for `gateway_ip`, and Tunnel C's v6 rule when `tunnel_c`
/// carries its `(gateway_ipv6, port)`. `pub(crate)` for the install rollback.
pub(crate) async fn remove_with_gateway_ip(
    conn: &Connection,
    record: &ServerRecord,
    gateway_ip: Option<&str>,
    tunnel_c: Option<(&str, u16)>,
    on: &(dyn Fn(Removed) + Sync),
) -> Result<(), ssh::Error> {
    remove_inner(conn, record, gateway_ip, tunnel_c, on).await
}

/// Remove a whole pair: the exit first, then the gateway, each reporting its
/// steps under its side. The tunnel's firewall rule on the exit is addressed
/// by the gateway's live address (read from a fresh facts probe), so the rule
/// is found even when the gateway was typed as a domain name.
pub async fn remove_pair(
    gw_conn: &Connection,
    ex_conn: &Connection,
    record: &crate::record::PairRecord,
    on: &(dyn Fn(crate::record::Role, Removed) + Sync),
) -> Result<(), ssh::Error> {
    let gw_ip = gateway_ip(gw_conn).await;
    let tunnel_c = record
        .tunnel
        .c
        .as_ref()
        .map(|c| (c.gateway_ipv6.as_str(), c.port));
    remove_inner(ex_conn, &record.exit, gw_ip.as_deref(), tunnel_c, &|step| {
        on(crate::record::Role::Exit, step)
    })
    .await?;
    remove_inner(gw_conn, &record.gateway, None, None, &|step| {
        on(crate::record::Role::Gateway, step)
    })
    .await?;
    Ok(())
}

/// The gateway's address as the exit sees it: the source address of its
/// default route, falling back to the typed host.
async fn gateway_ip(conn: &Connection) -> Option<String> {
    let out = conn
        .script(&[], crate::facts::SCRIPT, Duration::from_secs(60))
        .await
        .ok()?;
    if !out.ok() {
        return None;
    }
    let facts = crate::facts::Facts::parse(&out.stdout);
    if facts.primary_ip4.is_empty() {
        None
    } else {
        Some(facts.primary_ip4)
    }
}

/// What the tunnel check on one server reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// The management endpoint answered and the tunnel is up.
    pub up: bool,
    /// Seconds since the last handshake, when the server could say.
    pub last_handshake_secs_ago: Option<u64>,
    pub rx: Option<u64>,
    pub tx: Option<u64>,
    /// Why this is not `up`, in plain words; `None` when up.
    pub note: Option<String>,
    /// Tunnel B (VLESS+REALITY) key material is present on this server.
    #[serde(default)]
    pub tunnel_b_key: bool,
    /// This server's config carries Tunnel B (the `reality-tunnel` outbound
    /// on the gateway, the `tunnel-rt-in` inbound on the exit).
    #[serde(default)]
    pub tunnel_b_config: bool,
    /// Tunnel C (WireGuard over IPv6) key material is present on this server.
    #[serde(default)]
    pub tunnel_c_key: bool,
    /// This server's config carries Tunnel C (the `tunnel-c` outbound on
    /// the gateway, the `tunnel-c-in` inbound on the exit).
    #[serde(default)]
    pub tunnel_c_config: bool,
}

/// Ask one server about its side of the tunnel, through its management API.
/// `up` is false (with a note, never an error) when the program is too old to
/// have the endpoint or the tunnel is down.
pub async fn tunnel_status(
    conn: &Connection,
    record: &ServerRecord,
) -> Result<TunnelStatus, ssh::Error> {
    let port = record.management_port.to_string();
    let env = [
        ("TOKEN_FILE", layout::ZRAY_TOKEN),
        ("MANAGEMENT_PORT", port.as_str()),
        ("WORK", layout::WORK_DIR),
    ];
    let out = conn
        .script(&env, scripts::TUNNEL_STATUS, Duration::from_secs(20))
        .await?;
    let mut status = TunnelStatus {
        up: false,
        last_handshake_secs_ago: None,
        rx: None,
        tx: None,
        note: None,
        tunnel_b_key: false,
        tunnel_b_config: false,
        tunnel_c_key: false,
        tunnel_c_config: false,
    };
    for line in out.stdout.lines() {
        if line.trim() == "tunnel_b_key=1" {
            status.tunnel_b_key = true;
        } else if line.trim() == "tunnel_b_config=1" {
            status.tunnel_b_config = true;
        } else if line.trim() == "tunnel_c_key=1" {
            status.tunnel_c_key = true;
        } else if line.trim() == "tunnel_c_config=1" {
            status.tunnel_c_config = true;
        } else if let Some(value) = line.strip_prefix("tunnel=") {
            match value {
                "up" => status.up = true,
                "missing" => {
                    status.note = Some(
                        "This server's program has no tunnel endpoint yet; the tunnel state \
                         could not be read."
                            .into(),
                    );
                }
                _ => {}
            }
        } else if let Some(body) = line.strip_prefix("body=") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                let get = |key: &str| json.get(key).and_then(|v| v.as_u64());
                status.last_handshake_secs_ago = get("last_handshake_secs_ago");
                status.rx = get("rx")
                    .or_else(|| get("gateway_rx"))
                    .or_else(|| get("exit_rx"));
                status.tx = get("tx")
                    .or_else(|| get("gateway_tx"))
                    .or_else(|| get("exit_tx"));
            }
        }
    }
    if !status.up && status.note.is_none() {
        status.note = Some("The tunnel is down on this server.".into());
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
1760180000.100 host masterdns-server[1]: 2026/10/11 10:00:00 [MasterDnsVPN Server] [INFO] \u{1f9dd} Session Created, ID: 1, Mode: RAW (Bytes)
1760180010.200 host masterdns-server[1]: 2026/10/11 10:00:10 [MasterDnsVPN Server] [INFO] \u{1f9dd} Session Created, ID: 2, Mode: RAW (Bytes)
1760183000.300 host masterdns-server[1]: 2026/10/11 10:50:00 [MasterDnsVPN Server] [INFO] \u{1f9dd} Session Created, ID: 3, Mode: RAW (Bytes)
1760183100.400 host masterdns-server[1]: 2026/10/11 10:51:40 [MasterDnsVPN Server] [INFO] \u{1f6aa} Session Closed By Client, Session: 2
1760183200.500 host masterdns-server[1]: 2026/10/11 10:53:20 [MasterDnsVPN Server] [INFO] \u{1f4e1} Expired Sessions Cleaned, Count: 1
";

    #[test]
    fn open_sessions_are_created_less_closed_less_expired() {
        let usage = masterdns_usage(LOG, 1760183250);
        assert_eq!(usage.sessions, 1, "three created, one closed, one expired");
        assert_eq!(usage.devices_now, 1);
        // Only session 3 was created inside the last five minutes.
        assert_eq!(usage.devices_recent, 1);
        assert_eq!(usage.tag, "masterdns");
    }

    #[test]
    fn an_empty_log_is_no_one() {
        let usage = masterdns_usage("", 1760183250);
        assert_eq!(
            (usage.sessions, usage.devices_now, usage.devices_recent),
            (0, 0, 0)
        );
    }

    #[test]
    fn more_closes_than_creates_never_goes_negative() {
        let log = "1760183100.4 h m[1]: Session Closed By Client, Session: 9\n";
        assert_eq!(masterdns_usage(log, 1760183250).sessions, 0);
    }

    #[test]
    fn the_figure_carries_no_address() {
        let text = serde_json::to_string(&masterdns_usage(LOG, 1760183250)).unwrap();
        assert!(!text.contains("host"));
    }
}
