//! The operator panel (`zray-admin`) on a server the installer set up.
//!
//! How this works: after the server program is running, the installer puts
//! the panel program next to it, gives it a configuration that points at the
//! server program's loopback management API, tells it which inbounds the
//! server serves (so it can build a client link for each user), starts it, and
//! waits until it answers. The panel listens on `127.0.0.1` only; the app
//! reaches it over the SSH connection it already has, and a browser reaches it
//! through an SSH port forward. Nothing new is opened to the internet.
//!
//! The panel runs as the same account as the server program (`zray`), so the
//! users files it writes in `/etc/zray/users` are readable by the server, and
//! the salt both use to hash user identities is `/etc/zray/usage.salt`.
//!
//! The administrator's token and the panel password are made here and handed
//! back once, to the app, over the same SSH session. They are never logged.

use std::time::Duration;

use serde_json::json;

use crate::keys;
use crate::layout;
use crate::record::Service;
use crate::ssh::{Connection, Error};

/// The loopback port the panel listens on.
pub const ADMIN_PORT: u16 = 18080;
const ADMIN_BIN: &str = "/usr/local/bin/zray-admin";
const ADMIN_ETC: &str = "/etc/zeronet-admin";
const ADMIN_VAR: &str = "/var/lib/zeronet-admin";
const SALT_FILE: &str = "/etc/zray/usage.salt";
const USERS_DIR: &str = "/etc/zray/users";
const ADMIN_UNIT: &str = "/etc/systemd/system/zray-admin.service";
const QUICK: Duration = Duration::from_secs(60);

/// What the app needs to manage the panel, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelAccess {
    pub port: u16,
    pub admin_token: String,
    pub password: String,
}

/// The panel's systemd unit: the server's account, a read-only system, and
/// write access only where the panel keeps its database and the users files.
pub fn unit() -> String {
    format!(
        "[Unit]\n\
         Description=Zray operator panel\n\
         After=network-online.target zray.service\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         ExecStart={ADMIN_BIN} serve\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         UMask=0077\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
         RestrictNamespaces=true\n\
         LockPersonality=true\n\
         ReadWritePaths={ADMIN_VAR} {USERS_DIR}\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = layout::ZRAY_USER
    )
}

/// The panel's configuration file for a server whose management API is on
/// `management_port`.
pub fn config(role: &str, management_port: u16, install_id: &str, exit_host: Option<&str>, salt_hex: &str) -> String {
    serde_json::to_string_pretty(&json!({
        "role": role,
        "mode": "primary",
        "listen": format!("127.0.0.1:{ADMIN_PORT}"),
        "sub_listen": null,
        "engine_mgmt": format!("127.0.0.1:{management_port}"),
        "collector_target": null,
        "poll_interval_secs": 30,
        "install_id": install_id,
        "exit_host": exit_host,
        "sub_port": 18443,
        "usage_salt_hex": salt_hex,
    }))
    .expect("a JSON value always encodes")
}

/// The inbounds of `services`, in the form `zray-admin register-inbounds`
/// reads, so the panel can build each user's link.
pub fn inbounds(role: &str, host: &str, services: &[Service]) -> serde_json::Value {
    let mut list = Vec::new();
    for service in services {
        match service {
            Service::Reality(r) => list.push(json!({
                "tag": r.tag, "protocol": "vless-reality", "server_role": role,
                "host": host, "port": r.port, "enabled": true,
                "params": {"sni": r.sni, "pbk": r.public_key, "sid": r.short_id},
            })),
            Service::Xhttp(x) => list.push(json!({
                "tag": x.tag, "protocol": "vless-xhttp", "server_role": role,
                "host": host, "port": x.port, "enabled": true,
                "params": {"sni": x.sni, "pbk": x.public_key, "sid": x.short_id, "path": x.path},
            })),
            Service::Zerov1(z) => list.push(json!({
                "tag": z.tag, "protocol": "zerov1", "server_role": role,
                "host": host, "port": z.port, "enabled": true,
                "params": {"sni": z.sni, "pbk": z.public_key, "sid": z.short_id,
                           "server_key": z.server_key, "path": z.path},
            })),
            // MasterDNS has its own link form and no users file.
            Service::MasterDns(_) => {}
        }
    }
    serde_json::Value::Array(list)
}

/// Prepare the folders, run the panel's own set-up and hand the files to the
/// server's account. Prints `admin_token=`.
const SETUP: &str = r#"
install -d -m 750 -o root -g "$SVC_USER" "$USERS_DIR" 2>/dev/null || true
chown "$SVC_USER:$SVC_USER" "$USERS_DIR"
chmod 750 "$USERS_DIR"
"$ADMIN_BIN" init-layout >/dev/null
"$ADMIN_BIN" migrate >/dev/null
printf '%s\n' "$PANEL_PASSWORD" | "$ADMIN_BIN" set-password >/dev/null
"$ADMIN_BIN" register-inbounds < "$WORK/inbounds.json" >/dev/null
chown -R "$SVC_USER:$SVC_USER" "$ADMIN_ETC" "$ADMIN_VAR"
echo "admin_token=$(cat "$ADMIN_ETC/admin.token")"
"#;

/// Start the panel and wait until it answers on its loopback port.
const START_PANEL: &str = r#"
systemctl daemon-reload
systemctl enable zray-admin >/dev/null 2>&1
systemctl restart zray-admin
i=0
while [ $i -lt 20 ]; do
  if curl -fsS -m 3 -H "Authorization: Bearer $(cat "$ADMIN_ETC/admin.token")" "http://127.0.0.1:$PANEL_PORT/api/v1/status" >/dev/null 2>&1; then
    echo "panel=up"; exit 0
  fi
  i=$((i+1)); sleep 1
done
journalctl -u zray-admin -n 20 --no-pager >&2 || true
exit 70
"#;

/// Take the panel away again (rollback or removal).
pub const REMOVE: &str = r#"
systemctl disable --now zray-admin >/dev/null 2>&1 || true
rm -f "$ADMIN_UNIT" "$ADMIN_BIN" "$SALT_FILE"
systemctl daemon-reload >/dev/null 2>&1 || true
rm -rf "$ADMIN_ETC" "$ADMIN_VAR" "$USERS_DIR"
"#;

/// Put the panel on the server. `program` is the panel program for this
/// server's CPU; `services` are the inbounds the server serves; `host` is the
/// address clients reach it at.
pub async fn deploy(
    conn: &Connection,
    program: &[u8],
    role: &str,
    host: &str,
    management_port: u16,
    exit_host: Option<&str>,
    services: &[Service],
) -> Result<PanelAccess, Error> {
    let salt = keys::new_token();
    let password: String = keys::new_token().chars().take(24).collect();
    let owner = format!("root:{}", layout::ZRAY_USER);
    let cfg_owner = format!("{0}:{0}", layout::ZRAY_USER);

    conn.put_file(ADMIN_BIN, "755", "root:root", program).await?;
    // The salt both the server and the panel hash identities with.
    conn.put_file(SALT_FILE, "640", &owner, salt.as_bytes()).await?;
    // Folders must exist before the config goes in.
    let env = [
        ("SVC_USER", layout::ZRAY_USER),
        ("ADMIN_ETC", ADMIN_ETC),
        ("ADMIN_VAR", ADMIN_VAR),
        ("WORK", layout::WORK_DIR),
    ];
    let out = conn
        .script(
            &env,
            "install -d -m 700 \"$ADMIN_ETC\" \"$ADMIN_VAR\" \"$WORK\"",
            QUICK,
        )
        .await?;
    if !out.ok() {
        return Err(Error::Protocol(format!(
            "preparing the panel folders failed: {}",
            out.stderr.trim()
        )));
    }
    let install_id = keys::random_hex(8);
    conn.put_file(
        &format!("{ADMIN_ETC}/config.json"),
        "600",
        &cfg_owner,
        config(role, management_port, &install_id, exit_host, &salt).as_bytes(),
    )
    .await?;
    conn.put_file(ADMIN_UNIT, "644", "root:root", unit().as_bytes()).await?;
    let work = layout::WORK_DIR;
    conn.put_file(
        &format!("{work}/inbounds.json"),
        "600",
        "root:root",
        inbounds(role, host, services).to_string().as_bytes(),
    )
    .await?;

    let env = [
        ("SVC_USER", layout::ZRAY_USER),
        ("USERS_DIR", USERS_DIR),
        ("ADMIN_BIN", ADMIN_BIN),
        ("ADMIN_ETC", ADMIN_ETC),
        ("ADMIN_VAR", ADMIN_VAR),
        ("PANEL_PASSWORD", &password),
        ("WORK", work),
    ];
    let out = conn.script(&env, SETUP, QUICK).await?;
    if !out.ok() {
        return Err(Error::Protocol(format!(
            "setting the panel up failed: {}",
            out.stderr.trim()
        )));
    }
    let admin_token = out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("admin_token="))
        .unwrap_or("")
        .trim()
        .to_string();
    if admin_token.is_empty() {
        return Err(Error::Protocol("the panel made no admin token".into()));
    }

    let port = ADMIN_PORT.to_string();
    let env = [("ADMIN_ETC", ADMIN_ETC), ("PANEL_PORT", port.as_str())];
    let out = conn.script(&env, START_PANEL, Duration::from_secs(90)).await?;
    if !out.ok() {
        return Err(Error::Protocol(format!(
            "the panel did not start: {}",
            out.stderr.trim()
        )));
    }
    Ok(PanelAccess {
        port: ADMIN_PORT,
        admin_token,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Reality, User};

    #[test]
    fn the_unit_runs_as_the_servers_account_and_writes_only_its_own_folders() {
        let unit = unit();
        assert!(unit.contains("User=zray\n"));
        assert!(unit.contains("ReadWritePaths=/var/lib/zeronet-admin /etc/zray/users"));
        assert!(unit.contains("ExecStart=/usr/local/bin/zray-admin serve"));
    }

    #[test]
    fn the_config_listens_on_loopback_and_points_at_the_server() {
        let text = config("gateway", 21678, "abc", Some("203.0.113.5"), &"ab".repeat(32));
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["listen"], "127.0.0.1:18080");
        assert_eq!(v["engine_mgmt"], "127.0.0.1:21678");
        assert!(v["sub_listen"].is_null());
        assert_eq!(v["usage_salt_hex"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn inbounds_carry_what_a_link_needs() {
        let services = [Service::Reality(Reality {
            tag: "reality-in".into(),
            port: 443,
            sni: "www.microsoft.com".into(),
            public_key: "PBK".into(),
            short_id: "SID".into(),
            users: vec![User { name: "Main".into(), id: "u".into() }],
        })];
        let v = inbounds("gateway", "198.51.100.7", &services);
        assert_eq!(v[0]["protocol"], "vless-reality");
        assert_eq!(v[0]["host"], "198.51.100.7");
        assert_eq!(v[0]["params"]["pbk"], "PBK");
        assert_eq!(v[0]["params"]["sid"], "SID");
    }
}
