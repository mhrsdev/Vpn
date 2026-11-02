//! The installer as one string-in, events-out job, for apps that cannot call
//! Rust types directly (Android reaches it through JNI, see `zray-mobile`).
//!
//! A request is one JSON object with an `op`; the job emits JSON events to the
//! sink and always ends with exactly one `{"t":"done","ok":…}`:
//!
//! | `op`                    | needs                                             | `done` carries                      |
//! |-------------------------|---------------------------------------------------|-------------------------------------|
//! | `fingerprint`           | `host`, `port`                                    | `fingerprint`, `algorithm`          |
//! | `dns_plan`              | `domain`, `server`                                | `domain`, `ns_host`, `records`      |
//! | `dns`                   | `ns_host`, `server`                               | `status`: right, wrong or unknown   |
//! | `install`               | login, `trust`, `name`, what to install           | `record`, `notes`, `configs`        |
//! | `usage`                 | `record`                                          | `usage`                             |
//! | `remove`                | `record`                                          | nothing                             |
//! | `probe`                 | `record` (with a MasterDNS service)               | `answered`, `of`, `best_ms`         |
//! | `configs`               | `record`                                          | `configs`                           |
//! | `fingerprint_pair`      | `gateway`, `exit` hosts                           | both fingerprints                   |
//! | `install_pair`          | logins, `trust`, `name`, protocols, `modem_server`| `record`, `notes`, `configs`        |
//! | `link_servers`          | `record`                                          | `tunnel`, `ipv6_status`             |
//! | `tunnel_status`         | `record`                                          | per-side tunnel state               |
//! | `tunnel_switch`         | `record`, `transport` (`a`/`b`)                   | `active`                            |
//! | `usage_pair`            | `record`                                          | `gateway`, `exit` usage             |
//! | `remove_pair`           | `record`                                          | nothing                             |
//! | `rollback_pair`         | `record`                                          | nothing                             |
//! | `configs_pair`          | `record`                                          | `configs`                           |
//! | `modem_account_create`  | `record`, `name`                                  | `username`, `password` (once), `accounts` |
//! | `modem_account_revoke`  | `record`, `username`                              | `revoked`, `accounts`               |
//! | `modem_account_rotate`  | `record`, `username`                              | `username`, `password` (once), `accounts` |
//! | `modem_status`          | `record`                                          | `installed`, `active`, `sessions`   |
//!
//! `install` and `remove` also emit `{"t":"step",…}` and `{"t":"detail",…}`
//! as they go. Failures are `{"t":"done","ok":false,"error":"<a sentence for
//! the person>"}`; the app shows it as it is.
//!
//! The record is passed in and out as JSON and kept by the app: this job
//! stores nothing. The password in an `install` request is used for that run
//! and dropped with the request.

use serde::Deserialize;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use zero_discovery::discover::EndReason;
use zero_discovery::events::EventSink;

use crate::install::{
    self, BinarySource, MasterDnsRequest, RealityRequest, XhttpRequest, Zerov1Request,
};
use crate::record::{PairRecord, Role, ServerRecord, Service, TransportId};
use crate::ssh::{Auth, HostKey, Login};
use crate::{keys, layout, manage, probe, scripts, ssh};

/// SSH script timeout for the modem ops.
const MODEM_QUICK: std::time::Duration = std::time::Duration::from_secs(60);

/// What the app asks for.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Fingerprint {
        host: String,
        port: u16,
    },
    DnsPlan {
        domain: String,
        server: String,
    },
    Dns {
        ns_host: String,
        server: String,
    },
    Install(Box<InstallArgs>),
    Usage {
        record: Box<ServerRecord>,
    },
    Remove {
        record: Box<ServerRecord>,
    },
    Probe {
        record: Box<ServerRecord>,
    },
    Configs {
        record: Box<ServerRecord>,
    },
    FingerprintPair {
        gateway: PairHost,
        exit: PairHost,
    },
    InstallPair(Box<PairInstallArgs>),
    /// One call to the operator panel on the pair's gateway (the app's
    /// management screens): `method`, `path`, `query`, `body`, the panel's
    /// `token` and the pair's record.
    Admin(Box<AdminArgs>),
    LinkServers {
        record: Box<PairRecord>,
    },
    TunnelStatus {
        record: Box<PairRecord>,
    },
    UsagePair {
        record: Box<PairRecord>,
    },
    RemovePair {
        record: Box<PairRecord>,
    },
    RollbackPair {
        record: Box<PairRecord>,
    },
    ConfigsPair {
        record: Box<PairRecord>,
    },
    /// Switch the gateway's active inter-server transport (`"a"` WireGuard,
    /// `"b"` VLESS+REALITY). Both tunnels stay configured; this flips the
    /// catch-all routing rule.
    TunnelSwitch {
        record: Box<PairRecord>,
        transport: String,
    },
    /// Create a modem PPP account (chap-secrets) on the gateway.
    ModemAccountCreate {
        record: Box<PairRecord>,
        name: String,
    },
    /// Revoke a modem account: remove its chap-secrets line and kill its
    /// session.
    ModemAccountRevoke {
        record: Box<PairRecord>,
        username: String,
    },
    /// Rotate a modem account's password (kills its session, forcing
    /// re-authentication).
    ModemAccountRotate {
        record: Box<PairRecord>,
        username: String,
    },
    /// The modem L2TP server's state on the gateway.
    ModemStatus {
        record: Box<PairRecord>,
    },
}

/// An address to fingerprint: the host and SSH port of one side.
#[derive(Deserialize)]
pub struct PairHost {
    pub host: String,
    pub port: u16,
}

/// One side's login for a pair install.
#[derive(Deserialize)]
pub struct PairServerArgs {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// The login password; empty when a key is used instead.
    #[serde(default)]
    pub password: String,
    /// An SSH private key to log in with instead of a password (text, as
    /// pasted or read from a file) and its passphrase when it has one. Both
    /// are used for this request only and never stored.
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    /// The fingerprint the person confirmed.
    pub trust: HostKey,
}

impl std::fmt::Debug for PairServerArgs {
    // The password and key never print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairServerArgs")
            .field("host", &self.host)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// One call to the panel, from the app's management screens.
#[derive(Deserialize)]
pub struct AdminArgs {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: serde_json::Value,
    #[serde(default)]
    pub body: serde_json::Value,
    pub token: String,
    pub pair_record: PairRecord,
}

impl std::fmt::Debug for AdminArgs {
    // The token never prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminArgs")
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Which protocols a pair install sets up. Names follow the protocol table:
/// `reality`, `xhttp`, `zerov1` are on offer; anything else is reported as
/// unavailable, never silently skipped.
#[derive(Deserialize, Default)]
pub struct PairProtocols {
    #[serde(default)]
    pub gateway: Vec<String>,
    /// The exit's egress mode: `direct` is the only one on offer yet.
    #[serde(default)]
    pub exit_egress: Option<String>,
}

#[derive(Deserialize)]
pub struct PairInstallArgs {
    pub name: String,
    #[serde(default)]
    pub sni: Option<String>,
    pub gateway: PairServerArgs,
    pub exit: PairServerArgs,
    #[serde(default)]
    pub protocols: PairProtocols,
    #[serde(default)]
    pub masterdns_domain: Option<String>,
    #[serde(default = "default_true")]
    pub keep_access: bool,
    /// A server program on this device to install instead of the signed
    /// release (unverified; reported as such).
    #[serde(default)]
    pub local_binary_path: Option<String>,
    /// A folder holding `zray-linux-x64` and `zray-linux-arm64` shipped with
    /// the app; used when no `local_binary_path` is given.
    #[serde(default)]
    pub local_binary_dir: Option<String>,
    /// Install the Huawei modem L2TP server on the gateway (Design G).
    #[serde(default)]
    pub modem_server: bool,
}

/// Where the server program comes from: a file, a folder of per-CPU files the
/// app ships, or (neither given) the signed GitHub release.
fn binary_source(path: &Option<String>, dir: &Option<String>) -> Result<BinarySource, String> {
    let read = |p: &std::path::Path| {
        std::fs::read(p).map_err(|e| format!("Could not read the server program: {e}"))
    };
    if let Some(path) = path {
        return Ok(BinarySource::Local(read(std::path::Path::new(path))?));
    }
    if let Some(dir) = dir {
        let dir = std::path::Path::new(dir);
        // The panel programs are optional: without them no panel is installed.
        let optional = |name: &str| std::fs::read(dir.join(name)).unwrap_or_default();
        return Ok(BinarySource::Bundled {
            x64: read(&dir.join("zray-linux-x64"))?,
            arm64: optional("zray-linux-arm64"),
            admin_x64: optional("zray-admin-linux-x64"),
            admin_arm64: optional("zray-admin-linux-arm64"),
        });
    }
    Ok(BinarySource::Release { tag: None })
}

impl std::fmt::Debug for PairInstallArgs {
    // The passwords and keys never print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairInstallArgs")
            .field("name", &self.name)
            .field("protocols", &self.protocols.gateway)
            .finish_non_exhaustive()
    }
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
pub struct InstallArgs {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// The login password; empty when a key is used instead.
    #[serde(default)]
    pub password: String,
    /// An SSH private key to log in with instead of a password (text, as
    /// pasted or read from a file) and its passphrase when it has one. Both
    /// are used for this request only and never stored.
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    /// The fingerprint the person confirmed.
    pub trust: HostKey,
    pub name: String,
    #[serde(default)]
    pub reality: bool,
    /// Also (or only) install VLESS over XHTTP inside REALITY.
    #[serde(default)]
    pub xhttp: bool,
    /// Also (or only) install ZeroV1 inside REALITY.
    #[serde(default)]
    pub zerov1: bool,
    /// The website a REALITY server pretends to be; a default when absent.
    pub sni: Option<String>,
    /// Set to install MasterDNS for this tunnel domain.
    pub masterdns_domain: Option<String>,
    /// A server program on this device to install instead of the signed
    /// release (unverified; reported as such).
    pub local_binary_path: Option<String>,
    /// A folder holding `zray-linux-x64` and `zray-linux-arm64` shipped with
    /// the app; used when no `local_binary_path` is given.
    #[serde(default)]
    pub local_binary_dir: Option<String>,
}

impl std::fmt::Debug for InstallArgs {
    // The password and key never print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallArgs")
            .field("host", &self.host)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

const DEFAULT_SNI: &str = "www.microsoft.com";

fn done_err(sink: &EventSink, error: impl std::fmt::Display) -> EndReason {
    sink.emit(json!({"t": "done", "ok": false, "error": error.to_string()}));
    EndReason::Exhausted
}

fn done_ok(sink: &EventSink, mut fields: Value) -> EndReason {
    fields["t"] = json!("done");
    fields["ok"] = json!(true);
    sink.emit(fields);
    EndReason::Enough
}

/// Run one request. Cancelling ends it early with `ok: false`.
pub async fn run(request: Request, sink: EventSink, cancel: CancellationToken) -> EndReason {
    // The pair install handles cancellation itself: on cancel it rolls back
    // what the run created before reporting, so it must not race the generic
    // select below.
    if let Request::InstallPair(args) = request {
        return install_pair_job(*args, &sink, cancel).await;
    }
    tokio::select! {
        reason = work(request, &sink) => reason,
        () = cancel.cancelled() => {
            sink.emit(json!({"t": "done", "ok": false, "error": "cancelled"}));
            EndReason::Cancelled
        }
    }
}

async fn work(request: Request, sink: &EventSink) -> EndReason {
    match request {
        Request::Fingerprint { host, port } => match ssh::fetch_host_key(&host, port).await {
            Ok(key) => done_ok(
                sink,
                json!({"fingerprint": key.fingerprint, "algorithm": key.algorithm}),
            ),
            Err(e) => done_err(sink, e),
        },
        Request::DnsPlan { domain, server } => {
            let domain = match crate::guide::clean_domain(&domain) {
                Ok(domain) => domain,
                Err(e) => return done_err(sink, e),
            };
            // A server given by name has no address to put in the record yet;
            // the app shows the shape and says to use the server's IP.
            let ip = server
                .parse::<std::net::IpAddr>()
                .unwrap_or_else(|_| std::net::IpAddr::from([0, 0, 0, 0]));
            done_ok(
                sink,
                json!({
                    "ns_host": crate::guide::ns_host(&domain),
                    "records": crate::guide::delegation_records(&domain, ip),
                    "needs_ip": server.parse::<std::net::IpAddr>().is_err(),
                    "domain": domain,
                }),
            )
        }
        Request::Dns { ns_host, server } => {
            let status = match server.parse::<std::net::IpAddr>() {
                Err(_) => "unknown",
                Ok(ip) => {
                    match probe::ns_host_points_here(&ns_host, ip, &probe::public_resolvers()).await
                    {
                        Some(true) => "right",
                        Some(false) => "wrong",
                        None => "unknown",
                    }
                }
            };
            done_ok(sink, json!({"status": status}))
        }
        Request::Install(args) => install_job(*args, sink).await,
        Request::Usage { record } => {
            let conn = match manage::connect(&record).await {
                Ok(conn) => conn,
                Err(e) => return done_err(sink, e),
            };
            let usage = manage::usage(&conn, &record).await;
            conn.close().await;
            match usage {
                Ok(usage) => done_ok(sink, json!({"usage": usage})),
                Err(e) => done_err(sink, e),
            }
        }
        Request::Remove { record } => {
            let conn = match manage::connect(&record).await {
                Ok(conn) => conn,
                Err(e) => return done_err(sink, e),
            };
            let removed = manage::remove(&conn, &record, &|step| {
                sink.emit(json!({"t": "removed", "step": format!("{step:?}").to_lowercase()}));
            })
            .await;
            conn.close().await;
            match removed {
                Ok(()) => done_ok(sink, json!({})),
                Err(e) => done_err(sink, e),
            }
        }
        Request::Probe { record } => {
            let Some(service) = record.services.iter().find_map(|s| match s {
                Service::MasterDns(m) => Some(m),
                _ => None,
            }) else {
                return done_err(sink, "This server has no MasterDNS service.");
            };
            let results = probe::probe_masterdns(service, &probe::public_resolvers()).await;
            let answered = results.iter().filter(|r| r.answered).count();
            let best = results.iter().filter_map(|r| r.millis).min();
            done_ok(
                sink,
                json!({"answered": answered, "of": results.len(), "best_ms": best}),
            )
        }
        Request::Configs { record } => done_ok(sink, json!({"configs": record.client_configs()})),
        Request::FingerprintPair { gateway, exit } => {
            let (gw, ex) = tokio::join!(
                ssh::fetch_host_key(&gateway.host, gateway.port),
                ssh::fetch_host_key(&exit.host, exit.port),
            );
            match (gw, ex) {
                (Ok(gw), Ok(ex)) => done_ok(
                    sink,
                    json!({
                        "gateway": {"fingerprint": gw.fingerprint, "algorithm": gw.algorithm},
                        "exit": {"fingerprint": ex.fingerprint, "algorithm": ex.algorithm},
                    }),
                ),
                (Err(e), _) => done_err(sink, format!("gateway: {e}")),
                (_, Err(e)) => done_err(sink, format!("exit: {e}")),
            }
        }
        Request::LinkServers { record } => link_servers_job(*record, sink).await,
        Request::TunnelStatus { record } => tunnel_status_job(*record, sink).await,
        Request::UsagePair { record } => usage_pair_job(*record, sink).await,
        Request::Admin(args) => admin_job(*args, sink).await,
        Request::RemovePair { record } => remove_pair_job(*record, sink, false).await,
        Request::RollbackPair { record } => remove_pair_job(*record, sink, true).await,
        Request::ConfigsPair { record } => {
            done_ok(sink, json!({"configs": record.client_configs()}))
        }
        Request::TunnelSwitch { record, transport } => {
            tunnel_switch_job(*record, transport, sink).await
        }
        Request::ModemAccountCreate { record, name } => {
            modem_account_create_job(*record, name, sink).await
        }
        Request::ModemAccountRevoke { record, username } => {
            modem_account_revoke_job(*record, username, sink).await
        }
        Request::ModemAccountRotate { record, username } => {
            modem_account_rotate_job(*record, username, sink).await
        }
        Request::ModemStatus { record } => modem_status_job(*record, sink).await,
        // `InstallPair` is handled in `run`, where cancellation rolls back.
        Request::InstallPair(_) => done_err(sink, "unreachable"),
    }
}

/// The login password or key for one side of a pair install. The password is
/// used for this request only and dropped with it.
fn auth_of(
    password: &str,
    private_key: Option<&str>,
    key_passphrase: Option<String>,
) -> Result<Auth, String> {
    match private_key.filter(|key| !key.trim().is_empty()) {
        Some(key) => {
            let passphrase = key_passphrase.filter(|p| !p.is_empty());
            // Fail on a bad key now, before any connection is made.
            if let Err(e) = crate::ssh::parse_private_key(key, passphrase.as_deref()) {
                return Err(e.to_string());
            }
            Ok(Auth::UserKey {
                pem: key.to_string(),
                passphrase,
            })
        }
        None if password.is_empty() => Err("Give a password or an SSH key to log in with.".into()),
        None => Ok(Auth::Password(password.to_string())),
    }
}

fn pair_login(args: &PairServerArgs) -> Result<install::PairLogin, String> {
    let auth = auth_of(
        &args.password,
        args.private_key.as_deref(),
        args.key_passphrase.clone(),
    )?;
    Ok(install::PairLogin {
        login: Login {
            host: args.host.clone(),
            port: args.port,
            user: args.user.clone(),
            auth,
        },
        trust: args.trust.clone(),
    })
}

/// Emit installer events as job JSON. The `server` field is only present for
/// pair installs; the single-server shapes stay byte-compatible.
fn pair_emit(sink: &EventSink) -> impl Fn(install::Event) + '_ {
    move |event: install::Event| match event {
        install::Event::Step {
            step,
            preset,
            number,
            of,
            server,
        } => {
            let mut e =
                json!({"t": "step", "step": step, "preset": preset, "number": number, "of": of});
            if let Some(server) = server {
                e["server"] = json!(server);
            }
            sink.emit(e);
        }
        install::Event::Detail { server, text } => {
            let mut e = json!({"t": "detail", "text": text});
            if let Some(server) = server {
                e["server"] = json!(server);
            }
            sink.emit(e);
        }
    }
}

fn rollback_name(status: &install::RollbackStatus) -> &'static str {
    match status {
        install::RollbackStatus::Complete => "complete",
        install::RollbackStatus::Partial(_) => "partial",
        install::RollbackStatus::NotNeeded => "not_needed",
    }
}

async fn install_pair_job(
    args: PairInstallArgs,
    sink: &EventSink,
    cancel: CancellationToken,
) -> EndReason {
    // Map the protocol names to what the installer serves; anything else is
    // named as unavailable, never silently skipped.
    let (mut reality, mut xhttp, mut zerov1) = (false, false, false);
    for name in &args.protocols.gateway {
        match name.as_str() {
            "reality" => reality = true,
            "xhttp" => xhttp = true,
            "zerov1" => zerov1 = true,
            other => return done_err(sink, install::Error::Unavailable(other.to_string())),
        }
    }
    match args.protocols.exit_egress.as_deref().unwrap_or("direct") {
        "direct" => {}
        other => return done_err(sink, install::Error::Unavailable(format!("egress {other}"))),
    }
    let binary = match binary_source(&args.local_binary_path, &args.local_binary_dir) {
        Ok(b) => b,
        Err(e) => return done_err(sink, e),
    };
    let gateway = match pair_login(&args.gateway) {
        Ok(login) => login,
        Err(e) => return done_err(sink, e),
    };
    let exit = match pair_login(&args.exit) {
        Ok(login) => login,
        Err(e) => return done_err(sink, e),
    };
    let request = install::PairInstallRequest {
        name: args.name.trim().to_string(),
        first_user: "Main".into(),
        sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
        reality,
        xhttp,
        zerov1,
        masterdns_domain: args.masterdns_domain.clone(),
        binary,
        keep_access: args.keep_access,
        modem_server: args.modem_server,
    };
    let mut created = install::PairCreated::default();
    let emit = pair_emit(sink);
    // On cancellation the run's own future is dropped; what it created is
    // rolled back here before the cancellation is reported.
    let outcome = tokio::select! {
        result = install::install_pair(&gateway, &exit, &request, &mut created, &emit) => result,
        () = cancel.cancelled() => {
            let status = reconnect_and_rollback(&created, &gateway, &exit, &emit).await;
            sink.emit(json!({
                "t": "done", "ok": false, "error": "cancelled",
                "rollback": rollback_name(&status),
            }));
            return EndReason::Cancelled;
        }
    };
    match outcome {
        Ok(outcome) => done_ok(
            sink,
            json!({
                "configs": outcome.configs,
                "record": outcome.record,
                "notes": outcome.notes,
                "admin_token": outcome.panel.as_ref().map(|p| p.admin_token.clone()),
                "panel_password": outcome.panel.as_ref().map(|p| p.password.clone()),
                "panel_port": outcome.panel.as_ref().map(|p| p.port),
            }),
        ),
        Err(e) => {
            let mut error = json!({"t": "done", "ok": false, "error": e.to_string()});
            if let install::Error::PairFailed { rollback, .. } = &e {
                error["rollback"] = json!(rollback_name(rollback));
            }
            sink.emit(error);
            EndReason::Exhausted
        }
    }
}

/// Reconnect to whatever the cancelled run installed and roll it back.
async fn reconnect_and_rollback(
    created: &install::PairCreated,
    gateway: &install::PairLogin,
    exit: &install::PairLogin,
    on: &(dyn Fn(install::Event) + Send + Sync),
) -> install::RollbackStatus {
    let mut gw_conn = None;
    let mut ex_conn = None;
    if created.gateway.as_ref().is_some_and(|cs| cs.installed) {
        gw_conn = ssh::connect(&gateway.login, &gateway.trust.fingerprint)
            .await
            .ok();
    }
    if created.exit.as_ref().is_some_and(|cs| cs.installed) {
        ex_conn = ssh::connect(&exit.login, &exit.trust.fingerprint)
            .await
            .ok();
    }
    install::rollback_pair_conns(gw_conn, ex_conn, created, on).await
}

/// Log back in to both sides of a pair with the app's own key.
async fn connect_pair_record(
    record: &PairRecord,
) -> Result<(ssh::Connection, ssh::Connection), String> {
    let gw = manage::connect(&record.gateway)
        .await
        .map_err(|e| format!("gateway: {e}"))?;
    let ex = manage::connect(&record.exit)
        .await
        .map_err(|e| format!("exit: {e}"))?;
    Ok((gw, ex))
}

/// One side's login for the tunnel jobs, from the record the app keeps.
fn pair_login_of(record: &PairRecord, side: Role) -> Result<install::PairLogin, String> {
    let server = match side {
        Role::Gateway => &record.gateway,
        Role::Exit => &record.exit,
        Role::Single => return Err("This record is not a pair.".into()),
    };
    let key = server
        .ssh_key
        .clone()
        .ok_or_else(|| "The app has no login key for this pair.".to_string())?;
    Ok(install::PairLogin {
        login: Login {
            host: server.host.clone(),
            port: server.ssh_port,
            user: server.ssh_user.clone(),
            auth: Auth::Key(key),
        },
        trust: server.host_key.clone(),
    })
}

/// Run one panel call on the gateway, where the panel lives (it serves the
/// clients' inbounds), and report the panel's JSON answer as the `done` event.
async fn admin_job(args: AdminArgs, sink: &EventSink) -> EndReason {
    let conn = match manage::connect(&args.pair_record.gateway).await {
        Ok(conn) => conn,
        Err(e) => return done_err(sink, format!("gateway: {e}")),
    };
    let answer = crate::panel::call(
        &conn,
        &args.token,
        &args.method,
        &args.path,
        &args.query,
        &args.body,
    )
    .await;
    conn.close().await;
    let (status, body) = match answer {
        Ok(pair) => pair,
        // The token must never come back inside an error.
        Err(e) => return done_err(sink, e.replace(&args.token, "•••")),
    };
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(json!({}));
    if (200..300).contains(&status) {
        let mut fields = if parsed.is_object() {
            parsed
        } else {
            json!({ "value": parsed })
        };
        fields["status"] = json!(status);
        return done_ok(sink, fields);
    }
    let message = parsed
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("the panel answered HTTP {status}"));
    done_err(sink, message)
}

async fn link_servers_job(record: PairRecord, sink: &EventSink) -> EndReason {
    let gateway = match pair_login_of(&record, Role::Gateway) {
        Ok(login) => login,
        Err(e) => return done_err(sink, e),
    };
    let exit = match pair_login_of(&record, Role::Exit) {
        Ok(login) => login,
        Err(e) => return done_err(sink, e),
    };
    let emit = pair_emit(sink);
    match install::link_servers(&gateway, &exit, &record, &emit).await {
        Ok((tunnel, ipv6_status)) => {
            done_ok(sink, json!({"tunnel": tunnel, "ipv6_status": ipv6_status}))
        }
        Err(e) => done_err(sink, e),
    }
}

async fn tunnel_status_job(record: PairRecord, sink: &EventSink) -> EndReason {
    let (gw_conn, ex_conn) = match connect_pair_record(&record).await {
        Ok(conns) => conns,
        Err(e) => return done_err(sink, e),
    };
    let (gw, ex) = tokio::join!(
        manage::tunnel_status(&gw_conn, &record.gateway),
        manage::tunnel_status(&ex_conn, &record.exit),
    );
    gw_conn.close().await;
    ex_conn.close().await;
    match (gw, ex) {
        (Ok(gw), Ok(ex)) => {
            let up = gw.up && ex.up;
            let mut fields = json!({
                "up": up,
                "last_handshake_secs_ago": gw.last_handshake_secs_ago,
                "gateway_rx": gw.rx,
                "gateway_tx": gw.tx,
                "exit_rx": ex.rx,
                "exit_tx": ex.tx,
                // Tunnel B is monitored independently of Tunnel A; Tunnel C the
                // same way (its verdict lives on the pair record).
                "tunnel_b": {
                    "gateway": {"key": gw.tunnel_b_key, "config": gw.tunnel_b_config},
                    "exit": {"key": ex.tunnel_b_key, "config": ex.tunnel_b_config},
                    "active": record.tunnel.active == TransportId::B,
                },
                "tunnel_c": {
                    "gateway": {"key": gw.tunnel_c_key, "config": gw.tunnel_c_config},
                    "exit": {"key": ex.tunnel_c_key, "config": ex.tunnel_c_config},
                    "ipv6_status": record.ipv6_status,
                },
            });
            if !up {
                let notes: Vec<&str> = [gw.note.as_deref(), ex.note.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect();
                fields["note"] = json!(notes.join(" "));
            }
            done_ok(sink, fields)
        }
        (Err(e), _) => done_err(sink, format!("gateway: {e}")),
        (_, Err(e)) => done_err(sink, format!("exit: {e}")),
    }
}

async fn usage_pair_job(record: PairRecord, sink: &EventSink) -> EndReason {
    let (gw_conn, ex_conn) = match connect_pair_record(&record).await {
        Ok(conns) => conns,
        Err(e) => return done_err(sink, e),
    };
    let (gw, ex) = tokio::join!(
        manage::usage(&gw_conn, &record.gateway),
        manage::usage(&ex_conn, &record.exit),
    );
    gw_conn.close().await;
    ex_conn.close().await;
    match (gw, ex) {
        (Ok(gateway), Ok(exit)) => done_ok(sink, json!({"gateway": gateway, "exit": exit})),
        (Err(e), _) => done_err(sink, format!("gateway: {e}")),
        (_, Err(e)) => done_err(sink, format!("exit: {e}")),
    }
}

async fn remove_pair_job(record: PairRecord, sink: &EventSink, is_rollback: bool) -> EndReason {
    // The manual rollback is for a run the app itself killed: without the
    // app's key there is no credential, so the app must ask for the password
    // and the caller retries with it.
    if is_rollback && (record.gateway.ssh_key.is_none() || record.exit.ssh_key.is_none()) {
        return done_err(sink, "need_password");
    }
    let (gw_conn, ex_conn) = match connect_pair_record(&record).await {
        Ok(conns) => conns,
        Err(e) => return done_err(sink, e),
    };
    let removed = manage::remove_pair(&gw_conn, &ex_conn, &record, &|role, step| {
        let server = match role {
            Role::Gateway => "gateway",
            Role::Exit => "exit",
            Role::Single => "single",
        };
        sink.emit(
            json!({"t": "removed", "server": server, "step": format!("{step:?}").to_lowercase()}),
        );
    })
    .await;
    gw_conn.close().await;
    ex_conn.close().await;
    match removed {
        Ok(()) => done_ok(sink, json!({})),
        Err(e) => done_err(sink, e),
    }
}

async fn install_job(args: InstallArgs, sink: &EventSink) -> EndReason {
    let domain = match &args.masterdns_domain {
        Some(text) => match crate::guide::clean_domain(text) {
            Ok(domain) => Some(domain),
            Err(e) => return done_err(sink, e),
        },
        None => None,
    };
    let binary = match binary_source(&args.local_binary_path, &args.local_binary_dir) {
        Ok(b) => b,
        Err(e) => return done_err(sink, e),
    };
    let auth = match auth_of(
        &args.password,
        args.private_key.as_deref(),
        args.key_passphrase.clone(),
    ) {
        Ok(auth) => auth,
        Err(e) => return done_err(sink, e),
    };
    let login = Login {
        host: args.host.clone(),
        port: args.port,
        user: args.user.clone(),
        auth,
    };
    let request = install::Request {
        name: args.name.trim().to_string(),
        first_user: "Main".into(),
        reality: args.reality.then(|| RealityRequest {
            sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
            port: None,
        }),
        xhttp: args.xhttp.then(|| XhttpRequest {
            sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
            port: None,
        }),
        zerov1: args.zerov1.then(|| Zerov1Request {
            sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
            port: None,
        }),
        masterdns: domain.map(|domain| MasterDnsRequest { domain }),
        binary,
        keep_access: true,
    };
    let result = install::install(&login, &args.trust, &request, &|event| match event {
        install::Event::Step {
            step,
            preset,
            number,
            of,
            server,
        } => {
            debug_assert!(server.is_none(), "the single-server install has no sides");
            sink.emit(
                json!({"t": "step", "step": step, "preset": preset, "number": number, "of": of}),
            )
        }
        install::Event::Detail { server, text } => {
            debug_assert!(server.is_none(), "the single-server install has no sides");
            sink.emit(json!({"t": "detail", "text": text}))
        }
    })
    .await;
    match result {
        Ok(outcome) => done_ok(
            sink,
            json!({
                "configs": outcome.record.client_configs(),
                "record": outcome.record,
                "notes": outcome.notes,
                "admin_token": outcome.panel.as_ref().map(|p| p.admin_token.clone()),
                "panel_password": outcome.panel.as_ref().map(|p| p.password.clone()),
                "panel_port": outcome.panel.as_ref().map(|p| p.port),
            }),
        ),
        Err(e) => done_err(sink, e),
    }
}

async fn tunnel_switch_job(record: PairRecord, transport: String, sink: &EventSink) -> EndReason {
    let transport = match transport.trim().to_ascii_lowercase().as_str() {
        "a" | "wireguard" => TransportId::A,
        "b" | "reality" => TransportId::B,
        other => {
            return done_err(
                sink,
                format!(
                    "unknown transport {other:?}: use \"a\" (WireGuard) or \"b\" (VLESS+REALITY)"
                ),
            )
        }
    };
    let gateway = match pair_login_of(&record, Role::Gateway) {
        Ok(login) => login,
        Err(e) => return done_err(sink, e),
    };
    let emit = pair_emit(sink);
    match install::tunnel_switch(&gateway, &record, transport, &emit).await {
        Ok(active) => {
            let tag = match active {
                TransportId::A => "a",
                TransportId::B => "b",
            };
            done_ok(sink, json!({"active": tag}))
        }
        Err(e) => done_err(sink, e),
    }
}

/// Connect to the pair's gateway for a modem op. Errors when the pair was
/// installed without the modem server.
async fn modem_gateway(
    record: &PairRecord,
    sink: &EventSink,
) -> Result<ssh::Connection, EndReason> {
    if record.modem.is_none() {
        return Err(done_err(
            sink,
            "this pair has no modem L2TP server; reinstall with modem_server",
        ));
    }
    match manage::connect(&record.gateway).await {
        Ok(conn) => Ok(conn),
        Err(e) => Err(done_err(sink, format!("gateway: {e}"))),
    }
}

/// Read the server's chap-secrets over SSH.
async fn read_chap_secrets(
    conn: &ssh::Connection,
) -> Result<(Vec<layout::ChapEntry>, Vec<String>), String> {
    let out = conn
        .script(
            &[],
            "cat /etc/ppp/chap-secrets 2>/dev/null || true",
            MODEM_QUICK,
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(layout::parse_chap_secrets(&out.stdout))
}

/// Write chap-secrets back atomically (temp file + chmod + rename, 600
/// root:root — the same hygiene as `ssh.rs::put_file`).
async fn write_chap_secrets(
    conn: &ssh::Connection,
    entries: &[layout::ChapEntry],
    other: &[String],
) -> Result<(), String> {
    let text = layout::render_chap_secrets(entries, other);
    conn.put_file(
        layout::PPP_CHAP_SECRETS,
        "600",
        "root:root",
        text.as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// The account list the app stores (usernames only).
fn modem_accounts(entries: &[layout::ChapEntry]) -> Vec<String> {
    let mut names: Vec<String> = entries.iter().map(|e| e.user.clone()).collect();
    names.sort();
    names
}

async fn modem_account_create_job(record: PairRecord, name: String, sink: &EventSink) -> EndReason {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return done_err(sink, "account name: 1-32 ASCII letters, digits, - or _");
    }
    let conn = match modem_gateway(&record, sink).await {
        Ok(conn) => conn,
        Err(end) => return end,
    };
    let (mut entries, other) = match read_chap_secrets(&conn).await {
        Ok(parsed) => parsed,
        Err(e) => {
            conn.close().await;
            return done_err(sink, e);
        }
    };
    let username = keys::new_modem_username();
    let password = keys::new_modem_password();
    entries.push(layout::ChapEntry::new(&username, &password));
    let accounts = modem_accounts(&entries);
    let result = write_chap_secrets(&conn, &entries, &other).await;
    conn.close().await;
    match result {
        // The password is returned once, at creation: the panel shows it
        // after the informed-consent gate (Design G section d) and the
        // admin credential store keeps it. It is never logged.
        Ok(()) => done_ok(
            sink,
            json!({"name": name, "username": username, "password": password, "accounts": accounts}),
        ),
        Err(e) => done_err(sink, e),
    }
}

async fn modem_account_revoke_job(
    record: PairRecord,
    username: String,
    sink: &EventSink,
) -> EndReason {
    let username = username.trim();
    let conn = match modem_gateway(&record, sink).await {
        Ok(conn) => conn,
        Err(end) => return end,
    };
    let (mut entries, other) = match read_chap_secrets(&conn).await {
        Ok(parsed) => parsed,
        Err(e) => {
            conn.close().await;
            return done_err(sink, e);
        }
    };
    let before = entries.len();
    entries.retain(|e| e.user != username);
    if entries.len() == before {
        conn.close().await;
        return done_err(sink, format!("no such modem account {username:?}"));
    }
    let accounts = modem_accounts(&entries);
    let result = (async {
        write_chap_secrets(&conn, &entries, &other).await?;
        let out = conn
            .script(
                &[("USER", username)],
                scripts::MODEM_KILL_SESSION,
                MODEM_QUICK,
            )
            .await
            .map_err(|e| e.to_string())?;
        if !out.ok() {
            return Err("could not terminate the PPP session".to_string());
        }
        Ok(())
    })
    .await;
    conn.close().await;
    match result {
        Ok(()) => done_ok(sink, json!({"revoked": username, "accounts": accounts})),
        Err(e) => done_err(sink, e),
    }
}

async fn modem_account_rotate_job(
    record: PairRecord,
    username: String,
    sink: &EventSink,
) -> EndReason {
    let username = username.trim();
    let conn = match modem_gateway(&record, sink).await {
        Ok(conn) => conn,
        Err(end) => return end,
    };
    let (mut entries, other) = match read_chap_secrets(&conn).await {
        Ok(parsed) => parsed,
        Err(e) => {
            conn.close().await;
            return done_err(sink, e);
        }
    };
    let entry = match entries.iter_mut().find(|e| e.user == username) {
        Some(entry) => entry,
        None => {
            conn.close().await;
            return done_err(sink, format!("no such modem account {username:?}"));
        }
    };
    let password = keys::new_modem_password();
    entry.password = password.clone();
    let accounts = modem_accounts(&entries);
    let result = (async {
        write_chap_secrets(&conn, &entries, &other).await?;
        let out = conn
            .script(
                &[("USER", username)],
                scripts::MODEM_KILL_SESSION,
                MODEM_QUICK,
            )
            .await
            .map_err(|e| e.to_string())?;
        if !out.ok() {
            return Err("could not terminate the PPP session".to_string());
        }
        Ok(())
    })
    .await;
    conn.close().await;
    match result {
        Ok(()) => done_ok(
            sink,
            json!({"username": username, "password": password, "accounts": accounts}),
        ),
        Err(e) => done_err(sink, e),
    }
}

async fn modem_status_job(record: PairRecord, sink: &EventSink) -> EndReason {
    let conn = match modem_gateway(&record, sink).await {
        Ok(conn) => conn,
        Err(end) => return end,
    };
    let out = match conn.script(&[], scripts::MODEM_STATUS, MODEM_QUICK).await {
        Ok(out) => out,
        Err(e) => {
            conn.close().await;
            return done_err(sink, e.to_string());
        }
    };
    // The live account list comes from the server's chap-secrets, not from
    // the record's copy (which the panel refreshes from these responses).
    let live_accounts = match read_chap_secrets(&conn).await {
        Ok((entries, _)) => modem_accounts(&entries),
        Err(e) => {
            conn.close().await;
            return done_err(sink, e);
        }
    };
    conn.close().await;
    let mut fields = json!({
        "installed": false,
        "active": false,
        "sessions": Vec::<Value>::new(),
    });
    let mut sessions = Vec::new();
    for line in out.stdout.lines() {
        if line.trim() == "modem_config=1" {
            fields["installed"] = true.into();
        } else if line.trim() == "modem_active=1" {
            fields["active"] = true.into();
        } else if let Some(rest) = line.strip_prefix("session=") {
            let (user, address) = rest.split_once('@').unwrap_or((rest, ""));
            sessions.push(json!({"user": user, "address": address}));
        }
    }
    fields["sessions"] = sessions.into();
    fields["accounts"] = json!(live_accounts);
    if let Some(m) = &record.modem {
        fields["handoff_pending"] = m.handoff_pending.into();
    }
    done_ok(sink, fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Run `request` and return every event it emitted.
    async fn events(request: &str) -> Vec<Value> {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let callback = {
            let seen = Arc::clone(&seen);
            Arc::new(move |batch: String| seen.lock().unwrap().push(batch))
        };
        let (sink, flusher) = zero_discovery::events::batching_sink(callback);
        let request: Request = serde_json::from_str(request).expect("a valid request");
        run(request, sink.clone(), CancellationToken::new()).await;
        drop(sink);
        let _ = flusher.await;
        let all = seen.lock().unwrap().join("\n");
        all.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn the_password_never_prints() {
        let args: InstallArgs = serde_json::from_str(
            r#"{"host":"h","port":22,"user":"root","password":"hunter2","trust":{"fingerprint":"SHA256:x","algorithm":"a"},"name":"n","reality":true}"#,
        )
        .unwrap();
        assert!(!format!("{args:?}").contains("hunter2"));
    }

    #[test]
    fn unknown_ops_and_missing_fields_are_rejected_at_parse() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"explode"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"fingerprint","host":"h"}"#).is_err());
    }

    #[tokio::test]
    async fn dns_with_a_name_instead_of_an_address_is_unknown() {
        let out = events(r#"{"op":"dns","ns_host":"ns.example.com","server":"not-an-ip"}"#).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["t"], "done");
        assert_eq!(out[0]["status"], "unknown");
    }

    #[tokio::test]
    async fn the_dns_plan_cleans_the_domain_and_lists_two_records() {
        let out =
            events(r#"{"op":"dns_plan","domain":"https://T.Example.com/","server":"203.0.113.7"}"#)
                .await;
        assert_eq!(out[0]["domain"], "t.example.com");
        assert_eq!(out[0]["ns_host"], "ns.example.com");
        let records = out[0]["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["value"], "203.0.113.7");
        assert_eq!(records[1]["kind"], "NS");
        assert_eq!(out[0]["needs_ip"], false);
        let bad =
            events(r#"{"op":"dns_plan","domain":"example.com","server":"203.0.113.7"}"#).await;
        assert_eq!(bad[0]["ok"], false);
        assert!(bad[0]["error"].as_str().unwrap().contains("subdomain"));
    }

    #[tokio::test]
    async fn an_unreachable_server_ends_with_a_sentence() {
        // Port 1 on loopback refuses at once.
        let out = events(r#"{"op":"fingerprint","host":"127.0.0.1","port":1}"#).await;
        let last = out.last().unwrap();
        assert_eq!(
            (last["t"].as_str(), last["ok"].as_bool()),
            (Some("done"), Some(false))
        );
        assert!(
            last["error"]
                .as_str()
                .unwrap()
                .contains("127.0.0.1:1 refused"),
            "{last}"
        );
    }

    #[tokio::test]
    async fn a_bad_domain_stops_the_install_before_any_login() {
        let out = events(
            r#"{"op":"install","host":"127.0.0.1","port":1,"user":"root","password":"p","trust":{"fingerprint":"SHA256:x","algorithm":"a"},"name":"n","reality":false,"masterdns_domain":"example.com"}"#,
        )
        .await;
        let last = out.last().unwrap();
        assert_eq!(last["ok"], false);
        assert!(
            last["error"].as_str().unwrap().contains("subdomain"),
            "{last}"
        );
    }

    #[tokio::test]
    async fn configs_come_from_the_record() {
        let record = serde_json::json!({
            "version": 1, "id": "a", "name": "n", "host": "203.0.113.7", "ssh_port": 22,
            "ssh_user": "root", "host_key": {"fingerprint": "SHA256:x", "algorithm": "a"},
            "ssh_key": null, "os": "x", "zray_version": "1", "management_port": 1,
            "verified_download": true, "created": 0,
            "services": [{"kind": "reality", "tag": "reality", "port": 443, "sni": "www.microsoft.com",
                "public_key": "pk", "short_id": "ab", "users": [{"name": "Main", "id": "11111111-1111-4111-8111-111111111111"}]}]
        });
        let out = events(&json!({"op": "configs", "record": record}).to_string()).await;
        let configs = out[0]["configs"].as_array().unwrap();
        assert_eq!(configs.len(), 1);
        assert!(configs[0]["link"].as_str().unwrap().starts_with("vless://"));
    }

    #[tokio::test]
    async fn cancelling_ends_with_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let seen = Arc::new(Mutex::new(String::new()));
        let callback = {
            let seen = Arc::clone(&seen);
            Arc::new(move |batch: String| seen.lock().unwrap().push_str(&batch))
        };
        let (sink, flusher) = zero_discovery::events::batching_sink(callback);
        let request = Request::Fingerprint {
            host: "203.0.113.1".into(),
            port: 22,
        };
        let reason = run(request, sink.clone(), cancel).await;
        drop(sink);
        let _ = flusher.await;
        assert_eq!(reason, EndReason::Cancelled);
        assert!(seen.lock().unwrap().contains("cancelled"));
    }

    #[tokio::test]
    async fn an_install_needs_a_password_or_a_usable_key() {
        let install = |extra: &str| {
            format!(
                r#"{{"op":"install","host":"127.0.0.1","port":1,"user":"root",{extra}"trust":{{"fingerprint":"SHA256:x","algorithm":"a"}},"name":"n","reality":true}}"#
            )
        };
        let none = events(&install("")).await;
        assert!(none.last().unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("password or an SSH key"));
        // A public key (or anything that is not a private key) is explained before any connection.
        let public = events(&install(r#""private_key":"ssh-ed25519 AAAA user@host","#)).await;
        let error = public.last().unwrap()["error"].as_str().unwrap();
        assert!(error.contains("not a private key"), "{error}");
        assert!(
            !public.iter().any(|e| e["t"] == "step"),
            "no connection should be tried"
        );
    }

    #[test]
    fn the_key_and_its_passphrase_never_print() {
        let args: InstallArgs = serde_json::from_str(
            r#"{"host":"h","port":22,"user":"root","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----","key_passphrase":"hunter2","trust":{"fingerprint":"SHA256:x","algorithm":"a"},"name":"n","reality":true}"#,
        )
        .unwrap();
        let text = format!("{args:?}");
        assert!(!text.contains("BEGIN") && !text.contains("hunter2"));
    }
}
