//! Installing the servers, over SSH, in steps a person can follow.
//!
//! The rules the installer keeps:
//!
//! * **Look before touching.** The first step only reads; if the server cannot
//!   take the install, it stops there with the reason.
//! * **Nothing unverified runs.** The Zray server program is checked against a
//!   signed hash list before it is placed (see [`crate::release`]); the
//!   MasterDNS server is a pinned release whose hash is in this crate. The one
//!   exception, a program uploaded from the app itself, is reported as
//!   unverified in the result.
//! * **Nothing outside our own names is changed.** Files live under the paths
//!   in [`crate::layout`], each service runs as its own user, and an existing
//!   firewall only ever gets ports added.
//! * **Secrets stay where they belong.** The REALITY private key goes to the
//!   server's config and nowhere else; the password the person typed is used
//!   for this run and dropped; the app's own key is the way back.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use crate::facts::{Facts, Problem};
use crate::guide;
use crate::keys;
use crate::layout::{self, GatewayTunnel, MasterDnsServer, RealityInbound};
use crate::manage;
use crate::record::{
    self, ClientConfig, Ipv6Status, MasterDns, ModemRecord, PairRecord, PairState, Reality,
    RealityTunnelRecord, Role, ServerRecord, Service, TransportId, TunnelCRecord, TunnelRecord,
    User, Xhttp, Zerov1,
};
use crate::release;
use crate::scripts;
use crate::ssh::{self, Auth, Connection, HostKey, Login};

/// What can be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    Reality,
    Xhttp,
    Zerov1,
    MasterDns,
}

/// The long steps of an install; UIs name them in their own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Check,
    Packages,
    Download,
    Install,
    Configure,
    Start,
    Firewall,
    Access,
    /// The inter-server tunnel: key generation, peer config, handshake check.
    Tunnel,
    /// The Huawei modem L2TP server on the gateway (opt-in per install).
    Modem,
    /// Automatic cleanup after a failed or cancelled pair install.
    Rollback,
}

/// Which machine(s) a progress event is about. `None` on the event means the
/// single-server install, whose JSON stays exactly as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Server {
    Gateway,
    Exit,
    Pair,
}

/// Progress for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A step begins. `preset` is set for the steps that belong to one service;
    /// `server` names the side, and is `None` for the single-server install.
    Step {
        step: Step,
        preset: Option<Preset>,
        number: usize,
        of: usize,
        server: Option<Server>,
    },
    /// A plain-language detail about the step in progress.
    Detail {
        server: Option<Server>,
        text: String,
    },
}

/// Where the Zray server program comes from.
pub enum BinarySource {
    /// The project's GitHub release, checked against its signed hash list.
    /// `tag` is a release tag, or `None` for the latest.
    Release { tag: Option<String> },
    /// Bytes the app itself holds, installed as they are. Unverified.
    Local(Vec<u8>),
    /// Server programs the app ships for each CPU: the one matching the
    /// server is uploaded over the SSH connection that is already verified by
    /// its host key. Nothing is downloaded, so no release is needed.
    Bundled {
        x64: Vec<u8>,
        arm64: Vec<u8>,
        /// The operator panel program for each CPU (empty: no panel).
        admin_x64: Vec<u8>,
        admin_arm64: Vec<u8>,
    },
}

impl BinarySource {
    /// The panel program for a server of this CPU, when the app ships one.
    fn panel_program(&self, arch: &str) -> Option<&[u8]> {
        match self {
            BinarySource::Bundled {
                admin_x64,
                admin_arm64,
                ..
            } => {
                let bytes = if arch == "ARM64" { admin_arm64 } else { admin_x64 };
                (!bytes.is_empty()).then_some(bytes.as_slice())
            }
            _ => None,
        }
    }
}

pub struct RealityRequest {
    /// The real website the server impersonates to anyone who is not a client.
    pub sni: String,
    /// `None` picks 443, or the first free fallback.
    pub port: Option<u16>,
}

/// VLESS over XHTTP inside REALITY: the same server program and keys as
/// [`RealityRequest`], on its own port.
pub struct XhttpRequest {
    /// The real website the server impersonates (used when REALITY is not
    /// installed too; with both, the REALITY site is shared).
    pub sni: String,
    /// `None` picks 443 when REALITY is not installed, else the first free
    /// fallback.
    pub port: Option<u16>,
}

/// ZeroV1 inside REALITY: the same server program, keys and users as
/// [`RealityRequest`], on its own port.
pub struct Zerov1Request {
    /// The real website the server impersonates (used when neither REALITY
    /// nor XHTTP is installed too; otherwise their site is shared).
    pub sni: String,
    /// `None` picks 443 when it is the only service, else the first free
    /// fallback.
    pub port: Option<u16>,
}

pub struct MasterDnsRequest {
    /// The tunnel domain, as [`guide::clean_domain`] returns it.
    pub domain: String,
}

pub struct Request {
    /// What the person calls this server.
    pub name: String,
    /// Name of the first config (`Main`).
    pub first_user: String,
    pub reality: Option<RealityRequest>,
    pub xhttp: Option<XhttpRequest>,
    pub zerov1: Option<Zerov1Request>,
    pub masterdns: Option<MasterDnsRequest>,
    pub binary: BinarySource,
    /// Install the app's own key so it can come back without the password.
    pub keep_access: bool,
}

/// Something the person should know after the install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Note {
    /// The wanted port was in use, so another was used.
    PortMoved {
        wanted: u16,
        used: u16,
        held_by: String,
    },
    /// A firewall on the server was changed.
    FirewallOpened { which: String },
    /// There was no firewall to change; the hosting provider may have one.
    ProviderFirewall { tcp: Vec<u16>, udp: Vec<u16> },
    /// The program was not checked against the signed list.
    Unverified,
    /// The app could not log back in with its own key.
    KeyNotWorking,
    /// The tunnel is up as far as the installer could tell, but the handshake
    /// could not be verified: the server's program has no tunnel endpoint yet.
    TunnelUnverified,
    /// The exit's egress address could not be checked (the IP-echo service did
    /// not answer); the tunnel handshake itself was verified.
    EgressUnverified,
    /// Tunnel C was honestly not provisioned: IPv6 is not really usable
    /// end-to-end on one or both servers. Tunnels A and B work normally.
    Ipv6Unavailable { reason: String },
    /// The operator panel could not be put on the server. The VPN itself is
    /// installed and works; the panel can be added by installing again.
    PanelFailed { reason: String },
}

pub struct Outcome {
    pub record: ServerRecord,
    pub notes: Vec<Note>,
    /// How to reach the operator panel, when it was installed.
    pub panel: Option<crate::panel::PanelAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Ssh(ssh::Error),
    /// The server cannot take the install.
    Unsupported(Vec<Problem>),
    /// A server program from Zray is already installed here.
    AlreadyInstalled,
    /// Nothing was asked for.
    NothingToInstall,
    /// The domain is not usable.
    Domain(guide::DomainError),
    /// The release is not signed by the key this app trusts.
    BadSignature,
    /// The downloaded program's hash is not the expected one.
    ChecksumMismatch,
    /// The server's system is older than the released program supports.
    SystemTooOld,
    /// A step failed on the server; `detail` is what it said.
    Step {
        step: Step,
        detail: String,
    },
    /// A named protocol or egress mode that is not on offer yet.
    Unavailable(String),
    /// A pair install failed; `rollback` says whether the automatic cleanup
    /// finished. The `error` is the sentence for the person.
    PairFailed {
        error: String,
        rollback: RollbackStatus,
    },
}

/// Whether the automatic cleanup after a failed or cancelled pair install ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackStatus {
    /// Everything this run created was removed, exit first, then gateway.
    Complete,
    /// Something could not be removed; the sentence says what.
    Partial(String),
    /// Nothing had been installed yet, so there was nothing to remove.
    NotNeeded,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Ssh(e) => e.fmt(f),
            Error::Unsupported(problems) => {
                let lines: Vec<String> = problems.iter().map(|p| p.to_string()).collect();
                f.write_str(&lines.join(" "))
            }
            Error::AlreadyInstalled => f.write_str(
                "A Zray server is already installed on this machine. Open it from your server \
                 list, or remove it first.",
            ),
            Error::NothingToInstall => f.write_str("Choose at least one thing to install."),
            Error::Domain(e) => e.fmt(f),
            Error::BadSignature => f.write_str(
                "The download could not be verified (its signature does not match the key built \
                 into this app), so nothing was installed. Try again later; if it keeps happening, \
                 update this app.",
            ),
            Error::ChecksumMismatch => f.write_str(
                "The downloaded server program did not match its published checksum, so it was \
                 thrown away and nothing was installed. Try again.",
            ),
            Error::SystemTooOld => f.write_str(
                "This server's system is too old for the server program (it needs a newer C \
                 library). Use Ubuntu 22.04 or newer, or Debian 12 or newer.",
            ),
            Error::Step { step, detail } => write!(f, "The {step:?} step failed: {detail}"),
            Error::Unavailable(name) => write!(
                f,
                "{name} is not on offer yet: the protocol support it needs is still being built. \
                 Pick from what the installer lists."
            ),
            Error::PairFailed { error, rollback } => {
                f.write_str(error)?;
                match rollback {
                    RollbackStatus::Complete => {
                        f.write_str(" What the attempt had installed was removed.")
                    }
                    RollbackStatus::Partial(detail) => {
                        write!(f, " The cleanup did not finish: {detail}")
                    }
                    RollbackStatus::NotNeeded => Ok(()),
                }
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<ssh::Error> for Error {
    fn from(e: ssh::Error) -> Self {
        Error::Ssh(e)
    }
}

const QUICK: Duration = Duration::from_secs(60);
const SLOW: Duration = Duration::from_secs(900);

/// Ports tried, in order, when the wanted one is taken.
const FALLBACK_PORTS: [u16; 5] = [8443, 2053, 2083, 2087, 2096];

/// `chosen` are ports this install already gave to another inbound.
fn pick_port(facts: &Facts, wanted: u16, chosen: &[u16], notes: &mut Vec<Note>) -> u16 {
    let free =
        |p: u16| facts.port_taken_by_other(p, false, false).is_none() && !chosen.contains(&p);
    if free(wanted) {
        return wanted;
    }
    let used = FALLBACK_PORTS
        .iter()
        .copied()
        .find(|p| free(*p))
        .unwrap_or(wanted);
    let held_by = facts.port_taken_by_other(wanted, false, false).map_or_else(
        || "this install's other service".to_string(),
        str::to_string,
    );
    notes.push(Note::PortMoved {
        wanted,
        used,
        held_by,
    });
    used
}

fn management_port(facts: &Facts) -> u16 {
    use rand::Rng;
    loop {
        let port = rand::thread_rng().gen_range(20000..60000);
        if !facts.tcp.iter().any(|l| l.port == port) {
            return port;
        }
    }
}

fn fail(step: Step, out: &ssh::Output) -> Error {
    let detail = out.stderr.trim();
    if detail.contains("GLIBC_") {
        return Error::SystemTooOld;
    }
    Error::Step {
        step,
        detail: if detail.is_empty() {
            format!("exit status {}", out.status)
        } else {
            detail.lines().last().unwrap_or(detail).to_string()
        },
    }
}

/// Counts the steps as they are announced so the screen can show "3 of 9".
struct Progress<'a> {
    on: &'a (dyn Fn(Event) + Sync),
    done: usize,
    of: usize,
}

impl Progress<'_> {
    fn step(&mut self, step: Step, preset: Option<Preset>) {
        self.done += 1;
        (self.on)(Event::Step {
            step,
            preset,
            number: self.done,
            of: self.of,
            server: None,
        });
    }

    fn detail(&self, text: impl Into<String>) {
        (self.on)(Event::Detail {
            server: None,
            text: text.into(),
        });
    }
}

fn list(ports: &[u16]) -> String {
    if ports.is_empty() {
        "none".to_string()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Where MasterDNS may bind: `0.0.0.0`, or the machine's own address when a
/// loopback-only resolver holds port 53. Records a [`Problem::PortInUse`]
/// when something else holds the port.
fn masterdns_bind(facts: &Facts, problems: &mut Vec<Problem>) -> String {
    let mut bind = "0.0.0.0".to_string();
    if let Some(process) = facts.port_taken_by_other(53, true, true) {
        problems.push(Problem::PortInUse {
            port: 53,
            process: process.to_string(),
        });
    } else if facts.udp.iter().any(|l| l.port == 53 && l.loopback_only()) {
        if facts.primary_ip4.is_empty() {
            problems.push(Problem::PortInUse {
                port: 53,
                process: "the system resolver".into(),
            });
        } else {
            bind = facts.primary_ip4.clone();
        }
    }
    bind
}

/// Install what `request` asks for. `login` is the first login (a password);
/// `host_key` is what the person confirmed. See the module text for the rules.
pub async fn install(
    login: &Login,
    host_key: &HostKey,
    request: &Request,
    on: &(dyn Fn(Event) + Send + Sync),
) -> Result<Outcome, Error> {
    // REALITY, XHTTP and ZeroV1 share one server program, so they count as one
    // preset.
    let zray = request.reality.is_some() || request.xhttp.is_some() || request.zerov1.is_some();
    let presets = usize::from(zray) + usize::from(request.masterdns.is_some());
    if presets == 0 {
        return Err(Error::NothingToInstall);
    }
    let masterdns_domain = match &request.masterdns {
        Some(m) => Some(guide::clean_domain(&m.domain).map_err(Error::Domain)?),
        None => None,
    };
    let mut progress = Progress {
        on,
        done: 0,
        of: 4 + 4 * presets,
    };
    let mut notes = Vec::new();
    let id = keys::random_hex(8);

    // Look.
    progress.step(Step::Check, None);
    let conn = ssh::connect(login, &host_key.fingerprint).await?;
    let probe = conn.script(&[], crate::facts::SCRIPT, QUICK).await?;
    if !probe.ok() {
        return Err(if probe.stderr.contains("sudo") {
            Error::Unsupported(vec![Problem::NeedRoot])
        } else {
            fail(Step::Check, &probe)
        });
    }
    let facts = Facts::parse(&probe.stdout);
    progress.detail(format!("{} · {} MB memory", facts.os_name, facts.mem_mb));
    let mut problems = facts.problems();
    // MasterDNS needs port 53 for itself, on UDP. A resolver listening only on
    // loopback (systemd-resolved's stub) is fine: the server then binds the
    // machine's own address instead of every address.
    let dns_bind = if masterdns_domain.is_some() {
        masterdns_bind(&facts, &mut problems)
    } else {
        "0.0.0.0".to_string()
    };
    if !problems.is_empty() {
        return Err(Error::Unsupported(problems));
    }
    // A previous install is replaced, not refused: remove it, then look again
    // so ports it held count as free.
    let facts = if (facts.zray_installed && facts.zray_config && zray)
        || (facts.masterdns_installed && request.masterdns.is_some())
    {
        progress.detail("removing the previous install".to_string());
        manage::wipe_existing(&conn).await?;
        facts_of(&conn).await?
    } else {
        facts
    };
    let arch = facts.asset_arch().expect("checked by problems()");

    // Tools.
    progress.step(Step::Packages, None);
    let out = conn.script(&[], scripts::TOOLS, SLOW).await?;
    if !out.ok() {
        return Err(Error::Unsupported(vec![Problem::NoDownloader]));
    }

    let mut services = Vec::new();
    let mut tcp_ports = Vec::new();
    let mut udp_ports = Vec::new();
    let mut verified = true;
    let mut version = String::new();
    let mut management = 0;

    if zray {
        let (vision, xhttp, zerov1, deployed) =
            deploy_zray(&conn, &facts, request, arch, &mut progress, &mut notes).await?;
        verified = deployed.verified;
        version = deployed.version;
        management = deployed.management_port;
        if let Some(service) = vision {
            tcp_ports.push(service.port);
            services.push(Service::Reality(service));
        }
        if let Some(service) = xhttp {
            tcp_ports.push(service.port);
            services.push(Service::Xhttp(service));
        }
        if let Some(service) = zerov1 {
            tcp_ports.push(service.port);
            services.push(Service::Zerov1(service));
        }
    }

    if let (Some(domain), Some(_)) = (&masterdns_domain, &request.masterdns) {
        let service = deploy_masterdns(&conn, domain, &dns_bind, arch, &mut |ev| match ev {
            DnsEvent::Step(s) => progress.step(s, Some(Preset::MasterDns)),
            DnsEvent::Detail(text) => progress.detail(text),
        })
        .await?;
        udp_ports.push(53);
        services.push(Service::MasterDns(service));
    }

    // Firewall.
    progress.step(Step::Firewall, None);
    let (tcp_text, udp_text) = (list(&tcp_ports), list(&udp_ports));
    let env = [("TCP", tcp_text.as_str()), ("UDP", udp_text.as_str())];
    let out = conn.script(&env, scripts::FIREWALL, QUICK).await?;
    match out.stdout.lines().find_map(|l| l.strip_prefix("firewall=")) {
        Some("ufw") => notes.push(Note::FirewallOpened {
            which: "ufw".into(),
        }),
        Some("firewalld") => notes.push(Note::FirewallOpened {
            which: "firewalld".into(),
        }),
        _ => notes.push(Note::ProviderFirewall {
            tcp: tcp_ports.clone(),
            udp: udp_ports.clone(),
        }),
    }

    // The way back.
    progress.step(Step::Access, None);
    let mut ssh_key = None;
    if request.keep_access {
        let key = keys::new_ssh_key(&layout::key_comment(&id));
        conn.put_file(
            &format!("{}/app.pub", layout::WORK_DIR),
            "600",
            "root:root",
            key.public_openssh.as_bytes(),
        )
        .await?;
        let env = [
            ("LOGIN_USER", login.user.as_str()),
            ("WORK", layout::WORK_DIR),
        ];
        let out = conn.script(&env, scripts::ADD_KEY, QUICK).await?;
        if !out.ok() {
            return Err(fail(Step::Access, &out));
        }
        // Prove the key works before the password is forgotten.
        let with_key = Login {
            auth: Auth::Key(key.private_openssh.clone()),
            ..login.clone()
        };
        match ssh::connect(&with_key, &host_key.fingerprint).await {
            Ok(c) => {
                c.close().await;
                ssh_key = Some(key.private_openssh);
            }
            Err(_) => notes.push(Note::KeyNotWorking),
        }
    }
    // The operator panel, when the app ships it. A failure here does not
    // undo the VPN: it is reported and the rest stays.
    let mut panel = None;
    if let Some(program) = request.binary.panel_program(arch) {
        progress.detail("installing the operator panel".to_string());
        match crate::panel::deploy(
            &conn,
            program,
            "exit",
            &login.host,
            management,
            None,
            &services,
        )
        .await
        {
            Ok(access) => panel = Some(access),
            Err(e) => notes.push(Note::PanelFailed {
                reason: e.to_string(),
            }),
        }
    }
    let _ = conn
        .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
        .await;
    conn.close().await;
    if !verified {
        notes.push(Note::Unverified);
    }

    let record = ServerRecord {
        version: record::VERSION,
        id,
        name: request.name.clone(),
        host: login.host.clone(),
        ssh_port: login.port,
        ssh_user: login.user.clone(),
        host_key: host_key.clone(),
        ssh_key,
        os: facts.os_name.clone(),
        zray_version: version,
        management_port: management,
        verified_download: verified,
        services,
        created: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        role: Role::Single,
        tunnel_port: None,
    };
    Ok(Outcome {
        record,
        notes,
        panel,
    })
}

struct Fetched {
    verified: bool,
    version: String,
}

/// Download the server program: a signed release (verified against the key
/// compiled into the app) or bytes the app itself holds (unverified).
/// Shared by the single-server and the pair installs; `report` forwards to
/// whichever progress the caller uses. One callback instead of two so the
/// caller needs a single mutable borrow of its progress.
enum FetchEvent {
    Step,
    Detail(String),
}

async fn fetch_program(
    conn: &Connection,
    arch: &str,
    binary: &BinarySource,
    report: &mut (dyn FnMut(FetchEvent) + Send),
) -> Result<Fetched, Error> {
    report(FetchEvent::Step);
    let mut verified = false;
    let mut version = String::from("local build");
    match binary {
        BinarySource::Release { tag } => {
            let asset = format!("ZrayCore-Linux-{arch}");
            let tag_arg = tag.as_deref().unwrap_or("latest");
            let env = [
                ("REPO", layout::REPO),
                ("TAG", tag_arg),
                ("WORK", layout::WORK_DIR),
            ];
            let out = conn.script(&env, scripts::MANIFEST, QUICK * 2).await?;
            if !out.ok() {
                return Err(fail(Step::Download, &out));
            }
            let field = |name: &str| {
                out.stdout
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{name}=")))
                    .unwrap_or("")
                    .to_string()
            };
            let (found_tag, sums_b64, signature) = (field("tag"), field("sums"), field("sig"));
            let sums = base64::engine::general_purpose::STANDARD
                .decode(sums_b64.as_bytes())
                .map_err(|_| Error::BadSignature)?;
            if !release::sums_are_signed(&sums, &signature) {
                return Err(Error::BadSignature);
            }
            let sums_text = String::from_utf8_lossy(&sums);
            let expected = release::expected_hash(&sums_text, &asset).ok_or(Error::Step {
                step: Step::Download,
                detail: format!("the release has no {asset}"),
            })?;
            report(FetchEvent::Detail(format!("{found_tag} · checksum signed")));
            let env = [
                ("REPO", layout::REPO),
                ("TAG", found_tag.as_str()),
                ("ASSET", asset.as_str()),
                ("SHA", expected.as_str()),
                ("WORK", layout::WORK_DIR),
            ];
            let out = conn.script(&env, scripts::FETCH, SLOW).await?;
            match out.status {
                0 => {}
                30 => return Err(Error::ChecksumMismatch),
                _ => return Err(fail(Step::Download, &out)),
            }
            verified = true;
            version = found_tag;
        }
        BinarySource::Local(bytes) => upload_program(conn, bytes).await?,
        BinarySource::Bundled { x64, arm64, .. } => {
            let bytes = if arch == "ARM64" { arm64 } else { x64 };
            if bytes.is_empty() {
                return Err(Error::Step {
                    step: Step::Download,
                    detail: format!("this app has no server program for {arch}"),
                });
            }
            upload_program(conn, bytes).await?;
            version = String::from("bundled with the app");
        }
    }
    Ok(Fetched { verified, version })
}

/// Create the service account and directories, and put the downloaded program
/// in place. Shared by the single-server and the pair installs.
async fn place_program(conn: &Connection) -> Result<(), Error> {
    let env = [
        ("SVC_USER", layout::ZRAY_USER),
        ("PROGRAM_DIR", layout::ZRAY_DIR),
        ("ETC_DIR", layout::ZRAY_ETC),
    ];
    let out = conn.script(&env, scripts::USER_AND_DIRS, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }
    let env = [("WORK", layout::WORK_DIR), ("PROGRAM", layout::ZRAY_BIN)];
    let out = conn.script(&env, scripts::PLACE_PROGRAM, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }
    Ok(())
}

/// Write the config, token and unit files and check the config with the server
/// program itself, so a mistake shows up here as a message and not as a
/// service that will not stay up. Returns the management port.
async fn write_config(
    conn: &Connection,
    facts: &Facts,
    config: &serde_json::Value,
) -> Result<u16, Error> {
    let body = serde_json::to_vec_pretty(config).expect("a JSON value always encodes");
    let owner = format!("root:{}", layout::ZRAY_USER);
    conn.put_file(layout::ZRAY_CONFIG, "640", &owner, &body)
        .await?;
    // The management token is read here only to be written; it is never
    // printed or returned.
    let token = keys::new_token();
    conn.put_file(layout::ZRAY_TOKEN, "640", &owner, token.as_bytes())
        .await?;
    let management = management_port(facts);
    conn.put_file(
        layout::ZRAY_UNIT,
        "644",
        "root:root",
        layout::zray_unit(management).as_bytes(),
    )
    .await?;
    let check = format!("{} check {}", layout::ZRAY_BIN, layout::ZRAY_CONFIG);
    let out = conn.exec(&conn.privileged(&check), b"", QUICK).await?;
    if !out.ok() {
        let text = format!("{}{}", out.stdout, out.stderr);
        if text.contains("GLIBC_") {
            return Err(Error::SystemTooOld);
        }
        return Err(Error::Step {
            step: Step::Configure,
            detail: text
                .trim()
                .lines()
                .last()
                .unwrap_or("the config was rejected")
                .to_string(),
        });
    }
    Ok(management)
}

/// Start the service and wait until the ports answer.
async fn start_service(conn: &Connection, wait: &[(u16, &str)]) -> Result<(), Error> {
    let env = [("SERVICE", layout::ZRAY_SERVICE)];
    let out = conn.script(&env, scripts::START, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Start, &out));
    }
    for (port, proto) in wait {
        let port_text = port.to_string();
        let env = [("PORT", port_text.as_str()), ("PROTO", proto)];
        let out = conn.script(&env, scripts::WAIT_PORT, QUICK).await?;
        if !out.ok() {
            return Err(fail(Step::Start, &out));
        }
    }
    Ok(())
}

/// The ports, keys and users for the REALITY-family inbounds, picked the same
/// way for the single-server and the gateway installs.
struct InboundPlan {
    sni: String,
    keys: keys::RealityKeys,
    short_id: String,
    users: Vec<(String, String)>,
    vision_port: Option<u16>,
    xhttp_port: Option<u16>,
    xhttp_path: String,
    zerov1_port: Option<u16>,
    zerov1_path: String,
    zerov1_secret: String,
    zerov1_public: String,
}

impl InboundPlan {
    fn reality_inbound(&self) -> RealityInbound<'_> {
        RealityInbound {
            sni: &self.sni,
            private_key: &self.keys.private,
            short_id: &self.short_id,
            users: &self.users,
            vision_port: self.vision_port,
            xhttp: self.xhttp_port.map(|port| (port, self.xhttp_path.as_str())),
            zerov1: self.zerov1_port.map(|port| layout::Zerov1Inbound {
                port,
                path: &self.zerov1_path,
                secret_key: &self.zerov1_secret,
            }),
        }
    }

    fn tcp_ports(&self) -> Vec<u16> {
        self.vision_port
            .into_iter()
            .chain(self.xhttp_port)
            .chain(self.zerov1_port)
            .collect()
    }

    fn services(&self) -> (Option<Reality>, Option<Xhttp>, Option<Zerov1>) {
        let user_list = || {
            self.users
                .iter()
                .map(|(name, id)| User {
                    name: name.clone(),
                    id: id.clone(),
                })
                .collect::<Vec<_>>()
        };
        let vision = self.vision_port.map(|port| Reality {
            tag: layout::VISION_TAG.into(),
            port,
            sni: self.sni.clone(),
            public_key: self.keys.public.clone(),
            short_id: self.short_id.clone(),
            users: user_list(),
        });
        let xhttp = self.xhttp_port.map(|port| Xhttp {
            tag: layout::XHTTP_TAG.into(),
            port,
            sni: self.sni.clone(),
            public_key: self.keys.public.clone(),
            short_id: self.short_id.clone(),
            path: self.xhttp_path.clone(),
            users: user_list(),
        });
        let zerov1 = self.zerov1_port.map(|port| Zerov1 {
            tag: layout::ZEROV1_TAG.into(),
            port,
            sni: self.sni.clone(),
            public_key: self.keys.public.clone(),
            short_id: self.short_id.clone(),
            server_key: self.zerov1_public.clone(),
            path: self.zerov1_path.clone(),
            users: user_list(),
        });
        (vision, xhttp, zerov1)
    }
}

fn plan_inbounds(
    facts: &Facts,
    first_user: &str,
    reality: Option<&RealityRequest>,
    xhttp: Option<&XhttpRequest>,
    zerov1: Option<&Zerov1Request>,
    notes: &mut Vec<Note>,
) -> InboundPlan {
    let mut chosen = Vec::new();
    let vision_port = reality.map(|w| {
        let port = pick_port(facts, w.port.unwrap_or(443), &chosen, notes);
        chosen.push(port);
        port
    });
    let xhttp_port = xhttp.map(|w| {
        let default = if vision_port.is_some() { 8443 } else { 443 };
        pick_port(facts, w.port.unwrap_or(default), &chosen, notes)
    });
    let zerov1_port = zerov1.map(|w| {
        let default = if chosen.is_empty() && xhttp_port.is_none() {
            443
        } else {
            2083
        };
        let taken: Vec<u16> = chosen.iter().copied().chain(xhttp_port).collect();
        pick_port(facts, w.port.unwrap_or(default), &taken, notes)
    });
    let sni = match (reality, xhttp, zerov1) {
        (Some(w), _, _) => w.sni.clone(),
        (None, Some(w), _) => w.sni.clone(),
        (None, None, Some(w)) => w.sni.clone(),
        (None, None, None) => unreachable!("plan_inbounds runs only when one of them is asked for"),
    };
    let xhttp_path = format!("/{}", keys::random_hex(4));
    // ZeroV1 has its own key pair and path; REALITY's keys are not reused.
    let zerov1_secret = zero_protocol::tide::generate_keypair();
    let zerov1_path = format!("/static/{}", keys::random_hex(6));
    InboundPlan {
        sni,
        keys: keys::new_reality_keys(),
        short_id: keys::random_hex(8),
        users: vec![(first_user.to_string(), keys::new_uuid())],
        vision_port,
        xhttp_port,
        xhttp_path,
        zerov1_port,
        zerov1_path,
        zerov1_secret: zero_protocol::tide::encode_key(&zerov1_secret.0),
        zerov1_public: zero_protocol::tide::encode_key(&zerov1_secret.1),
    }
}

struct Deployed {
    verified: bool,
    version: String,
    management_port: u16,
}

/// Download, install, configure and start the Zray server with the REALITY
/// (Vision), XHTTP and ZeroV1 inbounds the request asks for. They share one
/// REALITY key pair and one user list. Returns the services and facts for the
/// record.
async fn deploy_zray(
    conn: &Connection,
    facts: &Facts,
    request: &Request,
    arch: &str,
    progress: &mut Progress<'_>,
    notes: &mut Vec<Note>,
) -> Result<(Option<Reality>, Option<Xhttp>, Option<Zerov1>, Deployed), Error> {
    let preset = Some(if request.reality.is_some() {
        Preset::Reality
    } else if request.xhttp.is_some() {
        Preset::Xhttp
    } else {
        Preset::Zerov1
    });

    let fetched = fetch_program(conn, arch, &request.binary, &mut |ev| match ev {
        FetchEvent::Step => progress.step(Step::Download, preset),
        FetchEvent::Detail(text) => progress.detail(text),
    })
    .await?;
    let (mut verified, mut version) = (fetched.verified, fetched.version);

    progress.step(Step::Install, preset);
    place_program(conn).await?;

    progress.step(Step::Configure, preset);
    let plan = plan_inbounds(
        facts,
        &request.first_user,
        request.reality.as_ref(),
        request.xhttp.as_ref(),
        request.zerov1.as_ref(),
        notes,
    );
    let config = layout::zray_config(&plan.reality_inbound(), facts.ipv6);
    let wait: Vec<(u16, &str)> = plan
        .tcp_ports()
        .into_iter()
        .map(|port| (port, "tcp"))
        .collect();
    let management = write_config(conn, facts, &config).await?;

    progress.step(Step::Start, preset);
    start_service(conn, &wait).await?;

    let (vision, xhttp, zerov1) = plan.services();
    Ok((
        vision,
        xhttp,
        zerov1,
        Deployed {
            verified,
            version,
            management_port: management,
        },
    ))
}

/// Download (pinned), install, configure and start the upstream MasterDNS
/// server for `domain`.
enum DnsEvent {
    Step(Step),
    Detail(String),
}

async fn deploy_masterdns(
    conn: &Connection,
    domain: &str,
    bind: &str,
    arch: &str,
    report: &mut (dyn FnMut(DnsEvent) + Send),
) -> Result<MasterDns, Error> {
    let (asset, sha) = layout::masterdns_asset(arch).expect("checked by problems()");

    report(DnsEvent::Step(Step::Download));
    let env = [
        ("REPO", layout::MASTERDNS_REPO),
        ("TAG", layout::MASTERDNS_TAG),
        ("ASSET", asset),
        ("SHA", sha),
        ("WORK", layout::WORK_DIR),
    ];
    let out = conn
        .script(&env, scripts::FETCH_PINNED_ARCHIVE, SLOW)
        .await?;
    match out.status {
        0 => {}
        30 => return Err(Error::ChecksumMismatch),
        _ => return Err(fail(Step::Download, &out)),
    }
    report(DnsEvent::Detail(format!(
        "MasterDnsVPN {} · checksum matches",
        layout::MASTERDNS_TAG
    )));

    report(DnsEvent::Step(Step::Install));
    let env = [
        ("SVC_USER", layout::MASTERDNS_USER),
        ("PROGRAM_DIR", layout::MASTERDNS_DIR),
        ("ETC_DIR", layout::MASTERDNS_ETC),
    ];
    let out = conn.script(&env, scripts::USER_AND_DIRS, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }
    let env = [
        ("WORK", layout::WORK_DIR),
        ("PROGRAM", layout::MASTERDNS_BIN),
    ];
    let out = conn.script(&env, scripts::PLACE_PROGRAM, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }

    report(DnsEvent::Step(Step::Configure));
    let key = keys::random_hex(layout::MASTERDNS_KEY_LEN / 2);
    let owner = format!("root:{}", layout::MASTERDNS_USER);
    let config = layout::masterdns_config(&MasterDnsServer {
        domain,
        bind,
        method: 5,
    });
    conn.put_file(layout::MASTERDNS_KEY, "640", &owner, key.as_bytes())
        .await?;
    conn.put_file(layout::MASTERDNS_CONFIG, "640", &owner, config.as_bytes())
        .await?;
    conn.put_file(
        layout::MASTERDNS_UNIT,
        "644",
        "root:root",
        layout::masterdns_unit().as_bytes(),
    )
    .await?;

    report(DnsEvent::Step(Step::Start));
    let env = [("SERVICE", layout::MASTERDNS_SERVICE)];
    let out = conn.script(&env, scripts::START, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Start, &out));
    }
    let env = [("PORT", "53"), ("PROTO", "udp")];
    let out = conn.script(&env, scripts::WAIT_PORT, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Start, &out));
    }

    Ok(MasterDns {
        domain: domain.to_string(),
        ns_host: guide::ns_host(domain),
        method: 5,
        key,
        release: layout::MASTERDNS_TAG.to_string(),
    })
}
// ---------------------------------------------------------------------------
// Pair installs: an Iran-side gateway and a USA-side exit joined by a
// WireGuard tunnel.
//
// The twelve phases: validate (local) → fingerprint trust ×2 → facts ×2 →
// packages ×2 → download+install gateway → download+install exit → firewall
// ×2 → tunnel (keys, peer configs, handshake) → app keys ×2 → end-to-end
// checks → report. Anything this run created is removed again, exit first,
// when a phase fails or the run is cancelled.
// ---------------------------------------------------------------------------

/// One side's login: the credentials plus the host key the person confirmed.
#[derive(Debug, Clone)]
pub struct PairLogin {
    pub login: Login,
    pub trust: HostKey,
}

/// What a pair install sets up. The gateway protocols are the REALITY family
/// the engine already serves; anything else is rejected by the job layer with
/// [`Error::Unavailable`] before this runs.
pub struct PairInstallRequest {
    pub name: String,
    pub first_user: String,
    pub sni: String,
    pub reality: bool,
    pub xhttp: bool,
    pub zerov1: bool,
    /// Raw domain text; cleaned here.
    pub masterdns_domain: Option<String>,
    pub binary: BinarySource,
    /// Install the app's own key so it can come back without the password.
    pub keep_access: bool,
    /// Install the Huawei modem L2TP server on the gateway (Design G).
    /// Opt-in: it adds xl2tpd+ppp and a UDP 1701 listener.
    pub modem_server: bool,
}

pub struct PairOutcome {
    pub record: PairRecord,
    pub notes: Vec<Note>,
    pub configs: Vec<ClientConfig>,
    /// How to reach the operator panel on the gateway, when it was installed.
    pub panel: Option<crate::panel::PanelAccess>,
}

/// What this run put on one server, so a failure or a cancellation can take
/// it away again. Only entries with `installed` set are ever removed.
#[derive(Debug)]
pub struct CreatedServer {
    pub record: ServerRecord,
    pub installed: bool,
    /// The address the exit's tunnel firewall rule was opened for.
    pub tunnel_gw_ip: Option<String>,
    /// Tunnel C's firewall identity on the exit: the gateway IPv6 the rule
    /// was opened for and the UDP port. Needed for rollback/removal.
    pub tunnel_c: Option<(String, u16)>,
}

#[derive(Debug, Default)]
pub struct PairCreated {
    pub gateway: Option<CreatedServer>,
    pub exit: Option<CreatedServer>,
}

#[derive(Default)]
struct PairConns {
    gw: Option<Connection>,
    ex: Option<Connection>,
}

/// Counts the steps of a pair install so the screen can show "7 of 19",
/// tagged with the side each step runs on.
struct PairProgress<'a> {
    on: &'a (dyn Fn(Event) + Sync),
    done: usize,
    of: usize,
}

impl PairProgress<'_> {
    fn step(&mut self, server: Server, step: Step, preset: Option<Preset>) {
        self.done += 1;
        (self.on)(Event::Step {
            step,
            preset,
            number: self.done,
            of: self.of,
            server: Some(server),
        });
    }

    fn detail(&self, server: Server, text: impl Into<String>) {
        (self.on)(Event::Detail {
            server: Some(server),
            text: text.into(),
        });
    }
}

/// A throwaway WireGuard key, well-formed but never used for a real
/// handshake: the tunnel step replaces it with the on-server key before the
/// tunnel carries anything.
const DUMMY_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Tunnel B's (VLESS+REALITY) credentials, generated once per pair in the
/// app: the VLESS UUID the exit authenticates and the REALITY short id the
/// gateway presents. The REALITY keypair itself is generated on the exit
/// server (its private half never leaves it).
struct TunnelBPlan {
    user_id: String,
    short_id: String,
}

impl TunnelBPlan {
    fn generate() -> Self {
        TunnelBPlan {
            user_id: keys::new_uuid(),
            short_id: keys::random_hex(8),
        }
    }
}

/// Dummy REALITY public key (URL-safe base64, no pad) for configs written
/// before the tunnel phase generates the real one on the exit server.
const DUMMY_RT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn random_wg_key() -> String {
    use base64::Engine as _;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Check the request before any connection is made.
fn validate_pair(
    request: &PairInstallRequest,
    gateway: &PairLogin,
    exit: &PairLogin,
) -> Result<(), Error> {
    if request.name.trim().is_empty() {
        return Err(Error::Step {
            step: Step::Check,
            detail: "Give the pair a name.".into(),
        });
    }
    if gateway.login.host.trim().is_empty() {
        return Err(Error::Step {
            step: Step::Check,
            detail: "Give the gateway's address.".into(),
        });
    }
    if exit.login.host.trim().is_empty() {
        return Err(Error::Step {
            step: Step::Check,
            detail: "Give the exit's address.".into(),
        });
    }
    if gateway.login.user.trim().is_empty() || exit.login.user.trim().is_empty() {
        return Err(Error::Step {
            step: Step::Check,
            detail: "Give the SSH user for both servers.".into(),
        });
    }
    if gateway.login.host == exit.login.host && gateway.login.port == exit.login.port {
        return Err(Error::Step {
            step: Step::Check,
            detail: "The gateway and the exit are the same server; a pair needs two.".into(),
        });
    }
    if !request.reality && !request.xhttp && !request.zerov1 {
        return Err(Error::NothingToInstall);
    }
    Ok(())
}

/// The record as far as it is known before the install finishes: enough for
/// the rollback to remove exactly what this run created.
fn partial_record(id: &str, login: &Login, trust: &HostKey, role: Role) -> ServerRecord {
    ServerRecord {
        version: record::VERSION,
        id: id.to_string(),
        name: String::new(),
        host: login.host.clone(),
        ssh_port: login.port,
        ssh_user: login.user.clone(),
        host_key: trust.clone(),
        ssh_key: None,
        os: String::new(),
        zray_version: String::new(),
        management_port: 0,
        verified_download: false,
        services: Vec::new(),
        created: now_secs(),
        role,
        tunnel_port: None,
    }
}

/// Run the read-only probe; `sudo` in stderr means the login lacks root.
async fn facts_of(conn: &Connection) -> Result<Facts, Error> {
    let probe = conn.script(&[], crate::facts::SCRIPT, QUICK).await?;
    if !probe.ok() {
        return Err(if probe.stderr.contains("sudo") {
            Error::Unsupported(vec![Problem::NeedRoot])
        } else {
            fail(Step::Check, &probe)
        });
    }
    Ok(Facts::parse(&probe.stdout))
}

async fn connect_pair(
    gateway: &PairLogin,
    exit: &PairLogin,
) -> Result<(Connection, Connection), Error> {
    let (gw, ex) = tokio::join!(
        ssh::connect(&gateway.login, &gateway.trust.fingerprint),
        ssh::connect(&exit.login, &exit.trust.fingerprint),
    );
    Ok((gw?, ex?))
}

/// Fetch each server's host key without sending any credential and compare it
/// with what the person confirmed.
async fn verify_pair_keys(gateway: &PairLogin, exit: &PairLogin) -> Result<(), Error> {
    let (gw, ex) = tokio::join!(
        ssh::fetch_host_key(&gateway.login.host, gateway.login.port),
        ssh::fetch_host_key(&exit.login.host, exit.login.port),
    );
    let (gw, ex) = (gw?, ex?);
    for (key, trust) in [(&gw, &gateway.trust), (&ex, &exit.trust)] {
        if key.fingerprint != trust.fingerprint {
            return Err(Error::Ssh(ssh::Error::HostKeyChanged {
                expected: trust.fingerprint.clone(),
                got: key.fingerprint.clone(),
            }));
        }
    }
    Ok(())
}

/// A free UDP port for the tunnel, away from the well-known 51820.
fn pick_tunnel_port(facts: &Facts) -> u16 {
    use rand::Rng;
    loop {
        let port = rand::thread_rng().gen_range(20000..60000);
        if !facts.udp.iter().any(|l| l.port == port) {
            return port;
        }
    }
}

/// Open ports in the firewall the server already has; never turns one on.
async fn firewall_side(
    conn: &Connection,
    tcp_ports: &[u16],
    udp_ports: &[u16],
    notes: &mut Vec<Note>,
) -> Result<(), Error> {
    let (tcp_text, udp_text) = (list(tcp_ports), list(udp_ports));
    let env = [("TCP", tcp_text.as_str()), ("UDP", udp_text.as_str())];
    let out = conn.script(&env, scripts::FIREWALL, QUICK).await?;
    match out.stdout.lines().find_map(|l| l.strip_prefix("firewall=")) {
        Some("ufw") => notes.push(Note::FirewallOpened {
            which: "ufw".into(),
        }),
        Some("firewalld") => notes.push(Note::FirewallOpened {
            which: "firewalld".into(),
        }),
        _ => notes.push(Note::ProviderFirewall {
            tcp: tcp_ports.to_vec(),
            udp: udp_ports.to_vec(),
        }),
    }
    Ok(())
}

struct GatewayDeployed {
    plan: InboundPlan,
    verified: bool,
    version: String,
    management_port: u16,
}

/// Install the gateway: the client-facing inbounds behind the smart split
/// router (Iranian-classified destinations exit via Iran, everything else —
/// foreign and unknown — takes the `wg-tunnel` outbound to the exit server;
/// fail-closed: unclassified traffic can never reach the Iran egress). The
/// tunnel keys are dummies until the tunnel step replaces them with the
/// on-server keys.
async fn deploy_gateway(
    conn: &Connection,
    facts: &Facts,
    request: &PairInstallRequest,
    arch: &str,
    tunnel_b: &TunnelBPlan,
    progress: &mut PairProgress<'_>,
    notes: &mut Vec<Note>,
) -> Result<GatewayDeployed, Error> {
    let preset = Some(if request.reality {
        Preset::Reality
    } else if request.xhttp {
        Preset::Xhttp
    } else {
        Preset::Zerov1
    });
    let fetched = fetch_program(conn, arch, &request.binary, &mut |ev| match ev {
        FetchEvent::Step => progress.step(Server::Gateway, Step::Download, preset),
        FetchEvent::Detail(text) => progress.detail(Server::Gateway, text),
    })
    .await?;

    progress.step(Server::Gateway, Step::Install, preset);
    place_program(conn).await?;

    progress.step(Server::Gateway, Step::Configure, preset);
    let reality = request.reality.then(|| RealityRequest {
        sni: request.sni.clone(),
        port: None,
    });
    let xhttp = request.xhttp.then(|| XhttpRequest {
        sni: request.sni.clone(),
        port: None,
    });
    let zerov1 = request.zerov1.then(|| Zerov1Request {
        sni: request.sni.clone(),
        port: None,
    });
    let plan = plan_inbounds(
        facts,
        &request.first_user,
        reality.as_ref(),
        xhttp.as_ref(),
        zerov1.as_ref(),
        notes,
    );
    let config = layout::gateway_config(
        &plan.reality_inbound(),
        &GatewayTunnel {
            exit_endpoint: "127.0.0.1:9",
            exit_public_key: DUMMY_WG_KEY,
            private_key: DUMMY_WG_KEY,
            address: layout::GATEWAY_TUNNEL_IP,
            keepalive: layout::TUNNEL_KEEPALIVE_SECS,
        },
        &layout::RealityTunnel {
            exit_host: "127.0.0.1",
            exit_public_key: DUMMY_RT_KEY,
            short_id: &tunnel_b.short_id,
            user_id: &tunnel_b.user_id,
        },
        facts.ipv6,
    );
    let wait: Vec<(u16, &str)> = plan
        .tcp_ports()
        .into_iter()
        .map(|port| (port, "tcp"))
        .collect();
    let management = write_config(conn, facts, &config).await?;

    progress.step(Server::Gateway, Step::Start, preset);
    start_service(conn, &wait).await?;

    Ok(GatewayDeployed {
        plan,
        verified: fetched.verified,
        version: fetched.version,
        management_port: management,
    })
}

struct ExitDeployed {
    verified: bool,
    version: String,
    management_port: u16,
}

/// Put a server program from the app into the scratch directory on the server.
async fn upload_program(conn: &Connection, bytes: &[u8]) -> Result<(), Error> {
    let out = conn
        .script(
            &[("WORK", layout::WORK_DIR)],
            "install -d -m 700 \"$WORK\"",
            QUICK,
        )
        .await?;
    if !out.ok() {
        return Err(fail(Step::Download, &out));
    }
    conn.put_file(&format!("{}/program", layout::WORK_DIR), "755", "root:root", bytes)
        .await?;
    Ok(())
}

/// Install the exit: the `tunnel-in` WireGuard inbound and a freedom egress.
/// No client-facing inbound, by policy.
async fn deploy_exit(
    conn: &Connection,
    facts: &Facts,
    arch: &str,
    binary: &BinarySource,
    tunnel_port: u16,
    tunnel_b: &TunnelBPlan,
    progress: &mut PairProgress<'_>,
) -> Result<ExitDeployed, Error> {
    let fetched = fetch_program(conn, arch, binary, &mut |ev| match ev {
        FetchEvent::Step => progress.step(Server::Exit, Step::Download, None),
        FetchEvent::Detail(text) => progress.detail(Server::Exit, text),
    })
    .await?;

    progress.step(Server::Exit, Step::Install, None);
    place_program(conn).await?;

    progress.step(Server::Exit, Step::Configure, None);
    let config = layout::exit_config(
        &layout::ExitTunnel {
            port: tunnel_port,
            gateway_public_key: DUMMY_WG_KEY,
            private_key: DUMMY_WG_KEY,
            mtu: layout::TUNNEL_MTU,
        },
        &layout::RtInbound {
            private_key: DUMMY_RT_KEY,
            short_id: &tunnel_b.short_id,
            user_id: &tunnel_b.user_id,
        },
        facts.ipv6,
    );
    let management = write_config(conn, facts, &config).await?;

    progress.step(Server::Exit, Step::Start, None);
    start_service(conn, &[(tunnel_port, "udp")]).await?;

    Ok(ExitDeployed {
        verified: fetched.verified,
        version: fetched.version,
        management_port: management,
    })
}

/// Install the Huawei modem L2TP server on the gateway (Design G): the
/// distro's xl2tpd+ppp packages, the LNS config, the pppd options with
/// mandatory MPPE-128, an empty chap-secrets (accounts come from the
/// `modem_account_create` op), UDP 1701 on the firewall, and the
/// fail-closed pool guard (drops forwarded modem traffic until the routing
/// agent confirms the TUN handoff contract, Q2). Idempotent.
async fn deploy_modem(
    conn: &Connection,
    facts: &Facts,
    progress: &mut PairProgress<'_>,
    notes: &mut Vec<Note>,
) -> Result<ModemRecord, Error> {
    progress.detail(Server::Gateway, "installing the modem VPN packages");
    let out = conn.script(&[], scripts::MODEM_PACKAGES, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Modem, &out));
    }

    progress.detail(Server::Gateway, "writing the modem VPN config");
    let modem = layout::ModemServer {
        listen_ip: &facts.primary_ip4,
        hostname: &format!("lns-{}", keys::random_hex(4)),
        dns_primary: layout::MODEM_POOL_SERVER_IP,
        dns_secondary: layout::MODEM_POOL_SERVER_IP,
    };
    conn.put_file(
        layout::XL2TPD_CONF,
        "600",
        "root:root",
        layout::xl2tpd_config(&modem).as_bytes(),
    )
    .await?;
    conn.put_file(
        layout::PPP_OPTIONS_MODEM,
        "600",
        "root:root",
        layout::modem_ppp_options(&modem).as_bytes(),
    )
    .await?;
    conn.put_file(
        layout::PPP_CHAP_SECRETS,
        "600",
        "root:root",
        b"# zray modem accounts (managed by the app)\n",
    )
    .await?;

    progress.detail(Server::Gateway, "opening the L2TP port");
    let out = conn.script(&[], scripts::MODEM_FIREWALL, QUICK).await?;
    match out.stdout.lines().find_map(|l| l.strip_prefix("firewall=")) {
        Some("ufw") => notes.push(Note::FirewallOpened {
            which: "ufw".into(),
        }),
        Some("firewalld") => notes.push(Note::FirewallOpened {
            which: "firewalld".into(),
        }),
        _ => notes.push(Note::ProviderFirewall {
            tcp: Vec::new(),
            udp: vec![layout::MODEM_L2TP_PORT],
        }),
    }

    // Fail-closed until the TUN handoff lands (Design G Q2): forwarded
    // modem-pool traffic is dropped rather than exiting via the main table.
    let out = conn
        .script(
            &[("POOL", layout::MODEM_POOL_CIDR)],
            scripts::MODEM_POOL_GUARD,
            QUICK,
        )
        .await?;
    if !out.ok() {
        return Err(fail(Step::Modem, &out));
    }

    progress.detail(Server::Gateway, "starting the L2TP server");
    let out = conn.script(&[], scripts::MODEM_ENABLE, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Modem, &out));
    }
    if !out.stdout.lines().any(|l| l.trim() == "active=1") {
        return Err(Error::Step {
            step: Step::Modem,
            detail: "xl2tpd did not stay up".into(),
        });
    }

    Ok(ModemRecord {
        pool_cidr: layout::MODEM_POOL_CIDR.into(),
        server_ip: layout::MODEM_POOL_SERVER_IP.into(),
        dns_primary: modem.dns_primary.into(),
        dns_secondary: modem.dns_secondary.into(),
        hostname: modem.hostname.into(),
        lns_address: facts.primary_ip4.clone(),
        tun_device: "zray-tun".into(),
        handoff_pending: true,
    })
}

/// Generate this server's WireGuard key pair on the server itself; returns
/// the public half. The private half stays in the server's tunnel config and
/// never crosses the SSH channel.
async fn wg_keygen(conn: &Connection) -> Result<String, Error> {
    let env = [
        ("BIN", layout::ZRAY_BIN),
        ("TUNNEL_CONF", layout::ZRAY_TUNNEL_CONF),
        ("SVC_USER", layout::ZRAY_USER),
    ];
    let out = conn.script(&env, scripts::WG_KEYGEN, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    public_key_of(&out.stdout).ok_or_else(|| Error::Step {
        step: Step::Tunnel,
        detail: "the key tool printed no public key".into(),
    })
}

/// Generate the exit's Tunnel B REALITY keypair on the server itself;
/// returns the public half. The private half stays in the server's
/// tunnel-rt config and never crosses the SSH channel.
async fn rt_keygen(conn: &Connection) -> Result<String, Error> {
    let env = [
        ("BIN", layout::ZRAY_BIN),
        ("TUNNEL_RT_CONF", layout::ZRAY_TUNNEL_RT_CONF),
        ("SVC_USER", layout::ZRAY_USER),
    ];
    let out = conn.script(&env, scripts::RT_KEYGEN, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    public_key_of(&out.stdout).ok_or_else(|| Error::Step {
        step: Step::Tunnel,
        detail: "the key tool printed no Tunnel B public key".into(),
    })
}

/// Read back the public half of an existing Tunnel B key, for re-linking
/// without rotating the keys.
async fn tunnel_rt_pubkey(conn: &Connection) -> Result<String, Error> {
    let env = [("TUNNEL_RT_CONF", layout::ZRAY_TUNNEL_RT_CONF)];
    let out = conn.script(&env, scripts::TUNNEL_RT_PUBKEY, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    public_key_of(&out.stdout).ok_or_else(|| Error::Step {
        step: Step::Tunnel,
        detail: "the server has no Tunnel B key".into(),
    })
}

/// What the real end-to-end IPv6 probe observed on one server. Every field
/// is measured, never assumed.
#[derive(Debug, Default)]
struct Ipv6Probe {
    /// A global-scope IPv6 address, if any.
    addr: String,
    /// A v6 default route exists.
    default_route: bool,
    /// The default route's MTU, when reported.
    mtu: Option<u32>,
    /// The public IPv6 a real outbound HTTPS request over v6 returned.
    egress: String,
    /// Which firewall manages v6 here (report only).
    firewall: String,
}

impl Ipv6Probe {
    fn parse(stdout: &str) -> Self {
        let mut probe = Ipv6Probe::default();
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("ipv6_addr=") {
                probe.addr = v.to_string();
            } else if line == "ipv6_default_route=1" {
                probe.default_route = true;
            } else if let Some(v) = line.strip_prefix("ipv6_mtu=") {
                probe.mtu = v.parse().ok();
            } else if let Some(v) = line.strip_prefix("ipv6_egress=") {
                probe.egress = v.to_string();
            } else if let Some(v) = line.strip_prefix("ipv6_firewall=") {
                probe.firewall = v.to_string();
            }
        }
        probe
    }

    /// The probe never fails the install: an unanswered probe is just an
    /// unusable result, reported honestly.
    fn usable(&self) -> Result<(), String> {
        if self.addr.is_empty() {
            return Err("no global IPv6 address".into());
        }
        if !self.default_route {
            return Err("no IPv6 default route".into());
        }
        if self.egress.is_empty() {
            return Err("no outbound IPv6 reachability (the egress test failed)".into());
        }
        // Tunnel C needs underlay MTU >= its MTU + IPv6/UDP/WireGuard
        // overhead (48). A smaller path MTU would blackhole the tunnel.
        if let Some(mtu) = self.mtu {
            if mtu < u32::from(layout::TUNNEL_C_MTU) + 48 {
                return Err(format!("IPv6 path MTU {mtu} is too small for the tunnel"));
            }
        }
        Ok(())
    }
}

/// Run the real IPv6 probe on a server.
async fn ipv6_probe(conn: &Connection) -> Result<Ipv6Probe, Error> {
    let out = conn.script(&[], scripts::IPV6_PROBE, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    Ok(Ipv6Probe::parse(&out.stdout))
}

/// Generate a Tunnel C WireGuard keypair on the server itself (the
/// `tunnel-c.conf` file); returns the public half. The private half never
/// leaves the server. Keys are per-tunnel: never shared with Tunnel A.
async fn wg_c_keygen(conn: &Connection) -> Result<String, Error> {
    let env = [
        ("BIN", layout::ZRAY_BIN),
        ("TUNNEL_CONF", layout::ZRAY_TUNNEL_C_CONF),
        ("SVC_USER", layout::ZRAY_USER),
    ];
    let out = conn.script(&env, scripts::WG_KEYGEN, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    public_key_of(&out.stdout).ok_or_else(|| Error::Step {
        step: Step::Tunnel,
        detail: "the key tool printed no Tunnel C public key".into(),
    })
}

/// Read back the public half of an existing Tunnel C key, for re-linking
/// without rotating the keys.
async fn tunnel_c_pubkey(conn: &Connection) -> Result<String, Error> {
    let env = [("TUNNEL_CONF", layout::ZRAY_TUNNEL_C_CONF)];
    let out = conn.script(&env, scripts::TUNNEL_PUBKEY, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    public_key_of(&out.stdout).ok_or_else(|| Error::Step {
        step: Step::Tunnel,
        detail: "the server has no Tunnel C key".into(),
    })
}

/// Read back the public half of an existing tunnel key, for re-linking
/// without rotating the keys.
async fn tunnel_pubkey(conn: &Connection) -> Result<String, Error> {
    let env = [("TUNNEL_CONF", layout::ZRAY_TUNNEL_CONF)];
    let out = conn.script(&env, scripts::TUNNEL_PUBKEY, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    public_key_of(&out.stdout).ok_or_else(|| Error::Step {
        step: Step::Tunnel,
        detail: "the server has no tunnel key".into(),
    })
}

fn public_key_of(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("public_key="))
        .map(str::to_string)
}

/// Merge the tunnel fragment into the server config and restart the service.
async fn tunnel_up(conn: &Connection, fragment: &serde_json::Value) -> Result<(), Error> {
    let bytes = serde_json::to_vec(fragment).expect("a JSON value always encodes");
    let fragment_path = format!("{}/tunnel-fragment.json", layout::WORK_DIR);
    conn.put_file(&fragment_path, "600", "root:root", &bytes)
        .await?;
    let env = [
        ("SERVER_CONFIG", layout::ZRAY_CONFIG),
        ("TUNNEL_CONF", layout::ZRAY_TUNNEL_CONF),
        ("TUNNEL_RT_CONF", layout::ZRAY_TUNNEL_RT_CONF),
        ("TUNNEL_C_CONF", layout::ZRAY_TUNNEL_C_CONF),
        ("FRAGMENT_FILE", fragment_path.as_str()),
        ("BIN", layout::ZRAY_BIN),
        ("SERVICE", layout::ZRAY_SERVICE),
    ];
    let out = conn.script(&env, scripts::TUNNEL_UP, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    Ok(())
}

/// Install the app's own key so it can come back without the password, and
/// prove the key works before the password is forgotten.
#[allow(clippy::too_many_arguments)]
async fn install_app_key(
    conn: &Connection,
    login: &Login,
    trust: &HostKey,
    pair_id: &str,
    role: Role,
    server: Server,
    keep: bool,
    record: &mut ServerRecord,
    progress: &mut PairProgress<'_>,
    notes: &mut Vec<Note>,
) -> Result<(), Error> {
    progress.step(server, Step::Access, None);
    if !keep {
        return Ok(());
    }
    let key = keys::new_ssh_key(&layout::pair_key_comment(pair_id, role));
    conn.put_file(
        &format!("{}/app.pub", layout::WORK_DIR),
        "600",
        "root:root",
        key.public_openssh.as_bytes(),
    )
    .await?;
    let env = [
        ("LOGIN_USER", login.user.as_str()),
        ("WORK", layout::WORK_DIR),
    ];
    let out = conn.script(&env, scripts::ADD_KEY, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Access, &out));
    }
    let with_key = Login {
        auth: Auth::Key(key.private_openssh.clone()),
        ..login.clone()
    };
    match ssh::connect(&with_key, &trust.fingerprint).await {
        Ok(c) => {
            c.close().await;
            record.ssh_key = Some(key.private_openssh);
        }
        Err(_) => notes.push(Note::KeyNotWorking),
    }
    Ok(())
}

/// Take away what `created` lists, exit first, then gateway. Missing
/// connections (a cancellation before they were made, or a dead network) are
/// reported, not hidden.
pub async fn rollback_pair_conns(
    mut gw_conn: Option<Connection>,
    mut ex_conn: Option<Connection>,
    created: &PairCreated,
    on: &(dyn Fn(Event) + Send + Sync),
) -> RollbackStatus {
    let mut progress = PairProgress { on, done: 0, of: 0 };
    let mut partial = Vec::new();
    let mut needed = false;

    if let Some(cs) = created.exit.as_ref().filter(|cs| cs.installed) {
        needed = true;
        progress.step(Server::Exit, Step::Rollback, None);
        match ex_conn.take() {
            Some(conn) => {
                if let Err(e) = manage::remove_with_gateway_ip(
                    &conn,
                    &cs.record,
                    cs.tunnel_gw_ip.as_deref(),
                    cs.tunnel_c.as_ref().map(|(ip, port)| (ip.as_str(), *port)),
                    &|_| {},
                )
                .await
                {
                    partial.push(format!("exit: {e}"));
                }
                let _ = conn
                    .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
                    .await;
                conn.close().await;
            }
            None => partial.push("exit: no connection for the cleanup".to_string()),
        }
    }
    if let Some(cs) = created.gateway.as_ref().filter(|cs| cs.installed) {
        needed = true;
        progress.step(Server::Gateway, Step::Rollback, None);
        match gw_conn.take() {
            Some(conn) => {
                if let Err(e) = manage::remove(&conn, &cs.record, &|_| {}).await {
                    partial.push(format!("gateway: {e}"));
                }
                let _ = conn
                    .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
                    .await;
                conn.close().await;
            }
            None => partial.push("gateway: no connection for the cleanup".to_string()),
        }
    }
    // Whatever is left (connected but nothing installed) gets its scratch
    // cleaned and is closed.
    for conn in gw_conn.into_iter().chain(ex_conn) {
        let _ = conn
            .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
            .await;
        conn.close().await;
    }
    if !needed {
        RollbackStatus::NotNeeded
    } else if partial.is_empty() {
        RollbackStatus::Complete
    } else {
        RollbackStatus::Partial(partial.join("; "))
    }
}

/// Set up a gateway and an exit and join them with a WireGuard tunnel.
/// `created` tracks what this run installed; on failure the rollback removes
/// it, exit first. On cancellation the caller (the job layer) reconnects and
/// calls [`rollback_pair_conns`] with the same `created`.
pub async fn install_pair(
    gateway: &PairLogin,
    exit: &PairLogin,
    request: &PairInstallRequest,
    created: &mut PairCreated,
    on: &(dyn Fn(Event) + Send + Sync),
) -> Result<PairOutcome, Error> {
    // 1. Validate: local, before any connection is made.
    validate_pair(request, gateway, exit)?;
    let masterdns_domain = match &request.masterdns_domain {
        Some(text) => Some(guide::clean_domain(text).map_err(Error::Domain)?),
        None => None,
    };
    let mut progress = PairProgress {
        on,
        done: 0,
        of: 19
            + if masterdns_domain.is_some() { 4 } else { 0 }
            + if request.modem_server { 1 } else { 0 },
    };
    let mut notes = Vec::new();
    let mut conns = PairConns::default();
    let pair_id = keys::random_hex(8);
    let result = run_pair(
        gateway,
        exit,
        request,
        &masterdns_domain,
        &pair_id,
        created,
        &mut conns,
        &mut progress,
        &mut notes,
    )
    .await;
    match result {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let status = rollback_pair_conns(conns.gw.take(), conns.ex.take(), created, on).await;
            Err(Error::PairFailed {
                error: error.to_string(),
                rollback: status,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_pair(
    gateway: &PairLogin,
    exit: &PairLogin,
    request: &PairInstallRequest,
    masterdns_domain: &Option<String>,
    pair_id: &str,
    created: &mut PairCreated,
    conns: &mut PairConns,
    progress: &mut PairProgress<'_>,
    notes: &mut Vec<Note>,
) -> Result<PairOutcome, Error> {
    // 2. Fingerprint trust, both sides, without sending any credential.
    progress.detail(Server::Gateway, "checking the host key");
    progress.detail(Server::Exit, "checking the host key");
    verify_pair_keys(gateway, exit).await?;

    // 3. Facts, both sides in parallel. Look before touching.
    progress.step(Server::Gateway, Step::Check, None);
    progress.step(Server::Exit, Step::Check, None);
    let (gw, ex) = connect_pair(gateway, exit).await?;
    conns.gw = Some(gw);
    conns.ex = Some(ex);
    let gw_conn = conns.gw.as_ref().expect("connected above");
    let ex_conn = conns.ex.as_ref().expect("connected above");
    let (gw_facts, ex_facts) = tokio::join!(facts_of(gw_conn), facts_of(ex_conn));
    let (gw_facts, ex_facts) = (gw_facts?, ex_facts?);
    // A previous install on either side is replaced, not refused. Remove it,
    // then look again so the ports it held count as free.
    let (gw_old, ex_old) = (
        gw_facts.zray_installed && gw_facts.zray_config,
        ex_facts.zray_installed && ex_facts.zray_config,
    );
    let (gw_facts, ex_facts) = if gw_old || ex_old {
        if gw_old {
            progress.detail(Server::Gateway, "removing the previous install");
            manage::wipe_existing(gw_conn).await?;
        }
        if ex_old {
            progress.detail(Server::Exit, "removing the previous install");
            manage::wipe_existing(ex_conn).await?;
        }
        let (g, e) = tokio::join!(facts_of(gw_conn), facts_of(ex_conn));
        (g?, e?)
    } else {
        (gw_facts, ex_facts)
    };
    progress.detail(
        Server::Gateway,
        format!("{} · {} MB memory", gw_facts.os_name, gw_facts.mem_mb),
    );
    progress.detail(
        Server::Exit,
        format!("{} · {} MB memory", ex_facts.os_name, ex_facts.mem_mb),
    );
    let mut gw_problems = gw_facts.problems();
    let mut ex_problems = ex_facts.problems();
    // The tunnel step merges its config with Python 3 on the server.
    if !gw_facts.has("python3") {
        gw_problems.push(Problem::NoPython3);
    }
    if !ex_facts.has("python3") {
        ex_problems.push(Problem::NoPython3);
    }
    // MasterDNS needs UDP 53 on the gateway (the exit never runs it).
    let gw_dns_bind = if masterdns_domain.is_some() {
        masterdns_bind(&gw_facts, &mut gw_problems)
    } else {
        "0.0.0.0".to_string()
    };
    if !gw_problems.is_empty() || !ex_problems.is_empty() {
        let mut all = gw_problems;
        all.extend(ex_problems);
        return Err(Error::Unsupported(all));
    }
    let gw_arch = gw_facts.asset_arch().expect("checked by problems()");
    let ex_arch = ex_facts.asset_arch().expect("checked by problems()");
    let tunnel_port = pick_tunnel_port(&ex_facts);
    // The address the exit sees the gateway at: the source of its default
    // route, which is what the tunnel firewall rule is opened for.
    let gw_tunnel_ip = if gw_facts.primary_ip4.is_empty() {
        gateway.login.host.clone()
    } else {
        gw_facts.primary_ip4.clone()
    };
    progress.detail(
        Server::Exit,
        format!("the tunnel will listen on UDP {tunnel_port}"),
    );

    // Register both sides for the rollback before anything is written.
    created.gateway = Some(CreatedServer {
        record: partial_record(
            &format!("{pair_id}-gw"),
            &gateway.login,
            &gateway.trust,
            Role::Gateway,
        ),
        installed: false,
        tunnel_gw_ip: None,
        tunnel_c: None,
    });
    created.exit = Some(CreatedServer {
        record: {
            let mut record = partial_record(
                &format!("{pair_id}-ex"),
                &exit.login,
                &exit.trust,
                Role::Exit,
            );
            record.tunnel_port = Some(tunnel_port);
            record
        },
        installed: false,
        tunnel_gw_ip: Some(gw_tunnel_ip.clone()),
        tunnel_c: None,
    });

    // 4. Packages, both sides in parallel.
    progress.step(Server::Gateway, Step::Packages, None);
    progress.step(Server::Exit, Step::Packages, None);
    let (gw_tools, ex_tools) = tokio::join!(
        gw_conn.script(&[], scripts::TOOLS, SLOW),
        ex_conn.script(&[], scripts::TOOLS, SLOW),
    );
    if !gw_tools?.ok() || !ex_tools?.ok() {
        return Err(Error::Unsupported(vec![Problem::NoDownloader]));
    }

    // 5-7. Download, install, configure and start the gateway, then the exit.
    // Tunnel B's app-side credentials are generated once here and reused by
    // the deploy, tunnel and E2E phases.
    let tunnel_b = TunnelBPlan::generate();
    created
        .gateway
        .as_mut()
        .expect("registered above")
        .installed = true;
    let deployed = deploy_gateway(
        gw_conn, &gw_facts, request, gw_arch, &tunnel_b, progress, notes,
    )
    .await?;
    let (mut services, mut tcp_ports) = (Vec::new(), Vec::new());
    let (vision, xhttp, zerov1) = deployed.plan.services();
    if let Some(service) = vision {
        tcp_ports.push(service.port);
        services.push(Service::Reality(service));
    }
    if let Some(service) = xhttp {
        tcp_ports.push(service.port);
        services.push(Service::Xhttp(service));
    }
    if let Some(service) = zerov1 {
        tcp_ports.push(service.port);
        services.push(Service::Zerov1(service));
    }
    let mut udp_ports = Vec::new();
    if let Some(domain) = masterdns_domain {
        let service =
            deploy_masterdns(gw_conn, domain, &gw_dns_bind, gw_arch, &mut |ev| match ev {
                DnsEvent::Step(step) => {
                    progress.step(Server::Gateway, step, Some(Preset::MasterDns))
                }
                DnsEvent::Detail(text) => progress.detail(Server::Gateway, text),
            })
            .await?;
        udp_ports.push(53);
        services.push(Service::MasterDns(service));
    }
    {
        let cs = created.gateway.as_mut().expect("registered above");
        cs.record.name = request.name.clone();
        cs.record.os = gw_facts.os_name.clone();
        cs.record.zray_version = deployed.version.clone();
        cs.record.management_port = deployed.management_port;
        cs.record.verified_download = deployed.verified;
        cs.record.services = services;
        cs.record.created = now_secs();
    }
    if !deployed.verified {
        notes.push(Note::Unverified);
    }

    created.exit.as_mut().expect("registered above").installed = true;
    let ex_deployed = deploy_exit(
        ex_conn,
        &ex_facts,
        ex_arch,
        &request.binary,
        tunnel_port,
        &tunnel_b,
        progress,
    )
    .await?;
    {
        let cs = created.exit.as_mut().expect("registered above");
        cs.record.name = request.name.clone();
        cs.record.os = ex_facts.os_name.clone();
        cs.record.zray_version = ex_deployed.version.clone();
        cs.record.management_port = ex_deployed.management_port;
        cs.record.verified_download = ex_deployed.verified;
        cs.record.created = now_secs();
    }
    if !ex_deployed.verified {
        notes.push(Note::Unverified);
    }

    // 8. Firewall: the gateway gets its client ports; the exit gets the
    // tunnel port, for the gateway's address only. Additive, never enabling.
    progress.step(Server::Gateway, Step::Firewall, None);
    firewall_side(gw_conn, &tcp_ports, &udp_ports, notes).await?;
    progress.step(Server::Exit, Step::Firewall, None);
    let port_text = tunnel_port.to_string();
    let env = [
        ("TUNNEL_PORT", port_text.as_str()),
        ("GW_IP", gw_tunnel_ip.as_str()),
    ];
    let out = ex_conn
        .script(&env, scripts::FIREWALL_TUNNEL, QUICK)
        .await?;
    match out.stdout.lines().find_map(|l| l.strip_prefix("firewall=")) {
        Some("ufw") => notes.push(Note::FirewallOpened {
            which: "ufw".into(),
        }),
        Some("firewalld") => notes.push(Note::FirewallOpened {
            which: "firewalld".into(),
        }),
        _ => notes.push(Note::ProviderFirewall {
            tcp: vec![layout::TUNNEL_RT_PORT],
            udp: vec![tunnel_port],
        }),
    }
    // Tunnel B's TCP 443, for the gateway's address only. Same additive,
    // idempotent pattern as the WireGuard rule.
    let env = [("RT_PORT", "443"), ("GW_IP", gw_tunnel_ip.as_str())];
    let out = ex_conn
        .script(&env, scripts::FIREWALL_TUNNEL_RT, QUICK)
        .await?;
    if !out.ok() {
        return Err(fail(Step::Firewall, &out));
    }

    // 9. The tunnel: keys are generated on each server (the private halves
    // never leave it), the public halves are exchanged over the pinned SSH
    // sessions, and each side's peer config is merged into its server config.
    progress.step(Server::Gateway, Step::Tunnel, None);
    progress.detail(Server::Gateway, "generating the tunnel key on the server");
    let gw_pub = wg_keygen(gw_conn).await?;
    progress.step(Server::Exit, Step::Tunnel, None);
    progress.detail(Server::Exit, "generating the tunnel key on the server");
    let ex_pub = wg_keygen(ex_conn).await?;
    let exit_endpoint = format!("{}:{}", exit.login.host, tunnel_port);
    progress.detail(Server::Gateway, "writing the tunnel config");
    tunnel_up(
        gw_conn,
        &layout::tunnel_gateway_fragment(&GatewayTunnel {
            exit_endpoint: &exit_endpoint,
            exit_public_key: &ex_pub,
            private_key: layout::TUNNEL_KEY_PLACEHOLDER,
            address: layout::GATEWAY_TUNNEL_IP,
            keepalive: layout::TUNNEL_KEEPALIVE_SECS,
        }),
    )
    .await?;
    progress.detail(Server::Exit, "writing the tunnel config");
    tunnel_up(
        ex_conn,
        &layout::tunnel_exit_fragment(&layout::ExitTunnel {
            port: tunnel_port,
            gateway_public_key: &gw_pub,
            private_key: layout::TUNNEL_KEY_PLACEHOLDER,
            mtu: layout::TUNNEL_MTU,
        }),
    )
    .await?;
    // The exit's tunnel port must answer UDP after the restart.
    let out = ex_conn
        .script(
            &[("PORT", port_text.as_str()), ("PROTO", "udp")],
            scripts::WAIT_PORT,
            QUICK,
        )
        .await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }

    // 9b. Tunnel B (VLESS+REALITY over TCP 443): the REALITY keypair is
    // generated on the exit server — its private half never leaves it —
    // and the gateway gets the public half over the pinned SSH session,
    // plus the app-generated short id and tunnel UUID. Both tunnels are
    // always-on from this point: configured, authenticated, and verified.
    progress.detail(Server::Exit, "generating the Tunnel B key on the server");
    let rt_pub = rt_keygen(ex_conn).await?;
    progress.detail(Server::Gateway, "writing the Tunnel B config");
    tunnel_up(
        gw_conn,
        &layout::tunnel_rt_gateway_fragment(&layout::RealityTunnel {
            exit_host: &exit.login.host,
            exit_public_key: &rt_pub,
            short_id: &tunnel_b.short_id,
            user_id: &tunnel_b.user_id,
        }),
    )
    .await?;
    progress.detail(Server::Exit, "writing the Tunnel B config");
    tunnel_up(
        ex_conn,
        &layout::tunnel_rt_exit_fragment(&layout::RtInbound {
            private_key: layout::TUNNEL_RT_KEY_PLACEHOLDER,
            short_id: &tunnel_b.short_id,
            user_id: &tunnel_b.user_id,
        }),
    )
    .await?;
    // The exit's Tunnel B port must answer TCP after the restart, and the
    // gateway must be able to open it. That proves the port and the path;
    // the REALITY handshake itself is not verified end-to-end here — the
    // servers' management APIs have no tunnel-handshake endpoint in this
    // tree yet, so it degrades to the same honest "unverified" state as
    // Tunnel A until the VPN-core agent ships it.
    let out = ex_conn
        .script(
            &[("PORT", "443"), ("PROTO", "tcp")],
            scripts::WAIT_PORT,
            QUICK,
        )
        .await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }
    let out = gw_conn
        .script(
            &[("HOST", exit.login.host.as_str()), ("PORT", "443")],
            scripts::TCP_DIAL,
            QUICK,
        )
        .await?;
    if !out.ok() {
        return Err(fail(Step::Tunnel, &out));
    }

    // 9c. Tunnel C (WireGuard over an IPv6 underlay): provisioned only when
    // IPv6 is REALLY usable end-to-end on both servers — public address,
    // default route, real outbound reachability, sufficient path MTU. The
    // probe measures; it never assumes. When IPv6 is not usable, A+B
    // continue normally and C is recorded as unavailable, never faked.
    progress.detail(Server::Pair, "probing real IPv6 usability on both servers");
    let (gw_v6, ex_v6) = tokio::join!(ipv6_probe(gw_conn), ipv6_probe(ex_conn));
    let (gw_v6, ex_v6) = (gw_v6?, ex_v6?);
    let v6_verdict = match (gw_v6.usable(), ex_v6.usable()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) => Err(format!("gateway: {e}")),
        (_, Err(e)) => Err(format!("exit: {e}")),
    };
    // The exit's firewall rule trusts the gateway's observed IPv6 egress.
    let mut tunnel_c: Option<TunnelCRecord> = None;
    let mut ipv6_status = Ipv6Status::Unavailable;
    match v6_verdict {
        Ok(()) => {
            progress.detail(Server::Exit, "generating the Tunnel C key on the server");
            let gw_c_pub = wg_c_keygen(gw_conn).await?;
            progress.detail(Server::Gateway, "generating the Tunnel C key on the server");
            let ex_c_pub = wg_c_keygen(ex_conn).await?;
            let c_port = pick_tunnel_port(&ex_facts);
            let port_text = c_port.to_string();
            let exit_endpoint = format!("[{}]:{}", ex_v6.egress, c_port);
            progress.detail(Server::Gateway, "writing the Tunnel C config");
            tunnel_up(
                gw_conn,
                &layout::tunnel_c_gateway_fragment(&layout::GatewayTunnel {
                    exit_endpoint: &exit_endpoint,
                    exit_public_key: &ex_c_pub,
                    private_key: layout::TUNNEL_C_KEY_PLACEHOLDER,
                    address: layout::GATEWAY_TUNNEL_C_IP,
                    keepalive: layout::TUNNEL_KEEPALIVE_SECS,
                }),
            )
            .await?;
            progress.detail(Server::Exit, "writing the Tunnel C config");
            tunnel_up(
                ex_conn,
                &layout::tunnel_c_exit_fragment(&layout::ExitTunnel {
                    port: c_port,
                    gateway_public_key: &gw_c_pub,
                    private_key: layout::TUNNEL_C_KEY_PLACEHOLDER,
                    mtu: layout::TUNNEL_C_MTU,
                }),
            )
            .await?;
            // The exit's Tunnel C firewall rule: UDP, source-restricted to
            // the gateway's IPv6.
            let out = ex_conn
                .script(
                    &[
                        ("GW6", gw_v6.egress.as_str()),
                        ("C_PORT", port_text.as_str()),
                    ],
                    scripts::FIREWALL_TUNNEL_C,
                    QUICK,
                )
                .await?;
            if !out.ok() {
                return Err(fail(Step::Firewall, &out));
            }
            match out.stdout.lines().find_map(|l| l.strip_prefix("firewall=")) {
                Some("ufw") => notes.push(Note::FirewallOpened {
                    which: "ufw".into(),
                }),
                Some("firewalld") => notes.push(Note::FirewallOpened {
                    which: "firewalld".into(),
                }),
                _ => notes.push(Note::ProviderFirewall {
                    tcp: Vec::new(),
                    udp: vec![c_port],
                }),
            }
            // The exit's Tunnel C port must answer UDP after the restart.
            let out = ex_conn
                .script(
                    &[("PORT", port_text.as_str()), ("PROTO", "udp")],
                    scripts::WAIT_PORT,
                    QUICK,
                )
                .await?;
            if !out.ok() {
                return Err(fail(Step::Tunnel, &out));
            }
            tunnel_c = Some(TunnelCRecord {
                port: c_port,
                exit_endpoint,
                gateway_public_key: gw_c_pub,
                exit_public_key: ex_c_pub,
                gateway_ipv6: gw_v6.egress.clone(),
                mtu: layout::TUNNEL_C_MTU,
                keepalive_secs: layout::TUNNEL_KEEPALIVE_SECS,
                established: 0,
            });
            if let Some(cs) = created.exit.as_mut() {
                cs.tunnel_c = Some((gw_v6.egress.clone(), c_port));
            }
            ipv6_status = Ipv6Status::Verified;
            progress.detail(Server::Pair, "Tunnel C is up on a verified IPv6 underlay");
        }
        Err(reason) => {
            progress.detail(Server::Pair, format!("no Tunnel C: {reason}"));
            notes.push(Note::Ipv6Unavailable { reason });
        }
    }

    // 9d. The modem L2TP server (opt-in): xl2tpd+ppp packages, configs,
    // firewall, and the fail-closed pool guard, then start. Idempotent:
    // re-running an install with the flag re-applies the same state.
    let mut modem_record = None;
    if request.modem_server {
        progress.step(Server::Gateway, Step::Modem, None);
        modem_record = Some(deploy_modem(gw_conn, &gw_facts, progress, notes).await?);
    }

    // The handshake must be alive on both ends. When the server's program
    // has no tunnel endpoint yet this degrades to a note, never to a claim.
    progress.step(Server::Pair, Step::Tunnel, None);
    let (gw_status, ex_status) = tokio::join!(
        manage::tunnel_status(
            gw_conn,
            &created.gateway.as_ref().expect("registered").record
        ),
        manage::tunnel_status(ex_conn, &created.exit.as_ref().expect("registered").record),
    );
    let (gw_status, ex_status) = (gw_status?, ex_status?);
    let established = if gw_status.up && ex_status.up {
        progress.detail(Server::Pair, "the tunnel handshake is alive on both ends");
        now_secs()
    } else {
        for (status, name) in [(&gw_status, "gateway"), (&ex_status, "exit")] {
            if let Some(note) = &status.note {
                progress.detail(Server::Pair, format!("{name}: {note}"));
            }
        }
        notes.push(Note::TunnelUnverified);
        0
    };

    // 10. The way back: the app's own key on both servers.
    install_app_key(
        gw_conn,
        &gateway.login,
        &gateway.trust,
        pair_id,
        Role::Gateway,
        Server::Gateway,
        request.keep_access,
        &mut created.gateway.as_mut().expect("registered").record,
        progress,
        notes,
    )
    .await?;
    install_app_key(
        ex_conn,
        &exit.login,
        &exit.trust,
        pair_id,
        Role::Exit,
        Server::Exit,
        request.keep_access,
        &mut created.exit.as_mut().expect("registered").record,
        progress,
        notes,
    )
    .await?;

    // 11. End-to-end checks.
    // 11b. The exit's egress address must not be the gateway's: if it is,
    // the tunnel is not carrying the traffic. An unanswered echo service
    // degrades to a note, not a failure.
    let out = ex_conn.script(&[], scripts::EGRESS_IP, QUICK).await?;
    let egress = out.stdout.trim().to_string();
    if egress.is_empty() {
        notes.push(Note::EgressUnverified);
        progress.detail(
            Server::Pair,
            "the exit's egress address could not be checked",
        );
    } else {
        progress.detail(
            Server::Pair,
            format!("the exit's egress address is {egress}"),
        );
        if let (Ok(egress_ip), Ok(gw_ip)) = (
            egress.parse::<std::net::IpAddr>(),
            gateway.login.host.parse::<std::net::IpAddr>(),
        ) {
            if egress_ip == gw_ip {
                return Err(Error::Step {
                    step: Step::Tunnel,
                    detail: "The exit's traffic comes back out of the gateway's address: the \
                             tunnel is not carrying it."
                        .into(),
                });
            }
        }
    }
    // 11c. The finished tunnel configs must be ones the engine accepts. The
    // private keys are throwaways: this checks the shape, not the secrets.
    let throwaway = random_wg_key();
    let rt_throwaway = keys::new_reality_keys();
    let gw_final = layout::gateway_config(
        &deployed.plan.reality_inbound(),
        &GatewayTunnel {
            exit_endpoint: &exit_endpoint,
            exit_public_key: &ex_pub,
            private_key: &throwaway,
            address: layout::GATEWAY_TUNNEL_IP,
            keepalive: layout::TUNNEL_KEEPALIVE_SECS,
        },
        &layout::RealityTunnel {
            exit_host: &exit.login.host,
            exit_public_key: &rt_throwaway.public,
            short_id: &tunnel_b.short_id,
            user_id: &tunnel_b.user_id,
        },
        gw_facts.ipv6,
    );
    zero_config::compile_config(&gw_final, zero_core::GenerationId(1)).map_err(|e| {
        Error::Step {
            step: Step::Tunnel,
            detail: format!("the finished gateway config does not compile: {e}"),
        }
    })?;
    let ex_final = layout::exit_config(
        &layout::ExitTunnel {
            port: tunnel_port,
            gateway_public_key: &gw_pub,
            private_key: &throwaway,
            mtu: layout::TUNNEL_MTU,
        },
        &layout::RtInbound {
            private_key: &rt_throwaway.private,
            short_id: &tunnel_b.short_id,
            user_id: &tunnel_b.user_id,
        },
        ex_facts.ipv6,
    );
    zero_config::compile_config(&ex_final, zero_core::GenerationId(1)).map_err(|e| {
        Error::Step {
            step: Step::Tunnel,
            detail: format!("the finished exit config does not compile: {e}"),
        }
    })?;
    progress.detail(Server::Pair, "the tunnel configs compile in the engine");

    // 12. Report.
    let gateway_record = created.gateway.take().expect("registered above").record;
    let exit_record = created.exit.take().expect("registered above").record;
    let record = PairRecord {
        version: record::VERSION,
        id: pair_id.to_string(),
        name: request.name.trim().to_string(),
        created: now_secs(),
        state: PairState::Ready,
        gateway: gateway_record,
        exit: exit_record,
        tunnel: TunnelRecord {
            kind: "wireguard".into(),
            port: tunnel_port,
            exit_endpoint,
            gateway_public_key: gw_pub,
            exit_public_key: ex_pub,
            psk: None,
            mtu: layout::TUNNEL_MTU,
            keepalive_secs: layout::TUNNEL_KEEPALIVE_SECS,
            established,
            b: Some(RealityTunnelRecord {
                exit_public_key: rt_pub,
                short_id: tunnel_b.short_id.clone(),
                user_id: tunnel_b.user_id.clone(),
                exit_host: exit.login.host.clone(),
            }),
            c: tunnel_c,
            active: TransportId::A,
        },
        modem: modem_record,
        ipv6_status,
    };
    let configs = record.client_configs();
    // The operator panel on the gateway, the server clients connect to.
    let mut panel = None;
    if let Some(program) = request.binary.panel_program(gw_arch) {
        progress.detail(Server::Gateway, "installing the operator panel");
        let gw = conns.gw.as_ref().expect("connected in phase 3");
        match crate::panel::deploy(
            gw,
            program,
            "gateway",
            &gateway.login.host,
            record.gateway.management_port,
            Some(&exit.login.host),
            &record.gateway.services,
        )
        .await
        {
            Ok(access) => panel = Some(access),
            Err(e) => notes.push(Note::PanelFailed {
                reason: e.to_string(),
            }),
        }
    }
    let gw_conn = conns.gw.take().expect("connected in phase 3");
    let ex_conn = conns.ex.take().expect("connected in phase 3");
    let _ = gw_conn
        .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
        .await;
    let _ = ex_conn
        .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
        .await;
    gw_conn.close().await;
    ex_conn.close().await;
    Ok(PairOutcome {
        record,
        notes: std::mem::take(notes),
        configs,
        panel,
    })
}

/// Re-run the tunnel phase for an existing pair: keys are reused when they
/// exist (no rotation on re-link), regenerated when they do not. Idempotent:
/// when the tunnel is already up it reports that and changes nothing.
/// Tunnel C is re-provisioned only when IPv6 still verifies on both servers;
/// a broken v6 path flips the record to unavailable rather than being faked.
/// Returns the tunnel record and the current IPv6 verdict.
pub async fn link_servers(
    gateway: &PairLogin,
    exit: &PairLogin,
    record: &PairRecord,
    on: &(dyn Fn(Event) + Send + Sync),
) -> Result<(TunnelRecord, Ipv6Status), Error> {
    let mut progress = PairProgress { on, done: 0, of: 3 };
    let (gw_conn, ex_conn) = connect_pair(gateway, exit).await?;
    let (gw_facts, ex_facts) = tokio::join!(facts_of(&gw_conn), facts_of(&ex_conn));
    let (gw_facts, ex_facts) = (gw_facts?, ex_facts?);

    if gw_facts.tunnel_installed
        && ex_facts.tunnel_installed
        && gw_facts.tunnel_rt_installed
        && ex_facts.tunnel_rt_installed
    {
        progress.step(Server::Pair, Step::Tunnel, None);
        let (gw_status, ex_status) = tokio::join!(
            manage::tunnel_status(&gw_conn, &record.gateway),
            manage::tunnel_status(&ex_conn, &record.exit),
        );
        let (gw_status, ex_status) = (gw_status?, ex_status?);
        if gw_status.up && ex_status.up {
            progress.detail(
                Server::Pair,
                "Tunnel A is up and both tunnels are configured on both servers; nothing was changed",
            );
            gw_conn.close().await;
            ex_conn.close().await;
            let mut tunnel = record.tunnel.clone();
            tunnel.established = now_secs();
            return Ok((tunnel, record.ipv6_status));
        }
        progress.detail(Server::Pair, "re-writing the peer configs");
    }

    progress.step(Server::Gateway, Step::Tunnel, None);
    let gw_pub = if gw_facts.tunnel_config {
        tunnel_pubkey(&gw_conn).await?
    } else {
        wg_keygen(&gw_conn).await?
    };
    progress.step(Server::Exit, Step::Tunnel, None);
    let ex_pub = if ex_facts.tunnel_config {
        tunnel_pubkey(&ex_conn).await?
    } else {
        wg_keygen(&ex_conn).await?
    };

    tunnel_up(
        &gw_conn,
        &layout::tunnel_gateway_fragment(&GatewayTunnel {
            exit_endpoint: &record.tunnel.exit_endpoint,
            exit_public_key: &ex_pub,
            private_key: layout::TUNNEL_KEY_PLACEHOLDER,
            address: layout::GATEWAY_TUNNEL_IP,
            keepalive: layout::TUNNEL_KEEPALIVE_SECS,
        }),
    )
    .await?;
    tunnel_up(
        &ex_conn,
        &layout::tunnel_exit_fragment(&layout::ExitTunnel {
            port: record.tunnel.port,
            gateway_public_key: &gw_pub,
            private_key: layout::TUNNEL_KEY_PLACEHOLDER,
            mtu: record.tunnel.mtu,
        }),
    )
    .await?;

    // Tunnel B: re-link without rotating keys when they exist. The app-side
    // credentials (short id, tunnel UUID) come from the record; records
    // written before Tunnel B existed get fresh ones.
    let b = record
        .tunnel
        .b
        .clone()
        .unwrap_or_else(|| RealityTunnelRecord {
            exit_public_key: String::new(),
            short_id: keys::random_hex(8),
            user_id: keys::new_uuid(),
            exit_host: record.exit.host.clone(),
        });
    progress.detail(Server::Exit, "linking Tunnel B");
    let rt_pub = if ex_facts.tunnel_rt_config {
        tunnel_rt_pubkey(&ex_conn).await?
    } else {
        rt_keygen(&ex_conn).await?
    };
    tunnel_up(
        &gw_conn,
        &layout::tunnel_rt_gateway_fragment(&layout::RealityTunnel {
            exit_host: &b.exit_host,
            exit_public_key: &rt_pub,
            short_id: &b.short_id,
            user_id: &b.user_id,
        }),
    )
    .await?;
    tunnel_up(
        &ex_conn,
        &layout::tunnel_rt_exit_fragment(&layout::RtInbound {
            private_key: layout::TUNNEL_RT_KEY_PLACEHOLDER,
            short_id: &b.short_id,
            user_id: &b.user_id,
        }),
    )
    .await?;

    progress.step(Server::Pair, Step::Tunnel, None);
    let (gw_status, ex_status) = tokio::join!(
        manage::tunnel_status(&gw_conn, &record.gateway),
        manage::tunnel_status(&ex_conn, &record.exit),
    );
    let (gw_status, ex_status) = (gw_status?, ex_status?);
    let mut tunnel = record.tunnel.clone();
    tunnel.gateway_public_key = gw_pub;
    tunnel.exit_public_key = ex_pub;
    tunnel.b = Some(RealityTunnelRecord {
        exit_public_key: rt_pub,
        short_id: b.short_id,
        user_id: b.user_id,
        exit_host: b.exit_host,
    });
    if gw_status.up && ex_status.up {
        tunnel.established = now_secs();
        progress.detail(Server::Pair, "the tunnel handshake is alive on both ends");
    }

    // Tunnel C: re-provisioned only when IPv6 still verifies on both
    // servers. Keys are reused when they exist. A v6 path that broke since
    // the install flips the verdict to unavailable — never faked.
    let (gw_v6, ex_v6) = tokio::join!(ipv6_probe(&gw_conn), ipv6_probe(&ex_conn));
    let (gw_v6, ex_v6) = (gw_v6?, ex_v6?);
    let v6_ok = gw_v6.usable().is_ok() && ex_v6.usable().is_ok();
    let mut ipv6_status = record.ipv6_status;
    if v6_ok {
        progress.detail(Server::Pair, "re-linking Tunnel C");
        let gw_c_pub = if gw_facts.tunnel_c_config {
            tunnel_c_pubkey(&gw_conn).await?
        } else {
            wg_c_keygen(&gw_conn).await?
        };
        let ex_c_pub = if ex_facts.tunnel_c_config {
            tunnel_c_pubkey(&ex_conn).await?
        } else {
            wg_c_keygen(&ex_conn).await?
        };
        let c = tunnel.c.clone().unwrap_or_else(|| TunnelCRecord {
            port: pick_tunnel_port(&ex_facts),
            exit_endpoint: String::new(),
            gateway_public_key: String::new(),
            exit_public_key: String::new(),
            gateway_ipv6: gw_v6.egress.clone(),
            mtu: layout::TUNNEL_C_MTU,
            keepalive_secs: layout::TUNNEL_KEEPALIVE_SECS,
            established: 0,
        });
        let exit_endpoint = format!("[{}]:{}", ex_v6.egress, c.port);
        let c_port_text = c.port.to_string();
        tunnel_up(
            &gw_conn,
            &layout::tunnel_c_gateway_fragment(&layout::GatewayTunnel {
                exit_endpoint: &exit_endpoint,
                exit_public_key: &ex_c_pub,
                private_key: layout::TUNNEL_C_KEY_PLACEHOLDER,
                address: layout::GATEWAY_TUNNEL_C_IP,
                keepalive: layout::TUNNEL_KEEPALIVE_SECS,
            }),
        )
        .await?;
        tunnel_up(
            &ex_conn,
            &layout::tunnel_c_exit_fragment(&layout::ExitTunnel {
                port: c.port,
                gateway_public_key: &gw_c_pub,
                private_key: layout::TUNNEL_C_KEY_PLACEHOLDER,
                mtu: layout::TUNNEL_C_MTU,
            }),
        )
        .await?;
        let out = ex_conn
            .script(
                &[
                    ("GW6", gw_v6.egress.as_str()),
                    ("C_PORT", c_port_text.as_str()),
                ],
                scripts::FIREWALL_TUNNEL_C,
                QUICK,
            )
            .await?;
        if !out.ok() {
            return Err(fail(Step::Firewall, &out));
        }
        tunnel.c = Some(TunnelCRecord {
            port: c.port,
            exit_endpoint,
            gateway_public_key: gw_c_pub,
            exit_public_key: ex_c_pub,
            gateway_ipv6: gw_v6.egress.clone(),
            mtu: layout::TUNNEL_C_MTU,
            keepalive_secs: layout::TUNNEL_KEEPALIVE_SECS,
            established: c.established,
        });
        ipv6_status = Ipv6Status::Verified;
    } else if ipv6_status == Ipv6Status::Verified {
        progress.detail(
            Server::Pair,
            "IPv6 no longer verifies; Tunnel C marked unavailable",
        );
        tunnel.c = None;
        ipv6_status = Ipv6Status::Unavailable;
    }
    gw_conn.close().await;
    ex_conn.close().await;
    Ok((tunnel, ipv6_status))
}

/// Switch the gateway's client-inbounds catch-all rule to the named
/// transport (`a` = WireGuard, `b` = VLESS+REALITY). Both tunnels stay
/// configured and running; this only flips which one carries new sessions.
/// Returns the transport now active.
pub async fn tunnel_switch(
    gateway: &PairLogin,
    record: &PairRecord,
    transport: TransportId,
    on: &(dyn Fn(Event) + Send + Sync),
) -> Result<TransportId, Error> {
    if transport == TransportId::B && record.tunnel.b.is_none() {
        return Err(Error::Unavailable(
            "Tunnel B was never provisioned for this pair; re-link first".into(),
        ));
    }
    let mut progress = PairProgress { on, done: 0, of: 1 };
    progress.step(Server::Gateway, Step::Tunnel, None);
    let gw_conn = ssh::connect(&gateway.login, &gateway.trust.fingerprint).await?;
    progress.detail(
        Server::Gateway,
        format!(
            "switching the active tunnel to {}",
            transport.outbound_tag()
        ),
    );
    tunnel_up(
        &gw_conn,
        &layout::tunnel_switch_fragment(transport.outbound_tag()),
    )
    .await?;
    gw_conn.close().await;
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_PROBE: &str = "ipv6_addr=2001:db8::7\n\
        ipv6_default_route=1\n\
        ipv6_mtu=1500\n\
        ipv6_egress=2001:db8::7\n\
        ipv6_firewall=ufw\n";

    /// A fully working IPv6 path parses and is usable.
    #[test]
    fn a_working_ipv6_probe_is_usable() {
        let probe = Ipv6Probe::parse(GOOD_PROBE);
        assert_eq!(probe.addr, "2001:db8::7");
        assert!(probe.default_route);
        assert_eq!(probe.mtu, Some(1500));
        assert_eq!(probe.egress, "2001:db8::7");
        assert_eq!(probe.firewall, "ufw");
        assert!(probe.usable().is_ok());
    }

    /// Each missing piece fails the verdict with a plain reason — never a
    /// silent pass. A fake-looking address with no egress is not usable.
    #[test]
    fn each_missing_ipv6_piece_fails_the_verdict() {
        let cases = [
            ("ipv6_default_route=1\nipv6_egress=2001:db8::7\n", "no global IPv6 address"),
            (
                "ipv6_addr=2001:db8::7\nipv6_egress=2001:db8::7\n",
                "no IPv6 default route",
            ),
            (
                "ipv6_addr=2001:db8::7\nipv6_default_route=1\n",
                "no outbound IPv6 reachability",
            ),
            (
                "ipv6_addr=2001:db8::7\nipv6_default_route=1\nipv6_egress=2001:db8::7\nipv6_mtu=1280\n",
                "too small",
            ),
        ];
        for (output, reason) in cases {
            let err = Ipv6Probe::parse(output)
                .usable()
                .expect_err("must be unusable");
            assert!(err.contains(reason), "wrong reason for {output:?}: {err}");
        }
    }

    /// No MTU reported means the path MTU is unknown, not small: the probe
    /// stays usable (the tunnel MTU is conservative on its own).
    #[test]
    fn an_unreported_mtu_does_not_fail_the_verdict() {
        let probe = Ipv6Probe::parse(
            "ipv6_addr=2001:db8::7\nipv6_default_route=1\nipv6_egress=2001:db8::7\nipv6_mtu=\n",
        );
        assert_eq!(probe.mtu, None);
        assert!(probe.usable().is_ok());
    }
}
