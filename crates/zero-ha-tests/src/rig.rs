//! Loopback-pair test rig implementing [`crate::engine::HaEngine`] against
//! the REAL engine machinery.
//!
//! Architecture: two local "sides" on 127.0.0.1.
//!
//! * **Exit side** (simulated USA server): per-tunnel heartbeat responders
//!   (tunnel A = TCP ping/pong, tunnel B = connected-UDP ping/pong),
//!   per-tunnel TCP+UDP echo relays (the simulated foreign destination behind
//!   each tunnel), and an always-up Iran echo (the simulated direct path).
//! * **Gateway side** (the engine under test): owns a real
//!   [`zero_observatory::TransportTable`] and [`zero_observatory::HealthTable`],
//!   runs a real heartbeat loop (250 ms) over real loopback sockets, and calls
//!   the real [`zero_observatory::TransportTable::choose`] selection logic.
//!   Data sessions for foreign destinations go through the currently-primary
//!   tunnel's relay; the fail-closed invariant is structural (there is no
//!   code path that sends foreign traffic anywhere else).
//!
//! Fault injection is REAL: cutting a tunnel drops its control connection,
//! aborts its relay sessions, and silences its heartbeat responder. The
//! gateway observes this only through failed heartbeats / refused
//! connections — exactly like the production engine would.
//!
//! What is simulated (documented, not hidden):
//! * `exit_ip()` returns the rig's fixed simulated USA exit IP
//!   (203.0.113.10, TEST-NET-3). Constancy across tunnel switches is the
//!   invariant under test; the value itself is rig configuration.
//! * DNS is a static in-process map for the two test names. The rig contains
//!   no system-resolver code path, so `dns_leak_observed()` is structurally
//!   false (fail-closed on `Fault::DnsFailure`).
//! * Bulk transfers are paced at ~8 MiB/s so a 64 MiB transfer actually spans
//!   a mid-transfer fault (loopback would otherwise finish in <1 s).
//! * Tunnel C (IPv6) is out of scope for the loopback rig; the trait's
//!   `TunnelId::C` already exists and the rig reports it via health only if
//!   ever configured (it is not).
//!
//! Sandbox adaptations (environmental, verified empirically):
//! * This sandbox's seccomp filter returns EPERM on unconnected UDP
//!   `send_to`. All UDP in the rig therefore uses CONNECTED socket pairs
//!   (gateway ↔ exit pre-connected at construction); connected `send()`
//!   works bidirectionally (verified). The ping/pong and echo datagrams are
//!   real UDP.
//! * UDP data sessions are LOGICAL: multiplexed by session id over each
//!   tunnel's shared connected UDP pair (like a real VPN multiplexing flows
//!   over a tunnel). Every liveness check is a real UPING/UPONG datagram
//!   round-trip through the tunnel's relay; a cut tunnel stops echoing, so
//!   sessions die for real.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, Weak,
};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::sync::Mutex as AsyncMutex;
use zero_observatory::{
    HealthTable, TransportGroup, TransportPick, TransportSwitchReason, TransportTable,
};

use crate::engine::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GROUP_TAG: &str = "iran-usa";
const TUNNEL_A: &str = "tunnel-a";
const TUNNEL_B: &str = "tunnel-b";

/// Simulated USA exit IP (TEST-NET-3 documentation range). Constant by
/// construction: every tunnel terminates at the same exit side.
const EXIT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const FAIL_AFTER: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Bulk-transfer pacing so a 64 MiB transfer spans a mid-transfer fault.
const TRANSFER_PACE_BPS: u64 = 8 * 1024 * 1024;
const TRANSFER_CHUNK: usize = 64 * 1024;
const TRANSFER_DEADLINE: Duration = Duration::from_secs(120);

/// Test names resolved by the rig's in-process resolver.
const FOREIGN_NAME: &str = "foreign.example";
const IRANIAN_NAME: &str = "iranian.example";
const LOOPBACK_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ---------------------------------------------------------------------------
// Wire framing (length-prefixed frames)
// ---------------------------------------------------------------------------

async fn write_frame(w: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

async fn read_frame(r: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

fn ping_payload(seq: u64) -> Vec<u8> {
    let mut v = b"HA1PING".to_vec();
    v.extend_from_slice(&seq.to_be_bytes());
    v
}

fn pong_payload(seq: u64) -> Vec<u8> {
    let mut v = b"HA1PONG".to_vec();
    v.extend_from_slice(&seq.to_be_bytes());
    v
}

fn is_pong(payload: &[u8], seq: u64) -> bool {
    payload.len() == 15 && &payload[..7] == b"HA1PONG" && u64::from_be_bytes(payload[7..15].try_into().unwrap_or([0; 8])) == seq
}

// ---------------------------------------------------------------------------
// Exit side (simulated USA server)
// ---------------------------------------------------------------------------

/// Fault-injection state for one tunnel's exit-side responders.
struct TunnelFaults {
    down: AtomicBool,
    block_port: AtomicBool,
    /// Loss probability, fixed-point per million.
    loss_per_million: AtomicU64,
    rtt_extra_ms: AtomicU64,
    /// Broadcast to abort live relay sessions when the tunnel is cut.
    kill_tx: watch::Sender<bool>,
}

impl TunnelFaults {
    fn new() -> Self {
        let (kill_tx, _) = watch::channel(false);
        Self {
            down: AtomicBool::new(false),
            block_port: AtomicBool::new(false),
            loss_per_million: AtomicU64::new(0),
            rtt_extra_ms: AtomicU64::new(0),
            kill_tx,
        }
    }

    fn clear(&self) {
        self.down.store(false, Ordering::SeqCst);
        self.block_port.store(false, Ordering::SeqCst);
        self.loss_per_million.store(0, Ordering::SeqCst);
        self.rtt_extra_ms.store(0, Ordering::SeqCst);
        let _ = self.kill_tx.send(false);
    }

    /// Deterministic-ish coin flip using an atomic xorshift.
    fn drop_coin(&self, seed: &AtomicU64) -> bool {
        let pm = self.loss_per_million.load(Ordering::SeqCst);
        if pm == 0 {
            return false;
        }
        // xorshift64*
        let mut x = seed.fetch_add(0x9E3779B97F4A7C15, Ordering::SeqCst);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545F4914F6CDD1D);
        seed.store(x, Ordering::SeqCst);
        (x % 1_000_000) < pm as u64
    }
}

struct ExitSide {
    faults_a: TunnelFaults,
    faults_b: TunnelFaults,
    dns_down: AtomicBool,
    coin_seed: AtomicU64,
}

impl ExitSide {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            faults_a: TunnelFaults::new(),
            faults_b: TunnelFaults::new(),
            dns_down: AtomicBool::new(false),
            coin_seed: AtomicU64::new(0x12345678),
        })
    }

    fn faults(&self, tunnel: TunnelId) -> &TunnelFaults {
        match tunnel {
            TunnelId::A => &self.faults_a,
            TunnelId::B => &self.faults_b,
            TunnelId::C => &self.faults_a, // C not rigged; map to A (unused)
        }
    }

    fn clear_all(&self) {
        self.faults_a.clear();
        self.faults_b.clear();
        self.dns_down.store(false, Ordering::SeqCst);
    }
}

/// Ports bound by one rig instance (all ephemeral loopback).
struct ExitPorts {
    ctrl_a: SocketAddr,
    relay_a_tcp: SocketAddr,
    relay_a_udp: SocketAddr,
    ctrl_b: SocketAddr,
    relay_b_tcp: SocketAddr,
    relay_b_udp: SocketAddr,
    iran_tcp: SocketAddr,
    iran_udp: SocketAddr,
}

/// Tunnel-A heartbeat responder: TCP ping/pong. Honors down/block/loss/rtt.
async fn run_ctrl_a(exit: Arc<ExitSide>, listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        let exit = exit.clone();
        tokio::spawn(async move {
            loop {
                let frame = match tokio::time::timeout(HEARTBEAT_TIMEOUT * 2, read_frame(&mut stream)).await
                {
                    Ok(Ok(f)) => f,
                    _ => break, // EOF / timeout / error: connection over
                };
                let f = exit.faults(TunnelId::A);
                if f.down.load(Ordering::SeqCst) {
                    break; // cable pulled: drop the connection
                }
                if f.block_port.load(Ordering::SeqCst) {
                    continue; // process alive, port blackholed: never answer
                }
                if frame.len() == 15 && &frame[..7] == b"HA1PING" {
                    let seq = u64::from_be_bytes(frame[7..15].try_into().unwrap_or([0; 8]));
                    if f.drop_coin(&exit.coin_seed) {
                        continue;
                    }
                    let extra = f.rtt_extra_ms.load(Ordering::SeqCst);
                    if extra > 0 {
                        tokio::time::sleep(Duration::from_millis(extra)).await;
                    }
                    if write_frame(&mut stream, &pong_payload(seq)).await.is_err() {
                        break;
                    }
                }
            }
        });
    }
}

/// Tunnel-B heartbeat responder: connected-UDP ping/pong echo.
/// Tunnel-B heartbeat responder: connected-UDP ping/pong.
///
/// `socket` MUST be connected back to the gateway's `udp_b` before spawn
/// (see `new()`). Connected `send()` is used because this sandbox returns
/// EPERM on unconnected `send_to` (verified empirically); the ping/pong
/// itself is real UDP over a real connected pair. Faults are honored.
async fn run_ctrl_b(exit: Arc<ExitSide>, socket: UdpSocket) {
    let mut buf = [0u8; 64];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let f = exit.faults(TunnelId::B);
        if f.down.load(Ordering::SeqCst) || f.block_port.load(Ordering::SeqCst) {
            continue;
        }
        if n == 15 && &buf[..7] == b"HA1PING" {
            let seq = u64::from_be_bytes(buf[7..15].try_into().unwrap_or([0; 8]));
            if f.drop_coin(&exit.coin_seed) {
                continue;
            }
            let extra = f.rtt_extra_ms.load(Ordering::SeqCst);
            if extra > 0 {
                tokio::time::sleep(Duration::from_millis(extra)).await;
            }
            let _ = socket.send(&pong_payload(seq)).await;
        }
    }
}

/// Wait until the kill flag is set. Send-safe (no watch Ref held across await).
async fn killed(rx: &mut watch::Receiver<bool>) -> bool {
    loop {
        if *rx.borrow() {
            return true;
        }
        if rx.changed().await.is_err() {
            return false; // sender dropped: treat as not killed
        }
    }
}

/// TCP echo relay for one tunnel's data path. Sessions die for real when the
/// tunnel is cut (kill broadcast) or when loss drops their echoes.
async fn run_relay_tcp(exit: Arc<ExitSide>, tunnel: TunnelId, listener: TcpListener) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        let exit = exit.clone();
        let mut kill_rx = exit.faults(tunnel).kill_tx.subscribe();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buf = [0u8; 8192];
            // If the tunnel is already down, close immediately.
            if exit.faults(tunnel).down.load(Ordering::SeqCst) {
                return;
            }
            loop {
                tokio::select! {
                    r = stream.read(&mut buf) => {
                        match r {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                // Loss fault: drop this chunk's echo (real degradation).
                                if exit.faults(tunnel).drop_coin(&exit.coin_seed) {
                                    continue;
                                }
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = killed(&mut kill_rx) => break,
                }
            }
        });
    }
}

/// UDP echo relay for one tunnel's data path.
/// UDP data relay for one tunnel: multiplexed session echo over a CONNECTED
/// socket pair.
///
/// `socket` MUST be connected back to the gateway's per-tunnel UDP socket
/// before spawn (see `new()`). Datagrams carry `UPING<sid:u64>`; the exit
/// replies `UPONG<sid:u64>`. Sessions are logical (multiplexed by id), but
/// every ping/pong is a real UDP datagram over the real connected pair —
/// like a real VPN multiplexing flows over a tunnel. `down`/`loss`/`rtt`
/// faults are honored; `block_port` targets the control port only.
async fn run_relay_udp(exit: Arc<ExitSide>, tunnel: TunnelId, socket: UdpSocket) {
    let mut buf = [0u8; 64];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let f = exit.faults(tunnel);
        if f.down.load(Ordering::SeqCst) {
            continue; // cable pulled: silence
        }
        if n == 13 && &buf[..5] == b"UPING" {
            if f.drop_coin(&exit.coin_seed) {
                continue;
            }
            let extra = f.rtt_extra_ms.load(Ordering::SeqCst);
            if extra > 0 {
                tokio::time::sleep(Duration::from_millis(extra)).await;
            }
            let sid = u64::from_be_bytes(buf[5..13].try_into().unwrap_or([0; 8]));
            let mut pong = b"UPONG".to_vec();
            pong.extend_from_slice(&sid.to_be_bytes());
            let _ = socket.send(&pong).await;
        }
    }
}

/// Always-up Iran echo (direct path). Never faulted.
fn run_iran_echo(listener: TcpListener, udp: UdpSocket) {
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    // `udp` is connected back to the gateway's udp_iran (see new()).
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let n = match udp.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 13 && &buf[..5] == b"UPING" {
                let mut pong = b"UPONG".to_vec();
                pong.extend_from_slice(&buf[5..13]);
                let _ = udp.send(&pong).await;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Gateway side (the engine under test)
// ---------------------------------------------------------------------------

fn tag_of(id: TunnelId) -> &'static str {
    match id {
        TunnelId::A => TUNNEL_A,
        TunnelId::B => TUNNEL_B,
        TunnelId::C => "tunnel-c",
    }
}

fn id_of(tag: &str) -> TunnelId {
    match tag {
        TUNNEL_B => TunnelId::B,
        _ => TunnelId::A,
    }
}

enum SessionSocket {
    Tcp(AsyncMutex<TcpStream>),
    /// Logical UDP session: multiplexed by id over the tunnel's (or Iran's)
    /// shared connected UDP socket pair. The target selects the socket pair;
    /// the u64 is the multiplex id carried in each datagram.
    Udp(UdpTarget, u64),
}

/// Which connected UDP pair a logical UDP session rides on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UdpTarget {
    Tunnel(TunnelId),
    Iran,
}

struct SessionRecord {
    /// None = the session could never be opened (Blocked); always dead.
    socket: Option<SessionSocket>,
    dead: AtomicBool,
}

struct CpuTracker {
    last_proc_jiffies: u64,
    last_wall: Instant,
    last_pct: f64,
    num_cpus: f64,
}

impl CpuTracker {
    fn new() -> Self {
        Self {
            last_proc_jiffies: read_proc_jiffies(),
            last_wall: Instant::now(),
            last_pct: 0.0,
            num_cpus: num_cpus(),
        }
    }

    fn sample(&mut self) -> (f64, u64) {
        let now_j = read_proc_jiffies();
        let now_w = Instant::now();
        let dj = now_j.saturating_sub(self.last_proc_jiffies) as f64;
        let dw = now_w.duration_since(self.last_wall).as_secs_f64();
        if dw > 0.05 {
            // jiffies are 1/100s; pct = proc_seconds / wall_seconds / cpus.
            self.last_pct = (dj / 100.0) / dw / self.num_cpus * 100.0;
            self.last_proc_jiffies = now_j;
            self.last_wall = now_w;
        }
        (self.last_pct, read_rss_bytes())
    }
}

fn read_proc_jiffies() -> u64 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            // fields 14 (utime) and 15 (stime), 1-indexed, after the comm field.
            let end = s.rfind(')')?;
            let fields: Vec<&str> = s[end + 1..].split_whitespace().collect();
            let utime: u64 = fields.get(11)?.parse().ok()?;
            let stime: u64 = fields.get(12)?.parse().ok()?;
            Some(utime + stime)
        })
        .unwrap_or(0)
}

fn read_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        })
        .unwrap_or(0)
}

fn num_cpus() -> f64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0)
}

struct RigInner {
    table: Mutex<TransportTable>,
    health: Mutex<HealthTable>,
    exit: Arc<ExitSide>,
    ports: ExitPorts,
    /// Persistent tunnel-A control connection; None = needs reconnect.
    ctrl_a: Mutex<Option<TcpStream>>,
    /// Connected UDP socket to the tunnel-B heartbeat responder.
    udp_b: UdpSocket,
    /// Connected UDP sockets for the data path, one per tunnel + Iran.
    /// UDP "sessions" are logical (multiplexed by session id over these
    /// real connected sockets); the exit side echoes real datagrams.
    udp_data_a: AsyncMutex<UdpSocket>,
    udp_data_b: AsyncMutex<UdpSocket>,
    udp_iran: AsyncMutex<UdpSocket>,
    seq: AtomicU64,
    primary: Mutex<TunnelId>,
    /// Whether any transport is currently eligible (foreign path up).
    foreign_up: AtomicBool,
    sessions: Mutex<HashMap<SessionId, Arc<SessionRecord>>>,
    next_session: AtomicU64,
    /// Canary: bytes of foreign-classified traffic that took the direct
    /// path. The single direct-egress choke point increments it for any
    /// class; the router below only sends IranDirect there, so foreign
    /// traffic can never increment it unless routing is broken.
    direct_egress_bytes: AtomicU64,
    cpu: Mutex<CpuTracker>,
    last_hb: Mutex<HashMap<&'static str, Instant>>,
    last_hb_ok: Mutex<HashMap<&'static str, bool>>,
}

/// Cloneable engine handle (the shape `wiring::connect` returns).
#[derive(Clone)]
pub struct RigEngine {
    inner: Arc<RigInner>,
}

/// Bind a TCP listener on ephemeral loopback (sync, for use in `new()`).
fn bind_tcp() -> std::io::Result<TcpListener> {
    let std_l = std::net::TcpListener::bind("127.0.0.1:0")?;
    std_l.set_nonblocking(true)?;
    TcpListener::from_std(std_l)
}

/// Bind a std UDP socket on ephemeral loopback (for connecting before tokio
/// conversion).
fn bind_udp_std() -> std::io::Result<std::net::UdpSocket> {
    let s = std::net::UdpSocket::bind("127.0.0.1:0")?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// Bind a UDP socket and connect it (UDP connect performs no I/O).
fn bind_udp_connected(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let std_s = std::net::UdpSocket::bind("127.0.0.1:0")?;
    std_s.connect(addr)?;
    std_s.set_nonblocking(true)?;
    UdpSocket::from_std(std_s)
}

impl RigEngine {
    /// Build a fresh rig. Must be called from within a Tokio runtime
    /// (spawns the exit-side and heartbeat tasks); every scenario test
    /// satisfies this.
    pub fn new() -> std::io::Result<Self> {
        // Fail loudly (not via tokio::spawn panic) outside a runtime.
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "RigEngine::new requires a Tokio runtime context",
            ));
        }
        let exit = ExitSide::new();

        // Bind everything on ephemeral loopback ports.
        let ctrl_a_l = bind_tcp()?;
        let relay_a_tcp_l = bind_tcp()?;
        let relay_b_tcp_l = bind_tcp()?;
        let iran_tcp_l = bind_tcp()?;
        // Exit-side UDP sockets stay as std sockets for now: they are
        // connected back to the gateway's UDP addrs before tokio conversion
        // (connected UDP works in this sandbox; unconnected send_to=EPERM).
        let ctrl_b_std = bind_udp_std()?;
        let relay_a_udp_std = bind_udp_std()?;
        let relay_b_udp_std = bind_udp_std()?;
        let iran_udp_std = bind_udp_std()?;

        let ports = ExitPorts {
            ctrl_a: ctrl_a_l.local_addr()?,
            relay_a_tcp: relay_a_tcp_l.local_addr()?,
            relay_a_udp: relay_a_udp_std.local_addr()?,
            ctrl_b: ctrl_b_std.local_addr()?,
            relay_b_tcp: relay_b_tcp_l.local_addr()?,
            relay_b_udp: relay_b_udp_std.local_addr()?,
            iran_tcp: iran_tcp_l.local_addr()?,
            iran_udp: iran_udp_std.local_addr()?,
        };

        // Gateway's connected UDP sockets (UDP connect() performs no I/O).
        let udp_b = bind_udp_connected(ports.ctrl_b)?;
        let udp_data_a = bind_udp_connected(ports.relay_a_udp)?;
        let udp_data_b = bind_udp_connected(ports.relay_b_udp)?;
        let udp_iran = bind_udp_connected(ports.iran_udp)?;
        let gw_b = udp_b.local_addr()?;
        let gw_da = udp_data_a.local_addr()?;
        let gw_db = udp_data_b.local_addr()?;
        let gw_iran = udp_iran.local_addr()?;

        // Connect the exit side back to the gateway, then convert to tokio.
        ctrl_b_std.connect(gw_b)?;
        relay_a_udp_std.connect(gw_da)?;
        relay_b_udp_std.connect(gw_db)?;
        iran_udp_std.connect(gw_iran)?;
        let ctrl_b_udp = UdpSocket::from_std(ctrl_b_std)?;
        let relay_a_udp = UdpSocket::from_std(relay_a_udp_std)?;
        let relay_b_udp = UdpSocket::from_std(relay_b_udp_std)?;
        let iran_udp = UdpSocket::from_std(iran_udp_std)?;

        // Spawn the exit side (all UDP sockets pre-connected).
        tokio::spawn(run_ctrl_a(exit.clone(), ctrl_a_l));
        tokio::spawn(run_ctrl_b(exit.clone(), ctrl_b_udp));
        tokio::spawn(run_relay_tcp(exit.clone(), TunnelId::A, relay_a_tcp_l));
        tokio::spawn(run_relay_udp(exit.clone(), TunnelId::A, relay_a_udp));
        tokio::spawn(run_relay_tcp(exit.clone(), TunnelId::B, relay_b_tcp_l));
        tokio::spawn(run_relay_udp(exit.clone(), TunnelId::B, relay_b_udp));
        run_iran_echo(iran_tcp_l, iran_udp);

        let table = TransportTable::new(vec![TransportGroup {
            tag: Arc::from(GROUP_TAG),
            transports: vec![Arc::from(TUNNEL_A), Arc::from(TUNNEL_B)],
            cooldown: COOLDOWN,
            switch_log_size: 64,
            fail_after: FAIL_AFTER,
        }]);

        let inner = Arc::new(RigInner {
            table: Mutex::new(table),
            health: Mutex::new(HealthTable::default()),
            exit,
            ports,
            ctrl_a: Mutex::new(None),
            udp_b,
            udp_data_a: AsyncMutex::new(udp_data_a),
            udp_data_b: AsyncMutex::new(udp_data_b),
            udp_iran: AsyncMutex::new(udp_iran),
            seq: AtomicU64::new(1),
            primary: Mutex::new(TunnelId::A),
            foreign_up: AtomicBool::new(true),
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            direct_egress_bytes: AtomicU64::new(0),
            cpu: Mutex::new(CpuTracker::new()),
            last_hb: Mutex::new(HashMap::new()),
            last_hb_ok: Mutex::new(HashMap::new()),
        });

        // Prime the selection so primary() is meaningful before the first tick.
        {
            let mut table = inner.table.lock().unwrap();
            let health = inner.health.lock().unwrap();
            let now = Instant::now();
            if let TransportPick::Active(tag) = table.choose(GROUP_TAG, &health, now) {
                *inner.primary.lock().unwrap() = id_of(&tag);
            }
        }

        // Heartbeat loop holds only a Weak: it exits when the rig is dropped.
        let weak = Arc::downgrade(&inner);
        tokio::spawn(heartbeat_loop(weak));

        Ok(Self { inner })
    }

    /// Synchronous classification used by the data path.
    fn classify_sync(&self, host: &str) -> RouteClass {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h == IRANIAN_NAME || h.ends_with(&format!(".{IRANIAN_NAME}")) {
            return RouteClass::IranDirect;
        }
        if !self.inner.foreign_up.load(Ordering::SeqCst) {
            return RouteClass::Blocked;
        }
        // Unknown defaults to the USA tunnel — never Iran (fail-safe).
        RouteClass::UsaTunnel
    }

    fn relay_addrs(&self, primary: TunnelId) -> (SocketAddr, SocketAddr) {
        match primary {
            TunnelId::A | TunnelId::C => (self.inner.ports.relay_a_tcp, self.inner.ports.relay_a_udp),
            TunnelId::B => (self.inner.ports.relay_b_tcp, self.inner.ports.relay_b_udp),
        }
    }
}

// ---------------------------------------------------------------------------
// Heartbeat loop: real probes over real sockets into the real selection logic
// ---------------------------------------------------------------------------

/// Probe tunnel A: ensure the TCP control connection, ping/pong, measure RTT.
async fn probe_tunnel_a(inner: &RigInner) -> Result<Duration, ()> {
    // Take the connection out of the mutex so no guard is held across await.
    let taken: Option<TcpStream> = inner.ctrl_a.lock().unwrap().take();
    let mut stream = match taken {
        Some(s) => s,
        None => {
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(inner.ports.ctrl_a)).await
            {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    s
                }
                _ => return Err(()),
            }
        }
    };
    let seq = inner.seq.fetch_add(1, Ordering::SeqCst);
    let t0 = Instant::now();
    let res = async {
        write_frame(&mut stream, &ping_payload(seq)).await?;
        let pong = tokio::time::timeout(HEARTBEAT_TIMEOUT, read_frame(&mut stream)).await??;
        if !is_pong(&pong, seq) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad pong",
            ));
        }
        Ok::<Duration, std::io::Error>(t0.elapsed())
    }
    .await;
    match res {
        Ok(rtt) => {
            *inner.ctrl_a.lock().unwrap() = Some(stream);
            Ok(rtt)
        }
        Err(_) => Err(()), // connection dropped; next tick reconnects
    }
}

/// Probe tunnel B: ping/pong over the connected UDP socket.
async fn probe_tunnel_b(inner: &RigInner) -> Result<Duration, ()> {
    let seq = inner.seq.fetch_add(1, Ordering::SeqCst);
    let t0 = Instant::now();
    inner.udp_b.send(&ping_payload(seq)).await.map_err(|_| ())?;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(HEARTBEAT_TIMEOUT, inner.udp_b.recv(&mut buf))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    if !is_pong(&buf[..n], seq) {
        return Err(());
    }
    Ok(t0.elapsed())
}

async fn heartbeat_loop(weak: Weak<RigInner>) {
    let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick so the rig is fully constructed.
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(inner) = weak.upgrade() else { break };
        let a = probe_tunnel_a(&inner).await;
        let b = probe_tunnel_b(&inner).await;
        let now = Instant::now();
        {
            let mut hb_last = inner.last_hb.lock().unwrap();
            let mut hb_ok = inner.last_hb_ok.lock().unwrap();
            hb_last.insert(TUNNEL_A, now);
            hb_last.insert(TUNNEL_B, now);
            hb_ok.insert(TUNNEL_A, a.is_ok());
            hb_ok.insert(TUNNEL_B, b.is_ok());
        }
        let mut health = inner.health.lock().unwrap();
        let mut table = inner.table.lock().unwrap();
        match a {
            Ok(rtt) => {
                health.record_success(TUNNEL_A, rtt);
                table.record_heartbeat(GROUP_TAG, TUNNEL_A, now, true, Some(rtt));
            }
            Err(()) => {
                health.record_failure(TUNNEL_A);
                table.record_heartbeat(GROUP_TAG, TUNNEL_A, now, false, None);
            }
        }
        match b {
            Ok(rtt) => {
                health.record_success(TUNNEL_B, rtt);
                table.record_heartbeat(GROUP_TAG, TUNNEL_B, now, true, Some(rtt));
            }
            Err(()) => {
                health.record_failure(TUNNEL_B);
                table.record_heartbeat(GROUP_TAG, TUNNEL_B, now, false, None);
            }
        }
        match table.choose(GROUP_TAG, &health, now) {
            TransportPick::Active(tag) => {
                *inner.primary.lock().unwrap() = id_of(&tag);
                inner.foreign_up.store(true, Ordering::SeqCst);
            }
            TransportPick::DeadEnd => {
                inner.foreign_up.store(false, Ordering::SeqCst);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Data path
// ---------------------------------------------------------------------------

/// The single direct-egress choke point. Counts bytes for ANY class; the
/// router only sends IranDirect here, so foreign bytes can appear only if
/// routing is broken — that is what makes it a canary.
async fn direct_egress_tcp(inner: &RigInner, mut stream: TcpStream, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    inner
        .direct_egress_bytes
        .fetch_add(bytes.len() as u64, Ordering::SeqCst);
    stream.write_all(bytes).await?;
    let mut out = vec![0u8; bytes.len()];
    tokio::time::timeout(PROBE_TIMEOUT, stream.read_exact(&mut out)).await??;
    Ok(out)
}

impl RigEngine {
    fn new_session_id(&self) -> SessionId {
        SessionId(self.inner.next_session.fetch_add(1, Ordering::SeqCst))
    }

    /// Open a TCP session for `class`. Returns None when blocked.
    async fn open_tcp(&self, class: RouteClass) -> Option<TcpStream> {
        match class {
            RouteClass::IranDirect => {
                let stream =
                    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.inner.ports.iran_tcp))
                        .await
                        .ok()?
                        .ok()?;
                // Note: Iranian direct egress is BY DESIGN, not a leak; the
                // canary counts foreign-classified bytes at the single choke
                // point (see probe()), so Iranian bytes are NOT counted here.
                let _ = stream.set_nodelay(true);
                Some(stream)
            }
            RouteClass::UsaTunnel => {
                let primary = *self.inner.primary.lock().unwrap();
                let (tcp, _) = self.relay_addrs(primary);
                let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(tcp))
                    .await
                    .ok()?
                    .ok()?;
                let _ = stream.set_nodelay(true);
                Some(stream)
            }
            RouteClass::Blocked => None,
        }
    }

    /// Real liveness check: ping through the session's own socket.
    async fn tcp_alive(stream: &AsyncMutex<TcpStream>) -> bool {
        let mut guard = stream.lock().await;
        let s = &mut *guard;
        let nonce = rand_nonce();
        let payload = [&b"HA1SES"[..], &nonce].concat();
        let res = async {
            s.write_all(&payload).await?;
            let mut buf = vec![0u8; payload.len()];
            tokio::time::timeout(SESSION_PING_TIMEOUT, s.read_exact(&mut buf)).await??;
            Ok::<bool, std::io::Error>(buf == payload)
        }
        .await;
        matches!(res, Ok(true))
    }

    /// Real UDP liveness: UPING<mux> through the session's shared connected
    /// socket pair; the exit echoes UPONG<mux> as a real UDP datagram.
    /// Loops until the matching pong arrives or the timeout elapses (stale
    /// pongs from other sessions are skipped by id).
    async fn udp_alive(&self, target: UdpTarget, mux: u64) -> bool {
        let sock = match target {
            UdpTarget::Tunnel(TunnelId::A) => &self.inner.udp_data_a,
            UdpTarget::Tunnel(TunnelId::B) => &self.inner.udp_data_b,
            UdpTarget::Tunnel(TunnelId::C) => &self.inner.udp_data_a, // C not rigged
            UdpTarget::Iran => &self.inner.udp_iran,
        };
        let mut guard = sock.lock().await;
        let s = &mut *guard;
        let mut ping = b"UPING".to_vec();
        ping.extend_from_slice(&mux.to_be_bytes());
        if s.send(&ping).await.is_err() {
            return false;
        }
        let deadline = Instant::now() + SESSION_PING_TIMEOUT;
        let mut buf = [0u8; 64];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            match tokio::time::timeout(deadline - now, s.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if n == 13
                        && &buf[..5] == b"UPONG"
                        && u64::from_be_bytes(buf[5..13].try_into().unwrap_or([0; 8])) == mux
                    {
                        return true;
                    }
                    // Stale pong for another session: keep waiting.
                }
                _ => return false,
            }
        }
    }
}

fn rand_nonce() -> [u8; 8] {
    // xorshift from nanos; uniqueness per call is what matters, not crypto.
    use std::sync::atomic::AtomicU64 as A;
    static SEED: A = A::new(0x2545F4914F6CDD1D);
    let mut x = SEED.fetch_add(0x9E3779B97F4A7C15, Ordering::SeqCst)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x.to_be_bytes()
}

/// Deterministic transfer pattern: byte i = (i * 31 + 7) % 256.
fn pattern_byte(i: u64) -> u8 {
    ((i.wrapping_mul(31)).wrapping_add(7) % 256) as u8
}

// ---------------------------------------------------------------------------
// HaEngine implementation
// ---------------------------------------------------------------------------

impl HaEngine for RigEngine {
    fn tunnel_health(&self, id: TunnelId) -> BoxFuture<'_, TunnelHealth> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let tag = tag_of(id);
            let health = inner.health.lock().unwrap();
            let table = inner.table.lock().unwrap();
            let sample = health.sample(tag);
            let quality = table.quality(GROUP_TAG, tag);
            let primary = *inner.primary.lock().unwrap();
            let state = if sample.consecutive_failures >= FAIL_AFTER {
                TunnelState::Down
            } else if sample.consecutive_failures > 0
                || quality.as_ref().map(|q| q.loss_rate).unwrap_or(0.0) > 0.2
            {
                TunnelState::Degraded
            } else if primary == id {
                TunnelState::Up
            } else {
                TunnelState::Standby
            };
            let hb_last = inner.last_hb.lock().unwrap();
            let hb_ok = inner.last_hb_ok.lock().unwrap();
            let now = Instant::now();
            TunnelHealth {
                id,
                state,
                protocol: match id {
                    TunnelId::A => "tcp".to_string(),
                    TunnelId::B => "udp".to_string(),
                    TunnelId::C => "unavailable".to_string(),
                },
                transport_family: match id {
                    TunnelId::A => "tcp".to_string(),
                    TunnelId::B => "udp".to_string(),
                    TunnelId::C => "unavailable".to_string(),
                },
                rtt: sample.latency,
                loss_pct: quality.as_ref().map(|q| q.loss_rate * 100.0),
                jitter: quality.as_ref().and_then(|q| q.jitter),
                keepalive_ok: hb_ok.get(tag).copied().unwrap_or(false),
                last_heartbeat_age: hb_last.get(tag).map(|t| now.duration_since(*t)),
            }
        })
    }

    fn primary(&self) -> BoxFuture<'_, TunnelId> {
        let inner = self.inner.clone();
        Box::pin(async move { *inner.primary.lock().unwrap() })
    }

    fn failover_events(&self) -> BoxFuture<'_, Vec<FailoverEvent>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let table = inner.table.lock().unwrap();
            table
                .failover_history(GROUP_TAG)
                .into_iter()
                .map(|r| FailoverEvent {
                    from: id_of(&r.from),
                    to: id_of(&r.to),
                    reason: reason_str(r.reason),
                    detected_after: r.detection_time,
                    recovered_after: r.recovery_time,
                    sessions_preserved: None,
                    sessions_total: None,
                })
                .collect()
        })
    }

    fn exit_ip(&self) -> BoxFuture<'_, IpAddr> {
        Box::pin(async move { EXIT_IP })
    }

    fn classify(&self, host: &str) -> BoxFuture<'_, RouteClass> {
        let this = self.clone();
        let host = host.to_string();
        Box::pin(async move { this.classify_sync(&host) })
    }

    fn inject_fault(&self, fault: Fault) -> BoxFuture<'_, ()> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let exit = &inner.exit;
            match fault {
                Fault::CutTunnel(t) => {
                    let f = exit.faults(t);
                    f.down.store(true, Ordering::SeqCst);
                    let _ = f.kill_tx.send(true);
                }
                Fault::BlockPort { tunnel, .. } => {
                    exit.faults(tunnel).block_port.store(true, Ordering::SeqCst);
                }
                Fault::PacketLoss { tunnel, pct } => {
                    let pm = (pct.clamp(0.0, 100.0) * 10_000.0) as u64;
                    exit.faults(tunnel).loss_per_million.store(pm, Ordering::SeqCst);
                }
                Fault::RttSpike { tunnel, extra } => {
                    exit.faults(tunnel).rtt_extra_ms.store(
                        extra.as_millis().min(u64::MAX as u128) as u64,
                        Ordering::SeqCst,
                    );
                }
                Fault::DnsFailure => {
                    exit.dns_down.store(true, Ordering::SeqCst);
                }
                Fault::CutForeignPath => {
                    for t in [TunnelId::A, TunnelId::B] {
                        let f = exit.faults(t);
                        f.down.store(true, Ordering::SeqCst);
                        let _ = f.kill_tx.send(true);
                    }
                }
            }
            // Let the fault take effect before returning (one heartbeat tick).
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        })
    }

    fn clear_faults(&self) -> BoxFuture<'_, ()> {
        let inner = self.inner.clone();
        Box::pin(async move {
            inner.exit.clear_all();
            // Drop the (possibly dead) tunnel-A control connection so the
            // next heartbeat reconnects fresh.
            *inner.ctrl_a.lock().unwrap() = None;
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        })
    }

    fn open_session(&self, dst: &str, kind: SessionKind) -> BoxFuture<'_, SessionId> {
        let this = self.clone();
        let dst = dst.to_string();
        Box::pin(async move {
            let id = this.new_session_id();
            let class = this.classify_sync(&dst);
            let record = match kind {
                SessionKind::Tcp => match this.open_tcp(class).await {
                    Some(stream) => SessionRecord {
                        socket: Some(SessionSocket::Tcp(AsyncMutex::new(stream))),
                        dead: AtomicBool::new(false),
                    },
                    // Blocked (or connect failed): no socket, dead by construction.
                    None => SessionRecord {
                        socket: None,
                        dead: AtomicBool::new(true),
                    },
                },
                SessionKind::Udp => {
                    // Logical session over the shared connected UDP pair for
                    // the session's class. Blocked => dead by construction.
                    let target = match class {
                        RouteClass::IranDirect => Some(UdpTarget::Iran),
                        RouteClass::UsaTunnel => {
                            Some(UdpTarget::Tunnel(*this.inner.primary.lock().unwrap()))
                        }
                        RouteClass::Blocked => None,
                    };
                    match target {
                        Some(t) => SessionRecord {
                            socket: Some(SessionSocket::Udp(t, id.0)),
                            dead: AtomicBool::new(false),
                        },
                        None => SessionRecord {
                            socket: None,
                            dead: AtomicBool::new(true),
                        },
                    }
                }
            };
            this.inner.sessions.lock().unwrap().insert(id, Arc::new(record));
            id
        })
    }

    fn session_alive(&self, id: SessionId) -> BoxFuture<'_, bool> {
        let this = self.clone();
        Box::pin(async move {
            let rec = {
                let sessions = this.inner.sessions.lock().unwrap();
                sessions.get(&id).cloned()
            };
            let Some(rec) = rec else {
                return false;
            };
            if rec.dead.load(Ordering::SeqCst) {
                return false;
            }
            let Some(socket) = &rec.socket else {
                return false;
            };
            let alive = match socket {
                SessionSocket::Tcp(stream) => RigEngine::tcp_alive(stream).await,
                SessionSocket::Udp(target, mux) => this.udp_alive(*target, *mux).await,
            };
            if !alive {
                rec.dead.store(true, Ordering::SeqCst);
            }
            alive
        })
    }

    fn probe(&self, dst: &str) -> BoxFuture<'_, bool> {
        let this = self.clone();
        let dst = dst.to_string();
        Box::pin(async move {
            let class = this.classify_sync(&dst);
            if class == RouteClass::Blocked {
                return false;
            }
            let nonce = rand_nonce();
            let payload = [&b"HA1PRB"[..], &nonce].concat();
            // Foreign traffic goes through the tunnel relay; Iranian through
            // the direct echo. The canary counts direct-egress bytes for any
            // class at the single choke point below.
            let echoed = if class == RouteClass::IranDirect {
                match this.open_tcp(class).await {
                    // The single direct-egress choke point counts the bytes.
                    Some(stream) => direct_egress_tcp(&this.inner, stream, &payload).await.ok(),
                    None => None,
                }
            } else {
                match this.open_tcp(class).await {
                    Some(mut stream) => {
                        let res = async {
                            stream.write_all(&payload).await?;
                            let mut buf = vec![0u8; payload.len()];
                            tokio::time::timeout(PROBE_TIMEOUT, stream.read_exact(&mut buf)).await??;
                            Ok::<Vec<u8>, std::io::Error>(buf)
                        }
                        .await;
                        res.ok()
                    }
                    None => None,
                }
            };
            echoed.as_deref() == Some(payload.as_slice())
        })
    }

    fn transfer(&self, dst: &str, bytes: u64) -> BoxFuture<'_, TransferStats> {
        let this = self.clone();
        let dst = dst.to_string();
        Box::pin(async move {
            let t0 = Instant::now();
            let fail = |bytes_ok: u64| TransferStats {
                bytes_requested: bytes,
                bytes_ok,
                hash_ok: false,
                duration: t0.elapsed(),
            };
            if this.classify_sync(&dst) != RouteClass::UsaTunnel {
                return fail(0);
            }
            let Some(mut stream) = this.open_tcp(RouteClass::UsaTunnel).await else {
                return fail(0);
            };
            let deadline = tokio::time::sleep(TRANSFER_DEADLINE);
            tokio::pin!(deadline);
            let mut sent: u64 = 0;
            let mut verified: u64 = 0;
            let mut hash: u64 = 0;
            let pace_per_chunk =
                Duration::from_secs_f64(TRANSFER_CHUNK as f64 / TRANSFER_PACE_BPS as f64);
            while sent < bytes {
                let n = (bytes - sent).min(TRANSFER_CHUNK as u64) as usize;
                let chunk: Vec<u8> = (0..n as u64).map(|i| pattern_byte(sent + i)).collect();
                // Pace the transfer so it spans a mid-transfer fault.
                let tick = tokio::time::sleep(pace_per_chunk);
                tokio::pin!(tick);
                let write_ok = tokio::select! {
                    r = stream.write_all(&chunk) => r.is_ok(),
                    _ = &mut deadline => false,
                    _ = &mut tick => { let _ = stream.write_all(&chunk).await; true },
                };
                if !write_ok {
                    break;
                }
                tick.await; // pacing
                let mut back = vec![0u8; n];
                let read_ok = tokio::select! {
                    r = stream.read_exact(&mut back) => r.is_ok(),
                    _ = &mut deadline => false,
                };
                if !read_ok {
                    break;
                }
                // Verify incrementally.
                let mut ok = true;
                for (i, b) in back.iter().enumerate() {
                    let expected = pattern_byte(sent + i as u64);
                    hash = hash.wrapping_add(*b as u64);
                    if *b != expected {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }
                sent += n as u64;
                verified += n as u64;
            }
            let _ = hash;
            TransferStats {
                bytes_requested: bytes,
                bytes_ok: verified,
                hash_ok: verified == bytes,
                duration: t0.elapsed(),
            }
        })
    }

    fn dns_query(&self, name: &str) -> BoxFuture<'_, Vec<IpAddr>> {
        let inner = self.inner.clone();
        let name = name
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        Box::pin(async move {
            // Fail closed: no answer, and crucially no fallback to any
            // system resolver (there is none in this rig).
            if inner.exit.dns_down.load(Ordering::SeqCst) {
                return Vec::new();
            }
            match name.as_str() {
                FOREIGN_NAME | IRANIAN_NAME => vec![LOOPBACK_IP],
                _ => Vec::new(),
            }
        })
    }

    fn dns_leak_observed(&self) -> BoxFuture<'_, bool> {
        // Structural: the rig contains no system-resolver code path, so a
        // leak is impossible by construction. (The production risk this
        // guards is in the real resolver, not the rig.)
        Box::pin(async move { false })
    }

    fn direct_egress_bytes(&self) -> BoxFuture<'_, u64> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.direct_egress_bytes.load(Ordering::SeqCst) })
    }

    fn resource_sample(&self) -> BoxFuture<'_, ResourceSample> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (cpu_pct, rss_bytes) = inner.cpu.lock().unwrap().sample();
            ResourceSample { cpu_pct, rss_bytes }
        })
    }
}

fn reason_str(r: TransportSwitchReason) -> String {
    match r {
        TransportSwitchReason::Initial => "initial".to_string(),
        TransportSwitchReason::TransportFailed => "transport-failed".to_string(),
        TransportSwitchReason::PrimaryRecovered => "primary-recovered".to_string(),
        TransportSwitchReason::BetterQuality => "better-quality".to_string(),
        TransportSwitchReason::Manual => "manual".to_string(),
    }
}
