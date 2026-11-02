//! SCAFFOLD: the `HaEngine` trait is the contract the real dual always-on
//! Iran→USA failover engine must implement before any scenario test can run.
//!
//! Nothing here is implemented. The harness compiles against this trait and
//! fails loudly (`SCAFFOLD` panic in [`crate::wiring::require_engine`]) until a
//! real engine is wired. Do NOT implement a fake/mock engine that returns
//! canned values and present passing tests as proof — the honesty rule is
//! load-bearing for the acceptance gate.
//!
//! Method style: plain `fn` returning boxed futures (no `async_trait`
//! dependency) so the trait stays object-safe for `Box<dyn HaEngine>`.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

/// Boxed future shorthand for object-safe async trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Tunnel identifier on the Iran→USA leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelId {
    /// Primary data path (IPv4).
    A,
    /// Hot standby (IPv4): always connected, authenticated, data-ready.
    B,
    /// Hot standby (IPv6): when real end-to-end IPv6 is verified; otherwise
    /// the engine reports it as Unavailable (never faked).
    C,
}

impl fmt::Display for TunnelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelId::A => write!(f, "A"),
            TunnelId::B => write!(f, "B"),
            TunnelId::C => write!(f, "C"),
        }
    }
}

/// Operational state of one inter-server tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Up,
    Degraded,
    /// Connected + authenticated + keepalive running, carrying no user data.
    Standby,
    Down,
}

/// Session kind for survival tracking (TCP and UDP behave differently
/// across a transport switch — the report must distinguish them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Tcp,
    Udp,
}

/// Opaque handle to one open end-to-end session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// Per-tunnel health snapshot.
#[derive(Debug, Clone)]
pub struct TunnelHealth {
    pub id: TunnelId,
    pub state: TunnelState,
    /// e.g. "wireguard".
    pub protocol: String,
    /// e.g. "udp" vs "tls-tcp" — the two tunnels should differ.
    pub transport_family: String,
    pub rtt: Option<Duration>,
    pub loss_pct: Option<f64>,
    pub jitter: Option<Duration>,
    pub keepalive_ok: bool,
    pub last_heartbeat_age: Option<Duration>,
}

/// A failover event as recorded by the engine itself.
#[derive(Debug, Clone)]
pub struct FailoverEvent {
    pub from: TunnelId,
    pub to: TunnelId,
    pub reason: String,
    /// Time from fault injection to the engine's failover decision.
    pub detected_after: Duration,
    /// Time from fault injection to first successful data on the new path.
    pub recovered_after: Option<Duration>,
    pub sessions_preserved: Option<u64>,
    pub sessions_total: Option<u64>,
}

/// Faults the harness may inject. The engine (or its test rig) must honor
/// them; how they are realized (netem, iptables, loopback rig) is the
/// routing agent's choice — see README.md.
#[derive(Debug, Clone)]
pub enum Fault {
    /// Abrupt link death on one tunnel (cable-pull equivalent).
    CutTunnel(TunnelId),
    /// The tunnel's protocol port is blackholed (e.g. UDP 51820 dropped).
    BlockPort { tunnel: TunnelId, port: u16 },
    /// Sustained packet loss on one tunnel.
    PacketLoss { tunnel: TunnelId, pct: f64 },
    /// Latency spike added on one tunnel.
    RttSpike { tunnel: TunnelId, extra: Duration },
    /// The resolver path breaks (DNS failure scenario).
    DnsFailure,
    /// Both tunnels down — full foreign-path cut (fail-closed scenario).
    CutForeignPath,
}

/// Split-routing classification of a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    IranDirect,
    UsaTunnel,
    Blocked,
}

/// One resource sample.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSample {
    pub cpu_pct: f64,
    pub rss_bytes: u64,
}

/// Result of a bulk transfer (download / file transfer scenarios).
#[derive(Debug, Clone, Copy)]
pub struct TransferStats {
    pub bytes_requested: u64,
    pub bytes_ok: u64,
    /// Integrity check over the received bytes.
    pub hash_ok: bool,
    pub duration: Duration,
}

/// Contract the real dual always-on engine must implement.
///
/// Every method is documented with what the harness expects. Until an
/// implementation exists, all scenario tests fail loudly as SCAFFOLD.
pub trait HaEngine: Send + Sync {
    /// Current health snapshot of one tunnel.
    fn tunnel_health(&self, id: TunnelId) -> BoxFuture<'_, TunnelHealth>;
    /// Which tunnel currently carries new sessions.
    fn primary(&self) -> BoxFuture<'_, TunnelId>;
    /// Engine-recorded failover history (for cross-checking harness timing).
    fn failover_events(&self) -> BoxFuture<'_, Vec<FailoverEvent>>;
    /// Public USA exit IP as seen from outside.
    fn exit_ip(&self) -> BoxFuture<'_, IpAddr>;
    /// Split-routing classification of a destination host.
    fn classify(&self, host: &str) -> BoxFuture<'_, RouteClass>;
    /// Inject a fault (see [`Fault`]).
    fn inject_fault(&self, fault: Fault) -> BoxFuture<'_, ()>;
    /// Remove all injected faults (start of auto-recovery).
    fn clear_faults(&self) -> BoxFuture<'_, ()>;
    /// Open one end-to-end session through the current primary path.
    fn open_session(&self, dst: &str, kind: SessionKind) -> BoxFuture<'_, SessionId>;
    /// Is a previously opened session still alive?
    fn session_alive(&self, id: SessionId) -> BoxFuture<'_, bool>;
    /// One end-to-end data transfer through the current path (true = ok).
    fn probe(&self, dst: &str) -> BoxFuture<'_, bool>;
    /// Bulk transfer with integrity check.
    fn transfer(&self, dst: &str, bytes: u64) -> BoxFuture<'_, TransferStats>;
    /// DNS resolution through the engine's resolver (policy-bound).
    fn dns_query(&self, name: &str) -> BoxFuture<'_, Vec<IpAddr>>;
    /// True if any DNS query escaped the routing policy during the run.
    fn dns_leak_observed(&self) -> BoxFuture<'_, bool>;
    /// Canary counter: bytes of foreign-classified traffic that egressed
    /// directly (not via the USA tunnel). Must stay 0 during failover
    /// (fail-closed invariant).
    fn direct_egress_bytes(&self) -> BoxFuture<'_, u64>;
    /// Current CPU/RSS of the engine process.
    fn resource_sample(&self) -> BoxFuture<'_, ResourceSample>;
}
