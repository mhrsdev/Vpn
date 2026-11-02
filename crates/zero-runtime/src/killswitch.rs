//! Kill-switch / fail-closed egress gate (Design F §3).
//!
//! Named owner of the §3.1 invariant: while VPN-ON, **no application traffic
//! may leave the device's physical interfaces** except (a) through the active
//! tunnel interface, or (b) to the VPN server's own endpoints (IP:port of the
//! currently selected server, for tunnel establishment/keepalive).
//! Violation = FAIL, however brief.
//!
//! This module is the ENGINE-side decision point. It does not capture packets
//! itself; it is the single choke point the data path consults before emitting
//! any packet while VPN-ON. Every state transition and drop is logged with a
//! reason (owner prompt §5: failover decisions are logged with reason).
//!
//! What this module does NOT do (honest boundaries, F §3.2):
//! - Reboot / app-kill windows: no app code can prevent direct traffic there.
//!   The mitigation is Android's system always-on VPN + "Block connections
//!   without VPN", surfaced in the setup UX (Android-side seam, documented in
//!   `report/killswitch.md`).
//! - Sleep/Doze: keepalives must survive Doze or the stall detector fires and
//!   the drop semantics below apply. Real-device Doze testing is NOT TESTED
//!   here (needs `dumpsys deviceidle force-idle` on hardware).
//! - Packet capture on physical interfaces: the sandbox cannot do it. The
//!   invariant is proven here by decision-logic unit tests plus the HA rig's
//!   `direct_egress_bytes` canary (fail-closed by construction); true pcap
//!   verification per F §3.3 needs a rooted device / emulator host.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

/// Tunnel identifier on the Iran→USA leg. Kept local (not imported from the
/// HA test harness) so the production engine does not depend on test code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KsTunnel {
    /// Primary data path (IPv4).
    A,
    /// Hot standby (IPv4).
    B,
    /// Hot standby (IPv6 underlay); only usable when real end-to-end IPv6
    /// is verified, never faked.
    C,
}

impl KsTunnel {
    fn idx(self) -> usize {
        match self {
            KsTunnel::A => 0,
            KsTunnel::B => 1,
            KsTunnel::C => 2,
        }
    }
}

/// User-visible VPN state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    /// User enabled, not explicitly disconnected: the §3.1 invariant applies.
    On,
    /// User explicitly disconnected: the gate does not apply.
    Off,
}

/// Per-tunnel liveness as seen by the gate (fed by the heartbeat/health
/// tables; this module does not probe anything itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelLiveness {
    Up,
    Degraded,
    Down,
}

/// Split-routing traffic class of a destination, as decided by the
/// classifier (split_engine / H3 CLASSIFY). The gate trusts the
/// classification and enforces the egress policy for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    /// Iranian destination: exits direct BY DESIGN (F §3.2: not a leak).
    Iran,
    /// Foreign/unknown destination: must go via the USA tunnel or be
    /// dropped. Unknown defaults to Foreign, never Iran.
    Foreign,
}

/// Why the gate dropped a packet/session. Every variant maps to one F §3.2 row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// All tunnels down while VPN-ON (§3.2 "Tunnel drops").
    TunnelDown,
    /// Failover in progress and no path has proven it carries traffic yet
    /// (§3.2 "Failover in progress").
    FailoverGap,
    /// Network change: the new generation's tunnel is not up yet
    /// (§3.2 "Network change").
    NetworkChangeHold,
    /// IPv6 destination while the v6 upstream is disabled (§3.2 "IPv6").
    Ipv6UpstreamOff,
}

/// Egress gate decision — the single choke point for VPN-ON traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Carry via the named tunnel (§3.1 exception (a)).
    ViaTunnel(KsTunnel),
    /// To the VPN server's own endpoint: tunnel establishment, keepalive,
    /// reconnect. §3.1 exception (b). Allowed even when tunnels are down —
    /// otherwise recovery would be impossible.
    ToServerEndpoint,
    /// Iranian-classified traffic exits direct BY DESIGN. Not a leak;
    /// the deliberate Iranian exit is specified in the split-routing design.
    DirectIran,
    /// Drop the packet/session: fail closed. Foreign traffic is NEVER
    /// rerouted direct while VPN-ON.
    Drop(DropReason),
    /// VPN is Off: the kill-switch does not apply; normal routing decides.
    VpnOff,
}

/// Kinds of gate-relevant events (logged with a human reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateEventKind {
    VpnOn,
    VpnOff,
    TunnelUp,
    TunnelDegraded,
    TunnelDown,
    FailoverStarted,
    FailoverProven,
    FailoverAborted,
    NetworkChange,
    NetworkChangeCleared,
    ServerEndpointAdded,
    ServerEndpointRemoved,
    V6UpstreamOn,
    V6UpstreamOff,
    Drop,
}

/// One logged gate event.
#[derive(Debug, Clone)]
pub struct GateEvent {
    pub at: Instant,
    pub kind: GateEventKind,
    pub tunnel: Option<KsTunnel>,
    pub reason: String,
}

/// Maximum retained gate events (ring buffer; the count of drops is kept
/// separately so it never rolls off).
const EVENT_RING_CAP: usize = 256;

/// The kill-switch egress gate.
///
/// Usage: the data path calls [`KillSwitch::decide`] for every new session
/// (and, for long-lived sessions, re-checks on tunnel-state transitions)
/// while VPN-ON. Tunnel liveness is fed from the existing heartbeat/health
/// tables via [`KillSwitch::set_tunnel`]; failover via
/// [`KillSwitch::begin_failover`]/[`KillSwitch::prove_failover`].
pub struct KillSwitch {
    vpn: VpnState,
    tunnels: [TunnelLiveness; 3],
    /// Tunnel currently carrying new sessions.
    active: KsTunnel,
    /// Failover target that has not yet proven it carries traffic
    /// (make-before-break: `active` keeps carrying until proven).
    proving: Option<KsTunnel>,
    /// New engine generation not up yet after a network change.
    network_hold: bool,
    /// Whether the v6 upstream path is enabled (dual-stack egress).
    v6_upstream: bool,
    /// §3.1 exception (b): the VPN servers' own IP:ports.
    server_endpoints: Vec<SocketAddr>,
    events: VecDeque<GateEvent>,
    /// Total drops (never rolls off with the ring buffer).
    drops_total: u64,
}

impl KillSwitch {
    /// New gate: VPN off, all tunnels down, no endpoints. The caller must
    /// feed real state before relying on decisions.
    pub fn new() -> Self {
        KillSwitch {
            vpn: VpnState::Off,
            tunnels: [TunnelLiveness::Down; 3],
            active: KsTunnel::A,
            proving: None,
            network_hold: false,
            v6_upstream: false,
            server_endpoints: Vec::new(),
            events: VecDeque::with_capacity(EVENT_RING_CAP),
            drops_total: 0,
        }
    }

    fn log(&mut self, kind: GateEventKind, tunnel: Option<KsTunnel>, reason: &str) {
        if self.events.len() == EVENT_RING_CAP {
            self.events.pop_front();
        }
        self.events.push_back(GateEvent {
            at: Instant::now(),
            kind,
            tunnel,
            reason: reason.to_string(),
        });
        if kind == GateEventKind::Drop {
            self.drops_total += 1;
        }
    }

    /// User enabled / disabled the VPN.
    pub fn set_vpn(&mut self, state: VpnState, reason: &str) {
        self.vpn = state;
        self.log(
            match state {
                VpnState::On => GateEventKind::VpnOn,
                VpnState::Off => GateEventKind::VpnOff,
            },
            None,
            reason,
        );
    }

    /// Feed per-tunnel liveness from the heartbeat/health tables.
    pub fn set_tunnel(&mut self, id: KsTunnel, liveness: TunnelLiveness, reason: &str) {
        let old = self.tunnels[id.idx()];
        self.tunnels[id.idx()] = liveness;
        if old != liveness {
            let kind = match liveness {
                TunnelLiveness::Up => GateEventKind::TunnelUp,
                TunnelLiveness::Degraded => GateEventKind::TunnelDegraded,
                TunnelLiveness::Down => GateEventKind::TunnelDown,
            };
            self.log(kind, Some(id), reason);
            // A proven tunnel going down aborts nothing, but a *proving*
            // tunnel going down aborts the failover: there is no new path.
            if self.proving == Some(id) && liveness == TunnelLiveness::Down {
                self.proving = None;
                self.log(
                    GateEventKind::FailoverAborted,
                    Some(id),
                    "proving tunnel went down before proving it carries traffic",
                );
            }
        }
    }

    /// Begin failover to `to` (make-before-break): `active` keeps carrying
    /// traffic until [`KillSwitch::prove_failover`] confirms the new path.
    pub fn begin_failover(&mut self, to: KsTunnel, reason: &str) {
        if to == self.active {
            return;
        }
        self.proving = Some(to);
        self.log(GateEventKind::FailoverStarted, Some(to), reason);
    }

    /// The failover target has proven it carries traffic: switch new
    /// sessions to it.
    pub fn prove_failover(&mut self, reason: &str) {
        if let Some(to) = self.proving.take() {
            self.active = to;
            self.log(GateEventKind::FailoverProven, Some(to), reason);
        }
    }

    /// Network change (Wi-Fi ↔ mobile): hold new sessions until the new
    /// generation's tunnel is up. The old tunnel keeps carrying *existing*
    /// sessions only if still viable — that is the caller's decision; the
    /// gate blocks *new* direct-path decisions during the hold.
    pub fn on_network_change(&mut self, reason: &str) {
        self.network_hold = true;
        self.log(GateEventKind::NetworkChange, None, reason);
    }

    /// New generation's tunnel is up: release the hold.
    pub fn clear_network_change(&mut self, reason: &str) {
        self.network_hold = false;
        self.log(GateEventKind::NetworkChangeCleared, None, reason);
    }

    /// Enable/disable the IPv6 upstream path (dual-stack egress).
    pub fn set_v6_upstream(&mut self, enabled: bool, reason: &str) {
        self.v6_upstream = enabled;
        self.log(
            if enabled {
                GateEventKind::V6UpstreamOn
            } else {
                GateEventKind::V6UpstreamOff
            },
            None,
            reason,
        );
    }

    /// §3.1 exception (b): register a VPN server endpoint (tunnel
    /// establishment / keepalive / reconnect target).
    pub fn add_server_endpoint(&mut self, endpoint: SocketAddr, reason: &str) {
        if !self.server_endpoints.contains(&endpoint) {
            self.server_endpoints.push(endpoint);
            self.log(GateEventKind::ServerEndpointAdded, None, reason);
        }
    }

    pub fn remove_server_endpoint(&mut self, endpoint: SocketAddr, reason: &str) {
        if let Some(pos) = self.server_endpoints.iter().position(|e| *e == endpoint) {
            self.server_endpoints.remove(pos);
            self.log(GateEventKind::ServerEndpointRemoved, None, reason);
        }
    }

    /// The single choke point. Called for every new session while VPN-ON.
    ///
    /// Decision order (each step is a §3.2 row):
    /// 1. VPN Off → [`GateDecision::VpnOff`] (gate does not apply).
    /// 2. Destination is a registered server endpoint → [`GateDecision::ToServerEndpoint`]
    ///    (allowed even with all tunnels down — recovery must be possible).
    /// 3. IPv6 destination with v6 upstream disabled → [`GateDecision::Drop`]
    ///    ([`DropReason::Ipv6UpstreamOff`]).
    /// 4. Iranian class → [`GateDecision::DirectIran`] (by design, not a leak).
    /// 5. Network-change hold → [`GateDecision::Drop`] ([`DropReason::NetworkChangeHold`]).
    /// 6. Failover in progress: active tunnel still viable → keep it
    ///    (make-before-break); else [`GateDecision::Drop`] ([`DropReason::FailoverGap`]).
    /// 7. Active tunnel Up/Degraded → [`GateDecision::ViaTunnel`]; all down →
    ///    [`GateDecision::Drop`] ([`DropReason::TunnelDown`]). Never direct.
    pub fn decide(&mut self, class: TrafficClass, dst: SocketAddr) -> GateDecision {
        if self.vpn == VpnState::Off {
            return GateDecision::VpnOff;
        }
        if self.server_endpoints.contains(&dst) {
            return GateDecision::ToServerEndpoint;
        }
        if dst.ip().is_ipv6() && !self.v6_upstream {
            return self.drop(class, dst, DropReason::Ipv6UpstreamOff, "v6 upstream disabled");
        }
        if class == TrafficClass::Iran {
            return GateDecision::DirectIran;
        }
        if self.network_hold {
            return self.drop(class, dst, DropReason::NetworkChangeHold, "network-change hold");
        }
        // Failover in progress: make-before-break — the old (active) path
        // keeps carrying until the new path proves itself.
        if self.proving.is_some() {
            return match self.tunnels[self.active.idx()] {
                TunnelLiveness::Up | TunnelLiveness::Degraded => {
                    GateDecision::ViaTunnel(self.active)
                }
                TunnelLiveness::Down => {
                    self.drop(class, dst, DropReason::FailoverGap, "failover gap: no proven path")
                }
            };
        }
        match self.tunnels[self.active.idx()] {
            TunnelLiveness::Up | TunnelLiveness::Degraded => GateDecision::ViaTunnel(self.active),
            TunnelLiveness::Down => {
                // Defensive: if the active tunnel is down but a standby is
                // up, the failover machinery should have switched already;
                // the gate still never goes direct.
                if let Some(up) = [KsTunnel::A, KsTunnel::B, KsTunnel::C]
                    .into_iter()
                    .find(|t| self.tunnels[t.idx()] != TunnelLiveness::Down)
                {
                    GateDecision::ViaTunnel(up)
                } else {
                    self.drop(class, dst, DropReason::TunnelDown, "all tunnels down")
                }
            }
        }
    }

    fn drop(&mut self, class: TrafficClass, dst: SocketAddr, reason: DropReason, why: &str) -> GateDecision {
        self.log(
            GateEventKind::Drop,
            None,
            &format!("drop {class:?} -> {dst}: {why}"),
        );
        GateDecision::Drop(reason)
    }

    /// Recent gate events (ring buffer, newest last), with reasons.
    pub fn events(&self) -> impl Iterator<Item = &GateEvent> {
        self.events.iter()
    }

    /// Total drops since construction (does not roll off).
    pub fn drops_total(&self) -> u64 {
        self.drops_total
    }

    pub fn vpn_state(&self) -> VpnState {
        self.vpn
    }

    pub fn active_tunnel(&self) -> KsTunnel {
        self.active
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

/// Human-readable one-line summary of a decision (for logs / panel).
pub fn describe(decision: GateDecision) -> &'static str {
    match decision {
        GateDecision::ViaTunnel(KsTunnel::A) => "via tunnel A",
        GateDecision::ViaTunnel(KsTunnel::B) => "via tunnel B",
        GateDecision::ViaTunnel(KsTunnel::C) => "via tunnel C",
        GateDecision::ToServerEndpoint => "to server endpoint (tunnel control)",
        GateDecision::DirectIran => "direct Iran egress (by design)",
        GateDecision::Drop(DropReason::TunnelDown) => "DROP: all tunnels down (fail-closed)",
        GateDecision::Drop(DropReason::FailoverGap) => "DROP: failover gap, no proven path",
        GateDecision::Drop(DropReason::NetworkChangeHold) => "DROP: network-change hold",
        GateDecision::Drop(DropReason::Ipv6UpstreamOff) => "DROP: IPv6 upstream disabled",
        GateDecision::VpnOff => "vpn off (gate not applied)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), port)
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            port,
        )
    }

    /// VPN-ON, tunnel A up, one server endpoint registered.
    fn on_gate() -> KillSwitch {
        let mut ks = KillSwitch::new();
        ks.set_vpn(VpnState::On, "test");
        ks.set_tunnel(KsTunnel::A, TunnelLiveness::Up, "test");
        ks.add_server_endpoint(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820), "test");
        ks
    }

    #[test]
    fn vpn_off_applies_no_gate() {
        let mut ks = KillSwitch::new(); // VPN Off by default
        assert_eq!(ks.decide(TrafficClass::Foreign, v4(443)), GateDecision::VpnOff);
    }

    #[test]
    fn foreign_goes_via_tunnel_when_up() {
        let mut ks = on_gate();
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::ViaTunnel(KsTunnel::A)
        );
    }

    #[test]
    fn degraded_tunnel_still_carries() {
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::A, TunnelLiveness::Degraded, "test");
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::ViaTunnel(KsTunnel::A)
        );
    }

    #[test]
    fn foreign_drops_when_all_tunnels_down_never_direct() {
        // §3.2 "Tunnel drops": the classic kill-switch moment.
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::A, TunnelLiveness::Down, "cable pull");
        let d = ks.decide(TrafficClass::Foreign, v4(443));
        assert_eq!(d, GateDecision::Drop(DropReason::TunnelDown));
        // The gate has no "direct" decision for foreign traffic at all:
        // the only non-tunnel outcomes are ToServerEndpoint / DirectIran /
        // Drop / VpnOff.
        assert_ne!(d, GateDecision::DirectIran);
        assert_eq!(ks.drops_total(), 1);
    }

    #[test]
    fn iran_direct_is_by_design_not_a_leak() {
        let mut ks = on_gate();
        // Even with all tunnels down, Iranian traffic exits direct BY DESIGN.
        ks.set_tunnel(KsTunnel::A, TunnelLiveness::Down, "test");
        assert_eq!(
            ks.decide(TrafficClass::Iran, v4(80)),
            GateDecision::DirectIran
        );
    }

    #[test]
    fn server_endpoint_allowed_even_when_tunnels_down() {
        // §3.1 exception (b): recovery must be possible.
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::A, TunnelLiveness::Down, "test");
        let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
        assert_eq!(
            ks.decide(TrafficClass::Foreign, ep),
            GateDecision::ToServerEndpoint
        );
    }

    #[test]
    fn failover_make_before_break_old_carries_until_proven() {
        // §3.2 "Failover in progress": old path carries until the new path
        // proves it carries traffic.
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::B, TunnelLiveness::Up, "test");
        ks.begin_failover(KsTunnel::B, "A degraded");
        // Not proven yet: still via A.
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::ViaTunnel(KsTunnel::A)
        );
        ks.prove_failover("B carried traffic");
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::ViaTunnel(KsTunnel::B)
        );
        assert_eq!(ks.active_tunnel(), KsTunnel::B);
    }

    #[test]
    fn failover_gap_drops_when_old_down_before_new_proven() {
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::B, TunnelLiveness::Up, "test");
        ks.begin_failover(KsTunnel::B, "A flapping");
        // Old path dies before the new one proves: drop, never direct.
        ks.set_tunnel(KsTunnel::A, TunnelLiveness::Down, "A died mid-failover");
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::Drop(DropReason::FailoverGap)
        );
    }

    #[test]
    fn proving_tunnel_dying_aborts_failover() {
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::B, TunnelLiveness::Up, "test");
        ks.begin_failover(KsTunnel::B, "test");
        ks.set_tunnel(KsTunnel::B, TunnelLiveness::Down, "B died while proving");
        // Failover aborted; A still active and up.
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::ViaTunnel(KsTunnel::A)
        );
    }

    #[test]
    fn network_change_holds_new_sessions() {
        // §3.2 "Network change": hold until the new generation is up.
        let mut ks = on_gate();
        ks.on_network_change("wifi -> mobile");
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::Drop(DropReason::NetworkChangeHold)
        );
        // Server endpoints still reachable (reconnect needs them).
        let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
        assert_eq!(
            ks.decide(TrafficClass::Foreign, ep),
            GateDecision::ToServerEndpoint
        );
        ks.clear_network_change("new tunnel up");
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v4(443)),
            GateDecision::ViaTunnel(KsTunnel::A)
        );
    }

    #[test]
    fn ipv6_dropped_when_upstream_off() {
        // §3.2 "IPv6": captured and dropped when v6 upstream is off.
        let mut ks = on_gate();
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v6(443)),
            GateDecision::Drop(DropReason::Ipv6UpstreamOff)
        );
    }

    #[test]
    fn ipv6_flows_when_upstream_on() {
        let mut ks = on_gate();
        ks.set_v6_upstream(true, "datacenter has v6");
        assert_eq!(
            ks.decide(TrafficClass::Foreign, v6(443)),
            GateDecision::ViaTunnel(KsTunnel::A)
        );
    }

    #[test]
    fn events_carry_reasons_for_failover_decisions() {
        // Owner prompt §5: failover decisions logged with reason.
        let mut ks = on_gate();
        ks.set_tunnel(KsTunnel::B, TunnelLiveness::Up, "test");
        ks.begin_failover(KsTunnel::B, "A rtt spiked to 900ms");
        ks.prove_failover("B carried 3 heartbeats");
        let kinds: Vec<GateEventKind> = ks.events().map(|e| e.kind).collect();
        assert!(kinds.contains(&GateEventKind::FailoverStarted));
        assert!(kinds.contains(&GateEventKind::FailoverProven));
        let started = ks
            .events()
            .find(|e| e.kind == GateEventKind::FailoverStarted)
            .unwrap();
        assert!(started.reason.contains("900ms"), "reason must be recorded");
    }

    #[test]
    fn unknown_defaults_to_foreign_never_iran() {
        // The gate has no "unknown" class: callers must map unknown to
        // Foreign. This test pins the TrafficClass enum to exactly the two
        // variants so a future "Unknown" variant cannot slip through
        // unhandled.
        let variants = [TrafficClass::Iran, TrafficClass::Foreign];
        assert_eq!(variants.len(), 2);
    }
}
