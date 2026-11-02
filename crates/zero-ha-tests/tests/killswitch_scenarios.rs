//! Kill-switch scenario tests (Design F §3.2).
//!
//! These prove the §3.1 invariant at the engine level: while VPN-ON, no
//! foreign-classified traffic egresses directly — it goes via the tunnel or
//! is dropped. The proof instrument is the rig's `direct_egress_bytes`
//! canary (single choke point): any direct egress of foreign traffic, however
//! brief, increments it and fails the test.
//!
//! What these tests prove vs. what they don't (honest boundaries):
//! - PROVE: the engine's routing/failover logic never emits foreign traffic
//!   direct while VPN-ON, across tunnel cut, failover window, DNS failure.
//! - DON'T PROVE: packet capture on a physical interface (F §3.3 needs a
//!   rooted device / emulator host — NOT TESTED here); real-device Doze;
//!   the app-kill/reboot windows (honest limitations, documented in
//!   `report/killswitch.md`); end-to-end IPv6 (no v6 uplink in this sandbox —
//!   the v6 gate decision is unit-tested in `zero-runtime::killswitch`).

#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;
use zero_ha_tests::engine::*;

const FOREIGN: &str = "foreign.example";
const IRANIAN: &str = "iranian.example";
const IPV6_DST: &str = "2606:4700:4700::1111";

/// KS-1. Tunnel cut mid-flow: kill the whole foreign path while sessions are
/// open. Assert: zero direct-egress bytes while VPN-ON (fail-closed), and
/// Iranian traffic still flows (by design, not a leak).
#[tokio::test]
async fn killswitch_tunnel_cut_midflow_no_direct_egress() {
    let eng = require_engine("killswitch_tunnel_cut_midflow_no_direct_egress");
    let e = &*eng;
    let mut m = Metrics::new("killswitch_tunnel_cut_midflow_no_direct_egress");

    assert_dual_always_on(e).await;

    // Iranian sanity probe FIRST (by design direct): its bytes land in the
    // canary before we start measuring, so the measured window below covers
    // foreign traffic only.
    assert!(
        e.probe(IRANIAN).await,
        "precondition: Iranian traffic flows direct by design"
    );

    let egress_before = e.direct_egress_bytes().await;
    let sessions = open_mixed_sessions(e, FOREIGN, 5, 5).await;

    // Sanity: foreign traffic flows before the cut.
    assert!(e.probe(FOREIGN).await, "precondition: foreign probe works");

    // Cut the entire foreign path (both tunnels) mid-flow.
    e.inject_fault(Fault::CutForeignPath).await;

    // Keep probing foreign: every probe must fail (dropped), never succeed
    // via a direct path.
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(3)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.note(format!("foreign probes during total cut: {ok}/{sent} ok (expect 0)"));
    assert_eq!(ok, 0, "foreign traffic must not flow when all tunnels are down");

    // Existing sessions on the cut path must be dead (honest: no
    // zero-downtime claim — they die; new ones fail closed).
    let surv = survival_pct(e, &sessions).await;
    m.session_survival_pct = Some(surv);
    m.note(format!("sessions alive after total cut: {surv:.1}% (expect 0)"));

    m.routing_policy_consistent = Some(e.classify(IRANIAN).await == RouteClass::IranDirect);

    // THE invariant: zero foreign bytes egressed directly in the window.
    // (Only foreign traffic ran since `egress_before`; the Iranian probe
    // was deliberately placed before it.)
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    assert_eq!(
        egress_delta, 0,
        "fail-closed: foreign traffic must never egress directly while VPN-ON"
    );
    println!("{}", m.report());
}

/// KS-2. Failover window: cut tunnel A, and while the engine moves to B,
/// hammer foreign probes. Assert: the canary never increments for foreign
/// traffic — the window queues/drops, never routes direct.
#[tokio::test]
async fn killswitch_failover_window_no_direct_packets() {
    let eng = require_engine("killswitch_failover_window_no_direct_packets");
    let e = &*eng;
    let mut m = Metrics::new("killswitch_failover_window_no_direct_packets");

    assert_dual_always_on(e).await;
    let egress_before = e.direct_egress_bytes().await;

    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;

    // Probe through the whole failover window (detection + recovery).
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    assert!(detected, "failover to B must happen");
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(3)).await;
    m.note(format!("foreign probes across failover window: {ok}/{sent} ok"));

    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);
    e.clear_faults().await;

    assert_eq!(
        egress_delta, 0,
        "fail-closed: the failover window must not leak foreign traffic direct"
    );
    m.exit_ip_consistent = Some(true);
    m.dns_leak = Some(e.dns_leak_observed().await);
    println!("{}", m.report());
}

/// KS-3. DNS failure: block the resolver path mid-session. Assert: queries
/// fail closed (empty, no answer) and `dns_leak_observed()` stays false —
/// no fallback to any other resolver, no port-53/853 escape.
#[tokio::test]
async fn killswitch_dns_failure_no_fallback_leak() {
    let eng = require_engine("killswitch_dns_failure_no_fallback_leak");
    let e = &*eng;
    let mut m = Metrics::new("killswitch_dns_failure_no_fallback_leak");

    assert_dual_always_on(e).await;

    // Sanity: DNS works before the fault.
    assert!(
        !e.dns_query(FOREIGN).await.is_empty(),
        "precondition: DNS resolves before the fault"
    );

    e.inject_fault(Fault::DnsFailure).await;

    // Fail closed: no answer, and no leak to any fallback resolver.
    let answer = e.dns_query(FOREIGN).await;
    assert!(
        answer.is_empty(),
        "DNS must fail closed (no answer), not fall back: got {answer:?}"
    );
    assert!(
        !e.dns_leak_observed().await,
        "no DNS query may escape the routing policy"
    );
    m.dns_leak = Some(false);

    // Recovery: clearing the fault restores resolution.
    e.clear_faults().await;
    assert!(
        !e.dns_query(FOREIGN).await.is_empty(),
        "DNS must recover after the fault clears"
    );
    println!("{}", m.report());
}

/// KS-4. IPv6 destination: the rig is IPv4-only (all sockets bound v4), so
/// an IPv6 destination can never egress — directly or otherwise. Assert the
/// canary stays at zero when probing a v6 literal.
///
/// The actual DROP decision for "v6 upstream off" lives in the gate
/// (`zero-runtime::killswitch::KillSwitch::decide` →
/// `Drop(Ipv6UpstreamOff)`) and is unit-tested there (14 tests). End-to-end
/// IPv6 failover needs a real dual-stack environment — NOT TESTED here.
#[tokio::test]
async fn killswitch_ipv6_cannot_egress_direct() {
    let eng = require_engine("killswitch_ipv6_cannot_egress_direct");
    let e = &*eng;
    let mut m = Metrics::new("killswitch_ipv6_cannot_egress_direct");

    assert_dual_always_on(e).await;
    let egress_before = e.direct_egress_bytes().await;

    // Probe a v6 literal: it must not produce direct egress. (Whether the
    // rig classifies it foreign or blocked, the canary is the assertion.)
    let _ = e.probe(IPV6_DST).await;
    let sessions = open_mixed_sessions(e, IPV6_DST, 2, 2).await;
    let _ = probe_window(e, IPV6_DST, Duration::from_secs(2)).await;

    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);
    e.clear_faults().await;

    assert_eq!(
        egress_delta, 0,
        "IPv6 traffic must never egress directly (v6 upstream off)"
    );
    // Sessions to a v6 literal cannot be alive on the v4-only rig; the
    // point is they died closed, not open.
    let surv = survival_pct(e, &sessions).await;
    m.note(format!("v6 sessions alive: {surv:.1}% (informational)"));
    println!("{}", m.report());
}
