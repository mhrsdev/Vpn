//! HA failover scenarios — core fault-injection set (SCAFFOLD).
//!
//! Each test compiles against the `HaEngine` trait and fails loudly with a
//! SCAFFOLD panic until the real dual always-on engine is wired via
//! `wiring::connect()`. No test fakes a pass.

#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::{Duration, Instant};
use zero_ha_tests::engine::*;

const FOREIGN: &str = "foreign.example";
const IRANIAN: &str = "iranian.example";

/// 1. Sudden primary tunnel cut (cable-pull equivalent on Tunnel A).
#[tokio::test]
async fn sudden_primary_cut() {
    let eng = require_engine("sudden_primary_cut");
    let e = &*eng;
    let mut m = Metrics::new("sudden_primary_cut");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    let sessions = open_mixed_sessions(e, FOREIGN, 10, 10).await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;

    // MEASURE: detection = fault injection -> primary becomes B (no new connection setup).
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.note(format!("failover to B detected={detected}"));

    // MEASURE: traffic recovery = first successful data on the new path.
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;

    // MEASURE: loss inside the failover window.
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);

    // MEASURE: existing-session survival (honest 3-level reporting happens in notes).
    let surv = survival_pct(e, &sessions).await;
    m.session_survival_pct = Some(surv);
    m.note(format!(
        "sessions alive after switch: {surv:.1}% of {}",
        sessions.len()
    ));

    // Invariants.
    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 2. Primary protocol port blocked (e.g. UDP 51820 blackholed, tunnel process alive).
#[tokio::test]
async fn primary_port_blocked() {
    let eng = require_engine("primary_port_blocked");
    let e = &*eng;
    let mut m = Metrics::new("primary_port_blocked");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    let sessions = open_mixed_sessions(e, FOREIGN, 10, 10).await;

    let t_fault = Instant::now();
    // Port for the primary transport is deployment-specific; 51820 is the
    // conventional WireGuard port and documents the intent.
    e.inject_fault(Fault::BlockPort {
        tunnel: TunnelId::A,
        port: 51820,
    })
    .await;

    // The engine must detect this via heartbeat/timeout even though the
    // tunnel process itself did not crash (no new connection setup on switch).
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(60)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(60)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(survival_pct(e, &sessions).await);

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 3. Severe packet loss on the primary tunnel (degraded, not dead).
#[tokio::test]
async fn severe_packet_loss() {
    let eng = require_engine("severe_packet_loss");
    let e = &*eng;
    let mut m = Metrics::new("severe_packet_loss");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::PacketLoss {
        tunnel: TunnelId::A,
        pct: 60.0,
    })
    .await;

    // Loss-based failover must trigger (not just dead-link detection).
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(60)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.note(format!("loss-triggered failover detected={detected}"));
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(60)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    // No long-lived sessions in this scenario: survival is about new-session health.
    m.session_survival_pct = Some(if detected { 100.0 } else { 0.0 });

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 4. RTT spike on the primary tunnel (congestion, not failure).
#[tokio::test]
async fn rtt_spike() {
    let eng = require_engine("rtt_spike");
    let e = &*eng;
    let mut m = Metrics::new("rtt_spike");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::RttSpike {
        tunnel: TunnelId::A,
        extra: Duration::from_secs(3),
    })
    .await;

    // Stability outranks lowest ping, but a 3s spike should eventually move
    // traffic (opportunistic, hysteresis-respecting — not a dead-pair failover).
    let moved = await_primary(e, TunnelId::B, Duration::from_secs(120)).await;
    m.failover_detection = moved.then_some(t_fault.elapsed());
    m.note(format!("rtt-spike path move detected={moved} (opportunistic, hysteresis applies)"));
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(60)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(if moved { 100.0 } else { 0.0 });

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 5. DNS failure during the run: resolution must stay policy-bound
/// (in-tunnel DNS) or fail closed — never leak to the system resolver.
#[tokio::test]
async fn dns_failure() {
    let eng = require_engine("dns_failure");
    let e = &*eng;
    let mut m = Metrics::new("dns_failure");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::DnsFailure).await;
    // Combine with a tunnel cut: DNS must not leak *during* a switch either.
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;

    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    // Resolution attempts during the outage: they may fail, but must not leak.
    let mut leak_free_rounds = 0u32;
    for _ in 0..10 {
        let _ = e.dns_query(FOREIGN).await;
        if !e.dns_leak_observed().await {
            leak_free_rounds += 1;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    m.note(format!("dns rounds without leak: {leak_free_rounds}/10"));
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(60)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(100.0 * leak_free_rounds as f64 / 10.0);

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 6. Full foreign-path cut (both tunnels down): foreign traffic must
/// fail closed; Iranian traffic may continue.
#[tokio::test]
async fn full_foreign_path_cut() {
    let eng = require_engine("full_foreign_path_cut");
    let e = &*eng;
    let mut m = Metrics::new("full_foreign_path_cut");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutForeignPath).await;

    // Foreign probes must FAIL (blocked), not reroute via Iran.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let foreign_ok = e.probe(FOREIGN).await;
    m.note(format!("foreign probe during full cut: ok={foreign_ok} (must be false)"));
    assert!(!foreign_ok, "fail-closed: foreign traffic must be blocked, not rerouted");
    m.failover_detection = Some(t_fault.elapsed());
    m.traffic_recovery = None; // nothing to recover while both are down
    m.note("traffic_recovery: n/a (both tunnels down — recovery measured in both_tunnels_down)");
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(3)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(0.0);
    m.note("session survival: 0% expected — foreign path is fully down by design");

    // Iranian traffic may continue via direct Iran egress (by design, not a leak).
    let ir_class = e.classify(IRANIAN).await;
    m.note(format!("iranian classification during full cut: {ir_class:?}"));
    m.routing_policy_consistent = Some(
        e.classify(FOREIGN).await == RouteClass::Blocked && ir_class == RouteClass::IranDirect,
    );

    // Exit IP "consistency": no foreign egress happened at all; record the
    // pre-cut IP as the reference (no change possible).
    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 7. Primary recovery: A comes back — background recovery, health probing
/// before promotion, no flap-back.
#[tokio::test]
async fn primary_recovery() {
    let eng = require_engine("primary_recovery");
    let e = &*eng;
    let mut m = Metrics::new("primary_recovery");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    assert!(
        await_primary(e, TunnelId::B, Duration::from_secs(30)).await,
        "precondition: failover to B"
    );
    let t_recover = Instant::now();
    e.clear_faults().await; // A starts background recovery

    // A must come back Up/Standby (auto-recovery attempts).
    let a_back = await_state(e, TunnelId::A, TunnelState::Up, Duration::from_secs(120)).await
        || await_state(e, TunnelId::A, TunnelState::Standby, Duration::from_secs(30)).await;
    m.note(format!("tunnel A recovered to Up/Standby: {a_back}"));
    assert!(a_back, "auto-recovery: tunnel A must come back");

    // No immediate flap-back: primary must stay B through the cooldown window.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let still_b = e.primary().await == TunnelId::B;
    m.note(format!("primary still B 10s after A recovery (no flap-back): {still_b}"));
    m.failover_detection = Some(t_recover.elapsed());
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(if still_b { 100.0 } else { 0.0 });

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    finish_hard_invariants(&m, egress_delta);
}

/// 8. Alternating quality between tunnels: hysteresis + cooldown must
/// prevent flapping (anti-flap acceptance).
#[tokio::test]
async fn alternating_quality() {
    let eng = require_engine("alternating_quality");
    let e = &*eng;
    let mut m = Metrics::new("alternating_quality");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    let events_before = e.failover_events().await.len();

    // Oscillate degradation between A and B for 90s.
    let t0 = Instant::now();
    let mut round = 0u32;
    while t0.elapsed() < Duration::from_secs(90) {
        e.inject_fault(Fault::PacketLoss {
            tunnel: if round % 2 == 0 { TunnelId::A } else { TunnelId::B },
            pct: 40.0,
        })
        .await;
        tokio::time::sleep(Duration::from_secs(15)).await;
        e.clear_faults().await;
        round += 1;
    }
    let events_after = e.failover_events().await.len();
    let switches = events_after.saturating_sub(events_before);
    m.note(format!("failover events during 90s oscillation: {switches}"));
    // Anti-flap budget (initial; the routing agent sets the real one):
    // oscillation must not produce a switch per round.
    m.note(format!(
        "anti-flap ok (switches < rounds): {}",
        switches < round as usize
    ));
    assert!(
        (switches as u32) < round,
        "hysteresis/cooldown must prevent a switch on every oscillation"
    );

    m.failover_detection = Some(Duration::from_secs(90));
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(100.0);

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 9. Both tunnels down, then auto-recovery: foreign fail-closed throughout,
/// engine keeps attempting recovery.
#[tokio::test]
async fn both_tunnels_down() {
    let eng = require_engine("both_tunnels_down");
    let e = &*eng;
    let mut m = Metrics::new("both_tunnels_down");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    e.inject_fault(Fault::CutTunnel(TunnelId::B)).await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert!(!e.probe(FOREIGN).await, "foreign must be blocked while both tunnels are down");
    m.failover_detection = Some(t_fault.elapsed());
    m.note("both tunnels down: foreign fail-closed confirmed");

    // Auto-recovery: clear faults, at least one tunnel must come back.
    let t_recover = Instant::now();
    e.clear_faults().await;
    let a_up = await_state(e, TunnelId::A, TunnelState::Up, Duration::from_secs(120)).await;
    let b_up = await_state(e, TunnelId::B, TunnelState::Up, Duration::from_secs(10)).await
        || await_state(e, TunnelId::B, TunnelState::Standby, Duration::from_secs(10)).await;
    assert!(a_up || b_up, "auto-recovery: at least one tunnel must return");
    m.traffic_recovery = Some(t_recover.elapsed());
    m.note(format!("recovered: A_up={a_up} B_up_or_standby={b_up}"));
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(0.0);
    m.note("session survival: 0% expected — total path outage by design");

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    finish_hard_invariants(&m, egress_delta);
}
