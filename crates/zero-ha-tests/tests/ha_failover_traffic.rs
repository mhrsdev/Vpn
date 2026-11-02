//! HA failover scenarios — traffic, leak, and resource set (SCAFFOLD).
//!
//! Each test compiles against the `HaEngine` trait and fails loudly with a
//! SCAFFOLD panic until the real dual always-on engine is wired via
//! `wiring::connect()`. No test fakes a pass.

#[path = "common/mod.rs"]
mod common;

use common::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zero_ha_tests::engine::*;

const FOREIGN: &str = "foreign.example";
const IRANIAN: &str = "iranian.example";

/// 10. Long download across a failover: the transfer must survive the
/// switch (or its interruption must be measured honestly).
#[tokio::test]
async fn long_download() {
    let eng = require_engine("long_download");
    let e = &*eng;
    let mut m = Metrics::new("long_download");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    // 64 MiB is the default; the rig may scale it via env in CI.
    let bytes: u64 = 64 * 1024 * 1024;
    let t_fault = Instant::now();
    let transfer = tokio::spawn({
        // Cloneable engine handle: the transfer must run against the SAME
        // rig the fault is injected into (wiring::connect is Arc-backed).
        let e2 = Arc::clone(&eng);
        async move { e2.transfer(FOREIGN, bytes).await }
    });
    // Cut the primary mid-transfer.
    tokio::time::sleep(Duration::from_secs(2)).await;
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());

    let stats = transfer.await.expect("transfer task panicked");
    m.traffic_recovery = Some(stats.duration);
    m.note(format!(
        "download: {}/{} bytes ok, hash_ok={}",
        stats.bytes_ok, stats.bytes_requested, stats.hash_ok
    ));
    // Survival here = transfer integrity across the switch (honest levels).
    m.session_survival_pct = Some(if stats.hash_ok { 100.0 } else { 0.0 });
    m.packet_loss_pct = Some(if stats.bytes_requested > 0 {
        100.0 * (stats.bytes_requested - stats.bytes_ok) as f64 / stats.bytes_requested as f64
    } else {
        0.0
    });

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 11. Stable long-lived TCP connection across a failover.
#[tokio::test]
async fn stable_tcp_connection() {
    let eng = require_engine("stable_tcp_connection");
    let e = &*eng;
    let mut m = Metrics::new("stable_tcp_connection");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    let sessions = open_mixed_sessions(e, FOREIGN, 5, 0).await; // TCP only
    // Let the connections settle.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;
    // Keep the connections for another 30s after the switch, then check.
    tokio::time::sleep(Duration::from_secs(30)).await;
    let surv = survival_pct(e, &sessions).await;
    m.session_survival_pct = Some(surv);
    m.note(format!(
        "TCP sessions alive 30s after switch: {surv:.1}% — existing-session preservation level, not zero-downtime"
    ));
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 12. UDP session across a failover (UDP has no retransmission — loss is
/// expected and must be measured, not hidden).
#[tokio::test]
async fn udp_session() {
    let eng = require_engine("udp_session");
    let e = &*eng;
    let mut m = Metrics::new("udp_session");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    let sessions = open_mixed_sessions(e, FOREIGN, 0, 10).await; // UDP only

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;
    // UDP loss during the window is the honest signal here.
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(10)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    let surv = survival_pct(e, &sessions).await;
    m.session_survival_pct = Some(surv);
    m.note(format!(
        "UDP sessions alive after switch: {surv:.1}% (UDP flows are re-created on the new path by design)"
    ));

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 13. File transfer with integrity check across a failover.
#[tokio::test]
async fn file_transfer() {
    let eng = require_engine("file_transfer");
    let e = &*eng;
    let mut m = Metrics::new("file_transfer");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let t_fault = Instant::now();
    e.inject_fault(Fault::PacketLoss {
        tunnel: TunnelId::A,
        pct: 30.0,
    })
    .await;
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(60)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());

    // Transfer under degraded-then-switched conditions; integrity is the verdict.
    let stats = e.transfer(FOREIGN, 16 * 1024 * 1024).await;
    m.traffic_recovery = Some(stats.duration);
    m.session_survival_pct = Some(if stats.hash_ok { 100.0 } else { 0.0 });
    m.packet_loss_pct = Some(if stats.bytes_requested > 0 {
        100.0 * (stats.bytes_requested - stats.bytes_ok) as f64 / stats.bytes_requested as f64
    } else {
        0.0
    });
    m.note(format!(
        "file transfer hash_ok={} ({}/{} bytes)",
        stats.hash_ok, stats.bytes_ok, stats.bytes_requested
    ));
    assert!(stats.hash_ok, "file integrity must survive the failover");

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 14. DNS/IP leak DURING the switch: hammer DNS + watch the canary counters
/// across the exact failover window.
#[tokio::test]
async fn leak_during_switch() {
    let eng = require_engine("leak_during_switch");
    let e = &*eng;
    let mut m = Metrics::new("leak_during_switch");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    assert!(!e.dns_leak_observed().await, "precondition: no leak before fault");

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    // Hammer DNS exactly while the switch happens.
    let mut leak_rounds = 0u32;
    for _ in 0..20 {
        let _ = e.dns_query(FOREIGN).await;
        let _ = e.probe(FOREIGN).await;
        if e.dns_leak_observed().await {
            leak_rounds += 1;
        }
        if e.primary().await == TunnelId::B {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let detected = e.primary().await == TunnelId::B;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.note(format!("dns rounds with leak observed during switch: {leak_rounds}/20 (must be 0)"));
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(100.0);

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);
    m.note(format!("direct egress bytes during switch: {egress_delta} (must be 0)"));

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 15. USA exit-IP constancy across failover (transport-level failover only —
/// the exit server never changes).
#[tokio::test]
async fn exit_ip_constancy() {
    let eng = require_engine("exit_ip_constancy");
    let e = &*eng;
    let mut m = Metrics::new("exit_ip_constancy");

    assert_dual_always_on(e).await;
    let egress_before = e.direct_egress_bytes().await;
    // Baseline: exit IP must be stable before the fault.
    let mut baseline = Vec::new();
    for _ in 0..5 {
        baseline.push(e.exit_ip().await);
    }
    assert!(
        baseline.windows(2).all(|w| w[0] == w[1]),
        "precondition: exit IP stable before fault"
    );
    let ip_before = baseline[0];

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;

    // Sample repeatedly after the switch.
    let mut stable = true;
    for _ in 0..10 {
        if e.exit_ip().await != ip_before {
            stable = false;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    m.exit_ip_consistent = Some(stable);
    m.note(format!("exit IP {ip_before} stable across 10 post-switch samples: {stable}"));
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(100.0);

    m.dns_leak = Some(e.dns_leak_observed().await);
    m.routing_policy_consistent = Some(e.classify(FOREIGN).await == RouteClass::UsaTunnel);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 16. Split-routing policy consistency during failover: Iranian stays
/// Iran-direct, foreign stays USA-tunnel, before/during/after.
#[tokio::test]
async fn split_routing_consistency() {
    let eng = require_engine("split_routing_consistency");
    let e = &*eng;
    let mut m = Metrics::new("split_routing_consistency");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;
    assert_eq!(e.classify(IRANIAN).await, RouteClass::IranDirect, "precondition");
    assert_eq!(e.classify(FOREIGN).await, RouteClass::UsaTunnel, "precondition");

    let t_fault = Instant::now();
    e.inject_fault(Fault::CutTunnel(TunnelId::A)).await;
    // Check classification DURING the switch, not just after.
    let mut consistent = true;
    for _ in 0..12 {
        if e.classify(IRANIAN).await != RouteClass::IranDirect
            || e.classify(FOREIGN).await != RouteClass::UsaTunnel
        {
            consistent = false;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let detected = await_primary(e, TunnelId::B, Duration::from_secs(30)).await;
    m.failover_detection = detected.then_some(t_fault.elapsed());
    m.note(format!("classification consistent during switch window: {consistent}"));
    // And after.
    consistent = consistent
        && e.classify(IRANIAN).await == RouteClass::IranDirect
        && e.classify(FOREIGN).await == RouteClass::UsaTunnel;
    m.routing_policy_consistent = Some(consistent);

    m.traffic_recovery = await_recovery(e, FOREIGN, Duration::from_secs(30)).await;
    let (sent, ok) = probe_window(e, FOREIGN, Duration::from_secs(5)).await;
    m.packet_loss_pct = (sent > 0).then(|| 100.0 * (sent - ok) as f64 / sent as f64);
    m.session_survival_pct = Some(100.0);

    m.exit_ip_consistent = Some(e.exit_ip().await == ip_before);
    m.dns_leak = Some(e.dns_leak_observed().await);
    let egress_delta = e.direct_egress_bytes().await.saturating_sub(egress_before);

    e.clear_faults().await;
    finish_hard_invariants(&m, egress_delta);
}

/// 17. CPU/RAM under failover: sample resources across a failover storm and
/// record peaks (budgets are informational until the engine lands).
#[tokio::test]
async fn cpu_ram_under_failover() {
    let eng = require_engine("cpu_ram_under_failover");
    let e = &*eng;
    let mut m = Metrics::new("cpu_ram_under_failover");

    assert_dual_always_on(e).await;
    let ip_before = e.exit_ip().await;
    let egress_before = e.direct_egress_bytes().await;

    let baseline = e.resource_sample().await;
    m.note(format!(
        "baseline: cpu {:.1}% rss {} bytes",
        baseline.cpu_pct, baseline.rss_bytes
    ));

    let t_fault = Instant::now();
    let mut peak: Option<ResourceSample> = None;
    // Failover storm: cut A, recover, cut B, recover — sample throughout.
    for (i, t) in [TunnelId::A, TunnelId::B, TunnelId::A].iter().enumerate() {
        e.inject_fault(Fault::CutTunnel(*t)).await;
        let want = if *t == TunnelId::A { TunnelId::B } else { TunnelId::A };
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            track_peak(&mut peak, e.resource_sample().await);
            if e.primary().await == want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        e.clear_faults().await;
        m.note(format!("storm round {i}: switched to {want}"));
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let peak = peak.unwrap_or(baseline);
    m.peak_cpu_pct = Some(peak.cpu_pct);
    m.peak_rss_bytes = Some(peak.rss_bytes);
    m.note(format!(
        "peak during storm: cpu {:.1}% rss {} bytes (budgets informational)",
        peak.cpu_pct, peak.rss_bytes
    ));

    m.failover_detection = Some(t_fault.elapsed());
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
