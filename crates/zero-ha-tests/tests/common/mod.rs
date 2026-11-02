//! Shared helpers for the HA failover scenario skeletons.
//! Everything here compiles against the `HaEngine` trait; the bodies are
//! complete — only the engine itself is missing (SCAFFOLD).

use std::sync::Arc;
use std::time::{Duration, Instant};
use zero_ha_tests::engine::*;
use zero_ha_tests::metrics::HaMetrics;
use zero_ha_tests::wiring;

pub use zero_ha_tests::metrics::HaMetrics as Metrics;

pub fn require_engine(scenario: &'static str) -> Arc<dyn HaEngine> {
    wiring::require_engine(scenario)
}

/// Wait until a tunnel reaches `want` (poll every 200ms).
pub async fn await_state(
    eng: &dyn HaEngine,
    id: TunnelId,
    want: TunnelState,
    timeout: Duration,
) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if eng.tunnel_health(id).await.state == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Wait until `want` becomes the primary tunnel.
pub async fn await_primary(eng: &dyn HaEngine, want: TunnelId, timeout: Duration) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if eng.primary().await == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Assert the dual always-on precondition: A up, B hot standby.
pub async fn assert_dual_always_on(eng: &dyn HaEngine) {
    assert!(
        await_state(eng, TunnelId::A, TunnelState::Up, Duration::from_secs(15)).await,
        "precondition: tunnel A must be Up"
    );
    assert!(
        await_state(eng, TunnelId::B, TunnelState::Standby, Duration::from_secs(15)).await,
        "precondition: tunnel B must be hot Standby (dual always-on)"
    );
}

/// Open a mix of TCP and UDP sessions through the current primary path.
pub async fn open_mixed_sessions(
    eng: &dyn HaEngine,
    dst: &str,
    tcp: usize,
    udp: usize,
) -> Vec<(SessionId, SessionKind)> {
    let mut out = Vec::with_capacity(tcp + udp);
    for _ in 0..tcp {
        out.push((eng.open_session(dst, SessionKind::Tcp).await, SessionKind::Tcp));
    }
    for _ in 0..udp {
        out.push((eng.open_session(dst, SessionKind::Udp).await, SessionKind::Udp));
    }
    out
}

/// Fraction of `sessions` still alive, as a percentage.
pub async fn survival_pct(eng: &dyn HaEngine, sessions: &[(SessionId, SessionKind)]) -> f64 {
    if sessions.is_empty() {
        return 100.0;
    }
    let mut alive = 0usize;
    for (id, _) in sessions {
        if eng.session_alive(*id).await {
            alive += 1;
        }
    }
    100.0 * alive as f64 / sessions.len() as f64
}

/// Probe in a loop for `dur`; returns (sent, ok) for loss measurement.
pub async fn probe_window(eng: &dyn HaEngine, dst: &str, dur: Duration) -> (u64, u64) {
    let t0 = Instant::now();
    let (mut sent, mut ok) = (0u64, 0u64);
    while t0.elapsed() < dur {
        sent += 1;
        if eng.probe(dst).await {
            ok += 1;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    (sent, ok)
}

/// Wait for the first successful probe; returns the elapsed time (None on timeout).
pub async fn await_recovery(eng: &dyn HaEngine, dst: &str, timeout: Duration) -> Option<Duration> {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if eng.probe(dst).await {
            return Some(t0.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

/// Track a peak resource sample. Used by the traffic scenarios; dead in the
/// core target by construction (each integration-test target compiles
/// `common` separately).
#[allow(dead_code)]
pub fn track_peak(peak: &mut Option<ResourceSample>, s: ResourceSample) {
    let better = match peak {
        None => true,
        Some(p) => s.cpu_pct > p.cpu_pct,
    };
    if better {
        *peak = Some(s);
    }
}

/// Assert the hard fail-closed invariants and print the metric report.
/// Called at the end of every scenario skeleton.
pub fn finish_hard_invariants(m: &HaMetrics, egress_delta: u64) {
    println!("{}", m.report());
    assert_eq!(
        m.exit_ip_consistent,
        Some(true),
        "USA exit IP must not change across failover"
    );
    assert_eq!(
        m.dns_leak,
        Some(false),
        "no DNS leak is allowed during failover"
    );
    assert_eq!(
        m.routing_policy_consistent,
        Some(true),
        "split-routing policy must hold during failover"
    );
    assert_eq!(
        egress_delta, 0,
        "fail-closed: foreign traffic must never egress directly"
    );
}
