//! [`HaMetrics`]: the metric record every failover scenario must fill.
//!
//! Required metrics (owner HA addendum, binding):
//! - failover detection time
//! - traffic recovery time
//! - existing-session survival %
//! - packet loss during failover
//! - USA exit-IP consistency (bool)
//! - DNS leak result
//! - routing policy consistency (bool)
//! - CPU/RAM under failover
//!
//! Hard invariants (asserted by the skeletons once wired): exit IP must not
//! change across a failover, no DNS leak, split-routing policy must hold,
//! zero direct egress of foreign traffic. Timing/survival/loss are recorded
//! and reported; their acceptance budgets are set by the routing agent when
//! the engine lands — the harness does not invent them.

use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct HaMetrics {
    pub scenario: &'static str,
    /// Fault injection -> engine's failover decision observed.
    pub failover_detection: Option<Duration>,
    /// Fault injection -> first successful data transfer on the new path.
    pub traffic_recovery: Option<Duration>,
    /// % of pre-failover sessions still alive afterwards (0..=100).
    pub session_survival_pct: Option<f64>,
    /// % of probes lost inside the failover window (0..=100).
    pub packet_loss_pct: Option<f64>,
    /// USA exit IP identical before/after the failover.
    pub exit_ip_consistent: Option<bool>,
    /// true = a leak was observed (BAD). None = not measured.
    pub dns_leak: Option<bool>,
    /// Split-routing classification held for the whole scenario.
    pub routing_policy_consistent: Option<bool>,
    pub peak_cpu_pct: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
    pub notes: Vec<String>,
}

impl HaMetrics {
    pub fn new(scenario: &'static str) -> Self {
        HaMetrics {
            scenario,
            ..Default::default()
        }
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    fn opt_dur(v: Option<Duration>) -> String {
        v.map(|d| format!("{:.2?}", d))
            .unwrap_or_else(|| "n/a".to_string())
    }

    fn opt_pct(v: Option<f64>) -> String {
        v.map(|p| format!("{:.1}%", p))
            .unwrap_or_else(|| "n/a".to_string())
    }

    fn opt_bool(v: Option<bool>) -> String {
        v.map(|b| b.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    }

    /// Human-readable report, printed by every scenario skeleton.
    pub fn report(&self) -> String {
        let mut s = format!("=== HA metrics: {} ===\n", self.scenario);
        s.push_str(&format!(
            "  failover_detection:       {}\n",
            Self::opt_dur(self.failover_detection)
        ));
        s.push_str(&format!(
            "  traffic_recovery:         {}\n",
            Self::opt_dur(self.traffic_recovery)
        ));
        s.push_str(&format!(
            "  session_survival_pct:     {}\n",
            Self::opt_pct(self.session_survival_pct)
        ));
        s.push_str(&format!(
            "  packet_loss_pct:          {}\n",
            Self::opt_pct(self.packet_loss_pct)
        ));
        s.push_str(&format!(
            "  exit_ip_consistent:       {}\n",
            Self::opt_bool(self.exit_ip_consistent)
        ));
        s.push_str(&format!(
            "  dns_leak:                 {} (true = LEAK, bad)\n",
            Self::opt_bool(self.dns_leak)
        ));
        s.push_str(&format!(
            "  routing_policy_consistent: {}\n",
            Self::opt_bool(self.routing_policy_consistent)
        ));
        s.push_str(&format!(
            "  peak_cpu_pct:             {}\n",
            Self::opt_pct(self.peak_cpu_pct)
        ));
        s.push_str(&format!(
            "  peak_rss_bytes:           {}\n",
            self.peak_rss_bytes
                .map(|b| b.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        for n in &self.notes {
            s.push_str(&format!("  note: {n}\n"));
        }
        s
    }

    /// True when every required metric was recorded.
    pub fn is_complete(&self) -> bool {
        self.failover_detection.is_some()
            && self.traffic_recovery.is_some()
            && self.session_survival_pct.is_some()
            && self.packet_loss_pct.is_some()
            && self.exit_ip_consistent.is_some()
            && self.dns_leak.is_some()
            && self.routing_policy_consistent.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_metrics_are_unmeasured() {
        let m = HaMetrics::new("unit");
        assert!(!m.is_complete());
        assert!(m.failover_detection.is_none());
    }

    #[test]
    fn report_contains_scenario_and_values() {
        let mut m = HaMetrics::new("unit-scenario");
        m.failover_detection = Some(Duration::from_millis(3200));
        m.exit_ip_consistent = Some(true);
        m.dns_leak = Some(false);
        m.note("hello");
        let r = m.report();
        assert!(r.contains("unit-scenario"));
        assert!(r.contains("3.20s"));
        assert!(r.contains("exit_ip_consistent:       true"));
        assert!(r.contains("note: hello"));
    }

    #[test]
    fn complete_when_all_required_recorded() {
        let mut m = HaMetrics::new("unit");
        m.failover_detection = Some(Duration::from_secs(1));
        m.traffic_recovery = Some(Duration::from_secs(2));
        m.session_survival_pct = Some(80.0);
        m.packet_loss_pct = Some(5.0);
        m.exit_ip_consistent = Some(true);
        m.dns_leak = Some(false);
        m.routing_policy_consistent = Some(true);
        assert!(m.is_complete());
    }
}
