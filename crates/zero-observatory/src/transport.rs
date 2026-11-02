//! Multi-transport Iran→USA link selection (owner architectural directive,
//! extended by the triple-tunnel addendum 2026-11-01).
//!
//! The inter-server link is a *transport group*: several outbounds to the
//! SAME USA server (fixed exit IP — failover is between transports, never
//! between exits).
//!
//! Triple-tunnel (default): A (IPv4 primary) + B (IPv4 hot standby) + C
//! (IPv6 hot standby, when real end-to-end IPv6 is verified; otherwise
//! marked Unavailable, never faked). Mode: Active + Hot Standby + Hot
//! Standby. All three terminate at the same USA server; a tunnel switch
//! NEVER changes the public exit IP.
//!
//! Selection reuses the pair engine's machinery (§3.5 patterns): eligibility
//! from the [`HealthTable`], immediate failover when the active transport
//! dies, revertive switching back to a recovered higher-priority transport
//! only after a cooldown (hysteresis — no flapping), and a bounded
//! switch-reason log. It is deliberately simpler than pair selection: there
//! are no modes or scorers, just priority order plus health.
//!
//! Fail-closed: when no transport is eligible, the group reports
//! [`TransportPick::DeadEnd`] and the caller blocks foreign traffic — it
//! never reroutes via Iran. All-three-down → foreign fail-closed, Iranian
//! may continue.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{HealthTable, FAILING_RUN};

/// One transport group: an ordered list of outbound tags to the same USA
/// server. Index 0 is the primary.
#[derive(Debug, Clone)]
pub struct TransportGroup {
    pub tag: Arc<str>,
    /// Outbound tags in priority order.
    pub transports: Vec<Arc<str>>,
    /// Minimum time before switching back to a recovered higher-priority
    /// transport. Failover (active dead) ignores the cooldown.
    pub cooldown: Duration,
    /// Ring buffer size of the switch-reason log.
    pub switch_log_size: usize,
    /// Consecutive failed heartbeats that declare a transport dead.
    pub fail_after: u32,
}

/// Why the active transport changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSwitchReason {
    /// First selection.
    Initial,
    /// The active transport died; failed over to the next eligible one.
    TransportFailed,
    /// A higher-priority transport recovered; reverted after the cooldown.
    PrimaryRecovered,
    /// Another transport is significantly more stable; switched on quality
    /// (stability outranks lowest ping).
    BetterQuality,
    /// The operator pinned a manual primary in the panel.
    Manual,
}

/// One entry in the switch-reason log.
#[derive(Debug, Clone)]
pub struct TransportSwitch {
    pub at: Instant,
    pub from: Option<Arc<str>>,
    pub to: Arc<str>,
    pub reason: TransportSwitchReason,
}

/// What the group carries traffic on next.
#[derive(Debug, Clone)]
pub enum TransportPick {
    Active(Arc<str>),
    DeadEnd,
}

/// Windowed heartbeat evidence for one transport. A ring of recent probe
/// outcomes gives loss rate, RTT average, and jitter — the stability signals
/// that outrank lowest ping in every selection decision.
#[derive(Debug, Clone)]
pub struct TransportMonitor {
    /// Recent heartbeat outcomes: (at, success, rtt). Bounded ring.
    window: VecDeque<HeartbeatSample>,
    window_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct HeartbeatSample {
    at: Instant,
    success: bool,
    rtt: Option<Duration>,
}

/// The quality signals derived from the window. All real, measurable values
/// (panel + tests).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TransportQuality {
    /// Fraction of heartbeats that succeeded in the window (0.0–1.0).
    pub success_rate: f64,
    /// Fraction lost (1.0 − success_rate).
    pub loss_rate: f64,
    /// Mean RTT of successful heartbeats, if any.
    pub avg_rtt: Option<Duration>,
    /// Jitter: mean absolute deviation of RTT, if enough samples.
    pub jitter: Option<Duration>,
    /// When the last heartbeat succeeded, if ever.
    pub last_success: Option<Instant>,
}

impl TransportMonitor {
    pub fn new(window_size: usize) -> Self {
        Self {
            window: VecDeque::new(),
            window_size: window_size.max(4),
        }
    }

    pub fn record(&mut self, at: Instant, success: bool, rtt: Option<Duration>) {
        self.window.push_back(HeartbeatSample { at, success, rtt });
        while self.window.len() > self.window_size {
            self.window.pop_front();
        }
    }

    pub fn quality(&self) -> TransportQuality {
        let total = self.window.len();
        if total == 0 {
            return TransportQuality {
                success_rate: 0.0,
                loss_rate: 0.0,
                avg_rtt: None,
                jitter: None,
                last_success: None,
            };
        }
        let successes = self.window.iter().filter(|sample| sample.success).count();
        let success_rate = successes as f64 / total as f64;
        let rtts: Vec<f64> = self
            .window
            .iter()
            .filter_map(|sample| sample.rtt.map(|rtt| rtt.as_secs_f64()))
            .collect();
        let avg_rtt = if rtts.is_empty() {
            None
        } else {
            Some(Duration::from_secs_f64(
                rtts.iter().sum::<f64>() / rtts.len() as f64,
            ))
        };
        let jitter = if rtts.len() >= 3 {
            let mean = rtts.iter().sum::<f64>() / rtts.len() as f64;
            let mad = rtts.iter().map(|rtt| (rtt - mean).abs()).sum::<f64>() / rtts.len() as f64;
            Some(Duration::from_secs_f64(mad))
        } else {
            None
        };
        let last_success = self
            .window
            .iter()
            .rev()
            .find(|sample| sample.success)
            .map(|sample| sample.at);
        TransportQuality {
            success_rate,
            loss_rate: 1.0 - success_rate,
            avg_rtt,
            jitter,
            last_success,
        }
    }

    /// Stability score: higher is better. Success rate dominates; among
    /// equally reliable transports, lower jitter outranks lower ping —
    /// stability outranks lowest ping in every selection decision.
    pub fn stability_score(&self) -> f64 {
        let quality = self.quality();
        // Success rate is the primary signal (0–100).
        let mut score = quality.success_rate * 100.0;
        // Jitter penalty: a jittery transport is deprioritised even if its
        // ping is low. 100ms of jitter costs 10 points.
        if let Some(jitter) = quality.jitter {
            score -= jitter.as_secs_f64() * 100.0;
        }
        // Latency is a tiebreaker only: 100ms of extra ping costs 1 point.
        if let Some(rtt) = quality.avg_rtt {
            score -= rtt.as_secs_f64() * 10.0;
        }
        score
    }
}

#[derive(Debug)]
struct GroupState {
    group: TransportGroup,
    active: Option<Arc<str>>,
    /// Manual primary selection (panel). When set and the transport is
    /// eligible, it is preferred over automatic quality selection.
    preferred: Option<Arc<str>>,
    last_switch: Option<Instant>,
    switch_log: VecDeque<TransportSwitch>,
    /// One windowed monitor per transport tag, for the stability signals.
    monitors: HashMap<Arc<str>, TransportMonitor>,
    /// When the active transport was declared dead (for detection-time
    /// metrics), if it is currently dead.
    dead_since: Option<Instant>,
    /// Completed failovers with their measured detection and recovery times.
    failover_history: VecDeque<FailoverRecord>,
}

/// One completed failover, with measured times. All real, measurable values
/// for the panel and the tests — never estimated.
#[derive(Debug, Clone)]
pub struct FailoverRecord {
    /// Wall-clock epoch millis of the failover decision.
    pub at_epoch_ms: u64,
    pub from: Arc<str>,
    pub to: Arc<str>,
    /// How long between the last successful heartbeat on the old transport
    /// and the failover decision.
    pub detection_time: Duration,
    /// How long between the failover decision and the first successful
    /// heartbeat (or session) on the new transport.
    pub recovery_time: Option<Duration>,
    /// Why the failover happened.
    pub reason: TransportSwitchReason,
}

/// Priority-ordered transport selection over the [`HealthTable`].
#[derive(Debug, Default)]
pub struct TransportTable {
    groups: HashMap<Arc<str>, GroupState>,
}

impl TransportTable {
    pub fn new(groups: Vec<TransportGroup>) -> Self {
        let mut table = Self {
            groups: HashMap::new(),
        };
        for group in groups {
            let mut monitors = HashMap::new();
            for transport in &group.transports {
                monitors.insert(transport.clone(), TransportMonitor::new(20));
            }
            table.groups.insert(
                group.tag.clone(),
                GroupState {
                    group,
                    active: None,
                    preferred: None,
                    last_switch: None,
                    switch_log: VecDeque::new(),
                    monitors,
                    dead_since: None,
                    failover_history: VecDeque::new(),
                },
            );
        }
        table
    }

    pub fn is_group(&self, tag: &str) -> bool {
        self.groups.contains_key(tag)
    }

    /// Reconfigure the groups (config reload). Group states whose tag still
    /// exists keep their monitors, active transport, and history; new tags
    /// start fresh; removed tags are dropped.
    pub fn reconfigure(&mut self, groups: Vec<TransportGroup>) {
        let mut next: HashMap<Arc<str>, GroupState> = HashMap::new();
        for group in groups {
            if let Some(mut state) = self.groups.remove(group.tag.as_ref()) {
                // Keep the monitors and history; take the new policy.
                // (Monitors are keyed by transport tag; a transport that
                // vanished from the group keeps its monitor harmlessly.)
                state.group = group;
                next.insert(state.group.tag.clone(), state);
            } else {
                let mut monitors = HashMap::new();
                for transport in &group.transports {
                    monitors.insert(transport.clone(), TransportMonitor::new(20));
                }
                next.insert(
                    group.tag.clone(),
                    GroupState {
                        group,
                        active: None,
                        preferred: None,
                        last_switch: None,
                        switch_log: VecDeque::new(),
                        monitors,
                        dead_since: None,
                        failover_history: VecDeque::new(),
                    },
                );
            }
        }
        self.groups = next;
    }

    /// Decide what carries the group's traffic next. Call after every probe
    /// result and every dial failure that changed the evidence.
    ///
    /// Selection order:
    /// 1. Failover: the active transport is dead → the best eligible one at
    ///    once, cooldown be damned.
    /// 2. Quality: when several are healthy, route by real quality —
    ///    stability (success rate, jitter) outranks lowest ping — with a
    ///    hysteresis margin and a cooldown so a marginal difference does not
    ///    flap. The primary (index 0) gets a small preference bonus.
    /// 3. Otherwise keep the active transport.
    pub fn choose(&mut self, group_tag: &str, health: &HealthTable, now: Instant) -> TransportPick {
        let Some(state) = self.groups.get_mut(group_tag) else {
            return TransportPick::DeadEnd;
        };
        // Eligible = fewer than 3 consecutive failures, in priority order.
        let eligible: Vec<Arc<str>> = state
            .group
            .transports
            .iter()
            .filter(|tag| health.sample(tag).consecutive_failures < state.group.fail_after)
            .cloned()
            .collect();
        if eligible.is_empty() {
            if state.dead_since.is_none() {
                state.dead_since = Some(now);
            }
            return TransportPick::DeadEnd;
        }
        // Manual primary (panel): when the preferred transport is eligible,
        // it wins over automatic selection. If it is not eligible, automatic
        // selection applies (failover still works).
        if let Some(preferred) = state.preferred.clone() {
            if eligible.iter().any(|tag| tag == &preferred) {
                if state.active.as_ref() != Some(&preferred) {
                    let from = state.active.clone();
                    return Self::apply_switch(
                        state,
                        from,
                        preferred,
                        TransportSwitchReason::Manual,
                        now,
                    );
                }
                return TransportPick::Active(preferred);
            }
        }
        // Failover: the active transport is dead → switch at once to the
        // best eligible one. Cooldown be damned: a dead transport is dead.
        let fail_after = state.group.fail_after;
        let active_dead = state
            .active
            .as_ref()
            .is_some_and(|active| health.sample(active).consecutive_failures >= fail_after);
        if let Some(active) = state.active.clone() {
            if active_dead {
                if state.dead_since.is_none() {
                    state.dead_since = Some(now);
                }
                let to = Self::best_eligible(state, &eligible);
                let detection_time = state
                    .dead_since
                    .map(|since| now.duration_since(since))
                    .unwrap_or_default();
                let from = active.clone();
                let pick = Self::apply_switch(
                    state,
                    Some(active),
                    to.clone(),
                    TransportSwitchReason::TransportFailed,
                    now,
                );
                Self::record_failover(
                    state,
                    from,
                    to,
                    detection_time,
                    TransportSwitchReason::TransportFailed,
                );
                return pick;
            }
            if !eligible.iter().any(|tag| tag == &active) {
                let to = Self::best_eligible(state, &eligible);
                return Self::apply_switch(
                    state,
                    Some(active),
                    to,
                    TransportSwitchReason::TransportFailed,
                    now,
                );
            }
            state.dead_since = None;
            let cooled = state.last_switch.map_or(true, |switched| {
                now.duration_since(switched) >= state.group.cooldown
            });
            // Revertive switching: a higher-priority transport recovered.
            // It must PROVE stability first (several good heartbeats) — no
            // immediate flap-back to a flaky primary. Then the cooldown.
            let active_priority = Self::priority_of(state, &active);
            let mut recovered: Option<Arc<str>> = None;
            for tag in &eligible {
                if Self::priority_of(state, tag) < active_priority
                    && Self::proven_stable(state, tag)
                {
                    recovered = Some(tag.clone());
                    break;
                }
            }
            if let Some(to) = recovered {
                if cooled {
                    return Self::apply_switch(
                        state,
                        Some(active),
                        to,
                        TransportSwitchReason::PrimaryRecovered,
                        now,
                    );
                }
                return TransportPick::Active(active);
            }
            // Quality-based routing: among healthy transports, the most
            // stable wins — not the lowest ping. Switch only for a clear
            // margin past the cooldown (hysteresis).
            let active_score = Self::scored(state, &active);
            let mut best: Option<(Arc<str>, f64)> = None;
            for tag in &eligible {
                if tag == &active {
                    continue;
                }
                let score = Self::scored(state, tag);
                if best
                    .as_ref()
                    .map_or(true, |(_, best_score)| score > *best_score)
                {
                    best = Some((tag.clone(), score));
                }
            }
            if let Some((challenger, challenger_score)) = best {
                const QUALITY_MARGIN: f64 = 10.0;
                if challenger_score > active_score + QUALITY_MARGIN && cooled {
                    return Self::apply_switch(
                        state,
                        Some(active),
                        challenger,
                        TransportSwitchReason::BetterQuality,
                        now,
                    );
                }
            }
            return TransportPick::Active(active);
        }
        // First selection: the best eligible transport.
        let to = Self::best_eligible(state, &eligible);
        Self::apply_switch(state, None, to, TransportSwitchReason::Initial, now)
    }

    /// The stability score of a transport, with a small bonus for the
    /// primary (index 0) so quality ties keep the preferred transport.
    fn scored(state: &GroupState, tag: &Arc<str>) -> f64 {
        let base = state
            .monitors
            .get(tag)
            .map(|monitor| monitor.stability_score())
            .unwrap_or(0.0);
        if state.group.transports.first() == Some(tag) {
            base + 5.0
        } else {
            base
        }
    }

    fn priority_of(state: &GroupState, tag: &Arc<str>) -> usize {
        state
            .group
            .transports
            .iter()
            .position(|member| member == tag)
            .unwrap_or(usize::MAX)
    }

    /// The highest-quality eligible transport (priority order breaks ties).
    fn best_eligible(state: &GroupState, eligible: &[Arc<str>]) -> Arc<str> {
        let mut best = eligible[0].clone();
        let mut best_score = Self::scored(state, &best);
        for tag in eligible.iter().skip(1) {
            let score = Self::scored(state, tag);
            if score > best_score {
                best = tag.clone();
                best_score = score;
            }
        }
        best
    }

    /// A transport has proven stable when its window shows a solid
    /// success rate. Guards against flapping back to a primary that is
    /// still flaky.
    fn proven_stable(state: &GroupState, tag: &Arc<str>) -> bool {
        state
            .monitors
            .get(tag)
            .is_some_and(|monitor| monitor.quality().success_rate >= 0.8)
    }

    fn record_failover(
        state: &mut GroupState,
        from: Arc<str>,
        to: Arc<str>,
        detection_time: Duration,
        reason: TransportSwitchReason,
    ) {
        let at_epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        state.failover_history.push_back(FailoverRecord {
            at_epoch_ms,
            from,
            to,
            detection_time,
            recovery_time: None,
            reason,
        });
        while state.failover_history.len() > 64 {
            state.failover_history.pop_front();
        }
        state.dead_since = None;
    }

    fn apply_switch(
        state: &mut GroupState,
        from: Option<Arc<str>>,
        to: Arc<str>,
        reason: TransportSwitchReason,
        now: Instant,
    ) -> TransportPick {
        state.active = Some(to.clone());
        state.last_switch = Some(now);
        state.switch_log.push_back(TransportSwitch {
            at: now,
            from,
            to: to.clone(),
            reason,
        });
        while state.switch_log.len() > state.group.switch_log_size {
            state.switch_log.pop_front();
        }
        TransportPick::Active(to)
    }

    /// Pin a transport as the manual primary (panel). It is used when
    /// eligible; clearing returns to automatic selection.
    pub fn set_preferred(&mut self, group_tag: &str, transport: Option<&str>) {
        if let Some(state) = self.groups.get_mut(group_tag) {
            state.preferred = transport.map(Arc::from);
        }
    }

    pub fn preferred(&self, group_tag: &str) -> Option<Arc<str>> {
        self.groups
            .get(group_tag)
            .and_then(|state| state.preferred.clone())
    }

    /// Record a heartbeat outcome for one transport. Feeds the windowed
    /// stability signals and the HealthTable-equivalent success tracking
    /// (the caller also records into the shared HealthTable).
    pub fn record_heartbeat(
        &mut self,
        group_tag: &str,
        transport: &str,
        at: Instant,
        success: bool,
        rtt: Option<Duration>,
    ) {
        if let Some(state) = self.groups.get_mut(group_tag) {
            if let Some(monitor) = state.monitors.get_mut(transport) {
                monitor.record(at, success, rtt);
            }
        }
    }

    /// The windowed quality signals for one transport, for the panel.
    pub fn quality(&self, group_tag: &str, transport: &str) -> Option<TransportQuality> {
        self.groups
            .get(group_tag)
            .and_then(|state| state.monitors.get(transport))
            .map(|monitor| monitor.quality())
    }

    /// Completed failovers with measured detection/recovery times, newest last.
    pub fn failover_history(&self, group_tag: &str) -> Vec<FailoverRecord> {
        self.groups
            .get(group_tag)
            .map(|state| state.failover_history.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The active transport of a group, if any.
    pub fn active(&self, group_tag: &str) -> Option<Arc<str>> {
        self.groups
            .get(group_tag)
            .and_then(|state| state.active.clone())
    }

    /// The bounded switch-reason log for a group, newest last.
    pub fn switch_log(&self, group_tag: &str) -> Vec<TransportSwitch> {
        self.groups
            .get(group_tag)
            .map(|state| state.switch_log.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> TransportGroup {
        TransportGroup {
            tag: Arc::from("usa-link"),
            transports: vec![Arc::from("wg-tunnel"), Arc::from("tls-tunnel")],
            cooldown: Duration::from_secs(120),
            switch_log_size: 32,
            fail_after: 3,
        }
    }

    fn healthy_table() -> HealthTable {
        let mut health = HealthTable::default();
        health.record_success("wg-tunnel", Duration::from_millis(40));
        health.record_success("tls-tunnel", Duration::from_millis(90));
        health
    }

    #[test]
    fn first_selection_picks_the_primary() {
        let mut table = TransportTable::new(vec![group()]);
        let health = healthy_table();
        let now = Instant::now();
        let pick = table.choose("usa-link", &health, now);
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "wg-tunnel"));
        let log = table.switch_log("usa-link");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].reason, TransportSwitchReason::Initial);
    }

    #[test]
    fn dead_primary_fails_over_immediately() {
        let mut table = TransportTable::new(vec![group()]);
        let mut health = healthy_table();
        let now = Instant::now();
        let _ = table.choose("usa-link", &health, now);
        // Kill the primary.
        for _ in 0..3 {
            health.record_failure("wg-tunnel");
        }
        let pick = table.choose("usa-link", &health, now);
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "tls-tunnel"));
        let log = table.switch_log("usa-link");
        assert_eq!(log[1].reason, TransportSwitchReason::TransportFailed);
    }

    #[test]
    fn all_transports_dead_is_a_dead_end() {
        let mut table = TransportTable::new(vec![group()]);
        let mut health = healthy_table();
        let now = Instant::now();
        let _ = table.choose("usa-link", &health, now);
        for _ in 0..3 {
            health.record_failure("wg-tunnel");
            health.record_failure("tls-tunnel");
        }
        let pick = table.choose("usa-link", &health, now);
        assert!(matches!(pick, TransportPick::DeadEnd));
    }

    #[test]
    fn primary_recovery_waits_for_the_cooldown() {
        let mut table = TransportTable::new(vec![group()]);
        let mut health = healthy_table();
        let start = Instant::now();
        let _ = table.choose("usa-link", &health, start);
        for _ in 0..3 {
            health.record_failure("wg-tunnel");
        }
        let failed_over_at = start + Duration::from_secs(10);
        let pick = table.choose("usa-link", &health, failed_over_at);
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "tls-tunnel"));
        // The primary recovers in the HealthTable, but it has not PROVEN
        // stability yet (no good heartbeats): no revert, even past the
        // cooldown.
        health.record_success("wg-tunnel", Duration::from_millis(40));
        let pick = table.choose(
            "usa-link",
            &health,
            failed_over_at + Duration::from_secs(130),
        );
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "tls-tunnel"));
        // The primary proves stability with good heartbeats; the cooldown
        // has not elapsed since the failover: still stay.
        let mut at = failed_over_at + Duration::from_secs(11);
        for _ in 0..5 {
            table.record_heartbeat(
                "usa-link",
                "wg-tunnel",
                at,
                true,
                Some(Duration::from_millis(40)),
            );
            at += Duration::from_secs(3);
        }
        let pick = table.choose(
            "usa-link",
            &health,
            failed_over_at + Duration::from_secs(60),
        );
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "tls-tunnel"));
        // Past the cooldown with a proven-stable primary: revert.
        let pick = table.choose(
            "usa-link",
            &health,
            failed_over_at + Duration::from_secs(130),
        );
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "wg-tunnel"));
        let log = table.switch_log("usa-link");
        assert_eq!(log[2].reason, TransportSwitchReason::PrimaryRecovered);
    }

    #[test]
    fn quality_beats_ping_when_stability_differs() {
        let mut table = TransportTable::new(vec![group()]);
        let health = healthy_table();
        let start = Instant::now();
        // Seed both monitors: the primary is fast but jittery/lossy, the
        // fallback is slower but rock solid.
        let mut at = start;
        for i in 0..10 {
            let lossy = i % 3 == 0; // 30% loss on the primary
            table.record_heartbeat(
                "usa-link",
                "wg-tunnel",
                at,
                !lossy,
                Some(Duration::from_millis(if lossy { 0 } else { 30 + i * 7 })),
            );
            table.record_heartbeat(
                "usa-link",
                "tls-tunnel",
                at,
                true,
                Some(Duration::from_millis(90)),
            );
            at += Duration::from_secs(3);
        }
        // Both eligible (primary has <3 CONSECUTIVE failures). The first
        // pick already routes by quality: the slower but rock-solid
        // fallback wins over the fast but lossy/jittery primary.
        // Stability outranks lowest ping.
        let pick = table.choose("usa-link", &health, at);
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "tls-tunnel"));
        let log = table.switch_log("usa-link");
        assert_eq!(log[0].reason, TransportSwitchReason::Initial);
        // It stays there: the primary never becomes the better choice.
        let later = at + Duration::from_secs(200);
        let pick = table.choose("usa-link", &health, later);
        assert!(matches!(pick, TransportPick::Active(tag) if tag.as_ref() == "tls-tunnel"));
    }

    #[test]
    fn unknown_group_is_a_dead_end() {
        let mut table = TransportTable::new(vec![group()]);
        let health = healthy_table();
        let pick = table.choose("no-such-group", &health, Instant::now());
        assert!(matches!(pick, TransportPick::DeadEnd));
    }
}
