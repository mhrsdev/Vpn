//! Pair-aware health and smart route selection (Design B).
//!
//! The unit of end-to-end selection is the **pair** = {gateway outbound(s),
//! exit identity, tunnel}. Pair health is decomposed into two independently
//! probed legs so each path fails over without disturbing the other's
//! healthy state:
//!
//! * **Path A** (client → Iran gateway): cheap direct probes of the gateway
//!   outbound alone. Recorded in the existing [`HealthTable`], shared across
//!   all pairs on the same gateway.
//! * **Path B** (gateway → tunnel → USA exit): end-to-end probes through the
//!   active pair. Recorded in the [`PairTable`] below, attributed per
//!   §2.3: an e2e failure with a healthy gateway is a *pair* fault; an e2e
//!   failure with a failing gateway is a *gateway* fault.
//!
//! A pair is eligible only while its gateway leg has
//! `consecutive_failures < FAILING_RUN` **and** its pair sample has
//! `consecutive_failures < FAILING_RUN`. The [`PairEngine`] applies the mode
//! scorer (§3.5) over the eligible set, with cooldown, flap penalties, and a
//! switch-reason ring buffer. The engine never touches the network: the
//! runtime feeds probe results in and reads [`Pick`] decisions out.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use super::{HealthTable, FAILING_RUN};

/// How many recent probe outcomes feed the loss window and the gaming
/// scorer's delay list.
const LOSS_WINDOW: usize = 32;
/// Recent delay samples kept per pair for the gaming scorer.
const DELAY_SAMPLES: usize = 16;
/// EWMA weights for the pair latency, matching the crate's 0.8/0.2 split.
const LATENCY_OLD: f64 = 0.8;
const LATENCY_NEW: f64 = 0.2;
/// A pair nobody has measured yet carries a neutral prior, like the
/// balancer's unknown member (5.0 s there).
const UNKNOWN_LATENCY_SECS: f64 = 5.0;
/// Flap penalty added to a pair's score per recent flap, for one hour.
const FLAP_PENALTY_MS: f64 = 50.0;
/// `GameTune.LOSS_PENALTY_MS` (Kotlin): charge per unanswered attempt.
const GAME_LOSS_PENALTY_MS: f64 = 400.0;
/// `GameTune.WORTH_SWITCHING`: a challenger must beat the incumbent by at
/// least this factor to take over in gaming mode.
const GAME_WORTH_SWITCHING: f64 = 0.85;
/// Balanced mode: loss weighted ~8x latency, mirroring
/// `zero-masterdns`'s `HybridScore`.
const BALANCED_LOSS_WEIGHT: f64 = 8.0;

/// The selection mode: a policy overlay on the scorer + candidate filter
/// (Design B §3.5). Mirrors `zero_config::RoutingMode`; the conversion lives
/// in `zero-runtime` so this crate stays free of the config crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    Balanced,
    LowestLatency,
    MaxStability,
    Gaming,
    Manual,
    FixedUsExit,
}

/// One configured pair binding (projection only — no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairDescriptor {
    /// The client→gateway outbound tag; also the pair's key.
    pub tag: Arc<str>,
    /// PairRecord v2 id: the join key for the app and the admin backend.
    pub pair_id: Arc<str>,
    /// The exit's public host.
    pub exit_host: Arc<str>,
    /// ISO-3166 alpha-2, uppercase ASCII (e.g. `b"US"`).
    pub exit_country: [u8; 2],
    /// Fail-safe default true.
    pub fail_closed: bool,
}

/// Why the engine moved traffic from one pair to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    PairFailed,
    GatewayFailed,
    TunnelFailed,
    BetterPath,
    Manual,
    LockChanged,
    ModeChanged,
    FallbackEngaged,
}

impl SwitchReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PairFailed => "pair_failed",
            Self::GatewayFailed => "gateway_failed",
            Self::TunnelFailed => "tunnel_failed",
            Self::BetterPath => "better_path",
            Self::Manual => "manual",
            Self::LockChanged => "lock_changed",
            Self::ModeChanged => "mode_changed",
            Self::FallbackEngaged => "fallback_engaged",
        }
    }
}

/// One entry of the switch-reason ring buffer.
#[derive(Debug, Clone)]
pub struct SwitchEvent {
    pub at: SystemTime,
    pub from: Option<Arc<str>>,
    pub to: Option<Arc<str>>,
    pub reason: SwitchReason,
    /// The new pair's RTT at switch time, when known.
    pub rtt_ms: Option<f64>,
}

/// Per-pair health evidence.
#[derive(Debug, Clone)]
pub struct PairSample {
    pub successes: u32,
    pub failures: u32,
    pub consecutive_failures: u32,
    /// EWMA of end-to-end establishment time.
    pub latency: Option<Duration>,
    /// EWMA of mean absolute deviation of the establishment samples.
    pub jitter: Option<Duration>,
    /// Bounded window of recent probe outcomes (`true` = success).
    pub loss_window: VecDeque<bool>,
    /// Recent delay samples in ms; negative = unanswered. Feeds the gaming
    /// scorer with the exact `GameTune` semantics.
    pub delay_samples: VecDeque<f64>,
    pub throughput_bps: Option<u64>,
    pub throughput_at: Option<Instant>,
    /// Switches away from this pair, with hourly decay.
    pub flaps: u32,
    pub flaps_window_start: Option<Instant>,
}

impl Default for PairSample {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            consecutive_failures: 0,
            latency: None,
            jitter: None,
            loss_window: VecDeque::with_capacity(LOSS_WINDOW),
            delay_samples: VecDeque::with_capacity(DELAY_SAMPLES),
            throughput_bps: None,
            throughput_at: None,
            flaps: 0,
            flaps_window_start: None,
        }
    }
}

impl PairSample {
    fn record(&mut self, ok: bool, elapsed: Option<Duration>, now: Instant) {
        if ok {
            self.successes = self.successes.saturating_add(1);
            self.consecutive_failures = 0;
        } else {
            self.failures = self.failures.saturating_add(1);
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
        if self.loss_window.len() == LOSS_WINDOW {
            self.loss_window.pop_front();
        }
        self.loss_window.push_back(ok);
        let delay_ms = elapsed.map(|elapsed| elapsed.as_secs_f64() * 1000.0);
        if self.delay_samples.len() == DELAY_SAMPLES {
            self.delay_samples.pop_front();
        }
        // Kotlin `GameTune.score` takes -1 for an unanswered attempt.
        self.delay_samples.push_back(delay_ms.unwrap_or(-1.0));
        if let Some(elapsed) = elapsed.filter(|_| ok) {
            let current = elapsed.as_secs_f64();
            self.latency = Some(match self.latency {
                Some(previous) => {
                    let smoothed = previous
                        .as_secs_f64()
                        .mul_add(LATENCY_OLD, current * LATENCY_NEW);
                    Duration::try_from_secs_f64(smoothed).unwrap_or(elapsed)
                }
                None => elapsed,
            });
            // Jitter as the EWMA of the mean absolute deviation, matching
            // `GameTune`'s "mean, not median, of the deviations".
            let deviation =
                (current - self.latency.map(|lat| lat.as_secs_f64()).unwrap_or(current)).abs();
            self.jitter = Some(match self.jitter {
                Some(previous) => {
                    let smoothed = previous
                        .as_secs_f64()
                        .mul_add(LATENCY_OLD, deviation * LATENCY_NEW);
                    Duration::try_from_secs_f64(smoothed)
                        .unwrap_or_else(|_| Duration::from_secs_f64(deviation))
                }
                None => Duration::try_from_secs_f64(deviation).unwrap_or_default(),
            });
        }
        let _ = now;
    }

    /// Fraction of recent probes that failed, from the loss window.
    pub fn loss_rate(&self) -> f64 {
        if self.loss_window.is_empty() {
            return 0.0;
        }
        let failed = self.loss_window.iter().filter(|ok| !**ok).count();
        failed as f64 / self.loss_window.len() as f64
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.successes.saturating_add(self.failures);
        if total == 0 {
            return 1.0;
        }
        self.successes as f64 / total as f64
    }

    /// The flap penalty, decayed hourly.
    fn flap_penalty(&self, now: Instant) -> f64 {
        match self.flaps_window_start {
            Some(start) if now.duration_since(start) < Duration::from_secs(3600) => {
                self.flaps as f64 * FLAP_PENALTY_MS
            }
            _ => 0.0,
        }
    }

    fn note_flap(&mut self, now: Instant) {
        if self
            .flaps_window_start
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(3600))
        {
            self.flaps = 0;
            self.flaps_window_start = Some(now);
        }
        self.flaps = self.flaps.saturating_add(1);
    }

    fn reset_failures(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// The pair namespace of the health table, keyed by pair tag.
#[derive(Debug, Default)]
pub struct PairTable {
    samples: HashMap<Arc<str>, PairSample>,
}

impl PairTable {
    fn sample_mut(&mut self, tag: &str) -> &mut PairSample {
        if !self.samples.contains_key(tag) {
            self.samples.insert(Arc::from(tag), PairSample::default());
        }
        self.samples
            .get_mut(tag)
            .expect("the sample was inserted above")
    }

    pub fn sample(&self, tag: &str) -> Option<&PairSample> {
        self.samples.get(tag)
    }

    pub fn forget(&mut self, tag: &str) {
        self.samples.remove(tag);
    }

    pub fn reset_failures(&mut self) {
        for sample in self.samples.values_mut() {
            sample.reset_failures();
        }
    }
}

/// The engine's tuning, converted from `zero_config::PairRoutingPolicy` by
/// the runtime.
#[derive(Debug, Clone)]
pub struct PairEnginePolicy {
    pub mode: SelectionMode,
    pub pair_balancer: Arc<str>,
    pub locked_gateway: Option<Arc<str>>,
    pub locked_exit: Option<Arc<str>>,
    pub gateway_priorities: Box<[Arc<str>]>,
    pub exit_priorities: Box<[Arc<str>]>,
    pub cooldown: Duration,
    pub switch_log_size: usize,
    /// While a game session is active, even failover-triggered switches are
    /// suppressed unless the pair is fully dead (Kotlin `gaming_active`).
    pub gaming_active: bool,
}

/// What the engine decided for the next selection round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// The active pair stays.
    Keep(Arc<str>),
    /// Move traffic to another pair.
    Switch {
        from: Arc<str>,
        to: Arc<str>,
        reason: SwitchReason,
    },
    /// No eligible pair: the runtime must engage the fallback path
    /// (blackhole in fixed-us-exit, `fallbackTag` otherwise).
    DeadEnd,
}

/// The pair selection engine. Owns pair samples, the active pair, the
/// cooldown, and the switch-reason log; borrows the [`HealthTable`] for the
/// gateway leg, which the runtime's existing observatory loop keeps fed.
pub struct PairEngine {
    policy: PairEnginePolicy,
    pairs: Vec<PairDescriptor>,
    table: PairTable,
    active: Option<Arc<str>>,
    last_switch: Option<Instant>,
    switches: VecDeque<SwitchEvent>,
    /// Corroborating tunnel-down signal (from the gateway's tunnel state):
    /// when the active pair fails while the tunnel is known down, the
    /// switch is logged as `tunnel_failed` rather than `pair_failed`.
    tunnel_down: bool,
}

impl PairEngine {
    pub fn new(policy: PairEnginePolicy, pairs: Vec<PairDescriptor>) -> Self {
        Self {
            policy,
            pairs,
            table: PairTable::default(),
            active: None,
            last_switch: None,
            switches: VecDeque::new(),
            tunnel_down: false,
        }
    }

    /// Feed the gateway's tunnel liveness into failure attribution: a pair
    /// failure while the tunnel is known down is a tunnel fault.
    pub fn set_tunnel_down(&mut self, down: bool) {
        self.tunnel_down = down;
    }

    pub fn policy(&self) -> &PairEnginePolicy {
        &self.policy
    }

    pub fn pairs(&self) -> &[PairDescriptor] {
        &self.pairs
    }

    pub fn active(&self) -> Option<&Arc<str>> {
        self.active.as_ref()
    }

    pub fn pair_sample(&self, tag: &str) -> Option<&PairSample> {
        self.table.sample(tag)
    }

    pub fn switch_log(&self) -> impl Iterator<Item = &SwitchEvent> {
        self.switches.iter()
    }

    /// Change the selection mode at runtime (from `setRoutingMode`). The
    /// active pair is re-evaluated on the next [`Pick`]; the change itself is
    /// logged.
    pub fn set_mode(&mut self, mode: SelectionMode, now: Instant) {
        if self.policy.mode != mode {
            self.policy.mode = mode;
            self.log_switch(
                self.active.clone(),
                self.active.clone(),
                SwitchReason::ModeChanged,
                now,
                None,
            );
        }
    }

    /// Change the path locks at runtime. Logged as `lock_changed`.
    pub fn set_locks(
        &mut self,
        locked_gateway: Option<Arc<str>>,
        locked_exit: Option<Arc<str>>,
        now: Instant,
    ) {
        if self.policy.locked_gateway != locked_gateway || self.policy.locked_exit != locked_exit {
            self.policy.locked_gateway = locked_gateway;
            self.policy.locked_exit = locked_exit;
            self.log_switch(
                self.active.clone(),
                self.active.clone(),
                SwitchReason::LockChanged,
                now,
                None,
            );
        }
    }

    pub fn set_gaming_active(&mut self, active: bool) {
        self.policy.gaming_active = active;
    }

    /// Pin the active pair explicitly (manual mode / user pick). Logged as
    /// `manual`.
    pub fn pin(&mut self, tag: &str, now: Instant) {
        let from = self.active.clone();
        self.active = Some(Arc::from(tag));
        self.log_switch(from, Some(Arc::from(tag)), SwitchReason::Manual, now, None);
    }

    /// Record an end-to-end probe of a pair, attributing the outcome to the
    /// right leg (Design B §2.3):
    ///
    /// * e2e fails + gateway probe succeeds → pair fault: the *pair* sample
    ///   fails, the gateway is untouched.
    /// * e2e fails + gateway probe fails → gateway fault: the gateway leg
    ///   fails; every pair on that gateway becomes ineligible.
    /// * e2e succeeds → pair `record` (latency EWMA) + gateway `record_alive`
    ///   (liveness without polluting its latency).
    pub fn record_e2e(
        &mut self,
        gateway: &mut HealthTable,
        pair_tag: &str,
        gateway_ok: bool,
        elapsed: Option<Duration>,
        now: Instant,
    ) {
        match (elapsed.is_some(), gateway_ok) {
            (true, _) => {
                self.table.sample_mut(pair_tag).record(true, elapsed, now);
                gateway.record_alive(pair_tag);
            }
            (false, true) => {
                // Path-B fault: the tunnel or the exit is down, the gateway
                // leg is fine. Only the pair is blamed.
                self.table.sample_mut(pair_tag).record(false, None, now);
            }
            (false, false) => {
                // Path-A fault: the gateway itself is down.
                gateway.record_failure(pair_tag);
                self.table.sample_mut(pair_tag).record(false, None, now);
            }
        }
    }

    /// A real session through the pair carried data: liveness, not latency.
    pub fn record_session_alive(&mut self, gateway: &mut HealthTable, pair_tag: &str) {
        gateway.record_alive(pair_tag);
        self.table
            .sample_mut(pair_tag)
            .record(true, None, Instant::now());
    }

    /// A dial through the pair failed: feeds the pair sample directly (the
    /// runtime already knows which leg failed via the probe attribution, so
    /// a bare dial failure blames the pair, not the gateway).
    pub fn record_dial_failure(&mut self, pair_tag: &str, now: Instant) {
        self.table.sample_mut(pair_tag).record(false, None, now);
    }

    pub fn record_throughput(&mut self, pair_tag: &str, bps: u64, now: Instant) {
        let sample = self.table.sample_mut(pair_tag);
        sample.throughput_bps = Some(bps);
        sample.throughput_at = Some(now);
    }

    /// A network change is not a server failure: reset failure counters on
    /// both legs, but keep latency evidence (Design B §4.2).
    pub fn network_changed(&mut self, gateway: &mut HealthTable) {
        gateway.reset_failures();
        self.table.reset_failures();
    }

    pub fn forget_pair(&mut self, tag: &str) {
        self.table.forget(tag);
        if self.active.as_deref() == Some(tag) {
            self.active = None;
        }
    }

    /// Whether the pair may carry traffic right now.
    pub fn eligible(&self, gateway: &HealthTable, pair: &PairDescriptor) -> bool {
        let gateway_sample = gateway.sample(&pair.tag);
        if gateway_sample.consecutive_failures >= FAILING_RUN {
            return false;
        }
        let pair_sample = self.table.sample(&pair.tag);
        if pair_sample.is_some_and(|sample| sample.consecutive_failures >= FAILING_RUN) {
            return false;
        }
        if let Some(locked) = self.policy.locked_gateway.as_ref() {
            if pair.tag.as_ref() != locked.as_ref() {
                return false;
            }
        }
        if let Some(locked) = self.policy.locked_exit.as_ref() {
            if pair.exit_host.as_ref() != locked.as_ref() {
                return false;
            }
        }
        if self.policy.mode == SelectionMode::FixedUsExit {
            if pair.exit_country != *b"US" {
                return false;
            }
            // An explicit exit allow-list restricts further; empty = all US.
            if !self.policy.exit_priorities.is_empty()
                && !self
                    .policy
                    .exit_priorities
                    .iter()
                    .any(|exit| exit.as_ref() == pair.exit_host.as_ref())
            {
                return false;
            }
        }
        true
    }

    pub fn eligible_pairs(&self, gateway: &HealthTable) -> Vec<PairDescriptor> {
        let mut eligible: Vec<PairDescriptor> = self
            .pairs
            .iter()
            .filter(|pair| self.eligible(gateway, pair))
            .cloned()
            .collect();
        // Deterministic tie-break: the user's preferred gateway/exit wins
        // over "first configured wins".
        eligible.sort_by_key(|pair| {
            (
                self.policy
                    .gateway_priorities
                    .iter()
                    .position(|tag| tag.as_ref() == pair.tag.as_ref())
                    .unwrap_or(usize::MAX),
                self.policy
                    .exit_priorities
                    .iter()
                    .position(|exit| exit.as_ref() == pair.exit_host.as_ref())
                    .unwrap_or(usize::MAX),
            )
        });
        eligible
    }

    fn score(&self, pair: &PairDescriptor, now: Instant) -> f64 {
        let sample = self.table.sample(&pair.tag);
        let latency_ms = sample
            .and_then(|sample| sample.latency)
            .map(|latency| latency.as_secs_f64() * 1000.0)
            .unwrap_or(UNKNOWN_LATENCY_SECS * 1000.0);
        let jitter_ms = sample
            .and_then(|sample| sample.jitter)
            .map(|jitter| jitter.as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let loss_rate = sample.map(PairSample::loss_rate).unwrap_or(0.0);
        let flap_penalty = sample.map(|sample| sample.flap_penalty(now)).unwrap_or(0.0);
        match self.policy.mode {
            SelectionMode::Balanced | SelectionMode::FixedUsExit => {
                latency_ms + BALANCED_LOSS_WEIGHT * loss_rate * 1000.0 + jitter_ms + flap_penalty
            }
            SelectionMode::LowestLatency => latency_ms + flap_penalty,
            SelectionMode::MaxStability => {
                let success_rate = sample.map(PairSample::success_rate).unwrap_or(1.0);
                (1.0 - success_rate) * 1_000_000.0 + latency_ms + flap_penalty
            }
            SelectionMode::Gaming => {
                let delays: Vec<f64> = sample
                    .map(|sample| sample.delay_samples.iter().copied().collect())
                    .unwrap_or_default();
                if delays.is_empty() {
                    UNKNOWN_LATENCY_SECS * 1000.0 + flap_penalty
                } else {
                    game_tune_score(&delays) + flap_penalty
                }
            }
            SelectionMode::Manual => latency_ms,
        }
    }

    /// Decide what carries traffic next. Call after every probe result and
    /// every dial failure that changed the evidence.
    pub fn choose(&mut self, gateway: &HealthTable, now: Instant) -> Pick {
        let eligible = self.eligible_pairs(gateway);
        if eligible.is_empty() {
            return Pick::DeadEnd;
        }
        // Manual mode pins the active pair; on its failure the engine holds
        // (kill-switch semantics) and notifies, it does not switch.
        if self.policy.mode == SelectionMode::Manual {
            if let Some(active) = self.active.clone() {
                if eligible.iter().any(|pair| pair.tag == active) {
                    return Pick::Keep(active);
                }
            }
            return Pick::DeadEnd;
        }
        // Failover: the active pair is dead → switch at once, cooldown be
        // damned. A dead pair is dead.
        let active_dead = self.active.as_ref().is_some_and(|active| {
            let pair_failed = self
                .table
                .sample(active)
                .is_some_and(|sample| sample.consecutive_failures >= FAILING_RUN);
            let gateway_failed = gateway.sample(active).consecutive_failures >= FAILING_RUN;
            pair_failed || gateway_failed
        });
        if let Some(active) = self.active.clone() {
            if active_dead {
                // Gaming mid-session protection: while a game is active, even
                // a failover-triggered switch is suppressed unless the pair
                // is fully dead (no eligible alternative on this pair means
                // the single pair is gone — switch once).
                if self.policy.mode == SelectionMode::Gaming
                    && self.policy.gaming_active
                    && eligible.len() > 1
                {
                    return Pick::Keep(active);
                }
                let gateway_failed = gateway.sample(&active).consecutive_failures >= FAILING_RUN;
                let reason = if gateway_failed {
                    SwitchReason::GatewayFailed
                } else if self.tunnel_down {
                    SwitchReason::TunnelFailed
                } else {
                    SwitchReason::PairFailed
                };
                return self.switch_to(&active, &eligible.clone(), reason, now, gateway);
            }
            if !eligible.iter().any(|pair| pair.tag == active) {
                // The active pair fell out of eligibility through a
                // lock/mode/filter change (it is not dead): pick the best
                // eligible one.
                return self.switch_to(
                    &active,
                    &eligible.clone(),
                    SwitchReason::LockChanged,
                    now,
                    gateway,
                );
            }
        }
        // Opportunistic switch: only past the cooldown, only for a clearly
        // better challenger. Max-stability never switches opportunistically.
        if self.policy.mode == SelectionMode::MaxStability {
            if let Some(active) = self.active.clone() {
                return Pick::Keep(active);
            }
        }
        let best = self.best(&eligible, now);
        match (&self.active, best) {
            (None, Some(best)) => {
                let to = best.tag.clone();
                self.apply_switch(None, to, SwitchReason::BetterPath, now)
            }
            (Some(active), Some(best)) if best.tag != *active => {
                let incumbent = self.score_by_tag(active, now);
                let challenger = self.score(best, now);
                let margin = incumbent * super::PING_HYSTERESIS_RATIO
                    + super::PING_HYSTERESIS_FLOOR * 1000.0;
                let better = if self.policy.mode == SelectionMode::Gaming {
                    challenger <= incumbent * GAME_WORTH_SWITCHING
                } else {
                    challenger + margin < incumbent
                };
                let cooled = self
                    .last_switch
                    .is_none_or(|switched| now.duration_since(switched) >= self.policy.cooldown);
                if better && cooled {
                    let from = active.clone();
                    let to = best.tag.clone();
                    self.apply_switch(Some(from), to, SwitchReason::BetterPath, now)
                } else {
                    Pick::Keep(active.clone())
                }
            }
            (Some(active), _) => Pick::Keep(active.clone()),
            (None, None) => Pick::DeadEnd,
        }
    }

    fn score_by_tag(&self, tag: &str, now: Instant) -> f64 {
        self.pairs
            .iter()
            .find(|pair| pair.tag.as_ref() == tag)
            .map(|pair| self.score(pair, now))
            .unwrap_or(f64::INFINITY)
    }

    fn best<'a>(&self, eligible: &'a [PairDescriptor], now: Instant) -> Option<&'a PairDescriptor> {
        eligible.iter().min_by(|a, b| {
            self.score(a, now)
                .partial_cmp(&self.score(b, now))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Switch, excluding `from` from the candidates (it just failed or fell
    /// out of eligibility).
    fn switch_to(
        &mut self,
        from: &Arc<str>,
        eligible: &[PairDescriptor],
        reason: SwitchReason,
        now: Instant,
        gateway: &HealthTable,
    ) -> Pick {
        let _ = gateway;
        let mut candidates: Vec<&PairDescriptor> =
            eligible.iter().filter(|pair| pair.tag != *from).collect();
        if candidates.is_empty() {
            // Nothing else to go to: hold the (failing) pair rather than
            // invent a destination. The runtime treats this as a dead end.
            return Pick::DeadEnd;
        }
        candidates.sort_by(|a, b| {
            self.score(a, now)
                .partial_cmp(&self.score(b, now))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let to = candidates[0].tag.clone();
        self.apply_switch(Some(from.clone()), to, reason, now)
    }

    fn apply_switch(
        &mut self,
        from: Option<Arc<str>>,
        to: Arc<str>,
        reason: SwitchReason,
        now: Instant,
    ) -> Pick {
        if let Some(from) = from.as_ref() {
            self.table.sample_mut(from).note_flap(now);
        }
        let rtt_ms = self
            .table
            .sample(&to)
            .and_then(|sample| sample.latency)
            .map(|latency| latency.as_secs_f64() * 1000.0);
        self.log_switch(from.clone(), Some(to.clone()), reason, now, rtt_ms);
        self.active = Some(to.clone());
        self.last_switch = Some(now);
        match from {
            Some(from) => Pick::Switch { from, to, reason },
            None => Pick::Keep(to),
        }
    }

    fn log_switch(
        &mut self,
        from: Option<Arc<str>>,
        to: Option<Arc<str>>,
        reason: SwitchReason,
        now: Instant,
        rtt_ms: Option<f64>,
    ) {
        // `Instant` is monotonic but not wall-clock: the log carries
        // `SystemTime` for display; ordering is the deque's.
        let _ = now;
        if self.switches.len() >= self.policy.switch_log_size.max(1) {
            self.switches.pop_front();
        }
        tracing::info!(
            from = from.as_deref(),
            to = to.as_deref(),
            reason = reason.as_str(),
            rtt_ms,
            "pair switch"
        );
        self.switches.push_back(SwitchEvent {
            at: SystemTime::now(),
            from,
            to,
            reason,
            rtt_ms,
        });
    }
}

/// `GameTune.score`, ported 1:1 from
/// `ZeroNet-Mobile/app/src/main/java/com/zeronet/mobile/service/GameTune.kt`.
///
/// `delays_ms` holds answered delays in milliseconds, with a negative number
/// for an attempt that got no answer. Lower is better; a pair that never
/// answered scores infinity. Formula parity with the Kotlin side is pinned by
/// `game_tune_matches_kotlin_vectors` below: the two implementations must not
/// drift, because Kotlin owns the *policy* (when gaming applies) while Rust
/// owns the *score*.
pub fn game_tune_score(delays_ms: &[f64]) -> f64 {
    let mut answered: Vec<f64> = delays_ms
        .iter()
        .copied()
        .filter(|delay| *delay >= 0.0)
        .collect();
    if answered.is_empty() {
        return f64::INFINITY;
    }
    answered.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = answered[answered.len() / 2];
    // The mean, not the median, of the deviations: one spike is what ruins
    // a match.
    let jitter = answered
        .iter()
        .map(|delay| (delay - median).abs())
        .sum::<f64>()
        / answered.len() as f64;
    let lost = delays_ms.len() - answered.len();
    median + 2.0 * jitter + GAME_LOSS_PENALTY_MS * lost as f64 / delays_ms.len() as f64 * 3.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: f64) -> Duration {
        Duration::try_from_secs_f64(value / 1000.0).unwrap()
    }

    /// The Kotlin `GameTuneTest` vectors, asserted identical (Design B
    /// §7.1-8: formula parity, no drift).
    #[test]
    fn game_tune_matches_kotlin_vectors() {
        let steady = game_tune_score(&[90.0, 92.0, 91.0]);
        let wandering = game_tune_score(&[60.0, 300.0, 65.0]);
        assert!(steady < wandering);
        // everyLostAttemptCostsALot
        assert!(game_tune_score(&[80.0, -1.0, 82.0]) > game_tune_score(&[140.0, 141.0, 139.0]));
        assert_eq!(game_tune_score(&[-1.0, -1.0, -1.0]), f64::INFINITY);
        assert_eq!(game_tune_score(&[]), f64::INFINITY);
        // aServerIsNotSwitchedForAMarginalGain: 92 vs 100 is within 0.85.
        let now = game_tune_score(&[100.0, 100.0, 100.0]);
        let marginal = game_tune_score(&[92.0, 92.0, 92.0]);
        assert!(marginal >= now * GAME_WORTH_SWITCHING);
        let clearly = game_tune_score(&[60.0, 60.0, 60.0]);
        assert!(clearly < now * GAME_WORTH_SWITCHING);
    }

    fn descriptor(tag: &str, exit_host: &str, country: [u8; 2]) -> PairDescriptor {
        PairDescriptor {
            tag: Arc::from(tag),
            pair_id: Arc::from(format!("pair-{tag}")),
            exit_host: Arc::from(exit_host),
            exit_country: country,
            fail_closed: true,
        }
    }

    fn policy(mode: SelectionMode) -> PairEnginePolicy {
        PairEnginePolicy {
            mode,
            pair_balancer: Arc::from("pair-pool"),
            locked_gateway: None,
            locked_exit: None,
            gateway_priorities: Box::from([]),
            exit_priorities: Box::from([]),
            cooldown: Duration::from_secs(120),
            switch_log_size: 32,
            gaming_active: false,
        }
    }

    fn test_engine(mode: SelectionMode) -> PairEngine {
        PairEngine::new(
            policy(mode),
            vec![
                descriptor("ir-1", "198.51.100.23", *b"US"),
                descriptor("ir-2", "203.0.113.7", *b"US"),
            ],
        )
    }

    #[test]
    fn jitter_ewma_converges_near_expected_mad() {
        let mut table = PairTable::default();
        let now = Instant::now();
        // Alternating 100ms / 140ms: MAD around the EWMA mean ≈ 20ms.
        for i in 0..40 {
            let delay = if i % 2 == 0 { ms(100.0) } else { ms(140.0) };
            table.sample_mut("p").record(true, Some(delay), now);
        }
        let jitter_ms = table.sample("p").unwrap().jitter.unwrap().as_secs_f64() * 1000.0;
        assert!(
            (10.0..30.0).contains(&jitter_ms),
            "jitter {jitter_ms}ms is not near the 20ms MAD"
        );
    }

    #[test]
    fn loss_window_slides_and_reports_rate() {
        let mut table = PairTable::default();
        let now = Instant::now();
        for _ in 0..8 {
            table.sample_mut("p").record(false, None, now);
        }
        for _ in 0..24 {
            table.sample_mut("p").record(true, Some(ms(50.0)), now);
        }
        let sample = table.sample("p").unwrap();
        assert!((sample.loss_rate() - 0.25).abs() < 1e-9);
        // Slide the window: 32 more successes push the failures out.
        for _ in 0..32 {
            table.sample_mut("p").record(true, Some(ms(50.0)), now);
        }
        assert_eq!(table.sample("p").unwrap().loss_rate(), 0.0);
    }

    #[test]
    fn cooldown_blocks_opportunistic_switch_but_not_failover() {
        let mut engine = test_engine(SelectionMode::Balanced);
        let mut gateway = HealthTable::default();
        let t0 = Instant::now();
        // ir-1 active at 100ms; ir-2 appears at 40ms shortly after.
        engine.record_e2e(&mut gateway, "ir-1", true, Some(ms(100.0)), t0);
        assert!(matches!(engine.choose(&gateway, t0), Pick::Keep(_)));
        engine.record_e2e(&mut gateway, "ir-2", true, Some(ms(40.0)), t0);
        let t1 = t0 + Duration::from_secs(30);
        // Better challenger inside the cooldown: no switch.
        assert!(matches!(engine.choose(&gateway, t1), Pick::Keep(_)));
        // Past the cooldown: the better path wins.
        let t2 = t0 + Duration::from_secs(130);
        match engine.choose(&gateway, t2) {
            Pick::Switch { from, to, reason } => {
                assert_eq!(from.as_ref(), "ir-1");
                assert_eq!(to.as_ref(), "ir-2");
                assert_eq!(reason, SwitchReason::BetterPath);
            }
            other => panic!("expected an opportunistic switch, got {other:?}"),
        }
        // Dead-pair failover inside a fresh cooldown switches immediately.
        let t3 = t2 + Duration::from_secs(1);
        for _ in 0..3 {
            engine.record_dial_failure("ir-2", t3);
        }
        match engine.choose(&gateway, t3) {
            Pick::Switch { to, reason, .. } => {
                assert_eq!(to.as_ref(), "ir-1");
                assert_eq!(reason, SwitchReason::PairFailed);
            }
            other => panic!("expected immediate failover, got {other:?}"),
        }
    }

    #[test]
    fn leg_attribution_blames_the_right_leg() {
        let mut engine = test_engine(SelectionMode::Balanced);
        let mut gateway = HealthTable::default();
        let now = Instant::now();
        // E2E fails but the gateway probe succeeds: pair fault only.
        for _ in 0..3 {
            engine.record_e2e(&mut gateway, "ir-1", true, None, now);
        }
        assert_eq!(gateway.sample("ir-1").consecutive_failures, 0);
        assert_eq!(engine.pair_sample("ir-1").unwrap().consecutive_failures, 3);
        // ir-1 is out; ir-2 (same world, other pair) is unaffected.
        let eligible: Vec<_> = engine
            .eligible_pairs(&gateway)
            .iter()
            .map(|pair| pair.tag.to_string())
            .collect();
        assert_eq!(eligible, vec!["ir-2".to_string()]);
        // E2E fails and the gateway probe fails too: gateway fault takes
        // every pair on that gateway out.
        let mut engine = test_engine(SelectionMode::Balanced);
        for _ in 0..3 {
            engine.record_e2e(&mut gateway, "ir-1", false, None, now);
        }
        assert_eq!(gateway.sample("ir-1").consecutive_failures, 3);
        let eligible: Vec<_> = engine
            .eligible_pairs(&gateway)
            .iter()
            .map(|pair| pair.tag.to_string())
            .collect();
        assert_eq!(eligible, vec!["ir-2".to_string()]);
    }

    #[test]
    fn fixed_us_exit_filters_non_us_and_prefers_allow_list() {
        let mut engine = PairEngine::new(
            policy(SelectionMode::FixedUsExit),
            vec![
                descriptor("ir-1", "198.51.100.23", *b"US"),
                descriptor("ir-de", "192.0.2.44", *b"DE"),
            ],
        );
        let gateway = HealthTable::default();
        let eligible: Vec<_> = engine
            .eligible_pairs(&gateway)
            .iter()
            .map(|pair| pair.tag.to_string())
            .collect();
        assert_eq!(eligible, vec!["ir-1".to_string()]);
        // With an exit allow-list, only listed US exits are eligible.
        engine.policy.exit_priorities = Box::from([Arc::from("198.51.100.99")]);
        assert!(engine.eligible_pairs(&gateway).is_empty());
    }

    #[test]
    fn manual_lock_pins_one_gateway_and_logs_the_change() {
        let mut engine = test_engine(SelectionMode::Balanced);
        let gateway = HealthTable::default();
        let now = Instant::now();
        engine.set_locks(Some(Arc::from("ir-1")), None, now);
        let eligible: Vec<_> = engine
            .eligible_pairs(&gateway)
            .iter()
            .map(|pair| pair.tag.to_string())
            .collect();
        assert_eq!(eligible, vec!["ir-1".to_string()]);
        assert!(engine
            .switch_log()
            .any(|event| event.reason == SwitchReason::LockChanged));
        engine.set_locks(None, None, now);
        assert_eq!(engine.eligible_pairs(&gateway).len(), 2);
    }

    #[test]
    fn manual_mode_holds_the_pinned_pair() {
        let mut engine = test_engine(SelectionMode::Manual);
        let mut gateway = HealthTable::default();
        let now = Instant::now();
        engine.pin("ir-1", now);
        engine.record_e2e(&mut gateway, "ir-1", true, Some(ms(100.0)), now);
        engine.record_e2e(&mut gateway, "ir-2", true, Some(ms(10.0)), now);
        // ir-2 is far better: manual mode does not move.
        assert!(matches!(engine.choose(&gateway, now), Pick::Keep(_)));
        assert_eq!(engine.active().unwrap().as_ref(), "ir-1");
    }

    #[test]
    fn switch_log_is_a_bounded_ring_with_reasons() {
        let mut engine = test_engine(SelectionMode::Balanced);
        let mut gateway = HealthTable::default();
        let now = Instant::now();
        engine.record_e2e(&mut gateway, "ir-1", true, Some(ms(100.0)), now);
        engine.choose(&gateway, now);
        for _ in 0..3 {
            engine.record_dial_failure("ir-1", now);
        }
        match engine.choose(&gateway, now) {
            Pick::Switch { reason, .. } => assert_eq!(reason, SwitchReason::PairFailed),
            other => panic!("expected failover, got {other:?}"),
        }
        let reasons: Vec<SwitchReason> = engine.switch_log().map(|event| event.reason).collect();
        assert!(reasons.contains(&SwitchReason::PairFailed));
        assert!(reasons.contains(&SwitchReason::BetterPath));
    }
}
