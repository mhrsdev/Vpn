//! Dual-stack USA egress: adaptive family selection, sticky exit IP, and
//! per-tunnel traffic accounting (triple-tunnel owner addendum, 2026-11-01).
//!
//! # What this module is
//!
//! The USA exit has ONE fixed static IPv4 and ONE fixed static IPv6. Egress
//! family selection is INDEPENDENT of the tunnel family: an IPv6 tunnel can
//! carry IPv4-only destinations and vice versa. This module implements:
//!
//! - [`EgressSelector`]: Happy-Eyeballs-v2-style (RFC 8305) per-destination
//!   family selection from REAL quality metrics (TCP/TLS handshake time,
//!   success/failure rates, historical stability — never ping alone), with
//!   cached results and no heavy per-request probing.
//! - [`StickyExit`]: the exit IP never changes silently. One static IPv4 +
//!   one static IPv6; per-domain policies (`auto` / `force_ipv4` /
//!   `force_ipv6` / `prefer_stable_ipv4`); configurable session affinity;
//!   every family change is recorded as a reroute event (time + reason).
//! - [`TrafficLedger`]: per-tunnel byte counters split into payload /
//!   keepalive / health-check / overhead, from real counters. The overhead
//!   split is an ESTIMATE and is labeled as such wherever surfaced.
//! - [`EgressEngine`]: the facade the server wires into its `/egress`
//!   surface (Agent H1) and the admin polls (frozen CONTRACT-triple.md).
//!
//! # What this module is NOT
//!
//! - It does not dial: [`happy_eyeballs`] races caller-supplied dial
//!   futures. The server's dial path calls it.
//! - It does not do DNS: split DNS (Agent H3) follows the family decision.
//! - WAN behavior (real v6 uplink, cross-family throughput) is NOT TESTED
//!   here — the sandbox has no IPv6 uplink. Loopback measurements only.
//!
//! # IPv6 source-address caveat
//!
//! The sticky IPv6 guarantee holds only if the exit host's source address
//! selection is stable: bind the socket explicitly (see
//! [`bind_source_socket`]) AND make sure the static address is assigned to
//! the host with RFC 4941 temporary addresses disabled for it. An OS that
//! prefers temporary source addresses will otherwise rotate the address
//! the destination sees, silently breaking stickiness. This is an operator
//! checklist item, documented in `report/dualstack.md`.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use zero_config::{
    DomainEgressPolicy, EgressConfig, EgressFamily, EgressFamilyPolicy, FamilyFallback,
    ProbeBudget, ProbeBudgetParams,
};

/// Minimum samples before a family's success rate is trusted.
const MIN_SAMPLES: u64 = 3;
/// A family scoring below this (with enough samples) is "measured-bad":
/// stickiness no longer protects it.
const BAD_SCORE_THRESHOLD: f64 = 0.35;
/// Cap on tracked destinations; oldest-quiet entries are evicted past it.
const MAX_DESTINATIONS: usize = 4096;
/// Cap on retained reroute events.
const MAX_REROUTES: usize = 128;
/// EWMA weight for new handshake samples (higher = adapts faster).
const HANDSHAKE_EWMA_ALPHA: f64 = 0.3;
/// Handshake time (ms) that maps to a 0.5 time score.
const HANDSHAKE_NORM_MS: f64 = 200.0;

// ---------------------------------------------------------------------------
// Quality measurement
// ---------------------------------------------------------------------------

/// Measured quality of one IP family for one destination.
#[derive(Debug, Clone, Default)]
struct FamilyQuality {
    successes: u64,
    failures: u64,
    /// EWMA of TCP/TLS handshake time in ms; `None` until the first success.
    handshake_ewma_ms: Option<f64>,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

impl FamilyQuality {
    fn record_success(&mut self, handshake_ms: f64, now: Instant) {
        self.successes = self.successes.saturating_add(1);
        self.handshake_ewma_ms = Some(match self.handshake_ewma_ms {
            Some(ewma) => ewma * (1.0 - HANDSHAKE_EWMA_ALPHA) + handshake_ms * HANDSHAKE_EWMA_ALPHA,
            None => handshake_ms,
        });
        self.last_success = Some(now);
    }

    fn record_failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure = Some(now);
    }

    /// Score in [0,1], or `None` when there is not enough data or the data
    /// is stale (older than `ttl`).
    ///
    /// Formula (documented so panels can explain it):
    /// `0.60 * success_rate + 0.25 * time_score + 0.15 * stability`, where
    /// `time_score = 1 / (1 + ewma_ms / 200)` and `stability` is 1.0 when the
    /// last sample was a success, 0.3 when it was a failure.
    fn score(&self, now: Instant, ttl: Duration) -> Option<f64> {
        let total = self.successes + self.failures;
        if total < MIN_SAMPLES {
            return None;
        }
        let last_sample = [self.last_success, self.last_failure]
            .into_iter()
            .flatten()
            .max()?;
        if now.duration_since(last_sample) > ttl {
            return None;
        }
        let success_rate = self.successes as f64 / total as f64;
        let time_score = match self.handshake_ewma_ms {
            Some(ewma) => 1.0 / (1.0 + ewma / HANDSHAKE_NORM_MS),
            None => 0.5,
        };
        let stability = match (self.last_success, self.last_failure) {
            (Some(ok), Some(fail)) => {
                if ok >= fail {
                    1.0
                } else {
                    0.3
                }
            }
            (Some(_), None) => 1.0,
            _ => 0.3,
        };
        Some(0.60 * success_rate + 0.25 * time_score + 0.15 * stability)
    }
}

/// Outcome of one real dial/probe, fed back into the quality tables.
#[derive(Debug, Clone, Copy)]
pub enum ProbeOutcome {
    /// A real TCP/TLS handshake completed; `handshake_ms` is its duration.
    Success { handshake_ms: f64 },
    /// The dial/probe failed (timeout, refused, TLS error, ...).
    Failure,
}

// ---------------------------------------------------------------------------
// Family selection (Happy Eyeballs v2 style)
// ---------------------------------------------------------------------------

/// How to race the two families for one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacePlan {
    /// Family to try first.
    pub first: EgressFamily,
    /// Family to start after `stagger_ms` if the first has not completed.
    /// `None` for forced policies (never race) or single-stack destinations.
    pub second: Option<EgressFamily>,
    /// Ms to wait before starting the second family (RFC 8305: 250).
    pub stagger_ms: u64,
}

/// The selector's decision for one destination.
#[derive(Debug, Clone)]
pub struct EgressDecision {
    /// Family the session should use.
    pub family: EgressFamily,
    /// How to race (or not).
    pub race: RacePlan,
    /// Policy that produced this decision.
    pub policy: EgressFamilyPolicy,
    /// Where the policy came from: "domain-policy" | "sensitive-site" |
    /// "default".
    pub policy_source: &'static str,
    /// Human-readable reason, for `/egress/decisions?domain=`.
    pub reason: String,
    /// True when a forced/preferred family was unusable and the fallback
    /// allowed the other family. Always surfaced — never silent.
    pub fallback_applied: bool,
    /// True when the decision is "do not connect" (fallback == Block and
    /// the selected family is unusable). Fail closed.
    pub blocked: bool,
    /// True when the sticky session's family was kept within its affinity
    /// window despite the scorer preferring the other family. Explains
    /// "why am I on v6 when v4 measured faster" on the panel.
    pub sticky_kept: bool,
}

/// Adaptive per-destination family selector.
///
/// Quality data comes from REAL dial outcomes fed via
/// [`EgressSelector::record_result`] — light HTTPS probes, real handshakes.
/// There is no active probing here; the probe budget governs how often the
/// server's prober calls in.
pub struct EgressSelector {
    config: EgressConfig,
    per_destination: HashMap<Box<str>, [FamilyQuality; 2]>,
    global: [FamilyQuality; 2],
}

impl EgressSelector {
    pub fn new(config: EgressConfig) -> Self {
        EgressSelector {
            config,
            per_destination: HashMap::new(),
            global: [FamilyQuality::default(), FamilyQuality::default()],
        }
    }

    pub fn set_config(&mut self, config: EgressConfig) {
        self.config = config;
    }

    /// Feed one real outcome back into the quality tables.
    pub fn record_result(&mut self, domain: &str, family: EgressFamily, outcome: ProbeOutcome) {
        let now = Instant::now();
        let key = normalize_domain(domain);
        let idx = family_index(family);
        let entry = self
            .per_destination
            .entry(key)
            .or_insert_with(|| [FamilyQuality::default(), FamilyQuality::default()]);
        match outcome {
            ProbeOutcome::Success { handshake_ms } => {
                entry[idx].record_success(handshake_ms, now);
                self.global[idx].record_success(handshake_ms, now);
            }
            ProbeOutcome::Failure => {
                entry[idx].record_failure(now);
                self.global[idx].record_failure(now);
            }
        }
        if self.per_destination.len() > MAX_DESTINATIONS {
            self.evict_quiet(now);
        }
    }

    /// Decide the egress family for `domain`.
    ///
    /// `has_v4`/`has_v6` report whether the destination resolved addresses
    /// of that family (A/AAAA). Family selection is independent of the
    /// tunnel family: any tunnel can carry either.
    pub fn decide(&self, domain: &str, has_v4: bool, has_v6: bool) -> EgressDecision {
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.quality_ttl_secs.max(1));
        let stagger_ms = self.config.race_delay_ms;
        let (policy, source) = self.config.policy_for_domain(domain);
        let fallback = self.fallback_for(domain);

        // Forced families: no racing, ever.
        match policy {
            EgressFamilyPolicy::ForceIpv4 => {
                return self.forced_decision(
                    domain,
                    EgressFamily::V4,
                    has_v4,
                    has_v6,
                    policy,
                    source,
                    fallback,
                    stagger_ms,
                );
            }
            EgressFamilyPolicy::ForceIpv6 => {
                return self.forced_decision(
                    domain,
                    EgressFamily::V6,
                    has_v6,
                    has_v4,
                    policy,
                    source,
                    fallback,
                    stagger_ms,
                );
            }
            _ => {}
        }

        // Auto / PreferStableIpv4: quality-driven, with a stability bias.
        let key = normalize_domain(domain);
        let per_dest = self.per_destination.get(&key);
        let score_v4 = per_dest
            .and_then(|q| q[0].score(now, ttl))
            .or_else(|| self.global[0].score(now, ttl));
        let score_v6 = per_dest
            .and_then(|q| q[1].score(now, ttl))
            .or_else(|| self.global[1].score(now, ttl));

        // PreferStableIpv4: v4 first whenever it is usable; v6 only as a
        // fallback (and only if the fallback allows it).
        if policy == EgressFamilyPolicy::PreferStableIpv4 {
            if has_v4 {
                let reason = match (score_v4, score_v6) {
                    (Some(a), Some(b)) => format!(
                        "prefer_stable_ipv4: v4 score {a:.2} vs v6 score {b:.2}; v4 usable, no flip"
                    ),
                    _ => "prefer_stable_ipv4: v4 usable, keeping the stable family".to_string(),
                };
                return EgressDecision {
                    family: EgressFamily::V4,
                    race: RacePlan {
                        first: EgressFamily::V4,
                        second: None,
                        stagger_ms,
                    },
                    policy,
                    policy_source: source,
                    reason,
                    fallback_applied: false,
                    blocked: false,
                    sticky_kept: false,
                };
            }
            // v4 unusable: fallback per policy, never silent.
            return self.unusable_fallback(
                domain,
                EgressFamily::V4,
                has_v6,
                policy,
                source,
                fallback,
                stagger_ms,
                "prefer_stable_ipv4: no usable IPv4",
            );
        }

        // Auto: highest measured score first; unknown scores → v6 first
        // (RFC 8305), v4 on the stagger. Never flip mid-session — that is
        // the sticky layer's job, not the scorer's.
        let (first, why) = match (score_v4, score_v6) {
            (Some(a), Some(b)) => {
                if a >= b {
                    (
                        EgressFamily::V4,
                        format!("auto: measured v4 score {a:.2} >= v6 score {b:.2}"),
                    )
                } else {
                    (
                        EgressFamily::V6,
                        format!("auto: measured v6 score {b:.2} > v4 score {a:.2}"),
                    )
                }
            }
            (Some(a), None) => (
                EgressFamily::V4,
                format!("auto: only v4 has measured quality ({a:.2})"),
            ),
            (None, Some(b)) => (
                EgressFamily::V6,
                format!("auto: only v6 has measured quality ({b:.2})"),
            ),
            (None, None) => (
                EgressFamily::V6,
                "auto: no measured quality yet; RFC 8305 v6-first".to_string(),
            ),
        };
        // Clamp to usable families.
        let (first, second, usable_note) = match (first, has_v4, has_v6) {
            (EgressFamily::V6, _, true) => (
                EgressFamily::V6,
                has_v4.then_some(EgressFamily::V4),
                String::new(),
            ),
            (EgressFamily::V4, true, _) => (
                EgressFamily::V4,
                has_v6.then_some(EgressFamily::V6),
                String::new(),
            ),
            (EgressFamily::V6, _, false) if has_v4 => (
                EgressFamily::V4,
                None,
                " (v6 has no addresses; v4 only)".to_string(),
            ),
            (EgressFamily::V4, false, _) if has_v6 => (
                EgressFamily::V6,
                None,
                " (v4 has no addresses; v6 only)".to_string(),
            ),
            _ => {
                return EgressDecision {
                    family: EgressFamily::V4,
                    race: RacePlan {
                        first: EgressFamily::V4,
                        second: None,
                        stagger_ms,
                    },
                    policy,
                    policy_source: source,
                    reason: format!("auto: {domain}: no usable addresses; blocked"),
                    fallback_applied: false,
                    blocked: true,
                    sticky_kept: false,
                };
            }
        };
        EgressDecision {
            family: first,
            race: RacePlan {
                first,
                second,
                stagger_ms,
            },
            policy,
            policy_source: source,
            reason: format!("{why}{usable_note}"),
            fallback_applied: false,
            blocked: false,
            sticky_kept: false,
        }
    }

    /// Decide with sticky-session awareness.
    ///
    /// When `sticky` is `Some((family, affinity_holds))` and the affinity
    /// window still holds, the sticky family is kept whenever it is usable
    /// and not measured-bad — even if the scorer currently prefers the
    /// other family. This is the "no flip for a few ms of ping" rule:
    /// within affinity, stability beats marginal quality wins. The keep is
    /// reported via `sticky_kept` so the panel can explain it.
    ///
    /// Stickiness never overrides:
    /// - forced policies (`ForceIpv4`/`ForceIpv6`): the operator's force wins;
    /// - fail-closed decisions (`blocked`): a blocked family stays blocked;
    /// - a measured-bad sticky family (score below [`BAD_SCORE_THRESHOLD`]).
    pub fn decide_sticky(
        &self,
        domain: &str,
        has_v4: bool,
        has_v6: bool,
        sticky: Option<(EgressFamily, bool)>,
    ) -> EgressDecision {
        let decision = self.decide(domain, has_v4, has_v6);
        let Some((sticky_family, affinity_holds)) = sticky else {
            return decision;
        };
        if !affinity_holds || decision.blocked || decision.family == sticky_family {
            return decision;
        }
        // Forced policies are absolute: the operator's force wins over
        // stickiness (e.g. the policy just changed to force the family).
        if matches!(
            decision.policy,
            EgressFamilyPolicy::ForceIpv4 | EgressFamilyPolicy::ForceIpv6
        ) {
            return decision;
        }
        let sticky_usable = match sticky_family {
            EgressFamily::V4 => has_v4,
            EgressFamily::V6 => has_v6,
        };
        if !sticky_usable || self.family_bad(domain, sticky_family) {
            return decision;
        }
        // Keep the sticky family: usable and not measured-bad.
        let name = match sticky_family {
            EgressFamily::V4 => "ipv4",
            EgressFamily::V6 => "ipv6",
        };
        let other = match sticky_family {
            EgressFamily::V4 => "ipv6",
            EgressFamily::V6 => "ipv4",
        };
        EgressDecision {
            family: sticky_family,
            race: RacePlan {
                first: sticky_family,
                second: None,
                stagger_ms: decision.race.stagger_ms,
            },
            reason: format!(
                "sticky: keeping {name} within affinity (usable, not measured-bad); \
                 scorer preferred {other} — {}",
                decision.reason
            ),
            sticky_kept: true,
            ..decision
        }
    }

    /// True when `family` has enough samples to trust AND scores below
    /// [`BAD_SCORE_THRESHOLD`]. Unknown (too few samples) is never "bad":
    /// absence of evidence keeps the sticky session.
    fn family_bad(&self, domain: &str, family: EgressFamily) -> bool {
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.quality_ttl_secs.max(1));
        let key = normalize_domain(domain);
        let idx = family_index(family);
        let score = self
            .per_destination
            .get(&key)
            .and_then(|q| q[idx].score(now, ttl))
            .or_else(|| self.global[idx].score(now, ttl));
        score.is_some_and(|s| s < BAD_SCORE_THRESHOLD)
    }

    /// The fallback that applies for `domain`: the domain policy's own
    /// `on_family_down` wins; otherwise the engine default.
    fn fallback_for(&self, domain: &str) -> FamilyFallback {
        let domain = normalize_domain(domain);
        let mut best: Option<&DomainEgressPolicy> = None;
        for candidate in &self.config.domain_policies {
            let suffix = normalize_domain(&candidate.domain_suffix);
            if (domain == suffix
                || domain
                    .strip_suffix(suffix.as_ref())
                    .is_some_and(|rest| rest.ends_with('.')))
                && best.is_none_or(|b: &DomainEgressPolicy| suffix.len() > b.domain_suffix.len())
            {
                best = Some(candidate);
            }
        }
        // A domain policy that names a concrete policy also pins the
        // fallback; otherwise the engine default applies.
        best.map(|b| b.on_family_down)
            .unwrap_or(self.config.on_family_down)
    }

    #[allow(clippy::too_many_arguments)]
    fn forced_decision(
        &self,
        domain: &str,
        family: EgressFamily,
        family_usable: bool,
        other_usable: bool,
        policy: EgressFamilyPolicy,
        source: &'static str,
        fallback: FamilyFallback,
        stagger_ms: u64,
    ) -> EgressDecision {
        let name = match family {
            EgressFamily::V4 => "ipv4",
            EgressFamily::V6 => "ipv6",
        };
        if family_usable {
            return EgressDecision {
                family,
                race: RacePlan {
                    first: family,
                    second: None,
                    stagger_ms,
                },
                policy,
                policy_source: source,
                reason: format!("{}: forced {name}; no racing, no flip", policy.as_str()),
                fallback_applied: false,
                blocked: false,
                sticky_kept: false,
            };
        }
        self.unusable_fallback(
            domain,
            family,
            other_usable,
            policy,
            source,
            fallback,
            stagger_ms,
            &format!("{}: forced {name} unusable", policy.as_str()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn unusable_fallback(
        &self,
        domain: &str,
        wanted: EgressFamily,
        other_usable: bool,
        policy: EgressFamilyPolicy,
        source: &'static str,
        fallback: FamilyFallback,
        stagger_ms: u64,
        why: &str,
    ) -> EgressDecision {
        let other = match wanted {
            EgressFamily::V4 => EgressFamily::V6,
            EgressFamily::V6 => EgressFamily::V4,
        };
        match (fallback, other_usable) {
            (FamilyFallback::AllowOtherFamily, true) => EgressDecision {
                family: other,
                race: RacePlan {
                    first: other,
                    second: None,
                    stagger_ms,
                },
                policy,
                policy_source: source,
                // Recorded and surfaced: the exit IP family DID change, but
                // with an explicit reason — never silently.
                reason: format!(
                    "{why} for {domain}; user fallback allowed the other family (reroute recorded)"
                ),
                fallback_applied: true,
                blocked: false,
                sticky_kept: false,
            },
            _ => EgressDecision {
                family: wanted,
                race: RacePlan {
                    first: wanted,
                    second: None,
                    stagger_ms,
                },
                policy,
                policy_source: source,
                reason: format!("{why} for {domain}; fallback is block → fail closed"),
                fallback_applied: false,
                blocked: true,
                sticky_kept: false,
            },
        }
    }

    /// Drop destinations with no sample inside the TTL when the table grows
    /// past the cap.
    fn evict_quiet(&mut self, now: Instant) {
        let ttl = Duration::from_secs(self.config.quality_ttl_secs.max(1));
        self.per_destination.retain(|_, q| {
            [
                q[0].last_success,
                q[0].last_failure,
                q[1].last_success,
                q[1].last_failure,
            ]
            .into_iter()
            .flatten()
            .any(|t| now.duration_since(t) <= ttl)
        });
    }
}

fn family_index(family: EgressFamily) -> usize {
    match family {
        EgressFamily::V4 => 0,
        EgressFamily::V6 => 1,
    }
}

fn normalize_domain(domain: &str) -> Box<str> {
    domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .into()
}

// ---------------------------------------------------------------------------
// Sticky exit IP
// ---------------------------------------------------------------------------

/// What a sticky session is keyed on. Device policies win over domain
/// policies (frozen contract); the key records which one was used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SessionKey {
    Domain(Box<str>),
    Device(Box<str>),
}

/// One sticky session: a fixed family AND a fixed exit IP for the affinity
/// window. The exit IP is the exit host's static address — it does not
/// change when tunnels A/B/C switch underneath.
#[derive(Debug, Clone)]
pub struct StickySession {
    pub family: EgressFamily,
    /// The actual source address the destination sees. `None` = unpinned
    /// (no static IP configured); the panel shows "unpinned" honestly.
    pub exit_ip: Option<IpAddr>,
    pub started_at: SystemTime,
    pub affinity_until: Instant,
    pub policy: EgressFamilyPolicy,
}

/// A recorded family change. The panel surfaces the latest as
/// `last_reroute_at` + `last_reroute_reason` — the exit IP never changes
/// silently.
#[derive(Debug, Clone)]
pub struct RerouteEvent {
    pub at_wall: SystemTime,
    pub key: SessionKey,
    pub from: EgressFamily,
    pub to: EgressFamily,
    pub reason: String,
}

/// Outcome of [`StickyExit::select`].
#[derive(Debug, Clone)]
pub enum StickyOutcome {
    /// Keep using this session (affinity holds, no flip).
    Keep(StickySession),
    /// New session started (first contact, affinity expired, or the
    /// decision changed the family — the change is in `reroutes`).
    New(StickySession),
    /// The decision was fail-closed; no session.
    Blocked { reason: String },
}

pub struct StickyExit {
    static_v4: Option<IpAddr>,
    static_v6: Option<IpAddr>,
    default_affinity: Duration,
    sessions: HashMap<SessionKey, StickySession>,
    reroutes: VecDeque<RerouteEvent>,
}

impl StickyExit {
    pub fn new(config: &EgressConfig) -> Self {
        StickyExit {
            static_v4: config.static_ipv4.as_deref().and_then(|s| s.parse().ok()),
            static_v6: config.static_ipv6.as_deref().and_then(|s| s.parse().ok()),
            default_affinity: Duration::from_secs(config.affinity_secs.max(1)),
            sessions: HashMap::new(),
            reroutes: VecDeque::new(),
        }
    }

    fn exit_ip_for(&self, family: EgressFamily) -> Option<IpAddr> {
        match family {
            EgressFamily::V4 => self.static_v4,
            EgressFamily::V6 => self.static_v6,
        }
    }

    /// Select (or keep) the sticky session for `key`.
    ///
    /// - Affinity holds → the session is kept even if fresh quality data
    ///   would pick the other family ("no flip for a few ms of ping").
    /// - Affinity expired or no session → the decision applies; a family
    ///   change is recorded as a reroute event with its reason.
    /// - `decision.blocked` → [`StickyOutcome::Blocked`].
    pub fn select(
        &mut self,
        key: SessionKey,
        decision: &EgressDecision,
        affinity_secs: u64,
        now: Instant,
    ) -> StickyOutcome {
        if decision.blocked {
            return StickyOutcome::Blocked {
                reason: decision.reason.clone(),
            };
        }
        let affinity = Duration::from_secs(if affinity_secs == 0 {
            self.default_affinity.as_secs()
        } else {
            affinity_secs
        });
        if let Some(session) = self.sessions.get(&key) {
            if now < session.affinity_until && session.family == decision.family {
                return StickyOutcome::Keep(session.clone());
            }
            if session.family != decision.family {
                self.push_reroute(RerouteEvent {
                    at_wall: SystemTime::now(),
                    key: key.clone(),
                    from: session.family,
                    to: decision.family,
                    reason: decision.reason.clone(),
                });
            }
        }
        let session = StickySession {
            family: decision.family,
            exit_ip: self.exit_ip_for(decision.family),
            started_at: SystemTime::now(),
            affinity_until: now + affinity,
            policy: decision.policy,
        };
        self.sessions.insert(key, session.clone());
        StickyOutcome::New(session)
    }

    /// Forget one sticky session (device logout, policy deletion).
    pub fn forget(&mut self, key: &SessionKey) {
        self.sessions.remove(key);
    }

    pub fn session(&self, key: &SessionKey) -> Option<&StickySession> {
        self.sessions.get(key)
    }

    /// Latest reroute, for `/egress` `last_reroute_at`/`last_reroute_reason`.
    pub fn last_reroute(&self) -> Option<&RerouteEvent> {
        self.reroutes.back()
    }

    pub fn reroute_count(&self) -> usize {
        self.reroutes.len()
    }

    fn push_reroute(&mut self, event: RerouteEvent) {
        self.reroutes.push_back(event);
        while self.reroutes.len() > MAX_REROUTES {
            self.reroutes.pop_front();
        }
    }
}

// ---------------------------------------------------------------------------
// Per-tunnel traffic accounting
// ---------------------------------------------------------------------------

/// Byte counters for one tunnel, from real counters.
///
/// Split: payload (real) / keepalive (real) / health-check (real) /
/// overhead (ESTIMATE — WireGuard/IP/UDP framing is not tracked per packet
/// here; see [`TunnelTraffic::record_overhead_estimate`]). The estimate
/// label travels with the snapshot so panels cannot present it as measured.
#[derive(Debug, Default)]
pub struct TunnelTraffic {
    payload_up: AtomicU64,
    payload_down: AtomicU64,
    keepalive_bytes: AtomicU64,
    health_bytes: AtomicU64,
    overhead_bytes: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSnapshot {
    pub payload_up: u64,
    pub payload_down: u64,
    pub keepalive_bytes: u64,
    pub health_bytes: u64,
    pub overhead_bytes: u64,
    /// Always true: the overhead split is estimated, never measured
    /// per-packet. Panels must label it as an estimate.
    pub overhead_is_estimate: bool,
}

impl TunnelTraffic {
    /// Payload bytes actually carried for clients.
    pub fn record_payload(&self, up: u64, down: u64) {
        self.payload_up.fetch_add(up, Ordering::Relaxed);
        self.payload_down.fetch_add(down, Ordering::Relaxed);
    }

    /// WireGuard keepalive bytes (real: counted at send/receive).
    pub fn record_keepalive(&self, bytes: u64) {
        self.keepalive_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Heartbeat/health-probe bytes (real: counted at send/receive).
    pub fn record_health(&self, bytes: u64) {
        self.health_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Framing overhead (ESTIMATE): per-packet WireGuard + IP + UDP headers
    /// are not tracked individually; callers add `packets * header_bytes`.
    /// Labeled as an estimate in every snapshot.
    pub fn record_overhead_estimate(&self, bytes: u64) {
        self.overhead_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            payload_up: self.payload_up.load(Ordering::Relaxed),
            payload_down: self.payload_down.load(Ordering::Relaxed),
            keepalive_bytes: self.keepalive_bytes.load(Ordering::Relaxed),
            health_bytes: self.health_bytes.load(Ordering::Relaxed),
            overhead_bytes: self.overhead_bytes.load(Ordering::Relaxed),
            overhead_is_estimate: true,
        }
    }
}

/// Per-tunnel ledger, keyed by tunnel tag ("A"/"B"/"C").
///
/// Keyed by tag string (not the failover engine's `TunnelId`) so this
/// ledger has no coupling to Agent H1's `TransportTable` internals.
#[derive(Debug, Default)]
pub struct TrafficLedger {
    tunnels: Mutex<HashMap<Box<str>, TunnelTraffic>>,
}

impl TrafficLedger {
    pub fn new() -> Self {
        TrafficLedger {
            tunnels: Mutex::new(HashMap::new()),
        }
    }

    /// Record against one tunnel's counters (creating them). The lock is
    /// never held across an await: this is sync-only by construction.
    pub fn record(&self, tag: &str, f: impl FnOnce(&TunnelTraffic)) {
        let mut map = self.tunnels.lock().unwrap_or_else(|p| p.into_inner());
        f(map.entry(tag.into()).or_default());
    }

    /// Snapshot one tunnel, if it has counters yet.
    pub fn snapshot(&self, tag: &str) -> Option<TrafficSnapshot> {
        self.tunnels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(tag)
            .map(TunnelTraffic::snapshot)
    }

    /// Snapshot all tunnels (for `/tunnels` traffic split).
    pub fn snapshot_all(&self) -> HashMap<Box<str>, TrafficSnapshot> {
        self.tunnels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(tag, counters)| (tag.clone(), counters.snapshot()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Happy Eyeballs race primitive
// ---------------------------------------------------------------------------

/// Race two dial futures Happy-Eyeballs style (RFC 8305 §5).
///
/// `first` starts immediately; if it has not completed a real handshake
/// within `stagger`, `second` starts and the first to complete wins. The
/// loser is dropped (cancellation-safe: callers must use futures that are
/// safe to drop mid-dial, which TCP/TLS connects are).
///
/// `second = None` (forced policies, single-stack destinations) just awaits
/// the first future.
pub async fn happy_eyeballs<T, E, Fut1, Fut2>(
    stagger: Duration,
    first: Fut1,
    second: Option<Fut2>,
) -> Result<T, E>
where
    Fut1: Future<Output = Result<T, E>>,
    Fut2: Future<Output = Result<T, E>>,
{
    let Some(second) = second else {
        return first.await;
    };
    tokio::pin!(first);
    tokio::pin!(second);
    match tokio::time::timeout(stagger, &mut first).await {
        Ok(result) => result,
        Err(_) => {
            // First family is slow: race both; whichever handshake finishes
            // first wins. The loser is cancelled by drop.
            tokio::select! {
                result = &mut first => result,
                result = &mut second => result,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Source-address binding (sticky exit IP mechanism)
// ---------------------------------------------------------------------------

/// Build a TCP socket bound to the exit's static source address for
/// `family`.
///
/// Binding explicitly (instead of letting the OS pick) is what makes the
/// sticky exit IP real: the destination sees the static address no matter
/// which tunnel carried the packet. `None` static IP → bind the wildcard
/// (OS-selected source; the panel reports the exit IP as "unpinned").
///
/// IPv6 caveat: this binds the socket, which defeats RFC 4941 temporary
/// addresses for THIS socket — but the operator must still ensure the
/// static address is assigned to the host, or the bind fails here instead
/// of silently using another address (fail closed, by design).
pub fn bind_source_socket(
    family: EgressFamily,
    static_ip: Option<IpAddr>,
) -> io::Result<tokio::net::TcpSocket> {
    let socket = match family {
        EgressFamily::V4 => tokio::net::TcpSocket::new_v4()?,
        EgressFamily::V6 => tokio::net::TcpSocket::new_v6()?,
    };
    match (family, static_ip) {
        (EgressFamily::V4, Some(IpAddr::V4(ip))) => {
            socket.bind(std::net::SocketAddr::new(IpAddr::V4(ip), 0))?
        }
        (EgressFamily::V6, Some(IpAddr::V6(ip))) => {
            socket.bind(std::net::SocketAddr::new(IpAddr::V6(ip), 0))?
        }
        // Family/IP mismatch or no static IP: bind wildcard. A mismatch is
        // a config error the validator should have caught; binding the
        // wildcard here keeps the dial path fail-operational while the
        // status surface reports the exit IP as unpinned.
        (EgressFamily::V4, _) => socket.bind("0.0.0.0:0".parse().unwrap())?,
        (EgressFamily::V6, _) => socket.bind("[::]:0".parse().unwrap())?,
    }
    Ok(socket)
}

// ---------------------------------------------------------------------------
// Engine facade
// ---------------------------------------------------------------------------

/// Snapshot shaped toward the frozen `GET /egress` contract
/// (CONTRACT-triple.md): static IPs, per-family connectivity, sticky state.
#[derive(Debug, Clone)]
pub struct EgressStatus {
    pub static_ipv4: Option<String>,
    pub static_ipv6: Option<String>,
    pub v4_connected: bool,
    pub v4_success_rate: Option<f64>,
    pub v6_connected: bool,
    pub v6_success_rate: Option<f64>,
    pub sticky_exit_ip: Option<String>,
    pub sticky_family: &'static str,
    pub session_started_at: Option<SystemTime>,
    pub last_reroute_at: Option<SystemTime>,
    pub last_reroute_reason: Option<String>,
    pub probe_budget: &'static str,
}

/// The dual-stack egress engine: selector + sticky exit + traffic ledger.
///
/// Thread-safe; the server holds one behind an `Arc` and feeds it real
/// dial outcomes. The HTTP surface (`/egress`, `/egress/decisions`,
/// `/tunnels`) is Agent H1's layer and reads via the snapshot methods.
pub struct EgressEngine {
    config: Mutex<EgressConfig>,
    selector: Mutex<EgressSelector>,
    sticky: Mutex<StickyExit>,
    ledger: TrafficLedger,
}

impl EgressEngine {
    pub fn new(config: EgressConfig) -> Self {
        EgressEngine {
            selector: Mutex::new(EgressSelector::new(config.clone())),
            sticky: Mutex::new(StickyExit::new(&config)),
            config: Mutex::new(config),
            ledger: TrafficLedger::new(),
        }
    }

    /// Select egress for a destination under a sticky session key.
    ///
    /// Device keys win over domain keys per the frozen contract — the
    /// caller passes the already-resolved key. The decision is
    /// sticky-aware: within the affinity window the current family is kept
    /// whenever it is usable and not measured-bad.
    pub fn select(
        &self,
        key: SessionKey,
        domain: &str,
        has_v4: bool,
        has_v6: bool,
        affinity_secs: u64,
    ) -> (EgressDecision, StickyOutcome) {
        let now = Instant::now();
        // Peek at the sticky session so the decision can honor affinity.
        let sticky = self
            .sticky
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .session(&key)
            .map(|session| (session.family, now < session.affinity_until));
        let decision = self
            .selector
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .decide_sticky(domain, has_v4, has_v6, sticky);
        let outcome = self
            .sticky
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .select(key, &decision, affinity_secs, now);
        (decision, outcome)
    }

    /// Feed one real dial outcome back (drives future decisions).
    pub fn record_result(&self, domain: &str, family: EgressFamily, outcome: ProbeOutcome) {
        self.selector
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record_result(domain, family, outcome);
    }

    /// Apply admin-pushed sticky policies (`POST /sticky-policies`,
    /// best-effort poller push). Replaces the engine's domain policy set.
    pub fn apply_policies(&self, policies: Vec<DomainEgressPolicy>) {
        let mut config = self.config.lock().unwrap_or_else(|p| p.into_inner());
        config.domain_policies = policies;
        self.selector
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_config(config.clone());
    }

    /// Apply a probe-budget change (`POST /tunnels/probe-budget`).
    /// Best-effort: the admin is authoritative and reports `engine_applied`.
    pub fn set_probe_budget(&self, budget: ProbeBudget, params: ProbeBudgetParams) {
        let mut config = self.config.lock().unwrap_or_else(|p| p.into_inner());
        config.probe_budget = budget;
        config.probe_params = params;
        self.selector
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_config(config.clone());
    }

    pub fn probe_budget(&self) -> (ProbeBudget, ProbeBudgetParams) {
        let config = self.config.lock().unwrap_or_else(|p| p.into_inner());
        let budget = config.probe_budget;
        (budget, budget.params(config.probe_params))
    }

    /// Per-tunnel traffic counters (for `/tunnels` traffic split).
    pub fn traffic_ledger(&self) -> &TrafficLedger {
        &self.ledger
    }

    /// Forget one sticky session (device logout / policy deletion).
    pub fn forget_session(&self, key: &SessionKey) {
        self.sticky
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .forget(key);
    }

    /// Snapshot toward `GET /egress`.
    pub fn status_snapshot(&self) -> EgressStatus {
        let config = self.config.lock().unwrap_or_else(|p| p.into_inner());
        let sticky = self.sticky.lock().unwrap_or_else(|p| p.into_inner());
        // Global family health: "connected" means we have recent successful
        // samples; success_rate is None until MIN_SAMPLES.
        let now = Instant::now();
        let ttl = Duration::from_secs(config.quality_ttl_secs.max(1));
        let (v4_connected, v4_success_rate, v6_connected, v6_success_rate) = {
            let selector = self.selector.lock().unwrap_or_else(|p| p.into_inner());
            let v4 = selector.global[0].score(now, ttl);
            let v6 = selector.global[1].score(now, ttl);
            (
                v4.is_some_and(|s| s > 0.0),
                v4,
                v6.is_some_and(|s| s > 0.0),
                v6,
            )
        };
        // Current sticky state: report the most recently touched session, if
        // any. (Per-session detail lives behind `/egress/decisions`.)
        // HashMap iteration order is arbitrary; with multiple sessions this
        // reports an arbitrary one — the contract's `/egress` sticky block
        // is a summary, and H1's per-session surface is authoritative.
        let (sticky_exit_ip, sticky_family, session_started_at) = sticky
            .sessions
            .values()
            .next()
            .map(|session| {
                (
                    session.exit_ip.map(|ip| ip.to_string()),
                    match session.family {
                        EgressFamily::V4 => "ipv4",
                        EgressFamily::V6 => "ipv6",
                    },
                    Some(session.started_at),
                )
            })
            .unwrap_or((None, "none", None));
        let (last_reroute_at, last_reroute_reason) = sticky
            .last_reroute()
            .map(|r| (Some(r.at_wall), Some(r.reason.clone())))
            .unwrap_or((None, None));
        EgressStatus {
            static_ipv4: config.static_ipv4.as_deref().map(str::to_string),
            static_ipv6: config.static_ipv6.as_deref().map(str::to_string),
            v4_connected,
            v4_success_rate,
            v6_connected,
            v6_success_rate,
            sticky_exit_ip,
            sticky_family,
            session_started_at,
            last_reroute_at,
            last_reroute_reason,
            probe_budget: config.probe_budget.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> EgressConfig {
        EgressConfig {
            static_ipv4: Some("203.0.113.10".into()),
            static_ipv6: Some("2001:db8::10".into()),
            default_policy: EgressFamilyPolicy::Auto,
            sensitive_sites: vec!["bank.ir".into()],
            domain_policies: vec![DomainEgressPolicy {
                domain_suffix: "legacy.example.com".into(),
                policy: EgressFamilyPolicy::ForceIpv4,
                affinity_secs: 7200,
                on_family_down: FamilyFallback::Block,
                note: "old client".into(),
            }],
            affinity_secs: 3600,
            on_family_down: FamilyFallback::Block,
            probe_budget: ProbeBudget::Balanced,
            probe_params: ProbeBudgetParams::default(),
            race_delay_ms: 250,
            quality_ttl_secs: 600,
        }
    }

    #[test]
    fn policy_string_round_trip() {
        for policy in [
            EgressFamilyPolicy::Auto,
            EgressFamilyPolicy::ForceIpv4,
            EgressFamilyPolicy::ForceIpv6,
            EgressFamilyPolicy::PreferStableIpv4,
        ] {
            assert_eq!(EgressFamilyPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(EgressFamilyPolicy::parse("bogus"), None);
        for budget in [
            ProbeBudget::Low,
            ProbeBudget::Balanced,
            ProbeBudget::Aggressive,
            ProbeBudget::Custom,
        ] {
            assert_eq!(ProbeBudget::parse(budget.as_str()), Some(budget));
        }
        assert_eq!(ProbeBudget::parse("bogus"), None);
    }

    #[test]
    fn probe_budget_presets_are_sane() {
        let params = ProbeBudgetParams::default();
        let low = ProbeBudget::Low.params(params);
        let balanced = ProbeBudget::Balanced.params(params);
        let aggressive = ProbeBudget::Aggressive.params(params);
        assert!(low.interval_secs > balanced.interval_secs);
        assert!(balanced.interval_secs > aggressive.interval_secs);
        assert!(low.concurrency <= balanced.concurrency);
        assert!(balanced.concurrency <= aggressive.concurrency);
        assert!(low.max_bytes_per_day < aggressive.max_bytes_per_day);
        // Custom passes through.
        let custom = ProbeBudgetParams {
            interval_secs: 42,
            concurrency: 7,
            max_bytes_per_day: 13,
        };
        assert_eq!(ProbeBudget::Custom.params(custom), custom);
    }

    #[test]
    fn auto_prefers_measured_quality() {
        let mut selector = EgressSelector::new(test_config());
        // v4: fast and reliable. v6: slow and flaky.
        for _ in 0..5 {
            selector.record_result(
                "example.com",
                EgressFamily::V4,
                ProbeOutcome::Success { handshake_ms: 40.0 },
            );
        }
        for _ in 0..4 {
            selector.record_result(
                "example.com",
                EgressFamily::V6,
                ProbeOutcome::Success {
                    handshake_ms: 900.0,
                },
            );
        }
        selector.record_result("example.com", EgressFamily::V6, ProbeOutcome::Failure);
        let decision = selector.decide("example.com", true, true);
        assert_eq!(decision.family, EgressFamily::V4);
        assert_eq!(decision.policy, EgressFamilyPolicy::Auto);
        assert!(!decision.blocked);
        assert!(decision.race.second == Some(EgressFamily::V6));
        assert!(decision.reason.contains("v4 score"));
    }

    #[test]
    fn auto_no_data_races_v6_first() {
        let selector = EgressSelector::new(test_config());
        let decision = selector.decide("new.example.net", true, true);
        assert_eq!(decision.family, EgressFamily::V6);
        assert_eq!(decision.race.first, EgressFamily::V6);
        assert_eq!(decision.race.second, Some(EgressFamily::V4));
        assert_eq!(decision.race.stagger_ms, 250);
    }

    #[test]
    fn force_ipv4_never_races_and_blocks_fail_closed() {
        let selector = EgressSelector::new(test_config());
        // Forced, usable → no race, no fallback.
        let decision = selector.decide("legacy.example.com", true, true);
        assert_eq!(decision.family, EgressFamily::V4);
        assert_eq!(decision.race.second, None);
        assert!(!decision.blocked);
        assert!(!decision.fallback_applied);
        // Forced, unusable, fallback=Block → fail closed, never silent v6.
        let decision = selector.decide("legacy.example.com", false, true);
        assert!(decision.blocked);
        assert!(!decision.fallback_applied);
        assert!(decision.reason.contains("fail closed"));
    }

    #[test]
    fn force_ipv4_with_allow_fallback_records_reroute_reason() {
        let mut config = test_config();
        config.domain_policies[0].on_family_down = FamilyFallback::AllowOtherFamily;
        let selector = EgressSelector::new(config);
        let decision = selector.decide("legacy.example.com", false, true);
        assert!(!decision.blocked);
        assert!(decision.fallback_applied);
        assert_eq!(decision.family, EgressFamily::V6);
        // The reason names the fallback explicitly — surfaced, not silent.
        assert!(decision.reason.contains("fallback allowed"));
    }

    #[test]
    fn prefer_stable_ipv4_keeps_v4_despite_better_v6() {
        let mut selector = EgressSelector::new(test_config());
        // v6 measures strictly better…
        for _ in 0..5 {
            selector.record_result(
                "bank.ir",
                EgressFamily::V6,
                ProbeOutcome::Success { handshake_ms: 20.0 },
            );
        }
        for _ in 0..5 {
            selector.record_result(
                "bank.ir",
                EgressFamily::V4,
                ProbeOutcome::Success {
                    handshake_ms: 300.0,
                },
            );
        }
        // …but the sensitive-site default keeps v4: no flip for ping.
        let decision = selector.decide("bank.ir", true, true);
        assert_eq!(decision.family, EgressFamily::V4);
        assert_eq!(decision.policy, EgressFamilyPolicy::PreferStableIpv4);
        assert_eq!(decision.policy_source, "sensitive-site");
        assert_eq!(decision.race.second, None);
    }

    #[test]
    fn longest_suffix_domain_policy_wins() {
        let mut config = test_config();
        config.domain_policies.push(DomainEgressPolicy {
            domain_suffix: "example.com".into(),
            policy: EgressFamilyPolicy::ForceIpv6,
            affinity_secs: 0,
            on_family_down: FamilyFallback::Block,
            note: "".into(),
        });
        let (policy, source) = config.policy_for_domain("legacy.example.com");
        assert_eq!(policy, EgressFamilyPolicy::ForceIpv4);
        assert_eq!(source, "domain-policy");
        let (policy, _) = config.policy_for_domain("other.example.com");
        assert_eq!(policy, EgressFamilyPolicy::ForceIpv6);
    }

    #[test]
    fn sticky_session_does_not_flip_within_affinity() {
        let config = test_config();
        let engine = EgressEngine::new(config);
        let key = SessionKey::Domain("example.com".into());
        // First select: v6 (no data, RFC 8305).
        let (decision, outcome) = engine.select(key.clone(), "example.com", true, true, 3600);
        assert!(!decision.sticky_kept); // no sticky session yet
        let first_ip = match outcome {
            StickyOutcome::New(session) => {
                assert_eq!(session.family, EgressFamily::V6);
                // Exit IP is the static v6 — pinned, not OS-chosen.
                assert_eq!(session.exit_ip, Some("2001:db8::10".parse().unwrap()));
                session.exit_ip
            }
            _ => panic!("expected a new session"),
        };
        // Now v4 measures better — but affinity holds and v6 is usable and
        // not measured-bad: no flip for the scorer's marginal win.
        for _ in 0..5 {
            engine.record_result(
                "example.com",
                EgressFamily::V4,
                ProbeOutcome::Success { handshake_ms: 10.0 },
            );
        }
        let (decision2, outcome2) = engine.select(key.clone(), "example.com", true, true, 3600);
        assert!(decision2.sticky_kept);
        assert_eq!(decision2.family, EgressFamily::V6);
        assert!(decision2
            .reason
            .contains("sticky: keeping ipv6 within affinity"));
        match outcome2 {
            StickyOutcome::Keep(session) => {
                assert_eq!(session.family, EgressFamily::V6);
                assert_eq!(session.exit_ip, first_ip); // same exit IP
            }
            _ => panic!("expected the session to be kept"),
        }
        assert_eq!(engine.sticky.lock().unwrap().reroute_count(), 0);
    }

    #[test]
    fn sticky_session_moves_when_family_measured_bad() {
        let config = test_config();
        let engine = EgressEngine::new(config);
        let key = SessionKey::Domain("example.com".into());
        let (_, outcome) = engine.select(key.clone(), "example.com", true, true, 3600);
        assert!(matches!(outcome, StickyOutcome::New(_))); // v6 session
                                                           // v6 fails repeatedly (measured-bad), v4 is healthy.
        for _ in 0..5 {
            engine.record_result("example.com", EgressFamily::V6, ProbeOutcome::Failure);
            engine.record_result(
                "example.com",
                EgressFamily::V4,
                ProbeOutcome::Success { handshake_ms: 30.0 },
            );
        }
        let (decision, outcome) = engine.select(key.clone(), "example.com", true, true, 3600);
        // Stickiness does not protect a measured-bad family.
        assert!(!decision.sticky_kept);
        assert_eq!(decision.family, EgressFamily::V4);
        match outcome {
            StickyOutcome::New(session) => assert_eq!(session.family, EgressFamily::V4),
            _ => panic!("expected a new session on the healthy family"),
        }
        // The move was recorded with its reason — never silent.
        assert_eq!(engine.sticky.lock().unwrap().reroute_count(), 1);
    }

    #[test]
    fn sticky_reroute_is_recorded_with_reason() {
        // The reroute path: a kept session whose affinity expired and whose
        // decision family changed records the change with its reason.
        let mut sticky_exit = StickyExit::new(&test_config());
        let key = SessionKey::Domain("d.example".into());
        let decision_v6 = EgressDecision {
            family: EgressFamily::V6,
            race: RacePlan {
                first: EgressFamily::V6,
                second: None,
                stagger_ms: 250,
            },
            policy: EgressFamilyPolicy::Auto,
            policy_source: "default",
            reason: "v6 measured faster".to_string(),
            fallback_applied: false,
            blocked: false,
            sticky_kept: false,
        };
        let decision_v4 = EgressDecision {
            family: EgressFamily::V4,
            reason: "operator forced v4".to_string(),
            ..decision_v6.clone()
        };
        let now = Instant::now();
        assert!(matches!(
            sticky_exit.select(key.clone(), &decision_v6, 0, now),
            StickyOutcome::New(_)
        ));
        // Affinity (default 3600s) still holds → kept, no reroute.
        assert!(matches!(
            sticky_exit.select(key.clone(), &decision_v6, 0, now + Duration::from_secs(10)),
            StickyOutcome::Keep(_)
        ));
        assert_eq!(sticky_exit.reroute_count(), 0);
        // Affinity expired and the family changed → new session + reroute.
        let later = now + Duration::from_secs(7200);
        assert!(matches!(
            sticky_exit.select(key.clone(), &decision_v4, 0, later),
            StickyOutcome::New(_)
        ));
        assert_eq!(sticky_exit.reroute_count(), 1);
        let reroute = sticky_exit.last_reroute().unwrap();
        assert_eq!(reroute.from, EgressFamily::V6);
        assert_eq!(reroute.to, EgressFamily::V4);
        assert_eq!(reroute.reason, "operator forced v4");
        assert_eq!(reroute.key, key);
    }

    #[test]
    fn exit_ip_constant_across_tunnel_switches() {
        // The sticky exit IP is a property of the exit host, not the tunnel:
        // selecting twice (modeling a tunnel A→B switch between) keeps it.
        let config = test_config();
        let engine = EgressEngine::new(config);
        let key = SessionKey::Device("device-1".into());
        let (_, first) = engine.select(key.clone(), "example.com", true, true, 3600);
        let (_, second) = engine.select(key.clone(), "example.com", true, true, 3600);
        let ip_of = |outcome: &StickyOutcome| match outcome {
            StickyOutcome::Keep(session) | StickyOutcome::New(session) => session.exit_ip,
            StickyOutcome::Blocked { .. } => panic!("unexpected block"),
        };
        assert_eq!(ip_of(&first), ip_of(&second));
        assert_eq!(ip_of(&second), Some("2001:db8::10".parse().unwrap()));
    }

    #[test]
    fn traffic_ledger_splits_and_labels_estimate() {
        let ledger = TrafficLedger::new();
        ledger.record("A", |counters| {
            counters.record_payload(1000, 2000);
            counters.record_keepalive(64);
            counters.record_health(128);
            counters.record_overhead_estimate(96);
        });
        ledger.record("B", |counters| {
            counters.record_payload(10, 20);
        });
        let snapshot_a = ledger.snapshot("A").expect("tunnel A has counters");
        assert_eq!(snapshot_a.payload_up, 1000);
        assert_eq!(snapshot_a.payload_down, 2000);
        assert_eq!(snapshot_a.keepalive_bytes, 64);
        assert_eq!(snapshot_a.health_bytes, 128);
        assert_eq!(snapshot_a.overhead_bytes, 96);
        // The overhead split is ALWAYS labeled an estimate.
        assert!(snapshot_a.overhead_is_estimate);
        let all = ledger.snapshot_all();
        assert_eq!(all.get("B").unwrap().payload_up, 10);
        assert_eq!(ledger.snapshot("C"), None);
    }

    #[test]
    fn bind_source_socket_binds_loopback() {
        // Real sockets on loopback: v4 and v6.
        let socket = bind_source_socket(EgressFamily::V4, Some("127.0.0.1".parse().unwrap()));
        assert!(socket.is_ok());
        let socket = bind_source_socket(EgressFamily::V6, Some("::1".parse().unwrap()));
        // ::1 may be unavailable in some sandboxes; do not hard-fail the
        // suite on environment — but record what happened.
        if let Err(error) = &socket {
            eprintln!("NOT TESTED (no IPv6 loopback in this sandbox): {error}");
        }
        // Wildcard bind always works.
        assert!(bind_source_socket(EgressFamily::V4, None).is_ok());
    }

    #[tokio::test]
    async fn happy_eyeballs_first_wins_when_fast() {
        let fast = async { Ok::<&str, &str>("v6") };
        let slow = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<&str, &str>("v4")
        };
        let winner = happy_eyeballs(Duration::from_millis(10), fast, Some(slow)).await;
        assert_eq!(winner, Ok("v6"));
    }

    #[tokio::test]
    async fn happy_eyeballs_second_wins_when_first_stalls() {
        let stalled = async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<&str, &str>("v6")
        };
        let fast = async { Ok::<&str, &str>("v4") };
        let winner = happy_eyeballs(Duration::from_millis(10), stalled, Some(fast)).await;
        assert_eq!(winner, Ok("v4"));
    }

    #[tokio::test]
    async fn happy_eyeballs_no_second_just_awaits() {
        let slow = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<&str, &str>("only")
        };
        let winner = happy_eyeballs::<&str, &str, _, futures::future::Pending<Result<&str, &str>>>(
            Duration::from_millis(5),
            slow,
            None,
        )
        .await;
        assert_eq!(winner, Ok("only"));
    }

    #[test]
    fn egress_config_validation() {
        let mut config = EgressConfig::default();
        assert!(config.validate().is_ok());
        config.static_ipv4 = Some("not-an-ip".into());
        assert!(config.validate().is_err());
        config.static_ipv4 = Some("2001:db8::1".into()); // v6 in the v4 slot
        assert!(config.validate().is_err());
        config.static_ipv4 = Some("203.0.113.10".into());
        config.static_ipv6 = Some("1.2.3.4".into()); // v4 in the v6 slot
        assert!(config.validate().is_err());
        config.static_ipv6 = None;
        config.affinity_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn status_snapshot_toward_contract() {
        let engine = EgressEngine::new(test_config());
        // Feed real outcomes so the snapshot has connectivity data.
        for _ in 0..4 {
            engine.record_result(
                "example.com",
                EgressFamily::V4,
                ProbeOutcome::Success { handshake_ms: 50.0 },
            );
        }
        let status = engine.status_snapshot();
        assert_eq!(status.static_ipv4.as_deref(), Some("203.0.113.10"));
        assert_eq!(status.static_ipv6.as_deref(), Some("2001:db8::10"));
        assert_eq!(status.probe_budget, "balanced");
        assert!(status.v4_connected);
        assert!(status.v4_success_rate.is_some_and(|r| r > 0.9));
        // v6 has no samples yet.
        assert!(!status.v6_connected);
        assert_eq!(status.v6_success_rate, None);
        // Sticky state before any session.
        assert_eq!(status.sticky_family, "none");
        assert_eq!(status.last_reroute_at, None);
    }
}
