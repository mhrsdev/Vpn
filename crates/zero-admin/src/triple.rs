//! Triple-tunnel / dual-stack / sticky-exit (owner addendum, binding).
//!
//! The routing agent owns the failover machinery; this module is the admin's
//! read/control surface, in the same style as `ha.rs`:
//!
//! - `GET /api/v1/tunnels/status` — tunnels A (IPv4) / B (IPv4) / C (IPv6),
//!   each with traffic split (payload / keepalive / health-check / overhead),
//!   active sessions, failover count, recovery time.
//! - `GET /api/v1/egress/status` — static IPv4/IPv6, v4/v6 connectivity,
//!   success rates, sticky-session state.
//! - `GET /api/v1/egress/decisions?domain=` — per-destination family + why.
//! - `GET/POST/PUT/DELETE /api/v1/sticky-policies/*` — admin-owned policy
//!   store (pushed to the engine best-effort, like routing rules).
//! - `POST /api/v1/tests/{ipv4|ipv6|both|exit-ip|failover}` — manual tests
//!   with REAL results, proxied to the engine.
//! - `GET/POST /api/v1/tunnels/probe-budget` — probe-traffic-budget setting.
//!
//! Binding honesty rules:
//! - Tunnel C shows "unavailable" (an explicit engine state) when IPv6 is not
//!   really usable — never fake-connected. Any other unknown/missing tunnel
//!   state surfaces as "down" (fail-closed).
//! - Manual tests proxy the engine; 502 when the engine has no test surface.
//!   The admin never invents results.
//! - Sticky exit: the engine never silently changes the exit IP; the panel
//!   shows `last_reroute_at` + `last_reroute_reason` from the engine.

use serde::{Deserialize, Serialize};

use crate::engine::{EngineClient, EngineError};

/// Tunnel ids the admin knows. The engine may report fewer (absent → down).
pub const TUNNEL_IDS: [&str; 3] = ["A", "B", "C"];

/// Tunnel families: A and B are IPv4, C is IPv6.
pub fn tunnel_family(id: &str) -> &'static str {
    match id {
        "C" => "ipv6",
        _ => "ipv4",
    }
}

/// Per-tunnel traffic accounting, from real counters (never estimated).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelTraffic {
    #[serde(default)]
    pub payload_up: u64,
    #[serde(default)]
    pub payload_down: u64,
    #[serde(default)]
    pub keepalive_bytes: u64,
    #[serde(default)]
    pub health_bytes: u64,
    #[serde(default)]
    pub overhead_bytes: u64,
}

/// One tunnel in the triple set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TripleTunnel {
    #[serde(default)]
    pub id: String,
    /// "ipv4" | "ipv6".
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub transport_family: Option<String>,
    /// "up" | "degraded" | "standby" | "down" | "unavailable".
    #[serde(default)]
    pub state: Option<String>,
    /// Integer millis.
    #[serde(default)]
    pub rtt_ms: Option<i64>,
    #[serde(default)]
    pub loss_pct: Option<f64>,
    /// Integer millis.
    #[serde(default)]
    pub jitter_ms: Option<i64>,
    #[serde(default)]
    pub keepalive_ok: Option<bool>,
    /// Epoch millis.
    #[serde(default)]
    pub last_heartbeat_at: Option<i64>,
    #[serde(default)]
    pub traffic: TunnelTraffic,
    #[serde(default)]
    pub active_sessions: Option<u64>,
    #[serde(default)]
    pub failover_count: Option<u64>,
    /// Measured seconds of the last recovery; None = not measured.
    #[serde(default)]
    pub recovery_time_s: Option<f64>,
}

impl TripleTunnel {
    /// Fail-closed view: explicit "unavailable" (IPv6 not really usable)
    /// passes through; anything else unknown/missing → "down".
    pub fn state_view(&self) -> &str {
        match self.state.as_deref() {
            Some("up") | Some("degraded") | Some("standby") | Some("down")
            | Some("unavailable") => self.state.as_deref().unwrap(),
            _ => "down",
        }
    }

    pub fn family_view(&self) -> &str {
        if self.family == "ipv6" {
            "ipv6"
        } else {
            tunnel_family(&self.id)
        }
    }
}

/// Probe-traffic budgets the panel offers. The engine declares which it
/// supports via `probe_budget_options`; the admin only offers those.
pub const PROBE_BUDGETS: [&str; 4] = ["low", "balanced", "aggressive", "custom"];

/// Full triple-tunnel snapshot from the engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TripleSnapshot {
    #[serde(default)]
    pub tunnels: Vec<TripleTunnel>,
    #[serde(default)]
    pub primary: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub available_modes: Vec<String>,
    #[serde(default)]
    pub probe_budget: Option<String>,
    #[serde(default)]
    pub probe_budget_options: Vec<String>,
    /// True when the data came from the real `/tunnels` contract.
    #[serde(skip)]
    pub from_tunnels_endpoint: bool,
}

impl TripleSnapshot {
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn supported(&self) -> bool {
        self.from_tunnels_endpoint || !self.tunnels.is_empty()
    }

    /// Tunnels in A/B/C order, synthesizing a fail-closed entry for any id
    /// the engine did not report.
    pub fn ordered_tunnels(&self) -> Vec<TripleTunnel> {
        TUNNEL_IDS
            .iter()
            .map(|id| {
                self.tunnels
                    .iter()
                    .find(|t| t.id == *id)
                    .cloned()
                    .unwrap_or_else(|| TripleTunnel {
                        id: id.to_string(),
                        family: tunnel_family(id).to_string(),
                        ..Default::default()
                    })
            })
            .collect()
    }

    pub fn probe_budget_view(&self) -> &str {
        match self.probe_budget.as_deref() {
            Some("low") | Some("balanced") | Some("aggressive") | Some("custom") => {
                self.probe_budget.as_deref().unwrap()
            }
            _ => "balanced",
        }
    }

    /// Budgets the admin may offer: the engine's own list wins, otherwise the
    /// full set (the engine is expected to accept them; a 409 from the engine
    /// is surfaced honestly).
    pub fn budget_options(&self) -> Vec<String> {
        if self.probe_budget_options.is_empty() {
            PROBE_BUDGETS.iter().map(|s| s.to_string()).collect()
        } else {
            self.probe_budget_options.clone()
        }
    }
}

/// Dual-stack USA egress state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressFamily {
    #[serde(default)]
    pub connected: Option<bool>,
    #[serde(default)]
    pub success_rate: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressSticky {
    #[serde(default)]
    pub exit_ip: Option<String>,
    #[serde(default)]
    pub exit_family: Option<String>,
    /// Epoch millis.
    #[serde(default)]
    pub session_started_at: Option<i64>,
    #[serde(default)]
    pub last_reroute_at: Option<i64>,
    #[serde(default)]
    pub last_reroute_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressSnapshot {
    #[serde(default)]
    pub static_ipv4: Option<String>,
    #[serde(default)]
    pub static_ipv6: Option<String>,
    #[serde(default)]
    pub v4: EgressFamily,
    #[serde(default)]
    pub v6: EgressFamily,
    #[serde(default)]
    pub sticky: EgressSticky,
    #[serde(skip)]
    pub from_egress_endpoint: bool,
}

impl EgressSnapshot {
    pub fn unknown() -> Self {
        Self::default()
    }
    pub fn supported(&self) -> bool {
        self.from_egress_endpoint || self.static_ipv4.is_some() || self.static_ipv6.is_some()
    }
}

/// Per-destination routing decision (family chosen + why).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressDecision {
    #[serde(default)]
    pub domain: String,
    /// "ipv4" | "ipv6".
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub exit_ip: Option<String>,
}

/// One manual test result — REAL, measured by the engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManualTest {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub results: Vec<ManualTestStep>,
    /// Epoch millis.
    #[serde(default)]
    pub measured_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManualTestStep {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// Manual test kinds the admin offers.
pub const TEST_KINDS: [&str; 5] = ["ipv4", "ipv6", "both", "exit-ip", "failover"];

/// Sticky-policy scopes and policies (frozen).
pub const STICKY_SCOPES: [&str; 2] = ["domain", "device"];
pub const STICKY_POLICIES: [&str; 4] = ["force_ipv4", "force_ipv6", "auto", "prefer_stable_ipv4"];

/// Validated sticky-policy input.
#[derive(Debug, Clone)]
pub struct ValidStickyPolicy {
    pub scope: String,
    pub target: String,
    pub policy: String,
    pub affinity_secs: i64,
    pub note: String,
}

#[derive(Debug, Clone)]
pub enum StickyError {
    BadPolicy(String),
}

impl std::fmt::Display for StickyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StickyError::BadPolicy(m) => write!(f, "invalid sticky policy: {m}"),
        }
    }
}

impl std::error::Error for StickyError {}

/// Fail-closed validation: unknown scope/policy rejected, never stored.
pub fn validate_sticky_policy(
    scope: &str,
    target: &str,
    policy: &str,
    affinity_secs: i64,
    note: &str,
) -> Result<ValidStickyPolicy, StickyError> {
    let bad = |m: &str| StickyError::BadPolicy(m.to_string());
    if !STICKY_SCOPES.contains(&scope) {
        return Err(bad("scope must be 'domain' or 'device'"));
    }
    let target = target.trim();
    if target.is_empty() || target.len() > 253 {
        return Err(bad("target is required (max 253 chars)"));
    }
    if !STICKY_POLICIES.contains(&policy) {
        return Err(bad(
            "policy must be force_ipv4 | force_ipv6 | auto | prefer_stable_ipv4",
        ));
    }
    if !(0..=86400).contains(&affinity_secs) {
        return Err(bad("affinity_secs must be 0..=86400"));
    }
    if note.len() > 500 {
        return Err(bad("note too long (max 500)"));
    }
    Ok(ValidStickyPolicy {
        scope: scope.to_string(),
        target: if scope == "domain" {
            target.to_ascii_lowercase()
        } else {
            target.to_string()
        },
        policy: policy.to_string(),
        affinity_secs,
        note: note.to_string(),
    })
}

impl EngineClient {
    /// `GET /tunnels` — the triple-tunnel contract. 404 → fall back to
    /// mapping the 2-tunnel `GET /ha` snapshot (tunnels A/B, no C); no HA
    /// surface at all → unknown (honest `supported:false`). Unreachable →
    /// Err (honest 502).
    pub async fn tunnels_snapshot(&self) -> Result<TripleSnapshot, EngineError> {
        match self.ha_get_json("/tunnels").await {
            Ok(v) => {
                let mut snap: TripleSnapshot = serde_json::from_value(v)
                    .map_err(|e| EngineError::BadResponse(e.to_string()))?;
                snap.from_tunnels_endpoint = true;
                normalize_triple(&mut snap);
                Ok(snap)
            }
            Err(EngineError::Status(404, _)) => self.tunnels_via_ha().await,
            Err(e) => Err(e),
        }
    }

    /// Map the 2-tunnel HA snapshot into the triple shape (A/B present, C
    /// synthesized as missing → "down" unless the engine reports it).
    async fn tunnels_via_ha(&self) -> Result<TripleSnapshot, EngineError> {
        match self.ha_snapshot().await {
            Ok(ha) if ha.supported() => {
                let mut snap = TripleSnapshot {
                    primary: ha.primary.clone(),
                    mode: ha.mode.clone(),
                    available_modes: ha.available_modes.clone(),
                    ..Default::default()
                };
                for t in &ha.tunnels {
                    snap.tunnels.push(TripleTunnel {
                        id: t.id.to_ascii_uppercase(),
                        family: tunnel_family(&t.id.to_ascii_uppercase()).to_string(),
                        protocol: t.protocol.clone(),
                        transport_family: t.transport_family.clone(),
                        state: t.state.clone(),
                        rtt_ms: t.rtt_ms,
                        loss_pct: t.loss_pct,
                        jitter_ms: t.jitter_ms,
                        keepalive_ok: t.keepalive_ok,
                        last_heartbeat_at: t.last_heartbeat_at,
                        traffic: TunnelTraffic {
                            payload_up: t.bytes_up,
                            payload_down: t.bytes_down,
                            ..Default::default()
                        },
                        ..Default::default()
                    });
                }
                normalize_triple(&mut snap);
                Ok(snap)
            }
            Ok(_) => Ok(TripleSnapshot::unknown()),
            Err(e) => Err(e),
        }
    }

    /// `GET /egress` — dual-stack USA egress state. 404 → unknown.
    pub async fn egress_snapshot(&self) -> Result<EgressSnapshot, EngineError> {
        match self.ha_get_json("/egress").await {
            Ok(v) => {
                let mut snap: EgressSnapshot = serde_json::from_value(v)
                    .map_err(|e| EngineError::BadResponse(e.to_string()))?;
                snap.from_egress_endpoint = true;
                Ok(snap)
            }
            Err(EngineError::Status(404, _)) => Ok(EgressSnapshot::unknown()),
            Err(e) => Err(e),
        }
    }

    /// `GET /egress/decisions?domain=` — per-destination family + why.
    pub async fn egress_decision(&self, domain: &str) -> Result<EgressDecision, EngineError> {
        let v = self
            .ha_get_json(&format!("/egress/decisions?domain={domain}"))
            .await?;
        let mut d: EgressDecision =
            serde_json::from_value(v).map_err(|e| EngineError::BadResponse(e.to_string()))?;
        if d.domain.is_empty() {
            d.domain = domain.to_string();
        }
        Ok(d)
    }

    /// `POST /tests/{kind}` — manual test with REAL results.
    pub async fn run_test(&self, kind: &str) -> Result<ManualTest, EngineError> {
        let (status, raw) = self
            .ha_request("POST", &format!("/tests/{kind}"), Some(b"{}"))
            .await?;
        match status {
            200 => {
                let mut t: ManualTest = serde_json::from_slice(&raw)
                    .map_err(|e| EngineError::BadResponse(e.to_string()))?;
                if t.kind.is_empty() {
                    t.kind = kind.to_string();
                }
                Ok(t)
            }
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }

    /// `POST /sticky-policies {policies:[...]}` — best-effort push.
    pub async fn push_sticky_policies(
        &self,
        policies: &[crate::store::StickyPolicy],
    ) -> Result<(), EngineError> {
        let body = serde_json::json!({ "policies": policies }).to_string();
        let (status, raw) = self
            .ha_request("POST", "/sticky-policies", Some(body.as_bytes()))
            .await?;
        match status {
            200 => Ok(()),
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }

    /// `POST /tunnels/probe-budget {budget}` — best-effort push.
    pub async fn set_probe_budget(&self, budget: &str) -> Result<(), EngineError> {
        let body = serde_json::json!({ "budget": budget }).to_string();
        let (status, raw) = self
            .ha_request("POST", "/tunnels/probe-budget", Some(body.as_bytes()))
            .await?;
        match status {
            200 => Ok(()),
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }
}

/// Normalize tunnel ids to uppercase A/B/C; drop anything else.
fn normalize_triple(snap: &mut TripleSnapshot) {
    for t in &mut snap.tunnels {
        t.id = t.id.to_ascii_uppercase();
    }
    snap.tunnels.retain(|t| TUNNEL_IDS.contains(&t.id.as_str()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_state_fail_closed_but_unavailable_passes_through() {
        let t = TripleTunnel {
            id: "C".to_string(),
            state: Some("unavailable".to_string()),
            ..Default::default()
        };
        assert_eq!(t.state_view(), "unavailable");
        let t = TripleTunnel {
            id: "A".to_string(),
            state: Some("weird".to_string()),
            ..Default::default()
        };
        assert_eq!(t.state_view(), "down");
        let t = TripleTunnel {
            id: "B".to_string(),
            ..Default::default()
        };
        assert_eq!(t.state_view(), "down");
    }

    #[test]
    fn ordered_tunnels_synthesizes_missing_ids() {
        let snap = TripleSnapshot {
            tunnels: vec![TripleTunnel {
                id: "A".to_string(),
                state: Some("up".to_string()),
                ..Default::default()
            }],
            from_tunnels_endpoint: true,
            ..Default::default()
        };
        let ordered = snap.ordered_tunnels();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].state_view(), "up");
        assert_eq!(ordered[1].state_view(), "down"); // missing B → down
        assert_eq!(ordered[2].family_view(), "ipv6"); // C is IPv6
    }

    #[test]
    fn sticky_policy_validation_is_fail_closed() {
        assert!(validate_sticky_policy("domain", "bank.ir", "auto", 3600, "").is_ok());
        assert!(validate_sticky_policy("asn", "bank.ir", "auto", 0, "").is_err());
        assert!(validate_sticky_policy("domain", "bank.ir", "prefer-ipv4", 0, "").is_err());
        assert!(validate_sticky_policy("domain", "", "auto", 0, "").is_err());
        assert!(validate_sticky_policy("domain", "bank.ir", "auto", 99999, "").is_err());
        let v = validate_sticky_policy("domain", "Bank.IR", "force_ipv4", 0, "").unwrap();
        assert_eq!(v.target, "bank.ir");
    }

    #[test]
    fn probe_budget_view_defaults_to_balanced() {
        let snap = TripleSnapshot::default();
        assert_eq!(snap.probe_budget_view(), "balanced");
        assert_eq!(snap.budget_options().len(), 4);
    }
}
