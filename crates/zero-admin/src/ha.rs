//! Inter-server High Availability (owner HA addendum, binding).
//!
//! The Iran→USA leg runs Tunnel A (primary) + Tunnel B (hot standby), both
//! connected/authenticated/ready with independent keepalives. The ROUTING
//! agent owns the failover machinery; this module is the admin's read/control
//! surface over the engine's HA contract.
//!
//! ## Frozen admin↔app contract (`/api/v1/ha/*`, see CONTRACT-ha.md)
//!
//! - `GET /api/v1/ha/status` → tunnels, primary, mode, available_modes,
//!   auto_recovery, heartbeat_interval_s, failover_threshold_missed,
//!   last_failover_at (millis), failover_count, total_downtime_s (MEASURED
//!   only), recent_failovers, exit. Tunnel state: up|degraded|standby|down.
//! - `POST /api/v1/ha/primary` `{tunnel:"A"|"B"}` → `{ok, primary}`.
//! - `POST /api/v1/ha/mode` `{mode}` → `{ok, mode}` (only modes in
//!   `available_modes`; active_active only when the engine really implements
//!   it — otherwise the backend offers hot_standby alone).
//! - `POST /api/v1/ha/settings`
//!   `{heartbeat_interval_s?, failover_threshold_missed?, auto_recovery?}`.
//!
//! ## Assumed engine contract (routing agent implements; coordinate)
//!
//! - `GET /ha` → snapshot JSON (preferred). Fallback: `GET /tunnel` with an
//!   `ha` field of the same shape. Field names and units match the app
//!   contract above (epoch MILLIS, snake_case modes).
//! - `POST /ha/primary` `{"tunnel": "A"|"B"}` → manual primary selection.
//! - `POST /ha/mode` `{"mode": "hot_standby"|"active_active"}`.
//! - `POST /ha/settings` `{heartbeat_interval_s?, failover_threshold_missed?,
//!   auto_recovery?}`.
//!
//! ## Honesty rules (binding)
//!
//! - Tunnel state unknown/missing → **down** (fail-closed). There is no
//!   "unknown" tunnel state on the wire.
//! - Downtime values are MEASURED only, never estimated. `total_downtime_s`
//!   is emitted only when the engine measured it (`downtime_measured`);
//!   otherwise it is 0.0 and the panel says "not measured".
//! - An engine without the HA surface yields `supported: false`; the admin
//!   labels the surface honestly instead of inventing values.

use crate::engine::{EngineClient, EngineError};
use serde::{Deserialize, Serialize};

/// Tunnel states on the wire. Unknown/missing input maps to `Down`
/// (fail-closed) — see [`tunnel_state_of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    Up,
    Degraded,
    Standby,
    Down,
}

impl TunnelState {
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelState::Up => "up",
            TunnelState::Degraded => "degraded",
            TunnelState::Standby => "standby",
            TunnelState::Down => "down",
        }
    }
}

/// Fail-closed mapping: anything that is not an explicit healthy-ish state
/// becomes `down`. Unknown is never surfaced as a state.
pub fn tunnel_state_of(raw: Option<&str>) -> TunnelState {
    match raw.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("up") => TunnelState::Up,
        Some("degraded") => TunnelState::Degraded,
        Some("standby") => TunnelState::Standby,
        _ => TunnelState::Down,
    }
}

/// Normalize engine mode spellings to the frozen `hot_standby|active_active`.
pub fn normalize_mode(raw: Option<&str>) -> String {
    match raw.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("active_active") | Some("active-active") => "active_active".to_string(),
        _ => "hot_standby".to_string(),
    }
}

/// One inter-server tunnel (A or B), as reported by the engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaTunnel {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub transport_family: Option<String>,
    /// Raw engine state; use [`tunnel_state_of`] for the fail-closed view.
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
    /// Epoch millis; None = unknown.
    #[serde(default)]
    pub last_heartbeat_at: Option<i64>,
    #[serde(default)]
    pub bytes_up: u64,
    #[serde(default)]
    pub bytes_down: u64,
}

/// Failover history counters (engine-measured).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaFailovers {
    #[serde(default)]
    pub count: u64,
    /// Epoch millis; None = none recorded.
    #[serde(default)]
    pub last_at: Option<i64>,
    /// Real MEASURED downtime of the last failover, seconds. None = not
    /// measured — never synthesized, never estimated.
    #[serde(default)]
    pub last_downtime_s: Option<f64>,
    /// Cumulative MEASURED downtime, seconds. None = not measured.
    #[serde(default)]
    pub total_downtime_s: Option<f64>,
}

/// USA exit as seen through the HA leg.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaExit {
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub healthy: Option<bool>,
    /// Epoch millis.
    #[serde(default)]
    pub checked_at: Option<i64>,
    /// Transport-level failover keeps the same USA exit IP.
    #[serde(default)]
    pub ip_stable: Option<bool>,
}

/// Full HA snapshot from the engine. Absent fields stay absent.
///
/// The frozen app contract carries failover counters as TOP-LEVEL fields
/// (epoch millis for `last_failover_at`); the nested `failovers` object is
/// accepted as a fallback for engines that nest them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaSnapshot {
    #[serde(default)]
    pub tunnels: Vec<HaTunnel>,
    #[serde(default)]
    pub primary: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub available_modes: Vec<String>,
    #[serde(default)]
    pub auto_recovery: Option<bool>,
    #[serde(default)]
    pub heartbeat_interval_s: Option<u64>,
    #[serde(default)]
    pub failover_threshold_missed: Option<u64>,
    /// Epoch millis; None = none recorded.
    #[serde(default)]
    pub last_failover_at: Option<i64>,
    #[serde(default)]
    pub failover_count: Option<u64>,
    /// Cumulative MEASURED downtime, seconds. None = not measured.
    #[serde(default)]
    pub total_downtime_s: Option<f64>,
    #[serde(default)]
    pub failovers: HaFailovers,
    #[serde(default)]
    pub exit: HaExit,
    /// True when the data came from the real HA contract (not the fallback).
    #[serde(skip)]
    pub from_ha_endpoint: bool,
}

impl HaSnapshot {
    /// Snapshot marking "engine predates the HA contract".
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn supported(&self) -> bool {
        self.from_ha_endpoint || !self.tunnels.is_empty() || self.primary.is_some()
    }

    pub fn tunnel(&self, id: &str) -> Option<&HaTunnel> {
        self.tunnels.iter().find(|t| t.id == id)
    }

    /// Modes the admin may offer for switching. The engine's own list wins;
    /// otherwise only hot_standby (active_active is INVESTIGATED, not assumed).
    pub fn offered_modes(&self) -> Vec<String> {
        if self.available_modes.is_empty() {
            vec!["hot_standby".to_string()]
        } else {
            self.available_modes.clone()
        }
    }

    pub fn mode_view(&self) -> String {
        normalize_mode(self.mode.as_deref())
    }
}

/// One failover event for `recent_failovers` — from the admin's own event
/// log (real observed transitions), not from the engine.
#[derive(Debug, Clone, Serialize)]
pub struct HaFailoverEvent {
    /// Epoch millis.
    pub at: i64,
    pub from: Option<String>,
    pub to: Option<String>,
    pub reason: String,
    /// Measured seconds; None = not measured (serialized as null, never 0.0
    /// masquerading as a measurement).
    pub downtime_s: Option<f64>,
    /// Not measured by the admin → always None (serialized null).
    pub sessions_preserved_pct: Option<f64>,
}

/// Honest 3-level failover distinction (owner addendum). Rendered in the
/// panel; never claim "zero downtime" without measured proof.
pub const HA_HONESTY: &str = "Failover honesty levels: (1) fast switch for NEW connections — new connections go to the healthy path immediately; (2) session preservation — existing sessions are preserved as much as the transport allows; (3) true lossless — NOT claimed without measured proof on the real link. Both tunnels down: foreign traffic fails closed, Iranian destinations may continue direct.";

impl EngineClient {
    /// Fetch the HA snapshot: `GET /ha`, falling back to `GET /tunnel`'s
    /// `ha` field. Returns `HaSnapshot::unknown()` when the engine has no
    /// HA surface (never an error for a missing contract — only for an
    /// unreachable engine).
    pub async fn ha_snapshot(&self) -> Result<HaSnapshot, EngineError> {
        match self.ha_direct().await {
            Ok(s) => Ok(s),
            Err(EngineError::Status(404, _)) => self.ha_via_tunnel().await,
            Err(e) => Err(e),
        }
    }

    async fn ha_direct(&self) -> Result<HaSnapshot, EngineError> {
        let v = self.ha_get_json("/ha").await?;
        let mut s: HaSnapshot =
            serde_json::from_value(v).map_err(|e| EngineError::BadResponse(e.to_string()))?;
        s.from_ha_endpoint = true;
        Ok(s)
    }

    async fn ha_via_tunnel(&self) -> Result<HaSnapshot, EngineError> {
        match self.tunnel().await {
            Ok(v) => match v.get("ha") {
                Some(ha) => {
                    let mut s: HaSnapshot = serde_json::from_value(ha.clone())
                        .map_err(|e| EngineError::BadResponse(e.to_string()))?;
                    s.from_ha_endpoint = false;
                    Ok(s)
                }
                None => Ok(HaSnapshot::unknown()),
            },
            Err(EngineError::Status(404, _)) => Ok(HaSnapshot::unknown()),
            Err(e) => Err(e),
        }
    }

    /// `POST /ha/primary {"tunnel": "A"|"B"}` — manual primary selection.
    pub async fn ha_set_primary(&self, tunnel: &str) -> Result<serde_json::Value, EngineError> {
        let body = serde_json::json!({ "tunnel": tunnel }).to_string();
        let (status, raw) = self
            .ha_request("POST", "/ha/primary", Some(body.as_bytes()))
            .await?;
        match status {
            200 => {
                serde_json::from_slice(&raw).map_err(|e| EngineError::BadResponse(e.to_string()))
            }
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }

    /// `POST /ha/mode {"mode": "hot_standby"|"active_active"}`.
    pub async fn ha_set_mode(&self, mode: &str) -> Result<serde_json::Value, EngineError> {
        let body = serde_json::json!({ "mode": mode }).to_string();
        let (status, raw) = self
            .ha_request("POST", "/ha/mode", Some(body.as_bytes()))
            .await?;
        match status {
            200 => {
                serde_json::from_slice(&raw).map_err(|e| EngineError::BadResponse(e.to_string()))
            }
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }

    /// `POST /ha/settings {...}` — HA tuning. Only validated keys are sent.
    pub async fn ha_post_settings(
        &self,
        settings: &serde_json::Value,
    ) -> Result<serde_json::Value, EngineError> {
        let body = settings.to_string();
        let (status, raw) = self
            .ha_request("POST", "/ha/settings", Some(body.as_bytes()))
            .await?;
        match status {
            200 => {
                serde_json::from_slice(&raw).map_err(|e| EngineError::BadResponse(e.to_string()))
            }
            _ => Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_state_is_fail_closed_down() {
        assert_eq!(tunnel_state_of(None), TunnelState::Down);
        assert_eq!(tunnel_state_of(Some("")), TunnelState::Down);
        assert_eq!(tunnel_state_of(Some("unknown")), TunnelState::Down);
        assert_eq!(tunnel_state_of(Some("weird")), TunnelState::Down);
        assert_eq!(tunnel_state_of(Some("up")), TunnelState::Up);
        assert_eq!(tunnel_state_of(Some("degraded")), TunnelState::Degraded);
        assert_eq!(tunnel_state_of(Some("standby")), TunnelState::Standby);
        assert_eq!(tunnel_state_of(Some("UP")), TunnelState::Up);
    }

    #[test]
    fn mode_normalization() {
        assert_eq!(normalize_mode(None), "hot_standby");
        assert_eq!(normalize_mode(Some("hot-standby")), "hot_standby");
        assert_eq!(normalize_mode(Some("active-active")), "active_active");
        assert_eq!(normalize_mode(Some("active_active")), "active_active");
    }

    #[test]
    fn offered_modes_default_to_hot_standby_only() {
        let s = HaSnapshot::unknown();
        assert_eq!(s.offered_modes(), vec!["hot_standby".to_string()]);
        let mut s2 = HaSnapshot::unknown();
        s2.available_modes = vec!["hot_standby".to_string(), "active_active".to_string()];
        assert_eq!(s2.offered_modes().len(), 2);
    }

    #[test]
    fn unknown_snapshot_is_not_supported() {
        assert!(!HaSnapshot::unknown().supported());
    }

    #[test]
    fn ha_honesty_disclaims_zero_downtime() {
        assert!(HA_HONESTY.contains("NOT claimed without measured proof"));
        assert!(HA_HONESTY.contains("fails closed"));
    }
}
