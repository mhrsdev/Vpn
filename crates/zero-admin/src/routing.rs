//! Smart split-routing rule management (owner prompt v2 / LEAD DELTA).
//!
//! The Iran gateway classifies destinations: Iranian → direct Iran egress,
//! foreign/unknown → USA tunnel (unknown defaults to USA — never to Iran
//! egress, never to direct).
//!
//! The admin is the authoritative rule store (versioned, validated,
//! rollback-able — see `store::RoutingRuleset`). The ROUTING agent owns the
//! classifier engine; the admin pushes the ACTIVE rule-set to it and proxies
//! the rule tester through the engine's CLASSIFY API:
//!
//! ## Assumed engine contract (routing agent implements; coordinate)
//!
//! - `POST /classify {"target": "example.com"}` →
//!   `{route: "iran"|"usa"|"blocked", matched_rule: {...}?, exit_country:
//!   "IR"|"US"|"unknown"?, dns_policy: "direct"|"tunnel"?, confidence: 0..1,
//!   reason: "..."}`.
//! - `POST /ruleset {version, rules:[...]}` → applies the pushed rule-set.
//!
//! Both are best-effort until the routing agent's contract lands: the tester
//! returns 502 (never a guessed answer) and rule pushes are marked pending.

use crate::engine::{EngineClient, EngineError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("bad rule: {0}")]
    BadRule(String),
}

/// A validated rule, ready to store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidRule {
    pub kind: String,
    pub value: String,
    pub action: String,
    pub priority: i64,
    pub enabled: bool,
    pub note: String,
}

/// Validate a rule's kind/value/action. Fail-closed: anything unparsable is
/// rejected (it must never silently misroute).
pub fn validate_rule(
    kind: &str,
    value: &str,
    action: &str,
    priority: i64,
    note: &str,
) -> Result<ValidRule, RoutingError> {
    let kind = kind.trim().to_ascii_lowercase();
    if !matches!(kind.as_str(), "domain" | "ip" | "cidr" | "geoip") {
        return Err(RoutingError::BadRule(format!(
            "kind must be domain|ip|cidr|geoip, got {kind:?}"
        )));
    }
    let value = value.trim();
    if value.is_empty() || value.len() > 253 {
        return Err(RoutingError::BadRule(
            "value is required (max 253 chars)".to_string(),
        ));
    }
    match kind.as_str() {
        "domain" => validate_domain(value)?,
        "ip" => {
            value
                .parse::<std::net::IpAddr>()
                .map_err(|_| RoutingError::BadRule(format!("invalid IP {value:?}")))?;
        }
        "cidr" => {
            parse_cidr(value)
                .ok_or_else(|| RoutingError::BadRule(format!("invalid CIDR {value:?}")))?;
        }
        "geoip" => {
            let v = value.to_ascii_uppercase();
            if v.len() != 2 || !v.bytes().all(|b| b.is_ascii_alphabetic()) {
                return Err(RoutingError::BadRule(format!(
                    "geoip value must be a 2-letter country code, got {value:?}"
                )));
            }
        }
        _ => unreachable!(),
    }
    let action = action.trim().to_ascii_lowercase();
    if !matches!(action.as_str(), "iran" | "usa") {
        return Err(RoutingError::BadRule(format!(
            "action must be iran|usa, got {action:?}"
        )));
    }
    if !(0..=10_000).contains(&priority) {
        return Err(RoutingError::BadRule(
            "priority must be 0..=10000".to_string(),
        ));
    }
    if note.len() > 500 {
        return Err(RoutingError::BadRule("note too long (max 500)".to_string()));
    }
    let value = if kind == "geoip" {
        value.to_ascii_uppercase()
    } else if kind == "domain" {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    };
    Ok(ValidRule {
        kind,
        value,
        action,
        priority,
        enabled: true,
        note: note.to_string(),
    })
}

fn validate_domain(value: &str) -> Result<(), RoutingError> {
    let v = value.strip_prefix("*.").unwrap_or(value);
    if v.is_empty() || v.len() > 253 {
        return Err(RoutingError::BadRule(format!("invalid domain {value:?}")));
    }
    for label in v.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(RoutingError::BadRule(format!("invalid domain {value:?}")));
        }
    }
    Ok(())
}

/// Parse `addr/prefix` for IPv4/IPv6 CIDR. Returns (network_int as u128, bits).
fn parse_cidr(cidr: &str) -> Option<(u128, u32)> {
    let (addr, bits) = cidr.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    let ip: std::net::IpAddr = addr.parse().ok()?;
    let max_bits = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    if bits > max_bits {
        return None;
    }
    let n: u128 = match ip {
        std::net::IpAddr::V4(v4) => u32::from(v4) as u128,
        std::net::IpAddr::V6(v6) => u128::from(v6),
    };
    Some((n, bits))
}

fn cidr_network(cidr: &str) -> Option<(u128, u128)> {
    let (n, bits) = parse_cidr(cidr)?;
    let total = if cidr.contains(':') { 128 } else { 32 };
    let mask = if bits == 0 {
        0
    } else {
        (!0u128) << (total - bits)
    };
    Some((n & mask, mask))
}

/// Conflict check against existing rules of the same version. Returns human
/// warnings (not hard errors — the owner may intend overrides; priority
/// decides). Checks: same kind+value with a different action; overlapping
/// CIDRs with different actions.
pub fn check_conflicts(
    candidate: &ValidRule,
    existing: &[crate::store::SplitRule],
    exclude_id: Option<&str>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for r in existing {
        if Some(r.id.as_str()) == exclude_id || !r.enabled {
            continue;
        }
        if r.kind == candidate.kind && r.value == candidate.value && r.action != candidate.action {
            warnings.push(format!(
                "conflict: rule {} already maps {} {:?} to {:?} (priority {})",
                r.id, r.kind, r.value, r.action, r.priority
            ));
        }
        if candidate.kind == "cidr" && r.kind == "cidr" && r.action != candidate.action {
            if let (Some((n1, m1)), Some((n2, m2))) =
                (cidr_network(&candidate.value), cidr_network(&r.value))
            {
                // Overlap if either network contains the other's base.
                let overlap = (n1 & m2) == n2 || (n2 & m1) == n1;
                if overlap {
                    warnings.push(format!(
                        "overlap: CIDR {} ({}) overlaps {} ({}, priority {})",
                        candidate.value, candidate.action, r.value, r.action, r.priority
                    ));
                }
            }
        }
    }
    warnings
}

/// The rule-test result, proxied from the engine's CLASSIFY API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteTest {
    pub route: String,
    pub matched_rule: Option<serde_json::Value>,
    pub exit_country: Option<String>,
    pub dns_policy: Option<String>,
    pub confidence: f64,
    pub reason: String,
}

impl EngineClient {
    /// `POST /classify {"target"}` — the rule tester. Defensive parse: the
    /// engine is authoritative; missing fields get honest defaults, never
    /// invented values.
    pub async fn classify(&self, target: &str) -> Result<RouteTest, EngineError> {
        let body = serde_json::json!({ "target": target }).to_string();
        let (status, raw) = self
            .ha_request("POST", "/classify", Some(body.as_bytes()))
            .await?;
        if status == 404 {
            return Err(EngineError::Status(
                404,
                "engine has no CLASSIFY API".to_string(),
            ));
        }
        if status != 200 {
            return Err(EngineError::Status(
                status,
                String::from_utf8_lossy(&raw).into_owned(),
            ));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| EngineError::BadResponse(e.to_string()))?;
        Ok(RouteTest {
            route: v
                .get("route")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown")
                .to_string(),
            matched_rule: v.get("matched_rule").cloned(),
            exit_country: v
                .get("exit_country")
                .and_then(|r| r.as_str())
                .map(str::to_string),
            dns_policy: v
                .get("dns_policy")
                .and_then(|r| r.as_str())
                .map(str::to_string),
            confidence: v.get("confidence").and_then(|r| r.as_f64()).unwrap_or(0.0),
            reason: v
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Push the active rule-set to the engine (`POST /ruleset`).
    pub async fn push_ruleset(
        &self,
        version: i64,
        rules: &[crate::store::SplitRule],
    ) -> Result<serde_json::Value, EngineError> {
        let body = serde_json::json!({
            "version": version,
            "rules": rules.iter().map(|r| serde_json::json!({
                "id": r.id, "kind": r.kind, "value": r.value,
                "action": r.action, "priority": r.priority,
                "enabled": r.enabled, "note": r.note,
            })).collect::<Vec<_>>(),
        })
        .to_string();
        let (status, raw) = self
            .ha_request("POST", "/ruleset", Some(body.as_bytes()))
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
    fn validate_kinds() {
        assert!(validate_rule("domain", "bank.ir", "iran", 10, "").is_ok());
        assert!(validate_rule("domain", "*.bank.ir", "iran", 10, "").is_ok());
        assert!(validate_rule("ip", "5.6.7.8", "usa", 10, "").is_ok());
        assert!(validate_rule("ip", "2001:db8::1", "iran", 10, "").is_ok());
        assert!(validate_rule("cidr", "5.6.0.0/16", "iran", 10, "").is_ok());
        assert!(validate_rule("geoip", "ir", "iran", 10, "").is_ok());
        assert!(validate_rule("domain", "not a domain!", "iran", 10, "").is_err());
        assert!(validate_rule("ip", "999.1.1.1", "iran", 10, "").is_err());
        assert!(validate_rule("cidr", "5.6.0.0/33", "iran", 10, "").is_err());
        assert!(validate_rule("geoip", "IRAN", "iran", 10, "").is_err());
        assert!(validate_rule("domain", "bank.ir", "moon", 10, "").is_err());
        assert!(validate_rule("asn", "123", "iran", 10, "").is_err());
    }

    #[test]
    fn conflict_detection() {
        let existing = vec![crate::store::SplitRule {
            id: "r1".to_string(),
            version: 1,
            kind: "domain".to_string(),
            value: "bank.ir".to_string(),
            action: "iran".to_string(),
            priority: 10,
            enabled: true,
            note: String::new(),
        }];
        let cand = validate_rule("domain", "bank.ir", "usa", 20, "").unwrap();
        let w = check_conflicts(&cand, &existing, None);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("conflict"));
        // Excluding the rule itself: no warning.
        let w2 = check_conflicts(&cand, &existing, Some("r1"));
        assert!(w2.is_empty());
    }

    #[test]
    fn cidr_overlap_detection() {
        let existing = vec![crate::store::SplitRule {
            id: "r1".to_string(),
            version: 1,
            kind: "cidr".to_string(),
            value: "5.6.0.0/16".to_string(),
            action: "iran".to_string(),
            priority: 10,
            enabled: true,
            note: String::new(),
        }];
        let cand = validate_rule("cidr", "5.6.7.0/24", "usa", 20, "").unwrap();
        let w = check_conflicts(&cand, &existing, None);
        assert!(w.iter().any(|x| x.contains("overlap")));
    }
}
