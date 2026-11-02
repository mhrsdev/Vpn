//! Engine-side CLASSIFY API (H3) — the admin's Rule Tester backend.
//!
//! The admin (`zero-admin`) proxies `POST /api/v1/routing/test` through the
//! engine's `POST /classify {"target": "..."}`. This module implements the
//! engine side: parse the target, apply the pushed rule-set overlay (the
//! admin's authoritative rules, delivered via `POST /ruleset`), fall back to
//! the compiled split policy, and report route / matched rule / exit country
//! / DNS policy / confidence / reason.
//!
//! Fail-closed throughout: an unparsable pushed rule-set is rejected, never
//! partially applied; an unknown target defaults to USA, never Iran.

use std::net::IpAddr;

use zero_config::routing::ipnet_lite::Cidr;
use zero_router::split::{Confidence, IranRuleSets, SplitClassification, SplitVerdict};

use crate::split_engine::SplitEngine;

/// The admin's rule kinds (`SplitRule.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushedKind {
    Domain,
    Ip,
    Cidr,
    GeoIp,
}

/// One validated rule pushed by the admin.
#[derive(Debug, Clone)]
pub struct PushedRule {
    pub id: Box<str>,
    pub kind: PushedKind,
    /// Normalized value (domains lower-cased, `*.` stripped; geoip upper-cased).
    pub value: Box<str>,
    /// Parsed networks for `Ip`/`Cidr` kinds.
    pub cidrs: Vec<Cidr>,
    pub action: SplitVerdict,
    pub priority: i64,
    pub enabled: bool,
}

/// The admin's active rule-set, as pushed via `POST /ruleset`.
#[derive(Debug, Clone)]
pub struct PushedRuleset {
    pub version: i64,
    /// Sorted by priority descending; first match wins.
    pub rules: Vec<PushedRule>,
}

/// Validate and compile a pushed rule-set. Fail-closed: any unparsable rule
/// rejects the whole push — the engine keeps serving the previous version
/// rather than a half-applied one.
pub fn parse_pushed_ruleset(
    version: i64,
    rules: &[serde_json::Value],
) -> Result<PushedRuleset, String> {
    let mut out = Vec::with_capacity(rules.len());
    for (idx, rule) in rules.iter().enumerate() {
        let path = format!("rules[{idx}]");
        let get = |key: &str| {
            rule.get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{path}.{key} is required"))
        };
        let id = get("id")?;
        let kind = match get("kind")?.to_ascii_lowercase().as_str() {
            "domain" => PushedKind::Domain,
            "ip" => PushedKind::Ip,
            "cidr" => PushedKind::Cidr,
            "geoip" => PushedKind::GeoIp,
            other => {
                return Err(format!(
                    "{path}.kind must be domain|ip|cidr|geoip, got {other:?}"
                ))
            }
        };
        let raw_value = get("value")?;
        if raw_value.trim().is_empty() || raw_value.len() > 253 {
            return Err(format!("{path}.value is required (max 253 chars)"));
        }
        let action = match get("action")?.to_ascii_lowercase().as_str() {
            "iran" => SplitVerdict::Iran,
            "usa" => SplitVerdict::Usa,
            other => return Err(format!("{path}.action must be iran|usa, got {other:?}")),
        };
        let priority = rule
            .get("priority")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if !(0..=10_000).contains(&priority) {
            return Err(format!("{path}.priority must be 0..=10000"));
        }
        let enabled = rule
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);

        // Normalize and pre-parse the value, fail-closed per kind.
        let (value, cidrs) = match kind {
            PushedKind::Domain => {
                let v = raw_value
                    .trim()
                    .strip_prefix("*.")
                    .unwrap_or(raw_value.trim())
                    .to_ascii_lowercase();
                validate_domain_shape(&v)
                    .ok_or_else(|| format!("{path}.value is not a valid domain: {raw_value:?}"))?;
                (v.into_boxed_str(), Vec::new())
            }
            PushedKind::Ip => {
                let ip: IpAddr = raw_value
                    .trim()
                    .parse()
                    .map_err(|_| format!("{path}.value is not a valid IP: {raw_value:?}"))?;
                let cidr = Cidr::parse(&ip.to_string())
                    .ok_or_else(|| format!("{path}.value is not a valid IP: {raw_value:?}"))?;
                (raw_value.trim().into(), vec![cidr])
            }
            PushedKind::Cidr => {
                let cidr = Cidr::parse(raw_value.trim())
                    .ok_or_else(|| format!("{path}.value is not a valid CIDR: {raw_value:?}"))?;
                (raw_value.trim().into(), vec![cidr])
            }
            PushedKind::GeoIp => {
                let v = raw_value.trim().to_ascii_uppercase();
                if v.len() != 2 || !v.bytes().all(|b| b.is_ascii_alphabetic()) {
                    return Err(format!(
                        "{path}.value must be a 2-letter country code, got {raw_value:?}"
                    ));
                }
                (v.into_boxed_str(), Vec::new())
            }
        };
        out.push(PushedRule {
            id: id.into(),
            kind,
            value,
            cidrs,
            action,
            priority,
            enabled,
        });
    }
    // Highest priority first; stable for equal priorities (admin order kept).
    out.sort_by(|a, b| b.priority.cmp(&a.priority));
    Ok(PushedRuleset {
        version,
        rules: out,
    })
}

fn validate_domain_shape(v: &str) -> Option<()> {
    if v.is_empty() || v.len() > 253 {
        return None;
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
            return None;
        }
    }
    Some(())
}

/// Suffix match for a domain rule (mirrors `ManualSplitRule` semantics).
fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// The outward-facing route for a classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifyRoute {
    Iran,
    Usa,
    Blocked,
}

impl ClassifyRoute {
    fn as_str(self) -> &'static str {
        match self {
            ClassifyRoute::Iran => "iran",
            ClassifyRoute::Usa => "usa",
            ClassifyRoute::Blocked => "blocked",
        }
    }
}

/// The full answer for `POST /classify`.
#[derive(Debug, Clone)]
pub struct ClassifyResult {
    pub route: ClassifyRoute,
    pub matched_rule: String,
    pub exit_country: &'static str,
    pub dns_policy: &'static str,
    pub confidence: f64,
    pub reason: String,
}

fn confidence_value(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::High => 1.0,
        Confidence::Medium => 0.65,
        Confidence::Low => 0.35,
    }
}

/// Domain-only overlay evaluation for split DNS (H3). DNS questions are
/// always names, never IP literals, so this is `apply_overlay` without the
/// IP-literal path. Returns the winning `(verdict, matched_rule)`.
pub fn apply_overlay_for_dns(
    overlay: &PushedRuleset,
    name: &str,
    iran: &IranRuleSets,
) -> Option<(SplitVerdict, String)> {
    apply_overlay(overlay, Some(name), None, iran)
}

/// Evaluate the pushed overlay against a target. Returns the winning
/// `(verdict, matched_rule)` or `None` when nothing matches.
///
/// `geoip` rules: only `IR` can be evaluated — the engine's rule data covers
/// Iranian domains/IPs. Any other country code is skipped with a debug log:
/// the engine must not guess a verdict it cannot compute.
fn apply_overlay(
    overlay: &PushedRuleset,
    target_domain: Option<&str>,
    target_ip: Option<IpAddr>,
    iran: &IranRuleSets,
) -> Option<(SplitVerdict, String)> {
    for rule in &overlay.rules {
        if !rule.enabled {
            continue;
        }
        let hit = match rule.kind {
            PushedKind::Domain => {
                target_domain.is_some_and(|domain| domain_matches_suffix(domain, &rule.value))
            }
            PushedKind::Ip | PushedKind::Cidr => {
                target_ip.is_some_and(|ip| rule.cidrs.iter().any(|cidr| cidr.contains(ip)))
            }
            PushedKind::GeoIp => {
                if rule.value.as_ref() != "IR" {
                    tracing::debug!(
                        rule = %rule.id,
                        country = %rule.value,
                        "geoip overlay rule skipped: no geodata for this country"
                    );
                    continue;
                }
                // IR: the target is Iranian per our rule data.
                let is_iranian = target_domain
                    .is_some_and(|domain| iran.match_domain(domain).is_some())
                    || target_ip.is_some_and(|ip| iran.match_ip(ip));
                is_iranian
            }
        };
        if hit {
            return Some((rule.action, format!("pushed:{}", rule.id)));
        }
    }
    None
}

/// Classify one target for the admin's Rule Tester.
///
/// `tunnel_up` is the USA-tunnel liveness signal (same bar as session
/// routing): a `Usa` verdict with a down tunnel becomes `Blocked` —
/// fail closed, never rerouted via Iran.
pub fn classify_target(
    engine: &SplitEngine,
    overlay: Option<&PushedRuleset>,
    target: &str,
    tunnel_up: bool,
) -> ClassifyResult {
    let target = target.trim();
    let target_ip: Option<IpAddr> = target.trim_matches(|c| c == '[' || c == ']').parse().ok();
    let target_domain: Option<&str> = if target_ip.is_none() && !target.is_empty() {
        Some(target)
    } else {
        None
    };

    // 1. Pushed overlay first (the admin's authoritative rules).
    if let Some(overlay) = overlay {
        if let Some((verdict, matched)) =
            apply_overlay(overlay, target_domain, target_ip, engine.iran_ruleset())
        {
            return finish(
                verdict,
                matched,
                Confidence::High,
                tunnel_up,
                "admin rule-set overlay",
            );
        }
    }

    // 2. The compiled split policy.
    let classification: SplitClassification = engine.classify_target(target);
    finish(
        match classification.verdict {
            SplitVerdict::Iran => SplitVerdict::Iran,
            SplitVerdict::Usa => SplitVerdict::Usa,
        },
        classification.matched_rule.to_string(),
        classification.confidence,
        tunnel_up,
        "split policy",
    )
}

fn finish(
    verdict: SplitVerdict,
    matched_rule: String,
    confidence: Confidence,
    tunnel_up: bool,
    source: &str,
) -> ClassifyResult {
    let (route, exit_country, reason) = match verdict {
        SplitVerdict::Iran => (
            ClassifyRoute::Iran,
            "IR",
            format!("{source}: Iranian destination → direct Iran egress (by design)"),
        ),
        SplitVerdict::Usa if tunnel_up => (
            ClassifyRoute::Usa,
            "US",
            format!("{source}: foreign/unknown destination → USA tunnel"),
        ),
        SplitVerdict::Usa => (
            ClassifyRoute::Blocked,
            "unknown",
            format!(
                "{source}: foreign/unknown destination but the USA tunnel is down → \
                 BLOCKED (fail closed, never via Iran)"
            ),
        ),
    };
    let dns_policy = match verdict {
        SplitVerdict::Iran => "direct",
        SplitVerdict::Usa => "tunnel",
    };
    ClassifyResult {
        route,
        matched_rule,
        exit_country,
        dns_policy,
        confidence: confidence_value(confidence),
        reason,
    }
}

impl ClassifyResult {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "route": self.route.as_str(),
            "matched_rule": self.matched_rule,
            "exit_country": self.exit_country,
            "dns_policy": self.dns_policy,
            "confidence": self.confidence,
            "reason": self.reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_config::model::SplitRoutingConfig;

    fn test_engine() -> SplitEngine {
        SplitEngine::build(&SplitRoutingConfig {
            tunnel_only: false,
            lan_as_iran: true,
            manual_rules: Vec::new(),
            iran_domains: Vec::new(),
            iran_cidrs: Vec::new(),
            pair_id: None,
            ruleset_path: None,
            dns_iran_tag: None,
            dns_tunnel_tag: None,
        })
    }

    fn parse_rules(version: i64, json: serde_json::Value) -> PushedRuleset {
        let rules = json.as_array().unwrap().clone();
        parse_pushed_ruleset(version, &rules).expect("test ruleset must parse")
    }

    #[test]
    fn pushed_domain_rule_wins_over_builtin() {
        let engine = test_engine();
        let overlay = parse_rules(
            3,
            serde_json::json!([
                {"id": "r1", "kind": "domain", "value": "example.com",
                 "action": "iran", "priority": 10, "enabled": true, "note": ""}
            ]),
        );
        let result = classify_target(&engine, Some(&overlay), "www.example.com", true);
        assert_eq!(result.route, ClassifyRoute::Iran);
        assert_eq!(result.matched_rule, "pushed:r1");
        assert_eq!(result.exit_country, "IR");
        assert_eq!(result.dns_policy, "direct");
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn pushed_ip_and_cidr_rules_match() {
        let engine = test_engine();
        let overlay = parse_rules(
            3,
            serde_json::json!([
                {"id": "r2", "kind": "ip", "value": "9.9.9.9",
                 "action": "usa", "priority": 5, "enabled": true, "note": ""},
                {"id": "r3", "kind": "cidr", "value": "10.99.0.0/16",
                 "action": "iran", "priority": 6, "enabled": true, "note": ""}
            ]),
        );
        let result = classify_target(&engine, Some(&overlay), "9.9.9.9", true);
        assert_eq!(result.route, ClassifyRoute::Usa);
        assert_eq!(result.matched_rule, "pushed:r2");
        // 10.99.0.0/16 is private → lan_as_iran would say Iran anyway, but the
        // pushed rule must be the reported match.
        let result = classify_target(&engine, Some(&overlay), "10.99.1.2", true);
        assert_eq!(result.matched_rule, "pushed:r3");
    }

    #[test]
    fn disabled_rules_are_ignored_and_priority_orders() {
        let engine = test_engine();
        let overlay = parse_rules(
            3,
            serde_json::json!([
                {"id": "low", "kind": "domain", "value": "example.com",
                 "action": "iran", "priority": 1, "enabled": true, "note": ""},
                {"id": "high", "kind": "domain", "value": "example.com",
                 "action": "usa", "priority": 99, "enabled": true, "note": ""},
                {"id": "off", "kind": "domain", "value": "other.com",
                 "action": "iran", "priority": 100, "enabled": false, "note": ""}
            ]),
        );
        let result = classify_target(&engine, Some(&overlay), "example.com", true);
        assert_eq!(result.matched_rule, "pushed:high");
        assert_eq!(result.route, ClassifyRoute::Usa);
        // Disabled rule never matches: other.com falls through to builtin.
        let result = classify_target(&engine, Some(&overlay), "other.com", true);
        assert_ne!(result.matched_rule, "pushed:off");
    }

    #[test]
    fn invalid_pushed_ruleset_is_rejected_whole() {
        let bad = vec![
            serde_json::json!({"id": "r1", "kind": "domain", "value": "ok.com",
                               "action": "iran", "priority": 1, "enabled": true}),
            serde_json::json!({"id": "r2", "kind": "bogus", "value": "x",
                               "action": "iran", "priority": 1, "enabled": true}),
        ];
        assert!(parse_pushed_ruleset(3, &bad).is_err());
        // One bad CIDR poisons the push too.
        let bad_cidr = vec![
            serde_json::json!({"id": "r1", "kind": "cidr", "value": "999.0.0.0/99",
                               "action": "iran", "priority": 1, "enabled": true}),
        ];
        assert!(parse_pushed_ruleset(3, &bad_cidr).is_err());
    }

    #[test]
    fn unknown_target_defaults_to_usa_never_iran() {
        let engine = test_engine();
        let result = classify_target(&engine, None, "some-unknown-site.example", true);
        assert_eq!(result.route, ClassifyRoute::Usa);
        assert_eq!(result.exit_country, "US");
        assert_eq!(result.dns_policy, "tunnel");
    }

    #[test]
    fn usa_verdict_with_down_tunnel_is_blocked() {
        let engine = test_engine();
        let result = classify_target(&engine, None, "some-unknown-site.example", false);
        assert_eq!(result.route, ClassifyRoute::Blocked);
        assert_eq!(result.exit_country, "unknown");
        assert!(result.reason.contains("fail closed"));
    }

    #[test]
    fn geoip_ir_rule_applies_to_iranian_targets() {
        let engine = test_engine();
        // digikala.com is in the v2 snapshot (verified in merge tests).
        let overlay = parse_rules(
            3,
            serde_json::json!([
                {"id": "g1", "kind": "geoip", "value": "ir",
                 "action": "usa", "priority": 50, "enabled": true, "note": ""}
            ]),
        );
        let result = classify_target(&engine, Some(&overlay), "digikala.com", true);
        assert_eq!(result.route, ClassifyRoute::Usa);
        assert_eq!(result.matched_rule, "pushed:g1");
        // Non-IR geoip cannot be evaluated: skipped, falls through.
        let overlay = parse_rules(
            3,
            serde_json::json!([
                {"id": "g2", "kind": "geoip", "value": "DE",
                 "action": "iran", "priority": 50, "enabled": true, "note": ""}
            ]),
        );
        let result = classify_target(&engine, Some(&overlay), "example.de", true);
        assert_ne!(result.matched_rule, "pushed:g2");
    }
}
