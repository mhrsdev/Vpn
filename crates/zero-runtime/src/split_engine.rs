//! The runtime side of smart split routing (LEAD DELTA, Iran gateway).
//!
//! [`SplitEngine`] compiles the `splitRouting` config block into a
//! [`SplitPolicy`] plus the Iranian rule sets, and evaluates
//! [`Decision::Split`] into a concrete outbound per session.
//!
//! Fail-closed semantics (frozen):
//! - USA exit (the wg-tunnel) down → foreign/unknown traffic is BLOCKED,
//!   never rerouted via Iran. Iranian traffic may continue direct.
//! - Iran gateway down → the VPN is disconnected; there is no direct egress.
//! - Deliberate Iranian exit for Iranian destinations is BY DESIGN, not a
//!   leak. Foreign-via-Iran or direct egress in `tunnel_only` mode IS a
//!   violation and is reported as such.

use std::net::IpAddr;
use std::sync::Arc;

use zero_config::model::SplitRoutingConfig;
use zero_config::routing::ipnet_lite::Cidr;
use zero_core::{Address, SessionContext};
use zero_router::split::{
    self, Confidence, IranRuleSets, ManualSplitRule, SplitClassification, SplitPolicy, SplitVerdict,
};
use zero_router::Decision;

/// The compiled split engine. Rebuilt on config reload and on every geodata
/// refresh (the Iranian rule sets come from the refreshed data).
pub struct SplitEngine {
    policy: SplitPolicy,
    iran: IranRuleSets,
    /// Operator overlay CIDRs, additive to geoip `ir`.
    iran_overlay_cidrs: Vec<Cidr>,
    /// The gateway's pair id, for attributing split-routed sessions to the
    /// correct pair in health/usage snapshots (modem traffic has no client
    /// outbound to attribute it to).
    pub pair_id: Option<Arc<str>>,
}

impl SplitEngine {
    /// Build from the config and the embedded v1 rule-set snapshot. The
    /// snapshot is the curated, license-clean source (see
    /// `zero_router::ruleset`); the geodata is no longer consulted for
    /// split classification.
    pub fn build(config: &SplitRoutingConfig) -> Self {
        // Rule-set snapshot: v2 (PRIMARY) from disk, v1 (FALLBACK) embedded.
        // The v2 JSON is 7MB — it is NOT embedded (stalls rustc); it loads
        // from `rulesetPath` or well-known locations. A snapshot that fails
        // validation is rejected and the embedded v1 is kept — fail closed
        // per `ruleset/RULESET.md`, never "everything is Iranian".
        // Refresh/rollback: point `rulesetPath` at the new/previous version
        // directory and reload.
        let ruleset = Self::load_snapshot(config.ruleset_path.as_deref());
        let manual_rules = config
            .manual_rules
            .iter()
            .map(|rule| ManualSplitRule {
                name: rule.name.clone(),
                domains: rule.domains.to_vec(),
                cidrs: rule
                    .cidrs
                    .iter()
                    .filter_map(|cidr| Cidr::parse(cidr))
                    .collect(),
                verdict: if rule.verdict_iran {
                    SplitVerdict::Iran
                } else {
                    SplitVerdict::Usa
                },
            })
            .collect();
        let policy = SplitPolicy {
            tunnel_only: config.tunnel_only,
            lan_as_iran: config.lan_as_iran,
            manual_rules,
        };
        let iran = IranRuleSets::from_ruleset(ruleset).with_extra_domains(&config.iran_domains);
        let iran_overlay_cidrs = config
            .iran_cidrs
            .iter()
            .filter_map(|cidr| Cidr::parse(cidr))
            .collect();
        Self {
            policy,
            iran,
            iran_overlay_cidrs,
            pair_id: config.pair_id.as_deref().map(Arc::from),
        }
    }

    /// Load the v2 PRIMARY from disk (`rulesetPath` or well-known
    /// locations), falling back to the embedded v1. Logs what it did.
    fn load_snapshot(ruleset_path: Option<&str>) -> zero_router::ruleset::RuleSet {
        let mut candidates: Vec<String> = Vec::new();
        if let Some(dir) = ruleset_path {
            candidates.push(dir.to_string());
        }
        // Well-known locations: the provisioner installs v2 here.
        candidates.push("/etc/zray/ruleset/v2".to_string());
        candidates.push("./ruleset/v2".to_string());
        for dir in candidates {
            match zero_router::ruleset::load_from_dir(&dir) {
                Ok(ruleset) => {
                    tracing::info!(
                        version = %ruleset.version,
                        updated = %ruleset.updated,
                        dir,
                        "loaded rule-set snapshot"
                    );
                    return ruleset;
                }
                Err(error) => {
                    tracing::debug!(%error, dir, "rule-set snapshot not usable here");
                }
            }
        }
        Self::embedded_fallback()
    }

    fn embedded_fallback() -> zero_router::ruleset::RuleSet {
        zero_router::ruleset::load_embedded().unwrap_or_else(|error| {
            tracing::error!(%error, "embedded v1 rule-set failed to load; split routing has no Iranian rule data");
            zero_router::ruleset::RuleSet {
                version: "unavailable".into(),
                updated: "".into(),
                domains: std::collections::HashMap::new(),
                cidrs_v4: Vec::new(),
                cidrs_v6: Vec::new(),
            }
        })
    }

    /// The compiled Iranian rule sets (for the admin's pushed `geoip:IR`
    /// overlay evaluation in `crate::classify`).
    pub fn iran_ruleset(&self) -> &IranRuleSets {
        &self.iran
    }

    /// Classify a bare target (domain or IP literal) for the admin's Rule
    /// Tester (`POST /classify`). Same policy as session evaluation, without
    /// a session context: no tunnel-liveness applied here — the caller maps
    /// a `Usa` verdict to `Blocked` when the tunnel is down.
    pub fn classify_target(&self, target: &str) -> SplitClassification {
        let target = target.trim();
        let ip: Option<IpAddr> = target.trim_matches(|c| c == '[' || c == ']').parse().ok();
        let domain: Option<&str> = if ip.is_none() && !target.is_empty() {
            Some(target)
        } else {
            None
        };
        let mut classification = split::classify(&self.policy, &self.iran, domain, false, ip);
        if classification.verdict == SplitVerdict::Usa
            && !self.policy.tunnel_only
            && ip.is_some_and(|ip| self.iran_overlay_cidrs.iter().any(|cidr| cidr.contains(ip)))
        {
            classification = SplitClassification {
                verdict: SplitVerdict::Iran,
                matched_rule: Arc::from("geoip:ir-overlay"),
                confidence: Confidence::Medium,
                sni_based: false,
            };
        }
        classification
    }

    /// Evaluate a `Decision::Split` for one session.
    ///
    /// `tunnel_up` is the liveness of the USA-tunnel outbound. When it is
    /// down, foreign/unknown traffic blackholes (fail closed); Iranian
    /// traffic still exits direct.
    pub fn evaluate(
        &self,
        ctx: &SessionContext,
        resolved: Option<IpAddr>,
        iran_tag: &Arc<str>,
        usa_tag: &Arc<str>,
        tunnel_up: bool,
    ) -> (Decision, SplitClassification) {
        let domain = ctx
            .destination
            .address
            .as_domain()
            .or_else(|| ctx.sniffed.domain.as_deref());
        let sni_based = ctx.destination.address.as_domain().is_none() && domain.is_some();
        let ip = match &ctx.destination.address {
            Address::Ip(ip) => Some(*ip),
            Address::Domain(_) => resolved,
        };
        let mut classification = split::classify(&self.policy, &self.iran, domain, sni_based, ip);
        if classification.verdict == SplitVerdict::Usa
            && !self.policy.tunnel_only
            && ip.is_some_and(|ip| self.iran_overlay_cidrs.iter().any(|cidr| cidr.contains(ip)))
        {
            classification = SplitClassification {
                verdict: SplitVerdict::Iran,
                matched_rule: Arc::from("geoip:ir-overlay"),
                confidence: Confidence::Medium,
                sni_based,
            };
        }
        let decision = match classification.verdict {
            SplitVerdict::Iran => Decision::Outbound(iran_tag.clone()),
            SplitVerdict::Usa if tunnel_up => Decision::Outbound(usa_tag.clone()),
            // Fail closed: the USA exit is down, so foreign traffic is
            // blocked — never rerouted via Iran.
            SplitVerdict::Usa => Decision::Block,
        };
        (decision, classification)
    }
}
