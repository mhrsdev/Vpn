//! Smart split routing: classify each destination as Iranian (direct Iran
//! egress) or foreign/unknown (USA tunnel).
//!
//! Classification sources, in priority order (frozen contract):
//!
//! 1. Unbreakable security policies (`tunnel_only`: everything via the USA
//!    tunnel, e.g. the strictest mode).
//! 2. LAN/local network exceptions (private/loopback/link-local IPs).
//! 3. User manual rules (domains, IPs, with Iran/USA assignment).
//! 4. Iranian domain rules (v1 snapshot + operator overlays).
//! 5. Iranian IP rules (v1 snapshot + operator overlays).
//! 6. Default → USA exit. Unknown defaults to USA, NEVER Iran.
//!
//! A `.ir` suffix alone is NOT sufficient: some Iranian services use `.com`
//! and some foreign sites use Iranian IPs/CDN. The rule sets above are the
//! mechanism; the suffix is just one signal among many.
//!
//! Encrypted traffic: where the inner destination is not visible
//! (already-encrypted streams), classification uses what is visible at the
//! handshake (SNI/IP). The [`Confidence`] on every classification says how
//! much that is worth — never claim per-request certainty you do not have.

use std::net::IpAddr;
use std::sync::Arc;

use zero_config::routing::ipnet_lite::Cidr;

use super::matcher::is_private_ip;

/// Where a classified destination exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitVerdict {
    /// Direct Iran egress (Iranian destination).
    Iran,
    /// Through the wg-tunnel to the USA exit (foreign or unknown).
    Usa,
}

/// How much the classification is worth. SNI-based and IP-only
/// classifications are inherently weaker than explicit domain or manual
/// matches — the confidence says so instead of pretending otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// One user manual rule: domains (suffix match) and/or IP CIDRs with an
/// explicit Iran/USA assignment. Rules are evaluated in config order; the
/// first match wins.
#[derive(Debug, Clone)]
pub struct ManualSplitRule {
    pub name: Box<str>,
    pub domains: Vec<Box<str>>,
    pub cidrs: Vec<Cidr>,
    pub verdict: SplitVerdict,
}

/// The split-routing policy. The rule data (geosite/geoip `ir`) comes from
/// the [`GeoData`] passed to [`classify`], which the runtime keeps current
/// through the asset pipeline; manual rules are inline config.
#[derive(Debug, Clone, Default)]
pub struct SplitPolicy {
    /// Unbreakable security policy: when true, every destination goes via
    /// the USA tunnel. Overrides everything below.
    pub tunnel_only: bool,
    /// Private/loopback/link-local destinations count as local (Iran).
    /// Default true.
    pub lan_as_iran: bool,
    pub manual_rules: Vec<ManualSplitRule>,
}

impl SplitPolicy {
    pub fn disabled() -> Self {
        Self {
            tunnel_only: true,
            lan_as_iran: true,
            manual_rules: Vec::new(),
        }
    }
}

/// The outcome of classifying one destination.
#[derive(Debug, Clone)]
pub struct SplitClassification {
    pub verdict: SplitVerdict,
    /// Which rule matched, for the rule tester and the logs, e.g.
    /// `security:tunnel-only`, `lan`, `manual:office`, `geosite:ir`,
    /// `geoip:ir`, `default:usa`.
    pub matched_rule: Arc<str>,
    pub confidence: Confidence,
    /// Whether the domain came from SNI sniffing rather than an explicit
    /// domain destination. SNI is weaker evidence (it can be absent,
    /// mismatched, or ECH-encrypted).
    pub sni_based: bool,
}

/// The compiled Iranian rule sets: the versioned v1 snapshot (curated
/// domains + RIPE-derived CIDRs) plus the operator overlays. Built once per
/// config load / snapshot refresh; `classify` borrows it.
///
/// The v1 snapshot replaced the geosite:ir / geoip:ir rule data: those
/// sources are either license-incompatible (GPL/CC-BY-SA — rejected, see
/// `ruleset/RULESET.md`) or have no Iranian list at all.
pub struct IranRuleSets {
    ruleset: super::ruleset::RuleSet,
    /// Operator overlay domains (additive to the snapshot).
    extra_domains: Vec<Box<str>>,
}

impl IranRuleSets {
    pub fn from_ruleset(ruleset: super::ruleset::RuleSet) -> Self {
        Self {
            ruleset,
            extra_domains: Vec::new(),
        }
    }

    pub fn with_extra_domains(mut self, domains: &[Box<str>]) -> Self {
        self.extra_domains = domains.to_vec();
        self
    }

    /// The snapshot version, for the panel (RULESET.md: the panel must show
    /// the snapshot version/date).
    pub fn version(&self) -> &str {
        &self.ruleset.version
    }

    pub fn updated(&self) -> &str {
        &self.ruleset.updated
    }

    /// Match a domain against the snapshot (returns the matched suffix for
    /// the Rule Tester) or the operator overlay.
    pub fn match_domain(&self, domain: &str) -> Option<String> {
        if let Some(entry) = self.ruleset.match_domain(domain) {
            return Some(format!("ruleset:{}:{}", self.ruleset.version, entry.suffix));
        }
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        for extra in &self.extra_domains {
            let suffix = extra.trim().trim_end_matches('.').to_ascii_lowercase();
            if domain == suffix
                || domain
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
            {
                return Some(format!("overlay:{extra}"));
            }
        }
        None
    }

    pub fn match_ip(&self, ip: IpAddr) -> bool {
        self.ruleset.match_ip(ip)
    }

    pub fn empty() -> Self {
        Self {
            ruleset: super::ruleset::RuleSet {
                version: "empty".into(),
                updated: "".into(),
                domains: std::collections::HashMap::new(),
                cidrs_v4: Vec::new(),
                cidrs_v6: Vec::new(),
            },
            extra_domains: Vec::new(),
        }
    }
}

/// Classify one destination.
///
/// * `domain`: the domain the client asked for, or the SNI sniffed from a
///   TLS handshake (`sni_based` says which).
/// * `ip`: the destination IP, when the destination is an IP literal or has
///   been resolved.
///
/// Priority: security policy → LAN → manual rules → Iranian domains →
/// Iranian IPs → default USA.
pub fn classify(
    policy: &SplitPolicy,
    rules: &IranRuleSets,
    domain: Option<&str>,
    sni_based: bool,
    ip: Option<IpAddr>,
) -> SplitClassification {
    if policy.tunnel_only {
        return SplitClassification {
            verdict: SplitVerdict::Usa,
            matched_rule: Arc::from("security:tunnel-only"),
            confidence: Confidence::High,
            sni_based: false,
        };
    }
    if let Some(ip) = ip {
        if policy.lan_as_iran && is_private_ip(ip) {
            return SplitClassification {
                verdict: SplitVerdict::Iran,
                matched_rule: Arc::from("lan"),
                confidence: Confidence::High,
                sni_based: false,
            };
        }
    }
    for rule in &policy.manual_rules {
        let domain_hit = domain.is_some_and(|domain| {
            rule.domains
                .iter()
                .any(|suffix| domain_matches_suffix(domain, suffix))
        });
        let ip_hit = ip.is_some_and(|ip| rule.cidrs.iter().any(|cidr| cidr.contains(ip)));
        if domain_hit || ip_hit {
            return SplitClassification {
                verdict: rule.verdict,
                matched_rule: Arc::from(format!("manual:{}", rule.name).as_str()),
                confidence: Confidence::High,
                sni_based: sni_based && domain_hit,
            };
        }
    }
    if let Some(domain) = domain {
        if let Some(matched) = rules.match_domain(domain) {
            // A `.ir` suffix alone is not sufficient — but a match against
            // the curated v1 snapshot (which covers .ir AND Iranian services
            // on other TLDs) is.
            return SplitClassification {
                verdict: SplitVerdict::Iran,
                matched_rule: Arc::from(matched.as_str()),
                confidence: if sni_based {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
                sni_based,
            };
        }
    }
    if let Some(ip) = ip {
        if rules.match_ip(ip) {
            return SplitClassification {
                verdict: SplitVerdict::Iran,
                matched_rule: Arc::from(format!("ruleset:{}:ip", rules.version()).as_str()),
                // An Iranian IP can front foreign content (CDN): strong but
                // not absolute.
                confidence: Confidence::Medium,
                sni_based,
            };
        }
    }
    // Unknown defaults to USA, NEVER Iran.
    SplitClassification {
        verdict: SplitVerdict::Usa,
        matched_rule: Arc::from("default:usa"),
        confidence: Confidence::Low,
        sni_based,
    }
}

/// Suffix match at a label boundary: `example.ir` matches `example.ir` and
/// `www.example.ir`, but not `notexample.ir`.
fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
    domain == suffix
        || domain
            .strip_suffix(suffix.as_str())
            .is_some_and(|rest| rest.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SplitPolicy {
        SplitPolicy {
            tunnel_only: false,
            lan_as_iran: true,
            manual_rules: vec![ManualSplitRule {
                name: "office".into(),
                domains: vec!["office.example.com".into()],
                cidrs: vec![Cidr::parse("1.2.3.0/24").unwrap()],
                verdict: SplitVerdict::Usa,
            }],
        }
    }

    fn ruleset() -> super::super::ruleset::RuleSet {
        // v2 PRIMARY from disk (not embedded).
        super::super::ruleset::load_from_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/ruleset/v2"))
            .expect("v2 ruleset must load")
    }

    fn rules() -> IranRuleSets {
        IranRuleSets::from_ruleset(ruleset())
    }

    #[test]
    fn tunnel_only_overrides_everything() {
        let policy = SplitPolicy::disabled();
        let rules = rules();
        let classification = classify(&policy, &rules, Some("digikala.com"), false, None);
        assert_eq!(classification.verdict, SplitVerdict::Usa);
        assert_eq!(classification.matched_rule.as_ref(), "security:tunnel-only");
    }

    #[test]
    fn lan_addresses_stay_local() {
        let policy = policy();
        let rules = rules();
        let classification = classify(
            &policy,
            &rules,
            None,
            false,
            Some("192.168.1.10".parse().unwrap()),
        );
        assert_eq!(classification.verdict, SplitVerdict::Iran);
        assert_eq!(classification.matched_rule.as_ref(), "lan");
        assert_eq!(classification.confidence, Confidence::High);
    }

    #[test]
    fn manual_rules_beat_the_rule_sets() {
        let policy = policy();
        let rules = rules();
        // office.example.com is manual → USA even though nothing else matches.
        let classification = classify(&policy, &rules, Some("office.example.com"), false, None);
        assert_eq!(classification.verdict, SplitVerdict::Usa);
        assert_eq!(classification.matched_rule.as_ref(), "manual:office");
        // A manual CIDR also wins over geoip.
        let classification = classify(
            &policy,
            &rules,
            None,
            false,
            Some("1.2.3.44".parse().unwrap()),
        );
        assert_eq!(classification.verdict, SplitVerdict::Usa);
    }

    #[test]
    fn iranian_domain_rules_match() {
        let policy = policy();
        let rules = rules();
        let classification = classify(&policy, &rules, Some("digikala.com"), false, None);
        assert_eq!(classification.verdict, SplitVerdict::Iran);
        assert_eq!(
            classification.matched_rule.as_ref(),
            "ruleset:v2:digikala.com"
        );
        assert_eq!(classification.confidence, Confidence::High);
        // SNI-based: same verdict, weaker confidence.
        let classification = classify(&policy, &rules, Some("digikala.com"), true, None);
        assert_eq!(classification.verdict, SplitVerdict::Iran);
        assert_eq!(classification.confidence, Confidence::Medium);
        assert!(classification.sni_based);
    }

    #[test]
    fn iranian_ip_rules_match() {
        let policy = policy();
        let rules = rules();
        let classification = classify(
            &policy,
            &rules,
            None,
            false,
            Some("2.57.3.44".parse().unwrap()),
        );
        assert_eq!(classification.verdict, SplitVerdict::Iran);
        assert!(classification
            .matched_rule
            .as_ref()
            .starts_with("ruleset:v2:ip"));
    }

    #[test]
    fn unknown_defaults_to_usa_never_iran() {
        let policy = policy();
        let rules = rules();
        let classification = classify(
            &policy,
            &rules,
            Some("unknown.example.net"),
            false,
            Some("9.9.9.9".parse().unwrap()),
        );
        assert_eq!(classification.verdict, SplitVerdict::Usa);
        assert_eq!(classification.matched_rule.as_ref(), "default:usa");
        assert_eq!(classification.confidence, Confidence::Low);
        // No domain, no IP at all: still USA.
        let classification = classify(&policy, &rules, None, false, None);
        assert_eq!(classification.verdict, SplitVerdict::Usa);
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        assert!(domain_matches_suffix("www.example.ir", "example.ir"));
        assert!(domain_matches_suffix("example.ir", "example.ir"));
        assert!(!domain_matches_suffix("notexample.ir", "example.ir"));
        assert!(domain_matches_suffix("WWW.EXAMPLE.IR.", "example.ir"));
    }
}
