//! Versioned Iranian destination rule-set (v1) for smart split routing.
//!
//! The v1 snapshot is curated by the rule-set agent (2026-11-01):
//! - `domains.json`: 117 curated Iranian domain suffixes (category+confidence).
//! - `ipv4.json`: 1,747 CIDRs from RIPE NCC delegated stats (factual data).
//! - `ipv6.json`: 577 CIDRs, same source.
//!
//! License: v1 contains zero bytes from GPL/CC-BY-SA sources
//! (Chocolate4U/Iran-sing-box-rules, Loyalsoldier/v2ray-rules-dat, and
//! v2fly/geoip were all REJECTED — see `ruleset/RULESET.md`). Never re-add
//! them.
//!
//! Loader contract (from `ruleset/RULESET.md`):
//! - Domains: suffix match (equals, or ends with `.` + suffix).
//! - IPs: longest-prefix match against the collapsed CIDR lists.
//! - Fail closed on corrupt data: keep the last good version, alert; never
//!   "everything is Iranian" or "everything is foreign".
//! - The snapshot version is surfaced for the panel.

use std::net::IpAddr;

/// The embedded v1 snapshot (FALLBACK): 117 curated domains + RIPE CIDRs,
/// license-clean. The v2 snapshot (PRIMARY, 57k domains, 7MB JSON) is NOT
/// embedded — `include_str!` of 7MB stalls rustc. v2 loads from disk at
/// runtime via `rulesetPath` (see `load_from_dir`); the files are vendored
/// in `crates/zero-router/ruleset/v2/` and installed by the provisioner.
/// Upstream: Chocolate4U/Iran-clash-rules release branch (GPL-3.0, vendored
/// per explicit owner override 2026-11-01 — see `ruleset/RULESET.md`).
/// Do not strip the license notes.
pub const V1_DOMAINS_JSON: &str = include_str!("../ruleset/v1/domains.json");
pub const V1_IPV4_JSON: &str = include_str!("../ruleset/v1/ipv4.json");
pub const V1_IPV6_JSON: &str = include_str!("../ruleset/v1/ipv6.json");

/// A validated, loaded rule-set snapshot.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub version: String,
    pub updated: String,
    /// Suffix -> entry. HashMap: v2 has 57,559 domains; a linear scan per
    /// classification would not keep up with a busy gateway.
    pub domains: std::collections::HashMap<String, DomainEntry>,
    pub cidrs_v4: Vec<ipnet::Ipv4Net>,
    pub cidrs_v6: Vec<ipnet::Ipv6Net>,
}

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub suffix: String,
    pub category: String,
    pub confidence: String,
}

#[derive(Debug)]
pub enum LoadError {
    InvalidJson(String),
    BadFormat(String),
    VersionMismatch { expected: String, found: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::InvalidJson(error) => write!(f, "invalid rule-set JSON: {error}"),
            LoadError::BadFormat(error) => write!(f, "bad rule-set format: {error}"),
            LoadError::VersionMismatch { expected, found } => {
                write!(
                    f,
                    "rule-set version mismatch: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Load a versioned snapshot from a directory holding `domains.json`,
/// `ipv4.json`, `ipv6.json` (e.g. `ruleset/v2/`). Used for the v2 PRIMARY
/// at runtime; validates before returning.
pub fn load_from_dir(dir: &str) -> Result<RuleSet, LoadError> {
    let read = |name: &str| {
        std::fs::read_to_string(format!("{dir}/{name}"))
            .map_err(|error| LoadError::InvalidJson(format!("cannot read {dir}/{name}: {error}")))
    };
    load_from_str(
        &read("domains.json")?,
        &read("ipv4.json")?,
        &read("ipv6.json")?,
    )
}

/// Load the embedded v1 snapshot (FALLBACK). Small (13KB); safe to embed.
/// The v2 PRIMARY loads from disk via `load_from_dir`.
pub fn load_embedded() -> Result<RuleSet, LoadError> {
    load_embedded_v1()
}

/// Load the embedded v1 snapshot directly (fallback / tests).
pub fn load_embedded_v1() -> Result<RuleSet, LoadError> {
    load_from_str(V1_DOMAINS_JSON, V1_IPV4_JSON, V1_IPV6_JSON)
}

/// Load and validate a snapshot from JSON strings (runtime override).
/// On any error, the caller keeps the last good version (fail closed).
pub fn load_from_str(
    domains_json: &str,
    ipv4_json: &str,
    ipv6_json: &str,
) -> Result<RuleSet, LoadError> {
    let domains_value: serde_json::Value = serde_json::from_str(domains_json)
        .map_err(|error| LoadError::InvalidJson(error.to_string()))?;
    let ipv4_value: serde_json::Value = serde_json::from_str(ipv4_json)
        .map_err(|error| LoadError::InvalidJson(error.to_string()))?;
    let ipv6_value: serde_json::Value = serde_json::from_str(ipv6_json)
        .map_err(|error| LoadError::InvalidJson(error.to_string()))?;

    for (name, value) in [
        ("domains.json", &domains_value),
        ("ipv4.json", &ipv4_value),
        ("ipv6.json", &ipv6_value),
    ] {
        let format = value
            .get("format")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if format != "zeronet-ruleset" {
            return Err(LoadError::BadFormat(format!(
                "{name}: format is {format:?}, expected \"zeronet-ruleset\""
            )));
        }
    }
    let version = domains_value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LoadError::BadFormat("domains.json has no version".into()))?
        .to_string();
    // All three files must agree on the version.
    for (name, value) in [("ipv4.json", &ipv4_value), ("ipv6.json", &ipv6_value)] {
        let file_version = value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if file_version != version {
            return Err(LoadError::VersionMismatch {
                expected: version.clone(),
                found: format!("{name} has {file_version:?}"),
            });
        }
    }
    let updated = domains_value
        .get("updated")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut domains = std::collections::HashMap::new();
    let entries = domains_value
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| LoadError::BadFormat("domains.json has no entries array".into()))?;
    for entry in entries {
        let suffix = entry
            .get("suffix")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| LoadError::BadFormat("domain entry has no suffix".into()))?;
        let suffix = suffix.to_ascii_lowercase();
        domains.insert(
            suffix.clone(),
            DomainEntry {
                suffix,
                category: entry
                    .get("category")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                confidence: entry
                    .get("confidence")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            },
        );
    }

    let mut cidrs_v4 = Vec::new();
    let cidrs = ipv4_value
        .get("cidrs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| LoadError::BadFormat("ipv4.json has no cidrs array".into()))?;
    for cidr in cidrs {
        let text = cidr
            .as_str()
            .ok_or_else(|| LoadError::BadFormat("ipv4 cidr is not a string".into()))?;
        let net: ipnet::Ipv4Net = text
            .parse()
            .map_err(|_| LoadError::BadFormat(format!("invalid IPv4 CIDR {text:?}")))?;
        cidrs_v4.push(net);
    }

    let mut cidrs_v6 = Vec::new();
    let cidrs = ipv6_value
        .get("cidrs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| LoadError::BadFormat("ipv6.json has no cidrs array".into()))?;
    for cidr in cidrs {
        let text = cidr
            .as_str()
            .ok_or_else(|| LoadError::BadFormat("ipv6 cidr is not a string".into()))?;
        let net: ipnet::Ipv6Net = text
            .parse()
            .map_err(|_| LoadError::BadFormat(format!("invalid IPv6 CIDR {text:?}")))?;
        cidrs_v6.push(net);
    }

    Ok(RuleSet {
        version,
        updated,
        domains,
        cidrs_v4,
        cidrs_v6,
    })
}

impl RuleSet {
    /// Suffix match: the domain equals a listed suffix or ends with `.` +
    /// suffix (case-insensitive). Probes each label boundary (longest match
    /// wins); O(labels) hash lookups, not O(entries). Returns the matched
    /// entry for the panel's Rule Tester.
    pub fn match_domain(&self, domain: &str) -> Option<&DomainEntry> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut rest = domain.as_str();
        loop {
            if let Some(entry) = self.domains.get(rest) {
                return Some(entry);
            }
            match rest.find('.') {
                Some(i) => rest = &rest[i + 1..],
                None => return None,
            }
        }
    }

    /// Longest-prefix match against the collapsed CIDR lists.
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.cidrs_v4.iter().any(|net| net.contains(&v4)),
            IpAddr::V6(v6) => self.cidrs_v6.iter().any(|net| net.contains(&v6)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2() -> RuleSet {
        // v2 loads from disk (7MB JSON is not embedded).
        load_from_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/ruleset/v2"))
            .expect("v2 must load from disk")
    }

    #[test]
    fn v2_loads_and_validates() {
        let ruleset = v2();
        assert_eq!(ruleset.version, "v2");
        assert_eq!(ruleset.domains.len(), 57559);
        assert_eq!(ruleset.cidrs_v4.len(), 2098);
        assert_eq!(ruleset.cidrs_v6.len(), 716);
    }

    #[test]
    fn v1_fallback_loads() {
        let ruleset = load_embedded_v1().expect("embedded v1 must load");
        assert_eq!(ruleset.version, "v1");
        assert_eq!(ruleset.domains.len(), 117);
    }

    #[test]
    fn domain_suffix_matching() {
        let ruleset = v2();
        // Exact and subdomain match (v2 has 57k suffixes; spot-check with a
        // suffix actually present in the upstream data).
        let entry = ruleset
            .match_domain("digikala.com")
            .expect("digikala.com must be in v2");
        assert_eq!(entry.suffix, "digikala.com");
        assert!(ruleset.match_domain("www.digikala.com").is_some());
        // Label-boundary respected.
        assert!(ruleset.match_domain("notdigikala.com").is_none());
        // Case-insensitive, trailing dot tolerated.
        assert!(ruleset.match_domain("WWW.DIGIKALA.COM.").is_some());
        // Foreign domain: no match.
        assert!(ruleset.match_domain("example.net").is_none());
    }

    #[test]
    fn ip_matching() {
        let ruleset = v2();
        // A CIDR from the v2 list (first entry).
        let first: ipnet::Ipv4Net = ruleset.cidrs_v4[0];
        let ip = IpAddr::V4(first.addr());
        assert!(ruleset.match_ip(ip), "{ip} should match {first}");
        // Foreign IP: no match.
        assert!(!ruleset.match_ip("8.8.8.8".parse().unwrap()));
        // Private ranges in the upstream data must NOT cause misclassification
        // here — but the classifier's priority-2 LAN check runs first, so
        // they never reach the rule-set. (This test documents the data
        // quality note; the LAN precedence is tested in split::tests.)
    }

    #[test]
    fn corrupt_data_is_rejected_not_silent() {
        let bad = load_from_str("not json", V1_IPV4_JSON, V1_IPV6_JSON);
        assert!(matches!(bad, Err(LoadError::InvalidJson(_))));
        let bad = load_from_str(V1_DOMAINS_JSON, "{\"format\":\"wrong\"}", V1_IPV6_JSON);
        assert!(matches!(bad, Err(LoadError::BadFormat(_))));
    }
}
