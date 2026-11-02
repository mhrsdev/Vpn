//! Split DNS (H3): DNS resolution follows the routing verdict.
//!
//! Every DNS query answered by a `dns` outbound gets a defined policy from
//! the split classifier:
//!
//! | Verdict | DNS path |
//! |---|---|
//! | Iranian | the `dns_iran_tag` resolver view (Iran path) |
//! | Foreign / unknown | the `dns_tunnel_tag` resolver view (USA tunnel path) |
//! | Foreign / unknown, tunnel down | SERVFAIL — fail closed, never answered via Iran |
//!
//! Split DNS is active only when the config's `splitRouting` block sets BOTH
//! `dnsIranTag` and `dnsTunnelTag`. Otherwise the default resolver answers
//! everything, exactly as before.
//!
//! ## Loop prevention
//!
//! 1. The classification input is the QNAME string only — never a resolved
//!    IP. The resolver's choice cannot change the QNAME, so there is nothing
//!    to recurse on.
//! 2. The chosen resolver view's servers carry FIXED routing tags from
//!    config; their own traffic never re-enters split classification.
//! 3. Answers are never re-classified for DNS purposes. (The TCP/UDP session
//!    the application then opens to a resolved IP goes through the normal
//!    session path and its own classification — that is intended, separate,
//!    and also single-pass.)
//!
//! ## Leak prevention
//!
//! `Resolver::for_tag` views have independent caches and in-flight maps, so
//! an answer learned on the Iran path cannot leak to the tunnel path or vice
//! versa. A foreign verdict with a down tunnel is SERVFAIL, not a quiet
//! fallback to the Iran resolver — that fallback would be a DNS leak by
//! another name.
//!
//! ## Honest limitation: encrypted-DNS bypass
//!
//! If the client resolves names itself over DoH/DoT/DoQ to an outside
//! resolver (bypassing the `dns` outbound), the engine never sees the query
//! and cannot apply split policy. The `dns` outbound only governs queries
//! routed to it (typically UDP/53 in TUN mode). This is documented, not
//! silently assumed away.

use std::sync::Arc;

use zero_dns::Resolver;

use crate::classify::PushedRuleset;
use crate::split_engine::SplitEngine;
use zero_router::split::SplitVerdict;

/// Where a DNS query is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRoute {
    /// Via the Iran resolver view.
    Iran,
    /// Via the USA-tunnel resolver view.
    Tunnel,
    /// Refuse: foreign verdict but the tunnel is down (fail closed).
    Blocked,
}

/// Decide the DNS path for one QNAME. `tunnel_up` is the same liveness
/// signal session routing uses.
pub fn dns_route(
    engine: &SplitEngine,
    overlay: Option<&PushedRuleset>,
    name: &str,
    tunnel_up: bool,
) -> DnsRoute {
    // The pushed overlay participates exactly like in session classification:
    // the admin's rules are authoritative.
    if let Some(overlay) = overlay {
        if let Some((verdict, _)) =
            crate::classify::apply_overlay_for_dns(overlay, name, engine.iran_ruleset())
        {
            return match verdict {
                SplitVerdict::Iran => DnsRoute::Iran,
                SplitVerdict::Usa if tunnel_up => DnsRoute::Tunnel,
                SplitVerdict::Usa => DnsRoute::Blocked,
            };
        }
    }
    match engine.classify_target(name).verdict {
        SplitVerdict::Iran => DnsRoute::Iran,
        SplitVerdict::Usa if tunnel_up => DnsRoute::Tunnel,
        SplitVerdict::Usa => DnsRoute::Blocked,
    }
}

/// Answer one DNS packet under split policy. This is a thin wrapper used by
/// `Server::answer_dns`; the server snapshots the route decision without
/// holding any lock across the await.
pub(crate) async fn answer_routed(
    resolver: &Resolver,
    packet: &[u8],
    rules: &[zero_config::DnsOutboundRule],
    route: DnsRoute,
    iran_tag: &str,
    tunnel_tag: &str,
) -> Option<Vec<u8>> {
    match route {
        DnsRoute::Iran => {
            let view = resolver.for_tag(iran_tag);
            crate::dns_out::answer(&view, packet, rules).await
        }
        DnsRoute::Tunnel => {
            let view = resolver.for_tag(tunnel_tag);
            crate::dns_out::answer(&view, packet, rules).await
        }
        DnsRoute::Blocked => {
            // Fail closed: SERVFAIL, never the Iran resolver. The query
            // parsed during routing, so this cannot fail here; a defensive
            // None keeps the caller's drop contract.
            let query = crate::dns_out::parse_query(packet)?;
            Some(crate::dns_out::servfail(&query))
        }
    }
}

/// The split-DNS tags from config, when both are set.
pub fn split_dns_tags(
    engine_config: &zero_config::model::SplitRoutingConfig,
) -> Option<(Arc<str>, Arc<str>)> {
    match (&engine_config.dns_iran_tag, &engine_config.dns_tunnel_tag) {
        (Some(iran), Some(tunnel)) => Some((Arc::from(iran.as_ref()), Arc::from(tunnel.as_ref()))),
        _ => None,
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
            dns_iran_tag: Some("iran-dns".into()),
            dns_tunnel_tag: Some("tunnel-dns".into()),
        })
    }

    #[test]
    fn iranian_name_resolves_via_iran() {
        let engine = test_engine();
        // digikala.com is in the v2 snapshot.
        assert_eq!(
            dns_route(&engine, None, "digikala.com", true),
            DnsRoute::Iran
        );
        assert_eq!(
            dns_route(&engine, None, "www.digikala.com", true),
            DnsRoute::Iran
        );
    }

    #[test]
    fn foreign_name_resolves_via_tunnel() {
        let engine = test_engine();
        assert_eq!(
            dns_route(&engine, None, "example.com", true),
            DnsRoute::Tunnel
        );
        assert_eq!(
            dns_route(&engine, None, "unknown-site-xyz.invalid", true),
            DnsRoute::Tunnel
        );
    }

    #[test]
    fn foreign_name_with_down_tunnel_is_blocked_never_iran() {
        let engine = test_engine();
        // Fail closed: SERVFAIL path, not the Iran resolver.
        assert_eq!(
            dns_route(&engine, None, "example.com", false),
            DnsRoute::Blocked
        );
        // Iranian names still resolve when the tunnel is down.
        assert_eq!(
            dns_route(&engine, None, "digikala.com", false),
            DnsRoute::Iran
        );
    }

    #[test]
    fn split_dns_tags_require_both() {
        let config = SplitRoutingConfig {
            tunnel_only: false,
            lan_as_iran: true,
            manual_rules: Vec::new(),
            iran_domains: Vec::new(),
            iran_cidrs: Vec::new(),
            pair_id: None,
            ruleset_path: None,
            dns_iran_tag: Some("a".into()),
            dns_tunnel_tag: None,
        };
        assert!(split_dns_tags(&config).is_none());
        let config = SplitRoutingConfig {
            dns_tunnel_tag: Some("b".into()),
            ..config
        };
        let (iran, tunnel) = split_dns_tags(&config).expect("both set");
        assert_eq!(iran.as_ref(), "a");
        assert_eq!(tunnel.as_ref(), "b");
    }
}
