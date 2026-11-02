//! `zero-router` — routing decisions.

pub mod assets;
pub mod matcher;
pub mod process;
pub mod router;
/// Versioned Iranian destination rule-set (v1) for smart split routing.
pub mod ruleset;
/// Smart split routing: Iranian destinations → direct Iran egress,
/// foreign/unknown → USA tunnel.
pub mod split;

pub use assets::{AssetKind, AssetPolicy, AssetSpec, AssetStore, RefreshOutcome};
pub use matcher::{is_private_ip, DomainMatcher, GeoData, IpMatcher};
pub use router::{Decision, Router};
