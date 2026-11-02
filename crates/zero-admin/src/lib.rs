//! zero-admin: the ZeroNet operator management plane.
//!
//! `zray-admin` runs on each server (loopback API + server-rendered panel),
//! owns the SQLite operator database, issues per-device credentials, and
//! talks to the engine's loopback management API (`GET /usage?detail=1`,
//! `GET /health`, `GET /tunnel`, `POST /api/v1/engine/users/reload`).
//!
//! Design C is the normative spec. The admin never fetches user-supplied
//! URLs, never binds the API to a public address, and contains no GeoIP
//! code of any kind (see [`NO_GEOIP`]).

pub mod api;
pub mod backup;
pub mod config;
pub mod crypto;
pub mod db;
pub mod engine;
pub mod ha;
pub mod ha_panel;
pub mod huawei_panel;
pub mod modem;
pub mod panel;
pub mod poller;
pub mod provision;
pub mod routing;
pub mod routing_panel;
pub mod secrets;
pub mod store;
pub mod subs;
pub mod triple;
pub mod triple_panel;

pub use config::AdminConfig;

/// Compile-time marker: this crate must never gain a GeoIP dependency.
///
/// The owner's hard rule: a carrier's tariff is never inferred from IP
/// geolocation. `tariff_note` stays `"unknown"` unless the owner records a
/// verified tariff. There is a test (`tests/no_geoip.rs`) asserting no
/// `geoip*`/`maxmind*` crate appears in this crate's dependency closure.
pub const NO_GEOIP: bool = true;

/// Test-only helper: a unique temporary directory.
///
/// Directory names used to be derived from `SystemTime::now().as_nanos()`
/// alone; two tests starting in the same nanosecond (real on a busy VM)
/// would share one directory — `create_dir_all` is idempotent — and then
/// share one SQLite file, racing migrations ("table already exists") or
/// polluting each other's data. The pid + process-wide atomic counter make
/// collisions impossible.
#[cfg(test)]
pub(crate) fn test_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "{}-{}-{}-{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        CTR.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("test temp dir");
    dir
}

#[cfg(test)]
mod lib_tests {
    use super::NO_GEOIP;

    #[test]
    fn no_geoip_marker_is_true() {
        const { assert!(NO_GEOIP) };
    }
}
