//! Background tasks: usage polling, quota/expiry sweepers, route-change
//! ingestion, and (gateway mode) the collector POST to the primary.
//!
//! The engine's counters are memory-only; these rollups are what survives
//! restarts (SQLite). Everything degrades gracefully when the engine is
//! unreachable — the panel labels that state honestly.

use crate::api::{now_secs, today_utc, AppState};
use crate::store;
use std::sync::Arc;
use std::time::Duration;

/// Run all background loops until the process exits.
pub async fn run(state: Arc<AppState>) {
    let interval = Duration::from_secs(state.config.poll_interval_secs.max(10));
    loop {
        tokio::time::sleep(interval).await;
        poll_usage(&state).await;
        ingest_modem_status(&state).await;
        poll_ha(&state).await;
        push_routing_ruleset(&state).await;
        push_sticky_policies(&state).await;
        sweep_expiry(&state).await;
        sweep_quotas(&state).await;
        ingest_route_changes(&state).await;
        maybe_collect(&state).await;
    }
}

/// Poll `GET /usage?detail=1`, join identity hashes to devices, and write
/// deltas into `usage_daily`. Counter resets (engine restart) are handled:
/// a decrease is treated as a fresh baseline, not negative usage.
pub async fn poll_usage(state: &AppState) {
    let detail = match state.engine.usage_detail().await {
        Ok(d) => d,
        Err(_) => return, // engine down: skip this round, keep old data
    };
    let day = today_utc();
    let role = state.config.role.to_string();
    let now = now_secs();
    let mut last = state.last_counters.lock().unwrap();
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    // Map identity_hash -> device_id once per round.
    let mut device_of: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    for u in &detail.users {
        let key = format!("{}|{}", u.h, u.tag);
        let (prev_up, prev_down) = last.get(&key).copied().unwrap_or((0, 0));
        let dup = u.up.saturating_sub(prev_up);
        let ddown = u.down.saturating_sub(prev_down);
        last.insert(key, (u.up, u.down));
        if dup == 0 && ddown == 0 {
            continue;
        }
        let device_id = device_of
            .entry(u.h.clone())
            .or_insert_with(|| {
                conn.query_row(
                    "SELECT device_id FROM credentials WHERE identity_hash=?1 LIMIT 1",
                    rusqlite::params![u.h],
                    |r| r.get::<_, String>(0),
                )
                .ok()
            })
            .clone();
        let _ = store::upsert_usage(
            &conn,
            &day,
            device_id.as_deref(),
            &role,
            dup as i64,
            ddown as i64,
            u.sessions as i64,
        );
        if let Some(did) = device_id {
            let _ = conn.execute(
                "UPDATE devices SET last_seen_at=?1 WHERE id=?2",
                rusqlite::params![now, did],
            );
        }
    }
}

/// Ingest the provisioner's modem session-monitor status file (Design G §g.8):
/// per-account connection status + usage counters.
///
/// Status rule (from the report): session up + recent activity = connected.
/// Absent file or unknown username → keep the stored status ("never" for new
/// accounts, "unknown" when the monitor never reported).
pub async fn ingest_modem_status(state: &AppState) {
    let path = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        store::get_setting(&conn, "modem.status_path")
            .ok()
            .flatten()
            .unwrap_or_else(|| "/var/lib/zeronet-admin/modem-status.json".to_string())
    };
    let snapshots = match crate::modem::read_status_file(&path) {
        Some(s) => s,
        None => return, // monitor not running yet: keep stored status, say nothing
    };
    let day = today_utc();
    let now = now_secs();
    let mut last = state.last_modem_counters.lock().unwrap();
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    let accounts = match store::list_modem_accounts(&conn) {
        Ok(a) => a,
        Err(_) => return,
    };
    for account in &accounts {
        let Some(snap) = snapshots.get(&account.username) else {
            continue;
        };
        let (status, last_seen) = if snap.session_up {
            ("connected", snap.last_seen.or(Some(now)))
        } else if snap.last_seen.is_some() {
            ("disconnected", snap.last_seen)
        } else if account.status == "never" {
            ("never", None)
        } else {
            ("unknown", account.last_seen_at)
        };
        let _ = store::update_modem_status(&conn, &account.id, status, last_seen);
        // Usage deltas: counter resets (session restart) are a fresh baseline.
        let (prev_up, prev_down) = last.get(&account.id).copied().unwrap_or((0, 0));
        let dup = snap.bytes_up.saturating_sub(prev_up);
        let ddown = snap.bytes_down.saturating_sub(prev_down);
        last.insert(account.id.clone(), (snap.bytes_up, snap.bytes_down));
        if dup == 0 && ddown == 0 {
            continue;
        }
        let _ = store::upsert_usage(
            &conn,
            &day,
            Some(&format!("modem:{}", account.id)),
            "modem",
            dup as i64,
            ddown as i64,
            if snap.session_up { 1 } else { 0 },
        );
    }
}

/// Poll the engine HA snapshot and log `ha_failover` events when the primary
/// path changes or the failover counter increases. Never invents data: if
/// the engine has no HA surface, nothing is logged.
pub async fn poll_ha(state: &AppState) {
    let snap = match state.engine.ha_snapshot().await {
        Ok(s) => s,
        Err(_) => return, // engine down: skip this round
    };
    if !snap.supported() {
        return;
    }
    let prev = state.last_ha.lock().unwrap().clone();
    *state.last_ha.lock().unwrap() = Some(snap.clone());
    let Some(prev) = prev else { return }; // first sighting: baseline, no event
    let primary_changed = prev.primary != snap.primary;
    let count_grew = snap.failovers.count > prev.failovers.count;
    if !primary_changed && !count_grew {
        return;
    }
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = store::log_event(
        &conn,
        now_secs(),
        "ha_failover",
        "poller",
        &serde_json::json!({
            "from": prev.primary,
            "to": snap.primary,
            "failover_count": snap.failovers.count,
            "last_downtime_ms": snap.failovers.last_downtime_s.map(|s| (s * 1000.0) as u64),
        }),
    );
}

/// Push the ACTIVE routing rule-set to the engine when `routing.push_pending`
/// is set (set by every rule mutation). Best-effort until the routing agent's
/// `/ruleset` contract lands: failures keep the pending flag and are reported
/// via `engine_synced:false` + `push_error` (no silent divergence).
pub async fn push_routing_ruleset(state: &AppState) {
    let pending = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        store::get_setting(&conn, "routing.push_pending")
            .ok()
            .flatten()
            .map(|v| v == "1")
            .unwrap_or(false)
    };
    if !pending {
        return;
    }
    let (version, rules) = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        match store::active_rules(&conn) {
            Ok(v) => v,
            Err(_) => return,
        }
    };
    let now = now_secs();
    match state.engine.push_ruleset(version, &rules).await {
        Ok(_) => {
            let conn = match state.db.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = store::set_setting(&conn, "routing.push_pending", "0");
            let _ = store::set_setting(&conn, "routing.push_error", "");
            let _ = store::log_event(
                &conn,
                now,
                "routing_push",
                "poller",
                &serde_json::json!({"version": version, "rules": rules.len()}),
            );
        }
        Err(e) => {
            let msg = e.to_string();
            let conn = match state.db.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            // Log only on change to avoid event spam every poll round.
            let last = store::get_setting(&conn, "routing.push_error")
                .ok()
                .flatten()
                .unwrap_or_default();
            if last != msg {
                let _ = store::set_setting(&conn, "routing.push_error", &msg);
                let _ = store::log_event(
                    &conn,
                    now,
                    "routing_push_failed",
                    "poller",
                    &serde_json::json!({"version": version, "error": msg.chars().take(200).collect::<String>()}),
                );
            }
        }
    }
}

/// Push the sticky-exit policies to the engine when `sticky.push_pending`
/// is set. Best-effort, same honesty discipline as the routing push.
pub async fn push_sticky_policies(state: &AppState) {
    let pending = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        store::get_setting(&conn, "sticky.push_pending")
            .ok()
            .flatten()
            .map(|v| v == "1")
            .unwrap_or(false)
    };
    if !pending {
        return;
    }
    let policies = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        match store::list_sticky_policies(&conn) {
            Ok(p) => p,
            Err(_) => return,
        }
    };
    let now = now_secs();
    match state.engine.push_sticky_policies(&policies).await {
        Ok(_) => {
            let conn = match state.db.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = store::set_setting(&conn, "sticky.push_pending", "0");
            let _ = store::set_setting(&conn, "sticky.push_error", "");
            let _ = store::log_event(
                &conn,
                now,
                "sticky_push",
                "poller",
                &serde_json::json!({"policies": policies.len()}),
            );
        }
        Err(e) => {
            let msg = e.to_string();
            let conn = match state.db.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let last = store::get_setting(&conn, "sticky.push_error")
                .ok()
                .flatten()
                .unwrap_or_default();
            if last != msg {
                let _ = store::set_setting(&conn, "sticky.push_error", &msg);
                let _ = store::log_event(
                    &conn,
                    now,
                    "sticky_push_failed",
                    "poller",
                    &serde_json::json!({"error": msg.chars().take(200).collect::<String>()}),
                );
            }
        }
    }
}

/// Expire users/devices past `expires_at`: same path as revoke.
pub async fn sweep_expiry(state: &AppState) {
    let now = now_secs();
    let expired_users: Vec<String> = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT id FROM users WHERE revoked=0 AND expires_at IS NOT NULL AND expires_at<?1",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        stmt.query_map(rusqlite::params![now], |r| r.get::<_, String>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    };
    for uid in expired_users {
        revoke_user_everywhere(state, &uid, "expired").await;
    }
    let expired_devices: Vec<String> = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT id FROM devices WHERE revoked=0 AND expires_at IS NOT NULL AND expires_at<?1",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        stmt.query_map(rusqlite::params![now], |r| r.get::<_, String>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    };
    for did in expired_devices {
        revoke_device_everywhere(state, &did, "expired").await;
    }
}

/// Quota sweeper: at 100% of `quota_bytes` (month-to-date) the credentials
/// are disabled (users file + engine reload) and a `quota_hit` event is
/// logged; at 80% a warning event fires (once per day per user).
pub async fn sweep_quotas(state: &AppState) {
    let today = today_utc();
    let month_start = format!("{}-01", &today[..7]);
    let now = now_secs();
    let over: Vec<(String, String, i64, i64)> = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let users = store::list_users(&conn).unwrap_or_default();
        let mut over = Vec::new();
        for u in users {
            if u.revoked {
                continue;
            }
            let Some(quota) = u.quota_bytes else { continue };
            let (up, down) =
                store::user_usage_bytes(&conn, &u.id, &month_start, &today).unwrap_or((0, 0));
            let used = up + down;
            if used >= quota {
                over.push((u.id.clone(), u.name.clone(), used, quota));
            } else if used * 5 >= quota * 4 {
                // 80% warning, once per day.
                let warned: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM events WHERE kind='quota_warn' AND at>?1 AND detail LIKE ?2",
                        rusqlite::params![now - 86400, format!("%{}%", u.id)],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                if warned == 0 {
                    let _ = store::log_event(
                        &conn,
                        now,
                        "quota_warn",
                        "system",
                        &serde_json::json!({"user_id": u.id, "used": used, "quota": quota}),
                    );
                }
            }
        }
        over
    };
    for (uid, name, used, quota) in over {
        revoke_user_everywhere(state, &uid, "quota").await;
        if let Ok(conn) = state.db.lock() {
            let _ = store::log_event(
                &conn,
                now,
                "quota_hit",
                "system",
                &serde_json::json!({"user_id": uid, "name": name, "used": used, "quota": quota}),
            );
        }
    }
}

async fn revoke_user_everywhere(state: &AppState, user_id: &str, reason: &str) {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = store::set_user_revoked(&conn, user_id, true);
        let devices = store::list_user_devices(&conn, user_id).unwrap_or_default();
        for d in &devices {
            let _ = store::set_device_revoked(&conn, &d.id, true);
        }
        let mut tags = std::collections::HashSet::new();
        for d in &devices {
            if let Ok(creds) = store::list_device_credentials(&conn, &d.id) {
                for c in creds {
                    tags.insert(c.inbound_tag.clone());
                }
            }
        }
        let _ = store::log_event(
            &conn,
            now,
            reason,
            "system",
            &serde_json::json!({"user_id": user_id}),
        );
        tags.into_iter().collect()
    };
    let _ = crate::api::sync_tags(state, &tags).await;
}

async fn revoke_device_everywhere(state: &AppState, device_id: &str, reason: &str) {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = store::set_device_revoked(&conn, device_id, true);
        let tags: Vec<String> = store::list_device_credentials(&conn, device_id)
            .map(|v| v.into_iter().map(|c| c.inbound_tag).collect())
            .unwrap_or_default();
        let _ = store::log_event(
            &conn,
            now,
            reason,
            "system",
            &serde_json::json!({"device_id": device_id}),
        );
        tags
    };
    let _ = crate::api::sync_tags(state, &tags).await;
}

/// Diff the engine's switch ring (`GET /health` → `switches`) against the
/// last seen timestamp and log new entries as `route_change` events.
pub async fn ingest_route_changes(state: &AppState) {
    let health = match state.engine.health().await {
        Ok(h) => h,
        Err(_) => return,
    };
    let switches = match health.get("switches").and_then(|s| s.as_array()) {
        Some(s) => s.clone(),
        None => return, // old engine: no switch ring; nothing to ingest
    };
    let mut last = state.last_switch_at.lock().unwrap();
    let mut new_events = Vec::new();
    for sw in switches {
        let at = sw.get("at").and_then(|v| v.as_i64()).unwrap_or(0);
        if last.map(|l| at > l).unwrap_or(true) {
            new_events.push((at, sw.clone()));
        }
    }
    if new_events.is_empty() {
        return;
    }
    new_events.sort_by_key(|(at, _)| *at);
    if let Ok(conn) = state.db.lock() {
        for (at, sw) in &new_events {
            let _ = store::log_event(&conn, *at, "route_change", "engine", sw);
        }
    }
    if let Some((at, _)) = new_events.last() {
        *last = Some(*at);
    }
}

/// Gateway (collector) mode: POST this round's aggregates to the primary.
async fn maybe_collect(state: &AppState) {
    use crate::config::AdminMode;
    if state.config.mode != AdminMode::Collector {
        return;
    }
    let target = match &state.config.collector_target {
        Some(t) => t.clone(),
        None => return,
    };
    let token = match &state.config.collector_token {
        Some(t) => t.clone(),
        None => return,
    };
    let detail = match state.engine.usage_detail().await {
        Ok(d) => d,
        Err(_) => return,
    };
    let rows: Vec<serde_json::Value> = detail
        .users
        .into_iter()
        .map(|u| serde_json::json!({"h": u.h, "tag": u.tag, "sessions": u.sessions, "up": u.up, "down": u.down}))
        .collect();
    if rows.is_empty() {
        return;
    }
    let body = serde_json::json!({ "day": today_utc(), "rows": rows }).to_string();
    // Minimal HTTP POST over plain TCP (collector target is http://host:port
    // on the inter-server link; never the open internet).
    let addr = match target.strip_prefix("http://") {
        Some(a) => a.to_string(),
        None => return,
    };
    let mut stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(_) => return,
    };
    use tokio::io::AsyncWriteExt;
    let req = format!(
        "POST /api/v1/collector/usage HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        addr,
        token.expose(),
        body.len(),
        body
    );
    let _ = stream.write_all(req.as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState as ApiState;

    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_state() -> (TempDir, Arc<ApiState>) {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "zero-admin-poller-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
        std::fs::create_dir_all(&dir.0).unwrap();
        let config = crate::config::AdminConfig::test(&dir.0);
        let state = ApiState::new(config).unwrap();
        (dir, state)
    }

    #[tokio::test]
    async fn sweep_expiry_revokes_expired_user() {
        let (_dir, state) = test_state();
        let now = now_secs();
        {
            let conn = state.db.lock().unwrap();
            store::create_user(
                &conn,
                &store::User {
                    id: "u-exp".into(),
                    name: "Expired".into(),
                    note: String::new(),
                    created_at: now - 100,
                    expires_at: Some(now - 10),
                    revoked: false,
                    quota_bytes: None,
                    quota_mbps: None,
                    max_devices: 8,
                },
            )
            .unwrap();
        }
        sweep_expiry(&state).await;
        let conn = state.db.lock().unwrap();
        assert!(store::get_user(&conn, "u-exp").unwrap().revoked);
        let events = store::list_events(&conn, Some("expired"), None, 10).unwrap();
        assert!(!events.is_empty());
    }

    #[tokio::test]
    async fn sweep_quotas_revokes_over_quota_user() {
        let (_dir, state) = test_state();
        let now = now_secs();
        let today = today_utc();
        {
            let conn = state.db.lock().unwrap();
            store::create_user(
                &conn,
                &store::User {
                    id: "u-q".into(),
                    name: "Quota".into(),
                    note: String::new(),
                    created_at: now - 100,
                    expires_at: None,
                    revoked: false,
                    quota_bytes: Some(1000),
                    quota_mbps: None,
                    max_devices: 8,
                },
            )
            .unwrap();
            store::create_device(
                &conn,
                &store::Device {
                    id: "d-q".into(),
                    user_id: "u-q".into(),
                    label: "phone".into(),
                    created_at: now - 100,
                    expires_at: None,
                    revoked: false,
                    last_seen_at: None,
                },
            )
            .unwrap();
            store::upsert_usage(&conn, &today, Some("d-q"), "exit", 800, 500, 1).unwrap();
        }
        sweep_quotas(&state).await;
        let conn = state.db.lock().unwrap();
        assert!(store::get_user(&conn, "u-q").unwrap().revoked);
        let events = store::list_events(&conn, Some("quota_hit"), None, 10).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn poll_usage_skips_when_engine_down() {
        // engine_mgmt points at 127.0.0.1:1 (nothing listening): must not panic.
        let (_dir, state) = test_state();
        poll_usage(&state).await;
        ingest_route_changes(&state).await;
    }
}
