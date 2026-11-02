//! SQLite storage: schema v1 + migration framework.
//!
//! One bundled-SQLite file per server (`/var/lib/zeronet-admin/admin.db`),
//! WAL mode, `meta.schema_version` gating. Before any migration the DB is
//! copied to `admin.db.pre-migrate-<ts>` (last 3 kept).

use rusqlite::{params, Connection};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("schema version {0} is newer than this binary supports")]
    NewerSchema(i64),
}

pub const SCHEMA_VERSION: i64 = 4;

const MIGRATIONS: &[(i64, &str)] = &[
    (
        1,
        r#"
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE users(
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  note          TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER,
  revoked       INTEGER NOT NULL DEFAULT 0,
  quota_bytes   INTEGER,
  quota_mbps    INTEGER,
  max_devices   INTEGER NOT NULL DEFAULT 8
);

CREATE TABLE devices(
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label         TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER,
  revoked       INTEGER NOT NULL DEFAULT 0,
  last_seen_at  INTEGER
);

CREATE TABLE credentials(
  id            TEXT PRIMARY KEY,
  device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  inbound_tag   TEXT NOT NULL,
  protocol      TEXT NOT NULL,
  identity_hash TEXT NOT NULL,
  secret        BLOB NOT NULL,
  created_at    INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0,
  UNIQUE(device_id, inbound_tag)
);
CREATE INDEX idx_credentials_identity ON credentials(identity_hash);

CREATE TABLE inbounds(
  tag           TEXT PRIMARY KEY,
  protocol      TEXT NOT NULL,
  server_role   TEXT NOT NULL,
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL,
  params        TEXT NOT NULL DEFAULT '{}',
  enabled       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE subscriptions(
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,
  name          TEXT NOT NULL,
  device_id     TEXT REFERENCES devices(id) ON DELETE CASCADE,
  token_hash    TEXT,
  source_url    TEXT,
  imported_at   INTEGER,
  body_crypt    BLOB,
  config_count  INTEGER NOT NULL DEFAULT 0,
  managed       INTEGER NOT NULL DEFAULT 0,
  expires_at    INTEGER,
  revoked       INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);

CREATE TABLE usage_daily(
  day           TEXT NOT NULL,
  device_id     TEXT,
  server_role   TEXT NOT NULL,
  bytes_up      INTEGER NOT NULL DEFAULT 0,
  bytes_down    INTEGER NOT NULL DEFAULT 0,
  sessions_peak INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, device_id, server_role)
);

CREATE TABLE costs(
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,
  label         TEXT NOT NULL,
  amount        REAL NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'IRR',
  period        TEXT NOT NULL DEFAULT 'monthly',
  volume_mb     INTEGER,
  operator      TEXT,
  tariff_note   TEXT NOT NULL DEFAULT 'unknown',
  recorded_at   INTEGER NOT NULL
);

CREATE TABLE events(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  at            INTEGER NOT NULL,
  kind          TEXT NOT NULL,
  actor         TEXT NOT NULL DEFAULT 'system',
  detail        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_kind_at ON events(kind, at);

CREATE TABLE settings(
  key           TEXT PRIMARY KEY,
  value         TEXT NOT NULL
);

CREATE TABLE sessions(
  token_hash    TEXT PRIMARY KEY,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  ip            TEXT NOT NULL
);
"#,
    ),
    (
        2,
        r#"
-- Modem accounts (Design G): dedicated L2TP credentials for Huawei H158-381
-- (and future native-modem clients). Independent from phone/laptop devices:
-- separate table, separate lifecycle, individually revocable. Secrets are
-- XChaCha20-Poly1305 sealed blobs (same protections as credentials.secret).
CREATE TABLE modem_accounts(
  id            TEXT PRIMARY KEY,
  label         TEXT NOT NULL,
  username      TEXT NOT NULL UNIQUE,
  hostname      TEXT NOT NULL,
  lns_address   TEXT NOT NULL,
  tunnel_secret BLOB NOT NULL,
  ppp_secret    BLOB NOT NULL,
  consent_at    INTEGER,
  consent_note  TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'never',
  last_seen_at  INTEGER,
  created_at    INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_modem_username ON modem_accounts(username);
CREATE INDEX idx_modem_status ON modem_accounts(status, revoked);
"#,
    ),
    (
        3,
        r#"
-- Smart split-routing rule-sets (owner prompt v2 / LEAD DELTA).
-- The admin is the authoritative rule store: versioned, validated,
-- rollback-able. The engine applies the ACTIVE version (pushed by the
-- poller; see routing.push_pending). Versions are append-only snapshots;
-- day-to-day edits mutate the active version's rules in place.
CREATE TABLE routing_rulesets(
  version     INTEGER PRIMARY KEY,
  note        TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  active      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE routing_rules(
  id          TEXT PRIMARY KEY,
  version     INTEGER NOT NULL REFERENCES routing_rulesets(version) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  action      TEXT NOT NULL,
  priority    INTEGER NOT NULL DEFAULT 100,
  enabled     INTEGER NOT NULL DEFAULT 1,
  note        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_routing_rules_version ON routing_rules(version, priority, id);
-- Seed: empty v1, active. Unknown destinations default to the USA tunnel
-- in the classifier, so an empty rule-set is a safe, honest starting point
-- (populated by the API or the rule-set curation workstream).
INSERT INTO routing_rulesets(version, note, created_at, active)
VALUES (1, 'seeded empty — populate via API or rule-set curation', 0, 1);
"#,
    ),
    (
        4,
        r#"
-- Sticky exit policies (triple-tunnel / dual-stack LEAD DELTA).
-- scope: "domain" | "device"; target: the domain (lowercase) or device id.
-- policy: "force_ipv4" | "force_ipv6" | "auto" | "prefer_stable_ipv4".
-- affinity_secs: how long a session sticks to its exit IP before the engine
--   may re-evaluate (0 = engine default). The admin owns the policy store;
--   the engine applies them (poller push, best-effort, like routing rules).
-- Honesty: if the user forces IPv4 and IPv4 breaks, the engine falls back
-- per the policy — it never silently changes the exit IP; the panel shows
-- last_reroute_at + last_reroute_reason from the engine's egress snapshot.
CREATE TABLE sticky_policies(
  id            TEXT PRIMARY KEY,
  scope         TEXT NOT NULL,
  target        TEXT NOT NULL,
  policy        TEXT NOT NULL,
  affinity_secs INTEGER NOT NULL DEFAULT 0,
  note          TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_sticky_policies_scope_target ON sticky_policies(scope, target);
"#,
    ),
];

/// Open (creating) the DB at `path`, enable WAL, and run migrations.
pub fn open(path: &Path) -> Result<Connection, DbError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
    )?;
    migrate(&conn, path)?;
    Ok(conn)
}

fn schema_version(conn: &Connection) -> Result<i64, DbError> {
    let has_meta: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'",
        [],
        |r| r.get(0),
    )?;
    if has_meta == 0 {
        return Ok(0);
    }
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .ok();
    Ok(v.and_then(|s| s.parse().ok()).unwrap_or(0))
}

/// Run pending migrations. Each migration runs in its own transaction and
/// the version is bumped only on success. Backs up the DB first.
pub fn migrate(conn: &Connection, path: &Path) -> Result<(), DbError> {
    let current = schema_version(conn)?;
    if current > SCHEMA_VERSION {
        return Err(DbError::NewerSchema(current));
    }
    let pending: Vec<_> = MIGRATIONS.iter().filter(|(v, _)| *v > current).collect();
    if pending.is_empty() {
        return Ok(());
    }
    backup_before_migrate(path)?;
    for (version, sql) in pending {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![version.to_string()],
        )?;
        tx.commit()?;
    }
    prune_migrate_backups(path);
    Ok(())
}

fn backup_before_migrate(path: &Path) -> Result<(), DbError> {
    if !path.exists() {
        return Ok(());
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = path.with_extension(format!("db.pre-migrate-{ts}"));
    std::fs::copy(path, backup)?;
    Ok(())
}

fn prune_migrate_backups(path: &Path) {
    let Some(parent) = path.parent() else { return };
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return;
    };
    let prefix = format!("{stem}.db.pre-migrate-");
    let mut backups: Vec<_> = std::fs::read_dir(parent)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(&prefix))
                })
                .collect()
        })
        .unwrap_or_default();
    backups.sort();
    while backups.len() > 3 {
        if let Some(oldest) = backups.first() {
            let _ = std::fs::remove_file(oldest);
        }
        backups.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Minimal temp-dir stand-in (no extra dev-dependency).
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp_db() -> (TempDir, Connection) {
        let dir = TempDir(crate::test_temp_dir("zero-admin-test"));
        let path = dir.path().join("admin.db");
        let conn = open(&path).unwrap();
        (dir, conn)
    }

    #[test]
    fn migrate_creates_schema_v1() {
        let (_dir, conn) = tmp_db();
        let v = schema_version(&conn).unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        // All v1 tables exist.
        for table in [
            "users",
            "devices",
            "credentials",
            "inbounds",
            "subscriptions",
            "usage_daily",
            "costs",
            "events",
            "settings",
            "sessions",
            "meta",
        ] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "table {table} missing");
        }
    }

    #[test]
    fn migrate_v2_adds_modem_accounts() {
        let (_dir, conn) = tmp_db();
        assert_eq!(schema_version(&conn).unwrap(), 4);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='modem_accounts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "modem_accounts table missing after v2");
    }

    #[test]
    fn migrate_v1_to_v2_upgrade_path() {
        // Simulate an existing v1 database, then re-open: v2 must apply cleanly.
        let (dir, conn) = tmp_db();
        // Force the DB back to v1 by dropping all later tables and resetting version.
        conn.execute_batch(
            "DROP TABLE modem_accounts; DROP TABLE routing_rules; DROP TABLE routing_rulesets; \
             DROP TABLE sticky_policies; UPDATE meta SET value='1' WHERE key='schema_version';",
        )
        .unwrap();
        drop(conn);
        let path = dir.path().join("admin.db");
        let conn2 = open(&path).unwrap();
        assert_eq!(schema_version(&conn2).unwrap(), 4);
        let n: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='modem_accounts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "modem_accounts table missing after v1->v2 upgrade");
    }

    #[test]
    fn migrate_v3_adds_routing_tables_and_seeds_v1() {
        let (_dir, conn) = tmp_db();
        assert_eq!(schema_version(&conn).unwrap(), 4);
        for table in ["routing_rulesets", "routing_rules"] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "table {table} missing after v3");
        }
        let active: i64 = conn
            .query_row(
                "SELECT version FROM routing_rulesets WHERE active=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 1);
    }

    #[test]
    fn migrate_v4_adds_sticky_policies() {
        let (_dir, conn) = tmp_db();
        assert_eq!(schema_version(&conn).unwrap(), 4);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sticky_policies'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "sticky_policies table missing after v4");
    }

    #[test]
    fn migrate_is_idempotent() {
        let (dir, conn) = tmp_db();
        drop(conn);
        let path = dir.path().join("admin.db");
        let conn2 = open(&path).unwrap();
        assert_eq!(schema_version(&conn2).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_is_rejected() {
        let (_dir, conn) = tmp_db();
        conn.execute(
            "INSERT INTO meta(key,value) VALUES ('schema_version','999')
             ON CONFLICT(key) DO UPDATE SET value='999'",
            [],
        )
        .unwrap();
        let path = std::env::temp_dir().join("zero-admin-test-nope/admin.db");
        let err = migrate(&conn, &path).unwrap_err();
        assert!(matches!(err, DbError::NewerSchema(999)));
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let (_dir, conn) = tmp_db();
        let err = conn
            .execute(
                "INSERT INTO devices(id, user_id, label, created_at) VALUES ('d','no-such-user','x',1)",
                [],
            )
            .unwrap_err();
        assert!(err.to_string().contains("FOREIGN KEY"));
    }
}
