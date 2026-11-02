//! Database CRUD for the admin entities.
//!
//! All secret material is encrypted before it reaches these functions
//! (see [`crate::crypto::seal`]); the store deals in opaque blobs.

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("event detail key not allowed: {0}")]
    BadEventKey(String),
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub note: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub quota_bytes: Option<i64>,
    pub quota_mbps: Option<i64>,
    pub max_devices: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub user_id: String,
    pub label: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub device_id: String,
    pub inbound_tag: String,
    pub protocol: String,
    pub identity_hash: String,
    /// XChaCha20-Poly1305 sealed JSON (`IssuedSecret`).
    pub secret: Vec<u8>,
    pub created_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbound {
    pub tag: String,
    pub protocol: String,
    pub server_role: String,
    pub host: String,
    pub port: i64,
    /// JSON params for link builders: sni, pbk, sid, path, server_key, ...
    pub params: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub kind: String, // personal | external
    pub name: String,
    pub device_id: Option<String>,
    pub token_hash: Option<String>,
    pub source_url: Option<String>,
    pub imported_at: Option<i64>,
    pub body_crypt: Option<Vec<u8>>,
    pub config_count: i64,
    pub managed: bool,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cost {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub amount: f64,
    pub currency: String,
    pub period: String,
    pub volume_mb: Option<i64>,
    pub operator: Option<String>,
    pub tariff_note: String,
    pub recorded_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub at: i64,
    pub kind: String,
    pub actor: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRow {
    pub day: String,
    pub device_id: Option<String>,
    pub server_role: String,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub sessions_peak: i64,
}

/// Dedicated modem account (Design G, Huawei H158-381 native L2TP client).
///
/// Independent from phone/laptop devices: own table, own lifecycle,
/// individually revocable. `tunnel_secret` / `ppp_secret` are
/// XChaCha20-Poly1305 sealed passwords (same protections as
/// [`Credential::secret`]); they are decrypted only for display after the
/// informed-consent gate and for the one-time issuance response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModemAccount {
    pub id: String,
    pub label: String,
    /// `h158-<8 random lowercase alnum>`; user-renameable within the pattern.
    pub username: String,
    pub hostname: String,
    pub lns_address: String,
    /// Sealed tunnel password (L2TP tunnel auth, defense-in-depth only).
    pub tunnel_secret: Vec<u8>,
    /// Sealed PPP password (CHAP credential for xl2tpd/pppd).
    pub ppp_secret: Vec<u8>,
    /// Informed-consent timestamp (Design G §d). NULL until the owner
    /// confirms the ⚠️ WEAK+ label. Secrets are never shown before this.
    pub consent_at: Option<i64>,
    pub consent_note: String,
    /// never | connected | disconnected | unknown
    pub status: String,
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

fn opt_i64(r: &Row, i: usize) -> rusqlite::Result<Option<i64>> {
    r.get(i)
}

impl User {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            name: r.get(1)?,
            note: r.get(2)?,
            created_at: r.get(3)?,
            expires_at: opt_i64(r, 4)?,
            revoked: r.get::<_, i64>(5)? != 0,
            quota_bytes: opt_i64(r, 6)?,
            quota_mbps: opt_i64(r, 7)?,
            max_devices: r.get(8)?,
        })
    }
}

impl Device {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            user_id: r.get(1)?,
            label: r.get(2)?,
            created_at: r.get(3)?,
            expires_at: opt_i64(r, 4)?,
            revoked: r.get::<_, i64>(5)? != 0,
            last_seen_at: opt_i64(r, 6)?,
        })
    }
}

impl Credential {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            device_id: r.get(1)?,
            inbound_tag: r.get(2)?,
            protocol: r.get(3)?,
            identity_hash: r.get(4)?,
            secret: r.get(5)?,
            created_at: r.get(6)?,
            revoked: r.get::<_, i64>(7)? != 0,
        })
    }
}

impl Inbound {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        let params_str: String = r.get(5)?;
        Ok(Self {
            tag: r.get(0)?,
            protocol: r.get(1)?,
            server_role: r.get(2)?,
            host: r.get(3)?,
            port: r.get(4)?,
            params: serde_json::from_str(&params_str).unwrap_or(serde_json::Value::Null),
            enabled: r.get::<_, i64>(6)? != 0,
        })
    }
}

impl Subscription {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            kind: r.get(1)?,
            name: r.get(2)?,
            device_id: r.get(3)?,
            token_hash: r.get(4)?,
            source_url: r.get(5)?,
            imported_at: opt_i64(r, 6)?,
            body_crypt: r.get(7)?,
            config_count: r.get(8)?,
            managed: r.get::<_, i64>(9)? != 0,
            expires_at: opt_i64(r, 10)?,
            revoked: r.get::<_, i64>(11)? != 0,
            created_at: r.get(12)?,
        })
    }
}

impl Cost {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            kind: r.get(1)?,
            label: r.get(2)?,
            amount: r.get(3)?,
            currency: r.get(4)?,
            period: r.get(5)?,
            volume_mb: opt_i64(r, 6)?,
            operator: r.get(7)?,
            tariff_note: r.get(8)?,
            recorded_at: r.get(9)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Modem accounts (Design G)
// ---------------------------------------------------------------------------

impl ModemAccount {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            label: r.get(1)?,
            username: r.get(2)?,
            hostname: r.get(3)?,
            lns_address: r.get(4)?,
            tunnel_secret: r.get(5)?,
            ppp_secret: r.get(6)?,
            consent_at: opt_i64(r, 7)?,
            consent_note: r.get(8)?,
            status: r.get(9)?,
            last_seen_at: opt_i64(r, 10)?,
            created_at: r.get(11)?,
            revoked: r.get::<_, i64>(12)? != 0,
        })
    }
}

const MODEM_COLUMNS: &str = "id,label,username,hostname,lns_address,tunnel_secret,ppp_secret,consent_at,consent_note,status,last_seen_at,created_at,revoked";

pub fn create_modem_account(conn: &Connection, m: &ModemAccount) -> Result<(), StoreError> {
    let n = conn.execute(
        "INSERT INTO modem_accounts(id,label,username,hostname,lns_address,tunnel_secret,ppp_secret,consent_at,consent_note,status,last_seen_at,created_at,revoked)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            m.id,
            m.label,
            m.username,
            m.hostname,
            m.lns_address,
            m.tunnel_secret,
            m.ppp_secret,
            m.consent_at,
            m.consent_note,
            m.status,
            m.last_seen_at,
            m.created_at,
            m.revoked as i64,
        ],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict(format!(
            "modem account {} not inserted",
            m.id
        )));
    }
    Ok(())
}

pub fn list_modem_accounts(conn: &Connection) -> Result<Vec<ModemAccount>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MODEM_COLUMNS} FROM modem_accounts ORDER BY created_at ASC"
    ))?;
    let rows = stmt
        .query_map([], ModemAccount::from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn get_modem_account(conn: &Connection, id: &str) -> Result<ModemAccount, StoreError> {
    conn.query_row(
        &format!("SELECT {MODEM_COLUMNS} FROM modem_accounts WHERE id=?1"),
        params![id],
        ModemAccount::from_row,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("modem account {id}")),
        other => StoreError::Sqlite(other),
    })
}

pub fn get_modem_account_by_username(
    conn: &Connection,
    username: &str,
) -> Result<Option<ModemAccount>, StoreError> {
    conn.query_row(
        &format!("SELECT {MODEM_COLUMNS} FROM modem_accounts WHERE username=?1"),
        params![username],
        ModemAccount::from_row,
    )
    .optional()
    .map_err(StoreError::Sqlite)
}

pub fn set_modem_revoked(conn: &Connection, id: &str, revoked: bool) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE modem_accounts SET revoked=?1 WHERE id=?2",
        params![revoked as i64, id],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("modem account {id}")));
    }
    Ok(())
}

/// Record the informed-consent gate (Design G §d). Secrets may be shown
/// only after this is set.
pub fn record_modem_consent(
    conn: &Connection,
    id: &str,
    at: i64,
    note: &str,
) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE modem_accounts SET consent_at=?1, consent_note=?2 WHERE id=?3",
        params![at, note, id],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("modem account {id}")));
    }
    Ok(())
}

/// Rotate the sealed passwords of a modem account (atomic).
pub fn rotate_modem_secrets(
    conn: &Connection,
    id: &str,
    tunnel_secret: &[u8],
    ppp_secret: &[u8],
) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE modem_accounts SET tunnel_secret=?1, ppp_secret=?2 WHERE id=?3",
        params![tunnel_secret, ppp_secret, id],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("modem account {id}")));
    }
    Ok(())
}

/// Update connection status from the session monitor (provisioner §g.8).
pub fn update_modem_status(
    conn: &Connection,
    id: &str,
    status: &str,
    last_seen_at: Option<i64>,
) -> Result<(), StoreError> {
    if !matches!(status, "never" | "connected" | "disconnected" | "unknown") {
        return Err(StoreError::Conflict(format!("bad modem status {status}")));
    }
    let n = conn.execute(
        "UPDATE modem_accounts SET status=?1, last_seen_at=?2 WHERE id=?3",
        params![status, last_seen_at, id],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("modem account {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Smart split-routing rule-sets
// ---------------------------------------------------------------------------

/// One split-routing rule. `action`: "iran" (direct Iran egress) | "usa".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitRule {
    pub id: String,
    pub version: i64,
    /// domain | ip | cidr | geoip
    pub kind: String,
    pub value: String,
    pub action: String,
    pub priority: i64,
    pub enabled: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRuleset {
    pub version: i64,
    pub note: String,
    pub created_at: i64,
    pub active: bool,
    pub rule_count: i64,
}

impl SplitRule {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            version: r.get(1)?,
            kind: r.get(2)?,
            value: r.get(3)?,
            action: r.get(4)?,
            priority: r.get(5)?,
            enabled: r.get::<_, i64>(6)? != 0,
            note: r.get(7)?,
        })
    }
}

const RULE_COLUMNS: &str = "id,version,kind,value,action,priority,enabled,note";

pub fn active_ruleset_version(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row(
        "SELECT version FROM routing_rulesets WHERE active=1 ORDER BY version DESC LIMIT 1",
        [],
        |r| r.get(0),
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            StoreError::NotFound("no active routing rule-set".to_string())
        }
        other => StoreError::Sqlite(other),
    })
}

pub fn list_rulesets(conn: &Connection) -> Result<Vec<RoutingRuleset>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT s.version, s.note, s.created_at, s.active, COUNT(r.id)
         FROM routing_rulesets s LEFT JOIN routing_rules r ON r.version=s.version
         GROUP BY s.version ORDER BY s.version ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(RoutingRuleset {
                version: r.get(0)?,
                note: r.get(1)?,
                created_at: r.get(2)?,
                active: r.get::<_, i64>(3)? != 0,
                rule_count: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn create_ruleset(
    conn: &Connection,
    version: i64,
    note: &str,
    at: i64,
) -> Result<(), StoreError> {
    let n = conn.execute(
        "INSERT INTO routing_rulesets(version, note, created_at, active) VALUES (?1,?2,?3,0)",
        params![version, note, at],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict(format!(
            "rule-set v{version} not inserted"
        )));
    }
    Ok(())
}

pub fn next_ruleset_version(conn: &Connection) -> Result<i64, StoreError> {
    let max: Option<i64> = conn
        .query_row("SELECT MAX(version) FROM routing_rulesets", [], |r| {
            r.get(0)
        })
        .map_err(StoreError::Sqlite)?;
    Ok(max.unwrap_or(0) + 1)
}

/// Activate a version (rollback = activate an older version). Exactly one
/// version is active at a time.
pub fn activate_ruleset(conn: &Connection, version: i64) -> Result<(), StoreError> {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM routing_rulesets WHERE version=?1",
            params![version],
            |r| r.get(0),
        )
        .map_err(StoreError::Sqlite)?;
    if exists != 1 {
        return Err(StoreError::NotFound(format!("rule-set v{version}")));
    }
    conn.execute("UPDATE routing_rulesets SET active=0", [])?;
    conn.execute(
        "UPDATE routing_rulesets SET active=1 WHERE version=?1",
        params![version],
    )?;
    Ok(())
}

/// Snapshot all rules of `from_version` into a new `to_version`.
pub fn snapshot_ruleset(
    conn: &Connection,
    from_version: i64,
    to_version: i64,
) -> Result<i64, StoreError> {
    let rules = list_rules(conn, from_version)?;
    for r in &rules {
        conn.execute(
            "INSERT INTO routing_rules(id,version,kind,value,action,priority,enabled,note)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                uuid::Uuid::new_v4().to_string(),
                to_version,
                r.kind,
                r.value,
                r.action,
                r.priority,
                r.enabled as i64,
                r.note,
            ],
        )?;
    }
    Ok(rules.len() as i64)
}

pub fn list_rules(conn: &Connection, version: i64) -> Result<Vec<SplitRule>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {RULE_COLUMNS} FROM routing_rules WHERE version=?1 ORDER BY priority ASC, id ASC"
    ))?;
    let rows = stmt
        .query_map(params![version], SplitRule::from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn active_rules(conn: &Connection) -> Result<(i64, Vec<SplitRule>), StoreError> {
    let v = active_ruleset_version(conn)?;
    Ok((v, list_rules(conn, v)?))
}

pub fn get_rule(conn: &Connection, id: &str) -> Result<SplitRule, StoreError> {
    conn.query_row(
        &format!("SELECT {RULE_COLUMNS} FROM routing_rules WHERE id=?1"),
        params![id],
        SplitRule::from_row,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("rule {id}")),
        other => StoreError::Sqlite(other),
    })
}

pub fn create_rule(conn: &Connection, r: &SplitRule) -> Result<(), StoreError> {
    let n = conn.execute(
        "INSERT INTO routing_rules(id,version,kind,value,action,priority,enabled,note)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            r.id,
            r.version,
            r.kind,
            r.value,
            r.action,
            r.priority,
            r.enabled as i64,
            r.note,
        ],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict(format!("rule {} not inserted", r.id)));
    }
    Ok(())
}

pub fn update_rule(conn: &Connection, r: &SplitRule) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE routing_rules SET kind=?1,value=?2,action=?3,priority=?4,enabled=?5,note=?6
         WHERE id=?7",
        params![
            r.kind,
            r.value,
            r.action,
            r.priority,
            r.enabled as i64,
            r.note,
            r.id
        ],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("rule {}", r.id)));
    }
    Ok(())
}

pub fn delete_rule(conn: &Connection, id: &str) -> Result<(), StoreError> {
    let n = conn.execute("DELETE FROM routing_rules WHERE id=?1", params![id])?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("rule {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Events: allow-listed detail keys, no secrets.
// ---------------------------------------------------------------------------

/// Keys allowed in `events.detail`. Anything secret-shaped is rejected:
/// any key containing (case-insensitive) `secret`, `token`, `password`,
/// `passwd`, `key`, `cred`, or `auth` is refused.
pub fn check_event_detail(detail: &serde_json::Value) -> Result<(), StoreError> {
    let deny = [
        "secret", "token", "password", "passwd", "key", "cred", "auth",
    ];
    if let Some(map) = detail.as_object() {
        for k in map.keys() {
            let lower = k.to_lowercase();
            if deny.iter().any(|d| lower.contains(d)) {
                return Err(StoreError::BadEventKey(k.clone()));
            }
        }
    }
    Ok(())
}

pub fn log_event(
    conn: &Connection,
    at: i64,
    kind: &str,
    actor: &str,
    detail: &serde_json::Value,
) -> Result<i64, StoreError> {
    check_event_detail(detail)?;
    conn.execute(
        "INSERT INTO events(at, kind, actor, detail) VALUES (?1, ?2, ?3, ?4)",
        params![at, kind, actor, detail.to_string()],
    )?;
    Ok(conn.last_insert_rowid())
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

pub fn create_user(conn: &Connection, u: &User) -> Result<(), StoreError> {
    let n = conn.execute(
        "INSERT INTO users(id, name, note, created_at, expires_at, revoked, quota_bytes, quota_mbps, max_devices)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            u.id, u.name, u.note, u.created_at, u.expires_at,
            u.revoked as i64, u.quota_bytes, u.quota_mbps, u.max_devices
        ],
    )?;
    debug_assert_eq!(n, 1);
    Ok(())
}

pub fn list_users(conn: &Connection) -> Result<Vec<User>, StoreError> {
    let mut stmt = conn.prepare("SELECT id,name,note,created_at,expires_at,revoked,quota_bytes,quota_mbps,max_devices FROM users ORDER BY created_at")?;
    let rows = stmt.query_map([], User::from_row)?;
    let out: Result<Vec<_>, _> = rows.collect();
    Ok(out?)
}

pub fn get_user(conn: &Connection, id: &str) -> Result<User, StoreError> {
    conn.query_row(
        "SELECT id,name,note,created_at,expires_at,revoked,quota_bytes,quota_mbps,max_devices FROM users WHERE id=?1",
        params![id],
        User::from_row,
    )
    .optional()?
    .ok_or_else(|| StoreError::NotFound(format!("user {id}")))
}

pub fn patch_user(
    conn: &Connection,
    id: &str,
    name: Option<&str>,
    note: Option<&str>,
    quota_bytes: Option<Option<i64>>,
    quota_mbps: Option<Option<i64>>,
    expires_at: Option<Option<i64>>,
) -> Result<User, StoreError> {
    let mut u = get_user(conn, id)?;
    if let Some(n) = name {
        u.name = n.to_string();
    }
    if let Some(n) = note {
        u.note = n.to_string();
    }
    if let Some(q) = quota_bytes {
        u.quota_bytes = q;
    }
    if let Some(q) = quota_mbps {
        u.quota_mbps = q;
    }
    if let Some(e) = expires_at {
        u.expires_at = e;
    }
    conn.execute(
        "UPDATE users SET name=?1, note=?2, quota_bytes=?3, quota_mbps=?4, expires_at=?5 WHERE id=?6",
        params![u.name, u.note, u.quota_bytes, u.quota_mbps, u.expires_at, u.id],
    )?;
    Ok(u)
}

pub fn set_user_revoked(conn: &Connection, id: &str, revoked: bool) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE users SET revoked=?1 WHERE id=?2",
        params![revoked as i64, id],
    )?;
    if n == 0 {
        return Err(StoreError::NotFound(format!("user {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Devices & credentials
// ---------------------------------------------------------------------------

pub fn create_device(conn: &Connection, d: &Device) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO devices(id, user_id, label, created_at, expires_at, revoked, last_seen_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            d.id,
            d.user_id,
            d.label,
            d.created_at,
            d.expires_at,
            d.revoked as i64,
            d.last_seen_at
        ],
    )?;
    Ok(())
}

pub fn list_user_devices(conn: &Connection, user_id: &str) -> Result<Vec<Device>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,user_id,label,created_at,expires_at,revoked,last_seen_at FROM devices WHERE user_id=?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![user_id], Device::from_row)?;
    let out: Result<Vec<_>, _> = rows.collect();
    Ok(out?)
}

pub fn get_device(conn: &Connection, id: &str) -> Result<Device, StoreError> {
    conn.query_row(
        "SELECT id,user_id,label,created_at,expires_at,revoked,last_seen_at FROM devices WHERE id=?1",
        params![id],
        Device::from_row,
    )
    .optional()?
    .ok_or_else(|| StoreError::NotFound(format!("device {id}")))
}

pub fn set_device_revoked(conn: &Connection, id: &str, revoked: bool) -> Result<(), StoreError> {
    let tx = conn.unchecked_transaction()?;
    let n = tx.execute(
        "UPDATE devices SET revoked=?1 WHERE id=?2",
        params![revoked as i64, id],
    )?;
    if n == 0 {
        return Err(StoreError::NotFound(format!("device {id}")));
    }
    tx.execute(
        "UPDATE credentials SET revoked=?1 WHERE device_id=?2",
        params![revoked as i64, id],
    )?;
    tx.commit()?;
    Ok(())
}

/// GDPR-style forget: revoke and purge credential secrets.
pub fn delete_device(conn: &Connection, id: &str) -> Result<(), StoreError> {
    get_device(conn, id)?; // 404 if missing
    conn.execute("DELETE FROM devices WHERE id=?1", params![id])?;
    Ok(())
}

pub fn create_credential(conn: &Connection, c: &Credential) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO credentials(id, device_id, inbound_tag, protocol, identity_hash, secret, created_at, revoked)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            c.id, c.device_id, c.inbound_tag, c.protocol, c.identity_hash, c.secret,
            c.created_at, c.revoked as i64
        ],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            StoreError::Conflict(format!("credential for {} exists", c.inbound_tag))
        } else {
            StoreError::Sqlite(e)
        }
    })?;
    Ok(())
}

pub fn list_device_credentials(
    conn: &Connection,
    device_id: &str,
) -> Result<Vec<Credential>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,device_id,inbound_tag,protocol,identity_hash,secret,created_at,revoked
         FROM credentials WHERE device_id=?1 ORDER BY inbound_tag",
    )?;
    let rows = stmt.query_map(params![device_id], Credential::from_row)?;
    let out: Result<Vec<_>, _> = rows.collect();
    Ok(out?)
}

/// Active (non-revoked) credentials for a device: what goes in users files.
pub fn active_device_credentials(
    conn: &Connection,
    device_id: &str,
) -> Result<Vec<Credential>, StoreError> {
    Ok(list_device_credentials(conn, device_id)?
        .into_iter()
        .filter(|c| !c.revoked)
        .collect())
}

/// All active credentials on an inbound tag, across devices (for users files).
pub fn active_credentials_for_tag(
    conn: &Connection,
    tag: &str,
) -> Result<Vec<(Credential, Device)>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT c.id,c.device_id,c.inbound_tag,c.protocol,c.identity_hash,c.secret,c.created_at,c.revoked,
                d.id,d.user_id,d.label,d.created_at,d.expires_at,d.revoked,d.last_seen_at
         FROM credentials c JOIN devices d ON d.id=c.device_id
         JOIN users u ON u.id=d.user_id
         WHERE c.inbound_tag=?1 AND c.revoked=0 AND d.revoked=0 AND u.revoked=0",
    )?;
    let rows = stmt.query_map(params![tag], |r| {
        let cred = Credential {
            id: r.get(0)?,
            device_id: r.get(1)?,
            inbound_tag: r.get(2)?,
            protocol: r.get(3)?,
            identity_hash: r.get(4)?,
            secret: r.get(5)?,
            created_at: r.get(6)?,
            revoked: false,
        };
        let device = Device {
            id: r.get(8)?,
            user_id: r.get(9)?,
            label: r.get(10)?,
            created_at: r.get(11)?,
            expires_at: r.get(12)?,
            revoked: r.get::<_, i64>(13)? != 0,
            last_seen_at: r.get(14)?,
        };
        Ok((cred, device))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Decrypt every active credential on a tag and return (identity, label)
/// pairs for the `/etc/zray/users/<tag>.json` users file.
pub fn credential_identities_for_tag(
    conn: &Connection,
    tag: &str,
    db_key: &[u8; 32],
) -> Result<Vec<(String, String)>, StoreError> {
    use crate::crypto::open;
    let mut out = Vec::new();
    for (cred, device) in active_credentials_for_tag(conn, tag)? {
        let pt = open(db_key, &cred.secret)
            .map_err(|_| StoreError::Conflict("credential secret undecryptable".to_string()))?;
        let issued: crate::subs::IssuedSecret =
            serde_json::from_slice(&pt).map_err(|e| StoreError::Conflict(e.to_string()))?;
        out.push((issued.identity, device.label));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Inbounds
// ---------------------------------------------------------------------------

pub fn upsert_inbound(conn: &Connection, ib: &Inbound) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO inbounds(tag, protocol, server_role, host, port, params, enabled)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(tag) DO UPDATE SET protocol=excluded.protocol, server_role=excluded.server_role,
           host=excluded.host, port=excluded.port, params=excluded.params, enabled=excluded.enabled",
        params![
            ib.tag, ib.protocol, ib.server_role, ib.host, ib.port,
            ib.params.to_string(), ib.enabled as i64
        ],
    )?;
    Ok(())
}

pub fn list_inbounds(conn: &Connection) -> Result<Vec<Inbound>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT tag,protocol,server_role,host,port,params,enabled FROM inbounds ORDER BY tag",
    )?;
    let rows = stmt.query_map([], Inbound::from_row)?;
    let out: Result<Vec<_>, _> = rows.collect();
    Ok(out?)
}

pub fn enabled_inbounds(conn: &Connection) -> Result<Vec<Inbound>, StoreError> {
    Ok(list_inbounds(conn)?
        .into_iter()
        .filter(|i| i.enabled)
        .collect())
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

pub fn create_subscription(conn: &Connection, s: &Subscription) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO subscriptions(id, kind, name, device_id, token_hash, source_url, imported_at, body_crypt,
          config_count, managed, expires_at, revoked, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            s.id, s.kind, s.name, s.device_id, s.token_hash, s.source_url, s.imported_at,
            s.body_crypt, s.config_count, s.managed as i64, s.expires_at, s.revoked as i64, s.created_at
        ],
    )?;
    Ok(())
}

pub fn list_subscriptions(conn: &Connection) -> Result<Vec<Subscription>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,kind,name,device_id,token_hash,source_url,imported_at,body_crypt,config_count,managed,expires_at,revoked,created_at
         FROM subscriptions ORDER BY created_at",
    )?;
    let rows = stmt.query_map([], Subscription::from_row)?;
    let out: Result<Vec<_>, _> = rows.collect();
    Ok(out?)
}

pub fn get_subscription(conn: &Connection, id: &str) -> Result<Subscription, StoreError> {
    conn.query_row(
        "SELECT id,kind,name,device_id,token_hash,source_url,imported_at,body_crypt,config_count,managed,expires_at,revoked,created_at
         FROM subscriptions WHERE id=?1",
        params![id],
        Subscription::from_row,
    )
    .optional()?
    .ok_or_else(|| StoreError::NotFound(format!("subscription {id}")))
}

pub fn find_subscription_by_token_hash(
    conn: &Connection,
    token_hash: &str,
) -> Result<Subscription, StoreError> {
    conn.query_row(
        "SELECT id,kind,name,device_id,token_hash,source_url,imported_at,body_crypt,config_count,managed,expires_at,revoked,created_at
         FROM subscriptions WHERE token_hash=?1",
        params![token_hash],
        Subscription::from_row,
    )
    .optional()?
    .ok_or_else(|| StoreError::NotFound("subscription".to_string()))
}

pub fn set_subscription_revoked(
    conn: &Connection,
    id: &str,
    revoked: bool,
) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE subscriptions SET revoked=?1 WHERE id=?2",
        params![revoked as i64, id],
    )?;
    if n == 0 {
        return Err(StoreError::NotFound(format!("subscription {id}")));
    }
    Ok(())
}

pub fn rotate_subscription_token(
    conn: &Connection,
    id: &str,
    new_token_hash: &str,
) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE subscriptions SET token_hash=?1 WHERE id=?2 AND kind='personal'",
        params![new_token_hash, id],
    )?;
    if n == 0 {
        return Err(StoreError::NotFound(format!("personal subscription {id}")));
    }
    Ok(())
}

pub fn update_external_body(
    conn: &Connection,
    id: &str,
    body_crypt: &[u8],
    config_count: i64,
    imported_at: i64,
) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE subscriptions SET body_crypt=?1, config_count=?2, imported_at=?3 WHERE id=?4 AND kind='external'",
        params![body_crypt, config_count, imported_at, id],
    )?;
    if n == 0 {
        return Err(StoreError::NotFound(format!("external subscription {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

pub fn upsert_usage(
    conn: &Connection,
    day: &str,
    device_id: Option<&str>,
    server_role: &str,
    up: i64,
    down: i64,
    sessions_peak: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO usage_daily(day, device_id, server_role, bytes_up, bytes_down, sessions_peak)
         VALUES (?1,?2,?3,?4,?5,?6)
         ON CONFLICT(day, device_id, server_role) DO UPDATE SET
           bytes_up=bytes_up+excluded.bytes_up, bytes_down=bytes_down+excluded.bytes_down,
           sessions_peak=max(sessions_peak, excluded.sessions_peak)",
        params![day, device_id, server_role, up, down, sessions_peak],
    )?;
    Ok(())
}

pub fn usage_range(conn: &Connection, from: &str, to: &str) -> Result<Vec<UsageRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT day,device_id,server_role,bytes_up,bytes_down,sessions_peak FROM usage_daily
         WHERE day>=?1 AND day<=?2 ORDER BY day, device_id",
    )?;
    let rows = stmt.query_map(params![from, to], |r| {
        Ok(UsageRow {
            day: r.get(0)?,
            device_id: r.get(1)?,
            server_role: r.get(2)?,
            bytes_up: r.get(3)?,
            bytes_down: r.get(4)?,
            sessions_peak: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Bytes for a user in `[from_day, to_day]` (summed over their devices).
pub fn user_usage_bytes(
    conn: &Connection,
    user_id: &str,
    from_day: &str,
    to_day: &str,
) -> Result<(i64, i64), StoreError> {
    let (up, down): (Option<i64>, Option<i64>) = conn.query_row(
        "SELECT SUM(bytes_up), SUM(bytes_down) FROM usage_daily
         WHERE day>=?1 AND day<=?2 AND device_id IN (SELECT id FROM devices WHERE user_id=?3)",
        params![from_day, to_day, user_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((up.unwrap_or(0), down.unwrap_or(0)))
}

// ---------------------------------------------------------------------------
// Costs
// ---------------------------------------------------------------------------

pub fn create_cost(conn: &Connection, c: &Cost) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO costs(id, kind, label, amount, currency, period, volume_mb, operator, tariff_note, recorded_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            c.id, c.kind, c.label, c.amount, c.currency, c.period,
            c.volume_mb, c.operator, c.tariff_note, c.recorded_at
        ],
    )?;
    Ok(())
}

pub fn list_costs(conn: &Connection) -> Result<Vec<Cost>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,kind,label,amount,currency,period,volume_mb,operator,tariff_note,recorded_at
         FROM costs ORDER BY recorded_at DESC",
    )?;
    let rows = stmt.query_map([], Cost::from_row)?;
    let out: Result<Vec<_>, _> = rows.collect();
    Ok(out?)
}

pub fn delete_cost(conn: &Connection, id: &str) -> Result<(), StoreError> {
    let n = conn.execute("DELETE FROM costs WHERE id=?1", params![id])?;
    if n == 0 {
        return Err(StoreError::NotFound(format!("cost {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Settings & sessions
// ---------------------------------------------------------------------------

pub fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    conn.query_row(
        "SELECT value FROM settings WHERE key=?1",
        params![key],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(StoreError::from)
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn list_settings(conn: &Connection) -> Result<Vec<(String, String)>, StoreError> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn create_session(
    conn: &Connection,
    token_hash: &str,
    created_at: i64,
    expires_at: i64,
    ip: &str,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO sessions(token_hash, created_at, expires_at, ip) VALUES (?1,?2,?3,?4)",
        params![token_hash, created_at, expires_at, ip],
    )?;
    Ok(())
}

pub fn get_session(
    conn: &Connection,
    token_hash: &str,
    now: i64,
) -> Result<Option<String>, StoreError> {
    conn.query_row(
        "SELECT ip FROM sessions WHERE token_hash=?1 AND expires_at>?2",
        params![token_hash, now],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(StoreError::from)
}

pub fn delete_session(conn: &Connection, token_hash: &str) -> Result<(), StoreError> {
    conn.execute(
        "DELETE FROM sessions WHERE token_hash=?1",
        params![token_hash],
    )?;
    Ok(())
}

pub fn prune_sessions(conn: &Connection, now: i64) -> Result<(), StoreError> {
    conn.execute("DELETE FROM sessions WHERE expires_at<=?1", params![now])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Events queries
// ---------------------------------------------------------------------------

pub fn list_events(
    conn: &Connection,
    kind: Option<&str>,
    from: Option<i64>,
    limit: i64,
) -> Result<Vec<Event>, StoreError> {
    let (sql, p1, p2): (&str, Option<String>, Option<i64>) = match (kind, from) {
        (Some(k), Some(f)) => (
            "SELECT id,at,kind,actor,detail FROM events WHERE kind=?1 AND at>=?2 ORDER BY id DESC LIMIT ?3",
            Some(k.to_string()),
            Some(f),
        ),
        (Some(k), None) => (
            "SELECT id,at,kind,actor,detail FROM events WHERE kind=?1 ORDER BY id DESC LIMIT ?2",
            Some(k.to_string()),
            None,
        ),
        (None, Some(f)) => (
            "SELECT id,at,kind,actor,detail FROM events WHERE at>=?1 ORDER BY id DESC LIMIT ?2",
            None,
            Some(f),
        ),
        (None, None) => (
            "SELECT id,at,kind,actor,detail FROM events ORDER BY id DESC LIMIT ?1",
            None,
            None,
        ),
    };
    let mut stmt = conn.prepare(sql)?;
    let detail_of = |s: String| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
    let rows: Result<Vec<Event>, _> = match (p1, p2) {
        (Some(k), Some(f)) => stmt
            .query_map(params![k, f, limit], |r| {
                Ok(Event {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    kind: r.get(2)?,
                    actor: r.get(3)?,
                    detail: detail_of(r.get::<_, String>(4)?),
                })
            })?
            .collect(),
        (Some(k), None) => stmt
            .query_map(params![k, limit], |r| {
                Ok(Event {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    kind: r.get(2)?,
                    actor: r.get(3)?,
                    detail: detail_of(r.get::<_, String>(4)?),
                })
            })?
            .collect(),
        (None, Some(f)) => stmt
            .query_map(params![f, limit], |r| {
                Ok(Event {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    kind: r.get(2)?,
                    actor: r.get(3)?,
                    detail: detail_of(r.get::<_, String>(4)?),
                })
            })?
            .collect(),
        (None, None) => stmt
            .query_map(params![limit], |r| {
                Ok(Event {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    kind: r.get(2)?,
                    actor: r.get(3)?,
                    detail: detail_of(r.get::<_, String>(4)?),
                })
            })?
            .collect(),
    };
    rows.map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_conn() -> (TempDir, Connection) {
        let dir = TempDir(crate::test_temp_dir("zero-admin-store"));
        let conn = db::open(&dir.0.join("admin.db")).unwrap();
        (dir, conn)
    }

    fn sample_user(id: &str) -> User {
        User {
            id: id.to_string(),
            name: "Test User".to_string(),
            note: String::new(),
            created_at: 1000,
            expires_at: None,
            revoked: false,
            quota_bytes: None,
            quota_mbps: None,
            max_devices: 8,
        }
    }

    #[test]
    fn event_detail_rejects_secret_keys() {
        for bad in [
            "secret",
            "api_token",
            "password",
            "privateKey",
            "credentials",
            "auth_header",
            "SECRET_VALUE",
        ] {
            let d = serde_json::json!({ bad: "x" });
            assert!(
                check_event_detail(&d).is_err(),
                "key {bad} should be rejected"
            );
        }
        let ok = serde_json::json!({"from": "a", "to": "b", "reason": "tunnel_failed", "count": 3});
        assert!(check_event_detail(&ok).is_ok());
        // Non-object details pass through.
        assert!(check_event_detail(&serde_json::json!("plain")).is_ok());
    }

    #[test]
    fn user_crud_round_trip() {
        let (_d, conn) = test_conn();
        create_user(&conn, &sample_user("u1")).unwrap();
        let u = get_user(&conn, "u1").unwrap();
        assert_eq!(u.name, "Test User");
        assert_eq!(list_users(&conn).unwrap().len(), 1);
        patch_user(
            &conn,
            "u1",
            Some("Renamed"),
            None,
            Some(Some(1024)),
            None,
            None,
        )
        .unwrap();
        let u = get_user(&conn, "u1").unwrap();
        assert_eq!(u.name, "Renamed");
        assert_eq!(u.quota_bytes, Some(1024));
        set_user_revoked(&conn, "u1", true).unwrap();
        assert!(get_user(&conn, "u1").unwrap().revoked);
        set_user_revoked(&conn, "u1", false).unwrap();
        assert!(!get_user(&conn, "u1").unwrap().revoked);
        assert!(matches!(
            get_user(&conn, "missing").unwrap_err(),
            StoreError::NotFound(_)
        ));
    }

    #[test]
    fn device_revocation_cascades_to_credentials() {
        let (_d, conn) = test_conn();
        create_user(&conn, &sample_user("u1")).unwrap();
        let dev = Device {
            id: "d1".to_string(),
            user_id: "u1".to_string(),
            label: "phone".to_string(),
            created_at: 1000,
            expires_at: None,
            revoked: false,
            last_seen_at: None,
        };
        create_device(&conn, &dev).unwrap();
        create_credential(
            &conn,
            &Credential {
                id: "c1".to_string(),
                device_id: "d1".to_string(),
                inbound_tag: "reality-in".to_string(),
                protocol: "vless".to_string(),
                identity_hash: "h1".to_string(),
                secret: b"blob".to_vec(),
                created_at: 1000,
                revoked: false,
            },
        )
        .unwrap();
        assert_eq!(active_device_credentials(&conn, "d1").unwrap().len(), 1);
        set_device_revoked(&conn, "d1", true).unwrap();
        assert!(get_device(&conn, "d1").unwrap().revoked);
        assert!(active_device_credentials(&conn, "d1").unwrap().is_empty());
        // Unique(device, tag) is enforced.
        let dup = create_credential(
            &conn,
            &Credential {
                id: "c2".to_string(),
                device_id: "d1".to_string(),
                inbound_tag: "reality-in".to_string(),
                protocol: "vless".to_string(),
                identity_hash: "h2".to_string(),
                secret: b"blob".to_vec(),
                created_at: 1001,
                revoked: false,
            },
        );
        assert!(matches!(dup.unwrap_err(), StoreError::Conflict(_)));
        // Delete purges secrets (cascade).
        delete_device(&conn, "d1").unwrap();
        assert!(list_device_credentials(&conn, "d1").unwrap().is_empty());
    }

    #[test]
    fn usage_upsert_accumulates() {
        let (_d, conn) = test_conn();
        upsert_usage(&conn, "2026-11-01", Some("d1"), "exit", 100, 200, 2).unwrap();
        upsert_usage(&conn, "2026-11-01", Some("d1"), "exit", 50, 25, 5).unwrap();
        let rows = usage_range(&conn, "2026-11-01", "2026-11-01").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bytes_up, 150);
        assert_eq!(rows[0].bytes_down, 225);
        assert_eq!(rows[0].sessions_peak, 5);
    }

    #[test]
    fn cost_tariff_defaults_to_unknown() {
        let (_d, conn) = test_conn();
        create_cost(
            &conn,
            &Cost {
                id: "c1".to_string(),
                kind: "data_package".to_string(),
                label: "Carrier pack".to_string(),
                amount: 100.0,
                currency: "IRR".to_string(),
                period: "monthly".to_string(),
                volume_mb: Some(102400),
                operator: Some("MCI".to_string()),
                tariff_note: "unknown".to_string(),
                recorded_at: 1000,
            },
        )
        .unwrap();
        let costs = list_costs(&conn).unwrap();
        assert_eq!(costs[0].tariff_note, "unknown");
        delete_cost(&conn, "c1").unwrap();
        assert!(list_costs(&conn).unwrap().is_empty());
    }

    #[test]
    fn settings_and_sessions_round_trip() {
        let (_d, conn) = test_conn();
        assert!(get_setting(&conn, "dns.mode").unwrap().is_none());
        set_setting(&conn, "dns.mode", "\"strict\"").unwrap();
        assert_eq!(
            get_setting(&conn, "dns.mode").unwrap().as_deref(),
            Some("\"strict\"")
        );
        create_session(&conn, "hash1", 1000, 2000, "127.0.0.1").unwrap();
        assert_eq!(
            get_session(&conn, "hash1", 1500).unwrap().as_deref(),
            Some("127.0.0.1")
        );
        assert!(get_session(&conn, "hash1", 2500).unwrap().is_none());
        delete_session(&conn, "hash1").unwrap();
        assert!(get_session(&conn, "hash1", 1500).unwrap().is_none());
    }
}

// ---------------------------------------------------------------------------
// Sticky exit policies (triple-tunnel / dual-stack LEAD DELTA)
// ---------------------------------------------------------------------------

/// One sticky-exit policy. `scope`: "domain" | "device". `policy`:
/// "force_ipv4" | "force_ipv6" | "auto" | "prefer_stable_ipv4".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickyPolicy {
    pub id: String,
    pub scope: String,
    pub target: String,
    pub policy: String,
    pub affinity_secs: i64,
    pub note: String,
    pub created_at: i64,
}

impl StickyPolicy {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            scope: r.get(1)?,
            target: r.get(2)?,
            policy: r.get(3)?,
            affinity_secs: r.get(4)?,
            note: r.get(5)?,
            created_at: r.get(6)?,
        })
    }
}

pub fn list_sticky_policies(conn: &Connection) -> Result<Vec<StickyPolicy>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,scope,target,policy,affinity_secs,note,created_at
         FROM sticky_policies ORDER BY scope, target",
    )?;
    let rows = stmt
        .query_map([], StickyPolicy::from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn create_sticky_policy(conn: &Connection, p: &StickyPolicy) -> Result<(), StoreError> {
    let n = conn.execute(
        "INSERT INTO sticky_policies(id,scope,target,policy,affinity_secs,note,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            p.id,
            p.scope,
            p.target,
            p.policy,
            p.affinity_secs,
            p.note,
            p.created_at
        ],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict(format!(
            "policy {} not inserted",
            p.id
        )));
    }
    Ok(())
}

pub fn update_sticky_policy(conn: &Connection, p: &StickyPolicy) -> Result<(), StoreError> {
    let n = conn.execute(
        "UPDATE sticky_policies SET policy=?1,affinity_secs=?2,note=?3 WHERE id=?4",
        params![p.policy, p.affinity_secs, p.note, p.id],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("sticky policy {}", p.id)));
    }
    Ok(())
}

pub fn delete_sticky_policy(conn: &Connection, id: &str) -> Result<(), StoreError> {
    let n = conn.execute("DELETE FROM sticky_policies WHERE id=?1", params![id])?;
    if n != 1 {
        return Err(StoreError::NotFound(format!("sticky policy {id}")));
    }
    Ok(())
}

/// Effective policy for a (domain, device) pair: device policy wins over
/// domain policy; absent both → the engine default (auto + sticky session).
pub fn effective_sticky_policy(
    conn: &Connection,
    domain: Option<&str>,
    device: Option<&str>,
) -> Result<Option<StickyPolicy>, StoreError> {
    if let Some(dev) = device {
        let mut stmt = conn.prepare(
            "SELECT id,scope,target,policy,affinity_secs,note,created_at
             FROM sticky_policies WHERE scope='device' AND target=?1",
        )?;
        let hit: Option<StickyPolicy> = stmt
            .query_row(params![dev], StickyPolicy::from_row)
            .optional()
            .map_err(StoreError::Sqlite)?;
        if hit.is_some() {
            return Ok(hit);
        }
    }
    if let Some(dom) = domain {
        let mut stmt = conn.prepare(
            "SELECT id,scope,target,policy,affinity_secs,note,created_at
             FROM sticky_policies WHERE scope='domain' AND target=?1",
        )?;
        let hit: Option<StickyPolicy> = stmt
            .query_row(params![dom.to_ascii_lowercase()], StickyPolicy::from_row)
            .optional()
            .map_err(StoreError::Sqlite)?;
        return Ok(hit);
    }
    Ok(None)
}
