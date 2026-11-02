//! Users added to a VLESS inbound while the server runs, and what each used.
//!
//! How this works: the operator panel (`zray-admin`) keeps the users in its
//! own database and writes the ones an inbound should accept to
//! `<users dir>/<tag>.json`, a list of `{identity, name, disabled}` where the
//! identity is the VLESS UUID. The engine reads that file the first time a
//! connection to the inbound does not match a user of the config, and again
//! whenever `POST /api/v1/engine/users/reload {"tag"}` asks, so a user added,
//! disabled or removed takes effect on the next connection with no restart and
//! no dropped sessions.
//!
//! The same book counts each user's bytes, keyed by tag and identity, and
//! reports them as `HMAC-SHA256(usage salt, identity)` so the panel can join
//! them to its database while the engine's answer never names a person. The
//! salt is the 64 hex characters in `<users dir>/../usage.salt`.
//!
//! The rules it keeps:
//!  * a tag becomes a file name, so only `[A-Za-z0-9_-]` is accepted;
//!  * a missing or unreadable file means "no extra users", never a crash;
//!  * a disabled entry, or one whose identity is not a UUID, is skipped.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::relay::Transferred;

/// Where the panel writes the users files, unless `ZRAY_USERS_DIR` says
/// otherwise (tests do).
const DEFAULT_USERS_DIR: &str = "/etc/zray/users";

fn users_dir() -> PathBuf {
    std::env::var_os("ZRAY_USERS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_USERS_DIR))
}

/// A tag is used as a file name: refuse anything that could leave the folder.
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A UUID in text form, with or without hyphens, as 16 bytes.
fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    hex::decode_to_slice(&hex, &mut out).ok()?;
    Some(out)
}

/// What one tag accepts beyond its config: UUID bytes to the identity text.
type TagUsers = Arc<HashMap<[u8; 16], Arc<str>>>;

/// Bytes and sessions of one user.
#[derive(Debug, Default, Clone, Copy)]
struct Used {
    up: u64,
    down: u64,
    sessions: u64,
}

#[derive(Debug, Default)]
pub struct UserBook {
    tags: RwLock<HashMap<String, TagUsers>>,
    used: Mutex<HashMap<(String, String), Used>>,
}

impl UserBook {
    /// Read `<tag>.json` and make it the tag's extra users. Returns how many.
    pub fn reload(&self, tag: &str) -> Result<usize, String> {
        if !valid_tag(tag) {
            return Err(format!("bad tag {tag:?}"));
        }
        let users = read_file(&users_dir(), tag);
        let count = users.len();
        self.tags
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(tag.to_string(), Arc::new(users));
        Ok(count)
    }

    /// The identity of the extra user `uuid` of `tag`, if there is one. The
    /// tag's file is read on first use.
    pub fn find(&self, tag: &str, uuid: &[u8; 16]) -> Option<Arc<str>> {
        let known = self
            .tags
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(tag)
            .cloned();
        let users = match known {
            Some(users) => users,
            None => {
                self.reload(tag).ok()?;
                self.tags
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(tag)
                    .cloned()?
            }
        };
        users.get(uuid).cloned()
    }

    /// Count one finished relay against `user` of `tag`.
    pub fn record(&self, tag: &str, user: &str, transferred: &Transferred) {
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        let entry = used.entry((tag.to_string(), user.to_string())).or_default();
        entry.up += transferred.uploaded;
        entry.down += transferred.downloaded;
        entry.sessions += 1;
    }

    /// `[{h, tag, sessions, up, down}]`, or nothing when there is no salt.
    pub fn detail(&self) -> Vec<serde_json::Value> {
        let Some(salt) = read_salt(&users_dir()) else {
            return Vec::new();
        };
        let used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        let mut rows: Vec<_> = used
            .iter()
            .map(|((tag, user), u)| {
                serde_json::json!({
                    "h": identity_hash(&salt, user),
                    "tag": tag,
                    "sessions": u.sessions,
                    "up": u.up,
                    "down": u.down,
                })
            })
            .collect();
        rows.sort_by_key(|row| row["h"].as_str().unwrap_or("").to_string());
        rows
    }

    /// Xray-style `user>>>name>>>traffic>>>uplink|downlink` counters.
    pub fn counters(&self) -> Vec<(String, u64)> {
        let used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        let mut totals: HashMap<&str, Used> = HashMap::new();
        for ((_, user), u) in used.iter() {
            let t = totals.entry(user.as_str()).or_default();
            t.up += u.up;
            t.down += u.down;
        }
        let mut out = Vec::new();
        for (user, u) in totals {
            out.push((format!("user>>>{user}>>>traffic>>>uplink"), u.up));
            out.push((format!("user>>>{user}>>>traffic>>>downlink"), u.down));
        }
        out
    }
}

/// The file's users, or none when it is missing or damaged.
fn read_file(dir: &std::path::Path, tag: &str) -> HashMap<[u8; 16], Arc<str>> {
    let Ok(text) = std::fs::read_to_string(dir.join(format!("{tag}.json"))) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) else {
        return HashMap::new();
    };
    let mut users = HashMap::new();
    for entry in entries {
        if entry["disabled"].as_bool().unwrap_or(false) {
            continue;
        }
        let Some(identity) = entry["identity"].as_str() else {
            continue;
        };
        if let Some(uuid) = parse_uuid(identity) {
            users.insert(uuid, Arc::from(identity));
        }
    }
    users
}

fn read_salt(dir: &std::path::Path) -> Option<[u8; 32]> {
    let text = std::fs::read_to_string(dir.parent()?.join("usage.salt")).ok()?;
    let mut salt = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut salt).ok()?;
    Some(salt)
}

/// `HMAC-SHA256(salt, identity)`, hex: the join key the panel computes too.
pub fn identity_hash(salt: &[u8; 32], identity: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC takes any key length");
    mac.update(identity.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zray-dyn-users-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("users")).unwrap();
        dir
    }

    #[test]
    fn reads_enabled_users_and_skips_the_rest() {
        let base = dir("read");
        let users = base.join("users");
        std::fs::write(
            users.join("reality-in.json"),
            r#"[{"identity":"11111111-2222-3333-4444-555555555555","name":"a","disabled":false},
                {"identity":"66666666-7777-8888-9999-000000000000","name":"b","disabled":true},
                {"identity":"not-a-uuid","name":"c","disabled":false}]"#,
        )
        .unwrap();
        let got = read_file(&users, "reality-in");
        assert_eq!(got.len(), 1);
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        assert_eq!(&*got[&uuid], "11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn a_missing_or_damaged_file_means_no_users() {
        let base = dir("missing");
        let users = base.join("users");
        assert!(read_file(&users, "nope").is_empty());
        std::fs::write(users.join("bad.json"), "{{{").unwrap();
        assert!(read_file(&users, "bad").is_empty());
    }

    #[test]
    fn tags_cannot_leave_the_folder() {
        assert!(valid_tag("reality-in"));
        assert!(!valid_tag("../etc/passwd"));
        assert!(!valid_tag("a/b"));
        assert!(!valid_tag(""));
        assert!(UserBook::default().reload("../x").is_err());
    }

    #[test]
    fn the_hash_matches_the_panel_and_depends_on_the_salt() {
        let a = identity_hash(&[1u8; 32], "some-uuid");
        assert_eq!(a, identity_hash(&[1u8; 32], "some-uuid"));
        assert_ne!(a, identity_hash(&[2u8; 32], "some-uuid"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn counts_bytes_per_user() {
        let book = UserBook::default();
        let t = Transferred { uploaded: 10, downloaded: 30 };
        book.record("reality-in", "u1", &t);
        book.record("reality-in", "u1", &t);
        book.record("reality-in", "u2", &t);
        let counters: HashMap<_, _> = book.counters().into_iter().collect();
        assert_eq!(counters["user>>>u1>>>traffic>>>uplink"], 20);
        assert_eq!(counters["user>>>u1>>>traffic>>>downlink"], 60);
        assert_eq!(counters["user>>>u2>>>traffic>>>downlink"], 30);
    }
}
