//! Modem accounts: dedicated L2TP credentials for Huawei H158-381
//! (5G CPE Pro 5) native VPN clients (Design G).
//!
//! The modem is a first-class client with its own account, independent from
//! phone/laptop devices: one account per modem, individually revocable.
//! Generation follows Design G §e; the honesty copy is verbatim from
//! Design G §d/§f/§h and is enforced by tests (`honesty_copy_*`).
//!
//! Security posture (non-negotiable):
//! - PPTP is never offered (only explained as absent).
//! - The L2TP link is labeled ⚠️ WEAK+ and never called "secure"
//!   without the qualifier.
//! - The informed-consent gate is mandatory before the first credential
//!   display.

use rand::RngCore;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModemError {
    #[error("bad username: {0}")]
    BadUsername(String),
    #[error("status file: {0}")]
    StatusFile(String),
}

const USERNAME_PREFIX: &str = "h158-";
const USERNAME_RANDOM_LEN: usize = 8;
const PPP_PASSWORD_LEN: usize = 24;
const TUNNEL_PASSWORD_LEN: usize = 16;

/// Typing-friendly alphabet (no 0/O/1/l) — these passwords are typed into
/// the modem's web UI by hand.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
const USERNAME_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn random_from(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(len);
    let mut b = [0u8; 1];
    for _ in 0..len {
        rng.fill_bytes(&mut b);
        out.push(alphabet[(b[0] % alphabet.len() as u8) as usize] as char);
    }
    out
}

/// Generate a modem username: `h158-<8 random lowercase alnum>` (Design G §e).
pub fn generate_username() -> String {
    format!(
        "{USERNAME_PREFIX}{}",
        random_from(USERNAME_ALPHABET, USERNAME_RANDOM_LEN)
    )
}

/// Validate a user-supplied username (renameable, but must keep the shape).
pub fn validate_username(username: &str) -> Result<(), ModemError> {
    let ok = username.len() == USERNAME_PREFIX.len() + USERNAME_RANDOM_LEN
        && username.starts_with(USERNAME_PREFIX)
        && username[USERNAME_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(ModemError::BadUsername(format!(
            "must match h158-<8 lowercase alnum>, got {username:?}"
        )))
    }
}

/// Generate a 24-char PPP password from the CSPRNG (Design G §e).
pub fn generate_ppp_password() -> String {
    random_from(PASSWORD_ALPHABET, PPP_PASSWORD_LEN)
}

/// Generate a 16-char L2TP tunnel password (defense in depth, not a
/// security boundary — Design G §c).
pub fn generate_tunnel_password() -> String {
    random_from(PASSWORD_ALPHABET, TUNNEL_PASSWORD_LEN)
}

/// Generate a hostname value for the modem's optional Hostname field.
pub fn generate_hostname() -> String {
    format!(
        "h158h-{}",
        random_from(USERNAME_ALPHABET, USERNAME_RANDOM_LEN)
    )
}

// ---------------------------------------------------------------------------
// Honesty copy — verbatim from Design G. Do not soften. Tests pin these.
// ---------------------------------------------------------------------------

/// Design G §d — PPTP label + wording.
pub const HONESTY_PPTP: &str = "⛔ INSECURE — PPTP's encryption (MPPE/RC4 with MS-CHAPv2) is broken and can be decrypted by a determined attacker. This panel does not generate PPTP credentials. PPTP is not offered as a choice; it is documented here only to explain its absence.";

/// Design G §d — plain L2TP label + wording (⚠️ WEAK, informed consent required).
pub const HONESTY_L2TP_WEAK: &str = "⚠️ WEAK — L2TP by itself provides no encryption. With the mandatory MPPE-128 setting below, traffic between the modem and the server gets RC4-based encryption: it defeats casual snooping but NOT a determined network observer. It is not modern-VPN-grade. Use it with eyes open — it is far better than no VPN, and it is the only protocol this modem's stock firmware offers.";

/// Design G §d — L2TP + required MPPE-128 (⚠️ WEAK+, what we actually configure).
pub const HONESTY_L2TP_WEAK_PLUS: &str = "⚠️ WEAK+ — L2TP + mandatory MPPE-128 (best available on this hardware). L2TP by itself provides no encryption. With the mandatory MPPE-128 setting, traffic between the modem and the server gets RC4-based encryption: it defeats casual snooping but NOT a determined network observer. It is not modern-VPN-grade. The server refuses connections that do not negotiate 128-bit MPPE, so the link can never silently fall back to plaintext. Use it with eyes open — it is far better than no VPN, and it is the only protocol this modem's stock firmware offers.";

/// Design G §d — protocols with no evidence on the H158-381.
pub const HONESTY_NOT_AVAILABLE: &str = "❌ NOT AVAILABLE — L2TP/IPsec, WireGuard and OpenVPN: no public evidence that the H158-381 stock firmware supports these. They are not offered because they do not exist — not because we omitted them.";

/// The fixed connection type shown in the config output (Design G §e).
/// Never editable, never anything else: the firmware offers only this.
pub const CONNECTION_TYPE: &str = "L2TP VPN client";

/// Informed-consent checkbox text. The owner confirmed the checkbox is
/// mandatory before the first credential display. (Persian translation is
/// the Android/app team's job — English is the source of truth here.)
pub const CONSENT_TEXT: &str = "I understand the ⚠️ WEAK+ limitations described above: the modem link resists casual snooping but NOT a determined network observer, there is no kill switch on the modem, and full-tunnel behavior is unverified. I want to see the credentials.";

/// Design G §h — honest limitations, disclosed in the panel. Auditors check these.
pub const LIMITATIONS: &[&str] = &[
    "1. No kill switch on the modem. If the L2TP session drops, the modem routes traffic directly over the mobile network until it reconnects. The panel shows live connection status; it cannot prevent the fallback. Do not imply otherwise anywhere in UI copy.",
    "2. Weak link crypto. L2TP + mandatory MPPE-128 resists casual snooping, not a determined observer. The Iran↔USA tunnel and everything past the gateway keep full modern crypto — the weak leg is only modem→gateway.",
    "3. Full-tunnel behavior UNVERIFIED. Whether all LAN-device traffic uses the tunnel must be tested on the real unit (connect → IP check from a LAN device). If the firmware only routes some subnets, this feature will be scoped accordingly — do not claim success before the test.",
    "4. IPv6 bypass risk. Mitigation: IPv4-only APN while VPN is active (see the IPv6 notice below). The server cannot fix the modem's stack.",
    "5. Throughput ceiling UNVERIFIED for the H158-381 (precedent ≈ 50 Mbps on older Huawei CPEs with the L2TP client on). Set expectations: fine for browsing/video, not for saturating a 5G link.",
    "6. Single VPN connection. The modem holds one L2TP session — no multi-protocol, no smart failover on the modem itself. All intelligence (protocol switching, path failover, split routing) lives on the Iran gateway.",
    "7. DNS control is partial. We push DNS via PPP, but a LAN device with hardcoded DNS (DoH in the browser, manual DNS on the device) bypasses it. The gateway cannot see inside the modem's LAN.",
    "8. Firmware variance. Operator-branded builds (STC etc.) may rename or hide the VPN page. The guide's path (Advanced > Route > VPN) matches Huawei's official doc; if your unit differs, report it instead of guessing.",
    "9. No remote management of the modem. The panel generates credentials and guides; it cannot push config into the modem (no API, no config import). \"Manage the modem from the panel\" = credentials + status + guide, nothing more.",
];

/// Design G §f — step-by-step guide, English source of truth (rendered
/// verbatim; Persian translation is the Android agent's job).
pub const GUIDE_STEPS: &[&str] = &[
    "1. Connect your phone or computer to the modem (Wi-Fi or LAN cable).",
    "2. Open http://192.168.8.1 in the browser and log in with the modem's admin password.",
    "3. Go to Advanced > Route > VPN.",
    "4. Turn Enable VPN on.",
    "5. Set Connection type to L2TP VPN client.",
    "6. Fill in the LNS address, Hostname, Tunnel password, PPP user name and PPP password from the config card above (use the Copy buttons).",
    "7. Click Save.",
    "8. Wait for Connection Status to show Connected.",
    "9. Verify: on a device connected to the modem, open an IP-check page — the reported IP should be the VPN exit IP shown in the panel, not your mobile operator's IP.",
    "10. If it stays on \"Connecting\": double-check the LNS address and PPP credentials; then see the troubleshooting section.",
];

/// Design G §f — troubleshooting, rendered verbatim.
pub const GUIDE_TROUBLESHOOTING: &[&str] = &[
    "\"Connected\" but IP unchanged → the modem may not be routing all traffic through the tunnel (UNVERIFIED behavior). Report it — this is a firmware limitation we cannot fix; do not claim success.",
    "Frequent drops → L2TP has no built-in kill switch on this modem; traffic falls back to direct until it reconnects. Check the panel's status card.",
    "Slow speeds → the modem's CPU forwards VPN traffic in software; expect well under the 5G radio rate (precedent ≈ 50 Mbps on older models). This is hardware, not our server.",
];

/// Design G §f — IPv6 notice, rendered verbatim.
pub const GUIDE_IPV6_NOTICE: &str = "If your mobile plan uses IPv6, set the modem's APN to IPv4-only while the VPN is active (Mobile network > APN settings). Otherwise IPv6 traffic may bypass the VPN.";

// ---------------------------------------------------------------------------
// Session-monitor status file (provisioner §g.8)
// ---------------------------------------------------------------------------

/// One account's snapshot as written by the provisioner's session monitor.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ModemSessionSnapshot {
    #[serde(default)]
    pub session_up: bool,
    #[serde(default)]
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub bytes_up: u64,
    #[serde(default)]
    pub bytes_down: u64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct StatusFile {
    #[allow(dead_code)]
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(default)]
    pub accounts: HashMap<String, ModemSessionSnapshot>,
}

/// Read the session-monitor status file written by the provisioner
/// (Design G §g.8). Returns `None` when the file is absent/unparseable —
/// callers must report status "unknown", never invent one.
pub fn read_status_file(path: &str) -> Option<HashMap<String, ModemSessionSnapshot>> {
    let data = std::fs::read(path).ok()?;
    if data.len() > 1_048_576 {
        return None; // sanity cap: never parse a giant file
    }
    let parsed: StatusFile = serde_json::from_slice(&data).ok()?;
    Some(parsed.accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_shape() {
        for _ in 0..50 {
            let u = generate_username();
            validate_username(&u).unwrap();
        }
        assert!(validate_username("h158-TOOLONG123").is_err());
        assert!(validate_username("pptp-user").is_err());
        assert!(validate_username("h158-ABCDef12").is_err()); // uppercase rejected
    }

    #[test]
    fn password_lengths_and_alphabet() {
        let p = generate_ppp_password();
        assert_eq!(p.len(), PPP_PASSWORD_LEN);
        let t = generate_tunnel_password();
        assert_eq!(t.len(), TUNNEL_PASSWORD_LEN);
        for c in p.chars().chain(t.chars()) {
            assert!(
                PASSWORD_ALPHABET.contains(&(c as u8)),
                "password char outside typing alphabet: {c}"
            );
        }
    }

    #[test]
    fn pptp_is_never_offered_wording() {
        // The panel must explain PPTP's absence, never present it as a choice.
        assert!(HONESTY_PPTP.contains("does not generate PPTP credentials"));
        assert!(!HONESTY_PPTP.to_lowercase().contains("select pptp"));
    }

    #[test]
    fn weak_plus_never_calls_link_secure_unqualified() {
        // "secure" may only appear inside "insecure"/negations, never as a
        // positive claim about the modem link.
        for text in [
            HONESTY_L2TP_WEAK,
            HONESTY_L2TP_WEAK_PLUS,
            HONESTY_NOT_AVAILABLE,
        ] {
            let lower = text.to_lowercase();
            let mut rest = lower.as_str();
            while let Some(i) = rest.find("secure") {
                let before = &rest[..i];
                assert!(
                    before.ends_with("in") || before.ends_with("not "),
                    "unqualified 'secure' in honesty copy: {text}"
                );
                rest = &rest[i + 6..];
            }
        }
    }

    #[test]
    fn limitations_cover_all_nine() {
        assert_eq!(LIMITATIONS.len(), 9);
        let joined = LIMITATIONS.join("\n").to_lowercase();
        for kw in [
            "kill switch",
            "weak leg",
            "unverified",
            "ipv6",
            "throughput",
            "single vpn",
            "dns control is partial",
            "firmware variance",
            "no remote management",
        ] {
            assert!(joined.contains(kw), "limitation missing: {kw}");
        }
    }

    #[test]
    fn status_file_missing_means_unknown() {
        assert!(read_status_file("/nonexistent/zero-admin-modem-status.json").is_none());
    }
}
