//! Huawei Router panel section (Design G).
//!
//! Server-rendered, no JS framework. Implements the honesty rules verbatim:
//! - PPTP is never offered (only explained as absent).
//! - The L2TP link is labeled ⚠️ WEAK+ and never called "secure" without
//!   the qualifier.
//! - The informed-consent checkbox is mandatory before the first credential
//!   display; passwords stay masked until Reveal.
//! - Design G §h limitations are disclosed on the page.
//! - The §f guide is rendered verbatim (English source of truth).
//!
//! Copy buttons: the panel has no JS (CSP `default-src 'self'`), so each
//! value renders in a readonly text field the owner can tap-to-select and
//! copy — the practical equivalent of a copy button without inline script.

use crate::api::{now_secs, AppState, HttpRequest, HttpResponse};
use crate::panel::{api_err, esc, fmt_bytes, form_body, nav, page, redirect};
use crate::{modem, store};

/// Honesty banner (Design G §d, verbatim). Rendered above everything.
pub(crate) fn honesty_html() -> String {
    format!(
        "<div class=\"warn-box\"><h2>Security status — read first</h2>\
         <p><strong>{}</strong></p>\
         <p>{}</p>\
         <p>{}</p></div>",
        esc(modem::HONESTY_L2TP_WEAK_PLUS),
        esc(modem::HONESTY_PPTP),
        esc(modem::HONESTY_NOT_AVAILABLE),
    )
}

/// Honest limitations (Design G §h). Auditors check these.
pub(crate) fn limitations_html() -> String {
    let mut s = String::from("<h2>Honest limitations</h2><ol class=\"limitations\">");
    for item in modem::LIMITATIONS {
        s.push_str(&format!("<li>{}</li>", esc(item)));
    }
    s.push_str("</ol>");
    s
}

/// Step-by-step guide + troubleshooting + IPv6 notice (Design G §f, verbatim).
pub(crate) fn guide_html() -> String {
    let mut s = String::from("<h2>Connection guide (Huawei H158-381, stock firmware)</h2><ol>");
    for step in modem::GUIDE_STEPS {
        s.push_str(&format!("<li>{}</li>", esc(step)));
    }
    s.push_str("</ol><h3>Troubleshooting</h3><ul>");
    for item in modem::GUIDE_TROUBLESHOOTING {
        s.push_str(&format!("<li>{}</li>", esc(item)));
    }
    s.push_str(&format!(
        "</ul><div class=\"warn-box\"><strong>IPv6 notice:</strong> {}</div>",
        esc(modem::GUIDE_IPV6_NOTICE)
    ));
    s
}

/// One readonly field = one "copy button" (no-JS panel: tap to select, copy).
fn copy_field(label: &str, value: &str) -> String {
    format!(
        "<div class=\"cfg-row\"><span class=\"cfg-label\">{}</span>\
         <input type=\"text\" readonly value=\"{}\"\
         title=\"tap the field to select, then copy\"></div>",
        esc(label),
        esc(value),
    )
}

/// Config card exactly per Design G §e:
/// Connection type / LNS address / Hostname / Tunnel password /
/// PPP user / PPP password / Security label / Status / Data used /
/// Revoke / Rotate.
///
/// Consumes the frozen `credentials` array ([ModemCredential]) in firmware
/// form order; secrets stay masked until revealed.
pub(crate) fn config_card_html(
    credentials: &serde_json::Value,
    account: &store::ModemAccount,
    data_used: &str,
    revealed: bool,
) -> String {
    let creds: Vec<&serde_json::Value> = credentials
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let mut rows = String::new();
    for c in creds {
        let label = c.get("label").and_then(|v| v.as_str()).unwrap_or("");
        let value = c.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let sensitive = c.get("sensitive").and_then(|v| v.as_bool()).unwrap_or(true);
        if sensitive && !revealed {
            rows.push_str(&format!(
                "<div class=\"cfg-row\"><span class=\"cfg-label\">{}</span>\
                 <span class=\"muted\">masked until Reveal</span></div>",
                esc(label),
            ));
        } else {
            // Revealed (or non-sensitive): show the real value. The masked
            // branch above is the only place bullets appear.
            rows.push_str(&copy_field(label, value));
        }
    }
    format!(
        "<div class=\"cfg-card\"><h3>Modem config — {}</h3>\
         {rows}\
         <div class=\"cfg-row\"><span class=\"cfg-label\">Security label</span><span>{}</span></div>\
         <div class=\"cfg-row\"><span class=\"cfg-label\">Status</span><span>{}</span></div>\
         <div class=\"cfg-row\"><span class=\"cfg-label\">Data used</span><span>{}</span></div>\
         <div class=\"cfg-actions\">\
         <form method=\"post\" action=\"/panel/huawei/{}/reveal\" style=\"display:inline\">\
         <button type=\"submit\">{}</button></form> \
         <form method=\"post\" action=\"/panel/huawei/{}/rotate\" style=\"display:inline\">\
         <button type=\"submit\">Rotate password</button></form> \
         <form method=\"post\" action=\"/panel/huawei/{}/revoke\" style=\"display:inline\">\
         <button type=\"submit\">Revoke account</button></form>\
         </div></div>",
        esc(&account.label),
        esc(modem::HONESTY_L2TP_WEAK_PLUS),
        esc(&account.status),
        esc(data_used),
        esc(&account.id),
        if revealed { "Hide" } else { "Reveal" },
        esc(&account.id),
        esc(&account.id),
    )
}

fn status_badge(account: &store::ModemAccount) -> String {
    let (cls, text) = match account.status.as_str() {
        "connected" => ("ok", "connected"),
        "disconnected" => ("warn", "disconnected"),
        "never" => ("muted", "never connected"),
        _ => ("muted", "unknown"),
    };
    let seen = account
        .last_seen_at
        .map(|t| format!(" · last seen {t}"))
        .unwrap_or_default();
    format!("<span class=\"{cls}\">{text}</span>{seen}")
}

fn account_data_used(conn: &rusqlite::Connection, account_id: &str) -> String {
    let key = format!("modem:{account_id}");
    let total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(bytes_up + bytes_down), 0) FROM usage_daily WHERE device_id=?1",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .unwrap_or(0);
    fmt_bytes(total)
}

pub async fn huawei_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let reveal_id = req.query.get("reveal").cloned().unwrap_or_default();
    let error = req.query.get("error").cloned().unwrap_or_default();
    let (accounts, usage) = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => {
                return page(
                    "Huawei Router",
                    &nav("huawei"),
                    "<p class=\"err\">db error</p>",
                )
            }
        };
        let accounts = store::list_modem_accounts(&conn).unwrap_or_default();
        let usage: Vec<String> = accounts
            .iter()
            .map(|a| account_data_used(&conn, &a.id))
            .collect();
        (accounts, usage)
    };

    let mut body = honesty_html();
    if !error.is_empty() {
        body.push_str(&format!("<p class=\"err\">{}</p>", esc(&error)));
    }

    // Revealed config card (consent-gated; each reveal is logged).
    if !reveal_id.is_empty() {
        match crate::api::modem_reveal_credentials(state, &reveal_id).await {
            Ok(credentials) => {
                if let Ok(conn) = state.db.lock() {
                    if let Ok(account) = store::get_modem_account(&conn, &reveal_id) {
                        let used = account_data_used(&conn, &account.id);
                        body.push_str(&config_card_html(&credentials, &account, &used, true));
                    }
                }
            }
            Err(e) => {
                let msg = String::from_utf8_lossy(&e.body).to_string();
                body.push_str(&format!("<p class=\"err\">{}</p>", esc(&msg)));
            }
        }
    }

    // Account list.
    body.push_str("<h2>Modem accounts</h2>");
    if accounts.is_empty() {
        body.push_str("<p class=\"muted\">No modem accounts yet. Create one below — one account per modem, independent from phone/laptop devices.</p>");
    } else {
        body.push_str("<table><tr><th>Label</th><th>PPP user</th><th>Status</th><th>Data used</th><th>Actions</th></tr>");
        for (account, used) in accounts.iter().zip(usage.iter()) {
            let consent_btn = if account.consent_at.is_none() && !account.revoked {
                format!(
                    "<form method=\"post\" action=\"/panel/huawei/{}/consent\" style=\"display:inline\">\
                     <input type=\"hidden\" name=\"acknowledged\" value=\"on\">\
                     <button type=\"submit\" title=\"{}\">I understand — show credentials</button></form> ",
                    esc(&account.id),
                    esc(modem::CONSENT_TEXT),
                )
            } else {
                String::new()
            };
            let revoke_btn = if account.revoked {
                format!(
                    "<form method=\"post\" action=\"/panel/huawei/{}/restore\" style=\"display:inline\">\
                     <button type=\"submit\">Restore</button></form>",
                    esc(&account.id),
                )
            } else {
                format!(
                    "<form method=\"post\" action=\"/panel/huawei/{}/reveal\" style=\"display:inline\">\
                     <button type=\"submit\">Reveal</button></form> \
                     <form method=\"post\" action=\"/panel/huawei/{}/revoke\" style=\"display:inline\">\
                     <button type=\"submit\">Revoke</button></form>",
                    esc(&account.id),
                    esc(&account.id),
                )
            };
            body.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
                esc(&account.label),
                esc(&account.username),
                status_badge(account),
                esc(used),
                consent_btn,
                revoke_btn,
            ));
        }
        body.push_str("</table>");
    }

    // Create form — consent checkbox is MANDATORY before credentials are shown.
    body.push_str(&format!(
        "<h2>New modem account</h2>\
         <form method=\"post\" action=\"/panel/huawei\">\
         <label>Label (e.g. home-5g) <input name=\"label\" maxlength=\"128\" required></label><br>\
         <label>PPP username (optional, auto: h158-xxxxxxxx) <input name=\"username\" maxlength=\"13\"></label><br>\
         <label>Hostname (optional) <input name=\"hostname\" maxlength=\"253\"></label><br>\
         <label>LNS address (optional, defaults to server setting) <input name=\"lns_address\" maxlength=\"253\"></label><br>\
         <label><input type=\"checkbox\" name=\"consent\" value=\"on\" required> <strong>{}</strong></label><br>\
         <button type=\"submit\">Create modem account</button></form>\
         <p class=\"muted\">Protocol is fixed: <strong>{}</strong>. {} \
         Persian translation of the consent text is the app team's job.</p>",
        esc(modem::CONSENT_TEXT),
        esc(modem::CONNECTION_TYPE),
        esc("PPTP is never offered."),
    ));

    body.push_str(&guide_html());
    body.push_str(&limitations_html());
    page("Huawei Router", &nav("huawei"), &body)
}

pub async fn huawei_create_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let consent = form.get("consent").map(|v| v == "on").unwrap_or(false);
    let input = crate::api::ModemCreateInput {
        label: form.get("label").cloned().unwrap_or_default(),
        username: form.get("username").cloned(),
        hostname: form.get("hostname").cloned(),
        lns_address: form.get("lns_address").cloned(),
        consent,
    };
    match crate::api::modem_issue(state, input).await {
        Ok(out) => {
            if out.credentials.is_some() {
                // Consent was given: one-time display of the config card.
                redirect(&format!("/panel/huawei?reveal={}", out.account.id))
            } else {
                // Created without consent: credentials stay hidden until the
                // "I understand" button is used.
                redirect("/panel/huawei")
            }
        }
        Err(e) => api_err(e),
    }
}

pub async fn huawei_consent_post(state: &AppState, id: &str, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    if form.get("acknowledged").map(|v| v == "on").unwrap_or(false) {
        let now = now_secs();
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return redirect("/panel/huawei?error=db+error"),
        };
        if store::get_modem_account(&conn, id).is_err() {
            return redirect("/panel/huawei");
        }
        let _ = store::record_modem_consent(&conn, id, now, "panel consent checkbox");
        let _ = store::log_event(
            &conn,
            now,
            "modem_consent",
            "panel",
            &serde_json::json!({"account_id": id}),
        );
        redirect(&format!("/panel/huawei?reveal={id}"))
    } else {
        redirect("/panel/huawei?error=consent+required")
    }
}

pub async fn huawei_reveal_post(_state: &AppState, id: &str) -> HttpResponse {
    // The GET renders (and logs) the reveal; the POST just routes there so
    // credentials are never in a GET-only URL the owner didn't ask for.
    redirect(&format!("/panel/huawei?reveal={id}"))
}

pub async fn huawei_rotate_post(state: &AppState, id: &str) -> HttpResponse {
    match crate::api::modem_rotate_credentials(state, id).await {
        Ok(_) => redirect(&format!("/panel/huawei?reveal={id}")),
        Err(e) => api_err(e),
    }
}

pub async fn huawei_revoke_post(state: &AppState, id: &str, revoked: bool) -> HttpResponse {
    let now = now_secs();
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return redirect("/panel/huawei?error=db+error"),
    };
    if store::set_modem_revoked(&conn, id, revoked).is_err() {
        return redirect("/panel/huawei");
    }
    let kind = if revoked {
        "modem_revoke"
    } else {
        "modem_restore"
    };
    let _ = store::log_event(
        &conn,
        now,
        kind,
        "panel",
        &serde_json::json!({"account_id": id}),
    );
    redirect("/panel/huawei")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_banner_is_verbatim_and_complete() {
        let html = honesty_html();
        assert!(html.contains("⚠️ WEAK+"));
        assert!(html.contains("does not generate PPTP credentials"));
        assert!(html.contains("❌ NOT AVAILABLE"));
        assert!(html.contains("The server refuses connections that do not negotiate 128-bit MPPE"));
    }

    #[test]
    fn honesty_banner_never_calls_link_secure_unqualified() {
        let html = honesty_html().to_lowercase();
        let mut rest = html.as_str();
        while let Some(i) = rest.find("secure") {
            let before = &rest[..i];
            assert!(
                before.ends_with("in") || before.ends_with("not "),
                "unqualified 'secure' in panel honesty banner"
            );
            rest = &rest[i + 6..];
        }
    }

    #[test]
    fn limitations_disclose_all_nine() {
        let html = limitations_html().to_lowercase();
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
            assert!(html.contains(kw), "limitation missing from panel: {kw}");
        }
    }

    #[test]
    fn guide_is_verbatim() {
        let html = guide_html();
        assert!(html.contains("Advanced &gt; Route &gt; VPN"));
        assert!(html.contains("192.168.8.1"));
        assert!(html.contains("IPv4-only"));
        assert!(html.contains("do not claim success"));
    }

    #[test]
    fn config_card_masks_secrets_until_reveal() {
        let card = serde_json::json!([
            {"field_id": "connection_type", "label": "Connection type", "value": "L2TP VPN client", "sensitive": false},
            {"field_id": "lns_address", "label": "LNS address", "value": "203.0.113.1", "sensitive": false},
            {"field_id": "hostname", "label": "Hostname", "value": "h158h-abcdef12", "sensitive": false},
            {"field_id": "tunnel_password", "label": "Tunnel password", "value": "TUNNELSECRET", "sensitive": true},
            {"field_id": "ppp_username", "label": "PPP user name", "value": "h158-abcdef12", "sensitive": false},
            {"field_id": "ppp_password", "label": "PPP password", "value": "PPPSECRET", "sensitive": true},
        ]);
        let account = store::ModemAccount {
            id: "macc-1".to_string(),
            label: "home-5g".to_string(),
            username: "h158-abcdef12".to_string(),
            hostname: "h158h-abcdef12".to_string(),
            lns_address: "203.0.113.1".to_string(),
            tunnel_secret: vec![],
            ppp_secret: vec![],
            consent_at: None,
            consent_note: String::new(),
            status: "never".to_string(),
            last_seen_at: None,
            created_at: 0,
            revoked: false,
        };
        let masked = config_card_html(&card, &account, "0 B", false);
        assert!(!masked.contains("TUNNELSECRET"));
        assert!(!masked.contains("PPPSECRET"));
        assert!(masked.contains("masked until Reveal"));
        assert!(masked.contains("L2TP VPN client"));
        // Section-e field order labels all present.
        for label in [
            "Connection type",
            "LNS address",
            "Hostname",
            "Tunnel password",
            "PPP user name",
            "PPP password",
            "Security label",
            "Status",
            "Data used",
        ] {
            assert!(masked.contains(label), "config card missing field: {label}");
        }
        let revealed = config_card_html(&card, &account, "0 B", true);
        assert!(revealed.contains("TUNNELSECRET"));
        assert!(revealed.contains("PPPSECRET"));
    }
}
