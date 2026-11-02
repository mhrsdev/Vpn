//! Server-rendered web panel (no JS framework, no build step).
//!
//! Pages under `/panel/`, session-cookie auth, embedded CSS. Follows the
//! `tide_users.rs` precedent: every dynamic string through [`esc`], CSP
//! headers, `Referrer-Policy: no-referrer`.

use crate::api::{
    check_rate, now_secs, panel_auth, render_device_configs, session_of, sync_tags, today_utc,
    AppState, HttpRequest, HttpResponse,
};
use crate::{crypto, store, subs};
use std::collections::HashMap;

const CSS: &str = include_str!("../assets/panel.css");

/// HTML-escape one dynamic string. Every user-controlled value goes through here.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn page(title: &str, nav: &str, body: &str) -> HttpResponse {
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{} — zray-admin</title>\
         <style>{CSS}</style></head><body>\
         <nav>{nav}</nav><main><h1>{}</h1>{body}</main></body></html>",
        esc(title),
        esc(title),
    );
    let r = HttpResponse {
        status: 200,
        content_type: "text/html; charset=utf-8",
        extra: vec![
            ("Content-Security-Policy".to_string(), "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'".to_string()),
            ("Referrer-Policy".to_string(), "no-referrer".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ],
        body: html.into_bytes(),
    };
    let _ = nav;
    r
}

pub(crate) fn nav(active: &str) -> String {
    let items = [
        ("", "Dashboard"),
        ("servers", "Servers"),
        ("link", "Link"),
        ("users", "Users"),
        ("devices", "Devices"),
        ("subscriptions", "Subscriptions"),
        ("quotas", "Quotas"),
        ("usage", "Usage"),
        ("exit-ip", "Exit IP"),
        ("routes", "Routes"),
        ("dns", "DNS"),
        ("costs", "Costs"),
        ("huawei", "Huawei Router"),
        ("ha", "HA"),
        ("routing", "Routing"),
        ("triple", "Triple Tunnel"),
        ("sticky", "Sticky Exit"),
        ("backup", "Backup"),
        ("errors", "Errors"),
    ];
    let mut s = String::from("<strong>zray-admin</strong> ");
    for (slug, label) in items {
        let cls = if slug == active {
            " class=\"active\""
        } else {
            ""
        };
        s.push_str(&format!("<a href=\"/panel/{slug}\"{cls}>{label}</a> "));
    }
    s.push_str("<form method=\"post\" action=\"/panel/logout\" style=\"display:inline\"><button>Logout</button></form>");
    s
}

pub(crate) fn form_body(req: &HttpRequest) -> HashMap<String, String> {
    let ct = req
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("");
    if ct.starts_with("application/x-www-form-urlencoded") {
        let mut m = HashMap::new();
        for pair in String::from_utf8_lossy(&req.body).split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                m.insert(pct_decode(k), pct_decode(v));
            }
        }
        m
    } else {
        HashMap::new()
    }
}

fn pct_decode(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h: String = chars.by_ref().take(2).collect();
            if let Ok(b) = u8::from_str_radix(&h, 16) {
                out.push(b as char);
                continue;
            }
            out.push('%');
            out.push_str(&h);
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn redirect(to: &str) -> HttpResponse {
    HttpResponse {
        status: 303,
        content_type: "text/plain",
        extra: vec![("Location".to_string(), to.to_string())],
        body: b"redirect".to_vec(),
    }
}

pub(crate) fn api_err(e: HttpResponse) -> HttpResponse {
    // Panel-friendly rendering of an API error response.
    let msg = String::from_utf8_lossy(&e.body).into_owned();
    page(
        "Error",
        &nav(""),
        &format!(
            "<p class=\"err\">Error {}: {}</p><p><a href=\"/panel/\">back</a></p>",
            e.status,
            esc(&msg)
        ),
    )
}

/// Panel entry point, called from the main router for `/panel/*`.
pub async fn handle_panel(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let tail: &[&str] = if segs.first() == Some(&"panel") {
        &segs[1..]
    } else {
        &segs
    };
    match (req.method.as_str(), tail) {
        ("GET", []) | ("GET", [""]) => {
            if panel_auth(state, req).is_err() {
                return redirect("/panel/login");
            }
            dashboard(state).await
        }
        ("GET", ["login"]) => login_page(None),
        ("POST", ["login"]) => login_post(state, req).await,
        ("POST", ["logout"]) => {
            if let Some(h) = session_of(state, req) {
                if let Ok(conn) = state.db.lock() {
                    let _ = store::delete_session(&conn, &h);
                }
            }
            let mut r = redirect("/panel/login");
            r.extra.push((
                "Set-Cookie".to_string(),
                "zadmin=; HttpOnly; SameSite=Strict; Path=/panel; Max-Age=0".to_string(),
            ));
            r
        }
        ("GET", ["style.css"]) => HttpResponse {
            status: 200,
            content_type: "text/css",
            extra: vec![],
            body: CSS.as_bytes().to_vec(),
        },
        _ => {
            if panel_auth(state, req).is_err() {
                return redirect("/panel/login");
            }
            match (req.method.as_str(), tail) {
                ("GET", ["servers"]) => servers_page(state).await,
                ("GET", ["link"]) => link_page(state).await,
                ("GET", ["users"]) => users_page(state).await,
                ("POST", ["users"]) => user_create_post(state, req).await,
                ("POST", ["users", id, "revoke"]) => user_revoke_post(state, id, true).await,
                ("POST", ["users", id, "restore"]) => user_revoke_post(state, id, false).await,
                ("GET", ["devices"]) => devices_page(state, req).await,
                ("POST", ["devices", "issue"]) => device_issue_post(state, req).await,
                ("POST", ["devices", id, "revoke"]) => device_act_post(state, id, "revoke").await,
                ("POST", ["devices", id, "restore"]) => device_act_post(state, id, "restore").await,
                ("POST", ["devices", id, "reissue"]) => device_reissue_post(state, id).await,
                ("POST", ["devices", id, "delete"]) => device_delete_post(state, id).await,
                ("GET", ["devices", id, "configs"]) => device_configs_page(state, id).await,
                ("GET", ["subscriptions"]) => subs_page(state).await,
                ("POST", ["subscriptions", "personal"]) => sub_personal_post(state, req).await,
                ("POST", ["subscriptions", id, "rotate"]) => sub_rotate_post(state, id).await,
                ("POST", ["subscriptions", id, "revoke"]) => sub_revoke_post(state, id).await,
                ("POST", ["subscriptions", "external"]) => sub_external_post(state, req).await,
                ("GET", ["quotas"]) => quotas_page(state).await,
                ("GET", ["usage"]) => usage_page(state, req).await,
                ("GET", ["exit-ip"]) => exit_ip_page(state).await,
                ("GET", ["errors"]) => errors_page(state).await,
                ("GET", ["routes"]) => routes_page(state).await,
                ("GET", ["dns"]) => dns_page(state).await,
                ("POST", ["dns"]) => dns_post(state, req).await,
                ("GET", ["costs"]) => costs_page(state).await,
                ("POST", ["costs"]) => cost_create_post(state, req).await,
                ("POST", ["costs", id, "delete"]) => cost_delete_post(state, id).await,
                ("GET", ["backup"]) => backup_page(),
                ("POST", ["backup"]) => backup_post(state, req).await,
                ("GET", ["huawei"]) => crate::huawei_panel::huawei_page(state, req).await,
                ("POST", ["huawei"]) => crate::huawei_panel::huawei_create_post(state, req).await,
                ("POST", ["huawei", id, "consent"]) => {
                    crate::huawei_panel::huawei_consent_post(state, id, req).await
                }
                ("POST", ["huawei", id, "reveal"]) => {
                    crate::huawei_panel::huawei_reveal_post(state, id).await
                }
                ("POST", ["huawei", id, "rotate"]) => {
                    crate::huawei_panel::huawei_rotate_post(state, id).await
                }
                ("POST", ["huawei", id, "revoke"]) => {
                    crate::huawei_panel::huawei_revoke_post(state, id, true).await
                }
                ("POST", ["huawei", id, "restore"]) => {
                    crate::huawei_panel::huawei_revoke_post(state, id, false).await
                }
                ("GET", ["ha"]) => crate::ha_panel::ha_page(state, req).await,
                ("POST", ["ha", "primary"]) => crate::ha_panel::ha_primary_post(state, req).await,
                ("POST", ["ha", "mode"]) => crate::ha_panel::ha_mode_post(state, req).await,
                ("POST", ["ha", "settings"]) => crate::ha_panel::ha_settings_post(state, req).await,
                ("GET", ["routing"]) => crate::routing_panel::routing_page(state, req).await,
                ("POST", ["routing", "rules"]) => {
                    crate::routing_panel::rule_create_post(state, req).await
                }
                ("POST", ["routing", "rules", id, "delete"]) => {
                    crate::routing_panel::rule_delete_post(state, id).await
                }
                ("POST", ["routing", "rules", id, "toggle"]) => {
                    crate::routing_panel::rule_toggle_post(state, id).await
                }
                ("POST", ["routing", "rulesets"]) => {
                    crate::routing_panel::ruleset_snapshot_post(state, req).await
                }
                ("POST", ["routing", "rulesets", version, "activate"]) => {
                    match version.parse::<i64>() {
                        Ok(v) => crate::routing_panel::ruleset_activate_post(state, v).await,
                        Err(_) => redirect("/panel/routing"),
                    }
                }
                ("GET", ["triple"]) => crate::triple_panel::triple_page(state, req).await,
                ("POST", ["triple", "probe-budget"]) => {
                    crate::triple_panel::probe_budget_post(state, req).await
                }
                ("POST", ["triple", "test", kind]) => {
                    crate::triple_panel::triple_test_post(state, kind, req).await
                }
                ("GET", ["sticky"]) => crate::triple_panel::sticky_page(state, req).await,
                ("POST", ["sticky"]) => crate::triple_panel::sticky_create_post(state, req).await,
                ("POST", ["sticky", id, "delete"]) => {
                    crate::triple_panel::sticky_delete_post(state, id).await
                }
                _ => page("Not found", &nav(""), "<p>Unknown panel page.</p>"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

fn login_page(error: Option<&str>) -> HttpResponse {
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "{err}<form method=\"post\" action=\"/panel/login\">\
         <label>Admin password <input type=\"password\" name=\"password\" autofocus></label>\
         <button type=\"submit\">Login</button></form>"
    );
    page("Login", "", &body)
}

async fn login_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    if check_rate(state, req.peer.ip(), "auth", 10.0, Some(1)).is_err() {
        return login_page(Some("too many attempts, try again later"));
    }
    let form = form_body(req);
    let password = form.get("password").map(String::as_str).unwrap_or("");
    let hash = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return login_page(Some("internal error")),
        };
        match store::get_setting(&conn, "panel.password_hash").unwrap_or(None) {
            Some(h) => h,
            None => return login_page(Some("panel password not set (provision must set it)")),
        }
    };
    if !crypto::verify_password(password, &hash) {
        return login_page(Some("invalid credentials"));
    }
    let token = crypto::new_token();
    let h = crypto::token_hash(&token);
    let now = now_secs();
    {
        let conn = state.db.lock().unwrap();
        let _ = store::create_session(&conn, &h, now, now + 12 * 3600, &req.peer.ip().to_string());
        let _ = store::log_event(
            &conn,
            now,
            "login",
            "panel",
            &serde_json::json!({"ip": req.peer.ip().to_string()}),
        );
    }
    let mut r = redirect("/panel/");
    r.extra.push((
        "Set-Cookie".to_string(),
        format!("zadmin={token}; HttpOnly; SameSite=Strict; Path=/panel; Max-Age=43200"),
    ));
    r
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

async fn dashboard(state: &AppState) -> HttpResponse {
    let engine_ok = state.engine.health().await.is_ok();
    let today = today_utc();
    let (up, down, users_n, devices_n) = {
        let conn = state.db.lock().unwrap();
        let rows = store::usage_range(&conn, &today, &today).unwrap_or_default();
        let up: i64 = rows.iter().map(|r| r.bytes_up).sum();
        let down: i64 = rows.iter().map(|r| r.bytes_down).sum();
        let users_n = store::list_users(&conn).map(|u| u.len()).unwrap_or(0);
        let devices_n: usize = store::list_users(&conn)
            .map(|users| {
                users
                    .iter()
                    .map(|u| {
                        store::list_user_devices(&conn, &u.id)
                            .map(|d| d.len())
                            .unwrap_or(0)
                    })
                    .sum()
            })
            .unwrap_or(0);
        (up, down, users_n, devices_n)
    };
    let exit_ip = state.exit_ip.lock().unwrap().clone();
    let body = format!(
        "<div class=\"cards\">\
         <div class=\"card\"><h3>Role</h3><p>{} ({:?})</p></div>\
         <div class=\"card\"><h3>Engine</h3><p>{}</p></div>\
         <div class=\"card\"><h3>Users / Devices</h3><p>{} / {}</p></div>\
         <div class=\"card\"><h3>Today</h3><p>↑ {} ↓ {}</p></div>\
         <div class=\"card\"><h3>Exit IP</h3><p>{}</p></div>\
         </div>\
         <p><a href=\"/panel/servers\">servers</a> · <a href=\"/panel/usage\">usage</a> · \
         <a href=\"/panel/routes\">route history</a> · <a href=\"/panel/errors\">error log</a></p>",
        esc(&state.config.role.to_string()),
        state.config.mode,
        if engine_ok {
            "reachable"
        } else {
            "<span class=\"warn\">unreachable (degraded mode)</span>"
        },
        users_n,
        devices_n,
        fmt_bytes(up),
        fmt_bytes(down),
        exit_ip
            .map(|e| esc(&e.ip))
            .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
    );
    page("Dashboard", &nav(""), &body)
}

pub(crate) fn fmt_bytes(b: i64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

// ---------------------------------------------------------------------------
// Servers & link
// ---------------------------------------------------------------------------

async fn servers_page(state: &AppState) -> HttpResponse {
    let health = state.engine.health().await.ok();
    let tunnel = state.engine.tunnel().await.ok();
    let body = format!(
        "<h2>Local server ({})</h2>\
         <p>Engine: {}</p>\
         <h3>Engine /health</h3><pre>{}</pre>\
         <h3>Tunnel</h3><pre>{}</pre>\
         <form method=\"post\" action=\"/panel/probe-local\" style=\"display:none\"></form>",
        esc(&state.config.role.to_string()),
        if health.is_some() {
            "reachable"
        } else {
            "unreachable"
        },
        esc(&health
            .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
            .unwrap_or_else(|| "n/a".to_string())),
        esc(&tunnel
            .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
            .unwrap_or_else(|| "unknown (engine may predate GET /tunnel)".to_string())),
    );
    page("Servers", &nav("servers"), &body)
}

async fn link_page(state: &AppState) -> HttpResponse {
    let tunnel = state.engine.tunnel().await.ok();
    let conn = state.db.lock().unwrap();
    let events = store::list_events(&conn, Some("route_change"), None, 50).unwrap_or_default();
    let mut rows = String::new();
    for e in events {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.at,
            esc(&e.actor),
            esc(&e.detail.to_string())
        ));
    }
    let body = format!(
        "<h2>Inter-server tunnel</h2><pre>{}</pre>\
         <h2>Failover history</h2>\
         <table><tr><th>at</th><th>actor</th><th>detail</th></tr>{rows}</table>",
        esc(&tunnel
            .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
            .unwrap_or_else(|| "unknown".to_string())),
    );
    page("Inter-server link", &nav("link"), &body)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

async fn users_page(state: &AppState) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let users = store::list_users(&conn).unwrap_or_default();
    let mut rows = String::new();
    for u in users {
        let toggle = if u.revoked {
            format!("<form method=\"post\" action=\"/panel/users/{}/restore\"><button>restore</button></form>", u.id)
        } else {
            format!("<form method=\"post\" action=\"/panel/users/{}/revoke\"><button class=\"danger\">revoke</button></form>", u.id)
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{toggle}</td></tr>",
            esc(&u.name),
            esc(&u.note),
            u.quota_bytes
                .map(fmt_bytes)
                .unwrap_or_else(|| "∞".to_string()),
            if u.revoked { "revoked" } else { "active" },
            u.expires_at
                .map(|e| e.to_string())
                .unwrap_or_else(|| "never".to_string()),
        ));
    }
    let body = format!(
        "<table><tr><th>name</th><th>note</th><th>quota</th><th>status</th><th>expires</th><th></th></tr>{rows}</table>\
         <h2>New user</h2>\
         <form method=\"post\" action=\"/panel/users\">\
         <label>name <input name=\"name\" required maxlength=\"128\"></label>\
         <label>note <input name=\"note\" maxlength=\"256\"></label>\
         <label>quota (bytes, empty=unlimited) <input name=\"quota_bytes\" type=\"number\" min=\"0\"></label>\
         <label>max devices <input name=\"max_devices\" type=\"number\" value=\"8\" min=\"1\" max=\"64\"></label>\
         <button type=\"submit\">create</button></form>"
    );
    page("Users", &nav("users"), &body)
}

async fn user_create_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let name = form.get("name").map(String::as_str).unwrap_or("").trim();
    if name.is_empty() {
        return redirect("/panel/users");
    }
    let now = now_secs();
    let user = store::User {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        note: form.get("note").cloned().unwrap_or_default(),
        created_at: now,
        expires_at: None,
        revoked: false,
        quota_bytes: form.get("quota_bytes").and_then(|v| v.parse::<i64>().ok()),
        quota_mbps: None,
        max_devices: form
            .get("max_devices")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(8)
            .clamp(1, 64),
    };
    let conn = state.db.lock().unwrap();
    let _ = store::create_user(&conn, &user);
    let _ = store::log_event(
        &conn,
        now,
        "user_create",
        "panel",
        &serde_json::json!({"user_id": user.id}),
    );
    redirect("/panel/users")
}

async fn user_revoke_post(state: &AppState, id: &str, revoked: bool) -> HttpResponse {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = state.db.lock().unwrap();
        let _ = store::set_user_revoked(&conn, id, revoked);
        let devices = store::list_user_devices(&conn, id).unwrap_or_default();
        for d in &devices {
            let _ = store::set_device_revoked(&conn, &d.id, revoked);
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
            if revoked { "revoke" } else { "restore" },
            "panel",
            &serde_json::json!({"user_id": id}),
        );
        tags.into_iter().collect()
    };
    let _ = sync_tags(state, &tags).await;
    redirect("/panel/users")
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

async fn devices_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let users = store::list_users(&conn).unwrap_or_default();
    let filter_user = req_query(req, "user");
    let mut rows = String::new();
    let mut user_opts = String::from("<option value=\"\">all users</option>");
    for u in &users {
        let sel = filter_user.as_deref() == Some(u.id.as_str());
        user_opts.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            esc(&u.id),
            if sel { " selected" } else { "" },
            esc(&u.name)
        ));
        if filter_user.as_deref().is_some_and(|f| f != u.id) {
            continue;
        }
        for d in store::list_user_devices(&conn, &u.id).unwrap_or_default() {
            let creds = store::list_device_credentials(&conn, &d.id).unwrap_or_default();
            let proto_list = creds
                .iter()
                .map(|c| esc(&c.protocol))
                .collect::<Vec<_>>()
                .join(", ");
            let toggle = if d.revoked {
                format!("<form method=\"post\" action=\"/panel/devices/{}/restore\" style=\"display:inline\"><button>restore</button></form>", d.id)
            } else {
                format!("<form method=\"post\" action=\"/panel/devices/{}/revoke\" style=\"display:inline\"><button class=\"danger\">revoke</button></form>", d.id)
            };
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td><a href=\"/panel/devices/{}/configs\">configs</a> {toggle} \
                 <form method=\"post\" action=\"/panel/devices/{}/reissue\" style=\"display:inline\"><button>reissue</button></form> \
                 <form method=\"post\" action=\"/panel/devices/{}/delete\" style=\"display:inline\" \
                 onsubmit=\"return confirm('forget this device and purge its secrets?')\">\
                 <button class=\"danger\">forget</button></form></td></tr>",
                esc(&u.name), esc(&d.label), proto_list,
                if d.revoked { "revoked" } else { "active" },
                d.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "never".to_string()),
                d.id, d.id, d.id,
            ));
        }
    }
    let inbounds = store::list_inbounds(&conn).unwrap_or_default();
    let mut ib_checks = String::new();
    for ib in &inbounds {
        if !ib.enabled || !subs::issuable(&ib.protocol) {
            continue;
        }
        ib_checks.push_str(&format!(
            "<label><input type=\"checkbox\" name=\"inbound\" value=\"{}\" checked> {} ({})</label> ",
            esc(&ib.tag), esc(&ib.tag), esc(&ib.protocol)
        ));
    }
    let mut user_select = String::new();
    for u in &users {
        user_select.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            esc(&u.id),
            esc(&u.name)
        ));
    }
    let body = format!(
        "<form method=\"get\" action=\"/panel/devices\"><label>user <select name=\"user\" onchange=\"this.form.submit()\">{user_opts}</select></label></form>\
         <table><tr><th>user</th><th>device</th><th>protocols</th><th>status</th><th>expires</th><th>actions</th></tr>{rows}</table>\
         <h2>Issue device</h2>\
         <form method=\"post\" action=\"/panel/devices/issue\">\
         <label>user <select name=\"user_id\">{user_select}</select></label>\
         <label>label <input name=\"label\" required maxlength=\"128\"></label>\
         <div>{ib_checks}</div>\
         <button type=\"submit\">issue</button></form>"
    );
    page("Devices", &nav("devices"), &body)
}

fn req_query(req: &HttpRequest, key: &str) -> Option<String> {
    req.query.get(key).cloned()
}

async fn device_issue_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let user_id = form.get("user_id").cloned().unwrap_or_default();
    let label = form.get("label").cloned().unwrap_or_default();
    // Multiple `inbound` checkboxes: collect all values.
    let mut tags = Vec::new();
    for pair in String::from_utf8_lossy(&req.body).split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "inbound" {
                tags.push(pct_decode(v));
            }
        }
    }
    let now = now_secs();
    match crate::api::issue_device(
        state,
        &user_id,
        label.trim(),
        if tags.is_empty() { None } else { Some(tags) },
        None,
        now,
    )
    .await
    {
        Ok(_) => redirect("/panel/devices"),
        Err(e) => api_err(e),
    }
}

async fn device_act_post(state: &AppState, id: &str, action: &str) -> HttpResponse {
    let now = now_secs();
    let revoked = action == "revoke";
    let tags: Vec<String> = {
        let conn = state.db.lock().unwrap();
        if store::get_device(&conn, id).is_err() {
            return redirect("/panel/devices");
        }
        let _ = store::set_device_revoked(&conn, id, revoked);
        let tags: Vec<String> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| c.inbound_tag).collect())
            .unwrap_or_default();
        let _ = store::log_event(
            &conn,
            now,
            action,
            "panel",
            &serde_json::json!({"device_id": id}),
        );
        tags
    };
    let _ = sync_tags(state, &tags).await;
    redirect("/panel/devices")
}

async fn device_reissue_post(state: &AppState, id: &str) -> HttpResponse {
    // Same rotation as the API reissue (old revoked, new issued).
    let now = now_secs();
    let new_tags: Vec<String> = {
        let conn = state.db.lock().unwrap();
        let device = match store::get_device(&conn, id) {
            Ok(d) => d,
            Err(_) => return redirect("/panel/devices"),
        };
        if device.revoked {
            return redirect("/panel/devices");
        }
        let old: Vec<(String, String)> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| (c.id, c.inbound_tag)).collect())
            .unwrap_or_default();
        let inbounds: HashMap<String, store::Inbound> = store::list_inbounds(&conn)
            .map(|v| v.into_iter().map(|i| (i.tag.clone(), i)).collect())
            .unwrap_or_default();
        let mut new_tags = Vec::new();
        for (cid, tag) in &old {
            let _ = conn.execute(
                "UPDATE credentials SET revoked=1 WHERE id=?1",
                rusqlite::params![cid],
            );
            if let Some(ib) = inbounds.get(tag) {
                if !subs::issuable(&ib.protocol) {
                    continue;
                }
                if let Some(material) = subs::generate_material(&ib.protocol, &ib.params) {
                    let identity_hash =
                        crypto::identity_hash(&state.config.usage_salt, &material.identity);
                    if let Ok(sealed) = crypto::seal(
                        &state.config.db_key,
                        &serde_json::to_vec(&material).unwrap(),
                    ) {
                        let _ = conn.execute(
                            "DELETE FROM credentials WHERE device_id=?1 AND inbound_tag=?2 AND revoked=1",
                            rusqlite::params![id, tag],
                        );
                        let cred = store::Credential {
                            id: uuid::Uuid::new_v4().to_string(),
                            device_id: id.to_string(),
                            inbound_tag: tag.clone(),
                            protocol: ib.protocol.clone(),
                            identity_hash,
                            secret: sealed,
                            created_at: now,
                            revoked: false,
                        };
                        if store::create_credential(&conn, &cred).is_ok() {
                            new_tags.push(tag.clone());
                        }
                    }
                }
            }
        }
        let _ = store::log_event(
            &conn,
            now,
            "reissue",
            "panel",
            &serde_json::json!({"device_id": id}),
        );
        new_tags
    };
    let _ = sync_tags(state, &new_tags).await;
    redirect(&format!("/panel/devices/{id}/configs"))
}

async fn device_delete_post(state: &AppState, id: &str) -> HttpResponse {
    let now = now_secs();
    let tags: Vec<String> = {
        let conn = state.db.lock().unwrap();
        let tags: Vec<String> = store::list_device_credentials(&conn, id)
            .map(|v| v.into_iter().map(|c| c.inbound_tag).collect())
            .unwrap_or_default();
        let _ = store::delete_device(&conn, id);
        let _ = store::log_event(
            &conn,
            now,
            "delete",
            "panel",
            &serde_json::json!({"device_id": id}),
        );
        tags
    };
    let _ = sync_tags(state, &tags).await;
    redirect("/panel/devices")
}

async fn device_configs_page(state: &AppState, id: &str) -> HttpResponse {
    let device = {
        let conn = state.db.lock().unwrap();
        match store::get_device(&conn, id) {
            Ok(d) => d,
            Err(_) => return page("Not found", &nav("devices"), "<p>No such device.</p>"),
        }
    };
    let configs = match render_device_configs(state, &device) {
        Ok(c) => c,
        Err(e) => return api_err(e),
    };
    let mut sections = String::new();
    for c in configs {
        let qr = c
            .qr_svg
            .as_deref()
            .unwrap_or("<p class=\"muted\">link too long for QR — copy it</p>");
        sections.push_str(&format!(
            "<section><h3>{} <span class=\"muted\">({})</span></h3>\
             <div class=\"qr\">{qr}</div>\
             <p><code class=\"link\">{}</code></p>\
             <details><summary>sing-box JSON</summary><pre>{}</pre></details>\
             <details><summary>Mihomo YAML</summary><pre>{}</pre></details></section>",
            esc(&c.inbound_tag),
            esc(&c.protocol),
            esc(&c.link),
            esc(&c.singbox.to_string()),
            esc(&c.mihomo),
        ));
    }
    let body = format!(
        "<h2>Configs for {}</h2><p class=\"warn\">Copy these now — raw secrets are shown \
         only to an authenticated admin, never logged.</p>{sections}",
        esc(&device.label)
    );
    page("Device configs", &nav("devices"), &body)
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

async fn subs_page(state: &AppState) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let subs_list = store::list_subscriptions(&conn).unwrap_or_default();
    let devices: HashMap<String, String> = store::list_users(&conn)
        .map(|users| {
            let mut m = HashMap::new();
            for u in users {
                for d in store::list_user_devices(&conn, &u.id).unwrap_or_default() {
                    m.insert(d.id.clone(), format!("{} / {}", u.name, d.label));
                }
            }
            m
        })
        .unwrap_or_default();
    let mut personal = String::new();
    let mut external = String::new();
    for s in subs_list {
        if s.kind == "personal" {
            let dev = s
                .device_id
                .as_deref()
                .and_then(|d| devices.get(d))
                .map(String::as_str)
                .unwrap_or("?");
            personal.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td><form method=\"post\" action=\"/panel/subscriptions/{}/rotate\"><button>rotate</button></form> \
                 <form method=\"post\" action=\"/panel/subscriptions/{}/revoke\"><button class=\"danger\">revoke</button></form></td></tr>",
                esc(&s.name), esc(dev),
                if s.revoked { "revoked" } else { "active" },
                s.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "never".to_string()),
                s.id, s.id,
            ));
        } else {
            external.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td>\
                 <td><span class=\"badge\">unmanaged — usage, quotas and revocation unavailable; exit IP unknown</span></td>\
                 <td><form method=\"post\" action=\"/panel/subscriptions/{}/revoke\"><button class=\"danger\">revoke</button></form></td></tr>",
                esc(&s.name), s.config_count,
                s.source_url.as_deref().map(esc).unwrap_or_else(|| "—".to_string()),
                s.id,
            ));
        }
    }
    let mut dev_opts = String::new();
    for (id, label) in &devices {
        dev_opts.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            esc(id),
            esc(label)
        ));
    }
    let body = format!(
        "<h2>Personal</h2>\
         <table><tr><th>name</th><th>device</th><th>status</th><th>expires</th><th></th></tr>{personal}</table>\
         <h3>Issue personal subscription</h3>\
         <form method=\"post\" action=\"/panel/subscriptions/personal\">\
         <label>device <select name=\"device_id\">{dev_opts}</select></label>\
         <button type=\"submit\">issue</button></form>\
         <h2>External</h2>\
         <table><tr><th>name</th><th>configs</th><th>source</th><th></th><th></th></tr>{external}</table>\
         <h3>Import external subscription</h3>\
         <form method=\"post\" action=\"/panel/subscriptions/external\">\
         <label>name <input name=\"name\" required maxlength=\"128\"></label>\
         <label>source URL (display only, never fetched by the server) <input name=\"source_url\" maxlength=\"512\"></label>\
         <label>subscription text (paste what your app fetched)<br><textarea name=\"body_text\" rows=\"6\" cols=\"60\" required></textarea></label>\
         <button type=\"submit\">import</button></form>"
    );
    page("Subscriptions", &nav("subscriptions"), &body)
}

async fn sub_personal_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let device_id = form.get("device_id").cloned().unwrap_or_default();
    let now = now_secs();
    let (sub_id, token) = {
        let conn = state.db.lock().unwrap();
        let device = match store::get_device(&conn, &device_id) {
            Ok(d) => d,
            Err(_) => return redirect("/panel/subscriptions"),
        };
        let token = crypto::new_token();
        let sub = store::Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            kind: "personal".to_string(),
            name: format!("{} — personal", device.label),
            device_id: Some(device.id.clone()),
            token_hash: Some(crypto::token_hash(&token)),
            source_url: None,
            imported_at: None,
            body_crypt: None,
            config_count: 0,
            managed: true,
            expires_at: None,
            revoked: false,
            created_at: now,
        };
        let _ = store::create_subscription(&conn, &sub);
        let _ = store::log_event(
            &conn,
            now,
            "sub_issue",
            "panel",
            &serde_json::json!({"subscription_id": sub.id}),
        );
        (sub.id, token)
    };
    let url = state
        .config
        .exit_host
        .as_ref()
        .map(|h| format!("https://{h}:{}/s/{token}", state.config.sub_port));
    let qr = url
        .as_deref()
        .and_then(subs::qr_svg)
        .unwrap_or_else(|| "<p class=\"muted\">no QR</p>".to_string());
    let body = format!(
        "<p>Subscription <code>{}</code> issued.</p>\
         <p>URL: <code>{}</code></p><div class=\"qr\">{qr}</div>\
         <p class=\"warn\">The token is shown once. It is stored hashed; it appears in no log.</p>\
         <p><a href=\"/panel/subscriptions\">back</a></p>",
        esc(&sub_id),
        esc(url.as_deref().unwrap_or("n/a (no exit_host configured)")),
    );
    page("Subscription issued", &nav("subscriptions"), &body)
}

async fn sub_rotate_post(state: &AppState, id: &str) -> HttpResponse {
    let token = crypto::new_token();
    let conn = state.db.lock().unwrap();
    let _ = store::rotate_subscription_token(&conn, id, &crypto::token_hash(&token));
    let _ = store::log_event(
        &conn,
        now_secs(),
        "sub_rotate",
        "panel",
        &serde_json::json!({"subscription_id": id}),
    );
    redirect("/panel/subscriptions")
}

async fn sub_revoke_post(state: &AppState, id: &str) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let _ = store::set_subscription_revoked(&conn, id, true);
    let _ = store::log_event(
        &conn,
        now_secs(),
        "sub_revoke",
        "panel",
        &serde_json::json!({"subscription_id": id}),
    );
    redirect("/panel/subscriptions")
}

async fn sub_external_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let name = form.get("name").cloned().unwrap_or_default();
    let body_text = form.get("body_text").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return redirect("/panel/subscriptions");
    }
    let parsed = zero_config::parse_subscription(&body_text);
    let count = parsed.iter().filter(|r| r.is_ok()).count() as i64;
    let now = now_secs();
    let sealed = match crypto::seal(&state.config.db_key, body_text.as_bytes()) {
        Ok(s) => s,
        Err(_) => return redirect("/panel/subscriptions"),
    };
    let sub = store::Subscription {
        id: uuid::Uuid::new_v4().to_string(),
        kind: "external".to_string(),
        name: name.trim().to_string(),
        device_id: None,
        token_hash: None,
        source_url: form.get("source_url").cloned().filter(|s| !s.is_empty()),
        imported_at: Some(now),
        body_crypt: Some(sealed),
        config_count: count,
        managed: false,
        expires_at: None,
        revoked: false,
        created_at: now,
    };
    let conn = state.db.lock().unwrap();
    let _ = store::create_subscription(&conn, &sub);
    let _ = store::log_event(
        &conn,
        now,
        "sub_import",
        "panel",
        &serde_json::json!({"subscription_id": sub.id, "config_count": count}),
    );
    redirect("/panel/subscriptions")
}

// ---------------------------------------------------------------------------
// Quotas / usage / exit-ip / errors / routes
// ---------------------------------------------------------------------------

async fn quotas_page(state: &AppState) -> HttpResponse {
    let today = today_utc();
    let month_start = format!("{}-01", &today[..7]);
    let conn = state.db.lock().unwrap();
    let users = store::list_users(&conn).unwrap_or_default();
    let mut rows = String::new();
    for u in users {
        let Some(quota) = u.quota_bytes else { continue };
        let (up, down) =
            store::user_usage_bytes(&conn, &u.id, &month_start, &today).unwrap_or((0, 0));
        let used = up + down;
        let pct = if quota > 0 {
            (used as f64 / quota as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let bar = format!("<div class=\"bar\"><div style=\"width:{pct:.0}%\"></div></div>");
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{} / {}</td><td>{bar} {pct:.1}%</td><td>{}</td></tr>",
            esc(&u.name),
            fmt_bytes(used),
            fmt_bytes(quota),
            if used >= quota {
                "<span class=\"warn\">OVER — access revoked by sweeper</span>"
            } else {
                "ok"
            },
        ));
    }
    let body = format!(
        "<p>Month: {}</p>\
         <table><tr><th>user</th><th>used / quota</th><th></th><th>status</th></tr>{rows}</table>\
         <p class=\"muted\">Over quota at 100%: credentials disabled + engine reload. Warning event at 80%.</p>",
        esc(&today[..7])
    );
    page("Quotas", &nav("quotas"), &body)
}

async fn usage_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let to = today_utc();
    let from = req_query(req, "from").unwrap_or_else(|| to.clone());
    let to_q = req_query(req, "to").unwrap_or_else(|| to.clone());
    let conn = state.db.lock().unwrap();
    let rows = store::usage_range(&conn, &from, &to_q).unwrap_or_default();
    let mut html_rows = String::new();
    let mut t_up = 0i64;
    let mut t_down = 0i64;
    for r in rows {
        let label = r
            .device_id
            .as_deref()
            .and_then(|id| store::get_device(&conn, id).ok())
            .map(|d| d.label)
            .unwrap_or_else(|| "server total".to_string());
        t_up += r.bytes_up;
        t_down += r.bytes_down;
        html_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&r.day),
            esc(&label),
            esc(&r.server_role),
            fmt_bytes(r.bytes_up),
            fmt_bytes(r.bytes_down),
            r.sessions_peak,
        ));
    }
    let body = format!(
        "<form method=\"get\" action=\"/panel/usage\">\
         <label>from <input name=\"from\" value=\"{}\" pattern=\"\\d{{4}}-\\d{{2}}-\\d{{2}}\"></label>\
         <label>to <input name=\"to\" value=\"{}\" pattern=\"\\d{{4}}-\\d{{2}}-\\d{{2}}\"></label>\
         <button>show</button></form>\
         <table><tr><th>day</th><th>device</th><th>server</th><th>up</th><th>down</th><th>peak sessions</th></tr>{html_rows}</table>\
         <p>Total: ↑ {} ↓ {}</p>\
         <p class=\"muted\">Rollups survive engine restarts (SQLite). Gateway aggregates arrive via the collector POST.</p>",
        esc(&from), esc(&to_q), fmt_bytes(t_up), fmt_bytes(t_down),
    );
    page("Usage", &nav("usage"), &body)
}

async fn exit_ip_page(state: &AppState) -> HttpResponse {
    let cached = state.exit_ip.lock().unwrap().clone();
    let (ip, at) = cached
        .map(|c| (c.ip, c.checked_at))
        .unwrap_or_else(|| ("unknown".to_string(), 0));
    let body = format!(
        "<p>Current exit IP: <strong>{}</strong> (checked at {})</p>\
         <p class=\"muted\">Country/tariff: <strong>unknown</strong> — tariff is never inferred from IP geolocation. \
         Record a verified tariff under Costs if your operator confirms one.</p>\
         <p>Use <code>GET /api/v1/net/exit-ip</code> for a fresh check.</p>",
        esc(&ip), at,
    );
    page("Exit IP", &nav("exit-ip"), &body)
}

async fn errors_page(state: &AppState) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let events = store::list_events(&conn, Some("error"), None, 200).unwrap_or_default();
    let mut rows = String::new();
    for e in events {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.at,
            esc(&e.actor),
            esc(&e.detail.to_string())
        ));
    }
    page(
        "Error log",
        &nav("errors"),
        &format!("<table><tr><th>at</th><th>actor</th><th>detail</th></tr>{rows}</table>"),
    )
}

async fn routes_page(state: &AppState) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let events = store::list_events(&conn, Some("route_change"), None, 200).unwrap_or_default();
    let mut rows = String::new();
    for e in events {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.at,
            esc(&e.actor),
            esc(&e.detail.to_string())
        ));
    }
    let body = format!(
        "<table><tr><th>at</th><th>actor</th><th>detail</th></tr>{rows}</table>\
         <p class=\"muted\">Populated by the poller from the engine's switch log (GET /health). \
         The routing engine (Design B) owns the decisions; the admin only displays them.</p>"
    );
    page("Route history", &nav("routes"), &body)
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

async fn dns_page(state: &AppState) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let mode = store::get_setting(&conn, "dns.mode")
        .unwrap_or(None)
        .unwrap_or_else(|| "\"strict\"".to_string());
    let resolvers = store::get_setting(&conn, "dns.resolvers")
        .unwrap_or(None)
        .unwrap_or_else(|| "[]".to_string());
    let strict_sel = if mode.contains("strict") {
        " selected"
    } else {
        ""
    };
    let auto_sel = if mode.contains("auto") {
        " selected"
    } else {
        ""
    };
    let body = format!(
        "<form method=\"post\" action=\"/panel/dns\">\
         <label>mode <select name=\"mode\"><option value=\"strict\"{strict_sel}>strict</option>\
         <option value=\"auto\"{auto_sel}>auto</option></select></label>\
         <label>resolvers (JSON array) <input name=\"resolvers\" value=\"{}\" size=\"40\"></label>\
         <button type=\"submit\">save</button></form>\
         <p class=\"muted\">Stored by the admin; enforcement lives in the engine config \
         (provision/core wire it). Current: <code>{}</code></p>",
        esc(&resolvers),
        esc(&mode),
    );
    page("DNS settings", &nav("dns"), &body)
}

async fn dns_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let mode = form.get("mode").map(String::as_str).unwrap_or("strict");
    if !matches!(mode, "strict" | "auto") {
        return redirect("/panel/dns");
    }
    let conn = state.db.lock().unwrap();
    let _ = store::set_setting(&conn, "dns.mode", &serde_json::json!(mode).to_string());
    let _ = store::set_setting(
        &conn,
        "dns.resolvers",
        form.get("resolvers")
            .map(|r| r.to_string())
            .unwrap_or_else(|| "[]".to_string())
            .as_str(),
    );
    let _ = store::log_event(
        &conn,
        now_secs(),
        "dns_change",
        "panel",
        &serde_json::json!({"mode": mode}),
    );
    redirect("/panel/dns")
}

// ---------------------------------------------------------------------------
// Costs
// ---------------------------------------------------------------------------

async fn costs_page(state: &AppState) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let costs = store::list_costs(&conn).unwrap_or_default();
    let mut rows = String::new();
    let mut monthly = 0.0f64;
    let mut baseline = 0.0f64;
    for c in costs {
        if c.period == "monthly" {
            if c.kind == "baseline" {
                baseline += c.amount;
            } else {
                monthly += c.amount;
            }
        }
        let tariff = if c.tariff_note == "unknown" {
            "<span class=\"muted\">unknown</span>".to_string()
        } else {
            esc(&c.tariff_note)
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.0} {}</td><td>{}</td><td>{tariff}</td>\
             <td><form method=\"post\" action=\"/panel/costs/{}/delete\"><button class=\"danger\">delete</button></form></td></tr>",
            esc(&c.kind), esc(&c.label), esc(&c.period), c.amount, esc(&c.currency),
            esc(&c.operator.clone().unwrap_or_else(|| "—".to_string())), c.id,
        ));
    }
    let body = format!(
        "<table><tr><th>kind</th><th>label</th><th>period</th><th>amount</th><th>operator</th><th>tariff</th><th></th></tr>{rows}</table>\
         <p>Monthly total: <strong>{monthly:.0} IRR</strong> · Baseline: <strong>{baseline:.0} IRR</strong> · \
         Estimated savings: <strong>{:.0} IRR</strong></p>\
         <p class=\"muted\">Whether your carrier bills this as domestic traffic is unknown — verify with your operator. \
         Tariff is never inferred from IP geolocation; it appears here only if you record a verified one.</p>\
         <h2>Record cost</h2>\
         <form method=\"post\" action=\"/panel/costs\">\
         <label>kind <select name=\"kind\"><option value=\"server\">server</option>\
         <option value=\"data_package\">data package</option><option value=\"baseline\">baseline</option></select></label>\
         <label>label <input name=\"label\" required maxlength=\"128\"></label>\
         <label>amount <input name=\"amount\" type=\"number\" step=\"0.01\" required></label>\
         <label>currency <input name=\"currency\" value=\"IRR\" maxlength=\"8\"></label>\
         <label>period <select name=\"period\"><option value=\"monthly\">monthly</option><option value=\"oneoff\">one-off</option></select></label>\
         <label>volume (MB) <input name=\"volume_mb\" type=\"number\" min=\"0\"></label>\
         <label>operator <input name=\"operator\" maxlength=\"64\"></label>\
         <label>tariff note (leave empty = unknown) <input name=\"tariff_note\" maxlength=\"256\"></label>\
         <button type=\"submit\">record</button></form>",
        baseline - monthly,
    );
    page("Costs", &nav("costs"), &body)
}

async fn cost_create_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let kind = form.get("kind").map(String::as_str).unwrap_or("server");
    if !matches!(kind, "server" | "data_package" | "baseline") {
        return redirect("/panel/costs");
    }
    let now = now_secs();
    let cost = store::Cost {
        id: uuid::Uuid::new_v4().to_string(),
        kind: kind.to_string(),
        label: form.get("label").cloned().unwrap_or_default(),
        amount: form
            .get("amount")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0),
        currency: form
            .get("currency")
            .cloned()
            .unwrap_or_else(|| "IRR".to_string()),
        period: form
            .get("period")
            .cloned()
            .unwrap_or_else(|| "monthly".to_string()),
        volume_mb: form.get("volume_mb").and_then(|v| v.parse::<i64>().ok()),
        operator: form.get("operator").cloned().filter(|s| !s.is_empty()),
        tariff_note: form
            .get("tariff_note")
            .cloned()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        recorded_at: now,
    };
    let conn = state.db.lock().unwrap();
    let _ = store::create_cost(&conn, &cost);
    redirect("/panel/costs")
}

async fn cost_delete_post(state: &AppState, id: &str) -> HttpResponse {
    let conn = state.db.lock().unwrap();
    let _ = store::delete_cost(&conn, id);
    redirect("/panel/costs")
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

fn backup_page() -> HttpResponse {
    let body = "\
        <h2>Create backup</h2>\
        <form method=\"post\" action=\"/panel/backup\">\
        <label>passphrase (min 8 chars) <input type=\"password\" name=\"passphrase\" required minlength=\"8\"></label>\
        <button type=\"submit\">download encrypted backup</button></form>\
        <h2>Restore</h2>\
        <form method=\"post\" action=\"/panel/restore\" enctype=\"multipart/form-data\">\
        <label>backup file <input type=\"file\" name=\"file\" required></label>\
        <label>passphrase <input type=\"password\" name=\"passphrase\" required></label>\
        <button type=\"submit\">restore (replaces the database)</button></form>\
        <p class=\"muted\">Backups are encrypted with a key derived from your passphrase. \
        There is no recovery if you lose it.</p>";
    page("Backup & restore", &nav("backup"), body)
}

async fn backup_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let passphrase = form.get("passphrase").map(String::as_str).unwrap_or("");
    match crate::backup::create_backup(&state.config.db_path, passphrase) {
        Ok(blob) => {
            let now = now_secs();
            if let Ok(conn) = state.db.lock() {
                let _ = store::log_event(&conn, now, "backup", "panel", &serde_json::json!({}));
            }
            let mut r = HttpResponse {
                status: 200,
                content_type: "application/octet-stream",
                extra: vec![(
                    "Content-Disposition".to_string(),
                    format!("attachment; filename=\"zray-admin-backup-{now}.zabk\""),
                )],
                body: blob,
            };
            let _ = &mut r;
            r
        }
        Err(e) => page(
            "Backup failed",
            &nav("backup"),
            &format!("<p class=\"err\">{}</p>", esc(&e.to_string())),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_escapes_html() {
        assert_eq!(
            esc("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(esc("a&b\"c"), "a&amp;b&quot;c");
        // Fuzz-ish: every ASCII punctuation is either passed through safely
        // or escaped.
        for c in 0x20u8..0x7f {
            let s = (c as char).to_string();
            let e = esc(&s);
            assert!(!e.contains('<') || e.contains("&lt;"));
            assert!(!e.contains('>') || e.contains("&gt;"));
            assert!(!e.contains('"') || e.contains("&quot;"));
        }
    }

    #[test]
    fn page_has_csp_and_no_js_framework() {
        let r = page("T", &nav(""), "<p>hi</p>");
        let csp = r
            .extra
            .iter()
            .find(|(k, _)| k == "Content-Security-Policy")
            .unwrap();
        assert!(csp.1.contains("default-src 'self'"));
        assert!(csp.1.contains("frame-ancestors 'none'"));
        let html = String::from_utf8(r.body).unwrap();
        assert!(!html.contains("react") && !html.contains("vue.js") && !html.contains("angular"));
    }
}
