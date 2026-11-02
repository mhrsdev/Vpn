//! Smart Routing panel section (owner prompt v2 / LEAD DELTA).
//!
//! Server-rendered, no JS framework. Rules table (add/delete/toggle),
//! rule-set list with snapshot + activate (rollback), a rule tester form
//! that proxies the engine's CLASSIFY API (502 when absent — never guessed),
//! and the conflict warnings computed on every mutation.
//!
//! The admin is the authoritative rule store; engine sync is best-effort via
//! the poller (`engine_synced` is reported honestly).

use crate::api::{now_secs, AppState, HttpRequest, HttpResponse};
use crate::panel::{api_err, esc, form_body, nav, page, redirect};
use crate::{routing, store};

pub async fn routing_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let (version, rules) = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
        };
        match store::active_rules(&conn) {
            Ok(v) => v,
            Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
        }
    };
    let (push_pending, push_error) = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
        };
        let pending = store::get_setting(&conn, "routing.push_pending")
            .ok()
            .flatten()
            .map(|v| v == "1")
            .unwrap_or(false);
        let err = store::get_setting(&conn, "routing.push_error")
            .ok()
            .flatten()
            .unwrap_or_default();
        (pending, err)
    };

    let mut s = String::from(
        "<h1>Smart Routing</h1>\
         <p>Iranian destinations → direct Iran egress. Foreign and unknown \
         destinations → the USA tunnel (unknown <strong>never</strong> goes direct). \
         Rules are priority-ordered; first match wins. \
         This panel is the authoritative rule store — the engine receives a \
         copy on each change (poller push, best-effort).</p>",
    );
    s.push_str(&format!(
        "<p><strong>Active rule-set:</strong> v{version} ({} rules) · \
         Engine sync: <strong>{}</strong>{}</p>",
        rules.len(),
        if push_pending { "pending" } else { "synced" },
        if push_error.is_empty() {
            String::new()
        } else {
            format!(" — last push failed: {}", esc(&push_error))
        }
    ));

    // Conflict warning from the last panel mutation.
    if req.query.contains_key("warned") {
        s.push_str(
            "<div class=\"warn-box\"><strong>Warning:</strong> the new rule overlaps \
             an existing rule with a different action. Priority decides the winner; \
             review the table below.</div>",
        );
    }

    // Tester result (proxied to the engine CLASSIFY API).
    if let Some(target) = req.query.get("test") {
        s.push_str(&tester_result_html(state, target).await);
    }

    // Rules table.
    s.push_str("<h2>Rules</h2><table><tr><th>Kind</th><th>Value</th><th>Action</th><th>Priority</th><th>Enabled</th><th>Note</th><th></th></tr>");
    for r in &rules {
        s.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td style=\"white-space:nowrap\">\
               <form method=\"post\" action=\"/panel/routing/rules/{}/delete\" style=\"display:inline\">\
                 <button type=\"submit\">delete</button></form>\
               <form method=\"post\" action=\"/panel/routing/rules/{}/toggle\" style=\"display:inline\">\
                 <button type=\"submit\">{}</button></form></td></tr>",
            esc(&r.kind),
            esc(&r.value),
            esc(&r.action),
            r.priority,
            if r.enabled { "yes" } else { "no" },
            esc(&r.note),
            esc(&r.id),
            esc(&r.id),
            if r.enabled { "disable" } else { "enable" },
        ));
    }
    s.push_str("</table>");
    if rules.is_empty() {
        s.push_str("<p>No rules yet — everything goes through the USA tunnel by default.</p>");
    }

    // Add-rule form.
    s.push_str(
        "<h2>Add rule</h2>\
         <form method=\"post\" action=\"/panel/routing/rules\">\
         <label>Kind <select name=\"kind\"><option value=\"domain\">domain</option>\
         <option value=\"ip\">ip</option><option value=\"cidr\">cidr</option>\
         <option value=\"geoip\">geoip (2-letter country code)</option></select></label> \
         <label>Value <input name=\"value\" size=\"32\" required placeholder=\"bank.ir or 5.6.0.0/16\"></label> \
         <label>Action <select name=\"action\"><option value=\"iran\">Iran egress</option>\
         <option value=\"usa\">USA tunnel</option></select></label> \
         <label>Priority <input name=\"priority\" type=\"number\" value=\"10\" min=\"0\" max=\"10000\" size=\"6\"></label> \
         <label>Note <input name=\"note\" size=\"24\"></label> \
         <button type=\"submit\">add</button></form>",
    );

    // Rule tester.
    s.push_str(
        "<h2>Rule tester</h2>\
         <form method=\"get\" action=\"/panel/routing\">\
         <label>Domain or IP <input name=\"test\" size=\"32\" required placeholder=\"example.com\"></label> \
         <button type=\"submit\">classify</button></form>\
         <p><em>The tester asks the routing engine live. When the engine has no \
         classifier it answers 502 — the panel never guesses.</em></p>",
    );

    // Rule-sets: snapshot + activate (rollback).
    s.push_str("<h2>Rule-sets</h2>");
    {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
        };
        if let Ok(sets) = store::list_rulesets(&conn) {
            s.push_str("<table><tr><th>Version</th><th>Active</th><th>Rules</th><th>Created (epoch)</th><th>Note</th><th></th></tr>");
            for rs in &sets {
                s.push_str(&format!(
                    "<tr><td>v{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>\
                     <form method=\"post\" action=\"/panel/routing/rulesets/{}/activate\" style=\"display:inline\">\
                       <button type=\"submit\">activate</button></form></td></tr>",
                    rs.version,
                    if rs.active { "yes" } else { "no" },
                    rs.rule_count,
                    rs.created_at,
                    esc(&rs.note),
                    rs.version,
                ));
            }
            s.push_str("</table>");
        }
    }
    s.push_str(
        "<form method=\"post\" action=\"/panel/routing/rulesets\">\
         <label>Snapshot note <input name=\"note\" size=\"24\"></label> \
         <button type=\"submit\">snapshot current rules</button></form>",
    );

    page("Smart Routing", &nav("routing"), &s)
}

/// Panel POST `/panel/routing/rules` — create a rule from the form.
/// Mirrors the API handler: validate (fail-closed) → conflict warnings →
/// store → mark engine push pending → log.
pub async fn rule_create_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let kind = form.get("kind").map(|s| s.as_str()).unwrap_or("");
    let value = form.get("value").map(|s| s.as_str()).unwrap_or("");
    let action = form.get("action").map(|s| s.as_str()).unwrap_or("");
    let priority = form
        .get("priority")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100);
    let note = form.get("note").map(|s| s.as_str()).unwrap_or("");
    let valid = match routing::validate_rule(kind, value, action, priority, note) {
        Ok(v) => v,
        Err(e) => return api_err(crate::api::err_json("bad_request", &e.to_string(), 400)),
    };
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    let version = match store::active_ruleset_version(&conn) {
        Ok(v) => v,
        Err(e) => return api_err(crate::api::store_err(e)),
    };
    let existing = store::list_rules(&conn, version).unwrap_or_default();
    let conflicts = routing::check_conflicts(&valid, &existing, None);
    let rule = store::SplitRule {
        id: format!("r-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        version,
        kind: valid.kind,
        value: valid.value,
        action: valid.action,
        priority: valid.priority,
        enabled: true,
        note: valid.note,
    };
    if let Err(e) = store::create_rule(&conn, &rule) {
        return api_err(crate::api::store_err(e));
    }
    let _ = store::set_setting(&conn, "routing.push_pending", "1");
    let _ = store::log_event(
        &conn,
        now,
        "routing_rule_create",
        "panel",
        &serde_json::json!({"rule_id": rule.id, "version": version}),
    );
    if conflicts.is_empty() {
        redirect("/panel/routing")
    } else {
        redirect("/panel/routing?warned=1")
    }
}

/// Panel POST `/panel/routing/rules/{id}/delete`.
pub async fn rule_delete_post(state: &AppState, id: &str) -> HttpResponse {
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    match store::delete_rule(&conn, id) {
        Ok(()) => {
            let _ = store::set_setting(&conn, "routing.push_pending", "1");
            let _ = store::log_event(
                &conn,
                now,
                "routing_rule_delete",
                "panel",
                &serde_json::json!({"id": id}),
            );
            redirect("/panel/routing")
        }
        Err(e) => api_err(crate::api::store_err(e)),
    }
}

/// Panel POST `/panel/routing/rules/{id}/toggle` — flip enabled.
pub async fn rule_toggle_post(state: &AppState, id: &str) -> HttpResponse {
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    let (_, rules) = match store::active_rules(&conn) {
        Ok(v) => v,
        Err(e) => return api_err(crate::api::store_err(e)),
    };
    let mut rule = match rules.iter().find(|r| r.id == id).cloned() {
        Some(r) => r,
        None => return api_err(crate::api::err_json("not_found", "rule not found", 404)),
    };
    rule.enabled = !rule.enabled;
    if let Err(e) = store::update_rule(&conn, &rule) {
        return api_err(crate::api::store_err(e));
    }
    let _ = store::set_setting(&conn, "routing.push_pending", "1");
    let _ = store::log_event(
        &conn,
        now,
        if rule.enabled {
            "routing_rule_enable"
        } else {
            "routing_rule_disable"
        },
        "panel",
        &serde_json::json!({"id": id}),
    );
    redirect("/panel/routing")
}

/// Panel POST `/panel/routing/rulesets` — snapshot the active rules.
pub async fn ruleset_snapshot_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let note = form.get("note").map(|s| s.as_str()).unwrap_or("");
    if note.len() > 500 {
        return api_err(crate::api::err_json(
            "bad_request",
            "note too long (max 500)",
            400,
        ));
    }
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    let from = match store::active_ruleset_version(&conn) {
        Ok(v) => v,
        Err(e) => return api_err(crate::api::store_err(e)),
    };
    let to = match store::next_ruleset_version(&conn) {
        Ok(v) => v,
        Err(e) => return api_err(crate::api::store_err(e)),
    };
    if let Err(e) = store::create_ruleset(&conn, to, note, now) {
        return api_err(crate::api::store_err(e));
    }
    match store::snapshot_ruleset(&conn, from, to) {
        Ok(copied) => {
            let _ = store::log_event(
                &conn,
                now,
                "routing_ruleset_snapshot",
                "panel",
                &serde_json::json!({"from_version": from, "to_version": to, "rules": copied}),
            );
            redirect("/panel/routing")
        }
        Err(e) => api_err(crate::api::store_err(e)),
    }
}

/// Panel POST `/panel/routing/rulesets/{version}/activate` — rollback.
pub async fn ruleset_activate_post(state: &AppState, version: i64) -> HttpResponse {
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    if let Err(e) = store::activate_ruleset(&conn, version) {
        return api_err(crate::api::store_err(e));
    }
    let _ = store::set_setting(&conn, "routing.push_pending", "1");
    let _ = store::log_event(
        &conn,
        now,
        "routing_ruleset_activate",
        "panel",
        &serde_json::json!({"version": version}),
    );
    redirect("/panel/routing")
}

async fn tester_result_html(state: &AppState, target: &str) -> String {
    match state.engine.classify(target).await {
        Ok(t) => {
            let mut v = serde_json::to_value(&t).unwrap_or(serde_json::Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.insert("target".to_string(), serde_json::json!(target));
            }
            format!(
                "<div class=\"result-box\"><h3>Classify result</h3><pre>{}</pre></div>",
                esc(&serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".to_string()))
            )
        }
        Err(e) => format!(
            "<div class=\"warn-box\"><strong>Classifier unavailable:</strong> {} \
             (the engine has no CLASSIFY API — no route was guessed)</div>",
            esc(&e.to_string())
        ),
    }
}
