//! Triple Tunnel & Dual-Stack Monitor + Sticky Exit Policies panel sections
//! (owner addendum, binding).
//!
//! Server-rendered, no JS framework. All tunnel/egress/test data is live
//! engine data (honest 502/degraded when the engine lacks the surface);
//! sticky policies are the admin's own store, pushed to the engine
//! best-effort by the poller.

use crate::api::{now_secs, AppState, HttpRequest, HttpResponse};
use crate::panel::{api_err, esc, fmt_bytes, form_body, nav, page, redirect};
use crate::{store, triple};

pub async fn triple_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    triple_page_inner(state, req, None).await
}

async fn triple_page_inner(
    state: &AppState,
    req: &HttpRequest,
    test_result: Option<triple::ManualTest>,
) -> HttpResponse {
    let mut s = String::from("<h1>Triple Tunnel &amp; Dual-Stack Monitor</h1>");

    // --- Tunnels A/B/C ----------------------------------------------------
    match state.engine.tunnels_snapshot().await {
        Ok(snap) => {
            if !snap.supported() {
                s.push_str(
                    "<div class=\"warn-box\">The engine has no <code>/tunnels</code> surface \
                    yet (the routing agent implements it). No tunnel data is shown rather than \
                    invented data.</div>",
                );
            } else {
                s.push_str("<h2>Tunnels</h2><div class=\"cards\">");
                for t in snap.ordered_tunnels() {
                    s.push_str(&tunnel_card(&t, snap.primary.as_deref()));
                }
                s.push_str("</div>");
                s.push_str(&format!(
                    "<p>Primary: <strong>{}</strong> · Mode: <strong>{}</strong> · \
                     Probe budget: <strong>{}</strong> (options: {})</p>",
                    esc(snap.primary.as_deref().unwrap_or("—")),
                    esc(snap.mode.as_deref().unwrap_or("—")),
                    esc(snap.probe_budget_view()),
                    esc(&snap.budget_options().join(", ")),
                ));
                s.push_str(
                    "<form method=\"post\" action=\"/panel/triple/probe-budget\">\
                     <label>Probe traffic budget <select name=\"budget\">\
                     <option value=\"low\">Low</option><option value=\"balanced\">Balanced</option>\
                     <option value=\"aggressive\">Aggressive</option><option value=\"custom\">Custom</option>\
                     </select></label> <button type=\"submit\">apply</button></form>",
                );
            }
        }
        Err(e) => {
            s.push_str(&format!(
                "<div class=\"warn-box\">Tunnel data unavailable: {} \
                 (engine unreachable — nothing is shown instead of stale data.)</div>",
                esc(&e.to_string())
            ));
        }
    }

    // --- USA egress --------------------------------------------------------
    s.push_str("<h2>USA egress</h2>");
    match state.engine.egress_snapshot().await {
        Ok(eg) => {
            if !eg.supported() {
                s.push_str("<div class=\"warn-box\">The engine has no <code>/egress</code> surface yet.</div>");
            } else {
                s.push_str(&format!(
                    "<table><tr><th>Static IPv4</th><th>Static IPv6</th>\
                     <th>IPv4 connectivity</th><th>IPv6 connectivity</th></tr>\
                     <tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr></table>",
                    esc(eg.static_ipv4.as_deref().unwrap_or("—")),
                    esc(eg.static_ipv6.as_deref().unwrap_or("—")),
                    family_state(&eg.v4),
                    family_state(&eg.v6),
                ));
                s.push_str(&format!(
                    "<h3>Sticky session</h3><table>\
                     <tr><th>Exit IP</th><th>Family</th><th>Session started</th>\
                     <th>Last reroute</th><th>Reroute reason</th></tr>\
                     <tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr></table>\
                     <p><em>The exit IP never changes silently: every reroute is listed \
                     here with its reason.</em></p>",
                    esc(eg.sticky.exit_ip.as_deref().unwrap_or("—")),
                    esc(eg.sticky.exit_family.as_deref().unwrap_or("—")),
                    fmt_ts(eg.sticky.session_started_at),
                    fmt_ts(eg.sticky.last_reroute_at),
                    esc(eg.sticky.last_reroute_reason.as_deref().unwrap_or("—")),
                ));
            }
        }
        Err(e) => {
            s.push_str(&format!(
                "<div class=\"warn-box\">Egress data unavailable: {}</div>",
                esc(&e.to_string())
            ));
        }
    }

    // --- Per-destination decision tester ------------------------------------
    s.push_str(
        "<h2>Per-destination decision</h2>\
         <form method=\"get\" action=\"/panel/triple\">\
         <label>Domain <input name=\"domain\" size=\"32\" required placeholder=\"example.com\"></label> \
         <button type=\"submit\">decide</button></form>",
    );
    if let Some(domain) = req.query.get("domain") {
        match state.engine.egress_decision(domain).await {
            Ok(d) => {
                s.push_str(&format!(
                    "<div class=\"result-box\"><h3>Decision for <code>{}</code></h3>\
                     <p>Family: <strong>{}</strong> · Policy: <strong>{}</strong> · \
                     Exit IP: <code>{}</code></p><p>Why: {}</p></div>",
                    esc(&d.domain),
                    esc(&d.family),
                    esc(d.policy.as_deref().unwrap_or("—")),
                    esc(d.exit_ip.as_deref().unwrap_or("—")),
                    esc(d.reason.as_deref().unwrap_or("—")),
                ));
            }
            Err(e) => {
                s.push_str(&format!(
                    "<div class=\"warn-box\">Decision unavailable: {} \
                     (the engine has no decision surface — nothing was guessed)</div>",
                    esc(&e.to_string())
                ));
            }
        }
    }

    // --- Manual tests -------------------------------------------------------
    s.push_str(
        "<h2>Manual tests</h2><p>Real measurements from the engine. \
        The failover test moves traffic — it requires confirmation.</p>",
    );
    s.push_str("<div class=\"cards\">");
    for kind in triple::TEST_KINDS {
        let confirm = if kind == "failover" {
            "<label><input type=\"checkbox\" name=\"confirm\" value=\"on\" required> I understand this moves traffic</label> "
        } else {
            ""
        };
        s.push_str(&format!(
            "<div class=\"card\"><h3>Test {}</h3>\
             <form method=\"post\" action=\"/panel/triple/test/{}\">{}<button type=\"submit\">run</button></form></div>",
            esc(kind), esc(kind), confirm,
        ));
    }
    s.push_str("</div>");
    if let Some(t) = test_result {
        s.push_str(&format!(
            "<div class=\"result-box\"><h3>Test result: {} — {}</h3><ul>",
            esc(&t.kind),
            if t.ok { "PASS" } else { "FAIL" },
        ));
        for step in &t.results {
            s.push_str(&format!(
                "<li><strong>{}</strong> — {} <span class=\"muted\">{} · {} ms</span></li>",
                esc(&step.name),
                if step.ok { "ok" } else { "FAILED" },
                esc(step.detail.as_deref().unwrap_or("")),
                step.duration_ms
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            ));
        }
        s.push_str("</ul></div>");
    }

    page("Triple Tunnel", &nav("triple"), &s)
}

fn tunnel_card(t: &triple::TripleTunnel, primary: Option<&str>) -> String {
    let state = t.state_view();
    let cls = match state {
        "up" => "ok",
        "degraded" => "warn",
        "standby" => "muted",
        "unavailable" => "warn",
        _ => "err",
    };
    let traffic = &t.traffic;
    format!(
        "<div class=\"card\"><h3>Tunnel {} {}</h3>\
         <p>Family: <strong>{}</strong> · Protocol: <strong>{}</strong> · \
         Transport: <strong>{}</strong></p>\
         <p>Status: <strong class=\"{}\">{}</strong>{}</p>\
         <p>RTT: {} · Loss: {} · Jitter: {}</p>\
         <h4>Traffic (real counters)</h4>\
         <p>Payload ↑ {} / ↓ {} · Keepalive {} · Health-check {} · Overhead {}</p>\
         <p>Active sessions: {} · Failovers: {} · Last recovery: {}</p></div>",
        esc(&t.id),
        t.family_view().to_ascii_uppercase(),
        esc(t.family_view()),
        esc(t.protocol.as_deref().unwrap_or("—")),
        esc(t.transport_family.as_deref().unwrap_or("—")),
        cls,
        esc(state),
        if primary == Some(t.id.as_str()) {
            " · <strong>PRIMARY</strong>"
        } else {
            ""
        },
        t.rtt_ms
            .map(|v| format!("{v} ms"))
            .unwrap_or_else(|| "—".to_string()),
        t.loss_pct
            .map(|v| format!("{v:.1}%"))
            .unwrap_or_else(|| "—".to_string()),
        t.jitter_ms
            .map(|v| format!("{v} ms"))
            .unwrap_or_else(|| "—".to_string()),
        fmt_bytes(traffic.payload_up.min(i64::MAX as u64) as i64),
        fmt_bytes(traffic.payload_down.min(i64::MAX as u64) as i64),
        fmt_bytes(traffic.keepalive_bytes.min(i64::MAX as u64) as i64),
        fmt_bytes(traffic.health_bytes.min(i64::MAX as u64) as i64),
        fmt_bytes(traffic.overhead_bytes.min(i64::MAX as u64) as i64),
        t.active_sessions
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".to_string()),
        t.failover_count
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".to_string()),
        t.recovery_time_s
            .map(|v| format!("{v:.1} s (measured)"))
            .unwrap_or_else(|| "not measured".to_string()),
    )
}

fn family_state(f: &triple::EgressFamily) -> String {
    let conn = match f.connected {
        Some(true) => "<strong class=\"ok\">connected</strong>",
        Some(false) => "<strong class=\"err\">down</strong>",
        None => "—",
    };
    let rate = f
        .success_rate
        .map(|r| format!(" · {:.0}% success", r * 100.0))
        .unwrap_or_default();
    format!("{conn}{rate}")
}

fn fmt_ts(ms: Option<i64>) -> String {
    ms.map(|v| format!("{v}"))
        .unwrap_or_else(|| "—".to_string())
}

/// Panel POST `/panel/triple/probe-budget`.
pub async fn probe_budget_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let budget = form.get("budget").map(|s| s.as_str()).unwrap_or("");
    if !triple::PROBE_BUDGETS.contains(&budget) {
        return redirect("/panel/triple");
    }
    let engine_err_msg = match state.engine.set_probe_budget(budget).await {
        Ok(()) => None,
        Err(e) => Some(e.to_string()),
    };
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return redirect("/panel/triple"),
    };
    let now = now_secs();
    let _ = store::set_setting(&conn, "tunnels.probe_budget", budget);
    let _ = store::log_event(
        &conn,
        now,
        "probe_budget_set",
        "panel",
        &serde_json::json!({"budget": budget, "engine_error": engine_err_msg}),
    );
    redirect("/panel/triple")
}

/// Panel POST `/panel/triple/test/{kind}` — runs the manual test and renders
/// the page with the REAL result.
pub async fn triple_test_post(state: &AppState, kind: &str, req: &HttpRequest) -> HttpResponse {
    if !triple::TEST_KINDS.contains(&kind) {
        return redirect("/panel/triple");
    }
    if kind == "failover" {
        let form = form_body(req);
        if !form.get("confirm").map(|v| v == "on").unwrap_or(false) {
            return redirect("/panel/triple");
        }
    }
    match state.engine.run_test(kind).await {
        Ok(t) => {
            // Scope the DB guard: it must not be held across the .await below.
            if let Ok(conn) = state.db.lock() {
                let now = now_secs();
                let _ = store::log_event(
                    &conn,
                    now,
                    "manual_test",
                    "panel",
                    &serde_json::json!({"kind": kind, "ok": t.ok, "steps": t.results.len()}),
                );
            }
            triple_page_inner(state, req, Some(t)).await
        }
        Err(e) => {
            let t = triple::ManualTest {
                kind: kind.to_string(),
                ok: false,
                results: vec![triple::ManualTestStep {
                    name: "engine request".to_string(),
                    ok: false,
                    detail: Some(e.to_string()),
                    duration_ms: None,
                }],
                ..Default::default()
            };
            triple_page_inner(state, req, Some(t)).await
        }
    }
}

// ---------------------------------------------------------------------------
// Sticky Exit Policies
// ---------------------------------------------------------------------------

pub async fn sticky_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let mut s = String::from(
        "<h1>Sticky Exit Policies</h1>\
         <p>One fixed exit IP per session: the exit IP never changes silently. \
         Defaults: <strong>Auto + Sticky Session</strong>; sensitive sites default \
         to <strong>Prefer Stable IPv4</strong>. If you force IPv4 and IPv4 breaks, \
         the fallback follows your policy — the panel shows every reroute with \
         its reason on the <a href=\"/panel/triple\">Triple Tunnel</a> page.</p>",
    );

    // Current sticky state from the engine.
    match state.engine.egress_snapshot().await {
        Ok(eg) if eg.supported() => {
            s.push_str(&format!(
                "<p>Current exit: <code><strong>{}</strong></code> ({}) · \
                 last reroute: {} — {}</p>",
                esc(eg.sticky.exit_ip.as_deref().unwrap_or("—")),
                esc(eg.sticky.exit_family.as_deref().unwrap_or("—")),
                fmt_ts(eg.sticky.last_reroute_at),
                esc(eg.sticky.last_reroute_reason.as_deref().unwrap_or("—")),
            ));
        }
        _ => {
            s.push_str("<p><em>Current exit state unavailable (engine has no /egress surface yet).</em></p>");
        }
    }

    // Policy table.
    s.push_str("<h2>Policies</h2>");
    {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
        };
        match store::list_sticky_policies(&conn) {
            Ok(policies) => {
                s.push_str(
                    "<table><tr><th>Scope</th><th>Target</th><th>Policy</th>\
                    <th>Affinity (s)</th><th>Note</th><th></th></tr>",
                );
                for p in &policies {
                    s.push_str(&format!(
                        "<tr><td>{}</td><td><code>{}</code></td><td><strong>{}</strong></td>\
                         <td>{}</td><td>{}</td>\
                         <td><form method=\"post\" action=\"/panel/sticky/{}/delete\" style=\"display:inline\">\
                         <button type=\"submit\">delete</button></form></td></tr>",
                        esc(&p.scope),
                        esc(&p.target),
                        esc(&p.policy),
                        p.affinity_secs,
                        esc(&p.note),
                        esc(&p.id),
                    ));
                }
                s.push_str("</table>");
                if policies.is_empty() {
                    s.push_str(
                        "<p>No custom policies — everything uses Auto + Sticky Session.</p>",
                    );
                }
            }
            Err(e) => return api_err(crate::api::store_err(e)),
        }
    }

    // Add form.
    s.push_str(
        "<h2>Add policy</h2>\
         <form method=\"post\" action=\"/panel/sticky\">\
         <label>Scope <select name=\"scope\"><option value=\"domain\">domain</option>\
         <option value=\"device\">device</option></select></label> \
         <label>Target <input name=\"target\" size=\"24\" required placeholder=\"bank.ir or device id\"></label> \
         <label>Policy <select name=\"policy\">\
         <option value=\"auto\">Auto</option><option value=\"prefer_stable_ipv4\">Prefer Stable IPv4</option>\
         <option value=\"force_ipv4\">Force IPv4</option><option value=\"force_ipv6\">Force IPv6</option>\
         </select></label> \
         <label>Affinity (s) <input name=\"affinity_secs\" type=\"number\" value=\"0\" min=\"0\" max=\"86400\" size=\"8\"></label> \
         <label>Note <input name=\"note\" size=\"20\"></label> \
         <button type=\"submit\">add</button></form>",
    );

    // Effective-policy lookup.
    s.push_str(
        "<h2>Effective policy</h2>\
         <form method=\"get\" action=\"/panel/sticky\">\
         <label>Domain <input name=\"domain\" size=\"24\"></label> \
         <label>Device <input name=\"device\" size=\"24\"></label> \
         <button type=\"submit\">lookup</button></form>",
    );
    if req.query.contains_key("domain") || req.query.contains_key("device") {
        let domain = req.query.get("domain").map(|v| v.as_str());
        let device = req.query.get("device").map(|v| v.as_str());
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
        };
        match store::effective_sticky_policy(&conn, domain, device) {
            Ok(Some(p)) => {
                s.push_str(&format!(
                    "<div class=\"result-box\"><p>Effective policy: <strong>{}</strong> \
                     ({} <code>{}</code>, affinity {}s)</p></div>",
                    esc(&p.policy),
                    esc(&p.scope),
                    esc(&p.target),
                    p.affinity_secs,
                ));
            }
            Ok(None) => {
                s.push_str(
                    "<div class=\"result-box\"><p>Effective policy: <strong>auto</strong> \
                    + sticky session (default — no stored policy matches).</p></div>",
                );
            }
            Err(e) => return api_err(crate::api::store_err(e)),
        }
    }

    page("Sticky Exit", &nav("sticky"), &s)
}

/// Panel POST `/panel/sticky` — create a policy from the form.
pub async fn sticky_create_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let scope = form.get("scope").map(|s| s.as_str()).unwrap_or("");
    let target = form.get("target").map(|s| s.as_str()).unwrap_or("");
    let policy = form.get("policy").map(|s| s.as_str()).unwrap_or("");
    let affinity_secs = form
        .get("affinity_secs")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let note = form.get("note").map(|s| s.as_str()).unwrap_or("");
    let valid = match triple::validate_sticky_policy(scope, target, policy, affinity_secs, note) {
        Ok(v) => v,
        Err(e) => return api_err(crate::api::err_json("bad_request", &e.to_string(), 400)),
    };
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    let p = store::StickyPolicy {
        id: format!("sp-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        scope: valid.scope,
        target: valid.target,
        policy: valid.policy,
        affinity_secs: valid.affinity_secs,
        note: valid.note,
        created_at: now,
    };
    if let Err(e) = store::create_sticky_policy(&conn, &p) {
        return api_err(crate::api::store_err(e));
    }
    let _ = store::set_setting(&conn, "sticky.push_pending", "1");
    let _ = store::log_event(
        &conn,
        now,
        "sticky_policy_create",
        "panel",
        &serde_json::json!({"id": p.id, "scope": p.scope, "target": p.target, "policy": p.policy}),
    );
    redirect("/panel/sticky")
}

/// Panel POST `/panel/sticky/{id}/delete`.
pub async fn sticky_delete_post(state: &AppState, id: &str) -> HttpResponse {
    let conn = match state.db.lock() {
        Ok(c) => c,
        Err(_) => return api_err(crate::api::err_json("db", "database unavailable", 500)),
    };
    let now = now_secs();
    match store::delete_sticky_policy(&conn, id) {
        Ok(()) => {
            let _ = store::set_setting(&conn, "sticky.push_pending", "1");
            let _ = store::log_event(
                &conn,
                now,
                "sticky_policy_delete",
                "panel",
                &serde_json::json!({"id": id}),
            );
            redirect("/panel/sticky")
        }
        Err(e) => api_err(crate::api::store_err(e)),
    }
}
