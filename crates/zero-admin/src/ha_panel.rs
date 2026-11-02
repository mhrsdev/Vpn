//! Inter-Server High Availability panel section (owner addendum).
//!
//! Server-rendered, no JS. Every value comes from the engine's HA snapshot
//! (`GET /ha` via [`crate::ha`]); tunnel states are fail-closed (unknown →
//! down), downtime is shown only when measured. Manual primary selection,
//! mode switches (only engine-offered modes) and settings changes are
//! forwarded to the engine and logged as events.

use crate::api::{AppState, HttpRequest, HttpResponse};
use crate::panel::{api_err, esc, form_body, nav, page, redirect};
use crate::{ha, store};

fn state_badge(state: &str) -> String {
    let cls = match state {
        "up" => "ok",
        "degraded" | "standby" => "warn",
        _ => "err",
    };
    format!("<span class=\"{cls}\">{}</span>", esc(state))
}

fn tunnel_card(snap: &ha::HaSnapshot, id: &str) -> String {
    let primary_mark = if snap.primary.as_deref() == Some(id) {
        " <strong>(primary)</strong>"
    } else {
        ""
    };
    match snap.tunnel(id) {
        Some(t) => {
            let state = ha::tunnel_state_of(t.state.as_deref()).as_str();
            let hb = t
                .last_heartbeat_at
                .map(|ms| format!("{ms} ms epoch"))
                .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string());
            format!(
                "<div class=\"card\"><h3>Tunnel {id}{primary_mark}</h3>\
                 <p>Protocol: {}</p>\
                 <p>Transport family: {}</p>\
                 <p>State: {}</p>\
                 <p>RTT: {}</p>\
                 <p>Loss: {}</p>\
                 <p>Jitter: {}</p>\
                 <p>Keepalive: {}</p>\
                 <p>Last heartbeat: {hb}</p>\
                 <p>Bytes ↑ {} ↓ {}</p></div>",
                t.protocol
                    .as_deref()
                    .map(esc)
                    .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
                t.transport_family
                    .as_deref()
                    .map(esc)
                    .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
                state_badge(state),
                t.rtt_ms
                    .map(|v| format!("{v} ms"))
                    .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
                t.loss_pct
                    .map(|v| format!("{v:.1} %"))
                    .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
                t.jitter_ms
                    .map(|v| format!("{v} ms"))
                    .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
                match t.keepalive_ok {
                    Some(true) => "ok",
                    _ => "<span class=\"err\">not ok</span>",
                },
                t.bytes_up,
                t.bytes_down,
            )
        }
        None => format!(
            "<div class=\"card\"><h3>Tunnel {id}{primary_mark}</h3>\
             <p class=\"muted\">not reported by the engine (fail-closed: treated as down)</p></div>"
        ),
    }
}

pub async fn ha_page(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let error = req.query.get("error").cloned().unwrap_or_default();
    let snap = match state.engine.ha_snapshot().await {
        Ok(s) => s,
        Err(_) => return page(
            "Inter-Server High Availability",
            &nav("ha"),
            "<p class=\"err\">Engine unreachable — HA state unknown. The admin does not guess.</p>",
        ),
    };

    let mut body = String::new();
    if !error.is_empty() {
        body.push_str(&format!("<p class=\"err\">{}</p>", esc(&error)));
    }
    if !snap.supported() {
        body.push_str(
            "<div class=\"warn-box\"><strong>Engine predates the HA contract.</strong> \
             No tunnel/failover data is available. Tunnel states are fail-closed to \
             <strong>down</strong>; downtime is not measured. HA requires the routing \
             agent's failover build on the engine.</div>",
        );
    }

    body.push_str("<div class=\"cards\">");
    body.push_str(&tunnel_card(&snap, "A"));
    body.push_str(&tunnel_card(&snap, "B"));
    body.push_str("</div>");

    let downtime = match snap.failovers.total_downtime_s {
        Some(s) => format!("{s:.1} s (measured)"),
        None => "<span class=\"muted\">not measured</span>".to_string(),
    };
    let offered = snap.offered_modes();
    body.push_str(&format!(
        "<h2>Status</h2>\
         <table>\
         <tr><th>Primary path</th><td>{}</td></tr>\
         <tr><th>Mode</th><td>{}</td></tr>\
         <tr><th>Modes offered by engine</th><td>{}</td></tr>\
         <tr><th>Failover count</th><td>{}</td></tr>\
         <tr><th>Last failover</th><td>{}</td></tr>\
         <tr><th>Total downtime</th><td>{downtime}</td></tr>\
         <tr><th>Heartbeat interval</th><td>{} s</td></tr>\
         <tr><th>Failover threshold</th><td>{} missed heartbeats</td></tr>\
         <tr><th>Auto-recovery</th><td>{}</td></tr>\
         </table>",
        snap.primary
            .as_deref()
            .map(esc)
            .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
        esc(&snap.mode_view()),
        esc(&offered.join(", ")),
        snap.failovers.count,
        snap.failovers
            .last_at
            .map(|t| format!("{} ms epoch", t * 1000))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string()),
        snap.heartbeat_interval_s
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
        snap.failover_threshold_missed
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
        match snap.auto_recovery {
            Some(true) => "on",
            Some(false) => "off",
            None => "<span class=\"muted\">unknown</span>",
        },
    ));

    // USA exit.
    body.push_str("<h2>USA exit server</h2>");
    let exit_ip = snap
        .exit
        .ip
        .clone()
        .or_else(|| state.exit_ip.lock().unwrap().clone().map(|e| e.ip));
    body.push_str(&format!(
        "<table>\
         <tr><th>Exit IP</th><td>{}</td></tr>\
         <tr><th>Healthy</th><td>{}</td></tr>\
         <tr><th>IP stable across failovers</th><td>{}</td></tr>\
         <tr><th>Checked at</th><td>{}</td></tr>\
         </table>\
         <p class=\"muted\">Country is always \"unknown\" — the admin crate contains no GeoIP.</p>",
        exit_ip
            .as_deref()
            .map(esc)
            .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
        match snap.exit.healthy {
            Some(true) => "<span class=\"ok\">healthy</span>",
            _ => "<span class=\"err\">not healthy</span>",
        },
        match snap.exit.ip_stable {
            Some(true) => "yes",
            Some(false) => "<span class=\"err\">no</span>",
            None => "<span class=\"muted\">unknown</span>",
        },
        snap.exit
            .checked_at
            .map(|t| format!("{} ms epoch", t * 1000))
            .unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string()),
    ));

    // Controls — only engine-offered modes get buttons.
    let mut mode_forms = String::new();
    for m in &offered {
        mode_forms.push_str(&format!(
            "<form method=\"post\" action=\"/panel/ha/mode\" style=\"display:inline\">\
             <input type=\"hidden\" name=\"mode\" value=\"{m}\">\
             <button type=\"submit\">{}</button></form> ",
            esc(m),
        ));
    }
    body.push_str(&format!(
        "<h2>Controls</h2>\
         <h3>Manual primary-path selection</h3>\
         <form method=\"post\" action=\"/panel/ha/primary\" style=\"display:inline\">\
         <input type=\"hidden\" name=\"tunnel\" value=\"A\"><button type=\"submit\">Make A primary</button></form> \
         <form method=\"post\" action=\"/panel/ha/primary\" style=\"display:inline\">\
         <input type=\"hidden\" name=\"tunnel\" value=\"B\"><button type=\"submit\">Make B primary</button></form>\
         <h3>Mode (only engine-offered modes)</h3>{mode_forms}\
         <h3>Tuning</h3>\
         <form method=\"post\" action=\"/panel/ha/settings\">\
         <label>Heartbeat interval (s, 1–30) <input name=\"heartbeat_interval_s\" inputmode=\"numeric\"></label><br>\
         <label>Missed heartbeats to fail over (1–10) <input name=\"failover_threshold_missed\" inputmode=\"numeric\"></label><br>\
         <label><input type=\"checkbox\" name=\"auto_recovery\" value=\"on\"> Auto-recovery (re-promote a healed tunnel after probing, no flap-back)</label><br>\
         <button type=\"submit\">Apply</button></form>",
    ));

    // Failover history from the admin's own event log (real observed transitions).
    let events = {
        let conn = match state.db.lock() {
            Ok(c) => c,
            Err(_) => return page("Inter-Server High Availability", &nav("ha"), &body),
        };
        store::list_events(&conn, Some("ha_failover"), None, 20).unwrap_or_default()
    };
    body.push_str("<h2>Failover history</h2>");
    if events.is_empty() {
        body.push_str("<p class=\"muted\">No failovers recorded by the admin.</p>");
    } else {
        body.push_str("<table><tr><th>At</th><th>From → To</th><th>Downtime (measured)</th></tr>");
        for e in events {
            let from = e.detail.get("from").and_then(|v| v.as_str()).unwrap_or("?");
            let to = e.detail.get("to").and_then(|v| v.as_str()).unwrap_or("?");
            let dt = e
                .detail
                .get("last_downtime_ms")
                .and_then(|v| v.as_u64())
                .map(|ms| format!("{:.1} s", ms as f64 / 1000.0))
                .unwrap_or_else(|| "not measured".to_string());
            body.push_str(&format!(
                "<tr><td>{}</td><td>{} → {}</td><td>{}</td></tr>",
                e.at,
                esc(from),
                esc(to),
                esc(&dt),
            ));
        }
        body.push_str("</table>");
    }

    body.push_str(&format!(
        "<div class=\"warn-box\"><strong>Honesty:</strong> {}</div>",
        esc(ha::HA_HONESTY)
    ));
    page("Inter-Server High Availability", &nav("ha"), &body)
}

pub async fn ha_primary_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let tunnel = form.get("tunnel").map(String::as_str).unwrap_or("");
    match crate::api::ha_select_primary(state, tunnel, "panel").await {
        Ok(_) => redirect("/panel/ha"),
        Err(e) => api_err(e),
    }
}

pub async fn ha_mode_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let mode = form.get("mode").map(String::as_str).unwrap_or("");
    match crate::api::ha_select_mode(state, mode, "panel").await {
        Ok(_) => redirect("/panel/ha"),
        Err(e) => api_err(e),
    }
}

pub async fn ha_settings_post(state: &AppState, req: &HttpRequest) -> HttpResponse {
    let form = form_body(req);
    let mut body = serde_json::Map::new();
    for name in ["heartbeat_interval_s", "failover_threshold_missed"] {
        if let Some(v) = form.get(name).filter(|v| !v.trim().is_empty()) {
            if let Ok(n) = v.trim().parse::<u64>() {
                body.insert(name.to_string(), serde_json::json!(n));
            }
        }
    }
    if form
        .get("auto_recovery")
        .map(|v| v == "on")
        .unwrap_or(false)
    {
        body.insert("auto_recovery".to_string(), serde_json::json!(true));
    }
    let body = serde_json::Value::Object(body);
    match crate::api::ha_apply_settings(state, &body, "panel").await {
        Ok(_) => redirect("/panel/ha"),
        Err(e) => api_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tunnel_card_is_fail_closed() {
        let snap = ha::HaSnapshot::unknown();
        let card = tunnel_card(&snap, "A");
        assert!(card.contains("fail-closed"));
        assert!(!card.contains(">up<"));
    }

    #[test]
    fn panel_honesty_disclaims_zero_downtime() {
        assert!(ha::HA_HONESTY.contains("NOT claimed without measured proof"));
    }
}
