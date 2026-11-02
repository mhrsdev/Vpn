# Frozen contract — `/api/v1/modem/*` (Huawei H158-381 native VPN client)

Design G is normative. Shapes frozen against the Android agent's
`RouterApi.kt` (app parses these exact keys). The informed-consent gate
(Design G §d, owner-confirmed 2026-11-01) still applies: credentials are
returned only after consent is recorded.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/modem/capabilities` | `{model, firmware, vpn_client:{protocols, fields}, note}` |
| GET | `/api/v1/modem/guide?protocol=l2tp` | `{protocol, steps:[{title, body}]}` (Design G §f, English source of truth) |
| GET | `/api/v1/modem/security?protocol=l2tp` | `{protocol, findings:[{id, severity, title, detail}]}` |
| GET | `/api/v1/modem/accounts` | `{accounts:[ModemAccount]}` — no secrets |
| POST | `/api/v1/modem/accounts` | `{name\|label, username?, hostname?, lns_address?, consent?}` → `201 {account, credentials:[...]}` |
| GET | `/api/v1/modem/accounts/{id}` | `{account, credentials}` — credentials only after consent (logged) |
| POST | `/api/v1/modem/accounts/{id}/consent` | `{acknowledged:true, note?}` → `{ok, consent_at}` |
| POST | `/api/v1/modem/accounts/{id}/reveal` | `{credentials}` — consent required, logged |
| POST | `/api/v1/modem/accounts/{id}/rotate` | `{credentials}` — new passwords, one-time |
| DELETE | `/api/v1/modem/accounts/{id}` | `{ok:true}` (revoke) |
| POST | `/api/v1/modem/accounts/{id}/revoke` | `{ok:true}` (panel compat) |
| POST | `/api/v1/modem/accounts/{id}/restore` | `{ok:true}` |
| GET | `/api/v1/modem/accounts/{id}/usage` | `{account_id, from, to, total_up, total_down, data_used, days, live?}` |
| GET | `/api/v1/modem/accounts/{id}/status` | `{account_id, username, status, last_seen_at, source, note}` |

Without consent, credential-bearing responses return
`{credentials: [], consent_required: true, consent_text: "..."}`.

### ModemAccount

```json
{"id":"…","name":"home-5g","username":"h158-abc12345",
 "status":"connected|last_seen|never|unknown",
 "last_seen":"1730412345","data_used":123456789}
```

`status` maps the session monitor: `connected` (session up), `last_seen`
(had a session, now down), `never`, `unknown` (monitor never reported).

### ModemCredential

```json
{"field_id":"lns_address","label":"LNS address","value":"203.0.113.1","sensitive":false}
```

Field ids in firmware form order (Design G §c): `connection_type`
(fixed `"L2TP VPN client"`), `lns_address`, `hostname`, `tunnel_password`,
`ppp_username`, `ppp_password`.

### Capabilities

`vpn_client.protocols` is `["l2tp"]` — PPTP is refused on principle and never
listed as offerable. `fields` is the exact H158-381 L2TP form (Design G §c);
the app renders only these.

### Security findings

Severities are the backend's word (the UI never upgrades them):
`pptp-refused` (insecure), `l2tp-weak` (untrustworthy),
`no-kill-switch` / `full-tunnel-unverified` / `ipv6-bypass` /
`weak-leg-scope` (warning).

## Binding rules

- PPTP is never offered (only explained as absent).
- The L2TP link is labeled ⚠️ WEAK+ and never called "secure" unqualified.
- Informed consent is mandatory before the first credential display.
- One account per modem, independent from phone/laptop devices, individually
  revocable. Server-side chap-secrets/xl2tpd lifecycle is the provisioner's
  job; the admin owns the credential record + status/usage ingestion.
