# Frozen contract — `/api/v1/routing/*` (smart split routing)

Owner prompt v2 / LEAD DELTA. Shapes frozen against the Android agent's
`RouterApi.kt` (app parses these exact keys). The admin is the authoritative
rule store; the routing agent owns the classifier engine.

Semantics: Iranian destinations → direct Iran egress; foreign/unknown → USA
tunnel. Unknown defaults to USA — never to Iran egress, never to direct.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/routing/rules` | `{version, rules:[SplitRule], engine_synced, push_error?}` |
| POST | `/api/v1/routing/rules` | `{kind,value,action,priority?,enabled?,note?}` → `201 {rule, conflicts:[...]}` |
| PUT | `/api/v1/routing/rules/{id}` | partial update → `{rule, conflicts:[...]}` |
| DELETE | `/api/v1/routing/rules/{id}` | `{ok:true}` |
| GET | `/api/v1/routing/rulesets` | `{rulesets:[{version,note,created_at,active,rule_count}]}` |
| POST | `/api/v1/routing/rulesets` | `{note?}` → `201 {ruleset}` — snapshots the active version's rules into a NEW inactive version |
| POST | `/api/v1/routing/rulesets/{version}/activate` | `{ok, version}` — rollback = activate an older version |
| POST | `/api/v1/routing/test` | `{target}` → `{route, matched_rule?, exit_country?, dns_policy?, confidence, reason}` |

### SplitRule

```json
{"id":"…","kind":"domain|ip|cidr|geoip","value":"bank.ir",
 "action":"iran|usa","priority":10,"enabled":true,"note":"…"}
```

Validation is fail-closed: unparsable values are rejected (400), never stored.
`geoip` values are 2-letter country codes (routing mechanism only — never
used for cost tariffs).

### Conflict check

`conflicts` returns human warnings (not hard blocks; priority decides):
same kind+value with a different action, or overlapping CIDRs with different
actions. Disabled rules are ignored.

### Versioning model

- Versions are append-only snapshots; exactly one version is `active`.
- Day-to-day edits (POST/PUT/DELETE `/rules`) mutate the ACTIVE version.
- `POST /rulesets` copies the active version's rules to version N+1 (inactive).
- `POST /rulesets/{v}/activate` switches (rollback = activate older).
- Every mutation marks `routing.push_pending`; the poller pushes the active
  rule-set to the engine and clears the flag on success. `engine_synced`
  reports the last push outcome honestly.

## Rule tester

`POST /api/v1/routing/test` proxies the engine's CLASSIFY API. `502` when
the engine has no classifier — never a guessed answer.

## Admin → engine (routing agent implements)

| Method | Path | Body |
|---|---|---|
| POST | `/classify` | `{"target":"example.com"}` → `{route:"iran"\|"usa"\|"blocked", matched_rule?, exit_country?:"IR"\|"US"\|"unknown", dns_policy?, confidence, reason}` |
| POST | `/ruleset` | `{version, rules:[{id,kind,value,action,priority,enabled,note}]}` → `{ok,…}` |

`exit_country` here comes from the matched RULE's action (usa→US, iran→IR),
not from geolocation — no GeoIP in the admin crate.
