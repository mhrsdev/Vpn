# Frozen contract — `/api/v1/sticky-policies/*` (Sticky Exit, owner addendum)

The admin owns the policy store (like routing rules); the engine applies the
policies (poller push, best-effort). One fixed exit IP per session: the exit
IP never changes silently — every reroute is visible with its reason on the
Triple Tunnel page (`last_reroute_at` + `last_reroute_reason`).

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/sticky-policies` | `{policies:[StickyPolicy], engine_synced, defaults}` |
| POST | `/api/v1/sticky-policies` | `{scope,target,policy,affinity_secs?,note?}` → `201 {policy}` |
| PUT | `/api/v1/sticky-policies/{id}` | `{policy?,affinity_secs?,note?}` → `{policy}` |
| DELETE | `/api/v1/sticky-policies/{id}` | `{ok:true}` |
| GET | `/api/v1/sticky-policies/effective?domain=&device=` | Effective policy for a domain/device pair |

### StickyPolicy

```json
{"id":"sp-…","scope":"domain|device","target":"bank.ir",
 "policy":"force_ipv4|force_ipv6|auto|prefer_stable_ipv4",
 "affinity_secs":3600,"note":"…","created_at":1730412345}
```

### Binding rules

- **Defaults:** `auto` + sticky session; sensitive sites default
  `prefer_stable_ipv4`. Absent a stored policy, `effective` returns the
  default with `"source":"default"` (never a 404 for "no policy").
- **Precedence:** a device policy wins over a domain policy.
- **Forced-family fallback:** if the user forces IPv4 and IPv4 breaks, the
  engine falls back per the policy — it never silently changes the exit IP;
  the reroute (time + reason) is surfaced via `/egress/status`.
- **Fail-closed validation:** unknown scope/policy rejected (400), never stored.
- **Sync honesty:** every mutation marks `sticky.push_pending`; the poller
  pushes and `engine_synced` reports the last outcome.

## Admin → engine (routing agent implements)

| Method | Path | Body |
|---|---|---|
| POST | `/sticky-policies` | `{"policies":[{id,scope,target,policy,affinity_secs,note}]}` → `{ok}` |
