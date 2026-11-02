# Frozen contract — `/api/v1/tunnels/*`, `/api/v1/egress/*`, `/api/v1/tests/*`
(Triple Tunnel & Dual-Stack, owner addendum binding)

The routing agent owns the failover machinery and the dual-stack egress;
these endpoints are the admin's read/control surface. Shapes below are what
the app's admin panel parses. Engine contracts are the routing agent's to
implement; the admin degrades honestly until they exist.

## Admin → app (`/api/v1`)

| Method | Path | Response |
|---|---|---|
| GET | `/api/v1/tunnels/status` | Triple snapshot (canonical) |
| POST | `/api/v1/tunnels/primary` | `{tunnel:"A"\|"B"\|"C"}` → `{ok, primary}` |
| GET | `/api/v1/tunnels/probe-budget` | `{budget, engine_budget, options}` |
| POST | `/api/v1/tunnels/probe-budget` | `{budget}` → `{ok, budget, engine_applied, engine_error?}` |
| GET | `/api/v1/egress/status` | Dual-stack egress + sticky state |
| GET | `/api/v1/egress/decisions?domain=` | Per-destination family + why |
| POST | `/api/v1/tests/{ipv4\|ipv6\|both\|exit-ip\|failover}` | Real test result |

### `GET /api/v1/tunnels/status` shape

```json
{
  "supported": true,
  "tunnels": [{
    "id": "A", "family": "ipv4", "protocol": "wireguard",
    "transport_family": "wireguard",
    "state": "up|degraded|standby|down|unavailable",
    "rtt_ms": 42, "loss_pct": 0.5, "jitter_ms": 3,
    "keepalive_ok": true, "last_heartbeat_at": 1730412345000,
    "traffic": {"payload_up": 1, "payload_down": 2, "keepalive_bytes": 3,
                "health_bytes": 4, "overhead_bytes": 5},
    "active_sessions": 7, "failover_count": 1, "recovery_time_s": 1.2
  }],
  "primary": "A", "mode": "hot_standby", "available_modes": ["hot_standby"],
  "probe_budget": "balanced",
  "probe_budget_options": ["low", "balanced", "aggressive", "custom"],
  "note": "live engine data"
}
```

### Binding rules

- **Tunnel C honesty:** `"unavailable"` is an explicit engine state meaning
  "IPv6 is not really usable" — shown as Unavailable, never fake-connected.
  Any other unknown/missing state → `"down"` (fail-closed).
- **Traffic split** comes from real counters; absent counters serialize as 0,
  `recovery_time_s` absent → `null` (never estimated).
- **Modes:** same rule as `/ha` — only engine-offered modes are switchable.
- **Manual tests** return measured results only; the failover test requires
  `{"confirm": true}`. Engine without the test surface → 502, never invented.
- **Probe budget:** the admin setting is authoritative; the engine push is
  best-effort (`engine_applied:false` + `engine_error` when it fails).

## Admin → engine (routing agent implements)

| Method | Path | Body |
|---|---|---|
| GET | `/tunnels` | → triple snapshot (tunnels A/B/C, traffic split, probe budget) |
| POST | `/tunnels/probe-budget` | `{"budget":"low"\|"balanced"\|"aggressive"\|"custom"}` |
| GET | `/egress` | → `{static_ipv4, static_ipv6, v4:{connected,success_rate}, v6:{...}, sticky:{exit_ip,exit_family,session_started_at,last_reroute_at,last_reroute_reason}}` |
| GET | `/egress/decisions?domain=` | → `{domain, family:"ipv4"\|"ipv6", policy, reason, exit_ip}` |
| POST | `/tests/{kind}` | `{}` (+`{"confirm":true}` for failover) → `{kind, ok, results:[{name,ok,detail,duration_ms}], measured_at}` |

Fallback: when `/tunnels` 404s, the admin maps the 2-tunnel `GET /ha`
snapshot (tunnels A/B, no C) rather than failing outright.
