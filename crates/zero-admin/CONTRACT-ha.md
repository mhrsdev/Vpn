# Frozen contract — `/api/v1/ha/*` (Inter-Server High Availability)

Owner HA addendum (binding). The routing agent owns the failover machinery;
these endpoints are the admin's read/control surface. Shapes frozen against
the Android agent's `HaApi.kt` (app parses these exact keys).

## Admin → app (`/api/v1`)

| Method | Path | Response |
|---|---|---|
| GET | `/api/v1/ha/status` | Full status (canonical) |
| GET | `/api/v1/ha` | Alias of `/status` |
| GET | `/api/v1/ha/tunnels` | `{supported, primary, tunnels}` |
| POST | `/api/v1/ha/primary` | `{tunnel:"A"\|"B"}` → `{ok, primary}` |
| POST | `/api/v1/ha/mode` | `{mode}` → `{ok, mode}` (409 unless engine-offered) |
| GET | `/api/v1/ha/settings` | Effective settings |
| POST | `/api/v1/ha/settings` | `{heartbeat_interval_s?, failover_threshold_missed?, auto_recovery?}` → `{ok, ...}` |
| PUT | `/api/v1/ha/settings` | Alias of POST |

### `GET /api/v1/ha/status` shape

```json
{
  "supported": true,
  "tunnels": [{
    "id": "A", "protocol": "wireguard", "transport_family": "wireguard",
    "state": "up|degraded|standby|down",
    "rtt_ms": 42, "loss_pct": 0.5, "jitter_ms": 3,
    "keepalive_ok": true, "last_heartbeat_at": 1730412345000,
    "bytes_up": 123, "bytes_down": 456
  }],
  "primary": "A",
  "mode": "hot_standby",
  "available_modes": ["hot_standby"],
  "auto_recovery": true,
  "heartbeat_interval_s": 3,
  "failover_threshold_missed": 3,
  "last_failover_at": 1730410000000,
  "failover_count": 2,
  "total_downtime_s": 1.2,
  "downtime_measured": true,
  "recent_failovers": [{
    "at": 1730410000000, "from": "A", "to": "B",
    "reason": "primary changed A → B",
    "downtime_s": 1.2, "sessions_preserved_pct": null
  }],
  "exit": {
    "ip": "203.0.113.9", "country": "unknown", "healthy": true,
    "checked_at": 1730412345000,
    "ip_stable": true, "ip_stable_across_failovers": true
  },
  "honesty": "Failover honesty levels: ..."
}
```

### Binding rules

- **Fail-closed states:** tunnel `state` unknown/missing → `"down"`. There is
  no `"unknown"` tunnel state on the wire.
- **Measured downtime only:** `total_downtime_s` / `downtime_s` are emitted
  only from measured values. Absent measurement → `0.0` with
  `"downtime_measured": false`; `sessions_preserved_pct` is `null` (the admin
  does not measure it). Never estimated, never "zero downtime" marketing.
- **Modes:** `available_modes` comes from the engine; default
  `["hot_standby"]`. `POST /ha/mode` with any other mode → `409`. The backend
  offers `active_active` only when the engine really implements it.
- **No GeoIP:** `exit.country` is always `"unknown"` (admin crate rule).
- **Engine absent:** `supported:false` + honest `note`; control endpoints →
  `502 not_supported`. The admin never invents tunnel data.

## Admin → engine (routing agent implements)

| Method | Path | Body |
|---|---|---|
| GET | `/ha` | → snapshot (preferred; fallback: `GET /tunnel` → `.ha`) |
| POST | `/ha/primary` | `{"tunnel":"A"\|"B"}` |
| POST | `/ha/mode` | `{"mode":"hot_standby"\|"active_active"}` |
| POST | `/ha/settings` | `{heartbeat_interval_s?, failover_threshold_missed?, auto_recovery?}` |

Snapshot fields mirror the app shape (epoch millis, snake_case modes).
The poller logs `ha_failover` events on primary change / counter increase;
`recent_failovers` is built from those real observed transitions.
