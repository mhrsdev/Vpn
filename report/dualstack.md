# Dual-Stack USA Egress — H2 Implementation Report

**Agent:** H2 (Dual-Stack Egress) · **Branch:** `impl/dualstack` (from `52689ee`)
**Date:** 2026-11-02 · **Target dir:** `~/workspace/vpn-zero/target-dualstack`

## What was built

### 1. Config (`crates/zero-config/src/model.rs`, +~280 lines)

- `EgressFamily` (`V4`/`V6`), `EgressFamilyPolicy` (`auto`/`force_ipv4`/
  `force_ipv6`/`prefer_stable_ipv4` — the frozen admin contract strings),
  `FamilyFallback` (`Block` default / `AllowOtherFamily`), `ProbeBudget`
  (`low`/`balanced`/`aggressive`/`custom`) + `ProbeBudgetParams`.
- `EgressConfig`: static IPv4/IPv6 (validated IP literals — never
  auto-detected, never rotated), default policy, `sensitive_sites`
  (default `prefer_stable_ipv4`), `domain_policies` (longest-suffix wins),
  `affinity_secs`, `on_family_down`, probe budget + params, `race_delay_ms`
  (default 250, RFC 8305), `quality_ttl_secs`.
- `RuntimeConfig.egress: Option<EgressConfig>` (`None` = legacy
  single-stack behavior). `EgressConfig::validate()` wired into
  `RuntimeConfig::validate()`.

### 2. JSON parsing (`crates/zero-config/src/xray_json.rs`)

Top-level `egress` object, camelCase keys mirroring `splitRouting`:
`staticIpv4`, `staticIpv6`, `defaultPolicy`, `sensitiveSites`,
`domainPolicies[]` (`domain`, `policy`, `affinitySecs`, `onFamilyDown`
(`block`|`allowOtherFamily`), `note`), `affinitySecs`, `onFamilyDown`,
`probeBudget`, `probeIntervalSecs`, `probeConcurrency`,
`probeMaxBytesPerDay`, `raceDelayMs`, `qualityTtlSecs`. Invalid IPs,
policies, and budgets are hard parse errors (fail closed at config load).

### 3. Engine (`crates/zero-runtime/src/egress.rs`, new, ~1100 lines)

- **`EgressSelector`** — Happy-Eyeballs-v2-style decisions from REAL
  quality: per-destination + global tables of
  `successes/failures/handshake-EWMA/last-sample`. Score =
  `0.60·success_rate + 0.25·time_score + 0.15·stability`,
  `time_score = 1/(1+ewma_ms/200)`; unknown until ≥3 samples; stale past
  TTL. Never ping.
- **`decide_sticky()`** — affinity-aware decision. Within the affinity
  window the sticky family is KEPT whenever usable and not measured-bad
  (score < 0.35 with enough samples), even if the scorer prefers the other
  family. This is the "no flip for a few ms of ping" rule; the keep is
  reported via `decision.sticky_kept` + reason so the panel can explain
  "why v6 when v4 measured faster". Stickiness never overrides forced
  policies, fail-closed blocks, or a measured-bad family.
- **`happy_eyeballs()`** — race primitive: first family starts at once,
  second starts after the stagger if the first hasn't completed a real
  handshake; first handshake wins, loser dropped (cancellation-safe).
  Forced policies and single-stack destinations get `second: None`.
- **`StickyExit`** — one static IPv4 + one static IPv6; sessions keyed by
  domain/device; affinity window; every family change recorded as a
  `RerouteEvent {at, key, from, to, reason}` (panel: `last_reroute_at` +
  `last_reroute_reason`). Exit IP never changes silently.
- **`TrafficLedger`** — per-tunnel (`"A"`/`"B"`/`"C"` tags, no coupling to
  H1's `TunnelId`) atomic counters: payload up/down, keepalive, health,
  overhead. Overhead is ALWAYS labeled estimate (`overhead_is_estimate`).
- **`bind_source_socket()`** — binds the static source address explicitly,
  which is what makes the sticky exit IP real.
- **`EgressEngine`** — facade: `select()`, `record_result()`,
  `apply_policies()` (admin `POST /sticky-policies` push),
  `set_probe_budget()`, `traffic_ledger()`, `status_snapshot()` shaped
  toward the frozen `GET /egress` contract. No changes to the frozen
  contracts.

### Design decisions

1. **Fail-closed beats clever:** `Force*` + unusable family + default
   fallback = blocked connection, not a silent family switch. The owner
   explicitly required "never silently change the exit IP".
2. **Unknown ≠ bad:** a family with too few samples is never "measured-bad";
   absence of evidence keeps the sticky session.
3. **Seams, not rewiring:** the module is self-contained; the server's hot
   dial path, `/egress` HTTP surface (H1), and split DNS (H3) integrate
   against `EgressEngine`. No existing hot paths were touched.
4. **Sensitive sites:** `prefer_stable_ipv4` keeps v4 even when v6 measures
   better — banking-style stability over speed, per the addendum.

### IPv6 source-address caveat (operator checklist)

Binding the socket defeats RFC 4941 temporary addresses *for that socket*,
but the operator must still: (a) assign the static IPv6 to the exit host,
(b) disable temporary addresses for it (`net.ipv6.conf.*.use_tempaddr=0`
or equivalent), (c) verify with `ip -6 addr` that no `temporary` flag is on
the egress path. Otherwise the destination may see a rotating address and
stickiness silently breaks. A bind failure here fails closed (no silent
fallback to another address).

## Tests (all run, all green)

- `zero-runtime --lib egress::`: **19/19 pass** — quality scoring &
  ordering, v6-first racing with no data, forced-policy no-race +
  fail-closed block, allow-fallback reroute reason, prefer-stable-v4
  despite better v6, longest-suffix policy precedence, sticky no-flip
  within affinity, sticky move when measured-bad, reroute recording,
  exit-IP constancy across tunnel switches, traffic split + estimate
  label, loopback socket binds, 3 happy-eyeballs races, config
  validation, contract-shaped status snapshot.
- `zero-config --lib`: **210/210 pass** (207 pre-existing + 3 new egress
  parse tests: full parse, absent→None, rejection of bad IPs/policies/
  budgets).
- `cargo fmt --check`: clean for all touched regions (pre-existing drift
  elsewhere left untouched).

## Measured vs NOT TESTED

- **Measured:** everything above, on loopback (127.0.0.1, ::1 where the
  sandbox allows). Happy-eyeballs races use real tokio timers and real
  (loopback) sockets.
- **NOT TESTED:** WAN behavior — real IPv6 uplink, cross-family
  throughput, path MTU, CGNAT interactions, the RFC 4941 caveat on a real
  host. The sandbox has no IPv6 uplink; these need the real USA exit.
- **NOT TESTED:** end-to-end dial-path integration (H1's wiring) and the
  `/egress` HTTP surface (H1's layer reads `status_snapshot()`).

## Integration points for H1 / H3 / panel

- H1 (`/egress`, `/egress/decisions`, `/tunnels`): construct
  `EgressEngine::new(config.egress)`; feed `record_result()` from real
  dial outcomes; serve `status_snapshot()`; push admin policies via
  `apply_policies()`; record keepalive/health bytes via
  `traffic_ledger().record(tag, …)` in the heartbeat loop.
- H3 (split DNS): the DNS family follows `EgressEngine::select()`; no
  separate DNS policy needed.
- Panel: `sticky_kept` + `reason` explain "why this family";
  `last_reroute_at`/`reason` from `status_snapshot()`; overhead bytes
  must be labeled "estimate" in the UI.
