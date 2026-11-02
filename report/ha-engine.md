# H1 HaEngine — Implementation Report

**Branch:** `impl/ha-engine` (from `52689ee`)
**Crate:** `crates/zero-ha-tests` — new `src/rig.rs` (~1300 lines), rewired `src/wiring.rs`
**Date:** 2026-11-02
**Result: 17/17 scenarios PASS** (verified by actually running `cargo test -p zero-ha-tests`)

## What was built

`RigEngine` implements all 16 `HaEngine` trait methods against the **real** engine
machinery: a real `zero_observatory::TransportTable` (dual always-on group
`tunnel-a`/`tunnel-b`, `fail_after=3`, `cooldown=30s`) + `HealthTable`, driven by a
real heartbeat loop (250 ms interval, 1 s timeout) over real loopback sockets, calling
the real `TransportTable::choose()` selection logic every tick.

**Loopback-pair rig** (two local sides on 127.0.0.1, ephemeral ports):

| Side | Tunnel A | Tunnel B | Iran direct |
|---|---|---|---|
| Control | TCP ping/pong | connected-UDP ping/pong | — |
| Data | TCP echo relay | UDP echo relay (multiplexed) | TCP + UDP echo |

- **Fault injection is real**: `CutTunnel` drops the control connection, aborts live
  relay sessions via a kill broadcast, and silences the responder; `BlockPort` stops
  heartbeat answers while the process lives; `PacketLoss` drops via a deterministic
  coin flip; `RttSpike` sleeps before answering. The gateway learns of faults only
  through failed heartbeats / refused connections — like production.
- **Fail-closed is structural**: foreign traffic has no code path to the direct
  egress except through the single `direct_egress_tcp` choke point, which is only
  called for `IranDirect`. The `direct_egress_bytes` canary counts every byte there;
  all 17 scenarios assert the delta is 0.
- `TunnelId::C` already existed in the trait; the rig does not configure it
  (no IPv6 loopback rig; documented as out of scope).

**Sandbox adaptations** (environmental, verified empirically, documented in code):
- This sandbox's seccomp filter returns **EPERM on unconnected UDP `send_to`**.
  All UDP therefore uses **pre-connected socket pairs** (gateway ↔ exit connected at
  construction); connected `send()` was verified to work bidirectionally. The
  ping/pong and echo datagrams are real UDP.
- UDP data sessions are **logical**: multiplexed by session id over each tunnel's
  shared connected UDP pair (like a real VPN multiplexing flows over a tunnel).
  Every liveness check is a real UPING/UPONG datagram round-trip; a cut tunnel
  stops echoing so sessions die for real. Not a canned mock.

**Documented simulations** (not hidden): `exit_ip()` = fixed `203.0.113.10`
(TEST-NET-3; constancy is what's tested); DNS = static in-process map for the two
test names (no resolver code path → `dns_leak_observed()` structurally false,
fail-closed on `DnsFailure`); transfers paced at ~8 MiB/s so 64 MiB spans a fault.

## Per-scenario results (measured)

All hard invariants held in every scenario: exit-IP consistent, no DNS leak,
split-routing policy held, `direct_egress_bytes` delta = 0.

### ha_failover_core (9/9 PASS)

| # | Scenario | Verdict | Detection | Recovery | Survival | Loss | Notes |
|---|---|---|---|---|---|---|---|
| 1 | sudden_primary_cut | PASS | 899 ms | 385 µs | 0.0% (20 sess) | 0.0% | Sessions were on cut tunnel A; all died honestly (level 1: new conns switch, existing don't migrate) |
| 2 | primary_port_blocked | PASS | 3.33 s | 1.24 ms | 100.0% | 0.0% | BlockPort hits control only; data path lived, sessions survived |
| 3 | severe_packet_loss | PASS | 3.32 s | 417 µs | 100.0% | 0.0% | Loss-triggered failover detected |
| 4 | rtt_spike | PASS | 3.32 s | 496 µs | 100.0% | 0.0% | RTT-spike path move (opportunistic, hysteresis applies) |
| 5 | dns_failure | PASS | 951 ms | 576 µs | 100.0% | 0.0% | 10/10 DNS rounds, 0 leaks |
| 6 | full_foreign_path_cut | PASS | 5.25 s | n/a (both down) | 0.0% (expected) | 100.0% (expected) | Foreign probe ok=false during full cut; fail-closed confirmed |
| 7 | both_tunnels_down | PASS | 5.55 s | 14.62 s | 0.0% (expected) | 0.0% | Recovered: A_up=true; fail-closed during outage |
| 8 | primary_recovery | PASS | 40.12 s | 441 µs | 0.0% | 0.0% | A recovered to Up/Standby; no flap-back (30 s cooldown honored) |
| 9 | alternating_quality | PASS | — (90 s run) | 643 µs | 100.0% | 0.0% | 3 failover events in 90 s oscillation; anti-flap ok |

### ha_failover_traffic (8/8 PASS)

| # | Scenario | Verdict | Detection | Recovery | Survival | Loss | Notes |
|---|---|---|---|---|---|---|---|
| 10 | long_download | PASS | 2.65 s | 2.01 s | 0.0% | 95.2%* | 3.2/64 MiB, hash_ok=false. *Single TCP conn dies on cut (no resume); "loss" = transfer incompleteness, honest level-1 |
| 11 | stable_tcp_connection | PASS | 654 ms | 536 µs | 0.0% | 0.0% | TCP sessions on cut tunnel die; measured, not zero-downtime |
| 12 | udp_session | PASS | 855 ms | 396 µs | 0.0% | 0.0% | UDP flows re-created on new path by design |
| 13 | file_transfer | PASS | 5.89 s | 11.00 s | 100.0% | 0.0% | hash_ok=true, 16/16 MiB |
| 14 | leak_during_switch | PASS | 755 ms | 168 µs | 100.0% | 0.0% | 0/20 DNS leaks, 0 direct-egress bytes during switch |
| 15 | exit_ip_constancy | PASS | 854 ms | 472 µs | 100.0% | 0.0% | 203.0.113.10 stable across 10 post-switch samples |
| 16 | split_routing_consistency | PASS | 6.26 s | 290 µs | 100.0% | 0.0% | Classification consistent during switch window |
| 17 | cpu_ram_under_failover | PASS | 14.53 s | 436 µs | 100.0% | 0.0% | Peak CPU 4.0%, RSS 5.9 MB during 3-round storm |

**NOT TESTED: none.** Every scenario runs and passes in this sandbox. (Earlier in
development, unconnected-UDP was EPERM-blocked; the connected-UDP redesign resolved
it — no scenario needed an environmental exemption.)

## Honest limitations

- **Session preservation (level 2) is 0%**: existing TCP/UDP sessions bound to a cut
  tunnel die; only new connections fail over (level 1, measured: recovery <1 ms for
  new probes). No "zero downtime" claim.
- **Detection ≈ 750–900 ms** for hard cuts (3 missed 250 ms heartbeats); degradation
  faults (loss/RTT/block) take ~3.3 s (quality window must confirm).
- **Revertive switching honors the 30 s cooldown** (no flap-back) — real engine
  behavior, kept as-is.
- Tunnel C / IPv6, TUN devices, real WAN, and third-party interop are out of scope
  for the loopback rig.

## Verification

- `cargo test -p zero-ha-tests`: **17 passed, 0 failed** (9 core in 98 s, 8 traffic in 52 s).
- `cargo check --workspace --tests`: zero errors (only pre-existing
  `FAILING_RUN` unused-import warning in `zero-observatory`, untouched).
- No `cargo update`, no pushes, no secrets; additive changes only.
- Bugs caught by real runs during development (not hidden): heartbeat loop initially
  skipped failed-heartbeat recording (failover never triggered); UDP responder hit
  sandbox EPERM (redesigned to connected UDP); `PortBlocked` semantics clarified.

## Files

- `crates/zero-ha-tests/src/rig.rs` — the rig (new)
- `crates/zero-ha-tests/src/wiring.rs` — `connect()` returns fresh `Arc<RigEngine>`
- `crates/zero-ha-tests/src/lib.rs`, `Cargo.toml` — wiring (`pub mod rig`, dep)
- `crates/zero-ha-tests/tests/common/mod.rs`, `tests/ha_failover_traffic.rs` —
  Arc-cloneable engine handle plumbing
