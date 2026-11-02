# zero-ha-tests — HA failover integration-test scaffolding

**Status: SCAFFOLD.** The 17 scenario tests compile against the `HaEngine`
trait (`src/engine.rs`) but no engine implements it yet. Every scenario fails
loudly with a `SCAFFOLD` panic until the real dual always-on Iran→USA engine
is wired. **No test here fakes a pass against a mock** — that is the
load-bearing honesty rule for the acceptance gate.

## Layout

```
crates/zero-ha-tests/
  Cargo.toml            # standalone ([workspace] detached — see below)
  README.md             # this file
  src/
    lib.rs
    engine.rs           # HaEngine trait + types (THE contract to implement)
    metrics.rs          # HaMetrics record (unit-tested, runnable today)
    wiring.rs           # connect() / require_engine() — the wiring point
  tests/
    common/mod.rs       # shared helpers (await_state, probe_window, ...)
    ha_failover_core.rs # 9 fault-injection scenarios
    ha_failover_traffic.rs # 8 traffic / leak / resource scenarios
```

## Scenarios (17)

Core fault injection (`ha_failover_core.rs`):
1. `sudden_primary_cut` — abrupt Tunnel A death
2. `primary_port_blocked` — protocol port blackholed (process alive)
3. `severe_packet_loss` — 60% loss on A (loss-triggered failover)
4. `rtt_spike` — +3s latency on A (opportunistic, hysteresis-respecting move)
5. `dns_failure` — resolver path broken, incl. during a switch
6. `full_foreign_path_cut` — both tunnels down (foreign fail-closed)
7. `primary_recovery` — A recovers: background recovery, no flap-back
8. `alternating_quality` — 90s oscillation (anti-flap acceptance)
9. `both_tunnels_down` — total outage + auto-recovery

Traffic / leak / resources (`ha_failover_traffic.rs`):
10. `long_download` — 64 MiB transfer across a switch
11. `stable_tcp_connection` — long-lived TCP across a switch
12. `udp_session` — UDP flows across a switch (loss measured honestly)
13. `file_transfer` — integrity-checked transfer under degradation
14. `leak_during_switch` — DNS hammered across the exact switch window
15. `exit_ip_constancy` — USA exit IP sampled 10x post-switch
16. `split_routing_consistency` — classification checked during the switch
17. `cpu_ram_under_failover` — failover storm with resource peaks

## Metrics (every scenario records)

- `failover_detection` — fault injection → engine failover decision
- `traffic_recovery` — fault injection → first successful data on new path
- `session_survival_pct` — pre-existing sessions still alive afterwards
- `packet_loss_pct` — probes lost inside the failover window
- `exit_ip_consistent` — USA exit IP identical before/after (hard invariant)
- `dns_leak` — true = leak observed (hard invariant: must be false)
- `routing_policy_consistent` — split-routing held (hard invariant)
- `peak_cpu_pct` / `peak_rss_bytes`
- `direct_egress_bytes` delta — canary counter, must stay 0 (fail-closed)

Hard invariants are asserted; timing/survival/loss are recorded and
reported — their acceptance budgets are set by the routing agent when the
engine lands, not invented here.

## Wiring checklist (routing agent)

1. Implement `engine::HaEngine` for the real dual always-on engine (or a
   dedicated rig driving the real engine code — loopback pairs per
   B-routing.md §7.2 test 11 are acceptable; canned-value mocks are not).
2. Return it from `wiring::connect()`. `connect()` must be cheaply callable
   (the `long_download` scenario calls it twice); an `Arc`-backed impl is
   the intended shape.
3. Realize `Fault` injection in the rig (netem/iptables/loopback control —
   your choice, documented).
4. Run: `cargo test` in this crate. Scenarios stop panicking with SCAFFOLD
   and start measuring.
5. Optional promotion: add `crates/zero-ha-tests` to the root workspace
   `members` and delete the `[workspace]` table in this crate's Cargo.toml.

## Standalone note

This crate is deliberately detached (`[workspace]` table) so the scaffold
lands without touching the root `Cargo.toml`. Run it with:

```
cd crates/zero-ha-tests
cargo test            # unit tests pass; scenarios fail loudly as SCAFFOLD
cargo test -- --nocapture   # see the SCAFFOLD messages
```

## Honesty rules (binding)

- A SCAFFOLD panic is a *failing* test, never a passing one.
- Never implement a mock engine returning canned values to make these green.
- "Zero downtime" is never asserted — the report distinguishes fast switch
  for new connections / session preservation / true lossless, per the HA
  addendum.
- Full-tunnel modem behavior, MPPE negotiation, and other device-dependent
  claims are out of scope here (see G-huawei.md Q5); this harness covers the
  Iran→USA leg only.
