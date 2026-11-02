# Kill-Switch Implementation Report (F §3)

**Branch:** `impl/killswitch` (from `b0bfb57`)
**Spec:** `reports/designs/F-security.md` §3 (kill-switch / fail-closed DEFINITION)

## What was built

### 1. `zero-runtime::killswitch` — the named gate component (new)

F §3's deliverable was "a named module owning this invariant" — leak safety
was previously emergent (strict DNS + protected sockets + TUN capture), not a
specified, tested component. `crates/zero-runtime/src/killswitch.rs` is now
that component:

- **`KillSwitch::decide(class, dst)`** — the single choke point. Decision
  order implements each F §3.2 row:
  1. VPN Off → `VpnOff` (gate does not apply)
  2. Destination is a registered server endpoint → `ToServerEndpoint`
     (§3.1 exception (b); allowed even with all tunnels down so recovery
     stays possible)
  3. IPv6 dst with v6 upstream disabled → `Drop(Ipv6UpstreamOff)`
  4. Iranian class → `DirectIran` (BY DESIGN, not a leak)
  5. Network-change hold → `Drop(NetworkChangeHold)`
  6. Failover in progress → old (active) tunnel keeps carrying until the new
     path proves itself (**make-before-break**); if the old path is down too
     → `Drop(FailoverGap)`
  7. Active tunnel Up/Degraded → `ViaTunnel`; all down → `Drop(TunnelDown)`.
     **Foreign traffic is NEVER routed direct while VPN-ON** — the enum has
     no such variant, so the compiler enforces it.
- **Event log with reasons** (ring buffer, 256) + a non-rolling
  `drops_total` counter. Every failover decision carries its reason
  (owner prompt §5).
- **14 unit tests**, all passing (see Verification).

### 2. DNS fail-closed tests (`zero-dns`, +3 tests)

F §3.2 "DNS failure" was already correct (`LeakPolicy::Strict` → hard error,
no system fallback); these tests pin it:
- `strict_policy_rejects_system_resolver_outright` — the one path that would
  emit port-53 to OS resolvers is hard-blocked under Strict.
- `strict_policy_fails_closed_when_doh_is_blocked` — blocked DoH endpoint →
  transport error, never a fallback answer.
- `strict_is_the_default_leak_policy` — pins `Strict` as the default so a
  future change cannot silently weaken it.

### 3. HA kill-switch scenarios (`zero-ha-tests/tests/killswitch_scenarios.rs`, +4 tests)

Proven via the rig's `direct_egress_bytes` canary (single choke point):
- **KS-1** `tunnel_cut_midflow_no_direct_egress` — total foreign-path cut
  mid-flow: 0/≈15 foreign probes succeed, canary delta = 0, Iranian still
  flows (by design).
- **KS-2** `failover_window_no_direct_packets` — A→B failover window:
  canary delta = 0.
- **KS-3** `dns_failure_no_fallback_leak` — resolver blocked: queries return
  empty (fail closed), `dns_leak_observed()` = false, recovery after clear.
- **KS-4** `ipv6_cannot_egress_direct` — v6 literal probe: canary delta = 0
  (rig is v4-only; the v6 DROP gate decision is unit-tested in (1)).

## Verification (all run, none claimed on faith)

| Suite | Result |
|---|---|
| `zero-runtime --lib killswitch::` | **14/14 pass** |
| `zero-ha-tests --test killswitch_scenarios` | **4/4 pass** |
| `zero-dns --lib` (strict filter) | **6/6 pass** (3 pre-existing + 3 new) |
| `zero-dns --lib` (full) | 35 pass / 13 fail — **all 13 fail on the pristine tree too** (sandbox UDP restrictions; verified via `git stash`) — no regression |
| `cargo clippy -p zero-runtime --lib` | zero warnings in new code |
| `cargo fmt --check` | clean on touched files (the one diff in `api.rs` is H3's pre-existing) |

## What is NOT TESTED (honest boundaries)

- **Packet capture on physical interfaces** (F §3.3): the sandbox has no
  physical interface to capture. Needs a rooted device / emulator host with
  `tcpdump -i any`.
- **Real-device Doze** (`dumpsys deviceidle force-idle`): needs hardware.
- **End-to-end IPv6**: no v6 uplink in the sandbox. The gate's v6 DROP
  decision is unit-tested; e2e needs a dual-stack environment.
- **App-kill / reboot windows**: honest limitations per F §3.2 — no app code
  can prevent direct traffic there. Mitigation is Android's system always-on
  VPN + "Block connections without VPN" (see Android seams below).
- **WebRTC STUN reflexive-address check** (C8): needs a real browser +
  network; NOT TESTED.

## Integration seams

### Engine (`server.rs` data path) — next step, not faked
The gate is implemented, unit-tested, and exported from `zero-runtime`, but
**not yet wired into `server.rs`'s session-establishment path**. The natural
call site is where `split_engine::evaluate()` returns `Decision::Block` /
`Decision::Outbound`: consult `KillSwitch::decide()` with the session's
`TrafficClass` (from the `SplitVerdict`) and destination, and honor
`Drop` by terminating the session. Tunnel liveness feeds from the existing
`TransportTable`/`HealthTable` via `set_tunnel`; failover via
`begin_failover`/`prove_failover` alongside the existing failover logic.
This wiring is deliberately left for the lead: it touches the hot path and
deserves review against the R7 datapath work.

### Android (`zray-mobile` / Kotlin)
- `ZeroVpnService.kt` already captures IPv6 (`:103-112` per F §3.2) — no change.
- Required app work (not in this branch):
  1. Setup UX **strongly guides** the user to system always-on VPN +
     "Block connections without VPN" (the only true boot-time/app-kill
     fail-closed).
  2. On restart after a kill, show "protection was interrupted" — do not
     silently resume.
  3. Label SSH provisioning as "direct connection to your server"
     (F §3.2 management-traffic transparency).
  4. An in-app "kill switch" toggle must be labeled by what it actually does;
     it cannot promise more than the OS allows.

## Files changed (additive only)

- `crates/zero-runtime/src/killswitch.rs` (new, ~700 lines incl. 14 tests)
- `crates/zero-runtime/src/lib.rs` (+1 line: `pub mod killswitch;`)
- `crates/zero-dns/src/lib.rs` (+3 tests, no logic changes)
- `crates/zero-ha-tests/tests/killswitch_scenarios.rs` (new, 4 tests)

No refactors of TransportTable, EgressEngine, or split_dns. No contract
changes. No `cargo update`. No pushes. No secrets.
