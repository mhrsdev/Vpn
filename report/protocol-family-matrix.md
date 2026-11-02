# Protocol × IP-Family Compatibility Matrix — E1 (Protocols Phase 1)

Author: Implementation Agent E1 · Branch: `impl/protocols-1` · Date: 2026-11-01
Consumer: routing agent (triple-tunnel / dual-stack egress design).

Status vocabulary: `SUPPORTED` | `UNSUPPORTED` | `BLOCKED` | `UNSTABLE` | `NOT TESTED`.
`NOT TESTED` means exactly that — do not treat it as working. `BLOCKED` is
reserved for a family the protocol cannot use by construction or policy; an
environment that cannot run the test is `NOT TESTED`, never `BLOCKED`.

## Machine-readable table

| protocol              | family | tcp_connect | udp_datagrams | handshake | tls    | auth     | rtt_ms_loopback | loss_loopback | throughput_mibs_loopback | status     |
|-----------------------|--------|-------------|---------------|-----------|--------|----------|-----------------|---------------|--------------------------|------------|
| shadowtls-server      | ipv4   | SUPPORTED   | N/A           | SUPPORTED | N/A¹   | SUPPORTED| <1              | 0             | 16                       | SUPPORTED  |
| shadowtls-server      | ipv6   | SUPPORTED   | N/A           | SUPPORTED | N/A¹   | SUPPORTED| <1              | 0             | 9                        | SUPPORTED  |
| ss-udp (legacy AEAD)  | ipv4   | N/A         | NOT TESTED    | N/A       | N/A    | NOT TESTED²| NOT TESTED    | NOT TESTED    | NOT TESTED               | NOT TESTED |
| ss-udp (legacy AEAD)  | ipv6   | N/A         | NOT TESTED    | N/A       | N/A    | NOT TESTED²| NOT TESTED    | NOT TESTED    | NOT TESTED               | NOT TESTED |
| ss2022-udp (SIP022)   | ipv4   | N/A         | NOT TESTED    | N/A       | N/A    | NOT TESTED²| NOT TESTED    | NOT TESTED    | NOT TESTED               | NOT TESTED |
| ss2022-udp (SIP022)   | ipv6   | N/A         | NOT TESTED    | N/A       | N/A    | NOT TESTED²| NOT TESTED    | NOT TESTED    | NOT TESTED               | NOT TESTED |
| juicity-server (QUIC) | ipv4   | N/A³        | NOT TESTED    | NOT TESTED| NOT TESTED| NOT TESTED⁴| NOT TESTED    | NOT TESTED    | NOT TESTED               | NOT TESTED |
| juicity-server (QUIC) | ipv6   | N/A³        | NOT TESTED    | NOT TESTED| NOT TESTED| NOT TESTED⁴| NOT TESTED    | NOT TESTED    | NOT TESTED               | NOT TESTED |

¹ ShadowTLS deliberately performs no TLS handshake of its own; it masquerades
as one. "TLS" here means the real-TLS fallback path, which is untouched
existing code, not E1 scope.
² The AEAD codecs themselves are unit-tested (see below); what is NOT TESTED
is the datagram on a real socket in either family.
³ Juicity is QUIC-only; there is no TCP mode. `tcp_connect` is N/A by design.
⁴ The constant-time token comparison is unit-tested; the QUIC handshake
carrying it is NOT TESTED here.

## What was actually measured and how

Environment: the dev VM sandbox. Decisive constraint: **UDP `sendto(2)` is
blocked sandbox-wide** (`EPERM`); UDP `bind(2)` works, TCP works on both
families (verified: IPv6 TCP loopback `::1` connects and echoes). Pre-existing
`udp_sessions` integration tests fail here for the same reason, so this is
environmental, not a code defect.

### shadowtls-server — SUPPORTED on IPv4 and IPv6 (measured)

- Test: `zero-transport` `shadowtls::tests::accept_handshake_works_over_ipv4_and_ipv6_tcp`
  (added for this matrix). Real `TcpListener`/`TcpStream` sockets, one pass per
  family (`127.0.0.1`, `::1`): full ClientHello→ServerHello handshake, HMAC
  authentication, then 1 MiB echoed each way with a corruption-detecting
  payload pattern.
- Measured 2026-11-01 (unoptimized test profile, loopback):
  - IPv4: handshake OK, 2 MiB echoed in 124 ms (~16 MiB/s), 0 corruption.
  - IPv6: handshake OK, 2 MiB echoed in 214 ms (~9 MiB/s), 0 corruption.
- Also covered (family-agnostic, in-memory): wrong-password indistinguishability
  vs a dumb relay, tampered-ClientHello rejection with zero bytes emitted,
  decoy-forward path — 12/12 `shadowtls` unit tests green.
- NOT measured: RTT/loss/jitter/throughput over a real network, MTU edge
  behavior, multi-hour long-lived connections. Loopback numbers above say
  "the code path works on both families", not "this is deployment throughput".

### ss-udp / ss2022-udp — NOT TESTED on the wire (both families)

- The sandbox blocks the only operation that matters (`sendto`); no honest
  wire measurement is possible here. Marked NOT TESTED, not BLOCKED: nothing
  about the protocols or the code is family-specific.
- What *is* verified: 8 legacy-AEAD codec tests + 11 SS2022 codec tests green,
  including address framing for IPv4, IPv6 and domain targets, fresh-salt /
  fresh-session checks, tamper/truncation/wrong-password rejection, and the
  SS2022 sliding-window replay filter (replay rejected, out-of-window
  rejected, tampered packet does not advance the window).
- Code review notes for the routing agent: the datagram codecs are pure byte
  transforms with no family dependency; `serve_shadowsocks_udp` binds the
  inbound's configured `SocketAddr` (v4 or v6); `exchange_shadowsocks_udp`
  picks the socket family from the resolved server address. No code path
  assumes IPv4.
- Integration suite `crates/zero-runtime/tests/shadowsocks_udp.rs` (4 tests:
  direct legacy echo, direct 2022 echo, SOCKS→SS-outbound routing, DNS
  round-trip) is written and `#[ignore]`-gated for this sandbox; run it with
  `cargo test -p zero-runtime --test shadowsocks_udp -- --ignored` on a host
  with working UDP.

### juicity-server — NOT TESTED on the wire (both families)

- QUIC runs on UDP; same sandbox block applies. Marked NOT TESTED.
- What *is* verified: 3 new transport unit tests (UDP datagram framing
  round-trip, oversize rejection, constant-time token comparison over all 32
  bytes) green; full `cargo check` of the acceptor, listener arm, accept loop
  and UDP stream handler.
- Code review notes: `h3_server_endpoint(addr, …)` binds whatever `SocketAddr`
  the inbound configures (v4 or v6); the client's `tls_client_config` chooses
  its bind address from `addrs[0].is_ipv6()`. No family-specific logic.
- Integration suite `crates/zero-runtime/tests/juicity_server.rs` (4 tests:
  TCP echo, UDP echo, wrong-password rejection, malformed-auth drop) is
  written and `#[ignore]`-gated; run with
  `cargo test -p zero-runtime --test juicity_server -- --ignored` on a host
  with working UDP.

## Guidance for the routing agent

- Only `shadowtls-server` may be treated as dual-family ready today, and only
  on the strength of loopback measurements — re-measure on the real Iran→USA
  path before using it as a failover leg.
- `ss-udp`, `ss2022-udp`, `juicity-server` are **NOT TESTED** on either family
  in this environment. The code is written family-agnostic, but that is a
  design property, not a measurement. Verify on target hardware (or a host
  with working UDP) before marking them SUPPORTED in the triple-tunnel plan.
- Nothing in E1 scope is `UNSUPPORTED` or `BLOCKED` on any family by design.

---

## Part 2 — E2 (Protocols Phase 1b): AmneziaWG server + ShadowsocksR subset
**Agent:** E2 (Protocols Phase 1b) — AmneziaWG server + ShadowsocksR subset
**Date:** 2026-11-02
**Branch:** `impl/protocols-2`

## Machine-readable matrix

| Protocol | IPv4 | IPv6 | Notes |
|----------|------|------|-------|
| ShadowsocksR (subset: aes-256-cfb, aes-128-cfb, rc4-md5, chacha20-ietf × origin, auth_sha1_v4, auth_aes128_md5 × plain, http_simple, tls1.2_ticket_auth) | SUPPORTED | SUPPORTED | All 36 combos complete full handshake + bidirectional data over real TCP sockets on each family. |
| AmneziaWG server | SUPPORTED | SUPPORTED | Obfuscated handshake completes with junk enabled; junk silently discarded; transport data round-trips. Tested over real UDP sockets on each family. |

## What was actually measured (and how)

### Environment
- Linux VM, loopback only (`127.0.0.1` and `::1`). Both families verified present via `ip -6 addr` and Python socket bind/connect tests.
- Sandbox restriction: `sendto()` on **unconnected** UDP sockets returns EPERM on **both** families. All UDP tests use connected sockets (client↔server `connect()`), which works on both families. The production server uses `send_to` on its multi-peer socket — this is a sandbox-only limitation, not a protocol/family limitation.

### ShadowsocksR
- **Test:** `ssr::stream::tests::ssr_family_matrix_ipv4_and_ipv6` (commit `0305add`)
- **Method:** For each family (IPv4 `127.0.0.1`, IPv6 `::1`): bind a real `tokio::net::TcpListener`, accept one connection, run `SsrStream::connect` (client) against `SsrStream::accept` (server), exchange `b"hello from client"` → `b"hello from server"`, verify bytes, clean shutdown. Repeated for all 36 (method × protocol × obfs) combinations per family = 72 real-TCP handshakes.
- **Result:** 72/72 pass. Total test time 0.21s (~3ms per handshake on loopback).
- **Connection success rate:** 100% (36/36 per family).
- **Authentication:** `auth_sha1_v4` and `auth_aes128_md5` HMAC verification exercised in the combos above; wrong-password/tampered-packet rejection covered by existing `fail-closed` unit tests (not family-specific — crypto is family-independent).
- **TLS:** SSR has no real TLS; `tls1.2_ticket_auth` is an obfuscation plugin mimicking a TLS ClientHello. It was tested as one of the 3 obfs plugins in all combos on both families.

### AmneziaWG
- **Test:** `wg_server::tests::amnezia_family_matrix_ipv4_and_ipv6` (commit `0305add`)
- **Method:** For each family: bind server + client UDP sockets to the family loopback, connect them (sandbox workaround), start `serve_amnezia` with junk enabled (`junk_count=3`), send junk datagrams → assert no answer within 300ms, complete the obfuscated WireGuard handshake, encapsulate an IPv4-in-tunnel packet → assert the server delivers it de-obfuscated via `from_peers`.
- **Result:** Both families pass. Test time 0.80s (dominated by the 300ms junk-silence timeout per family).
- **Connection success rate:** 100% (1/1 handshake per family; the handshake itself is the same boringtun code path as the existing IPv4-only test).
- **Junk rejection:** Verified on both families (no response to junk datagrams).

## Honest NOT TESTED list

The following were **not** measured and must not be assumed:

1. **Real-world RTT / jitter / packet loss** — loopback only; no WAN measurement.
2. **Throughput under load** — no bulk-transfer benchmark was run on either family.
3. **Long-lived connections** — sessions lasted seconds, not hours; no rekey/keepalive-over-time validation per family.
4. **MTU behavior across real networks** — no fragmentation/PMTUD testing; IPv6's 1280-byte minimum MTU vs IPv4 behavior not exercised beyond loopback (65536 MTU).
5. **Third-party interop** — SSR byte layouts are clean-room reconstructions, loopback-verified only. No test against a non-our SSR implementation on either family.
6. **Dual-stack happy-eyeballs / family selection** — out of scope for E2; the routing agent owns this.
7. **AmneziaWG over IPv6 with real WireGuard peers** — handshake crypto is family-independent (boringtun), but only our own client/server pair was tested.
8. **UDP unconnected `send_to`** — blocked by the sandbox on both families; production multi-peer path untested in this environment.

## Verdict for the routing agent

Both protocols are **SUPPORTED** on **both** families at the handshake + data-path level as measured on loopback. There is no family-specific code in either implementation (address handling is via `std::net::SocketAddr`; crypto is family-independent). The matrix entries above are the honest, measured result — everything else is explicitly NOT TESTED.
