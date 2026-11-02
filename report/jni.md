# H4 — JNI Bridge: 5 Routing/Management Functions

Branch: `impl/jni` (from `52689ee`). All changes additive; no secrets in git; never pushed.

## The 5 functions (Design B §4.3, Design D §5.1)

Rust: `crates/zray-mobile/src/android.rs` (new "routing JNI" section, ~700 lines).
Kotlin: `ZrayNative.kt` (5 `external fun`), `NativeExtras.kt` (wired, no more
"not wired yet" throws), `AdminModel.kt` (`api()` now sends `pair_record` +
`target`), `docs/native-contract.md` (admin section updated).

| Kotlin (`ZrayNative`, `com.zeronet.mobile.core`) | Rust (`Java_com_zeronet_mobile_core_ZrayNative_*`) | Signature / contract |
|---|---|---|
| `routingHealth(): String` | `routingHealth` | `() -> jstring` (JSON). Read-only snapshot for the ~1/s UI poll. Combines `Server::ha_snapshot()` + `health_snapshot()` + stored `RoutingMode` into Design B's `{running, mode, pairs, picks, switches, tunnel}`. Fields the phone cannot know (`pairId`, `exit`, `throughput_bps`) are **omitted, never invented**. |
| `setRoutingMode(requestJson: String): String?` | `setRoutingMode` | `(JString) -> jstring` (null = success, else error). Validates Design B §4.3 shape (nested `priorities.{gateways,exits}`, `probe.intervalSec`, `cooldownSec`, leg locks, flags) and stores it without restart. Eligibility/scoring itself is Kotlin-side (`Engine.kt`); the stored mode is what `routingHealth` reports. |
| `probeNow(): String?` | `probeNow` | `() -> jstring` (null = success). Rate-limited to 1/10 s (atomic epoch counter). Calls `Server::request_probe()` (new `tokio::sync::Notify` wired into `zero-runtime`'s observatory + transport-heartbeat waits). |
| `pairTest(tag: String): String` | `pairTest` | `(JString) -> jstring` (JSON). TCP-connects to the outbound's server address via `connect_protected` (VPN-protected socket path, no leak around the tunnel), 10 s timeout. Success: `{tag, ok:true, establish_ms, rtt_ms}` — `establish_ms` *is* a round-trip measurement so `rtt_ms` carries the same value. `udp_ok: null` — honest: a UDP claim needs a cooperating endpoint and is not faked. Unknown tag / non-proxy outbound / DNS failure → `{ok:false, failed_leg:"gateway", detail}`. |
| `adminCall(requestJson: String, listener: NativeListener): Long` | `adminCall` | `(JString, JObject) -> jlong` (job handle, cancellable via `cancel`). Management plane: SSHes to the target server (pinned host key, key from the pair record), opens a `direct-tcpip` channel to `127.0.0.1:<management_port>` (loopback-only admin API — new `Connection::open_direct_tcpip` in `zero-provision/src/ssh.rs`), speaks minimal HTTP/1.1 (`Connection: close` delimited), streams `step`/`detail`/`done` events. Request gains `"pair_record"` (PairRecord v2) + `"target": "exit"\|"gateway"` (Kotlin side). |

## Error handling

- **No panics cross FFI.** Every export is wrapped in `contained()` (catch_unwind → fallback string). `setRoutingMode`/`probeNow` return null on success, error string otherwise (existing convention). `routingHealth`/`pairTest` return error-shaped JSON (`{ok:false,…}` / `{"error":…}`) since they must return a string.
- **adminCall trust rules:** bearer <redacted> Authorization header only, never in URL; never persisted; dropped from memory after the request is built; error strings redact the token before crossing to Kotlin (defense in depth, F W1). Path must start with `/api/v1/`; method allow-listed. Malformed/truncated HTTP responses are errors, never silent empty bodies. 4 MiB response cap.
- **probeNow** rate limit prevents UI-driven probe storms. **pairTest** uses `connect_protected` so the probe itself cannot leak around the tunnel.

## Verification

- `cargo check -p zray-mobile --features jni`: **0 errors** (first pass, clean).
- `cargo fmt --check -p zray-mobile`: clean.
- `cargo clippy`: not re-run (sibling agents hold the cargo lock; the check above is the gate).
- Kotlin: HaApiTest/RouterApiTest unaffected (they test `HaApi.kt`/`RouterApi.kt` parsing, untouched). AdminModelTest covers the modified `api()` — its scripted `run` receives the request with the new `pair_record`/`target` fields; existing assertions (pair id, token, no token in errors) still hold by construction. **Full Gradle build/APK: NOT RUN** (environment — daemon blocked, needs user present for Ask cards).
- New Rust unit tests: none added — the functions are thin JNI adapters over already-tested engine surfaces (`ha_snapshot`, `health_snapshot`, `ssh::connect`); the honest gaps (UDP probe, full proxy handshake) are documented above rather than faked.

## Open / deferred

- `setRoutingMode` stores + validates; live eligibility/scoring stays in Kotlin's `Engine.kt` (documented, not a silent no-op).
- `pairTest` is a TCP reachability probe, not a full proxy-handshake test — the observatory's ongoing probes cover session health.
- `zray.h`/`header_parity.rs` cover only the C ABI (`lib.rs`), not JNI `extern "system"` functions — no header changes needed.
