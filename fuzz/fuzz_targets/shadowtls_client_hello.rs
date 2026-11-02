#![no_main]
//! Fuzz the ShadowTLS v3 ClientHello verifier.
//!
//! `verify_client_hello` parses an unauthenticated, attacker-controlled
//! handshake message: the tag offset is derived from the session-id length
//! byte inside the message, so the parser must reject anything malformed
//! with `false` and never panic or index out of bounds. A panic here would be
//! reachable by any prober that opens a TCP connection to the inbound.

use libfuzzer_sys::fuzz_target;
use zero_transport::shadowtls::verify_client_hello;

fuzz_target!(|data: &[u8]| {
    // Both a wrong and a right password: the verifier must answer false, not
    // crash, for every input shape.
    let _ = verify_client_hello("fuzz-password", data);
    let _ = verify_client_hello("", data);
});
