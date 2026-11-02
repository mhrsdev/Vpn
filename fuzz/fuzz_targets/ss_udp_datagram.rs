#![no_main]
//! Fuzz the legacy Shadowsocks AEAD UDP datagram parser.
//!
//! `UdpCodec::decode_datagram` parses unauthenticated, attacker-controlled
//! datagrams: every input shape must decode to `Ok` or a clean `Err`, never
//! panic or index out of bounds. A panic here would be reachable by any host
//! that can send the inbound a UDP datagram.

use libfuzzer_sys::fuzz_target;
use zero_protocol::shadowsocks::{Method, UdpCodec};

fuzz_target!(|data: &[u8]| {
    for method in [
        Method::Aes128Gcm,
        Method::Aes256Gcm,
        Method::Chacha20Poly1305,
    ] {
        let codec = UdpCodec::new(method, "fuzz-password");
        let _ = codec.decode_datagram(data);
    }
});
