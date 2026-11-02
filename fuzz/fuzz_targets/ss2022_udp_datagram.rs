#![no_main]
//! Fuzz the Shadowsocks 2022 UDP datagram parser.
//!
//! `UdpServer::decode` parses unauthenticated, attacker-controlled datagrams:
//! every input shape must decode to `Ok` or a clean `Err`, never panic or
//! index out of bounds. A panic here would be reachable by any host that can
//! send the inbound a UDP datagram.

use libfuzzer_sys::fuzz_target;
use std::net::SocketAddr;
use zero_protocol::shadowsocks2022::{Method, UdpServer};

fuzz_target!(|data: &[u8]| {
    let source: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    // (method, base64 PSK of the method's key length). Wrong-shaped inputs
    // must still decode to Err, not panic, for every method.
    let cases = [
        (Method::Aes128Gcm, "AAAAAAAAAAAAAAAAAAAAAA=="),
        (
            Method::Aes256Gcm,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        (
            Method::Chacha20Poly1305,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    ];
    for (method, password) in cases {
        if let Ok(mut server) = UdpServer::new(method, password) {
            let _ = server.decode(data, source);
        }
    }
});
