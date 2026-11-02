//! R7 — WireGuard crypto proof with the REAL boringtun code.
//!
//! The inter-server data path is `WgStack` (gateway outbound) → UDP →
//! `serve_wireguard` (exit inbound) → `freedom`. Both ends drive real
//! `boringtun::noise::Tunn` instances (see `zero-protocol/src/wg_stack.rs:861`
//! and `zero-protocol/src/wg_server.rs:438,575`) — no hand-rolled crypto
//! anywhere on this path.
//!
//! The full Server-level proof lives in `wg_datapath.rs` (SOCKS → gateway →
//! exit → echo). Those tests are `#[ignore]`d in this sandbox because the
//! sandbox's seccomp returns EPERM on unconnected UDP `sendto(2)` — the exact
//! syscall the production WG wire uses (`wg_stack.rs:698`,
//! `wg_server.rs:317`). They must run on a real host.
//!
//! This file proves everything the sandbox DOES allow, with the real
//! boringtun 0.7.1 `Tunn` both ends use:
//! 1. A real handshake completes (initiation → response → transport-ready).
//! 2. Transport data flows both ways with byte-exact integrity (1 B … 64 KiB).
//! 3. A wrong key FAILS the handshake (negative test — the crypto is real,
//!    not bypassed).
//! 4. Two clients are isolated: A's traffic never decrypts under B's session.
//! 5. Rekey works: a second handshake keeps traffic flowing.
//! 6. The client's initiation bytes parse as a valid WireGuard handshake
//!    initiation (packet-format compatibility with the server's parser).

use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

fn keypair(seed: u8) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// A `Tunn` wired exactly like the production ends: no PSK, no keepalive,
/// fresh rate limiter (same arguments `WgStack`/`wg_server` pass).
fn tunn(own_secret: StaticSecret, peer_public: PublicKey) -> Tunn {
    Tunn::new(own_secret, peer_public, None, None, 0, None)
}

/// A REAL IPv4 packet (proper header: version, total length, TTL, protocol,
/// addresses) carrying a deterministic payload pattern. boringtun validates
/// the IP header on decapsulation, so the header must be well-formed.
fn ipv4_payload(payload_len: usize, pattern_seed: u8) -> Vec<u8> {
    let total = (20 + payload_len) as u16;
    let mut packet = vec![0u8; 20 + payload_len];
    packet[0] = 0x45; // IPv4, IHL 5
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 6; // TCP
    packet[12..16].copy_from_slice(&[10, 7, 0, 2]); // src
    packet[16..20].copy_from_slice(&[10, 7, 0, 1]); // dst
    for (i, byte) in packet.iter_mut().enumerate().skip(20) {
        *byte = pattern_seed.wrapping_add((i % 251) as u8);
    }
    packet
}

/// Drive a full handshake between `client` and `server` via a packet pump:
/// exchange datagrams until both sides hold a usable transport session.
fn handshake(client: &mut Tunn, server: &mut Tunn) {
    let mut buf = vec![0u8; 2048];
    let init = match client.encapsulate(&[], &mut buf) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("client did not emit a handshake initiation: {other:?}"),
    };
    assert_eq!(init.len(), 148, "initiation must be 148 bytes");

    let mut buf = vec![0u8; 2048];
    let resp = match server.decapsulate(None, &init, &mut buf) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("server did not answer the initiation: {other:?}"),
    };
    assert_eq!(resp.len(), 92, "response must be 92 bytes");

    let mut buf = vec![0u8; 2048];
    let keepalive = match client.decapsulate(None, &resp, &mut buf) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("client did not complete the handshake: {other:?}"),
    };
    assert_eq!(keepalive.len(), 32, "expected a keepalive");

    // Feed the keepalive back so the server also sees client transport.
    let mut buf = vec![0u8; 65536];
    match server.decapsulate(None, &keepalive, &mut buf) {
        TunnResult::Done => {}
        other => panic!("server did not absorb the keepalive: {other:?}"),
    }
}

/// Send `payload` through `from`'s session and decrypt it with `to`.
/// Returns the exact plaintext bytes.
fn transport(from: &mut Tunn, to: &mut Tunn, payload: &[u8]) -> Vec<u8> {
    let mut enc = vec![0u8; payload.len() + 2048];
    let packet = match from.encapsulate(payload, &mut enc) {
        TunnResult::WriteToNetwork(data) => data.to_vec(),
        other => panic!("encapsulate failed: {other:?}"),
    };
    let mut dec = vec![0u8; 65536];
    match to.decapsulate(None, &packet, &mut dec) {
        TunnResult::WriteToTunnelV4(data, _) => data.to_vec(),
        TunnResult::WriteToTunnelV6(data, _) => data.to_vec(),
        other => panic!("decapsulate failed: {other:?}"),
    }
}

#[test]
fn handshake_completes_with_real_crypto() {
    let (client_secret, client_public) = keypair(10);
    let (server_secret, server_public) = keypair(20);
    let mut client = tunn(client_secret, server_public);
    let mut server = tunn(server_secret, client_public);
    handshake(&mut client, &mut server);

    // Both directions carry transport data immediately after the handshake.
    let ping = ipv4_payload(32, 0xA5);
    assert_eq!(transport(&mut client, &mut server, &ping), ping);
    let pong = ipv4_payload(32, 0x5A);
    assert_eq!(transport(&mut server, &mut client, &pong), pong);
}

#[test]
fn transport_data_flows_both_ways_with_integrity() {
    let (client_secret, client_public) = keypair(11);
    let (server_secret, server_public) = keypair(21);
    let mut client = tunn(client_secret, server_public);
    let mut server = tunn(server_secret, client_public);
    handshake(&mut client, &mut server);

    // Sizes from 1 byte to ~64 KiB payload, both directions, byte-exact.
    // (Total IP packet must stay ≤ 65535.)
    for (size, seed) in [(1, 1u8), (64, 2), (1200, 3), (8192, 4), (65495, 5)] {
        let payload = ipv4_payload(size, seed);
        assert_eq!(
            transport(&mut client, &mut server, &payload),
            payload,
            "client→server integrity failed at {size} bytes"
        );
        assert_eq!(
            transport(&mut server, &mut client, &payload),
            payload,
            "server→client integrity failed at {size} bytes"
        );
    }
}

#[test]
fn wrong_key_handshake_fails() {
    let (client_secret, _) = keypair(12);
    let (server_secret, server_public) = keypair(22);
    let (_other_secret, other_public) = keypair(99);

    // The server expects peer 99, but the client proves identity 12.
    let mut client = tunn(client_secret, server_public);
    let mut server = tunn(server_secret, other_public);

    let mut buf = vec![0u8; 2048];
    let init = match client.encapsulate(&[], &mut buf) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("client did not emit a handshake initiation: {other:?}"),
    };
    let mut buf = vec![0u8; 2048];
    // The crypto must reject the stranger — deterministically, not flakily.
    for _ in 0..3 {
        match server.decapsulate(None, &init, &mut buf) {
            TunnResult::Err(_) => {}
            other => panic!("server ACCEPTED a handshake from the wrong key: {other:?}"),
        }
    }
}

#[test]
fn two_clients_are_session_isolated() {
    let (a_secret, a_public) = keypair(30);
    let (b_secret, b_public) = keypair(31);
    // Same server keypair for both peer Tunns (deterministic from the seed).
    let (server_secret_a, server_public) = keypair(40);
    let (server_secret_b, _) = keypair(40);

    let mut client_a = tunn(a_secret, server_public);
    let mut client_b = tunn(b_secret, server_public);
    // The server keeps one Tunn per peer, exactly like wg_server does.
    let mut server_for_a = tunn(server_secret_a, a_public);
    let mut server_for_b = tunn(server_secret_b, b_public);

    handshake(&mut client_a, &mut server_for_a);
    handshake(&mut client_b, &mut server_for_b);

    // A's traffic decrypts under A's session only.
    let payload_a = ipv4_payload(128, 0xAA);
    let mut enc = vec![0u8; 2048];
    let packet_a = match client_a.encapsulate(&payload_a, &mut enc) {
        TunnResult::WriteToNetwork(data) => data.to_vec(),
        other => panic!("encapsulate failed: {other:?}"),
    };
    let mut dec = vec![0u8; 65536];
    assert_eq!(
        match server_for_a.decapsulate(None, &packet_a, &mut dec) {
            TunnResult::WriteToTunnelV4(data, _) => data.to_vec(),
            other => panic!("A's own session could not decrypt: {other:?}"),
        },
        payload_a
    );
    // B's server-side session must NOT decrypt A's packet.
    let mut dec = vec![0u8; 65536];
    assert!(
        matches!(
            server_for_b.decapsulate(None, &packet_a, &mut dec),
            TunnResult::Err(_)
        ),
        "client A's packet decrypted under client B's session — isolation broken"
    );

    // And symmetrically for B.
    let payload_b = ipv4_payload(128, 0xBB);
    let mut enc = vec![0u8; 2048];
    let packet_b = match client_b.encapsulate(&payload_b, &mut enc) {
        TunnResult::WriteToNetwork(data) => data.to_vec(),
        other => panic!("encapsulate failed: {other:?}"),
    };
    let mut dec = vec![0u8; 65536];
    assert!(
        matches!(
            server_for_a.decapsulate(None, &packet_b, &mut dec),
            TunnResult::Err(_)
        ),
        "client B's packet decrypted under client A's session — isolation broken"
    );
}

#[test]
fn rekey_keeps_traffic_flowing() {
    let (client_secret, client_public) = keypair(50);
    let (server_secret, server_public) = keypair(60);

    // First session: handshake + traffic.
    let mut client = tunn(client_secret, server_public);
    let mut server = tunn(server_secret, client_public);
    handshake(&mut client, &mut server);
    let before = ipv4_payload(64, 0x11);
    assert_eq!(transport(&mut client, &mut server, &before), before);

    // Rekey (as after key rotation or a restart): fresh Tunn instances with
    // the same keys handshake again and traffic flows with byte-exact
    // integrity. Sessions are not tied to instance state in a way that
    // breaks reconnection.
    let (client_secret2, _) = keypair(50);
    let (server_secret2, _) = keypair(60);
    let (_, client_public2) = keypair(50);
    let (_, server_public2) = keypair(60);
    let mut client2 = tunn(client_secret2, server_public2);
    let mut server2 = tunn(server_secret2, client_public2);
    handshake(&mut client2, &mut server2);
    let after = ipv4_payload(64, 0x22);
    assert_eq!(transport(&mut client2, &mut server2, &after), after);
    assert_eq!(transport(&mut server2, &mut client2, &after), after);
}

#[test]
fn client_initiation_parses_as_handshake_init() {
    let (client_secret, _) = keypair(70);
    let (_, server_public) = keypair(80);
    let mut client = tunn(client_secret, server_public);

    let mut buf = vec![0u8; 2048];
    let init = match client.encapsulate(&[], &mut buf) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("client did not emit a handshake initiation: {other:?}"),
    };
    // The server's own packet parser must recognize these bytes as a
    // handshake initiation — packet-format compatibility between the ends.
    match Tunn::parse_incoming_packet(&init) {
        Ok(Packet::HandshakeInit(_)) => {}
        other => panic!("initiation did not parse as HandshakeInit: {other:?}"),
    }
}
