//! Shadowsocks UDP relay end to end, both cipher generations.
//!
//! * Direct: a raw UDP client seals datagrams with the codec under test and
//!   exchanges them with the real server inbound (legacy AEAD and 2022).
//! * Routed: a SOCKS UDP associate is routed through a Shadowsocks outbound
//!   to a second server, exercising the outbound datagram exchange.
//! * DNS: a real DNS query round-trips through the relay and the answer
//!   parses as DNS with the query's transaction id.
//!
//! These need a host whose sandbox lets UDP datagrams through (this
//! repository's dev sandbox blocks UDP `sendto`); run them with
//!   cargo test -p zero-runtime --test shadowsocks_udp -- --ignored

use std::net::{SocketAddr, TcpListener as StdListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const PASSWORD_2022_AES256: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local addr")
            .port();
        // The UDP half of the port must be free too for UDP-facing inbounds.
        if StdUdpSocket::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free port");
}

async fn spawn(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        if let Err(error) = running.run().await {
            panic!("server failed to start: {error}");
        }
    });
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .expect("server never reported its listeners bound");
    server
}

/// A UDP peer that echoes every datagram back unchanged.
async fn echo_peer() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let _ = socket.send_to(&buffer[..length], from).await;
        }
    });
    address
}

fn ss_inbound(port: u16, method: &str, password: &str) -> Value {
    json!({
        "tag": "ss-in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "shadowsocks",
        "settings": {"method": method, "password": password},
        "streamSettings": {"network": "raw"},
    })
}

#[ignore = "needs a host where UDP datagrams are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_aead_udp_relay_echoes_through_the_server() {
    let peer = echo_peer().await;
    let port = free_port();
    let _server = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [ss_inbound(port, "aes-256-gcm", "udp-test-password")],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;

    let codec = zero_protocol::shadowsocks::UdpCodec::new(
        zero_protocol::shadowsocks::Method::Aes256Gcm,
        "udp-test-password",
    );
    let destination = zero_core::Destination::udp(zero_core::Address::Ip(peer.ip()), peer.port());
    let sealed = codec.encode_datagram(&destination, b"hello udp").unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&sealed, ("127.0.0.1", port)).await.unwrap();
    let mut buffer = vec![0u8; 65_535];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .expect("UDP reply timed out")
        .unwrap();
    let (source, payload) = codec.decode_datagram(&buffer[..length]).unwrap();
    assert_eq!(source.address, zero_core::Address::Ip(peer.ip()));
    assert_eq!(source.port, peer.port());
    assert_eq!(payload, b"hello udp");
}

#[ignore = "needs a host where UDP datagrams are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_udp_relay_echoes_through_the_server() {
    let peer = echo_peer().await;
    let port = free_port();
    let _server = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [ss_inbound(port, "2022-blake3-aes-256-gcm", PASSWORD_2022_AES256)],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;

    let method = zero_protocol::shadowsocks2022::Method::Aes256Gcm;
    let mut session =
        zero_protocol::shadowsocks2022::UdpClient::new(method, PASSWORD_2022_AES256).unwrap();
    let destination = zero_core::Destination::udp(zero_core::Address::Ip(peer.ip()), peer.port());
    let sealed = session.encode(&destination, b"hello udp 2022").unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&sealed, ("127.0.0.1", port)).await.unwrap();
    let mut buffer = vec![0u8; 65_535];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .expect("UDP reply timed out")
        .unwrap();
    let (source, payload) = session.decode(&buffer[..length]).unwrap();
    assert_eq!(source.address, zero_core::Address::Ip(peer.ip()));
    assert_eq!(source.port, peer.port());
    assert_eq!(payload, b"hello udp 2022");
}

fn socks_udp_datagram(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0, 0, 0, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => datagram.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test targets are IPv4"),
    }
    datagram.extend_from_slice(&target.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

/// A SOCKS UDP associate routed through a Shadowsocks outbound to a second
/// server: exercises the outbound datagram exchange end to end.
#[ignore = "needs a host where UDP datagrams are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_udp_routed_over_a_shadowsocks_outbound() {
    let peer = echo_peer().await;
    let ss_port = free_port();
    let socks_port = free_port();
    let _exit = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [ss_inbound(ss_port, "aes-256-gcm", "hop-password")],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;
    let _gateway = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{
            "tag": "ss-out",
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": "127.0.0.1",
                "port": ss_port,
                "method": "aes-256-gcm",
                "password": "hop-password",
            }]},
            "streamSettings": {"network": "raw"},
        }],
    }))
    .await;

    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE was refused");
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&socks_udp_datagram(peer, b"via ss"), relay)
        .await
        .unwrap();
    let mut buffer = vec![0u8; 65_535];
    let (length, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut buffer))
        .await
        .expect("UDP reply timed out")
        .unwrap();
    // RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2), then the payload.
    assert_eq!(&buffer[10..length], b"via ss");
    drop(control);
}

/// A real DNS query (example.com A) round-trips through the Shadowsocks UDP
/// relay; the answer parses as DNS and carries the query's transaction id.
#[ignore = "needs a host where UDP datagrams are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_query_round_trips_through_the_ss_udp_relay() {
    let dns = dns_responder().await;
    let port = free_port();
    let _server = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [ss_inbound(port, "aes-256-gcm", "dns-password")],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;

    let codec = zero_protocol::shadowsocks::UdpCodec::new(
        zero_protocol::shadowsocks::Method::Aes256Gcm,
        "dns-password",
    );
    let destination = zero_core::Destination::udp(zero_core::Address::Ip(dns.ip()), dns.port());
    let query = dns_query(0x1234, "example.com");
    let sealed = codec.encode_datagram(&destination, &query).unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&sealed, ("127.0.0.1", port)).await.unwrap();
    let mut buffer = vec![0u8; 65_535];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .expect("DNS answer timed out")
        .unwrap();
    let (_, answer) = codec.decode_datagram(&buffer[..length]).unwrap();
    assert_eq!(u16::from_be_bytes([answer[0], answer[1]]), 0x1234);
    assert_eq!(answer[2] & 0x80, 0x80, "QR bit marks a response");
    assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 1, "one answer");
}

/// A minimal DNS responder: answers any query with one A record for
/// 93.184.216.34, copying the query's transaction id and question.
async fn dns_responder() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let query = &buffer[..length];
            if query.len() < 12 {
                continue;
            }
            let mut response = Vec::with_capacity(query.len() + 16);
            response.extend_from_slice(&query[0..2]); // transaction id
            response.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA
            response.extend_from_slice(&query[4..6]); // QDCOUNT
            response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS + AR = 0
            response.extend_from_slice(&query[12..]); // question
            response.extend_from_slice(&[
                0xc0, 0x0c, // name pointer to the question
                0x00, 0x01, // TYPE A
                0x00, 0x01, // CLASS IN
                0x00, 0x00, 0x00, 0x3c, // TTL 60
                0x00, 0x04, // RDLENGTH
                93, 184, 216, 34, // RDATA
            ]);
            let _ = socket.send_to(&response, from).await;
        }
    });
    address
}

/// A minimal DNS query for one A record: header + QNAME + QTYPE + QCLASS.
fn dns_query(txid: u16, name: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&txid.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // RD
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
    query
}
