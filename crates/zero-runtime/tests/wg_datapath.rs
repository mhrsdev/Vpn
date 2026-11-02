//! R7 proof — the inter-server data path end to end.
//!
//! The gateway's `wg-tunnel` WireGuard outbound (built on `WgStack` via
//! `warp::tunnel_for`, `OutboundProtocol::AmneziaWireguard` with a plain
//! WireGuard config) talks to the exit's `wireguard` inbound
//! (`serve_wireguard`): decrypted packets go into a userspace netstack and the
//! exit's routing sends them to `freedom`. TCP **and** UDP must reach a
//! loopback echo through the whole chain:
//!
//! ```text
//! test client --SOCKS--> gateway (socks-in)
//!                        --wg-tunnel--> exit (wireguard inbound)
//!                                      --freedom--> echo server
//! ```
//!
//! This is the single highest-risk integration in Design B (§8-R7): if this
//! path does not carry traffic, the two-path architecture is dead on arrival.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn key_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = x25519_dalek::StaticSecret::from([seed; 32]);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn free_tcp_port() -> u16 {
    use std::collections::HashSet;
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("read ephemeral address")
            .port();
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free test port");
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn(config: &Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    server
}

async fn wait_for_listener(address: SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{address} never started listening");
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let mut reply = b"tcp:".to_vec();
                reply.extend_from_slice(&buffer[..read]);
                let _ = stream.write_all(&reply).await;
            });
        }
    });
    address
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            let mut reply = b"udp:".to_vec();
            reply.extend_from_slice(&buffer[..read]);
            let _ = socket.send_to(&reply, from).await;
        }
    });
    address
}

fn exit_config(wg_port: u16, exit_secret: &[u8; 32], gateway_public: &[u8; 32]) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "wg-in",
            "listen": "127.0.0.1",
            "port": wg_port,
            "protocol": "wireguard",
            "settings": {
                "secretKey": b64(exit_secret),
                "mtu": 1380,
                "peers": [{
                    "publicKey": b64(gateway_public),
                    "allowedIPs": ["10.7.0.2/32"],
                }],
            },
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["wg-in"], "outboundTag": "direct"},
        ]},
    })
}

fn gateway_config(
    socks_port: u16,
    wg_port: u16,
    gateway_secret: &[u8; 32],
    exit_public: &[u8; 32],
) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{
            "tag": "wg-tunnel",
            "protocol": "wireguard",
            "settings": {
                "privateKey": b64(gateway_secret),
                "peerPublicKey": b64(exit_public),
                "address": "127.0.0.1",
                "port": wg_port,
                "tunnelAddress": "10.7.0.2",
                "persistentKeepalive": 5,
            },
        }],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["socks-in"], "outboundTag": "wg-tunnel"},
        ]},
    })
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.expect("connect SOCKS");
    stream.set_nodelay(true).unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test targets IPv4"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    let addr_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        other => panic!("unexpected reply atyp {other}"),
    };
    let mut discard = vec![0u8; addr_len + 2];
    stream.read_exact(&mut discard).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT failed");
    stream
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

struct Topology {
    gateway_socks: SocketAddr,
}

async fn bring_up() -> Topology {
    let (exit_secret, exit_public) = key_pair(20);
    let (gateway_secret, gateway_public) = key_pair(10);
    let wg_port = free_udp_port();
    let socks_port = free_tcp_port();

    let _exit = spawn(&exit_config(wg_port, &exit_secret, &gateway_public));
    let _gateway = spawn(&gateway_config(
        socks_port,
        wg_port,
        &gateway_secret,
        &exit_public,
    ));
    let gateway_socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
    wait_for_listener(gateway_socks).await;
    // The WireGuard handshake is lazy: the first packet triggers it, and
    // `WgStack::connect` retries while the handshake completes. Give the
    // peer endpoints a moment to exist before the first dial.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Topology { gateway_socks }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "sandbox EPERM on unconnected UDP sendto(2), the production WG wire's syscall; run on a real host"]
async fn tcp_rides_the_gateway_to_exit_tunnel() {
    let topology = bring_up().await;
    let echo = tcp_echo().await;
    let mut client = tokio::time::timeout(
        Duration::from_secs(30),
        socks_connect(topology.gateway_socks, echo),
    )
    .await
    .expect("SOCKS connect through the tunnel timed out");
    client.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(15), client.read_exact(&mut back))
        .await
        .expect("tunnelled TCP got no answer")
        .unwrap();
    assert_eq!(&back, b"tcp:hello");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "sandbox EPERM on unconnected UDP sendto(2), the production WG wire's syscall; run on a real host"]
async fn udp_rides_the_gateway_to_exit_tunnel() {
    let topology = bring_up().await;
    let echo = udp_echo().await;

    let mut control = TcpStream::connect(topology.gateway_socks).await.unwrap();
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
        .send_to(&socks_udp_datagram(echo, b"ping"), relay)
        .await
        .unwrap();

    let exchange = async {
        let mut buffer = vec![0u8; 65_535];
        let (length, _) = client.recv_from(&mut buffer).await.unwrap();
        // RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2), then the payload.
        buffer[10..length].to_vec()
    };
    let answer = tokio::time::timeout(Duration::from_secs(30), exchange)
        .await
        .expect("tunnelled UDP got no answer");
    assert_eq!(answer, b"udp:ping");
    drop(control);
}
