//! Juicity server termination end to end.
//!
//! The client is the real runtime (SOCKS in, Juicity out); the server is the
//! real runtime with a Juicity inbound. Covers a TCP echo, a UDP echo, a
//! wrong-password rejection, and a malformed-authentication drop.
//!
//! QUIC runs on UDP, so these need a host where the sandbox lets datagrams
//! through (this repository's dev sandbox blocks UDP `sendto`):
//!   cargo test -p zero-runtime --test juicity_server -- --ignored

use std::net::{SocketAddr, TcpListener as StdListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "a-juicity-shared-password";
const SERVER_NAME: &str = "zray.test";

const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA_CERTIFICATE: &str = include_str!("fixtures/loopback-ca.pem");

fn free_tcp_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

async fn echo_service() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    address
}

async fn udp_echo_service() -> SocketAddr {
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

fn server_config(relay_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "juicity-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": "juicity",
            "settings": {"uuid": UUID, "password": PASSWORD},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificate": [CERTIFICATE],
                        "key": [PRIVATE_KEY],
                    }],
                },
            },
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    })
}

fn client_config(socks_port: u16, relay_port: u16, password: &str) -> Value {
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
            "tag": "proxy",
            "protocol": "juicity",
            "settings": {
                "address": SERVER_NAME,
                "port": relay_port,
                "uuid": UUID,
                "password": password,
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": SERVER_NAME,
                    "certificates": [{"usage": "verify", "certificate": [CA_CERTIFICATE]}],
                },
            },
        }],
        "dns": {"hosts": {SERVER_NAME: ["127.0.0.1"]}},
    })
}

struct Tunnel {
    socks: SocketAddr,
    echo: SocketAddr,
    udp_echo: SocketAddr,
}

async fn tunnel(password: &str) -> Tunnel {
    let echo = echo_service().await;
    let udp_echo = udp_echo_service().await;
    let relay_port = free_udp_port();
    let socks_port = free_tcp_port();
    spawn(server_config(relay_port)).await;
    let client = spawn(client_config(socks_port, relay_port, password)).await;
    drop(client);
    Tunnel {
        socks: SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
        udp_echo,
    }
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 only");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT failed");
    let mut discard = [0u8; 6];
    stream.read_exact(&mut discard).await?;
    Ok(stream)
}

#[ignore = "needs a host where UDP datagrams (QUIC) are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_server_echoes_tcp() {
    let tunnel = tunnel(PASSWORD).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo)
        .await
        .expect("SOCKS CONNECT through Juicity failed");
    let payload = b"hello over juicity";
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(echoed, payload);
}

#[ignore = "needs a host where UDP datagrams (QUIC) are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_server_echoes_udp() {
    let tunnel = tunnel(PASSWORD).await;
    let mut control = TcpStream::connect(tunnel.socks).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await.unwrap();
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE refused");
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::IpAddr::V4(ip) = tunnel.udp_echo.ip() else {
        panic!("IPv4 only");
    };
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01];
    datagram.extend_from_slice(&ip.octets());
    datagram.extend_from_slice(&tunnel.udp_echo.port().to_be_bytes());
    datagram.extend_from_slice(b"datagram over juicity");
    socket.send_to(&datagram, relay).await.unwrap();

    let mut received = vec![0u8; 65_535];
    let (read, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut received))
        .await
        .expect("UDP echo timed out")
        .unwrap();
    assert!(read > 10, "reply is too short to contain a payload");
    assert_eq!(&received[10..read], b"datagram over juicity");
    drop(control);
}

/// A client with the wrong password authenticates the QUIC connection but
/// fails the token check: the server drops it, so no echo ever comes back.
#[ignore = "needs a host where UDP datagrams (QUIC) are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_server_rejects_a_wrong_password() {
    let tunnel = tunnel("not-the-password").await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo)
        .await
        .expect("SOCKS handshake itself failed");
    stream.write_all(b"probe").await.unwrap();
    let mut echoed = [0u8; 5];
    let result =
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed)).await;
    assert!(
        matches!(result, Err(_) | Ok(Err(_))),
        "a wrong password must not produce an echo"
    );
}

/// A client that speaks garbage instead of the 50-byte authentication command
/// gets its connection dropped: the server answers nothing and closes.
#[ignore = "needs a host where UDP datagrams (QUIC) are not blocked by the sandbox"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_server_drops_a_malformed_authentication() {
    let relay_port = free_udp_port();
    let _server = spawn(server_config(relay_port)).await;

    let mut roots = rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(CA_CERTIFICATE.as_bytes());
    for certificate in
        rustls_pki_types::pem::PemObject::pem_reader_iter(&mut reader).filter_map(Result::ok)
    {
        let _ = roots.add(certificate);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC TLS client");
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(
            SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port),
            SERVER_NAME,
        )
        .expect("QUIC connect")
        .await
        .expect("QUIC handshake");
    let mut auth = connection.open_uni().await.expect("auth stream");
    auth.write_all(b"this is not a juicity auth command")
        .await
        .unwrap();
    auth.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(15), connection.closed())
        .await
        .expect("the server kept a client with malformed authentication");
    endpoint.close(0u32.into(), b"done");
}
