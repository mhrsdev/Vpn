//! Fallback transport proof: VLESS+TLS client → VLESS+TLS server → freedom.
//!
//! The Iran→USA link runs DUAL ALWAYS-ON: WireGuard (primary, UDP) + a
//! TLS-based fallback (TCP). This test proves the fallback transport carries
//! real payload end to end, the same bar the R7 `wg_datapath` test sets for
//! the primary. If this path does not work, the hot-standby design is built
//! on a transport that cannot carry traffic.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
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

fn spawn(config: Value) -> Arc<zero_runtime::Server> {
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
    server
}

async fn wait_until_listening(server: &Arc<zero_runtime::Server>) {
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .expect("server never reported its listeners bound");
}

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

async fn works_through(socks: SocketAddr, target: SocketAddr) -> bool {
    let attempt = async {
        let mut stream = TcpStream::connect(socks).await.ok()?;
        stream.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.ok()?;
        let std::net::IpAddr::V4(ip) = target.ip() else {
            return None;
        };
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&request).await.ok()?;
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.ok()?;
        if reply[1] != 0 {
            return None;
        }
        stream.write_all(b"ping").await.ok()?;
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.ok()?;
        (&echoed == b"ping").then_some(())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(15), attempt).await,
        Ok(Some(()))
    )
}

/// The fallback transport (VLESS+TLS) carries payload end to end:
/// gateway SOCKS → VLESS+TLS client → exit VLESS+TLS server → freedom → echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_tls_fallback_carries_payload() {
    let echo = echo_service().await;
    let relay_port = free_tcp_port();
    // The "USA exit": VLESS+TLS inbound, freedom egress.
    let exit = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": "vless",
            "settings": {"clients": [{"id": UUID}]},
            "streamSettings": {
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
    }));
    wait_until_listening(&exit).await;

    // The "Iran gateway": SOCKS inbound, VLESS+TLS client outbound (the
    // tls-tunnel fallback transport).
    let socks_port = free_tcp_port();
    let gateway = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": false},
        }],
        "outbounds": [{
            "tag": "tls-tunnel",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1",
                "port": relay_port,
                "users": [{"id": UUID, "encryption": "none"}],
            }]},
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
    }));
    wait_until_listening(&gateway).await;

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    assert!(
        works_through(socks, echo).await,
        "the VLESS+TLS fallback transport did not carry payload end to end"
    );
}
