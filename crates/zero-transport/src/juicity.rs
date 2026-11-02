//! Juicity QUIC carrier (client side) and server termination.
//!
//! Juicity rides one authenticated QUIC connection per server, like TUIC, but
//! carries each proxied request on its own bidirectional stream rather than in
//! datagrams: a TCP request is a stream whose first bytes name the target, and
//! a UDP request is a stream that frames every datagram with its address. The
//! wire contract follows the MIT-licensed `daeuniverse/outbound` reference and
//! the `juicity` server:
//!
//! * **Authentication** is one unidirectional stream carrying a TUIC-style
//!   `Authenticate` command — `[VER=0][CMD=0][uuid(16)][token(32)]`, where the
//!   token is TLS exported keying material over the uuid and password. The
//!   server reads those 50 bytes once per connection and compares the token
//!   in constant time; finishing the stream after them is fine (the server
//!   treats it as a client with no full-cone underlay).
//! * A **TCP** stream opens with `[network=1][addr]` and then relays bytes,
//!   where `addr` is the trojan metadata `[type][host][port]`.
//! * A **UDP** stream opens with `[network=3][addr]` and then frames each
//!   datagram as `[addr][len(16-bit BE)][payload]`; responses use the same
//!   datagram framing, with no stream header.
//!
//! The runtime owns routing; this module only turns a QUIC connection into a
//! byte stream (`connect`) or one request/response datagram exchange
//! (`exchange_udp`) on the client side, and accepts authenticated connections
//! (`Acceptor`) on the server side.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::duplex;
use tokio::time::{timeout, Duration};
use zero_core::{boxed, BoxStream, Destination};

/// Juicity's command version. Both the version byte and the command byte of
/// the authentication command are zero (`Version0`, `AuthenticateType`).
const VERSION: u8 = 0;
const AUTHENTICATE: u8 = 0;
/// Trojan "network" selector that opens the stream: TCP relays bytes, UDP
/// frames datagrams.
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 3;
/// Longest trojan hostname the one-byte length field can describe.
const MAX_DOMAIN: usize = 255;
/// Bound on one UDP request/response exchange.
const UDP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
/// Client keep-alive and idle timeout, matching the reference dialer (5 s
/// keep-alive) and the QUIC carriers in this crate (60 s idle).
const CLIENT_KEEP_ALIVE: Duration = Duration::from_secs(5);
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Build a QUIC client endpoint and the TLS parameters to dial with. ALPN is
/// forced to `h3`, which is the only protocol a Juicity server offers.
fn tls_client_config(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
) -> Result<(h3_quinn::quinn::Endpoint, zero_security::TlsParams), String> {
    if addrs.is_empty() {
        return Err("Juicity has no resolved endpoint".into());
    }
    let mut tls = tls.clone();
    tls.alpn = vec![b"h3".to_vec()];
    let rustls = zero_security::try_client_config(&tls)
        .map_err(|error| format!("Juicity TLS configuration: {error}"))?;
    let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from((*rustls).clone())
        .map_err(|error| format!("Juicity TLS configuration: {error}"))?;
    let mut client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(crate::relay::quic_transport(
        CLIENT_IDLE_TIMEOUT,
        Some(CLIENT_KEEP_ALIVE),
    )));
    let bind: SocketAddr = if addrs[0].is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = crate::relay::protected_client_endpoint(bind)
        .map_err(|error| format!("Juicity endpoint: {error}"))?;
    endpoint.set_default_client_config(client_config);
    Ok((endpoint, tls))
}

async fn connect_quic(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
) -> Result<(h3_quinn::quinn::Endpoint, h3_quinn::quinn::Connection), String> {
    let (endpoint, tls) = tls_client_config(addrs, tls)?;
    let mut last_error = None;
    for address in addrs {
        match endpoint.connect(*address, &tls.server_name) {
            Ok(connecting) => match connecting.await {
                Ok(connection) => return Ok((endpoint, connection)),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(format!(
        "Juicity QUIC connect failed: {}",
        last_error.unwrap_or_else(|| "no candidate succeeded".into())
    ))
}

/// Send the one-shot authentication command on a fresh unidirectional stream.
///
/// The token is the same TLS exported keying material TUIC uses, so a Juicity
/// server (which recomputes it the same way) accepts a correct uuid/password
/// pair and nothing else. The stream is finished after the 50-byte command;
/// the full-cone underlay this client does not use would otherwise keep it
/// open.
async fn authenticate(
    connection: &h3_quinn::quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> Result<(), String> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|error| format!("Juicity key export: {error:?}"))?;
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| format!("Juicity auth stream: {error}"))?;
    let mut command = Vec::with_capacity(50);
    command.push(VERSION);
    command.push(AUTHENTICATE);
    command.extend_from_slice(uuid);
    command.extend_from_slice(&token);
    stream
        .write_all(&command)
        .await
        .map_err(|error| format!("Juicity auth write: {error}"))?;
    stream
        .finish()
        .map_err(|error| format!("Juicity auth finish: {error}"))?;
    Ok(())
}

/// Encode the trojan metadata `[type][host][port]` for a destination.
///
/// Address types follow trojan: IPv4 = 1 (4 bytes), domain = 3 (one length
/// byte then the name), IPv6 = 4 (16 bytes); the port is two big-endian bytes.
fn encode_address(destination: &Destination) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(1 + MAX_DOMAIN + 3);
    match &destination.address {
        zero_core::Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        zero_core::Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        zero_core::Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_DOMAIN {
                return Err("Juicity hostname is outside the one-byte length limit".into());
            }
            out.push(3);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

/// Read one trojan metadata address from a stream, returning it as a UDP
/// destination (the only caller is the UDP response reader).
async fn read_address(stream: &mut h3_quinn::quinn::RecvStream) -> Result<Destination, String> {
    let mut kind = [0u8; 1];
    stream
        .read_exact(&mut kind)
        .await
        .map_err(|error| format!("Juicity address type: {error}"))?;
    let address = match kind[0] {
        1 => {
            let mut bytes = [0u8; 4];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("Juicity IPv4 address: {error}"))?;
            zero_core::Address::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(bytes)))
        }
        3 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|error| format!("Juicity hostname length: {error}"))?;
            let mut bytes = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("Juicity hostname: {error}"))?;
            let host = std::str::from_utf8(&bytes)
                .map_err(|_| "Juicity hostname is not UTF-8".to_string())?;
            zero_core::Address::parse_host(host)
        }
        4 => {
            let mut bytes = [0u8; 16];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("Juicity IPv6 address: {error}"))?;
            zero_core::Address::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        other => return Err(format!("Juicity address type {other} is invalid")),
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|error| format!("Juicity port: {error}"))?;
    Ok(Destination::udp(address, u16::from_be_bytes(port)))
}

/// The pooled, authenticated connection to a Juicity server (see
/// [`crate::quic_pool`]). Authentication is a one-way command, sent once per
/// connection; every stream after it rides the same connection.
async fn pooled(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
) -> Result<(String, std::sync::Arc<crate::quic_pool::Pooled>), String> {
    let mut secret = uuid.to_vec();
    secret.extend_from_slice(password.as_bytes());
    let key = crate::quic_pool::key("juicity", addrs, tls, &secret);
    let pooled = crate::quic_pool::get(&key, || async {
        let (endpoint, connection) = connect_quic(addrs, tls).await?;
        authenticate(&connection, uuid, password).await?;
        Ok((endpoint, connection))
    })
    .await?;
    Ok((key, pooled))
}

/// Open a bidirectional stream on the pooled connection, dialling a fresh
/// connection once if the pooled one has died since it was last used.
async fn open_bi(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
) -> Result<
    (
        crate::quic_pool::StreamGuard,
        h3_quinn::quinn::SendStream,
        h3_quinn::quinn::RecvStream,
    ),
    String,
> {
    let mut opened = None;
    for attempt in 0..2 {
        let (key, pooled) = pooled(addrs, tls, uuid, password).await?;
        match pooled.connection.open_bi().await {
            Ok(pair) => {
                opened = Some((pooled.stream_guard(), pair));
                break;
            }
            Err(error) if attempt == 0 => {
                tracing::debug!(%error, "Juicity pooled connection is gone; dialling anew");
                crate::quic_pool::evict(&key, &pooled);
            }
            Err(error) => return Err(format!("Juicity stream: {error}")),
        }
    }
    let (guard, (send, recv)) = opened.ok_or("Juicity stream: no connection")?;
    Ok((guard, send, recv))
}

/// Open an authenticated Juicity TCP stream to `destination`.
pub async fn connect(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
    destination: &Destination,
) -> Result<BoxStream, String> {
    if destination.network != zero_core::Network::Tcp {
        return Err("Juicity stream connect requires a TCP destination".into());
    }
    let (guard, mut send, recv) = open_bi(addrs, tls, uuid, password).await?;
    // `[network=1][addr]`. The header goes out on its own, which both avoids
    // the deadlock where the target speaks first and matches the reference's
    // 100 ms "flush the header even with no payload" timer.
    let mut header = vec![NETWORK_TCP];
    header.extend_from_slice(&encode_address(destination)?);
    send.write_all(&header)
        .await
        .map_err(|error| format!("Juicity TCP header: {error}"))?;
    let (app, worker) = duplex(128 * 1024);
    tokio::spawn(async move {
        crate::relay::bridge_quic_stream(worker, send, recv, "Juicity").await;
        // The connection stays in the pool for the next stream.
        drop(guard);
    });
    Ok(boxed(app))
}

/// Exchange one Juicity UDP datagram and wait for the matching response.
///
/// A UDP stream opens with `[network=3][addr]`; each datagram on it is framed
/// `[addr][len(16-bit BE)][payload]`. For a single request/response the client
/// writes the stream header and one framed datagram, then reads one framed
/// response datagram (responses carry no stream header). The destination
/// returned is the address the server reports the response came from.
pub async fn exchange_udp(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
    destination: &Destination,
    payload: &[u8],
) -> Result<(Destination, Vec<u8>), String> {
    if destination.network != zero_core::Network::Udp {
        return Err("Juicity packet exchange requires a UDP destination".into());
    }
    if payload.len() > u16::MAX as usize {
        return Err("Juicity UDP payload is too large".into());
    }
    let address = encode_address(destination)?;
    // Stream header `[network=3][addr]`, then the datagram frame
    // `[addr][len][payload]`.
    let mut request = Vec::with_capacity(1 + address.len() * 2 + 2 + payload.len());
    request.push(NETWORK_UDP);
    request.extend_from_slice(&address);
    request.extend_from_slice(&address);
    request.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    request.extend_from_slice(payload);

    let (guard, mut send, mut recv) = open_bi(addrs, tls, uuid, password).await?;
    let exchange = async {
        send.write_all(&request)
            .await
            .map_err(|error| format!("Juicity UDP request: {error}"))?;
        let source = read_address(&mut recv).await?;
        let mut length = [0u8; 2];
        recv.read_exact(&mut length)
            .await
            .map_err(|error| format!("Juicity UDP length: {error}"))?;
        let length = u16::from_be_bytes(length) as usize;
        let mut response = vec![0u8; length];
        recv.read_exact(&mut response)
            .await
            .map_err(|error| format!("Juicity UDP payload: {error}"))?;
        Ok::<_, String>((source, response))
    };
    let result = timeout(UDP_EXCHANGE_TIMEOUT, exchange)
        .await
        .map_err(|_| "Juicity UDP response timed out".to_string())?;
    drop(guard);
    result
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Bound on the QUIC handshake plus the Juicity authentication of a
/// connection.
const SERVER_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on reading one request header once its stream is open.
const SERVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Accepted requests queued for the runtime.
const ACCEPT_QUEUE: usize = 64;
/// Largest command accepted on a unidirectional stream after authentication.
const MAX_UNI_COMMAND: usize = 64 * 1024;

/// One authenticated Juicity request, ready for the runtime to route.
pub enum Accepted {
    Tcp {
        stream: BoxStream,
        destination: Destination,
        peer: SocketAddr,
    },
    Udp {
        send: h3_quinn::quinn::SendStream,
        recv: h3_quinn::quinn::RecvStream,
        destination: Destination,
        /// The first datagram's payload; the stream stays open for more.
        payload: Vec<u8>,
        peer: SocketAddr,
    },
}

/// Accepts Juicity connections and yields every TCP/UDP request stream they
/// carry.
///
/// Each QUIC connection is handshaken, authenticated and served on its own
/// task; the acceptor itself only funnels finished requests to the runtime.
pub struct Acceptor {
    endpoint: h3_quinn::quinn::Endpoint,
    accepted: tokio::sync::mpsc::Receiver<Result<Accepted, String>>,
    sender: tokio::sync::mpsc::Sender<Result<Accepted, String>>,
}

impl Acceptor {
    pub fn new(endpoint: h3_quinn::quinn::Endpoint) -> Self {
        let (sender, accepted) = tokio::sync::mpsc::channel(ACCEPT_QUEUE);
        Self {
            endpoint,
            accepted,
            sender,
        }
    }

    /// Wait for the next TCP/UDP request. `Err` reports one rejected
    /// connection or request and is not fatal; `Ok(None)` means the endpoint
    /// closed. The credentials apply to connections accepted from this call
    /// on.
    pub async fn accept(
        &mut self,
        uuid: &[u8; 16],
        password: &str,
    ) -> Result<Option<Accepted>, String> {
        let credentials: Arc<([u8; 16], Box<str>)> = Arc::new((*uuid, password.into()));
        loop {
            tokio::select! {
                biased;
                item = self.accepted.recv() => {
                    return match item {
                        Some(item) => item.map(Some),
                        None => Ok(None),
                    };
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(None);
                    };
                    tokio::spawn(serve_connection(
                        incoming,
                        Arc::clone(&credentials),
                        self.sender.clone(),
                    ));
                }
            }
        }
    }
}

/// Compare two equal-length tokens without an early-exit branch, so a wrong
/// password costs the same time as a right one up to the comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn serve_connection(
    incoming: h3_quinn::quinn::Incoming,
    credentials: Arc<([u8; 16], Box<str>)>,
    out: tokio::sync::mpsc::Sender<Result<Accepted, String>>,
) {
    let authenticated = timeout(SERVER_AUTH_TIMEOUT, async {
        let connection = incoming
            .await
            .map_err(|error| format!("Juicity QUIC handshake: {error}"))?;
        authenticate_server(&connection, &credentials.0, &credentials.1).await?;
        Ok::<_, String>(connection)
    })
    .await
    .unwrap_or_else(|_| Err("Juicity handshake or authentication timed out".into()));
    let connection = match authenticated {
        Ok(connection) => connection,
        Err(error) => {
            let _ = out.send(Err(error)).await;
            return;
        }
    };
    let peer = connection.remote_address();
    loop {
        tokio::select! {
            result = connection.accept_bi() => {
                let Ok((send, recv)) = result else {
                    return;
                };
                let out = out.clone();
                tokio::spawn(async move {
                    let accepted =
                        timeout(SERVER_REQUEST_TIMEOUT, accept_request_stream(send, recv, peer))
                            .await
                            .unwrap_or_else(|_| Err("Juicity request header timed out".into()));
                    let _ = out.send(accepted).await;
                });
            }
            result = connection.accept_uni() => {
                let Ok(mut stream) = result else {
                    return;
                };
                // Juicity defines no post-authentication uni-stream commands;
                // still consume them, or the client's stream credit runs out.
                tokio::spawn(async move {
                    let _ = timeout(SERVER_REQUEST_TIMEOUT, stream.read_to_end(MAX_UNI_COMMAND)).await;
                });
            }
            () = out.closed() => {
                connection.close(0u32.into(), b"server stopped");
                return;
            }
        }
    }
}

/// Verify one authentication command: `[VER=0][CMD=0][uuid(16)][token(32)]`
/// with the token recomputed from this connection's TLS keying material.
/// Anything wrong drops the connection without an answer.
async fn authenticate_server(
    connection: &h3_quinn::quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> Result<(), String> {
    let mut expected = [0u8; 32];
    connection
        .export_keying_material(&mut expected, uuid, password.as_bytes())
        .map_err(|error| format!("Juicity key export: {error:?}"))?;
    let mut stream = connection
        .accept_uni()
        .await
        .map_err(|error| format!("Juicity auth accept: {error}"))?;
    let mut command = [0u8; 50];
    stream
        .read_exact(&mut command)
        .await
        .map_err(|error| format!("Juicity auth command: {error}"))?;
    if command[0] != VERSION || command[1] != AUTHENTICATE {
        return Err("Juicity authentication command is invalid".into());
    }
    if command[2..18] != uuid[..] {
        return Err("Juicity UUID authentication failed".into());
    }
    if !constant_time_eq(&command[18..50], &expected) {
        return Err("Juicity token authentication failed".into());
    }
    Ok(())
}

/// Read one request header from a freshly accepted bidirectional stream.
async fn accept_request_stream(
    send: h3_quinn::quinn::SendStream,
    mut recv: h3_quinn::quinn::RecvStream,
    peer: SocketAddr,
) -> Result<Accepted, String> {
    let mut network = [0u8; 1];
    recv.read_exact(&mut network)
        .await
        .map_err(|error| format!("Juicity network selector: {error}"))?;
    match network[0] {
        NETWORK_TCP => {
            let mut destination = read_address(&mut recv).await?;
            destination.network = zero_core::Network::Tcp;
            let (app, worker) = duplex(128 * 1024);
            // Other requests share this connection; the bridge must not
            // close it.
            tokio::spawn(crate::relay::bridge_quic_stream(
                worker,
                send,
                recv,
                "Juicity server",
            ));
            Ok(Accepted::Tcp {
                stream: boxed(app),
                destination,
                peer,
            })
        }
        NETWORK_UDP => {
            let destination = read_address(&mut recv).await?;
            // The stream header names the target; each datagram repeats its
            // address as part of the framing and is consumed here.
            let (_, payload) = read_udp_datagram(&mut recv).await?;
            Ok(Accepted::Udp {
                send,
                recv,
                destination,
                payload,
                peer,
            })
        }
        other => Err(format!("Juicity network selector {other} is invalid")),
    }
}

/// Read one UDP datagram frame `[addr][len(16-bit BE)][payload]` from a UDP
/// request stream.
pub async fn read_udp_datagram(
    recv: &mut h3_quinn::quinn::RecvStream,
) -> Result<(Destination, Vec<u8>), String> {
    let source = read_address(recv).await?;
    let mut length = [0u8; 2];
    recv.read_exact(&mut length)
        .await
        .map_err(|error| format!("Juicity UDP length: {error}"))?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0u8; length];
    recv.read_exact(&mut payload)
        .await
        .map_err(|error| format!("Juicity UDP payload: {error}"))?;
    Ok((source, payload))
}

/// Encode one UDP datagram frame `[addr][len(16-bit BE)][payload]` for a
/// response on a UDP request stream.
pub fn encode_udp_datagram(destination: &Destination, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err("Juicity UDP payload is too large".into());
    }
    let address = encode_address(destination)?;
    let mut frame = Vec::with_capacity(address.len() + 2 + payload.len());
    frame.extend_from_slice(&address);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_framing_matches_trojan_layout() {
        let v4 = encode_address(&Destination::tcp(
            zero_core::Address::Ip("192.0.2.1".parse().unwrap()),
            443,
        ))
        .unwrap();
        assert_eq!(v4, vec![1, 192, 0, 2, 1, 0x01, 0xbb]);

        let domain =
            encode_address(&Destination::tcp(zero_core::Address::domain("ex.com"), 80)).unwrap();
        assert_eq!(
            domain,
            vec![3, 6, b'e', b'x', b'.', b'c', b'o', b'm', 0x00, 0x50]
        );

        let v6 = encode_address(&Destination::udp(
            zero_core::Address::Ip("2001:db8::1".parse().unwrap()),
            53,
        ))
        .unwrap();
        assert_eq!(v6[0], 4);
        assert_eq!(v6.len(), 1 + 16 + 2);
        assert_eq!(&v6[17..], &[0x00, 0x35]);
    }

    #[test]
    fn hostname_over_the_length_limit_is_rejected() {
        let long = "a".repeat(256);
        let destination = Destination::tcp(zero_core::Address::domain(long), 443);
        assert!(encode_address(&destination).is_err());
    }

    #[test]
    fn udp_datagram_framing_roundtrips() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let frame = encode_udp_datagram(&destination, b"query").unwrap();
        // [addr][len BE16][payload]: the address is the trojan metadata.
        assert_eq!(&frame[..2], &[3, 11]);
        let len_at = frame.len() - 7;
        assert_eq!(&frame[len_at..len_at + 2], &[0x00, 0x05]);
        assert_eq!(&frame[len_at + 2..], b"query");
    }

    #[test]
    fn udp_datagram_framing_rejects_an_oversize_payload() {
        let destination =
            Destination::udp(zero_core::Address::Ip("192.0.2.1".parse().unwrap()), 53);
        assert!(encode_udp_datagram(&destination, &vec![0u8; 65_536]).is_err());
    }

    #[test]
    fn token_comparison_is_exact_over_all_32_bytes() {
        let a = [0xabu8; 32];
        let mut b = [0xabu8; 32];
        assert!(constant_time_eq(&a, &b));
        for i in 0..32 {
            b[i] ^= 0x01;
            assert!(!constant_time_eq(&a, &b), "byte {i} must matter");
            b[i] ^= 0x01;
        }
        assert!(!constant_time_eq(&a[..31], &a));
    }
}
