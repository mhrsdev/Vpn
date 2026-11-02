//! A WireGuard server: the responder side of the protocol, for the
//! `wireguard` inbound.
//!
//! It owns one UDP socket and one `boringtun` tunnel per configured peer, and
//! shows the rest of the program a plain IP-packet link:
//!
//! * [`WgLink::from_peers`] yields the packets peers sent, already decrypted;
//! * [`WgLink::to_peers`] takes packets to send, and finds the peer that
//!   should get each one.
//!
//! How packets find their peer (WireGuard's "cryptokey routing"):
//!
//! * **Inbound:** a handshake names its peer by its static key, which is
//!   readable once the message is parsed with our private key. Every later
//!   message carries the receiver index we gave out, whose high bits are the
//!   peer's number here.
//! * **Decrypted packets** are accepted only when their source address is in
//!   that peer's `allowed` list. Without this a peer could pose as any other.
//! * **Outbound:** the peer whose `allowed` list holds the packet's
//!   destination wins, the longest prefix first. A peer that has not yet
//!   spoken has no endpoint to send to, and a packet for it is dropped:
//!   a server cannot start a conversation with a client it has never heard.
//!
//! The one task owns every tunnel, so no tunnel is locked. Trade-off: all
//! peers share that task's time; one core carries a few hundred Mbit/s of
//! ChaCha20, which is what a proxy inbound needs.
//!
//! Not done: cookie-based load shedding for handshake floods beyond what
//! `boringtun` does for each peer's own tunnel.
//!
//! ## AmneziaWG server mode
//!
//! [`serve_amnezia`] starts the same server with the AmneziaWG 2.x
//! obfuscation layer wrapped around it (the `amnezia-wireguard` inbound):
//! every datagram is de-obfuscated with the peer's [`AmneziaParams`] before
//! it reaches `boringtun`, and every reply is re-obfuscated before it goes
//! back on the wire. Random junk datagrams fail the de-obfuscation and are
//! silently discarded without ever touching the authenticated tunnel engine.
//!
//! A single UDP port serves either plain WireGuard or AmneziaWG peers, never
//! both: an obfuscated handshake could otherwise be misclassified, so the
//! two inbounds are separate by construction and the obfuscation parameters
//! are configured per peer out of band (AmneziaWG negotiates nothing
//! in-band).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{handshake::parse_handshake_anon, Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::SeedableRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::amnezia::{decode_packet, encode_packet, AmneziaParams};

/// How often each tunnel's timers (keepalives, rekeys) are driven.
const TICK: Duration = Duration::from_millis(250);
/// Largest datagram or IP packet handled.
const MAX_PACKET: usize = 65_535;
/// Packets queued between the socket task and its user, each way.
const QUEUE: usize = 1024;

/// One peer the server accepts.
#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Source addresses this peer may use, and destinations sent to it, as
    /// `(network, prefix length)`.
    pub allowed: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
}

/// One peer the AmneziaWG server accepts: a [`PeerSpec`] plus the
/// obfuscation parameters the peer was configured with out of band.
#[derive(Debug, Clone)]
pub struct AmneziaPeerSpec {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Source addresses this peer may use, and destinations sent to it, as
    /// `(network, prefix length)`.
    pub allowed: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
    /// The obfuscation parameters for this peer. AmneziaWG negotiates
    /// nothing in-band, so both sides must be configured with the same
    /// values; a datagram that does not de-obfuscate with these parameters
    /// is discarded as junk or noise.
    pub amnezia: AmneziaParams,
}

/// The packet side of a running server.
pub struct WgLink {
    /// Decrypted IP packets from peers.
    pub from_peers: mpsc::Receiver<Vec<u8>>,
    /// IP packets to encrypt and send to whichever peer owns the destination.
    pub to_peers: mpsc::Sender<Vec<u8>>,
    /// The task that drives the socket; aborting it stops the server.
    pub task: tokio::task::JoinHandle<()>,
}

struct Peer {
    tunn: Tunn,
    public_key: [u8; 32],
    allowed: Vec<(IpAddr, u8)>,
    /// Where this peer's last authenticated packet came from.
    endpoint: Option<SocketAddr>,
    /// Set on every peer when the server runs in AmneziaWG mode
    /// ([`serve_amnezia`]); `None` for plain WireGuard.
    amnezia: Option<AmneziaParams>,
}

fn in_prefix(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
        let whole = usize::from(prefix / 8);
        let rest = prefix % 8;
        a[..whole] == b[..whole] && (rest == 0 || (a[whole] ^ b[whole]) >> (8 - rest) == 0)
    }
    match (network, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            prefix <= 32 && bits_match(&n.octets(), &i.octets(), prefix)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            prefix <= 128 && bits_match(&n.octets(), &i.octets(), prefix)
        }
        _ => false,
    }
}

impl Peer {
    /// The longest prefix of this peer's list that holds `ip`, if any.
    fn prefix_for(&self, ip: IpAddr) -> Option<u8> {
        self.allowed
            .iter()
            .filter(|(network, prefix)| in_prefix(*network, *prefix, ip))
            .map(|(_, prefix)| *prefix)
            .max()
    }
}

struct Server {
    socket: Arc<UdpSocket>,
    secret: StaticSecret,
    public: PublicKey,
    peers: Vec<Peer>,
    buffer: Vec<u8>,
    /// Whether this server de-obfuscates inbound datagrams and obfuscates
    /// outbound ones (the AmneziaWG mode); false for plain WireGuard.
    obfuscated: bool,
    /// Randomness for the obfuscation layer's padding and header choices.
    /// Unused in plain mode.
    rng: rand::rngs::StdRng,
}

impl Server {
    /// Datagrams to put on the wire and IP packets for the user, gathered
    /// while a tunnel's result is unwrapped so no borrow outlives it.
    fn unwrap_result(
        result: TunnResult<'_>,
        wire: &mut Vec<Vec<u8>>,
        packets: &mut Vec<(Vec<u8>, IpAddr)>,
    ) -> bool {
        match result {
            TunnResult::WriteToNetwork(datagram) => {
                wire.push(datagram.to_vec());
                true
            }
            TunnResult::WriteToTunnelV4(packet, source) => {
                packets.push((packet.to_vec(), IpAddr::V4(source)));
                false
            }
            TunnResult::WriteToTunnelV6(packet, source) => {
                packets.push((packet.to_vec(), IpAddr::V6(source)));
                false
            }
            TunnResult::Done | TunnResult::Err(_) => false,
        }
    }

    /// Which peer a datagram belongs to, or `None` for anything unknown.
    fn peer_of(&self, datagram: &[u8]) -> Option<usize> {
        let index = match Tunn::parse_incoming_packet(datagram).ok()? {
            Packet::HandshakeInit(init) => {
                let half = parse_handshake_anon(&self.secret, &self.public, &init).ok()?;
                return self
                    .peers
                    .iter()
                    .position(|peer| peer.public_key == half.peer_static_public);
            }
            Packet::HandshakeResponse(response) => response.receiver_idx,
            Packet::PacketCookieReply(reply) => reply.receiver_idx,
            Packet::PacketData(data) => data.receiver_idx,
        };
        let peer = (index >> 8) as usize;
        (peer < self.peers.len()).then_some(peer)
    }

    async fn on_datagram(
        &mut self,
        length: usize,
        from: SocketAddr,
        to_user: &mpsc::Sender<Vec<u8>>,
    ) {
        if self.obfuscated {
            self.on_datagram_obfuscated(length, from, to_user).await;
        } else {
            let datagram = self.buffer[..length].to_vec();
            let Some(index) = self.peer_of(&datagram) else {
                return;
            };
            let wire = self.drive(index, from, &datagram, to_user).await;
            for datagram in wire {
                let _ = self.socket.send_to(&datagram, from).await;
            }
        }
    }

    /// Feed one plain WireGuard datagram into a peer's tunnel and collect
    /// the plain reply datagrams the tunnel wants on the wire. Decrypted IP
    /// packets go to the user as they arrive.
    async fn drive(
        &mut self,
        index: usize,
        from: SocketAddr,
        datagram: &[u8],
        to_user: &mpsc::Sender<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let mut wire = Vec::new();
        let mut packets = Vec::new();
        let mut scratch = vec![0u8; MAX_PACKET];
        let peer = &mut self.peers[index];
        let mut again = Self::unwrap_result(
            peer.tunn
                .decapsulate(Some(from.ip()), datagram, &mut scratch),
            &mut wire,
            &mut packets,
        );
        // After a reply is written, the tunnel may hold more to say (queued
        // packets, a keepalive): asking with no datagram drains it.
        while again {
            again = Self::unwrap_result(
                peer.tunn.decapsulate(None, &[], &mut scratch),
                &mut wire,
                &mut packets,
            );
        }
        // Anything that decrypted or answered came from the peer holding the
        // key, so this is where it is now (WireGuard roams the same way).
        if !wire.is_empty() || !packets.is_empty() {
            peer.endpoint = Some(from);
        }
        for (packet, source) in packets {
            if peer.prefix_for(source).is_some() {
                let _ = to_user.send(packet).await;
            }
        }
        wire
    }

    /// AmneziaWG receive path: each datagram is tried against every peer's
    /// obfuscation parameters. Junk datagrams — and anything else that does
    /// not de-obfuscate — are silently discarded without reaching the
    /// authenticated tunnel engine.
    async fn on_datagram_obfuscated(
        &mut self,
        length: usize,
        from: SocketAddr,
        to_user: &mpsc::Sender<Vec<u8>>,
    ) {
        let raw = self.buffer[..length].to_vec();
        let mut decoded = Vec::with_capacity(raw.len());
        let Some((index, offset)) = self.peer_of_obfuscated(&raw, &mut decoded) else {
            return;
        };
        let wire = self.drive(index, from, &decoded[offset..], to_user).await;
        for datagram in wire {
            self.send_wire(index, &datagram, from).await;
        }
    }

    /// Try each peer's obfuscation parameters against a raw wire datagram.
    /// On success the plain packet is left in `decoded` and the peer index
    /// plus the offset where the packet begins are returned. The packet's
    /// own identity (static key or receiver index) is cross-checked against
    /// the peer whose parameters decoded it; any disagreement fails closed.
    fn peer_of_obfuscated(&self, datagram: &[u8], decoded: &mut Vec<u8>) -> Option<(usize, usize)> {
        for (index, peer) in self.peers.iter().enumerate() {
            let Some(params) = peer.amnezia else {
                continue;
            };
            decoded.clear();
            decoded.extend_from_slice(datagram);
            let Ok(Some(offset)) = decode_packet(params, decoded) else {
                continue;
            };
            let Some(identified) = self.peer_of(&decoded[offset..]) else {
                continue;
            };
            if identified == index {
                return Some((index, offset));
            }
        }
        None
    }

    /// Send one tunnel-produced datagram to a peer, obfuscating it first in
    /// AmneziaWG mode. The parameters were validated when the server
    /// started, so an encoding failure here drops the datagram rather than
    /// panicking the server task.
    async fn send_wire(&mut self, index: usize, datagram: &[u8], to: SocketAddr) {
        let params = self.peers[index].amnezia;
        let socket = Arc::clone(&self.socket);
        match params {
            Some(params) => {
                if let Ok(encoded) = encode_packet(params, datagram, &mut self.rng) {
                    let _ = socket.send_to(&encoded, to).await;
                }
            }
            None => {
                let _ = socket.send_to(datagram, to).await;
            }
        }
    }

    async fn on_packet(&mut self, packet: &[u8]) {
        let Some(destination) = Tunn::dst_address(packet) else {
            return;
        };
        let Some(index) = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| Some((index, peer.prefix_for(destination)?)))
            .max_by_key(|(_, prefix)| *prefix)
            .map(|(index, _)| index)
        else {
            return;
        };
        let Some(endpoint) = self.peers[index].endpoint else {
            return;
        };
        let mut wire = Vec::new();
        let mut packets = Vec::new();
        let mut scratch = vec![0u8; packet.len() + 256];
        Self::unwrap_result(
            self.peers[index].tunn.encapsulate(packet, &mut scratch),
            &mut wire,
            &mut packets,
        );
        for datagram in wire {
            self.send_wire(index, &datagram, endpoint).await;
        }
    }

    async fn on_tick(&mut self) {
        let mut scratch = vec![0u8; 256];
        // Drive timers first and send afterwards: `send_wire` needs `&mut
        // self`, which the peer borrow below cannot overlap.
        let mut pending: Vec<(usize, SocketAddr, Vec<Vec<u8>>)> = Vec::new();
        for (index, peer) in self.peers.iter_mut().enumerate() {
            let Some(endpoint) = peer.endpoint else {
                continue;
            };
            let mut wire = Vec::new();
            let mut packets = Vec::new();
            Self::unwrap_result(
                peer.tunn.update_timers(&mut scratch),
                &mut wire,
                &mut packets,
            );
            if !wire.is_empty() {
                pending.push((index, endpoint, wire));
            }
        }
        for (index, endpoint, wire) in pending {
            for datagram in wire {
                self.send_wire(index, &datagram, endpoint).await;
            }
        }
    }
}

/// Start serving on `socket` for `peers` (at most 2^23, far more than a
/// config will hold), answering with `secret_key`.
pub fn serve(socket: Arc<UdpSocket>, secret_key: [u8; 32], peers: Vec<PeerSpec>) -> WgLink {
    let amnezia = peers.iter().map(|_| None).collect();
    serve_inner(socket, secret_key, peers, amnezia, false)
}

/// Start serving with the AmneziaWG 2.x obfuscation layer: every datagram
/// is de-obfuscated with the peer's parameters before it reaches the
/// WireGuard engine, and every reply is obfuscated before it goes back on
/// the wire. Random junk datagrams are silently discarded.
///
/// A port serves either plain WireGuard ([`serve`]) or AmneziaWG peers,
/// never both; run a separate socket for each.
///
/// Panics when any peer's obfuscation parameters fail [`AmneziaParams::validate`]:
/// a misconfigured obfuscation layer must refuse to start, not run half-open.
pub fn serve_amnezia(
    socket: Arc<UdpSocket>,
    secret_key: [u8; 32],
    peers: Vec<AmneziaPeerSpec>,
) -> WgLink {
    for spec in &peers {
        spec.amnezia
            .validate()
            .expect("AmneziaWG peer parameters must validate");
    }
    let plain: Vec<PeerSpec> = peers
        .iter()
        .map(|spec| PeerSpec {
            public_key: spec.public_key,
            preshared_key: spec.preshared_key,
            allowed: spec.allowed.clone(),
            keepalive: spec.keepalive,
        })
        .collect();
    let amnezia: Vec<Option<AmneziaParams>> = peers.iter().map(|spec| Some(spec.amnezia)).collect();
    serve_inner(socket, secret_key, plain, amnezia, true)
}

fn serve_inner(
    socket: Arc<UdpSocket>,
    secret_key: [u8; 32],
    peers: Vec<PeerSpec>,
    amnezia: Vec<Option<AmneziaParams>>,
    obfuscated: bool,
) -> WgLink {
    let secret = StaticSecret::from(secret_key);
    let public = PublicKey::from(&secret);
    let peers: Vec<Peer> = peers
        .into_iter()
        .zip(amnezia)
        .enumerate()
        .map(|(index, (spec, amnezia))| Peer {
            tunn: Tunn::new(
                secret.clone(),
                PublicKey::from(spec.public_key),
                spec.preshared_key,
                spec.keepalive,
                index as u32,
                None,
            ),
            public_key: spec.public_key,
            allowed: spec.allowed,
            endpoint: None,
            amnezia,
        })
        .collect();
    let (to_user, from_peers) = mpsc::channel(QUEUE);
    let (to_peers, mut from_user) = mpsc::channel::<Vec<u8>>(QUEUE);
    let mut server = Server {
        socket,
        secret,
        public,
        peers,
        buffer: vec![0u8; MAX_PACKET],
        obfuscated,
        rng: rand::rngs::StdRng::from_entropy(),
    };
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK);
        let receiving = Arc::clone(&server.socket);
        loop {
            // The receive buffer is a field, so reading into it needs the
            // socket cloned out first: the borrow would otherwise span the
            // `&mut self` calls below.
            let mut buffer = std::mem::take(&mut server.buffer);
            tokio::select! {
                received = receiving.recv_from(&mut buffer) => {
                    server.buffer = buffer;
                    match received {
                        Ok((length, from)) => server.on_datagram(length, from, &to_user).await,
                        // A connection-reset notice for an earlier send: the
                        // socket is fine.
                        Err(error) if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                        ) => {}
                        Err(_) => return,
                    }
                }
                packet = from_user.recv() => {
                    server.buffer = buffer;
                    match packet {
                        Some(packet) => server.on_packet(&packet).await,
                        None => return,
                    }
                }
                _ = ticker.tick() => {
                    server.buffer = buffer;
                    server.on_tick().await;
                }
            }
        }
    });
    WgLink {
        from_peers,
        to_peers,
        task,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amnezia::{junk_packets, HeaderRange, RangeU16};

    /// Obfuscation parameters for the loopback tests: junk enabled, fixed
    /// (deterministic) headers and padding, header magic values far from
    /// the standard WireGuard type words so the obfuscation is really
    /// exercised.
    fn test_params() -> AmneziaParams {
        AmneziaParams {
            junk_count: 3,
            junk_size: RangeU16::fixed(64),
            init_padding: RangeU16::fixed(16),
            response_padding: RangeU16::fixed(16),
            cookie_padding: RangeU16::fixed(16),
            transport_padding: RangeU16::fixed(16),
            init_header: HeaderRange::fixed(0x1111_1111),
            response_header: HeaderRange::fixed(0x2222_2222),
            cookie_header: HeaderRange::fixed(0x3333_3333),
            transport_header: HeaderRange::fixed(0x4444_4444),
        }
    }

    struct Loopback {
        params: AmneziaParams,
        server_addr: SocketAddr,
        client: UdpSocket,
        tunn: Tunn,
        rng: rand::rngs::StdRng,
        link: WgLink,
    }

    impl Loopback {
        async fn start() -> Self {
            Self::start_on("127.0.0.1".parse().unwrap()).await
        }

        /// Bind both ends to `bind_ip` (127.0.0.1 or ::1) for the
        /// protocol x IP-family compatibility matrix.
        async fn start_on(bind_ip: std::net::IpAddr) -> Self {
            let params = test_params();
            let server_sk = [0x10u8; 32];
            let client_sk = [0x20u8; 32];
            let server_pk: [u8; 32] = PublicKey::from(&StaticSecret::from(server_sk)).to_bytes();
            let client_pk: [u8; 32] = PublicKey::from(&StaticSecret::from(client_sk)).to_bytes();

            let socket = UdpSocket::bind((bind_ip, 0)).await.unwrap();
            let client = UdpSocket::bind((bind_ip, 0)).await.unwrap();
            // Test-environment workaround: this sandbox rejects `sendto`
            // on unconnected UDP sockets (EPERM) while `send` on a
            // connected socket works. Connecting both ends keeps the
            // loopback functional; the production server keeps using
            // `send_to` for its multi-peer socket.
            socket.connect(client.local_addr().unwrap()).await.unwrap();
            let server_addr = socket.local_addr().unwrap();
            client.connect(server_addr).await.unwrap();
            let link = serve_amnezia(
                Arc::new(socket),
                server_sk,
                vec![AmneziaPeerSpec {
                    public_key: client_pk,
                    preshared_key: None,
                    allowed: vec![("10.8.0.2".parse().unwrap(), 32)],
                    keepalive: None,
                    amnezia: params,
                }],
            );

            let tunn = Tunn::new(
                StaticSecret::from(client_sk),
                PublicKey::from(server_pk),
                None,
                None,
                0,
                None,
            );
            Self {
                params,
                server_addr,
                client,
                tunn,
                rng: rand::rngs::StdRng::from_entropy(),
                link,
            }
        }

        /// Send one obfuscated datagram to the server.
        async fn send_obfuscated(&mut self, packet: &[u8]) {
            let encoded = encode_packet(self.params, packet, &mut self.rng).unwrap();
            self.client.send(&encoded).await.unwrap();
        }

        /// Receive one datagram from the server and de-obfuscate it,
        /// returning the plain WireGuard packet.
        async fn recv_plain(&mut self) -> Vec<u8> {
            let mut buf = vec![0u8; 2048];
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(2), self.client.recv_from(&mut buf))
                    .await
                    .expect("server answered")
                    .unwrap();
            assert_eq!(from, self.server_addr, "reply comes from the server");
            let offset = decode_packet(self.params, &mut buf[..n])
                .unwrap()
                .expect("server reply de-obfuscates");
            buf[offset..n].to_vec()
        }

        /// Drive the handshake to completion, then return.
        async fn handshake(&mut self) {
            let mut init = vec![0u8; 2048];
            let init_len = match self.tunn.format_handshake_initiation(&mut init, false) {
                TunnResult::WriteToNetwork(d) => d.len(),
                other => panic!("handshake initiation: {other:?}"),
            };
            self.send_obfuscated(&init[..init_len]).await;

            let mut out = vec![0u8; 2048];
            // The initiator's handshake completes when the response is
            // processed. boringtun may emit the first (empty) transport
            // packet straight away; that is not another handshake round.
            for _ in 0..4 {
                let plain = self.recv_plain().await;
                match self.tunn.decapsulate(None, &plain, &mut out) {
                    TunnResult::Done => break,
                    TunnResult::WriteToNetwork(d) => {
                        let is_transport = d.first() == Some(&4);
                        let reply = d.to_vec();
                        self.send_obfuscated(&reply).await;
                        if is_transport {
                            break;
                        }
                    }
                    other => panic!("handshake stalled: {other:?}"),
                }
            }
        }
    }

    fn ipv4_packet(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut packet = vec![0u8; 20 + payload.len()];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 0x11;
        packet[12..16].copy_from_slice(&src.parse::<std::net::Ipv4Addr>().unwrap().octets());
        packet[16..20].copy_from_slice(&dst.parse::<std::net::Ipv4Addr>().unwrap().octets());
        packet[20..].copy_from_slice(payload);
        let mut sum = 0u32;
        for word in packet[..20].chunks_exact(2) {
            sum += u16::from_be_bytes([word[0], word[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        packet
    }

    #[tokio::test]
    async fn amnezia_loopback_handshake_with_junk_enabled() {
        let mut lb = Loopback::start().await;

        // Junk datagrams go first: the server must silently discard them —
        // no answer, nothing delivered to the packet link.
        for junk in junk_packets(lb.params, &mut lb.rng).unwrap() {
            lb.client.send(&junk).await.unwrap();
        }
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), lb.client.recv(&mut buf))
                .await
                .is_err(),
            "junk must get no answer"
        );

        // The obfuscated handshake completes.
        lb.handshake().await;

        // And transport data round-trips through the obfuscation layer.
        let packet = ipv4_packet("10.8.0.2", "10.8.0.1", b"hello amnezia");
        let mut enc = vec![0u8; 2048];
        let data_len = match lb.tunn.encapsulate(&packet, &mut enc) {
            TunnResult::WriteToNetwork(d) => d.len(),
            other => panic!("encapsulate: {other:?}"),
        };
        lb.send_obfuscated(&enc[..data_len]).await;
        let got = tokio::time::timeout(Duration::from_secs(2), lb.link.from_peers.recv())
            .await
            .expect("server delivers the packet")
            .unwrap();
        assert_eq!(got, packet);

        // The server's reply path is obfuscated too: ask for a packet back
        // through `to_peers` and check it de-obfuscates to a transport
        // data packet.
        let back = ipv4_packet("10.8.0.1", "10.8.0.2", b"hello client");
        lb.link.to_peers.send(back.clone()).await.unwrap();
        let plain = lb.recv_plain().await;
        let mut out = vec![0u8; 2048];
        match lb.tunn.decapsulate(None, &plain, &mut out) {
            TunnResult::WriteToTunnelV4(data, _src) => assert_eq!(data, back.as_slice()),
            other => panic!("expected transport data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn amnezia_wrong_params_are_silently_rejected() {
        let mut lb = Loopback::start().await;
        // Same keys, but the peer was configured with different obfuscation
        // parameters: the server must not be able to de-obfuscate, so the
        // handshake initiation is discarded before the tunnel engine.
        let wrong = AmneziaParams {
            init_header: HeaderRange::fixed(0x9999_9999),
            ..lb.params
        };
        let mut init = vec![0u8; 2048];
        let init_len = match lb.tunn.format_handshake_initiation(&mut init, false) {
            TunnResult::WriteToNetwork(d) => d.len(),
            other => panic!("handshake initiation: {other:?}"),
        };
        let encoded = encode_packet(wrong, &init[..init_len], &mut lb.rng).unwrap();
        lb.client.send(&encoded).await.unwrap();

        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), lb.client.recv(&mut buf))
                .await
                .is_err(),
            "wrong params must get no answer"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), lb.link.from_peers.recv())
                .await
                .is_err(),
            "wrong params must deliver nothing"
        );
    }

    /// Protocol x IP-family matrix for AmneziaWG: the obfuscated handshake
    /// must complete over real IPv4 AND real IPv6 UDP loopback, with junk
    /// enabled, independently per family.
    #[tokio::test]
    async fn amnezia_family_matrix_ipv4_and_ipv6() {
        for (family_name, bind_ip) in [
            ("ipv4", "127.0.0.1".parse().unwrap()),
            ("ipv6", "::1".parse().unwrap()),
        ] {
            let mut lb = Loopback::start_on(bind_ip).await;

            // Junk is silently discarded on this family too.
            for junk in junk_packets(lb.params, &mut lb.rng).unwrap() {
                lb.client.send(&junk).await.unwrap();
            }
            let mut buf = vec![0u8; 2048];
            assert!(
                tokio::time::timeout(Duration::from_millis(300), lb.client.recv(&mut buf))
                    .await
                    .is_err(),
                "{family_name}: junk must get no answer"
            );

            // Handshake completes on this family.
            lb.handshake().await;

            // Transport data round-trips through obfuscation on this family.
            let packet = ipv4_packet("10.8.0.2", "10.8.0.1", b"hello amnezia v6");
            let mut enc = vec![0u8; 2048];
            let data_len = match lb.tunn.encapsulate(&packet, &mut enc) {
                TunnResult::WriteToNetwork(d) => d.len(),
                other => panic!("{family_name} encapsulate: {other:?}"),
            };
            lb.send_obfuscated(&enc[..data_len]).await;
            let got = tokio::time::timeout(Duration::from_secs(2), lb.link.from_peers.recv())
                .await
                .expect("{family_name}: server delivers the packet")
                .unwrap();
            assert_eq!(got, packet);
            eprintln!("amneziawg {family_name}: handshake + junk + data OK over real UDP");
        }
    }

    #[test]
    fn prefixes_match_bit_by_bit() {
        let net: IpAddr = "10.8.0.0".parse().unwrap();
        assert!(in_prefix(net, 24, "10.8.0.77".parse().unwrap()));
        assert!(!in_prefix(net, 24, "10.8.1.77".parse().unwrap()));
        assert!(in_prefix(net, 13, "10.15.255.255".parse().unwrap()));
        assert!(!in_prefix(net, 13, "10.16.0.0".parse().unwrap()));
        assert!(in_prefix(net, 0, "203.0.113.1".parse().unwrap()));
        assert!(
            !in_prefix(net, 24, "::1".parse().unwrap()),
            "families differ"
        );
        assert!(in_prefix(
            "fd00::".parse().unwrap(),
            8,
            "fdff::1".parse().unwrap()
        ));
        assert!(
            !in_prefix(net, 40, "10.8.0.1".parse().unwrap()),
            "prefix past the family"
        );
    }

    #[test]
    fn the_longest_prefix_wins() {
        let spec = |allowed: &[(&str, u8)]| Peer {
            tunn: Tunn::new(
                StaticSecret::from([1u8; 32]),
                PublicKey::from([2u8; 32]),
                None,
                None,
                0,
                None,
            ),
            public_key: [2; 32],
            allowed: allowed
                .iter()
                .map(|(ip, prefix)| (ip.parse().unwrap(), *prefix))
                .collect(),
            endpoint: None,
            amnezia: None,
        };
        let peer = spec(&[("0.0.0.0", 0), ("10.8.0.0", 24)]);
        assert_eq!(peer.prefix_for("10.8.0.9".parse().unwrap()), Some(24));
        assert_eq!(peer.prefix_for("8.8.8.8".parse().unwrap()), Some(0));
        assert_eq!(peer.prefix_for("::1".parse().unwrap()), None);
    }
}
