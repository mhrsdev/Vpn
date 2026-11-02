//! Async ShadowsocksR byte streams: `app -> protocol -> cipher -> obfs`
//! over TCP, mirrored on the way back.
//!
//! [`ClientStream::connect`] performs the client first flight (clear IV,
//! protocol auth packet, obfs hello) with the SOCKS5-style target address
//! as the first application chunk. [`ServerStream::accept`] reads that
//! flight and returns the target address plus any pipelined application
//! bytes. Both directions then relay framed chunks until EOF.

use rand::SeedableRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zero_core::{Address, Destination, Network};

use super::method::{evp_bytes_to_key, Method, StreamCipher};
use super::obfs;
use super::protocol::{self, Decode, MAX_CHUNK};

/// Client-side SSR parameters.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub method: Method,
    pub password: Box<str>,
    pub protocol: protocol::Plugin,
    pub obfs: obfs::Plugin,
    pub obfs_param: Box<str>,
}

/// Server-side SSR parameters.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub method: Method,
    pub password: Box<str>,
    pub protocol: protocol::Plugin,
    pub obfs: obfs::Plugin,
}

/// SOCKS5-style address encoding, shared with plain Shadowsocks.
fn encode_address(destination: &Destination) -> Result<Vec<u8>, String> {
    if destination.network != Network::Tcp {
        return Err("SSR carries TCP destinations only".into());
    }
    let mut out = Vec::new();
    match &destination.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err("SSR domain address too long".into());
            }
            out.push(3);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

/// Parse one SOCKS5-style address from the front of `buf`.
/// Returns (address, port, bytes consumed).
fn parse_address(buf: &[u8]) -> Result<(Address, u16, usize), String> {
    let fail = |msg: &str| -> Result<(Address, u16, usize), String> { Err(msg.into()) };
    let kind = *buf.first().ok_or("SSR: empty address")?;
    let (address, mut pos) = match kind {
        1 => {
            if buf.len() < 5 {
                return fail("SSR: truncated IPv4 address");
            }
            let ip: [u8; 4] = buf[1..5].try_into().expect("4 bytes");
            (Address::Ip(std::net::IpAddr::V4(ip.into())), 5)
        }
        4 => {
            if buf.len() < 17 {
                return fail("SSR: truncated IPv6 address");
            }
            let ip: [u8; 16] = buf[1..17].try_into().expect("16 bytes");
            (Address::Ip(std::net::IpAddr::V6(ip.into())), 17)
        }
        3 => {
            if buf.len() < 2 {
                return fail("SSR: truncated domain address");
            }
            let len = buf[1] as usize;
            if len == 0 || buf.len() < 2 + len {
                return fail("SSR: truncated domain address");
            }
            let domain =
                std::str::from_utf8(&buf[2..2 + len]).map_err(|_| "SSR: invalid domain address")?;
            (Address::Domain(domain.into()), 2 + len)
        }
        _ => return fail("SSR: invalid address type"),
    };
    if buf.len() < pos + 2 {
        return fail("SSR: truncated address port");
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Ok((address, port, pos))
}

/// Which protocol-decode step a decrypted buffer is fed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeMode {
    /// The client's auth packet (server side only).
    First,
    /// A later client -> server chunk (server side).
    Chunk,
    /// A server -> client chunk (client side).
    Reply,
}

/// Feed decrypted bytes through one protocol-decode step, buffering what a
/// partial frame leaves behind.
fn protocol_feed(
    session: &mut protocol::Session,
    decrypted: &mut Vec<u8>,
    mode: DecodeMode,
) -> Result<Option<Vec<u8>>, String> {
    let decode = match mode {
        DecodeMode::First => session.decode_first(decrypted)?,
        DecodeMode::Chunk => session.decode_chunk(decrypted)?,
        DecodeMode::Reply => session.decode_reply(decrypted)?,
    };
    match decode {
        Decode::NeedMore(_) => Ok(None),
        Decode::Done(payload, consumed) => {
            decrypted.drain(..consumed);
            Ok(Some(payload))
        }
    }
}

/// Which side of the connection this stream serves. The framing differs:
/// the client sends the auth first-packet and reads reply chunks; the
/// server reads the auth first-packet (done in [`SsrStream::accept`]) and
/// sends reply chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Client,
    Server,
}

/// One SSR connection: `app -> protocol -> cipher -> obfs` on the way out,
/// mirrored on the way in. Implements [`AsyncRead`]/[`AsyncWrite`] (and
/// thereby [`zero_core::Stream`]) so the runtime can relay it like any
/// other protocol stream.
///
/// Reads and writes are framed in bounded chunks; partial TCP segments are
/// buffered internally, so callers see an ordinary byte stream.
pub struct SsrStream<S> {
    inner: S,
    direction: Direction,
    cipher: StreamCipher,
    protocol: protocol::Session,
    obfs: obfs::Session,
    rng: rand::rngs::StdRng,
    /// Raw TCP bytes not yet de-obfuscated.
    raw: Vec<u8>,
    /// Decrypted bytes not yet protocol-decoded.
    decrypted: Vec<u8>,
    /// Application bytes ready for `poll_read`.
    app: Vec<u8>,
    /// Framed bytes awaiting the TCP write.
    write_buf: Vec<u8>,
    write_pos: usize,
    /// Client: the server's first flight has been de-obfuscated.
    greeted: bool,
    /// Server: the client's auth packet has been decoded.
    first_done: bool,
    /// Server: the reply hello has been sent.
    reply_first_done: bool,
}

impl<S> SsrStream<S> {
    fn new(
        inner: S,
        direction: Direction,
        cipher: StreamCipher,
        protocol: protocol::Session,
        obfs: obfs::Session,
    ) -> Self {
        Self {
            inner,
            direction,
            cipher,
            protocol,
            obfs,
            rng: rand::rngs::StdRng::from_entropy(),
            raw: Vec::new(),
            decrypted: Vec::new(),
            app: Vec::new(),
            write_buf: Vec::new(),
            write_pos: 0,
            greeted: false,
            first_done: false,
            reply_first_done: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    fn protocol_error(error: String) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SsrStream<S> {
    /// Connect and send the first flight carrying the target address.
    pub async fn connect(
        mut inner: S,
        config: &ClientConfig,
        destination: &Destination,
    ) -> Result<Self, String> {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let password = config.password.as_bytes();
        let (mut cipher, iv) = StreamCipher::new_client(config.method, password, &mut rng)?;
        let cipher_key = evp_bytes_to_key(password, config.method.key_len());
        let mut protocol = protocol::Session::new(config.protocol, &iv, &cipher_key, password);
        let mut obfs = obfs::Session::new_client(config.obfs, &config.obfs_param, &mut rng);
        let first = encode_address(destination)?;
        let proto = protocol.encode_first(&first, &mut rng);
        let mut enc = proto;
        cipher.apply(&mut enc, true);
        let mut wire = iv;
        wire.extend_from_slice(&enc);
        let flight = obfs.encode_first(&wire, password, &mut rng);
        inner
            .write_all(&flight)
            .await
            .map_err(|e| format!("SSR connect write: {e}"))?;
        Ok(Self::new(inner, Direction::Client, cipher, protocol, obfs))
    }
}

impl<S: AsyncRead + Unpin> SsrStream<S> {
    /// Read the client's first flight. Returns the stream and the target
    /// destination; any application bytes pipelined behind the address are
    /// queued and returned by the first reads.
    pub async fn accept(
        mut inner: S,
        config: &ServerConfig,
    ) -> Result<(Self, Destination), String> {
        let password = config.password.as_bytes();
        let mut obfs = obfs::Session::new_server(config.obfs);
        let mut raw = Vec::new();
        // De-obfuscate the first flight.
        let enc_flight = loop {
            let mut tmp = [0u8; 16384];
            let n = inner
                .read(&mut tmp)
                .await
                .map_err(|e| format!("SSR accept read: {e}"))?;
            if n == 0 {
                return Err("SSR accept: EOF during first flight".into());
            }
            raw.extend_from_slice(&tmp[..n]);
            match obfs.decode_first(&raw, password)? {
                Decode::NeedMore(_) => continue,
                Decode::Done(payload, consumed) => {
                    raw.drain(..consumed);
                    break payload;
                }
            }
        };
        // Split the clear IV, then decrypt.
        let iv_len = config.method.iv_len();
        if enc_flight.len() < iv_len {
            return Err("SSR accept: first flight shorter than the IV".into());
        }
        let (iv, enc) = enc_flight.split_at(iv_len);
        let mut cipher = StreamCipher::with_iv(config.method, password, iv)?;
        let mut decrypted = enc.to_vec();
        cipher.apply(&mut decrypted, false);
        // Protocol-decode the auth packet.
        let cipher_key = evp_bytes_to_key(password, config.method.key_len());
        let mut protocol = protocol::Session::new(config.protocol, iv, &cipher_key, password);
        let first_app = loop {
            match protocol.decode_first(&decrypted)? {
                Decode::NeedMore(_) => {
                    // The auth packet never spans flights in practice, but
                    // stay correct if it does: read more and continue.
                    let mut tmp = [0u8; 16384];
                    let n = inner
                        .read(&mut tmp)
                        .await
                        .map_err(|e| format!("SSR accept read: {e}"))?;
                    if n == 0 {
                        return Err("SSR accept: EOF during auth packet".into());
                    }
                    raw.extend_from_slice(&tmp[..n]);
                    let more = match obfs.decode(&raw)? {
                        Decode::NeedMore(_) => continue,
                        Decode::Done(payload, consumed) => {
                            raw.drain(..consumed);
                            payload
                        }
                    };
                    let mut more = more;
                    cipher.apply(&mut more, false);
                    decrypted.extend_from_slice(&more);
                }
                Decode::Done(payload, consumed) => {
                    decrypted.drain(..consumed);
                    break payload;
                }
            }
        };
        let (address, port, addr_len) = parse_address(&first_app)?;
        let pending = first_app[addr_len..].to_vec();
        let mut stream = Self::new(inner, Direction::Server, cipher, protocol, obfs);
        stream.raw = raw;
        stream.decrypted = decrypted;
        stream.app = pending;
        stream.first_done = true;
        Ok((stream, Destination::tcp(address, port)))
    }
}

impl<S> SsrStream<S> {
    /// Drive one decode step: TCP -> obfs -> cipher -> protocol -> `app`.
    /// Returns true when application bytes are (newly) available.
    fn drive_decode(&mut self) -> Result<bool, std::io::Error> {
        // Protocol-decode what is already decrypted.
        if !self.decrypted.is_empty() {
            let mode = match self.direction {
                Direction::Client => DecodeMode::Reply,
                Direction::Server if !self.first_done => DecodeMode::First,
                Direction::Server => DecodeMode::Chunk,
            };
            match protocol_feed(&mut self.protocol, &mut self.decrypted, mode)
                .map_err(Self::protocol_error)?
            {
                Some(payload) => {
                    self.first_done = true;
                    self.app.extend_from_slice(&payload);
                    return Ok(true);
                }
                None => {}
            }
        }
        Ok(false)
    }

    /// De-obfuscate and decrypt `raw` into `decrypted`. Returns true when
    /// new decrypted bytes arrived.
    fn drive_decrypt(&mut self) -> Result<bool, std::io::Error> {
        let decoded = match self.direction {
            Direction::Client if !self.greeted => {
                match self
                    .obfs
                    .decode_reply_first(&self.raw)
                    .map_err(Self::protocol_error)?
                {
                    Decode::NeedMore(_) => return Ok(false),
                    Decode::Done(payload, consumed) => {
                        self.raw.drain(..consumed);
                        self.greeted = true;
                        payload
                    }
                }
            }
            Direction::Client => match self
                .obfs
                .decode_reply(&self.raw)
                .map_err(Self::protocol_error)?
            {
                Decode::NeedMore(_) => return Ok(false),
                Decode::Done(payload, consumed) => {
                    self.raw.drain(..consumed);
                    payload
                }
            },
            Direction::Server => match self.obfs.decode(&self.raw).map_err(Self::protocol_error)? {
                Decode::NeedMore(_) => return Ok(false),
                Decode::Done(payload, consumed) => {
                    self.raw.drain(..consumed);
                    payload
                }
            },
        };
        if decoded.is_empty() {
            return Ok(false);
        }
        let mut enc = decoded;
        self.cipher.apply(&mut enc, false);
        self.decrypted.extend_from_slice(&enc);
        Ok(true)
    }

    /// Frame one `poll_write` input through protocol -> cipher -> obfs into
    /// the write buffer. Returns the input bytes accepted.
    fn frame_write(&mut self, buf: &[u8]) -> usize {
        const BATCH: usize = 4 * MAX_CHUNK;
        let take = buf.len().min(BATCH);
        let mut rest = &buf[..take];
        let mut framed = Vec::new();
        while !rest.is_empty() {
            let n = rest.len().min(MAX_CHUNK);
            let chunk = match self.direction {
                Direction::Client => self.protocol.encode_chunk(&rest[..n]),
                Direction::Server => self.protocol.encode_reply(&rest[..n]),
            };
            rest = &rest[n..];
            framed.extend_from_slice(&chunk);
        }
        let mut enc = framed;
        self.cipher.apply(&mut enc, true);
        let wire = match self.direction {
            Direction::Client => self.obfs.encode(&enc),
            Direction::Server if !self.reply_first_done => {
                self.reply_first_done = true;
                self.obfs.encode_reply_first(&enc, &mut self.rng)
            }
            Direction::Server => self.obfs.encode_reply(&enc),
        };
        self.write_buf.extend_from_slice(&wire);
        take
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SsrStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.app.is_empty() {
                let n = this.app.len().min(buf.remaining());
                buf.put_slice(&this.app[..n]);
                this.app.drain(..n);
                return std::task::Poll::Ready(Ok(()));
            }
            match this.drive_decode() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return std::task::Poll::Ready(Err(error)),
            }
            // Need more TCP bytes.
            let mut tmp = [0u8; 16384];
            let mut read_buf = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(())) => {}
            }
            let n = read_buf.filled().len();
            if n == 0 {
                // Clean EOF. If undecodable bytes remain they are dropped:
                // the peer closed mid-frame.
                return std::task::Poll::Ready(Ok(()));
            }
            this.raw.extend_from_slice(read_buf.filled());
            match this.drive_decrypt() {
                Ok(_) => {}
                Err(error) => return std::task::Poll::Ready(Err(error)),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SsrStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let accepted = this.frame_write(buf);
        // Best-effort drain; whatever remains goes out on flush.
        while this.write_pos < this.write_buf.len() {
            match std::pin::Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_buf[this.write_pos..])
            {
                std::task::Poll::Pending => break,
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "SSR underlying write returned zero",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => this.write_pos += n,
            }
        }
        if this.write_pos == this.write_buf.len() {
            this.write_buf.clear();
            this.write_pos = 0;
        }
        std::task::Poll::Ready(Ok(accepted))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.write_pos < this.write_buf.len() {
            match std::pin::Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_buf[this.write_pos..])
            {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "SSR underlying write returned zero",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => this.write_pos += n,
            }
        }
        this.write_buf.clear();
        this.write_pos = 0;
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
            std::task::Poll::Ready(Ok(())) => {}
        }
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn client_config(
        method: Method,
        protocol: protocol::Plugin,
        obfs: obfs::Plugin,
    ) -> ClientConfig {
        ClientConfig {
            method,
            password: "test-password".into(),
            protocol,
            obfs,
            obfs_param: "".into(),
        }
    }

    fn server_config(
        method: Method,
        protocol: protocol::Plugin,
        obfs: obfs::Plugin,
    ) -> ServerConfig {
        ServerConfig {
            method,
            password: "test-password".into(),
            protocol,
            obfs,
        }
    }

    async fn read_exact_len<S: AsyncRead + Unpin>(stream: &mut S, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut read = 0;
        while read < len {
            let n = stream.read(&mut out[read..]).await.expect("read");
            assert!(n > 0, "peer must send {len} bytes");
            read += n;
        }
        out
    }

    /// Drive one client<->server exchange over an in-memory duplex pipe and
    /// assert the bytes round-trip. `writes` are client->server payloads,
    /// `replies` server->client.
    async fn exchange(
        method: Method,
        protocol: protocol::Plugin,
        obfs: obfs::Plugin,
        writes: &[&[u8]],
        replies: &[&[u8]],
    ) {
        let (client_io, server_io) = duplex(65536);
        let cc = client_config(method, protocol, obfs);
        let sc = server_config(method, protocol, obfs);
        let destination = Destination::tcp(Address::Domain("example.com".into()), 80);
        let writes_owned: Vec<Vec<u8>> = writes.iter().map(|w| w.to_vec()).collect();
        let replies_owned: Vec<Vec<u8>> = replies.iter().map(|r| r.to_vec()).collect();

        let client_writes = writes_owned.clone();
        let client_replies = replies_owned.clone();
        let client_task = tokio::spawn(async move {
            let mut client = SsrStream::connect(client_io, &cc, &destination)
                .await
                .expect("client connects");
            for write in &client_writes {
                client.write_all(write).await.expect("client writes");
                client.flush().await.expect("client flushes");
            }
            let expected: Vec<u8> = client_replies.concat();
            let got = read_exact_len(&mut client, expected.len()).await;
            assert_eq!(got, expected, "client received replies");
            client.shutdown().await.expect("client shuts down");
        });

        let server_task = tokio::spawn(async move {
            let (mut server, destination) = SsrStream::accept(server_io, &sc)
                .await
                .expect("server accepts");
            assert_eq!(destination.port, 80);
            let expected: Vec<u8> = writes_owned.concat();
            let got = read_exact_len(&mut server, expected.len()).await;
            assert_eq!(got, expected, "server received writes");
            for reply in &replies_owned {
                server.write_all(reply).await.expect("server replies");
                server.flush().await.expect("server flushes");
            }
        });

        let (c, s) = tokio::join!(client_task, server_task);
        c.expect("client task");
        s.expect("server task");
    }

    /// Every (method x protocol x obfs) combination in the honest subset,
    /// both directions.
    #[tokio::test]
    async fn every_subset_combination_exchanges_both_directions() {
        for method in [
            Method::Aes256Cfb,
            Method::Aes128Cfb,
            Method::Rc4Md5,
            Method::Chacha20Ietf,
        ] {
            for protocol in [
                protocol::Plugin::Origin,
                protocol::Plugin::AuthSha1V4,
                protocol::Plugin::AuthAes128Md5,
            ] {
                for obfs in [
                    obfs::Plugin::Plain,
                    obfs::Plugin::HttpSimple,
                    obfs::Plugin::Tls12TicketAuth,
                ] {
                    exchange(
                        method,
                        protocol,
                        obfs,
                        &[b"hello from client", b"second client chunk"],
                        &[b"hello from server"],
                    )
                    .await;
                }
            }
        }
    }

    #[tokio::test]
    async fn large_payloads_fragment_and_reassemble() {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let big2: Vec<u8> = (0..150_000u32).map(|i| (i * 7 % 251) as u8).collect();
        exchange(
            Method::Aes256Cfb,
            protocol::Plugin::AuthSha1V4,
            obfs::Plugin::Tls12TicketAuth,
            &[&big],
            &[&big2],
        )
        .await;
    }

    #[tokio::test]
    async fn wrong_password_is_rejected_at_accept() {
        let (client_io, server_io) = duplex(65536);
        let mut cc = client_config(
            Method::Aes256Cfb,
            protocol::Plugin::AuthSha1V4,
            obfs::Plugin::Plain,
        );
        cc.password = "wrong".into();
        let sc = server_config(
            Method::Aes256Cfb,
            protocol::Plugin::AuthSha1V4,
            obfs::Plugin::Plain,
        );
        let destination = Destination::tcp(Address::Domain("example.com".into()), 80);
        let client_task =
            tokio::spawn(async move { SsrStream::connect(client_io, &cc, &destination).await });
        let server_result = SsrStream::accept(server_io, &sc).await;
        assert!(
            server_result.is_err(),
            "auth_sha1_v4 must reject a wrong password"
        );
        let _ = client_task.await;
    }

    #[test]
    fn address_codecs_roundtrip() {
        for destination in [
            Destination::tcp(Address::Ip("1.2.3.4".parse().unwrap()), 443),
            Destination::tcp(Address::Ip("::1".parse().unwrap()), 80),
            Destination::tcp(Address::Domain("example.com".into()), 8080),
        ] {
            let bytes = encode_address(&destination).unwrap();
            let (address, port, consumed) = parse_address(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(address, destination.address);
            assert_eq!(port, destination.port);
        }
        assert!(parse_address(&[9]).is_err());
        assert!(parse_address(&[3, 0]).is_err());
    }

    /// Drive one SSR client<->server exchange over a REAL TCP socket bound to
    /// `bind_addr` (127.0.0.1 or ::1). Used for the protocol x IP-family
    /// compatibility matrix: proves the handshake and data path work on the
    /// actual network stack, not just an in-memory pipe.
    async fn exchange_over_tcp(
        bind_addr: std::net::IpAddr,
        method: Method,
        protocol: protocol::Plugin,
        obfs: obfs::Plugin,
    ) {
        let listener = tokio::net::TcpListener::bind((bind_addr, 0))
            .await
            .expect("bind TCP listener");
        let addr = listener.local_addr().expect("local addr");
        let cc = client_config(method, protocol, obfs);
        let sc = server_config(method, protocol, obfs);
        let destination = Destination::tcp(Address::Domain("example.com".into()), 80);

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let (mut server, dest) = SsrStream::accept(socket, &sc)
                .await
                .expect("server accepts");
            assert_eq!(dest.port, 80);
            let got = read_exact_len(&mut server, 17).await;
            assert_eq!(got, b"hello from client");
            server.write_all(b"hello from server").await.expect("reply");
            server.flush().await.expect("flush");
        });

        let client_task = tokio::spawn(async move {
            let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut client = SsrStream::connect(socket, &cc, &destination)
                .await
                .expect("client connects");
            client.write_all(b"hello from client").await.expect("write");
            client.flush().await.expect("flush");
            let got = read_exact_len(&mut client, 17).await;
            assert_eq!(got, b"hello from server");
            client.shutdown().await.expect("shutdown");
        });

        let (c, s) = tokio::join!(client_task, server_task);
        c.expect("client task");
        s.expect("server task");
    }

    /// Protocol x IP-family matrix: every subset combination over real IPv4
    /// AND real IPv6 TCP loopback. Each combo must complete a full handshake
    /// and bidirectional data exchange on each family independently.
    #[tokio::test]
    async fn ssr_family_matrix_ipv4_and_ipv6() {
        let families = [
            ("ipv4", "127.0.0.1".parse().unwrap()),
            ("ipv6", "::1".parse().unwrap()),
        ];
        let methods = [
            Method::Aes256Cfb,
            Method::Aes128Cfb,
            Method::Rc4Md5,
            Method::Chacha20Ietf,
        ];
        let protocols = [
            protocol::Plugin::Origin,
            protocol::Plugin::AuthSha1V4,
            protocol::Plugin::AuthAes128Md5,
        ];
        let obfss = [
            obfs::Plugin::Plain,
            obfs::Plugin::HttpSimple,
            obfs::Plugin::Tls12TicketAuth,
        ];
        for (family_name, bind_addr) in families {
            for method in methods {
                for protocol in protocols {
                    for obfs in obfss {
                        exchange_over_tcp(bind_addr, method, protocol, obfs).await;
                    }
                }
            }
            eprintln!("ssr {family_name}: all 36 combos OK over real TCP");
        }
    }
}
