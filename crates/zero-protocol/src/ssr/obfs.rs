//! ShadowsocksR obfuscation plugins: `plain`, `http_simple`,
//! `tls1.2_ticket_auth`.
//!
//! Clean-room basis: the public ShadowsocksR obfuscation specification. No
//! GPL-licensed implementation was consulted.
//!
//! ## Wire formats implemented here
//!
//! The obfs layer is outermost on the wire:
//! `app -> protocol -> cipher -> obfs.encode -> TCP`.
//!
//! `plain` is the identity transformation.
//!
//! `http_simple` disguises the stream as an HTTP/1.1 exchange. Only the
//! first flight in each direction carries headers; everything after is raw:
//!
//! ```text
//! Client -> server:
//!   GET /<random-path> HTTP/1.1\r\n
//!   Host: <obfs_param, or a random host>\r\n
//!   User-Agent: <a real UA>\r\n
//!   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n
//!   Accept-Encoding: gzip, deflate\r\n
//!   Accept-Language: en-US,en;q=0.5\r\n
//!   Connection: keep-alive\r\n
//!   \r\n
//!   <first data chunk>
//! Server -> client:
//!   HTTP/1.1 200 OK\r\n
//!   Server: nginx/1.18.0\r\n
//!   Date: <fixed plausible date>\r\n
//!   Content-Type: text/html; charset=utf-8\r\n
//!   Content-Length: 4294967295\r\n
//!   Connection: keep-alive\r\n
//!   \r\n
//!   <first reply chunk>
//! ```
//!
//! `tls1.2_ticket_auth` disguises the stream as a TLS 1.2 session-resumption
//! handshake, then frames all later data as TLS Application Data records:
//!
//! ```text
//! Client -> server, first flight (one TLS record, type 22):
//!   16 03 01 <len:u16>
//!   ClientHello(01 <len:u24> 03 03 <random:32> <sid_len=32><sid:32>
//!     <cs_len><cipher suites> 01 00 <ext_len><extensions>)
//!   extensions: server_name(0x0000, obfs_param or random host),
//!               session_ticket(0x0023, ticket)
//!   ticket = HMAC-SHA1(password, first_data)[..10] || first_data (capped)
//!   any first_data beyond the ticket cap follows as Application Data records
//! Server -> client, first flight:
//!   16 03 03 <len> ServerHello(02 ... 03 03 <random:32> ... cipher 0x002f ...
//!     extensions: session_ticket(0x0023, empty))
//!   14 03 03 00 01 01   (ChangeCipherSpec)
//! Later data, both directions:
//!   17 03 03 <len:u16> <data>   (chunked to 16384)
//! ```
//!
//! ## Verification status
//!
//! Same as the protocol plugins: loopback-tested here; third-party
//! interop NOT tested (no non-GPL reference peer available).

use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;

use super::protocol::Decode;

/// Largest Application Data payload per TLS record (TLS caps at 2^14).
const MAX_RECORD: usize = 16384;
/// First-data bytes carried inside the session ticket.
const MAX_TICKET_DATA: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plugin {
    Plain,
    HttpSimple,
    Tls12TicketAuth,
}

const USER_AGENTS: [&str; 3] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];

const HOSTS: [&str; 4] = [
    "www.bing.com",
    "www.microsoft.com",
    "ajax.aspnetcdn.com",
    "www.cloudflare.com",
];

fn random_host(rng: &mut impl Rng) -> String {
    if rng.gen_bool(0.5) {
        HOSTS[rng.gen_range(0..HOSTS.len())].to_string()
    } else {
        // A plausible random hostname under a common suffix.
        const SUFFIX: [&str; 3] = [".com", ".net", ".org"];
        let len = rng.gen_range(6..14);
        let name: String = (0..len)
            .map(|_| rng.gen_range(b'a'..=b'z') as char)
            .collect();
        format!("www.{name}{}", SUFFIX[rng.gen_range(0..SUFFIX.len())])
    }
}

fn random_path(rng: &mut impl Rng) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let len = rng.gen_range(8..24);
    let path: String = (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect();
    format!("/{path}")
}

pub struct Session {
    plugin: Plugin,
    host: String,
    sent_first: bool,
    received_first: bool,
}

impl Session {
    pub fn new_client(plugin: Plugin, obfs_param: &str, rng: &mut impl Rng) -> Self {
        let host = if obfs_param.trim().is_empty() {
            random_host(rng)
        } else {
            obfs_param.trim().to_string()
        };
        Self {
            plugin,
            host,
            sent_first: false,
            received_first: false,
        }
    }

    pub fn new_server(plugin: Plugin) -> Self {
        Self {
            plugin,
            host: String::new(),
            sent_first: false,
            received_first: false,
        }
    }

    /// First client -> server flight.
    pub fn encode_first(&mut self, data: &[u8], password: &[u8], rng: &mut impl Rng) -> Vec<u8> {
        self.sent_first = true;
        match self.plugin {
            Plugin::Plain => data.to_vec(),
            Plugin::HttpSimple => {
                let request = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\n\r\n",
                    random_path(rng),
                    self.host,
                    USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())],
                );
                let mut out = Vec::with_capacity(request.len() + data.len());
                out.extend_from_slice(request.as_bytes());
                out.extend_from_slice(data);
                out
            }
            Plugin::Tls12TicketAuth => {
                let ticket_data_len = data.len().min(MAX_TICKET_DATA);
                let ticket_data = &data[..ticket_data_len];
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(password).expect("HMAC-SHA1 takes any key");
                mac.update(ticket_data);
                let tag: [u8; 10] = mac.finalize().into_bytes()[..10]
                    .try_into()
                    .expect("10 of 20 bytes");
                let hello = client_hello(&self.host, &tag, ticket_data, rng);
                let mut out = Vec::with_capacity(5 + hello.len() + data.len());
                out.extend_from_slice(&[0x16, 0x03, 0x01]);
                out.extend_from_slice(&(hello.len() as u16).to_be_bytes());
                out.extend_from_slice(&hello);
                // First-data beyond the ticket cap rides as app-data records.
                out.extend_from_slice(&frame_records(&data[ticket_data_len..]));
                out
            }
        }
    }

    /// Later client -> server data.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        match self.plugin {
            Plugin::Plain | Plugin::HttpSimple => data.to_vec(),
            Plugin::Tls12TicketAuth => frame_records(data),
        }
    }

    /// First server -> client flight.
    pub fn encode_reply_first(&mut self, data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
        self.sent_first = true;
        match self.plugin {
            Plugin::Plain => data.to_vec(),
            Plugin::HttpSimple => {
                let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 4294967295\r\nConnection: keep-alive\r\n\r\n";
                let mut out = Vec::with_capacity(response.len() + data.len());
                out.extend_from_slice(response.as_bytes());
                out.extend_from_slice(data);
                out
            }
            Plugin::Tls12TicketAuth => {
                let hello = server_hello(rng);
                let mut out = Vec::with_capacity(5 + hello.len() + 6 + data.len());
                out.extend_from_slice(&[0x16, 0x03, 0x03]);
                out.extend_from_slice(&(hello.len() as u16).to_be_bytes());
                out.extend_from_slice(&hello);
                // ChangeCipherSpec.
                out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
                out.extend_from_slice(&frame_records(data));
                out
            }
        }
    }

    /// Later server -> client data.
    pub fn encode_reply(&mut self, data: &[u8]) -> Vec<u8> {
        self.encode(data)
    }

    /// Server: decode the first client -> server flight. Returns the
    /// de-obfuscated payload and bytes consumed.
    pub fn decode_first(&mut self, buf: &[u8], password: &[u8]) -> Result<Decode, String> {
        self.received_first = true;
        match self.plugin {
            Plugin::Plain => Ok(Decode::Done(buf.to_vec(), buf.len())),
            Plugin::HttpSimple => {
                let end = match find_header_end(buf) {
                    Some(end) => end,
                    None => {
                        if buf.len() > 8192 {
                            return Err("http_simple: headers too long".into());
                        }
                        return Ok(Decode::NeedMore(buf.len() + 1));
                    }
                };
                let head = &buf[..end];
                if !head.starts_with(b"GET /") {
                    return Err("http_simple: not an HTTP GET".into());
                }
                Ok(Decode::Done(buf[end..].to_vec(), buf.len()))
            }
            Plugin::Tls12TicketAuth => match parse_client_hello(buf, password)? {
                None => Ok(Decode::NeedMore(buf.len() + 1)),
                Some((consumed, ticket_data)) => {
                    // First-data beyond the ticket cap followed as
                    // Application Data records; de-frame them.
                    let rest = &buf[consumed..];
                    let mut out = ticket_data;
                    if !rest.is_empty() {
                        match deframe_records(rest)? {
                            Decode::Done(payload, used) if used == rest.len() => {
                                out.extend_from_slice(&payload)
                            }
                            Decode::Done(_, _) | Decode::NeedMore(_) => {
                                return Ok(Decode::NeedMore(buf.len() + 1))
                            }
                        }
                    }
                    Ok(Decode::Done(out, buf.len()))
                }
            },
        }
    }

    /// Server: decode later client -> server data.
    pub fn decode(&mut self, buf: &[u8]) -> Result<Decode, String> {
        match self.plugin {
            Plugin::Plain | Plugin::HttpSimple => Ok(Decode::Done(buf.to_vec(), buf.len())),
            Plugin::Tls12TicketAuth => deframe_records(buf),
        }
    }

    /// Client: decode the first server -> client flight.
    pub fn decode_reply_first(&mut self, buf: &[u8]) -> Result<Decode, String> {
        self.received_first = true;
        match self.plugin {
            Plugin::Plain => Ok(Decode::Done(buf.to_vec(), buf.len())),
            Plugin::HttpSimple => {
                let end = find_header_end(buf);
                let end = match end {
                    Some(end) => end,
                    None => {
                        if buf.len() > 8192 {
                            return Err("http_simple: response headers too long".into());
                        }
                        return Ok(Decode::NeedMore(buf.len() + 1));
                    }
                };
                if !buf.starts_with(b"HTTP/1.1 200") {
                    return Err("http_simple: not an HTTP 200 response".into());
                }
                Ok(Decode::Done(buf[end..].to_vec(), buf.len()))
            }
            Plugin::Tls12TicketAuth => {
                // ServerHello record + ChangeCipherSpec record, then
                // application data.
                let (consumed1, typ1) = match parse_record_header(buf)? {
                    Some(parsed) => parsed,
                    None => return Ok(Decode::NeedMore(buf.len() + 1)),
                };
                if typ1 != 0x16 {
                    return Err("tls1.2_ticket_auth: expected handshake record".into());
                }
                let (consumed2, typ2) = match parse_record_header(&buf[consumed1..])? {
                    Some(parsed) => parsed,
                    None => return Ok(Decode::NeedMore(buf.len() + 1)),
                };
                if typ2 != 0x14 {
                    return Err("tls1.2_ticket_auth: expected change-cipher-spec".into());
                }
                let rest = &buf[consumed1 + consumed2..];
                // Any application data already pipelined is de-framed; the
                // stream layer re-feeds leftovers.
                let mut out = Vec::new();
                let mut consumed = 0;
                let mut cursor = rest;
                while !cursor.is_empty() {
                    match deframe_records(cursor)? {
                        Decode::Done(payload, used) => {
                            out.extend_from_slice(&payload);
                            consumed += used;
                            cursor = &cursor[used..];
                        }
                        Decode::NeedMore(_) => break,
                    }
                }
                Ok(Decode::Done(out, consumed1 + consumed2 + consumed))
            }
        }
    }

    /// Client: decode later server -> client data.
    pub fn decode_reply(&mut self, buf: &[u8]) -> Result<Decode, String> {
        self.decode(buf)
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Frame data as TLS 1.2 Application Data records.
fn frame_records(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / MAX_RECORD + 1));
    for chunk in data.chunks(MAX_RECORD) {
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// De-frame one or more TLS records; only Application Data (0x17) is
/// accepted. Returns the concatenated payload and bytes consumed, stopping
/// at the first incomplete record.
fn deframe_records(buf: &[u8]) -> Result<Decode, String> {
    let mut out = Vec::new();
    let mut consumed = 0;
    loop {
        if buf.len() < consumed + 5 {
            if consumed == 0 {
                return Ok(Decode::NeedMore(5));
            }
            break;
        }
        let at = consumed;
        let typ = buf[at];
        if typ != 0x17 {
            return Err(format!(
                "tls1.2_ticket_auth: unexpected record type {typ:#x}, want application data"
            ));
        }
        let len = u16::from_be_bytes([buf[at + 3], buf[at + 4]]) as usize;
        if len > MAX_RECORD {
            return Err("tls1.2_ticket_auth: absurd record length".into());
        }
        if buf.len() < at + 5 + len {
            if consumed == 0 {
                return Ok(Decode::NeedMore(at + 5 + len));
            }
            break;
        }
        out.extend_from_slice(&buf[at + 5..at + 5 + len]);
        consumed = at + 5 + len;
    }
    Ok(Decode::Done(out, consumed))
}

/// Parse one TLS record header; returns `Ok(None)` when the header or body
/// hasn't fully arrived yet, `Err` on a malformed record.
fn parse_record_header(buf: &[u8]) -> Result<Option<(usize, u8)>, String> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let typ = buf[0];
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len > 1 << 15 {
        return Err("tls1.2_ticket_auth: absurd record length".into());
    }
    if buf.len() < 5 + len {
        return Ok(None);
    }
    Ok(Some((5 + len, typ)))
}

/// Build a TLS 1.2 ClientHello with SNI and a session-ticket extension
/// carrying `tag || ticket_data`.
fn client_hello(host: &str, tag: &[u8; 10], ticket_data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.push(0x01); // ClientHello
    hello.extend_from_slice(&[0, 0, 0]); // length placeholder
    hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    hello.extend_from_slice(&random);
    let mut sid = [0u8; 32];
    rng.fill(&mut sid);
    hello.push(32);
    hello.extend_from_slice(&sid);
    // Cipher suites: a plausible modern-but-TLS1.2 list.
    let suites: [u16; 8] = [
        0xc02f, 0xc030, 0x009e, 0x009f, 0xc02b, 0xc02c, 0xcca9, 0xcca8,
    ];
    hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }
    hello.extend_from_slice(&[0x01, 0x00]); // null compression
    let mut extensions = Vec::new();
    // server_name
    {
        let host_bytes = host.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        let mut data = Vec::new();
        data.extend_from_slice(&((1 + 2 + host_bytes.len()) as u16).to_be_bytes());
        data.push(0x00); // host_name
        data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(host_bytes);
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&data);
        extensions.extend_from_slice(&ext);
    }
    // session_ticket with our authenticator
    {
        let mut ticket = Vec::with_capacity(10 + ticket_data.len());
        ticket.extend_from_slice(tag);
        ticket.extend_from_slice(ticket_data);
        extensions.extend_from_slice(&[0x00, 0x23]); // session_ticket
        extensions.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ticket);
    }
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let len = hello.len() - 4;
    hello[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    hello
}

/// Build a minimal TLS 1.2 ServerHello answering the client's hello.
fn server_hello(rng: &mut impl Rng) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.push(0x02); // ServerHello
    hello.extend_from_slice(&[0, 0, 0]);
    hello.extend_from_slice(&[0x03, 0x03]);
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    hello.extend_from_slice(&random);
    hello.push(32);
    let mut sid = [0u8; 32];
    rng.fill(&mut sid);
    hello.extend_from_slice(&sid);
    hello.extend_from_slice(&0xc02fu16.to_be_bytes()); // ECDHE-RSA-AES128-GCM-SHA256
    hello.push(0x00); // null compression
                      // Echo the session_ticket extension, empty (we "accept" resumption).
    let extensions: [u8; 6] = [0x00, 0x23, 0x00, 0x00, 0x00, 0x00];
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let len = hello.len() - 4;
    hello[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    hello
}

/// Parse the client's first flight: one handshake record carrying the
/// ClientHello. Verifies the session ticket's HMAC and returns
/// `Ok(None)` when the flight hasn't fully arrived, otherwise
/// `(bytes consumed, ticket data)`.
fn parse_client_hello(buf: &[u8], password: &[u8]) -> Result<Option<(usize, Vec<u8>)>, String> {
    let fail = |msg: &str| -> Result<Option<(usize, Vec<u8>)>, String> {
        Err(format!("tls1.2_ticket_auth: {msg}"))
    };
    let Some((record_len, typ)) = parse_record_header(buf)? else {
        return Ok(None);
    };
    if typ != 0x16 || buf[1] != 0x03 {
        return fail("first record is not a TLS handshake");
    }
    let body = &buf[5..record_len];
    if body.first() != Some(&0x01) {
        return fail("first handshake message is not a ClientHello");
    }
    // Walk the hello: random(32) | sid | cipher_suites | compression | extensions.
    let mut pos = 4 + 2 + 32;
    let require = |pos: usize, need: usize| -> Result<(), String> {
        if body.len() < pos + need {
            return Err("tls1.2_ticket_auth: truncated ClientHello".into());
        }
        Ok(())
    };
    require(pos, 1)?;
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    require(pos, 2)?;
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    require(pos, 1)?;
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    require(pos, 2)?;
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    require(pos, ext_len)?;
    let ext_end = pos + ext_len;
    let mut ticket: Option<&[u8]> = None;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        require(pos, ext_data_len)?;
        if ext_type == 0x0023 {
            ticket = Some(&body[pos..pos + ext_data_len]);
        }
        pos += ext_data_len;
    }
    let ticket = ticket.ok_or_else(|| "tls1.2_ticket_auth: no session ticket".to_string())?;
    if ticket.len() < 10 {
        return fail("session ticket too short");
    }
    let (tag, ticket_data) = ticket.split_at(10);
    let mut mac = Hmac::<Sha1>::new_from_slice(password).expect("HMAC-SHA1 takes any key");
    mac.update(ticket_data);
    let expected: [u8; 10] = mac.finalize().into_bytes()[..10]
        .try_into()
        .expect("10 of 20 bytes");
    // Constant-time comparison: the ticket is the authenticator.
    if !constant_time_eq(&expected, tag.try_into().expect("10 bytes")) {
        return fail("session ticket HMAC mismatch");
    }
    Ok(Some((record_len, ticket_data.to_vec())))
}

fn constant_time_eq(a: &[u8; 10], b: &[u8; 10]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng() -> impl Rng {
        rand::rngs::StdRng::from_entropy()
    }

    #[test]
    fn plain_is_the_identity() {
        let mut client = Session::new_client(Plugin::Plain, "", &mut rng());
        let mut server = Session::new_server(Plugin::Plain);
        let data = b"anything goes";
        let encoded = client.encode_first(data, b"pw", &mut rng());
        assert_eq!(encoded, data);
        match server.decode_first(&encoded, b"pw").unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, data);
                assert_eq!(consumed, data.len());
            }
            _ => panic!("plain decodes immediately"),
        }
    }

    #[test]
    fn http_simple_roundtrips_with_headers_only_on_first_flight() {
        let mut rng = rng();
        let mut client = Session::new_client(Plugin::HttpSimple, "example.com", &mut rng);
        let mut server = Session::new_server(Plugin::HttpSimple);

        let first = client.encode_first(b"first-chunk", b"pw", &mut rng);
        assert!(first.starts_with(b"GET /"), "client flight looks like HTTP");
        assert!(first.windows(4).any(|w| w == b"\r\n\r\n"));
        let (payload, consumed) = match server.decode_first(&first, b"pw").unwrap() {
            Decode::Done(payload, consumed) => (payload, consumed),
            _ => panic!("http_simple first flight decodes"),
        };
        assert_eq!(payload, b"first-chunk");
        assert_eq!(consumed, first.len());

        // Later data is raw both ways.
        let later = client.encode(b"later");
        assert_eq!(later, b"later");
        match server.decode(&later).unwrap() {
            Decode::Done(payload, _) => assert_eq!(payload, b"later"),
            _ => panic!("http_simple later data is raw"),
        }

        // Server reply carries a response header once.
        let mut client2 = Session::new_client(Plugin::HttpSimple, "", &mut rng);
        let reply = server.encode_reply_first(b"reply-data", &mut rng);
        assert!(reply.starts_with(b"HTTP/1.1 200 OK"));
        match client2.decode_reply_first(&reply).unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, b"reply-data");
                assert_eq!(consumed, reply.len());
            }
            _ => panic!("http_simple reply decodes"),
        }
        // A non-GET first flight is refused.
        let mut server2 = Session::new_server(Plugin::HttpSimple);
        assert!(server2
            .decode_first(b"POST /x HTTP/1.1\r\n\r\n", b"pw")
            .is_err());
    }

    #[test]
    fn http_simple_asks_for_more_on_partial_headers() {
        let mut rng = rng();
        let mut client = Session::new_client(Plugin::HttpSimple, "", &mut rng);
        let mut server = Session::new_server(Plugin::HttpSimple);
        let first = client.encode_first(b"data", b"pw", &mut rng);
        let cut = first.len() / 2;
        match server.decode_first(&first[..cut], b"pw").unwrap() {
            Decode::NeedMore(_) => {}
            _ => panic!("partial headers must ask for more"),
        }
    }

    #[test]
    fn tls_ticket_auth_roundtrips() {
        let mut rng = rng();
        let mut client = Session::new_client(Plugin::Tls12TicketAuth, "example.com", &mut rng);
        let mut server = Session::new_server(Plugin::Tls12TicketAuth);

        // First data larger than the ticket cap: the overflow rides as records.
        let first: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let flight = client.encode_first(&first, b"password", &mut rng);
        assert_eq!(&flight[..3], &[0x16, 0x03, 0x01], "TLS 1.2 record");
        let (payload, consumed) = match server.decode_first(&flight, b"password").unwrap() {
            Decode::Done(payload, consumed) => (payload, consumed),
            _ => panic!("ticket flight decodes"),
        };
        assert_eq!(payload, first, "ticket + overflow records reassemble");
        assert_eq!(consumed, flight.len());

        // Later data is framed as application-data records.
        let later = client.encode(b"later-data");
        assert_eq!(&later[..3], &[0x17, 0x03, 0x03]);
        match server.decode(&later).unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, b"later-data");
                assert_eq!(consumed, later.len());
            }
            _ => panic!("records decode"),
        }

        // Server reply: ServerHello + CCS, then records.
        let mut client2 = Session::new_client(Plugin::Tls12TicketAuth, "", &mut rng);
        let reply = server.encode_reply_first(b"reply-bytes", &mut rng);
        match client2.decode_reply_first(&reply).unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, b"reply-bytes");
                assert_eq!(consumed, reply.len());
            }
            _ => panic!("server flight decodes"),
        }
    }

    #[test]
    fn tls_ticket_auth_rejects_wrong_password() {
        let mut rng = rng();
        let mut client = Session::new_client(Plugin::Tls12TicketAuth, "", &mut rng);
        let mut server = Session::new_server(Plugin::Tls12TicketAuth);
        let flight = client.encode_first(b"data", b"right", &mut rng);
        assert!(server.decode_first(&flight, b"wrong").is_err());
    }

    #[test]
    fn tls_ticket_auth_rejects_garbage() {
        let mut server = Session::new_server(Plugin::Tls12TicketAuth);
        // A truncated record is not an error: it may be a partial read.
        assert!(matches!(
            server.decode_first(b"\x16\x03\x01\x00\x10garbage-garbage", b"pw"),
            Ok(Decode::NeedMore(_))
        ));
        // But a complete record with a bad ticket HMAC is rejected.
        let mut server = Session::new_server(Plugin::Tls12TicketAuth);
        assert!(server
            .decode_first(b"\x16\x03\x01\x00\x10garbage-garbage!", b"pw")
            .is_err());
        // The client reply decoder expects TLS records (ServerHello, then
        // change-cipher-spec): a truncated ServerHello waits for more
        // bytes, and a non-handshake first record is rejected.
        let mut client = Session::new_client(Plugin::Tls12TicketAuth, "", &mut rng());
        assert!(matches!(
            client.decode_reply_first(b"\x16\x03\x03\x00\x40"),
            Ok(Decode::NeedMore(_))
        ));
        let mut client = Session::new_client(Plugin::Tls12TicketAuth, "", &mut rng());
        assert!(client
            .decode_reply_first(b"\x15\x03\x03\x00\x02\x02\x28")
            .is_err());
    }

    #[test]
    fn records_reject_non_application_data() {
        let mut server = Session::new_server(Plugin::Tls12TicketAuth);
        // A handshake record smuggled into the data phase is refused.
        let bad = [0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(server.decode(&bad).is_err());
    }
}
