//! ShadowTLS v3 client and server (simplified).
//!
//! ShadowTLS hides a proxy behind a real TLS server. The client sends a
//! genuine, browser-shaped ClientHello to a ShadowTLS relay; the relay forwards
//! it to a decoy TLS site (a popular, unblocked domain) and streams the decoy's
//! answer back, so a censor watching the wire sees an ordinary TLS session to
//! that domain. The client proves it is "one of us" with a keyed HMAC hidden in
//! the ClientHello's `legacy_session_id`; once the relay sees the first client
//! data frame carrying the matching HMAC it stops talking to the decoy and
//! proxies the real backend instead. The wire contract is verified against the
//! MIT-licensed `sagernet/sing-shadowtls` reference (v3).
//!
//! This module also terminates ShadowTLS itself ([`accept`]): it verifies the
//! ClientHello HMAC, answers with a synthetic ServerHello, and then frames the
//! data stream with the key chains swapped relative to the client (verify
//! with "C", tag with "S"). A failed authentication never produces a
//! ShadowTLS-specific response: the stream is relayed verbatim to a decoy
//! endpoint when one is configured, and dropped otherwise, so a prober cannot
//! tell this server from a dumb TLS relay.
//!
//! What makes this a *simplified* client: it never runs a real TLS handshake.
//! A stock client would complete TLS with the decoy (through the relay) so the
//! handshake looks perfect end to end. We only need three things the server
//! actually checks, so we do only those:
//!
//! * a ClientHello whose `legacy_session_id` carries
//!   `HMAC-SHA1(password, ClientHello-with-those-4-bytes-zeroed)[..4]`, which is
//!   how the relay authenticates us;
//! * the 32-byte server random lifted from the ServerHello, which seeds every
//!   data-phase HMAC;
//! * HMAC-SHA1 record framing on the data stream afterwards.
//!
//! We skip the rest of the decoy's TLS flight. The relay does not require the
//! client to finish it: it switches to us on the first data frame whose HMAC
//! matches (`copyByFrameUntilHMACMatches` in the reference). Everything the
//! decoy sent in the meantime — a dummy ChangeCipherSpec, the XORed-and-tagged
//! TLS flight — is discarded by [`VerifiedStream`] on the read side: the
//! `hmac_ignore` chain recognises the decoy's own frames and drops them, and
//! stray ChangeCipherSpec / handshake records are dropped by type.
//!
//! Security note: this is not `allowInsecure`. A wrong password means the relay
//! never switches to us, so the first "real" frame we try to read fails its
//! HMAC check and the stream errors out — it fails closed, it does not fall
//! back to an unauthenticated tunnel.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use zero_core::{boxed, Address, BoxStream};
use zero_security::tls13::hello::{self, HelloParams};
use zero_security::FingerprintProfile;

type HmacSha1 = Hmac<Sha1>;

/// TLS record header: one content-type byte, two version bytes, two length
/// bytes.
const TLS_HEADER: usize = 5;
/// Bytes of HMAC-SHA1 carried per data frame (the reference truncates to four).
const HMAC_SIZE: usize = 4;
/// A data frame's framing header: the TLS record header plus the HMAC tag.
const TLS_HMAC_HEADER: usize = TLS_HEADER + HMAC_SIZE;
/// Size of the TLS `random` field in both ClientHello and ServerHello.
const TLS_RANDOM_SIZE: usize = 32;
/// Size of `legacy_session_id`, which carries the client's auth HMAC.
const SESSION_ID_SIZE: usize = 32;

/// TLS record content types.
const RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const RECORD_ALERT: u8 = 0x15;
const RECORD_HANDSHAKE: u8 = 0x16;
const RECORD_APPLICATION_DATA: u8 = 0x17;

/// Handshake message type for a ServerHello.
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// Offset of the handshake `random` within a handshake *message* (no record
/// header): one type byte, three length bytes, two legacy-version bytes.
const HANDSHAKE_RANDOM_OFFSET: usize = 1 + 3 + 2;

/// Largest payload the client puts in one data frame, matching the reference's
/// 16384-byte split point. The record body is then `HMAC_SIZE + payload`.
const MAX_PAYLOAD: usize = 16384;

/// Offset of `legacy_session_id` within the ClientHello handshake message, as
/// emitted by [`hello::build`]: type(1) + length(3) + version(2) + random(32) +
/// session-id-length(1).
const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;
/// Offset of the four auth-HMAC bytes inside that session id (its last four).
const HMAC_TAG_START: usize = SESSION_ID_START + SESSION_ID_SIZE - HMAC_SIZE;

/// Most records to read while hunting for the ServerHello before giving up. A
/// well-behaved relay sends it first; this only bounds a pathological peer.
const MAX_HANDSHAKE_RECORDS: usize = 16;

/// Perform the ShadowTLS v3 client handshake over `base` and return the framed
/// data stream.
///
/// `base` is the raw connection to the relay. `password` is the shared secret,
/// `server_name` the decoy SNI, `alpn` the ALPN list to advertise (camouflage
/// only; empty keeps the browser default), and `fingerprint` the ClientHello
/// shape. On return the stream is ready for the inner protocol (Shadowsocks) to
/// write its first bytes, which become the first authenticated data frame and
/// trigger the relay to switch to the real backend.
pub async fn connect(
    mut base: BoxStream,
    password: &str,
    server_name: &str,
    alpn: &[Vec<u8>],
    fingerprint: FingerprintProfile,
) -> io::Result<BoxStream> {
    let client_hello = build_client_hello(password, server_name, alpn, fingerprint);

    // Wrap the handshake message in a TLS record. The record version is the
    // browser-shaped 0x0301; it is outside the HMAC, so the relay ignores it.
    let mut record = Vec::with_capacity(TLS_HEADER + client_hello.len());
    record.push(RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&client_hello);
    base.write_all(&record).await?;
    base.flush().await?;

    let server_random = read_server_random(&mut base).await?;

    // Three keyed chains, all seeded from the server random (reference
    // `client.go`): "C" tags data we send, "S" verifies real data we read, and
    // the suffix-less chain recognises the decoy frames the relay forwarded
    // before it switched to us.
    let hmac_add = seeded(password, &server_random, b"C");
    let hmac_verify = seeded(password, &server_random, b"S");
    let hmac_ignore = seeded(password, &server_random, b"");
    Ok(boxed(VerifiedStream::new(
        base,
        hmac_add,
        hmac_verify,
        hmac_ignore,
    )))
}

/// Build an HMAC-SHA1 keyed with `password`, pre-fed the server random and an
/// optional role suffix. An empty suffix is a no-op update, which is exactly
/// the decoy-skip chain's seed.
fn seeded(password: &str, server_random: &[u8], suffix: &[u8]) -> HmacSha1 {
    let mut mac =
        <HmacSha1 as Mac>::new_from_slice(password.as_bytes()).expect("HMAC takes any key length");
    mac.update(server_random);
    mac.update(suffix);
    mac
}

/// Build the ClientHello handshake message with its auth HMAC in place.
///
/// The session id is 28 random bytes followed by four zero bytes; the HMAC is
/// computed over the whole message with that four-byte slot still zeroed, then
/// the first four digest bytes are written into it. The relay recomputes the
/// same way (`verifyClientHello`), so the record header must stay out of the
/// hash — it is added by the caller, after this returns.
fn build_client_hello(
    password: &str,
    server_name: &str,
    alpn: &[Vec<u8>],
    fingerprint: FingerprintProfile,
) -> Vec<u8> {
    let mut session_id = [0u8; SESSION_ID_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut session_id[..SESSION_ID_SIZE - HMAC_SIZE]);

    let mut params = HelloParams::new(server_name);
    params.session_id = session_id;
    params.fingerprint = fingerprint;
    // No hybrid key share: the simplified client never completes a real
    // handshake, so the extra ML-KEM key generation would be wasted work.
    params.hybrid_kem = false;
    if !alpn.is_empty() {
        params.alpn = alpn.to_vec();
    }

    // The keypair is discarded: with no real handshake there is no ECDH to run.
    let (mut msg, _keypair) = hello::build(&params);

    debug_assert!(
        msg.len() >= HMAC_TAG_START + HMAC_SIZE,
        "hello is shorter than its session id"
    );
    debug_assert_eq!(
        &msg[HMAC_TAG_START..HMAC_TAG_START + HMAC_SIZE],
        &[0u8; HMAC_SIZE],
        "the four HMAC bytes must start zeroed"
    );

    let mut mac =
        <HmacSha1 as Mac>::new_from_slice(password.as_bytes()).expect("HMAC takes any key length");
    mac.update(&msg);
    let tag = mac.finalize().into_bytes();
    msg[HMAC_TAG_START..HMAC_TAG_START + HMAC_SIZE].copy_from_slice(&tag[..HMAC_SIZE]);
    msg
}

/// Read TLS records from `base` until a ServerHello appears, and return its
/// 32-byte random. ChangeCipherSpec records are tolerated; an alert or an
/// unexpected record type is an error, as is never finding the ServerHello.
async fn read_server_random(base: &mut BoxStream) -> io::Result<[u8; TLS_RANDOM_SIZE]> {
    for _ in 0..MAX_HANDSHAKE_RECORDS {
        let mut header = [0u8; TLS_HEADER];
        base.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; length];
        base.read_exact(&mut body).await?;
        match header[0] {
            RECORD_ALERT => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "shadowtls: relay sent a TLS alert during the handshake",
                ));
            }
            RECORD_HANDSHAKE => {
                if body.first() == Some(&HANDSHAKE_SERVER_HELLO)
                    && body.len() >= HANDSHAKE_RANDOM_OFFSET + TLS_RANDOM_SIZE
                {
                    let mut random = [0u8; TLS_RANDOM_SIZE];
                    random.copy_from_slice(
                        &body[HANDSHAKE_RANDOM_OFFSET..HANDSHAKE_RANDOM_OFFSET + TLS_RANDOM_SIZE],
                    );
                    return Ok(random);
                }
                // A handshake record that is not the ServerHello: keep reading.
            }
            RECORD_CHANGE_CIPHER_SPEC => {
                // The dummy CCS can precede a late ServerHello; tolerate it.
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "shadowtls: unexpected TLS record type {other} before the server hello"
                    ),
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "shadowtls: no server hello within the first records",
    ))
}

/// The ShadowTLS v3 data stream.
///
/// Each write becomes one `application_data` record `[0x17,0x03,0x03,len][tag]
/// [payload]`, where `tag` is the rolling HMAC the relay checks to recognise
/// us. Each read strips and verifies that framing. The relay forwards some
/// decoy traffic before it switches to us; those frames are dropped here (see
/// [`process_record`]).
///
/// The read side keeps two cursors rather than draining from the front on every
/// record: `raw_start` marks how much of `read_raw` has been parsed, and the
/// consumed prefix is dropped only when more bytes are pulled from the
/// transport, so a burst of several records in one read costs one shift, not
/// one per record.
struct VerifiedStream<S> {
    inner: S,
    /// Write chain, seeded `HMAC(pw) + serverRandom + "C"`.
    hmac_add: HmacSha1,
    /// Read chain for the real backend, seeded `... + "S"`.
    hmac_verify: HmacSha1,
    /// Decoy-skip chain, seeded `... ` with no suffix. Dropped the moment a
    /// frame fails to match it, after which reads go straight to `hmac_verify`.
    hmac_ignore: Option<HmacSha1>,
    /// Raw transport bytes, parsed into records starting at `raw_start`.
    read_raw: Vec<u8>,
    raw_start: usize,
    /// Verified plaintext not yet handed to the caller, drained from
    /// `plain_start`.
    read_plain: Vec<u8>,
    plain_start: usize,
    /// Framed bytes queued for the transport, flushed from `write_start`.
    write_buf: Vec<u8>,
    write_start: usize,
    /// Set once the transport reports EOF, so the next empty read returns it.
    read_eof: bool,
}

impl<S> VerifiedStream<S> {
    fn new(inner: S, hmac_add: HmacSha1, hmac_verify: HmacSha1, hmac_ignore: HmacSha1) -> Self {
        Self {
            inner,
            hmac_add,
            hmac_verify,
            hmac_ignore: Some(hmac_ignore),
            read_raw: Vec::new(),
            raw_start: 0,
            read_plain: Vec::new(),
            plain_start: 0,
            write_buf: Vec::new(),
            write_start: 0,
            read_eof: false,
        }
    }
}

/// The outcome of trying to parse one record from the read buffer.
enum RecordStep {
    /// A full record was parsed; carries its total wire length. Any plaintext
    /// it produced is already in `read_plain`.
    Consumed(usize),
    /// Not enough bytes buffered yet for a complete record.
    NeedMore,
}

/// Parse at most one record from the front of `buf`.
///
/// `buf` is the unparsed slice (`read_raw[raw_start..]`); the HMAC chains and
/// the plaintext sink are passed as separate borrows so this can run against
/// disjoint fields of the stream. An alert, a failed verification, or an
/// unknown record type is a hard error — the stream fails closed.
fn process_record(
    buf: &[u8],
    hmac_verify: &mut HmacSha1,
    hmac_ignore: &mut Option<HmacSha1>,
    read_plain: &mut Vec<u8>,
) -> io::Result<RecordStep> {
    if buf.len() < TLS_HEADER {
        return Ok(RecordStep::NeedMore);
    }
    let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = TLS_HEADER + length;
    if buf.len() < total {
        return Ok(RecordStep::NeedMore);
    }
    let record = &buf[..total];
    match record[0] {
        RECORD_ALERT => Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "shadowtls: relay sent a TLS alert",
        )),
        RECORD_APPLICATION_DATA => {
            // Frames the relay forwarded from the decoy before switching to us
            // carry the decoy's own tag; the ignore chain recognises and drops
            // them. The first frame it does not recognise is our real data.
            if let Some(ignore) = hmac_ignore.as_mut() {
                if verify_frame(record, ignore, false) {
                    return Ok(RecordStep::Consumed(total));
                }
                *hmac_ignore = None;
            }
            if !verify_frame(record, hmac_verify, true) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shadowtls: application data verification failed",
                ));
            }
            let payload = &record[TLS_HMAC_HEADER..];
            read_plain.extend_from_slice(payload);
            Ok(RecordStep::Consumed(total))
        }
        RECORD_CHANGE_CIPHER_SPEC | RECORD_HANDSHAKE => {
            // The simplified client runs no TLS state machine, so the dummy
            // ChangeCipherSpec and any stray handshake record are dropped.
            Ok(RecordStep::Consumed(total))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("shadowtls: unexpected TLS record type {other}"),
        )),
    }
}

/// Verify one `application_data` record against `mac`, mirroring the
/// reference's `verifyApplicationData`.
///
/// The payload is always folded into the chain (so the chain tracks the stream
/// either way); `update` additionally feeds the computed tag back, which the
/// real-data chain does and the decoy-skip chain does not. Returns whether the
/// record's tag matches. A wrong version or an undersized record returns
/// `false` without touching the chain, exactly as the reference does.
fn verify_frame(record: &[u8], mac: &mut HmacSha1, update: bool) -> bool {
    if record.len() < TLS_HMAC_HEADER || record[1] != 0x03 || record[2] != 0x03 {
        return false;
    }
    let frame_tag = &record[TLS_HEADER..TLS_HMAC_HEADER];
    let payload = &record[TLS_HMAC_HEADER..];
    mac.update(payload);
    let digest = mac.clone().finalize().into_bytes();
    let computed = &digest[..HMAC_SIZE];
    if update {
        mac.update(computed);
    }
    constant_time_eq(computed, frame_tag)
}

/// Fold `payload` into one framed data record appended to `buf`, advancing the
/// write chain. Mirrors the reference's `verifiedConn.write`: tag the payload,
/// then feed the tag back so the next frame chains on it.
fn frame_into(buf: &mut Vec<u8>, hmac_add: &mut HmacSha1, payload: &[u8]) {
    let length = (HMAC_SIZE + payload.len()) as u16;
    hmac_add.update(payload);
    let digest = hmac_add.clone().finalize().into_bytes();
    let tag = &digest[..HMAC_SIZE];
    hmac_add.update(tag);
    buf.reserve(TLS_HMAC_HEADER + payload.len());
    buf.push(RECORD_APPLICATION_DATA);
    buf.extend_from_slice(&[0x03, 0x03]);
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(payload);
}

/// Compare two equal-length tags without an early-exit branch, matching the
/// reference's `hmac.Equal`. The inputs here are always `HMAC_SIZE` long.
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

/// Push as much of `write_buf[write_start..]` to the transport as it will take.
/// On full drain the buffer is cleared and the cursor reset, so it never grows
/// past one queued frame.
fn drain_write<S: AsyncWrite + Unpin>(
    inner: &mut S,
    write_buf: &mut Vec<u8>,
    write_start: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *write_start < write_buf.len() {
        match Pin::new(&mut *inner).poll_write(cx, &write_buf[*write_start..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadowtls: transport accepted no bytes",
                )));
            }
            Poll::Ready(Ok(n)) => *write_start += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    write_buf.clear();
    *write_start = 0;
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VerifiedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            // 1. Hand over any decoded plaintext still buffered.
            if this.plain_start < this.read_plain.len() {
                let available = &this.read_plain[this.plain_start..];
                let n = available.len().min(dst.remaining());
                dst.put_slice(&available[..n]);
                this.plain_start += n;
                if this.plain_start == this.read_plain.len() {
                    this.read_plain.clear();
                    this.plain_start = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. Turn one buffered record into plaintext (or skip/alert on it).
            match process_record(
                &this.read_raw[this.raw_start..],
                &mut this.hmac_verify,
                &mut this.hmac_ignore,
                &mut this.read_plain,
            )? {
                RecordStep::Consumed(total) => {
                    this.raw_start += total;
                    continue;
                }
                RecordStep::NeedMore => {}
            }

            // 3. No complete record buffered: pull more from the transport.
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            if this.raw_start > 0 {
                this.read_raw.drain(..this.raw_start);
                this.raw_start = 0;
            }
            let mut scratch = [0u8; 16 * 1024];
            let mut buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let filled = buf.filled();
                    if filled.is_empty() {
                        this.read_eof = true;
                    } else {
                        this.read_raw.extend_from_slice(filled);
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VerifiedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Backpressure: clear the queued frame before taking more. If the
        // transport cannot take it all, do not accept new bytes yet.
        if this.write_start < this.write_buf.len() {
            match drain_write(
                &mut this.inner,
                &mut this.write_buf,
                &mut this.write_start,
                cx,
            ) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &src[..src.len().min(MAX_PAYLOAD)];
        frame_into(&mut this.write_buf, &mut this.hmac_add, chunk);
        // Start sending immediately; the remainder stays queued for the next
        // call, flush or shutdown.
        if let Poll::Ready(Err(e)) = drain_write(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.write_start,
            cx,
        ) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match drain_write(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.write_start,
            cx,
        ) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match drain_write(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.write_start,
            cx,
        ) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Length of the synthetic ServerHello handshake message: version(2) +
/// random(32) + session-id-length(1) + cipher-suite(2) + compression(1) +
/// extensions-length(2).
const SERVER_HELLO_BODY: usize = 2 + TLS_RANDOM_SIZE + 1 + 2 + 1 + 2;

/// Perform the ShadowTLS v3 server handshake over `base` and return the framed
/// data stream.
///
/// Reads the client's ClientHello TLS record and recomputes
/// `HMAC-SHA1(password, ClientHello-with-auth-slot-zeroed)[..4]`, comparing in
/// constant time (`verifyClientHello` in the reference). On success it answers
/// with a synthetic ServerHello carrying a fresh 32-byte `server_random` and
/// returns the data stream with the chains swapped relative to the client:
/// frames read from the peer are verified with the "C" chain and frames sent
/// are tagged with the "S" chain.
///
/// On authentication failure the stream is indistinguishable from a dumb TLS
/// relay: it is forwarded verbatim to `fallback` (the decoy endpoint) when one
/// is configured, and dropped without emitting any ShadowTLS-specific bytes
/// otherwise. A prober that fails authentication must never learn that this
/// endpoint terminates ShadowTLS.
pub async fn accept(
    mut base: BoxStream,
    password: &str,
    fallback: Option<(Address, u16)>,
) -> io::Result<BoxStream> {
    // The first TLS record must carry the ClientHello. Its raw bytes are kept
    // so a failed authentication can forward exactly what arrived, like a
    // relay that never recognised us would.
    let mut header = [0u8; TLS_HEADER];
    base.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; length];
    base.read_exact(&mut body).await?;
    let mut raw = Vec::with_capacity(TLS_HEADER + length);
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&body);

    let authenticated = header[0] == RECORD_HANDSHAKE && verify_client_hello(password, &body);
    if !authenticated {
        return relay_or_drop(base, raw, fallback).await;
    }

    let mut server_random = [0u8; TLS_RANDOM_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut server_random);
    let hello = build_server_hello(&server_random);
    base.write_all(&hello).await?;
    base.flush().await?;

    // Chains swapped relative to the client: the server verifies the client's
    // "C" frames and tags its own with "S". The decoy-skip chain stays armed
    // so a reference client that pipelines data with its hello is tolerated.
    let hmac_add = seeded(password, &server_random, b"S");
    let hmac_verify = seeded(password, &server_random, b"C");
    let hmac_ignore = seeded(password, &server_random, b"");
    Ok(boxed(VerifiedStream::new(
        base,
        hmac_add,
        hmac_verify,
        hmac_ignore,
    )))
}

/// Verify the ClientHello handshake message's auth HMAC the way the reference
/// `verifyClientHello` does: the four tag bytes sit at the end of the
/// `legacy_session_id`; zero them, HMAC-SHA1 the whole message with
/// `password`, and compare the first four digest bytes in constant time.
///
/// Returns `false` (rather than erroring) for any message that cannot be a
/// ShadowTLS ClientHello — wrong type, truncated, or a session id too short
/// to hold the tag — so the caller funnels every failure into the same
/// decoy/drop path.
///
/// Public so the `shadowtls_client_hello` fuzz target exercises the exact
/// parser that faces the network.
pub fn verify_client_hello(password: &str, message: &[u8]) -> bool {
    if message.first() != Some(&0x01) {
        return false; // not a ClientHello
    }
    if message.len() < SESSION_ID_START + 1 {
        return false;
    }
    let session_id_len = message[SESSION_ID_START - 1] as usize;
    if session_id_len < HMAC_SIZE || message.len() < SESSION_ID_START + session_id_len {
        return false;
    }
    let tag_start = SESSION_ID_START + session_id_len - HMAC_SIZE;
    let mut mac =
        <HmacSha1 as Mac>::new_from_slice(password.as_bytes()).expect("HMAC takes any key length");
    mac.update(&message[..tag_start]);
    mac.update(&[0u8; HMAC_SIZE]);
    mac.update(&message[tag_start + HMAC_SIZE..]);
    let tag = mac.finalize().into_bytes();
    constant_time_eq(
        &tag[..HMAC_SIZE],
        &message[tag_start..tag_start + HMAC_SIZE],
    )
}

/// Build a minimal, well-formed ServerHello TLS record. The client only reads
/// the 32-byte random out of it; the cipher suite and empty extensions exist
/// so the flight looks like an ordinary TLS server answering.
fn build_server_hello(server_random: &[u8; TLS_RANDOM_SIZE]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + SERVER_HELLO_BODY);
    message.push(HANDSHAKE_SERVER_HELLO);
    message.extend_from_slice(&(SERVER_HELLO_BODY as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&[0x03, 0x03]); // legacy version
    message.extend_from_slice(server_random);
    message.push(0); // empty legacy session id
    message.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    message.push(0); // null compression
    message.extend_from_slice(&[0x00, 0x00]); // no extensions
    debug_assert_eq!(message.len(), 4 + SERVER_HELLO_BODY);

    let mut record = Vec::with_capacity(TLS_HEADER + message.len());
    record.push(RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// Handle a failed ClientHello authentication without revealing the relay.
///
/// With a `fallback` configured the stream behaves exactly like a dumb TCP
/// relay to the decoy: the bytes already read are forwarded and the two
/// directions are shuttled in the background, while the returned stream is
/// already at EOF so the inner protocol fails the session. Without one, the
/// connection is dropped without emitting a single ShadowTLS byte.
async fn relay_or_drop(
    base: BoxStream,
    prefix: Vec<u8>,
    fallback: Option<(Address, u16)>,
) -> io::Result<BoxStream> {
    let eof: BoxStream = {
        let (stream, writer) = tokio::io::duplex(1);
        drop(writer);
        boxed(stream)
    };
    let Some((address, port)) = fallback else {
        return Ok(eof);
    };
    let target = match &address {
        Address::Ip(ip) => std::net::SocketAddr::new(*ip, port),
        Address::Domain(domain) => {
            let resolved = tokio::net::lookup_host((domain.as_ref(), port)).await?;
            let Some(addr) = resolved.into_iter().next() else {
                return Ok(eof);
            };
            addr
        }
    };
    let mut decoy = match tokio::net::TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(_) => return Ok(eof),
    };
    // If the decoy is unreachable the relay cannot impersonate one; dropping
    // is the behaviour a relay with a dead decoy shows too.
    if decoy.write_all(&prefix).await.is_err() {
        return Ok(eof);
    }
    let mut base = base;
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut base, &mut decoy).await;
    });
    Ok(eof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    const PASSWORD: &str = "correct horse battery staple";

    fn server_random() -> [u8; TLS_RANDOM_SIZE] {
        let mut r = [0u8; TLS_RANDOM_SIZE];
        for (i, b) in r.iter_mut().enumerate() {
            *b = i as u8;
        }
        r
    }

    /// A test peer that frames data exactly as the reference server does for
    /// the "S" direction, and verifies the client's "C" frames.
    struct Peer {
        write_chain: HmacSha1,
        read_chain: HmacSha1,
    }

    impl Peer {
        fn new() -> Self {
            Self {
                // Server writes with "S" (what the client verifies) and reads
                // the client's "C" frames.
                write_chain: seeded(PASSWORD, &server_random(), b"S"),
                read_chain: seeded(PASSWORD, &server_random(), b"C"),
            }
        }

        fn frame(&mut self, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            frame_into(&mut out, &mut self.write_chain, payload);
            out
        }

        /// Strip and verify one "C" frame, returning its payload.
        fn unframe(&mut self, record: &[u8]) -> Vec<u8> {
            assert!(
                verify_frame(record, &mut self.read_chain, true),
                "bad C tag"
            );
            record[TLS_HMAC_HEADER..].to_vec()
        }
    }

    #[test]
    fn session_id_hmac_matches_the_server_recomputation() {
        let hello = build_client_hello(PASSWORD, "example.com", &[], FingerprintProfile::Chrome);
        // Recompute the way `verifyClientHello` does: zero the four tag bytes,
        // HMAC the whole message, compare the first four digest bytes.
        let tag = hello[HMAC_TAG_START..HMAC_TAG_START + HMAC_SIZE].to_vec();
        let mut zeroed = hello.clone();
        for b in &mut zeroed[HMAC_TAG_START..HMAC_TAG_START + HMAC_SIZE] {
            *b = 0;
        }
        let mut mac = <HmacSha1 as Mac>::new_from_slice(PASSWORD.as_bytes()).unwrap();
        mac.update(&zeroed);
        let expected = mac.finalize().into_bytes();
        assert_eq!(tag, expected[..HMAC_SIZE]);
    }

    #[test]
    fn wrong_password_fails_the_session_id_hmac() {
        let hello = build_client_hello(PASSWORD, "example.com", &[], FingerprintProfile::Chrome);
        let tag = hello[HMAC_TAG_START..HMAC_TAG_START + HMAC_SIZE].to_vec();
        let mut zeroed = hello.clone();
        for b in &mut zeroed[HMAC_TAG_START..HMAC_TAG_START + HMAC_SIZE] {
            *b = 0;
        }
        let mut mac = <HmacSha1 as Mac>::new_from_slice(b"the wrong password").unwrap();
        mac.update(&zeroed);
        let wrong = mac.finalize().into_bytes();
        assert_ne!(tag, wrong[..HMAC_SIZE]);
    }

    #[test]
    fn framing_is_wire_shaped() {
        let mut peer = Peer::new();
        let record = peer.frame(b"hello");
        assert_eq!(record[0], RECORD_APPLICATION_DATA);
        assert_eq!(&record[1..3], &[0x03, 0x03]);
        assert_eq!(
            u16::from_be_bytes([record[3], record[4]]) as usize,
            HMAC_SIZE + 5
        );
        assert_eq!(record.len(), TLS_HMAC_HEADER + 5);
    }

    #[tokio::test]
    async fn round_trips_data_after_skipping_decoy_frames() {
        let (client_side, mut peer_side) = duplex(64 * 1024);
        let mut stream = VerifiedStream::new(
            client_side,
            seeded(PASSWORD, &server_random(), b"C"),
            seeded(PASSWORD, &server_random(), b"S"),
            seeded(PASSWORD, &server_random(), b""),
        );
        let mut peer = Peer::new();

        // The peer first replays two decoy frames (tagged with the ignore
        // chain, as the relay forwards them) and a dummy ChangeCipherSpec, then
        // the real backend data. Decoy frames are tagged payload-only, with no
        // tag fed back, exactly as the reference relay forwards them.
        let mut ignore_chain = seeded(PASSWORD, &server_random(), b"");
        let mut decoy = Vec::new();
        decoy.extend_from_slice(&decoy_frame(&mut ignore_chain, b"decoy one"));
        decoy.extend_from_slice(&decoy_frame(&mut ignore_chain, b"decoy two"));
        decoy.extend_from_slice(&[RECORD_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
        let real = peer.frame(b"real backend payload");
        peer_side.write_all(&decoy).await.unwrap();
        peer_side.write_all(&real).await.unwrap();
        peer_side.flush().await.unwrap();

        let mut got = vec![0u8; b"real backend payload".len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"real backend payload");

        // And a client write comes back out as a valid "C" frame.
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut header = [0u8; TLS_HMAC_HEADER];
        peer_side.read_exact(&mut header).await.unwrap();
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize - HMAC_SIZE;
        let mut payload = vec![0u8; payload_len];
        peer_side.read_exact(&mut payload).await.unwrap();
        let mut record = header.to_vec();
        record.extend_from_slice(&payload);
        assert_eq!(peer.unframe(&record), b"ping");
    }

    #[tokio::test]
    async fn tampered_backend_frame_fails_closed() {
        let (client_side, mut peer_side) = duplex(64 * 1024);
        let mut stream = VerifiedStream::new(
            client_side,
            seeded(PASSWORD, &server_random(), b"C"),
            seeded(PASSWORD, &server_random(), b"S"),
            seeded(PASSWORD, &server_random(), b""),
        );
        let mut peer = Peer::new();
        let mut record = peer.frame(b"real backend payload");
        // Flip a payload byte after the tag was computed.
        let last = record.len() - 1;
        record[last] ^= 0xff;
        peer_side.write_all(&record).await.unwrap();
        peer_side.flush().await.unwrap();

        let mut got = [0u8; 8];
        let err = stream.read(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn large_write_splits_into_capped_frames() {
        let (client_side, mut peer_side) = duplex(1024 * 1024);
        let mut stream = VerifiedStream::new(
            client_side,
            seeded(PASSWORD, &server_random(), b"C"),
            seeded(PASSWORD, &server_random(), b"S"),
            seeded(PASSWORD, &server_random(), b""),
        );
        let mut peer = Peer::new();

        let big = vec![0x5au8; MAX_PAYLOAD + 100];
        tokio::spawn(async move {
            stream.write_all(&big).await.unwrap();
            stream.flush().await.unwrap();
        });

        // First frame carries exactly MAX_PAYLOAD, the second the remainder.
        let first = read_one_frame(&mut peer_side).await;
        assert_eq!(peer.unframe(&first).len(), MAX_PAYLOAD);
        let second = read_one_frame(&mut peer_side).await;
        assert_eq!(peer.unframe(&second).len(), 100);
    }

    async fn read_one_frame(peer: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
        let mut header = [0u8; TLS_HMAC_HEADER];
        peer.read_exact(&mut header).await.unwrap();
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize - HMAC_SIZE;
        let mut payload = vec![0u8; payload_len];
        peer.read_exact(&mut payload).await.unwrap();
        let mut record = header.to_vec();
        record.extend_from_slice(&payload);
        record
    }

    /// Tag a decoy frame the way the relay forwards one: fold the payload into
    /// the chain, take the first four digest bytes as the tag, and do *not*
    /// feed the tag back (the reference `copyByFrameWithModification`).
    fn decoy_frame(chain: &mut HmacSha1, payload: &[u8]) -> Vec<u8> {
        chain.update(payload);
        let tag = chain.clone().finalize().into_bytes();
        let length = (HMAC_SIZE + payload.len()) as u16;
        let mut out = Vec::with_capacity(TLS_HMAC_HEADER + payload.len());
        out.push(RECORD_APPLICATION_DATA);
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&tag[..HMAC_SIZE]);
        out.extend_from_slice(payload);
        out
    }

    // ------------------------------------------------- server-side handshake

    /// Wrap a ClientHello handshake message in a TLS record, the way
    /// [`connect`] sends it.
    fn client_hello_record(password: &str) -> Vec<u8> {
        let hello = build_client_hello(password, "example.com", &[], FingerprintProfile::Chrome);
        let mut record = Vec::with_capacity(TLS_HEADER + hello.len());
        record.push(RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        record
    }

    #[tokio::test]
    async fn accept_completes_the_handshake_with_our_client() {
        let (client_side, server_side) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            accept(boxed(server_side), PASSWORD, None)
                .await
                .expect("accept with the right password")
        });
        let mut client = connect(
            boxed(client_side),
            PASSWORD,
            "example.com",
            &[],
            FingerprintProfile::Chrome,
        )
        .await
        .expect("client handshake");
        let mut server = server.await.unwrap();

        // Both directions carry real data: the chains are swapped, so this
        // only works if each side verifies with the other's tagging chain.
        client.write_all(b"client to server").await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; 16];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"client to server");

        server.write_all(b"server to client").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"server to client");
    }

    /// The handshake runs over real TCP sockets here (not the in-memory
    /// duplex above), once per IP family, with a 1 MiB echo each way so the
    /// family matrix records a measured throughput, not an assumption.
    #[tokio::test]
    async fn accept_handshake_works_over_ipv4_and_ipv6_tcp() {
        for host in ["127.0.0.1", "::1"] {
            let listener = tokio::net::TcpListener::bind((host, 0))
                .await
                .unwrap_or_else(|error| panic!("TCP bind on {host}: {error}"));
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                accept(boxed(socket), PASSWORD, None)
                    .await
                    .expect("accept with the right password")
            });
            let socket = tokio::net::TcpStream::connect(addr)
                .await
                .unwrap_or_else(|error| panic!("TCP connect to {addr}: {error}"));
            let mut client = connect(
                boxed(socket),
                PASSWORD,
                "example.com",
                &[],
                FingerprintProfile::Chrome,
            )
            .await
            .unwrap_or_else(|error| panic!("client handshake over {host}: {error}"));
            let mut server = server.await.unwrap();

            // 1 MiB each way; the payload pattern catches corruption, the
            // clock catches a family that stalls.
            let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
            let started = std::time::Instant::now();
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; payload.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload, "client->server corrupted over {host}");
            server.write_all(&payload).await.unwrap();
            server.flush().await.unwrap();
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload, "server->client corrupted over {host}");
            let elapsed = started.elapsed();
            let mbps = (payload.len() as f64 * 2.0 / 1_048_576.0) / elapsed.as_secs_f64();
            eprintln!("shadowtls {host}: 2 MiB echoed in {elapsed:?} ({mbps:.0} MiB/s)");
        }
    }

    #[tokio::test]
    async fn accept_rejects_a_tampered_client_hello() {
        let (mut client_side, server_side) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            accept(boxed(server_side), PASSWORD, None)
                .await
                .expect("accept returns even on failure")
        });
        let mut record = client_hello_record(PASSWORD);
        // Flip a byte inside the session id: the HMAC no longer matches.
        let flip = TLS_HEADER + HMAC_TAG_START;
        record[flip] ^= 0xff;
        client_side.write_all(&record).await.unwrap();
        client_side.flush().await.unwrap();

        // No fallback configured: the server sends nothing and the stream it
        // returns is already at EOF, so no ShadowTLS byte leaks to a prober.
        let mut transcript = Vec::new();
        client_side.read_to_end(&mut transcript).await.unwrap();
        assert!(
            transcript.is_empty(),
            "a failed handshake must emit no bytes, got {}",
            transcript.len()
        );
        let mut server = server.await.unwrap();
        let mut probe = [0u8; 1];
        assert_eq!(server.read(&mut probe).await.unwrap(), 0);
    }

    /// A wrong-password ClientHello relayed to a fallback must be
    /// byte-identical to what a dumb TCP relay to the same fallback produces.
    /// Any difference would be a distinguisher: proof a prober could tell this
    /// endpoint terminates ShadowTLS.
    #[tokio::test]
    async fn wrong_password_is_indistinguishable_from_a_dumb_relay() {
        // The "decoy": answers every connection with a fixed banner, like a
        // TLS site sending its flight.
        let banner = b"decoy tls flight bytes";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let banner = banner.to_vec();
                tokio::spawn(async move {
                    let mut first = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut first).await;
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, &banner).await;
                });
            }
        });

        let client_hello = client_hello_record("the wrong password");

        // Through our server, with the wrong password and a fallback set.
        let (mut client_side, server_side) = duplex(64 * 1024);
        let fallback = Some((Address::Ip(decoy_addr.ip()), decoy_addr.port()));
        let server = tokio::spawn(async move {
            accept(boxed(server_side), PASSWORD, fallback)
                .await
                .expect("accept returns even on failure")
        });
        client_side.write_all(&client_hello).await.unwrap();
        client_side.flush().await.unwrap();
        let mut via_server = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_side.read_to_end(&mut via_server),
        )
        .await
        .expect("relay responds promptly")
        .unwrap();
        drop(server);

        // Through a plain TCP relay with no ShadowTLS anywhere in the path.
        let mut dumb = tokio::net::TcpStream::connect(decoy_addr).await.unwrap();
        dumb.write_all(&client_hello).await.unwrap();
        let mut via_dumb = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_to_end(&mut dumb, &mut via_dumb),
        )
        .await
        .expect("decoy responds promptly")
        .unwrap();

        assert_eq!(via_server, via_dumb);
        assert_eq!(via_server, banner);
    }

    #[test]
    fn verify_client_hello_rejects_malformed_input() {
        let hello = build_client_hello(PASSWORD, "example.com", &[], FingerprintProfile::Chrome);
        assert!(verify_client_hello(PASSWORD, &hello));
        // Wrong handshake type.
        let mut not_hello = hello.clone();
        not_hello[0] = 0x02;
        assert!(!verify_client_hello(PASSWORD, &not_hello));
        // Truncated before the session id.
        assert!(!verify_client_hello(PASSWORD, &hello[..SESSION_ID_START]));
        // Empty and garbage.
        assert!(!verify_client_hello(PASSWORD, &[]));
        assert!(!verify_client_hello(PASSWORD, &[0x01, 0x02, 0x03]));
    }

    #[test]
    fn server_hello_carries_a_well_formed_random() {
        let mut random = [0u8; TLS_RANDOM_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let record = build_server_hello(&random);
        assert_eq!(record[0], RECORD_HANDSHAKE);
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), TLS_HEADER + length);
        let body = &record[TLS_HEADER..];
        assert_eq!(body[0], HANDSHAKE_SERVER_HELLO);
        assert_eq!(
            &body[HANDSHAKE_RANDOM_OFFSET..HANDSHAKE_RANDOM_OFFSET + TLS_RANDOM_SIZE],
            &random
        );
    }
}
