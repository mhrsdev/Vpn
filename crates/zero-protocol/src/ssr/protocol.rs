//! ShadowsocksR protocol plugins: `origin`, `auth_sha1_v4`, `auth_aes128_md5`.
//!
//! Clean-room basis: the public ShadowsocksR protocol specification. No
//! GPL-licensed implementation was consulted.
//!
//! ## Wire formats implemented here
//!
//! The protocol layer sits between the application bytes and the stream
//! cipher: `app -> protocol.encode -> cipher -> obfs -> TCP`.
//!
//! `origin` is the identity transformation.
//!
//! `auth_sha1_v4` authenticates every chunk with HMAC-SHA1 keyed by
//! `hmac_key = IV || cipher_key` (the cipher IV as sent in the clear,
//! concatenated with the stretched cipher key):
//!
//! ```text
//! Client -> server, first packet:
//!   data_len:  u32 LE, length of the first application chunk
//!   hmac1:     10 bytes = HMAC-SHA1(hmac_key, data_len)[..10]
//!   auth:      18 bytes = random[6] || utc_time u32 LE || client_id[4] || connection_id[4]
//!   hmac2:     10 bytes = HMAC-SHA1(hmac_key, auth)[..10]
//!   data:      the first application chunk
//! Client -> server, later chunks (pack_id starts at 1, ++ per chunk):
//!   data_len:  u16 LE
//!   hmac:      10 bytes = HMAC-SHA1(hmac_key, pack_id u32 LE || data_len u16 LE || data)[..10]
//!   data
//! Server -> client, chunks (recv_id starts at 1, ++ per chunk):
//!   data_len:  u16 LE
//!   hmac:      10 bytes = HMAC-SHA1(hmac_key, recv_id u32 LE || data_len u16 LE || data)[..10]
//!   data
//! ```
//!
//! `auth_aes128_md5` is the same shape with HMAC-MD5 (full 16-byte digests)
//! and the 18-byte auth block AES-128-CBC encrypted under `aes_key =
//! MD5(password)[..16]`:
//!
//! ```text
//! Client -> server, first packet:
//!   data_len:  u32 LE
//!   hmac1:     16 bytes = HMAC-MD5(hmac_key, data_len)
//!   iv:        16 random bytes
//!   enc_auth:  32 bytes = AES-128-CBC(aes_key, iv, PKCS#7(auth))
//!   hmac2:     16 bytes = HMAC-MD5(hmac_key, iv || enc_auth)
//!   data
//! Client -> server, later chunks (pack_id from 1):
//!   data_len:  u16 LE
//!   hmac:      16 bytes = HMAC-MD5(hmac_key, pack_id u32 LE || data_len u16 LE || data)
//!   data
//! Server -> client: same chunk shape with recv_id from 1.
//! ```
//!
//! Chunk payloads are fragmented at 32768 bytes so the u16 length always
//! fits.
//!
//! ## Verification status
//!
//! Client and server halves are loopback-tested against each other below.
//! Interoperation with third-party SSR implementations has NOT been tested
//! in this environment (no non-GPL reference peer is available); validate
//! the auth plugins against a real peer before relying on them in
//! production.

use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use rand::Rng;
use sha1::Sha1;

/// Largest application payload per framed chunk (u16 length must fit).
pub const MAX_CHUNK: usize = 32768;

/// One framed unit decoded from the stream, or the signal to read more.
pub enum Decode {
    /// Need at least this many bytes total before retrying.
    NeedMore(usize),
    /// A complete unit: (application payload, bytes consumed).
    Done(Vec<u8>, usize),
}

/// The protocol plugin in use. One value serves both directions: the client
/// uses `encode_first`/`encode_chunk` for C->S and `decode_reply` for S->C;
/// the server mirrors with `decode_first`/`decode_chunk` and
/// `encode_reply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plugin {
    Origin,
    AuthSha1V4,
    AuthAes128Md5,
}

fn hmac_sha1_10(key: &[u8], data: &[u8]) -> [u8; 10] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 takes any key");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    digest[..10].try_into().expect("10 of 20 bytes")
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC-MD5 takes any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// AES-128-CBC encryption with PKCS#7 padding, written over the `aes` crate
/// (no CBC crate is in the tree).
fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    use cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    let cipher = Aes128::new_from_slice(key).expect("16-byte key");
    let mut padded = plain.to_vec();
    let pad = 16 - (padded.len() % 16);
    padded.extend(std::iter::repeat(pad as u8).take(pad));
    let mut out = Vec::with_capacity(padded.len());
    let mut prev = *iv;
    for chunk in padded.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(&prev);
        for (b, c) in block.iter_mut().zip(chunk.iter()) {
            *b ^= *c;
        }
        cipher.encrypt_block(&mut block);
        let bytes: &[u8] = &block;
        prev = bytes.try_into().expect("16-byte block");
        out.extend_from_slice(bytes);
    }
    out
}

/// AES-128-CBC decryption with PKCS#7 validation. `None` on any padding or
/// length error (fail closed).
fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], cipher: &[u8]) -> Option<Vec<u8>> {
    use aes::Aes128;
    use cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    if cipher.len() % 16 != 0 || cipher.is_empty() {
        return None;
    }
    let cipher_impl = Aes128::new_from_slice(key).expect("16-byte key");
    let mut out = Vec::with_capacity(cipher.len());
    let mut prev = *iv;
    for chunk in cipher.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher_impl.decrypt_block(&mut block);
        let bytes: &[u8] = &block;
        for (b, p) in bytes.iter().zip(prev.iter()) {
            out.push(b ^ p);
        }
        prev = chunk.try_into().expect("16-byte chunk");
    }
    let pad = *out.last()? as usize;
    if pad == 0 || pad > 16 || out.len() < pad {
        return None;
    }
    if !out[out.len() - pad..].iter().all(|b| *b as usize == pad) {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

/// Shared per-connection protocol state. `pack_id`/`recv_id` count the
/// framed chunks this side has sent; the peer's counters are tracked
/// implicitly by verifying against the expected next value.
pub struct Session {
    plugin: Plugin,
    hmac_key: Vec<u8>,
    aes_key: Option<[u8; 16]>,
    /// Next chunk id this side will send (C->S uses pack_id, S->C recv_id).
    send_id: u32,
    /// Next chunk id this side expects to receive.
    recv_id: u32,
    /// First-packet auth already exchanged.
    authed: bool,
}

impl Session {
    /// `iv` is the cipher IV as sent in the clear, `cipher_key` the
    /// stretched cipher key, `password` the raw password (only needed for
    /// `auth_aes128_md5`'s AES key).
    pub fn new(plugin: Plugin, iv: &[u8], cipher_key: &[u8], password: &[u8]) -> Self {
        let mut hmac_key = Vec::with_capacity(iv.len() + cipher_key.len());
        hmac_key.extend_from_slice(iv);
        hmac_key.extend_from_slice(cipher_key);
        let aes_key = match plugin {
            Plugin::AuthAes128Md5 => {
                let mut hasher = Md5::new();
                hasher.update(password);
                let digest = hasher.finalize();
                Some(digest[..16].try_into().expect("16 of 16 bytes"))
            }
            _ => None,
        };
        Self {
            plugin,
            hmac_key,
            aes_key,
            send_id: 1,
            recv_id: 1,
            authed: false,
        }
    }

    /// Encode the first application chunk (client -> server). For `origin`
    /// this is the identity.
    pub fn encode_first(&mut self, data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
        match self.plugin {
            Plugin::Origin => data.to_vec(),
            Plugin::AuthSha1V4 => {
                let data_len = data.len().min(MAX_CHUNK);
                let data = &data[..data_len];
                let mut auth = [0u8; 18];
                rng.fill(&mut auth[..6]);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                auth[6..10].copy_from_slice(&now.to_le_bytes());
                rng.fill(&mut auth[10..14]); // client_id
                rng.fill(&mut auth[14..18]); // connection_id
                let len_bytes = (data.len() as u32).to_le_bytes();
                let hmac1 = hmac_sha1_10(&self.hmac_key, &len_bytes);
                let hmac2 = hmac_sha1_10(&self.hmac_key, &auth);
                let mut out = Vec::with_capacity(4 + 10 + 18 + 10 + data.len());
                out.extend_from_slice(&len_bytes);
                out.extend_from_slice(&hmac1);
                out.extend_from_slice(&auth);
                out.extend_from_slice(&hmac2);
                out.extend_from_slice(data);
                self.authed = true;
                out
            }
            Plugin::AuthAes128Md5 => {
                let data_len = data.len().min(MAX_CHUNK);
                let data = &data[..data_len];
                let mut auth = [0u8; 18];
                rng.fill(&mut auth[..6]);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                auth[6..10].copy_from_slice(&now.to_le_bytes());
                rng.fill(&mut auth[10..14]);
                rng.fill(&mut auth[14..18]);
                let aes_key = self.aes_key.expect("auth_aes128_md5 always sets aes_key");
                let mut iv = [0u8; 16];
                rng.fill(&mut iv);
                let enc_auth = aes128_cbc_encrypt(&aes_key, &iv, &auth);
                debug_assert_eq!(enc_auth.len(), 32);
                let len_bytes = (data.len() as u32).to_le_bytes();
                let hmac1 = hmac_md5(&self.hmac_key, &len_bytes);
                let mut hmac2_input = Vec::with_capacity(48);
                hmac2_input.extend_from_slice(&iv);
                hmac2_input.extend_from_slice(&enc_auth);
                let hmac2 = hmac_md5(&self.hmac_key, &hmac2_input);
                let mut out = Vec::with_capacity(4 + 16 + 16 + 32 + 16 + data.len());
                out.extend_from_slice(&len_bytes);
                out.extend_from_slice(&hmac1);
                out.extend_from_slice(&iv);
                out.extend_from_slice(&enc_auth);
                out.extend_from_slice(&hmac2);
                out.extend_from_slice(data);
                self.authed = true;
                out
            }
        }
    }

    /// Encode one later chunk (client -> server), fragmenting at MAX_CHUNK.
    /// Returns the framed bytes; callers loop until the input is consumed.
    pub fn encode_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        match self.plugin {
            Plugin::Origin => data.to_vec(),
            Plugin::AuthSha1V4 => {
                let data_len = data.len().min(MAX_CHUNK);
                let data = &data[..data_len];
                let len_bytes = (data.len() as u16).to_le_bytes();
                let id_bytes = self.send_id.to_le_bytes();
                let mut mac_input = Vec::with_capacity(4 + 2 + data.len());
                mac_input.extend_from_slice(&id_bytes);
                mac_input.extend_from_slice(&len_bytes);
                mac_input.extend_from_slice(data);
                let hmac = hmac_sha1_10(&self.hmac_key, &mac_input);
                self.send_id = self.send_id.wrapping_add(1);
                let mut out = Vec::with_capacity(2 + 10 + data.len());
                out.extend_from_slice(&len_bytes);
                out.extend_from_slice(&hmac);
                out.extend_from_slice(data);
                out
            }
            Plugin::AuthAes128Md5 => {
                let data_len = data.len().min(MAX_CHUNK);
                let data = &data[..data_len];
                let len_bytes = (data.len() as u16).to_le_bytes();
                let id_bytes = self.send_id.to_le_bytes();
                let mut mac_input = Vec::with_capacity(4 + 2 + data.len());
                mac_input.extend_from_slice(&id_bytes);
                mac_input.extend_from_slice(&len_bytes);
                mac_input.extend_from_slice(data);
                let hmac = hmac_md5(&self.hmac_key, &mac_input);
                self.send_id = self.send_id.wrapping_add(1);
                let mut out = Vec::with_capacity(2 + 16 + data.len());
                out.extend_from_slice(&len_bytes);
                out.extend_from_slice(&hmac);
                out.extend_from_slice(data);
                out
            }
        }
    }

    /// Encode one reply chunk (server -> client).
    pub fn encode_reply(&mut self, data: &[u8]) -> Vec<u8> {
        // The reply framing is identical to the chunk framing; only the
        // counter differs (recv_id on the sender's side).
        let id = self.send_id;
        self.send_id = self.send_id.wrapping_add(1);
        match self.plugin {
            Plugin::Origin => data.to_vec(),
            Plugin::AuthSha1V4 => {
                let data_len = data.len().min(MAX_CHUNK);
                let data = &data[..data_len];
                let len_bytes = (data.len() as u16).to_le_bytes();
                let mut mac_input = Vec::with_capacity(4 + 2 + data.len());
                mac_input.extend_from_slice(&id.to_le_bytes());
                mac_input.extend_from_slice(&len_bytes);
                mac_input.extend_from_slice(data);
                let hmac = hmac_sha1_10(&self.hmac_key, &mac_input);
                let mut out = Vec::with_capacity(2 + 10 + data.len());
                out.extend_from_slice(&len_bytes);
                out.extend_from_slice(&hmac);
                out.extend_from_slice(data);
                out
            }
            Plugin::AuthAes128Md5 => {
                let data_len = data.len().min(MAX_CHUNK);
                let data = &data[..data_len];
                let len_bytes = (data.len() as u16).to_le_bytes();
                let mut mac_input = Vec::with_capacity(4 + 2 + data.len());
                mac_input.extend_from_slice(&id.to_le_bytes());
                mac_input.extend_from_slice(&len_bytes);
                mac_input.extend_from_slice(data);
                let hmac = hmac_md5(&self.hmac_key, &mac_input);
                let mut out = Vec::with_capacity(2 + 16 + data.len());
                out.extend_from_slice(&len_bytes);
                out.extend_from_slice(&hmac);
                out.extend_from_slice(data);
                out
            }
        }
    }

    /// Decode the first packet (server side, client -> server).
    pub fn decode_first(&mut self, buf: &[u8]) -> Result<Decode, String> {
        match self.plugin {
            Plugin::Origin => Ok(Decode::Done(buf.to_vec(), buf.len())),
            Plugin::AuthSha1V4 => {
                const HEAD: usize = 4 + 10 + 18 + 10;
                if buf.len() < HEAD {
                    return Ok(Decode::NeedMore(HEAD));
                }
                let data_len = u32::from_le_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
                if data_len > MAX_CHUNK {
                    return Err("auth_sha1_v4: absurd first-chunk length".into());
                }
                if buf.len() < HEAD + data_len {
                    return Ok(Decode::NeedMore(HEAD + data_len));
                }
                if hmac_sha1_10(&self.hmac_key, &buf[..4])[..] != buf[4..14] {
                    return Err("auth_sha1_v4: first-packet length HMAC mismatch".into());
                }
                if hmac_sha1_10(&self.hmac_key, &buf[14..32])[..] != buf[32..42] {
                    return Err("auth_sha1_v4: first-packet auth HMAC mismatch".into());
                }
                self.authed = true;
                Ok(Decode::Done(
                    buf[HEAD..HEAD + data_len].to_vec(),
                    HEAD + data_len,
                ))
            }
            Plugin::AuthAes128Md5 => {
                const HEAD: usize = 4 + 16 + 16 + 32 + 16;
                if buf.len() < HEAD {
                    return Ok(Decode::NeedMore(HEAD));
                }
                let data_len = u32::from_le_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
                if data_len > MAX_CHUNK {
                    return Err("auth_aes128_md5: absurd first-chunk length".into());
                }
                if buf.len() < HEAD + data_len {
                    return Ok(Decode::NeedMore(HEAD + data_len));
                }
                if hmac_md5(&self.hmac_key, &buf[..4])[..] != buf[4..20] {
                    return Err("auth_aes128_md5: first-packet length HMAC mismatch".into());
                }
                let aes_key = self.aes_key.expect("auth_aes128_md5 always sets aes_key");
                let iv: [u8; 16] = buf[20..36].try_into().expect("16 bytes");
                let enc_auth = &buf[36..68];
                let mut hmac2_input = Vec::with_capacity(48);
                hmac2_input.extend_from_slice(&iv);
                hmac2_input.extend_from_slice(enc_auth);
                if hmac_md5(&self.hmac_key, &hmac2_input)[..] != buf[68..84] {
                    return Err("auth_aes128_md5: first-packet auth HMAC mismatch".into());
                }
                let auth = aes128_cbc_decrypt(&aes_key, &iv, enc_auth)
                    .ok_or_else(|| "auth_aes128_md5: auth block decrypt failed".to_string())?;
                if auth.len() != 18 {
                    return Err("auth_aes128_md5: auth block wrong length".into());
                }
                self.authed = true;
                Ok(Decode::Done(
                    buf[HEAD..HEAD + data_len].to_vec(),
                    HEAD + data_len,
                ))
            }
        }
    }

    /// Decode one later chunk (server side, client -> server).
    pub fn decode_chunk(&mut self, buf: &[u8]) -> Result<Decode, String> {
        self.decode_framed(buf, false)
    }

    /// Decode one reply chunk (client side, server -> client).
    pub fn decode_reply(&mut self, buf: &[u8]) -> Result<Decode, String> {
        self.decode_framed(buf, true)
    }

    fn decode_framed(&mut self, buf: &[u8], _reply: bool) -> Result<Decode, String> {
        // Both directions verify against this side's receive counter: the
        // sender's send_id starts at 1 exactly where the receiver's recv_id
        // starts, so one counter serves both.
        let (tag_len, name) = match self.plugin {
            Plugin::Origin => return Ok(Decode::Done(buf.to_vec(), buf.len())),
            Plugin::AuthSha1V4 => (10usize, "auth_sha1_v4"),
            Plugin::AuthAes128Md5 => (16usize, "auth_aes128_md5"),
        };
        let head = 2 + tag_len;
        if buf.len() < head {
            return Ok(Decode::NeedMore(head));
        }
        let data_len = u16::from_le_bytes(buf[..2].try_into().expect("2 bytes")) as usize;
        if data_len > MAX_CHUNK {
            return Err(format!("{name}: absurd chunk length"));
        }
        if buf.len() < head + data_len {
            return Ok(Decode::NeedMore(head + data_len));
        }
        let data = &buf[head..head + data_len];
        let mut mac_input = Vec::with_capacity(4 + 2 + data.len());
        mac_input.extend_from_slice(&self.recv_id.to_le_bytes());
        mac_input.extend_from_slice(&buf[..2]);
        mac_input.extend_from_slice(data);
        let ok = match self.plugin {
            Plugin::AuthSha1V4 => hmac_sha1_10(&self.hmac_key, &mac_input)[..] == buf[2..head],
            Plugin::AuthAes128Md5 => hmac_md5(&self.hmac_key, &mac_input)[..] == buf[2..head],
            Plugin::Origin => unreachable!(),
        };
        if !ok {
            return Err(format!("{name}: chunk HMAC mismatch"));
        }
        self.recv_id = self.recv_id.wrapping_add(1);
        Ok(Decode::Done(data.to_vec(), head + data_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_iv() -> (Vec<u8>, Vec<u8>) {
        (b"0123456789abcdef".to_vec(), b"iv-16-bytes----".to_vec())
    }

    #[test]
    fn origin_is_the_identity() {
        let (key, iv) = key_iv();
        let mut client = Session::new(Plugin::Origin, &iv, &key, b"pw");
        let mut server = Session::new(Plugin::Origin, &iv, &key, b"pw");
        let data = b"hello world";
        let encoded = client.encode_first(data, &mut rand::thread_rng());
        assert_eq!(encoded, data);
        match server.decode_first(&encoded).unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, data);
                assert_eq!(consumed, data.len());
            }
            _ => panic!("origin decodes immediately"),
        }
    }

    fn roundtrip(plugin: Plugin) {
        let (key, iv) = key_iv();
        let mut rng = rand::thread_rng();
        let mut client = Session::new(plugin, &iv, &key, b"password");
        let mut server = Session::new(plugin, &iv, &key, b"password");

        // More than one chunk worth, so chunking is exercised too.
        let first = vec![0xabu8; 100_000];
        let encoded = client.encode_first(&first, &mut rng);
        let first_take = first.len().min(MAX_CHUNK);
        match server.decode_first(&encoded).unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, first[..first_take], "{plugin:?} first packet");
                assert_eq!(
                    consumed,
                    encoded.len(),
                    "{plugin:?} first packet consumed whole"
                );
            }
            Decode::NeedMore(_) => panic!("{plugin:?}: first packet should be complete"),
        }
        let mut decoded = first[..first_take].to_vec();
        let mut rest = &first[first_take..];
        while !rest.is_empty() {
            let take = rest.len().min(MAX_CHUNK);
            let framed = client.encode_chunk(&rest[..take]);
            match server.decode_chunk(&framed).unwrap() {
                Decode::Done(payload, consumed) => {
                    assert_eq!(consumed, framed.len(), "{plugin:?} chunk consumed whole");
                    decoded.extend_from_slice(&payload);
                }
                Decode::NeedMore(_) => panic!("{plugin:?}: chunk should be complete"),
            }
            rest = &rest[take..];
        }
        assert_eq!(decoded, first, "{plugin:?} C->S roundtrip");

        // Partial reads: feed the first packet a byte at a time until it
        // completes; the framing must not misparse a prefix.
        let encoded = client.encode_first(b"partial", &mut rng);
        let mut server2 = Session::new(plugin, &iv, &key, b"password");
        let mut fed = 0;
        let payload = loop {
            fed += 1;
            match server2.decode_first(&encoded[..fed]).unwrap() {
                Decode::Done(payload, consumed) => {
                    assert_eq!(consumed, encoded.len());
                    break payload;
                }
                Decode::NeedMore(_) => {
                    assert!(fed < encoded.len(), "{plugin:?}: must complete eventually");
                }
            }
        };
        assert_eq!(payload, b"partial", "{plugin:?} partial-feed first packet");
    }

    #[test]
    fn auth_sha1_v4_roundtrips() {
        roundtrip(Plugin::AuthSha1V4);
    }

    #[test]
    fn auth_aes128_md5_roundtrips() {
        roundtrip(Plugin::AuthAes128Md5);
    }

    #[test]
    fn reply_direction_roundtrips() {
        for plugin in [Plugin::Origin, Plugin::AuthSha1V4, Plugin::AuthAes128Md5] {
            let (key, iv) = key_iv();
            let mut server = Session::new(plugin, &iv, &key, b"password");
            let mut client = Session::new(plugin, &iv, &key, b"password");
            let reply = b"HTTP/1.1 200 OK\r\n\r\nbody";
            let framed = server.encode_reply(reply);
            match client.decode_reply(&framed).unwrap() {
                Decode::Done(payload, consumed) => {
                    assert_eq!(payload, reply);
                    assert_eq!(consumed, framed.len());
                }
                _ => panic!("{plugin:?}: reply should decode"),
            }
        }
    }

    #[test]
    fn tampered_chunk_fails_closed() {
        let (key, iv) = key_iv();
        let mut client = Session::new(Plugin::AuthSha1V4, &iv, &key, b"password");
        let mut server = Session::new(Plugin::AuthSha1V4, &iv, &key, b"password");
        let first = client.encode_first(b"init", &mut rand::thread_rng());
        assert!(matches!(
            server.decode_first(&first).unwrap(),
            Decode::Done(_, _)
        ));
        let mut framed = client.encode_chunk(b"tamper me");
        framed[5] ^= 0xff;
        assert!(server.decode_chunk(&framed).is_err());
    }

    #[test]
    fn wrong_key_fails_first_packet_auth() {
        let (key, iv) = key_iv();
        let mut client = Session::new(Plugin::AuthSha1V4, &iv, &key, b"password");
        let mut server = Session::new(Plugin::AuthSha1V4, &iv, b"other-key-16byte", b"password");
        let first = client.encode_first(b"init", &mut rand::thread_rng());
        assert!(server.decode_first(&first).is_err());
    }

    #[test]
    fn need_more_signals_partial_reads() {
        let (key, iv) = key_iv();
        let mut client = Session::new(Plugin::AuthSha1V4, &iv, &key, b"password");
        let mut server = Session::new(Plugin::AuthSha1V4, &iv, &key, b"password");
        let first = client.encode_first(b"init", &mut rand::thread_rng());
        match server.decode_first(&first[..10]).unwrap() {
            Decode::NeedMore(_) => {}
            _ => panic!("short read must ask for more"),
        }
        // Feeding the rest completes the same packet.
        match server.decode_first(&first).unwrap() {
            Decode::Done(payload, consumed) => {
                assert_eq!(payload, b"init");
                assert_eq!(consumed, first.len());
            }
            _ => panic!("full read must decode"),
        }
    }

    #[test]
    fn aes128_cbc_roundtrips_with_padding() {
        let key = [0x33u8; 16];
        let iv = [0x44u8; 16];
        for len in [0, 1, 15, 16, 17, 18, 31, 32, 100] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let enc = aes128_cbc_encrypt(&key, &iv, &plain);
            assert_eq!(enc.len() % 16, 0);
            let dec = aes128_cbc_decrypt(&key, &iv, &enc).expect("decrypts");
            assert_eq!(dec, plain, "len {len}");
        }
    }

    #[test]
    fn aes128_cbc_rejects_bad_padding() {
        let key = [0x33u8; 16];
        let iv = [0x44u8; 16];
        let mut enc = aes128_cbc_encrypt(&key, &iv, b"hello");
        let last = enc.len() - 1;
        enc[last] ^= 0xff;
        assert!(aes128_cbc_decrypt(&key, &iv, &enc).is_none());
        assert!(aes128_cbc_decrypt(&key, &iv, &[0u8; 15]).is_none());
    }
}
