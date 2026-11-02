//! ShadowsocksR stream-cipher methods: `aes-256-cfb`, `aes-128-cfb`,
//! `rc4-md5`, `chacha20-ietf`.
//!
//! Clean-room basis: the public Shadowsocks stream-cipher specification
//! (passwords are stretched with OpenSSL's `EVP_BytesToKey`, a TCP stream is
//! `[IV][encrypted payload]` with the IV sent in the clear) and the published
//! cipher definitions themselves. AES-CFB128 follows NIST SP 800-38A: the
//! `aes` crate owns the block function (with its own NIST vectors upstream)
//! and this module owns the CFB chaining, verified against the NIST ECB
//! vectors (see tests). RC4 is implemented from the cipher's public
//! definition and checked against the canonical published test vector.
//! ChaCha20 uses the `chacha20` crate (MIT/Apache-2.0, on the workspace
//! allow-list); the nonce construction (IV || 0x00000000, counter 0) is
//! pinned by a construction test. No GPL-licensed implementation was
//! consulted.
//!
//! Anything outside the four methods above is refused by the config layer
//! (`zero_config::SsrMethod::parse` returns `None`) before this module is
//! ever constructed.

use aes::{Aes128, Aes256};
use chacha20::ChaCha20;
use cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher as _};
use md5::{Digest as _, Md5};
use rand::Rng;

/// The SSR stream methods this module implements. Mirrors
/// `zero_config::SsrMethod`; the runtime maps between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes256Cfb,
    Aes128Cfb,
    Rc4Md5,
    Chacha20Ietf,
}

impl Method {
    /// Cipher key length in bytes, after `EVP_BytesToKey` stretching.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes256Cfb => 32,
            Self::Aes128Cfb => 16,
            Self::Rc4Md5 => 16,
            Self::Chacha20Ietf => 32,
        }
    }

    /// IV bytes sent in the clear at the start of the stream. `chacha20-ietf`
    /// sends 8 IV bytes; the 12-byte ChaCha nonce is the IV followed by four
    /// zero bytes, per the public stream-cipher specification.
    pub fn iv_len(self) -> usize {
        match self {
            Self::Aes256Cfb | Self::Aes128Cfb | Self::Rc4Md5 => 16,
            Self::Chacha20Ietf => 8,
        }
    }
}

/// OpenSSL `EVP_BytesToKey` with MD5, no salt, one iteration — the password
/// stretching the Shadowsocks stream-cipher specification prescribes:
/// `D_1 = MD5(password)`, `D_i = MD5(D_{i-1} || password)`, concatenated and
/// truncated to the wanted length.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        let digest = hasher.finalize();
        previous = digest.to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

/// RC4 (KSA + PRGA), written from the public algorithm description. Used
/// only through `rc4-md5`, which re-keys it per stream (see below).
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        debug_assert!(!key.is_empty());
        let mut s = [0u8; 256];
        for (index, slot) in s.iter_mut().enumerate() {
            *slot = index as u8;
        }
        let mut j = 0u8;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

/// AES-CFB128 as a continuous byte-stream cipher, matching NIST SP 800-38A.
///
/// CFB128 encrypts a stream as `C[i] = P[i] XOR E_k(C[i-16..i])` with
/// `C[-16..0] = IV`: the keystream block boundaries are stream offsets,
/// NOT the caller's `apply` chunk boundaries. The state therefore keeps
/// the in-progress keystream block (`ks`, `pos`) and the ciphertext bytes
/// accumulating toward the next feedback block (`next_fb`) across calls,
/// so the peer can encrypt and decrypt in differently-sized chunks (TCP
/// segmentation) and still agree on the keystream.
struct Cfb<C: BlockEncrypt> {
    cipher: C,
    /// Last complete 16-byte ciphertext block (the feedback register).
    /// Only meaningful when `pos == 16`; `next_fb` doubles as the IV
    /// before the first block.
    feedback: [u8; 16],
    /// Current keystream block `E_k(feedback)`.
    ks: [u8; 16],
    /// Keystream bytes consumed from `ks`; 16 means "generate the next
    /// block". Always equals the number of valid bytes in `next_fb`.
    pos: u8,
    /// Ciphertext bytes since the last feedback rotation (the IV for the
    /// first block).
    next_fb: [u8; 16],
}

impl<C: BlockEncrypt> Cfb<C> {
    fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Self {
            cipher,
            feedback: [0u8; 16],
            ks: [0u8; 16],
            pos: 16,
            next_fb: *iv,
        }
    }

    /// Rotate the feedback register and generate the next keystream block.
    /// Requires `pos == 16`, i.e. `next_fb` holds a complete block.
    fn next_block(&mut self) {
        debug_assert_eq!(self.pos, 16);
        self.feedback = self.next_fb;
        let mut block = GenericArray::clone_from_slice(&self.feedback);
        self.cipher.encrypt_block(&mut block);
        self.ks.copy_from_slice(&block);
        self.pos = 0;
    }

    fn apply_byte(&mut self, byte: &mut u8, encrypt: bool) {
        if self.pos == 16 {
            self.next_block();
        }
        let k = self.ks[self.pos as usize];
        if encrypt {
            *byte ^= k;
            self.next_fb[self.pos as usize] = *byte; // ciphertext out
        } else {
            self.next_fb[self.pos as usize] = *byte; // ciphertext in
            *byte ^= k;
        }
        self.pos += 1;
    }

    fn apply(&mut self, data: &mut [u8], encrypt: bool) {
        let mut off = 0;
        // Drain a partially-consumed keystream block first.
        while off < data.len() && self.pos < 16 {
            self.apply_byte(&mut data[off], encrypt);
            off += 1;
        }
        // Fast path: whole blocks straight off the keystream.
        while off + 16 <= data.len() {
            debug_assert_eq!(self.pos, 16);
            self.next_block();
            let ks: &[u8] = &self.ks;
            if encrypt {
                for i in 0..16 {
                    data[off + i] ^= ks[i];
                    self.next_fb[i] = data[off + i];
                }
            } else {
                for i in 0..16 {
                    self.next_fb[i] = data[off + i];
                    data[off + i] ^= ks[i];
                }
            }
            self.pos = 16;
            off += 16;
        }
        // Tail partial block.
        while off < data.len() {
            self.apply_byte(&mut data[off], encrypt);
            off += 1;
        }
    }
}

enum CipherState {
    Aes128(Cfb<Aes128>),
    Aes256(Cfb<Aes256>),
    Rc4(Rc4),
    ChaCha20(ChaCha20),
}

/// One direction of an SSR stream cipher: stateful, in-place, symmetric
/// (stream ciphers encrypt and decrypt with the same operation).
pub struct StreamCipher {
    state: CipherState,
}

impl StreamCipher {
    /// Client side: stretches the password, generates a random IV and
    /// returns the cipher plus the IV bytes to send in the clear first.
    pub fn new_client(
        method: Method,
        password: &[u8],
        rng: &mut impl Rng,
    ) -> Result<(Self, Vec<u8>), String> {
        let mut iv = vec![0u8; method.iv_len()];
        rng.fill(iv.as_mut_slice());
        let cipher = Self::with_iv(method, password, &iv)?;
        Ok((cipher, iv))
    }

    /// Server side: the IV was read from the wire in the clear.
    pub fn with_iv(method: Method, password: &[u8], iv: &[u8]) -> Result<Self, String> {
        if iv.len() != method.iv_len() {
            return Err(format!(
                "SSR {:?}: wrong IV length {}, want {}",
                method,
                iv.len(),
                method.iv_len()
            ));
        }
        let key = evp_bytes_to_key(password, method.key_len());
        let state = match method {
            Method::Aes128Cfb => {
                let mut feedback = [0u8; 16];
                feedback.copy_from_slice(iv);
                let cipher = Aes128::new_from_slice(&key).expect("16-byte AES-128 key");
                CipherState::Aes128(Cfb::new(cipher, &feedback))
            }
            Method::Aes256Cfb => {
                let mut feedback = [0u8; 16];
                feedback.copy_from_slice(iv);
                let cipher = Aes256::new_from_slice(&key).expect("32-byte AES-256 key");
                CipherState::Aes256(Cfb::new(cipher, &feedback))
            }
            Method::Rc4Md5 => {
                // rc4-md5 re-keys RC4 per stream: MD5(stretched key || IV).
                let mut hasher = Md5::new();
                hasher.update(&key);
                hasher.update(iv);
                let rc4_key = hasher.finalize();
                CipherState::Rc4(Rc4::new(&rc4_key))
            }
            Method::Chacha20Ietf => {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(iv);
                let cipher = ChaCha20::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&nonce_bytes[..]),
                );
                CipherState::ChaCha20(cipher)
            }
        };
        Ok(Self { state })
    }

    /// Transform bytes in place. `encrypt` selects the direction: for the
    /// true stream ciphers (RC4, ChaCha20) the operation is symmetric, but
    /// AES-CFB feeds ciphertext back into the register, so decryption must
    /// capture the input bytes, not the output.
    pub fn apply(&mut self, data: &mut [u8], encrypt: bool) {
        match &mut self.state {
            CipherState::Aes128(cfb) => cfb.apply(data, encrypt),
            CipherState::Aes256(cfb) => cfb.apply(data, encrypt),
            CipherState::Rc4(rc4) => rc4.apply(data),
            CipherState::ChaCha20(cipher) => cipher.apply_keystream(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_bytes_to_key_matches_md5_of_password_for_16_bytes() {
        // MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99 (public digest).
        let key = evp_bytes_to_key(b"password", 16);
        let mut hasher = Md5::new();
        hasher.update(b"password");
        assert_eq!(key, hasher.finalize().as_slice());
    }

    #[test]
    fn evp_bytes_to_key_chains_md5_for_longer_keys() {
        let key = evp_bytes_to_key(b"password", 32);
        assert_eq!(key.len(), 32);
        // First block is MD5(password); the second is MD5(first || password).
        let mut first = Md5::new();
        first.update(b"password");
        let first = first.finalize();
        assert_eq!(&key[..16], first.as_slice());
        let mut second = Md5::new();
        second.update(first.as_slice());
        second.update(b"password");
        assert_eq!(&key[16..], second.finalize().as_slice());
    }

    /// Known-answer check for the CFB feedback logic, derived from the NIST
    /// SP 800-38A F.1.1 AES-128 ECB vector rather than from memory of a CFB
    /// vector: with the IV set to the F.1.1 plaintext
    /// (`6bc1bee22e409f96e93d7e117393172a`), the first CFB keystream block
    /// is `E_k(IV)`, which the ECB vector pins to
    /// `3ad77bb40d7a3660a89ecaf32466ef97`. Encrypting 16 zero bytes must
    /// therefore reproduce the ECB ciphertext exactly. This isolates the
    /// part we wrote (the CFB chaining) from the part the `aes` crate owns
    /// (the block function, which carries its own NIST vectors upstream).
    #[test]
    fn aes_128_cfb_keystream_matches_nist_ecb_vector() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv: [u8; 16] = hex::decode("6bc1bee22e409f96e93d7e117393172a")
            .unwrap()
            .try_into()
            .unwrap();
        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut cfb = Cfb::new(cipher, &iv);
        let mut data = vec![0u8; 16];
        cfb.apply(&mut data, true);
        assert_eq!(hex::encode(&data), "3ad77bb40d7a3660a89ecaf32466ef97");
    }

    /// Same construction for AES-256 via the F.1.3 ECB vector. The key
    /// (`603d...14dff4`) is the published F.1.3/FIPS-197 key — verified
    /// against the `aes` crate's own key-expansion test data — and the
    /// expected first keystream block `f3eed1bdb5d2a03c064b5a7e3db181f8`
    /// is the published F.1.3 ciphertext, independently reproduced here
    /// with the local OpenSSL AES-256-ECB as a black-box oracle.
    #[test]
    fn aes_256_cfb_keystream_matches_nist_ecb_vector() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv: [u8; 16] = hex::decode("6bc1bee22e409f96e93d7e117393172a")
            .unwrap()
            .try_into()
            .unwrap();
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut cfb = Cfb::new(cipher, &iv);
        let mut data = vec![0u8; 16];
        cfb.apply(&mut data, true);
        assert_eq!(hex::encode(&data), "f3eed1bdb5d2a03c064b5a7e3db181f8");
    }

    /// Multi-block encrypt/decrypt symmetry through the public API: the
    /// decryptor replays the ciphertext feedback register.
    #[test]
    fn aes_cfb_encrypt_decrypt_are_inverse() {
        for method in [Method::Aes128Cfb, Method::Aes256Cfb] {
            let password = b"cfb symmetry probe";
            let iv = vec![0x11u8; method.iv_len()];
            let mut enc = StreamCipher::with_iv(method, password, &iv).unwrap();
            let mut dec = StreamCipher::with_iv(method, password, &iv).unwrap();
            let plain: Vec<u8> = (0u8..100).collect();
            let mut ct = plain.clone();
            enc.apply(&mut ct, true);
            assert_ne!(ct, plain);
            dec.apply(&mut ct, false);
            assert_eq!(ct, plain, "{method:?} roundtrip");
        }
    }

    /// The keystream must not depend on the caller's chunk boundaries: a
    /// peer doing TCP segmentation decrypts in different chunk sizes than
    /// the sender encrypted with. This is the regression test for
    /// per-`apply` chunk re-alignment.
    #[test]
    fn aes_cfb_keystream_is_chunk_boundary_independent() {
        for method in [Method::Aes128Cfb, Method::Aes256Cfb] {
            let password = b"chunk boundary probe";
            let iv = vec![0x22u8; method.iv_len()];
            let plain: Vec<u8> = (0u8..200).map(|b| b.wrapping_mul(7)).collect();

            // Encrypt in odd-sized chunks.
            let mut enc = StreamCipher::with_iv(method, password, &iv).unwrap();
            let mut ct = Vec::new();
            for chunk in plain.chunks(7) {
                let mut c = chunk.to_vec();
                enc.apply(&mut c, true);
                ct.extend_from_slice(&c);
            }

            // Decrypt in different odd-sized chunks, including byte-at-a-time.
            let mut dec = StreamCipher::with_iv(method, password, &iv).unwrap();
            let mut got = Vec::new();
            for chunk in ct.chunks(13) {
                let mut p = chunk.to_vec();
                dec.apply(&mut p, false);
                got.extend_from_slice(&p);
            }
            assert_eq!(got, plain, "{method:?} chunk-boundary independence");

            // And byte-at-a-time both ways.
            let mut enc = StreamCipher::with_iv(method, password, &iv).unwrap();
            let mut dec = StreamCipher::with_iv(method, password, &iv).unwrap();
            let mut ct1 = plain.clone();
            for b in ct1.iter_mut() {
                enc.apply(std::slice::from_mut(b), true);
            }
            for b in ct1.iter_mut() {
                dec.apply(std::slice::from_mut(b), false);
            }
            assert_eq!(ct1, plain, "{method:?} byte-at-a-time roundtrip");
        }
    }

    #[test]
    fn aes_cfb_handles_short_final_blocks() {
        for method in [Method::Aes128Cfb, Method::Aes256Cfb] {
            let password = b"short block probe";
            let iv = vec![0x11u8; method.iv_len()];
            let mut enc = StreamCipher::with_iv(method, password, &iv).unwrap();
            let mut dec = StreamCipher::with_iv(method, password, &iv).unwrap();
            let plain: Vec<u8> = (0..100u8).collect();
            let mut data = plain.clone();
            enc.apply(&mut data, true);
            assert_ne!(data, plain);
            dec.apply(&mut data, false);
            assert_eq!(data, plain, "{method:?} short final block roundtrip");
        }
    }

    #[test]
    fn rc4_matches_published_test_vector() {
        // The canonical RC4 test vector (key "Key", plaintext "Plaintext"):
        // ciphertext BBF316E8D940AF0AD3. Published in the original RC4
        // documentation and reproduced widely; no GPL source involved.
        let mut rc4 = Rc4::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        rc4.apply(&mut data);
        assert_eq!(hex::encode(&data), "bbf316e8d940af0ad3");
        // And decrypting returns the plaintext (XOR symmetry).
        let mut rc4 = Rc4::new(b"Key");
        rc4.apply(&mut data);
        assert_eq!(data, b"Plaintext");
    }

    #[test]
    fn rc4_keystream_is_position_dependent() {
        let key = b"test key";
        let mut a = Rc4::new(key);
        let mut b = Rc4::new(key);
        let (mut x, mut y) = (vec![0u8; 64], vec![0u8; 64]);
        a.apply(&mut x);
        b.apply(&mut y[..32]);
        b.apply(&mut y[32..]);
        assert_eq!(x, y, "split applies continue the stream");
    }

    #[test]
    fn chacha20_ietf_nonce_is_iv_followed_by_zeros_starting_at_counter_zero() {
        // Pins the documented wire construction: the 8 clear IV bytes are
        // the first 8 bytes of the 12-byte ChaCha nonce, the last 4 are
        // zero, and the block counter starts at 0. The ChaCha20 block
        // function itself is the `chacha20` crate's responsibility (it
        // carries its own RFC 8439 vectors upstream).
        let password = b"nonce construction probe";
        let iv = [0x42u8; 8];
        let key = evp_bytes_to_key(password, 32);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&iv);
        let mut expected = ChaCha20::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce_bytes[..]),
        );
        let mut want = vec![0u8; 200];
        expected.apply_keystream(&mut want);

        let mut cipher = StreamCipher::with_iv(Method::Chacha20Ietf, password, &iv)
            .expect("chacha20-ietf builds");
        let mut got = vec![0u8; 200];
        cipher.apply(&mut got, true);
        assert_eq!(got, want);
    }

    #[test]
    fn every_method_roundtrips_through_client_and_server_halves() {
        let mut rng = rand::thread_rng();
        for method in [
            Method::Aes256Cfb,
            Method::Aes128Cfb,
            Method::Rc4Md5,
            Method::Chacha20Ietf,
        ] {
            let (mut client, iv) = StreamCipher::new_client(method, b"correct horse", &mut rng)
                .expect("client cipher builds");
            let mut server =
                StreamCipher::with_iv(method, b"correct horse", &iv).expect("server cipher builds");
            // Split writes continue the keystream: the cipher is a stream.
            let mut first = b"hello, ".to_vec();
            let mut second = b"shadowsocksr world".to_vec();
            client.apply(&mut first, true);
            client.apply(&mut second, true);
            server.apply(&mut first, false);
            server.apply(&mut second, false);
            assert_eq!(first, b"hello, ", "{method:?} first chunk");
            assert_eq!(second, b"shadowsocksr world", "{method:?} second chunk");
        }
    }

    #[test]
    fn wrong_password_does_not_decrypt() {
        let mut rng = rand::thread_rng();
        let (mut client, iv) = StreamCipher::new_client(Method::Aes256Cfb, b"right", &mut rng)
            .expect("client cipher builds");
        let mut server =
            StreamCipher::with_iv(Method::Aes256Cfb, b"wrong", &iv).expect("server cipher builds");
        let mut data = b"secret".to_vec();
        client.apply(&mut data, true);
        server.apply(&mut data, false);
        assert_ne!(data, b"secret");
    }

    #[test]
    fn wrong_iv_length_is_refused() {
        assert!(StreamCipher::with_iv(Method::Aes256Cfb, b"pw", &[0u8; 8]).is_err());
        assert!(StreamCipher::with_iv(Method::Chacha20Ietf, b"pw", &[0u8; 16]).is_err());
    }
}
