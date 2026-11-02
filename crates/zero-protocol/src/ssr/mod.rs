//! ShadowsocksR (subset): stream-cipher methods, protocol plugins and
//! obfuscation plugins with symmetric client and server halves.
//!
//! ## Clean-room statement
//!
//! This module was implemented strictly from the public ShadowsocksR
//! protocol specification and the public cipher specifications it builds
//! on (Shadowsocks stream ciphers, NIST SP 800-38A, RFC 6229, RFC 8439).
//! No GPL-licensed implementation (including the reference
//! implementations and sing-box) was read or consulted at any point.
//! Known-answer tests are drawn from public standards documents, and the
//! client/server halves are verified against each other in loopback
//! tests, never against GPL-derived vectors.
//!
//! ## Honest subset
//!
//! Methods: `aes-256-cfb`, `aes-128-cfb`, `rc4-md5`, `chacha20-ietf`.
//! Protocol plugins: `origin`, `auth_sha1_v4`, `auth_aes128_md5`.
//! Obfuscation plugins: `plain`, `http_simple`, `tls1.2_ticket_auth`.
//!
//! Anything else is refused at config-compile time with an explicit
//! "unsupported" error — see [`server::Acceptor::new`] and
//! `zero_config::SsrMethod`/`SsrProtocol`/`SsrObfs`.
//!
//! ## Layering
//!
//! ```text
//! app -> protocol.encode -> cipher.encrypt -> obfs.encode -> TCP
//! TCP -> obfs.decode -> cipher.decrypt -> protocol.decode -> app
//! ```
//!
//! ## Verification status
//!
//! The auth and obfs wire formats follow the public specification as
//! documented in [`protocol`] and [`obfs`]. Loopback client<->server tests
//! cover every (method x protocol x obfs) combination in the subset.
//! Interoperation with third-party SSR implementations has NOT been
//! tested here (no non-GPL reference peer is available in this
//! environment); validate against a real peer before production use.

pub mod method;
pub mod obfs;
pub mod protocol;
pub mod server;
pub mod stream;

pub use method::Method;
pub use obfs::Plugin as ObfsPlugin;
pub use protocol::Plugin as ProtocolPlugin;
pub use server::Acceptor;
pub use stream::{ClientConfig, ServerConfig, SsrStream};
