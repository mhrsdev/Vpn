//! ShadowsocksR server side: the accept facade the runtime's inbound
//! loop drives.
//!
//! Each accepted TCP stream goes through [`Acceptor::accept`], which runs
//! the obfs hello, the cipher IV split and the protocol auth packet, and
//! hands back a framed [`SsrStream`](super::stream::SsrStream) plus the
//! target destination. Afterwards the stream is an ordinary
//! [`AsyncRead`](tokio::io::AsyncRead)/[`AsyncWrite`](tokio::io::AsyncWrite)
//! byte stream the runtime relays like any other inbound.

use tokio::io::{AsyncRead, AsyncWrite};
use zero_core::Destination;

use super::method::Method;
use super::obfs;
use super::protocol;
use super::stream::{ServerConfig, SsrStream};

/// Map a config method name to the cipher. Anything outside the honest
/// subset is refused here, before any network I/O.
pub fn parse_method(name: &str) -> Result<Method, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "aes-256-cfb" => Ok(Method::Aes256Cfb),
        "aes-128-cfb" => Ok(Method::Aes128Cfb),
        "rc4-md5" => Ok(Method::Rc4Md5),
        "chacha20-ietf" => Ok(Method::Chacha20Ietf),
        other => Err(format!("SSR: unsupported method {other:?}")),
    }
}

/// Map a config protocol-plugin name. Anything outside the honest subset
/// is refused here.
pub fn parse_protocol(name: &str) -> Result<protocol::Plugin, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "" | "origin" => Ok(protocol::Plugin::Origin),
        "auth_sha1_v4" => Ok(protocol::Plugin::AuthSha1V4),
        "auth_aes128_md5" => Ok(protocol::Plugin::AuthAes128Md5),
        other => Err(format!("SSR: unsupported protocol plugin {other:?}")),
    }
}

/// Map a config obfs-plugin name. Anything outside the honest subset is
/// refused here.
pub fn parse_obfs(name: &str) -> Result<obfs::Plugin, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "" | "plain" => Ok(obfs::Plugin::Plain),
        "http_simple" => Ok(obfs::Plugin::HttpSimple),
        "tls1.2_ticket_auth" => Ok(obfs::Plugin::Tls12TicketAuth),
        other => Err(format!("SSR: unsupported obfs plugin {other:?}")),
    }
}

/// A bound SSR inbound: validates the config once, then accepts
/// connections.
pub struct Acceptor {
    config: ServerConfig,
}

impl Acceptor {
    /// Build from validated parts; refuses anything outside the subset.
    pub fn new(method: &str, password: &str, protocol: &str, obfs: &str) -> Result<Self, String> {
        if password.is_empty() {
            return Err("SSR: empty password".into());
        }
        Ok(Self {
            config: ServerConfig {
                method: parse_method(method)?,
                password: password.into(),
                protocol: parse_protocol(protocol)?,
                obfs: parse_obfs(obfs)?,
            },
        })
    }

    /// Accept one TCP stream: obfs hello, cipher IV, protocol auth.
    /// Returns the framed stream and the target destination.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<(SsrStream<S>, Destination), String> {
        SsrStream::accept(stream, &self.config).await
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_subset_names_are_refused_before_any_io() {
        assert!(parse_method("aes-256-gcm").is_err());
        assert!(parse_method("chacha20").is_err());
        assert!(parse_protocol("auth_chain_a").is_err());
        assert!(parse_protocol("verify_sha1").is_err());
        assert!(parse_obfs("http_post").is_err());
        assert!(parse_obfs("random_head").is_err());
        assert!(Acceptor::new("aes-256-cfb", "", "origin", "plain").is_err());
        // The subset itself parses.
        assert!(Acceptor::new("rc4-md5", "pw", "auth_sha1_v4", "tls1.2_ticket_auth").is_ok());
    }
}
