//! Secret-bearing types with redacting `Debug` impls.
//!
//! Pattern: the repo's `job.rs:78` `InstallArgs` redacting-Debug. Any struct
//! that carries a token, password, key, or other credential wraps it in
//! [`SecretString`] (or [`SecretBytes`]) so `format!("{:?}", …)` can never
//! leak it into logs. There are tests asserting this for every secret struct.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string that is never shown in `Debug` output and is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrow the secret. Callers must not log or persist it carelessly.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time: do NOT repeat api.rs:122's `!=` pattern.
        bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }
}

impl Eq for SecretString {}

/// Byte secret with redacting `Debug` and zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_debug_redacts() {
        let s = SecretString::new("super-secret-token-123".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret-token-123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn secret_bytes_debug_redacts() {
        let s = SecretBytes::new(b"key-material".to_vec());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("key-material"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn secret_eq_is_constant_time_equal() {
        let a = SecretString::new("abc".to_string());
        let b = SecretString::new("abc".to_string());
        let c = SecretString::new("abd".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Different lengths must not compare equal.
        let d = SecretString::new("abcd".to_string());
        assert_ne!(a, d);
    }
}
