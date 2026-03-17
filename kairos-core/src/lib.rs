//! kairos-core — shared TOTP-derived port sequence logic.
//!
//! Both the client (`kairos`) and server daemon (`kairosd`) depend on this
//! crate for the single source of truth of the derivation algorithm.
//!
//! # Security properties
//!
//! - Secret bytes are always held in [`SecretKey`], a newtype wrapping
//!   [`zeroize::Zeroizing`].  Memory is overwritten with zeros the moment
//!   the value is dropped, preventing secrets from lingering in heap or
//!   stack memory after use.
//! - [`derive_sequence`] accepts a plain `&[u8]` slice so it composes with
//!   both owned and borrowed secrets without copying.
//! - No I/O, no networking — this crate is pure computation.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

// ── Constants ────────────────────────────────────────────────────────────────

/// Default time window length in seconds (matches common TOTP deployments).
pub const DEFAULT_WINDOW_SECS: u64 = 30;

/// Default number of ports in a knock sequence.
pub const DEFAULT_KNOCK_COUNT: usize = 4;

/// Maximum number of ports derivable from a single HMAC-SHA256 output.
/// 32 bytes / 2 bytes per port = 16 slots.
pub const MAX_KNOCK_COUNT: usize = 16;

/// Minimum port emitted (stay out of privileged range).
pub const PORT_MIN: u16 = 1024;

/// Number of ports in the unprivileged range [1024, 65535].
const PORT_RANGE: u16 = 64512; // 65535 - 1024 + 1

// ── SecretKey ─────────────────────────────────────────────────────────────────

/// A zeroizing wrapper around a decoded HMAC key.
///
/// The inner bytes are overwritten with zeros as soon as this value is
/// dropped, regardless of how the drop is triggered (normal scope exit,
/// panic, or early return).
///
/// # Example
/// ```rust
/// use kairos_core::SecretKey;
///
/// let key = SecretKey::from_hex("deadbeef").unwrap();
/// // key.as_bytes() available for HMAC operations
/// // Zeros written to memory when `key` goes out of scope.
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Zeroizing<Vec<u8>>);

impl SecretKey {
    /// Decode from a lowercase hex string or plain passphrase.
    pub fn from_hex_or_passphrase(input: &str) -> Result<Self, hex::FromHexError> {
        decode_secret(input).map(|v| Self(Zeroizing::new(v)))
    }

    /// Decode from a hex string only.
    pub fn from_hex(input: &str) -> Result<Self, hex::FromHexError> {
        hex::decode(input.trim()).map(|v| Self(Zeroizing::new(v)))
    }

    /// Wrap raw bytes (e.g. already-loaded from a file).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw key bytes for use in HMAC operations.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

// ── Core derivation ──────────────────────────────────────────────────────────

/// Derive a knock sequence from a shared secret and a time-window counter.
///
/// # Algorithm
/// ```text
/// mac   = HMAC-SHA256(secret, window as u64 big-endian)
/// ports = mac[0 .. 2*count]
///             .chunks(2)
///             .map(|b| PORT_MIN + u16::from_be_bytes(b) % PORT_RANGE)
/// ```
///
/// The intermediate HMAC digest is held in a `Zeroizing` buffer and zeroed
/// after the ports are extracted.
///
/// # Panics
///
/// Panics if `count > MAX_KNOCK_COUNT` (16).  Callers **must** validate
/// `count` before calling this function — typically by checking the
/// configuration value at startup.  Passing a value obtained from
/// untrusted input without validation will cause a hard abort.
pub fn derive_sequence(secret: &[u8], window: u64, count: usize) -> Vec<u16> {
    assert!(
        count <= MAX_KNOCK_COUNT,
        "count {count} exceeds MAX_KNOCK_COUNT ({MAX_KNOCK_COUNT})"
    );

    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&window.to_be_bytes());

    // Hold the digest in a Zeroizing buffer so it is wiped after use.
    let digest: Zeroizing<Vec<u8>> =
        Zeroizing::new(mac.finalize().into_bytes().to_vec());

    digest
        .chunks_exact(2)
        .take(count)
        .map(|chunk| {
            let raw = u16::from_be_bytes([chunk[0], chunk[1]]);
            PORT_MIN + (raw % PORT_RANGE)
        })
        .collect()
}

// ── Time helpers ─────────────────────────────────────────────────────────────

/// Return the current time-window counter for a given window length.
pub fn current_window(window_secs: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
        / window_secs
}

/// Return an iterator over `[T-skew, T+skew]` (inclusive) to tolerate clock
/// drift, mirroring RFC 6238 §5.2.
pub fn windows_with_skew(window_secs: u64, skew: u64) -> impl Iterator<Item = u64> {
    let t = current_window(window_secs);
    t.saturating_sub(skew)..=t.saturating_add(skew)
}

// ── Decode helper (pub for config crates) ────────────────────────────────────

/// Decode a secret from either a lowercase hex string or a raw passphrase.
///
/// Returns a plain `Vec<u8>`; callers that need zeroize-on-drop semantics
/// should wrap the result in [`SecretKey::from_bytes`].
pub fn decode_secret(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let trimmed = input.trim();
    if trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed)
    } else {
        Ok(trimmed.as_bytes().to_vec())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_deterministic() {
        let a = derive_sequence(b"hunter2", 99_999, 4);
        let b = derive_sequence(b"hunter2", 99_999, 4);
        assert_eq!(a, b);
    }

    #[test]
    fn different_windows_produce_different_sequences() {
        let a = derive_sequence(b"secret", 1000, 4);
        let b = derive_sequence(b"secret", 1001, 4);
        assert_ne!(a, b);
    }

    #[test]
    fn different_secrets_produce_different_sequences() {
        let a = derive_sequence(b"alice-secret", 42, 4);
        let b = derive_sequence(b"bob-secret", 42, 4);
        assert_ne!(a, b);
    }

    #[test]
    fn all_ports_in_unprivileged_range() {
        for window in 0..50 {
            for port in derive_sequence(b"range-test", window, MAX_KNOCK_COUNT) {
                assert!(port >= PORT_MIN, "port {port} below PORT_MIN");
                assert!(port <= 65535);
            }
        }
    }

    #[test]
    fn windows_with_skew_spans_correct_range() {
        let skew = 2u64;
        let windows: Vec<u64> = windows_with_skew(30, skew).collect();
        assert_eq!(windows.len(), 2 * skew as usize + 1);
    }

    #[test]
    fn hex_decoding() {
        let raw = decode_secret("deadbeef").unwrap();
        assert_eq!(raw, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn passphrase_decoding() {
        let raw = decode_secret("  my secret phrase  ").unwrap();
        assert_eq!(raw, b"my secret phrase");
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let k = SecretKey::from_bytes(vec![0xde, 0xad]);
        assert_eq!(format!("{k:?}"), "SecretKey([redacted])");
    }

    #[test]
    fn secret_key_derives_same_sequence() {
        let key = SecretKey::from_bytes(b"test-key".to_vec());
        let direct = derive_sequence(b"test-key", 42, 4);
        let via_key = derive_sequence(key.as_bytes(), 42, 4);
        assert_eq!(direct, via_key);
    }
}
