//! Validated Arweave transaction-ID newtype (SEC-21).
//!
//! An Arweave transaction ID is base64url (RFC 4648 §5, no padding):
//! `A-Z`, `a-z`, `0-9`, `-`, `_`. A real tx ID is exactly 43 characters
//! (a 32-byte digest), but qub also mints 7-character base62 short
//! codes and accepts either on its `/c/:tx_id` and `/s/:code` routes —
//! so [`TxId`] admits `1..=64` characters of the base64url alphabet,
//! matching the Worker's `^[A-Za-z0-9_-]{1,64}$` (`TX_ID_PATTERN`).
//!
//! Construction is validated: a `TxId` cannot hold a value that would
//! be rejected when interpolated into a request path, so callers (the
//! SPA, `qub-mcp`, any future Rust signer) share one rule instead of
//! re-deriving the regex.

use thiserror::Error;

/// A validated Arweave transaction ID or qub short code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxId(String);

/// Error returned by [`TxId::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TxIdError {
    /// The string was empty or longer than 64 characters.
    #[error("tx_id length out of range (1..=64), got {0}")]
    BadLength(usize),
    /// The string contained a character outside `[A-Za-z0-9_-]`.
    #[error("tx_id contains a character outside the base64url alphabet")]
    BadCharacter,
}

impl TxId {
    /// Parse and validate a tx-id (or short-code) string.
    ///
    /// # Errors
    ///
    /// Returns [`TxIdError`] if `s` is empty, longer than 64 characters,
    /// or contains a character outside `[A-Za-z0-9_-]`.
    pub fn parse(s: &str) -> Result<Self, TxIdError> {
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(TxIdError::BadCharacter);
        }
        // All bytes are ASCII here, so byte length == character count.
        let len = s.len();
        if len == 0 || len > 64 {
            return Err(TxIdError::BadLength(len));
        }
        Ok(Self(s.to_owned()))
    }

    /// The validated tx-id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Display::fmt` replaced with `Ok(Default::default())` writes
    /// nothing at all and still reports success — and survived, because
    /// nothing asserted the rendered string.
    #[test]
    fn display_renders_the_full_tx_id() {
        let raw = "abc123_-XYZ";
        let txid = TxId::parse(raw).expect("valid tx id");
        assert_eq!(txid.to_string(), raw);
        assert_eq!(format!("{txid}"), raw);
    }

    #[test]
    fn accepts_a_real_arweave_tx_id() {
        // 43-char base64url — the canonical Arweave shape.
        let id = "abcDEF123456789_-abcDEF123456789_-abcDEF123";
        assert_eq!(id.len(), 43);
        assert_eq!(TxId::parse(id).unwrap().as_str(), id);
    }

    #[test]
    fn accepts_a_short_code() {
        assert!(TxId::parse("aB3xZ9q").is_ok());
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert_eq!(TxId::parse(""), Err(TxIdError::BadLength(0)));
        assert_eq!(TxId::parse(&"a".repeat(65)), Err(TxIdError::BadLength(65)));
        assert!(TxId::parse(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn rejects_path_traversal_and_other_bad_characters() {
        for bad in ["../etc", "a/b", "a.b", "a b", "a%2f", "tx\u{0000}"] {
            assert_eq!(
                TxId::parse(bad),
                Err(TxIdError::BadCharacter),
                "{bad:?} must be rejected",
            );
        }
    }
}
