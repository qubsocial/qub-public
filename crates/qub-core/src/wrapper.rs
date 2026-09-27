//! Optional outer encryption wrapper for private qub delivery.
//!
//! Private producers wrap the canonical CBOR bytes of a [`SealedQubCbor`]
//! with AES-256-GCM, binding the ciphertext to `qub_id` through the AEAD
//! additional-authenticated-data (AAD) channel. In the default browser flow,
//! the 256-bit key `K` lives only in the delivery URL fragment
//! (`/c/<tx_id>#<base64url(K)>`), which browsers do not send to servers.
//! Public delivery deliberately stores bare `SealedQubCbor` instead.
//!
//! Net effect:
//! - **Enumeration resistance for private delivery.** The wrapper hides the
//!   recognisable inner `SealedQub` structure and public drand signatures are
//!   insufficient to recover plaintext without `K`.
//! - **Crypto-shredding for the default private browser flow.** The service
//!   holds no decryption capability unless the creator explicitly opts into a
//!   recovery channel. Public delivery and trusted server-side sealing have
//!   different, documented trust boundaries.
//! - **Layered with tlock.** The wrapper is composed *outside* the existing
//!   [`crate::types::SealedQub`] / [`crate::types::QubEnvelope`] / tlock
//!   pipeline, so seal and unlock keep their existing signatures and the
//!   wrapper attaches at the call site. The inner protocol layers are
//!   unchanged.
//!
//! See PROTOCOL.md §13 for the normative specification.
//!
//! # Layering
//!
//! ```text
//! plaintext body                      ← QubEnvelope.body
//!   ↓ canonical CBOR                  ← cbor::serialize_qub_envelope
//! envelope CBOR
//!   ↓ tlock encrypt to drand round    ← seal::seal
//! tlock_ciphertext (inside SealedQub)
//!   ↓ canonical CBOR                  ← cbor::serialize_sealed_qub
//! SealedQubCbor bytes
//!   ├─ public  ────────────────────────────→ stored bare
//!   └─ private
//!        ↓ AES-256-GCM(K, nonce, AAD=qub_id)   ← THIS MODULE
//!      OuterWrapper CBOR bytes          ← stored private artifact
//! ```
//!
//! # Versioning
//!
//! The wrapper carries its own [`OUTER_WRAPPER_VERSION_1`] byte, independent
//! of the inner [`crate::types::PROTOCOL_VERSION_1`]. Future PQ-safe
//! algorithm replacements will bump this byte without touching the inner
//! protocol version.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use ciborium::Value;
use thiserror::Error;

use crate::cbor::{
    CborError, assert_canonical_key_order, encode_map, extract_u8, parse_top_level_map,
    reject_structural_elements_in_map, reject_unknown_keys, text, u8_value,
};
use crate::wire::{SealedQubCbor, is_cbor_map_header};

// -----------------------------------------------------------------------------
// Public constants
// -----------------------------------------------------------------------------

/// Outer wrapper version for AES-256-GCM with a 12-byte nonce and a
/// 16-byte tag. Independent of [`crate::types::PROTOCOL_VERSION_1`].
pub const OUTER_WRAPPER_VERSION_1: u8 = 0x01;

/// AES-256-GCM key length, in bytes.
pub const OUTER_WRAPPER_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length, in bytes (96 bits).
pub const OUTER_WRAPPER_NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length, in bytes (128 bits).
pub const OUTER_WRAPPER_TAG_LEN: usize = 16;

/// Hard ceiling on the size of an outer-wrapper ciphertext field, in bytes.
///
/// The inner [`SealedQubCbor`] is bounded by the protocol-layer size limits
/// (see [`crate::types::MAX_SERIALISED_SIZE`] and the CBOR layer's
/// `MAX_CIPHERTEXT_SIZE`); the outer ciphertext is at most that size plus
/// the AEAD tag. Doubling the inner ceiling gives ample headroom.
const MAX_OUTER_CIPHERTEXT_SIZE: usize = 2 * crate::types::MAX_SERIALISED_SIZE;

// -----------------------------------------------------------------------------
// Canonical key order (PROTOCOL.md §11.x)
// -----------------------------------------------------------------------------

/// Canonical key order for [`OuterWrapper`].
///
/// Sorted by encoded byte length ascending, then lexicographically by byte
/// value for same-length keys (matching [`crate::cbor`]'s convention).
///
/// | key          | chars | encoded bytes |
/// |--------------|------:|--------------:|
/// | `nonce`      |     5 |             6 |
/// | `qub_id`     |     6 |             7 |
/// | `version`    |     7 |             8 |
/// | `ciphertext` |    10 |            11 |
const OUTER_WRAPPER_KEYS_CANONICAL: &[&str] = &["nonce", "qub_id", "version", "ciphertext"];

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors produced by the outer-wrapper layer.
///
/// `#[non_exhaustive]`: additional variants may be added in minor releases.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum WrapperError {
    /// AEAD decryption failed. This is the catch-all for any combination of
    /// wrong key, wrong nonce, AAD mismatch, or tampered ciphertext —
    /// `aes-gcm` deliberately collapses these into a single error so timing
    /// channels cannot distinguish them.
    #[error(
        "outer wrapper: AEAD decryption failed (wrong key, wrong nonce, AAD mismatch, or tampered ciphertext)"
    )]
    DecryptFailed,

    /// AEAD encryption failed. In practice this should never trigger for a
    /// well-formed call: AES-GCM has no failure path for valid 32-byte keys
    /// and 12-byte nonces below the 2^39-byte plaintext limit, and a
    /// [`SealedQubCbor`] is bounded far below that. Surfaced as a defensive
    /// error rather than a panic.
    #[error("outer wrapper: AEAD encryption failed")]
    EncryptFailed,

    /// CBOR encoding or decoding of the wrapper structure failed.
    #[error("outer wrapper: CBOR error: {0}")]
    Cbor(#[from] CborError),

    /// The outer wrapper version byte is not [`OUTER_WRAPPER_VERSION_1`].
    #[error("outer wrapper: unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// An AES-GCM ciphertext cannot be shorter than its authentication tag.
    #[error(
        "outer wrapper: ciphertext is shorter than the {OUTER_WRAPPER_TAG_LEN}-byte authentication tag"
    )]
    CiphertextTooShort,

    /// The public `qub_id` authenticated as wrapper AAD did not match the
    /// `qub_id` carried by the decrypted [`crate::types::SealedQub`].
    #[error("outer wrapper: qub_id does not match the inner sealed qub")]
    QubIdMismatch,

    /// The decrypted plaintext does not begin with a CBOR map header, so
    /// it cannot be a [`SealedQubCbor`]. Surfaced separately from
    /// [`WrapperError::DecryptFailed`] because by the time we reach this
    /// branch the AEAD has *already* authenticated the bytes — a non-map
    /// plaintext means the producer wrapped non-conforming bytes, not that
    /// the wrapper was tampered with.
    #[error("outer wrapper: decrypted plaintext is not a CBOR map")]
    InnerNotAMap,
}

// -----------------------------------------------------------------------------
// Type definition
// -----------------------------------------------------------------------------

/// In-memory representation of the private-delivery outer wrapper.
///
/// Construction is intentionally restricted to the [`OuterWrapperBuilder`]
/// and the public [`wrap_sealed_qub`] / [`OuterWrapperCbor::parse`] entry
/// points so that callers cannot bypass the structural invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterWrapper {
    version: u8,
    qub_id: [u8; 32],
    nonce: [u8; OUTER_WRAPPER_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl OuterWrapper {
    /// Outer wrapper version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// AAD-bound qub identifier.
    #[must_use]
    pub const fn qub_id(&self) -> &[u8; 32] {
        &self.qub_id
    }

    /// 96-bit AEAD nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; OUTER_WRAPPER_NONCE_LEN] {
        &self.nonce
    }

    /// Authenticated ciphertext bytes (AES-GCM ciphertext concatenated with
    /// the 16-byte tag, as produced by the `aes-gcm` crate's
    /// [`Aead::encrypt`] method).
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Builder for [`OuterWrapper`].
///
/// Used internally by the CBOR decoder. Public callers should obtain an
/// [`OuterWrapper`] (wrapped in [`OuterWrapperCbor`]) via
/// [`wrap_sealed_qub`].
#[derive(Debug, Default, Clone)]
pub struct OuterWrapperBuilder {
    version: Option<u8>,
    qub_id: Option<[u8; 32]>,
    nonce: Option<[u8; OUTER_WRAPPER_NONCE_LEN]>,
    ciphertext: Option<Vec<u8>>,
}

impl OuterWrapperBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the outer wrapper version byte.
    #[must_use]
    pub const fn version(mut self, v: u8) -> Self {
        self.version = Some(v);
        self
    }

    /// Sets the AAD-bound `qub_id`.
    #[must_use]
    pub const fn qub_id(mut self, id: [u8; 32]) -> Self {
        self.qub_id = Some(id);
        self
    }

    /// Sets the AEAD nonce.
    #[must_use]
    pub const fn nonce(mut self, n: [u8; OUTER_WRAPPER_NONCE_LEN]) -> Self {
        self.nonce = Some(n);
        self
    }

    /// Sets the AEAD ciphertext (including the 16-byte tag).
    #[must_use]
    pub fn ciphertext(mut self, ct: Vec<u8>) -> Self {
        self.ciphertext = Some(ct);
        self
    }

    /// Finalises the builder.
    ///
    /// # Errors
    ///
    /// Returns [`WrapperError::UnsupportedVersion`] if `version` is set to a
    /// value other than [`OUTER_WRAPPER_VERSION_1`], or
    /// [`WrapperError::Cbor`] (with [`CborError::MissingField`] inside) if a
    /// required field is absent.
    pub fn build(self) -> Result<OuterWrapper, WrapperError> {
        let version = self.version.ok_or(CborError::MissingField("version"))?;
        if version != OUTER_WRAPPER_VERSION_1 {
            return Err(WrapperError::UnsupportedVersion(version));
        }
        let qub_id = self.qub_id.ok_or(CborError::MissingField("qub_id"))?;
        let nonce = self.nonce.ok_or(CborError::MissingField("nonce"))?;
        let ciphertext = self
            .ciphertext
            .ok_or(CborError::MissingField("ciphertext"))?;
        if ciphertext.len() < OUTER_WRAPPER_TAG_LEN {
            return Err(WrapperError::CiphertextTooShort);
        }
        Ok(OuterWrapper {
            version,
            qub_id,
            nonce,
            ciphertext,
        })
    }
}

// -----------------------------------------------------------------------------
// CBOR codec
// -----------------------------------------------------------------------------

/// Serialises an [`OuterWrapper`] to canonical CBOR bytes.
///
/// Output is deterministic: same input always produces the same byte
/// sequence. Canonical key order matches [`OUTER_WRAPPER_KEYS_CANONICAL`].
fn serialize_outer_wrapper(w: &OuterWrapper) -> Result<Vec<u8>, CborError> {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(OUTER_WRAPPER_KEYS_CANONICAL.len());
    let mut keys_used: Vec<&str> = Vec::with_capacity(OUTER_WRAPPER_KEYS_CANONICAL.len());

    map.push((text("nonce"), Value::Bytes(w.nonce().to_vec())));
    keys_used.push("nonce");

    map.push((text("qub_id"), Value::Bytes(w.qub_id().to_vec())));
    keys_used.push("qub_id");

    map.push((text("version"), u8_value(w.version())));
    keys_used.push("version");

    map.push((text("ciphertext"), Value::Bytes(w.ciphertext().to_vec())));
    keys_used.push("ciphertext");

    assert_canonical_key_order(&keys_used);

    encode_map(map)
}

/// Deserialises canonical CBOR bytes into an [`OuterWrapper`].
fn deserialize_outer_wrapper(bytes: &[u8]) -> Result<OuterWrapper, WrapperError> {
    let map = parse_top_level_map(bytes)?;
    reject_structural_elements_in_map(&map)?;
    reject_unknown_keys(&map, OUTER_WRAPPER_KEYS_CANONICAL, "OuterWrapper")?;

    let version = extract_u8(&map, "version")?;
    if version != OUTER_WRAPPER_VERSION_1 {
        return Err(WrapperError::UnsupportedVersion(version));
    }

    let qub_id = extract_fixed_bytes::<32>(&map, "qub_id")?;
    let nonce = extract_fixed_bytes::<OUTER_WRAPPER_NONCE_LEN>(&map, "nonce")?;
    let ciphertext = extract_bytes_bounded(&map, "ciphertext", MAX_OUTER_CIPHERTEXT_SIZE)?;

    OuterWrapperBuilder::new()
        .version(version)
        .qub_id(qub_id)
        .nonce(nonce)
        .ciphertext(ciphertext)
        .build()
}

// Local extractors mirror cbor.rs's pattern but operate on the parsed map
// type. The cbor.rs versions are file-private; rather than widening their
// visibility we reproduce the small, well-tested logic here. Matches the
// "wrapper.rs is self-contained" decision documented in the plan.

fn extract_bytes(map: &[(String, Value)], key: &'static str) -> Result<Vec<u8>, CborError> {
    match map.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "bytes",
            actual: cbor_type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

fn extract_bytes_bounded(
    map: &[(String, Value)],
    key: &'static str,
    max_size: usize,
) -> Result<Vec<u8>, CborError> {
    let bytes = extract_bytes(map, key)?;
    if bytes.len() > max_size {
        return Err(CborError::PayloadTooLarge {
            field: key,
            size: bytes.len(),
            max: max_size,
        });
    }
    Ok(bytes)
}

fn extract_fixed_bytes<const N: usize>(
    map: &[(String, Value)],
    key: &'static str,
) -> Result<[u8; N], CborError> {
    let bytes = extract_bytes(map, key)?;
    if bytes.len() != N {
        return Err(CborError::WrongLength {
            field: key,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

const fn cbor_type_name(v: &Value) -> &'static str {
    match v {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
        _ => "unknown",
    }
}

// -----------------------------------------------------------------------------
// Wire-format newtype
// -----------------------------------------------------------------------------

/// Canonical CBOR bytes of an [`OuterWrapper`].
///
/// Mirrors [`crate::wire::SealedQubCbor`]'s API: construction is restricted
/// to either CBOR serialisation of an [`OuterWrapper`] or wrapping bytes
/// that have already been produced by the canonical serialiser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterWrapperCbor(Vec<u8>);

impl OuterWrapperCbor {
    /// Wraps CBOR bytes that have been produced by the canonical
    /// outer-wrapper serialiser.
    ///
    /// Performs a lightweight structural check: the input must be non-empty
    /// and its first byte must be a valid CBOR definite-length map header.
    /// Full structural validation happens at parse time via
    /// [`Self::parse`].
    ///
    /// # Errors
    ///
    /// Returns [`CborError::NotAMap`] (wrapped in [`WrapperError::Cbor`]) if
    /// `bytes` is empty or does not begin with a CBOR map header.
    pub fn from_encoded(bytes: Vec<u8>) -> Result<Self, WrapperError> {
        match bytes.first() {
            Some(&b) if is_cbor_map_header(b) => Ok(Self(bytes)),
            _ => Err(WrapperError::Cbor(CborError::NotAMap)),
        }
    }

    /// Parses these CBOR bytes back into an [`OuterWrapper`].
    pub fn parse(&self) -> Result<OuterWrapper, WrapperError> {
        deserialize_outer_wrapper(&self.0)
    }

    /// Returns the raw CBOR bytes of the wrapper.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the raw CBOR bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length of the CBOR bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the CBOR bytes are empty. Always `false` for values
    /// produced via [`Self::from_encoded`] or [`wrap_sealed_qub`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// -----------------------------------------------------------------------------
// Public API: wrap / unwrap
// -----------------------------------------------------------------------------

/// Wraps a [`SealedQubCbor`] in an AES-256-GCM outer wrapper.
///
/// `qub_id` is bound as AAD: tampering with it after the fact (or moving
/// the ciphertext under a different `qub_id`) causes [`unwrap_sealed_qub`]
/// to reject. `key` and `nonce` are caller-supplied so this function is
/// testable without an RNG; the WASM creator generates `(key, nonce)` via
/// `getrandom` with the `wasm_js` backend; the Worker generates them via
/// `crypto.getRandomValues`.
///
/// The supplied `qub_id` is checked against the inner `SealedQub` before
/// encryption. This prevents callers from producing a wrapper whose AAD is
/// internally authenticated but describes a different artifact.
///
/// # Errors
///
/// Returns [`WrapperError::EncryptFailed`] if the AEAD encryption fails
/// (in practice unreachable for a well-formed key + nonce + bounded
/// plaintext) or [`WrapperError::Cbor`] if CBOR encoding fails.
pub fn wrap_sealed_qub(
    sealed_cbor: &SealedQubCbor,
    qub_id: &[u8; 32],
    key: &[u8; OUTER_WRAPPER_KEY_LEN],
    nonce: &[u8; OUTER_WRAPPER_NONCE_LEN],
) -> Result<OuterWrapperCbor, WrapperError> {
    let sealed = sealed_cbor.parse()?;
    if sealed.qub_id() != qub_id {
        return Err(WrapperError::QubIdMismatch);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| WrapperError::EncryptFailed)?;
    let payload = Payload {
        msg: sealed_cbor.as_bytes(),
        aad: qub_id,
    };
    let ciphertext = cipher
        .encrypt(nonce.into(), payload)
        .map_err(|_| WrapperError::EncryptFailed)?;

    let wrapper = OuterWrapper {
        version: OUTER_WRAPPER_VERSION_1,
        qub_id: *qub_id,
        nonce: *nonce,
        ciphertext,
    };

    let bytes = serialize_outer_wrapper(&wrapper)?;
    // Bypass the `from_encoded` map-header check — we just produced these
    // bytes via the canonical serialiser, so the check would be redundant.
    Ok(OuterWrapperCbor(bytes))
}

/// Unwraps an [`OuterWrapperCbor`] to recover the inner [`SealedQubCbor`].
///
/// Verifies the AEAD authentication tag using `key` and the wrapper's
/// nonce, with `qub_id` (read from the wrapper's plaintext field) as AAD.
/// Any mismatch — wrong key, tampered ciphertext, swapped `qub_id` — fails
/// authentication and produces [`WrapperError::DecryptFailed`].
///
/// # Errors
///
/// - [`WrapperError::Cbor`] if the wrapper bytes are malformed.
/// - [`WrapperError::UnsupportedVersion`] if `version != 0x01`.
/// - [`WrapperError::DecryptFailed`] for any AEAD authentication failure.
/// - [`WrapperError::InnerNotAMap`] if the decrypted plaintext is not a
///   CBOR map (i.e. cannot possibly be a `SealedQubCbor`).
/// - [`WrapperError::QubIdMismatch`] if the authenticated wrapper id does not
///   equal the id carried by the decrypted sealed qub.
pub fn unwrap_sealed_qub(
    wrapper: &OuterWrapperCbor,
    key: &[u8; OUTER_WRAPPER_KEY_LEN],
) -> Result<SealedQubCbor, WrapperError> {
    let parsed = wrapper.parse()?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| WrapperError::DecryptFailed)?;
    let payload = Payload {
        msg: parsed.ciphertext(),
        aad: parsed.qub_id(),
    };
    let plaintext = cipher
        .decrypt(parsed.nonce().into(), payload)
        .map_err(|_| WrapperError::DecryptFailed)?;

    let sealed_cbor = SealedQubCbor::from_encoded(plaintext).map_err(|e| match e {
        CborError::NotAMap => WrapperError::InnerNotAMap,
        other => WrapperError::Cbor(other),
    })?;
    let sealed = sealed_cbor.parse()?;
    if sealed.qub_id() != parsed.qub_id() {
        return Err(WrapperError::QubIdMismatch);
    }
    Ok(sealed_cbor)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PROTOCOL_VERSION_1, SealedQubBuilder, VISIBILITY_PUBLIC};

    fn sample_sealed_cbor() -> SealedQubCbor {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x42; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(1_736_294_400)
            .drand_chain_id("a".repeat(64))
            .drand_round(4_675_285)
            .tlock_ciphertext(vec![0xCD; 96])
            .build()
            .expect("valid sealed");
        SealedQubCbor::from_sealed_qub(&sealed).expect("serialise")
    }

    fn sample_key() -> [u8; OUTER_WRAPPER_KEY_LEN] {
        [0xA5; OUTER_WRAPPER_KEY_LEN]
    }

    fn sample_nonce() -> [u8; OUTER_WRAPPER_NONCE_LEN] {
        [0x5A; OUTER_WRAPPER_NONCE_LEN]
    }

    /// Accessor read-back on the CBOR wire newtype.
    ///
    /// These four projections — `as_bytes`, `into_bytes`, `len`,
    /// `is_empty` — accounted for a large share of this repository's 230
    /// surviving mutants, and always for the same reason: the newtypes
    /// are exercised end-to-end through `from_*` / `parse`, but a
    /// round-trip compares whole values and never asks a getter what it
    /// returns. Each could be replaced by `vec![]`, `0`, `1` or `true`
    /// with the suite still green.
    ///
    /// The `len() > 1` assertion is load-bearing rather than decorative:
    /// `0` and `1` are the two constants a mutant substitutes, so a
    /// sample shorter than two bytes would prove nothing.
    /// `cbor_type_name` feeds the `actual:` field of the decoder's
    /// `UnexpectedType` error — the part of the message that tells a
    /// caller what they actually sent. Every one of its nine arms was a
    /// surviving mutant, because a `_ => "unknown"` catch-all absorbs any
    /// deleted arm: the decoder would still reject the input, just stop
    /// naming what it got. Two files carry an independent copy of this
    /// helper, so both are pinned.
    /// Bounds-check boundary for this file's own copy of
    /// `extract_bytes_bounded`. `>` → `>=` is invisible unless something
    /// of EXACTLY `max` is accepted; `>` → `==` is invisible unless
    /// something strictly larger is rejected. Neither existed.
    /// `MAX_OUTER_CIPHERTEXT_SIZE` is `2 * MAX_SERIALISED_SIZE`, and the
    /// doubling is the whole point: the outer ciphertext is the inner
    /// payload PLUS the AEAD tag and CBOR framing, so it must be allowed
    /// to exceed the inner ceiling. Mutating `*` to `+` collapses
    /// 204,800 to 102,402 — barely above the inner ceiling — which would
    /// reject exactly the headroom the constant exists to provide.
    ///
    /// A test phrased in terms of the constant cannot catch that: it
    /// shrinks with the constant and still passes. This one is phrased in
    /// concrete bytes ABOVE the inner ceiling, which is the property that
    /// actually matters.
    ///
    /// Decoding is separate from decryption here, so a synthetic
    /// ciphertext round-trips without needing a real AEAD payload.
    #[test]
    fn outer_ciphertext_limit_allows_more_than_the_inner_ceiling() {
        let oversized = crate::types::MAX_SERIALISED_SIZE + 50_000;
        let wrapper = OuterWrapperBuilder::new()
            .version(OUTER_WRAPPER_VERSION_1)
            .qub_id([7u8; 32])
            .nonce(sample_nonce())
            .ciphertext(vec![0xAB; oversized])
            .build()
            .expect("builder");
        let bytes = serialize_outer_wrapper(&wrapper).expect("encode");
        let parsed = deserialize_outer_wrapper(&bytes)
            .expect("a ciphertext above the INNER ceiling must still decode");
        assert_eq!(parsed.ciphertext().len(), oversized);
    }

    #[test]
    fn extract_bytes_bounded_pins_both_sides_of_the_limit() {
        let map = |n: usize| -> Vec<(String, Value)> {
            vec![("k".to_owned(), Value::Bytes(vec![0xAA; n]))]
        };
        assert_eq!(
            extract_bytes_bounded(&map(8), "k", 8)
                .expect("exactly max is legal")
                .len(),
            8
        );
        assert!(matches!(
            extract_bytes_bounded(&map(9), "k", 8),
            Err(CborError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn cbor_type_name_names_every_variant() {
        assert_eq!(cbor_type_name(&Value::Integer(7.into())), "integer");
        assert_eq!(cbor_type_name(&Value::Bytes(vec![1, 2])), "bytes");
        assert_eq!(cbor_type_name(&Value::Text("x".to_owned())), "text");
        assert_eq!(cbor_type_name(&Value::Array(vec![Value::Null])), "array");
        assert_eq!(
            cbor_type_name(&Value::Map(vec![(Value::Null, Value::Null)])),
            "map"
        );
        assert_eq!(
            cbor_type_name(&Value::Tag(42, Box::new(Value::Null))),
            "tag"
        );
        assert_eq!(cbor_type_name(&Value::Bool(true)), "bool");
        assert_eq!(cbor_type_name(&Value::Null), "null");
        assert_eq!(cbor_type_name(&Value::Float(1.5)), "float");
    }

    #[test]
    fn outer_wrapper_cbor_accessors_read_back() {
        let wrapped = wrap_sealed_qub(
            &sample_sealed_cbor(),
            &[0x42u8; 32],
            &sample_key(),
            &sample_nonce(),
        )
        .unwrap();
        let bytes = wrapped.as_bytes().to_vec();
        assert!(
            bytes.len() > 1,
            "sample must exceed the 0/1 replacement constants"
        );
        assert_eq!(wrapped.len(), bytes.len());
        assert!(!wrapped.is_empty());
        assert_eq!(wrapped.into_bytes(), bytes);
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let wrapped = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        let recovered = unwrap_sealed_qub(&wrapped, &key).unwrap();
        assert_eq!(recovered.as_bytes(), sealed.as_bytes());
    }

    #[test]
    fn wrap_rejects_qub_id_that_disagrees_with_inner_sealed_qub() {
        let err = wrap_sealed_qub(
            &sample_sealed_cbor(),
            &[0x99; 32],
            &sample_key(),
            &sample_nonce(),
        )
        .unwrap_err();
        assert_eq!(err, WrapperError::QubIdMismatch);
    }

    #[test]
    fn unwrap_rejects_authenticated_wrapper_with_inconsistent_inner_qub_id() {
        let sealed = sample_sealed_cbor();
        let outer_qub_id = [0x99; 32];
        let key = sample_key();
        let nonce = sample_nonce();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: sealed.as_bytes(),
                    aad: &outer_qub_id,
                },
            )
            .unwrap();
        let wrapper = OuterWrapperBuilder::new()
            .version(OUTER_WRAPPER_VERSION_1)
            .qub_id(outer_qub_id)
            .nonce(nonce)
            .ciphertext(ciphertext)
            .build()
            .unwrap();
        let encoded = OuterWrapperCbor(serialize_outer_wrapper(&wrapper).unwrap());

        assert_eq!(
            unwrap_sealed_qub(&encoded, &key),
            Err(WrapperError::QubIdMismatch),
        );
    }

    #[test]
    fn builder_rejects_ciphertext_shorter_than_authentication_tag() {
        let err = OuterWrapperBuilder::new()
            .version(OUTER_WRAPPER_VERSION_1)
            .qub_id([1; 32])
            .nonce(sample_nonce())
            .ciphertext(vec![0; OUTER_WRAPPER_TAG_LEN - 1])
            .build()
            .unwrap_err();
        assert_eq!(err, WrapperError::CiphertextTooShort);
    }

    #[test]
    fn wrap_is_deterministic_for_fixed_key_nonce() {
        // Same (sealed, qub_id, key, nonce) MUST produce the same bytes —
        // canonical CBOR + deterministic AEAD demand it. Useful for
        // cross-language test vectors.
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let a = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        let b = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn wrap_with_different_nonce_produces_different_bytes() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();

        let a = wrap_sealed_qub(&sealed, &qub_id, &key, &[0x01; 12]).unwrap();
        let b = wrap_sealed_qub(&sealed, &qub_id, &key, &[0x02; 12]).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn unwrap_rejects_wrong_key() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let wrapped = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        let mut wrong = key;
        wrong[0] ^= 0x01;
        let err = unwrap_sealed_qub(&wrapped, &wrong).unwrap_err();
        assert!(matches!(err, WrapperError::DecryptFailed));
    }

    #[test]
    fn unwrap_rejects_tampered_ciphertext() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let wrapped = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        let mut parsed = wrapped.parse().unwrap();
        // Flip a single byte deep in the ciphertext.
        let mid = parsed.ciphertext.len() / 2;
        parsed.ciphertext[mid] ^= 0xFF;
        let bytes = serialize_outer_wrapper(&parsed).unwrap();
        let tampered = OuterWrapperCbor::from_encoded(bytes).unwrap();

        let err = unwrap_sealed_qub(&tampered, &key).unwrap_err();
        assert!(matches!(err, WrapperError::DecryptFailed));
    }

    #[test]
    fn unwrap_rejects_swapped_qub_id_aad() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let wrapped = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        // Decode, replace qub_id (the AAD source), re-encode. AEAD MUST reject.
        let mut parsed = wrapped.parse().unwrap();
        parsed.qub_id = [0x99; 32];
        let bytes = serialize_outer_wrapper(&parsed).unwrap();
        let swapped = OuterWrapperCbor::from_encoded(bytes).unwrap();

        let err = unwrap_sealed_qub(&swapped, &key).unwrap_err();
        assert!(matches!(err, WrapperError::DecryptFailed));
    }

    #[test]
    fn unwrap_rejects_swapped_nonce() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let wrapped = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        let mut parsed = wrapped.parse().unwrap();
        parsed.nonce = [0xFF; 12];
        let bytes = serialize_outer_wrapper(&parsed).unwrap();
        let swapped = OuterWrapperCbor::from_encoded(bytes).unwrap();

        let err = unwrap_sealed_qub(&swapped, &key).unwrap_err();
        assert!(matches!(err, WrapperError::DecryptFailed));
    }

    #[test]
    fn unwrap_rejects_wrong_version() {
        let sealed = sample_sealed_cbor();
        let qub_id = [0x42; 32];
        let key = sample_key();
        let nonce = sample_nonce();

        let wrapped = wrap_sealed_qub(&sealed, &qub_id, &key, &nonce).unwrap();
        let mut parsed = wrapped.parse().unwrap();
        parsed.version = 0x02; // unsupported
        let bytes = serialize_outer_wrapper(&parsed).unwrap();
        let unsupported = OuterWrapperCbor::from_encoded(bytes).unwrap();

        let err = unwrap_sealed_qub(&unsupported, &key).unwrap_err();
        assert!(matches!(err, WrapperError::UnsupportedVersion(0x02)));
    }

    #[test]
    fn from_encoded_rejects_non_map_bytes() {
        // 0x80 is a CBOR empty array, not a map.
        let err = OuterWrapperCbor::from_encoded(vec![0x80]).unwrap_err();
        assert!(matches!(err, WrapperError::Cbor(CborError::NotAMap)));

        // Empty input.
        let err = OuterWrapperCbor::from_encoded(vec![]).unwrap_err();
        assert!(matches!(err, WrapperError::Cbor(CborError::NotAMap)));
    }

    #[test]
    fn wrapped_overhead_is_predictable() {
        // 4 keys + 4 values, plus the AEAD tag. For a small SealedQubCbor
        // we expect roughly: map header (1) + nonce key+value (~17) +
        // qub_id key+value (~40) + version key+value (~3) + ciphertext
        // key+value (~plaintext_len + 16 + small overhead). The exact
        // figure isn't important for tests, but the overhead must be
        // bounded and must not depend on plaintext content.
        let sealed = sample_sealed_cbor();
        let plain_len = sealed.as_bytes().len();
        let wrapped =
            wrap_sealed_qub(&sealed, &[0x42; 32], &sample_key(), &sample_nonce()).unwrap();
        let wrapped_len = wrapped.as_bytes().len();
        assert!(
            wrapped_len > plain_len,
            "wrapped must be larger than plaintext"
        );
        // Overhead is bounded above by a generous constant. AEAD tag is 16
        // bytes; CBOR map framing is < 100 bytes for our key set.
        assert!(
            wrapped_len < plain_len + 200,
            "overhead unexpectedly large: {wrapped_len} > {plain_len} + 200",
        );
    }

    #[test]
    fn canonical_key_order_constant_is_actually_canonical() {
        // Defensive: the constant is consumed only by the debug-only
        // assert_canonical_key_order in encode paths, but if it ever
        // diverges from the documented order we want a unit test to
        // catch it independently.
        for pair in OUTER_WRAPPER_KEYS_CANONICAL.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            let by_len = a.len().cmp(&b.len());
            let ord = by_len.then_with(|| a.as_bytes().cmp(b.as_bytes()));
            assert!(
                ord.is_lt(),
                "canonical order violated: {a:?} must come before {b:?}",
            );
        }
    }
}
