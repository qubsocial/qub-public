//! Canonical CBOR encoding and decoding for the qub wire format.
//!
//! This module implements the canonical CBOR profile defined in
//! `PROTOCOL.md` §3. Two conforming implementations given the same logical
//! [`QubEnvelope`] or [`SealedQub`] MUST produce byte-identical output.
//!
//! The implementation is **hand-written** — `serde` is deliberately not
//! used. Serialisation builds [`ciborium::Value`] trees with map entries
//! inserted in the normative key order from §3.2; deserialisation walks the
//! parsed [`ciborium::Value`] manually to enforce the structural rules of
//! §3.1 (no tags, no floats, no duplicate keys, required fields, etc.).
//!
//! # Text strings and NFC
//!
//! All text strings in the wire format are **NFC normalised**. On
//! serialisation the encoder silently applies NFC normalisation. On
//! deserialisation the decoder verifies that input strings are already in
//! NFC form and returns [`CborError::NfcNormalisationRequired`] otherwise,
//! preventing two semantically-equal but byte-distinct inputs from being
//! accepted.
//!
//! # Optional fields
//!
//! Absent optional fields (`None`) are omitted from the CBOR map entirely;
//! they are never encoded as `null`. Present optional fields are included
//! in the canonical key order described in §3.2.

use ciborium::Value;
use ciborium::value::Integer;
use thiserror::Error;
use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

use crate::handle::contains_hostile_text_codepoint;
use crate::types::{
    PROTOCOL_VERSION_1, QubEnvelope, QubEnvelopeBuilder, SealedQub, SealedQubBuilder,
};

// -----------------------------------------------------------------------------
// Canonical key tables
// -----------------------------------------------------------------------------

/// Canonical key order for [`QubEnvelope`] (PROTOCOL.md §3.2).
///
/// Keys are sorted by encoded byte length (ascending), then
/// lexicographically by byte value for same-length keys.
const ENVELOPE_KEYS_CANONICAL: &[&str] = &[
    "body",
    "qub_id",
    "sig_alg",
    "version",
    "reply_to", // 8 encoded bytes — sorts after 7-byte keys, before 9-byte
    "body_hash",
    "unlock_at",
    "created_at",
    // "outcome_at" — 10 chars → 11 encoded bytes, same as
    // "created_at"; lex order puts 'c' < 'o' so it sorts after
    // created_at and before content_type (13 bytes). Optional;
    // omitted from the map when None. See
    // `tasks/verdict-uplift-plan.md` §3.1 + protocol.md §3.2.
    "outcome_at",
    "content_type",
    "sender_label",
    "author_pubkey",
    "cosigner_pubkey",
    "author_signature",
    "cosigner_signature",
];

/// Canonical key order for [`SealedQub`].
///
/// **Note on PROTOCOL.md §3.2:** the spec table annotates both
/// `"visibility"` and `"drand_round"` as "11 encoded bytes", but
/// `"drand_round"` is 11 characters → 12 encoded bytes, while
/// `"visibility"` is 10 characters → 11 encoded bytes. The normative
/// sort rule (shortest encoded length first, then lex) therefore places
/// `"visibility"` **before** `"drand_round"`. The order below follows the
/// normative rule; the §3.2 table is a summary with a typo in the byte
/// counts.
///
/// The optional `"title"` field (added in v1.0 alongside the
/// `title_hash` `qub_id` binding) is 5 characters → 6 encoded
/// bytes, the shortest key, so it sorts to the top of the
/// canonical map.
const SEALED_KEYS_CANONICAL: &[&str] = &[
    "title",
    "qub_id",
    "version",
    "unlock_at",
    // "outcome_at" — 10 chars → 11 encoded bytes, same as
    // "visibility"; lex order puts 'o' < 'v' so it sorts after
    // unlock_at and before visibility. Optional; omitted from the
    // map when None. See `tasks/verdict-uplift-plan.md` §3.1.
    "outcome_at",
    "visibility",
    "drand_round",
    "drand_chain_id",
    "recipient_pubkey",
    "tlock_ciphertext",
    // "drand_chain_version" — 19 chars → 20 encoded bytes, longer than
    // every other key, so it sorts last in the length-then-bytewise
    // canonical order. Optional; omitted from the map when None
    // (quicknet). See W3 / UP-B4 and `crate::tlock`.
    "drand_chain_version",
];

/// Maximum length of the [`SealedQub`] `title` field, in Unicode code
/// points (NFC). Mirrors [`crate::types::MAX_TITLE_CODEPOINTS`].
const MAX_TITLE_CODEPOINTS: usize = 100;

/// Maximum allowed size for `tlock_ciphertext` byte strings (128 KiB).
const MAX_CIPHERTEXT_SIZE: usize = 128 * 1024;

/// Maximum allowed size for `body` byte strings (64 KiB).
const MAX_BODY_SIZE: usize = 102_400; // 100 KB — accommodates pact bodies (PROTOCOL.md §6)

/// Maximum nesting depth for structural validation.
const MAX_RECURSION_DEPTH: usize = 32;

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors produced by canonical CBOR encoding / decoding.
///
/// This enum is `#[non_exhaustive]`: additional variants may be added in
/// minor releases. Match arms on it must include a wildcard.
///
/// # Examples
///
/// Decoding arbitrary garbage produces a [`CborError::DecodingFailed`]:
///
/// ```
/// use qub_core::cbor::{deserialize_qub_envelope, CborError};
///
/// let err = deserialize_qub_envelope(&[0xFF, 0xFF, 0xFF]).unwrap_err();
/// assert!(matches!(err, CborError::DecodingFailed(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CborError {
    /// Encoding to CBOR bytes failed at the ciborium layer.
    #[error("CBOR encoding failed: {0}")]
    EncodingFailed(String),

    /// Decoding from CBOR bytes failed at the ciborium layer (malformed).
    #[error("CBOR decoding failed: {0}")]
    DecodingFailed(String),

    /// A CBOR value did not have the expected type.
    #[error("unexpected CBOR type for {field}: expected {expected}, got {actual}")]
    UnexpectedType {
        /// Name of the field being extracted.
        field: &'static str,
        /// Expected CBOR type name.
        expected: &'static str,
        /// Actual CBOR type name.
        actual: &'static str,
    },

    /// A required field was missing from the CBOR map.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// The same map key was present twice.
    #[error("duplicate map key: {0}")]
    DuplicateKey(String),

    /// The supplied protocol version is not supported.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// A CBOR tag (major type 6) was encountered.
    #[error("CBOR tags are forbidden")]
    ForbiddenTag,

    /// A CBOR floating-point value was encountered.
    #[error("floating-point values are forbidden")]
    ForbiddenFloat,

    /// A text string was not in NFC form.
    #[error("NFC normalisation required: input string was not NFC")]
    NfcNormalisationRequired,

    /// The top-level CBOR value was not a map.
    #[error("top-level CBOR value is not a map")]
    NotAMap,

    /// A non-text key was found in a map where only text keys are allowed.
    #[error("non-text map key encountered")]
    NonTextKey,

    /// An integer value did not fit into the expected Rust integer type.
    #[error("integer out of range for field {0}")]
    IntegerOutOfRange(&'static str),

    /// A fixed-size byte array had the wrong length.
    #[error("wrong byte-string length for {field}: expected {expected}, got {actual}")]
    WrongLength {
        /// Name of the field being extracted.
        field: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// A field rejected by the `types` module during reconstruction.
    #[error("structural validation failed: {0}")]
    StructuralError(String),

    /// A variable-length byte string exceeded the maximum allowed size.
    #[error("{field} exceeds maximum size: {size} bytes > {max} bytes")]
    PayloadTooLarge {
        /// Name of the field.
        field: &'static str,
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },
}

// -----------------------------------------------------------------------------
// Debug-only canonical order assertion
// -----------------------------------------------------------------------------

/// Canonical CBOR map-key ordering: shorter encoded byte length before
/// longer, then lexicographic byte ordering for equal lengths.
///
/// Comparing raw string lengths is provably equivalent to comparing CBOR
/// *encoded* key lengths for text-string keys: the length-prefix width is a
/// non-decreasing step function of the string length, so `a.len() < b.len()`
/// implies `encoded(a) < encoded(b)`, and equal raw lengths share an
/// identical header — making the byte-wise tie-break on the raw bytes
/// identical to the tie-break on the encoded keys. This is why the decoder
/// (`parsed_map_from_entries`) can reuse it to reject out-of-order maps and
/// the serialiser can reuse it to assert its own output is canonical.
pub(crate) fn canonical_key_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// Debug-only assertion that `keys` is in canonical CBOR key order.
///
/// This helper is a development-time safety net used by the serialiser to
/// catch regressions; it is compiled out of release builds. The decode path
/// enforces the same rule in *all* builds via [`canonical_key_cmp`] in
/// [`parsed_map_from_entries`].
#[cfg(debug_assertions)]
pub(crate) fn assert_canonical_key_order(keys: &[&str]) {
    for pair in keys.windows(2) {
        // `windows(2)` always yields a length-2 slice — destructure
        // rather than index so the panic-prone path is gone (SEC-15).
        let [a, b] = pair else { continue };
        assert!(
            canonical_key_cmp(a, b).is_lt(),
            "canonical key order violated: {a:?} must come before {b:?}",
        );
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub(crate) const fn assert_canonical_key_order(_keys: &[&str]) {}

// -----------------------------------------------------------------------------
// NFC helpers
// -----------------------------------------------------------------------------

/// Normalises a string to NFC, allocating only if normalisation changes it.
pub(crate) fn to_nfc(s: &str) -> String {
    if is_nfc_quick(s.chars()) == IsNormalized::Yes {
        s.to_owned()
    } else {
        s.nfc().collect()
    }
}

/// Returns an error if `s` is not already in NFC form.
pub(crate) fn require_nfc(s: &str) -> Result<(), CborError> {
    match is_nfc_quick(s.chars()) {
        IsNormalized::Yes => Ok(()),
        IsNormalized::No => Err(CborError::NfcNormalisationRequired),
        IsNormalized::Maybe => {
            let normalised: String = s.nfc().collect();
            if normalised == s {
                Ok(())
            } else {
                Err(CborError::NfcNormalisationRequired)
            }
        },
    }
}

// -----------------------------------------------------------------------------
// Serialisation
// -----------------------------------------------------------------------------

/// Serialises a [`QubEnvelope`] to canonical CBOR bytes.
///
/// The output is deterministic: the same input always produces the same
/// byte sequence. Canonical key order, NFC normalisation of text keys,
/// and rejection of forbidden CBOR features (tags, floats) are enforced.
///
/// # Errors
///
/// Returns [`CborError::EncodingFailed`] if the underlying `ciborium`
/// writer fails. In practice this should not happen for a well-formed
/// envelope built via [`QubEnvelopeBuilder`].
///
/// # Examples
///
/// Round-trip via [`deserialize_qub_envelope`]:
///
/// ```
/// use qub_core::cbor::{deserialize_qub_envelope, serialize_qub_envelope};
/// use qub_core::hash::derive_envelope_hashes;
/// use qub_core::types::{
///     QubEnvelopeBuilder, CONTENT_TYPE_TEXT, PROTOCOL_VERSION_1,
/// };
///
/// let body = b"Hello, future.".to_vec();
/// let (body_hash, qub_id) = derive_envelope_hashes(
///     PROTOCOL_VERSION_1,
///     CONTENT_TYPE_TEXT,
///     1_735_689_600,
///     1_736_294_400,
///     None, // outcome_at
///     4_695_445, // drand_round
///     &body,
///     None, // title
/// );
/// let envelope = QubEnvelopeBuilder::new()
///     .version(PROTOCOL_VERSION_1)
///     .qub_id(qub_id)
///     .content_type(CONTENT_TYPE_TEXT)
///     .created_at(1_735_689_600)
///     .unlock_at(1_736_294_400)
///     .body(body)
///     .body_hash(body_hash)
///     .build()
///     .unwrap();
///
/// // Serialisation is deterministic.
/// let bytes_a = serialize_qub_envelope(&envelope).unwrap();
/// let bytes_b = serialize_qub_envelope(&envelope).unwrap();
/// assert_eq!(bytes_a, bytes_b);
///
/// // Round-trip recovers the original value.
/// let decoded = deserialize_qub_envelope(&bytes_a).unwrap();
/// assert_eq!(decoded, envelope);
/// ```
pub fn serialize_qub_envelope(envelope: &QubEnvelope) -> Result<Vec<u8>, CborError> {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(ENVELOPE_KEYS_CANONICAL.len());
    let mut keys_used: Vec<&str> = Vec::with_capacity(ENVELOPE_KEYS_CANONICAL.len());

    // Canonical key order: body, qub_id, sig_alg, version, body_hash,
    // unlock_at, created_at, content_type, [sender_label], [author_pubkey],
    // [cosigner_pubkey], [author_signature], [cosigner_signature].

    map.push((text("body"), Value::Bytes(envelope.body().to_vec())));
    keys_used.push("body");

    map.push((text("qub_id"), Value::Bytes(envelope.qub_id().to_vec())));
    keys_used.push("qub_id");

    map.push((text("sig_alg"), u8_value(envelope.sig_alg())));
    keys_used.push("sig_alg");

    map.push((text("version"), u8_value(envelope.version())));
    keys_used.push("version");

    // Optional reply_to (Sprint B.1). Slots after `version` and
    // before `body_hash` in the canonical order (8 encoded bytes).
    // Omitted entirely when None so old envelopes without reply_to
    // retain byte-identical CBOR.
    if let Some(parent) = envelope.reply_to() {
        map.push((text("reply_to"), Value::Bytes(parent.to_vec())));
        keys_used.push("reply_to");
    }

    map.push((
        text("body_hash"),
        Value::Bytes(envelope.body_hash().to_vec()),
    ));
    keys_used.push("body_hash");

    map.push((text("unlock_at"), i64_value(envelope.unlock_at())));
    keys_used.push("unlock_at");

    map.push((text("created_at"), i64_value(envelope.created_at())));
    keys_used.push("created_at");

    // Optional outcome_at (verdict-uplift-plan §3.1). Slots between
    // created_at (11 bytes encoded) and content_type (13 bytes
    // encoded) per the canonical sort. Omitted entirely when None
    // so pre-V1.1 envelopes round-trip byte-identical.
    if let Some(outcome_at) = envelope.outcome_at() {
        map.push((text("outcome_at"), i64_value(outcome_at)));
        keys_used.push("outcome_at");
    }

    map.push((text("content_type"), u8_value(envelope.content_type())));
    keys_used.push("content_type");

    if let Some(label) = envelope.sender_label() {
        // Andre 2026-05-22 SYSTEMIC-THREAT-REVIEW Finding 47 — encoder-
        // side hostile-codepoint check, plus the Worker-edge 80-code-point
        // length ceiling (shared `validate_sender_label`). The TS API edge
        // already rejects via normaliseAndValidateText (PR 0c); this
        // catches non-API write paths (qub-mcp, future Rust signer,
        // third-party builders) before a hostile or oversized record
        // reaches Arweave. The decoder applies the same rule, so encode
        // and decode accept exactly the same labels.
        crate::types::validate_sender_label(label)
            .map_err(|e| CborError::StructuralError(e.to_string()))?;
        map.push((text("sender_label"), Value::Text(to_nfc(label))));
        keys_used.push("sender_label");
    }

    if let Some(pk) = envelope.author_pubkey() {
        map.push((text("author_pubkey"), Value::Bytes(pk.to_vec())));
        keys_used.push("author_pubkey");
    }

    if let Some(cpk) = envelope.cosigner_pubkey() {
        map.push((text("cosigner_pubkey"), Value::Bytes(cpk.to_vec())));
        keys_used.push("cosigner_pubkey");
    }

    if let Some(sig) = envelope.author_signature() {
        map.push((text("author_signature"), Value::Bytes(sig.to_vec())));
        keys_used.push("author_signature");
    }

    if let Some(csig) = envelope.cosigner_signature() {
        map.push((text("cosigner_signature"), Value::Bytes(csig.to_vec())));
        keys_used.push("cosigner_signature");
    }

    assert_canonical_key_order(&keys_used);

    encode_map(map)
}

/// Serialises a [`SealedQub`] to canonical CBOR bytes.
///
/// The output is deterministic and uses the canonical key order for
/// `SealedQub` (see PROTOCOL.md §3.2).
///
/// # Errors
///
/// Returns [`CborError::EncodingFailed`] if the underlying `ciborium`
/// writer fails.
///
/// # Examples
///
/// Round-trip via [`deserialize_sealed_qub`]:
///
/// ```
/// use qub_core::cbor::{deserialize_sealed_qub, serialize_sealed_qub};
/// use qub_core::types::{
///     SealedQubBuilder, PROTOCOL_VERSION_1, VISIBILITY_PUBLIC,
/// };
///
/// let sealed = SealedQubBuilder::new()
///     .version(PROTOCOL_VERSION_1)
///     .qub_id([0x11; 32])
///     .visibility(VISIBILITY_PUBLIC)
///     .unlock_at(1_736_294_400)
///     .drand_chain_id("example-chain".into())
///     .drand_round(4_675_285)
///     .tlock_ciphertext(vec![0xAA; 64])
///     .build()
///     .unwrap();
///
/// let bytes = serialize_sealed_qub(&sealed).unwrap();
/// let decoded = deserialize_sealed_qub(&bytes).unwrap();
/// assert_eq!(decoded, sealed);
/// ```
pub fn serialize_sealed_qub(sealed: &SealedQub) -> Result<Vec<u8>, CborError> {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(SEALED_KEYS_CANONICAL.len());
    let mut keys_used: Vec<&str> = Vec::with_capacity(SEALED_KEYS_CANONICAL.len());

    // Canonical key order: [title], qub_id, version, unlock_at,
    // visibility, drand_round, drand_chain_id, [recipient_pubkey],
    // tlock_ciphertext.

    if let Some(title) = sealed.title() {
        // Andre 2026-05-22 SYSTEMIC-THREAT-REVIEW Finding 47 — see the
        // same comment in serialize_qub_envelope above. The shared
        // validator covers hostile codepoints, the empty-string case
        // (absent title must be field omission), and the NFC-counted
        // length ceiling, so the encoder can never emit a title slot
        // the decoder rejects — an encode-accepts/decode-rejects gap
        // here mints paid, permanently undecodable artifacts.
        crate::types::validate_title(title)
            .map_err(|e| CborError::StructuralError(e.to_string()))?;
        map.push((text("title"), Value::Text(to_nfc(title))));
        keys_used.push("title");
    }

    map.push((text("qub_id"), Value::Bytes(sealed.qub_id().to_vec())));
    keys_used.push("qub_id");

    map.push((text("version"), u8_value(sealed.version())));
    keys_used.push("version");

    map.push((text("unlock_at"), i64_value(sealed.unlock_at())));
    keys_used.push("unlock_at");

    // Optional outcome_at (verdict-uplift-plan §3.1). Slots between
    // unlock_at (10 bytes encoded) and visibility (11 bytes
    // encoded; 'o' < 'v' lex-tie on same-length).
    if let Some(outcome_at) = sealed.outcome_at() {
        map.push((text("outcome_at"), i64_value(outcome_at)));
        keys_used.push("outcome_at");
    }

    map.push((text("visibility"), u8_value(sealed.visibility())));
    keys_used.push("visibility");

    map.push((text("drand_round"), u64_value(sealed.drand_round())));
    keys_used.push("drand_round");

    map.push((
        text("drand_chain_id"),
        Value::Text(to_nfc(sealed.drand_chain_id())),
    ));
    keys_used.push("drand_chain_id");

    if let Some(pk) = sealed.recipient_pubkey() {
        map.push((text("recipient_pubkey"), Value::Bytes(pk.to_vec())));
        keys_used.push("recipient_pubkey");
    }

    map.push((
        text("tlock_ciphertext"),
        Value::Bytes(sealed.tlock_ciphertext().to_vec()),
    ));
    keys_used.push("tlock_ciphertext");

    // Optional drand chain-migration version (W3 / UP-B4). Sorts last
    // (longest key); omitted when None so existing quicknet seals are
    // byte-identical to the pre-W3 encoding.
    if let Some(v) = sealed.drand_chain_version() {
        map.push((text("drand_chain_version"), u8_value(v)));
        keys_used.push("drand_chain_version");
    }

    assert_canonical_key_order(&keys_used);

    encode_map(map)
}

pub(crate) fn encode_map(map: Vec<(Value, Value)>) -> Result<Vec<u8>, CborError> {
    let value = Value::Map(map);
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)
        .map_err(|e| CborError::EncodingFailed(e.to_string()))?;
    Ok(buf)
}

pub(crate) fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

pub(crate) fn u8_value(v: u8) -> Value {
    Value::Integer(Integer::from(v))
}

pub(crate) fn i64_value(v: i64) -> Value {
    Value::Integer(Integer::from(v))
}

pub(crate) fn u64_value(v: u64) -> Value {
    Value::Integer(Integer::from(v))
}

// -----------------------------------------------------------------------------
// Deserialisation
// -----------------------------------------------------------------------------

/// Deserialises canonical CBOR bytes into a [`QubEnvelope`].
///
/// Rejects non-map roots, non-text keys, duplicate keys, CBOR tags,
/// floating-point values, non-NFC text, wrong-sized byte arrays, and any
/// envelope that fails structural validation during [`QubEnvelopeBuilder`]
/// reconstruction.
///
/// # Errors
///
/// Returns a [`CborError`] variant describing the first violation
/// encountered. Common variants include [`CborError::DecodingFailed`]
/// (malformed CBOR), [`CborError::UnsupportedVersion`] (version byte is
/// not [`PROTOCOL_VERSION_1`]), [`CborError::MissingField`], and
/// [`CborError::DuplicateKey`].
///
/// # Examples
///
/// See [`serialize_qub_envelope`] for a round-trip example. The error
/// path for malformed input:
///
/// ```
/// use qub_core::cbor::{deserialize_qub_envelope, CborError};
///
/// // Empty input is not valid CBOR.
/// assert!(matches!(
///     deserialize_qub_envelope(&[]),
///     Err(CborError::DecodingFailed(_))
/// ));
///
/// // A top-level CBOR array (0x80 = empty array) is not a map.
/// assert!(matches!(
///     deserialize_qub_envelope(&[0x80]),
///     Err(CborError::NotAMap)
/// ));
/// ```
pub fn deserialize_qub_envelope(bytes: &[u8]) -> Result<QubEnvelope, CborError> {
    let map = parse_top_level_map(bytes)?;
    reject_structural_elements_in_map(&map)?;
    reject_unknown_keys(&map, ENVELOPE_KEYS_CANONICAL, "QubEnvelope")?;

    let version = extract_u8(&map, "version")?;
    if version != PROTOCOL_VERSION_1 {
        return Err(CborError::UnsupportedVersion(version));
    }

    let body = extract_bytes_bounded(&map, "body", MAX_BODY_SIZE)?;
    let qub_id = extract_fixed_bytes::<32>(&map, "qub_id")?;
    let sig_alg = extract_u8(&map, "sig_alg")?;
    let body_hash = extract_fixed_bytes::<32>(&map, "body_hash")?;
    let unlock_at = extract_i64(&map, "unlock_at")?;
    let created_at = extract_i64(&map, "created_at")?;
    let outcome_at = extract_optional_i64(&map, "outcome_at")?;
    let content_type = extract_u8(&map, "content_type")?;
    let sender_label = extract_optional_text(&map, "sender_label")?;
    if let Some(label) = sender_label.as_deref() {
        // Decode-side mirror of the encoder's Finding-47 hostile-codepoint
        // check plus the Worker-edge 80-code-point length ceiling
        // (`crate::types::validate_sender_label`). Without this, a
        // tampered / third-party artifact could carry bidi overrides,
        // zero-width spoofing codepoints, or an unbounded label past the
        // wire boundary even though every legitimate write path rejects
        // them.
        crate::types::validate_sender_label(label)
            .map_err(|e| CborError::StructuralError(e.to_string()))?;
    }
    let reply_to = extract_optional_fixed_bytes::<32>(&map, "reply_to")?;
    let author_pubkey = extract_optional_bytes(&map, "author_pubkey")?;
    let cosigner_pubkey = extract_optional_bytes(&map, "cosigner_pubkey")?;
    let author_signature = extract_optional_bytes(&map, "author_signature")?;
    let cosigner_signature = extract_optional_bytes(&map, "cosigner_signature")?;

    // Wire-level outcome_at sanity: reject non-positive values
    // outright so the absent sentinel (`None`) is the only way to
    // mean "no outcome" on the wire. Mirrors `ComposeQub::validate`
    // and keeps the qub_id-preimage 0-sentinel disjoint from valid
    // outcomes. The outcome >= unlock cross-check happens on the
    // typed value (the builder doesn't see unlock_at in scope here,
    // and the deserializer's job is shape-validation; semantic
    // outcome>=unlock is checked downstream in the seal/unlock
    // paths and at the Worker edge).
    if let Some(t) = outcome_at
        && t <= 0
    {
        return Err(CborError::StructuralError(format!(
            "outcome_at must be a positive Unix timestamp, got {t}"
        )));
    }

    QubEnvelopeBuilder::new()
        .version(version)
        .qub_id(qub_id)
        .content_type(content_type)
        .created_at(created_at)
        .unlock_at(unlock_at)
        .outcome_at(outcome_at)
        .sender_label(sender_label)
        .reply_to(reply_to)
        .body(body)
        .body_hash(body_hash)
        .sig_alg(sig_alg)
        .author_signature(author_signature)
        .author_pubkey(author_pubkey)
        .cosigner_pubkey(cosigner_pubkey)
        .cosigner_signature(cosigner_signature)
        .build()
        .map_err(|e| CborError::StructuralError(e.to_string()))
}

/// Deserialises canonical CBOR bytes into a [`SealedQub`].
///
/// Applies the same rejection rules as [`deserialize_qub_envelope`]:
/// non-map roots, non-text keys, duplicate keys, CBOR tags, floats, and
/// non-NFC text all produce a [`CborError`].
///
/// # Errors
///
/// Returns a [`CborError`] variant describing the first violation
/// encountered. See [`deserialize_qub_envelope`] for the common variants.
///
/// # Examples
///
/// See [`serialize_sealed_qub`] for a round-trip example.
pub fn deserialize_sealed_qub(bytes: &[u8]) -> Result<SealedQub, CborError> {
    let map = parse_top_level_map(bytes)?;
    reject_structural_elements_in_map(&map)?;
    reject_unknown_keys(&map, SEALED_KEYS_CANONICAL, "SealedQub")?;

    let version = extract_u8(&map, "version")?;
    if version != PROTOCOL_VERSION_1 {
        return Err(CborError::UnsupportedVersion(version));
    }

    let qub_id = extract_fixed_bytes::<32>(&map, "qub_id")?;
    let unlock_at = extract_i64(&map, "unlock_at")?;
    let outcome_at = extract_optional_i64(&map, "outcome_at")?;
    if let Some(t) = outcome_at
        && t <= 0
    {
        return Err(CborError::StructuralError(format!(
            "outcome_at must be a positive Unix timestamp, got {t}"
        )));
    }
    let drand_round = extract_u64(&map, "drand_round")?;
    let visibility = extract_u8(&map, "visibility")?;
    let drand_chain_id = extract_text(&map, "drand_chain_id")?;
    let recipient_pubkey = extract_optional_fixed_bytes::<32>(&map, "recipient_pubkey")?;
    let drand_chain_version = extract_optional_u8(&map, "drand_chain_version")?;
    let tlock_ciphertext = extract_bytes_bounded(&map, "tlock_ciphertext", MAX_CIPHERTEXT_SIZE)?;
    let title = extract_optional_text(&map, "title")?;
    if let Some(s) = title.as_deref() {
        // Reject empty strings: the canonical encoding of an absent
        // title is field omission, not the empty string. Length and
        // control-character checks mirror `validate_title` so wire
        // input cannot bypass the type-level invariants.
        if s.is_empty() || s.chars().count() > MAX_TITLE_CODEPOINTS {
            return Err(CborError::StructuralError(format!(
                "title length out of range (1..={MAX_TITLE_CODEPOINTS} code points)"
            )));
        }
        if s.chars().any(|c| (c as u32) < 0x20 || c == '\u{007F}') {
            return Err(CborError::StructuralError(
                "title contains a control character".into(),
            ));
        }
        // Decode-side mirror of the encoder's Finding-47 check: the C0/DEL
        // branch above catches plain controls, but bidi overrides /
        // isolates, zero-width space, BOM, C1 controls, and the tag block
        // are equally hostile in pre-reveal display text and used to pass
        // the decoder untouched.
        if contains_hostile_text_codepoint(s) {
            return Err(CborError::StructuralError(
                "title contains a hostile / invisible codepoint".into(),
            ));
        }
    }

    SealedQubBuilder::new()
        .version(version)
        .qub_id(qub_id)
        .visibility(visibility)
        .unlock_at(unlock_at)
        .outcome_at(outcome_at)
        .drand_chain_id(drand_chain_id)
        .drand_round(drand_round)
        .drand_chain_version(drand_chain_version)
        .tlock_ciphertext(tlock_ciphertext)
        .recipient_pubkey(recipient_pubkey)
        .title(title)
        .build()
        .map_err(|e| CborError::StructuralError(e.to_string()))
}

// -----------------------------------------------------------------------------
// Map parsing helpers
// -----------------------------------------------------------------------------

/// Representation of a parsed CBOR map as a slice of `(key, value)` pairs.
///
/// We do **not** convert this into a `HashMap` because we need to preserve
/// the original entry order (for debugging) and detect duplicate keys.
pub(crate) type ParsedMap = Vec<(String, Value)>;

/// Parse CBOR bytes into a top-level map, rejecting non-map roots, non-text
/// keys, duplicate keys, trailing bytes after the top-level value,
/// non-canonical encodings, and obvious structural violations.
///
/// The trailing-byte check matters because `ciborium::de::from_reader` only
/// reads one CBOR value and silently ignores any remainder — without the
/// explicit position check below, `{}...junk` would parse. The TS
/// counterpart (`cborg.decode`) rejects trailing bytes by default, and any
/// asymmetry between the two parsers is a split-brain risk for shared
/// Arweave artifacts.
///
/// The canonical-form check (PROTOCOL.md §3.1) closes a subtler asymmetry:
/// `ciborium` decodes non-canonical encodings — indefinite-length items at
/// any depth, non-minimal integer encodings — into the *same* [`Value`] as
/// their canonical equivalents, so neither the value walk nor the field
/// extractors can see the malleability. Re-encoding the decoded value (via
/// the same `ciborium::into_writer` that [`encode_map`] uses) and requiring
/// a byte-for-byte match rejects every such form: it is what guarantees a
/// decoded protocol artifact has a *single* canonical byte representation,
/// which the `body_hash` / signature layer depends on. Canonical input —
/// everything qub's own encoder produces — re-encodes identically and is
/// unaffected.
pub(crate) fn parse_top_level_map(bytes: &[u8]) -> Result<ParsedMap, CborError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| CborError::DecodingFailed(e.to_string()))?;

    let consumed = usize::try_from(cursor.position())
        .map_err(|_| CborError::DecodingFailed("CBOR cursor position exceeds usize".into()))?;
    if consumed != bytes.len() {
        return Err(CborError::DecodingFailed(format!(
            "trailing bytes after CBOR value: consumed {consumed} of {}",
            bytes.len()
        )));
    }

    let mut reencoded = Vec::with_capacity(bytes.len());
    ciborium::into_writer(&value, &mut reencoded)
        .map_err(|e| CborError::EncodingFailed(e.to_string()))?;
    if reencoded != bytes {
        return Err(CborError::StructuralError(
            "non-canonical CBOR encoding: input is not minimal canonical form".into(),
        ));
    }

    let Value::Map(entries) = value else {
        return Err(CborError::NotAMap);
    };

    parsed_map_from_entries(&entries)
}

/// Convert raw CBOR map entries into a [`ParsedMap`], enforcing the
/// structural rules every qub CBOR map obeys at *any* depth: keys must be
/// text, NFC-normalised, and unique. Shared by [`parse_top_level_map`] and
/// the nested pact party / term maps so the duplicate-key and NFC rules
/// hold in nested maps too — not only at the top level.
pub(crate) fn parsed_map_from_entries(entries: &[(Value, Value)]) -> Result<ParsedMap, CborError> {
    let mut out: ParsedMap = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let key_string = match k {
            Value::Text(s) => {
                require_nfc(s)?;
                s.clone()
            },
            _ => return Err(CborError::NonTextKey),
        };
        if out.iter().any(|(existing, _)| existing == &key_string) {
            return Err(CborError::DuplicateKey(key_string));
        }
        // Canonical key-order enforcement (PROTOCOL.md §3.1). The
        // re-encode-and-compare guard in `parse_top_level_map` does NOT catch
        // shuffled keys: `ciborium` preserves the decoded `Value::Map` entry
        // order on re-encode, so a map whose keys are out of canonical order
        // re-encodes to the same (out-of-order) bytes and slips through. Check
        // adjacent keys explicitly here — the single chokepoint shared by the
        // top-level and every nested map — so the rule holds at all depths and
        // a Rust decoder can never accept an artifact a strict TS decoder
        // would reject. (FD-CBOR-MAP-ORDER-MALLEABILITY)
        if let Some((prev, _)) = out.last()
            && canonical_key_cmp(prev, &key_string).is_gt()
        {
            return Err(CborError::StructuralError(format!(
                "non-canonical CBOR encoding: map keys out of canonical order \
                 ({prev:?} must not precede {key_string:?})"
            )));
        }
        out.push((key_string, v.clone()));
    }
    Ok(out)
}

/// Reject any key not in the decoder's allowlist.
///
/// The re-encode-and-compare canonical guard in [`parse_top_level_map`]
/// forces minimal encoding and canonical key order but does **not**
/// forbid extra well-placed keys — so two distinct canonical byte
/// strings could decode to the same struct (`encode(decode(x)) != x`),
/// and for signed payloads (pact terms) a drafter could embed a
/// non-rendered "hidden term" key that both parties' signatures commit
/// to. The TS mirror (`cbor.ts::rejectUnknownKeys`) has always rejected
/// unknown keys; every Rust decoder calls this helper so the two
/// implementations accept byte-identical input sets.
pub(crate) fn reject_unknown_keys(
    map: &ParsedMap,
    allowed: &[&str],
    context: &'static str,
) -> Result<(), CborError> {
    for (key, _) in map {
        if !allowed.contains(&key.as_str()) {
            return Err(CborError::StructuralError(format!(
                "{context}: unknown key {key:?}"
            )));
        }
    }
    Ok(())
}

/// Walk the parsed map's *values* and reject any forbidden CBOR constructs
/// (tags and floats). Does not recurse into deeply nested structures because
/// the qub wire format only contains scalars and byte/text strings at the
/// top level.
pub(crate) fn reject_structural_elements_in_map(map: &ParsedMap) -> Result<(), CborError> {
    for (_, v) in map {
        reject_structural_elements(v, MAX_RECURSION_DEPTH)?;
    }
    Ok(())
}

fn reject_structural_elements(v: &Value, depth: usize) -> Result<(), CborError> {
    if depth == 0 {
        return Err(CborError::DecodingFailed("CBOR nesting too deep".into()));
    }
    match v {
        Value::Tag(_, _) => Err(CborError::ForbiddenTag),
        Value::Float(_) => Err(CborError::ForbiddenFloat),
        Value::Array(xs) => {
            for x in xs {
                reject_structural_elements(x, depth - 1)?;
            }
            Ok(())
        },
        Value::Map(entries) => {
            for (k, vv) in entries {
                reject_structural_elements(k, depth - 1)?;
                reject_structural_elements(vv, depth - 1)?;
            }
            Ok(())
        },
        _ => Ok(()),
    }
}

fn find<'a>(map: &'a ParsedMap, key: &'static str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

const fn type_name(v: &Value) -> &'static str {
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

fn extract_bytes(map: &ParsedMap, key: &'static str) -> Result<Vec<u8>, CborError> {
    match find(map, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "bytes",
            actual: type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

pub(crate) fn extract_bytes_bounded(
    map: &ParsedMap,
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

pub(crate) fn extract_fixed_bytes<const N: usize>(
    map: &ParsedMap,
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

pub(crate) fn extract_u8(map: &ParsedMap, key: &'static str) -> Result<u8, CborError> {
    match find(map, key) {
        Some(Value::Integer(i)) => u8::try_from(*i).map_err(|_| CborError::IntegerOutOfRange(key)),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "integer",
            actual: type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

pub(crate) fn extract_i64(map: &ParsedMap, key: &'static str) -> Result<i64, CborError> {
    match find(map, key) {
        Some(Value::Integer(i)) => i64::try_from(*i).map_err(|_| CborError::IntegerOutOfRange(key)),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "integer",
            actual: type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

pub(crate) fn extract_u64(map: &ParsedMap, key: &'static str) -> Result<u64, CborError> {
    match find(map, key) {
        Some(Value::Integer(i)) => u64::try_from(*i).map_err(|_| CborError::IntegerOutOfRange(key)),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "integer",
            actual: type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

pub(crate) fn extract_optional_i64(
    map: &ParsedMap,
    key: &'static str,
) -> Result<Option<i64>, CborError> {
    match find(map, key) {
        Some(Value::Integer(i)) => i64::try_from(*i)
            .map(Some)
            .map_err(|_| CborError::IntegerOutOfRange(key)),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "integer",
            actual: type_name(other),
        }),
        None => Ok(None),
    }
}

/// Extract an optional `u64` field — `None` when the key is absent.
/// Used by transparency-log leaf / proof fields (W5) where a `u64` may be
/// omitted by leaf kind (e.g. `drand_round` on a `kind=0x02` leaf, or
/// `block_height` on an inclusion proof's anchor reference).
pub(crate) fn extract_optional_u64(
    map: &ParsedMap,
    key: &'static str,
) -> Result<Option<u64>, CborError> {
    match find(map, key) {
        Some(Value::Integer(i)) => u64::try_from(*i)
            .map(Some)
            .map_err(|_| CborError::IntegerOutOfRange(key)),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "integer",
            actual: type_name(other),
        }),
        None => Ok(None),
    }
}

/// Extract an optional `u8` field — `None` when the key is absent.
/// Used by `drand_chain_version` (W3 / UP-B4); an integer outside the
/// `u8` range is a structural error, not a silent truncation.
fn extract_optional_u8(map: &ParsedMap, key: &'static str) -> Result<Option<u8>, CborError> {
    match find(map, key) {
        Some(Value::Integer(i)) => u8::try_from(*i)
            .map(Some)
            .map_err(|_| CborError::IntegerOutOfRange(key)),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "integer",
            actual: type_name(other),
        }),
        None => Ok(None),
    }
}

pub(crate) fn extract_text(map: &ParsedMap, key: &'static str) -> Result<String, CborError> {
    match find(map, key) {
        Some(Value::Text(s)) => {
            require_nfc(s)?;
            Ok(s.clone())
        },
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "text",
            actual: type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

pub(crate) fn extract_optional_text(
    map: &ParsedMap,
    key: &'static str,
) -> Result<Option<String>, CborError> {
    match find(map, key) {
        Some(Value::Text(s)) => {
            require_nfc(s)?;
            Ok(Some(s.clone()))
        },
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "text",
            actual: type_name(other),
        }),
        None => Ok(None),
    }
}

pub(crate) fn extract_optional_bytes(
    map: &ParsedMap,
    key: &'static str,
) -> Result<Option<Vec<u8>>, CborError> {
    match find(map, key) {
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "bytes",
            actual: type_name(other),
        }),
        None => Ok(None),
    }
}

pub(crate) fn extract_optional_fixed_bytes<const N: usize>(
    map: &ParsedMap,
    key: &'static str,
) -> Result<Option<[u8; N]>, CborError> {
    match find(map, key) {
        Some(Value::Bytes(b)) => {
            if b.len() != N {
                return Err(CborError::WrongLength {
                    field: key,
                    expected: N,
                    actual: b.len(),
                });
            }
            let mut out = [0u8; N];
            out.copy_from_slice(b);
            Ok(Some(out))
        },
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "bytes",
            actual: type_name(other),
        }),
        None => Ok(None),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CONTENT_TYPE_TEXT, PROTOCOL_VERSION_1, SIG_ALG_NONE, VISIBILITY_PUBLIC};

    fn sample_envelope() -> QubEnvelope {
        QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([1u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(1_700_000_000)
            .unlock_at(1_800_000_000)
            .body(b"hello world".to_vec())
            .body_hash([2u8; 32])
            .sig_alg(SIG_ALG_NONE)
            .build()
            .unwrap()
    }

    fn sample_envelope_full() -> QubEnvelope {
        QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([3u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(10)
            .outcome_at(Some(20))
            .sender_label(Some("alice".into()))
            .reply_to(Some([0x42; 32]))
            .body(b"hi".to_vec())
            .body_hash([4u8; 32])
            .sig_alg(SIG_ALG_NONE)
            .author_pubkey(Some(vec![9, 9, 9]))
            .cosigner_pubkey(Some(vec![10, 10, 10]))
            .author_signature(Some(vec![7, 7, 7, 7]))
            .cosigner_signature(Some(vec![8, 8, 8, 8, 8]))
            .build()
            .unwrap()
    }

    fn sample_sealed() -> SealedQub {
        SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([5u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(1_800_000_000)
            .drand_chain_id("abcd".into())
            .drand_round(1_234_567)
            .tlock_ciphertext(vec![0xAB, 0xCD, 0xEF])
            .build()
            .unwrap()
    }

    fn sample_sealed_with_recipient() -> SealedQub {
        SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([6u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(0)
            .drand_chain_id("xyz".into())
            .drand_round(1)
            .tlock_ciphertext(vec![1, 2, 3])
            .recipient_pubkey(Some([7u8; 32]))
            .build()
            .unwrap()
    }

    fn sample_sealed_with_title() -> SealedQub {
        SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([8u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(1_800_000_000)
            .drand_chain_id("abcd".into())
            .drand_round(99)
            .tlock_ciphertext(vec![0xDE, 0xAD])
            .title(Some("Q1 BTC call".into()))
            .build()
            .unwrap()
    }

    // -------- Canonical key order sanity --------

    #[test]
    fn envelope_canonical_order_is_sorted() {
        assert_canonical_key_order(ENVELOPE_KEYS_CANONICAL);
    }

    #[test]
    fn sealed_canonical_order_is_sorted() {
        assert_canonical_key_order(SEALED_KEYS_CANONICAL);
    }

    // -------- Round-trip --------

    #[test]
    fn envelope_roundtrip_minimal() {
        let env = sample_envelope();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let back = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_roundtrip_full() {
        let env = sample_envelope_full();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let back = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(env, back);
    }

    // -------- reply_to (Sprint B.1) --------

    #[test]
    fn envelope_without_reply_to_matches_pre_feature_bytes() {
        // Backward-compat invariant: an envelope with `reply_to =
        // None` must produce byte-identical CBOR to what a pre-
        // Feature 5a client would have emitted. If this breaks, old
        // sealed qubs stop verifying — a protocol-level regression.
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(
            !keys.iter().any(|k| k == "reply_to"),
            "reply_to must not appear when None",
        );
    }

    #[test]
    fn envelope_with_reply_to_roundtrips() {
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([9u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(100)
            .unlock_at(200)
            .reply_to(Some([0xAB; 32]))
            .body(b"reply body".to_vec())
            .body_hash([0xBC; 32])
            .sig_alg(SIG_ALG_NONE)
            .build()
            .unwrap();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let back = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(back.reply_to(), Some(&[0xAB; 32]));
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_reply_to_canonical_position() {
        // reply_to (8 bytes) must sort between version (7) and
        // body_hash (9). Emitted key list pins the exact position so
        // accidental reordering breaks the test instead of silently
        // shipping an incompatible wire format.
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([1u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(10)
            .reply_to(Some([0x11; 32]))
            .body(b"x".to_vec())
            .body_hash([2u8; 32])
            .sig_alg(SIG_ALG_NONE)
            .build()
            .unwrap();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let keys = parsed_keys(&bytes);
        assert_eq!(
            keys,
            vec![
                "body",
                "qub_id",
                "sig_alg",
                "version",
                "reply_to",
                "body_hash",
                "unlock_at",
                "created_at",
                "content_type",
            ]
        );
    }

    #[test]
    fn sealed_roundtrip_minimal() {
        let s = sample_sealed();
        let bytes = serialize_sealed_qub(&s).unwrap();
        let back = deserialize_sealed_qub(&bytes).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn sealed_roundtrip_with_recipient() {
        let s = sample_sealed_with_recipient();
        let bytes = serialize_sealed_qub(&s).unwrap();
        let back = deserialize_sealed_qub(&bytes).unwrap();
        assert_eq!(s, back);
    }

    // -------- Determinism --------

    #[test]
    fn envelope_determinism() {
        let env = sample_envelope_full();
        let a = serialize_qub_envelope(&env).unwrap();
        let b = serialize_qub_envelope(&env).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sealed_determinism() {
        let s = sample_sealed_with_recipient();
        let a = serialize_sealed_qub(&s).unwrap();
        let b = serialize_sealed_qub(&s).unwrap();
        assert_eq!(a, b);
    }

    // -------- Key order in emitted bytes --------

    fn parsed_keys(bytes: &[u8]) -> Vec<String> {
        let v: Value = ciborium::de::from_reader(bytes).unwrap();
        match v {
            Value::Map(entries) => entries
                .into_iter()
                .map(|(k, _)| match k {
                    Value::Text(s) => s,
                    _ => panic!("non-text key"),
                })
                .collect(),
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn envelope_minimal_key_order_matches_spec() {
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        let keys = parsed_keys(&bytes);
        assert_eq!(
            keys,
            vec![
                "body",
                "qub_id",
                "sig_alg",
                "version",
                "body_hash",
                "unlock_at",
                "created_at",
                "content_type",
            ]
        );
    }

    #[test]
    fn envelope_full_key_order_matches_spec() {
        let bytes = serialize_qub_envelope(&sample_envelope_full()).unwrap();
        let keys = parsed_keys(&bytes);
        assert_eq!(keys, ENVELOPE_KEYS_CANONICAL.to_vec());
    }

    #[test]
    fn sealed_minimal_key_order_matches_spec() {
        let bytes = serialize_sealed_qub(&sample_sealed()).unwrap();
        let keys = parsed_keys(&bytes);
        assert_eq!(
            keys,
            vec![
                "qub_id",
                "version",
                "unlock_at",
                "visibility",
                "drand_round",
                "drand_chain_id",
                "tlock_ciphertext",
            ]
        );
    }

    #[test]
    fn envelope_outcome_at_round_trip() {
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([1u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(10)
            .outcome_at(Some(1_800_000_000))
            .body(b"x".to_vec())
            .body_hash([2u8; 32])
            .build()
            .unwrap();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let back = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(back.outcome_at(), Some(1_800_000_000));
        assert_eq!(back, env);
    }

    #[test]
    fn envelope_outcome_at_absent_omitted_from_wire() {
        // No outcome_at set ⇒ the key MUST NOT appear in the CBOR
        // map (canonical: absent fields are omitted, not encoded as
        // null). Mirrors the rule for reply_to / sender_label.
        let env = sample_envelope();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(
            !keys.iter().any(|k| k == "outcome_at"),
            "outcome_at key must not appear on the wire when None: {keys:?}"
        );
    }

    #[test]
    fn sealed_outcome_at_round_trip() {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([5u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(1_800_000_000)
            .outcome_at(Some(1_900_000_000))
            .drand_chain_id("abcd".into())
            .drand_round(1_234_567)
            .tlock_ciphertext(vec![0xAB, 0xCD])
            .build()
            .unwrap();
        let bytes = serialize_sealed_qub(&sealed).unwrap();
        let back = deserialize_sealed_qub(&bytes).unwrap();
        assert_eq!(back.outcome_at(), Some(1_900_000_000));
        assert_eq!(back, sealed);
    }

    #[test]
    fn envelope_rejects_non_positive_outcome_at_on_wire() {
        // Hand-craft a CBOR map with outcome_at = 0; the deserializer
        // must reject it (0 is the absent sentinel inside the qub_id
        // preimage; explicit-0 on the wire is therefore ambiguous and
        // refused outright).
        let mut env = sample_envelope_full();
        // Bypass the type-level builder validation by directly
        // mutating the in-memory value, then re-serialising with the
        // bypass — easiest path is to construct the bytes from a
        // raw map that mirrors a real envelope plus outcome_at=0.
        // Faster: round-trip the typed value (outcome_at=unlock_at)
        // and patch one byte.
        env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(*env.qub_id())
            .content_type(env.content_type())
            .created_at(env.created_at())
            .unlock_at(env.unlock_at())
            .outcome_at(Some(env.unlock_at()))
            .body(env.body().to_vec())
            .body_hash(*env.body_hash())
            .build()
            .unwrap();
        let mut bytes = serialize_qub_envelope(&env).unwrap();
        // The "outcome_at" key is encoded as 0x6A "outcome_at"
        // followed by its CBOR-encoded value (currently `0x0A` for
        // i64=10). Patch the value byte to 0x00 (i64=0).
        let needle: &[u8] = b"\x6Aoutcome_at";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("outcome_at key in serialized bytes");
        let value_byte_pos = pos + needle.len();
        bytes[value_byte_pos] = 0x00;
        let err = deserialize_qub_envelope(&bytes).unwrap_err();
        assert!(matches!(err, CborError::StructuralError(_)));
    }

    #[test]
    fn sealed_full_key_order_matches_spec() {
        // Build a SealedQub with every optional field present so we
        // exercise the full canonical key order, including the v1.0
        // `title` field (added alongside the title_hash qub_id binding),
        // the V1.1 `outcome_at` field, and the W3 `drand_chain_version`
        // field (sorts last — longest key).
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([6u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(10)
            .outcome_at(Some(20))
            .drand_chain_id("xyz".into())
            .drand_round(1)
            .drand_chain_version(Some(0))
            .tlock_ciphertext(vec![1, 2, 3])
            .recipient_pubkey(Some([7u8; 32]))
            .title(Some("Q1 BTC call".into()))
            .build()
            .unwrap();
        let bytes = serialize_sealed_qub(&sealed).unwrap();
        let keys = parsed_keys(&bytes);
        assert_eq!(keys, SEALED_KEYS_CANONICAL.to_vec());
    }

    // -------- drand_chain_version (W3 / UP-B4) --------

    /// Build a minimal quicknet `SealedQub`, optionally carrying a
    /// chain-migration version.
    fn sealed_with_version(version: Option<u8>) -> SealedQub {
        SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([9u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(100)
            .drand_chain_id("quicknet".into())
            .drand_round(7)
            .drand_chain_version(version)
            .tlock_ciphertext(vec![0xAA, 0xBB])
            .build()
            .unwrap()
    }

    #[test]
    fn drand_chain_version_round_trips() {
        for v in [Some(0u8), Some(1u8), Some(255u8)] {
            let sealed = sealed_with_version(v);
            let bytes = serialize_sealed_qub(&sealed).unwrap();
            let back = deserialize_sealed_qub(&bytes).unwrap();
            assert_eq!(back.drand_chain_version(), v);
        }
    }

    #[test]
    fn drand_chain_version_none_omits_the_key() {
        // A quicknet seal (version None) must encode byte-identically
        // to the pre-W3 format — the key is absent, not null. This is
        // what keeps every existing on-chain qub valid.
        let sealed = sealed_with_version(None);
        let bytes = serialize_sealed_qub(&sealed).unwrap();
        assert!(!parsed_keys(&bytes).contains(&"drand_chain_version".to_string()));
        assert_eq!(
            deserialize_sealed_qub(&bytes)
                .unwrap()
                .drand_chain_version(),
            None,
        );
    }

    #[test]
    fn versionless_wire_decodes_to_none() {
        // Forward-compat: bytes produced before the field existed (no
        // `drand_chain_version` key at all) decode to None rather than
        // erroring. `sealed_with_version(None)` produces exactly that
        // versionless wire shape.
        let legacy_bytes = serialize_sealed_qub(&sealed_with_version(None)).unwrap();
        let decoded = deserialize_sealed_qub(&legacy_bytes).unwrap();
        assert_eq!(decoded.drand_chain_version(), None);
        assert_eq!(decoded.drand_round(), 7);
        assert_eq!(decoded.drand_chain_id(), "quicknet");
    }

    // -------- Integer / byte encoding --------

    #[test]
    fn version_encodes_as_single_byte() {
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        // Locate the "version" key header 0x67 + "version" = 67 76 65 72 73 69 6f 6e
        // and check the byte immediately after it is 0x01.
        let needle: &[u8] = &[0x67, b'v', b'e', b'r', b's', b'i', b'o', b'n'];
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        assert_eq!(bytes[pos + needle.len()], 0x01);
    }

    #[test]
    fn thirty_two_byte_hash_encoded_with_0x58_0x20_header() {
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        // "body_hash" key header 0x69 + ascii → followed by 0x58 0x20 + 32 bytes.
        let needle: &[u8] = &[0x69, b'b', b'o', b'd', b'y', b'_', b'h', b'a', b's', b'h'];
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        assert_eq!(bytes[pos + needle.len()], 0x58);
        assert_eq!(bytes[pos + needle.len() + 1], 0x20);
    }

    #[test]
    fn positive_timestamp_encodes_as_major_type_0() {
        // created_at=1_700_000_000 → major type 0 (unsigned); 4-byte follow
        // 1_700_000_000 = 0x65524640 → initial byte 0x1A (major 0, info 26)
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        let needle: &[u8] = &[
            0x6A, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
        ];
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        assert_eq!(bytes[pos + needle.len()], 0x1A);
    }

    #[test]
    fn negative_timestamp_encodes_as_major_type_1() {
        // Build an envelope with a negative created_at.
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([1u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(-1)
            .unlock_at(0)
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let needle: &[u8] = &[
            0x6A, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
        ];
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        // -1 = major type 1, value 0 → 0x20.
        assert_eq!(bytes[pos + needle.len()], 0x20);
    }

    #[test]
    fn u64_drand_round_encodes_shortest_form() {
        let s = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(0)
            .drand_chain_id("x".into())
            .drand_round(23)
            .tlock_ciphertext(vec![1])
            .build()
            .unwrap();
        let bytes = serialize_sealed_qub(&s).unwrap();
        // "drand_round" is 11 chars → header 0x6B + bytes.
        let needle: &[u8] = &[
            0x6B, b'd', b'r', b'a', b'n', b'd', b'_', b'r', b'o', b'u', b'n', b'd',
        ];
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        // 23 fits in the initial-byte range (0–23) → 0x17.
        assert_eq!(bytes[pos + needle.len()], 0x17);
    }

    // -------- Optional field omission --------

    #[test]
    fn absent_optional_envelope_fields_omitted() {
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(!keys.contains(&"sender_label".to_string()));
        assert!(!keys.contains(&"author_pubkey".to_string()));
        assert!(!keys.contains(&"author_signature".to_string()));
    }

    #[test]
    fn present_optional_envelope_fields_emitted() {
        let bytes = serialize_qub_envelope(&sample_envelope_full()).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(keys.contains(&"sender_label".to_string()));
        assert!(keys.contains(&"author_pubkey".to_string()));
        assert!(keys.contains(&"author_signature".to_string()));
    }

    #[test]
    fn absent_recipient_pubkey_omitted() {
        let bytes = serialize_sealed_qub(&sample_sealed()).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(!keys.contains(&"recipient_pubkey".to_string()));
    }

    #[test]
    fn absent_title_omitted() {
        let bytes = serialize_sealed_qub(&sample_sealed()).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(!keys.contains(&"title".to_string()));
    }

    #[test]
    fn present_title_round_trips() {
        let sealed = sample_sealed_with_title();
        let bytes = serialize_sealed_qub(&sealed).unwrap();
        let decoded = deserialize_sealed_qub(&bytes).unwrap();
        assert_eq!(decoded, sealed);
        assert_eq!(decoded.title(), Some("Q1 BTC call"));
        let keys = parsed_keys(&bytes);
        assert!(keys.contains(&"title".to_string()));
    }

    /// Cross-language byte vector for `sample_sealed_with_title`.
    ///
    /// The expected hex is the canonical wire encoding. If this test fails, the
    /// Rust encoder has changed and the TypeScript mirror must be re-checked
    /// against it — `workers/api/src/crypto/__tests__/cross-impl.test.ts`, which
    /// reads `tests/vectors/wrapper_v1.json` and runs on every PR.
    ///
    /// This comment named `crypto/cbor-vectors.ts` until 2026-08-24. That file
    /// was a hand-maintained second copy of the same check that nothing imported
    /// and nothing ran, and it was deleted — so the instruction pointed at a
    /// file that did not exist, which is worse than pointing at nothing.
    #[test]
    fn sealed_with_title_canonical_bytes() {
        use std::fmt::Write as _;
        let bytes = serialize_sealed_qub(&sample_sealed_with_title()).unwrap();
        let mut hex_str = String::with_capacity(bytes.len() * 2);
        for b in &bytes {
            let _ = write!(hex_str, "{b:02x}");
        }
        // Pinned reference. Recompute (and update both sides) only if the
        // canonical CBOR encoding rules change.
        assert_eq!(
            hex_str,
            "a8657469746c656b5131204254432063616c6c667175625f6964582008080808080808080808080808080808080808080808080808080808080808086776657273696f6e0169756e6c6f636b5f61741a6b49d2006a7669736962696c697479016b6472616e645f726f756e6418636e6472616e645f636861696e5f6964646162636470746c6f636b5f6369706865727465787442dead",
            "canonical bytes drifted — re-check the TypeScript mirror via \
             workers/api/src/crypto/__tests__/cross-impl.test.ts",
        );
    }

    #[test]
    fn title_is_first_key_in_canonical_order() {
        // Canonical CBOR sorts map keys by encoded length first, then lex.
        // "title" → 6 encoded bytes, shorter than every other SealedQub
        // key, so when present it MUST appear first in the wire form.
        let bytes = serialize_sealed_qub(&sample_sealed_with_title()).unwrap();
        let keys = parsed_keys(&bytes);
        assert_eq!(keys.first().map(String::as_str), Some("title"));
    }

    #[test]
    fn empty_string_title_rejected_on_decode() {
        // The canonical encoding of an absent title is field omission.
        // An empty string in the title slot is a non-canonical
        // representation of "absent" and must be rejected.
        use ciborium::{Value, cbor};
        let map = cbor!({
            "title" => "",
            "qub_id" => Value::Bytes(vec![5u8; 32]),
            "version" => 1u8,
            "unlock_at" => 1_800_000_000i64,
            "visibility" => 1u8,
            "drand_round" => 1u64,
            "drand_chain_id" => "abcd",
            "tlock_ciphertext" => Value::Bytes(vec![0xAA]),
        })
        .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("title")),
            "expected title-related StructuralError, got {err:?}",
        );
    }

    /// An extra well-formed key in canonical position re-encodes
    /// byte-identically, so the canonical-form guard alone cannot catch
    /// it — two distinct canonical byte strings would decode to the
    /// same struct. The TS decoder has always rejected unknown keys;
    /// the Rust side must match (`encode(decode(x)) == x`).
    #[test]
    fn unknown_key_rejected_on_decode() {
        use ciborium::{Value, cbor};
        // "zz" (2 chars → 3 encoded bytes) sorts before every real
        // SealedQub key in length-then-lex canonical order.
        let map = cbor!({
            "zz" => 1u8,
            "title" => "Q1 call",
            "qub_id" => Value::Bytes(vec![5u8; 32]),
            "version" => 1u8,
            "unlock_at" => 1_800_000_000i64,
            "visibility" => 1u8,
            "drand_round" => 1u64,
            "drand_chain_id" => "abcd",
            "tlock_ciphertext" => Value::Bytes(vec![0xAA]),
        })
        .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("unknown key")),
            "expected unknown-key StructuralError, got {err:?}",
        );
    }

    // -------- A5: decode-side hostile-codepoint / length tampering --------

    /// Raw canonical-order `SealedQub` map with an attacker-chosen title.
    fn raw_sealed_with_title(title: &str) -> Vec<u8> {
        use ciborium::{Value, cbor};
        let map = cbor!({
            "title" => title,
            "qub_id" => Value::Bytes(vec![5u8; 32]),
            "version" => 1u8,
            "unlock_at" => 1_800_000_000i64,
            "visibility" => 1u8,
            "drand_round" => 1u64,
            "drand_chain_id" => "abcd",
            "tlock_ciphertext" => Value::Bytes(vec![0xAA]),
        })
        .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// Raw canonical-order `QubEnvelope` map with an attacker-chosen
    /// `sender_label`.
    fn raw_envelope_with_sender_label(label: &str) -> Vec<u8> {
        use ciborium::{Value, cbor};
        let map = cbor!({
            "body" => Value::Bytes(b"hi".to_vec()),
            "qub_id" => Value::Bytes(vec![1u8; 32]),
            "sig_alg" => 0u8,
            "version" => 1u8,
            "body_hash" => Value::Bytes(vec![2u8; 32]),
            "unlock_at" => 1_800_000_000i64,
            "created_at" => 1_700_000_000i64,
            "content_type" => 1u8,
            "sender_label" => label,
        })
        .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// The decoder's OWN title guards were unobservable, and the way
    /// they were unobservable is the lesson. `deserialize_sealed_qub`
    /// ends in `SealedQubBuilder::build()`, whose `validate_title`
    /// rejects the same inputs with its own title-flavoured message. Every
    /// existing test asserted only that the error mentions "title", so
    /// mutation could delete a decoder guard entirely — flipping either
    /// `||` to `&&` — and the downstream builder silently covered for it.
    /// The suite stayed green while the wire-input check was gone.
    ///
    /// Asserting the DECODER's exact wording is what separates "the
    /// decoder rejected this" from "something eventually did".
    #[test]
    fn decoder_title_guards_fire_before_the_builder_covers_for_them() {
        for (title, want) in [
            (String::new(), "length out of range"),
            ("a".repeat(MAX_TITLE_CODEPOINTS + 1), "length out of range"),
            ("ok\u{0001}".to_owned(), "control character"),
            ("ok\u{007F}".to_owned(), "control character"),
        ] {
            let buf = raw_sealed_with_title(&title);
            let err = deserialize_sealed_qub(&buf).unwrap_err();
            let CborError::StructuralError(ref m) = err else {
                panic!("expected StructuralError for {title:?}, got {err:?}")
            };
            assert!(
                m.contains(want),
                "title {title:?} must be rejected by the decoder's own {want:?} \
                 guard, not by a later one; got {m:?}",
            );
        }
    }

    /// The other half of the length arm: a title of EXACTLY the limit is
    /// legal and must decode. Without this, `>` and `>=` are
    /// indistinguishable — the over-length case above fails identically
    /// under both — and mutation duly survived the boundary flip. A
    /// rejection test alone can never pin a boundary; it takes the
    /// largest accepted value AND the smallest rejected one.
    /// The nesting-depth guard had NO test at all, and all six mutants on
    /// its three `depth - 1` sites survived. Both replacements (`+` and
    /// `/`) stop the counter ever reaching zero, so arbitrarily deep
    /// attacker-supplied CBOR would be walked instead of refused — the
    /// guard was, in effect, deleted.
    ///
    /// THREE recursion sites, three container shapes. The first attempt
    /// here nested only ARRAYS and left four mutants alive, because a map
    /// recurses separately into its KEYS and its VALUES and neither arm
    /// is reachable through an array. Each shape below exists to reach one
    /// site; dropping any one of them un-kills two mutants.
    ///
    /// Both directions are asserted per shape: a rejection test alone
    /// cannot tell a working limit from one that refuses everything.
    /// `assert_canonical_key_order` is the debug-build guard that catches
    /// a hand-maintained key table drifting out of canonical order. Its
    /// whole body could be replaced with `()` — deleting the guard — and
    /// nothing failed, because nothing had ever made it FIRE. A control
    /// that has only ever passed carries no evidence.
    ///
    /// Canonical CBOR orders map keys by LENGTH first, then
    /// lexicographically, so "bb" must precede "aaa"; the reverse is the
    /// violation the guard exists to catch.
    ///
    /// DEBUG BUILDS ONLY, and the reason matters: there are two
    /// definitions of this function. The `#[cfg(not(debug_assertions))]`
    /// one is a no-op stub, so in a release-profile build there is no
    /// assertion to fire and a `should_panic` test cannot pass. That is
    /// not a gap — the mutation lane runs under the test profile, where
    /// the real definition is live and its mutant dies here.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "canonical key order violated")]
    fn assert_canonical_key_order_fires_on_disorder() {
        assert_canonical_key_order(&["aaa", "bb"]);
    }

    /// ...and does not fire on a correctly ordered table, so the guard is
    /// pinned in both directions rather than merely known to panic.
    #[test]
    fn assert_canonical_key_order_accepts_canonical_order() {
        assert_canonical_key_order(&["bb", "aaa"]);
        assert_canonical_key_order(SEALED_KEYS_CANONICAL);
    }

    #[test]
    fn nesting_depth_guard_rejects_beyond_the_limit_and_accepts_within_it() {
        // Array elements — `reject_structural_elements(x, depth - 1)`.
        fn nest_array(levels: usize) -> Value {
            let mut v = Value::Bool(true);
            for _ in 0..levels {
                v = Value::Array(vec![v]);
            }
            v
        }
        // Map VALUES — `reject_structural_elements(vv, depth - 1)`.
        fn nest_map_value(levels: usize) -> Value {
            let mut v = Value::Bool(true);
            for _ in 0..levels {
                v = Value::Map(vec![(Value::Null, v)]);
            }
            v
        }
        // Map KEYS — `reject_structural_elements(k, depth - 1)`. A nested
        // key is legal CBOR and is its own recursion arm.
        fn nest_map_key(levels: usize) -> Value {
            let mut v = Value::Bool(true);
            for _ in 0..levels {
                v = Value::Map(vec![(v, Value::Null)]);
            }
            v
        }

        for (shape, build) in [
            ("array", nest_array as fn(usize) -> Value),
            ("map value", nest_map_value),
            ("map key", nest_map_key),
        ] {
            assert!(
                reject_structural_elements(&build(MAX_RECURSION_DEPTH - 1), MAX_RECURSION_DEPTH)
                    .is_ok(),
                "{shape} nesting within the limit must be accepted"
            );

            let err =
                reject_structural_elements(&build(MAX_RECURSION_DEPTH + 1), MAX_RECURSION_DEPTH)
                    .expect_err("nesting beyond the limit must be rejected");
            assert!(
                matches!(err, CborError::DecodingFailed(ref m) if m.contains("nesting too deep")),
                "{shape}: expected a nesting-depth rejection, got {err:?}"
            );
        }
    }

    #[test]
    fn extract_bytes_bounded_pins_both_sides_of_the_limit() {
        let map = |n: usize| -> ParsedMap { vec![("k".to_owned(), Value::Bytes(vec![0xAA; n]))] };
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
    fn decoder_accepts_a_title_of_exactly_the_limit() {
        let title = "a".repeat(MAX_TITLE_CODEPOINTS);
        let buf = raw_sealed_with_title(&title);
        let sealed = deserialize_sealed_qub(&buf)
            .expect("a title of exactly MAX_TITLE_CODEPOINTS must be accepted");
        assert_eq!(sealed.title(), Some(title.as_str()));
    }

    #[test]
    fn hostile_codepoint_title_rejected_on_decode() {
        // The encoder refuses to write these, so a wire artifact carrying
        // them is by definition tampered / third-party. Each codepoint is
        // NFC-stable, so the NFC gate alone would let it through. U+202E
        // (RLO bidi override), U+200B (ZWSP), U+FEFF (BOM), U+E0041
        // (tag-block 'A'), U+0085 (C1 NEL).
        for hostile in [
            "ok\u{202E}",
            "ok\u{200B}",
            "ok\u{FEFF}",
            "ok\u{E0041}",
            "ok\u{0085}",
        ] {
            let buf = raw_sealed_with_title(hostile);
            let err = deserialize_sealed_qub(&buf).unwrap_err();
            assert!(
                matches!(err, CborError::StructuralError(ref m) if m.contains("title")),
                "hostile title {hostile:?} must be rejected, got {err:?}",
            );
        }
    }

    #[test]
    fn hostile_codepoint_sender_label_rejected_on_decode() {
        // Includes a plain C0 control ("ok\u{0007}") — pre-A5 the decode
        // path applied NO validation at all to sender_label.
        for hostile in [
            "ok\u{0007}",
            "ok\u{202E}",
            "ok\u{200B}",
            "ok\u{FEFF}",
            "ok\u{E0041}",
            "ok\u{0085}",
        ] {
            let buf = raw_envelope_with_sender_label(hostile);
            let err = deserialize_qub_envelope(&buf).unwrap_err();
            assert!(
                matches!(err, CborError::StructuralError(ref m) if m.contains("sender_label")),
                "hostile sender_label {hostile:?} must be rejected, got {err:?}",
            );
        }
    }

    #[test]
    fn oversized_sender_label_rejected_on_decode() {
        // 81 code points — one over the Worker-mirrored 80-cp ceiling.
        let long = "a".repeat(81);
        let buf = raw_envelope_with_sender_label(&long);
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("sender_label")),
            "over-long sender_label must be rejected, got {err:?}",
        );
        // Exactly 80 code points decodes fine.
        let ok = "a".repeat(80);
        let buf = raw_envelope_with_sender_label(&ok);
        let parsed = deserialize_qub_envelope(&buf).unwrap();
        assert_eq!(parsed.sender_label(), Some(ok.as_str()));
    }

    #[test]
    fn oversized_sender_label_rejected_on_encode() {
        // Encode-side mirror: the serialiser refuses to produce a wire
        // artifact the decoder would reject.
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([1u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(10)
            .sender_label(Some("a".repeat(81)))
            .body(b"hi".to_vec())
            .body_hash([2u8; 32])
            .build()
            .unwrap();
        let err = serialize_qub_envelope(&env).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("sender_label")),
            "over-long sender_label must be rejected on encode, got {err:?}",
        );
    }

    // -------- Cosigner fields --------

    #[test]
    fn envelope_roundtrip_with_cosigner() {
        let env = sample_envelope_full();
        assert!(env.cosigner_pubkey().is_some());
        assert!(env.cosigner_signature().is_some());
        let bytes = serialize_qub_envelope(&env).unwrap();
        let parsed = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn envelope_roundtrip_without_cosigner_backward_compat() {
        // Envelope without cosigner fields produces the same bytes as
        // pre-cosigner code would have.
        let env = sample_envelope();
        assert!(env.cosigner_pubkey().is_none());
        assert!(env.cosigner_signature().is_none());
        let bytes = serialize_qub_envelope(&env).unwrap();
        let keys = parsed_keys(&bytes);
        assert!(!keys.contains(&"cosigner_pubkey".to_string()));
        assert!(!keys.contains(&"cosigner_signature".to_string()));
        let parsed = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn envelope_cosigner_key_order() {
        let env = sample_envelope_full();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let keys = parsed_keys(&bytes);
        // cosigner_pubkey must come after author_pubkey and before
        // author_signature in canonical order.
        let cpk_pos = keys.iter().position(|k| k == "cosigner_pubkey").unwrap();
        let apk_pos = keys.iter().position(|k| k == "author_pubkey").unwrap();
        let asig_pos = keys.iter().position(|k| k == "author_signature").unwrap();
        let csig_pos = keys.iter().position(|k| k == "cosigner_signature").unwrap();
        assert!(apk_pos < cpk_pos, "author_pubkey before cosigner_pubkey");
        assert!(
            cpk_pos < asig_pos,
            "cosigner_pubkey before author_signature"
        );
        assert!(
            asig_pos < csig_pos,
            "author_signature before cosigner_signature"
        );
    }

    #[test]
    fn envelope_cosigner_one_without_other_parses() {
        // Only cosigner_pubkey present, no cosigner_signature — should
        // parse successfully (validation is a higher-level concern).
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([3u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(10)
            .body(b"hi".to_vec())
            .body_hash([4u8; 32])
            .cosigner_pubkey(Some(vec![1, 2, 3]))
            .build()
            .unwrap();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let parsed = deserialize_qub_envelope(&bytes).unwrap();
        assert!(parsed.cosigner_pubkey().is_some());
        assert!(parsed.cosigner_signature().is_none());
    }

    // -------- Error handling --------

    #[test]
    fn deserialize_garbage_fails() {
        let err = deserialize_qub_envelope(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert!(matches!(err, CborError::DecodingFailed(_)));
    }

    #[test]
    fn deserialize_non_map_root_fails() {
        // CBOR integer 1 at the root.
        let err = deserialize_qub_envelope(&[0x01]).unwrap_err();
        assert!(matches!(err, CborError::NotAMap));
    }

    #[test]
    fn deserialize_missing_required_field() {
        // Build a map missing "body_hash" by serialising a full envelope then
        // re-encoding its Value tree with that key removed.
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
        let Value::Map(mut entries) = value else {
            panic!()
        };
        entries.retain(|(k, _)| !matches!(k, Value::Text(s) if s == "body_hash"));
        let mut mutated = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut mutated).unwrap();
        let err = deserialize_qub_envelope(&mutated).unwrap_err();
        assert_eq!(err, CborError::MissingField("body_hash"));
    }

    #[test]
    fn deserialize_duplicate_key_rejected() {
        // Synthesise a CBOR map that contains "version" twice.
        let entries = vec![
            (
                Value::Text("version".into()),
                Value::Integer(Integer::from(1u8)),
            ),
            (
                Value::Text("version".into()),
                Value::Integer(Integer::from(1u8)),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert!(matches!(err, CborError::DuplicateKey(ref k) if k == "version"));
    }

    #[test]
    fn deserialize_wrong_version_rejected() {
        // Build a minimally valid envelope map but with version=2.
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("sig_alg".into()), u8_value(0)),
            (Value::Text("version".into()), u8_value(2)),
            (Value::Text("body_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("created_at".into()), i64_value(0)),
            (Value::Text("content_type".into()), u8_value(1)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(err, CborError::UnsupportedVersion(2));
    }

    #[test]
    fn deserialize_float_rejected() {
        // Inject a float as the value of "version". Keys are in canonical
        // order ("body" (4) before "version" (7)) so the new decode-side
        // key-order check passes and the float is what gets rejected.
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("version".into()), Value::Float(1.0)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(err, CborError::ForbiddenFloat);
    }

    #[test]
    fn deserialize_tag_rejected() {
        let entries = vec![(
            Value::Text("version".into()),
            Value::Tag(42, Box::new(Value::Integer(Integer::from(1u8)))),
        )];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(err, CborError::ForbiddenTag);
    }

    // -------- Canonical-form rejection (SEC-1) --------

    /// A non-minimal integer encoding — the value `1` written in the
    /// uint8-follows form (`0x18 0x01`) rather than the canonical single
    /// byte `0x01` — must be rejected; the canonical encoding of the same
    /// logical map must still be accepted.
    #[test]
    fn reject_non_minimal_integer_encoding() {
        // {"v": 1} with the value encoded non-minimally as 0x18 0x01.
        let non_minimal = [0xA1, 0x61, 0x76, 0x18, 0x01];
        let err = parse_top_level_map(&non_minimal).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("non-canonical")),
            "expected non-canonical rejection, got {err:?}",
        );
        // The canonical encoding of the same map is accepted.
        let canonical = [0xA1, 0x61, 0x76, 0x01];
        assert!(parse_top_level_map(&canonical).is_ok());
    }

    /// Indefinite-length items — top-level and nested as a field value,
    /// for arrays, maps, byte strings and text strings — must be rejected.
    /// `ciborium` decodes them into the same `Value` as their
    /// definite-length equivalents, so only the re-encode check catches
    /// them.
    #[test]
    fn reject_indefinite_length_items() {
        // Top-level indefinite-length map: 0xBF ... 0xFF.
        assert!(matches!(
            parse_top_level_map(&[0xBF, 0xFF]).unwrap_err(),
            CborError::StructuralError(_),
        ));
        // {"v": [_ ]} — nested indefinite-length array.
        assert!(matches!(
            parse_top_level_map(&[0xA1, 0x61, 0x76, 0x9F, 0xFF]).unwrap_err(),
            CborError::StructuralError(_),
        ));
        // {"v": {_ }} — nested indefinite-length map.
        assert!(matches!(
            parse_top_level_map(&[0xA1, 0x61, 0x76, 0xBF, 0xFF]).unwrap_err(),
            CborError::StructuralError(_),
        ));
        // {"v": (_ )} — nested indefinite-length byte string.
        assert!(matches!(
            parse_top_level_map(&[0xA1, 0x61, 0x76, 0x5F, 0xFF]).unwrap_err(),
            CborError::StructuralError(_),
        ));
        // {"v": (_ )} — nested indefinite-length text string.
        assert!(matches!(
            parse_top_level_map(&[0xA1, 0x61, 0x76, 0x7F, 0xFF]).unwrap_err(),
            CborError::StructuralError(_),
        ));
    }

    /// Out-of-order map keys must be rejected even though `ciborium`
    /// preserves decoded `Value::Map` order on re-encode (so the
    /// re-encode-and-compare guard alone would accept a shuffled map).
    /// (FD-CBOR-MAP-ORDER-MALLEABILITY)
    #[test]
    fn reject_out_of_order_map_keys() {
        // {"version": 1, "body": h'78'} — "version" (7) before "body" (4)
        // is out of canonical order (shorter encoded length must come
        // first). ciborium re-encodes it byte-identically, so only the
        // explicit decode-side order check rejects it.
        let shuffled = vec![
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(shuffled), &mut buf).unwrap();
        let err = parse_top_level_map(&buf).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("non-canonical")),
            "expected non-canonical key-order rejection, got {err:?}",
        );

        // The same two keys in canonical order ("body" before "version")
        // parse cleanly.
        let canonical = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("version".into()), u8_value(1)),
        ];
        let mut ok_buf = Vec::new();
        ciborium::into_writer(&Value::Map(canonical), &mut ok_buf).unwrap();
        assert!(parse_top_level_map(&ok_buf).is_ok());
    }

    /// The canonical-form check must not regress valid artifacts: a
    /// canonically-encoded envelope still parses and round-trips.
    #[test]
    fn canonical_envelope_passes_canonical_check() {
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        assert!(parse_top_level_map(&bytes).is_ok());
        assert_eq!(deserialize_qub_envelope(&bytes).unwrap(), sample_envelope());
    }

    // -------- Unknown-key rejection (TS parity) --------

    #[test]
    fn deserialize_unknown_key_rejected() {
        // Unknown keys were previously tolerated ("forward
        // compatibility"), but the TS decoder rejects them
        // (`cbor.ts::rejectUnknownKeys`) — the asymmetry was a
        // split-brain risk and, for signed payloads, a hidden-content
        // vector. Schema evolution goes through `version`, not extra
        // keys.
        let bytes = serialize_qub_envelope(&sample_envelope()).unwrap();
        let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
        let Value::Map(mut entries) = value else {
            panic!()
        };
        entries.push((
            Value::Text("future_field".into()),
            Value::Bytes(vec![0xDE, 0xAD]),
        ));
        let mut mutated = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut mutated).unwrap();
        let err = deserialize_qub_envelope(&mutated).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(ref m) if m.contains("unknown key")),
            "expected unknown-key StructuralError, got {err:?}",
        );
    }

    // -------- NFC --------

    #[test]
    fn serialize_normalises_nfc() {
        // "é" as U+0065 U+0301 (NFD) should be normalised to U+00E9 on encode.
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(0)
            .sender_label(Some("e\u{0301}".into()))
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let back = deserialize_qub_envelope(&bytes).unwrap();
        assert_eq!(back.sender_label(), Some("\u{00E9}"));
    }

    #[test]
    fn deserialize_rejects_non_nfc_text() {
        // Hand-build a map containing an NFD sender_label.
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("sig_alg".into()), u8_value(0)),
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("body_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("created_at".into()), i64_value(0)),
            (Value::Text("content_type".into()), u8_value(1)),
            (
                Value::Text("sender_label".into()),
                Value::Text("e\u{0301}".into()),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(err, CborError::NfcNormalisationRequired);
    }

    // -------- Missing error variant coverage --------

    #[test]
    fn deserialize_rejects_non_text_key() {
        // Build a CBOR map where one key is an integer instead of text.
        let entries = vec![
            (
                Value::Integer(Integer::from(42)),
                Value::Bytes(b"x".to_vec()),
            ),
            (Value::Text("version".into()), u8_value(1)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(err, CborError::NonTextKey);
    }

    #[test]
    fn deserialize_rejects_integer_out_of_range_for_u8() {
        // Build a valid-looking envelope but with version = 9999 (overflows u8).
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("sig_alg".into()), u8_value(0)),
            (
                Value::Text("version".into()),
                Value::Integer(Integer::from(9999)),
            ),
            (Value::Text("body_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("created_at".into()), i64_value(0)),
            (Value::Text("content_type".into()), u8_value(1)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(err, CborError::IntegerOutOfRange("version"));
    }

    #[test]
    fn deserialize_rejects_wrong_length_qub_id() {
        // Build a map with a 16-byte qub_id instead of required 32 bytes.
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("sig_alg".into()), u8_value(0)),
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("body_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("created_at".into()), i64_value(0)),
            (Value::Text("content_type".into()), u8_value(1)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(
            err,
            CborError::WrongLength {
                field: "qub_id",
                expected: 32,
                actual: 16,
            }
        );
    }

    #[test]
    fn deserialize_rejects_wrong_length_body_hash() {
        // body_hash is 10 bytes instead of 32.
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("sig_alg".into()), u8_value(0)),
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("body_hash".into()), Value::Bytes(vec![0u8; 10])),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("created_at".into()), i64_value(0)),
            (Value::Text("content_type".into()), u8_value(1)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert_eq!(
            err,
            CborError::WrongLength {
                field: "body_hash",
                expected: 32,
                actual: 10,
            }
        );
    }

    #[test]
    fn deserialize_structural_error_from_empty_body() {
        // version=1 but body is empty → QubEnvelopeBuilder::build fails →
        // StructuralError.
        let entries = vec![
            (Value::Text("body".into()), Value::Bytes(vec![])),
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("sig_alg".into()), u8_value(0)),
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("body_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("created_at".into()), i64_value(0)),
            (Value::Text("content_type".into()), u8_value(1)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_qub_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CborError::StructuralError(_)),
            "expected StructuralError, got {err:?}"
        );
    }

    #[test]
    fn deserialize_sealed_rejects_negative_drand_round() {
        // drand_round as -1 → IntegerOutOfRange.
        let entries = vec![
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("visibility".into()), u8_value(1)),
            (
                Value::Text("drand_round".into()),
                Value::Integer(Integer::from(-1)),
            ),
            (
                Value::Text("drand_chain_id".into()),
                Value::Text("chain".into()),
            ),
            (
                Value::Text("tlock_ciphertext".into()),
                Value::Bytes(vec![0xAA]),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert_eq!(err, CborError::IntegerOutOfRange("drand_round"));
    }

    #[test]
    fn deserialize_sealed_rejects_non_text_key() {
        let entries = vec![(Value::Integer(Integer::from(1)), Value::Bytes(vec![0xAA]))];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert_eq!(err, CborError::NonTextKey);
    }

    #[test]
    fn deserialize_sealed_wrong_length_recipient_pubkey() {
        // recipient_pubkey must be 32 bytes; provide 10.
        let entries = vec![
            (Value::Text("qub_id".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("version".into()), u8_value(1)),
            (Value::Text("unlock_at".into()), i64_value(0)),
            (Value::Text("visibility".into()), u8_value(1)),
            (
                Value::Text("drand_round".into()),
                Value::Integer(Integer::from(100u64)),
            ),
            (
                Value::Text("drand_chain_id".into()),
                Value::Text("chain".into()),
            ),
            (
                Value::Text("recipient_pubkey".into()),
                Value::Bytes(vec![0u8; 10]),
            ),
            (
                Value::Text("tlock_ciphertext".into()),
                Value::Bytes(vec![0xAA]),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert_eq!(
            err,
            CborError::WrongLength {
                field: "recipient_pubkey",
                expected: 32,
                actual: 10,
            }
        );
    }

    // -------- Error Display coverage --------

    #[test]
    fn cbor_error_display_all_variants() {
        // Exercise Display impl on every variant.
        let variants: Vec<CborError> = vec![
            CborError::EncodingFailed("enc".into()),
            CborError::DecodingFailed("dec".into()),
            CborError::UnexpectedType {
                field: "f",
                expected: "bytes",
                actual: "text",
            },
            CborError::MissingField("version"),
            CborError::DuplicateKey("k".into()),
            CborError::UnsupportedVersion(99),
            CborError::ForbiddenTag,
            CborError::ForbiddenFloat,
            CborError::NfcNormalisationRequired,
            CborError::NotAMap,
            CborError::NonTextKey,
            CborError::IntegerOutOfRange("drand_round"),
            CborError::WrongLength {
                field: "qub_id",
                expected: 32,
                actual: 16,
            },
            CborError::StructuralError("bad".into()),
            CborError::PayloadTooLarge {
                field: "body",
                size: 100_000,
                max: 65_536,
            },
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display should not be empty for {v:?}");
        }
        assert_eq!(variants.len(), 15);
    }

    // -------- type_name coverage --------

    #[test]
    fn type_name_returns_correct_string_for_each_variant() {
        // Exercise every match arm in type_name() and verify the exact
        // string — killing mutants that delete arms or replace the return.
        assert_eq!(type_name(&Value::Integer(42.into())), "integer");
        assert_eq!(type_name(&Value::Bytes(vec![0x00])), "bytes");
        assert_eq!(type_name(&Value::Text("hi".into())), "text");
        assert_eq!(type_name(&Value::Array(vec![])), "array");
        assert_eq!(type_name(&Value::Map(vec![])), "map");
        assert_eq!(type_name(&Value::Tag(1, Box::new(Value::Null))), "tag");
        assert_eq!(type_name(&Value::Bool(true)), "bool");
        assert_eq!(type_name(&Value::Null), "null");
        assert_eq!(type_name(&Value::Float(1.0)), "float");
    }

    #[test]
    fn unexpected_type_error_includes_type_name() {
        // Feed a boolean where an integer is expected for `version`;
        // verify the error message contains the type_name output.
        let map = vec![(Value::Text("version".into()), Value::Bool(true))];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bool"),
            "error should name the actual type 'bool', got: {msg}"
        );
        assert!(
            msg.contains("version"),
            "error should name the field 'version', got: {msg}"
        );
    }

    // -------- reject_structural_elements coverage --------

    #[test]
    fn reject_tag_nested_in_array_value() {
        // A tag buried inside an array field should be caught by the
        // recursive reject_structural_elements traversal.
        let tagged = Value::Tag(1, Box::new(Value::Integer(42.into())));
        let map = vec![
            (Value::Text("qub_id".into()), Value::Bytes(vec![0; 32])),
            (Value::Text("version".into()), Value::Array(vec![tagged])),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert_eq!(err, CborError::ForbiddenTag);
    }

    #[test]
    fn reject_float_nested_in_map_value() {
        // A float buried inside a nested map should be caught.
        let inner_map = Value::Map(vec![(Value::Text("nested".into()), Value::Float(1.5))]);
        let map = vec![
            (Value::Text("qub_id".into()), Value::Bytes(vec![0; 32])),
            (Value::Text("version".into()), inner_map),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut buf).unwrap();
        let err = deserialize_sealed_qub(&buf).unwrap_err();
        assert_eq!(err, CborError::ForbiddenFloat);
    }

    // -------- Property test --------

    use proptest::prelude::*;

    /// Regression for finding H-4 (2026-04 security review): a canonical
    /// `SealedQub` with junk bytes appended must be rejected. Without the
    /// explicit `cursor.position() == bytes.len()` check in
    /// `parse_top_level_map`, `ciborium::de::from_reader` would silently
    /// consume the valid prefix and ignore the remainder — the Rust side
    /// would accept bytes that the Worker-side TS parser (cborg) rejects,
    /// producing a split-brain read of the same Arweave artifact.
    #[test]
    fn parse_rejects_trailing_bytes_after_sealed() {
        let sealed = sample_sealed();
        let mut bytes = serialize_sealed_qub(&sealed).unwrap();
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let err = deserialize_sealed_qub(&bytes).unwrap_err();
        assert!(
            matches!(err, CborError::DecodingFailed(ref s) if s.contains("trailing bytes")),
            "expected DecodingFailed(trailing bytes…), got {err:?}",
        );
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_envelope() {
        let env = sample_envelope();
        let mut bytes = serialize_qub_envelope(&env).unwrap();
        bytes.push(0x00); // single trailing byte is enough
        let err = deserialize_qub_envelope(&bytes).unwrap_err();
        assert!(
            matches!(err, CborError::DecodingFailed(ref s) if s.contains("trailing bytes")),
            "expected DecodingFailed(trailing bytes…), got {err:?}",
        );
    }

    proptest! {
        // Default config natively; under Miri, 8 cases from a fixed seed —
        // Miri checks the code paths for UB rather than exploring inputs. The
        // full argument is on `tests/common/mod.rs::config`.
        #![proptest_config(if cfg!(miri) {
            ProptestConfig {
                cases: 8,
                rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed_09ab),
                ..ProptestConfig::default()
            }
        } else {
            ProptestConfig::default()
        })]

        #[test]
        fn prop_envelope_roundtrip(
            body in proptest::collection::vec(any::<u8>(), 1..64),
            created_at in any::<i64>(),
            unlock_at in any::<i64>(),
            qub_id in any::<[u8; 32]>(),
            body_hash in any::<[u8; 32]>(),
            include_label in any::<bool>(),
        ) {
            let mut b = QubEnvelopeBuilder::new()
                .version(PROTOCOL_VERSION_1)
                .qub_id(qub_id)
                .content_type(CONTENT_TYPE_TEXT)
                .created_at(created_at)
                .unlock_at(unlock_at)
                .body(body)
                .body_hash(body_hash);
            if include_label {
                b = b.sender_label(Some("label".into()));
            }
            let env = b.build().unwrap();
            let bytes_a = serialize_qub_envelope(&env).unwrap();
            let back = deserialize_qub_envelope(&bytes_a).unwrap();
            let bytes_b = serialize_qub_envelope(&back).unwrap();
            prop_assert_eq!(bytes_a, bytes_b);
            prop_assert_eq!(env, back);
        }
    }
}
