//! Pact — structured bilateral agreement (content type `0x03`).
//!
//! A pact is a set of structured terms signed by two parties and sealed
//! inside a [`QubEnvelope`](crate::types::QubEnvelope). The body of a
//! pact qub is canonical CBOR encoding of [`PactTerms`], consistent with
//! how text qubs store UTF-8 bytes in the body field.
//!
//! This module provides:
//!
//! - [`PactTerms`], [`PactTerm`], [`PartyIdentifier`] — in-memory types
//! - [`PactTermsCbor`] — wire format newtype
//! - [`serialize_pact_terms`] / [`parse_pact_terms`] — canonical CBOR
//! - [`validate_pact_terms`] — field-level validation

use ciborium::Value;

use crate::cbor::{
    CborError, assert_canonical_key_order, encode_map, extract_optional_text, extract_text,
    extract_u8, parse_top_level_map, parsed_map_from_entries, reject_structural_elements_in_map,
    reject_unknown_keys, text, to_nfc, u8_value,
};
use crate::handle::contains_hostile_text_codepoint;
use crate::types::QubError;
use crate::wire::is_cbor_map_header;
use unicode_normalization::UnicodeNormalization;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const PACT_VERSION_1: u8 = 1;
const MAX_TITLE_BYTES: usize = 200;
const MAX_TERM_KEY_BYTES: usize = 100;
const MAX_TERM_VALUE_BYTES: usize = 2000;
const MAX_TERMS: usize = 20;
const MAX_LABEL_BYTES: usize = 100;
const MAX_CONTACT_BYTES: usize = 320;
const MAX_NOTES_BYTES: usize = 5000;
const MAX_PACT_CBOR_SIZE: usize = 102_400; // 100 KB

// Canonical key orders (sorted by encoded byte length, then lexicographic).

// PactTerms: "notes"(6) < "terms"(6) < "title"(6) < "party_a"(8) < "party_b"(8) < "pact_version"(13)
const PACT_TERMS_KEYS: &[&str] = &[
    "notes",        // 5 chars → 6 encoded
    "terms",        // 5 chars → 6 encoded
    "title",        // 5 chars → 6 encoded
    "party_a",      // 7 chars → 8 encoded
    "party_b",      // 7 chars → 8 encoded
    "pact_version", // 12 chars → 13 encoded
];

// PactTerm: "key"(4) < "value"(6)
const PACT_TERM_KEYS: &[&str] = &[
    "key",   // 3 chars → 4 encoded
    "value", // 5 chars → 6 encoded
];

// PartyIdentifier: "label"(6) < "contact"(8)
const PARTY_ID_KEYS: &[&str] = &[
    "label",   // 5 chars → 6 encoded
    "contact", // 7 chars → 8 encoded
];

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// A single key-value term in a pact agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PactTerm {
    key: String,
    value: String,
}

impl PactTerm {
    /// Creates a new pact term. Both fields are NFC-normalised on
    /// construction so the in-memory value always matches the canonical
    /// wire bytes — validation counts and hashes are computed on what
    /// will actually be serialised.
    #[must_use]
    pub fn new(key: String, value: String) -> Self {
        Self {
            key: into_nfc(key),
            value: into_nfc(value),
        }
    }

    /// Returns the term key (e.g. "Item", "Price").
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the term value (e.g. "Honda scooter", "$100").
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Identifies a party in a pact agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyIdentifier {
    label: String,
    contact: Option<String>,
}

impl PartyIdentifier {
    /// Creates a party identifier with a label and optional contact.
    /// Both fields are NFC-normalised on construction — see
    /// [`PactTerm::new`].
    #[must_use]
    pub fn new(label: String, contact: Option<String>) -> Self {
        Self {
            label: into_nfc(label),
            contact: contact.map(into_nfc),
        }
    }

    /// Returns the display label (e.g. "Mark", "Jane's Scooters").
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the optional contact (e.g. email address).
    #[must_use]
    pub fn contact(&self) -> Option<&str> {
        self.contact.as_deref()
    }
}

/// Structured agreement terms sealed inside a qub pact.
///
/// Serialised as canonical CBOR inside the
/// [`QubEnvelope`](crate::types::QubEnvelope) body field. Does NOT use
/// serde — hand-written CBOR, consistent with all protocol types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PactTerms {
    pact_version: u8,
    title: String,
    terms: Vec<PactTerm>,
    party_a: PartyIdentifier,
    party_b: PartyIdentifier,
    notes: Option<String>,
}

impl PactTerms {
    /// Returns the schema version.
    #[must_use]
    pub const fn pact_version(&self) -> u8 {
        self.pact_version
    }

    /// Returns the agreement title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the structured terms.
    #[must_use]
    pub fn terms(&self) -> &[PactTerm] {
        &self.terms
    }

    /// Returns the drafter (Party A).
    #[must_use]
    pub const fn party_a(&self) -> &PartyIdentifier {
        &self.party_a
    }

    /// Returns the counter-signer (Party B).
    #[must_use]
    pub const fn party_b(&self) -> &PartyIdentifier {
        &self.party_b
    }

    /// Returns optional freeform notes.
    #[must_use]
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }
}

/// Builder for [`PactTerms`].
#[derive(Debug, Default)]
pub struct PactTermsBuilder {
    pact_version: Option<u8>,
    title: Option<String>,
    terms: Option<Vec<PactTerm>>,
    party_a: Option<PartyIdentifier>,
    party_b: Option<PartyIdentifier>,
    notes: Option<String>,
}

impl PactTermsBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the schema version (must be 1).
    #[must_use]
    pub const fn pact_version(mut self, v: u8) -> Self {
        self.pact_version = Some(v);
        self
    }

    /// Sets the agreement title.
    #[must_use]
    pub fn title(mut self, t: String) -> Self {
        self.title = Some(t);
        self
    }

    /// Sets the structured terms.
    #[must_use]
    pub fn terms(mut self, t: Vec<PactTerm>) -> Self {
        self.terms = Some(t);
        self
    }

    /// Sets the drafter (Party A).
    #[must_use]
    pub fn party_a(mut self, p: PartyIdentifier) -> Self {
        self.party_a = Some(p);
        self
    }

    /// Sets the counter-signer (Party B).
    #[must_use]
    pub fn party_b(mut self, p: PartyIdentifier) -> Self {
        self.party_b = Some(p);
        self
    }

    /// Sets optional notes.
    #[must_use]
    pub fn notes(mut self, n: Option<String>) -> Self {
        self.notes = n;
        self
    }

    /// Builds the [`PactTerms`], returning an error for missing fields.
    ///
    /// Text fields are NFC-normalised (terms and parties were already
    /// normalised by their constructors). Field-level *validation* —
    /// hostile codepoints, byte caps, duplicate keys, email shape —
    /// runs in [`serialize_pact_terms`], so nothing invalid can reach
    /// the wire even through a hand-rolled `PactTerms`.
    pub fn build(self) -> Result<PactTerms, QubError> {
        Ok(PactTerms {
            pact_version: self
                .pact_version
                .ok_or(QubError::MissingBuilderField("pact_version"))?,
            title: to_nfc(&self.title.ok_or(QubError::MissingBuilderField("title"))?),
            terms: self.terms.ok_or(QubError::MissingBuilderField("terms"))?,
            party_a: self
                .party_a
                .ok_or(QubError::MissingBuilderField("party_a"))?,
            party_b: self
                .party_b
                .ok_or(QubError::MissingBuilderField("party_b"))?,
            notes: self.notes.map(|n| to_nfc(&n)),
        })
    }
}

// -----------------------------------------------------------------------------
// Wire newtype
// -----------------------------------------------------------------------------

/// Canonical CBOR bytes of [`PactTerms`].
///
/// Produced by [`serialize_pact_terms`], consumed by [`parse_pact_terms`].
/// There is no blanket `From<Vec<u8>>` — construction is restricted to
/// [`from_encoded`](PactTermsCbor::from_encoded) (structural check) or
/// [`from_pact_terms`](PactTermsCbor::from_pact_terms) (serialisation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PactTermsCbor(Vec<u8>);

impl PactTermsCbor {
    /// Wraps pre-serialised CBOR bytes after a lightweight structural check.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::NotAMap`] if the first byte is not a valid
    /// definite-length CBOR map header.
    pub fn from_encoded(bytes: Vec<u8>) -> Result<Self, CborError> {
        match bytes.first() {
            Some(&b) if is_cbor_map_header(b) => Ok(Self(bytes)),
            _ => Err(CborError::NotAMap),
        }
    }

    /// Serialises a [`PactTerms`] to canonical CBOR and wraps the result.
    ///
    /// # Errors
    ///
    /// Returns a [`CborError`] if encoding fails.
    pub fn from_pact_terms(terms: &PactTerms) -> Result<Self, CborError> {
        let bytes = serialize_pact_terms(terms)?;
        Ok(Self(bytes))
    }

    /// Parses the wrapped bytes back into a [`PactTerms`].
    ///
    /// # Errors
    ///
    /// Returns a [`CborError`] if the bytes are not valid canonical CBOR
    /// or do not conform to the [`PactTerms`] schema.
    pub fn parse(&self) -> Result<PactTerms, CborError> {
        parse_pact_terms(&self.0)
    }

    /// Returns a reference to the raw CBOR bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the newtype and returns the inner byte vector.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the byte length of the encoded CBOR.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the encoded CBOR is empty (should not happen for
    /// valid pact terms).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// -----------------------------------------------------------------------------
// Serialisation
// -----------------------------------------------------------------------------

/// Serialises a [`PartyIdentifier`] to a CBOR map value.
fn serialize_party(party: &PartyIdentifier) -> Value {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(2);
    let mut keys_used: Vec<&str> = Vec::with_capacity(2);

    map.push((text("label"), Value::Text(to_nfc(party.label()))));
    keys_used.push("label");

    if let Some(c) = party.contact() {
        map.push((text("contact"), Value::Text(to_nfc(c))));
        keys_used.push("contact");
    }

    assert_canonical_key_order(&keys_used);
    Value::Map(map)
}

/// Serialises a [`PactTerm`] to a CBOR map value.
fn serialize_term(term: &PactTerm) -> Value {
    let map: Vec<(Value, Value)> = vec![
        (text("key"), Value::Text(to_nfc(term.key()))),
        (text("value"), Value::Text(to_nfc(term.value()))),
    ];

    assert_canonical_key_order(PACT_TERM_KEYS);
    Value::Map(map)
}

/// Serialises [`PactTerms`] to canonical CBOR bytes.
///
/// The output is deterministic: identical [`PactTerms`] always produce
/// byte-identical CBOR, following the canonical profile in PROTOCOL.md §3.
///
/// Runs the full [`validate_pact_terms`] field validation before
/// encoding, and the serialised-size cap after. The validator used to
/// be test-only — the compose path called this function directly, so
/// hostile codepoints, out-of-contract shapes, and malformed contact
/// emails could reach both parties' signed bytes (and the email-shape
/// failure would surface only at *reveal*, rendering a signed pact
/// with no terms). Encode and decode now accept exactly the same set.
///
/// # Errors
///
/// Returns [`CborError::StructuralError`] for any field-validation
/// failure, or [`CborError::EncodingFailed`] if the underlying
/// `ciborium` writer fails.
pub fn serialize_pact_terms(terms: &PactTerms) -> Result<Vec<u8>, CborError> {
    validate_pact_terms_fields(terms)?;
    let bytes = encode_pact_terms(terms)?;
    if bytes.len() > MAX_PACT_CBOR_SIZE {
        return Err(CborError::StructuralError(format!(
            "serialised pact exceeds {MAX_PACT_CBOR_SIZE} bytes: {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Raw canonical CBOR encoding of [`PactTerms`] — no validation. Only
/// callable through [`serialize_pact_terms`] (which validates) and
/// [`validate_pact_terms`] (which needs the bytes for the size cap).
fn encode_pact_terms(terms: &PactTerms) -> Result<Vec<u8>, CborError> {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(PACT_TERMS_KEYS.len());
    let mut keys_used: Vec<&str> = Vec::with_capacity(PACT_TERMS_KEYS.len());

    // Canonical key order: [notes], terms, title, party_a, party_b, pact_version

    if let Some(notes) = terms.notes() {
        map.push((text("notes"), Value::Text(to_nfc(notes))));
        keys_used.push("notes");
    }

    let term_values: Vec<Value> = terms.terms().iter().map(serialize_term).collect();
    map.push((text("terms"), Value::Array(term_values)));
    keys_used.push("terms");

    map.push((text("title"), Value::Text(to_nfc(terms.title()))));
    keys_used.push("title");

    map.push((text("party_a"), serialize_party(terms.party_a())));
    keys_used.push("party_a");

    map.push((text("party_b"), serialize_party(terms.party_b())));
    keys_used.push("party_b");

    map.push((text("pact_version"), u8_value(terms.pact_version())));
    keys_used.push("pact_version");

    assert_canonical_key_order(&keys_used);

    encode_map(map)
}

// -----------------------------------------------------------------------------
// Deserialisation
// -----------------------------------------------------------------------------

/// Parses a [`PartyIdentifier`] from a CBOR map value.
fn parse_party(value: &Value, field_name: &'static str) -> Result<PartyIdentifier, CborError> {
    let Value::Map(entries) = value else {
        return Err(CborError::StructuralError(format!(
            "{field_name} must be a CBOR map"
        )));
    };

    // Shared helper: rejects non-text keys, non-NFC keys, and duplicate
    // keys inside this nested map — the duplicate-key rule the top-level
    // decoder already enforces (SEC-2).
    let map = parsed_map_from_entries(entries)?;
    reject_unknown_keys(&map, PARTY_ID_KEYS, "PartyIdentifier")?;

    let label = extract_text(&map, "label")?;
    let contact = extract_optional_text(&map, "contact")?;

    // Andre 2026-05-22 SYSTEMIC-THREAT-REVIEW Finding 50 — party.contact
    // is downstream interpreted as an email address (the Worker's
    // normaliseEmail + recipient address for staged-pact mail), but
    // parse_pact_terms previously accepted any string up to
    // MAX_CONTACT_BYTES. A malformed value would slip through to the
    // mailer. Reject obvious shape failures at the CBOR boundary —
    // single '@', non-zero local + domain, '.' in domain. Keep the
    // check lenient (no IDN punycode here; the Worker enforces that
    // in PR 1b before the pact is staged) so legitimate uncommon
    // shapes pass.
    if let Some(c) = contact.as_deref()
        && !is_valid_email_shape(c)
    {
        return Err(CborError::StructuralError(format!(
            "party.contact is not a well-formed email: {c}"
        )));
    }

    Ok(PartyIdentifier::new(label, contact))
}

/// NFC-normalise an owned string, reusing the allocation when the
/// input is already NFC (the common case for typed input).
fn into_nfc(s: String) -> String {
    if unicode_normalization::is_nfc(&s) {
        s
    } else {
        s.nfc().collect()
    }
}

/// Lightweight email-shape check applied to party.contact at CBOR
/// decode. Mirrors `workers/api/src/utils/email.ts::isValidEmail`
/// with a smaller surface — we don't IDN-punycode here because the
/// TS Worker side already does (PR 1b); this is a defensive
/// fail-loud at the protocol layer.
fn is_valid_email_shape(s: &str) -> bool {
    if s.is_empty() || s.len() > 320 {
        return false;
    }
    // Reject any non-ASCII codepoint in the local part. The Worker
    // converts IDN domains to xn-- before constructing pacts; if a
    // non-ASCII codepoint reaches here it bypassed that step.
    if !s.is_ascii() {
        return false;
    }
    let Some(at) = s.find('@') else {
        return false;
    };
    if s[at + 1..].contains('@') {
        return false;
    }
    let (local, domain_with_at) = s.split_at(at);
    let domain = &domain_with_at[1..];
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    // Reject whitespace + controls.
    if s.bytes()
        .any(|b| b.is_ascii_whitespace() || b < 0x20 || b == 0x7F)
    {
        return false;
    }
    true
}

/// Parses a [`PactTerm`] from a CBOR map value.
fn parse_term(value: &Value, index: usize) -> Result<PactTerm, CborError> {
    let Value::Map(entries) = value else {
        return Err(CborError::StructuralError(format!(
            "terms[{index}] must be a CBOR map"
        )));
    };

    // Shared helper: rejects non-text keys, non-NFC keys, and duplicate
    // keys inside this nested map (SEC-2).
    let map = parsed_map_from_entries(entries)?;
    // Unknown-key rejection closes the hidden-signed-term vector: a
    // drafter could otherwise embed an extra key both parties'
    // signatures commit to but no renderer ever shows.
    reject_unknown_keys(&map, PACT_TERM_KEYS, "PactTerm")?;

    let key = extract_text(&map, "key")?;
    let value = extract_text(&map, "value")?;

    Ok(PactTerm::new(key, value))
}

/// Parses canonical CBOR bytes into a [`PactTerms`].
///
/// Applies the same rejection rules as
/// [`deserialize_qub_envelope`](crate::cbor::deserialize_qub_envelope):
/// non-map roots, non-text keys, duplicate keys, CBOR tags, floats, and
/// non-NFC text all produce a [`CborError`].
///
/// # Errors
///
/// Returns a [`CborError`] variant describing the first violation
/// encountered.
pub fn parse_pact_terms(bytes: &[u8]) -> Result<PactTerms, CborError> {
    // Enforce the resource bound before CBOR decoding. Checking only after
    // `parse_top_level_map` would still let an attacker force allocation and
    // traversal of an arbitrarily large value before we reject it.
    if bytes.len() > MAX_PACT_CBOR_SIZE {
        return Err(CborError::StructuralError(format!(
            "serialised pact exceeds {MAX_PACT_CBOR_SIZE} bytes: {}",
            bytes.len()
        )));
    }

    let map = parse_top_level_map(bytes)?;
    reject_structural_elements_in_map(&map)?;
    reject_unknown_keys(&map, PACT_TERMS_KEYS, "PactTerms")?;

    let pact_version = extract_u8(&map, "pact_version")?;
    let title = extract_text(&map, "title")?;
    let notes = extract_optional_text(&map, "notes")?;

    // Parse terms array
    let terms_value = map
        .iter()
        .find(|(k, _)| k == "terms")
        .map(|(_, v)| v)
        .ok_or(CborError::MissingField("terms"))?;

    let Value::Array(term_entries) = terms_value else {
        return Err(CborError::StructuralError(
            "terms must be a CBOR array".into(),
        ));
    };

    let mut terms = Vec::with_capacity(term_entries.len());
    for (i, entry) in term_entries.iter().enumerate() {
        terms.push(parse_term(entry, i)?);
    }

    let drafter_cbor = map
        .iter()
        .find(|(k, _)| k == "party_a")
        .map(|(_, v)| v)
        .ok_or(CborError::MissingField("party_a"))?;
    let party_a = parse_party(drafter_cbor, "party_a")?;

    let cosigner_cbor = map
        .iter()
        .find(|(k, _)| k == "party_b")
        .map(|(_, v)| v)
        .ok_or(CborError::MissingField("party_b"))?;
    let party_b = parse_party(cosigner_cbor, "party_b")?;

    let terms = PactTermsBuilder::new()
        .pact_version(pact_version)
        .title(title)
        .terms(terms)
        .party_a(party_a)
        .party_b(party_b)
        .notes(notes)
        .build()
        .map_err(|e| CborError::StructuralError(e.to_string()))?;

    // Decode must enforce the same semantic contract as encode. Without
    // this, a third-party canonical artifact could bypass the version,
    // field-size, term-count, duplicate-key, and hostile-text checks that
    // locally-created pacts receive, splitting Worker and viewer behavior.
    validate_pact_terms_fields(&terms)?;
    Ok(terms)
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validates [`PactTerms`] field constraints, including the serialised
/// size cap.
///
/// [`serialize_pact_terms`] runs the same validation internally, so
/// callers that serialise don't need to call this separately; it
/// remains public for callers that want validation without the bytes.
///
/// # Errors
///
/// Returns a [`CborError::StructuralError`] describing the first
/// violation encountered.
pub fn validate_pact_terms(terms: &PactTerms) -> Result<(), CborError> {
    // serialize_pact_terms = field validation + encode + size cap.
    serialize_pact_terms(terms).map(|_| ())
}

/// Field-level validation shared by [`serialize_pact_terms`] and
/// [`validate_pact_terms`] — everything except the serialised-size cap
/// (which needs the encoded bytes).
fn validate_pact_terms_fields(terms: &PactTerms) -> Result<(), CborError> {
    if terms.pact_version != PACT_VERSION_1 {
        return Err(CborError::StructuralError(format!(
            "pact_version must be {PACT_VERSION_1}, got {}",
            terms.pact_version
        )));
    }

    validate_nfc_field(terms.title(), "title", MAX_TITLE_BYTES)?;

    if terms.terms.is_empty() {
        return Err(CborError::StructuralError(
            "terms must have at least 1 entry".into(),
        ));
    }
    if terms.terms.len() > MAX_TERMS {
        return Err(CborError::StructuralError(format!(
            "terms must have at most {MAX_TERMS} entries, got {}",
            terms.terms.len()
        )));
    }

    // Check for duplicate keys (case-insensitive after NFC).
    let mut seen_keys: Vec<String> = Vec::with_capacity(terms.terms.len());
    for term in &terms.terms {
        validate_nfc_field(term.key(), "term key", MAX_TERM_KEY_BYTES)?;
        validate_nfc_field(term.value(), "term value", MAX_TERM_VALUE_BYTES)?;
        let lower = to_nfc(term.key()).to_lowercase();
        if seen_keys.contains(&lower) {
            return Err(CborError::StructuralError(format!(
                "duplicate term key (case-insensitive): {:?}",
                term.key()
            )));
        }
        seen_keys.push(lower);
    }

    validate_nfc_field(terms.party_a.label(), "party_a.label", MAX_LABEL_BYTES)?;
    validate_nfc_field(terms.party_b.label(), "party_b.label", MAX_LABEL_BYTES)?;

    // Contact shape is enforced at *encode* as well as decode
    // (`parse_party`) — a malformed contact used to sail through the
    // compose path, get signed by both parties, and then fail
    // `parse_pact_terms` at reveal, rendering a signed pact with no
    // terms.
    if let Some(c) = terms.party_a.contact() {
        validate_nfc_field(c, "party_a.contact", MAX_CONTACT_BYTES)?;
        if !is_valid_email_shape(c) {
            return Err(CborError::StructuralError(format!(
                "party_a.contact is not a well-formed email: {c}"
            )));
        }
    }
    if let Some(c) = terms.party_b.contact() {
        validate_nfc_field(c, "party_b.contact", MAX_CONTACT_BYTES)?;
        if !is_valid_email_shape(c) {
            return Err(CborError::StructuralError(format!(
                "party_b.contact is not a well-formed email: {c}"
            )));
        }
    }

    if let Some(notes) = terms.notes() {
        validate_nfc_field(notes, "notes", MAX_NOTES_BYTES)?;
    }

    Ok(())
}

/// Validates a NFC-normalised text field: non-empty, within byte limit,
/// genuinely in NFC, and free of hostile codepoints (bidi spoof, zero-
/// width brand bypass, tag-block steganography). The function name
/// previously over-promised — it only checked length — so Andre Perry's
/// 2026-05-22 review flagged it as a gap (Finding 15). The full check
/// now lives here so every pact-term value, party label, and contact
/// inherits the uplift automatically.
fn validate_nfc_field(s: &str, name: &str, max_bytes: usize) -> Result<(), CborError> {
    if s.is_empty() {
        return Err(CborError::StructuralError(format!(
            "{name} must not be empty"
        )));
    }
    if s.len() > max_bytes {
        return Err(CborError::StructuralError(format!(
            "{name} exceeds {max_bytes} bytes: {}",
            s.len()
        )));
    }
    let nfc: String = s.nfc().collect();
    if nfc != s {
        return Err(CborError::StructuralError(format!(
            "{name} is not NFC-normalised"
        )));
    }
    if contains_hostile_text_codepoint(s) {
        return Err(CborError::StructuralError(format!(
            "{name} contains a hostile / invisible codepoint"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// structured/v1 — Frozen acknowledgement strings + term keys
// -----------------------------------------------------------------------------

/// # Frozen Acknowledgement Strings — `structured/v1`
///
/// Stored verbatim in the signed pact body. Both parties' ML-DSA-65
/// signatures commit to these exact bytes via `body_hash`.
///
/// **DO NOT EDIT** after first production use. Any wording change —
/// including whitespace or punctuation — requires `structured/v2`.
///
/// Version: `structured/v1` (frozen 2026-04-13)
/// Spec: `docs/PACT-FROZEN-STRINGS.md`
///
/// Not in i18n — English-only by design. The signed body is language-
/// neutral (the legal text both parties committed to, regardless of
/// their UI language). Golden hash tests in
/// `crates/qub-core/tests/golden_pact_hashes.rs` pin these bytes.
// --- Standard terms (4) ---
pub const GOODS_SELLER_STANDARD: &str = "The goods are described above. Nothing in this contract excludes, restricts, or modifies any rights or remedies that apply by law.";

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const GOODS_BUYER_STANDARD: &str = "I accept the goods as described above.";

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const SERVICES_PROVIDER_STANDARD: &str = "The services are to be performed in accordance with the scope of work described above and subject to any rights or remedies that apply by law.";

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const SERVICES_CLIENT_STANDARD: &str = "I accept the scope of work described above.";

// --- Capacity / authority terms (4) ---

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const GOODS_SELLER_CAPACITY: &str = "I, or the party I represent, have the right to transfer the described goods, and the goods are free from any undisclosed security interest, lien, charge, or other encumbrance. I have legal capacity and, if signing for an entity, am duly authorised to enter into this contract.";

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const GOODS_BUYER_CAPACITY: &str = "I have legal capacity and, if signing for an entity, am duly authorised to enter into this contract for the purchase of the described goods.";

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const SERVICES_PROVIDER_CAPACITY: &str = "Where required by applicable law to perform the described services, I, or the party I represent, hold the licences and insurance required to perform them. I have legal capacity and, if signing for an entity, am duly authorised to enter into this contract.";

/// See [`GOODS_SELLER_STANDARD`] for the freeze policy.
pub const SERVICES_CLIENT_CAPACITY: &str = "I have legal capacity and, if signing for an entity, am duly authorised to enter into this contract for the procurement of the described services.";

/// Term keys for the four acknowledgement slots in the CBOR body.
///
/// These strings appear as `key` on the respective [`PactTerm`] rows.
/// Frozen for `structured/v1` — renaming a key silently changes every
/// future `body_hash` and breaks viewer lookups on historical pacts.
pub const INITIATOR_STANDARD_TERMS: &str = "initiator_standard_terms";
/// See [`INITIATOR_STANDARD_TERMS`].
pub const INITIATOR_CAPACITY_TERMS: &str = "initiator_capacity_terms";
/// See [`INITIATOR_STANDARD_TERMS`].
pub const COUNTERPARTY_STANDARD_TERMS: &str = "counterparty_standard_terms";
/// See [`INITIATOR_STANDARD_TERMS`].
pub const COUNTERPARTY_CAPACITY_TERMS: &str = "counterparty_capacity_terms";

/// The four party roles that index the frozen acknowledgement strings.
///
/// Derived from `(pact_type, whose_side)` — goods → seller/buyer,
/// services → provider/client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PactRole {
    /// Goods + sell-side.
    Seller,
    /// Goods + buy-side.
    Buyer,
    /// Services + sell-side.
    Provider,
    /// Services + buy-side.
    Client,
}

/// Which of the two acknowledgement kinds per role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcknowledgementKind {
    /// Narrow "what's described above" acceptance, preserving
    /// statutory rights.
    Standard,
    /// Legal-capacity / authority / unencumbered-title assertion.
    Capacity,
}

/// Resolve the frozen acknowledgement string for a given role + kind.
///
/// Pure `const fn` lookup over the eight [`GOODS_SELLER_STANDARD`]-style
/// constants. Used by the compose form to populate the [`PactTerm`]
/// value written into the signed body. Viewer / staging code reads
/// `term.value` from the parsed body directly — never this function —
/// so historical pacts keep rendering the exact bytes they were
/// signed with.
#[must_use]
pub const fn acknowledgement_for(role: PactRole, kind: AcknowledgementKind) -> &'static str {
    match (role, kind) {
        (PactRole::Seller, AcknowledgementKind::Standard) => GOODS_SELLER_STANDARD,
        (PactRole::Seller, AcknowledgementKind::Capacity) => GOODS_SELLER_CAPACITY,
        (PactRole::Buyer, AcknowledgementKind::Standard) => GOODS_BUYER_STANDARD,
        (PactRole::Buyer, AcknowledgementKind::Capacity) => GOODS_BUYER_CAPACITY,
        (PactRole::Provider, AcknowledgementKind::Standard) => SERVICES_PROVIDER_STANDARD,
        (PactRole::Provider, AcknowledgementKind::Capacity) => SERVICES_PROVIDER_CAPACITY,
        (PactRole::Client, AcknowledgementKind::Standard) => SERVICES_CLIENT_STANDARD,
        (PactRole::Client, AcknowledgementKind::Capacity) => SERVICES_CLIENT_CAPACITY,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::body_hash;

    /// `is_valid_email_shape` is the protocol-layer fail-loud on
    /// `party.contact`, and three of its rejection arms were invisible to
    /// the whole suite — mutation flipped each `||` to `&&` and nothing
    /// failed. Every case below is chosen so that ONLY the mutated arm
    /// separates accept from reject; the obvious inputs do not work,
    /// which is precisely why the gap survived:
    ///
    /// - `""` cannot isolate the length arm, because the missing `@`
    ///   rejects it one check later anyway.
    /// - `"a@"` cannot isolate the empty-part arm, because the
    ///   missing-dot check rejects it anyway.
    #[test]
    fn email_shape_rejects_each_disjunct_independently() {
        // Length arm: 320 local chars + "@example.com" is over the 320
        // cap but otherwise perfectly well formed.
        let long_local = "a".repeat(320);
        assert!(
            !is_valid_email_shape(&format!("{long_local}@example.com")),
            "an over-length address must be rejected by the length arm"
        );

        // Empty-part arm: empty local part, non-empty valid domain.
        assert!(
            !is_valid_email_shape("@example.com"),
            "an empty local part must be rejected by the empty-part arm"
        );

        // Control arm: a C0 control that is NOT ASCII whitespace, so the
        // whitespace arm sitting beside it cannot cover for it.
        assert!(
            !is_valid_email_shape("a\u{0001}b@example.com"),
            "a C0 control must be rejected by the control arm"
        );
    }

    /// The accepting half of the length boundary. Without it, `> 320` and
    /// `>= 320` behave identically on every rejection test, so mutation
    /// flips the comparison and nothing fails. A boundary needs the
    /// largest ACCEPTED value as well as the smallest rejected one.
    #[test]
    fn email_shape_accepts_exactly_the_length_limit() {
        // 308 + "@example.com" (12) == 320 bytes exactly.
        let addr = format!("{}@example.com", "a".repeat(308));
        assert_eq!(addr.len(), 320);
        assert!(
            is_valid_email_shape(&addr),
            "an address of exactly 320 bytes must be accepted"
        );
    }

    /// Helper: build a minimal valid `PactTerms`.
    fn sample_pact() -> PactTerms {
        PactTermsBuilder::new()
            .pact_version(1)
            .title("Scooter deposit".into())
            .terms(vec![
                PactTerm::new("Item".into(), "Honda Metropolitan scooter".into()),
                PactTerm::new("Price".into(), "$100".into()),
                PactTerm::new("Deposit".into(), "$10".into()),
            ])
            .party_a(PartyIdentifier::new("Alice".into(), None))
            .party_b(PartyIdentifier::new(
                "Bob".into(),
                Some("bob@example.com".into()),
            ))
            .notes(None)
            .build()
            .unwrap()
    }

    /// Helper: build a `PactTerms` with all optional fields.
    fn sample_pact_full() -> PactTerms {
        PactTermsBuilder::new()
            .pact_version(1)
            .title("Scooter deposit".into())
            .terms(vec![
                PactTerm::new("Item".into(), "Honda Metropolitan scooter".into()),
                PactTerm::new("Price".into(), "$100".into()),
            ])
            .party_a(PartyIdentifier::new(
                "Alice".into(),
                Some("alice@example.com".into()),
            ))
            .party_b(PartyIdentifier::new(
                "Bob".into(),
                Some("bob@example.com".into()),
            ))
            .notes(Some("Blue scooter, garage 3".into()))
            .build()
            .unwrap()
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
    #[test]
    fn pact_terms_cbor_accessors_read_back() {
        let pact = sample_pact_full();
        assert_eq!(pact.pact_version(), 1);
        let cbor = PactTermsCbor::from_pact_terms(&pact).unwrap();
        let bytes = cbor.as_bytes().to_vec();
        assert!(
            bytes.len() > 1,
            "sample must exceed the 0/1 replacement constants"
        );
        assert_eq!(cbor.len(), bytes.len());
        assert!(!cbor.is_empty());
        assert_eq!(cbor.into_bytes(), bytes);
    }

    /// Field caps, pinned from the ACCEPTING side. Every existing test
    /// feeds an over-long value, under which `>` and `>=` behave
    /// identically — so the boundary was never located, only the fact
    /// that something too big is refused.
    #[test]
    fn pact_field_caps_accept_exactly_the_limit() {
        let encode = |title: String, term_count: usize| {
            let pact = PactTermsBuilder::new()
                .pact_version(1)
                .title(title)
                .terms(
                    (0..term_count)
                        .map(|i| PactTerm::new(format!("k{i}"), "v".to_owned()))
                        .collect(),
                )
                .party_a(PartyIdentifier::new("Alice".to_owned(), None))
                .party_b(PartyIdentifier::new("Bob".to_owned(), None))
                .build()
                .expect("builder only checks presence, not size");
            serialize_pact_terms(&pact)
        };

        assert!(
            encode("t".to_owned(), MAX_TERMS).is_ok(),
            "exactly MAX_TERMS entries must be accepted"
        );
        assert!(encode("t".to_owned(), MAX_TERMS + 1).is_err());

        assert!(
            encode("a".repeat(MAX_TITLE_BYTES), 1).is_ok(),
            "a title of exactly MAX_TITLE_BYTES must be accepted"
        );
        assert!(encode("a".repeat(MAX_TITLE_BYTES + 1), 1).is_err());
    }

    /// `from_encoded`'s match guard could be replaced with `false` —
    /// rejecting every input as "not a map" — and nothing failed, because
    /// no test asserted that a genuine encoding is ACCEPTED.
    #[test]
    fn from_encoded_accepts_a_real_map_header() {
        let bytes = PactTermsCbor::from_pact_terms(&sample_pact_full())
            .unwrap()
            .into_bytes();
        assert!(
            PactTermsCbor::from_encoded(bytes).is_ok(),
            "canonical pact bytes must be accepted by from_encoded"
        );
    }

    /// `parse_pact_terms` applies its size cap BEFORE decoding, so an
    /// input of exactly the cap must get PAST it and fail for some other
    /// reason. Asserting only that oversized input is refused cannot tell
    /// `>` from `>=`.
    ///
    /// Note the asymmetry with the identical-looking cap in
    /// `serialize_pact_terms`: that one runs AFTER
    /// `validate_pact_terms_fields`, whose per-field limits bound a valid
    /// pact to roughly 48 KB — under half of `MAX_PACT_CBOR_SIZE`. It can
    /// therefore never fire, and its two mutants are equivalent. This one
    /// is reachable because it guards attacker-supplied bytes that nothing
    /// has validated yet, which is exactly why it exists.
    #[test]
    fn parse_pact_terms_size_cap_admits_exactly_the_limit() {
        let at_cap = vec![0xA1u8; MAX_PACT_CBOR_SIZE];
        let err = parse_pact_terms(&at_cap).expect_err("still invalid CBOR");
        assert!(
            !format!("{err}").contains("exceeds"),
            "input of exactly the cap must pass the size gate, got {err:?}"
        );

        let over_cap = vec![0xA1u8; MAX_PACT_CBOR_SIZE + 1];
        let err = parse_pact_terms(&over_cap).expect_err("over the cap");
        assert!(
            format!("{err}").contains("exceeds"),
            "one byte over the cap must be refused by the size gate, got {err:?}"
        );
    }

    #[test]
    fn pact_terms_roundtrip_all_fields() {
        let pact = sample_pact_full();
        let cbor = PactTermsCbor::from_pact_terms(&pact).unwrap();
        let parsed = cbor.parse().unwrap();
        assert_eq!(parsed, pact);
    }

    /// Serialisation must run the full field validation — the compose
    /// path serialises directly, and an RLO override inside a signed
    /// agreement (digit-flipping a price) previously flowed through.
    #[test]
    fn serialize_rejects_hostile_codepoint_in_term_value() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Deal".into())
            .terms(vec![PactTerm::new(
                "Price".into(),
                "$\u{202E}001".into(), // RLO renders "$100"
            )])
            .party_a(PartyIdentifier::new("Alice".into(), None))
            .party_b(PartyIdentifier::new("Bob".into(), None))
            .build()
            .unwrap();
        assert!(serialize_pact_terms(&pact).is_err());
        assert!(validate_pact_terms(&pact).is_err());
    }

    /// A malformed contact email must fail at encode, not at reveal —
    /// `parse_pact_terms` rejects it, so letting it serialise produced
    /// a signed pact whose terms silently never render.
    #[test]
    fn serialize_rejects_malformed_contact_email() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Deal".into())
            .terms(vec![PactTerm::new("Item".into(), "Scooter".into())])
            .party_a(PartyIdentifier::new("Alice".into(), None))
            .party_b(PartyIdentifier::new(
                "Bob".into(),
                Some("john smith@example.com".into()),
            ))
            .build()
            .unwrap();
        assert!(serialize_pact_terms(&pact).is_err());
    }

    /// Out-of-contract shapes (wrong version, too many terms) must not
    /// reach the wire either.
    #[test]
    fn serialize_rejects_wrong_pact_version() {
        let pact = PactTermsBuilder::new()
            .pact_version(2)
            .title("Deal".into())
            .terms(vec![PactTerm::new("Item".into(), "Scooter".into())])
            .party_a(PartyIdentifier::new("Alice".into(), None))
            .party_b(PartyIdentifier::new("Bob".into(), None))
            .build()
            .unwrap();
        assert!(serialize_pact_terms(&pact).is_err());
    }

    /// NFD input is normalised at construction, so the round trip
    /// (encode → decode, which rejects non-NFC) succeeds and compares
    /// equal — pasted decomposed text (classic macOS clipboard shape)
    /// must not brick a pact.
    #[test]
    fn nfd_input_normalised_at_construction() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Cafe\u{0301} lease".into()) // NFD é
            .terms(vec![PactTerm::new(
                "Cle\u{0301}".into(),
                "Nume\u{0301}ro 7".into(),
            )])
            .party_a(PartyIdentifier::new("Rene\u{0301}".into(), None))
            .party_b(PartyIdentifier::new("Bob".into(), None))
            .build()
            .unwrap();
        assert_eq!(pact.title(), "Café lease");
        let cbor = PactTermsCbor::from_pact_terms(&pact).unwrap();
        let parsed = cbor.parse().unwrap();
        assert_eq!(parsed, pact);
    }

    #[test]
    fn pact_terms_roundtrip_optional_absent() {
        let pact = sample_pact();
        let cbor = PactTermsCbor::from_pact_terms(&pact).unwrap();
        let parsed = cbor.parse().unwrap();
        assert_eq!(parsed, pact);
        assert!(parsed.notes().is_none());
        assert!(parsed.party_a().contact().is_none());
    }

    #[test]
    fn pact_terms_canonical_key_order() {
        // Verify canonical key ordering is valid.
        assert_canonical_key_order(PACT_TERMS_KEYS);
        assert_canonical_key_order(PACT_TERM_KEYS);
        assert_canonical_key_order(PARTY_ID_KEYS);
    }

    #[test]
    fn pact_terms_rejects_duplicate_keys() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Test".into())
            .terms(vec![
                PactTerm::new("Item".into(), "value1".into()),
                PactTerm::new("item".into(), "value2".into()), // case-insensitive dup
            ])
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let err = validate_pact_terms(&pact).unwrap_err();
        assert!(
            err.to_string().contains("duplicate term key"),
            "expected duplicate key error, got: {err}"
        );
    }

    /// A duplicate CBOR map key inside a *nested* pact map — `party_a` or a
    /// `terms` entry — must be rejected, not silently last-wins. The
    /// top-level decoder already rejected duplicates; SEC-2 extends the
    /// rule to nested maps.
    #[test]
    fn pact_rejects_duplicate_key_in_nested_map() {
        // Duplicate "label" inside the party_a map.
        let bytes = serialize_pact_terms(&sample_pact()).unwrap();
        let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
        let Value::Map(mut entries) = value else {
            panic!("pact CBOR root is a map");
        };
        for (k, v) in &mut entries {
            if let Value::Text(s) = k
                && s == "party_a"
                && let Value::Map(party) = v
            {
                let dup = party[0].clone();
                party.push(dup);
            }
        }
        let mut mutated = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut mutated).unwrap();
        let err = parse_pact_terms(&mutated).unwrap_err();
        assert!(
            matches!(err, CborError::DuplicateKey(_)),
            "expected DuplicateKey for nested party_a dup, got {err:?}",
        );

        // Duplicate "key" inside the first terms entry.
        let bytes = serialize_pact_terms(&sample_pact()).unwrap();
        let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
        let Value::Map(mut entries) = value else {
            panic!("pact CBOR root is a map");
        };
        for (k, v) in &mut entries {
            if let Value::Text(s) = k
                && s == "terms"
                && let Value::Array(terms) = v
                && let Some(Value::Map(term0)) = terms.first_mut()
            {
                let dup = term0[0].clone();
                term0.push(dup);
            }
        }
        let mut mutated = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut mutated).unwrap();
        let err = parse_pact_terms(&mutated).unwrap_err();
        assert!(
            matches!(err, CborError::DuplicateKey(_)),
            "expected DuplicateKey for nested terms[0] dup, got {err:?}",
        );
    }

    #[test]
    fn pact_terms_rejects_oversized_title() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("x".repeat(201))
            .terms(vec![PactTerm::new("k".into(), "v".into())])
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let err = validate_pact_terms(&pact).unwrap_err();
        assert!(
            err.to_string().contains("title"),
            "expected title error, got: {err}"
        );
    }

    #[test]
    fn pact_terms_rejects_empty_terms() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Test".into())
            .terms(vec![])
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let err = validate_pact_terms(&pact).unwrap_err();
        assert!(
            err.to_string().contains("at least 1"),
            "expected empty terms error, got: {err}"
        );
    }

    #[test]
    fn pact_terms_rejects_too_many_terms() {
        let terms: Vec<PactTerm> = (0..21)
            .map(|i| PactTerm::new(format!("Key{i}"), format!("Value{i}")))
            .collect();

        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Test".into())
            .terms(terms)
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let err = validate_pact_terms(&pact).unwrap_err();
        assert!(
            err.to_string().contains("at most 20"),
            "expected too many terms error, got: {err}"
        );
    }

    #[test]
    fn pact_terms_nfc_normalization() {
        // Create pact with non-NFC title (e with combining accent)
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("caf\u{0065}\u{0301}".into()) // "café" decomposed
            .terms(vec![PactTerm::new("k".into(), "v".into())])
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let cbor = PactTermsCbor::from_pact_terms(&pact).unwrap();
        let parsed = cbor.parse().unwrap();

        // NFC normalises the decomposed é → precomposed é
        assert_eq!(parsed.title(), "caf\u{00E9}");
    }

    #[test]
    fn pact_terms_body_hash_matches() {
        let pact = sample_pact();
        let cbor = PactTermsCbor::from_pact_terms(&pact).unwrap();
        let hash = body_hash(cbor.as_bytes());
        // Just verify it's a valid 32-byte hash and is deterministic.
        let cbor2 = PactTermsCbor::from_pact_terms(&pact).unwrap();
        assert_eq!(body_hash(cbor2.as_bytes()), hash);
    }

    #[test]
    fn pact_terms_cbor_newtype_rejects_non_map() {
        let err = PactTermsCbor::from_encoded(vec![0x80]).unwrap_err(); // array header
        assert!(matches!(err, CborError::NotAMap));

        let err = PactTermsCbor::from_encoded(vec![]).unwrap_err(); // empty
        assert!(matches!(err, CborError::NotAMap));
    }

    #[test]
    fn pact_terms_cbor_deterministic() {
        let pact = sample_pact_full();
        let bytes1 = serialize_pact_terms(&pact).unwrap();
        let bytes2 = serialize_pact_terms(&pact).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "same input must produce byte-identical CBOR"
        );
    }

    #[test]
    fn pact_terms_validation_accepts_valid() {
        let pact = sample_pact();
        validate_pact_terms(&pact).unwrap();
    }

    #[test]
    fn pact_terms_validation_accepts_full() {
        let pact = sample_pact_full();
        validate_pact_terms(&pact).unwrap();
    }

    #[test]
    fn pact_terms_rejects_wrong_version() {
        let pact = PactTermsBuilder::new()
            .pact_version(2)
            .title("Test".into())
            .terms(vec![PactTerm::new("k".into(), "v".into())])
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let err = validate_pact_terms(&pact).unwrap_err();
        assert!(
            err.to_string().contains("pact_version must be 1"),
            "expected version error, got: {err}"
        );
    }

    #[test]
    fn decode_rejects_semantically_invalid_pact_version() {
        let mut bytes = serialize_pact_terms(&sample_pact()).unwrap();
        // `pact_version` is the final canonical map entry and the V1 value is
        // the final single-byte integer. Mutating only that byte preserves a
        // structurally valid, canonical CBOR map while violating the pact
        // semantic contract.
        assert_eq!(bytes.last(), Some(&1));
        *bytes.last_mut().unwrap() = 2;

        let err = parse_pact_terms(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("pact_version must be 1"),
            "expected decode-side version error, got: {err}"
        );
    }

    #[test]
    fn decode_rejects_oversized_input_before_cbor_parsing() {
        // Deliberately not valid CBOR. The size boundary must win before the
        // decoder inspects or allocates the attacker-controlled structure.
        let oversized = vec![0_u8; MAX_PACT_CBOR_SIZE + 1];
        let err = parse_pact_terms(&oversized).unwrap_err();
        assert!(
            err.to_string().contains("serialised pact exceeds"),
            "expected pre-decode size error, got: {err}"
        );
    }

    #[test]
    fn pact_terms_rejects_empty_title() {
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title(String::new())
            .terms(vec![PactTerm::new("k".into(), "v".into())])
            .party_a(PartyIdentifier::new("A".into(), None))
            .party_b(PartyIdentifier::new("B".into(), None))
            .notes(None)
            .build()
            .unwrap();

        let err = validate_pact_terms(&pact).unwrap_err();
        assert!(
            err.to_string().contains("title must not be empty"),
            "expected empty title error, got: {err}"
        );
    }
}
