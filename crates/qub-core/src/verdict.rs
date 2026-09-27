//! Verdict body — structured self-grading of a verdict-bearing parent
//! qub (verdict-uplift-plan §3.4, §6.4).
//!
//! The verdict body is canonical CBOR encoding of [`VerdictBody`],
//! consistent with how pacts store [`crate::pact::PactTerms`] in their
//! body field. The parent relationship is carried by the `Parent-Tx-Id`
//! Arweave tag, NOT on the body — the body is self-contained creator
//! self-grading of a claim whose context lives one step up the chain.
//!
//! The verdict outcome is a generic four-way enum (Right / Partial /
//! Wrong / Unfalsifiable). Per-intent labels ("Called it" / "Kept it"
//! / "Shipped" / "Confirmed" for Right, etc.) are a viewer-side
//! rendering concern resolved against the parent qub's intent; the
//! wire stays language- and intent-neutral.
//!
//! No serde — hand-written CBOR per the protocol rule. Mirrors the
//! pact body's design (and the protocol-no-serde gate).
//!
//! Safety surface for the evidence URL (plan §6.4.1): HTTPS only,
//! ≤ 2048 chars, NFC, no hostile codepoints. The Worker re-validates
//! at `/api/v1/seal` so the protocol layer is the defence-in-depth
//! checkpoint, not the only one. The reveal-side renderer emits
//! `rel="nofollow noopener noreferrer" target="_blank"` and shows the
//! visible host (V1.5e).

use ciborium::Value;

use crate::cbor::{
    CborError, assert_canonical_key_order, encode_map, extract_optional_text, extract_u8,
    parse_top_level_map, reject_unknown_keys, text, to_nfc, u8_value,
};
use crate::handle::contains_hostile_text_codepoint;
use crate::types::QubError;
use crate::wire::is_cbor_map_header;
use unicode_normalization::UnicodeNormalization;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Schema version of the verdict body. Future revisions bump this and
/// land alongside a new protocol version (PROTOCOL.md §12).
pub const VERDICT_VERSION_1: u8 = 1;

/// Maximum length of the optional `reflection` text, in bytes (NFC
/// UTF-8). Plan §6.4: "optional, 500 chars". Bytes here, not
/// codepoints — a 500-char ceiling is intent; the byte-cap is the
/// enforced floor.
const MAX_REFLECTION_BYTES: usize = 2_000;

/// Maximum length of the optional `evidence_url`. Plan §6.4.1: 2048
/// characters (browser URL practical limit). Bytes since URLs are
/// ASCII-or-percent-encoded by construction.
const MAX_EVIDENCE_URL_BYTES: usize = 2_048;

/// Maximum total serialised CBOR size for a verdict body. Cross-
/// checked against `max_body_size(CONTENT_TYPE_VERDICT, _) = 8_192`
/// in [`crate::types`]; the cap is the same.
pub const MAX_VERDICT_CBOR_SIZE: usize = 8_192;

// Canonical key order (sorted by encoded byte length, then lex).
// Same rule as PactTerms and the envelope/sealed types — keep
// debug-assertions in lockstep with the order encoded by
// `serialize_verdict_body`.
//
// "outcome"          (7 chars  → 8 encoded)
// "reflection"       (10 chars → 11 encoded)
// "evidence_url"     (12 chars → 13 encoded)
// "verdict_version"  (15 chars → 16 encoded)
const VERDICT_BODY_KEYS: &[&str] = &["outcome", "reflection", "evidence_url", "verdict_version"];

// -----------------------------------------------------------------------------
// Parent-author proof-of-possession challenge
// -----------------------------------------------------------------------------

/// Domain separator for the verdict parent-author proof-of-possession.
///
/// Exactly 21 ASCII bytes; mirrored byte-for-byte by the Worker's
/// `buildVerdictParentChallenge` (`workers/api/src/utils/upload-proofs.ts`).
pub const VERDICT_PARENT_PROOF_DOMAIN: &[u8; 21] = b"QUB_VERDICT_PARENT_V1";

/// Build the verdict parent-author proof-of-possession challenge bytes.
///
/// Only the author of a parent qub may publish a verdict on it. The Worker
/// is byte-blind, and the parent link lives only on the out-of-band
/// `Parent-Tx-Id` Arweave tag (it is NOT in the signed verdict body), so
/// the Worker cannot recover an owner check from the wire. This detached
/// proof closes that gap (`QUB-UPLOAD-002`): the uploader signs this
/// challenge with the key whose fingerprint equals the PARENT's published
/// `Author` fingerprint, binding the chosen `outcome` and this verdict's
/// own `verdict_qub_id` (so a proof can't be lifted onto another verdict or
/// outcome) to `parent_tx_id`.
///
/// Layout (raw — signed directly via ML-DSA-65, not pre-hashed):
///
/// ```text
/// "QUB_VERDICT_PARENT_V1"  ||  // 21 bytes
/// parent_tx_id (ASCII)     ||  // 43 bytes (Arweave tx id)
/// outcome                  ||  // u8, 1 byte (1..=4)
/// verdict_qub_id               // [u8; 32]
/// ```
#[must_use]
pub fn build_verdict_parent_proof_challenge(
    parent_tx_id: &str,
    outcome: u8,
    verdict_qub_id: &[u8; 32],
) -> Vec<u8> {
    // `parent_tx_id` is concatenated with no length delimiter, so the
    // anti-collision property of the preimage rests on it being a
    // fixed-width 43-char Arweave tx id (callers validate via
    // `crate::txid`). Assert the contract so a variable-length value
    // can never silently create ambiguous challenge bytes.
    debug_assert!(
        parent_tx_id.len() == 43 && parent_tx_id.is_ascii(),
        "parent_tx_id must be a 43-char ASCII Arweave tx id, got {} bytes",
        parent_tx_id.len()
    );
    let mut out =
        Vec::with_capacity(VERDICT_PARENT_PROOF_DOMAIN.len() + parent_tx_id.len() + 1 + 32);
    out.extend_from_slice(VERDICT_PARENT_PROOF_DOMAIN);
    out.extend_from_slice(parent_tx_id.as_bytes());
    out.push(outcome);
    out.extend_from_slice(verdict_qub_id);
    out
}

// -----------------------------------------------------------------------------
// Outcome enum
// -----------------------------------------------------------------------------

/// One of the four outcome buckets a verdict can carry.
///
/// The wire encoding is a single CBOR byte under the `outcome` map
/// key. Values outside `1..=4` are rejected at the decode boundary.
///
/// Per-intent labels (resolved viewer-side, NOT on the wire):
///
/// | Outcome         | prediction      | commitment       | announcement    | thesis        |
/// | --------------- | --------------- | ---------------- | --------------- | ------------- |
/// | `Right`         | Called it       | I kept it        | Shipped         | Confirmed     |
/// | `Partial`       | Too close       | I kept part of it| Slipped         | Inconclusive  |
/// | `Wrong`         | Missed it       | I broke it       | Cancelled       | Disconfirmed  |
/// | `Unfalsifiable` | Unfalsifiable   | Unfalsifiable    | Unfalsifiable   | Unfalsifiable |
///
/// `Unfalsifiable` is the universal escape — the creator who realised
/// in hindsight that the claim couldn't be verified has a way to say
/// so without lying in either direction (plan §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VerdictOutcome {
    /// The creator's claim held — they were right (per-intent label
    /// rendered viewer-side).
    Right = 1,
    /// Mixed signal — partial validation, slipped on time, or
    /// otherwise neither clean win nor clean loss.
    Partial = 2,
    /// The creator's claim failed — they were wrong / it didn't ship
    /// / the thesis was disconfirmed.
    Wrong = 3,
    /// In hindsight the claim wasn't falsifiable. The integrity
    /// option (plan §6.4) — admits the framing problem instead of
    /// forcing a binary that the data can't support.
    Unfalsifiable = 4,
}

impl VerdictOutcome {
    /// Stable English shorthand for analytics / telemetry. Not for
    /// user-facing display — that's the per-intent label rendered
    /// viewer-side from the localised string catalogue.
    #[must_use]
    pub const fn telemetry_label(self) -> &'static str {
        match self {
            Self::Right => "right",
            Self::Partial => "partial",
            Self::Wrong => "wrong",
            Self::Unfalsifiable => "unfalsifiable",
        }
    }

    /// Raw wire byte. The CBOR encoder writes this under the
    /// `outcome` map key.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parse a wire byte into a [`VerdictOutcome`]. Returns `None`
    /// for any value outside `1..=4` — the decode boundary rejects.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Right),
            2 => Some(Self::Partial),
            3 => Some(Self::Wrong),
            4 => Some(Self::Unfalsifiable),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------------------
// VerdictBody
// -----------------------------------------------------------------------------

/// Structured verdict body sealed inside a qub envelope for
/// `content_type = 0x04` (verdict-uplift-plan §3.4).
///
/// The parent relationship lives on the Arweave `Parent-Tx-Id` tag
/// (out-of-band) — it is NOT part of the signed/sealed body. This is
/// deliberate: a verdict carries a self-contained claim ("I was
/// right"), and the audit chain ("right about what?") is established
/// by the Arweave-tag lookup. Without the tag the body is still a
/// valid signed statement of self-assessment.
///
/// Construct via [`VerdictBodyBuilder`] so the validation rules in
/// plan §6.4 + §6.4.1 fire deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictBody {
    verdict_version: u8,
    outcome: VerdictOutcome,
    /// Optional creator reflection ("what changed", "what did you
    /// learn"). Up to [`MAX_REFLECTION_BYTES`] NFC-normalised bytes.
    /// Plan §6.4: "optional, 500 chars" — interpreted as a UX
    /// guidance figure; the byte-cap above is the enforced floor.
    reflection: Option<String>,
    /// Optional evidence URL. HTTPS only, ≤
    /// [`MAX_EVIDENCE_URL_BYTES`] bytes, NFC, no hostile codepoints
    /// (plan §6.4.1). Viewer-side rendering attaches
    /// `rel="nofollow noopener noreferrer" target="_blank"` and
    /// shows the visible host.
    evidence_url: Option<String>,
}

impl VerdictBody {
    /// Returns the schema version.
    #[must_use]
    pub const fn verdict_version(&self) -> u8 {
        self.verdict_version
    }

    /// Returns the verdict outcome.
    #[must_use]
    pub const fn outcome(&self) -> VerdictOutcome {
        self.outcome
    }

    /// Returns the optional reflection text.
    #[must_use]
    pub fn reflection(&self) -> Option<&str> {
        self.reflection.as_deref()
    }

    /// Returns the optional evidence URL.
    #[must_use]
    pub fn evidence_url(&self) -> Option<&str> {
        self.evidence_url.as_deref()
    }
}

/// Builder for [`VerdictBody`]. Validates per plan §6.4 + §6.4.1 at
/// `build()` time so callers get a single error surface.
#[derive(Debug, Default, Clone)]
pub struct VerdictBodyBuilder {
    verdict_version: Option<u8>,
    outcome: Option<VerdictOutcome>,
    reflection: Option<String>,
    evidence_url: Option<String>,
}

impl VerdictBodyBuilder {
    /// New empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            verdict_version: None,
            outcome: None,
            reflection: None,
            evidence_url: None,
        }
    }

    /// Pin the schema version. Always [`VERDICT_VERSION_1`] for V1.
    #[must_use]
    pub const fn verdict_version(mut self, v: u8) -> Self {
        self.verdict_version = Some(v);
        self
    }

    /// Pin the verdict outcome.
    #[must_use]
    pub const fn outcome(mut self, o: VerdictOutcome) -> Self {
        self.outcome = Some(o);
        self
    }

    /// Attach the optional reflection text. Empty / whitespace-only
    /// strings collapse to `None` at build time.
    #[must_use]
    pub fn reflection(mut self, s: Option<String>) -> Self {
        self.reflection = s;
        self
    }

    /// Attach the optional evidence URL. Empty strings collapse to
    /// `None` at build time. Validation runs in `build()`.
    #[must_use]
    pub fn evidence_url(mut self, s: Option<String>) -> Self {
        self.evidence_url = s;
        self
    }

    /// Build the [`VerdictBody`]. Runs every validation rule from
    /// plan §6.4 + §6.4.1.
    pub fn build(self) -> Result<VerdictBody, QubError> {
        let verdict_version = self
            .verdict_version
            .ok_or(QubError::MissingBuilderField("verdict_version"))?;
        if verdict_version != VERDICT_VERSION_1 {
            return Err(QubError::UnsupportedVerdictVersion(verdict_version));
        }
        let outcome = self
            .outcome
            .ok_or(QubError::MissingBuilderField("outcome"))?;

        let reflection = match self.reflection {
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    let nfc: String = trimmed.nfc().collect();
                    if nfc.len() > MAX_REFLECTION_BYTES {
                        return Err(QubError::VerdictReflectionTooLong {
                            len: nfc.len(),
                            max: MAX_REFLECTION_BYTES,
                        });
                    }
                    if contains_hostile_text_codepoint(&nfc) {
                        return Err(QubError::VerdictReflectionHostileCodepoint);
                    }
                    Some(nfc)
                }
            },
            None => None,
        };

        let evidence_url = match self.evidence_url {
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    let nfc: String = trimmed.nfc().collect();
                    validate_evidence_url(&nfc)?;
                    Some(nfc)
                }
            },
            None => None,
        };

        Ok(VerdictBody {
            verdict_version,
            outcome,
            reflection,
            evidence_url,
        })
    }
}

/// Apply plan §6.4.1 safety rules to an evidence URL. Pure — no
/// network; never fetches the URL. Defence-in-depth: the Worker
/// re-validates at `/api/v1/seal` and the reveal-side renderer
/// attaches `rel="nofollow noopener noreferrer"`.
fn validate_evidence_url(url: &str) -> Result<(), QubError> {
    if url.len() > MAX_EVIDENCE_URL_BYTES {
        return Err(QubError::VerdictEvidenceUrlTooLong {
            len: url.len(),
            max: MAX_EVIDENCE_URL_BYTES,
        });
    }
    if !url.starts_with("https://") {
        // Note the scheme prefix-check includes the `://` so a
        // string like `"httpsx://example.com"` is rejected too.
        return Err(QubError::VerdictEvidenceUrlSchemeInvalid);
    }
    // After the `https://` prefix there must be a non-empty host
    // segment. `https://` alone or `https:///path` are rejected.
    let after_scheme = url
        .get("https://".len()..)
        .ok_or(QubError::VerdictEvidenceUrlInvalid)?;
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host = after_scheme
        .get(..host_end)
        .ok_or(QubError::VerdictEvidenceUrlInvalid)?;
    if host.is_empty() {
        return Err(QubError::VerdictEvidenceUrlInvalid);
    }
    if contains_hostile_text_codepoint(url) {
        return Err(QubError::VerdictEvidenceUrlHostileCodepoint);
    }
    // Reject any ASCII control / whitespace anywhere in the URL.
    // The bidi-spoof / ZWSP / tag-block check above covers the
    // unicode side; this catches plain `\n` / `\t` injections.
    if url
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b < 0x20 || b == 0x7F)
    {
        return Err(QubError::VerdictEvidenceUrlInvalid);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Wire newtype
// -----------------------------------------------------------------------------

/// Canonical CBOR bytes for a [`VerdictBody`]. Mirrors
/// [`crate::pact::PactTermsCbor`] one-to-one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictBodyCbor(Vec<u8>);

impl VerdictBodyCbor {
    /// Wrap raw bytes assumed to already be canonical CBOR (e.g. on
    /// the read path from Arweave). Validation happens at parse
    /// time — same posture as [`crate::wire::SealedQubCbor`].
    #[must_use]
    pub const fn from_encoded(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the newtype and returns the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

// -----------------------------------------------------------------------------
// Serialisation
// -----------------------------------------------------------------------------

/// Serialise a [`VerdictBody`] to canonical CBOR bytes.
///
/// Key order is locked at the module-private `VERDICT_BODY_KEYS`
/// array; the debug assertion in `assert_canonical_key_order` fires
/// if a future edit reorders silently. Optional fields are omitted
/// entirely when `None` — canonical CBOR per the protocol rule.
pub fn serialize_verdict_body(body: &VerdictBody) -> Result<Vec<u8>, CborError> {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(VERDICT_BODY_KEYS.len());
    let mut keys_used: Vec<&str> = Vec::with_capacity(VERDICT_BODY_KEYS.len());

    // Canonical order: outcome, reflection (optional), evidence_url
    // (optional), verdict_version.

    map.push((text("outcome"), u8_value(body.outcome().as_byte())));
    keys_used.push("outcome");

    if let Some(reflection) = body.reflection() {
        map.push((text("reflection"), Value::Text(to_nfc(reflection))));
        keys_used.push("reflection");
    }

    if let Some(url) = body.evidence_url() {
        map.push((text("evidence_url"), Value::Text(to_nfc(url))));
        keys_used.push("evidence_url");
    }

    map.push((text("verdict_version"), u8_value(body.verdict_version())));
    keys_used.push("verdict_version");

    assert_canonical_key_order(&keys_used);

    encode_map(map)
}

/// Parse canonical CBOR bytes into a [`VerdictBody`]. Same posture
/// as [`crate::pact::parse_pact_terms`]:
///
/// - rejects non-canonical key order (duplicate keys, wrong order,
///   non-text keys, non-NFC keys)
/// - rejects unsupported `verdict_version`
/// - rejects out-of-range outcome bytes
/// - re-runs the §6.4.1 evidence-URL validation on read (so a
///   tampered KV entry can't bypass the rules)
pub fn parse_verdict_body(bytes: &[u8]) -> Result<VerdictBody, CborError> {
    if bytes.len() > MAX_VERDICT_CBOR_SIZE {
        return Err(CborError::StructuralError(format!(
            "verdict body exceeds maximum size of {MAX_VERDICT_CBOR_SIZE} bytes",
        )));
    }
    match bytes.first() {
        Some(&b) if is_cbor_map_header(b) => {},
        _ => {
            return Err(CborError::StructuralError(
                "verdict body must be a CBOR map".into(),
            ));
        },
    }

    let map = parse_top_level_map(bytes)?;
    reject_unknown_keys(&map, VERDICT_BODY_KEYS, "VerdictBody")?;

    let outcome_byte = extract_u8(&map, "outcome")?;
    let outcome = VerdictOutcome::from_byte(outcome_byte).ok_or_else(|| {
        CborError::StructuralError(format!(
            "verdict outcome byte {outcome_byte} is outside the 1..=4 range",
        ))
    })?;

    let reflection = extract_optional_text(&map, "reflection")?;
    let evidence_url = extract_optional_text(&map, "evidence_url")?;
    let verdict_version = extract_u8(&map, "verdict_version")?;

    // Use the builder so the size + NFC + hostile-codepoint rules
    // run on read as well as on construct. This is the
    // defence-in-depth checkpoint the plan calls out: a tampered
    // KV entry MUST NOT bypass §6.4.1.
    VerdictBodyBuilder::new()
        .verdict_version(verdict_version)
        .outcome(outcome)
        .reflection(reflection)
        .evidence_url(evidence_url)
        .build()
        .map_err(|e| CborError::StructuralError(format!("verdict validation failed: {e}")))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn body_called_it() -> VerdictBody {
        VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .reflection(Some("S&P closed at 8,512 on 2026-12-01.".into()))
            .evidence_url(Some("https://example.com/sp500-close-2026-12-01".into()))
            .build()
            .unwrap()
    }

    #[test]
    fn verdict_parent_proof_challenge_layout() {
        // 21-byte domain || 43-byte parent_tx_id || 1-byte outcome ||
        // 32-byte verdict_qub_id. Pinned so the Worker's
        // buildVerdictParentChallenge stays in lockstep.
        assert_eq!(VERDICT_PARENT_PROOF_DOMAIN, b"QUB_VERDICT_PARENT_V1");
        assert_eq!(VERDICT_PARENT_PROOF_DOMAIN.len(), 21);
        let parent = "0123456789abcdef0123456789abcdef0123456_AB-";
        assert_eq!(parent.len(), 43);
        let qub_id = [0x33u8; 32];
        let c = build_verdict_parent_proof_challenge(parent, 2, &qub_id);
        assert_eq!(c.len(), 21 + 43 + 1 + 32);
        assert_eq!(&c[..21], VERDICT_PARENT_PROOF_DOMAIN);
        assert_eq!(&c[21..64], parent.as_bytes());
        assert_eq!(c[64], 2);
        assert_eq!(&c[65..97], &qub_id);
    }

    #[test]
    fn outcome_byte_round_trip() {
        for o in [
            VerdictOutcome::Right,
            VerdictOutcome::Partial,
            VerdictOutcome::Wrong,
            VerdictOutcome::Unfalsifiable,
        ] {
            assert_eq!(VerdictOutcome::from_byte(o.as_byte()), Some(o));
        }
    }

    #[test]
    fn outcome_rejects_invalid_bytes() {
        for b in [0u8, 5, 6, 100, 255] {
            assert_eq!(VerdictOutcome::from_byte(b), None, "byte {b} must reject");
        }
    }

    /// Accessor read-back for the verdict body and its wire newtype.
    /// `as_bytes` / `into_bytes` / `verdict_version` were all `FnValue`
    /// survivors — projections of state the round-trip tests exercise but
    /// never read back individually.
    /// Length-bound boundary, pinned from both sides. `>` → `>=` is
    /// invisible unless something of EXACTLY the limit is accepted, and
    /// `>` → `==` is invisible unless something strictly larger is
    /// rejected. Neither case existed here.
    /// `parse_verdict_body` applies its size cap BEFORE decoding, so an
    /// input of exactly the cap must get past it and fail for some other
    /// reason. Only asserting that oversized input is refused cannot tell
    /// `>` from `>=`.
    #[test]
    fn parse_verdict_body_size_cap_admits_exactly_the_limit() {
        let at_cap = vec![0xA1u8; MAX_VERDICT_CBOR_SIZE];
        let err = parse_verdict_body(&at_cap).expect_err("still invalid CBOR");
        assert!(
            !format!("{err}").contains("exceeds maximum size"),
            "input of exactly the cap must pass the size gate, got {err:?}"
        );

        let over_cap = vec![0xA1u8; MAX_VERDICT_CBOR_SIZE + 1];
        let err = parse_verdict_body(&over_cap).expect_err("over the cap");
        assert!(
            format!("{err}").contains("exceeds maximum size"),
            "one byte over the cap must be refused by the size gate, got {err:?}"
        );
    }

    #[test]
    fn verdict_text_caps_are_pinned_both_sides() {
        let with_reflection = |n: usize| {
            VerdictBodyBuilder::new()
                .verdict_version(VERDICT_VERSION_1)
                .outcome(VerdictOutcome::Right)
                .reflection(Some("a".repeat(n)))
                .build()
        };
        assert!(
            with_reflection(MAX_REFLECTION_BYTES).is_ok(),
            "a reflection of exactly the cap must be accepted"
        );
        assert!(matches!(
            with_reflection(MAX_REFLECTION_BYTES + 1),
            Err(QubError::VerdictReflectionTooLong { .. })
        ));

        // The evidence URL cap, with a well-formed https URL padded to
        // exactly the limit so only the length arm can reject it.
        let url = |total: usize| {
            let prefix = "https://e.example/";
            format!("{prefix}{}", "a".repeat(total - prefix.len()))
        };
        assert!(
            validate_evidence_url(&url(MAX_EVIDENCE_URL_BYTES)).is_ok(),
            "a URL of exactly the cap must be accepted"
        );
        assert!(matches!(
            validate_evidence_url(&url(MAX_EVIDENCE_URL_BYTES + 1)),
            Err(QubError::VerdictEvidenceUrlTooLong { .. })
        ));
    }

    #[test]
    fn verdict_accessors_read_back() {
        assert_eq!(body_called_it().verdict_version(), VERDICT_VERSION_1);

        let raw = vec![0xA1, 0xB2, 0xC3, 0xD4];
        let cbor = VerdictBodyCbor::from_encoded(raw.clone());
        assert_eq!(cbor.as_bytes(), raw.as_slice());
        assert_eq!(cbor.into_bytes(), raw);
    }

    #[test]
    fn builder_round_trip() {
        let body = body_called_it();
        let bytes = serialize_verdict_body(&body).unwrap();
        let parsed = parse_verdict_body(&bytes).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn builder_omits_optionals_when_none() {
        let body = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Unfalsifiable)
            .build()
            .unwrap();
        let bytes = serialize_verdict_body(&body).unwrap();
        // No `reflection` key, no `evidence_url` key — canonical
        // omission. The presence of either as a serialised key
        // would indicate a regression in the optional encoding.
        let parsed = parse_verdict_body(&bytes).unwrap();
        assert_eq!(parsed.reflection(), None);
        assert_eq!(parsed.evidence_url(), None);
    }

    #[test]
    fn rejects_http_evidence_url() {
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .evidence_url(Some("http://example.com".into()))
            .build()
            .unwrap_err();
        assert!(
            matches!(err, QubError::VerdictEvidenceUrlSchemeInvalid),
            "got {err:?}",
        );
    }

    #[test]
    fn rejects_data_uri_evidence_url() {
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .evidence_url(Some("data:text/plain,evidence".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::VerdictEvidenceUrlSchemeInvalid));
    }

    #[test]
    fn rejects_javascript_uri_evidence_url() {
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .evidence_url(Some("javascript:alert(1)".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::VerdictEvidenceUrlSchemeInvalid));
    }

    #[test]
    fn rejects_evidence_url_with_whitespace() {
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .evidence_url(Some("https://example.com/with space".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::VerdictEvidenceUrlInvalid));
    }

    #[test]
    fn rejects_evidence_url_at_oversize() {
        // 2048 + 1 bytes, starting with valid https:// prefix.
        let oversized = format!("https://example.com/{}", "a".repeat(2048));
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .evidence_url(Some(oversized))
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::VerdictEvidenceUrlTooLong { .. }));
    }

    #[test]
    fn rejects_evidence_url_with_bidi_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — a classic bidi spoof.
        let url = "https://example.com/\u{202E}reverse";
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .evidence_url(Some(url.into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::VerdictEvidenceUrlHostileCodepoint));
    }

    #[test]
    fn rejects_reflection_with_zwsp() {
        // U+200B ZERO WIDTH SPACE — zero-width brand bypass.
        let reflection = "I was \u{200B}right.";
        let err = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .reflection(Some(reflection.into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::VerdictReflectionHostileCodepoint));
    }

    #[test]
    fn empty_reflection_collapses_to_none() {
        let body = VerdictBodyBuilder::new()
            .verdict_version(VERDICT_VERSION_1)
            .outcome(VerdictOutcome::Right)
            .reflection(Some("   ".into()))
            .build()
            .unwrap();
        assert_eq!(body.reflection(), None);
    }

    #[test]
    fn rejects_unsupported_verdict_version() {
        let err = VerdictBodyBuilder::new()
            .verdict_version(99)
            .outcome(VerdictOutcome::Right)
            .build()
            .unwrap_err();
        assert!(matches!(err, QubError::UnsupportedVerdictVersion(99)));
    }

    #[test]
    fn parse_rejects_outcome_byte_out_of_range() {
        // Serialise a valid body then patch the encoded outcome
        // byte to `5` — still inside CBOR shortform u8 range
        // (0..=23 encode as a single byte) so the decoder reads
        // it as a u8, but outside the 1..=4 range
        // `VerdictOutcome::from_byte` accepts. Anything ≥24 would
        // shift the encoding to multi-byte and confuse the
        // decoder before the value check runs.
        let body = body_called_it();
        let mut bytes = serialize_verdict_body(&body).unwrap();
        let key = b"outcome";
        let pos = bytes.windows(key.len()).position(|w| w == key).unwrap();
        bytes[pos + key.len()] = 5;
        let err = parse_verdict_body(&bytes).unwrap_err();
        assert!(matches!(err, CborError::StructuralError(_)), "got {err:?}");
    }

    #[test]
    fn parse_rejects_oversize_body() {
        // A buffer larger than MAX_VERDICT_CBOR_SIZE must reject
        // before even reaching the CBOR decoder. Any byte content
        // is fine; the cap is purely a length gate.
        let bytes = vec![0xA1; MAX_VERDICT_CBOR_SIZE + 1];
        let err = parse_verdict_body(&bytes).unwrap_err();
        assert!(matches!(err, CborError::StructuralError(_)));
    }

    #[test]
    fn parse_rejects_non_map_header() {
        let bytes = vec![0x82, 0x01, 0x02]; // CBOR array of 2 ints
        let err = parse_verdict_body(&bytes).unwrap_err();
        assert!(matches!(err, CborError::StructuralError(_)));
    }

    #[test]
    fn telemetry_labels_are_stable() {
        // Pinning the analytics surface — dashboards consume these
        // strings directly. A rename without updating downstream
        // would silently break the verdict outcome distribution
        // graph.
        assert_eq!(VerdictOutcome::Right.telemetry_label(), "right");
        assert_eq!(VerdictOutcome::Partial.telemetry_label(), "partial");
        assert_eq!(VerdictOutcome::Wrong.telemetry_label(), "wrong");
        assert_eq!(
            VerdictOutcome::Unfalsifiable.telemetry_label(),
            "unfalsifiable",
        );
    }

    #[test]
    fn serialized_form_carries_canonical_key_order() {
        let body = body_called_it();
        let bytes = serialize_verdict_body(&body).unwrap();
        // Find the position of each key in the encoded bytes and
        // assert they appear in ascending order. Key ordering is
        // load-bearing — a misorder breaks the canonical-CBOR
        // contract and any qub_id derivation that includes this
        // body (qub_id derivation hashes body_hash, which hashes
        // the encoded bytes).
        let positions: Vec<usize> = ["outcome", "reflection", "evidence_url", "verdict_version"]
            .iter()
            .map(|k| {
                bytes
                    .windows(k.len())
                    .position(|w| w == k.as_bytes())
                    .unwrap_or_else(|| panic!("key {k} not found"))
            })
            .collect();
        for w in positions.windows(2) {
            assert!(
                w[0] < w[1],
                "non-canonical key order: positions {positions:?}",
            );
        }
    }
}
