//! Shared domain types for qub payloads, metadata, and protocol envelopes.
//!
//! This module defines the in-memory Rust representation of the four core
//! protocol data structures described in `PROTOCOL.md` §2:
//!
//! * [`ComposeQub`] — creator-side in-memory draft state (not serialised).
//! * [`QubEnvelope`] — the decrypted payload (serialised via canonical CBOR
//!   in task A3, then encrypted inside a [`SealedQub`]).
//! * [`SealedQub`] — the canonical on-wire artifact stored on Arweave.
//! * [`RevealedQub`] — viewer-side application state produced after
//!   successful decryption and verification (not serialised).
//!
//! Serialisation, hashing, and cryptographic operations are intentionally
//! *not* implemented here — they live in sibling modules (`cbor`, `hash`,
//! `wire`) and later tasks. The types in this module describe the *shape*
//! of the data and enforce the structural invariants that downstream layers
//! rely on.

use sha3::{Digest, Sha3_256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

// -----------------------------------------------------------------------------
// Protocol version and size limits
// -----------------------------------------------------------------------------

/// Protocol major version for qub v1.
pub const PROTOCOL_VERSION_1: u8 = 0x01;

/// Hard ceiling on the size of a serialised CBOR payload, in bytes.
///
/// Applies to [`SealedQub`] bytes as stored on Arweave. See PDD §7.6.
pub const MAX_SERIALISED_SIZE: usize = 102_400; // 100 KB

/// Maximum length of a [`SealedQub::title`] string, in NFC code points.
///
/// The title is plaintext on `SealedQub`, surfaced on the viewer
/// countdown page before reveal, and bound to `qub_id` via
/// `title_hash` (see [`crate::hash::title_hash`]).
pub const MAX_TITLE_CODEPOINTS: usize = 100;

/// Maximum length of a [`QubEnvelope::sender_label`] string, in NFC code
/// points.
///
/// Mirrors the Worker edge (`normaliseAndValidateText` with
/// `maxCodepoints: 80` in `workers/api/src/routes/seal.ts`) so the
/// library-side compose validation and the wire decoder enforce the same
/// ceiling as the server-side seal path.
pub const MAX_SENDER_LABEL_CODEPOINTS: usize = 80;

// -----------------------------------------------------------------------------
// Visibility
// -----------------------------------------------------------------------------

/// Visibility byte for a publicly-addressable qub.
pub const VISIBILITY_PUBLIC: u8 = 0x01;

/// Visibility byte for a private, link-capability-gated qub.
pub const VISIBILITY_PRIVATE: u8 = 0x00;

/// Returns `true` if `value` corresponds to a known visibility byte.
const fn is_known_visibility(value: u8) -> bool {
    matches!(value, VISIBILITY_PUBLIC | VISIBILITY_PRIVATE)
}

// -----------------------------------------------------------------------------
// Content type registry
// -----------------------------------------------------------------------------

/// Reserved content type value `0x00`. MUST NOT be used on the wire.
pub const CONTENT_TYPE_RESERVED_ZERO: u8 = 0x00;

/// Plain text (UTF-8, restricted Markdown). The only supported content type
/// in the MVP.
pub const CONTENT_TYPE_TEXT: u8 = 0x01;

/// Opus-encoded voice note (Phase 2).
pub const CONTENT_TYPE_VOICE: u8 = 0x02;

/// Pact — structured bilateral agreement (Phase 2).
pub const CONTENT_TYPE_PACT: u8 = 0x03;

/// Verdict body — creator self-grading of a verdict-bearing parent qub.
///
/// Body is canonical CBOR encoding of [`crate::verdict::VerdictBody`]
/// (verdict-uplift-plan §3.4, §6.4); the parent relationship lives on
/// the `Parent-Tx-Id` Arweave tag, not on the body itself. Only
/// emitted from the system-side `verdict` entry in
/// [`crate::intent::INTENT_NAMES`]; not user-selectable in the
/// `IntentSelector`.
pub const CONTENT_TYPE_VERDICT: u8 = 0x04;

/// Maximum body size, in bytes, permitted for a given content type and tier.
///
/// Returns `None` when `content_type` is unknown, reserved, or otherwise
/// unsupported. The `is_paid` flag selects between the free-tier and
/// paid-tier limits for content types that differentiate (currently only
/// plain text; see PDD §7.6).
///
/// Verdict bodies are bounded at 8 KB — the structured body is small
/// by construction (outcome byte + bounded reflection + bounded URL),
/// so the cap is well above any legitimate use and well under the
/// 50 KB paid-text ceiling. Tier-independent for V1; the verdict
/// ceremony is part of the audience-integrity loop and shouldn't be
/// paywalled.
///
/// Tier enforcement is performed at the Worker level; this function exposes
/// the limits so that creator-side validation can catch oversized bodies
/// early.
///
/// # Examples
///
/// ```
/// use qub_core::types::{
///     max_body_size, CONTENT_TYPE_TEXT, CONTENT_TYPE_VOICE, CONTENT_TYPE_PACT,
///     CONTENT_TYPE_RESERVED_ZERO,
/// };
///
/// // Text: free tier 10 KB, paid tier 50 KB.
/// assert_eq!(max_body_size(CONTENT_TYPE_TEXT, false), Some(10_240));
/// assert_eq!(max_body_size(CONTENT_TYPE_TEXT, true), Some(51_200));
///
/// // Voice is not tier-differentiated (2 MB for everyone).
/// assert_eq!(max_body_size(CONTENT_TYPE_VOICE, false), Some(2_097_152));
///
/// // Pact: 100 KB, no tier differentiation.
/// assert_eq!(max_body_size(CONTENT_TYPE_PACT, false), Some(102_400));
/// assert_eq!(max_body_size(CONTENT_TYPE_PACT, true), Some(102_400));
///
/// // Reserved / unknown content types return None.
/// assert_eq!(max_body_size(CONTENT_TYPE_RESERVED_ZERO, true), None);
/// assert_eq!(max_body_size(0xFF, true), None);
/// ```
#[must_use]
pub const fn max_body_size(content_type: u8, is_paid: bool) -> Option<usize> {
    match content_type {
        CONTENT_TYPE_TEXT => Some(if is_paid { 51_200 } else { 10_240 }),
        CONTENT_TYPE_VOICE => Some(2_097_152),
        CONTENT_TYPE_PACT => Some(102_400),
        CONTENT_TYPE_VERDICT => Some(8_192),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Signature algorithm registry
// -----------------------------------------------------------------------------

/// No author signature present (MVP default; see PROTOCOL.md §9.2).
pub const SIG_ALG_NONE: u8 = 0x00;

/// ML-DSA-65 (Dilithium level 3) post-quantum signatures (Phase 2).
pub const SIG_ALG_ML_DSA_65: u8 = 0x01;

/// Ed25519 classical signatures (reserved as a fallback/interop option).
pub const SIG_ALG_ED25519: u8 = 0x02;

// -----------------------------------------------------------------------------
// Draft status
// -----------------------------------------------------------------------------

/// Lifecycle state of a [`ComposeQub`] draft as it progresses from
/// composition through sealing and upload.
///
/// # Examples
///
/// ```
/// use qub_core::types::{ComposeQub, DraftStatus, CONTENT_TYPE_TEXT};
///
/// let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
/// assert_eq!(draft.status(), DraftStatus::Composing);
///
/// draft.transition_status(DraftStatus::Sealed).unwrap();
/// assert_eq!(draft.status(), DraftStatus::Sealed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftStatus {
    /// The user is still editing the draft.
    Composing,
    /// The draft has been sealed (encrypted into a [`SealedQub`]) locally.
    Sealed,
    /// The sealed draft has been uploaded to Arweave successfully.
    Uploaded,
    /// Sealing or upload failed.
    Failed,
}

impl DraftStatus {
    /// Whether a draft may legally move from `self` to `to`.
    ///
    /// A draft is created `Composing`; sealing moves it to `Sealed`, a
    /// successful upload to `Uploaded`. `Failed` records a sealing or
    /// upload failure, and a retry may move it back to `Sealed` or on
    /// to `Uploaded`. `Uploaded` is terminal — the qub is permanently
    /// on Arweave. Same-state reaffirmations are idempotent.
    #[must_use]
    pub fn can_transition_to(self, to: Self) -> bool {
        if self == to {
            return true;
        }
        matches!(
            (self, to),
            (Self::Composing, Self::Sealed | Self::Failed)
                | (Self::Sealed, Self::Uploaded | Self::Failed)
                | (Self::Failed, Self::Sealed | Self::Uploaded)
        )
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors produced when validating or constructing protocol types.
///
/// Higher-level error types (for serialisation, crypto, and network
/// failures) are defined in sibling modules and later tasks.
///
/// This enum is `#[non_exhaustive]`: additional variants may be added in
/// minor releases. Match arms on it must include a wildcard.
///
/// # Examples
///
/// The error type implements [`std::error::Error`] and [`std::fmt::Display`]
/// via `thiserror`, so it can be inspected with the usual patterns:
///
/// ```
/// use qub_core::types::{ComposeQub, QubError, CONTENT_TYPE_TEXT};
///
/// let draft = ComposeQub::new(CONTENT_TYPE_TEXT);
/// // Draft has empty body → EmptyBody variant.
/// assert!(matches!(draft.validate(), Err(QubError::EmptyBody)));
///
/// // Display formatting is stable.
/// let err = QubError::UnsupportedContentType(0x99);
/// assert_eq!(err.to_string(), "unsupported content type: 0x99");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QubError {
    /// The body / plaintext is empty.
    #[error("body is empty")]
    EmptyBody,

    /// `unlock_at` was not set on a draft being validated.
    #[error("unlock time is required")]
    MissingUnlockTime,

    /// The supplied content type is unknown, reserved, or not yet supported.
    #[error("unsupported content type: {0:#04x}")]
    UnsupportedContentType(u8),

    /// The body exceeds the maximum size for its content type and tier.
    #[error("body exceeds maximum size: {actual} bytes > {max} bytes")]
    BodyTooLarge {
        /// Actual body length, in bytes.
        actual: usize,
        /// Maximum permitted body length, in bytes.
        max: usize,
    },

    /// The supplied protocol version is not supported by this implementation.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// The tlock ciphertext is empty.
    #[error("ciphertext is empty")]
    EmptyCiphertext,

    /// The drand chain identifier string is empty.
    #[error("drand chain ID is empty")]
    EmptyChainId,

    /// The supplied visibility byte is not a known registry value.
    #[error("unknown visibility value: {0:#04x}")]
    UnknownVisibility(u8),

    /// A required builder field was not set before `build()` was called.
    #[error("required builder field not set: {0}")]
    MissingBuilderField(&'static str),

    /// The drand chain period is zero, which is invalid.
    #[error("drand period must be non-zero")]
    InvalidPeriod,

    /// Drand round zero does not exist. Round numbering starts at one, so a
    /// sealed artifact carrying zero can never be unlocked against a real
    /// drand chain.
    #[error("drand round must be non-zero")]
    InvalidDrandRound,

    /// The unlock time is at or before the drand genesis time.
    #[error("unlock time must be after drand genesis")]
    UnlockBeforeGenesis,

    /// The `sig_alg` byte on a parsed envelope does not correspond to a
    /// known entry in the signature algorithm registry (see
    /// `PROTOCOL.md` §9.2). Unknown values MUST be rejected by
    /// conforming viewers.
    #[error("unknown signature algorithm: {0:#04x}")]
    UnknownSignatureAlgorithm(u8),

    /// A cryptographic signing operation failed (invalid key material,
    /// RNG failure, or an internal ML-DSA-65 error surfaced by the
    /// `fips204` crate).
    #[error("signing failed: {0}")]
    SigningFailed(&'static str),

    /// A signing public key or signature byte string had an unexpected
    /// length for the declared algorithm.
    #[error("wrong length for {field}: expected {expected}, got {actual}")]
    WrongSignatureLength {
        /// Name of the field whose length was invalid (e.g. `"public_key"`).
        field: &'static str,
        /// Expected length, in bytes.
        expected: usize,
        /// Actual length, in bytes.
        actual: usize,
    },

    /// Exactly one of `cosigner_pubkey` / `cosigner_signature` is present
    /// but not the other.
    #[error("cosigner fields must be both present or both absent")]
    CosignerFieldsMismatch,

    /// The cosigner public key is identical to the author public key.
    #[error("cosigner pubkey must differ from author pubkey")]
    CosignerSameAsAuthor,

    /// The title exceeds [`MAX_TITLE_CODEPOINTS`] Unicode code points after
    /// NFC normalisation.
    #[error("title exceeds maximum length: {actual} code points > {max}")]
    TitleTooLong {
        /// Actual title length, in Unicode code points (NFC).
        actual: usize,
        /// Maximum permitted length, in Unicode code points.
        max: usize,
    },

    /// The title contains a control character (U+0000..=U+001F or U+007F).
    /// Control characters are forbidden so the plaintext rendering on the
    /// viewer countdown can never inject formatting or terminal escapes.
    #[error("title contains a control character")]
    TitleHasControlChar,

    /// The title is an empty string. The canonical wire encoding of an
    /// absent title is field omission, and the decoder rejects an empty
    /// title slot — accepting `Some("")` at compose time would mint a
    /// sealed artifact no decoder accepts. Callers should map an empty
    /// input to `None` instead.
    #[error("title must be omitted rather than empty")]
    TitleEmpty,

    /// The title contains a hostile codepoint (C0/C1 control, DEL, bidi
    /// override / isolate, zero-width space, BOM, or tag-block — see
    /// [`crate::handle::is_hostile_text_codepoint`]). Same rule as the
    /// encoder-side check; enforcing it here surfaces a typed error at
    /// compose time instead of an untyped seal-time CBOR failure.
    #[error("title contains a hostile / invisible codepoint")]
    TitleHostileCodepoint,

    /// The sender label exceeds [`MAX_SENDER_LABEL_CODEPOINTS`] Unicode
    /// code points after NFC normalisation. The bound mirrors the Worker
    /// edge (`maxCodepoints: 80`).
    #[error("sender_label exceeds maximum length: {actual} code points > {max}")]
    SenderLabelTooLong {
        /// Actual sender-label length, in Unicode code points (NFC).
        actual: usize,
        /// Maximum permitted length, in Unicode code points.
        max: usize,
    },

    /// The sender label contains a hostile codepoint (C0/C1 control, DEL,
    /// bidi override / isolate, zero-width space, BOM, or tag-block —
    /// see [`crate::handle::is_hostile_text_codepoint`]). Same rule as the
    /// encoder-side check; enforcing it on decode too closes the
    /// tampered-wire injection vector.
    #[error("sender_label contains a hostile / invisible codepoint")]
    SenderLabelHostileCodepoint,

    /// `outcome_at` is set to a non-positive Unix timestamp. Outcome
    /// timestamps must be strictly positive (and, per the Worker-side
    /// validator, in the future at seal time). 0 is reserved as the
    /// absent sentinel inside the `qub_id` preimage (see
    /// `crate::hash::qub_id`). See `tasks/verdict-uplift-plan.md` §3.3.
    #[error("outcome_at must be a positive Unix timestamp")]
    InvalidOutcomeAt,

    /// `outcome_at` is set to a time at or before `unlock_at`. The
    /// outcome cannot be known before the reveal — the verdict-watch
    /// mechanic relies on `outcome_at >= unlock_at`. The equality
    /// case ("skin-in-the-game mode" — outcome IS reveal) is
    /// permitted per plan §4.2; only strict precedence is rejected.
    #[error("outcome_at ({outcome_at}) must be at or after unlock_at ({unlock_at})")]
    OutcomeBeforeUnlock {
        /// The rejected outcome timestamp (Unix seconds UTC).
        outcome_at: i64,
        /// The unlock timestamp the outcome was compared against (Unix seconds UTC).
        unlock_at: i64,
    },

    /// A verdict body carries a `verdict_version` byte the current
    /// implementation does not recognise. V1 supports
    /// [`crate::verdict::VERDICT_VERSION_1`] only; future schema
    /// revisions bump this and land alongside a new protocol
    /// version (verdict-uplift-plan §3.4).
    #[error("unsupported verdict_version: {0}")]
    UnsupportedVerdictVersion(u8),

    /// Verdict reflection text exceeded the byte cap after NFC
    /// normalisation. Plan §6.4 spells the cap as "500 chars" —
    /// the byte ceiling is the enforced floor.
    #[error("verdict reflection exceeds {max} bytes (got {len})")]
    VerdictReflectionTooLong {
        /// Actual reflection length after NFC normalisation.
        len: usize,
        /// Maximum permitted byte length.
        max: usize,
    },

    /// Verdict reflection text contained a hostile codepoint (bidi
    /// override, zero-width space, tag-block, BOM, C0/C1 control).
    /// Same rule as the title path; closes the same translation-
    /// time / pasted-from-elsewhere injection vector.
    #[error("verdict reflection contains a hostile codepoint")]
    VerdictReflectionHostileCodepoint,

    /// Evidence URL exceeded the byte cap (plan §6.4.1: 2048).
    #[error("evidence_url exceeds {max} bytes (got {len})")]
    VerdictEvidenceUrlTooLong {
        /// Actual URL length.
        len: usize,
        /// Maximum permitted length.
        max: usize,
    },

    /// Evidence URL scheme is not `https://`. Plan §6.4.1 rejects
    /// `http://`, `ftp://`, `javascript:`, `data:`, `file:`, and
    /// every non-`https` scheme outright.
    #[error("evidence_url must be https://")]
    VerdictEvidenceUrlSchemeInvalid,

    /// Evidence URL is structurally malformed (empty host, embedded
    /// whitespace, etc.). The rule complements the scheme + length
    /// + hostile-codepoint checks.
    #[error("evidence_url is malformed")]
    VerdictEvidenceUrlInvalid,

    /// Evidence URL contained a hostile codepoint. Same vector as
    /// the reflection path.
    #[error("evidence_url contains a hostile codepoint")]
    VerdictEvidenceUrlHostileCodepoint,

    /// A draft-status transition the [`DraftStatus`] lifecycle forbids —
    /// e.g. `Composing -> Uploaded` (skipping `Sealed`) or any move out
    /// of the terminal `Uploaded` state.
    #[error("illegal draft status transition: {from:?} -> {to:?}")]
    InvalidDraftTransition {
        /// The draft's current status.
        from: DraftStatus,
        /// The rejected target status.
        to: DraftStatus,
    },
}

// -----------------------------------------------------------------------------
// ComposeQub
// -----------------------------------------------------------------------------

/// Creator-side in-memory draft state.
///
/// A `ComposeQub` is **never** serialised to CBOR and **never** uploaded to
/// Arweave. It represents the working state of a draft inside the creator
/// application before it is sealed into a [`SealedQub`].
///
/// Construct with [`ComposeQub::new`] and mutate via the provided setters.
/// Call [`ComposeQub::validate`] before attempting to seal.
///
/// # Examples
///
/// Typical compose flow: create a draft, fill in the fields, validate:
///
/// ```
/// use qub_core::types::{ComposeQub, DraftStatus, CONTENT_TYPE_TEXT};
///
/// let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
/// draft.set_plaintext(b"Hello, future.".to_vec());
/// draft.set_unlock_at(1_736_294_400); // 2025-01-08 00:00:00 UTC
/// draft.set_created_at(1_735_689_600); // 2025-01-01 00:00:00 UTC
/// draft.set_sender_label(Some("Alice".into()));
///
/// // Ready to seal.
/// draft.validate().expect("draft is well-formed");
/// assert_eq!(draft.content_type(), CONTENT_TYPE_TEXT);
/// assert_eq!(draft.status(), DraftStatus::Composing);
/// assert_eq!(draft.sender_label(), Some("Alice"));
/// assert_eq!(draft.draft_id().len(), 16);
/// ```
#[derive(Debug, Clone)]
pub struct ComposeQub {
    draft_id: [u8; 16],
    created_at: i64,
    unlock_at: Option<i64>,
    visibility: u8,
    content_type: u8,
    plaintext: Vec<u8>,
    sender_label: Option<String>,
    /// Optional plaintext title surfaced on the viewer countdown page
    /// before reveal. Bound to `qub_id` via `title_hash` so a gateway
    /// cannot swap the displayed title without invalidating the qub
    /// identity. `None` means the viewer falls back to a localised
    /// intent label. See `crate::hash::derive_envelope_hashes` and
    /// PROTOCOL.md §3.2.
    title: Option<String>,
    /// Optional reference to another qub's `qub_id` — set when this
    /// draft is a reply in a chain. Carried end-to-end inside the
    /// encrypted [`QubEnvelope`] (never exposed on the pre-reveal
    /// [`SealedQub`] surface), and deliberately excluded from the
    /// `qub_id` hash preimage so adding a reply does not destabilise
    /// the canonical identity. See `crate::hash::derive_envelope_hashes`.
    reply_to: Option<[u8; 32]>,
    /// Optional outcome time — when reality will render judgment on
    /// this qub. Meaningful only for verdict-bearing intents
    /// (prediction, commitment, announcement, thesis); the
    /// intent-coupling check happens at the Worker edge and the
    /// compose UI, since `ComposeQub` doesn't carry the intent tag.
    /// When set, MUST be `>= unlock_at` (the outcome can't be known
    /// before the reveal). Folded into the `qub_id` preimage so a
    /// gateway cannot swap the displayed verdict-on date without
    /// invalidating the qub identity. See
    /// `tasks/verdict-uplift-plan.md` §3.1.
    outcome_at: Option<i64>,
    status: DraftStatus,
}

impl ComposeQub {
    /// Creates a fresh draft for the given `content_type`.
    ///
    /// A random 16-byte `draft_id` is generated via [`getrandom`]. The draft
    /// starts with empty plaintext, no unlock time, no sender label,
    /// `visibility` = [`VISIBILITY_PUBLIC`], and `status` =
    /// [`DraftStatus::Composing`]. The `created_at` field is initialised to
    /// `0`; the creator app is expected to set the real creation timestamp
    /// at seal time via [`ComposeQub::set_created_at`].
    ///
    /// For deterministic / pure construction (e.g. property tests), see
    /// [`ComposeQub::with_draft_id`].
    ///
    /// # Panics
    ///
    /// Panics if the platform random number generator fails. Interactive
    /// entry points should use [`Self::try_new`] when that platform failure
    /// must be reported rather than terminating the current task.
    #[must_use]
    // Retained for API compatibility; production entry points use `try_new`.
    #[allow(clippy::expect_used)]
    pub fn new(content_type: u8) -> Self {
        Self::try_new(content_type).expect("platform RNG failed")
    }

    /// Tries to create a fresh draft without panicking when the platform CSPRNG
    /// is unavailable.
    ///
    /// Interactive and server entry points should prefer this constructor so a
    /// broken Web Crypto/OS RNG becomes an ordinary recoverable error rather
    /// than terminating a WASM component or MCP request. [`Self::new`] remains
    /// as the convenient infallible API for callers whose environment contract
    /// guarantees randomness.
    ///
    /// # Errors
    ///
    /// Returns the platform [`getrandom::Error`] when 16 random draft-id bytes
    /// cannot be generated.
    pub fn try_new(content_type: u8) -> Result<Self, getrandom::Error> {
        let mut draft_id = [0_u8; 16];
        getrandom::fill(&mut draft_id)?;
        Ok(Self::with_draft_id(draft_id, content_type))
    }

    /// Pure constructor that accepts an explicit `draft_id`.
    ///
    /// Identical to [`ComposeQub::new`] except the caller supplies the
    /// draft identifier bytes — no platform RNG is invoked. All other
    /// fields are initialised to the same defaults as [`new`](Self::new).
    /// Use this for deterministic property testing and reproducible seal
    /// pipelines. For production use, prefer [`new`](Self::new) which
    /// generates a cryptographically random draft id.
    #[must_use]
    pub const fn with_draft_id(draft_id: [u8; 16], content_type: u8) -> Self {
        Self {
            draft_id,
            created_at: 0,
            unlock_at: None,
            visibility: VISIBILITY_PUBLIC,
            content_type,
            plaintext: Vec::new(),
            sender_label: None,
            title: None,
            reply_to: None,
            outcome_at: None,
            status: DraftStatus::Composing,
        }
    }

    /// Returns the locally-generated draft identifier.
    #[must_use]
    pub const fn draft_id(&self) -> &[u8; 16] {
        &self.draft_id
    }

    /// Returns the creation timestamp (Unix seconds UTC).
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Returns the target unlock timestamp (Unix seconds UTC), if set.
    #[must_use]
    pub const fn unlock_at(&self) -> Option<i64> {
        self.unlock_at
    }

    /// Returns the visibility byte for this draft.
    #[must_use]
    pub const fn visibility(&self) -> u8 {
        self.visibility
    }

    /// Returns the content type byte for this draft.
    #[must_use]
    pub const fn content_type(&self) -> u8 {
        self.content_type
    }

    /// Returns the raw plaintext body bytes.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Returns the optional decorative sender label.
    #[must_use]
    pub fn sender_label(&self) -> Option<&str> {
        self.sender_label.as_deref()
    }

    /// Returns the optional plaintext title surfaced on the viewer
    /// countdown. `None` means the viewer falls back to a localised
    /// intent label.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns the optional `reply_to` reference — the `qub_id` of the
    /// qub this draft is a reply to. `None` for top-level (non-reply)
    /// drafts. Lives inside the encrypted envelope only and never
    /// leaks to the pre-reveal sealed surface.
    #[must_use]
    pub const fn reply_to(&self) -> Option<&[u8; 32]> {
        self.reply_to.as_ref()
    }

    /// Returns the optional outcome time (Unix seconds UTC) — when
    /// reality will render judgment on this qub. `None` for the
    /// verdict-irrelevant intents (letter, secret) or when the
    /// creator declined to commit to an outcome date for a
    /// verdict-bearing intent. See
    /// `tasks/verdict-uplift-plan.md` §3.1.
    #[must_use]
    pub const fn outcome_at(&self) -> Option<i64> {
        self.outcome_at
    }

    /// Returns the current lifecycle status of this draft.
    #[must_use]
    pub const fn status(&self) -> DraftStatus {
        self.status
    }

    /// Replaces the plaintext body.
    pub fn set_plaintext(&mut self, text: Vec<u8>) {
        self.plaintext = text;
    }

    /// Sets the target unlock timestamp (Unix seconds UTC).
    pub const fn set_unlock_at(&mut self, ts: i64) {
        self.unlock_at = Some(ts);
    }

    /// Sets the delivery visibility byte.
    ///
    /// Validation runs at [`ComposeQub::validate`] time so persisted drafts
    /// can be restored before their fields are checked as a complete unit.
    pub const fn set_visibility(&mut self, visibility: u8) {
        self.visibility = visibility;
    }

    /// Sets or clears the decorative sender label.
    pub fn set_sender_label(&mut self, label: Option<String>) {
        self.sender_label = label;
    }

    /// Sets or clears the plaintext title surfaced on the viewer
    /// countdown. Validation (length, control characters) runs at
    /// [`ComposeQub::validate`] time, not here, so callers can stage
    /// a partially-edited title in compose state.
    pub fn set_title(&mut self, title: Option<String>) {
        self.title = title;
    }

    /// Sets or clears the `reply_to` reference. Pass `Some(qub_id)`
    /// to mark this draft as a reply to the qub with that id; pass
    /// `None` to detach the reply relationship (e.g. when the user
    /// changes their mind from inside the compose screen).
    pub const fn set_reply_to(&mut self, reply_to: Option<[u8; 32]>) {
        self.reply_to = reply_to;
    }

    /// Sets the optional outcome time (Unix seconds UTC). Pass `None`
    /// to clear an existing outcome. Validation (positivity,
    /// outcome >= unlock) runs at [`ComposeQub::validate`] time, not
    /// here, so the compose UI can stage a partially-edited outcome
    /// without rejection.
    pub const fn set_outcome_at(&mut self, outcome_at: Option<i64>) {
        self.outcome_at = outcome_at;
    }

    /// Moves this draft to `status`, enforcing the [`DraftStatus`]
    /// lifecycle (`Composing → Sealed → Uploaded`, with `Failed` and
    /// retries; `Uploaded` is terminal). Replaces the former
    /// unconditional `set_status` so an illegal move — e.g. reviving an
    /// `Uploaded` draft, or skipping straight to `Uploaded` — is
    /// refused rather than silently applied (SEC-11).
    ///
    /// # Errors
    ///
    /// Returns [`QubError::InvalidDraftTransition`] when the move is not
    /// legal for the current status.
    pub fn transition_status(&mut self, status: DraftStatus) -> Result<(), QubError> {
        if !self.status.can_transition_to(status) {
            return Err(QubError::InvalidDraftTransition {
                from: self.status,
                to: status,
            });
        }
        self.status = status;
        Ok(())
    }

    /// Sets the creation timestamp. Typically called at seal time.
    pub const fn set_created_at(&mut self, ts: i64) {
        self.created_at = ts;
    }

    /// Reconstructs a `ComposeQub` from individually stored fields.
    ///
    /// Unlike [`ComposeQub::new`], this does **not** generate a random
    /// `draft_id` — it uses the one supplied by the caller. Intended for
    /// restoring drafts from persistence (`IndexedDB`) where the original
    /// `draft_id` must be preserved.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn restore(
        draft_id: [u8; 16],
        created_at: i64,
        unlock_at: Option<i64>,
        visibility: u8,
        content_type: u8,
        plaintext: Vec<u8>,
        sender_label: Option<String>,
        title: Option<String>,
        reply_to: Option<[u8; 32]>,
        outcome_at: Option<i64>,
        status: DraftStatus,
    ) -> Self {
        Self {
            draft_id,
            created_at,
            unlock_at,
            visibility,
            content_type,
            plaintext,
            sender_label,
            title,
            reply_to,
            outcome_at,
            status,
        }
    }

    /// Validates that the draft is structurally complete and eligible for
    /// sealing, using the **free-tier** body-size ceiling.
    ///
    /// Shorthand for [`ComposeQub::validate_for_tier`] with
    /// `is_paid = false` — the conservative default for callers that do
    /// not know the user's payment tier. See that method for the full
    /// list of checks.
    ///
    /// # Errors
    ///
    /// Returns the first [`QubError`] encountered.
    ///
    /// # Examples
    ///
    /// ```
    /// use qub_core::types::{ComposeQub, QubError, CONTENT_TYPE_TEXT};
    ///
    /// // Empty body → EmptyBody.
    /// let draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    /// assert!(matches!(draft.validate(), Err(QubError::EmptyBody)));
    ///
    /// // Missing unlock_at → MissingUnlockTime.
    /// let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    /// draft.set_plaintext(b"hi".to_vec());
    /// assert!(matches!(draft.validate(), Err(QubError::MissingUnlockTime)));
    ///
    /// // Unknown content type → UnsupportedContentType.
    /// let mut draft = ComposeQub::new(0x99);
    /// draft.set_plaintext(b"hi".to_vec());
    /// draft.set_unlock_at(1_736_294_400);
    /// assert!(matches!(
    ///     draft.validate(),
    ///     Err(QubError::UnsupportedContentType(0x99))
    /// ));
    /// ```
    pub fn validate(&self) -> Result<(), QubError> {
        self.validate_for_tier(false)
    }

    /// Validates that the draft is structurally complete and eligible for
    /// sealing, using the body-size ceiling for the given payment tier.
    ///
    /// This performs only the type-level checks that do not depend on
    /// external state (the current clock, the selected drand chain). In
    /// particular it verifies:
    ///
    /// * The plaintext body is non-empty.
    /// * `unlock_at` has been set.
    /// * `visibility` is a known registry value.
    /// * `content_type` is a known, supported value (MVP: only text).
    /// * The body does not exceed the maximum for its content type and
    ///   the given tier (see [`max_body_size`]). The Worker performs the
    ///   authoritative tier-aware check at upload time; pass
    ///   `is_paid = false` when the tier is unknown so drafts that would
    ///   fail for a free user are caught early.
    /// * The optional title passes [`validate_title`].
    /// * The optional sender label passes [`validate_sender_label`].
    /// * The optional `outcome_at` is positive and not before `unlock_at`.
    ///
    /// # Errors
    ///
    /// Returns the first [`QubError`] encountered.
    ///
    /// # Examples
    ///
    /// ```
    /// use qub_core::types::{ComposeQub, QubError, CONTENT_TYPE_TEXT};
    ///
    /// // A 50 KB text body seals on the paid tier but not the free tier.
    /// let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    /// draft.set_plaintext(vec![b'A'; 51_200]);
    /// draft.set_unlock_at(1_736_294_400);
    /// assert!(matches!(
    ///     draft.validate_for_tier(false),
    ///     Err(QubError::BodyTooLarge { .. })
    /// ));
    /// assert!(draft.validate_for_tier(true).is_ok());
    /// ```
    pub fn validate_for_tier(&self, is_paid: bool) -> Result<(), QubError> {
        if self.plaintext.is_empty() {
            return Err(QubError::EmptyBody);
        }
        let unlock_at = self.unlock_at.ok_or(QubError::MissingUnlockTime)?;
        if !is_known_visibility(self.visibility) {
            return Err(QubError::UnknownVisibility(self.visibility));
        }
        if !matches!(
            self.content_type,
            CONTENT_TYPE_TEXT | CONTENT_TYPE_PACT | CONTENT_TYPE_VERDICT,
        ) {
            return Err(QubError::UnsupportedContentType(self.content_type));
        }
        let max = max_body_size(self.content_type, is_paid)
            .ok_or(QubError::UnsupportedContentType(self.content_type))?;
        if self.plaintext.len() > max {
            return Err(QubError::BodyTooLarge {
                actual: self.plaintext.len(),
                max,
            });
        }
        if let Some(title) = self.title.as_deref() {
            validate_title(title)?;
        }
        if let Some(label) = self.sender_label.as_deref() {
            validate_sender_label(label)?;
        }
        if let Some(outcome_at) = self.outcome_at {
            validate_outcome_at(outcome_at, unlock_at)?;
        }
        Ok(())
    }
}

/// Validate the temporal relationship shared by compose drafts and both wire
/// surfaces. Keeping this in one place prevents a direct builder call from
/// creating an envelope or sealed artifact that the compose path would reject.
const fn validate_outcome_at(outcome_at: i64, unlock_at: i64) -> Result<(), QubError> {
    if outcome_at <= 0 {
        return Err(QubError::InvalidOutcomeAt);
    }
    if outcome_at < unlock_at {
        return Err(QubError::OutcomeBeforeUnlock {
            outcome_at,
            unlock_at,
        });
    }
    Ok(())
}

/// Validate a plaintext title: non-empty, bounded length, no control
/// characters, no hostile codepoints.
///
/// This is the canonical title-validation function shared by
/// [`ComposeQub::validate`] and the CBOR layer when reading back a
/// [`SealedQub`]. Length is counted over the **NFC-normalised** form —
/// the CBOR encoder NFC-normalises before writing and the decoder
/// re-counts the NFC form, so counting the raw input here would let a
/// title that NFC-*expands* (composition-exclusion characters such as
/// Devanagari U+0958..=U+095F) pass validation, seal, and then be
/// rejected by every decoder forever. Validation must count what the
/// wire will carry.
///
/// # Errors
///
/// - [`QubError::TitleEmpty`] if the title is the empty string — the
///   canonical encoding of an absent title is field omission.
/// - [`QubError::TitleTooLong`] if the NFC form exceeds
///   [`MAX_TITLE_CODEPOINTS`] code points.
/// - [`QubError::TitleHasControlChar`] if any code point is a C0 or DEL
///   control character (U+0000..=U+001F or U+007F).
/// - [`QubError::TitleHostileCodepoint`] if any code point is in the
///   hostile class the encoder and decoder reject
///   ([`crate::handle::is_hostile_text_codepoint`]).
pub fn validate_title(title: &str) -> Result<(), QubError> {
    if title.is_empty() {
        return Err(QubError::TitleEmpty);
    }
    if title.chars().any(|c| (c as u32) < 0x20 || c == '\u{007F}') {
        return Err(QubError::TitleHasControlChar);
    }
    if crate::handle::contains_hostile_text_codepoint(title) {
        return Err(QubError::TitleHostileCodepoint);
    }
    let len = title.nfc().count();
    if len > MAX_TITLE_CODEPOINTS {
        return Err(QubError::TitleTooLong {
            actual: len,
            max: MAX_TITLE_CODEPOINTS,
        });
    }
    Ok(())
}

/// Validate a decorative sender label: bounded length and no hostile
/// codepoints.
///
/// This is the canonical sender-label validation shared by
/// [`ComposeQub::validate_for_tier`] and the CBOR layer when reading a
/// [`QubEnvelope`] back off the wire. The hostile-codepoint class
/// ([`crate::handle::is_hostile_text_codepoint`]) covers C0/C1 controls,
/// DEL, bidi overrides / isolates, zero-width space, BOM, and the tag
/// block — the same set the encoder and the Worker edge reject — so a
/// tampered artifact cannot smuggle spoofing codepoints past decode. The
/// length bound ([`MAX_SENDER_LABEL_CODEPOINTS`]) mirrors the Worker's
/// 80-code-point ceiling.
///
/// # Errors
///
/// - [`QubError::SenderLabelHostileCodepoint`] if any code point is in
///   the hostile class.
/// - [`QubError::SenderLabelTooLong`] if `label.chars().count() >
///   MAX_SENDER_LABEL_CODEPOINTS`.
pub fn validate_sender_label(label: &str) -> Result<(), QubError> {
    if crate::handle::contains_hostile_text_codepoint(label) {
        return Err(QubError::SenderLabelHostileCodepoint);
    }
    // Count the NFC form — the encoder writes NFC and the decoder
    // re-counts it, so a label that NFC-expands past the cap would
    // otherwise seal (tlock-encrypted, invisible until reveal) and then
    // fail to parse at the reveal moment. See `validate_title`.
    let len = label.nfc().count();
    if len > MAX_SENDER_LABEL_CODEPOINTS {
        return Err(QubError::SenderLabelTooLong {
            actual: len,
            max: MAX_SENDER_LABEL_CODEPOINTS,
        });
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// QubEnvelope
// -----------------------------------------------------------------------------

/// The decrypted protocol payload — the structure that proves content
/// integrity after decryption.
///
/// A `QubEnvelope` is serialised using the canonical CBOR profile (task A3)
/// and the resulting bytes are then tlock-encrypted to produce the
/// `tlock_ciphertext` field of a [`SealedQub`]. Instances are typically
/// constructed via [`QubEnvelopeBuilder`].
///
/// # Examples
///
/// Build a minimal envelope using the derivations from [`crate::hash`]:
///
/// ```
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
///
/// let envelope = QubEnvelopeBuilder::new()
///     .version(PROTOCOL_VERSION_1)
///     .qub_id(qub_id)
///     .content_type(CONTENT_TYPE_TEXT)
///     .created_at(1_735_689_600)
///     .unlock_at(1_736_294_400)
///     .body(body.clone())
///     .body_hash(body_hash)
///     .build()
///     .expect("all required fields set");
///
/// assert_eq!(envelope.version(), PROTOCOL_VERSION_1);
/// assert_eq!(envelope.qub_id(), &qub_id);
/// assert_eq!(envelope.body(), body.as_slice());
/// assert_eq!(envelope.body_hash(), &body_hash);
/// assert_eq!(envelope.sender_label(), None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QubEnvelope {
    version: u8,
    qub_id: [u8; 32],
    content_type: u8,
    created_at: i64,
    unlock_at: i64,
    /// Optional outcome time (Unix seconds UTC) — when reality will
    /// render judgment on this qub. Mirrors [`SealedQub::outcome_at`]
    /// (both surfaces carry the same value; the unlock pipeline
    /// cross-checks them after decryption — see [`crate::unlock`]).
    /// Folded into the `qub_id` preimage so a gateway cannot
    /// swap the value without invalidating the qub identity. See
    /// `tasks/verdict-uplift-plan.md` §3.1.
    outcome_at: Option<i64>,
    sender_label: Option<String>,
    /// `qub_id` of the parent qub when this envelope is a reply.
    /// `None` for top-level qubs. Lives inside the encrypted
    /// envelope so the reply relationship is only revealed after
    /// unlock; the pre-reveal [`SealedQub`] surface has no
    /// `reply_to` field, keeping the relationship tlock-gated.
    /// Deliberately excluded from the `qub_id` hash preimage (see
    /// `crate::hash::derive_envelope_hashes`).
    reply_to: Option<[u8; 32]>,
    body: Vec<u8>,
    body_hash: [u8; 32],
    sig_alg: u8,
    author_signature: Option<Vec<u8>>,
    author_pubkey: Option<Vec<u8>>,
    cosigner_pubkey: Option<Vec<u8>>,
    cosigner_signature: Option<Vec<u8>>,
}

impl QubEnvelope {
    /// Returns the protocol version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the derived qub identifier (see PROTOCOL.md §4.1).
    #[must_use]
    pub const fn qub_id(&self) -> &[u8; 32] {
        &self.qub_id
    }

    /// Returns the content type byte.
    #[must_use]
    pub const fn content_type(&self) -> u8 {
        self.content_type
    }

    /// Returns the creation timestamp (Unix seconds UTC).
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Returns the target unlock timestamp (Unix seconds UTC).
    #[must_use]
    pub const fn unlock_at(&self) -> i64 {
        self.unlock_at
    }

    /// Returns the optional outcome time (Unix seconds UTC). Mirrors
    /// [`SealedQub::outcome_at`]; the unlock pipeline cross-checks that
    /// both surfaces carry the same value after decryption. `None` for
    /// verdict-irrelevant qubs and verdict-bearing qubs whose creator
    /// declined to commit to an outcome date.
    #[must_use]
    pub const fn outcome_at(&self) -> Option<i64> {
        self.outcome_at
    }

    /// Returns the optional decorative sender label.
    #[must_use]
    pub fn sender_label(&self) -> Option<&str> {
        self.sender_label.as_deref()
    }

    /// Returns the optional `reply_to` reference — the `qub_id` of
    /// the parent qub when this envelope is a reply in a chain.
    /// `None` for top-level qubs. Post-reveal viewers use this to
    /// render the reply-to context banner.
    #[must_use]
    pub const fn reply_to(&self) -> Option<&[u8; 32]> {
        self.reply_to.as_ref()
    }

    /// Returns the raw body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the SHA3-256 hash of the body.
    #[must_use]
    pub const fn body_hash(&self) -> &[u8; 32] {
        &self.body_hash
    }

    /// Returns the signature algorithm byte (see PROTOCOL.md §9.2).
    #[must_use]
    pub const fn sig_alg(&self) -> u8 {
        self.sig_alg
    }

    /// Returns the optional author signature (Phase 2+).
    #[must_use]
    pub fn author_signature(&self) -> Option<&[u8]> {
        self.author_signature.as_deref()
    }

    /// Returns the optional author public key (Phase 2+).
    #[must_use]
    pub fn author_pubkey(&self) -> Option<&[u8]> {
        self.author_pubkey.as_deref()
    }

    /// Returns the optional cosigner public key (Phase 2 — pact).
    #[must_use]
    pub fn cosigner_pubkey(&self) -> Option<&[u8]> {
        self.cosigner_pubkey.as_deref()
    }

    /// Returns the optional cosigner signature (Phase 2 — pact).
    #[must_use]
    pub fn cosigner_signature(&self) -> Option<&[u8]> {
        self.cosigner_signature.as_deref()
    }
}

/// Fluent builder for [`QubEnvelope`].
///
/// Required fields: `version`, `qub_id`, `content_type`, `created_at`,
/// `unlock_at`, `body`, `body_hash`. Optional fields: `sender_label`,
/// `sig_alg` (defaults to [`SIG_ALG_NONE`]), `author_signature`,
/// `author_pubkey`, `cosigner_pubkey`, `cosigner_signature`.
#[derive(Debug, Default, Clone)]
pub struct QubEnvelopeBuilder {
    version: Option<u8>,
    qub_id: Option<[u8; 32]>,
    content_type: Option<u8>,
    created_at: Option<i64>,
    unlock_at: Option<i64>,
    outcome_at: Option<i64>,
    sender_label: Option<String>,
    reply_to: Option<[u8; 32]>,
    body: Option<Vec<u8>>,
    body_hash: Option<[u8; 32]>,
    sig_alg: Option<u8>,
    author_signature: Option<Vec<u8>>,
    author_pubkey: Option<Vec<u8>>,
    cosigner_pubkey: Option<Vec<u8>>,
    cosigner_signature: Option<Vec<u8>>,
}

impl QubEnvelopeBuilder {
    /// Creates a new, empty builder with no fields set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the protocol version byte (required; must be
    /// [`PROTOCOL_VERSION_1`]).
    #[must_use]
    pub const fn version(mut self, version: u8) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the derived qub identifier (required).
    #[must_use]
    pub const fn qub_id(mut self, qub_id: [u8; 32]) -> Self {
        self.qub_id = Some(qub_id);
        self
    }

    /// Sets the content type byte (required).
    #[must_use]
    pub const fn content_type(mut self, content_type: u8) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Sets the creation timestamp (required).
    #[must_use]
    pub const fn created_at(mut self, created_at: i64) -> Self {
        self.created_at = Some(created_at);
        self
    }

    /// Sets the unlock timestamp (required).
    #[must_use]
    pub const fn unlock_at(mut self, unlock_at: i64) -> Self {
        self.unlock_at = Some(unlock_at);
        self
    }

    /// Sets the optional outcome time (Unix seconds UTC). Pass
    /// `None` (or omit the call) to leave the qub without an
    /// outcome date. See `tasks/verdict-uplift-plan.md` §3.1.
    #[must_use]
    pub const fn outcome_at(mut self, outcome_at: Option<i64>) -> Self {
        self.outcome_at = outcome_at;
        self
    }

    /// Sets the optional decorative sender label.
    #[must_use]
    pub fn sender_label(mut self, label: Option<String>) -> Self {
        self.sender_label = label;
        self
    }

    /// Sets the optional `reply_to` parent `qub_id` (Sprint B.1 —
    /// reply chains). `None` clears the reply relationship.
    #[must_use]
    pub const fn reply_to(mut self, reply_to: Option<[u8; 32]>) -> Self {
        self.reply_to = reply_to;
        self
    }

    /// Sets the body bytes (required; must be non-empty).
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Sets the SHA3-256 body hash (required).
    #[must_use]
    pub const fn body_hash(mut self, body_hash: [u8; 32]) -> Self {
        self.body_hash = Some(body_hash);
        self
    }

    /// Sets the signature algorithm byte. Defaults to [`SIG_ALG_NONE`].
    #[must_use]
    pub const fn sig_alg(mut self, sig_alg: u8) -> Self {
        self.sig_alg = Some(sig_alg);
        self
    }

    /// Sets the optional author signature bytes (Phase 2+).
    #[must_use]
    pub fn author_signature(mut self, sig: Option<Vec<u8>>) -> Self {
        self.author_signature = sig;
        self
    }

    /// Sets the optional author public key bytes (Phase 2+).
    #[must_use]
    pub fn author_pubkey(mut self, pk: Option<Vec<u8>>) -> Self {
        self.author_pubkey = pk;
        self
    }

    /// Sets the optional cosigner public key bytes (Phase 2 — pact).
    #[must_use]
    pub fn cosigner_pubkey(mut self, pk: Option<Vec<u8>>) -> Self {
        self.cosigner_pubkey = pk;
        self
    }

    /// Sets the optional cosigner signature bytes (Phase 2 — pact).
    #[must_use]
    pub fn cosigner_signature(mut self, sig: Option<Vec<u8>>) -> Self {
        self.cosigner_signature = sig;
        self
    }

    /// Consumes the builder and produces a validated [`QubEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`QubError::MissingBuilderField`] if any required field has
    /// not been set, [`QubError::UnsupportedVersion`] if `version` is not
    /// [`PROTOCOL_VERSION_1`], or [`QubError::EmptyBody`] if the body is
    /// empty.
    ///
    /// # Examples
    ///
    /// Error path — missing required fields:
    ///
    /// ```
    /// use qub_core::types::{QubEnvelopeBuilder, QubError};
    ///
    /// let err = QubEnvelopeBuilder::new().build().unwrap_err();
    /// assert!(matches!(err, QubError::MissingBuilderField("version")));
    /// ```
    pub fn build(self) -> Result<QubEnvelope, QubError> {
        let version = self
            .version
            .ok_or(QubError::MissingBuilderField("version"))?;
        if version != PROTOCOL_VERSION_1 {
            return Err(QubError::UnsupportedVersion(version));
        }
        let qub_id = self.qub_id.ok_or(QubError::MissingBuilderField("qub_id"))?;
        let content_type = self
            .content_type
            .ok_or(QubError::MissingBuilderField("content_type"))?;
        let created_at = self
            .created_at
            .ok_or(QubError::MissingBuilderField("created_at"))?;
        let unlock_at = self
            .unlock_at
            .ok_or(QubError::MissingBuilderField("unlock_at"))?;
        if let Some(outcome_at) = self.outcome_at {
            validate_outcome_at(outcome_at, unlock_at)?;
        }
        let body = self.body.ok_or(QubError::MissingBuilderField("body"))?;
        if body.is_empty() {
            return Err(QubError::EmptyBody);
        }
        let body_hash = self
            .body_hash
            .ok_or(QubError::MissingBuilderField("body_hash"))?;

        Ok(QubEnvelope {
            version,
            qub_id,
            content_type,
            created_at,
            unlock_at,
            outcome_at: self.outcome_at,
            sender_label: self.sender_label,
            reply_to: self.reply_to,
            body,
            body_hash,
            sig_alg: self.sig_alg.unwrap_or(SIG_ALG_NONE),
            author_signature: self.author_signature,
            author_pubkey: self.author_pubkey,
            cosigner_pubkey: self.cosigner_pubkey,
            cosigner_signature: self.cosigner_signature,
        })
    }
}

// -----------------------------------------------------------------------------
// SealedQub
// -----------------------------------------------------------------------------

/// The canonical on-wire artifact uploaded to Arweave.
///
/// Serialised using canonical CBOR (task A3). Contains the tlock-encrypted
/// bytes of a [`QubEnvelope`] together with the metadata needed to locate
/// the drand round required for decryption.
///
/// # Examples
///
/// ```
/// use qub_core::types::{
///     SealedQubBuilder, PROTOCOL_VERSION_1, VISIBILITY_PUBLIC,
/// };
///
/// let sealed = SealedQubBuilder::new()
///     .version(PROTOCOL_VERSION_1)
///     .qub_id([0x11; 32])
///     .visibility(VISIBILITY_PUBLIC)
///     .unlock_at(1_736_294_400)
///     .drand_chain_id("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into())
///     .drand_round(4_675_285)
///     .tlock_ciphertext(vec![0xAA; 64])
///     .build()
///     .expect("all required fields set");
///
/// assert_eq!(sealed.version(), PROTOCOL_VERSION_1);
/// assert_eq!(sealed.visibility(), VISIBILITY_PUBLIC);
/// assert_eq!(sealed.drand_round(), 4_675_285);
/// assert_eq!(sealed.recipient_pubkey(), None); // omitted → None
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedQub {
    version: u8,
    qub_id: [u8; 32],
    visibility: u8,
    unlock_at: i64,
    /// Optional outcome time (Unix seconds UTC) — surfaced on the
    /// viewer countdown before reveal so the verdict-watch CTA
    /// (verdict-uplift-plan §5.1) has a date to render. Bound to
    /// `qub_id` via the preimage (see [`crate::hash::qub_id`]) so a
    /// gateway cannot swap it without invalidating the qub
    /// identity. Mirrors [`QubEnvelope::outcome_at`]; the unlock
    /// pipeline cross-checks both surfaces carry the same value
    /// after decryption. `None` for verdict-irrelevant qubs.
    outcome_at: Option<i64>,
    drand_chain_id: String,
    drand_round: u64,
    /// Optional drand chain-migration version. `None` (the wire-absent
    /// state) and `0` both mean quicknet — the only chain qub uses
    /// today. The field exists so a future chain migration ("quicknet
    /// deprecated") has a versioned wire story without a breaking
    /// format change (W3 / UP-B4). NOT part of the `qub_id` preimage
    /// (like `drand_chain_id`), so adding it never changes an existing
    /// qub's identity. See
    /// [`crate::tlock::DRAND_CHAIN_VERSION_QUICKNET`].
    drand_chain_version: Option<u8>,
    tlock_ciphertext: Vec<u8>,
    recipient_pubkey: Option<[u8; 32]>,
    /// Optional plaintext title shown on the viewer countdown before
    /// reveal. Bound to `qub_id` via `title_hash` (see
    /// [`crate::hash::title_hash`] and [`crate::hash::qub_id`]) so a
    /// gateway cannot swap it without invalidating the qub identity.
    /// `None` when the creator did not set a title; viewers fall back
    /// to a localised intent label.
    title: Option<String>,
}

impl SealedQub {
    /// Returns the protocol version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the qub identifier.
    #[must_use]
    pub const fn qub_id(&self) -> &[u8; 32] {
        &self.qub_id
    }

    /// Returns the visibility byte.
    #[must_use]
    pub const fn visibility(&self) -> u8 {
        self.visibility
    }

    /// Returns the target unlock timestamp (Unix seconds UTC).
    #[must_use]
    pub const fn unlock_at(&self) -> i64 {
        self.unlock_at
    }

    /// Returns the optional outcome time (Unix seconds UTC). Mirrors
    /// [`QubEnvelope::outcome_at`]; both surfaces carry the same
    /// value and the unlock pipeline cross-checks them after
    /// decryption. `None` when the creator did not set an outcome.
    #[must_use]
    pub const fn outcome_at(&self) -> Option<i64> {
        self.outcome_at
    }

    /// Returns the drand chain identifier (hex string).
    #[must_use]
    pub fn drand_chain_id(&self) -> &str {
        &self.drand_chain_id
    }

    /// Returns the target drand round number.
    #[must_use]
    pub const fn drand_round(&self) -> u64 {
        self.drand_round
    }

    /// Returns the optional drand chain-migration version. `None` / `0`
    /// ⇒ quicknet (the only chain today). See the struct field for
    /// rationale (W3 / UP-B4).
    #[must_use]
    pub const fn drand_chain_version(&self) -> Option<u8> {
        self.drand_chain_version
    }

    /// Returns the tlock-encrypted envelope bytes.
    #[must_use]
    pub fn tlock_ciphertext(&self) -> &[u8] {
        &self.tlock_ciphertext
    }

    /// Returns the optional recipient public key (Phase 2+ private qubs).
    #[must_use]
    pub const fn recipient_pubkey(&self) -> Option<&[u8; 32]> {
        self.recipient_pubkey.as_ref()
    }

    /// Returns the optional plaintext title surfaced on the viewer
    /// countdown. `None` means the viewer falls back to a localised
    /// intent label.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
}

/// Fluent builder for [`SealedQub`].
///
/// Required fields: `version`, `qub_id`, `visibility`, `unlock_at`,
/// `drand_chain_id`, `drand_round`, `tlock_ciphertext`. Optional fields:
/// `recipient_pubkey`, `title`.
#[derive(Debug, Default, Clone)]
pub struct SealedQubBuilder {
    version: Option<u8>,
    qub_id: Option<[u8; 32]>,
    visibility: Option<u8>,
    unlock_at: Option<i64>,
    outcome_at: Option<i64>,
    drand_chain_id: Option<String>,
    drand_round: Option<u64>,
    drand_chain_version: Option<u8>,
    tlock_ciphertext: Option<Vec<u8>>,
    recipient_pubkey: Option<[u8; 32]>,
    title: Option<String>,
}

impl SealedQubBuilder {
    /// Creates a new, empty builder with no fields set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the protocol version byte (required; must be
    /// [`PROTOCOL_VERSION_1`]).
    #[must_use]
    pub const fn version(mut self, version: u8) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the qub identifier (required).
    #[must_use]
    pub const fn qub_id(mut self, qub_id: [u8; 32]) -> Self {
        self.qub_id = Some(qub_id);
        self
    }

    /// Sets the visibility byte (required).
    #[must_use]
    pub const fn visibility(mut self, visibility: u8) -> Self {
        self.visibility = Some(visibility);
        self
    }

    /// Sets the target unlock timestamp (required).
    #[must_use]
    pub const fn unlock_at(mut self, unlock_at: i64) -> Self {
        self.unlock_at = Some(unlock_at);
        self
    }

    /// Sets the optional outcome time (Unix seconds UTC). Pass
    /// `None` (or omit the call) to seal without an outcome date.
    /// See `tasks/verdict-uplift-plan.md` §3.1.
    #[must_use]
    pub const fn outcome_at(mut self, outcome_at: Option<i64>) -> Self {
        self.outcome_at = outcome_at;
        self
    }

    /// Sets the drand chain identifier (required; must be non-empty).
    #[must_use]
    pub fn drand_chain_id(mut self, chain_id: String) -> Self {
        self.drand_chain_id = Some(chain_id);
        self
    }

    /// Sets the target drand round number (required).
    #[must_use]
    pub const fn drand_round(mut self, round: u64) -> Self {
        self.drand_round = Some(round);
        self
    }

    /// Sets the optional drand chain-migration version. Pass `None`
    /// (or omit the call) for quicknet — the wire-absent default
    /// (W3 / UP-B4).
    #[must_use]
    pub const fn drand_chain_version(mut self, version: Option<u8>) -> Self {
        self.drand_chain_version = version;
        self
    }

    /// Sets the tlock-encrypted envelope bytes (required; must be
    /// non-empty).
    #[must_use]
    pub fn tlock_ciphertext(mut self, ciphertext: Vec<u8>) -> Self {
        self.tlock_ciphertext = Some(ciphertext);
        self
    }

    /// Sets the optional recipient public key (Phase 2+ private qubs).
    #[must_use]
    pub const fn recipient_pubkey(mut self, pk: Option<[u8; 32]>) -> Self {
        self.recipient_pubkey = pk;
        self
    }

    /// Sets the optional plaintext title. The title is bounded by
    /// [`MAX_TITLE_CODEPOINTS`] and rejected if it contains control
    /// characters; both checks run at [`SealedQubBuilder::build`] time.
    #[must_use]
    pub fn title(mut self, title: Option<String>) -> Self {
        self.title = title;
        self
    }

    /// Consumes the builder and produces a validated [`SealedQub`].
    ///
    /// # Errors
    ///
    /// Returns [`QubError::MissingBuilderField`] if any required field has
    /// not been set, [`QubError::UnsupportedVersion`] if `version` is not
    /// [`PROTOCOL_VERSION_1`], [`QubError::EmptyCiphertext`] if
    /// `tlock_ciphertext` is empty, [`QubError::EmptyChainId`] if
    /// `drand_chain_id` is empty, or [`QubError::UnknownVisibility`] if
    /// `visibility` is not a known registry value.
    ///
    /// # Examples
    ///
    /// Empty ciphertext is rejected:
    ///
    /// ```
    /// use qub_core::types::{
    ///     SealedQubBuilder, QubError, PROTOCOL_VERSION_1, VISIBILITY_PUBLIC,
    /// };
    ///
    /// let err = SealedQubBuilder::new()
    ///     .version(PROTOCOL_VERSION_1)
    ///     .qub_id([0; 32])
    ///     .visibility(VISIBILITY_PUBLIC)
    ///     .unlock_at(1)
    ///     .drand_chain_id("chain".into())
    ///     .drand_round(1)
    ///     .tlock_ciphertext(Vec::new())
    ///     .build()
    ///     .unwrap_err();
    /// assert!(matches!(err, QubError::EmptyCiphertext));
    /// ```
    pub fn build(self) -> Result<SealedQub, QubError> {
        let version = self
            .version
            .ok_or(QubError::MissingBuilderField("version"))?;
        if version != PROTOCOL_VERSION_1 {
            return Err(QubError::UnsupportedVersion(version));
        }
        let qub_id = self.qub_id.ok_or(QubError::MissingBuilderField("qub_id"))?;
        let visibility = self
            .visibility
            .ok_or(QubError::MissingBuilderField("visibility"))?;
        if !is_known_visibility(visibility) {
            return Err(QubError::UnknownVisibility(visibility));
        }
        let unlock_at = self
            .unlock_at
            .ok_or(QubError::MissingBuilderField("unlock_at"))?;
        if let Some(outcome_at) = self.outcome_at {
            validate_outcome_at(outcome_at, unlock_at)?;
        }
        let drand_chain_id = self
            .drand_chain_id
            .ok_or(QubError::MissingBuilderField("drand_chain_id"))?;
        if drand_chain_id.is_empty() {
            return Err(QubError::EmptyChainId);
        }
        let drand_round = self
            .drand_round
            .ok_or(QubError::MissingBuilderField("drand_round"))?;
        if drand_round == 0 {
            return Err(QubError::InvalidDrandRound);
        }
        let tlock_ciphertext = self
            .tlock_ciphertext
            .ok_or(QubError::MissingBuilderField("tlock_ciphertext"))?;
        if tlock_ciphertext.is_empty() {
            return Err(QubError::EmptyCiphertext);
        }
        if let Some(title) = self.title.as_deref() {
            validate_title(title)?;
        }

        Ok(SealedQub {
            version,
            qub_id,
            visibility,
            unlock_at,
            outcome_at: self.outcome_at,
            drand_chain_id,
            drand_round,
            drand_chain_version: self.drand_chain_version,
            tlock_ciphertext,
            recipient_pubkey: self.recipient_pubkey,
            title: self.title,
        })
    }
}

// -----------------------------------------------------------------------------
// RevealedQub
// -----------------------------------------------------------------------------

/// Viewer-side application state produced after a [`SealedQub`] has been
/// fetched, decrypted, and verified.
///
/// `RevealedQub` is **not** serialised; it is a convenience aggregate used
/// by the viewer UI to render a successfully-opened qub. It is constructed
/// programmatically by the viewer after verification, so a direct
/// constructor is provided instead of a builder.
///
/// # Examples
///
/// ```
/// use qub_core::types::{RevealedQub, CONTENT_TYPE_TEXT, VISIBILITY_PUBLIC};
///
/// let revealed = RevealedQub::new(
///     [0x22; 32],              // qub_id
///     "arweave-tx-123".into(), // arweave_tx_id
///     VISIBILITY_PUBLIC,
///     CONTENT_TYPE_TEXT,       // content_type
///     1_735_689_600,           // created_at
///     1_736_294_400,           // unlock_at
///     None,                    // outcome_at
///     "drand-chain-id".into(),
///     4_675_285,               // drand_round
///     Some("Alice".into()),    // sender_label
///     None,                    // title
///     None,                    // reply_to
///     b"Hello, future.".to_vec(),
///     [0xAB; 32],              // body_hash
///     true,                    // body_hash_verified
///     None,                    // author_signature
///     None,                    // author_pubkey
///     None,                    // signature_verified
///     None,                    // cosigner_pubkey
///     None,                    // cosigner_signature
///     None,                    // cosigner_verified
/// );
///
/// assert_eq!(revealed.qub_id(), &[0x22; 32]);
/// assert_eq!(revealed.content_type(), CONTENT_TYPE_TEXT);
/// assert_eq!(revealed.sender_label(), Some("Alice"));
/// assert_eq!(revealed.title(), None);
/// assert!(revealed.body_hash_verified());
/// assert_eq!(revealed.signature_verified(), None);
/// ```
#[derive(Debug, Clone)]
pub struct RevealedQub {
    qub_id: [u8; 32],
    arweave_tx_id: String,
    visibility: u8,
    content_type: u8,
    created_at: i64,
    unlock_at: i64,
    /// Outcome timestamp carried forward from [`SealedQub::outcome_at`] /
    /// [`QubEnvelope::outcome_at`] for verdict-bearing intents (verdict-
    /// uplift-plan §3.1). `None` for verdict-irrelevant intents
    /// (letter / secret) and for verdict-bearing qubs whose creator
    /// declined to commit to an outcome date. Surfaced by the reveal-
    /// page outcome block (plan §5.1).
    outcome_at: Option<i64>,
    drand_chain_id: String,
    drand_round: u64,
    sender_label: Option<String>,
    /// Plaintext title carried forward from [`SealedQub::title`]. `None`
    /// when the creator did not set a title.
    title: Option<String>,
    /// Parent `qub_id` when this reveal is a reply in a chain.
    /// `None` for top-level qubs. Lifted out of the decrypted envelope
    /// so the viewer can render reply-context UI (Sprint B.1).
    reply_to: Option<[u8; 32]>,
    body: Vec<u8>,
    body_hash: [u8; 32],
    body_hash_verified: bool,
    author_signature: Option<Vec<u8>>,
    author_pubkey: Option<Vec<u8>>,
    signature_verified: Option<bool>,
    cosigner_pubkey: Option<Vec<u8>>,
    cosigner_signature: Option<Vec<u8>>,
    cosigner_verified: Option<bool>,
}

impl RevealedQub {
    /// Constructs a `RevealedQub` from its component fields.
    ///
    /// This constructor performs no validation: callers are expected to be
    /// the verification logic in the viewer, which produces the
    /// `body_hash_verified` and `signature_verified` fields itself.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        qub_id: [u8; 32],
        arweave_tx_id: String,
        visibility: u8,
        content_type: u8,
        created_at: i64,
        unlock_at: i64,
        outcome_at: Option<i64>,
        drand_chain_id: String,
        drand_round: u64,
        sender_label: Option<String>,
        title: Option<String>,
        reply_to: Option<[u8; 32]>,
        body: Vec<u8>,
        body_hash: [u8; 32],
        body_hash_verified: bool,
        author_signature: Option<Vec<u8>>,
        author_pubkey: Option<Vec<u8>>,
        signature_verified: Option<bool>,
        cosigner_pubkey: Option<Vec<u8>>,
        cosigner_signature: Option<Vec<u8>>,
        cosigner_verified: Option<bool>,
    ) -> Self {
        Self {
            qub_id,
            arweave_tx_id,
            visibility,
            content_type,
            created_at,
            unlock_at,
            outcome_at,
            drand_chain_id,
            drand_round,
            sender_label,
            title,
            reply_to,
            body,
            body_hash,
            body_hash_verified,
            author_signature,
            author_pubkey,
            signature_verified,
            cosigner_pubkey,
            cosigner_signature,
            cosigner_verified,
        }
    }

    /// Returns the qub identifier.
    #[must_use]
    pub const fn qub_id(&self) -> &[u8; 32] {
        &self.qub_id
    }

    /// Returns the Arweave transaction identifier this qub was fetched from.
    #[must_use]
    pub fn arweave_tx_id(&self) -> &str {
        &self.arweave_tx_id
    }

    /// Returns the visibility byte.
    #[must_use]
    pub const fn visibility(&self) -> u8 {
        self.visibility
    }

    /// Returns the creation timestamp (Unix seconds UTC).
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Returns the outcome timestamp (Unix seconds UTC) for verdict-
    /// bearing qubs whose creator committed to one. `None` for
    /// verdict-irrelevant qubs and for verdict-bearing qubs whose
    /// creator declined to commit (verdict-uplift-plan §3.1).
    #[must_use]
    pub const fn outcome_at(&self) -> Option<i64> {
        self.outcome_at
    }

    /// Returns the unlock timestamp (Unix seconds UTC).
    #[must_use]
    pub const fn unlock_at(&self) -> i64 {
        self.unlock_at
    }

    /// Returns the drand chain identifier (hex string).
    #[must_use]
    pub fn drand_chain_id(&self) -> &str {
        &self.drand_chain_id
    }

    /// Returns the drand round number.
    #[must_use]
    pub const fn drand_round(&self) -> u64 {
        self.drand_round
    }

    /// Returns the optional decorative sender label.
    #[must_use]
    pub fn sender_label(&self) -> Option<&str> {
        self.sender_label.as_deref()
    }

    /// Returns the optional plaintext title carried forward from
    /// [`SealedQub::title`]. `None` when the creator did not set a
    /// title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns the optional `reply_to` parent `qub_id` when this qub
    /// is a reply in a chain. `None` for top-level qubs (Sprint B.1).
    #[must_use]
    pub const fn reply_to(&self) -> Option<&[u8; 32]> {
        self.reply_to.as_ref()
    }

    /// Returns the decrypted body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the SHA3-256 body hash from the envelope.
    #[must_use]
    pub const fn body_hash(&self) -> &[u8; 32] {
        &self.body_hash
    }

    /// Returns `true` if the viewer has verified that the decrypted body
    /// hashes to `body_hash`.
    #[must_use]
    pub const fn body_hash_verified(&self) -> bool {
        self.body_hash_verified
    }

    /// Returns the optional author signature from the envelope.
    #[must_use]
    pub fn author_signature(&self) -> Option<&[u8]> {
        self.author_signature.as_deref()
    }

    /// Returns the optional author public key from the envelope.
    #[must_use]
    pub fn author_pubkey(&self) -> Option<&[u8]> {
        self.author_pubkey.as_deref()
    }

    /// Returns the author-signature verification result: `None` if no
    /// signature was present, `Some(true)` if verified, `Some(false)` if
    /// verification failed.
    #[must_use]
    pub const fn signature_verified(&self) -> Option<bool> {
        self.signature_verified
    }

    /// Returns the content type byte.
    #[must_use]
    pub const fn content_type(&self) -> u8 {
        self.content_type
    }

    /// Returns the optional cosigner public key (Phase 2 — pact).
    #[must_use]
    pub fn cosigner_pubkey(&self) -> Option<&[u8]> {
        self.cosigner_pubkey.as_deref()
    }

    /// Returns the optional cosigner signature (Phase 2 — pact).
    #[must_use]
    pub fn cosigner_signature(&self) -> Option<&[u8]> {
        self.cosigner_signature.as_deref()
    }

    /// Returns the cosigner-signature verification result: `None` if no
    /// cosigner was present, `Some(true)` if verified, `Some(false)` if
    /// verification failed.
    #[must_use]
    pub const fn cosigner_verified(&self) -> Option<bool> {
        self.cosigner_verified
    }
}

// -----------------------------------------------------------------------------
// PubkeyFingerprint (derived display type, not a protocol wire type)
// -----------------------------------------------------------------------------

/// Derived fingerprint of an author public key, used for viewer-side
/// identity resolution and display fallback.
///
/// A `PubkeyFingerprint` is computed as `SHA3-256(author_pubkey_bytes)` —
/// the same hash function used throughout the rest of the protocol (see
/// `hash::body_hash`, `hash::qub_id`). The input is the raw serialised
/// public key as it appears in the `author_pubkey` field of
/// [`QubEnvelope`].
///
/// # Derived, not wire
///
/// This is a **display / resolution type**, not a protocol wire type. The
/// fingerprint is never serialised in a `SealedQub`, `QubEnvelope`, or any
/// other on-wire structure — it is always re-derived from `author_pubkey`
/// at the point of use. That is why this type intentionally does **not**
/// implement `serde::Serialize` / `serde::Deserialize`: if a future API
/// response needs to carry a fingerprint over the wire, that will be a
/// separate DTO defined alongside the API client, not this core type.
///
/// # Display format
///
/// The `Display` impl produces `qub:<first 4 bytes hex>…<last 4 bytes hex>`
/// — for example `qub:7f3a1b2c…9e8d7c6b`. The middle character is the
/// Unicode `HORIZONTAL ELLIPSIS` (U+2026, `…`), not three ASCII dots. This
/// short form is designed for inline viewer display when no richer
/// attestation (email, social handle) has been resolved. See
/// [`IDENTITY.md`](../../../../docs/IDENTITY.md) §2 for the full
/// specification.
///
/// # Examples
///
/// ```
/// use qub_core::types::PubkeyFingerprint;
///
/// let fp = PubkeyFingerprint::from_pubkey(b"example-author-pubkey");
/// let display = fp.to_string();
/// assert!(display.starts_with("qub:"));
/// assert!(display.contains('…'));
/// ```
///
/// Determinism — the same public key bytes always produce the same
/// fingerprint:
///
/// ```
/// use qub_core::types::PubkeyFingerprint;
///
/// let a = PubkeyFingerprint::from_pubkey(b"pk");
/// let b = PubkeyFingerprint::from_pubkey(b"pk");
/// assert_eq!(a, b);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PubkeyFingerprint([u8; 32]);

impl PubkeyFingerprint {
    /// Computes the fingerprint of a public key: `SHA3-256(pubkey_bytes)`.
    ///
    /// The input is the raw serialised public key bytes exactly as they
    /// appear in the `author_pubkey` field of [`QubEnvelope`]. For
    /// ML-DSA-65 this is 1,952 bytes; for Ed25519 this is 32 bytes. This
    /// function does not validate the length or shape of the input — any
    /// byte slice is accepted and hashed.
    ///
    /// # Examples
    ///
    /// ```
    /// use qub_core::types::PubkeyFingerprint;
    ///
    /// let fp = PubkeyFingerprint::from_pubkey(b"hello");
    /// assert_eq!(fp.as_bytes().len(), 32);
    /// ```
    #[must_use]
    pub fn from_pubkey(pubkey_bytes: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(pubkey_bytes);
        Self(hasher.finalize().into())
    }

    /// Returns the raw 32-byte fingerprint.
    ///
    /// Use this form when computing a KV lookup key or any other
    /// full-precision identifier. For human-readable UI display, use the
    /// [`std::fmt::Display`] impl instead.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for PubkeyFingerprint {
    /// Formats the fingerprint as `qub:<first 4 bytes hex>…<last 4 bytes hex>`.
    ///
    /// The middle character is the Unicode `HORIZONTAL ELLIPSIS`
    /// (U+2026, `…`). The hex encoding is lower-case.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "qub:{:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[28],
            self.0[29],
            self.0[30],
            self.0[31],
        )
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_compose() -> ComposeQub {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hello world".to_vec());
        c.set_unlock_at(1_800_000_000);
        c
    }

    /// Length must be counted on the NFC form the encoder writes.
    /// U+0958 (क़) is a composition exclusion: NFC *expands* it to
    /// U+0915 U+093C, so a raw count of 100 becomes an NFC count of
    /// 101 — accepting it would seal a title every decoder rejects.
    /// `reply_to` on both the compose and revealed sides, plus
    /// `cosigner_verified`, were `FnValue` survivors replaced with `None`
    /// / `Some(true)`. Nothing set a reply target and read it back, and
    /// nothing constructed a revealed qub whose cosigner check FAILED —
    /// so "cosigner verified" could have been hardcoded true.
    ///
    /// `QubEnvelope::version` and `SealedQub::version` are not asserted
    /// here: both are 1 and the mutant substitutes `1`, so no test can
    /// tell them apart. Equivalent mutants, not gaps.
    #[test]
    fn reply_to_and_cosigner_verified_read_back() {
        let mut compose = valid_compose();
        assert_eq!(compose.reply_to(), None);
        compose.set_reply_to(Some([0xAB; 32]));
        assert_eq!(compose.reply_to(), Some(&[0xAB; 32]));
        compose.set_reply_to(None);
        assert_eq!(compose.reply_to(), None);

        let body = b"revealed body".to_vec();
        let bh = crate::hash::body_hash(&body);
        let revealed = RevealedQub::new(
            [0xCD; 32],
            "tx".to_owned(),
            1,
            1,
            1_700_000_000,
            1_800_000_000,
            None,
            "chain".to_owned(),
            4_242,
            None,
            None,
            Some([0xEF; 32]),
            body,
            bh,
            true,
            None,
            None,
            None,
            None,
            None,
            Some(false),
        );
        assert_eq!(revealed.reply_to(), Some(&[0xEF; 32]));
        assert_eq!(revealed.cosigner_verified(), Some(false));
    }

    #[test]
    fn validate_title_counts_nfc_expansion() {
        let mut title = "\u{0958}".to_string();
        title.push_str(&"a".repeat(MAX_TITLE_CODEPOINTS - 1));
        assert_eq!(title.chars().count(), MAX_TITLE_CODEPOINTS);
        assert!(matches!(
            validate_title(&title),
            Err(QubError::TitleTooLong { actual, max })
                if actual == MAX_TITLE_CODEPOINTS + 1 && max == MAX_TITLE_CODEPOINTS
        ));
    }

    /// The canonical encoding of an absent title is field omission;
    /// `Some("")` must fail validation rather than seal an artifact the
    /// decoder rejects.
    #[test]
    fn validate_title_rejects_empty() {
        assert!(matches!(validate_title(""), Err(QubError::TitleEmpty)));
    }

    /// Bidi overrides in a title must fail with a typed error at
    /// compose time, mirroring the encoder-side rejection.
    #[test]
    fn validate_title_rejects_hostile_codepoint() {
        assert!(matches!(
            validate_title("evil\u{202E}title"),
            Err(QubError::TitleHostileCodepoint)
        ));
    }

    /// The control-character arm is a two-way `||` (C0 range, then DEL),
    /// and mutation flipped it to `&&` without a single test noticing.
    /// The reason is instructive: the hostile-codepoint check on the very
    /// next line catches the same input, so a test that asserts merely
    /// "some error" is satisfied either way. Asserting the EXACT variant
    /// is what makes this arm observable — the weaker assertion was
    /// indistinguishable from having no test at all.
    #[test]
    fn validate_title_rejects_control_chars_by_the_control_arm() {
        for c in ['\u{0001}', '\u{001F}', '\u{007F}'] {
            assert!(
                matches!(
                    validate_title(&format!("a{c}b")),
                    Err(QubError::TitleHasControlChar)
                ),
                "U+{:04X} must fail as a control char, not fall through to a later check",
                c as u32
            );
        }
    }

    /// The accepting half of the title-length boundary, for the same
    /// reason: every existing test fed an OVER-long title, under which
    /// `>` and `>=` are indistinguishable, so mutation flipped the
    /// comparison and the suite stayed green.
    #[test]
    fn validate_title_accepts_exactly_the_limit() {
        let title = "a".repeat(MAX_TITLE_CODEPOINTS);
        assert!(
            validate_title(&title).is_ok(),
            "a title of exactly MAX_TITLE_CODEPOINTS must be accepted"
        );
    }

    /// Sender labels share the NFC-counting rule; the failure would
    /// otherwise surface only at the reveal moment, after months of
    /// countdown.
    #[test]
    fn validate_sender_label_counts_nfc_expansion() {
        let mut label = "\u{0958}".to_string();
        label.push_str(&"a".repeat(MAX_SENDER_LABEL_CODEPOINTS - 1));
        assert_eq!(label.chars().count(), MAX_SENDER_LABEL_CODEPOINTS);
        assert!(matches!(
            validate_sender_label(&label),
            Err(QubError::SenderLabelTooLong { actual, max })
                if actual == MAX_SENDER_LABEL_CODEPOINTS + 1
                    && max == MAX_SENDER_LABEL_CODEPOINTS
        ));
    }

    #[test]
    fn draft_status_can_transition_to_matches_lifecycle() {
        use DraftStatus::{Composing, Failed, Sealed, Uploaded};
        // Legal forward path + failure + retry.
        assert!(Composing.can_transition_to(Sealed));
        assert!(Composing.can_transition_to(Failed));
        assert!(Sealed.can_transition_to(Uploaded));
        assert!(Sealed.can_transition_to(Failed));
        assert!(Failed.can_transition_to(Sealed));
        assert!(Failed.can_transition_to(Uploaded));
        // Same-state is idempotent.
        for s in [Composing, Sealed, Uploaded, Failed] {
            assert!(s.can_transition_to(s));
        }
        // Illegal: skipping Sealed, and any escape from terminal Uploaded.
        assert!(!Composing.can_transition_to(Uploaded));
        assert!(!Sealed.can_transition_to(Composing));
        assert!(!Uploaded.can_transition_to(Composing));
        assert!(!Uploaded.can_transition_to(Sealed));
        assert!(!Uploaded.can_transition_to(Failed));
    }

    #[test]
    fn transition_status_refuses_illegal_move_and_leaves_status_intact() {
        let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
        assert_eq!(draft.status(), DraftStatus::Composing);
        draft.transition_status(DraftStatus::Sealed).unwrap();
        assert_eq!(draft.status(), DraftStatus::Sealed);

        let err = draft.transition_status(DraftStatus::Composing).unwrap_err();
        assert!(matches!(err, QubError::InvalidDraftTransition { .. }));
        // A rejected transition must not mutate the draft.
        assert_eq!(draft.status(), DraftStatus::Sealed);
    }

    #[test]
    fn compose_new_generates_unique_draft_ids() {
        let a = ComposeQub::new(CONTENT_TYPE_TEXT);
        let b = ComposeQub::new(CONTENT_TYPE_TEXT);
        assert_ne!(a.draft_id(), b.draft_id());
    }

    #[test]
    fn compose_new_defaults() {
        let c = ComposeQub::new(CONTENT_TYPE_TEXT);
        assert_eq!(c.created_at(), 0);
        assert_eq!(c.unlock_at(), None);
        assert_eq!(c.visibility(), VISIBILITY_PUBLIC);
        assert_eq!(c.content_type(), CONTENT_TYPE_TEXT);
        assert!(c.plaintext().is_empty());
        assert_eq!(c.sender_label(), None);
        assert_eq!(c.status(), DraftStatus::Composing);
    }

    #[test]
    fn compose_validate_succeeds() {
        assert!(valid_compose().validate().is_ok());
    }

    #[test]
    fn compose_validate_empty_body() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_unlock_at(1_800_000_000);
        assert_eq!(c.validate(), Err(QubError::EmptyBody));
    }

    #[test]
    fn compose_validate_missing_unlock() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hi".to_vec());
        assert_eq!(c.validate(), Err(QubError::MissingUnlockTime));
    }

    #[test]
    fn compose_validate_unknown_content_type() {
        let mut c = ComposeQub::new(0x7F);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(1);
        assert_eq!(c.validate(), Err(QubError::UnsupportedContentType(0x7F)));
    }

    #[test]
    fn compose_validate_voice_not_supported_in_mvp() {
        let mut c = ComposeQub::new(CONTENT_TYPE_VOICE);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(1);
        assert_eq!(
            c.validate(),
            Err(QubError::UnsupportedContentType(CONTENT_TYPE_VOICE))
        );
    }

    #[test]
    fn compose_validate_body_too_large() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(vec![b'x'; 10_241]);
        c.set_unlock_at(1);
        assert_eq!(
            c.validate(),
            Err(QubError::BodyTooLarge {
                actual: 10_241,
                max: 10_240,
            })
        );
    }

    #[test]
    fn compose_setters_roundtrip() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"body".to_vec());
        c.set_unlock_at(42);
        c.set_sender_label(Some("alice".into()));
        c.transition_status(DraftStatus::Sealed).unwrap();
        c.set_created_at(100);
        assert_eq!(c.plaintext(), b"body");
        assert_eq!(c.unlock_at(), Some(42));
        assert_eq!(c.sender_label(), Some("alice"));
        assert_eq!(c.status(), DraftStatus::Sealed);
        assert_eq!(c.created_at(), 100);
    }

    // -------- outcome_at validation (verdict-uplift-plan §3.3) --------

    #[test]
    fn compose_outcome_at_default_is_none() {
        let c = ComposeQub::new(CONTENT_TYPE_TEXT);
        assert_eq!(c.outcome_at(), None);
    }

    #[test]
    fn compose_outcome_at_setter_roundtrips() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_outcome_at(Some(1_800_000_000));
        assert_eq!(c.outcome_at(), Some(1_800_000_000));
        c.set_outcome_at(None);
        assert_eq!(c.outcome_at(), None);
    }

    #[test]
    fn compose_validate_outcome_before_unlock_rejected() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(200);
        c.set_outcome_at(Some(100));
        assert_eq!(
            c.validate(),
            Err(QubError::OutcomeBeforeUnlock {
                outcome_at: 100,
                unlock_at: 200,
            }),
        );
    }

    #[test]
    fn compose_validate_outcome_equal_to_unlock_accepted() {
        // Skin-in-the-game mode per plan §4.2 — outcome IS reveal —
        // is permitted. Only strict precedence is rejected.
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(200);
        c.set_outcome_at(Some(200));
        assert!(c.validate().is_ok());
    }

    #[test]
    fn compose_validate_outcome_at_zero_rejected() {
        // 0 is the absent sentinel in the qub_id preimage; explicit
        // 0 must never reach the wire as "set".
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(100);
        c.set_outcome_at(Some(0));
        assert_eq!(c.validate(), Err(QubError::InvalidOutcomeAt));
    }

    #[test]
    fn compose_validate_outcome_at_negative_rejected() {
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(100);
        c.set_outcome_at(Some(-1));
        assert_eq!(c.validate(), Err(QubError::InvalidOutcomeAt));
    }

    #[test]
    fn compose_validate_outcome_at_absent_is_fine() {
        // The protocol leaves outcome_at optional; verdict-bearing
        // intents that decline to commit to a verdict date still
        // produce a valid ComposeQub. Intent-coupling lives at the
        // compose UI / Worker, not in this layer.
        let mut c = ComposeQub::new(CONTENT_TYPE_TEXT);
        c.set_plaintext(b"hi".to_vec());
        c.set_unlock_at(100);
        assert_eq!(c.outcome_at(), None);
        assert!(c.validate().is_ok());
    }

    fn builder_with_required() -> QubEnvelopeBuilder {
        QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([1u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(10)
            .unlock_at(20)
            .body(b"hello".to_vec())
            .body_hash([2u8; 32])
    }

    #[test]
    fn envelope_builder_happy_path() {
        let env = builder_with_required()
            .sender_label(Some("s".into()))
            .build()
            .unwrap();
        assert_eq!(env.version(), PROTOCOL_VERSION_1);
        assert_eq!(env.qub_id(), &[1u8; 32]);
        assert_eq!(env.content_type(), CONTENT_TYPE_TEXT);
        assert_eq!(env.created_at(), 10);
        assert_eq!(env.unlock_at(), 20);
        assert_eq!(env.sender_label(), Some("s"));
        assert_eq!(env.body(), b"hello");
        assert_eq!(env.body_hash(), &[2u8; 32]);
        assert_eq!(env.sig_alg(), SIG_ALG_NONE);
        assert_eq!(env.author_signature(), None);
        assert_eq!(env.author_pubkey(), None);
    }

    #[test]
    fn envelope_builder_missing_version() {
        let err = QubEnvelopeBuilder::new()
            .qub_id([0u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(0)
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("version"));
    }

    #[test]
    fn envelope_builder_missing_qub_id() {
        let err = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(0)
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("qub_id"));
    }

    #[test]
    fn envelope_builder_missing_content_type() {
        let err = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .created_at(0)
            .unlock_at(0)
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("content_type"));
    }

    #[test]
    fn envelope_builder_missing_created_at() {
        let err = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .unlock_at(0)
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("created_at"));
    }

    #[test]
    fn envelope_builder_missing_unlock_at() {
        let err = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .body(b"x".to_vec())
            .body_hash([0u8; 32])
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("unlock_at"));
    }

    #[test]
    fn envelope_builder_missing_body() {
        let err = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(0)
            .body_hash([0u8; 32])
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("body"));
    }

    #[test]
    fn envelope_builder_missing_body_hash() {
        let err = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0u8; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(0)
            .unlock_at(0)
            .body(b"x".to_vec())
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("body_hash"));
    }

    #[test]
    fn envelope_builder_empty_body_rejected() {
        let err = builder_with_required()
            .body(Vec::new())
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::EmptyBody);
    }

    #[test]
    fn envelope_builder_unsupported_version() {
        let err = builder_with_required().version(0x02).build().unwrap_err();
        assert_eq!(err, QubError::UnsupportedVersion(0x02));
    }

    #[test]
    fn envelope_builder_rejects_invalid_outcome_time() {
        assert_eq!(
            builder_with_required().outcome_at(Some(0)).build(),
            Err(QubError::InvalidOutcomeAt),
        );
        assert_eq!(
            builder_with_required().outcome_at(Some(19)).build(),
            Err(QubError::OutcomeBeforeUnlock {
                outcome_at: 19,
                unlock_at: 20,
            }),
        );
        assert!(builder_with_required().outcome_at(Some(20)).build().is_ok());
    }

    fn sealed_builder_with_required() -> SealedQubBuilder {
        SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([3u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(100)
            .drand_chain_id("abc".into())
            .drand_round(42)
            .tlock_ciphertext(vec![9, 9, 9])
    }

    #[test]
    fn sealed_builder_happy_path() {
        let s = sealed_builder_with_required().build().unwrap();
        assert_eq!(s.version(), PROTOCOL_VERSION_1);
        assert_eq!(s.qub_id(), &[3u8; 32]);
        assert_eq!(s.visibility(), VISIBILITY_PUBLIC);
        assert_eq!(s.unlock_at(), 100);
        assert_eq!(s.drand_chain_id(), "abc");
        assert_eq!(s.drand_round(), 42);
        assert_eq!(s.tlock_ciphertext(), &[9, 9, 9]);
        assert_eq!(s.recipient_pubkey(), None);
    }

    #[test]
    fn sealed_builder_empty_ciphertext() {
        let err = sealed_builder_with_required()
            .tlock_ciphertext(Vec::new())
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::EmptyCiphertext);
    }

    #[test]
    fn sealed_builder_empty_chain_id() {
        let err = sealed_builder_with_required()
            .drand_chain_id(String::new())
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::EmptyChainId);
    }

    #[test]
    fn sealed_builder_unknown_visibility() {
        let err = sealed_builder_with_required()
            .visibility(0x7F)
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::UnknownVisibility(0x7F));
    }

    #[test]
    fn sealed_builder_unsupported_version() {
        let err = sealed_builder_with_required()
            .version(0x02)
            .build()
            .unwrap_err();
        assert_eq!(err, QubError::UnsupportedVersion(0x02));
    }

    #[test]
    fn sealed_builder_rejects_invalid_outcome_time() {
        assert_eq!(
            sealed_builder_with_required().outcome_at(Some(-1)).build(),
            Err(QubError::InvalidOutcomeAt),
        );
        assert_eq!(
            sealed_builder_with_required().outcome_at(Some(99)).build(),
            Err(QubError::OutcomeBeforeUnlock {
                outcome_at: 99,
                unlock_at: 100,
            }),
        );
        assert!(
            sealed_builder_with_required()
                .outcome_at(Some(100))
                .build()
                .is_ok()
        );
    }

    #[test]
    fn sealed_builder_rejects_round_zero() {
        assert_eq!(
            sealed_builder_with_required().drand_round(0).build(),
            Err(QubError::InvalidDrandRound),
        );
    }

    #[test]
    fn sealed_builder_missing_fields() {
        let err = SealedQubBuilder::new().build().unwrap_err();
        assert_eq!(err, QubError::MissingBuilderField("version"));
    }

    #[test]
    fn max_body_size_text_free() {
        assert_eq!(max_body_size(CONTENT_TYPE_TEXT, false), Some(10_240));
    }

    #[test]
    fn max_body_size_text_paid() {
        assert_eq!(max_body_size(CONTENT_TYPE_TEXT, true), Some(51_200));
    }

    #[test]
    fn max_body_size_voice() {
        assert_eq!(max_body_size(CONTENT_TYPE_VOICE, false), Some(2_097_152));
        assert_eq!(max_body_size(CONTENT_TYPE_VOICE, true), Some(2_097_152));
    }

    #[test]
    fn max_body_size_unknown() {
        assert_eq!(max_body_size(CONTENT_TYPE_RESERVED_ZERO, false), None);
        assert_eq!(max_body_size(0xFF, true), None);
    }

    #[test]
    fn revealed_new_roundtrip() {
        let r = RevealedQub::new(
            [7u8; 32],
            "tx123".into(),
            VISIBILITY_PUBLIC,
            CONTENT_TYPE_TEXT,
            10,
            20,
            Some(50), // outcome_at
            "chain".into(),
            99,
            Some("bob".into()),
            Some("Q1 prediction".into()),
            Some([0x42; 32]), // reply_to
            b"hi".to_vec(),
            [8u8; 32],
            true,
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
            Some(true),
            Some(vec![7, 8, 9]),
            Some(vec![10, 11, 12]),
            Some(true),
        );
        assert_eq!(r.qub_id(), &[7u8; 32]);
        assert_eq!(r.arweave_tx_id(), "tx123");
        assert_eq!(r.visibility(), VISIBILITY_PUBLIC);
        assert_eq!(r.content_type(), CONTENT_TYPE_TEXT);
        assert_eq!(r.created_at(), 10);
        assert_eq!(r.unlock_at(), 20);
        assert_eq!(r.drand_chain_id(), "chain");
        assert_eq!(r.drand_round(), 99);
        assert_eq!(r.sender_label(), Some("bob"));
        assert_eq!(r.title(), Some("Q1 prediction"));
        assert_eq!(r.body(), b"hi");
        assert_eq!(r.body_hash(), &[8u8; 32]);
        assert!(r.body_hash_verified());
        assert_eq!(r.author_signature(), Some(&[1, 2, 3][..]));
        assert_eq!(r.author_pubkey(), Some(&[4, 5, 6][..]));
        assert_eq!(r.signature_verified(), Some(true));
        assert_eq!(r.cosigner_pubkey(), Some(&[7, 8, 9][..]));
        assert_eq!(r.cosigner_signature(), Some(&[10, 11, 12][..]));
        assert_eq!(r.cosigner_verified(), Some(true));
    }

    #[test]
    fn compose_qub_restore_round_trip() {
        let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
        draft.set_plaintext(b"hello".to_vec());
        draft.set_unlock_at(1_700_000_000);
        draft.set_sender_label(Some("Alice".into()));
        draft.set_created_at(1_600_000_000);
        draft.transition_status(DraftStatus::Sealed).unwrap();

        let restored = ComposeQub::restore(
            *draft.draft_id(),
            draft.created_at(),
            draft.unlock_at(),
            draft.visibility(),
            draft.content_type(),
            draft.plaintext().to_vec(),
            draft.sender_label().map(str::to_owned),
            draft.title().map(str::to_owned),
            draft.reply_to().copied(),
            draft.outcome_at(),
            draft.status(),
        );

        assert_eq!(restored.draft_id(), draft.draft_id());
        assert_eq!(restored.created_at(), draft.created_at());
        assert_eq!(restored.unlock_at(), draft.unlock_at());
        assert_eq!(restored.visibility(), draft.visibility());
        assert_eq!(restored.content_type(), draft.content_type());
        assert_eq!(restored.plaintext(), draft.plaintext());
        assert_eq!(restored.sender_label(), draft.sender_label());
        assert_eq!(restored.title(), draft.title());
        assert_eq!(restored.outcome_at(), draft.outcome_at());
        assert_eq!(restored.status(), draft.status());
    }

    #[test]
    fn qub_error_display_all_variants() {
        let variants: Vec<QubError> = vec![
            QubError::EmptyBody,
            QubError::MissingUnlockTime,
            QubError::UnsupportedContentType(0x99),
            QubError::BodyTooLarge {
                actual: 20_000,
                max: 10_240,
            },
            QubError::UnsupportedVersion(2),
            QubError::EmptyCiphertext,
            QubError::EmptyChainId,
            QubError::UnknownVisibility(0x42),
            QubError::MissingBuilderField("version"),
            QubError::InvalidPeriod,
            QubError::InvalidDrandRound,
            QubError::UnlockBeforeGenesis,
            QubError::UnknownSignatureAlgorithm(0x99),
            QubError::SigningFailed("test"),
            QubError::WrongSignatureLength {
                field: "public_key",
                expected: 1952,
                actual: 100,
            },
            QubError::CosignerFieldsMismatch,
            QubError::CosignerSameAsAuthor,
            QubError::InvalidOutcomeAt,
            QubError::OutcomeBeforeUnlock {
                outcome_at: 100,
                unlock_at: 200,
            },
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display should produce output for {v:?}");
        }
        assert_eq!(variants.len(), 19, "all QubError variants exercised");
    }

    #[test]
    fn draft_status_all_variants() {
        let statuses = [
            DraftStatus::Composing,
            DraftStatus::Sealed,
            DraftStatus::Uploaded,
            DraftStatus::Failed,
        ];
        for s in &statuses {
            // Verify Copy + Clone + PartialEq
            let cloned = *s;
            assert_eq!(&cloned, s);
        }
    }

    #[test]
    fn max_body_size_pact_returns_100kb() {
        assert_eq!(max_body_size(CONTENT_TYPE_PACT, false), Some(102_400));
        assert_eq!(max_body_size(CONTENT_TYPE_PACT, true), Some(102_400));
    }

    // -------- Mutation-resistance: non-default field values --------

    #[test]
    fn compose_visibility_private() {
        let draft = ComposeQub::restore(
            [0; 16],
            0,
            None,
            VISIBILITY_PRIVATE,
            CONTENT_TYPE_TEXT,
            Vec::new(),
            None,
            None,
            None,
            None,
            DraftStatus::Composing,
        );
        assert_eq!(draft.visibility(), VISIBILITY_PRIVATE);
        assert_ne!(draft.visibility(), VISIBILITY_PUBLIC);
    }

    #[test]
    fn compose_visibility_setter_and_validation() {
        let mut draft = valid_compose();
        draft.set_visibility(VISIBILITY_PRIVATE);
        assert_eq!(draft.visibility(), VISIBILITY_PRIVATE);
        assert!(draft.validate().is_ok());

        draft.set_visibility(0x7F);
        assert_eq!(draft.validate(), Err(QubError::UnknownVisibility(0x7F)));
    }

    #[test]
    fn compose_content_type_voice() {
        let draft = ComposeQub::restore(
            [0; 16],
            0,
            None,
            VISIBILITY_PUBLIC,
            CONTENT_TYPE_VOICE,
            Vec::new(),
            None,
            None,
            None,
            None,
            DraftStatus::Composing,
        );
        assert_eq!(draft.content_type(), CONTENT_TYPE_VOICE);
        assert_ne!(draft.content_type(), CONTENT_TYPE_TEXT);
    }

    #[test]
    fn sealed_visibility_private() {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x42; 32])
            .visibility(VISIBILITY_PRIVATE)
            .unlock_at(1_800_000_000)
            .drand_chain_id("a".repeat(64))
            .drand_round(1)
            .tlock_ciphertext(vec![0xAA])
            .build()
            .unwrap();
        assert_eq!(sealed.visibility(), VISIBILITY_PRIVATE);
        assert_ne!(sealed.visibility(), VISIBILITY_PUBLIC);
    }

    #[test]
    fn envelope_sig_alg_nonzero() {
        // sig_alg=1 is a plausible future value; verify the getter
        // returns it rather than a hardcoded 0.
        let env = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x42; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(1_700_000_000)
            .unlock_at(1_800_000_000)
            .body(b"test".to_vec())
            .body_hash([0x11; 32])
            .sig_alg(1)
            .build()
            .unwrap();
        assert_eq!(env.sig_alg(), 1);
        assert_ne!(env.sig_alg(), 0);
    }

    #[test]
    fn revealed_visibility_private_and_hash_unverified() {
        let r = RevealedQub::new(
            [0x42; 32],
            "tx".into(),
            VISIBILITY_PRIVATE,
            CONTENT_TYPE_TEXT,
            10,
            20,
            None, // outcome_at
            "chain".into(),
            99,
            None,
            None, // title
            None, // reply_to
            b"body".to_vec(),
            [0x11; 32],
            false, // body_hash NOT verified
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(r.visibility(), VISIBILITY_PRIVATE);
        assert_ne!(r.visibility(), VISIBILITY_PUBLIC);
        assert!(!r.body_hash_verified());
        assert_eq!(r.title(), None);
    }

    // ---------- PubkeyFingerprint ----------

    #[test]
    fn pubkey_fingerprint_is_deterministic() {
        let a = PubkeyFingerprint::from_pubkey(b"some-pubkey-bytes");
        let b = PubkeyFingerprint::from_pubkey(b"some-pubkey-bytes");
        assert_eq!(a, b);
        assert_eq!(a.as_bytes().len(), 32);
    }

    #[test]
    fn pubkey_fingerprint_varies_with_input() {
        let a = PubkeyFingerprint::from_pubkey(b"pubkey-alpha");
        let b = PubkeyFingerprint::from_pubkey(b"pubkey-beta");
        assert_ne!(a, b);
    }

    #[test]
    fn pubkey_fingerprint_matches_sha3_256() {
        // The fingerprint must be exactly SHA3-256 of the input bytes.
        // Cross-check against the `hash::body_hash` helper (which is
        // documented as SHA3-256 and covered by the §14.1 test vector).
        let pk = b"pubkey";
        let fp = PubkeyFingerprint::from_pubkey(pk);
        let expected = crate::hash::body_hash(pk);
        assert_eq!(fp.as_bytes(), &expected);
    }

    #[test]
    fn pubkey_fingerprint_display_format() {
        // Construct a fingerprint whose SHA3-256 output is known (use the
        // §14.1 test vector bytes directly by hashing the same input).
        let fp = PubkeyFingerprint::from_pubkey(b"Hello, future.");
        let s = fp.to_string();

        // Canonical prefix.
        assert!(s.starts_with("qub:"));
        // Unicode HORIZONTAL ELLIPSIS (U+2026), not three ASCII dots.
        assert!(s.contains('…'));
        assert!(!s.contains("..."));
        // Shape: "qub:" (4) + 8 hex + '…' (1 char) + 8 hex = 21 chars.
        assert_eq!(s.chars().count(), 21);

        // Concretely: §14.1 says body_hash("Hello, future.") =
        // 76ab8b3f843c6ed4f2d0fd75b9f457b4ad49dd4450f9c22723ae430e3af3211d
        // First 4 bytes [0..4]  = 76 ab 8b 3f → "76ab8b3f"
        // Last 4 bytes  [28..32] = 3a f3 21 1d → "3af3211d"
        assert_eq!(s, "qub:76ab8b3f…3af3211d");
    }

    #[test]
    fn pubkey_fingerprint_display_is_lower_case_hex() {
        let fp = PubkeyFingerprint::from_pubkey(&[0xFFu8; 16]);
        let s = fp.to_string();
        // No upper-case hex characters anywhere after the `qub:` prefix.
        let hex_part = s.trim_start_matches("qub:");
        assert!(
            hex_part
                .chars()
                .all(|c| !c.is_ascii_uppercase() || c == '…'),
            "fingerprint display must use lower-case hex: {s}"
        );
    }

    #[test]
    fn pubkey_fingerprint_as_bytes_returns_full_digest() {
        let fp = PubkeyFingerprint::from_pubkey(b"anything");
        let bytes = fp.as_bytes();
        assert_eq!(bytes.len(), 32);
        // Round-trip: constructing a new fingerprint from a different
        // input yields a different byte array.
        let other = PubkeyFingerprint::from_pubkey(b"something-else");
        assert_ne!(fp.as_bytes(), other.as_bytes());
    }

    #[test]
    fn pubkey_fingerprint_accepts_ml_dsa_65_sized_input() {
        // ML-DSA-65 public key is 1,952 bytes. Verify the constructor
        // accepts a realistic pubkey size without panicking or truncating.
        let pk = vec![0x5Au8; 1_952];
        let fp = PubkeyFingerprint::from_pubkey(&pk);
        assert_eq!(fp.as_bytes().len(), 32);
    }
}
