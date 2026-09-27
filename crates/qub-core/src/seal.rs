//! Seal protocol: validate, hash, encrypt, and produce a [`SealedQubCbor`].
//!
//! Implements PROTOCOL.md §7 steps 2–12. Steps 1 (compose) and 13–17
//! (UI confirmation, upload) are handled by the app layer.
//!
//! The public entry point is [`seal`], which takes a [`SealInput`] and
//! returns a [`SealOutput`]. The function is deterministic given the same
//! inputs and tlock provider, except for the tlock ciphertext itself which
//! contains randomness (see [`TimelockProvider::encrypt`]).
//!
//! # Example
//!
//! ```
//! use qub_core::seal::{seal, SealInput};
//! use qub_core::tlock::MockTimelockProvider;
//! use qub_core::types::{ComposeQub, CONTENT_TYPE_TEXT};
//!
//! let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
//! draft.set_plaintext(b"Hello, future.".to_vec());
//! draft.set_unlock_at(2_000_000_000);
//!
//! let tlock = MockTimelockProvider;
//! let out = seal(SealInput {
//!     draft: &draft,
//!     now: 1_800_000_000,
//!     chain_genesis_time: 1_595_431_050,
//!     chain_period_seconds: 30,
//!     chain_id: "example-chain".into(),
//!     tlock: &tlock,
//!     signing: None,
//! })
//! .unwrap();
//!
//! assert_eq!(out.qub_id.len(), 32);
//! assert!(out.drand_round > 0);
//! ```

use crate::cbor::CborError;
use crate::hash::{derive_envelope_hashes, unlock_round};
use crate::signing::{SIG_ALG_UNSIGNED, sign_envelope};
use crate::tlock::{TimelockError, TimelockProvider};
use crate::types::{
    ComposeQub, PROTOCOL_VERSION_1, QubEnvelopeBuilder, QubError, SealedQubBuilder,
};
use crate::wire::{QubEnvelopeCbor, SealedQubCbor};

/// Maximum horizon between `created_at` and `unlock_at`, in years
/// (PROTOCOL.md §4.3).
pub const MAX_UNLOCK_HORIZON_YEARS: u32 = 10;

/// Seconds in one year used for the horizon check. Uses 365 days; any
/// reasonable value works for the 10-year limit.
const SECONDS_PER_YEAR: i64 = 365 * 86_400;

/// Errors produced by the [`seal`] entry point.
///
/// Wraps the lower-level error types so callers can distinguish
/// validation, serialisation, and crypto failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SealError {
    /// Structural validation of the draft or envelope failed.
    #[error("validation failed: {0}")]
    Validation(#[from] QubError),

    /// Canonical CBOR serialisation failed.
    #[error("CBOR serialisation failed: {0}")]
    Cbor(#[from] CborError),

    /// Timelock encryption failed.
    #[error("timelock encryption failed: {0}")]
    Tlock(#[from] TimelockError),

    /// `unlock_at` is not strictly after the provided `now`.
    #[error("unlock time is not in the future")]
    UnlockNotInFuture,

    /// `unlock_at` exceeds the 10-year horizon from `created_at`.
    #[error("unlock time exceeds maximum horizon ({max_years} years)")]
    UnlockTooFarFuture {
        /// The configured maximum horizon, in years.
        max_years: u32,
    },
}

/// Optional authorship-signing material for [`seal`].
///
/// When `Some(SigningParams { .. })` is passed via
/// [`SealInput::signing`], the envelope is signed with ML-DSA-65
/// before CBOR serialisation — `sig_alg = 0x01`,
/// `author_signature` and `author_pubkey` are populated per
/// `PROTOCOL.md` §9. When `None`, the envelope is unsigned and
/// `sig_alg = 0x00` (MVP default).
#[derive(Clone, Copy)]
pub struct SigningParams<'a> {
    /// ML-DSA-65 secret key bytes ([`crate::signing::ML_DSA_65_SECRET_KEY_SIZE`]).
    pub secret_key: &'a [u8],
    /// ML-DSA-65 public key bytes ([`crate::signing::ML_DSA_65_PUBLIC_KEY_SIZE`]).
    pub public_key: &'a [u8],
}

/// Configuration for sealing a qub.
///
/// All fields are required except `signing`. `now` is passed in
/// explicitly so the function is deterministic and testable; the
/// caller is expected to supply the current Unix timestamp.
pub struct SealInput<'a> {
    /// The draft to seal.
    pub draft: &'a ComposeQub,

    /// Current Unix timestamp (seconds UTC).
    pub now: i64,

    /// drand chain genesis time (Unix seconds UTC).
    pub chain_genesis_time: i64,

    /// drand chain period, in seconds.
    pub chain_period_seconds: u64,

    /// drand chain identifier (hex string) placed in the [`crate::types::SealedQub`].
    pub chain_id: String,

    /// Timelock encryption provider (see [`TimelockProvider`]).
    pub tlock: &'a dyn TimelockProvider,

    /// Optional authorship-signing material. `None` produces an
    /// unsigned qub (MVP default); `Some(..)` signs the envelope
    /// with ML-DSA-65 per `PROTOCOL.md` §9.
    pub signing: Option<SigningParams<'a>>,
}

/// Result of a successful [`seal`] operation.
#[derive(Debug, Clone)]
pub struct SealOutput {
    /// The sealed qub in canonical CBOR wire format, ready for upload.
    pub sealed_cbor: SealedQubCbor,

    /// The derived qub identifier (see PROTOCOL.md §4.1).
    pub qub_id: [u8; 32],

    /// The computed drand round.
    pub drand_round: u64,
}

/// Seal a [`ComposeQub`]: validate, hash, encrypt, and produce a
/// [`SealedQubCbor`].
///
/// Implements PROTOCOL.md §7 steps 2–12. The `created_at` embedded in the
/// resulting envelope is always `input.now` — the seal function captures the
/// moment of sealing, not the moment the draft was first opened.
///
/// Uses the **free-tier** body-size ceiling; callers that know the user
/// is on the paid tier should use [`seal_with_tier`] instead, otherwise
/// paid-tier 50 KB text bodies can never seal through the library.
///
/// # Errors
///
/// - [`SealError::Validation`] for draft-level validation failures (empty
///   body, missing unlock time, unsupported content type, oversized body).
/// - [`SealError::UnlockNotInFuture`] if `unlock_at <= now`.
/// - [`SealError::UnlockTooFarFuture`] if `unlock_at > now + 10 years`.
/// - [`SealError::Cbor`] for canonical CBOR serialisation failures.
/// - [`SealError::Tlock`] for timelock encryption failures.
///
/// # Properties
///
/// - **Lossless roundtrip**: `unlock(seal(draft))` recovers all metadata
///   (body, `created_at`, `unlock_at`, `outcome_at`, `qub_id`,
///   `visibility`, `sender_label`).
/// - **Canonical output**: the sealed CBOR is already in canonical form —
///   re-serialising a parsed `SealOutput` produces byte-identical output.
/// - **`created_at` capture**: the envelope's `created_at` is always `input.now`,
///   not the draft's `created_at` field.
/// - **Deterministic** (modulo tlock ciphertext): given the same inputs and
///   `TimelockProvider`, all output fields except the ciphertext are identical.
pub fn seal(input: SealInput<'_>) -> Result<SealOutput, SealError> {
    seal_with_tier(input, false)
}

/// Seal a [`ComposeQub`] with an explicit payment tier.
///
/// Identical to [`seal`] except the body-size ceiling is selected by
/// `is_paid` (see [`crate::types::max_body_size`]): `false` applies the
/// free-tier limit (e.g. 10 KB for text), `true` the paid-tier limit
/// (50 KB for text). The Worker performs the authoritative tier check at
/// upload time; this parameter only stops the library from rejecting
/// bodies the user's tier legitimately allows.
///
/// # Errors
///
/// See [`seal`].
pub fn seal_with_tier(input: SealInput<'_>, is_paid: bool) -> Result<SealOutput, SealError> {
    let SealInput {
        draft,
        now,
        chain_genesis_time,
        chain_period_seconds,
        chain_id,
        tlock,
        signing,
    } = input;

    // Step 2a/b/e and body-size checks: delegate to
    // ComposeQub::validate_for_tier which covers empty body, missing
    // unlock_at, unsupported content type, and the tier-appropriate
    // body-size ceiling.
    draft.validate_for_tier(is_paid)?;

    // `validate()` guarantees unlock_at is set; unwrap is infallible.
    let unlock_at = draft.unlock_at().ok_or(QubError::MissingUnlockTime)?;

    // Step 2c: unlock_at strictly in the future.
    if unlock_at <= now {
        return Err(SealError::UnlockNotInFuture);
    }

    // Step 2d: unlock_at ≤ created_at + 10 years. `created_at` = `now`
    // per step 4, so the horizon is relative to `now`.
    let horizon = now.saturating_add(i64::from(MAX_UNLOCK_HORIZON_YEARS) * SECONDS_PER_YEAR);
    if unlock_at > horizon {
        return Err(SealError::UnlockTooFarFuture {
            max_years: MAX_UNLOCK_HORIZON_YEARS,
        });
    }

    // Step 4: created_at = now.
    let created_at = now;

    // Steps 8 & 9 (hoisted): compute the target drand round for
    // unlock_at. This is derived *before* the qub_id so it can be folded
    // into the qub_id preimage (C1) — binding the timelock round to the
    // committed identity, so a gateway cannot rebind the ciphertext to an
    // already-past round while leaving the displayed countdown intact.
    let drand_round = unlock_round(unlock_at, chain_genesis_time, chain_period_seconds)?;

    // Steps 3 & 5: compute body_hash and qub_id in one shot. The title
    // is folded into the qub_id preimage (PROTOCOL.md §4.1) so a gateway
    // cannot swap the plaintext title displayed on the countdown without
    // invalidating the qub identity; `drand_round` is folded in for the
    // same reason (C1).
    let (body_hash, qub_id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        draft.content_type(),
        created_at,
        unlock_at,
        draft.outcome_at(),
        drand_round,
        draft.plaintext(),
        draft.title(),
    );

    // Step 6: construct the QubEnvelope. If the caller supplied
    // `signing` material, compute the signature now (using the
    // already-derived qub_id + body_hash) and splice `sig_alg`,
    // `author_signature`, and `author_pubkey` onto the builder
    // before `build()`. This runs before CBOR serialisation so the
    // canonical wire bytes include the signature — `PROTOCOL.md` §9
    // specifies that signing happens before tlock encryption.
    let (sig_alg, author_signature, author_pubkey) = match signing {
        Some(params) => {
            let (alg, sig, pk) = sign_envelope(
                PROTOCOL_VERSION_1,
                &qub_id,
                &body_hash,
                unlock_at,
                draft.sender_label(),
                draft.reply_to(),
                params.secret_key,
                params.public_key,
            )?;
            (alg, Some(sig), Some(pk))
        },
        None => (SIG_ALG_UNSIGNED, None, None),
    };

    // The optional outcome_at rides on BOTH wire surfaces (envelope +
    // sealed, below) — it participates in the qub_id preimage above, so
    // dropping it from either surface would make the identity
    // unreconstructable from the artifact's own fields.
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .content_type(draft.content_type())
        .created_at(created_at)
        .unlock_at(unlock_at)
        .outcome_at(draft.outcome_at())
        .sender_label(draft.sender_label().map(str::to_owned))
        .reply_to(draft.reply_to().copied())
        .body(draft.plaintext().to_vec())
        .body_hash(body_hash)
        .sig_alg(sig_alg)
        .author_signature(author_signature)
        .author_pubkey(author_pubkey)
        .build()?;

    // Step 7: serialise envelope to canonical CBOR.
    let envelope_cbor = QubEnvelopeCbor::from_qub_envelope(&envelope)?;

    // Step 10: tlock-encrypt the envelope CBOR bytes for the target round
    // (`drand_round` was computed above so it could bind into the qub_id).
    let tlock_ciphertext = tlock.encrypt(envelope_cbor.as_bytes(), drand_round)?;

    // Step 11: construct the SealedQub with matching qub_id / unlock_at.
    // The plaintext title is carried on the SealedQub (visible pre-reveal)
    // and bound to qub_id via title_hash above (PROTOCOL.md §4.1).
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .visibility(draft.visibility())
        .unlock_at(unlock_at)
        .outcome_at(draft.outcome_at())
        .drand_chain_id(chain_id)
        .drand_round(drand_round)
        .tlock_ciphertext(tlock_ciphertext)
        .title(draft.title().map(str::to_owned))
        .build()?;

    // Step 12: serialise SealedQub to canonical CBOR.
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed)?;

    Ok(SealOutput {
        sealed_cbor,
        qub_id,
        drand_round,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{body_hash as sha3_body_hash, qub_id as derive_qub_id, title_hash};
    use crate::tlock::MockTimelockProvider;
    use crate::types::{CONTENT_TYPE_TEXT, ComposeQub};

    const GENESIS: i64 = 1_595_431_050;
    const PERIOD: u64 = 30;
    const CHAIN_ID: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

    fn sample_draft(plaintext: &[u8], unlock_at: i64) -> ComposeQub {
        let mut d = ComposeQub::new(CONTENT_TYPE_TEXT);
        d.set_plaintext(plaintext.to_vec());
        d.set_unlock_at(unlock_at);
        d.set_sender_label(Some("Alice".into()));
        d
    }

    fn seal_input<'a>(
        draft: &'a ComposeQub,
        now: i64,
        tlock: &'a MockTimelockProvider,
    ) -> SealInput<'a> {
        SealInput {
            draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.to_string(),
            tlock,
            signing: None,
        }
    }

    #[test]
    fn seal_happy_path_mock() {
        let now = 1_700_000_000;
        let unlock_at = now + 86_400;
        let draft = sample_draft(b"Hello, future.", unlock_at);
        let tlock = MockTimelockProvider;
        let out = seal(seal_input(&draft, now, &tlock)).expect("seal ok");
        assert_eq!(out.qub_id.len(), 32);
        assert!(out.drand_round > 0);
        // Parseable result.
        let sealed = out.sealed_cbor.parse().expect("parses");
        assert_eq!(sealed.qub_id(), &out.qub_id);
        assert_eq!(sealed.unlock_at(), unlock_at);
        assert_eq!(sealed.drand_round(), out.drand_round);
        assert_eq!(sealed.drand_chain_id(), CHAIN_ID);
    }

    #[cfg(feature = "tlock-drand")]
    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn seal_happy_path_real_drand() {
        use crate::tlock::DrandTimelockProvider;
        let now = 1_700_000_000;
        let unlock_at = now + 86_400;
        let draft = sample_draft(b"payload for real tlock", unlock_at);
        let tlock = DrandTimelockProvider::quicknet();
        let out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: 1_692_803_367,
            chain_period_seconds: 3,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        })
        .expect("seal ok");
        let sealed = out.sealed_cbor.parse().expect("parses");
        assert_eq!(sealed.qub_id(), &out.qub_id);
        assert!(!sealed.tlock_ciphertext().is_empty());
    }

    #[test]
    fn seal_empty_body_rejected() {
        let mut d = ComposeQub::new(CONTENT_TYPE_TEXT);
        d.set_unlock_at(2_000_000_000);
        let tlock = MockTimelockProvider;
        let err = seal(seal_input(&d, 1_700_000_000, &tlock)).unwrap_err();
        assert!(matches!(err, SealError::Validation(QubError::EmptyBody)));
    }

    #[test]
    fn seal_unlock_not_in_future_rejected() {
        let now = 1_700_000_000;
        // unlock_at == now is not strictly in the future.
        let draft = sample_draft(b"x", now);
        let tlock = MockTimelockProvider;
        let err = seal(seal_input(&draft, now, &tlock)).unwrap_err();
        assert!(matches!(err, SealError::UnlockNotInFuture));

        // unlock_at < now.
        let draft = sample_draft(b"x", now - 1);
        let err = seal(seal_input(&draft, now, &tlock)).unwrap_err();
        assert!(matches!(err, SealError::UnlockNotInFuture));
    }

    #[test]
    fn seal_unlock_too_far_future_rejected() {
        let now = 1_700_000_000;
        // 10 years + 1 second.
        let unlock_at = now + 10 * SECONDS_PER_YEAR + 1;
        let draft = sample_draft(b"x", unlock_at);
        let tlock = MockTimelockProvider;
        let err = seal(seal_input(&draft, now, &tlock)).unwrap_err();
        assert!(matches!(
            err,
            SealError::UnlockTooFarFuture { max_years: 10 }
        ));
    }

    #[test]
    fn seal_unlock_exactly_at_horizon_accepted() {
        let now = 1_700_000_000;
        let unlock_at = now + 10 * SECONDS_PER_YEAR;
        let draft = sample_draft(b"x", unlock_at);
        let tlock = MockTimelockProvider;
        seal(seal_input(&draft, now, &tlock)).expect("exactly at horizon is allowed");
    }

    #[test]
    fn seal_unknown_content_type_rejected() {
        let mut d = ComposeQub::new(0xFF);
        d.set_plaintext(b"x".to_vec());
        d.set_unlock_at(2_000_000_000);
        let tlock = MockTimelockProvider;
        let err = seal(seal_input(&d, 1_700_000_000, &tlock)).unwrap_err();
        assert!(matches!(
            err,
            SealError::Validation(QubError::UnsupportedContentType(0xFF))
        ));
    }

    #[test]
    fn seal_qub_id_consistency() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"consistency check".to_vec();
        let draft = sample_draft(&body, unlock_at);
        let tlock = MockTimelockProvider;
        let out = seal(seal_input(&draft, now, &tlock)).expect("seal ok");

        // Re-derive the expected qub_id and match against output + parsed sealed.
        let bh = sha3_body_hash(&body);
        let round = unlock_round(unlock_at, GENESIS, PERIOD).unwrap();
        let expected_id = derive_qub_id(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            now,
            unlock_at,
            None,
            round,
            &bh,
            &title_hash(None),
        );
        assert_eq!(out.qub_id, expected_id);
        let sealed = out.sealed_cbor.parse().unwrap();
        assert_eq!(sealed.qub_id(), &expected_id);
    }

    #[test]
    fn seal_drand_round_matches_unlock_round() {
        let now = 1_700_000_000;
        let unlock_at = now + 7 * 86_400;
        let draft = sample_draft(b"round check", unlock_at);
        let tlock = MockTimelockProvider;
        let out = seal(seal_input(&draft, now, &tlock)).expect("seal ok");
        assert_eq!(
            out.drand_round,
            unlock_round(unlock_at, GENESIS, PERIOD).unwrap()
        );
    }

    #[test]
    fn seal_error_display_all_variants() {
        let variants: Vec<SealError> = vec![
            SealError::Validation(QubError::EmptyBody),
            SealError::Cbor(crate::cbor::CborError::NotAMap),
            SealError::Tlock(crate::tlock::TimelockError::EncryptionFailed("x".into())),
            SealError::UnlockNotInFuture,
            SealError::UnlockTooFarFuture { max_years: 10 },
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display should produce output for {v:?}");
        }
        assert_eq!(variants.len(), 5, "all SealError variants exercised");
    }

    #[test]
    fn seal_free_tier_rejects_paid_size_body() {
        // 50 KB text body: over the free-tier 10 KB ceiling.
        let now = 1_700_000_000;
        let body = vec![b'A'; 51_200];
        let draft = sample_draft(&body, now + 3600);
        let tlock = MockTimelockProvider;
        let err = seal(seal_input(&draft, now, &tlock)).unwrap_err();
        assert!(matches!(
            err,
            SealError::Validation(QubError::BodyTooLarge { .. })
        ));
        // Explicit free tier behaves identically to the default.
        let err = seal_with_tier(seal_input(&draft, now, &tlock), false).unwrap_err();
        assert!(matches!(
            err,
            SealError::Validation(QubError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn seal_paid_tier_accepts_50kb_text_body() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = vec![b'A'; 51_200];
        let draft = sample_draft(&body, unlock_at);
        let tlock = MockTimelockProvider;
        let out = seal_with_tier(seal_input(&draft, now, &tlock), true).expect("paid tier seals");
        let sealed = out.sealed_cbor.parse().expect("parses");
        assert_eq!(sealed.unlock_at(), unlock_at);
    }

    #[test]
    fn seal_paid_tier_still_rejects_over_paid_limit() {
        let now = 1_700_000_000;
        let body = vec![b'A'; 51_201];
        let draft = sample_draft(&body, now + 3600);
        let tlock = MockTimelockProvider;
        let err = seal_with_tier(seal_input(&draft, now, &tlock), true).unwrap_err();
        assert!(matches!(
            err,
            SealError::Validation(QubError::BodyTooLarge {
                actual: 51_201,
                max: 51_200,
            })
        ));
    }

    /// A2: the optional `outcome_at` must ride BOTH wire surfaces — it
    /// participates in the `qub_id` preimage, so dropping it from either
    /// surface makes the identity unreconstructable from the artifact.
    #[test]
    fn seal_carries_outcome_at_on_both_surfaces() {
        use crate::tlock::TimelockProvider;

        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let outcome_at = unlock_at + 86_400;
        let mut draft = sample_draft(b"verdict body", unlock_at);
        draft.set_outcome_at(Some(outcome_at));
        let tlock = MockTimelockProvider;
        let out = seal(seal_input(&draft, now, &tlock)).expect("seal ok");

        // Sealed surface.
        let sealed = out.sealed_cbor.parse().expect("parses");
        assert_eq!(sealed.outcome_at(), Some(outcome_at));

        // Envelope surface (mock-decrypt the ciphertext).
        let envelope_bytes = tlock.decrypt(sealed.tlock_ciphertext(), &[]).unwrap();
        let envelope = crate::cbor::deserialize_qub_envelope(&envelope_bytes).unwrap();
        assert_eq!(envelope.outcome_at(), Some(outcome_at));

        // The qub_id is reconstructable from artifact fields alone.
        let expected_id = derive_qub_id(
            PROTOCOL_VERSION_1,
            envelope.content_type(),
            envelope.created_at(),
            envelope.unlock_at(),
            envelope.outcome_at(),
            sealed.drand_round(),
            envelope.body_hash(),
            &title_hash(sealed.title()),
        );
        assert_eq!(sealed.qub_id(), &expected_id);
    }

    #[test]
    fn seal_uses_now_as_created_at_not_draft_field() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let mut draft = sample_draft(b"x", unlock_at);
        // Set a stale created_at on the draft — seal must ignore it.
        draft.set_created_at(1);
        let tlock = MockTimelockProvider;
        let out = seal(seal_input(&draft, now, &tlock)).unwrap();
        // Re-derive qub_id using `now` as created_at; must match.
        let bh = sha3_body_hash(b"x");
        let round = unlock_round(unlock_at, GENESIS, PERIOD).unwrap();
        let expected = derive_qub_id(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            now,
            unlock_at,
            None,
            round,
            &bh,
            &title_hash(None),
        );
        assert_eq!(out.qub_id, expected);
    }
}
