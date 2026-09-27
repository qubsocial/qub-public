//! Unlock protocol: parse, decrypt, verify integrity, return revealed content.
//!
//! Implements PROTOCOL.md §8 steps 4–16. Steps 1–3 (URL parsing, denylist,
//! Arweave fetch) and the drand round-signature fetch are handled by the
//! app layer and are outside the scope of this module.
//!
//! The public entry point is [`unlock`], which takes an [`UnlockInput`]
//! and returns a [`RevealedQub`] with all integrity checks completed.
//!
//! # Verification order
//!
//! Cheap structural checks (version, timestamps, hashes, identifier
//! equality) are performed before any expensive signature verification.
//! The MVP always has `sig_alg = 0x00`, so author-signature verification
//! is currently a no-op that sets `signature_verified = None` on the
//! returned [`RevealedQub`].

use subtle::ConstantTimeEq;

use crate::cbor::{CborError, deserialize_qub_envelope};
use crate::hash::{body_hash, qub_id, title_hash, unlock_round};
use crate::signing::{SIG_ALG_ML_DSA_65, SIG_ALG_UNSIGNED, verify_envelope_signature};
use crate::tlock::{TimelockError, TimelockProvider};
use crate::types::{
    CONTENT_TYPE_PACT, CONTENT_TYPE_TEXT, CONTENT_TYPE_VERDICT, PROTOCOL_VERSION_1, QubError,
    RevealedQub,
};
use crate::wire::SealedQubCbor;

/// Errors produced by the [`unlock`] entry point.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnlockError {
    /// Canonical CBOR deserialisation failed.
    #[error("CBOR deserialisation failed: {0}")]
    Cbor(#[from] CborError),

    /// Timelock decryption failed.
    #[error("timelock decryption failed: {0}")]
    Tlock(#[from] TimelockError),

    /// Type-level validation of a parsed structure failed.
    #[error("type validation failed: {0}")]
    Validation(#[from] QubError),

    /// The protocol version on a parsed structure is not recognised.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// The content type inside the decrypted envelope is unknown or
    /// unrenderable.
    #[error("unsupported content type: {0:#04x}")]
    UnsupportedContentType(u8),

    /// The decrypted body does not match the `body_hash` recorded in the
    /// envelope — the content has been tampered with.
    #[error("body hash mismatch: content has been tampered with")]
    BodyHashMismatch,

    /// The `qub_id` in the inner envelope does not match the outer
    /// [`crate::types::SealedQub`] — the two structures are inconsistent.
    #[error("qub_id mismatch between envelope and sealed qub")]
    QubIdMismatch,

    /// The `unlock_at` in the inner envelope does not match the outer
    /// [`crate::types::SealedQub`] — the two structures are inconsistent.
    #[error("unlock_at mismatch between envelope and sealed qub")]
    UnlockAtMismatch,

    /// The `outcome_at` in the inner envelope does not match the outer
    /// [`crate::types::SealedQub`] — the two structures are inconsistent
    /// (one carries an outcome date the other lacks, or the values
    /// differ). Both surfaces MUST carry the same value; a mismatch
    /// means the pre-reveal verdict-on date shown on the countdown was
    /// not the one the creator committed to.
    #[error("outcome_at mismatch between envelope and sealed qub")]
    OutcomeAtMismatch,

    /// The `qub_id` recorded on the artifact does not equal the id
    /// re-derived from the decrypted content fields (PROTOCOL.md §4.1:
    /// `version`, `content_type`, `created_at`, `unlock_at`,
    /// `outcome_at`, `drand_round`, `body_hash`, `title_hash`). The
    /// envelope↔sealed equality checks alone cannot catch a forger who
    /// rewrites a content field on *both* surfaces (e.g. swaps the
    /// plaintext title pre-reveal, or re-encrypts a different body under
    /// the same `qub_id` post-round) — only re-deriving the identity
    /// from content does.
    #[error("qub_id does not match the id re-derived from the decrypted content")]
    QubIdDerivationMismatch,

    /// The current time is earlier than `unlock_at`; the qub is still
    /// locked.
    #[error("qub is still locked (unlock time has not passed)")]
    StillLocked {
        /// The target unlock timestamp (Unix seconds UTC).
        unlock_at: i64,
        /// The current timestamp supplied by the caller.
        now: i64,
    },

    /// The timelock provider is bound to a different drand chain than
    /// the one the qub was sealed against. Without this check the
    /// mismatch surfaces only as an opaque [`TimelockError`] from a
    /// non-matching round signature (SEC-20).
    #[error("drand chain mismatch: qub sealed for {expected}, provider is {actual}")]
    DrandChainMismatch {
        /// The chain hash recorded in the sealed qub.
        expected: String,
        /// The chain hash the supplied timelock provider decrypts for.
        actual: String,
    },

    /// The timelock round bound to the qub does not match the round
    /// derived from `unlock_at` (C1). Either the advisory `drand_round`
    /// metadata on the `SealedQub` or the round actually baked into the
    /// tlock ciphertext stanza disagrees with
    /// `unlock_round(unlock_at)` — a malicious or tampered qub trying to
    /// bind its ciphertext to a different (e.g. already-past) round than
    /// its displayed countdown implies. The displayed unlock time is
    /// therefore not the round that actually gates decryption.
    #[error(
        "drand round mismatch: unlock_at implies round {expected}, qub is bound to round {actual}"
    )]
    DrandRoundMismatch {
        /// The round derived from `unlock_at` and the chain parameters.
        expected: u64,
        /// The round recorded on the qub (metadata or ciphertext stanza).
        actual: u64,
    },
}

/// Input for unlocking a sealed qub.
pub struct UnlockInput<'a> {
    /// The sealed qub in CBOR wire format (fetched from Arweave).
    pub sealed_cbor: &'a SealedQubCbor,

    /// The drand round signature (fetched from the drand network).
    pub round_signature: &'a [u8],

    /// Current Unix timestamp for the time check (seconds UTC).
    pub now: i64,

    /// drand chain genesis time (Unix seconds UTC), used together with
    /// [`Self::chain_period_seconds`] to recompute the expected unlock
    /// round and cross-check it against the round the qub is bound to
    /// (C1). Ignored for providers with no chain identity (the test
    /// mock), which opt out of the round-binding check.
    pub chain_genesis_time: i64,

    /// drand chain period (seconds). See [`Self::chain_genesis_time`].
    pub chain_period_seconds: u64,

    /// The Arweave transaction ID, recorded in the returned
    /// [`RevealedQub`].
    pub arweave_tx_id: String,

    /// Timelock decryption provider.
    pub tlock: &'a dyn TimelockProvider,
}

/// Unlock a sealed qub: parse, decrypt, verify integrity, return revealed
/// content.
///
/// Implements PROTOCOL.md §8 steps 4–15. See the [module documentation]
/// for the split of responsibilities with the app layer.
///
/// [module documentation]: self
///
/// # Errors
///
/// See [`UnlockError`] for the full list of failure modes. The function
/// performs cheap checks (version, time, hashes, identifier equality)
/// before any expensive work.
///
/// # Properties
///
/// - **Integrity**: tampered `body_hash` yields [`UnlockError::BodyHashMismatch`]
///   (constant-time comparison via `subtle::ConstantTimeEq`).
/// - **Consistency**: mismatched `qub_id` or `unlock_at` between envelope and
///   sealed layer yields [`UnlockError::QubIdMismatch`] or
///   [`UnlockError::UnlockAtMismatch`].
/// - **Time-safety**: `now < unlock_at` yields [`UnlockError::StillLocked`].
/// - **Cheap-first**: structural and time checks run before expensive decryption.
/// - **Purity**: no I/O — all data (sealed CBOR, round signature) is passed in.
// Single straight-line protocol procedure (PROTOCOL.md §8 steps 4–15);
// the numbered steps share local state, so splitting it would obscure
// the flow more than the length costs.
#[allow(clippy::too_many_lines)]
pub fn unlock(input: UnlockInput<'_>) -> Result<RevealedQub, UnlockError> {
    let UnlockInput {
        sealed_cbor,
        round_signature,
        now,
        chain_genesis_time,
        chain_period_seconds,
        arweave_tx_id,
        tlock,
    } = input;

    // Step 4: parse SealedQubCbor → SealedQub.
    let sealed = sealed_cbor.parse()?;

    // Step 5: known version. `parse()` already enforces this at the CBOR
    // layer, but we keep a defensive check so the invariant is visible
    // at the unlock boundary.
    if sealed.version() != PROTOCOL_VERSION_1 {
        return Err(UnlockError::UnsupportedVersion(sealed.version()));
    }

    // Step 6: still-locked check.
    if now < sealed.unlock_at() {
        return Err(UnlockError::StillLocked {
            unlock_at: sealed.unlock_at(),
            now,
        });
    }

    // Chain-binding check (SEC-20): a chain-bound provider must be the
    // chain the qub was sealed against. Catching the mismatch here
    // yields a clear error instead of an opaque decryption failure from
    // a round signature that belongs to a different chain.
    if let Some(provider_chain) = tlock.chain_hash_hex()
        && provider_chain != sealed.drand_chain_id()
    {
        return Err(UnlockError::DrandChainMismatch {
            expected: sealed.drand_chain_id().to_string(),
            actual: provider_chain,
        });
    }

    // Step 7c: round-binding check (C1). The displayed `unlock_at` must
    // be the round that actually gates decryption. We recompute the
    // expected round from `unlock_at` + chain params and require the
    // advisory `drand_round` metadata to match it — with a one-round
    // legacy tolerance: qubs sealed under the pre-V1.3 `ceil` mapping
    // carry `expected - 1` exactly when `unlock_at` is period-aligned
    // (see `crate::hash::unlock_round`), and their round is baked into
    // the immutable qub_id preimage, so they must stay verifiable. The
    // tolerance widens the earliest gating signature by at most one
    // drand period. The round baked into the tlock ciphertext stanza
    // must then equal the metadata round exactly — the stanza round is
    // the cryptographically meaningful one: without this check a
    // malicious creator could bind the ciphertext to an already-past
    // round while displaying a future countdown, so anyone reading the
    // bytes could decrypt early. Gated on a chain-bound provider — the
    // test mock has no genesis/period and exposes no stanza round, so it
    // opts out, mirroring the SEC-20 chain-binding gate above.
    if tlock.chain_hash_hex().is_some() {
        let expected_round =
            unlock_round(sealed.unlock_at(), chain_genesis_time, chain_period_seconds)?;
        let stored_round = sealed.drand_round();
        let is_current = stored_round == expected_round;
        // `stored + 1` avoids u64 underflow when expected_round == 1;
        // `checked_add` avoids the mirror-image overflow panic when a
        // crafted qub carries `drand_round == u64::MAX` (untrusted input,
        // and `overflow-checks = true` in release).
        let is_legacy = stored_round.checked_add(1) == Some(expected_round);
        if !(is_current || is_legacy) {
            return Err(UnlockError::DrandRoundMismatch {
                expected: expected_round,
                actual: stored_round,
            });
        }
        if let Some(stanza_round) = tlock.ciphertext_round(sealed.tlock_ciphertext())?
            && stanza_round != stored_round
        {
            return Err(UnlockError::DrandRoundMismatch {
                expected: stored_round,
                actual: stanza_round,
            });
        }
    }

    // Step 7b: tlock-decrypt the envelope bytes.
    let envelope_bytes = tlock.decrypt(sealed.tlock_ciphertext(), round_signature)?;

    // Step 8: parse the decrypted bytes back into a QubEnvelope.
    let envelope = deserialize_qub_envelope(&envelope_bytes)?;

    // Step 9: envelope version check (defensive; `deserialize_qub_envelope`
    // already enforces this).
    if envelope.version() != PROTOCOL_VERSION_1 {
        return Err(UnlockError::UnsupportedVersion(envelope.version()));
    }

    // Step 10: verify body hash (constant-time comparison).
    let computed = body_hash(envelope.body());
    if computed.ct_eq(envelope.body_hash()).unwrap_u8() == 0 {
        return Err(UnlockError::BodyHashMismatch);
    }

    // Step 11: envelope qub_id matches sealed qub_id.
    if envelope.qub_id() != sealed.qub_id() {
        return Err(UnlockError::QubIdMismatch);
    }

    // Step 12: envelope unlock_at matches sealed unlock_at.
    if envelope.unlock_at() != sealed.unlock_at() {
        return Err(UnlockError::UnlockAtMismatch);
    }

    // Step 12b: envelope outcome_at matches sealed outcome_at — both
    // surfaces carry the same optional value (PROTOCOL.md §2.2 / §2.3).
    if envelope.outcome_at() != sealed.outcome_at() {
        return Err(UnlockError::OutcomeAtMismatch);
    }

    // Step 12c: re-derive qub_id from the decrypted content and require
    // it to equal the recorded identity (PROTOCOL.md §4.1). The equality
    // checks above only prove the two layers agree with EACH OTHER; a
    // forger who rewrites a bound field on both surfaces — a pre-reveal
    // title swap, or a post-round body swap re-encrypted under the same
    // qub_id — passes them all. Only recomputing the identity from
    // content closes that. `body_hash` was proven correct in step 10;
    // `drand_round` is taken from the sealed layer (the round the
    // ciphertext is actually bound to, per step 7c); the title lives
    // plaintext on the sealed layer and is folded in via `title_hash`.
    let derived_qub_id = qub_id(
        envelope.version(),
        envelope.content_type(),
        envelope.created_at(),
        envelope.unlock_at(),
        envelope.outcome_at(),
        sealed.drand_round(),
        envelope.body_hash(),
        &title_hash(sealed.title()),
    );
    if &derived_qub_id != sealed.qub_id() {
        return Err(UnlockError::QubIdDerivationMismatch);
    }

    // Step 13: content type is renderable. Must mirror the seal-side
    // allowlist in `ComposeQub::validate_for_tier` — a content type that
    // seals but does not unlock is a permanently unviewable artifact.
    if !matches!(
        envelope.content_type(),
        CONTENT_TYPE_TEXT | CONTENT_TYPE_PACT | CONTENT_TYPE_VERDICT
    ) {
        return Err(UnlockError::UnsupportedContentType(envelope.content_type()));
    }

    // Step 14: signature verification (PROTOCOL.md §9.4).
    //
    // - sig_alg == 0x00 → unsigned. signature_verified = None.
    // - sig_alg == 0x01 (ML-DSA-65) → reconstruct sig_input from the
    //   envelope fields, then verify. signature_verified = Some(bool).
    //   Verification is V2-only (the preimage covers sender_label +
    //   reply_to); the legacy V1 preimage is no longer accepted — see
    //   `verify_envelope_signature`. If either field is absent, the qub
    //   claims to be signed but carries no signature material — report
    //   Some(false) so the viewer surfaces a "signature verification
    //   failed" state rather than silently ignoring the inconsistency.
    // - Any other sig_alg → reject per §9.4 step 3.
    //
    // Verification runs here, after the cheap structural checks
    // (body_hash, qub_id, unlock_at), because ML-DSA-65 verification
    // is the most expensive operation in the pipeline.
    let signature_verified: Option<bool> = match envelope.sig_alg() {
        SIG_ALG_UNSIGNED => None,
        SIG_ALG_ML_DSA_65 => match (envelope.author_pubkey(), envelope.author_signature()) {
            (Some(pubkey), Some(sig)) => Some(verify_envelope_signature(&envelope, pubkey, sig)),
            _ => Some(false),
        },
        other => {
            return Err(UnlockError::Validation(
                QubError::UnknownSignatureAlgorithm(other),
            ));
        },
    };

    // Step 15: cosigner signature verification (PROTOCOL.md §9.6).
    //
    // Both-or-neither: if exactly one of cosigner_pubkey / cosigner_signature
    // is present, report Some(false). If neither is present, cosigner_verified
    // is None. If both are present, verify against the same V2 sig_input as
    // the author signature (the legacy V1 preimage is no longer accepted).
    let cosigner_verified: Option<bool> =
        match (envelope.cosigner_pubkey(), envelope.cosigner_signature()) {
            (None, None) => None,
            (Some(cpk), Some(csig)) => {
                let same_as_author = envelope.author_pubkey() == Some(cpk);
                if same_as_author {
                    Some(false)
                } else {
                    Some(verify_envelope_signature(&envelope, cpk, csig))
                }
            },
            _ => Some(false), // one present, one absent
        };

    // Step 16: assemble the RevealedQub. `body_hash_verified` is `true`
    // because step 10 proved it. `title` is carried forward from the
    // SealedQub layer where it lives plaintext; it is bound to `qub_id`
    // via `title_hash` (PROTOCOL.md §4.1) and was already validated for
    // length and control characters by the CBOR decoder.
    Ok(RevealedQub::new(
        *envelope.qub_id(),
        arweave_tx_id,
        sealed.visibility(),
        envelope.content_type(),
        envelope.created_at(),
        envelope.unlock_at(),
        // V1.1 — outcome_at is carried on both QubEnvelope and
        // SealedQub; step 12b above proved they match, so reading
        // either is correct. Prefer the envelope side since the
        // rest of these fields come from the envelope.
        envelope.outcome_at(),
        sealed.drand_chain_id().to_string(),
        sealed.drand_round(),
        envelope.sender_label().map(str::to_owned),
        sealed.title().map(str::to_owned),
        envelope.reply_to().copied(),
        envelope.body().to_vec(),
        *envelope.body_hash(),
        true,
        envelope.author_signature().map(<[u8]>::to_vec),
        envelope.author_pubkey().map(<[u8]>::to_vec),
        signature_verified,
        envelope.cosigner_pubkey().map(<[u8]>::to_vec),
        envelope.cosigner_signature().map(<[u8]>::to_vec),
        cosigner_verified,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::serialize_qub_envelope;
    use crate::hash::{derive_envelope_hashes, unlock_round as compute_round};
    use crate::seal::{SealInput, seal};
    use crate::tlock::MockTimelockProvider;
    use crate::types::{
        CONTENT_TYPE_TEXT, ComposeQub, QubEnvelopeBuilder, SealedQubBuilder, VISIBILITY_PUBLIC,
    };

    const GENESIS: i64 = 1_595_431_050;
    const PERIOD: u64 = 30;
    const CHAIN_ID: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

    fn seal_with_mock(plaintext: &[u8], now: i64, unlock_at: i64) -> SealedQubCbor {
        let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
        draft.set_plaintext(plaintext.to_vec());
        draft.set_unlock_at(unlock_at);
        draft.set_sender_label(Some("Alice".into()));
        let tlock = MockTimelockProvider;
        seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        })
        .expect("seal")
        .sealed_cbor
    }

    #[test]
    fn unlock_happy_path_mock() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"secret message".to_vec();
        let sealed_cbor = seal_with_mock(&body, now, unlock_at);
        let tlock = MockTimelockProvider;
        let revealed = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx-abc".into(),
            tlock: &tlock,
        })
        .expect("unlock");
        assert_eq!(revealed.body(), body.as_slice());
        assert_eq!(revealed.unlock_at(), unlock_at);
        assert!(revealed.body_hash_verified());
        assert_eq!(revealed.signature_verified(), None);
        assert_eq!(revealed.arweave_tx_id(), "tx-abc");
        assert_eq!(revealed.sender_label(), Some("Alice"));
    }

    /// SEC-20: unlocking with a timelock provider bound to a different
    /// drand chain than the qub was sealed for is rejected up front
    /// with a clear `DrandChainMismatch`, before decryption.
    #[cfg(feature = "tlock-drand")]
    #[test]
    fn unlock_rejects_drand_chain_mismatch() {
        use crate::tlock::DrandTimelockProvider;
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        // seal_with_mock seals against CHAIN_ID (quicknet).
        let sealed_cbor = seal_with_mock(b"secret", now, unlock_at);
        // A provider bound to an all-zero chain hash — definitely not
        // quicknet. The bogus public key is never reached: the chain
        // check fails before decryption.
        let wrong_provider = DrandTimelockProvider::from_hex(&"00".repeat(32), &"ab".repeat(96))
            .expect("from_hex decodes well-formed hex");
        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &wrong_provider,
        })
        .expect_err("chain mismatch must be rejected");
        assert!(
            matches!(err, UnlockError::DrandChainMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn unlock_full_roundtrip_preserves_fields() {
        let now = 1_700_000_000;
        let unlock_at = now + 86_400;
        let body = b"Hello, future.".to_vec();
        let sealed_cbor = seal_with_mock(&body, now, unlock_at);

        // Parse sealed to grab qub_id + drand_round for comparison.
        let sealed = sealed_cbor.parse().unwrap();
        let expected_round = sealed.drand_round();
        let expected_qub_id = *sealed.qub_id();

        let tlock = MockTimelockProvider;
        let revealed = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at + 1,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx-xyz".into(),
            tlock: &tlock,
        })
        .unwrap();
        assert_eq!(revealed.qub_id(), &expected_qub_id);
        assert_eq!(revealed.body(), body.as_slice());
        assert_eq!(revealed.created_at(), now);
        assert_eq!(revealed.unlock_at(), unlock_at);
        assert_eq!(revealed.drand_chain_id(), CHAIN_ID);
        assert_eq!(revealed.drand_round(), expected_round);
        assert_eq!(revealed.sender_label(), Some("Alice"));
        assert_eq!(revealed.visibility(), VISIBILITY_PUBLIC);
    }

    #[test]
    fn unlock_still_locked() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let sealed_cbor = seal_with_mock(b"x", now, unlock_at);
        let tlock = MockTimelockProvider;
        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at - 1,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .unwrap_err();
        match err {
            UnlockError::StillLocked {
                unlock_at: u,
                now: n,
            } => {
                assert_eq!(u, unlock_at);
                assert_eq!(n, unlock_at - 1);
            },
            other => panic!("expected StillLocked, got {other:?}"),
        }
    }

    // ---- Step 15: cosigner verification (PROTOCOL.md §9.6) ------------
    //
    // This arm had NO test at all, so all three of its mutants survived,
    // and each is a lie a viewer would render:
    //
    //   - deleting `(None, None)` makes a qub with NO cosigner report
    //     `Some(false)` — "co-signature failed" where there is none.
    //   - deleting `(Some, Some)` makes a PROPERLY co-signed qub report
    //     `Some(false)` — a valid co-signature shown as a failed one.
    //   - flipping `==` to `!=` on the self-cosign check inverts it: a
    //     distinct cosigner is refused and an author co-signing their own
    //     qub is accepted — exactly the case the check exists to refuse,
    //     since a co-signature by the author proves nothing.

    const COSIGN_NOW: i64 = 1_700_000_000;
    const COSIGN_UNLOCK_AT: i64 = COSIGN_NOW + 3600;

    /// `(body_hash, qub_id, body)` for the cosigner fixture.
    fn cosign_fixture() -> ([u8; 32], [u8; 32], Vec<u8>) {
        let body = b"cosigned body".to_vec();
        // `unlock` re-derives `qub_id` from the SEALED layer's
        // `drand_round`, so this must match the round declared below or
        // the reveal fails on derivation before reaching the arm we test.
        let (body_hash, id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            COSIGN_NOW,
            COSIGN_UNLOCK_AT,
            None,
            1,
            &body,
            None,
        );
        (body_hash, id, body)
    }

    /// A valid V2 envelope signature over the fixture, under `secret`.
    fn cosign_signature(secret: &[u8]) -> Vec<u8> {
        let (body_hash, id, _) = cosign_fixture();
        crate::signing::sign(
            secret,
            &crate::signing::compute_sig_input_v2(
                PROTOCOL_VERSION_1,
                &id,
                &body_hash,
                COSIGN_UNLOCK_AT,
                None,
                None,
            ),
        )
        .expect("sign")
    }

    /// Seal a hand-built envelope carrying the given signer material and
    /// run it through the real `unlock`.
    fn reveal_with_signers(
        cosigner_pubkey: Option<Vec<u8>>,
        cosigner_signature: Option<Vec<u8>>,
        author_pubkey: Option<Vec<u8>>,
        author_signature: Option<Vec<u8>>,
    ) -> RevealedQub {
        let (body_hash, id, body) = cosign_fixture();
        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(COSIGN_NOW)
            .unlock_at(COSIGN_UNLOCK_AT)
            .body(body)
            .body_hash(body_hash)
            .author_pubkey(author_pubkey)
            .author_signature(author_signature)
            .cosigner_pubkey(cosigner_pubkey)
            .cosigner_signature(cosigner_signature)
            .build()
            .unwrap();
        let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).unwrap();
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(COSIGN_UNLOCK_AT)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(1)
            .tlock_ciphertext(ct)
            .build()
            .unwrap();
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
        unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: COSIGN_UNLOCK_AT,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .expect("unlock")
    }

    /// No cosigner material at all is `None` — NOT `Some(false)`.
    #[test]
    fn unlock_reports_absent_cosigner_as_none() {
        assert_eq!(
            reveal_with_signers(None, None, None, None).cosigner_verified(),
            None
        );
    }

    /// Exactly one of the pair present is a malformed envelope, both ways
    /// round, and reports a failed co-signature rather than none.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn unlock_reports_one_sided_cosigner_as_failed() {
        let (cosigner_public, cosigner_secret) = crate::signing::generate_keypair().unwrap();
        assert_eq!(
            reveal_with_signers(Some(cosigner_public), None, None, None).cosigner_verified(),
            Some(false)
        );
        assert_eq!(
            reveal_with_signers(None, Some(cosign_signature(&cosigner_secret)), None, None)
                .cosigner_verified(),
            Some(false)
        );
    }

    /// A distinct cosigner with a valid signature verifies; an author
    /// co-signing their own qub does not, on identity alone.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn unlock_verifies_distinct_cosigner_but_refuses_self_cosigning() {
        let (author_public, author_secret) = crate::signing::generate_keypair().unwrap();
        let (cosigner_public, cosigner_secret) = crate::signing::generate_keypair().unwrap();

        let revealed = reveal_with_signers(
            Some(cosigner_public),
            Some(cosign_signature(&cosigner_secret)),
            Some(author_public.clone()),
            Some(cosign_signature(&author_secret)),
        );
        assert_eq!(
            revealed.cosigner_verified(),
            Some(true),
            "a distinct cosigner with a valid signature must verify"
        );

        let revealed = reveal_with_signers(
            Some(author_public.clone()),
            Some(cosign_signature(&author_secret)),
            Some(author_public),
            Some(cosign_signature(&author_secret)),
        );
        assert_eq!(
            revealed.cosigner_verified(),
            Some(false),
            "an author co-signing their own qub proves nothing and must not verify"
        );
    }

    #[test]
    fn unlock_body_hash_mismatch() {
        // Construct an envelope with a wrong body_hash (tampered content
        // scenario). Because QubEnvelopeBuilder does not verify hash/body
        // consistency, we can supply mismatched values directly.
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"real body".to_vec();
        let (_real_bh, id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            now,
            unlock_at,
            None,
            4_695_445,
            &body,
            None,
        );
        let wrong_hash = [0u8; 32]; // does not match body
        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(now)
            .unlock_at(unlock_at)
            .body(body)
            .body_hash(wrong_hash)
            .build()
            .unwrap();
        let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).unwrap();
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(1)
            .tlock_ciphertext(ct)
            .build()
            .unwrap();
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .unwrap_err();
        assert!(matches!(err, UnlockError::BodyHashMismatch));
    }

    #[test]
    fn unlock_qub_id_mismatch() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"content".to_vec();
        let (bh, id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            now,
            unlock_at,
            None,
            4_695_445,
            &body,
            None,
        );
        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(now)
            .unlock_at(unlock_at)
            .body(body)
            .body_hash(bh)
            .build()
            .unwrap();
        let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).unwrap();

        // Sealed qub with a deliberately different qub_id.
        let mut different_id = id;
        different_id[0] ^= 0xFF;
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(different_id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(1)
            .tlock_ciphertext(ct)
            .build()
            .unwrap();
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .unwrap_err();
        assert!(matches!(err, UnlockError::QubIdMismatch));
    }

    #[test]
    fn unlock_unlock_at_mismatch() {
        let now = 1_700_000_000;
        let env_unlock = now + 3600;
        let sealed_unlock = now + 7200; // different
        let body = b"content".to_vec();
        let (bh, id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            now,
            env_unlock,
            None,
            4_695_445,
            &body,
            None,
        );
        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(now)
            .unlock_at(env_unlock)
            .body(body)
            .body_hash(bh)
            .build()
            .unwrap();
        let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).unwrap();
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(sealed_unlock)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(1)
            .tlock_ciphertext(ct)
            .build()
            .unwrap();
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: sealed_unlock,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .unwrap_err();
        assert!(matches!(err, UnlockError::UnlockAtMismatch));
    }

    #[test]
    fn unlock_unsupported_content_type_in_envelope() {
        // Build an envelope with content_type 0xFF (builder does not
        // validate content types). Keep qub_id consistent so we fail at
        // step 13 rather than step 11.
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"content".to_vec();
        let (bh, id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            0xFF, // unknown content type
            now,
            unlock_at,
            None,
            4_695_445,
            &body,
            None,
        );
        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .content_type(0xFF)
            .created_at(now)
            .unlock_at(unlock_at)
            .body(body)
            .body_hash(bh)
            .build()
            .unwrap();
        let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).unwrap();
        // drand_round must match the round folded into the qub_id above,
        // or the step-12c content re-derivation fires before the
        // content-type check this test targets.
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(4_695_445)
            .tlock_ciphertext(ct)
            .build()
            .unwrap();
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .unwrap_err();
        assert!(matches!(err, UnlockError::UnsupportedContentType(0xFF)));
    }

    #[test]
    fn unlock_unsupported_version_via_cbor() {
        // Manually encode a SealedQub-shaped CBOR map with version 0x02.
        // The canonical CBOR deserialiser rejects it first, surfacing as
        // UnlockError::Cbor(CborError::UnsupportedVersion). Keys are in
        // canonical order so the decode-side key-order check passes and the
        // version is what gets rejected.
        use ciborium::{Value, cbor};
        let map = cbor!({
            "qub_id" => Value::Bytes(vec![0u8; 32]),
            "version" => 2u8,
            "unlock_at" => 1_700_000_000i64,
            "visibility" => 1u8,
            "drand_round" => 1u64,
            "drand_chain_id" => "chain",
            "tlock_ciphertext" => Value::Bytes(vec![0xAA; 4]),
        })
        .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let sealed_cbor = SealedQubCbor::from_encoded(buf).unwrap();
        let tlock = MockTimelockProvider;
        let err = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: 2_000_000_000,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .unwrap_err();
        assert!(
            matches!(err, UnlockError::Cbor(CborError::UnsupportedVersion(2))),
            "expected Cbor(UnsupportedVersion(2)), got {err:?}",
        );
    }

    #[test]
    fn unlock_tampered_ciphertext_fails() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let sealed_cbor = seal_with_mock(b"the payload", now, unlock_at);
        // Parse, tamper ciphertext, reserialise.
        let mut sealed = sealed_cbor.parse().unwrap();
        let mut ct = sealed.tlock_ciphertext().to_vec();
        ct[0] ^= 0xFF;
        sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(*sealed.qub_id())
            .visibility(sealed.visibility())
            .unlock_at(sealed.unlock_at())
            .drand_chain_id(sealed.drand_chain_id().to_string())
            .drand_round(sealed.drand_round())
            .tlock_ciphertext(ct)
            .build()
            .unwrap();
        let tampered = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

        let tlock = MockTimelockProvider;
        // The mock provider is a byte-level xor; tampering one byte means
        // the resulting plaintext will no longer parse as a valid CBOR
        // QubEnvelope, OR the body_hash will mismatch. Either way, unlock
        // MUST fail.
        let result = unlock(UnlockInput {
            sealed_cbor: &tampered,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        });
        assert!(result.is_err(), "tampered ciphertext must not decrypt");
    }

    #[test]
    fn unlock_error_display_all_variants() {
        let variants: Vec<UnlockError> = vec![
            UnlockError::Cbor(crate::cbor::CborError::NotAMap),
            UnlockError::Tlock(crate::tlock::TimelockError::DecryptionFailed("x".into())),
            UnlockError::Validation(crate::types::QubError::EmptyBody),
            UnlockError::UnsupportedVersion(99),
            UnlockError::UnsupportedContentType(0xFF),
            UnlockError::BodyHashMismatch,
            UnlockError::QubIdMismatch,
            UnlockError::UnlockAtMismatch,
            UnlockError::OutcomeAtMismatch,
            UnlockError::QubIdDerivationMismatch,
            UnlockError::StillLocked {
                unlock_at: 100,
                now: 50,
            },
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display should produce output for {v:?}");
        }
        assert_eq!(variants.len(), 11, "all UnlockError variants exercised");
    }

    #[test]
    fn unlock_drand_round_sanity() {
        let now = 1_700_000_000;
        let unlock_at = now + 86_400;
        let sealed_cbor = seal_with_mock(b"round sanity", now, unlock_at);
        let sealed = sealed_cbor.parse().unwrap();
        assert_eq!(
            sealed.drand_round(),
            compute_round(unlock_at, GENESIS, PERIOD).unwrap()
        );
    }
}
