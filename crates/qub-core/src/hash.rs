//! Hashing and normative derivations for the qub protocol.
//!
//! This module implements the four normative derivations defined in
//! PROTOCOL.md §4:
//!
//! - [`body_hash`]  — SHA3-256 of the raw body bytes (§4.2).
//! - [`title_hash`] — SHA3-256 of the NFC-normalised title bytes (§4.1),
//!   or 32 zero bytes when the title is absent.
//! - [`qub_id`]     — SHA3-256 over a domain-separated 108-byte preimage (§4.1, V1.2).
//! - [`unlock_round`] — drand round number for a given unlock timestamp (§4.3).
//!
//! All functions are pure and deterministic. The preimage for `qub_id` is
//! assembled as a flat byte array (not CBOR) and is exactly 108 bytes.
//! V1.1 extended the original 92-byte layout to 100 bytes to fold
//! `outcome_at` into the binding (verdict-uplift-plan §3.1); V1.2 extended
//! it to 108 bytes to fold `drand_round` into the binding so a gateway
//! cannot swap the timelock round displayed/committed against `unlock_at`
//! (C1, post-Opus-4.8 review).

use sha3::{Digest, Sha3_256};
use unicode_normalization::UnicodeNormalization;

use crate::types::QubError;

/// Domain separator for [`qub_id`] derivation: ASCII `"QUB_ID_V2"` (9 bytes)
/// followed by a single `0x00` padding byte, for a total of 10 bytes.
///
/// The `V2` tag marks the 108-byte preimage that folds `drand_round` into
/// the binding (C1). See PROTOCOL.md §4.1.
///
/// # Examples
///
/// ```
/// use qub_core::hash::QUB_ID_DOMAIN_SEPARATOR;
///
/// assert_eq!(QUB_ID_DOMAIN_SEPARATOR.len(), 10);
/// assert_eq!(&QUB_ID_DOMAIN_SEPARATOR[..9], b"QUB_ID_V2");
/// assert_eq!(QUB_ID_DOMAIN_SEPARATOR[9], 0x00);
/// ```
pub const QUB_ID_DOMAIN_SEPARATOR: [u8; 10] =
    [0x51, 0x55, 0x42, 0x5F, 0x49, 0x44, 0x5F, 0x56, 0x32, 0x00];

/// Length in bytes of the `qub_id` preimage.
///
/// V1.1 (verdict-uplift-plan §3.1) extended this from 92 → 100 bytes
/// to fold `outcome_at` into the binding. V1.2 (C1, post-Opus-4.8
/// review) extended it to 108 bytes to fold `drand_round` into the
/// binding, so a gateway cannot swap the timelock round committed
/// against `unlock_at` without invalidating the qub identity. Absent
/// `outcome_at` is encoded as 8 zero bytes (the validator forbids
/// `outcome_at == 0` so the sentinel is unambiguous); `drand_round` is
/// a non-zero `u64` (round 0 predates any drand chain genesis).
const QUB_ID_PREIMAGE_LEN: usize = 108;

/// Sentinel value for an absent `outcome_at` in the `qub_id`
/// preimage. Zero is reserved as the absent sentinel — the protocol
/// validators (compose-time + wire-time + Worker edge) reject
/// `outcome_at <= 0` so this byte pattern cannot collide with a
/// legitimate value.
const OUTCOME_AT_ABSENT: i64 = 0;

/// Sentinel `title_hash` used when the `SealedQub` carries no title. 32
/// zero bytes are not a valid SHA3-256 output for any non-empty input,
/// so this value is reserved for the absent case and the bound title
/// distinguishes "absent" from "empty string" (the empty string is
/// rejected by the CBOR layer as a non-canonical encoding of `None`).
const TITLE_HASH_ABSENT: [u8; 32] = [0u8; 32];

/// Compute the body hash: SHA3-256 of the raw body bytes.
///
/// `body_hash = SHA3-256(body)` (PROTOCOL.md §4.2).
///
/// The output is always 32 bytes and is deterministic: the same input
/// always produces the same digest.
///
/// # Properties
///
/// - **Determinism**: `body_hash(x) == body_hash(x)` for all `x`.
/// - **Injectivity** (probabilistic): `x != y` implies `body_hash(x) != body_hash(y)`.
/// - **Purity**: no side effects, no state, no I/O.
///
/// # Examples
///
/// Canonical PROTOCOL.md §14.1 test vector — any conforming
/// implementation MUST produce this exact digest for this input:
///
/// ```
/// use qub_core::hash::body_hash;
///
/// assert_eq!(
///     body_hash(b"Hello, future."),
///     [
///         0x76, 0xab, 0x8b, 0x3f, 0x84, 0x3c, 0x6e, 0xd4, 0xf2, 0xd0, 0xfd,
///         0x75, 0xb9, 0xf4, 0x57, 0xb4, 0xad, 0x49, 0xdd, 0x44, 0x50, 0xf9,
///         0xc2, 0x27, 0x23, 0xae, 0x43, 0x0e, 0x3a, 0xf3, 0x21, 0x1d,
///     ],
/// );
/// ```
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(body);
    hasher.finalize().into()
}

/// Compute the title hash: SHA3-256 of the NFC-normalised UTF-8 bytes of
/// `title`, or 32 zero bytes (the absent sentinel) when `title` is `None`.
///
/// `title_hash = SHA3-256(NFC(title).as_bytes())  if Some(title)`
/// `title_hash = [0u8; 32]                        if None` (PROTOCOL.md §4.1).
///
/// The NFC normalisation is applied here to make the hash agnostic to the
/// byte form the caller happens to hold; the canonical CBOR layer
/// independently rejects non-NFC text on the wire, so anything decoded
/// from a parsed `SealedQub` is already NFC and the normalisation pass
/// is a no-op cost.
///
/// # Properties
///
/// - **Determinism**: same input always produces the same digest.
/// - **Absent sentinel**: `title_hash(None) == [0u8; 32]`.
/// - **NFC-equivalence**: any two strings that NFC-normalise to the same
///   bytes hash to the same digest.
/// - **Purity**: no side effects, no state, no I/O.
///
/// # Examples
///
/// ```
/// use qub_core::hash::title_hash;
///
/// // Absent title → 32 zero bytes.
/// assert_eq!(title_hash(None), [0u8; 32]);
///
/// // Present title → SHA3-256 of NFC-normalised bytes.
/// let h = title_hash(Some("Prediction"));
/// assert_eq!(h.len(), 32);
/// assert_ne!(h, [0u8; 32]);
/// ```
#[must_use]
pub fn title_hash(title: Option<&str>) -> [u8; 32] {
    title.map_or(TITLE_HASH_ABSENT, |s| {
        let nfc: String = s.nfc().collect();
        let mut hasher = Sha3_256::new();
        hasher.update(nfc.as_bytes());
        hasher.finalize().into()
    })
}

/// Derive the `qub_id` from envelope content fields.
///
/// The preimage is exactly 108 bytes (PROTOCOL.md §4.1, V1.2):
///
/// - Domain separator [`QUB_ID_DOMAIN_SEPARATOR`] (10 bytes)
/// - `version` (1 byte, `u8`)
/// - `content_type` (1 byte, `u8`)
/// - `created_at` (8 bytes, `i64` big-endian)
/// - `unlock_at` (8 bytes, `i64` big-endian)
/// - `outcome_at_or_zero` (8 bytes, `i64` big-endian; 0 when absent)
/// - `drand_round` (8 bytes, `u64` big-endian)
/// - `body_hash` (32 bytes)
/// - `title_hash` (32 bytes; all-zeros sentinel when no title)
///
/// `qub_id = SHA3-256(preimage)`.
///
/// The `body_hash` argument is the SHA3-256 of the envelope body —
/// produced by [`body_hash`]. The `title_hash` is the SHA3-256 of
/// the NFC-normalised title bytes, or 32 zero bytes when absent —
/// produced by [`title_hash`]. The `outcome_at` argument is the
/// optional second temporal moment (verdict-uplift-plan §3.1);
/// `None` is encoded as 8 zero bytes (`OUTCOME_AT_ABSENT`), and the
/// protocol validators reject `outcome_at == 0` everywhere so the
/// sentinel cannot collide with a legitimate value.
///
/// Per PROTOCOL.md §4.1, the `qub_id` does not depend on
/// `sender_label`, `author_signature`, `author_pubkey`, or
/// `reply_to`, which is why those fields are not accepted here.
///
/// # Properties
///
/// - **Determinism**: same 8-tuple always produces the same `qub_id`.
/// - **Injectivity**: changing any single input field produces a different output.
/// - **Domain separation**: the 10-byte prefix prevents collisions with `body_hash`.
/// - **Title binding**: changing the title (with everything else fixed) changes
///   `qub_id`, so a gateway cannot swap the plaintext title on `SealedQub`
///   without invalidating the qub identity.
/// - **Outcome binding**: changing `outcome_at` (with everything else
///   fixed) changes `qub_id`, so a gateway cannot swap the verdict-on
///   date displayed pre-reveal.
/// - **Round binding**: changing `drand_round` (with everything else
///   fixed) changes `qub_id`, so a gateway cannot swap the timelock
///   round the ciphertext is bound to without invalidating the qub
///   identity (C1).
/// - **Purity**: no side effects, no state, no I/O.
// The eight inputs are the normative qub_id preimage fields (PROTOCOL.md
// §4.1); they are not a refactorable cluster — each is an independent
// scalar bound into the identity.
#[allow(clippy::too_many_arguments)]
pub fn qub_id(
    version: u8,
    content_type: u8,
    created_at: i64,
    unlock_at: i64,
    outcome_at: Option<i64>,
    drand_round: u64,
    body_hash: &[u8; 32],
    title_hash: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = [0u8; QUB_ID_PREIMAGE_LEN];
    preimage[0..10].copy_from_slice(&QUB_ID_DOMAIN_SEPARATOR);
    preimage[10] = version;
    preimage[11] = content_type;
    preimage[12..20].copy_from_slice(&created_at.to_be_bytes());
    preimage[20..28].copy_from_slice(&unlock_at.to_be_bytes());
    let outcome_at_value = outcome_at.unwrap_or(OUTCOME_AT_ABSENT);
    preimage[28..36].copy_from_slice(&outcome_at_value.to_be_bytes());
    preimage[36..44].copy_from_slice(&drand_round.to_be_bytes());
    preimage[44..76].copy_from_slice(body_hash);
    preimage[76..108].copy_from_slice(title_hash);

    debug_assert_eq!(preimage.len(), QUB_ID_PREIMAGE_LEN);

    let mut hasher = Sha3_256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Derive the drand round number from an unlock timestamp and chain parameters.
///
/// `drand_round = floor((unlock_at - genesis_time) / period_seconds) + 1`
///
/// This is the reference tlock mapping (drand's `CurrentRound`): drand
/// publishes round `N` at `genesis + (N - 1) * period`, so the formula
/// selects the round current at `unlock_at` (PROTOCOL.md §4.3). When
/// `unlock_at` falls exactly on a beacon tick — always the case for the
/// reference deployment, since quicknet's genesis is period-aligned and
/// the app pins unlock times to whole minutes — the round's signature is
/// published **exactly at** `unlock_at`, never before.
///
/// The pre-V1.3 formula was `ceil(delta / period)`, which made the round
/// signature public one full period *before* a period-aligned
/// `unlock_at`. The two formulas differ by exactly `+1` when
/// `delta % period == 0` and agree otherwise; the unlock path accepts
/// the legacy round on existing artifacts (see [`crate::unlock`]).
///
/// # Properties
///
/// - **No early publish (aligned)**: when `delta % period == 0`,
///   `genesis + (round - 1) * period == unlock_at` — the gating signature
///   is first available exactly at `unlock_at`.
/// - **Current round**: `genesis + (round - 1) * period <= unlock_at <
///   genesis + round * period` — the round is the one current at
///   `unlock_at`, so earliness for non-aligned times is strictly less
///   than one period.
/// - **Monotonicity**: `t1 <= t2` implies `unlock_round(t1, g, p) <= unlock_round(t2, g, p)`.
/// - **Purity**: no side effects, no state, no I/O.
///
/// # Edge cases
///
/// - If `(unlock_at - genesis_time)` is exactly divisible by `period_seconds`,
///   the result is that exact round **plus one** — the round published at
///   `unlock_at` itself, not the one published a period earlier.
/// - If `unlock_at <= genesis_time`, the function returns an error
///   ([`QubError::UnlockBeforeGenesis`]).
/// - If `period_seconds == 0`, the function returns an error
///   ([`QubError::InvalidPeriod`]).
///
/// # Examples
///
/// Canonical PROTOCOL.md §14.2 test vector (drand League of Entropy
/// mainnet parameters):
///
/// ```
/// use qub_core::hash::unlock_round;
///
/// assert_eq!(
///     unlock_round(1_735_689_600, 1_595_431_050, 30),
///     Ok(4_675_286),
/// );
/// ```
///
/// Current-round semantics — the round's publish time
/// (`genesis + (round - 1) * period`) is never before a period-aligned
/// `unlock_at`:
///
/// ```
/// use qub_core::hash::unlock_round;
///
/// // Exact division: delta of 90s, period 30s → round 4, published at
/// // genesis + 90 == unlock_at (the legacy formula returned 3,
/// // published 30s early).
/// assert_eq!(unlock_round(1090, 1000, 30), Ok(4));
///
/// // Non-exact: delta of 91s → still round 4 (same as legacy).
/// assert_eq!(unlock_round(1091, 1000, 30), Ok(4));
/// ```
///
/// Edge cases return errors:
///
/// ```
/// use qub_core::hash::unlock_round;
///
/// // unlock_at in the past relative to genesis → error
/// assert!(unlock_round(500, 1000, 30).is_err());
/// // zero-period chain config is invalid → error
/// assert!(unlock_round(2000, 1000, 0).is_err());
/// ```
pub const fn unlock_round(
    unlock_at: i64,
    genesis_time: i64,
    period_seconds: u64,
) -> Result<u64, QubError> {
    if period_seconds == 0 {
        return Err(QubError::InvalidPeriod);
    }
    if unlock_at <= genesis_time {
        return Err(QubError::UnlockBeforeGenesis);
    }
    // `unlock_at > genesis_time`, so the difference is strictly positive and
    // fits in u64. Use `wrapping_sub` on u64 after casting to sidestep
    // clippy's "i64 as u64 may lose sign" lint while preserving semantics.
    let delta = unlock_at
        .cast_unsigned()
        .wrapping_sub(genesis_time.cast_unsigned());
    // Reference tlock formula (drand `CurrentRound`): floor + 1. `delta`
    // is bounded by i64::MAX so the +1 cannot overflow u64.
    Ok(delta / period_seconds + 1)
}

/// Compute both [`body_hash`] and [`qub_id`] from compose-time fields.
///
/// This is the primary entry point used during the seal flow. Returns
/// `(body_hash, qub_id)` — equivalent to calling the three primitives
/// in sequence but expressed as a single step to make the seal flow
/// call site harder to get wrong. The `title` is hashed via
/// [`title_hash`] and folded into the `qub_id` preimage; the title
/// hash itself is not returned because callers carry the plaintext
/// `title` directly on `SealedQub`. The `outcome_at` argument is the
/// optional second temporal moment (verdict-uplift-plan §3.1) — pass
/// `None` for verdict-irrelevant qubs or verdict-bearing qubs whose
/// creator declined to commit to an outcome date.
///
/// # Examples
///
/// ```
/// use qub_core::hash::{body_hash, derive_envelope_hashes, qub_id, title_hash};
///
/// let (bh, id) = derive_envelope_hashes(
///     0x01,          // version
///     0x01,          // content_type
///     1_735_689_600, // created_at
///     1_736_294_400, // unlock_at
///     None,          // outcome_at
///     4_695_446,     // drand_round
///     b"Hello, future.",
///     None,          // title
/// );
///
/// // Equivalent to calling the primitives in sequence.
/// assert_eq!(bh, body_hash(b"Hello, future."));
/// let th = title_hash(None);
/// assert_eq!(
///     id,
///     qub_id(0x01, 0x01, 1_735_689_600, 1_736_294_400, None, 4_695_446, &bh, &th),
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn derive_envelope_hashes(
    version: u8,
    content_type: u8,
    created_at: i64,
    unlock_at: i64,
    outcome_at: Option<i64>,
    drand_round: u64,
    body: &[u8],
    title: Option<&str>,
) -> ([u8; 32], [u8; 32]) {
    let bh = body_hash(body);
    let th = title_hash(title);
    let id = qub_id(
        version,
        content_type,
        created_at,
        unlock_at,
        outcome_at,
        drand_round,
        &bh,
        &th,
    );
    (bh, id)
}

/// Compute the pact-retract signing input:
/// `SHA3-256("QUB_PACT_RETRACT_V1" || staging_id_bytes)`.
///
/// `staging_id` is the **raw 16 bytes** of the staging id, not the
/// 32-character lowercase-hex string it travels as in URLs — callers
/// holding the hex form must decode it first. The Worker rebuilds this
/// exact preimage from the decoded path segment
/// (`workers/api/src/routes/pact.ts`, retract handler) before
/// `verifyMlDsa65`, so a client that hashes the ASCII hex instead
/// produces a signature over a different message and every retraction
/// fails with `retract_unauthorized` — the 2026-06 prod defect this
/// helper exists to prevent recurring.
///
/// # Examples
///
/// Cross-stack test vector — the TypeScript mirror
/// (`workers/api/src/crypto/__tests__/hash.test.ts`) MUST produce
/// this exact digest for this staging id:
///
/// ```
/// use qub_core::hash::pact_retract_input;
///
/// let staging_id: [u8; 16] = [
///     0xd4, 0x0d, 0x38, 0x23, 0xe0, 0x42, 0xa6, 0x61, 0x46, 0xca, 0x77,
///     0xe0, 0xda, 0x23, 0x31, 0x99,
/// ];
/// assert_eq!(
///     pact_retract_input(&staging_id),
///     [
///         0x72, 0xa1, 0x64, 0xf5, 0xc8, 0x67, 0x9e, 0x56, 0xce, 0x60,
///         0x2e, 0x01, 0xca, 0x44, 0xd2, 0x11, 0xb9, 0x3e, 0xfc, 0x16,
///         0x59, 0xec, 0xe7, 0xa1, 0x7f, 0xac, 0x51, 0x55, 0x18, 0xfd,
///         0xcd, 0x65,
///     ],
/// );
/// ```
#[must_use]
pub fn pact_retract_input(staging_id: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"QUB_PACT_RETRACT_V1");
    hasher.update(staging_id);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pact_retract_input` carried this cross-stack vector already — but
    /// only in a doctest, and the mutation lane runs under nextest, which
    /// does not execute doctests. Both `FnValue` replacements ([0; 32] and
    /// [1; 32]) therefore survived a suite that genuinely did pin the
    /// value. Duplicating the vector here puts it in front of the runner
    /// that measures.
    ///
    /// Oracle: the TypeScript mirror
    /// (`workers/api/src/crypto/__tests__/hash.test.ts`) must produce this
    /// exact digest — a differential oracle, not an implementation-derived
    /// one.
    #[test]
    fn pact_retract_input_matches_the_cross_stack_vector() {
        let staging_id: [u8; 16] = [
            0xd4, 0x0d, 0x38, 0x23, 0xe0, 0x42, 0xa6, 0x61, 0x46, 0xca, 0x77, 0xe0, 0xda, 0x23,
            0x31, 0x99,
        ];
        assert_eq!(
            pact_retract_input(&staging_id),
            [
                0x72, 0xa1, 0x64, 0xf5, 0xc8, 0x67, 0x9e, 0x56, 0xce, 0x60, 0x2e, 0x01, 0xca, 0x44,
                0xd2, 0x11, 0xb9, 0x3e, 0xfc, 0x16, 0x59, 0xec, 0xe7, 0xa1, 0x7f, 0xac, 0x51, 0x55,
                0x18, 0xfd, 0xcd, 0x65,
            ],
        );
    }

    // Test vector inputs from PROTOCOL.md §14.1.
    const TV_VERSION: u8 = 0x01;
    const TV_CONTENT_TYPE: u8 = 0x01;
    const TV_CREATED_AT: i64 = 1_735_689_600;
    const TV_UNLOCK_AT: i64 = 1_736_294_400;
    /// The §14.1 `drand_round` for `TV_UNLOCK_AT` under drand mainnet
    /// params (`genesis = 1_595_431_050`, `period = 30`):
    /// `floor((1_736_294_400 - 1_595_431_050) / 30) + 1 = 4_695_446`
    /// (§4.3 current-round mapping). Folded into the V1.2 `qub_id`
    /// preimage (C1).
    const TV_DRAND_ROUND: u64 = 4_695_446;
    const TV_BODY: &[u8] = b"Hello, future.";
    /// The §14.1 test vector pins the absent-title case (`title = None`),
    /// so `title_hash` is the [`TITLE_HASH_ABSENT`] sentinel.
    const TV_TITLE: Option<&str> = None;

    // Canonical expected outputs for the §14.1 test vector. These values
    // are computed by this implementation and become the reference that
    // other implementations must match.
    //
    // body_hash    = SHA3-256("Hello, future.")
    // title_hash   = [0u8; 32] (no title)
    // qub_id       = SHA3-256(domain_sep || 0x01 || 0x01 ||
    //                         created_at_be || unlock_at_be ||
    //                         body_hash || title_hash)
    //
    // Canonical values computed by this implementation. Any conforming
    // implementation MUST produce these exact outputs for the §14.1 inputs.
    const TV_BODY_HASH_HEX: &str =
        "76ab8b3f843c6ed4f2d0fd75b9f457b4ad49dd4450f9c22723ae430e3af3211d";
    // qub_id value with the V1.2 108-byte preimage (created_at ||
    // unlock_at || outcome_at_or_zero || drand_round || body_hash ||
    // title_hash). The V1.1 100-byte reference was
    // b0d032898ad629795150fdcb3f84e518f59ed05b7a2a82bc24ebdb87f52144ed
    // — the 8 extra bytes (drand_round, big-endian) plus the
    // QUB_ID_V1→V2 domain-separator bump shifted the digest. The V1.2
    // vector with the legacy ceil round-mapping (drand_round =
    // 4_695_445) was
    // 3a9fcb31b750d985c262fada6d4f777fd6a28be831d941d85c131f5a4bbaf8a4;
    // the V1.3 §4.3 current-round mapping bumps the example round to
    // 4_695_446 (the preimage layout is unchanged). Pre-launch, no live
    // qubs depended on the old values; see C1 + protocol.md §4.1.
    const TV_QUB_ID_HEX: &str = "4a84e3dfaec32954949c30073f8e6506fd3204c1bb97f9162b81c7587afe412e";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(&mut s, "{b:02x}").expect("writing to String cannot fail");
        }
        s
    }

    #[test]
    fn body_hash_is_deterministic() {
        let a = body_hash(b"hello");
        let b = body_hash(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn body_hash_varies_with_input() {
        let a = body_hash(b"hello");
        let b = body_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn qub_id_is_deterministic() {
        let bh = body_hash(b"payload");
        let th = title_hash(None);
        let a = qub_id(1, 1, 1000, 2000, None, 42, &bh, &th);
        let b = qub_id(1, 1, 1000, 2000, None, 42, &bh, &th);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn qub_id_varies_with_version() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let a = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let b = qub_id(2, 1, 100, 200, None, 42, &bh, &th);
        assert_ne!(a, b);
    }

    #[test]
    fn qub_id_varies_with_content_type() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let a = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let b = qub_id(1, 2, 100, 200, None, 42, &bh, &th);
        assert_ne!(a, b);
    }

    #[test]
    fn qub_id_varies_with_created_at() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let a = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let b = qub_id(1, 1, 101, 200, None, 42, &bh, &th);
        assert_ne!(a, b);
    }

    #[test]
    fn qub_id_varies_with_unlock_at() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let a = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let b = qub_id(1, 1, 100, 201, None, 42, &bh, &th);
        assert_ne!(a, b);
    }

    #[test]
    fn qub_id_varies_with_body_hash() {
        let th = title_hash(None);
        let a = qub_id(1, 1, 100, 200, None, 42, &body_hash(b"x"), &th);
        let b = qub_id(1, 1, 100, 200, None, 42, &body_hash(b"y"), &th);
        assert_ne!(a, b);
    }

    /// Mutation-resistance: changing the bound title (with everything else
    /// fixed) must change `qub_id`, so a gateway cannot swap the plaintext
    /// title displayed on the countdown page without invalidating the qub
    /// identity.
    #[test]
    fn qub_id_varies_with_title() {
        let bh = body_hash(b"x");
        let id_none = qub_id(1, 1, 100, 200, None, 42, &bh, &title_hash(None));
        let id_a = qub_id(
            1,
            1,
            100,
            200,
            None,
            42,
            &bh,
            &title_hash(Some("Prediction")),
        );
        let id_b = qub_id(
            1,
            1,
            100,
            200,
            None,
            42,
            &bh,
            &title_hash(Some("Announcement")),
        );
        assert_ne!(id_none, id_a);
        assert_ne!(id_a, id_b);
        assert_ne!(id_none, id_b);
    }

    /// Per PROTOCOL.md §4.1: the `qub_id` MUST NOT depend on `sender_label`,
    /// `author_signature`, or `author_pubkey`. The function signature
    /// enforces this structurally (those fields are not parameters), and
    /// this test documents the property: identical content fields always
    /// yield the same `qub_id` regardless of any surrounding envelope
    /// metadata.
    #[test]
    fn qub_id_does_not_depend_on_sender_identity() {
        let bh = body_hash(b"same content");
        let th = title_hash(None);
        let id_1 = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let id_2 = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        assert_eq!(id_1, id_2);
    }

    #[test]
    fn qub_id_preimage_is_exactly_108_bytes() {
        // Reconstruct the V1.2 preimage the same way the
        // implementation does and verify its length. Beyond the
        // pre-V1.1 92-byte layout, +8 bytes carry `outcome_at_or_zero`
        // (V1.1) and +8 bytes carry `drand_round` (V1.2).
        let bh = body_hash(b"anything");
        let th = title_hash(None);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&QUB_ID_DOMAIN_SEPARATOR);
        preimage.push(1u8);
        preimage.push(1u8);
        preimage.extend_from_slice(&100i64.to_be_bytes());
        preimage.extend_from_slice(&200i64.to_be_bytes());
        preimage.extend_from_slice(&OUTCOME_AT_ABSENT.to_be_bytes());
        preimage.extend_from_slice(&7u64.to_be_bytes());
        preimage.extend_from_slice(&bh);
        preimage.extend_from_slice(&th);
        assert_eq!(preimage.len(), 108);
        assert_eq!(preimage.len(), QUB_ID_PREIMAGE_LEN);
    }

    /// Mutation-resistance: changing `outcome_at` (with everything
    /// else fixed) must change `qub_id`, so a gateway cannot swap the
    /// pre-reveal verdict-on date without invalidating the qub
    /// identity. Mirrors the `qub_id_varies_with_title` pattern
    /// (verdict-uplift-plan §12.1).
    #[test]
    fn qub_id_varies_with_outcome_at() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let id_none = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let id_a = qub_id(1, 1, 100, 200, Some(300), 42, &bh, &th);
        let id_b = qub_id(1, 1, 100, 200, Some(400), 42, &bh, &th);
        assert_ne!(id_none, id_a);
        assert_ne!(id_a, id_b);
        assert_ne!(id_none, id_b);
    }

    /// Mutation-resistance: changing `drand_round` (with everything
    /// else fixed) must change `qub_id`, so a gateway cannot rebind the
    /// timelock ciphertext to a different (e.g. already-past) round
    /// while leaving the displayed `unlock_at` intact (C1). Mirrors the
    /// `qub_id_varies_with_outcome_at` pattern.
    #[test]
    fn qub_id_varies_with_drand_round() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let id_a = qub_id(1, 1, 100, 200, None, 4_695_445, &bh, &th);
        let id_b = qub_id(1, 1, 100, 200, None, 4_695_446, &bh, &th);
        assert_ne!(id_a, id_b);
    }

    /// `outcome_at = Some(0)` MUST hash the same as `None` because
    /// `OUTCOME_AT_ABSENT == 0`. The protocol validators reject
    /// `outcome_at == 0` everywhere on the wire, so this isn't a
    /// runtime concern, but the function itself is honest about the
    /// sentinel collision.
    #[test]
    fn qub_id_outcome_at_zero_collides_with_none() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let id_none = qub_id(1, 1, 100, 200, None, 42, &bh, &th);
        let id_zero = qub_id(1, 1, 100, 200, Some(0), 42, &bh, &th);
        assert_eq!(
            id_none, id_zero,
            "Some(0) must hash like None — see OUTCOME_AT_ABSENT comment",
        );
    }

    #[test]
    fn domain_separator_matches_ascii_encoding() {
        assert_eq!(QUB_ID_DOMAIN_SEPARATOR.len(), 10);
        assert_eq!(&QUB_ID_DOMAIN_SEPARATOR[0..9], b"QUB_ID_V2");
        assert_eq!(QUB_ID_DOMAIN_SEPARATOR[9], 0x00);
    }

    #[test]
    fn timestamp_big_endian_encoding_is_correct() {
        // Verify i64::to_be_bytes produces the big-endian encodings shown
        // in PROTOCOL.md §14.1 for the test-vector timestamps.
        assert_eq!(
            TV_CREATED_AT.to_be_bytes(),
            [0x00, 0x00, 0x00, 0x00, 0x67, 0x74, 0x85, 0x80]
        );
        assert_eq!(
            TV_UNLOCK_AT.to_be_bytes(),
            [0x00, 0x00, 0x00, 0x00, 0x67, 0x7D, 0xC0, 0x00]
        );
    }

    /// PROTOCOL.md §14.1 test vector. The expected `body_hash` and `qub_id`
    /// values are computed by this implementation and become canonical.
    #[test]
    fn protocol_test_vector_14_1_qub_id_derivation() {
        let bh = body_hash(TV_BODY);
        let th = title_hash(TV_TITLE);
        let id = qub_id(
            TV_VERSION,
            TV_CONTENT_TYPE,
            TV_CREATED_AT,
            TV_UNLOCK_AT,
            None,
            TV_DRAND_ROUND,
            &bh,
            &th,
        );

        // The values below are the canonical reference for any future
        // reimplementation. If this test ever fails, something in the
        // preimage construction has changed and the spec has been broken.
        let body_hash_hex = hex(&bh);
        let qub_id_hex = hex(&id);

        // Print for visibility in `cargo test -- --nocapture`.
        eprintln!("§14.1 body_hash = {body_hash_hex}");
        eprintln!("§14.1 qub_id    = {qub_id_hex}");

        assert_eq!(body_hash_hex, TV_BODY_HASH_HEX);
        assert_eq!(qub_id_hex, TV_QUB_ID_HEX);
        assert_eq!(bh.len(), 32);
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn derive_envelope_hashes_matches_individual_calls() {
        let (bh, id) = derive_envelope_hashes(1, 1, 100, 200, None, 42, b"body", None);
        assert_eq!(bh, body_hash(b"body"));
        let th = title_hash(None);
        assert_eq!(id, qub_id(1, 1, 100, 200, None, 42, &bh, &th));
    }

    #[test]
    fn derive_envelope_hashes_with_title_matches_individual_calls() {
        let (bh, id) = derive_envelope_hashes(1, 1, 100, 200, None, 42, b"body", Some("My title"));
        assert_eq!(bh, body_hash(b"body"));
        let th = title_hash(Some("My title"));
        assert_eq!(id, qub_id(1, 1, 100, 200, None, 42, &bh, &th));
    }

    /// Mutation-resistance: domain separator must be exactly these bytes.
    /// If anyone changes any byte, all `qub_id` values will change — this test catches that.
    #[test]
    fn domain_separator_is_exactly_specified_bytes() {
        assert_eq!(
            QUB_ID_DOMAIN_SEPARATOR,
            [0x51, 0x55, 0x42, 0x5F, 0x49, 0x44, 0x5F, 0x56, 0x32, 0x00]
        );
    }

    #[test]
    fn body_hash_empty_input() {
        let h = body_hash(b"");
        assert_eq!(h.len(), 32);
        // Must be the SHA3-256 of empty string — a known constant.
        let h2 = body_hash(b"");
        assert_eq!(h, h2);
    }

    #[test]
    fn body_hash_single_byte() {
        let h = body_hash(&[0x00]);
        assert_eq!(h.len(), 32);
        assert_ne!(h, body_hash(b""));
    }

    #[test]
    fn qub_id_zero_timestamps() {
        let bh = body_hash(b"x");
        let th = title_hash(None);
        let id = qub_id(1, 1, 0, 0, None, 42, &bh, &th);
        assert_eq!(id.len(), 32);
        // Different from nonzero timestamps.
        let id2 = qub_id(1, 1, 1, 0, None, 42, &bh, &th);
        assert_ne!(id, id2);
    }

    #[test]
    fn title_hash_is_deterministic_and_nonzero_for_present() {
        let h = title_hash(Some("Prediction"));
        assert_eq!(h.len(), 32);
        assert_ne!(h, [0u8; 32]);
        // Same input → same output.
        assert_eq!(h, title_hash(Some("Prediction")));
    }

    #[test]
    fn title_hash_absent_is_zero_sentinel() {
        assert_eq!(title_hash(None), [0u8; 32]);
        // The absent sentinel must differ from every present hash.
        assert_ne!(title_hash(None), title_hash(Some("any")));
    }

    #[test]
    fn title_hash_nfc_equivalent_inputs_match() {
        // U+00E9 (precomposed é) and U+0065 + U+0301 (e + combining acute)
        // NFC-normalise to the same byte sequence and so MUST hash the
        // same. The CBOR layer also rejects non-NFC text on the wire,
        // but the title_hash function is independently NFC-aware.
        let precomposed = "café";
        let decomposed = "cafe\u{0301}";
        assert_ne!(precomposed.as_bytes(), decomposed.as_bytes());
        assert_eq!(title_hash(Some(precomposed)), title_hash(Some(decomposed)));
    }

    #[test]
    fn unlock_round_large_period() {
        // Period larger than delta → rounds up to 1.
        assert_eq!(unlock_round(1001, 1000, 9999), Ok(1));
    }

    // ---------- Unlock-round mapping tests ----------

    /// PROTOCOL.md §14.2 test vector. The delta (`140_258_550`) divides
    /// the 30s period exactly, so the §4.3 current-round mapping yields
    /// `floor + 1 = 4_675_286` (the legacy ceil mapping gave `4_675_285`,
    /// whose signature published 30s before `unlock_at`).
    #[test]
    fn protocol_test_vector_14_2_unlock_round() {
        let round = unlock_round(1_735_689_600, 1_595_431_050, 30);
        assert_eq!(round, Ok(4_675_286));
    }

    #[test]
    fn unlock_round_exact_division() {
        // delta 90, period 30: floor(90/30) + 1 = 4. Round 4 publishes at
        // genesis + 3 * 30 = 1090 == unlock_at — available exactly at,
        // never before, the unlock time. (Legacy ceil gave round 3,
        // published at 1060 — a full period early.)
        assert_eq!(unlock_round(1090, 1000, 30), Ok(4));
    }

    #[test]
    fn unlock_round_non_exact_division() {
        // delta 91, period 30: floor(91/30) + 1 = 4 — identical to the
        // legacy ceil mapping for non-aligned unlock times.
        assert_eq!(unlock_round(1091, 1000, 30), Ok(4));
    }

    #[test]
    fn unlock_round_minimal_positive_delta() {
        // genesis + 1 → round 1 (floor(1/30) + 1).
        assert_eq!(unlock_round(1001, 1000, 30), Ok(1));
    }

    /// Pinned A3 property: for a period-aligned `unlock_at` (the
    /// reference deployment case — quicknet genesis is divisible by the
    /// 3s period and the app pins unlock times to whole minutes), the
    /// signature that gates decryption is first published **at**
    /// `unlock_at`, never before it.
    #[test]
    fn unlock_round_signature_not_available_before_aligned_unlock_at() {
        // quicknet params: genesis 1_692_803_367 (divisible by 3), period 3.
        let genesis = 1_692_803_367i64;
        let period = 3u64;
        for k in [1i64, 2, 20, 1_000_000, 999_999_999] {
            let unlock_at = genesis + k * 3;
            let round = unlock_round(unlock_at, genesis, period).unwrap();
            // drand publishes round N at genesis + (N - 1) * period.
            let publish_at = genesis + (i64::try_from(round).unwrap() - 1) * 3;
            assert!(
                publish_at >= unlock_at,
                "round {round} publishes at {publish_at}, before unlock_at {unlock_at}"
            );
            assert_eq!(
                publish_at, unlock_at,
                "aligned case publishes exactly at unlock_at"
            );
        }
    }

    /// Boundary relation to the legacy (pre-V1.3) `ceil` mapping: the
    /// new round equals legacy + 1 exactly when `delta % period == 0`,
    /// and equals the legacy round otherwise. The unlock path's legacy
    /// tolerance relies on this relation.
    #[test]
    fn unlock_round_legacy_relation() {
        let genesis = 1000i64;
        let period = 30u64;
        for delta in 1i64..=121 {
            let unlock_at = genesis + delta;
            let new = unlock_round(unlock_at, genesis, period).unwrap();
            let legacy = delta.cast_unsigned().div_ceil(period);
            if delta % 30 == 0 {
                assert_eq!(new, legacy + 1, "delta {delta}");
            } else {
                assert_eq!(new, legacy, "delta {delta}");
            }
        }
    }

    #[test]
    fn unlock_round_at_genesis_returns_err() {
        assert!(unlock_round(1000, 1000, 30).is_err());
    }

    #[test]
    fn unlock_round_before_genesis_returns_err() {
        assert!(unlock_round(500, 1000, 30).is_err());
    }

    #[test]
    fn unlock_round_zero_period_returns_err() {
        assert!(unlock_round(2000, 1000, 0).is_err());
    }

    #[test]
    fn qub_id_unaffected_by_cosigner_fields() {
        // qub_id derivation uses (version, content_type, created_at,
        // unlock_at, body_hash, title_hash). Cosigner fields are NOT
        // inputs, so two envelopes differing only in cosigner fields
        // must have the same qub_id.
        use crate::types::{CONTENT_TYPE_PACT, PROTOCOL_VERSION_1};
        let bh = body_hash(b"pact body");
        let th = title_hash(None);
        let id = qub_id(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_PACT,
            100,
            200,
            None,
            7,
            &bh,
            &th,
        );
        // Same inputs → same id (cosigner fields are irrelevant).
        let id2 = qub_id(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_PACT,
            100,
            200,
            None,
            7,
            &bh,
            &th,
        );
        assert_eq!(id, id2);
        // Different content type → different id.
        let id3 = qub_id(
            PROTOCOL_VERSION_1,
            crate::types::CONTENT_TYPE_TEXT,
            100,
            200,
            None,
            7,
            &bh,
            &th,
        );
        assert_ne!(id, id3);
    }
}
