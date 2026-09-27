//! Cross-module integration and property tests for `qub-core`.
//!
//! These tests tie together the foundation tasks (A2–A5) and exercise the
//! full simulated seal → verify pipeline, the canonical CBOR round-trip
//! property (PROTOCOL.md §14.3), wire-newtype guarantees, and the normative
//! hashing derivations in PROTOCOL.md §4.

use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization as _;

use qub_core::cbor::{
    CborError, deserialize_sealed_qub, serialize_qub_envelope, serialize_sealed_qub,
};
use qub_core::export::QubBundle;
use qub_core::hash::{body_hash, derive_envelope_hashes, qub_id, title_hash, unlock_round};
use qub_core::seal::{SealInput, seal};
use qub_core::tlock::{MockTimelockProvider, TimelockProvider};
use qub_core::types::{
    CONTENT_TYPE_TEXT, ComposeQub, PROTOCOL_VERSION_1, QubEnvelope, QubEnvelopeBuilder, SealedQub,
    SealedQubBuilder, VISIBILITY_PUBLIC,
};
use qub_core::unlock::{UnlockInput, unlock};
use qub_core::wire::{QubEnvelopeCbor, SealedQubCbor};

// -----------------------------------------------------------------------------
// Builders for test fixtures
// -----------------------------------------------------------------------------

fn build_envelope(
    body: Vec<u8>,
    created_at: i64,
    unlock_at: i64,
    sender_label: Option<String>,
) -> QubEnvelope {
    let (bh, id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        created_at,
        unlock_at,
        None,
        4_675_285,
        &body,
        None,
    );
    QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(id)
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(created_at)
        .unlock_at(unlock_at)
        .sender_label(sender_label)
        .body(body)
        .body_hash(bh)
        .build()
        .expect("valid envelope")
}

fn build_sealed_from_envelope(env: &QubEnvelope, ciphertext: Vec<u8>) -> SealedQub {
    SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(*env.qub_id())
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(env.unlock_at())
        .drand_chain_id("a".repeat(64))
        .drand_round(4_675_285)
        .tlock_ciphertext(ciphertext)
        .build()
        .expect("valid sealed")
}

// -----------------------------------------------------------------------------
// 1. Full simulated seal → verify pipeline
// -----------------------------------------------------------------------------

#[test]
fn full_pipeline_simulated_seal_and_verify() {
    // (a) Compose draft.
    let mut compose = ComposeQub::new(CONTENT_TYPE_TEXT);
    compose.set_plaintext(b"Hello, future.".to_vec());
    compose.set_created_at(1_735_689_600);
    compose.set_unlock_at(1_736_294_400);
    compose.validate().unwrap();

    // (b) Derive normative hashes.
    let (bh, id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        compose.content_type(),
        compose.created_at(),
        compose.unlock_at().unwrap(),
        None,
        4_695_445,
        compose.plaintext(),
        None,
    );

    // (c) Build the envelope.
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(id)
        .content_type(compose.content_type())
        .created_at(compose.created_at())
        .unlock_at(compose.unlock_at().unwrap())
        .body(compose.plaintext().to_vec())
        .body_hash(bh)
        .build()
        .unwrap();

    // (d) Serialise envelope to canonical CBOR.
    let envelope_cbor = QubEnvelopeCbor::from_qub_envelope(&envelope).unwrap();

    // (e) Stand in for the tlock ciphertext with the raw envelope bytes.
    //     This simulates the "seal" step without any real crypto.
    let fake_ciphertext = envelope_cbor.as_bytes().to_vec();

    // (f) Construct and serialise the sealed qub.
    let sealed = build_sealed_from_envelope(&envelope, fake_ciphertext);
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

    // (g) Parse SealedQubCbor back.
    let parsed_sealed = sealed_cbor.parse().unwrap();

    // (h) qub_id and (i) unlock_at match between envelope and sealed.
    assert_eq!(parsed_sealed.qub_id(), envelope.qub_id());
    assert_eq!(parsed_sealed.unlock_at(), envelope.unlock_at());

    // (j) Parse the "ciphertext" back as an envelope.
    let inner_cbor =
        QubEnvelopeCbor::from_encoded(parsed_sealed.tlock_ciphertext().to_vec()).unwrap();
    let parsed_envelope = inner_cbor.parse().unwrap();

    // (k) body_hash matches recomputation.
    let recomputed_bh = body_hash(parsed_envelope.body());
    assert_eq!(parsed_envelope.body_hash(), &recomputed_bh);

    // (l) qub_id matches recomputed derivation.
    let recomputed_id = qub_id(
        parsed_envelope.version(),
        parsed_envelope.content_type(),
        parsed_envelope.created_at(),
        parsed_envelope.unlock_at(),
        None,
        4_695_445,
        parsed_envelope.body_hash(),
        &title_hash(None),
    );
    assert_eq!(parsed_envelope.qub_id(), &recomputed_id);
}

// -----------------------------------------------------------------------------
// 2. Tampered ciphertext detection
// -----------------------------------------------------------------------------

#[test]
fn tampered_cbor_is_detectable() {
    let env = build_envelope(b"hello".to_vec(), 1_000_000_000, 2_000_000_000, None);
    let sealed = build_sealed_from_envelope(&env, vec![0x01, 0x02, 0x03]);
    let bytes = serialize_sealed_qub(&sealed).unwrap();

    // Flip a byte somewhere past the map header.
    let mut tampered = bytes.clone();
    let flip_index = tampered.len() / 2;
    tampered[flip_index] ^= 0xFF;

    // Either deserialisation fails outright, or it yields a value that is
    // no longer byte-for-byte equal to the original. Both outcomes are
    // acceptable detection signals for a mutation in the encoded form.
    match deserialize_sealed_qub(&tampered) {
        Err(_) => {},
        Ok(other) => {
            let reserialised = serialize_sealed_qub(&other).unwrap();
            assert_ne!(reserialised, bytes, "tampered bytes re-encoded identically");
        },
    }
}

#[test]
fn tampered_header_byte_fails_parse() {
    let env = build_envelope(b"tamper".to_vec(), 1_000_000_000, 2_000_000_000, None);
    let sealed = build_sealed_from_envelope(&env, vec![0xAA, 0xBB]);
    let mut bytes = serialize_sealed_qub(&sealed).unwrap();
    bytes[0] = 0x01; // no longer a CBOR map header
    assert!(deserialize_sealed_qub(&bytes).is_err());
}

// -----------------------------------------------------------------------------
// 3. Cross-field consistency between envelope and sealed
// -----------------------------------------------------------------------------

#[test]
fn envelope_and_sealed_share_qub_id_and_unlock_at() {
    let env = build_envelope(
        b"consistency check".to_vec(),
        1_700_000_000,
        1_800_000_000,
        Some("alice".to_string()),
    );
    let sealed = build_sealed_from_envelope(&env, vec![0xCA, 0xFE]);

    assert_eq!(env.qub_id(), sealed.qub_id());
    assert_eq!(env.unlock_at(), sealed.unlock_at());
}

#[test]
fn mismatched_qub_id_between_envelope_and_sealed_is_detectable() {
    let env = build_envelope(b"one".to_vec(), 1_700_000_000, 1_800_000_000, None);

    // Build a sealed with a different qub_id than the envelope.
    let mut wrong_id = *env.qub_id();
    wrong_id[0] ^= 0xFF;
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(wrong_id)
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(env.unlock_at())
        .drand_chain_id("a".repeat(64))
        .drand_round(1)
        .tlock_ciphertext(vec![0x00])
        .build()
        .unwrap();

    assert_ne!(env.qub_id(), sealed.qub_id());
}

// -----------------------------------------------------------------------------
// 4. Wire newtype round-trip via convenience constructors
// -----------------------------------------------------------------------------

#[test]
fn envelope_wire_newtype_round_trip() {
    let env = build_envelope(
        b"wire newtype".to_vec(),
        1_700_000_000,
        1_800_000_000,
        Some("carol".to_string()),
    );
    let wire = QubEnvelopeCbor::from_qub_envelope(&env).unwrap();
    let parsed = wire.parse().unwrap();
    assert_eq!(env, parsed);
}

#[test]
fn sealed_wire_newtype_round_trip() {
    let env = build_envelope(b"inside".to_vec(), 1_700_000_000, 1_800_000_000, None);
    let sealed = build_sealed_from_envelope(&env, b"cipher".to_vec());
    let wire = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
    let parsed = wire.parse().unwrap();
    assert_eq!(sealed, parsed);
}

// -----------------------------------------------------------------------------
// 5. Wire newtype rejection of bad inputs
// -----------------------------------------------------------------------------

#[test]
fn sealed_cbor_from_encoded_rejects_empty() {
    assert!(matches!(
        SealedQubCbor::from_encoded(vec![]),
        Err(CborError::NotAMap)
    ));
}

#[test]
fn sealed_cbor_from_encoded_rejects_non_map_bytes() {
    assert!(matches!(
        SealedQubCbor::from_encoded(vec![0x01, 0x02]),
        Err(CborError::NotAMap)
    ));
}

#[test]
fn sealed_cbor_from_encoded_accepts_empty_map_header() {
    // 0xA0 is a valid but structurally-empty map. The construction-time
    // check passes; parsing fails because required fields are absent.
    let w = SealedQubCbor::from_encoded(vec![0xA0]).unwrap();
    assert!(w.parse().is_err());
}

// -----------------------------------------------------------------------------
mod common;

// 6–8. Property tests
// -----------------------------------------------------------------------------

proptest! {
    #![proptest_config(common::config(128))]

    // 6. QubEnvelope CBOR round-trip.
    #[test]
    fn envelope_cbor_round_trip(
        body in common::wire_body_bytes(),
        created_at in 1_000_000_000i64..2_000_000_000i64,
        unlock_at in 2_000_000_001i64..3_000_000_000i64,
        sender_label in common::sender_label(),
    ) {
        // The label is compared in its NFC form because that is what the wire
        // carries: `cbor.rs` normalises on the way out. The old generator drew
        // from `[a-zA-Z0-9 ]`, an alphabet NFC cannot change, so comparing
        // against the raw draw passed — not because the property held, but
        // because no input could distinguish the two. See
        // `tests/property_reach.rs`.
        let expected_label: Option<String> =
            sender_label.as_deref().map(|s| s.nfc().collect());
        let env = build_envelope(body, created_at, unlock_at, sender_label);
        let bytes = serialize_qub_envelope(&env).unwrap();
        let parsed = QubEnvelopeCbor::from_encoded(bytes).unwrap().parse().unwrap();
        prop_assert_eq!(parsed.sender_label(), expected_label.as_deref());
        prop_assert_eq!(env.body(), parsed.body());
        prop_assert_eq!(env.created_at(), parsed.created_at());
        prop_assert_eq!(env.unlock_at(), parsed.unlock_at());
    }

    // 7. SealedQub CBOR round-trip.
    #[test]
    fn sealed_cbor_round_trip(
        ciphertext in common::wire_body_bytes(),
        unlock_at in 2_000_000_001i64..3_000_000_000i64,
        drand_round in 1u64..10_000_000u64,
        chain_id in "[a-f0-9]{64}",
    ) {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x42; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(chain_id)
            .drand_round(drand_round)
            .tlock_ciphertext(ciphertext)
            .build()
            .unwrap();
        let bytes = serialize_sealed_qub(&sealed).unwrap();
        let parsed = SealedQubCbor::from_encoded(bytes).unwrap().parse().unwrap();
        prop_assert_eq!(sealed, parsed);
    }

    // 8a. Canonical CBOR property (§14.3) for envelopes:
    //     serialize(parse(serialize(env))) == serialize(env).
    #[test]
    fn envelope_canonical_cbor_property(
        body in common::wire_body_bytes(),
        created_at in 1_000_000_000i64..2_000_000_000i64,
        unlock_at in 2_000_000_001i64..3_000_000_000i64,
    ) {
        let env = build_envelope(body, created_at, unlock_at, None);
        let bytes1 = serialize_qub_envelope(&env).unwrap();
        let parsed = QubEnvelopeCbor::from_encoded(bytes1.clone()).unwrap().parse().unwrap();
        let bytes2 = serialize_qub_envelope(&parsed).unwrap();
        prop_assert_eq!(bytes1, bytes2);
    }

    // 8b. Canonical CBOR property (§14.3) for sealed qubs.
    #[test]
    fn sealed_canonical_cbor_property(
        ciphertext in proptest::collection::vec(any::<u8>(), 1..1000),
        unlock_at in 2_000_000_001i64..3_000_000_000i64,
        drand_round in 1u64..10_000_000u64,
    ) {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x17; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id("b".repeat(64))
            .drand_round(drand_round)
            .tlock_ciphertext(ciphertext)
            .build()
            .unwrap();
        let bytes1 = serialize_sealed_qub(&sealed).unwrap();
        let parsed = SealedQubCbor::from_encoded(bytes1.clone()).unwrap().parse().unwrap();
        let bytes2 = serialize_sealed_qub(&parsed).unwrap();
        prop_assert_eq!(bytes1, bytes2);
    }

    // 9. qub_id uniqueness under field variation: changing any single
    //    input to qub_id() produces a different output.
    #[test]
    fn qub_id_changes_when_any_field_changes(
        version in 1u8..200u8,
        content_type in 1u8..200u8,
        created_at in -1_000_000_000i64..1_000_000_000i64,
        unlock_at in -1_000_000_000i64..1_000_000_000i64,
        body in proptest::collection::vec(any::<u8>(), 1..200),
    ) {
        let bh = body_hash(&body);
        // Held constant across all comparisons so the test isolates the
        // intended varied field (drand_round variance is covered elsewhere).
        let round = 4_695_445;
        let base = qub_id(version, content_type, created_at, unlock_at, None, round, &bh, &title_hash(None));

        // Use wrapping_add on the unsigned repr to avoid overflow panics
        // while guaranteeing a distinct value.
        let diff_version = version.wrapping_add(1);
        let diff_content = content_type.wrapping_add(1);
        let diff_created = created_at.wrapping_add(1);
        let diff_unlock = unlock_at.wrapping_add(1);

        let alt_bh = body_hash(&[body.as_slice(), &[0xFF]].concat());

        prop_assert_ne!(base, qub_id(diff_version, content_type, created_at, unlock_at, None, round, &bh, &title_hash(None)));
        prop_assert_ne!(base, qub_id(version, diff_content, created_at, unlock_at, None, round, &bh, &title_hash(None)));
        prop_assert_ne!(base, qub_id(version, content_type, diff_created, unlock_at, None, round, &bh, &title_hash(None)));
        prop_assert_ne!(base, qub_id(version, content_type, created_at, diff_unlock, None, round, &bh, &title_hash(None)));
        prop_assert_ne!(base, qub_id(version, content_type, created_at, unlock_at, None, round, &alt_bh, &title_hash(None)));
    }

    // 11. Unlock-round monotonicity: for fixed genesis/period, a larger
    //     unlock_at yields a non-decreasing round.
    #[test]
    fn unlock_round_is_monotonic(
        genesis in 1_000_000i64..2_000_000i64,
        period in 1u64..600u64,
        t1 in 2_000_001i64..3_000_000i64,
        delta in 0i64..1_000_000i64,
    ) {
        let t2 = t1 + delta;
        let r1 = unlock_round(t1, genesis, period).unwrap();
        let r2 = unlock_round(t2, genesis, period).unwrap();
        prop_assert!(r2 >= r1);
    }

    // 12. Unlock-round coverage: any t in [genesis + (R-1)*period,
    //     genesis + R*period) with t > genesis maps to round R — the
    //     §4.3 current-round mapping (round R is published at
    //     genesis + (R-1)*period).
    #[test]
    fn unlock_round_coverage(
        genesis in 1_000_000i64..2_000_000i64,
        period in 1u64..600u64,
        r in 1i64..1_000_000i64,
        offset_frac in 0i64..i64::MAX,
    ) {
        // offset ∈ [0, period - 1]; t = genesis + (r-1)*period + offset
        // lies in the interval that MUST map to round r (skipping the
        // single invalid point t == genesis).
        let period_i = period.cast_signed();
        let offset = offset_frac.rem_euclid(period_i);
        let t = genesis + (r - 1) * period_i + offset;
        prop_assume!(t > genesis);
        let round = unlock_round(t, genesis, period).unwrap();
        prop_assert_eq!(round, r.cast_unsigned());
    }
}

// -----------------------------------------------------------------------------
// 10. body_hash collision-resistance sanity check
// -----------------------------------------------------------------------------

#[test]
fn body_hash_is_injective_on_distinct_inputs() {
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for i in 0..100u32 {
        let input = format!("body-{i}-{}", i.wrapping_mul(2_654_435_761));
        let h = body_hash(input.as_bytes());
        assert!(seen.insert(h), "duplicate body_hash at i={i}");
    }
    assert_eq!(seen.len(), 100);
}

// -----------------------------------------------------------------------------
// Additional sanity checks tying modules together
// -----------------------------------------------------------------------------

#[test]
fn envelope_body_hash_matches_body_hash_fn() {
    let body = b"deterministic".to_vec();
    let env = build_envelope(body.clone(), 1_000_000_000, 2_000_000_000, None);
    assert_eq!(env.body_hash(), &body_hash(&body));
}

#[test]
fn envelope_qub_id_matches_derivation() {
    let body = b"derivation".to_vec();
    let env = build_envelope(body.clone(), 1_000_000_000, 2_000_000_000, None);
    let bh = body_hash(&body);
    let expected = qub_id(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        1_000_000_000,
        2_000_000_000,
        None,
        4_675_285,
        &bh,
        &title_hash(None),
    );
    assert_eq!(env.qub_id(), &expected);
}

#[test]
fn wire_newtype_bytes_match_direct_serialisation() {
    let env = build_envelope(b"match".to_vec(), 1_000_000_000, 2_000_000_000, None);
    let direct = serialize_qub_envelope(&env).unwrap();
    let via_newtype = QubEnvelopeCbor::from_qub_envelope(&env).unwrap();
    assert_eq!(via_newtype.as_bytes(), &direct[..]);
}

// =============================================================================
// B2/B3 — Seal & Unlock end-to-end integration tests
// =============================================================================

const GENESIS: i64 = 1_595_431_050;
const PERIOD: u64 = 30;
const CHAIN_ID: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// Full pipeline with mock: compose → seal → serialize → deserialize → unlock
/// → verify all fields match.
#[test]
fn seal_unlock_full_pipeline_mock() {
    let now = 1_700_000_000;
    let unlock_at = now + 7 * 86_400;
    let body = b"Integration test body.".to_vec();

    // Compose
    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);
    draft.set_sender_label(Some("IntegrationAlice".into()));

    // Seal
    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // Wire round-trip: serialise → bytes → deserialise.
    let bytes = seal_out.sealed_cbor.as_bytes().to_vec();
    let received = SealedQubCbor::from_encoded(bytes).unwrap();

    // Unlock
    let revealed = unlock(UnlockInput {
        sealed_cbor: &received,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-integration".into(),
        tlock: &tlock,
    })
    .unwrap();

    // Verify every field.
    assert_eq!(revealed.body(), body.as_slice());
    assert_eq!(revealed.qub_id(), &seal_out.qub_id);
    assert_eq!(revealed.created_at(), now);
    assert_eq!(revealed.unlock_at(), unlock_at);
    assert_eq!(revealed.sender_label(), Some("IntegrationAlice"));
    assert_eq!(revealed.drand_chain_id(), CHAIN_ID);
    assert_eq!(revealed.drand_round(), seal_out.drand_round);
    assert!(revealed.body_hash_verified());
    assert_eq!(revealed.signature_verified(), None);
    assert_eq!(revealed.arweave_tx_id(), "tx-integration");
    assert_eq!(revealed.visibility(), VISIBILITY_PUBLIC);
}

// A verdict qub (content type 0x04) must survive the full seal → wire →
// unlock pipeline. Regression test: the unlock step-13 allowlist once
// omitted CONTENT_TYPE_VERDICT while `validate_for_tier` accepted it,
// so every sealed verdict was a permanently unviewable artifact.
#[test]
fn verdict_seal_unlock_round_trip() {
    use qub_core::types::CONTENT_TYPE_VERDICT;
    use qub_core::verdict::{
        VERDICT_VERSION_1, VerdictBodyBuilder, VerdictOutcome, parse_verdict_body,
        serialize_verdict_body,
    };

    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let verdict = VerdictBodyBuilder::new()
        .verdict_version(VERDICT_VERSION_1)
        .outcome(VerdictOutcome::Right)
        .reflection(Some("Called it.".into()))
        .build()
        .unwrap();
    let body = serialize_verdict_body(&verdict).unwrap();

    let mut draft = ComposeQub::new(CONTENT_TYPE_VERDICT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    let bytes = seal_out.sealed_cbor.as_bytes().to_vec();
    let received = SealedQubCbor::from_encoded(bytes).unwrap();

    let revealed = unlock(UnlockInput {
        sealed_cbor: &received,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-verdict".into(),
        tlock: &tlock,
    })
    .unwrap();

    assert_eq!(revealed.content_type(), CONTENT_TYPE_VERDICT);
    assert_eq!(revealed.body(), body.as_slice());
    let parsed = parse_verdict_body(revealed.body()).unwrap();
    assert_eq!(parsed.outcome(), VerdictOutcome::Right);
    assert_eq!(parsed.reflection(), Some("Called it."));
}

// =============================================================================
// G1 — End-to-end integration tests
// =============================================================================

// Full lifecycle: seal -> serialize -> deserialize -> unlock -> verify all fields.
// Uses real DrandTimelockProvider to prove the full cryptographic pipeline.
#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn full_lifecycle_seal_to_reveal() {
    use qub_core::tlock::DrandTimelockProvider;

    const QN_GENESIS: i64 = 1_692_803_367;
    const QN_PERIOD: u64 = 3;
    const ROUND: u64 = 1000;
    const ROUND_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

    // unlock_at chosen so the §4.3 current-round mapping targets ROUND:
    // floor((unlock_at - genesis) / period) + 1 = 1000.
    let unlock_at = QN_GENESIS + i64::try_from((ROUND - 1) * QN_PERIOD).unwrap();
    let now = unlock_at - 1;
    let body = b"Full lifecycle test content".to_vec();

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);
    draft.set_sender_label(Some("lifecycle-sender".into()));

    let tlock = DrandTimelockProvider::quicknet();
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // Simulate Arweave storage: raw bytes round-trip
    let wire_bytes = seal_out.sealed_cbor.as_bytes().to_vec();
    let fetched = SealedQubCbor::from_encoded(wire_bytes).unwrap();

    let round_sig = hex::decode(ROUND_SIG_HEX).unwrap();
    let revealed = unlock(UnlockInput {
        sealed_cbor: &fetched,
        round_signature: &round_sig,
        now: unlock_at,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        arweave_tx_id: "tx-lifecycle".into(),
        tlock: &tlock,
    })
    .unwrap();

    // Verify all fields
    assert_eq!(revealed.body(), body.as_slice());
    assert!(revealed.body_hash_verified());
    assert_eq!(revealed.qub_id(), &seal_out.qub_id);
    assert_eq!(revealed.unlock_at(), unlock_at);
    assert_eq!(revealed.created_at(), now);
    assert_eq!(revealed.sender_label(), Some("lifecycle-sender"));
    assert_eq!(revealed.drand_round(), seal_out.drand_round);
    assert_eq!(revealed.drand_chain_id(), CHAIN_ID);
    assert_eq!(revealed.visibility(), VISIBILITY_PUBLIC);
    assert_eq!(revealed.arweave_tx_id(), "tx-lifecycle");
}

// Early unlock rejection: attempt unlock before unlock_at -> StillLocked.
#[test]
fn unlock_before_time_fails() {
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 365 * 86_400; // 1 year in the future
    let body = b"not yet".to_vec();

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body);
    draft.set_unlock_at(unlock_at);

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    let too_early = unlock_at - 1;
    let err = unlock(UnlockInput {
        sealed_cbor: &seal_out.sealed_cbor,
        round_signature: &[],
        now: too_early,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-early".into(),
        tlock: &tlock,
    })
    .unwrap_err();

    assert!(
        matches!(err, UnlockError::StillLocked { unlock_at: ua, now: n } if ua == unlock_at && n == too_early)
    );
}

// Independent viewer decryption: two separate MockTimelockProvider instances
// prove no shared state is needed.
#[test]
fn viewer_can_decrypt_independently() {
    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let body = b"independent decryption".to_vec();

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);

    // Seal with one provider instance
    let creator_tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &creator_tlock,
        signing: None,
    })
    .unwrap();

    // Unlock with a SEPARATE provider instance (simulates independent viewer)
    let viewer_tlock = MockTimelockProvider;
    let revealed = unlock(UnlockInput {
        sealed_cbor: &seal_out.sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-independent".into(),
        tlock: &viewer_tlock,
    })
    .unwrap();

    assert_eq!(revealed.body(), body.as_slice());
    assert!(revealed.body_hash_verified());
}

// Tampered ciphertext: flip bytes in tlock_ciphertext -> unlock fails.
#[test]
fn tampered_tlock_ciphertext_rejected() {
    let now = 1_700_000_000;
    let unlock_at = now + 86_400;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(b"tamper target".to_vec());
    draft.set_unlock_at(unlock_at);

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // Parse the sealed qub, tamper with ciphertext, re-serialize
    let sealed = seal_out.sealed_cbor.parse().unwrap();
    let mut tampered_ct = sealed.tlock_ciphertext().to_vec();
    // Flip several bytes to ensure corruption
    for b in tampered_ct.iter_mut().take(4) {
        *b ^= 0xFF;
    }

    // Build a new sealed qub with tampered ciphertext
    let tampered_sealed = SealedQubBuilder::new()
        .version(sealed.version())
        .qub_id(*sealed.qub_id())
        .visibility(sealed.visibility())
        .unlock_at(sealed.unlock_at())
        .drand_chain_id(sealed.drand_chain_id().to_string())
        .drand_round(sealed.drand_round())
        .tlock_ciphertext(tampered_ct)
        .build()
        .unwrap();
    let tampered_cbor = SealedQubCbor::from_sealed_qub(&tampered_sealed).unwrap();

    let result = unlock(UnlockInput {
        sealed_cbor: &tampered_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-tampered".into(),
        tlock: &tlock,
    });

    assert!(
        result.is_err(),
        "tampered ciphertext should cause unlock failure"
    );
}

// Unknown content type in ComposeQub is rejected at validation.
#[test]
fn unknown_content_type_in_compose_rejected() {
    use qub_core::types::QubError;

    let mut draft = ComposeQub::new(0xFF);
    draft.set_plaintext(b"some content".to_vec());
    draft.set_unlock_at(2_000_000_000);

    assert!(matches!(
        draft.validate(),
        Err(QubError::UnsupportedContentType(0xFF))
    ));
}

// Body exactly at free-tier limit (10,240 bytes) passes validation.
#[test]
fn body_size_at_free_limit_accepted() {
    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(vec![b'A'; 10_240]);
    draft.set_unlock_at(2_000_000_000);

    assert!(draft.validate().is_ok());
}

// Body one byte over free-tier limit (10,241 bytes) fails validation.
#[test]
fn body_size_over_free_limit_rejected() {
    use qub_core::types::QubError;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(vec![b'A'; 10_241]);
    draft.set_unlock_at(2_000_000_000);

    assert!(matches!(
        draft.validate(),
        Err(QubError::BodyTooLarge { .. })
    ));
}

// Wire round-trip preserves all fields including optional recipient_pubkey.
#[test]
fn sealed_cbor_wire_round_trip_preserves_all_fields() {
    let recipient_pk = [0xAB; 32];
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id([0xCD; 32])
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(1_800_000_000)
        .drand_chain_id("e".repeat(64))
        .drand_round(999_999)
        .tlock_ciphertext(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .recipient_pubkey(Some(recipient_pk))
        .build()
        .unwrap();

    let cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
    let bytes = cbor.as_bytes().to_vec();
    let parsed = SealedQubCbor::from_encoded(bytes).unwrap().parse().unwrap();

    assert_eq!(parsed.version(), sealed.version());
    assert_eq!(parsed.qub_id(), sealed.qub_id());
    assert_eq!(parsed.visibility(), sealed.visibility());
    assert_eq!(parsed.unlock_at(), sealed.unlock_at());
    assert_eq!(parsed.drand_chain_id(), sealed.drand_chain_id());
    assert_eq!(parsed.drand_round(), sealed.drand_round());
    assert_eq!(parsed.tlock_ciphertext(), sealed.tlock_ciphertext());
    assert_eq!(parsed.recipient_pubkey(), sealed.recipient_pubkey());
}

// Same content with different timestamps produces different qub_ids.
#[test]
fn same_content_different_times_produce_different_qub_ids() {
    let body = b"identical content".to_vec();
    let bh = body_hash(&body);

    let id1 = qub_id(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        1_700_000_000,
        1_800_000_000,
        None,
        4_695_445,
        &bh,
        &title_hash(None),
    );
    let id2 = qub_id(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        1_700_000_000,
        1_900_000_000,
        None,
        4_695_445,
        &bh,
        &title_hash(None),
    );
    let id3 = qub_id(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        1_700_000_001,
        1_800_000_000,
        None,
        4_695_445,
        &bh,
        &title_hash(None),
    );

    assert_ne!(
        id1, id2,
        "different unlock_at should produce different qub_ids"
    );
    assert_ne!(
        id1, id3,
        "different created_at should produce different qub_ids"
    );
}

/// Full pipeline with real `DrandTimelockProvider` using hardcoded
/// quicknet data — **Gate 1** evidence for native targets.
///
/// drand quicknet: genesis = 1692803367, period = 3s.
/// Round 1000 signature is publicly known and hardcoded.
#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn seal_unlock_full_pipeline_real_drand() {
    use qub_core::tlock::DrandTimelockProvider;

    // Quicknet chain parameters.
    const QN_GENESIS: i64 = 1_692_803_367;
    const QN_PERIOD: u64 = 3;
    const ROUND: u64 = 1000;
    // Round 1000 signature (public, immutable).
    const ROUND_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

    // Pick unlock_at that maps exactly to round 1000 under the §4.3
    // current-round formula: floor((unlock_at - genesis) / period) + 1 =
    // 1000 ⟹ unlock_at = genesis + 999 * 3. Round 1000 publishes exactly
    // at unlock_at.
    let unlock_at = QN_GENESIS + i64::try_from((ROUND - 1) * QN_PERIOD).unwrap();
    assert_eq!(unlock_round(unlock_at, QN_GENESIS, QN_PERIOD), Ok(ROUND));
    let now = unlock_at - 1;

    let body = b"Gate 1 evidence".to_vec();
    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);
    draft.set_sender_label(Some("drand-test".into()));

    let tlock = DrandTimelockProvider::quicknet();
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();
    assert_eq!(seal_out.drand_round, ROUND);

    let round_sig = hex::decode(ROUND_SIG_HEX).unwrap();
    let revealed = unlock(UnlockInput {
        sealed_cbor: &seal_out.sealed_cbor,
        round_signature: &round_sig,
        now: unlock_at,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        arweave_tx_id: "tx-gate1".into(),
        tlock: &tlock,
    })
    .unwrap();

    assert_eq!(revealed.body(), body.as_slice());
    assert_eq!(revealed.qub_id(), &seal_out.qub_id);
    assert_eq!(revealed.created_at(), now);
    assert_eq!(revealed.unlock_at(), unlock_at);
    assert_eq!(revealed.sender_label(), Some("drand-test"));
    assert!(revealed.body_hash_verified());
}

// =============================================================================
// C1 round-binding tests (the displayed unlock time must be the round that
// actually gates decryption)
// =============================================================================

/// drand quicknet chain hash — must be set on the sealed qub so the
/// chain-binding check (SEC-20) passes and the round-binding check (C1)
/// is the one that fires.
const QN_CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// C1: a `SealedQub` whose advisory `drand_round` metadata disagrees with
/// `unlock_round(unlock_at)` — beyond the one-round legacy tolerance — is
/// rejected (the cheap metadata branch).
#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn c1_round_binding_rejects_metadata_round_lie() {
    use qub_core::tlock::DrandTimelockProvider;
    use qub_core::unlock::UnlockError;

    const QN_GENESIS: i64 = 1_692_803_367;
    const QN_PERIOD: u64 = 3;
    const HONEST_ROUND: u64 = 1000;

    // unlock_at implies round 1000 under the §4.3 current-round mapping.
    let unlock_at = QN_GENESIS + i64::try_from((HONEST_ROUND - 1) * QN_PERIOD).unwrap();
    assert_eq!(
        unlock_round(unlock_at, QN_GENESIS, QN_PERIOD),
        Ok(HONEST_ROUND)
    );
    let tlock = DrandTimelockProvider::quicknet();
    let ciphertext = tlock.encrypt(b"anything", HONEST_ROUND).unwrap();

    // Advertise round 998 while unlock_at implies round 1000. (999 would
    // be inside the pre-V1.3 legacy tolerance — see the dedicated
    // legacy-round test below.)
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id([7u8; 32])
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(unlock_at)
        .drand_chain_id(QN_CHAIN_HASH.to_string())
        .drand_round(HONEST_ROUND - 2)
        .tlock_ciphertext(ciphertext)
        .build()
        .unwrap();
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

    let err = unlock(UnlockInput {
        sealed_cbor: &sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        arweave_tx_id: "tx".into(),
        tlock: &tlock,
    })
    .expect_err("metadata round lie must be rejected");
    assert!(
        matches!(
            err,
            UnlockError::DrandRoundMismatch {
                expected: 1000,
                actual: 998
            }
        ),
        "got: {err:?}"
    );
}

/// A3 legacy tolerance: a qub sealed under the pre-V1.3 `ceil` round
/// mapping — metadata AND ciphertext both bound to `expected - 1` for a
/// period-aligned `unlock_at` — still unlocks. The legacy round is baked
/// into its immutable `qub_id` preimage, so rejecting it would brick
/// every existing period-aligned qub.
#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn legacy_ceil_round_qub_still_unlocks() {
    use qub_core::tlock::DrandTimelockProvider;

    const QN_GENESIS: i64 = 1_692_803_367;
    const QN_PERIOD: u64 = 3;
    const LEGACY_ROUND: u64 = 1000; // pre-V1.3 ceil mapping for this unlock_at
    const ROUND_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

    // delta = 3000 (period-aligned): legacy ceil gave round 1000; the new
    // mapping gives 1001. The stored round is therefore expected - 1.
    let unlock_at = QN_GENESIS + i64::try_from(LEGACY_ROUND * QN_PERIOD).unwrap();
    assert_eq!(
        unlock_round(unlock_at, QN_GENESIS, QN_PERIOD),
        Ok(LEGACY_ROUND + 1)
    );
    let now = unlock_at - 1;
    let body = b"sealed under the old round mapping".to_vec();

    // Reconstruct what the pre-V1.3 seal pipeline produced: qub_id folds
    // the LEGACY round, and the ciphertext is bound to it.
    let (bh, id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        now,
        unlock_at,
        None,
        LEGACY_ROUND,
        &body,
        None,
    );
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(id)
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(now)
        .unlock_at(unlock_at)
        .body(body.clone())
        .body_hash(bh)
        .build()
        .unwrap();
    let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
    let tlock = DrandTimelockProvider::quicknet();
    let ct = tlock.encrypt(&envelope_cbor, LEGACY_ROUND).unwrap();
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(id)
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(unlock_at)
        .drand_chain_id(QN_CHAIN_HASH.to_string())
        .drand_round(LEGACY_ROUND)
        .tlock_ciphertext(ct)
        .build()
        .unwrap();
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

    let round_sig = hex::decode(ROUND_SIG_HEX).unwrap();
    let revealed = unlock(UnlockInput {
        sealed_cbor: &sealed_cbor,
        round_signature: &round_sig,
        now: unlock_at,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        arweave_tx_id: "tx-legacy-round".into(),
        tlock: &tlock,
    })
    .expect("legacy-round qub must stay unlockable");
    assert_eq!(revealed.body(), body.as_slice());
    assert_eq!(revealed.drand_round(), LEGACY_ROUND);
}

/// C1 (the load-bearing case): a `SealedQub` whose metadata round agrees
/// with `unlock_at` but whose tlock ciphertext is actually bound to a
/// different (already-past) round is rejected. This is the malicious-
/// creator scenario — a future countdown over a ciphertext anyone can
/// already decrypt. The stanza round is the cryptographically meaningful
/// one, so the check reads it back via `decrypt_header` and fires before
/// any decryption.
#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn c1_round_binding_rejects_stanza_round_lie() {
    use qub_core::tlock::DrandTimelockProvider;
    use qub_core::unlock::UnlockError;

    const QN_GENESIS: i64 = 1_692_803_367;
    const QN_PERIOD: u64 = 3;
    const STANZA_ROUND: u64 = 1000; // already-past round the ciphertext is really bound to
    const DISPLAYED_ROUND: u64 = 1001; // future round the countdown claims

    // unlock_at implies DISPLAYED_ROUND under the §4.3 current-round mapping.
    let unlock_at = QN_GENESIS + i64::try_from((DISPLAYED_ROUND - 1) * QN_PERIOD).unwrap();
    assert_eq!(
        unlock_round(unlock_at, QN_GENESIS, QN_PERIOD),
        Ok(DISPLAYED_ROUND)
    );

    let tlock = DrandTimelockProvider::quicknet();
    // Bind the ciphertext to the PAST round while the metadata is honest
    // about the displayed round, so the metadata branch passes and the
    // stanza branch must catch it. (Note the stanza check compares the
    // stanza against the METADATA round, so a stanza≠metadata split is
    // rejected even when the stanza would fall inside the metadata
    // branch's legacy tolerance.)
    let ciphertext = tlock.encrypt(b"already decryptable", STANZA_ROUND).unwrap();

    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id([7u8; 32])
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(unlock_at)
        .drand_chain_id(QN_CHAIN_HASH.to_string())
        .drand_round(DISPLAYED_ROUND)
        .tlock_ciphertext(ciphertext)
        .build()
        .unwrap();
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

    let err = unlock(UnlockInput {
        sealed_cbor: &sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: QN_GENESIS,
        chain_period_seconds: QN_PERIOD,
        arweave_tx_id: "tx".into(),
        tlock: &tlock,
    })
    .expect_err("stanza round lie must be rejected");
    assert!(
        matches!(
            err,
            UnlockError::DrandRoundMismatch {
                expected: 1001,
                actual: 1000
            }
        ),
        "got: {err:?}"
    );
}

// =============================================================================
// Mutation-resistance tests
// =============================================================================

/// Mutation-resistance: verify that the `body_hash` check in `unlock()`
/// actually catches mismatches. If the check were removed, this test
/// would pass — it specifically tests that a tampered `body_hash` is
/// detected.
#[test]
fn mutation_body_hash_check_is_enforced() {
    use qub_core::cbor::serialize_qub_envelope;
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 3600;
    let body = b"integrity-check body".to_vec();
    let (_bh, id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        now,
        unlock_at,
        None,
        4_695_445,
        &body,
        None,
    );
    // Construct envelope with WRONG body_hash (all zeros).
    let wrong_hash = [0u8; 32];
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
    assert!(
        matches!(err, UnlockError::BodyHashMismatch),
        "body_hash check must be enforced, got: {err:?}"
    );
}

/// Mutation-resistance: verify that `qub_id` cross-check between
/// envelope and sealed is enforced in `unlock()`.
#[test]
fn mutation_qub_id_cross_check_is_enforced() {
    use qub_core::cbor::serialize_qub_envelope;
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 3600;
    let body = b"qub-id-check".to_vec();
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

    // Use a DIFFERENT qub_id in the sealed qub.
    let mut wrong_id = id;
    wrong_id[31] ^= 0xFF;
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(wrong_id)
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
    assert!(
        matches!(err, UnlockError::QubIdMismatch),
        "qub_id cross-check must be enforced, got: {err:?}"
    );
}

/// Mutation-resistance: verify that `unlock_at` cross-check between
/// envelope and sealed is enforced in `unlock()`.
#[test]
fn mutation_unlock_at_cross_check_is_enforced() {
    use qub_core::cbor::serialize_qub_envelope;
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let env_unlock = now + 3600;
    let sealed_unlock = now + 7200;
    let body = b"unlock-at-check".to_vec();
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
        .unlock_at(sealed_unlock) // DIFFERENT from envelope
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
    assert!(
        matches!(err, UnlockError::UnlockAtMismatch),
        "unlock_at cross-check must be enforced, got: {err:?}"
    );
}

/// Mutation-resistance: verify content type check rejects non-text types.
#[test]
fn mutation_content_type_check_is_enforced() {
    use qub_core::cbor::serialize_qub_envelope;
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 3600;
    let body = b"content-type-check".to_vec();
    // Use 0x02 (voice) — valid for builder but unsupported for unlock.
    let (bh, id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        0x02,
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
        .content_type(0x02)
        .created_at(now)
        .unlock_at(unlock_at)
        .body(body)
        .body_hash(bh)
        .build()
        .unwrap();
    let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
    let tlock = MockTimelockProvider;
    let ct = tlock.encrypt(&envelope_cbor, 1).unwrap();
    // drand_round matches the round folded into the qub_id above so the
    // step-12c content re-derivation passes and the content-type check
    // is the one that fires.
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
    assert!(
        matches!(err, UnlockError::UnsupportedContentType(0x02)),
        "content type check must be enforced, got: {err:?}"
    );
}

/// Mutation-resistance: verify version check rejects version 0x02.
#[test]
fn mutation_version_check_is_enforced_via_sealed() {
    // Craft a CBOR map with version = 0x02.
    use ciborium::{Value, cbor};
    let map = cbor!({
        "version" => 2u8,
        "qub_id" => Value::Bytes(vec![0u8; 32]),
        "visibility" => 1u8,
        "unlock_at" => 1_700_000_000i64,
        "drand_chain_id" => "chain",
        "drand_round" => 1u64,
        "tlock_ciphertext" => Value::Bytes(vec![0xAA; 4]),
    })
    .unwrap();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).unwrap();
    let sealed_cbor = SealedQubCbor::from_encoded(buf).unwrap();
    let tlock = MockTimelockProvider;
    let result = unlock(UnlockInput {
        sealed_cbor: &sealed_cbor,
        round_signature: &[],
        now: 2_000_000_000,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx".into(),
        tlock: &tlock,
    });
    assert!(result.is_err(), "version 0x02 must be rejected");
}

/// CBOR key order is canonical: serialize → parse raw CBOR → verify keys
/// are in the normative order from PROTOCOL.md §3.2.
#[test]
fn cbor_envelope_key_order_is_canonical() {
    let env = build_envelope(
        b"key order test".to_vec(),
        1_700_000_000,
        1_800_000_000,
        Some("sender".to_string()),
    );
    let bytes = serialize_qub_envelope(&env).unwrap();

    // Parse raw CBOR to inspect key order.
    let value: ciborium::Value = ciborium::de::from_reader(&bytes[..]).unwrap();
    let ciborium::Value::Map(entries) = value else {
        panic!("expected map");
    };

    let keys: Vec<String> = entries
        .iter()
        .filter_map(|(k, _)| {
            if let ciborium::Value::Text(s) = k {
                Some(s.clone())
            } else {
                None
            }
        })
        .collect();

    // Canonical order: sorted by encoded byte length, then lexicographically.
    // For text keys: length = 1 + key.len() for keys < 24 bytes.
    for pair in keys.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        let ord = a
            .len()
            .cmp(&b.len())
            .then_with(|| a.as_bytes().cmp(b.as_bytes()));
        assert!(
            ord.is_lt(),
            "canonical key order violated: {a:?} must come before {b:?}"
        );
    }
}

/// CBOR key order for `SealedQub` is canonical.
#[test]
fn cbor_sealed_key_order_is_canonical() {
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id([0x42; 32])
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(1_800_000_000)
        .drand_chain_id("a".repeat(64))
        .drand_round(999)
        .tlock_ciphertext(vec![0xAA; 16])
        .build()
        .unwrap();
    let bytes = qub_core::cbor::serialize_sealed_qub(&sealed).unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(&bytes[..]).unwrap();
    let ciborium::Value::Map(entries) = value else {
        panic!("expected map");
    };

    let keys: Vec<String> = entries
        .iter()
        .filter_map(|(k, _)| {
            if let ciborium::Value::Text(s) = k {
                Some(s.clone())
            } else {
                None
            }
        })
        .collect();

    for pair in keys.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        let ord = a
            .len()
            .cmp(&b.len())
            .then_with(|| a.as_bytes().cmp(b.as_bytes()));
        assert!(
            ord.is_lt(),
            "canonical key order violated: {a:?} must come before {b:?}"
        );
    }
}

/// Multiple qubs sealed in sequence have distinct `qub_id` values and ciphertexts.
#[test]
fn sequential_seals_produce_distinct_qub_ids() {
    let tlock = MockTimelockProvider;
    let now = 1_700_000_000;
    let mut ids = std::collections::HashSet::new();
    let mut ciphertexts = std::collections::HashSet::new();

    for i in 0..5u32 {
        let body = format!("body-{i}");
        let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
        draft.set_plaintext(body.into_bytes());
        draft.set_unlock_at(now + 3600 + i64::from(i));

        let out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        })
        .unwrap();

        assert!(ids.insert(out.qub_id), "qub_id collision at iteration {i}");
        assert!(
            ciphertexts.insert(out.sealed_cbor.as_bytes().to_vec()),
            "ciphertext collision at iteration {i}"
        );
    }
}

/// Seal with Unicode/emoji in `sender_label` — verify round-trip through
/// seal/unlock preserves the label exactly.
#[test]
fn unicode_sender_label_preserved() {
    let tlock = MockTimelockProvider;
    let now = 1_700_000_000;
    let unlock_at = now + 3600;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(b"unicode test".to_vec());
    draft.set_unlock_at(unlock_at);
    draft.set_sender_label(Some("\u{1F600} Héllo Wörld".into()));

    let out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    let revealed = unlock(UnlockInput {
        sealed_cbor: &out.sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx".into(),
        tlock: &tlock,
    })
    .unwrap();

    assert_eq!(revealed.sender_label(), Some("\u{1F600} Héllo Wörld"));
}

/// Seal at exact body size limit (10,240 bytes for free-tier text).
#[test]
fn seal_at_exact_body_limit() {
    let tlock = MockTimelockProvider;
    let now = 1_700_000_000;
    let unlock_at = now + 3600;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(vec![b'A'; 10_240]);
    draft.set_unlock_at(unlock_at);

    let out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    });
    assert!(out.is_ok(), "exactly at body limit should succeed");
}

/// Seal one byte over body size limit — must fail.
#[test]
fn seal_one_byte_over_body_limit() {
    use qub_core::seal::SealError;
    use qub_core::types::QubError;

    let tlock = MockTimelockProvider;
    let now = 1_700_000_000;
    let unlock_at = now + 3600;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(vec![b'A'; 10_241]);
    draft.set_unlock_at(unlock_at);

    let err = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap_err();
    assert!(
        matches!(err, SealError::Validation(QubError::BodyTooLarge { .. })),
        "expected BodyTooLarge, got: {err:?}"
    );
}

// =============================================================================
// Additional property tests
// =============================================================================

proptest! {
    #![proptest_config(common::config(256))]

    /// Any valid ComposeQub that passes validate() can be sealed and
    /// unsealed with MockTimelockProvider, recovering ALL original fields.
    #[test]
    fn valid_compose_roundtrips_all_fields(
        body in common::text_compose_body_bytes(),
        unlock_offset in 3600i64..315_360_000i64,
        sender_label in common::sender_label(),
    ) {
        let now = 1_700_000_000i64;
        let unlock_at = now + unlock_offset;

        let mut draft = ComposeQub::with_draft_id([0x42; 16], CONTENT_TYPE_TEXT);
        draft.set_plaintext(body.clone());
        draft.set_unlock_at(unlock_at);
        draft.set_sender_label(sender_label.clone());
        draft.validate().unwrap();

        let tlock = MockTimelockProvider;
        let out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        }).unwrap();

        let expected_round = unlock_round(unlock_at, GENESIS, PERIOD).unwrap();

        let revealed = unlock(UnlockInput {
            sealed_cbor: &out.sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx-prop".into(),
            tlock: &tlock,
        }).unwrap();

        // Body integrity
        prop_assert_eq!(revealed.body(), body.as_slice());
        prop_assert!(revealed.body_hash_verified());
        // Metadata preservation
        prop_assert_eq!(revealed.created_at(), now);
        prop_assert_eq!(revealed.unlock_at(), unlock_at);
        prop_assert_eq!(revealed.qub_id(), &out.qub_id);
        prop_assert_eq!(revealed.drand_round(), expected_round);
        prop_assert_eq!(revealed.drand_round(), out.drand_round);
        prop_assert_eq!(revealed.visibility(), VISIBILITY_PUBLIC);
        // NFC again: the wire carries the normalised form (see
        // `envelope_cbor_round_trip`).
        let expected_label: Option<String> =
            sender_label.as_deref().map(|s| s.nfc().collect());
        prop_assert_eq!(revealed.sender_label(), expected_label.as_deref());
    }

    /// body_hash collision resistance: different bodies always produce
    /// different hashes.
    #[test]
    fn body_hash_collision_resistance(
        body_a in proptest::collection::vec(any::<u8>(), 1..500),
        body_b in proptest::collection::vec(any::<u8>(), 1..500),
    ) {
        if body_a != body_b {
            prop_assert_ne!(body_hash(&body_a), body_hash(&body_b));
        }
    }

    /// qub_id is pure (deterministic): same inputs always produce same output.
    #[test]
    fn qub_id_is_pure(
        version in any::<u8>(),
        content_type in any::<u8>(),
        created_at in any::<i64>(),
        unlock_at_val in any::<i64>(),
        body in proptest::collection::vec(any::<u8>(), 1..100),
    ) {
        let bh = body_hash(&body);
        let id1 = qub_id(version, content_type, created_at, unlock_at_val, None, 4_695_445, &bh, &title_hash(None));
        let id2 = qub_id(version, content_type, created_at, unlock_at_val, None, 4_695_445, &bh, &title_hash(None));
        prop_assert_eq!(id1, id2);
    }

    /// Seal output is already in canonical CBOR form: re-serialising a
    /// parsed seal output produces byte-identical output.
    #[test]
    fn seal_output_is_canonical_cbor(
        body in proptest::collection::vec(1u8..=255, 1..=10_240),
        unlock_offset in 3600i64..315_360_000i64,
    ) {
        let now = 1_700_000_000i64;
        let unlock_at = now + unlock_offset;

        let mut draft = ComposeQub::with_draft_id([0xAA; 16], CONTENT_TYPE_TEXT);
        draft.set_plaintext(body);
        draft.set_unlock_at(unlock_at);

        let tlock = MockTimelockProvider;
        let out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        }).unwrap();

        let original_bytes = out.sealed_cbor.as_bytes().to_vec();
        let parsed = out.sealed_cbor.parse().unwrap();
        let re_encoded = SealedQubCbor::from_sealed_qub(&parsed).unwrap();
        prop_assert_eq!(original_bytes, re_encoded.as_bytes().to_vec());
    }

    /// unlock_round current-round semantics (§4.3): drand publishes
    /// round N at genesis + (N-1)*period, and the selected round is the
    /// one current at unlock_at — published at or before unlock_at,
    /// with the NEXT round strictly after. For period-aligned
    /// unlock_at (the reference deployment: quicknet genesis is
    /// period-aligned and the app pins whole-minute unlock times) this
    /// pins the A3 property: the gating signature is first published
    /// exactly AT unlock_at, never before it.
    #[test]
    fn unlock_round_current_round_semantics(
        genesis in 1_000_000i64..2_000_000i64,
        period in 1u64..600u64,
        unlock_at in 2_000_001i64..3_000_000i64,
    ) {
        let r = unlock_round(unlock_at, genesis, period).unwrap();
        let period_i = period.cast_signed();
        // drand publishes round N at genesis + (N - 1) * period.
        let publish_time = genesis + (i64::try_from(r).unwrap() - 1) * period_i;
        // The selected round is current at unlock_at…
        prop_assert!(publish_time <= unlock_at, "publish_time {publish_time} > unlock_at {unlock_at}");
        // …and the next round publishes strictly after unlock_at, so
        // earliness is strictly bounded by one period.
        prop_assert!(publish_time + period_i > unlock_at, "next round publishes at or before unlock_at");
        // Pinned A3 property: aligned unlock times are never decryptable
        // early — the gating signature publishes exactly at unlock_at.
        if (unlock_at - genesis) % period_i == 0 {
            prop_assert_eq!(publish_time, unlock_at);
        }
    }
}

// =============================================================================
// Negative property tests — seal rejects invalid inputs
// =============================================================================

proptest! {
    #![proptest_config(common::config(128))]

    /// Seal always rejects empty body, regardless of other parameters.
    #[test]
    fn seal_rejects_empty_body(
        unlock_offset in 3600i64..315_360_000i64,
    ) {
        let now = 1_700_000_000i64;
        let unlock_at = now + unlock_offset;

        let mut draft = ComposeQub::with_draft_id([0xBB; 16], CONTENT_TYPE_TEXT);
        draft.set_unlock_at(unlock_at);
        // plaintext left empty

        let tlock = MockTimelockProvider;
        let result = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        });
        prop_assert!(result.is_err(), "seal must reject empty body");
    }

    /// Seal always rejects unlock_at in the past or equal to now.
    #[test]
    fn seal_rejects_unlock_not_in_future(
        body in proptest::collection::vec(1u8..=255, 1..=100),
        offset in 0i64..1_000_000i64,
    ) {
        let now = 1_700_000_000i64;
        let unlock_at = now - offset; // at or before now

        let mut draft = ComposeQub::with_draft_id([0xCC; 16], CONTENT_TYPE_TEXT);
        draft.set_plaintext(body);
        draft.set_unlock_at(unlock_at);

        let tlock = MockTimelockProvider;
        let result = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        });
        prop_assert!(result.is_err(), "seal must reject unlock_at <= now");
    }
}

// -----------------------------------------------------------------------------
// Authorship signing — PROTOCOL.md §9
// -----------------------------------------------------------------------------

mod signing_tests {
    use qub_core::cbor::{deserialize_qub_envelope, serialize_qub_envelope};
    use qub_core::seal::{SealInput, SigningParams, seal};
    use qub_core::signing::{
        AUTHOR_SIG_DOMAIN_SEPARATOR, ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
        SIG_ALG_ML_DSA_65, compute_sig_input, generate_keypair, sign, sign_envelope, verify,
    };
    use qub_core::tlock::MockTimelockProvider;
    use qub_core::types::{
        CONTENT_TYPE_TEXT, ComposeQub, PROTOCOL_VERSION_1, QubEnvelopeBuilder, QubError,
    };
    use qub_core::unlock::{UnlockError, UnlockInput, unlock};

    const GENESIS: i64 = 1_595_431_050;
    const PERIOD: u64 = 30;
    const CHAIN_ID: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

    // ---- sig_input primitive ---------------------------------------------

    #[test]
    fn sig_input_domain_separator_bytes() {
        // PROTOCOL.md §9.3 byte list (authoritative).
        assert_eq!(
            AUTHOR_SIG_DOMAIN_SEPARATOR, b"QUB_AUTHOR_SIG_V1",
            "domain separator literal must match spec"
        );
        assert_eq!(AUTHOR_SIG_DOMAIN_SEPARATOR.len(), 17);
    }

    #[test]
    fn sig_input_deterministic() {
        let a = compute_sig_input(1, &[0xAA; 32], &[0xBB; 32], 1_800_000_000);
        let b = compute_sig_input(1, &[0xAA; 32], &[0xBB; 32], 1_800_000_000);
        assert_eq!(a, b);
    }

    #[test]
    fn sig_input_varies_with_every_field() {
        let base = compute_sig_input(1, &[1u8; 32], &[2u8; 32], 1_800_000_000);
        let diff_ver = compute_sig_input(2, &[1u8; 32], &[2u8; 32], 1_800_000_000);
        let mut other_id = [1u8; 32];
        other_id[0] = 9;
        let diff_id = compute_sig_input(1, &other_id, &[2u8; 32], 1_800_000_000);
        let mut other_body = [2u8; 32];
        other_body[31] = 9;
        let diff_body = compute_sig_input(1, &[1u8; 32], &other_body, 1_800_000_000);
        let diff_unlock = compute_sig_input(1, &[1u8; 32], &[2u8; 32], 1_800_000_001);
        assert_ne!(base, diff_ver);
        assert_ne!(base, diff_id);
        assert_ne!(base, diff_body);
        assert_ne!(base, diff_unlock);
    }

    #[test]
    fn sig_input_pinned_test_vector() {
        // Pinned vector: if the preimage construction changes, this
        // assertion breaks and the change is caught in code review.
        // Inputs chosen so every byte of the preimage is distinct
        // from zero.
        let version: u8 = 1;
        let qub_id = [0x11; 32];
        let body_hash = [0x22; 32];
        let unlock_at: i64 = 1_800_000_000;
        let got = compute_sig_input(version, &qub_id, &body_hash, unlock_at);
        // Value computed once and pinned. If any constant in §9.3
        // changes (domain separator, byte order, org_id_present byte),
        // this expectation must be updated in lock-step with the spec.
        let expected_hex = "3ef6cf480ab978a2e8abf554f82bf39bac58120df75dcab4b2ec158b1f1257ae";
        assert_eq!(
            hex::encode(got),
            expected_hex,
            "sig_input preimage construction regression"
        );
    }

    // ---- sign / verify primitives ----------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let sig_input = compute_sig_input(1, &[0x33; 32], &[0x44; 32], 1_800_000_000);
        let sig = sign(&sk, &sig_input).expect("sign");
        assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_SIZE);
        assert_eq!(pk.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert!(verify(&pk, &sig_input, &sig).expect("verify"));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn verify_rejects_wrong_key() {
        let (_pk_a, sk_a) = generate_keypair().expect("keygen a");
        let (pk_b, _sk_b) = generate_keypair().expect("keygen b");
        let sig_input = compute_sig_input(1, &[0xAA; 32], &[0xBB; 32], 1_800_000_000);
        let sig = sign(&sk_a, &sig_input).expect("sign");
        assert!(!verify(&pk_b, &sig_input, &sig).expect("verify"));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn verify_rejects_tampered_sig_input() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let good = compute_sig_input(1, &[0x55; 32], &[0x66; 32], 1_800_000_000);
        let bad = compute_sig_input(1, &[0x55; 32], &[0x66; 32], 1_800_000_001);
        let sig = sign(&sk, &good).expect("sign");
        assert!(!verify(&pk, &bad, &sig).expect("verify"));
    }

    #[test]
    fn verify_rejects_wrong_lengths() {
        let err = verify(&[0u8; 5], &[0u8; 32], &[0u8; ML_DSA_65_SIGNATURE_SIZE]).unwrap_err();
        assert!(matches!(
            err,
            QubError::WrongSignatureLength {
                field: "public_key",
                ..
            }
        ));

        let err = verify(&[0u8; ML_DSA_65_PUBLIC_KEY_SIZE], &[0u8; 32], &[0u8; 5]).unwrap_err();
        assert!(matches!(
            err,
            QubError::WrongSignatureLength {
                field: "signature",
                ..
            }
        ));
    }

    // ---- sign_envelope convenience --------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn sign_envelope_returns_ml_dsa_65_tuple() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let (alg, sig, pk_out) = sign_envelope(
            1,
            &[0x77; 32],
            &[0x88; 32],
            1_800_000_000,
            Some("Alice"),
            None,
            &sk,
            &pk,
        )
        .expect("sign");
        assert_eq!(alg, SIG_ALG_ML_DSA_65);
        assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_SIZE);
        assert_eq!(pk_out, pk);
        // sign_envelope commits to the V2 preimage (sender_label +
        // reply_to covered), not the legacy V1 preimage.
        let v2 = qub_core::signing::compute_sig_input_v2(
            1,
            &[0x77; 32],
            &[0x88; 32],
            1_800_000_000,
            Some("Alice"),
            None,
        );
        assert!(verify(&pk, &v2, &sig).expect("verify"));
        let v1 = compute_sig_input(1, &[0x77; 32], &[0x88; 32], 1_800_000_000);
        assert!(!verify(&pk, &v1, &sig).expect("verify"));
    }

    // ---- signed seal / unlock round-trip --------------------------------

    fn sample_draft(plaintext: &[u8], unlock_at: i64) -> ComposeQub {
        let mut d = ComposeQub::new(CONTENT_TYPE_TEXT);
        d.set_plaintext(plaintext.to_vec());
        d.set_unlock_at(unlock_at);
        d.set_sender_label(Some("Alice".into()));
        d
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn signed_seal_unlock_reports_verified() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let draft = sample_draft(b"signed payload", unlock_at);
        let tlock = MockTimelockProvider;
        let out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: Some(SigningParams {
                secret_key: &sk,
                public_key: &pk,
            }),
        })
        .expect("seal");

        let revealed = unlock(UnlockInput {
            sealed_cbor: &out.sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .expect("unlock");
        assert_eq!(revealed.signature_verified(), Some(true));
        assert_eq!(
            revealed.author_pubkey().map(<[u8]>::len),
            Some(ML_DSA_65_PUBLIC_KEY_SIZE)
        );
        assert_eq!(
            revealed.author_signature().map(<[u8]>::len),
            Some(ML_DSA_65_SIGNATURE_SIZE)
        );
    }

    #[test]
    fn unsigned_seal_unlock_reports_none() {
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let draft = sample_draft(b"unsigned payload", unlock_at);
        let tlock = MockTimelockProvider;
        let out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        })
        .expect("seal");
        let revealed = unlock(UnlockInput {
            sealed_cbor: &out.sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .expect("unlock");
        assert_eq!(revealed.signature_verified(), None);
        assert!(revealed.author_pubkey().is_none());
        assert!(revealed.author_signature().is_none());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn signed_envelope_cbor_roundtrip_preserves_signing_fields() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let sig_input = compute_sig_input(1, &[0x99; 32], &[0xAA; 32], 2_000_000_000);
        let sig = sign(&sk, &sig_input).expect("sign");

        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x99; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(1_700_000_000)
            .unlock_at(2_000_000_000)
            .body(b"hello".to_vec())
            .body_hash([0xAA; 32])
            .sig_alg(SIG_ALG_ML_DSA_65)
            .author_pubkey(Some(pk.clone()))
            .author_signature(Some(sig.clone()))
            .build()
            .expect("build");

        let bytes = serialize_qub_envelope(&envelope).expect("serialize");
        let decoded = deserialize_qub_envelope(&bytes).expect("deserialize");
        assert_eq!(decoded.sig_alg(), SIG_ALG_ML_DSA_65);
        assert_eq!(decoded.author_pubkey(), Some(pk.as_slice()));
        assert_eq!(decoded.author_signature(), Some(sig.as_slice()));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn signed_envelope_canonical_key_order() {
        // With sig_alg = 1 and both pubkey + signature populated, the
        // encoded CBOR must contain the text keys in §3.2 order:
        // body, qub_id, sig_alg, version, body_hash, unlock_at,
        // created_at, content_type, [sender_label], author_pubkey,
        // author_signature.
        let (pk, sk) = generate_keypair().expect("keygen");
        let sig_input = compute_sig_input(1, &[0x11; 32], &[0x22; 32], 1_800_000_000);
        let sig = sign(&sk, &sig_input).expect("sign");
        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x11; 32])
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(1_700_000_000)
            .unlock_at(1_800_000_000)
            .body(b"k".to_vec())
            .body_hash([0x22; 32])
            .sig_alg(SIG_ALG_ML_DSA_65)
            .author_pubkey(Some(pk))
            .author_signature(Some(sig))
            .build()
            .expect("build");
        let bytes = serialize_qub_envelope(&envelope).expect("serialize");

        // Find each expected key's first occurrence offset (as a text
        // string) and assert the offsets are strictly increasing.
        let expected_order = [
            "body",
            "qub_id",
            "sig_alg",
            "version",
            "body_hash",
            "unlock_at",
            "created_at",
            "content_type",
            "author_pubkey",
            "author_signature",
        ];
        let mut last = 0usize;
        for key in expected_order {
            let needle = key.as_bytes();
            let pos = bytes
                .windows(needle.len())
                .position(|w| w == needle)
                .unwrap_or_else(|| panic!("key {key} not found in CBOR"));
            assert!(
                pos >= last,
                "key {key} at {pos} is before previous key at {last}",
            );
            last = pos;
        }
    }

    #[test]
    fn unlock_rejects_unknown_sig_alg() {
        // Build an envelope with sig_alg = 0xFE (unknown), encrypt,
        // and seal. unlock() must reject with
        // QubError::UnknownSignatureAlgorithm.
        use qub_core::cbor::serialize_qub_envelope;
        use qub_core::hash::derive_envelope_hashes;
        use qub_core::tlock::TimelockProvider;
        use qub_core::types::{SealedQubBuilder, VISIBILITY_PUBLIC};
        use qub_core::wire::SealedQubCbor;

        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"unknown alg".to_vec();
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
            .sig_alg(0xFE)
            .build()
            .expect("build");
        let envelope_cbor = serialize_qub_envelope(&envelope).expect("serialize");
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).expect("encrypt");
        // drand_round matches the qub_id preimage input so the step-12c
        // re-derivation passes and the sig_alg check is what fires.
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(4_695_445)
            .tlock_ciphertext(ct)
            .build()
            .expect("sealed");
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).expect("cbor");
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
        assert!(matches!(
            err,
            UnlockError::Validation(QubError::UnknownSignatureAlgorithm(0xFE))
        ));
    }

    #[test]
    fn unlock_reports_failure_when_signed_but_fields_absent() {
        // sig_alg = 1 but no pubkey/signature → Some(false).
        use qub_core::cbor::serialize_qub_envelope;
        use qub_core::hash::derive_envelope_hashes;
        use qub_core::tlock::TimelockProvider;
        use qub_core::types::{SealedQubBuilder, VISIBILITY_PUBLIC};
        use qub_core::wire::SealedQubCbor;

        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"claim signed".to_vec();
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
            .sig_alg(SIG_ALG_ML_DSA_65)
            .build()
            .expect("build");
        let envelope_cbor = serialize_qub_envelope(&envelope).expect("serialize");
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, 1).expect("encrypt");
        // drand_round matches the qub_id preimage input so the step-12c
        // re-derivation passes and the absent-signature-material branch
        // is what this test exercises.
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(4_695_445)
            .tlock_ciphertext(ct)
            .build()
            .expect("sealed");
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).expect("cbor");
        let revealed = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx".into(),
            tlock: &tlock,
        })
        .expect("unlock");
        assert_eq!(revealed.signature_verified(), Some(false));
    }
}

// -----------------------------------------------------------------------------
// Brand-neutrality of the canonical wire format (FUTURE.md §15.4)
// -----------------------------------------------------------------------------
//
// White-label deployments depend on the wire format being free of qub-product
// brand references — any viewer (qub's or a white-label org's) must be able to
// render any qub from Arweave, regardless of which deployment sealed it. The
// only sanctioned occurrence of the byte sequence `b"qub"` is the protocol
// field key `qub_id`, which is the cryptographic identifier of a qub and is
// part of the protocol primitive's name (lowercase, like `ipfs cid`). Any new
// occurrence — a marker string, a header, a new field key — would be a brand
// regression that this test catches before it reaches Arweave.
mod brand_neutrality {
    use qub_core::cbor::{serialize_qub_envelope, serialize_sealed_qub};
    use qub_core::hash::derive_envelope_hashes;
    use qub_core::pact::{PactTerm, PactTermsBuilder, PartyIdentifier, serialize_pact_terms};
    use qub_core::signing::{
        ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, SIG_ALG_ML_DSA_65,
    };
    use qub_core::types::{
        CONTENT_TYPE_PACT, CONTENT_TYPE_TEXT, PROTOCOL_VERSION_1, QubEnvelopeBuilder,
        SealedQubBuilder, VISIBILITY_PUBLIC,
    };

    fn count_windows(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count()
    }

    /// Deterministic byte stream that provably never contains `b"qub"`.
    ///
    /// The pattern `0, 1, 2, 3, …, 255, 0, 1, …` increases monotonically
    /// (mod 256), so no three consecutive bytes can equal
    /// `[0x71, 0x75, 0x62]`.
    fn ramp_bytes(len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        let mut next: u8 = 0;
        for _ in 0..len {
            buf.push(next);
            next = next.wrapping_add(1);
        }
        buf
    }

    #[test]
    fn ramp_bytes_helper_is_qub_free() {
        // Self-test of the ramp helper. If this assertion ever fires, the
        // test fixtures below are no longer trustworthy.
        let buf = ramp_bytes(8192);
        assert_eq!(count_windows(&buf, b"qub"), 0);
    }

    #[test]
    fn envelope_wire_format_has_no_brand_byte_sequences() {
        // Maximally-populated envelope: every optional field set, including
        // a 32-byte reply_to and a full ML-DSA-65 pubkey + signature.
        // None of the user-supplied strings contain `b"qub"` so any
        // occurrence in the encoded bytes must be format-introduced.
        let body = b"Hello, future. The lock holds time.".to_vec();
        let created_at: i64 = 1_700_000_000;
        let unlock_at: i64 = 1_800_000_000;
        let (body_hash_bytes, qub_id_bytes) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            created_at,
            unlock_at,
            None,
            4_695_445,
            &body,
            None,
        );

        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(qub_id_bytes)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(created_at)
            .unlock_at(unlock_at)
            .sender_label(Some("Alice".to_string()))
            .body(body)
            .body_hash(body_hash_bytes)
            .reply_to(Some([0x33; 32]))
            .sig_alg(SIG_ALG_ML_DSA_65)
            .author_pubkey(Some(ramp_bytes(ML_DSA_65_PUBLIC_KEY_SIZE)))
            .author_signature(Some(ramp_bytes(ML_DSA_65_SIGNATURE_SIZE)))
            .build()
            .expect("build envelope");

        let bytes = serialize_qub_envelope(&envelope).expect("serialize envelope");

        let qub_count = count_windows(&bytes, b"qub");
        let qub_id_key_count = count_windows(&bytes, b"qub_id");

        // Every `qub` window must be the start of a `qub_id` field key.
        // Inequality means a new brand reference has been introduced into
        // the wire format.
        assert_eq!(
            qub_count, qub_id_key_count,
            "envelope CBOR contains {qub_count} `qub` byte sequences but only {qub_id_key_count} accounted for by `qub_id` field keys — a brand reference may have been introduced"
        );
        // Sanity check: the `qub_id` field is present.
        assert!(
            qub_id_key_count >= 1,
            "expected at least one `qub_id` field key"
        );
    }

    #[test]
    fn sealed_wire_format_has_no_brand_byte_sequences() {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([0x44; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(1_800_000_000)
            .drand_chain_id("a".repeat(64))
            .drand_round(123_456)
            .tlock_ciphertext(ramp_bytes(256))
            .build()
            .expect("build sealed");

        let bytes = serialize_sealed_qub(&sealed).expect("serialize sealed");

        let qub_count = count_windows(&bytes, b"qub");
        let qub_id_key_count = count_windows(&bytes, b"qub_id");

        assert_eq!(
            qub_count, qub_id_key_count,
            "sealed CBOR contains {qub_count} `qub` byte sequences but only {qub_id_key_count} accounted for by `qub_id` field keys — a brand reference may have been introduced"
        );
        assert!(
            qub_id_key_count >= 1,
            "expected at least one `qub_id` field key"
        );
    }

    #[test]
    fn pact_terms_wire_format_is_strictly_brand_free() {
        // PactTerms has no `qub_id` field and is structurally brand-free.
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Couch payment commitment".to_string())
            .terms(vec![
                PactTerm::new("amount".to_string(), "500 USD".to_string()),
                PactTerm::new("due_date".to_string(), "Friday".to_string()),
            ])
            .party_a(PartyIdentifier::new(
                "Alice".to_string(),
                Some("alice@example.org".to_string()),
            ))
            .party_b(PartyIdentifier::new(
                "Bob".to_string(),
                Some("bob@example.org".to_string()),
            ))
            .notes(Some("Verbal agreement made on the 14th.".to_string()))
            .build()
            .expect("build pact terms");

        let bytes = serialize_pact_terms(&pact).expect("serialize pact terms");

        let qub_count = count_windows(&bytes, b"qub");
        assert_eq!(
            qub_count, 0,
            "pact terms CBOR contains {qub_count} `qub` byte sequences — pact wire format must be strictly brand-free"
        );
    }

    #[test]
    fn pact_envelope_wire_format_has_no_brand_byte_sequences_beyond_qub_id() {
        // A pact qub: an envelope whose body is the canonical CBOR
        // encoding of PactTerms and whose content_type is 0x03. Exercises
        // the full content-type=PACT path on the wire.
        let pact = PactTermsBuilder::new()
            .pact_version(1)
            .title("Roommate split".to_string())
            .terms(vec![PactTerm::new(
                "share".to_string(),
                "fifty / fifty".to_string(),
            )])
            .party_a(PartyIdentifier::new("Alice".to_string(), None))
            .party_b(PartyIdentifier::new("Bob".to_string(), None))
            .notes(None)
            .build()
            .expect("build pact terms");
        let body = serialize_pact_terms(&pact).expect("serialize pact terms");

        let created_at: i64 = 1_710_000_000;
        let unlock_at: i64 = 1_810_000_000;
        let (body_hash_bytes, qub_id_bytes) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_PACT,
            created_at,
            unlock_at,
            None,
            4_695_445,
            &body,
            None,
        );

        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(qub_id_bytes)
            .content_type(CONTENT_TYPE_PACT)
            .created_at(created_at)
            .unlock_at(unlock_at)
            .body(body)
            .body_hash(body_hash_bytes)
            .build()
            .expect("build pact envelope");

        let bytes = serialize_qub_envelope(&envelope).expect("serialize pact envelope");

        let qub_count = count_windows(&bytes, b"qub");
        let qub_id_key_count = count_windows(&bytes, b"qub_id");

        assert_eq!(
            qub_count, qub_id_key_count,
            "pact envelope CBOR contains {qub_count} `qub` byte sequences but only {qub_id_key_count} accounted for by `qub_id` field keys — a brand reference may have been introduced"
        );
    }
}

// =============================================================================
// Title field — protocol v1.0 integration coverage
// =============================================================================

/// End-to-end seal → wire → unlock with a title set, asserting the
/// title round-trips cleanly across the full pipeline.
#[test]
fn title_round_trips_through_seal_unlock_pipeline() {
    let now = 1_700_000_000;
    let unlock_at = now + 7 * 86_400;
    let body = b"Title round-trip body.".to_vec();
    let title = "Q1 BTC call";

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);
    draft.set_title(Some(title.into()));

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // Title is plaintext on the SealedQub layer (visible pre-reveal).
    let parsed_sealed = seal_out.sealed_cbor.parse().unwrap();
    assert_eq!(parsed_sealed.title(), Some(title));

    let revealed = unlock(UnlockInput {
        sealed_cbor: &seal_out.sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-title".into(),
        tlock: &tlock,
    })
    .unwrap();
    assert_eq!(revealed.title(), Some(title));
    assert_eq!(revealed.body(), body.as_slice());
}

/// Mutation-resistance: changing the title (with body, timestamps, and
/// content type fixed) must change `qub_id`. This is the gateway-swap
/// protection promised by the v1.0 title binding (PROTOCOL.md §4.1).
#[test]
fn title_change_alters_qub_id() {
    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let body = b"binding test".to_vec();

    let mk = |title: Option<&str>| {
        let mut d = ComposeQub::new(CONTENT_TYPE_TEXT);
        d.set_plaintext(body.clone());
        d.set_unlock_at(unlock_at);
        d.set_title(title.map(str::to_owned));
        let tlock = MockTimelockProvider;
        seal(SealInput {
            draft: &d,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        })
        .unwrap()
        .qub_id
    };

    let id_none = mk(None);
    let id_a = mk(Some("Prediction"));
    let id_b = mk(Some("Announcement"));
    assert_ne!(id_none, id_a, "absent vs present title must differ");
    assert_ne!(id_a, id_b, "two distinct titles must differ");
    assert_ne!(id_none, id_b);
}

/// Gateway-swap simulation: take a sealed wire artifact, swap the
/// plaintext `title` to a new value, re-derive the `qub_id` from the
/// envelope content, and confirm the swapped sealed qub no longer
/// matches its own envelope's `qub_id` — proving an attacker cannot
/// silently substitute a different title pre-reveal.
#[test]
fn swapped_title_breaks_qub_id_consistency() {
    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let body = b"swap test".to_vec();
    let original_title = "Original";
    let attacker_title = "Tampered";

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);
    draft.set_title(Some(original_title.into()));
    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // Build a tampered SealedQub with the attacker's title but the
    // original qub_id. The qub_id was bound to the original title via
    // `title_hash`, so any viewer that re-derives qub_id from the
    // envelope content (post-reveal) will detect the mismatch.
    let original = seal_out.sealed_cbor.parse().unwrap();
    let tampered = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(*original.qub_id())
        .visibility(original.visibility())
        .unlock_at(original.unlock_at())
        .drand_chain_id(original.drand_chain_id().to_string())
        .drand_round(original.drand_round())
        .tlock_ciphertext(original.tlock_ciphertext().to_vec())
        .title(Some(attacker_title.into()))
        .build()
        .unwrap();

    // The sealed qub_id stays the same (the attacker preserved it),
    // but anyone independently deriving qub_id from the displayed
    // (tampered) title finds a different value.
    let bh = body_hash(&body);
    // Same round the seal used, so the qub_id recomputation isolates the
    // title field (the only thing the attacker changed).
    let round = unlock_round(unlock_at, GENESIS, PERIOD).unwrap();
    let recomputed_with_tampered = qub_id(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        now,
        unlock_at,
        None,
        round,
        &bh,
        &title_hash(Some(attacker_title)),
    );
    assert_ne!(tampered.qub_id(), &recomputed_with_tampered);
    let recomputed_with_original = qub_id(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        now,
        unlock_at,
        None,
        round,
        &bh,
        &title_hash(Some(original_title)),
    );
    assert_eq!(tampered.qub_id(), &recomputed_with_original);
}

/// NFC equivalence: titles that NFC-normalise to the same bytes share
/// a `qub_id`. This protects against trivial visual-spoofing tricks
/// where an attacker substitutes precomposed Latin characters for
/// decomposed combining sequences.
#[test]
fn title_nfc_equivalence_yields_same_qub_id() {
    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let body = b"nfc test".to_vec();

    let mk = |title: &str| {
        let mut d = ComposeQub::new(CONTENT_TYPE_TEXT);
        d.set_plaintext(body.clone());
        d.set_unlock_at(unlock_at);
        d.set_title(Some(title.into()));
        let tlock = MockTimelockProvider;
        seal(SealInput {
            draft: &d,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: None,
        })
        .unwrap()
        .qub_id
    };

    let precomposed = "café";
    let decomposed = "cafe\u{0301}";
    assert_ne!(precomposed.as_bytes(), decomposed.as_bytes());
    assert_eq!(mk(precomposed), mk(decomposed));
}

// -----------------------------------------------------------------------------
// PR T20 / Andre 2026-05-22 §13 P2 #28 — CBOR-parse worst-case wall-clock
// regression. The reader's MAX_RECURSION_DEPTH (32) + MAX_BODY_SIZE (~100 KB)
// together bound the parser's CPU cost, but a 50 KB attacker-shaped input
// that exercises both ceilings is still the worst case anonymous /
// qub-read paths admit. The tests pin a wall-clock budget so a future
// change to the parser's recursion scheme can't silently regress into
// pathological territory.
//
// Budget rationale: Andre's report mentioned a 5 ms wall-clock target for
// production. The test's job is to catch exponential blow-up (an O(2^n)
// or O(n^2) regression on malformed input would burn whole seconds), not
// pin the parser's microbench-grade timing. The budget therefore covers
// the union of three slowdown sources:
//
//  - Debug builds run 5–10× slower than release (no inlining, no
//    const-folding, full bounds-checks).
//  - GitHub Actions hosted runners share 2 vCPUs with the runner agent
//    and tail-latency-spike by another 2–4× on bursty work — measured
//    79 ms on a clean-shaped 50 KB input that a dev machine completes
//    in ~15 ms.
//  - `cargo-llvm-cov` source instrumentation adds another 1.5–3× on top.
//
// A 200 ms ceiling keeps all three combined inside the budget and still
// fails loudly on the only thing that matters: a parser regression that
// pushes the cost into the seconds. Coverage and mutation runs additionally
// suppress the wall-clock check entirely — see
// `timing_budget_uninterpretable` below, which is where the reason lives.
// -----------------------------------------------------------------------------

const CBOR_WORST_CASE_BUDGET_MS: u128 = 200;

/// Whether the wall-clock half of the two budget tests below is interpretable
/// in this environment.
///
/// A wall-clock assertion measures the machine as much as the code, so it is
/// only evidence where the machine is not the variable. Three lanes make it
/// the variable:
///
/// - **Coverage** (`CARGO_LLVM_COV`). Source instrumentation adds 1.5–3× on
///   every branch. The check would fail on a parser that is fine.
/// - **Mutation** (`QUB_NO_TIMING_BUDGETS`, set by `scripts/mutants.sh`).
///   cargo-mutants runs the whole suite once per mutant, several mutants at a
///   time, for over a thousand mutants. That is sustained contention by
///   construction — and here the failure is the flattering one, which is why it
///   matters more: a mutant that changes nothing about the parse can still push
///   the elapsed time past 200 ms on a loaded box, the assertion fires, and
///   cargo-mutants records a **kill the tests did not earn**.
///   RQ-SPECIFICATION §4.2's harness cross-check exists for exactly that shape.
///   A false kill inflates `observed` and buys an evidence grade with nothing
///   behind it; a missed mutant only understates. Suppressing here loses the
///   timing signal and keeps the `is_err()` assertion, which is the part that
///   says the parser rejected the input at all.
///
/// - **Miri** (`cfg(miri)`, miri.yml). An interpreter, roughly four orders of
///   magnitude slower than native: the 50 KB case took 359 s against the
///   200 ms budget (measured 2026-09-25). Miri is looking for undefined
///   behaviour; the `is_err()` half still runs under it.
///
/// The suppression cost this repository a red weekly `mutants` job from at
/// least 2026-08-17: the run aborted in its BASELINE phase — 311 ms against the
/// 200 ms budget on the contended runner — and produced `total_mutants: 0`. A
/// mutation lane that generates no mutants is not a lane that found nothing.
/// The Miri case was latent the same way: the weekly Miri job never reached
/// this binary, so the failure it would have reported — as "undefined
/// behaviour found" — had never been seen.
fn timing_budget_uninterpretable() -> bool {
    cfg!(miri)
        || std::env::var_os("CARGO_LLVM_COV").is_some()
        || std::env::var_os("QUB_NO_TIMING_BUDGETS").is_some()
}

#[test]
fn cbor_worst_case_depth_rejects_in_budget() {
    use std::time::Instant;
    // Build an indefinite-length-array bomb: 33 nested array opens
    // (one past MAX_RECURSION_DEPTH = 32) followed by 33 closes. The
    // parser must reject before exhausting CPU on the deep walk.
    let mut bytes = Vec::with_capacity(64);
    bytes.extend(std::iter::repeat_n(0x9f_u8, 33)); // CBOR major type 4 (array), indefinite
    bytes.extend(std::iter::repeat_n(0xff_u8, 33)); // break stop code
    let start = Instant::now();
    let result = deserialize_sealed_qub(&bytes);
    let elapsed = start.elapsed();
    assert!(result.is_err(), "max-depth bomb must reject (not parse)");
    if !timing_budget_uninterpretable() {
        assert!(
            elapsed.as_millis() < CBOR_WORST_CASE_BUDGET_MS,
            "deep-CBOR rejection took {elapsed:?}, expected < {CBOR_WORST_CASE_BUDGET_MS} ms — \
             the MAX_RECURSION_DEPTH cap may be missing or the early-exit broken"
        );
    }
}

#[test]
fn cbor_worst_case_50kb_rejects_in_budget() {
    use std::time::Instant;
    // 50 KB of valid-shaped but useless CBOR — repeated nested
    // array structures within the depth cap. The reader's structural
    // walk has to visit every byte to confirm the shape is malformed
    // (no qub envelope top-level), but the cost should stay under
    // the debug-mode budget.
    // Under Miri the timing half is off (`timing_budget_uninterpretable`), and
    // what is left — the rejection walk — is the same loop at a tenth of the
    // input: 359 s of interpretation at 50 KB, for no path 5 KB does not take.
    let fill_to = if cfg!(miri) { 5_100 } else { 51_180 };
    let mut bytes = Vec::with_capacity(51_200);
    // 25 levels of nesting (under the cap of 32), then fill to 50 KB
    // with array-element tags that the parser has to enumerate.
    bytes.extend(std::iter::repeat_n(0x9f_u8, 25));
    // Fill with byte-string-marker tags + 1-byte payloads until we
    // hit ~50 KB.
    while bytes.len() < fill_to {
        bytes.push(0x41); // bytes(1) tag
        bytes.push(0x00); // zero byte
    }
    bytes.extend(std::iter::repeat_n(0xff_u8, 25));
    let start = Instant::now();
    let result = deserialize_sealed_qub(&bytes);
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "garbage 50 KB CBOR must reject (not parse to a SealedQub)"
    );
    if !timing_budget_uninterpretable() {
        assert!(
            elapsed.as_millis() < CBOR_WORST_CASE_BUDGET_MS,
            "50 KB CBOR rejection took {elapsed:?}, expected < {CBOR_WORST_CASE_BUDGET_MS} ms — \
             the parser may have lost an early-exit somewhere"
        );
    }
}

// =============================================================================
// W7 — `.qub` export bundle: seal → bundle → CBOR round-trip → offline open
// =============================================================================

// The export bundle's whole point is that a third party with no qub infra can
// verify a revealed qub from the bundle alone. This exercises that path end to
// end: seal a qub, package it (plus the round signature) into a `QubBundle`,
// serialise to the raw `.qub` CBOR, parse it back, and `open()` it — recovering
// the body and every verification verdict without a second network fetch.
#[test]
fn export_bundle_roundtrip_and_offline_open_mock() {
    let now = 1_700_000_000;
    let unlock_at = now + 7 * 86_400;
    let body = b"Verify me from the bundle alone.".to_vec();

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.clone());
    draft.set_unlock_at(unlock_at);
    draft.set_sender_label(Some("BundleAlice".into()));

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // Package: sealed bytes + (mock) round signature + Arweave tx id.
    let round_signature = vec![0xAB; 48];
    let bundle = QubBundle::new(
        seal_out.sealed_cbor.clone(),
        round_signature,
        "tx-export-bundle".into(),
    )
    .unwrap()
    .with_sealed_at(Some(now));

    // The bundle's convenience fields are derived from the sealed payload.
    assert_eq!(bundle.drand_round(), seal_out.drand_round);
    assert_eq!(bundle.drand_chain_id(), CHAIN_ID);

    // Transport: raw `.qub` CBOR round-trips byte-stably.
    let qub_bytes = bundle.to_cbor().unwrap();
    let received = QubBundle::from_cbor(&qub_bytes).unwrap();
    assert_eq!(received, bundle);
    assert_eq!(received.to_cbor().unwrap(), qub_bytes);

    // Offline verification: drive the standard unlock path from the bundle,
    // supplying only the (public) drand chain parameters and a tlock provider.
    let revealed = received
        .open(unlock_at, GENESIS, PERIOD, &tlock)
        .expect("bundle opens once the round has elapsed");

    assert_eq!(revealed.body(), body.as_slice());
    assert_eq!(revealed.qub_id(), &seal_out.qub_id);
    assert_eq!(revealed.created_at(), now);
    assert_eq!(revealed.unlock_at(), unlock_at);
    assert_eq!(revealed.sender_label(), Some("BundleAlice"));
    assert_eq!(revealed.drand_round(), seal_out.drand_round);
    assert!(revealed.body_hash_verified());
    assert_eq!(revealed.arweave_tx_id(), "tx-export-bundle");
}

// A bundle whose round has not yet elapsed must refuse to open — the temporal
// gate lives in the shared unlock path, so the bundle inherits it for free.
#[test]
fn export_bundle_open_before_unlock_fails() {
    let now = 1_700_000_000;
    let unlock_at = now + 7 * 86_400;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(b"too early".to_vec());
    draft.set_unlock_at(unlock_at);

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    let bundle = QubBundle::new(seal_out.sealed_cbor, vec![0x01; 48], "tx-early".into()).unwrap();

    // now == unlock_at - 1: still locked.
    let err = bundle
        .open(unlock_at - 1, GENESIS, PERIOD, &tlock)
        .unwrap_err();
    assert!(
        matches!(err, qub_core::unlock::UnlockError::StillLocked { .. }),
        "expected StillLocked, got {err:?}"
    );
}

// =============================================================================
// A1 — unlock() re-derives qub_id from the decrypted content
// =============================================================================

/// A1 (a): a pre-reveal title swap — the attacker rewrites the plaintext
/// `title` on the sealed layer while keeping the recorded `qub_id` — is
/// rejected by the step-12c content re-derivation. The layer-equality
/// checks alone cannot catch this (the title lives only on the sealed
/// layer), so before A1 the swapped artifact unlocked cleanly.
#[test]
fn unlock_rejects_pre_reveal_title_swap() {
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(b"title swap target".to_vec());
    draft.set_unlock_at(unlock_at);
    draft.set_title(Some("Original".into()));
    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    let original = seal_out.sealed_cbor.parse().unwrap();
    let tampered = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(*original.qub_id())
        .visibility(original.visibility())
        .unlock_at(original.unlock_at())
        .drand_chain_id(original.drand_chain_id().to_string())
        .drand_round(original.drand_round())
        .tlock_ciphertext(original.tlock_ciphertext().to_vec())
        .title(Some("Tampered".into()))
        .build()
        .unwrap();
    let tampered_cbor = SealedQubCbor::from_sealed_qub(&tampered).unwrap();

    let err = unlock(UnlockInput {
        sealed_cbor: &tampered_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-title-swap".into(),
        tlock: &tlock,
    })
    .expect_err("swapped title must be rejected");
    assert!(
        matches!(err, UnlockError::QubIdDerivationMismatch),
        "got: {err:?}"
    );
}

/// A1 (b): a post-round re-encryption forgery — the attacker swaps the
/// body, recomputes a *consistent* `body_hash`, keeps the original
/// `qub_id` on BOTH layers, and re-encrypts to the same round. Every
/// pairwise check passes (body↔hash, envelope↔sealed `qub_id`,
/// `unlock_at`); only re-deriving the identity from content catches that
/// this content was never the one committed to under that `qub_id`.
#[test]
fn unlock_rejects_reencrypted_body_swap_forgery() {
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 86_400;
    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(b"the real committed content".to_vec());
    draft.set_unlock_at(unlock_at);
    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();
    let original = seal_out.sealed_cbor.parse().unwrap();

    // Forge: different body, CORRECT hash for it, original qub_id.
    let forged_body = b"a different message entirely".to_vec();
    let forged_envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(*original.qub_id())
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(now)
        .unlock_at(unlock_at)
        .body(forged_body.clone())
        .body_hash(body_hash(&forged_body))
        .build()
        .unwrap();
    let forged_cbor = serialize_qub_envelope(&forged_envelope).unwrap();
    let forged_ct = tlock.encrypt(&forged_cbor, original.drand_round()).unwrap();
    let forged_sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(*original.qub_id())
        .visibility(original.visibility())
        .unlock_at(unlock_at)
        .drand_chain_id(original.drand_chain_id().to_string())
        .drand_round(original.drand_round())
        .tlock_ciphertext(forged_ct)
        .build()
        .unwrap();
    let forged_sealed_cbor = SealedQubCbor::from_sealed_qub(&forged_sealed).unwrap();

    let err = unlock(UnlockInput {
        sealed_cbor: &forged_sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-body-forge".into(),
        tlock: &tlock,
    })
    .expect_err("re-encrypted body swap must be rejected");
    assert!(
        matches!(err, UnlockError::QubIdDerivationMismatch),
        "got: {err:?}"
    );
}

// =============================================================================
// A2 — outcome_at rides both wire surfaces and round-trips through unlock
// =============================================================================

/// Seal a draft with `outcome_at` set and assert (i) both wire surfaces
/// carry it, (ii) unlock succeeds, (iii) the step-12c re-derivation
/// passes (implied by the successful unlock) and the revealed qub
/// carries the value.
#[test]
fn outcome_at_round_trips_through_seal_unlock_pipeline() {
    let now = 1_700_000_000;
    let unlock_at = now + 7 * 86_400;
    let outcome_at = unlock_at + 30 * 86_400;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(b"verdict-bearing body".to_vec());
    draft.set_unlock_at(unlock_at);
    draft.set_outcome_at(Some(outcome_at));

    let tlock = MockTimelockProvider;
    let seal_out = seal(SealInput {
        draft: &draft,
        now,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        chain_id: CHAIN_ID.into(),
        tlock: &tlock,
        signing: None,
    })
    .unwrap();

    // (i) Sealed wire surface carries outcome_at…
    let sealed = seal_out.sealed_cbor.parse().unwrap();
    assert_eq!(sealed.outcome_at(), Some(outcome_at));
    // …and so does the encrypted envelope surface.
    let envelope_bytes = tlock.decrypt(sealed.tlock_ciphertext(), &[]).unwrap();
    let envelope = qub_core::cbor::deserialize_qub_envelope(&envelope_bytes).unwrap();
    assert_eq!(envelope.outcome_at(), Some(outcome_at));

    // (ii) + (iii): unlock succeeds — which requires the step-12b
    // envelope↔sealed outcome cross-check AND the step-12c qub_id
    // re-derivation (whose preimage folds outcome_at) to pass.
    let revealed = unlock(UnlockInput {
        sealed_cbor: &seal_out.sealed_cbor,
        round_signature: &[],
        now: unlock_at,
        chain_genesis_time: GENESIS,
        chain_period_seconds: PERIOD,
        arweave_tx_id: "tx-outcome".into(),
        tlock: &tlock,
    })
    .unwrap();
    assert_eq!(revealed.outcome_at(), Some(outcome_at));
}

// =============================================================================
// A4 — envelope↔sealed outcome_at cross-check
// =============================================================================

/// Mutation-resistance: an artifact whose envelope and sealed layers
/// disagree on `outcome_at` is rejected with `OutcomeAtMismatch`.
#[test]
fn mutation_outcome_at_cross_check_is_enforced() {
    use qub_core::unlock::UnlockError;

    let now = 1_700_000_000;
    let unlock_at = now + 3600;
    let env_outcome = unlock_at + 86_400;
    let sealed_outcome = unlock_at + 172_800; // different
    let body = b"outcome-check".to_vec();
    let (bh, id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        now,
        unlock_at,
        Some(env_outcome),
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
        .outcome_at(Some(env_outcome))
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
        .unlock_at(unlock_at)
        .outcome_at(Some(sealed_outcome)) // DIFFERENT from envelope
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
    assert!(
        matches!(err, UnlockError::OutcomeAtMismatch),
        "outcome_at cross-check must be enforced, got: {err:?}"
    );
}

// =============================================================================
// A7 — author signature covers sender_label / reply_to (V2 preimage)
// =============================================================================

mod signature_scope_tests {
    use qub_core::cbor::serialize_qub_envelope;
    use qub_core::hash::derive_envelope_hashes;
    use qub_core::seal::{SealInput, SigningParams, seal};
    use qub_core::signing::{SIG_ALG_ML_DSA_65, compute_sig_input, generate_keypair, sign};
    use qub_core::tlock::{MockTimelockProvider, TimelockProvider};
    use qub_core::types::{
        CONTENT_TYPE_TEXT, ComposeQub, PROTOCOL_VERSION_1, QubEnvelopeBuilder, SealedQubBuilder,
        VISIBILITY_PUBLIC,
    };
    use qub_core::unlock::{UnlockInput, unlock};
    use qub_core::wire::SealedQubCbor;

    const GENESIS: i64 = 1_595_431_050;
    const PERIOD: u64 = 30;
    const CHAIN_ID: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

    /// A post-round `sender_label` rewrite on a V2-signed qub flips the
    /// verification result to `Some(false)`. Before A7 the signature did
    /// not cover the label, so the rewritten artifact still reported
    /// Some(true).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn sender_label_rewrite_breaks_v2_signature() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
        draft.set_plaintext(b"signed with label".to_vec());
        draft.set_unlock_at(unlock_at);
        draft.set_sender_label(Some("Alice".into()));
        let tlock = MockTimelockProvider;
        let seal_out = seal(SealInput {
            draft: &draft,
            now,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            chain_id: CHAIN_ID.into(),
            tlock: &tlock,
            signing: Some(SigningParams {
                secret_key: &sk,
                public_key: &pk,
            }),
        })
        .expect("seal");

        // Post-round attacker: decrypt, rewrite the label, re-encrypt.
        let sealed = seal_out.sealed_cbor.parse().unwrap();
        let envelope_bytes = tlock.decrypt(sealed.tlock_ciphertext(), &[]).unwrap();
        let envelope = qub_core::cbor::deserialize_qub_envelope(&envelope_bytes).unwrap();
        let rewritten = QubEnvelopeBuilder::new()
            .version(envelope.version())
            .qub_id(*envelope.qub_id())
            .content_type(envelope.content_type())
            .created_at(envelope.created_at())
            .unlock_at(envelope.unlock_at())
            .sender_label(Some("Mallory".into())) // the rewrite
            .body(envelope.body().to_vec())
            .body_hash(*envelope.body_hash())
            .sig_alg(envelope.sig_alg())
            .author_signature(envelope.author_signature().map(<[u8]>::to_vec))
            .author_pubkey(envelope.author_pubkey().map(<[u8]>::to_vec))
            .build()
            .unwrap();
        let rewritten_cbor = serialize_qub_envelope(&rewritten).unwrap();
        let rewritten_ct = tlock
            .encrypt(&rewritten_cbor, sealed.drand_round())
            .unwrap();
        let forged = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(*sealed.qub_id())
            .visibility(sealed.visibility())
            .unlock_at(sealed.unlock_at())
            .drand_chain_id(sealed.drand_chain_id().to_string())
            .drand_round(sealed.drand_round())
            .tlock_ciphertext(rewritten_ct)
            .build()
            .unwrap();
        let forged_cbor = SealedQubCbor::from_sealed_qub(&forged).unwrap();

        // qub_id deliberately does NOT bind sender_label, so the unlock
        // succeeds — but the signature must now report failure.
        let revealed = unlock(UnlockInput {
            sealed_cbor: &forged_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx-label-rewrite".into(),
            tlock: &tlock,
        })
        .expect("unlock succeeds; signature must fail");
        assert_eq!(revealed.sender_label(), Some("Mallory"));
        assert_eq!(
            revealed.signature_verified(),
            Some(false),
            "rewritten sender_label must break the V2 signature"
        );
    }

    /// Legacy compatibility: a signature over the V1 preimage (as
    /// produced before the V2 rollout, and still produced by the pact
    /// staging / cosign flow) verifies via the fallback path.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn legacy_v1_signature_now_rejected() {
        // The V1 preimage fallback was retired (security-audit-2026-07-14):
        // a signature that only commits to V1 (no sender_label / reply_to)
        // must no longer verify. This is the inverse of the pre-retirement
        // `legacy_v1_signature_still_verifies` acceptance test.
        let (pk, sk) = generate_keypair().expect("keygen");
        let now = 1_700_000_000;
        let unlock_at = now + 3600;
        let body = b"legacy-signed".to_vec();
        let round = 4_695_445;
        let (bh, id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            now,
            unlock_at,
            None,
            round,
            &body,
            Some("Legacy title"), // must match the sealed-layer title below
        );
        // Pre-V2 pipeline: sign the (now-rejected) V1 preimage.
        let sig_input = compute_sig_input(PROTOCOL_VERSION_1, &id, &bh, unlock_at);
        let signature = sign(&sk, &sig_input).expect("sign");

        let envelope = QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(now)
            .unlock_at(unlock_at)
            .sender_label(Some("Alice".into()))
            .body(body)
            .body_hash(bh)
            .sig_alg(SIG_ALG_ML_DSA_65)
            .author_signature(Some(signature))
            .author_pubkey(Some(pk))
            .build()
            .unwrap();
        let envelope_cbor = serialize_qub_envelope(&envelope).unwrap();
        let tlock = MockTimelockProvider;
        let ct = tlock.encrypt(&envelope_cbor, round).unwrap();
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(id)
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(unlock_at)
            .drand_chain_id(CHAIN_ID.into())
            .drand_round(round)
            .tlock_ciphertext(ct)
            .title(Some("Legacy title".into()))
            .build()
            .unwrap();
        let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).unwrap();

        let revealed = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &[],
            now: unlock_at,
            chain_genesis_time: GENESIS,
            chain_period_seconds: PERIOD,
            arweave_tx_id: "tx-legacy-sig".into(),
            tlock: &tlock,
        })
        .expect("unlock");
        assert_eq!(
            revealed.signature_verified(),
            Some(false),
            "V1-preimage signature must be rejected now that the legacy fallback is retired"
        );
    }
}
