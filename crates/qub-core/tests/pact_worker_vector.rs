//! The Rust client opening a pact the Worker cosigned and stored.
//!
//! `tests/vectors/pact_cosigned_v1.json` is written by the Worker's S5 pact
//! scenario (`workers/api/src/routes/__tests__/scn-pact-chain-s5.test.ts`,
//! `QUB_REGEN_VECTORS=1 npx vitest run scn-pact-chain-s5`): a pact staged,
//! invited, bound and cosigned through the real Worker handlers, sealed by
//! the TypeScript timelock and signed by both parties with an ML-DSA-65
//! implementation that is not this crate's. `stored_hex` is what the read
//! API served. For this crate the vector is a `differential` oracle: an
//! independent implementation produced every byte, and this one has to
//! agree with it (RQ-SPECIFICATION §4.6).
//!
//! What the client does with it, in PROTOCOL.md §8 order: resolve the
//! delivery shape, check the beacon, refuse to open early, open at the
//! unlock time with both signatures verified, and read the agreement.
//!
//! No network: both beacons are pinned in the vector, and published drand
//! signatures are immutable. `other_beacon` is a genuine quicknet beacon of
//! another round, so its refusal is a refusal of a real signature, not of a
//! forgery.

use std::fs;
use std::path::PathBuf;

use qub_core::cbor::{deserialize_qub_envelope, serialize_qub_envelope, serialize_sealed_qub};
use qub_core::hash::{body_hash, unlock_round};
use qub_core::pact::{parse_pact_terms, serialize_pact_terms};
use qub_core::tlock::{DrandTimelockProvider, TimelockError, TimelockProvider};
use qub_core::types::{
    CONTENT_TYPE_PACT, QubEnvelopeBuilder, SIG_ALG_ML_DSA_65, SealedQub, SealedQubBuilder,
    VISIBILITY_PUBLIC,
};
use qub_core::unlock::{UnlockError, UnlockInput, unlock};
use qub_core::wire::SealedQubCbor;
use qub_core::wrapper::OuterWrapperCbor;
use serde_json::Value;

fn vector() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/pact_cosigned_v1.json");
    let text = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&text).expect("vector is valid JSON")
}

fn hex_at(v: &Value, pointer: &str) -> Vec<u8> {
    let s = v
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} must be a hex string"));
    hex::decode(s).unwrap_or_else(|_| panic!("{pointer} must be valid hex"))
}

fn int_at(v: &Value, pointer: &str) -> i64 {
    v.pointer(pointer)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{pointer} must be an integer"))
}

fn str_at<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} must be a string"))
}

fn round_at(v: &Value, pointer: &str) -> u64 {
    u64::try_from(int_at(v, pointer)).expect("a round is non-negative")
}

/// The stored bytes, resolved as the public delivery shape.
fn stored(v: &Value) -> SealedQubCbor {
    SealedQubCbor::from_encoded(hex_at(v, "/stored_hex")).expect("a CBOR map")
}

/// `unlock()` as the client calls it, on the vector's chain parameters.
fn open(
    v: &Value,
    sealed: &SealedQubCbor,
    signature: &[u8],
    now: i64,
) -> Result<qub_core::types::RevealedQub, UnlockError> {
    unlock(UnlockInput {
        sealed_cbor: sealed,
        round_signature: signature,
        now,
        chain_genesis_time: int_at(v, "/genesis_time"),
        chain_period_seconds: u64::try_from(int_at(v, "/period")).expect("u64 period"),
        arweave_tx_id: str_at(v, "/tx_id").to_owned(),
        tlock: &DrandTimelockProvider::quicknet(),
    })
}

/// `sealed` with its round metadata, ciphertext or both replaced.
fn reseal(sealed: &SealedQub, round: u64, ciphertext: Vec<u8>) -> SealedQubCbor {
    let rebuilt = SealedQubBuilder::new()
        .version(sealed.version())
        .qub_id(*sealed.qub_id())
        .visibility(sealed.visibility())
        .unlock_at(sealed.unlock_at())
        .outcome_at(sealed.outcome_at())
        .drand_chain_id(sealed.drand_chain_id().to_owned())
        .drand_round(round)
        .drand_chain_version(sealed.drand_chain_version())
        .tlock_ciphertext(ciphertext)
        .recipient_pubkey(sealed.recipient_pubkey().copied())
        .title(sealed.title().map(str::to_owned))
        .build()
        .expect("a rebuilt sealed qub is valid");
    SealedQubCbor::from_sealed_qub(&rebuilt).expect("serialises")
}

#[test]
fn the_worker_stored_pact_is_a_bare_public_sealed_qub_in_canonical_form() {
    let v = vector();
    assert_eq!(str_at(&v, "/delivery"), "bare");
    let bytes = hex_at(&v, "/stored_hex");

    // PROTOCOL.md §13.8: a public qub is delivered bare. The stored bytes
    // are a SealedQub, and not an OuterWrapper that only parsed as a map.
    let as_wrapper = OuterWrapperCbor::from_encoded(bytes.clone()).expect("a CBOR map");
    assert!(
        as_wrapper.parse().is_err(),
        "the stored pact must not resolve as the private (wrapped) delivery shape"
    );
    let sealed = stored(&v)
        .parse()
        .expect("the stored pact parses as a SealedQub");
    assert_eq!(sealed.visibility(), VISIBILITY_PUBLIC, "bare ⇒ public");

    // Canonical: re-encoding what was parsed gives back the stored bytes.
    assert_eq!(
        serialize_sealed_qub(&sealed).expect("re-encodes"),
        bytes,
        "the Worker's SealedQubCbor is not this crate's canonical encoding"
    );

    assert_eq!(sealed.qub_id().to_vec(), hex_at(&v, "/expected/qub_id_hex"));
    assert_eq!(sealed.unlock_at(), int_at(&v, "/unlock_at"));
    assert_eq!(sealed.drand_chain_id(), str_at(&v, "/chain_hash"));
    assert_eq!(sealed.title(), None);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn the_pact_rounds_beacon_verifies_and_a_genuine_beacon_of_another_round_is_refused() {
    let v = vector();
    let tlock = DrandTimelockProvider::quicknet();
    let sealed_cbor = stored(&v);
    let sealed = sealed_cbor.parse().expect("parses");
    let unlock_at = int_at(&v, "/unlock_at");

    // The round the unlock time maps to (PROTOCOL.md §4.3) is the round the
    // pact is bound to, and its recorded beacon verifies for it.
    let round = round_at(&v, "/beacon/round");
    assert_eq!(
        unlock_round(
            unlock_at,
            int_at(&v, "/genesis_time"),
            u64::try_from(int_at(&v, "/period")).expect("u64")
        ),
        Ok(round)
    );
    assert_eq!(sealed.drand_round(), round);
    assert_eq!(
        tlock.ciphertext_round(sealed.tlock_ciphertext()),
        Ok(Some(round)),
        "the ciphertext stanza is bound to the pact's round"
    );
    let beacon = hex_at(&v, "/beacon/signature_hex");
    assert_eq!(tlock.verify_round_signature(round, &beacon), Ok(()));

    // The other beacon is genuine: it verifies for its own round…
    let other_round = round_at(&v, "/other_beacon/round");
    let other = hex_at(&v, "/other_beacon/signature_hex");
    assert_ne!(other_round, round);
    assert_eq!(tlock.verify_round_signature(other_round, &other), Ok(()));

    // …and is refused for the pact's round, by the beacon check and by the
    // timelock itself.
    assert!(matches!(
        tlock.verify_round_signature(round, &other),
        Err(TimelockError::InvalidSignature(_))
    ));
    assert!(
        matches!(
            open(&v, &sealed_cbor, &other, unlock_at),
            Err(UnlockError::Tlock(TimelockError::InvalidSignature(_)))
        ),
        "a genuine beacon of another round must open nothing"
    );

    // Relabelling the pact to the other round, so that beacon would be the
    // "right" one, is refused before any decryption: the round no longer
    // follows from the unlock time.
    let relabelled = reseal(&sealed, other_round, sealed.tlock_ciphertext().to_vec());
    match open(&v, &relabelled, &other, unlock_at) {
        Err(UnlockError::DrandRoundMismatch { expected, actual }) => {
            assert_eq!((expected, actual), (round, other_round));
        },
        other => panic!("a pact relabelled to another round must be refused, got {other:?}"),
    }
}

#[test]
fn one_second_before_the_unlock_time_even_the_genuine_beacon_is_refused() {
    let v = vector();
    let unlock_at = int_at(&v, "/unlock_at");
    let beacon = hex_at(&v, "/beacon/signature_hex");
    match open(&v, &stored(&v), &beacon, unlock_at - 1) {
        Err(UnlockError::StillLocked { unlock_at: at, now }) => {
            assert_eq!((at, now), (unlock_at, unlock_at - 1));
        },
        other => panic!("expected StillLocked one second early, got {other:?}"),
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn at_the_unlock_time_the_pact_opens_with_both_signatures_verified() {
    let v = vector();
    let unlock_at = int_at(&v, "/unlock_at");
    let beacon = hex_at(&v, "/beacon/signature_hex");
    let revealed = open(&v, &stored(&v), &beacon, unlock_at)
        .unwrap_or_else(|e| panic!("the client must open the Worker's pact: {e}"));

    assert_eq!(
        revealed.qub_id().to_vec(),
        hex_at(&v, "/expected/qub_id_hex")
    );
    assert_eq!(revealed.arweave_tx_id(), str_at(&v, "/tx_id"));
    assert_eq!(revealed.content_type(), CONTENT_TYPE_PACT);
    assert_eq!(
        i64::from(revealed.content_type()),
        int_at(&v, "/expected/content_type")
    );
    assert_eq!(revealed.created_at(), int_at(&v, "/expected/created_at"));
    assert_eq!(revealed.unlock_at(), unlock_at);
    assert_eq!(
        revealed.sender_label(),
        Some(str_at(&v, "/expected/sender_label"))
    );
    assert_eq!(revealed.body(), hex_at(&v, "/expected/body_hex"));
    assert!(revealed.body_hash_verified());

    // Both parties signed, and both signatures verify over the preimage this
    // crate recomputes from the revealed fields.
    assert_eq!(
        revealed.signature_verified(),
        Some(true),
        "author signature"
    );
    assert_eq!(
        revealed.cosigner_verified(),
        Some(true),
        "cosigner signature"
    );
    // Under the keys the parties hold: the author's attested key and the key
    // the invite was bound to.
    assert_eq!(
        body_hash(revealed.author_pubkey().expect("author key")).to_vec(),
        hex_at(&v, "/expected/author_fingerprint_hex")
    );
    assert_eq!(
        body_hash(revealed.cosigner_pubkey().expect("cosigner key")).to_vec(),
        hex_at(&v, "/expected/cosigner_fingerprint_hex")
    );

    // The verdicts are about these signatures: swap them, so each sits under
    // the other party's key, and the same pact, resealed to the same round,
    // verifies neither.
    let tlock = DrandTimelockProvider::quicknet();
    let sealed = stored(&v).parse().expect("parses");
    let envelope = deserialize_qub_envelope(
        &tlock
            .decrypt(sealed.tlock_ciphertext(), &beacon)
            .expect("the genuine beacon opens the envelope"),
    )
    .expect("the envelope parses");
    assert_eq!(envelope.sig_alg(), SIG_ALG_ML_DSA_65);
    let swapped = QubEnvelopeBuilder::new()
        .version(envelope.version())
        .qub_id(*envelope.qub_id())
        .content_type(envelope.content_type())
        .created_at(envelope.created_at())
        .unlock_at(envelope.unlock_at())
        .outcome_at(envelope.outcome_at())
        .sender_label(envelope.sender_label().map(str::to_owned))
        .reply_to(envelope.reply_to().copied())
        .body(envelope.body().to_vec())
        .body_hash(*envelope.body_hash())
        .sig_alg(envelope.sig_alg())
        .author_pubkey(envelope.author_pubkey().map(<[u8]>::to_vec))
        .author_signature(envelope.cosigner_signature().map(<[u8]>::to_vec))
        .cosigner_pubkey(envelope.cosigner_pubkey().map(<[u8]>::to_vec))
        .cosigner_signature(envelope.author_signature().map(<[u8]>::to_vec))
        .build()
        .expect("the swapped envelope is structurally valid");
    let ciphertext = tlock
        .encrypt(
            &serialize_qub_envelope(&swapped).expect("serialises"),
            sealed.drand_round(),
        )
        .expect("encrypts offline");
    let crossed_cbor = reseal(&sealed, sealed.drand_round(), ciphertext);
    let crossed = open(&v, &crossed_cbor, &beacon, unlock_at).expect("still opens");
    assert_eq!(
        crossed.signature_verified(),
        Some(false),
        "author signature"
    );
    assert_eq!(
        crossed.cosigner_verified(),
        Some(false),
        "cosigner signature"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn the_revealed_body_parses_into_the_agreement_both_parties_signed() {
    let v = vector();
    let beacon = hex_at(&v, "/beacon/signature_hex");
    let revealed = open(&v, &stored(&v), &beacon, int_at(&v, "/unlock_at")).expect("opens");

    let terms = parse_pact_terms(revealed.body()).expect("the body is canonical PactTerms");
    assert_eq!(
        serialize_pact_terms(&terms).expect("re-encodes"),
        revealed.body(),
        "the Worker's PactTerms CBOR is not this crate's canonical encoding"
    );

    let expected = v.pointer("/expected/terms").expect("expected terms");
    assert_eq!(
        i64::from(terms.pact_version()),
        int_at(expected, "/pact_version")
    );
    assert_eq!(terms.title(), str_at(expected, "/title"));
    let rows: Vec<(&str, &str)> = terms.terms().iter().map(|t| (t.key(), t.value())).collect();
    let expected_rows: Vec<(&str, &str)> = expected["terms"]
        .as_array()
        .expect("terms array")
        .iter()
        .map(|t| (str_at(t, "/key"), str_at(t, "/value")))
        .collect();
    assert_eq!(rows, expected_rows);
    for (party, side) in [(terms.party_a(), "party_a"), (terms.party_b(), "party_b")] {
        assert_eq!(party.label(), str_at(expected, &format!("/{side}/label")));
        assert_eq!(
            party.contact(),
            Some(str_at(expected, &format!("/{side}/contact")))
        );
    }
    assert_eq!(terms.notes(), None);
}
