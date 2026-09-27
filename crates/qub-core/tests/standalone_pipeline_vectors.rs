//! Cross-check of the standalone reference viewer's Phase 3 fixture.
//!
//! `tests/vectors/standalone_pipeline_v1.json` is produced by the
//! JavaScript generator `scripts/standalone-build/gen-full-pipeline-fixture.mjs`
//! (an implementation independent of this crate) and embedded in the
//! standalone viewer (`public-mirror/standalone/index.html`). This test
//! runs every case through the Rust reference implementation's own
//! delivery-shape resolution and `unlock()` with the pinned drand beacon,
//! so a generator that drifts from PROTOCOL.md — a stale `qub_id`
//! preimage, a wrong key order, a wrong round mapping — fails here rather
//! than only in a browser nobody opened.
//!
//! No network: the drand round signature is pinned in the fixture, and
//! published drand signatures are immutable.

use std::fs;
use std::path::PathBuf;

use qub_core::tlock::DrandTimelockProvider;
use qub_core::types::{VISIBILITY_PRIVATE, VISIBILITY_PUBLIC};
use qub_core::unlock::{UnlockInput, unlock};
use qub_core::wire::SealedQubCbor;
use qub_core::wrapper::{OuterWrapperCbor, unwrap_sealed_qub};

/// drand quicknet genesis time and period (PROTOCOL.md §4.3).
const QUICKNET_GENESIS: i64 = 1_692_803_367;
const QUICKNET_PERIOD: u64 = 3;

fn fixture() -> serde_json::Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/standalone_pipeline_v1.json");
    let text = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&text).expect("fixture is valid JSON")
}

fn hex_field(case: &serde_json::Value, field: &str) -> Vec<u8> {
    let s = case[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} must be a hex string"));
    hex::decode(s).unwrap_or_else(|_| panic!("{field} must be valid hex"))
}

fn int_field(case: &serde_json::Value, field: &str) -> i64 {
    case[field]
        .as_i64()
        .unwrap_or_else(|| panic!("{field} must be an integer"))
}

#[test]
#[cfg_attr(
    miri,
    ignore = "interprets safe BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
)]
fn every_case_unlocks_under_the_reference_implementation() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().expect("cases array");
    let shapes: Vec<&str> = cases
        .iter()
        .map(|c| c["delivery"].as_str().expect("delivery"))
        .collect();
    assert!(
        shapes.contains(&"wrapped") && shapes.contains(&"bare"),
        "fixture must cover both §13.8 delivery shapes, got {shapes:?}"
    );

    let tlock = DrandTimelockProvider::quicknet();

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let stored = hex_field(case, "stored_hex");
        let expected_sealed = hex_field(case, "sealed_cbor_hex");
        let visibility = u8::try_from(int_field(case, "sealed_visibility")).expect("u8");

        // §8 step 3a — resolve the delivery shape.
        let sealed_cbor = match case["delivery"].as_str() {
            Some("wrapped") => {
                assert_eq!(visibility, VISIBILITY_PRIVATE, "{name}: wrapped ⇒ private");
                let key: [u8; 32] = hex_field(case, "key_hex").try_into().expect("32-byte key");
                let wrapper = OuterWrapperCbor::from_encoded(stored).expect("OuterWrapper parses");
                unwrap_sealed_qub(&wrapper, &key).expect("unwrap with pinned key")
            },
            Some("bare") => {
                assert_eq!(visibility, VISIBILITY_PUBLIC, "{name}: bare ⇒ public");
                assert!(
                    case["key_hex"].is_null(),
                    "{name}: public delivery carries no key"
                );
                SealedQubCbor::from_encoded(stored).expect("bare SealedQubCbor parses")
            },
            other => panic!("{name}: unknown delivery {other:?}"),
        };
        assert_eq!(
            sealed_cbor.clone().into_bytes(),
            expected_sealed,
            "{name}: recovered SealedQubCbor differs from the pinned bytes"
        );

        let round = u64::try_from(int_field(case, "round")).expect("u64 round");
        let signature = hex_field(case, "signature_hex");
        tlock
            .verify_round_signature(round, &signature)
            .unwrap_or_else(|e| panic!("{name}: pinned drand signature must verify: {e}"));

        let unlock_at = int_field(case, "sealed_unlock_at");
        let revealed = unlock(UnlockInput {
            sealed_cbor: &sealed_cbor,
            round_signature: &signature,
            now: unlock_at,
            chain_genesis_time: QUICKNET_GENESIS,
            chain_period_seconds: QUICKNET_PERIOD,
            arweave_tx_id: String::new(),
            tlock: &tlock,
        })
        .unwrap_or_else(|e| panic!("{name}: reference unlock rejected the fixture: {e}"));

        assert_eq!(
            revealed.qub_id().to_vec(),
            hex_field(case, "qub_id_hex"),
            "{name}: qub_id"
        );
        assert_eq!(revealed.visibility(), visibility, "{name}: visibility");
        assert_eq!(revealed.drand_round(), round, "{name}: drand_round");
        assert_eq!(
            revealed.body(),
            hex_field(case, "envelope_body_hex"),
            "{name}: body"
        );
        assert!(revealed.body_hash_verified(), "{name}: body_hash");
        assert_eq!(
            revealed.title(),
            case["sealed_title"].as_str(),
            "{name}: title"
        );
        assert_eq!(
            revealed.created_at(),
            int_field(case, "envelope_created_at"),
            "{name}: created_at"
        );
    }
}
