//! Cross-language test vectors for `OuterWrapper` v1.
//!
//! The fixture file `tests/vectors/wrapper_v1.json` is the single source of
//! truth for cross-language parity: this Rust integration test reads it
//! and asserts `wrap_sealed_qub` produces byte-identical output, and the
//! TypeScript mirror at `workers/api/src/crypto/__tests__/wrapper.test.ts`
//! reads the same JSON file and asserts the same.
//!
//! To regenerate the fixture after a deliberate format change, run:
//!
//! ```text
//! QUB_REGEN_VECTORS=1 cargo test -p qub-core --test wrapper_vectors
//! ```
//!
//! The test populates `qub_id_hex`, `sealed_cbor_hex`, and
//! `expected_wrapper_hex` in regen mode based on the named cases below.
//! Without the env var the test only verifies the output and never writes.

use std::fs;
use std::path::PathBuf;

use qub_core::hash::derive_envelope_hashes;
use qub_core::types::{
    CONTENT_TYPE_TEXT, PROTOCOL_VERSION_1, QubEnvelopeBuilder, SealedQubBuilder, VISIBILITY_PUBLIC,
};
use qub_core::wire::{QubEnvelopeCbor, SealedQubCbor};
use qub_core::wrapper::{unwrap_sealed_qub, wrap_sealed_qub};

const REGEN_ENV_VAR: &str = "QUB_REGEN_VECTORS";

/// Inputs for a named case. Returns the canonical [`SealedQubCbor`] bytes
/// that the wrapper test wraps, plus the matching `qub_id` (which is the
/// AAD).
fn inputs_for_case(name: &str) -> ([u8; 32], SealedQubCbor) {
    match name {
        "basic-text-public" => sample_basic_text(),
        "with-recipient-pubkey" => sample_with_recipient_pubkey(),
        "longer-body" => sample_longer_body(),
        other => panic!("unknown case name {other:?}; add an arm to inputs_for_case"),
    }
}

fn sample_basic_text() -> ([u8; 32], SealedQubCbor) {
    let body = b"Hello, future.".to_vec();
    let created_at: i64 = 1_735_689_600;
    let unlock_at: i64 = 1_736_294_400;
    let (body_hash, qub_id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        created_at,
        unlock_at,
        None,
        4_675_285,
        &body,
        None,
    );
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(created_at)
        .unlock_at(unlock_at)
        .body(body)
        .body_hash(body_hash)
        .build()
        .expect("valid envelope");
    let envelope_bytes = QubEnvelopeCbor::from_qub_envelope(&envelope)
        .expect("serialise envelope")
        .into_bytes();

    // Use the envelope CBOR bytes as the tlock_ciphertext placeholder for
    // the fixture — wrappers are byte-blind to the inner SealedQub shape,
    // so any deterministic choice that survives canonical CBOR round-trip
    // is fine. Real callers pass actual tlock-encrypted bytes here.
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(unlock_at)
        .drand_chain_id("a".repeat(64))
        .drand_round(4_675_285)
        .tlock_ciphertext(envelope_bytes)
        .build()
        .expect("valid sealed");
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).expect("serialise sealed");
    (qub_id, sealed_cbor)
}

fn sample_with_recipient_pubkey() -> ([u8; 32], SealedQubCbor) {
    let body = b"Recipient-targeted draft.".to_vec();
    let created_at: i64 = 1_735_689_600;
    let unlock_at: i64 = 1_736_294_400;
    let (body_hash, qub_id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        created_at,
        unlock_at,
        None,
        4_675_285,
        &body,
        None,
    );
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(created_at)
        .unlock_at(unlock_at)
        .body(body)
        .body_hash(body_hash)
        .build()
        .expect("valid envelope");
    let envelope_bytes = QubEnvelopeCbor::from_qub_envelope(&envelope)
        .expect("serialise envelope")
        .into_bytes();

    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(unlock_at)
        .drand_chain_id("a".repeat(64))
        .drand_round(4_675_285)
        .recipient_pubkey(Some([0xCC; 32]))
        .tlock_ciphertext(envelope_bytes)
        .build()
        .expect("valid sealed");
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).expect("serialise sealed");
    (qub_id, sealed_cbor)
}

fn sample_longer_body() -> ([u8; 32], SealedQubCbor) {
    // 4 KiB body — well below the 100 KB protocol ceiling but large
    // enough that CBOR length-prefix encoding shifts to multi-byte.
    let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let created_at: i64 = 1_735_689_600;
    let unlock_at: i64 = 1_736_294_400;
    let (body_hash, qub_id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        created_at,
        unlock_at,
        None,
        4_675_285,
        &body,
        None,
    );
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(created_at)
        .unlock_at(unlock_at)
        .body(body)
        .body_hash(body_hash)
        .build()
        .expect("valid envelope");
    let envelope_bytes = QubEnvelopeCbor::from_qub_envelope(&envelope)
        .expect("serialise envelope")
        .into_bytes();

    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(unlock_at)
        .drand_chain_id("a".repeat(64))
        .drand_round(4_675_285)
        .tlock_ciphertext(envelope_bytes)
        .build()
        .expect("valid sealed");
    let sealed_cbor = SealedQubCbor::from_sealed_qub(&sealed).expect("serialise sealed");
    (qub_id, sealed_cbor)
}

fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/wrapper_v1.json");
    p
}

fn decode_fixed<const N: usize>(v: &serde_json::Value) -> [u8; N] {
    let bytes = decode_var(v);
    bytes.try_into().expect("wrong fixed length")
}

fn decode_var(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    hex::decode(s).expect("valid hex")
}

#[test]
fn wrapper_v1_vectors_round_trip_byte_for_byte() {
    let raw = fs::read_to_string(vectors_path()).expect("read vectors fixture");
    let mut json: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors fixture");
    let regen = std::env::var(REGEN_ENV_VAR).is_ok();

    let cases = json["cases"]
        .as_array_mut()
        .expect("vectors `cases` must be an array");

    for case in cases.iter_mut() {
        let name = case["name"]
            .as_str()
            .expect("each case has a name")
            .to_owned();
        let key = decode_fixed::<32>(&case["key_hex"]);
        let nonce = decode_fixed::<12>(&case["nonce_hex"]);

        // In regen mode we (re)compute the inputs from the named generator
        // and write them back to the fixture. In normal mode we read them
        // as opaque hex strings — exactly what the TS mirror does — to
        // exercise the same parser path.
        let (qub_id, sealed_cbor) = if regen {
            inputs_for_case(&name)
        } else {
            let qub_id = decode_fixed::<32>(&case["qub_id_hex"]);
            let sealed_bytes = decode_var(&case["sealed_cbor_hex"]);
            let sealed = SealedQubCbor::from_encoded(sealed_bytes)
                .unwrap_or_else(|e| panic!("case {name}: invalid sealed_cbor_hex: {e:?}"));
            (qub_id, sealed)
        };

        let wrapped = wrap_sealed_qub(&sealed_cbor, &qub_id, &key, &nonce)
            .unwrap_or_else(|e| panic!("case {name}: wrap failed: {e:?}"));
        let actual_hex = hex::encode(wrapped.as_bytes());

        if regen {
            case["qub_id_hex"] = serde_json::Value::String(hex::encode(qub_id));
            case["sealed_cbor_hex"] =
                serde_json::Value::String(hex::encode(sealed_cbor.as_bytes()));
            case["expected_wrapper_hex"] = serde_json::Value::String(actual_hex.clone());
        } else {
            let expected_hex = case["expected_wrapper_hex"]
                .as_str()
                .unwrap_or_else(|| panic!("case {name}: expected_wrapper_hex missing"));
            assert_eq!(
                actual_hex, expected_hex,
                "case {name}: wrapper bytes diverged from canonical fixture (rerun with {REGEN_ENV_VAR}=1 to update)"
            );
        }

        // Round-trip — independent of canonical output, must always hold.
        let recovered = unwrap_sealed_qub(&wrapped, &key)
            .unwrap_or_else(|e| panic!("case {name}: unwrap failed: {e:?}"));
        assert_eq!(
            recovered.as_bytes(),
            sealed_cbor.as_bytes(),
            "case {name}: round-trip diverged"
        );
    }

    if regen {
        let pretty = serde_json::to_string_pretty(&json).expect("re-serialise vectors");
        fs::write(vectors_path(), pretty + "\n").expect("write vectors fixture");
        eprintln!(
            "regenerated {} cases at {}",
            json["cases"].as_array().unwrap().len(),
            vectors_path().display()
        );
    }
}
