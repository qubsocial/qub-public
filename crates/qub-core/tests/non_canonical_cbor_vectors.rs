//! Shared cross-language negative-vector corpus for non-canonical CBOR
//! (SEC-3).
//!
//! The fixture file `tests/vectors/non_canonical_cbor.json` is the single
//! source of truth: this Rust test reads it and asserts the qub-core
//! decoder rejects every entry at the structural layer, and the
//! TypeScript mirror at
//! `workers/api/src/crypto/__tests__/non-canonical-cbor.test.ts` reads the
//! same JSON and asserts the same. The two decoders agreeing on what is
//! *not* canonical is what stops a two-party signed pact from verifying on
//! one platform and not the other.

use std::fs;
use std::path::PathBuf;

use qub_core::cbor::{CborError, deserialize_qub_envelope};

/// Every corpus entry must be rejected, and rejected at the structural /
/// canonical layer — `parse_top_level_map` runs before any field
/// validation, so a non-canonical input fails with `StructuralError`
/// (re-encode mismatch) or `DecodingFailed` (trailing bytes / malformed),
/// never with a field-level error such as `MissingField`.
#[test]
fn rust_decoder_rejects_every_non_canonical_vector() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/non_canonical_cbor.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let json: serde_json::Value =
        serde_json::from_str(&raw).expect("parse non_canonical_cbor.json");

    let vectors = json["vectors"]
        .as_array()
        .expect("non_canonical_cbor.json has a `vectors` array");
    assert!(!vectors.is_empty(), "corpus must not be empty");

    for v in vectors {
        let name = v["name"].as_str().expect("vector has a string `name`");
        let hex_str = v["hex"].as_str().expect("vector has a string `hex`");
        let reason = v["reason"].as_str().expect("vector has a string `reason`");

        let bytes =
            hex::decode(hex_str).unwrap_or_else(|e| panic!("vector {name:?} has invalid hex: {e}"));
        match deserialize_qub_envelope(&bytes) {
            Ok(_) => panic!(
                "vector {name:?} ({reason}) was ACCEPTED by the decoder but must be rejected",
            ),
            Err(CborError::StructuralError(_) | CborError::DecodingFailed(_)) => {},
            Err(other) => panic!(
                "vector {name:?} ({reason}) was rejected, but not at the structural layer: {other:?}",
            ),
        }
    }
}
