// Phase 6 fuzz target — qub_core::cbor::deserialize_sealed_qub.
//
// The decoder is a primary attack surface: any byte stream from
// Arweave / R2 / a malicious viewer-link reaches it. The goals
// of fuzzing are:
//   1. NEVER panic on any input — only `CborError::*` variants
//      should surface.
//   2. Roundtrip property: when decode succeeds, re-encode must
//      produce the same bytes (canonical CBOR contract).
//
// Seed corpus: pull `sealed_cbor_hex` from the cross-language
// vector file at `crates/qub-core/tests/vectors/wrapper_v1.json`
// — see scripts/fuzz-seed.sh (Phase 6 follow-up) for the
// generator. libFuzzer mutates from there.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qub_core::cbor::{deserialize_sealed_qub, serialize_sealed_qub};

fuzz_target!(|data: &[u8]| {
    if let Ok(sealed) = deserialize_sealed_qub(data) {
        // Roundtrip invariant: parsed output re-encodes byte-for-byte.
        let re_encoded =
            serialize_sealed_qub(&sealed).expect("re-encoding a parsed SealedQub must succeed");
        assert_eq!(
            re_encoded.as_slice(),
            data,
            "canonical CBOR roundtrip drift: parse(data).serialize() != data"
        );
    }
    // Decode failures are expected — only panics fail the fuzz run.
});
