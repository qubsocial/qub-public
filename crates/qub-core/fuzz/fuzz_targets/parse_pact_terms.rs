// Phase 6 fuzz target — qub_core::pact::parse_pact_terms.
//
// PactTerms decoding is reachable from POST /api/v1/pact/stage and
// from the viewer when it cracks open a pact-content-type sealed
// qub. Fuzzing here protects both server-side intake and
// client-side render from panic on a malformed terms blob.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qub_core::pact::parse_pact_terms;

fuzz_target!(|data: &[u8]| {
    let _ = parse_pact_terms(data);
    // Roundtrip not asserted here — `PactTerms` does not have a
    // pure-CBOR re-encode path exposed; the canonical-bytes contract
    // is enforced by `crates/qub-core/tests/golden_pact_hashes.rs`.
});
