// Phase 6 fuzz target — qub_core::wrapper::unwrap_sealed_qub.
//
// AES-256-GCM unwrap is reachable from any viewer that follows a
// share URL: the wrapper key rides as the URL fragment, and the
// wrapped bytes come from R2 / Arweave (potentially attacker-
// controlled). A panic here would crash the WASM viewer on a
// malformed input; worse, an information leak in the error path
// (e.g. timing) could weaken the wrapper's privacy guarantee.
//
// Input shape: 32-byte key || 12-byte nonce || arbitrary wrapped
// CBOR map. We slice the fuzzer's bytes into those parts so
// libFuzzer can mutate any field independently.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qub_core::wrapper::{OuterWrapperCbor, unwrap_sealed_qub};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for the wrapper key.
    if data.len() < 32 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);

    // OuterWrapperCbor::from_encoded does its own structural check
    // (rejects non-map / oversize inputs early). Anything that
    // survives that goes through full AES-GCM decrypt + inner-map
    // verification. Both paths must be panic-free.
    if let Ok(wrapper) = OuterWrapperCbor::from_encoded(data[32..].to_vec()) {
        let _ = unwrap_sealed_qub(&wrapper, &key);
    }
});
