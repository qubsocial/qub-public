// Phase 6 fuzz target — qub_core::cbor::deserialize_qub_envelope.
//
// QubEnvelope is the inner-content shape carried inside a
// SealedQub's tlock_ciphertext. After unlock, the bytes go through
// this decoder. A panic here is reachable by anyone holding a
// future-round drand signature.
//
// Goals match decode_sealed_qub: no panics, canonical roundtrip.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qub_core::cbor::{deserialize_qub_envelope, serialize_qub_envelope};

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = deserialize_qub_envelope(data) {
        let re_encoded = serialize_qub_envelope(&envelope)
            .expect("re-encoding a parsed QubEnvelope must succeed");
        assert_eq!(
            re_encoded.as_slice(),
            data,
            "canonical CBOR roundtrip drift on QubEnvelope"
        );
    }
});
