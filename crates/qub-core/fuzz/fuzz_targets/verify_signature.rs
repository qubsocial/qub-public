// 2026-05-13 security review — fuzz target for ML-DSA-65 signature
// verification (`qub_core::signing::verify`).
//
// ML-DSA-65 is the authorship-signing primitive (PROTOCOL.md §9).
// The verify path is reachable from every viewer-side unlock and
// every cross-impl read of a signed envelope, so a panic on
// malformed input is a denial-of-service surface against the
// trust-vertical promise. A bounds-check fault that accepts a
// malleated signature would be worse.
//
// Property fuzzed here:
//   * verify(pk, sig_input, sig) MUST terminate with `Ok(_)` or
//     `Err(QubError)` on any byte stream — never panic. libFuzzer
//     reports a panic as a crash, which auto-files an issue via
//     `.github/workflows/fuzz.yml`.
//
// Length-mismatch + bit-flip semantics are covered by the unit
// tests in `signing.rs` (deterministic) — this target adds runtime
// coverage of arbitrary inputs the unit tests can't enumerate.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qub_core::signing::{ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, verify};

const SIG_INPUT_LEN: usize = 32;

fuzz_target!(|data: &[u8]| {
    // First 32 bytes (or zero-padded) become the sig_input digest.
    let mut sig_input = [0u8; SIG_INPUT_LEN];
    let n = core::cmp::min(data.len(), SIG_INPUT_LEN);
    sig_input[..n].copy_from_slice(&data[..n]);

    let rest: &[u8] = if data.len() > SIG_INPUT_LEN {
        &data[SIG_INPUT_LEN..]
    } else {
        &[]
    };

    // Two regimes:
    //   * When `rest` is large enough to hold full-sized inputs,
    //     hand verify exact-length pk + sig so the fuzzer exercises
    //     the inner ML-DSA verify path (length checks pass).
    //   * Otherwise split `rest` arbitrarily so the fuzzer keeps the
    //     length-mismatch path warm.
    if rest.len() >= ML_DSA_65_PUBLIC_KEY_SIZE + ML_DSA_65_SIGNATURE_SIZE {
        let pk = &rest[..ML_DSA_65_PUBLIC_KEY_SIZE];
        let sig =
            &rest[ML_DSA_65_PUBLIC_KEY_SIZE..ML_DSA_65_PUBLIC_KEY_SIZE + ML_DSA_65_SIGNATURE_SIZE];
        let _ = verify(pk, &sig_input, sig);
    } else {
        let split = rest.len() / 2;
        let _ = verify(&rest[..split], &sig_input, &rest[split..]);
    }
});
