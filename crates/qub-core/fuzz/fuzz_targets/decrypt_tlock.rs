// 2026-05 security review (SEC-16) — fuzz target for drand timelock
// decryption (`qub_core::tlock::TimelockProvider::decrypt`).
//
// The tlock ciphertext is the `SealedQub.tlock_ciphertext` field —
// fully attacker-controlled bytes fetched from Arweave. `unlock()`
// hands it (and the drand round signature) straight to
// `TimelockProvider::decrypt`, so a panic in the IBE / age decryption
// path is a denial-of-service surface against every viewer.
//
// Property fuzzed: `decrypt` MUST terminate with `Ok(_)` or
// `Err(TimelockError)` on any byte stream — never panic. libFuzzer
// reports a panic as a crash, which auto-files an issue via
// `.github/workflows/fuzz.yml`.
//
// Input shape: the first 96 bytes (or fewer) are the drand round
// signature; the remainder is the tlock ciphertext. The fuzzer can
// mutate either side independently.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qub_core::tlock::{DrandTimelockProvider, TimelockProvider};

/// drand quicknet beacon signatures are G1 points (96 bytes).
const ROUND_SIG_LEN: usize = 96;

fuzz_target!(|data: &[u8]| {
    let provider = DrandTimelockProvider::quicknet();
    let split = core::cmp::min(data.len(), ROUND_SIG_LEN);
    let (round_signature, ciphertext) = data.split_at(split);
    let _ = provider.decrypt(ciphertext, round_signature);
});
