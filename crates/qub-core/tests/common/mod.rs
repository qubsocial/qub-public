//! Shared proptest strategies — `STANDARD.md` §6.5, as amended 2026-08-24.
//!
//! # Why the strategies live here and not beside their properties
//!
//! `tests/property_reach.rs` measures the distribution these produce and fails
//! when a declared partition is never reached. That measurement is only worth
//! anything if it samples **the same strategy the property draws from**. A
//! strategy copied into two files drifts, and a reach harness sampling a copy
//! is measuring something no property uses — which is the defect it exists to
//! catch, wearing the harness's own clothes.
//!
//! So: one definition, imported by both. If a property needs a different
//! distribution, it gets a new function here and a new partition table there.
//!
//! # What each of these is widened FOR
//!
//! Every strategy below replaced a narrower one, and each replacement closed a
//! partition the reach harness proved unreachable. The narrow versions are
//! quoted in the doc comments rather than deleted from history, because "why is
//! this generator so elaborate" is the question a future reader will ask.

// EVERY TEST BINARY COMPILES THIS FILE SEPARATELY, and no one of them uses all
// of it: `handle.rs` draws handles and challenge pairs, `integration.rs` draws
// bodies and labels, `property_reach.rs` draws all five. Rust warns
// per-binary, and the workspace runs CI with `-D warnings`, so without this the
// build fails on functions that ARE used — just not by the binary complaining.
//
// Scoped to this module rather than sprinkled per-item so that a genuinely
// dead strategy is still visible: it will have no caller anywhere, which is
// what `scripts/check-*`-style review catches, and what `property_reach.rs`
// makes loud — a strategy nothing samples has no partition table.
#![allow(dead_code, reason = "each test binary uses a different subset")]

use proptest::prelude::*;

/// Proptest cases per property under Miri — see [`config`].
pub const MIRI_CASES: u32 = 8;

/// The fixed RNG seed properties draw from under Miri — see [`config`].
pub const MIRI_SEED: u64 = 0x5eed_09ab;

/// The proptest config for a property: `native` cases from a fresh seed
/// normally; [`MIRI_CASES`] from [`MIRI_SEED`] under Miri.
///
/// The two runs answer different questions. The native run (nextest, every PR)
/// explores the INPUT space, and its volume is what the reach harness in
/// `property_reach.rs` is calibrated against. Miri (miri.yml, weekly) looks for
/// undefined behaviour along the CODE PATHS qub-core drives into its
/// dependencies — qub-core itself has no `unsafe` — and every case walks the
/// same paths at up to minutes of interpretation each. At native volume the
/// proptests alone cost Miri hours, and the weekly job hit its timeout on
/// every scheduled run it ever had (miri.yml has the history). A handful of
/// cases keeps every property executing under Miri; the volume stays where it
/// is measured.
///
/// The seed is fixed under Miri because a case's cost is not constant:
/// `wire_body_bytes` draws its ~64 KB band one time in eight, and one such
/// draw costs minutes to interpret, so with a fresh seed eight cases cost
/// anywhere from none to several of them — a job whose runtime is a lottery
/// eventually loses it to its timeout. Fixed, the cost is the same every week,
/// and a UB report reproduces from the seed.
#[must_use]
pub fn config(native: u32) -> ProptestConfig {
    let mut config = ProptestConfig::with_cases(if cfg!(miri) { MIRI_CASES } else { native });
    if cfg!(miri) {
        config.rng_seed = proptest::test_runner::RngSeed::Fixed(MIRI_SEED);
    }
    config
}

/// Body bytes that reach **all four** canonical-CBOR length encodings.
///
/// Canonical CBOR (PROTOCOL.md §3) requires the shortest length encoding, and
/// which one is shortest changes at 24, 256 and 65,536 bytes. Those three
/// thresholds are branches in the encoder, and the bytes they produce are
/// hashed into `qub_id`.
///
/// **Was `vec(any::<u8>(), 1..1000)`.** Measured over its own 128 draws that
/// reached the inline, 1-byte and 2-byte forms and **never the 4-byte form** —
/// it cannot, 1000 < 65,536. So the canonicality property had never once
/// exercised the length encoding used by every pact body over 64 KB, on a codec
/// whose output identifies the qub.
///
/// The weights are deliberate: the large band is expensive (each draw is ~64 KB
/// of random bytes through a full serialise / parse / re-serialise cycle) and
/// one in eight draws is enough to reach it reliably at 128 cases while keeping
/// the property's runtime in the same order it was.
pub fn wire_body_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => proptest::collection::vec(any::<u8>(), 1..24),
        3 => proptest::collection::vec(any::<u8>(), 24..256),
        3 => proptest::collection::vec(any::<u8>(), 256..2_000),
        1 => proptest::collection::vec(any::<u8>(), LARGE_BODY),
    ]
}

/// The large band of [`wire_body_bytes`]: past 65,535 bytes natively, which is
/// what reaches the 4-byte length prefix. Under Miri it is ~2 KB instead —
/// same weights, so native draws are untouched. That prefix is a branch in
/// qub-core's own safe code, which is the native run's job (and the reach
/// harness that insists on it is `ignore`d under Miri); what Miri checks for
/// UB, the hashing and codec below it, takes the same path at 2 KB, and one
/// 64 KB draw cost minutes of interpretation per case.
const LARGE_BODY: std::ops::Range<usize> = if cfg!(miri) {
    2_000..2_100
} else {
    65_536..66_100
};

/// The three length encodings a **free text body** can reach.
///
/// `max_body_size(CONTENT_TYPE_TEXT, false)` is 10,240, so the 4-byte length
/// prefix is unreachable here **by a real bound rather than by a narrow
/// generator**, and the two are worth telling apart: one is a gap to close, the
/// other is the system's own limit. `wire_body_bytes` covers the fourth form on
/// the path that has no such cap.
pub fn text_compose_body_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        1 => proptest::collection::vec(1u8..=255, 1..24),
        1 => proptest::collection::vec(1u8..=255, 24..256),
        1 => proptest::collection::vec(1u8..=255, 256..=10_240),
    ]
}

/// Sender labels that reach absence, both sides of a CBOR length boundary, and
/// **text that NFC normalisation changes**.
///
/// **Was `option::of("[a-zA-Z0-9 ]{1,50}")`.** That alphabet is exactly the set
/// of characters `validate_sender_label` has nothing to say about: it cannot
/// express a hostile codepoint, cannot exceed the 80-code-point cap, and — the
/// one that mattered — cannot produce a string NFC changes.
///
/// The last is not a hypothetical. `cbor.rs` NFC-normalises on the way out
/// (`s.nfc().collect()`), so a decomposed label is a DIFFERENT string after a
/// round-trip. The round-trip properties compared the revealed label against
/// the pre-normalisation draw and passed for years — because the generator
/// could not produce a value on which that comparison was wrong. Widening the
/// alphabet made them fail, correctly, and they now compare against the NFC
/// form, which is the guarantee the protocol actually makes.
///
/// The decomposed forms below are `e` + U+0301 (combining acute) and `a` +
/// U+030A (combining ring), which NFC composes to `é` and `å`. Both are
/// ordinary in European names, which is what a sender label holds.
pub fn sender_label() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(prop_oneof![
        3 => "[a-zA-Z0-9 ]{1,50}",
        1 => "[a-zA-Z ]{0,20}(e\u{0301}|a\u{030A}|o\u{0308})[a-zA-Z ]{0,20}",
        1 => "[\u{00E0}-\u{00FF}]{1,40}",
    ])
}

/// Handle inputs that reach acceptance, the reserved deny list, **and**
/// rejection.
///
/// **Was `"[a-z][a-z0-9_]{2,19}"`.** Valid charset, valid length, every draw.
/// The property that consumed it matched on three outcomes and the generator
/// could produce one: `Ok`. The `Err(Reserved)` arm needed a random string to
/// land on a hand-curated deny-list entry, and the `Err(other)` arm was written
/// as `prop_assert!(false, …)` — an assertion guarding a branch nothing could
/// enter.
///
/// The reserved words are drawn from `RESERVED_HANDLES` itself rather than
/// spelled out here, so the strategy cannot go stale against the list: an entry
/// removed from the deny list is removed from this generator on the same
/// commit.
pub fn handle_input() -> impl Strategy<Value = String> {
    let reserved = prop::sample::select(qub_core::handle_reserved::RESERVED_HANDLES)
        .prop_map(|word| (*word).to_owned());
    prop_oneof![
        // Plainly valid.
        6 => "[a-z][a-z0-9_]{2,19}".prop_map(|s| s),
        // On the deny list.
        2 => reserved,
        // Too short, too long, leading digit, disallowed script, and an
        // invisible character — one draw each from the rejection space.
        1 => prop_oneof![
            "[a-z]{1,2}",
            "[a-z]{21,30}",
            "[0-9][a-z0-9_]{3,10}",
            "[a-z]{2}[\u{4E00}-\u{4E20}][a-z]{2}",
            "[a-z]{2}\u{200B}[a-z]{2}",
        ],
    ]
}

/// A pair of challenge inputs that sometimes agree.
///
/// **Was four independent draws.** The property they fed reads:
///
/// ```text
/// if fp_a != fp_b || cur_a != cur_b || new_a != new_b || ts_a != ts_b {
///     prop_assert_ne!(c1, c2);
/// } else {
///     prop_assert_eq!(c1, c2);   // determinism
/// }
/// ```
///
/// `fp_a` and `fp_b` are independently drawn 32-byte arrays, so the `else` arm
/// requires a 2^-256 coincidence. It has never executed. The property's name
/// says "injective", and injectivity has two halves — distinct inputs give
/// distinct outputs, **and equal inputs give equal outputs** — and only one
/// half was ever tested.
///
/// This returns the two tuples plus the flag that decided, so the property can
/// take the branch deliberately instead of waiting for the universe to.
pub type ChallengePair = ([u8; 32], String, String, i64, [u8; 32], String, String, i64);

pub fn challenge_pair() -> impl Strategy<Value = ChallengePair> {
    (
        proptest::array::uniform32(any::<u8>()),
        "[a-z][a-z0-9_]{2,19}",
        "[a-z][a-z0-9_]{2,19}",
        any::<i64>(),
        proptest::array::uniform32(any::<u8>()),
        "[a-z][a-z0-9_]{2,19}",
        "[a-z][a-z0-9_]{2,19}",
        any::<i64>(),
        // Half the draws reuse the first tuple for the second, which is the
        // only way the equality arm is ever reached.
        any::<bool>(),
    )
        .prop_map(
            |(fp_a, cur_a, new_a, ts_a, fp_b, cur_b, new_b, ts_b, same)| {
                if same {
                    (
                        fp_a,
                        cur_a.clone(),
                        new_a.clone(),
                        ts_a,
                        fp_a,
                        cur_a,
                        new_a,
                        ts_a,
                    )
                } else {
                    (fp_a, cur_a, new_a, ts_a, fp_b, cur_b, new_b, ts_b)
                }
            },
        )
}
