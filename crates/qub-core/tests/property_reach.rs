//! Generator reach — `STANDARD.md` §6.5, as amended 2026-08-24.
//!
//! # What this file exists to refuse
//!
//! > *A generator that cannot reach the boundary its predicate turns on is
//! > decoration.*
//!
//! §6.5's property clause used to be a presence check, and the amendment says
//! why that was not enough: `lagstyr#343` added seven properties over integer
//! money, and **two of them passed against mutants the pre-existing example
//! tests already caught**. Both were generator defects, not assertion defects.
//! `any::<i64>()` draws zero one time in 2^64; `".*"` never draws `"usd"`. The
//! assertions were right. The generators never presented an input on which they
//! could be wrong.
//!
//! Mutation testing cannot see this. §6.5 says so in as many words: "mutation
//! cannot tell a property that killed from a property that could never have
//! failed, because both kill." Coverage cannot see it either — the property's
//! lines all execute. The only thing that can see it is **sampling the
//! generator and counting**, which is what this file does.
//!
//! # Obligation 1, discharged as a test rather than as a report
//!
//! The amendment's first obligation is "measure the distribution; do not infer
//! it from the strategy source". A report would go stale the first time a
//! strategy changed. These are assertions, so a strategy that stops reaching a
//! partition fails a test rather than making a document wrong.
//!
//! **Deliberately no floor.** §6.5: "There is no minimum case count and no
//! minimum property count here, because 'cases executed' is the property-test
//! analogue of measuring coverage and doing nothing with the number." The
//! assertion is `>= 1` — reached at all — and the printed table is the
//! distribution, for a human to read. A partition hit once in 256 draws passes
//! and should still make somebody uncomfortable, which is the point of printing
//! it.
//!
//! # The case counts here are the properties' own
//!
//! Each block below samples the SAME number of draws its property is configured
//! for. A reach measurement taken at 100,000 draws would answer a question
//! nobody asked: the obligation is about the distribution the property actually
//! sees, and at 256 draws a one-in-a-thousand partition is not reached.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use proptest::prelude::*;
use proptest::strategy::ValueTree as _;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use unicode_normalization::UnicodeNormalization as _;

mod common;

/// A tally of which partitions a sample of draws reached.
struct Reach {
    property: &'static str,
    draws: usize,
    counts: BTreeMap<&'static str, usize>,
}

impl Reach {
    /// Declares every partition up front.
    ///
    /// Declaring is separate from hitting on purpose. A partition that is only
    /// created when first hit can never be reported as unreached — the map
    /// would simply not contain it, and the assertion below would pass over
    /// an absence. That is the same shape as an empty result reading as a pass.
    fn new(property: &'static str, draws: usize, partitions: &[&'static str]) -> Self {
        let mut counts = BTreeMap::new();
        for partition in partitions {
            counts.insert(*partition, 0);
        }
        Self {
            property,
            draws,
            counts,
        }
    }

    fn hit(&mut self, partition: &'static str) {
        *self
            .counts
            .get_mut(partition)
            .unwrap_or_else(|| panic!("`{partition}` was hit but never declared")) += 1;
    }

    /// Prints the distribution and fails on any partition never reached.
    fn assert_every_partition_reached(&self) {
        let mut report = format!(
            "\n{} — {} draws\n{:<44} {:>7} {:>8}\n",
            self.property, self.draws, "partition", "hits", "share"
        );
        let mut unreached = Vec::new();
        for (partition, hits) in &self.counts {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a percentage for a human to read; the assertion is on the integer"
            )]
            let share = (*hits as f64) * 100.0 / (self.draws as f64);
            let _ = writeln!(report, "{partition:<44} {hits:>7} {share:>7.2}%");
            if *hits == 0 {
                unreached.push(*partition);
            }
        }
        // Printed on success as well as on failure: the obligation is to
        // MEASURE the distribution, and a number only visible when something
        // is already broken is not a measurement anybody reads.
        eprint!("{report}");
        assert!(
            unreached.is_empty(),
            "{}: {} partition(s) NEVER REACHED in {} draws: {:?}\n\
             {report}\n\
             A generator that cannot reach the boundary its predicate turns on \
             is decoration (STANDARD.md §6.5). Widen the strategy — do not \
             delete the partition.",
            self.property,
            unreached.len(),
            self.draws,
            unreached,
        );
    }
}

// MIRI_REACH — every test here is `ignore`d under Miri, visibly, and on purpose.
//
// This file measures the GENERATORS: that 128 or 256 draws reach every declared
// partition. Under Miri the properties run `common::MIRI_CASES`, not those
// volumes, so a reach assertion there would be about a run that does not
// happen. And it is the wrong tool for Miri's question — the draws are proptest
// code, and the one qub-core call (`normalise_handle`) is already interpreted by
// `handle.rs`. Measured cost of the first test alone under Miri: over 25
// minutes, of a weekly job that had never once finished (miri.yml).

/// Draws `count` values from a strategy with a fixed RNG.
///
/// Fixed, so a red run is reproducible and a green one is not luck. The
/// alternative — a fresh entropy seed each run — makes a marginal partition
/// flap between reached and unreached, and a flapping gate is one people learn
/// to re-run.
fn sample<S: Strategy>(strategy: &S, count: usize, mut visit: impl FnMut(S::Value)) {
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    for _ in 0..count {
        let tree = strategy
            .new_tree(&mut runner)
            .expect("the strategy must produce a value");
        visit(tree.current());
    }
}

// ---------------------------------------------------------------------------
// CBOR round-trip and canonicality (integration.rs, 128 and 256 cases)
// ---------------------------------------------------------------------------

/// The partitions the CBOR encoder actually branches on.
///
/// **A byte-string length is not one number to the encoder, it is four.**
/// Canonical CBOR (PROTOCOL.md §3) requires the shortest length encoding, and
/// which one is shortest changes at 24, 256 and 65,536. Those three thresholds
/// are the boundaries the canonicality property turns on, and a body-length
/// strategy that never crosses the last of them has never exercised the 4-byte
/// prefix — on a codec whose output is hashed into `qub_id`.
#[test]
#[cfg_attr(
    miri,
    ignore = "reach is a property of the native case volume; see MIRI_REACH"
)]
fn cbor_body_length_generator_reaches_every_length_prefix() {
    let strategy = common::wire_body_bytes();
    let mut reach = Reach::new(
        "envelope_cbor_round_trip::body",
        128,
        &[
            "tiny: len < 24 (length inline in the head byte)",
            "small: 24 <= len < 256 (1-byte length prefix)",
            "medium: 256 <= len < 65536 (2-byte length prefix)",
            "large: len >= 65536 (4-byte length prefix)",
        ],
    );
    sample(&strategy, 128, |body| {
        reach.hit(match body.len() {
            0..=23 => "tiny: len < 24 (length inline in the head byte)",
            24..=255 => "small: 24 <= len < 256 (1-byte length prefix)",
            256..=65_535 => "medium: 256 <= len < 65536 (2-byte length prefix)",
            _ => "large: len >= 65536 (4-byte length prefix)",
        });
    });
    reach.assert_every_partition_reached();
}

/// `sender_label` is optional, bounded, and NFC-normalised. Three properties
/// pass it through and all three draw from `[a-zA-Z0-9 ]{1,50}`, which is an
/// alphabet that cannot express any of the things the validator exists to
/// reject.
#[test]
#[cfg_attr(
    miri,
    ignore = "reach is a property of the native case volume; see MIRI_REACH"
)]
fn sender_label_generator_reaches_absent_present_and_the_length_bound() {
    let strategy = common::sender_label();
    let mut reach = Reach::new(
        "envelope_cbor_round_trip::sender_label",
        128,
        &[
            "absent (None)",
            "present, short (len <= 24)",
            "present, long (len > 24)",
            "present, non-ASCII",
            "present, NFC changes it",
        ],
    );
    sample(&strategy, 128, |label| {
        let Some(label) = label else {
            reach.hit("absent (None)");
            return;
        };
        if !label.is_ascii() {
            reach.hit("present, non-ASCII");
        }
        // THE PARTITION THAT MATTERED. `cbor.rs` normalises text on the way
        // out, so a decomposed label is a different string after a round-trip.
        // The old alphabet could not produce one, and the round-trip properties
        // compared against the raw draw and passed for years.
        let normalised: String = label.nfc().collect();
        if normalised != label {
            reach.hit("present, NFC changes it");
        }
        if label.chars().count() > 24 {
            reach.hit("present, long (len > 24)");
        } else {
            reach.hit("present, short (len <= 24)");
        }
    });
    reach.assert_every_partition_reached();
}

// ---------------------------------------------------------------------------
// Challenge injectivity (handle.rs, 256 cases)
// ---------------------------------------------------------------------------

/// `rename_challenge_distinct_on_any_input_diff` has two branches, and one of
/// them is unreachable.
///
/// ```text
/// if fp_a != fp_b || cur_a != cur_b || new_a != new_b || ts_a != ts_b {
///     prop_assert_ne!(c1, c2);      // taken every time
/// } else {
///     prop_assert_eq!(c1, c2);      // requires two independent draws to agree
/// }
/// ```
///
/// `fp_a` and `fp_b` are independently drawn 32-byte arrays. Their agreeing is
/// a 2^-256 event, so the `else` arm — the one asserting the challenge builder
/// is DETERMINISTIC — has never executed and never will. This is the
/// amendment's `any::<i64>()` case, several orders of magnitude further out.
#[test]
#[cfg_attr(
    miri,
    ignore = "reach is a property of the native case volume; see MIRI_REACH"
)]
fn challenge_injectivity_generator_reaches_both_of_its_branches() {
    let strategy = common::challenge_pair();
    let mut reach = Reach::new(
        "rename_challenge_is_injective_in_both_directions",
        256,
        &[
            "inputs differ -> assert challenges differ",
            "inputs identical -> assert challenges match",
        ],
    );
    sample(
        &strategy,
        256,
        |(fp_a, cur_a, new_a, ts_a, fp_b, cur_b, new_b, ts_b)| {
            if fp_a == fp_b && cur_a == cur_b && new_a == new_b && ts_a == ts_b {
                reach.hit("inputs identical -> assert challenges match");
            } else {
                reach.hit("inputs differ -> assert challenges differ");
            }
        },
    );
    reach.assert_every_partition_reached();
}

// ---------------------------------------------------------------------------
// Handle normalisation (handle.rs, 256 cases)
// ---------------------------------------------------------------------------

/// `normalise_idempotent_on_valid_handles` matches on three outcomes and its
/// generator can produce one.
///
/// The strategy is `"[a-z][a-z0-9_]{2,19}"` — the valid charset, at valid
/// lengths, always. The `Err(Reserved)` arm needs the draw to land on an entry
/// of a hand-curated deny list, and the `Err(other)` arm is written to fail the
/// test. So of three arms, one is live, one is a lottery, and one is an
/// assertion.
#[test]
#[cfg_attr(
    miri,
    ignore = "reach is a property of the native case volume; see MIRI_REACH"
)]
fn handle_generator_reaches_the_reserved_and_rejected_outcomes() {
    use qub_core::handle::{HandleValidationError, normalise_handle};

    let strategy = common::handle_input();
    let mut reach = Reach::new(
        "normalise_is_idempotent_and_rejection_is_deterministic",
        256,
        &[
            "Ok(normalised)",
            "Err(Reserved) — the deny list fires",
            "Err(other) — some other rejection",
        ],
    );
    sample(&strategy, 256, |raw: String| {
        reach.hit(match normalise_handle(&raw) {
            Ok(_) => "Ok(normalised)",
            Err(HandleValidationError::Reserved) => "Err(Reserved) — the deny list fires",
            Err(_) => "Err(other) — some other rejection",
        });
    });
    reach.assert_every_partition_reached();
}

/// A body cap is not the same thing as a narrow generator, and this test is
/// where the difference is written down.
///
/// `max_body_size(CONTENT_TYPE_TEXT, false)` is 10,240, so a free text body can
/// never reach CBOR's 4-byte length prefix. Declaring that partition here and
/// letting it fail would be false: the system refuses those bodies. Declaring
/// only three, and saying why the fourth is absent, is the honest record —
/// `cbor_body_length_generator_reaches_every_length_prefix` covers the fourth
/// on the wire path, which has no such cap.
#[test]
#[cfg_attr(
    miri,
    ignore = "reach is a property of the native case volume; see MIRI_REACH"
)]
fn text_compose_body_generator_reaches_every_prefix_its_cap_permits() {
    let strategy = common::text_compose_body_bytes();
    let mut reach = Reach::new(
        "valid_compose_roundtrips_all_fields::body",
        256,
        &[
            "tiny: len < 24",
            "small: 24 <= len < 256",
            "medium: 256 <= len <= 10,240 (the free-text cap)",
        ],
    );
    sample(&strategy, 256, |body| {
        reach.hit(match body.len() {
            0..=23 => "tiny: len < 24",
            24..=255 => "small: 24 <= len < 256",
            _ => "medium: 256 <= len <= 10,240 (the free-text cap)",
        });
    });
    reach.assert_every_partition_reached();
}
