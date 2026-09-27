//! Property and integration tests for the handle module.
//!
//! Mirrors the style of `tests/integration.rs` — proptest-based
//! invariants over normalisation idempotence, challenge injectivity,
//! and auto-shape round-trip against the auto-allocator output.

use proptest::prelude::*;

use qub_core::handle::{
    AVATAR_SET_DOMAIN, HANDLE_DELETE_DOMAIN, HANDLE_RENAME_DOMAIN, HandleValidationError,
    PROFILE_SET_DOMAIN, build_avatar_set_challenge, build_delete_challenge,
    build_profile_set_challenge, build_rename_challenge, is_auto_allocated_shape, normalise_handle,
};

// -----------------------------------------------------------------------------
// Fixed-vector sanity
// -----------------------------------------------------------------------------

#[test]
fn rename_challenge_exact_length_for_canonical_inputs() {
    let fp = [0x42u8; 32];
    let challenge = build_rename_challenge(&fp, "quiet_fox_482", "markharper", 1_735_689_600);
    let expected =
        HANDLE_RENAME_DOMAIN.len() + 32 + 8 + "quiet_fox_482".len() + 8 + "markharper".len() + 8;
    assert_eq!(challenge.len(), expected);
}

#[test]
fn rename_challenge_length_prefixes_disambiguate_handle_boundary() {
    let fp = [0x42u8; 32];
    // These two valid handle pairs have the same bare concatenation. The V1
    // layout therefore signed identical bytes for two different renames.
    assert_eq!(
        format!("{}{}", "abc", "defg"),
        format!("{}{}", "abcd", "efg")
    );
    let first = build_rename_challenge(&fp, "abc", "defg", 1_735_689_600);
    let second = build_rename_challenge(&fp, "abcd", "efg", 1_735_689_600);
    assert_ne!(first, second);
}

#[test]
fn delete_challenge_binds_handle_value() {
    let fp = [0x42u8; 32];
    let challenge = build_delete_challenge(&fp, "alice", 0);
    // domain (29) + fp (32) + utf8("alice") (5) + ts (8)
    assert_eq!(challenge.len(), HANDLE_DELETE_DOMAIN.len() + 32 + 5 + 8);
    assert_eq!(
        &challenge[..HANDLE_DELETE_DOMAIN.len()],
        HANDLE_DELETE_DOMAIN
    );
    let handle_offset = HANDLE_DELETE_DOMAIN.len() + 32;
    assert_eq!(&challenge[handle_offset..handle_offset + 5], b"alice");
    // A different handle must produce different bytes (Finding 5).
    let other = build_delete_challenge(&fp, "alicx", 0);
    assert_ne!(challenge, other);
}

#[test]
fn profile_set_domain_is_27_ascii_bytes() {
    assert_eq!(PROFILE_SET_DOMAIN.len(), 27);
    assert!(PROFILE_SET_DOMAIN.iter().all(u8::is_ascii));
    assert_eq!(&PROFILE_SET_DOMAIN[..], b"QUB_IDENTITY_PROFILE_SET_V2");
}

#[test]
fn profile_set_challenge_byte_layout_for_canonical_inputs() {
    let fp = [0x42u8; 32];
    let prev_updated_at: i64 = 1_700_000_000;
    let display_name = "Mark Harper";
    let url = "https://barranjoey.com.au";
    let timestamp: i64 = 1_735_689_600;
    let c = build_profile_set_challenge(
        &fp,
        prev_updated_at,
        Some(display_name),
        Some(url),
        timestamp,
    );

    let expected = PROFILE_SET_DOMAIN.len()
        + 32
        + 8 // prev_updated_at
        + 1 // presence bitmask
        + 2 + display_name.len() // display_name length-prefixed (already NFC)
        + 2 + url.len()           // url length-prefixed
        + 8; // timestamp
    assert_eq!(c.len(), expected);

    let mut offset = 0;
    assert_eq!(&c[offset..offset + 27], PROFILE_SET_DOMAIN);
    offset += 27;
    assert_eq!(&c[offset..offset + 32], &fp);
    offset += 32;
    assert_eq!(
        i64::from_be_bytes(c[offset..offset + 8].try_into().unwrap()),
        prev_updated_at
    );
    offset += 8;
    // Presence bitmask: both fields present (set) -> 0b11.
    assert_eq!(c[offset], 0b0000_0011);
    offset += 1;
    let dn_len = u16::from_be_bytes([c[offset], c[offset + 1]]);
    offset += 2;
    assert_eq!(dn_len as usize, display_name.len());
    assert_eq!(
        &c[offset..offset + dn_len as usize],
        display_name.as_bytes()
    );
    offset += dn_len as usize;
    let url_len = u16::from_be_bytes([c[offset], c[offset + 1]]);
    offset += 2;
    assert_eq!(url_len as usize, url.len());
    assert_eq!(&c[offset..offset + url_len as usize], url.as_bytes());
    offset += url_len as usize;
    assert_eq!(
        i64::from_be_bytes(c[offset..offset + 8].try_into().unwrap()),
        timestamp
    );
}

#[test]
fn profile_set_challenge_handles_empty_clear_signal() {
    // Some("") + Some("") is the "clear both fields" signal. Layout still
    // includes the presence byte (both set -> 0b11) plus the two zero
    // length prefixes and the timestamp tail.
    let fp = [0u8; 32];
    let c = build_profile_set_challenge(&fp, 0, Some(""), Some(""), 0);
    // domain (27) + fp (32) + prev (8) + presence (1) + dn_len (2)
    // + url_len (2) + ts (8).
    let expected = PROFILE_SET_DOMAIN.len() + 32 + 8 + 1 + 2 + 2 + 8;
    assert_eq!(c.len(), expected);
    // Presence byte: both present (clear is "present-and-empty").
    let presence_offset = PROFILE_SET_DOMAIN.len() + 32 + 8;
    assert_eq!(c[presence_offset], 0b0000_0011);
    // Length prefixes both zero.
    let dn_offset = presence_offset + 1;
    assert_eq!(u16::from_be_bytes([c[dn_offset], c[dn_offset + 1]]), 0);
    let url_offset = dn_offset + 2;
    assert_eq!(u16::from_be_bytes([c[url_offset], c[url_offset + 1]]), 0);
}

#[test]
fn reserved_deny_list_folds_nfc_stable_confusables() {
    // NFC is canonical and does not fold compatibility characters, so
    // these lookalikes pass the single-script Latin check but never equal
    // the ASCII reserved entries. NFKC folds them back — reject as
    // Reserved. Parity mirror of the Worker `normaliseHandle` test in
    // `workers/api/src/routes/__tests__/handle-alloc.test.ts`.
    // Only platform-reserved words live in qub-core's deny list; brand
    // words (paypal, etc.) are enforced server-side in the Worker.
    for confusable in [
        "\u{FF41}\u{FF44}\u{FF4D}\u{FF49}\u{FF4E}", // fullwidth "admin"
        "o\u{FB03}cial",                            // "o" + ﬃ (U+FB03) + "cial" -> "official"
    ] {
        assert_eq!(
            normalise_handle(confusable),
            Err(HandleValidationError::Reserved),
            "confusable {confusable:?} must fold to a reserved word",
        );
    }
}

#[test]
fn profile_set_challenge_omit_and_clear_sign_to_different_bytes() {
    // The crux of Finding 1: an omitted field (None = "keep existing")
    // and a cleared field (Some("") = "clear") MUST produce different
    // signed bytes on BOTH axes, so a captured "set one field" request
    // cannot be tampered to also clear the other without breaking the
    // signature.
    let fp = [7u8; 32];

    // display_name axis: omit name vs clear name (url fixed).
    let omit_name = build_profile_set_challenge(&fp, 0, None, Some("https://x.com"), 9);
    let clear_name = build_profile_set_challenge(&fp, 0, Some(""), Some("https://x.com"), 9);
    assert_ne!(omit_name, clear_name);
    // They differ only in the presence byte (offset 67).
    let presence_offset = PROFILE_SET_DOMAIN.len() + 32 + 8;
    assert_eq!(omit_name[presence_offset], 0b0000_0010); // url only
    assert_eq!(clear_name[presence_offset], 0b0000_0011); // dn + url

    // url axis: omit url vs clear url (name fixed).
    let omit_url = build_profile_set_challenge(&fp, 0, Some("Alice"), None, 9);
    let clear_url = build_profile_set_challenge(&fp, 0, Some("Alice"), Some(""), 9);
    assert_ne!(omit_url, clear_url);
    assert_eq!(omit_url[presence_offset], 0b0000_0001); // dn only
    assert_eq!(clear_url[presence_offset], 0b0000_0011); // dn + url
}

#[test]
fn profile_set_challenge_nfc_normalises_display_name() {
    // NFD form of "Café" — 'e' followed by combining acute. NFC
    // collapses to a single 'é'. The challenge MUST emit the NFC
    // form so the TS and Rust implementations agree byte-for-byte.
    let fp = [0u8; 32];
    let decomposed = "Cafe\u{0301}";
    let composed = "Café";
    assert_ne!(decomposed, composed); // sanity — they're different bytes
    let from_decomposed = build_profile_set_challenge(&fp, 0, Some(decomposed), Some(""), 0);
    let from_composed = build_profile_set_challenge(&fp, 0, Some(composed), Some(""), 0);
    assert_eq!(
        from_decomposed, from_composed,
        "NFC normalisation must be idempotent"
    );
}

#[test]
fn profile_set_challenge_changes_when_prev_updated_at_changes() {
    // CAS token is part of the signed bytes — different prev values
    // must produce different challenges so a captured signature can
    // never be replayed across an intervening edit.
    let fp = [1u8; 32];
    let a = build_profile_set_challenge(&fp, 100, Some("name"), Some("https://x.com"), 200);
    let b = build_profile_set_challenge(&fp, 101, Some("name"), Some("https://x.com"), 200);
    assert_ne!(a, b);
}

#[test]
fn avatar_set_domain_is_26_ascii_bytes() {
    assert_eq!(AVATAR_SET_DOMAIN.len(), 26);
    assert!(AVATAR_SET_DOMAIN.iter().all(u8::is_ascii));
    assert_eq!(&AVATAR_SET_DOMAIN[..], b"QUB_IDENTITY_AVATAR_SET_V1");
}

#[test]
fn avatar_set_challenge_byte_layout() {
    // Fixed 98 bytes: domain (26) + fingerprint (32) + image_hash (32)
    // + timestamp (8). The TS `buildAvatarSetChallenge` MUST emit the
    // identical layout — see workers/api/src/routes/attestation.ts.
    let fp = [0x42u8; 32];
    let image_hash = [0x99u8; 32];
    let timestamp: i64 = 1_735_689_600;
    let c = build_avatar_set_challenge(&fp, &image_hash, timestamp);

    assert_eq!(c.len(), 26 + 32 + 32 + 8);
    let mut offset = 0;
    assert_eq!(&c[offset..offset + 26], AVATAR_SET_DOMAIN);
    offset += 26;
    assert_eq!(&c[offset..offset + 32], &fp);
    offset += 32;
    assert_eq!(&c[offset..offset + 32], &image_hash);
    offset += 32;
    assert_eq!(
        i64::from_be_bytes(c[offset..offset + 8].try_into().unwrap()),
        timestamp
    );
}

#[test]
fn avatar_set_challenge_binds_to_image_hash() {
    // A different image hash (or the all-zero removal sentinel) must
    // produce a different challenge so a captured upload signature
    // cannot be replayed against a substituted image.
    let fp = [1u8; 32];
    let upload = build_avatar_set_challenge(&fp, &[0xabu8; 32], 200);
    let removal = build_avatar_set_challenge(&fp, &[0u8; 32], 200);
    assert_ne!(upload, removal);
}

// -----------------------------------------------------------------------------
// Proptest invariants
// -----------------------------------------------------------------------------

mod common;

proptest! {
    #![proptest_config(common::config(256))]

    // Normalisation is idempotent where it succeeds, and DETERMINISTIC where
    // it does not.
    //
    // The second half is new, and it is why the generator changed. This
    // property used to draw only `[a-z][a-z0-9_]{2,19}` — valid charset, valid
    // length, every draw — and matched on three outcomes it could produce one
    // of. `tests/property_reach.rs` measured it: 256 draws, 256 `Ok`, zero
    // `Err(Reserved)`, zero anything else. The `Err(other)` arm was written as
    // `prop_assert!(false, …)`, an assertion guarding a branch nothing could
    // enter, which is the exact shape STANDARD.md §6.5's 2026-08-24 amendment
    // was written about.
    //
    // `common::handle_input()` now draws from the acceptance set, the reserved
    // deny list, and five rejection shapes. A rejection is not "nothing further
    // to assert": normalisation must be a FUNCTION, so the same input must give
    // the same error twice. That is the property this arm should always have
    // been making.
    #[test]
    fn normalise_is_idempotent_and_rejection_is_deterministic(
        raw in common::handle_input(),
    ) {
        match normalise_handle(&raw) {
            Ok(once) => {
                let twice = normalise_handle(&once).expect("re-normalise must succeed");
                prop_assert_eq!(once, twice);
            }
            Err(first) => {
                let second = normalise_handle(&raw).expect_err("must reject twice");
                prop_assert_eq!(
                    format!("{first:?}"),
                    format!("{second:?}"),
                    "normalisation must be deterministic for {:?}",
                    raw
                );
            }
        }
    }

    // Any ASCII-uppercase input that is otherwise valid normalises to the
    // same lower-case as the pre-lowered version.
    #[test]
    fn uppercase_folds_to_lowercase(
        raw in "[a-z][a-z0-9_]{2,19}",
    ) {
        let lower = raw.clone();
        let upper: String = raw.chars().map(|c| c.to_ascii_uppercase()).collect();
        let lower_result = normalise_handle(&lower);
        let upper_result = normalise_handle(&upper);
        prop_assert_eq!(lower_result, upper_result);
    }

    // The '@' prefix is optional and never part of the canonical form.
    #[test]
    fn at_prefix_is_stripped(
        raw in "[a-z][a-z0-9_]{2,19}",
    ) {
        let with_at = format!("@{raw}");
        prop_assert_eq!(normalise_handle(&raw), normalise_handle(&with_at));
    }

    // Rename challenge is injective in each input.
    // Injectivity has TWO halves — distinct inputs give distinct outputs, and
    // equal inputs give equal outputs — and until 2026-08-24 only one of them
    // was ever tested.
    //
    // The four inputs used to be drawn independently, so the equality arm
    // needed two 32-byte arrays to agree: a 2^-256 event. `property_reach.rs`
    // measured 256 draws and found the arm entered zero times. The determinism
    // half of a challenge builder is not a footnote — a builder that returned
    // fresh bytes per call would pass the inequality half perfectly and be
    // useless, because the verifier recomputes the challenge and compares.
    #[test]
    fn rename_challenge_is_injective_in_both_directions(
        inputs in common::challenge_pair(),
    ) {
        let (fp_a, cur_a, new_a, ts_a, fp_b, cur_b, new_b, ts_b) = inputs;
        let c1 = build_rename_challenge(&fp_a, &cur_a, &new_a, ts_a);
        let c2 = build_rename_challenge(&fp_b, &cur_b, &new_b, ts_b);
        if fp_a != fp_b || cur_a != cur_b || new_a != new_b || ts_a != ts_b {
            prop_assert_ne!(c1, c2);
        } else {
            prop_assert_eq!(c1, c2);
        }
    }

    // Delete challenge is injective in fingerprint, handle, and
    // timestamp. The 8-byte timestamp tail keeps the variable-length
    // handle unambiguous, so distinct (fp, handle, ts) tuples never
    // collide.
    #[test]
    // Both halves, for the reason spelled out on the rename property above.
    // The delete challenge authorises DESTROYING a handle, so its determinism
    // half is if anything the more load-bearing of the two: the verifier
    // recomputes and compares, and a builder that did not agree with itself
    // would refuse every legitimate deletion while passing the inequality
    // assertion perfectly.
    #[test]
    fn delete_challenge_is_injective_in_both_directions(
        inputs in common::challenge_pair(),
    ) {
        // `challenge_pair` carries a rename's two handles; the delete challenge
        // takes one. The second is unused here, and using the FIRST of the pair
        // keeps the "same" flag meaningful — reusing the tuple must reuse the
        // handle this challenge actually reads.
        let (fp_a, handle_a, _, ts_a, fp_b, handle_b, _, ts_b) = inputs;
        let c1 = build_delete_challenge(&fp_a, &handle_a, ts_a);
        let c2 = build_delete_challenge(&fp_b, &handle_b, ts_b);
        if fp_a != fp_b || handle_a != handle_b || ts_a != ts_b {
            prop_assert_ne!(c1, c2);
        } else {
            prop_assert_eq!(c1, c2);
        }
    }

    // Latin-1 supplement / Latin Extended-A characters (U+00C0–U+017F)
    // are accepted by the V2 multi-script validator as long as the
    // handle stays in a single script. The proptest builds an
    // ASCII-Latin prefix + a Latin-extended character + an ASCII-Latin
    // tail, so the result is single-script-Latin and should normalise
    // successfully (post-NFC, post-lowercase). The only failure modes
    // are length boundaries, since NFC + lowercase can change the
    // code-point count.
    #[test]
    fn latin_extended_accepted_under_v2(
        leading in "[a-z]{2}",
        // Latin-1 supplement + Latin Extended-A letter range, with the
        // two non-letter holes excluded: U+00D7 (×, multiplication
        // sign) and U+00F7 (÷, division sign) are Common-script math
        // symbols inside the otherwise-Latin block.
        bad in "[\u{00C0}-\u{00D6}\u{00D8}-\u{00F6}\u{00F8}-\u{017F}]",
        trailing in "[a-z0-9_]{0,17}",
    ) {
        let raw = format!("{leading}{bad}{trailing}");
        let result = normalise_handle(&raw);
        match result {
            // The `bad` character set is purely Latin letters, so the
            // result is single-script-Latin and either succeeds or is
            // rejected only by the length bounds (some characters
            // expand under NFC + lowercase, e.g. `İ` → `i\u{0307}`).
            Ok(_) | Err(HandleValidationError::TooShort | HandleValidationError::TooLong) => {},
            other => prop_assert!(false, "unexpected result {:?} for {:?}", other, raw),
        }
    }

    // Code points outside any allowed script (e.g. math operators) are
    // always rejected. We use U+2200 FOR ALL — Common-script, Sm
    // category, clearly outside every script allowlist — to avoid the
    // Latin-extended boundary case above.
    #[test]
    fn disallowed_script_rejected(
        leading in "[a-z]{2}",
        trailing in "[a-z0-9_]{0,17}",
    ) {
        let raw = format!("{leading}\u{2200}{trailing}");
        let result = normalise_handle(&raw);
        match result {
            Err(HandleValidationError::DisallowedScript | HandleValidationError::TooLong) => {},
            other => prop_assert!(false, "unexpected result {:?} for {:?}", other, raw),
        }
    }
}

// -----------------------------------------------------------------------------
// Auto-shape exhaustive cross-check against the wordlists
// -----------------------------------------------------------------------------

#[test]
fn every_wordlist_combination_matches_auto_shape() {
    use qub_core::handle::{adjectives, nouns};
    // Sample 16 combinations with varying digit suffixes to avoid O(N²)
    // over the full lists — exhaustive coverage is the wordlist tests'
    // job; this confirms auto-shape detection is consistent.
    for (i, adj) in adjectives().iter().enumerate().step_by(17) {
        for (j, noun) in nouns().iter().enumerate().step_by(17) {
            let handle = format!("{adj}_{noun}_{:03}", (i + j) % 1000);
            assert!(
                is_auto_allocated_shape(&handle),
                "{handle} should match auto-shape but didn't"
            );
        }
    }
}

#[test]
fn qub_hex_fallback_matches_auto_shape() {
    for case in &[
        "qub_00000000",
        "qub_deadbeef",
        "qub_ffffffff",
        "qub_12345678",
    ] {
        assert!(
            is_auto_allocated_shape(case),
            "{case} should match auto-shape"
        );
    }
}

#[test]
fn user_chosen_handles_do_not_match_auto_shape() {
    for case in &[
        "markharper",
        "jane",
        "hello_world",
        "mark_harper",
        "name123",
        "a_b_c",         // not 3 digits
        "a_b_12",        // not 3 digits
        "a_b_1234",      // 4 digits
        "qub_deadbee",   // 7 hex
        "qub_deadbeefx", // too long
        "qub_dead_beef", // extra underscore
    ] {
        assert!(
            !is_auto_allocated_shape(case),
            "{case} must NOT match auto-shape"
        );
    }
}
