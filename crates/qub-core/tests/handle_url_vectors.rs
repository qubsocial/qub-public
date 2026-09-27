//! Cross-language fixture for [`qub_core::handle::encode_handle_for_url`].
//!
//! The canonical fixture at `tests/vectors/handle_url_v1.json` is read by
//! both this Rust integration test and the TypeScript mirror at
//! `workers/api/src/utils/__tests__/handle-url-cross-impl.test.ts`. Both
//! sides MUST assert byte-identical output for every case — the parity
//! is the contract documented at `docs/IDENTITY.md` §3.2.6.9.
//!
//! Unlike the wrapper-vectors test, the fixture is fully deterministic
//! and hand-maintained — there is no regen mode. To add a case, edit
//! the JSON file directly with the new `input` + `encoded` pair, then
//! confirm both sides pass.

use std::fs;
use std::path::PathBuf;

use qub_core::handle::encode_handle_for_url;
use serde_json::Value;

fn fixture_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("tests/vectors/handle_url_v1.json")
}

#[test]
fn every_case_encodes_to_the_documented_form() {
    let path = fixture_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let json: Value = serde_json::from_str(&raw).expect("handle_url_v1.json parses as JSON");
    let cases = json["cases"].as_array().expect("`cases` array");
    assert!(!cases.is_empty(), "fixture has at least one case");

    for case in cases {
        let name = case["name"].as_str().expect("case has `name`");
        let input = case["input"].as_str().expect("case has `input`");
        let expected = case["encoded"].as_str().expect("case has `encoded`");
        let actual = encode_handle_for_url(input);
        assert_eq!(
            actual, expected,
            "case `{name}`: input={input:?} expected={expected:?} got={actual:?}"
        );
    }
}
