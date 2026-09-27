//! Cross-language test vectors for the transparency log (PROTOCOL.md §16.8 /
//! §16.14).
//!
//! The fixture `tests/vectors/tlog_v1.json` is the single source of truth for
//! Rust ↔ TypeScript parity on the Merkle tree and the canonical-CBOR log
//! types. This Rust integration test (re)generates it from a deterministic
//! scenario and asserts byte-identical output; the TypeScript mirror at
//! `workers/api/src/crypto/__tests__/tlog.test.ts` reads the same JSON and
//! asserts the same. The ANS-104 deep-hash / `DataItem` vectors are TS-authored
//! (`workers/api/test/fixtures/ans104_v1.json`) because ANS-104 is Worker-only.
//!
//! Regenerate after a deliberate format change:
//!
//! ```text
//! QUB_REGEN_VECTORS=1 cargo test -p qub-core --test tlog_vectors
//! ```

use std::fs;
use std::path::PathBuf;

use qub_core::log::{
    AnchorBundle, AnchorRef, ConsistencyProof, InclusionProof, LogLeaf, LogProfile, SignedTreeHead,
};
use qub_core::merkle;
use serde_json::{Value, json};

const REGEN_ENV_VAR: &str = "QUB_REGEN_VECTORS";

/// Number of leaves in the fixture tree (5 exercises the §16.3 right-edge
/// promotion case a power-of-two tree hides).
const TREE_SIZE: usize = 5;
const INCLUSION_INDEX: usize = 2;
const CONSISTENCY_FIRST: usize = 4;

fn hx(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").expect("write hex");
    }
    s
}

fn dehex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

const fn fixed32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The two standalone leaves (one of each kind).
fn standalone_leaves() -> Vec<LogLeaf> {
    vec![
        LogLeaf::asserted(
            7,
            fixed32(0x11),
            fixed32(0x22),
            1_800_000_000,
            1_700_000_000,
        )
        .expect("asserted leaf"),
        LogLeaf::attested(
            9,
            fixed32(0x33),
            fixed32(0x44),
            1_800_000_000,
            1_700_000_000,
            fixed32(0x55),
            4_695_445,
        )
        .expect("attested leaf"),
    ]
}

/// The `TREE_SIZE`-leaf tree: leaf i has seq=i, ref=[i+1;32], chash=[i+101;32].
fn tree_leaves() -> Vec<LogLeaf> {
    (0..TREE_SIZE)
        .map(|i| {
            let idx = u8::try_from(i).expect("small");
            let offset = i64::try_from(i).expect("small");
            LogLeaf::asserted(
                i as u64,
                fixed32(idx + 1),
                fixed32(idx + 101),
                1_800_000_000 + offset,
                1_700_000_000 + offset,
            )
            .expect("tree leaf")
        })
        .collect()
}

fn sample_anchor_ref() -> AnchorRef {
    AnchorRef::new(
        fixed32(0x66),
        2,
        fixed32(0x77),
        LogProfile::qub().log_id(),
        Some(123_456),
        Some(1_700_000_500),
    )
}

fn sample_sth(root: [u8; 32]) -> SignedTreeHead {
    SignedTreeHead::new(
        TREE_SIZE as u64,
        root,
        2,
        [0u8; 32],
        LogProfile::qub().log_id(),
        0,
        1_700_000_500,
    )
}

/// Build the full fixture JSON from the deterministic scenario.
fn build_fixture() -> Value {
    let standalone = standalone_leaves();
    let standalone_json: Vec<Value> = standalone
        .iter()
        .map(|leaf| {
            let cbor = leaf.to_cbor().expect("leaf cbor");
            json!({
                "leaf_cbor_hex": hx(&cbor),
                "leaf_hash_hex": hx(&leaf.leaf_hash().expect("leaf hash")),
            })
        })
        .collect();

    let leaves = tree_leaves();
    let leaf_cbors: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_cbor().expect("cbor")).collect();
    let leaf_hashes: Vec<[u8; 32]> = leaf_cbors.iter().map(|c| merkle::leaf_hash(c)).collect();
    let root = merkle::merkle_root(&leaf_hashes);

    // Inclusion proof for INCLUSION_INDEX.
    let audit = merkle::inclusion_proof(INCLUSION_INDEX, &leaf_hashes).expect("audit");
    let inclusion = InclusionProof::new(
        leaf_cbors[INCLUSION_INDEX].clone(),
        INCLUSION_INDEX as u64,
        TREE_SIZE as u64,
        audit.clone(),
        root,
        sample_anchor_ref(),
    );

    // Consistency proof CONSISTENCY_FIRST -> TREE_SIZE.
    let nodes = merkle::consistency_proof(CONSISTENCY_FIRST, &leaf_hashes).expect("nodes");
    let first_root = merkle::merkle_root(&leaf_hashes[..CONSISTENCY_FIRST]);
    let consistency = ConsistencyProof::new(
        CONSISTENCY_FIRST as u64,
        TREE_SIZE as u64,
        first_root,
        root,
        nodes.clone(),
        sample_anchor_ref(),
        sample_anchor_ref(),
    );

    let sth = sample_sth(root);
    let anchor = AnchorBundle::new(
        sth.to_cbor().expect("sth cbor"),
        None,
        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".to_owned(),
        leaf_cbors.clone(),
    );

    json!({
        "_comment": "Generated by `QUB_REGEN_VECTORS=1 cargo test -p qub-core --test tlog_vectors`. Single source of truth for Rust<->TS transparency-log parity (PROTOCOL.md §16).",
        "standalone_leaves": standalone_json,
        "tree": {
            "size": TREE_SIZE,
            "leaf_cbor_hex": leaf_cbors.iter().map(|c| hx(c)).collect::<Vec<_>>(),
            "leaf_hash_hex": leaf_hashes.iter().map(|h| hx(h)).collect::<Vec<_>>(),
            "root_hex": hx(&root),
        },
        "inclusion": {
            "index": INCLUSION_INDEX,
            "size": TREE_SIZE,
            "audit_hex": audit.iter().map(|h| hx(h)).collect::<Vec<_>>(),
            "proof_cbor_hex": hx(&inclusion.to_cbor().expect("inclusion cbor")),
        },
        "consistency": {
            "first_size": CONSISTENCY_FIRST,
            "second_size": TREE_SIZE,
            "first_root_hex": hx(&first_root),
            "second_root_hex": hx(&root),
            "nodes_hex": nodes.iter().map(|h| hx(h)).collect::<Vec<_>>(),
            "proof_cbor_hex": hx(&consistency.to_cbor().expect("consistency cbor")),
        },
        "sth": {
            "sth_cbor_hex": hx(&sth.to_cbor().expect("sth cbor")),
            "sth_hash_hex": hx(&sth.sth_hash().expect("sth hash")),
        },
        "anchor_bundle": {
            "anchor_cbor_hex": hx(&anchor.to_cbor().expect("anchor cbor")),
        },
        "log_profile": {
            "anchor_owner_hex": hx(LogProfile::qub().anchor_owner()),
            "log_id_hex": hx(&LogProfile::qub().log_id()),
        }
    })
}

fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/tlog_v1.json");
    p
}

#[test]
fn tlog_v1_vectors_round_trip() {
    let regen = std::env::var(REGEN_ENV_VAR).is_ok();

    if regen {
        let fixture = build_fixture();
        let pretty = serde_json::to_string_pretty(&fixture).expect("serialise");
        fs::write(vectors_path(), pretty + "\n").expect("write fixture");
        eprintln!("regenerated tlog vectors at {}", vectors_path().display());
        return;
    }

    let raw = fs::read_to_string(vectors_path()).expect("read tlog fixture");
    let json: Value = serde_json::from_str(&raw).expect("parse tlog fixture");

    // Recompute the entire scenario and assert byte-identity with the fixture.
    let expected = build_fixture();
    assert_eq!(
        json["standalone_leaves"], expected["standalone_leaves"],
        "standalone leaf vectors diverged (rerun with {REGEN_ENV_VAR}=1)"
    );
    assert_eq!(json["tree"], expected["tree"], "tree vectors diverged");
    assert_eq!(
        json["inclusion"], expected["inclusion"],
        "inclusion proof diverged"
    );
    assert_eq!(
        json["consistency"], expected["consistency"],
        "consistency proof diverged"
    );
    assert_eq!(json["sth"], expected["sth"], "sth vectors diverged");
    assert_eq!(
        json["anchor_bundle"], expected["anchor_bundle"],
        "anchor bundle diverged"
    );
    assert_eq!(
        json["log_profile"], expected["log_profile"],
        "log profile diverged"
    );

    // Round-trip decode + verify the proofs from the fixture bytes (the path
    // the TS mirror and the standalone verifier exercise).
    let inclusion_bytes = dehex(&json["inclusion"]["proof_cbor_hex"]);
    let inclusion = InclusionProof::from_cbor(&inclusion_bytes).expect("decode inclusion");
    assert!(
        inclusion.verify_root(),
        "fixture inclusion proof must verify"
    );

    let consistency_bytes = dehex(&json["consistency"]["proof_cbor_hex"]);
    let consistency = ConsistencyProof::from_cbor(&consistency_bytes).expect("decode consistency");
    assert!(
        consistency.verify(),
        "fixture consistency proof must verify"
    );

    let anchor_bytes = dehex(&json["anchor_bundle"]["anchor_cbor_hex"]);
    let anchor = AnchorBundle::from_cbor(&anchor_bytes).expect("decode anchor");
    assert_eq!(
        anchor.leaves().len(),
        TREE_SIZE,
        "anchor carries the full leaf stream"
    );

    // The embedded STH inside the anchor re-derives the fixture root.
    let sth = SignedTreeHead::from_cbor(anchor.sth()).expect("decode sth");
    assert_eq!(hx(sth.root()), json["tree"]["root_hex"].as_str().unwrap());
}
