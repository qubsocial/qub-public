//! End-to-end acceptance tests for the `qub-verify` binary.
//!
//! The headline test ([`cli_verifies_real_quicknet_bundle`]) is the W7
//! acceptance gate: a third party, with no qub infrastructure, verifies a
//! revealed qub from a `.qub` bundle alone. It seals a qub to a **real** drand
//! quicknet round and bundles it with that round's **real** beacon signature
//! (pinned below — drand round signatures are immutable), then runs the actual
//! binary and asserts a VERIFIED verdict. No network is touched at test time:
//! the signature is a constant, and seal/unlock are pure crypto.

use qub_core::export::QubBundle;
use qub_core::hash;
use qub_core::log::{AnchorRef, InclusionProof, LogLeaf, LogProfile};
use qub_core::merkle;
use qub_core::seal::{SealInput, seal};
use qub_core::tlock::DrandTimelockProvider;
use qub_core::types::{CONTENT_TYPE_TEXT, ComposeQub};
use qub_core::wire::SealedQubCbor;

// drand quicknet parameters (baked into the protocol).
const QUICKNET_GENESIS: i64 = 1_692_803_367;
const QUICKNET_PERIOD: u64 = 3;
const QUICKNET_CHAIN: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

// A real, elapsed quicknet round and its real G1 beacon signature (48 bytes,
// 96 hex chars). Pinned once; immutable forever. Fetched from the public drand
// API during development — NOT at test time.
const ROUND: u64 = 29_536_804;
const ROUND_SIG_HEX: &str = "a9ca3a9597a00dfa2b16bd8eb18b57ee0d6b583884e7c8dccdd078fc4c9a17d0b7de2ac4e8f26e0aca3f77a2f15b1514";

/// The pinned drand quicknet round signature, decoded.
fn signature_bytes() -> Vec<u8> {
    hex::decode(ROUND_SIG_HEX).expect("pinned signature is valid hex")
}

/// Seals a text qub to the pinned quicknet round and returns the sealed CBOR
/// plus the components a transparency-log leaf binds to: `(sealed_cbor,
/// unlock_at, qub_id, drand_round)`.
fn seal_quicknet(body: &str) -> (SealedQubCbor, i64, [u8; 32], u64) {
    // Under the reference tlock mapping (`floor(delta/period) + 1`,
    // PROTOCOL.md §4.3), unlock_round(unlock_at) == ROUND for any
    // unlock_at with delta in ((ROUND-1)*period, ROUND*period]. Pick the
    // top of that window so the pinned real signature for ROUND (already
    // published at genesis + (ROUND-1)*period) stays the correct beacon.
    let round_i64 = i64::try_from(ROUND).expect("round fits i64");
    let period_i64 = i64::try_from(QUICKNET_PERIOD).expect("period fits i64");
    let unlock_at = QUICKNET_GENESIS + round_i64 * period_i64 - 1;
    // Fabricated seal time just before unlock (seal requires unlock_at > now).
    let seal_now = unlock_at - 100;

    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.as_bytes().to_vec());
    draft.set_unlock_at(unlock_at);

    let tlock = DrandTimelockProvider::quicknet();
    let seal_out = seal(SealInput {
        draft: &draft,
        now: seal_now,
        chain_genesis_time: QUICKNET_GENESIS,
        chain_period_seconds: QUICKNET_PERIOD,
        chain_id: QUICKNET_CHAIN.into(),
        tlock: &tlock,
        signing: None,
    })
    .expect("seal to quicknet round");
    assert_eq!(seal_out.drand_round, ROUND, "unlock_at must map to ROUND");

    let qub_id = *seal_out
        .sealed_cbor
        .parse()
        .expect("sealed CBOR parses")
        .qub_id();
    (
        seal_out.sealed_cbor,
        unlock_at,
        qub_id,
        seal_out.drand_round,
    )
}

/// Seals a text qub to the pinned quicknet round and packages it into a
/// `.qub` bundle's raw CBOR bytes. Returns `(bytes, unlock_at)`.
fn build_real_quicknet_bundle(body: &str) -> (Vec<u8>, i64) {
    let (sealed_cbor, unlock_at, _qub_id, _round) = seal_quicknet(body);
    let bundle = QubBundle::new(sealed_cbor, signature_bytes(), "tx-acceptance".into())
        .expect("bundle builds")
        .with_sealed_at(Some(unlock_at - 100));
    (bundle.to_cbor().expect("bundle encodes"), unlock_at)
}

/// The qub fields a transparency-log leaf commits to, passed to the leaf-builder
/// closures below.
struct LeafCtx {
    qub_id: [u8; 32],
    body_hash: [u8; 32],
    drand_round: u64,
    unlock_at: i64,
}

/// Builds a `.qub` bundle for `body` carrying a typed transparency-log inclusion
/// proof whose proven leaf (placed at index 2 of a real 5-leaf tree) is built by
/// `make_leaf`. When `tamper`, the proof's leaf bytes are corrupted after the
/// tree is built, so the Merkle audit path no longer reproduces the root.
fn anchored_bundle(
    body: &str,
    make_leaf: impl Fn(&LeafCtx) -> LogLeaf,
    tamper: bool,
) -> (Vec<u8>, i64) {
    let (sealed_cbor, unlock_at, qub_id, drand_round) = seal_quicknet(body);
    let ctx = LeafCtx {
        qub_id,
        body_hash: hash::body_hash(body.as_bytes()),
        drand_round,
        unlock_at,
    };
    let prove_leaf = make_leaf(&ctx);

    // Surround the proven leaf with distinct, well-formed filler leaves.
    let filler = |seq: u64, b: u8| {
        LogLeaf::asserted(
            seq,
            [b; 32],
            [b.wrapping_add(50); 32],
            1_800_000_000,
            1_700_000_000,
        )
        .expect("filler leaf builds")
    };
    let leaves = [
        filler(0, 1),
        filler(1, 2),
        prove_leaf,
        filler(3, 4),
        filler(4, 5),
    ];
    let leaf_cbors: Vec<Vec<u8>> = leaves
        .iter()
        .map(|l| l.to_cbor().expect("leaf cbor"))
        .collect();
    let leaf_hashes: Vec<[u8; 32]> = leaf_cbors.iter().map(|c| merkle::leaf_hash(c)).collect();
    let root = merkle::merkle_root(&leaf_hashes);
    let audit = merkle::inclusion_proof(2, &leaf_hashes).expect("audit path in range");

    let mut proof_leaf = leaf_cbors[2].clone();
    if tamper {
        let mid = proof_leaf.len() / 2;
        proof_leaf[mid] ^= 0x01;
    }
    let anchor = AnchorRef::new(
        [0x66; 32],
        2,
        [0x77; 32],
        LogProfile::qub().log_id(),
        None,
        None,
    );
    let proof = InclusionProof::new(proof_leaf, 2, 5, audit, root, anchor);

    let bundle = QubBundle::new(sealed_cbor, signature_bytes(), "tx-anchored".into())
        .expect("bundle builds")
        .with_sealed_at(Some(unlock_at - 100))
        .with_inclusion_proof_typed(&proof)
        .expect("attach typed inclusion proof");
    (bundle.to_cbor().expect("bundle encodes"), unlock_at)
}

/// Writes bytes to a unique temp `.qub` path and returns it.
fn temp_qub_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("qub-verify-{tag}-{}.qub", std::process::id()))
}

fn run_verify(args: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_qub-verify"))
        .args(args)
        .output()
        .expect("spawn qub-verify")
}

#[test]
fn cli_verifies_real_quicknet_bundle() {
    let body = "qub-verify acceptance: sealed to real drand quicknet.";
    let (bytes, unlock_at) = build_real_quicknet_bundle(body);

    let path = temp_qub_path("verified");
    std::fs::write(&path, &bytes).expect("write .qub");

    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("VERDICT: VERIFIED"),
        "missing VERIFIED verdict:\n{stdout}"
    );
    assert!(
        stdout.contains(body),
        "recovered body missing from report:\n{stdout}"
    );
    assert!(
        stdout.contains("unsigned"),
        "unsigned qub should report 'unsigned':\n{stdout}"
    );
}

#[test]
fn cli_json_report_for_real_bundle() {
    let (bytes, unlock_at) = build_real_quicknet_bundle("json mode");
    let path = temp_qub_path("json");
    std::fs::write(&path, &bytes).expect("write .qub");

    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
        std::ffi::OsStr::new("--json"),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "exit {:?}", output.status.code());
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON report");
    assert_eq!(parsed["verified"], serde_json::Value::Bool(true));
    assert_eq!(parsed["drand_round"], serde_json::json!(ROUND));
    assert_eq!(parsed["body"], serde_json::json!("json mode"));
}

#[test]
fn cli_refuses_bundle_still_locked() {
    let (bytes, unlock_at) = build_real_quicknet_bundle("not yet");
    let path = temp_qub_path("locked");
    std::fs::write(&path, &bytes).expect("write .qub");

    // now well before unlock_at → StillLocked.
    let now_arg = (unlock_at - 10_000).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "still-locked must exit 1\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("NOT VERIFIED") && stdout.contains("still locked"),
        "expected still-locked reason:\n{stdout}"
    );
}

#[test]
fn cli_rejects_garbage_input() {
    let path = temp_qub_path("garbage");
    std::fs::write(&path, [0xFF, 0xFF, 0xFF, 0x00, 0x01]).expect("write garbage");

    let output = run_verify(&[path.as_os_str()]);
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed input must exit 2 (usage/parse error)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid .qub bundle"),
        "expected parse error on stderr:\n{stderr}"
    );
}

// ---- transparency-log anchored verification (W5 / §16.9) ----

#[test]
fn cli_anchored_attested_bundle_is_inclusion_only_without_anchor() {
    // A kind=0x01 attested leaf binds fully to the sealed qub_id / body_hash /
    // drand_round and the Merkle leg holds — but WITHOUT a verified Arweave
    // anchor (no --anchor), anchoring is NOT proven offline (§16.9 steps 5-6).
    // The bundle's own timing/authorship still verifies (top-line VERIFIED);
    // the anchoring sub-claim is honestly scoped to inclusion-only (§17.5).
    let body = "anchored attested qub";
    let (bytes, unlock_at) = anchored_bundle(
        body,
        |c| {
            LogLeaf::attested(
                2,
                c.qub_id,
                [0x33; 32],
                c.unlock_at,
                1_700_000_000,
                c.body_hash,
                c.drand_round,
            )
            .expect("attested leaf builds")
        },
        false,
    );

    let path = temp_qub_path("anchored-attested");
    std::fs::write(&path, &bytes).expect("write .qub");
    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\n{stdout}",
        output.status.code()
    );
    assert!(stdout.contains("VERDICT: VERIFIED"), "{stdout}");
    // Anchoring is NOT claimed verified without the anchor leg.
    assert!(
        stdout.contains("anchoring NOT proven offline"),
        "anchoring must not over-claim without --anchor:\n{stdout}"
    );
    assert!(
        stdout.contains("no signed Arweave anchor supplied"),
        "anchoring gap reason missing:\n{stdout}"
    );
    assert!(stdout.contains("0x01 (attested)"), "{stdout}");
    assert!(
        stdout.contains("bound to qub_id, body_hash, and drand_round"),
        "{stdout}"
    );
}

#[test]
fn cli_anchored_attested_json_report() {
    let (bytes, unlock_at) = anchored_bundle(
        "anchored json",
        |c| {
            LogLeaf::attested(
                2,
                c.qub_id,
                [0x33; 32],
                c.unlock_at,
                1_700_000_000,
                c.body_hash,
                c.drand_round,
            )
            .expect("attested leaf builds")
        },
        false,
    );
    let path = temp_qub_path("anchored-json");
    std::fs::write(&path, &bytes).expect("write .qub");
    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
        std::ffi::OsStr::new("--json"),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "exit {:?}", output.status.code());
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON report");
    assert_eq!(parsed["verified"], serde_json::Value::Bool(true));
    // Without --anchor the anchoring claim is inclusion-only, machine-legibly:
    // bound to the qub but anchor not confirmed.
    assert_eq!(
        parsed["anchored"]["state"],
        serde_json::json!("inclusion_only")
    );
    assert_eq!(parsed["anchored"]["binding"], serde_json::json!("attested"));
    assert_eq!(
        parsed["anchored"]["bound_to_qub"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        parsed["anchored"]["anchor_confirmed"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(parsed["anchored"]["leaf_kind"], serde_json::json!(1));
    assert_eq!(parsed["anchored"]["size"], serde_json::json!(5));
}

#[test]
fn cli_verifies_anchored_asserted_public_bundle() {
    // A kind=0x02 asserted leaf whose `ref` equals the (public) qub_id binds as
    // `asserted_public` — the Merkle leg proves inclusion, the ref proves it is
    // this qub.
    let (bytes, unlock_at) = anchored_bundle(
        "anchored asserted public",
        |c| {
            LogLeaf::asserted(2, c.qub_id, [0x33; 32], c.unlock_at, 1_700_000_000)
                .expect("asserted leaf builds")
        },
        false,
    );
    let path = temp_qub_path("anchored-asserted");
    std::fs::write(&path, &bytes).expect("write .qub");
    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "exit {:?}\n{stdout}",
        output.status.code()
    );
    assert!(stdout.contains("VERDICT: VERIFIED"), "{stdout}");
    assert!(stdout.contains("0x02 (asserted)"), "{stdout}");
    assert!(stdout.contains("bound to public qub_id"), "{stdout}");
    // ref==qub_id ties the leaf to this qub, but anchoring still needs the
    // anchor leg — inclusion-only without --anchor.
    assert!(stdout.contains("anchoring NOT proven offline"), "{stdout}");
}

#[test]
fn cli_rejects_tampered_inclusion_proof() {
    // A present-but-broken proof (corrupted leaf → the Merkle audit path no
    // longer reproduces the root) is a genuine integrity signal: NOT VERIFIED,
    // exit 1 (§17.5).
    let (bytes, unlock_at) = anchored_bundle(
        "tampered proof",
        |c| {
            LogLeaf::attested(
                2,
                c.qub_id,
                [0x33; 32],
                c.unlock_at,
                1_700_000_000,
                c.body_hash,
                c.drand_round,
            )
            .expect("attested leaf builds")
        },
        true,
    );
    let path = temp_qub_path("anchored-tampered");
    std::fs::write(&path, &bytes).expect("write .qub");
    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
    ]);
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a broken inclusion proof must exit 1\n{stdout}"
    );
    assert!(stdout.contains("VERDICT: NOT VERIFIED"), "{stdout}");
    assert!(
        stdout.contains("anchored") && stdout.contains("BROKEN"),
        "expected a broken-anchor signal:\n{stdout}"
    );
}

#[test]
fn cli_anchor_flag_verifies_typescript_anchor() {
    // The optional `--anchor` leg, end to end across languages: the bundle
    // carries the TypeScript-built inclusion proof from `ans104_v1.json`, and
    // `--anchor` points at that fixture's TypeScript-signed anchor DataItem. The
    // Rust verifier confirms the RSA-PSS signature, that the AnchorBundle commits
    // the proof's root/size, and the txid match.
    //
    // The outcome is INCLUSION-ONLY, honestly, for two independent reasons: (a)
    // the pinned `anchor_owner` is still the deploy-gated placeholder, so the
    // owner pin is informational rather than trust-bearing (§16.6); and (b) the
    // fixture leaf's `ref` is a synthetic id, so it binds as `asserted_opaque`
    // (§16.11 byte-blind scope). Neither is a failure. (The TS→Rust attested /
    // asserted-public binding arms are cross-checked separately by the §16.14
    // `tlog_v1.json` leaf vectors, so this opaque-only path is a deliberate, not
    // accidental, coverage boundary.)
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/qub-core/tests/vectors/ans104_v1.json"
    );
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path).expect("read fixture"))
            .expect("fixture json");
    let fixture_hex = |ptr: &str| -> Vec<u8> {
        hex::decode(
            fixture
                .pointer(ptr)
                .and_then(serde_json::Value::as_str)
                .expect("fixture field present"),
        )
        .expect("fixture hex decodes")
    };
    let proof_bytes = fixture_hex("/inclusion_proof/proof_cbor_hex");
    let anchor_raw = fixture_hex("/data_item/raw_hex");

    let (sealed_cbor, unlock_at, _qub_id, _round) = seal_quicknet("anchor-leg acceptance");
    let bundle = QubBundle::new(sealed_cbor, signature_bytes(), "tx-anchor".into())
        .expect("bundle builds")
        .with_inclusion_proof(Some(proof_bytes));
    let bytes = bundle.to_cbor().expect("bundle encodes");

    let bundle_path = temp_qub_path("anchor-bundle");
    let anchor_path = temp_qub_path("anchor-dataitem");
    std::fs::write(&bundle_path, &bytes).expect("write bundle");
    std::fs::write(&anchor_path, &anchor_raw).expect("write anchor DataItem");

    let now_arg = (unlock_at + 1).to_string();
    let output = run_verify(&[
        bundle_path.as_os_str(),
        std::ffi::OsStr::new("--now"),
        std::ffi::OsStr::new(&now_arg),
        std::ffi::OsStr::new("--anchor"),
        anchor_path.as_os_str(),
    ]);
    let _ = std::fs::remove_file(&bundle_path);
    let _ = std::fs::remove_file(&anchor_path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\n{stdout}",
        output.status.code()
    );
    assert!(stdout.contains("VERDICT: VERIFIED"), "{stdout}");
    assert!(stdout.contains("0x02 (asserted)"), "{stdout}");
    // The anchor leg DID run (signature + commits verified) ...
    assert!(
        stdout.contains("anchor_tx"),
        "anchor leg missing:\n{stdout}"
    );
    assert!(stdout.contains("signature ok"), "{stdout}");
    assert!(
        stdout.contains("owner pin: placeholder"),
        "owner pin should be deploy-gated placeholder:\n{stdout}"
    );
    // ... but anchoring is NOT claimed proven: placeholder owner + opaque leaf.
    assert!(
        stdout.contains("anchoring NOT proven offline"),
        "must not over-claim anchoring under placeholder owner:\n{stdout}"
    );
    assert!(
        stdout.contains("anchor wallet not yet provisioned"),
        "expected the deploy-gated reason:\n{stdout}"
    );
}
