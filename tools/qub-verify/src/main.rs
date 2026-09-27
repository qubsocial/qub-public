//! `qub-verify` — offline verifier for `.qub` export bundles.
//!
//! Reads a `.qub` bundle (the canonical-CBOR container produced by
//! `qub_core::export`), then confirms a revealed qub's content integrity,
//! round binding, and authorship **from the bundle alone** — no qub
//! infrastructure, no Arweave fetch, no live drand call. The bundle embeds the
//! drand round signature, and timelock decryption can only succeed with the
//! genuine beacon for the bound round, so a bundle that opens proves that the
//! round elapsed. A pre-existing commitment time additionally requires a
//! verified storage inclusion or anchored transparency-log proof.
//!
//! ```text
//! qub-verify reveal.qub              # verify a raw .qub file
//! cat reveal.qub | qub-verify -      # read from stdin
//! qub-verify --base64url token.txt   # input is base64url(no-pad) text
//! qub-verify --json reveal.qub       # machine-readable report
//! ```
//!
//! Exit codes: `0` verified · `1` verification failed (still locked, tampered,
//! bad signature, decrypt failure) · `2` usage / I/O / malformed-bundle error.

use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use clap::Parser;
use qub_core::export::QubBundle;
use qub_core::tlock::DrandTimelockProvider;
use qub_core::types::{CONTENT_TYPE_PACT, CONTENT_TYPE_TEXT, RevealedQub};
use qub_core::unlock::UnlockError;

mod anchor;
mod ans104;

use anchor::{AnchorDetails, AnchorState, AnchorTxReport, Binding};

/// drand quicknet genesis time (Unix seconds) — baked into the protocol.
const QUICKNET_GENESIS: i64 = 1_692_803_367;
/// drand quicknet round period (seconds).
const QUICKNET_PERIOD: u64 = 3;

#[derive(Parser)]
#[command(
    name = "qub-verify",
    version,
    about = "Offline verifier for qub .qub export bundles",
    long_about = "Confirms a revealed qub's content integrity, round binding, and authorship from a .qub bundle alone — \
                  no network, no qub infrastructure. The bundle carries the drand round \
                  signature that unlocks it; a bundle that decrypts proves the round elapsed."
)]
struct Cli {
    /// Path to a `.qub` bundle file, or `-` to read from stdin.
    path: String,

    /// Treat the input as base64url(no-pad) text rather than raw CBOR bytes.
    #[arg(long)]
    base64url: bool,

    /// Override the current time (Unix seconds). Defaults to the system clock.
    #[arg(long, value_name = "UNIX_SECONDS")]
    now: Option<i64>,

    /// Path to the raw Arweave anchor `DataItem` (ANS-104) referenced by the
    /// bundle's inclusion proof. When supplied, the anchor's RSA-PSS signature
    /// and committed tree head are verified (§16.9 steps 5-6); otherwise only
    /// the Merkle + leaf-binding legs run.
    #[arg(long, value_name = "PATH")]
    anchor: Option<String>,

    /// Emit a machine-readable JSON report instead of human-readable text.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("qub-verify: {message}");
            ExitCode::from(2)
        },
    }
}

fn run(cli: &Cli) -> Result<ExitCode, String> {
    let raw = read_input(&cli.path)?;

    let bytes = if cli.base64url {
        let text = String::from_utf8(raw)
            .map_err(|e| format!("input is not valid UTF-8 base64url text: {e}"))?;
        BASE64URL
            .decode(text.trim().as_bytes())
            .map_err(|e| format!("base64url decode failed: {e}"))?
    } else {
        raw
    };

    let bundle =
        QubBundle::from_cbor(&bytes).map_err(|e| format!("not a valid .qub bundle: {e}"))?;

    // The optional anchor DataItem (read up front so a bad path errors as a
    // usage error, before any verdict is rendered).
    let anchor_bytes = match &cli.anchor {
        Some(path) => Some(read_input(path)?),
        None => None,
    };

    let now = cli.now.unwrap_or_else(current_unix_time);
    let tlock = DrandTimelockProvider::quicknet();

    // Reject a malformed or wrong-round beacon value explicitly before it
    // reaches tlock decryption. Decryption already fails closed, but the
    // standalone verifier should apply the same pinned-key BLS check as the
    // browser and Worker verification paths (PROTOCOL.md §11 / §17.4).
    if let Err(err) = tlock.verify_round_signature(bundle.drand_round(), bundle.drand_signature()) {
        return report_failure(cli, &bundle, &UnlockError::Tlock(err));
    }

    match bundle.open(now, QUICKNET_GENESIS, QUICKNET_PERIOD, &tlock) {
        Ok(revealed) => report_outcome(cli, &bundle, &revealed, anchor_bytes.as_deref()),
        Err(err) => report_failure(cli, &bundle, &err),
    }
}

/// Reads the whole input — a file path, or `-` for stdin.
fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))
    }
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Verification succeeded at the crypto layer — now grade authorship and (if
/// the bundle carries one) the transparency-log inclusion proof.
fn report_outcome(
    cli: &Cli,
    bundle: &QubBundle,
    revealed: &RevealedQub,
    anchor_bytes: Option<&[u8]>,
) -> Result<ExitCode, String> {
    let anchored = anchor::verify_anchored(bundle, revealed, anchor_bytes);
    let signature_ok = revealed.signature_verified() != Some(false);
    let cosigner_ok = revealed.cosigner_verified() != Some(false);
    // §17.5: an absent proof never fails the verdict; a present-but-broken one
    // is a genuine integrity signal that does.
    let verified =
        revealed.body_hash_verified() && signature_ok && cosigner_ok && !anchored.is_broken();

    if cli.json {
        write_json(&json_report(
            bundle,
            Some(revealed),
            verified,
            None,
            Some(&anchored),
        ))?;
    } else {
        write_text(&text_report(bundle, revealed, verified, &anchored))?;
    }

    Ok(if verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Verification failed at the crypto layer (locked, tampered, bad signature).
fn report_failure(cli: &Cli, bundle: &QubBundle, err: &UnlockError) -> Result<ExitCode, String> {
    let reason = describe_unlock_error(err);
    if cli.json {
        write_json(&json_report(bundle, None, false, Some(&reason), None))?;
    } else {
        let mut s = String::new();
        s.push_str("VERDICT: NOT VERIFIED\n");
        let line = format!("  reason:         {reason}\n");
        s.push_str(&line);
        let tx = format!("  arweave_tx_id:  {}\n", bundle.arweave_tx_id());
        s.push_str(&tx);
        let round = format!("  drand_round:    {}\n", bundle.drand_round());
        s.push_str(&round);
        write_text(&s)?;
    }
    Ok(ExitCode::from(1))
}

fn describe_unlock_error(err: &UnlockError) -> String {
    match err {
        UnlockError::StillLocked { unlock_at, now } => format!(
            "still locked — unlocks at {unlock_at} (Unix), current time {now}; \
             {} seconds remaining",
            (unlock_at - now).max(0)
        ),
        UnlockError::BodyHashMismatch => {
            "body hash mismatch — the content does not match its commitment (tampered)".to_owned()
        },
        UnlockError::DrandRoundMismatch { expected, actual } => format!(
            "drand round binding broken — ciphertext is bound to round {actual}, expected {expected}"
        ),
        UnlockError::DrandChainMismatch { expected, actual } => {
            format!("drand chain mismatch — bundle chain {actual}, verifier expects {expected}")
        },
        other => format!("{other}"),
    }
}

const fn content_type_label(content_type: u8) -> &'static str {
    match content_type {
        CONTENT_TYPE_TEXT => "text",
        CONTENT_TYPE_PACT => "pact",
        _ => "other",
    }
}

const fn signature_label(verified: Option<bool>) -> &'static str {
    match verified {
        None => "unsigned",
        Some(true) => "valid (ML-DSA-65)",
        Some(false) => "INVALID",
    }
}

fn body_preview(body: &[u8]) -> String {
    std::str::from_utf8(body).map_or_else(
        |_| format!("<{} bytes of binary content>", body.len()),
        str::to_owned,
    )
}

fn text_report(
    bundle: &QubBundle,
    revealed: &RevealedQub,
    verified: bool,
    anchored: &AnchorState,
) -> String {
    let mut s = String::new();

    // The per-field rows below (signature / anchored) carry the specific
    // reason, so the headline stays neutral — a NOT-VERIFIED verdict can come
    // from a bad signature OR a broken transparency-log proof.
    let headline = if verified {
        "VERDICT: VERIFIED\n"
    } else {
        "VERDICT: NOT VERIFIED\n"
    };
    s.push_str(headline);

    push_field(&mut s, "qub_id", &hex::encode(revealed.qub_id()));
    push_field(&mut s, "arweave_tx_id", revealed.arweave_tx_id());
    push_field(
        &mut s,
        "content_type",
        content_type_label(revealed.content_type()),
    );
    push_field(&mut s, "created_at", &revealed.created_at().to_string());
    push_field(&mut s, "unlock_at", &revealed.unlock_at().to_string());
    if let Some(outcome_at) = revealed.outcome_at() {
        push_field(&mut s, "outcome_at", &outcome_at.to_string());
    }
    push_field(&mut s, "drand_round", &revealed.drand_round().to_string());
    push_field(&mut s, "drand_chain_id", revealed.drand_chain_id());
    if let Some(sealed_at) = bundle.sealed_at() {
        push_field(&mut s, "sealed_at", &sealed_at.to_string());
    }
    push_field(
        &mut s,
        "body_hash_ok",
        if revealed.body_hash_verified() {
            "yes"
        } else {
            "NO"
        },
    );
    push_field(
        &mut s,
        "signature",
        signature_label(revealed.signature_verified()),
    );
    if revealed.cosigner_verified().is_some() {
        push_field(
            &mut s,
            "cosigner",
            signature_label(revealed.cosigner_verified()),
        );
    }
    if let Some(label) = revealed.sender_label() {
        push_field(&mut s, "sender_label", label);
    }
    if let Some(title) = revealed.title() {
        push_field(&mut s, "title", title);
    }
    push_anchored_fields(&mut s, anchored);

    s.push('\n');
    s.push_str("--- content ---\n");
    s.push_str(&body_preview(revealed.body()));
    s.push('\n');
    s
}

fn push_field(buf: &mut String, key: &str, value: &str) {
    // Pad the key column to 16 chars for a tidy aligned report.
    let line = format!("  {key:<16}{value}\n");
    buf.push_str(&line);
}

const fn leaf_kind_label(kind: u8) -> &'static str {
    match kind {
        0x01 => "0x01 (attested)",
        0x02 => "0x02 (asserted)",
        _ => "unknown",
    }
}

const fn binding_text(binding: Binding) -> &'static str {
    match binding {
        Binding::Attested => "bound to qub_id, body_hash, and drand_round",
        Binding::AssertedPublic => "bound to public qub_id",
        Binding::AssertedOpaque => {
            "ref opaque/blinded — bound by Merkle position only (kind=0x02 scope)"
        },
    }
}

fn anchor_tx_text(tx: &AnchorTxReport) -> String {
    let sig = if tx.signature_valid { "ok" } else { "INVALID" };
    let commits = if tx.committed_root_ok && tx.committed_size_ok {
        "commits root+size"
    } else {
        "root/size MISMATCH"
    };
    let txid = if tx.txid_match {
        "txid match"
    } else {
        "txid MISMATCH"
    };
    let owner = match tx.owner_pin {
        anchor::OwnerPin::Placeholder => "owner pin: placeholder (deploy-gated)",
        anchor::OwnerPin::Match => "owner pin: match",
        anchor::OwnerPin::Mismatch => "owner pin: MISMATCH",
    };
    format!("signature {sig}, {commits}, {txid}, {owner}")
}

/// Why an [`AnchorState::InclusionOnly`] proof is not proven anchoring — the
/// honest scope statement that keeps the §16.11 claim ceiling.
fn inclusion_only_reason(d: &AnchorDetails) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !d.anchor_confirmed() {
        match d.anchor_tx() {
            None => parts.push("no signed Arweave anchor supplied (pass --anchor)"),
            Some(tx) if matches!(tx.owner_pin, anchor::OwnerPin::Placeholder) => {
                parts.push("anchor wallet not yet provisioned (owner pin deploy-gated)");
            },
            Some(_) => parts.push("anchor transaction not trust-bearing"),
        }
    }
    if !d.bound_to_qub() {
        parts.push("leaf ref opaque/blinded — not tied to this qub offline (kind=0x02 scope)");
    }
    parts.join("; ")
}

/// Push the shared per-proof detail rows (both verified + inclusion-only).
fn push_anchor_details(buf: &mut String, d: &AnchorDetails) {
    push_field(buf, "leaf_kind", leaf_kind_label(d.kind()));
    push_field(buf, "leaf_binding", binding_text(d.binding()));
    let pos = format!("leaf {} of {}", d.index(), d.size());
    push_field(buf, "tree_position", &pos);
    push_field(buf, "anchor_txid", d.txid_hex());
    if let Some(tx) = d.anchor_tx() {
        push_field(buf, "anchor_tx", &anchor_tx_text(tx));
    }
}

/// Render the transparency-log anchoring verdict into the aligned text report.
fn push_anchored_fields(buf: &mut String, anchored: &AnchorState) {
    match anchored {
        AnchorState::Absent => {
            push_field(buf, "anchored", "n/a (no inclusion proof in bundle)");
        },
        AnchorState::Broken(reason) => {
            let value = format!("BROKEN — {reason}");
            push_field(buf, "anchored", &value);
        },
        AnchorState::Verified(d) => {
            push_field(
                buf,
                "anchored",
                "verified (anchoring proven — anchor tx confirmed, leaf bound)",
            );
            push_anchor_details(buf, d);
        },
        AnchorState::InclusionOnly(d) => {
            push_field(
                buf,
                "anchored",
                "inclusion path self-consistent — anchoring NOT proven offline",
            );
            push_anchor_details(buf, d);
            push_field(buf, "anchoring_gap", &inclusion_only_reason(d));
        },
    }
}

/// Build the typed `anchored` JSON object (PRESENCE-ONLY was the pre-W5 shape;
/// this is the §16.9 typed verdict). `None` is the failure path — there is no
/// revealed qub to bind against, so only presence is reported.
/// The typed details object shared by the `verified` + `inclusion_only` states.
///
/// `merkle_root_ok` / `log_id_ok` are reported as descriptive facts (both
/// checks ran), NOT as the trust signal — the trust signal is `state` +
/// `anchor_confirmed` + `bound_to_qub`, since the Merkle root and `log_id` are
/// both attacker-settable in a fabricated proof (§16.9).
fn anchor_details_json(state: &str, d: &AnchorDetails) -> serde_json::Value {
    use serde_json::json;
    let anchor_tx = d.anchor_tx().map(|tx| {
        json!({
            "signature_valid": tx.signature_valid,
            "committed_root_ok": tx.committed_root_ok,
            "committed_size_ok": tx.committed_size_ok,
            "txid_match": tx.txid_match,
            "owner_pin": tx.owner_pin.label(),
        })
    });
    json!({
        "present": true,
        "state": state,
        "leaf_kind": d.kind(),
        "binding": d.binding().label(),
        "bound_to_qub": d.bound_to_qub(),
        "anchor_confirmed": d.anchor_confirmed(),
        "index": d.index(),
        "size": d.size(),
        "merkle_root_ok": true,
        "log_id_ok": true,
        "anchor_txid": d.txid_hex(),
        "anchor_tx": anchor_tx,
    })
}

fn anchored_json(bundle: &QubBundle, anchored: Option<&AnchorState>) -> serde_json::Value {
    use serde_json::json;
    let present = bundle.inclusion_proof().is_some();
    match anchored {
        None => json!({ "present": present }),
        Some(AnchorState::Absent) => json!({ "present": false, "state": "absent" }),
        Some(AnchorState::Broken(reason)) => {
            json!({ "present": true, "state": "broken", "reason": reason })
        },
        Some(AnchorState::Verified(d)) => anchor_details_json("verified", d),
        Some(AnchorState::InclusionOnly(d)) => {
            let mut obj = anchor_details_json("inclusion_only", d);
            obj["anchoring_gap"] = json!(inclusion_only_reason(d));
            obj
        },
    }
}

fn json_report(
    bundle: &QubBundle,
    revealed: Option<&RevealedQub>,
    verified: bool,
    failure_reason: Option<&str>,
    anchored: Option<&AnchorState>,
) -> serde_json::Value {
    use serde_json::json;
    let mut obj = json!({
        "verified": verified,
        "arweave_tx_id": bundle.arweave_tx_id(),
        "drand_round": bundle.drand_round(),
        "drand_chain_id": bundle.drand_chain_id(),
        "anchored": anchored_json(bundle, anchored),
    });
    if let Some(sealed_at) = bundle.sealed_at() {
        obj["sealed_at"] = json!(sealed_at);
    }
    if let Some(reason) = failure_reason {
        obj["reason"] = json!(reason);
    }
    if let Some(r) = revealed {
        obj["qub_id"] = json!(hex::encode(r.qub_id()));
        obj["content_type"] = json!(content_type_label(r.content_type()));
        obj["created_at"] = json!(r.created_at());
        obj["unlock_at"] = json!(r.unlock_at());
        obj["outcome_at"] = json!(r.outcome_at());
        obj["body_hash_verified"] = json!(r.body_hash_verified());
        obj["signature"] = json!(signature_label(r.signature_verified()));
        obj["signature_verified"] = json!(r.signature_verified());
        obj["cosigner_verified"] = json!(r.cosigner_verified());
        obj["sender_label"] = json!(r.sender_label());
        obj["title"] = json!(r.title());
        obj["body"] = json!(body_preview(r.body()));
    }
    obj
}

fn write_text(s: &str) -> Result<(), String> {
    io::stdout()
        .write_all(s.as_bytes())
        .map_err(|e| format!("failed to write output: {e}"))
}

fn write_json(value: &serde_json::Value) -> Result<(), String> {
    let text =
        serde_json::to_string_pretty(value).map_err(|e| format!("failed to render JSON: {e}"))?;
    let mut out = io::stdout();
    out.write_all(text.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .map_err(|e| format!("failed to write output: {e}"))
}
