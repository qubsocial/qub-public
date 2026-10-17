//! `qub-verify` — verifier for `.qub` export bundles.
//!
//! Reads a `.qub` bundle (the canonical-CBOR container produced by
//! `qub_core::export`), then confirms a revealed qub's content integrity,
//! round binding, and authorship **from the bundle alone** — no qub
//! infrastructure, no Arweave fetch, no live drand call. The bundle embeds the
//! drand round signature, and timelock decryption can only succeed with the
//! genuine beacon for the bound round, so a bundle that opens proves that the
//! round elapsed. That says nothing about when the ciphertext was created.
//!
//! `--timing` adds the one network step, and it is never taken without the
//! flag: for a **public** qub it asks Arweave gateways that qub does not run
//! about the bundle's storage transaction and reports the block time they
//! agree on as an upper bound on when those bytes existed (see
//! `qub_verify::timing` for exactly what is checked and what is assumed).
//! `--deadline` then requires that bound to be before a deadline.
//!
//! ```text
//! qub-verify reveal.qub              # verify a raw .qub file, offline
//! cat reveal.qub | qub-verify -      # read from stdin
//! qub-verify --base64url token.txt   # input is base64url(no-pad) text
//! qub-verify --json reveal.qub       # machine-readable report
//! qub-verify --timing reveal.qub                      # + storage block time
//! qub-verify --timing --deadline 1800000000 reveal.qub  # + before a deadline?
//! ```
//!
//! Exit codes: `0` verified · `1` verification failed (still locked, tampered,
//! bad signature, decrypt failure, storage transaction commits to other bytes,
//! or `--deadline` not established) · `2` usage / I/O / malformed-bundle error.

use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use clap::Parser;
use qub_core::export::QubBundle;
use qub_core::tlock::DrandTimelockProvider;
use qub_core::txid::TxId;
use qub_core::types::{CONTENT_TYPE_PACT, CONTENT_TYPE_TEXT, RevealedQub, VISIBILITY_PUBLIC};
use qub_core::unlock::UnlockError;

use qub_verify::anchor::{self, AnchorDetails, AnchorState, AnchorTxReport, Binding};
use qub_verify::timing::{
    self, DeadlineVerdict, Fetched, GatewayOutcome, GatewayReport, HttpReply, StatusReply,
    TimingEvidence, TimingPolicy, TimingState,
};

/// drand quicknet genesis time (Unix seconds) — baked into the protocol.
const QUICKNET_GENESIS: i64 = 1_692_803_367;
/// drand quicknet round period (seconds).
const QUICKNET_PERIOD: u64 = 3;

#[derive(Parser)]
#[command(
    name = "qub-verify",
    version,
    about = "Verifier for qub .qub export bundles",
    long_about = "Confirms a revealed qub's content integrity, round binding, and authorship from a .qub bundle alone — \
                  no network, no qub infrastructure. The bundle carries the drand round \
                  signature that unlocks it; a bundle that decrypts proves the round elapsed, \
                  not when the ciphertext was created. With --timing (the only network step, \
                  never taken without it) the storage transaction of a public qub is looked \
                  up on Arweave gateways that qub does not run and the block time they agree on is \
                  reported as an upper bound on when those bytes existed."
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

    /// Look up the bundle's storage transaction on third-party Arweave
    /// gateways and report the block time they agree on (public qubs only).
    /// This is the only option that uses the network.
    #[arg(long)]
    timing: bool,

    /// Require the storage block time to be before this deadline (Unix
    /// seconds), with the policy margin. Without that, the verdict is NOT
    /// VERIFIED.
    #[arg(long, value_name = "UNIX_SECONDS", requires = "timing", value_parser = parse_deadline)]
    deadline: Option<i64>,

    /// An Arweave gateway origin to consult instead of the built-in list
    /// (repeatable). At least two distinct gateways must agree.
    #[arg(long = "gateway", value_name = "URL", requires = "timing")]
    gateways: Vec<String>,

    /// Emit a machine-readable JSON report instead of human-readable text.
    #[arg(long)]
    json: bool,
}

/// What `--timing` established about the bundle's storage transaction.
enum TimingOutcome {
    /// `--timing` was not requested: nothing was looked up.
    NotRequested,
    /// The qub is private: no timing evidence is offered for it.
    Private,
    /// The gateways were consulted.
    Checked(TimingEvidence),
}

impl TimingOutcome {
    /// How the outcome compares with `--deadline`, when one was given.
    fn deadline_verdict(&self, deadline: Option<i64>) -> Option<DeadlineVerdict> {
        let deadline = deadline?;
        Some(match self {
            Self::Checked(evidence) => evidence.deadline_verdict(deadline),
            Self::NotRequested | Self::Private => DeadlineVerdict::Unknown,
        })
    }

    /// Whether the outcome must fail the overall verdict: the transaction the
    /// bundle names stores other bytes, or a requested deadline is not met.
    fn fails_verdict(&self, deadline: Option<i64>) -> bool {
        let invalid =
            matches!(self, Self::Checked(evidence) if evidence.state() == TimingState::Invalid);
        let deadline_unmet = self
            .deadline_verdict(deadline)
            .is_some_and(|verdict| verdict != DeadlineVerdict::Before);
        invalid || deadline_unmet
    }
}

/// Time allowed for one gateway request.
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(20);

/// One `GET` against a gateway, tried a second time if the first attempt
/// failed in transport (a dropped connection is common on a 700 KiB block
/// body; an HTTP status is an answer and is never retried).
fn gateway_get(client: &reqwest::blocking::Client, url: &str) -> Fetched {
    gateway_get_once(client, url).or_else(|_| gateway_get_once(client, url))
}

/// One bounded `GET` against a gateway. Redirects are not followed: a gateway
/// that bounces to another origin has not answered for itself.
fn gateway_get_once(client: &reqwest::blocking::Client, url: &str) -> Fetched {
    let response = client
        .get(url)
        .send()
        .map_err(|error| error.without_url().to_string())?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let limit = u64::try_from(timing::MAX_GATEWAY_BODY_BYTES).unwrap_or(u64::MAX);
    response
        .take(limit.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|error| format!("response could not be read: {error}"))?;
    if body.len() > timing::MAX_GATEWAY_BODY_BYTES {
        return Err("response is too large".to_owned());
    }
    Ok(HttpReply {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Ask each gateway about `tx_id`: its status, and when mined, its header and
/// block.
fn gather_reports(gateways: &[String], tx_id: &str) -> Result<Vec<GatewayReport>, String> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(GATEWAY_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("qub-verify/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    Ok(gateways
        .iter()
        .map(|gateway| {
            match timing::read_status(&gateway_get(&client, &timing::status_url(gateway, tx_id))) {
                StatusReply::Confirmed(status) => {
                    let header = gateway_get(&client, &timing::header_url(gateway, tx_id));
                    let block = gateway_get(
                        &client,
                        &timing::block_url(gateway, &status.block_indep_hash),
                    );
                    GatewayReport::confirmed(gateway, tx_id, status, &header, &block)
                },
                StatusReply::Pending => GatewayReport::new(gateway, GatewayOutcome::Pending),
                StatusReply::NotFound => GatewayReport::new(gateway, GatewayOutcome::NotFound),
                StatusReply::Unusable(reason) => {
                    GatewayReport::new(gateway, GatewayOutcome::Unusable(reason))
                },
            }
        })
        .collect())
}

/// Run the `--timing` leg for a bundle whose content already verified.
fn check_timing(
    cli: &Cli,
    bundle: &QubBundle,
    revealed: &RevealedQub,
) -> Result<TimingOutcome, String> {
    if !cli.timing {
        return Ok(TimingOutcome::NotRequested);
    }
    // A private qub is stored wrapped: the bundle does not hold the stored
    // bytes, so nothing here can tie it to its transaction.
    if revealed.visibility() != VISIBILITY_PUBLIC {
        return Ok(TimingOutcome::Private);
    }
    let gateways = if cli.gateways.is_empty() {
        timing::normalise_gateways(&timing::DEFAULT_GATEWAYS)
    } else {
        timing::normalise_gateways(&cli.gateways)
    }?;
    let policy = TimingPolicy::PROVISIONAL;
    // The id is placed in request paths: refuse anything that is not one.
    let Ok(tx_id) = TxId::parse(bundle.arweave_tx_id()) else {
        return Ok(TimingOutcome::Checked(TimingEvidence::unavailable(
            "the bundle's arweave_tx_id is not a transaction id",
            policy,
        )));
    };
    let reports = gather_reports(&gateways, tx_id.as_str())?;
    Ok(TimingOutcome::Checked(timing::evaluate(
        tx_id.as_str(),
        bundle.sealed_cbor().as_bytes(),
        &reports,
        &policy,
    )))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(message) => {
            // An error can quote the bundle (a duplicated map key, say), and
            // the bundle is untrusted: nothing of it reaches the terminal raw.
            eprintln!("qub-verify: {}", printable(&message));
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
    let content_verified =
        revealed.body_hash_verified() && signature_ok && cosigner_ok && !anchored.is_broken();
    // The network leg runs only for content that already verified.
    let timing = if content_verified {
        check_timing(cli, bundle, revealed)?
    } else {
        TimingOutcome::NotRequested
    };
    let verified = content_verified && !timing.fails_verdict(cli.deadline);

    if cli.json {
        let mut report = json_report(bundle, Some(revealed), verified, None, Some(&anchored));
        if cli.timing {
            report["content_verified"] = serde_json::json!(content_verified);
            report["timing"] = timing_json(&timing, bundle.arweave_tx_id(), cli.deadline);
        }
        write_json(&report)?;
    } else {
        // Everything this tool established comes first; the content — which
        // its author controls — comes last, fenced, and the verdict is
        // repeated after it.
        let mut report = text_report(bundle, revealed, verified, &anchored);
        if cli.timing {
            report.push_str(&timing_text(&timing, cli.deadline));
        }
        report.push_str(&content_section(revealed.body(), verified));
        write_text(&report)?;
    }

    Ok(if verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// `--deadline`: Unix seconds, refused when it can only be something else.
fn parse_deadline(text: &str) -> Result<i64, String> {
    let deadline = text
        .parse::<i64>()
        .map_err(|_| "not an integer".to_owned())?;
    timing::check_deadline(deadline)
}

/// Verification failed at the crypto layer (locked, tampered, bad signature).
fn report_failure(cli: &Cli, bundle: &QubBundle, err: &UnlockError) -> Result<ExitCode, String> {
    let reason = describe_unlock_error(err);
    if cli.json {
        write_json(&json_report(bundle, None, false, Some(&reason), None))?;
    } else {
        let mut s = String::new();
        s.push_str(verdict_line(false));
        push_field(&mut s, "reason:", &reason);
        // The bundle is untrusted input: its transaction id is any string.
        push_field(&mut s, "arweave_tx_id:", bundle.arweave_tx_id());
        push_field(&mut s, "drand_round:", &bundle.drand_round().to_string());
        write_text(&s)?;
    }
    Ok(ExitCode::from(1))
}

/// The `timing` member of the JSON report.
fn timing_json(timing: &TimingOutcome, tx_id: &str, deadline: Option<i64>) -> serde_json::Value {
    match timing {
        TimingOutcome::Checked(evidence) => evidence.to_json(tx_id, deadline),
        TimingOutcome::Private => timing::not_established_json(
            timing::STATE_UNSUPPORTED_PRIVATE,
            timing::PRIVATE_REASON,
            deadline,
        ),
        TimingOutcome::NotRequested => timing::not_established_json(
            timing::STATE_NOT_CHECKED,
            "content did not verify, so nothing was looked up",
            deadline,
        ),
    }
}

/// The timing section appended to the text report.
fn timing_text(timing: &TimingOutcome, deadline: Option<i64>) -> String {
    let mut s = String::from("\n--- storage time (--timing) ---\n");
    match timing {
        TimingOutcome::NotRequested => {
            push_field(&mut s, "timing", "not checked (content did not verify)");
        },
        TimingOutcome::Private => {
            push_field(&mut s, "timing", "not offered for private qubs");
            push_field(&mut s, "reason", timing::PRIVATE_REASON);
        },
        TimingOutcome::Checked(evidence) => {
            push_field(&mut s, "timing", evidence.state().label());
            push_field(&mut s, "reason", evidence.reason());
            if let Some(bound) = evidence.bound() {
                push_field(&mut s, "block_time", &bound.block_time.to_string());
                push_field(&mut s, "block_height", &bound.block_height.to_string());
                push_field(&mut s, "confirmations", &bound.confirmations.to_string());
            }
            for (gateway, result) in evidence.gateways() {
                push_field(&mut s, "gateway", &format!("{gateway} — {result}"));
            }
            let policy = evidence.policy();
            push_field(
                &mut s,
                "policy",
                &format!(
                    "provisional: {} gateways must agree, {} confirmations, {} s margin",
                    policy.min_agreeing_gateways,
                    policy.min_confirmations,
                    policy.timestamp_margin_secs
                ),
            );
            push_field(&mut s, "claim", &evidence.claim());
        },
    }
    if let Some(deadline) = deadline {
        let verdict = timing
            .deadline_verdict(Some(deadline))
            .unwrap_or(DeadlineVerdict::Unknown);
        let text = match verdict {
            DeadlineVerdict::Before => "before the deadline",
            DeadlineVerdict::TooClose => "NOT established — too close to the deadline to call",
            DeadlineVerdict::NotBefore => "NOT before the deadline",
            DeadlineVerdict::Unknown => "NOT established — no independent storage time",
        };
        push_field(&mut s, "deadline", &format!("{deadline}: {text}"));
    }
    s
}

fn describe_unlock_error(err: &UnlockError) -> String {
    match err {
        UnlockError::StillLocked { unlock_at, now } => format!(
            "still locked — unlocks at {unlock_at} (Unix), current time {now}; \
             {} seconds remaining",
            unlock_at.saturating_sub(*now).max(0)
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

const fn verdict_line(verified: bool) -> &'static str {
    if verified {
        "VERDICT: VERIFIED\n"
    } else {
        "VERDICT: NOT VERIFIED\n"
    }
}

/// True for a character that can move the cursor, hide text or reorder it
/// on a terminal: every control character, the Unicode line and paragraph
/// separators, and the bidirectional overrides and isolates.
const fn rewrites_the_screen(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Soft hyphen, Arabic letter mark, Mongolian vowel separator.
            '\u{00AD}' | '\u{061C}' | '\u{180E}'
            // Zero-width characters, marks, line/paragraph separators, the
            // bidirectional embeddings, overrides and isolates, and the
            // other invisible format characters of this block.
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            // Byte-order mark, interlinear annotation, tag characters.
            | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E007F}'
            // Private use: no shared meaning, so no way to know what is drawn.
            | '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{10FFFF}'
        )
}

/// A run of this many spaces or more is shown as a count instead.
const LONGEST_SPACE_RUN: usize = 8;

/// `text` on one line, with every screen-rewriting character shown as its
/// escape (`\u{1b}`) instead of being sent to the terminal.
///
/// A `.qub` bundle and the qub inside it are untrusted: a transaction id, a
/// title, a sender label or a body can hold an escape sequence that clears
/// the screen and draws a verdict this tool never gave.
///
/// A long run of spaces is shown as a count: padding to the terminal's
/// width would otherwise push the text after it to the start of a new
/// visual row, where it reads as a line of its own.
fn printable(text: &str) -> String {
    fn flush_spaces(out: &mut String, spaces: &mut usize) {
        if *spaces >= LONGEST_SPACE_RUN {
            out.push_str("\\u{20}x");
            out.push_str(&spaces.to_string());
        } else {
            out.extend(std::iter::repeat_n(' ', *spaces));
        }
        *spaces = 0;
    }
    let mut out = String::with_capacity(text.len());
    let mut spaces = 0;
    for c in text.chars() {
        if c == ' ' {
            spaces += 1;
            continue;
        }
        flush_spaces(&mut out, &mut spaces);
        if rewrites_the_screen(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    flush_spaces(&mut out, &mut spaces);
    out
}

/// Marks every line of untrusted content in the text report.
const CONTENT_PREFIX: &str = "| ";

/// The content, last in the report and fenced: every line of it starts with
/// [`CONTENT_PREFIX`], so no line of it can pass for a line of the report,
/// and the verdict is stated again after it.
fn content_section(body: &[u8], verified: bool) -> String {
    let mut s = format!(
        "\n--- content: {} bytes, written by the qub's author; every line of it starts with `{}` ---\n",
        body.len(),
        CONTENT_PREFIX.trim_end()
    );
    for line in body_preview(body).split('\n') {
        s.push_str(CONTENT_PREFIX);
        // A tab is harmless and common in text; everything else is escaped.
        for (index, part) in line.split('\t').enumerate() {
            if index > 0 {
                s.push('\t');
            }
            s.push_str(&printable(part));
        }
        s.push('\n');
    }
    s.push_str("--- end of content ---\n");
    s.push_str(verdict_line(verified));
    s
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
    s.push_str(verdict_line(verified));

    push_field(&mut s, "qub_id", &hex::encode(revealed.qub_id()));
    // The id is whatever the bundle says. Only `--timing` ties it to
    // anything, and reports that below.
    push_field(
        &mut s,
        "arweave_tx_id",
        &format!("{} (bundle-supplied)", revealed.arweave_tx_id()),
    );
    push_field(
        &mut s,
        "content_type",
        content_type_label(revealed.content_type()),
    );
    push_field(
        &mut s,
        "created_at",
        &format!("{} (author-supplied)", revealed.created_at()),
    );
    push_field(&mut s, "unlock_at", &revealed.unlock_at().to_string());
    if let Some(outcome_at) = revealed.outcome_at() {
        push_field(&mut s, "outcome_at", &outcome_at.to_string());
    }
    push_field(&mut s, "drand_round", &revealed.drand_round().to_string());
    push_field(&mut s, "drand_chain_id", revealed.drand_chain_id());
    if let Some(sealed_at) = bundle.sealed_at() {
        push_field(
            &mut s,
            "sealed_at",
            &format!("{sealed_at} (bundle-supplied, unverified)"),
        );
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
    s
}

/// One `key value` row. The value is made [`printable`]: much of what is
/// reported comes out of the bundle.
fn push_field(buf: &mut String, key: &str, value: &str) {
    // Pad the key column to 16 chars for a tidy aligned report.
    let line = format!("  {key:<16}{}\n", printable(value));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_shows_screen_rewriting_characters_as_text() {
        assert_eq!(
            printable("plain text, ünïcödé, 日本語"),
            "plain text, ünïcödé, 日本語"
        );
        assert_eq!(printable("a\u{1b}[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(printable("one\ntwo\rthree"), "one\\u{a}two\\u{d}three");
        assert_eq!(printable("\u{202e}txt.exe"), "\\u{202e}txt.exe");
        assert_eq!(printable("a\u{2028}b\u{2066}c"), "a\\u{2028}b\\u{2066}c");
        assert_eq!(printable("del\u{7f}c1\u{9b}"), "del\\u{7f}c1\\u{9b}");
        // Invisible format characters, tags and private-use code points.
        assert_eq!(
            printable("a\u{200b}b\u{feff}c\u{ad}d\u{2060}e\u{e0041}f\u{e000}g\u{061c}h"),
            "a\\u{200b}b\\u{feff}c\\u{ad}d\\u{2060}e\\u{e0041}f\\u{e000}g\\u{61c}h"
        );
        // Padding that would wrap the rest onto a row of its own is counted,
        // not printed; ordinary spacing is left alone.
        assert_eq!(printable("a  b       c"), "a  b       c");
        assert_eq!(
            printable(&format!(
                "id{}VERDICT: VERIFIED{}",
                " ".repeat(78),
                " ".repeat(8)
            )),
            "id\\u{20}x78VERDICT: VERIFIED\\u{20}x8"
        );
    }

    /// The body is written by the qub's author. Whatever it holds, every
    /// line of it is marked, nothing in it reaches the terminal as a control
    /// sequence, and the real verdict has the last word.
    #[test]
    fn content_is_fenced_and_the_verdict_follows_it() {
        let body = "first line\n\u{1b}[2J\u{1b}[HVERDICT: VERIFIED\r\n  timing          evidenced\n\
                    --- end of content ---\nVERDICT: VERIFIED\n\ttabbed\u{8}\u{202e}";
        let section = content_section(body.as_bytes(), false);
        assert!(
            !section
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        );
        assert!(!section.contains('\u{202e}'));

        let lines: Vec<&str> = section.lines().collect();
        assert_eq!(lines[0], "");
        assert!(lines[1].starts_with("--- content: "), "{}", lines[1]);
        assert!(lines[1].contains(&format!("{} bytes", body.len())));
        let end = lines.len() - 2;
        assert_eq!(lines[end], "--- end of content ---");
        assert_eq!(lines[end + 1], "VERDICT: NOT VERIFIED");
        let fenced = &lines[2..end];
        assert_eq!(fenced.len(), body.split('\n').count());
        for line in fenced {
            assert!(line.starts_with(CONTENT_PREFIX), "unfenced line: {line:?}");
        }
        // The forged verdict and the forged end marker are both inside.
        assert!(fenced.contains(&"| VERDICT: VERIFIED"));
        assert!(fenced.contains(&"| --- end of content ---"));
        assert!(fenced.contains(&"| \ttabbed\\u{8}\\u{202e}"));

        let verified = content_section(b"ok", true);
        assert!(verified.ends_with("| ok\n--- end of content ---\nVERDICT: VERIFIED\n"));
        let binary = content_section(&[0xff, 0xfe], true);
        assert!(binary.contains("| <2 bytes of binary content>"));
    }

    #[test]
    fn report_rows_are_one_printable_line_each() {
        let mut out = String::new();
        push_field(&mut out, "title", "x\nVERDICT: VERIFIED\u{1b}[8m");
        assert_eq!(out.lines().count(), 1);
        assert!(!out.contains('\u{1b}'));
        assert!(out.starts_with("  title           x\\u{a}VERDICT"));
    }

    /// `--now` is operator input; an extreme value must not panic.
    #[test]
    fn a_far_past_clock_does_not_overflow() {
        let text = describe_unlock_error(&UnlockError::StillLocked {
            unlock_at: i64::MAX,
            now: i64::MIN,
        });
        assert!(text.contains("still locked"), "{text}");
    }
}
