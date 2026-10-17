//! Existence-time evidence from a qub's own Arweave storage transaction.
//!
//! PROTOCOL.md §17.4 step 9: a bundle alone never says when its ciphertext was
//! created; "independently verify the referenced storage transaction" and
//! "report its block time as an upper bound on ciphertext existence". This
//! module is that leg, for **public** artifacts, whose stored bytes are exactly
//! the canonical `SealedQubCbor` a verifier already holds.
//!
//! # What is checked, and what is assumed
//!
//! Checked locally, with no trust in anyone ([`crate::arweave_tx`]): the bytes
//! hash to the transaction's `data_root`, the header's signature covers that
//! root, and the id is the hash of that signature.
//!
//! Read from gateways, and therefore **assumed**: which header belongs to the
//! id, that a block contains it, that block's timestamp and its depth. A light
//! verifier cannot validate Arweave consensus, so no single gateway is
//! believed. A verdict needs [`TimingPolicy::min_agreeing_gateways`] distinct
//! gateways reporting the *same* header in the *same* block at the *same*
//! time, at least [`TimingPolicy::min_confirmations`] deep. A gateway that has
//! not seen the transaction, or has not mined it, does not veto the ones that
//! have: it lowers the count, it is not a contradiction. The gateways are
//! operated by parties other than qub; they are not known to be independent
//! of one another, and the claim is never stronger than that.
//!
//! A block timestamp is set by its miner within the network's rules. It is an
//! evidence bound under those rules, not a wall-clock measurement, so a
//! deadline comparison keeps [`TimingPolicy::timestamp_margin_secs`] in hand
//! and reports "too close" instead of guessing.
//!
//! # Fail closed
//!
//! Every state other than [`TimingState::Evidenced`] carries no time at all.
//! A transaction no gateway has seen — for example one that was signed and
//! acknowledged but never mined — is [`TimingState::NotOnChain`]; an
//! unreachable network is [`TimingState::Unavailable`]; disagreement is
//! [`TimingState::Conflict`]. None of them can produce
//! [`DeadlineVerdict::Before`]. Nothing here reads an author-supplied time, a
//! drand round, a Worker receipt or an operator timestamp.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::{Value, json};

use crate::arweave_tx::TxHeader;

/// Gateways consulted by default — the same three the qub Worker reads from.
///
/// None is run by qub. They are **not** shown to be three sources: two of
/// them answer with the response headers of an AR.IO gateway node, software
/// that by default answers chain queries (`/tx`, `/block`) by forwarding
/// them to another node, and nothing here can see which. Until that is
/// measured, "two gateways agree" may mean one upstream said so twice.
pub const DEFAULT_GATEWAYS: [&str; 3] = [
    "https://arweave.net",
    "https://ar-io.dev",
    "https://permagate.io",
];

/// Most gateways one evaluation will consult.
pub const MAX_GATEWAYS: usize = 8;

/// Upper bound on a status or block response body, in bytes. A block header
/// carries its proof-of-access chunks, so it is large: about 740 KiB for the
/// mainnet block recorded in the fixtures.
pub const MAX_GATEWAY_BODY_BYTES: usize = 4 * 1024 * 1024;

/// No Arweave block is older than this (the network launched in June 2018;
/// the bound is deliberately loose). A "block time" before it is not one.
pub const MIN_PLAUSIBLE_BLOCK_TIME: i64 = 1_500_000_000;

/// Unix seconds for the year 3000. A larger "time" is almost certainly
/// milliseconds, and a millisecond deadline would make every block "before"
/// it.
pub const MAX_PLAUSIBLE_UNIX_SECS: i64 = 32_503_680_000;

/// Accept `deadline` only if it can be Unix **seconds**.
///
/// # Errors
///
/// A description of why the value is refused.
pub fn check_deadline(deadline: i64) -> Result<i64, String> {
    if deadline <= 0 {
        return Err("deadline must be a positive Unix timestamp in seconds".to_owned());
    }
    if deadline >= MAX_PLAUSIBLE_UNIX_SECS {
        return Err(format!(
            "deadline {deadline} is not a plausible Unix timestamp in seconds \
             (is it in milliseconds?)"
        ));
    }
    Ok(deadline)
}

/// Length of a base64url block `indep_hash` (48 bytes, no padding).
const INDEP_HASH_LEN: usize = 64;

/// The thresholds a verdict must clear.
///
/// **These numbers are provisional.** The owner approved this evidence path
/// and these thresholds for the pilot on 2026-10-11, as provisional: no
/// publication-to-confirmation latency or reorganisation depth has been
/// measured for this product yet, and the numbers are to be revisited when
/// one has. They are deliberately conservative, and every report prints
/// them, so no verdict hides what it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingPolicy {
    /// Distinct gateways that must report the identical observation.
    pub min_agreeing_gateways: usize,
    /// Blocks that must have been mined on top of the containing block,
    /// counted by the least optimistic agreeing gateway.
    pub min_confirmations: u64,
    /// Seconds a block timestamp must clear a deadline by.
    pub timestamp_margin_secs: i64,
}

impl TimingPolicy {
    /// The provisional policy every qub tool uses (see the type's docs).
    pub const PROVISIONAL: Self = Self {
        min_agreeing_gateways: 2,
        min_confirmations: 10,
        timestamp_margin_secs: 600,
    };
}

/// One HTTP exchange with a gateway, as far as a verdict needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    /// HTTP status code.
    pub status: u16,
    /// Response body (already bounded by the caller).
    pub body: String,
}

/// A gateway exchange, or why there was none (`Err`: transport failure).
pub type Fetched = Result<HttpReply, String>;

/// Normalise a gateway base URL to its origin, or refuse it.
///
/// Only `https://host[:port]` is accepted, plus plain `http://` for a loopback
/// host so tests can stand in a local gateway. A path, query, fragment or
/// user-info is refused: a "gateway" is an origin, and two paths on one host
/// are not two gateways.
///
/// # Errors
///
/// A description of what is wrong with `input`.
pub fn normalise_gateway(input: &str) -> Result<String, String> {
    let bare =
        || format!("gateway {input:?} must be a bare origin (scheme, host and optional port)");
    let trimmed = input.trim().trim_end_matches('/');
    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| format!("gateway {input:?} is not an http(s) URL"))?;
    let scheme = scheme.to_ascii_lowercase();
    let rest = rest.to_ascii_lowercase();
    let (name, port) = split_host_port(&rest);
    let name = canonical_host(name).ok_or_else(bare)?;
    let name = name.as_str();
    let port = match port {
        None => None,
        // Digits only (`u16::from_str` alone would take `+80`), in range.
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            Some(text.parse::<u16>().map_err(|_| bare())?)
        },
        Some(_) => return Err(bare()),
    };
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" if is_loopback(name) => 80,
        "http" => {
            return Err(format!(
                "gateway {input:?} must use https (plain http is accepted for loopback only)"
            ));
        },
        _ => return Err(format!("gateway {input:?} is not an http(s) URL")),
    };
    // One spelling per origin: the default port is never written, and a
    // port has no leading zeros.
    Ok(port.filter(|port| *port != default_port).map_or_else(
        || format!("{scheme}://{name}"),
        |port| format!("{scheme}://{name}:{port}"),
    ))
}

/// One spelling per host, or `None` for something that is not a host.
///
/// An address must be written the one way the standard library prints it,
/// so `127.1`, `0x7f000001`, `2130706433` and `[0:0:0:0:0:0:0:1]` cannot
/// stand beside `127.0.0.1` and `[::1]` as further gateways. A name loses
/// one trailing dot and may hold no empty label.
fn canonical_host(name: &str) -> Option<String> {
    if let Some(inner) = name.strip_prefix('[') {
        let address: Ipv6Addr = inner.strip_suffix(']')?.parse().ok()?;
        return Some(format!("[{address}]"));
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    let labelled = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !labelled {
        return None;
    }
    // No top-level domain starts with a digit: such a name is an address,
    // and must be a dotted quad.
    let numeric = name
        .rsplit('.')
        .next()
        .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_digit()));
    if numeric {
        // The parser takes only the canonical dotted quad (no short, octal
        // or hexadecimal forms, no leading zeros), and what is kept is what
        // it prints.
        let address: Ipv4Addr = name.parse().ok()?;
        return Some(address.to_string());
    }
    Some(name.to_owned())
}

/// Split `host[:port]`. An IPv6 literal is bracketed and holds colons of its
/// own, so only a colon after the closing bracket separates a port.
fn split_host_port(rest: &str) -> (&str, Option<&str>) {
    match rest.rfind(':') {
        Some(at) if !rest[at..].contains(']') => (&rest[..at], Some(&rest[at + 1..])),
        _ => (rest, None),
    }
}

/// True for a (canonical) name of this machine's loopback interface:
/// `localhost`, anything in `127.0.0.0/8`, or `[::1]`.
fn is_loopback(name: &str) -> bool {
    name == "localhost"
        || name.parse::<Ipv4Addr>().is_ok_and(|a| a.is_loopback())
        || name
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
            .is_some_and(|a| a.is_loopback())
}

/// What two entries must differ in to count as two gateways.
///
/// A normalised origin, except that every loopback name on one port is the
/// same key: `localhost` and `127.0.0.1` are one server. Two public names
/// that resolve to one server cannot be told apart from here — the operator
/// who lists them is the one who knows.
fn source_key(gateway: &str) -> String {
    let rest = gateway.split_once("://").map_or(gateway, |(_, rest)| rest);
    let (name, port) = split_host_port(rest);
    if is_loopback(name) {
        format!("loopback:{}", port.unwrap_or_default())
    } else {
        gateway.to_owned()
    }
}

/// Normalise a gateway list: every entry valid, duplicates dropped, at most
/// [`MAX_GATEWAYS`].
///
/// # Errors
///
/// The first invalid entry's description, or a note that the list is empty or
/// too long.
pub fn normalise_gateways<S: AsRef<str>>(inputs: &[S]) -> Result<Vec<String>, String> {
    let mut gateways: Vec<String> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    for input in inputs {
        let gateway = normalise_gateway(input.as_ref())?;
        let source = source_key(&gateway);
        if !sources.contains(&source) {
            sources.push(source);
            gateways.push(gateway);
        }
    }
    if gateways.is_empty() {
        return Err("no Arweave gateway configured".to_owned());
    }
    if gateways.len() > MAX_GATEWAYS {
        return Err(format!("at most {MAX_GATEWAYS} gateways may be configured"));
    }
    Ok(gateways)
}

/// `GET` URL for a transaction's inclusion status on `gateway`.
#[must_use]
pub fn status_url(gateway: &str, tx_id: &str) -> String {
    format!("{gateway}/tx/{tx_id}/status")
}

/// `GET` URL for a transaction's header on `gateway`.
#[must_use]
pub fn header_url(gateway: &str, tx_id: &str) -> String {
    format!("{gateway}/tx/{tx_id}")
}

/// `GET` URL for the block with `indep_hash` on `gateway`.
#[must_use]
pub fn block_url(gateway: &str, indep_hash: &str) -> String {
    format!("{gateway}/block/hash/{indep_hash}")
}

/// Where a gateway says a transaction was mined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    /// Height of the containing block.
    pub block_height: u64,
    /// `indep_hash` of the containing block (validated base64url, so it is
    /// safe to place in [`block_url`]).
    pub block_indep_hash: String,
    /// Blocks the gateway counts on top of it.
    pub confirmations: u64,
}

/// A gateway's answer to [`status_url`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReply {
    /// Mined: the header and block can now be fetched.
    Confirmed(TxStatus),
    /// Known to the gateway, not in a block yet.
    Pending,
    /// Unknown to the gateway.
    NotFound,
    /// No usable answer (transport failure, error status, malformed body).
    Unusable(String),
}

/// True for a well-formed block `indep_hash`.
fn is_indep_hash(text: &str) -> bool {
    text.len() == INDEP_HASH_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Classify a gateway's status response.
#[must_use]
pub fn read_status(reply: &Fetched) -> StatusReply {
    let reply = match reply {
        Ok(reply) => reply,
        Err(error) => return StatusReply::Unusable(format!("status request failed: {error}")),
    };
    match reply.status {
        200 => {},
        202 => return StatusReply::Pending,
        404 => return StatusReply::NotFound,
        other => return StatusReply::Unusable(format!("status request answered HTTP {other}")),
    }
    let Ok(body) = serde_json::from_str::<Value>(&reply.body) else {
        return StatusReply::Unusable("status response is not JSON".to_owned());
    };
    let height = body.get("block_height").and_then(Value::as_u64);
    let hash = body
        .get("block_indep_hash")
        .and_then(Value::as_str)
        .filter(|hash| is_indep_hash(hash));
    let confirmations = body.get("number_of_confirmations").and_then(Value::as_u64);
    match (height, hash, confirmations) {
        (Some(block_height), Some(hash), Some(confirmations)) => StatusReply::Confirmed(TxStatus {
            block_height,
            block_indep_hash: hash.to_owned(),
            confirmations,
        }),
        _ => StatusReply::Unusable("status response is missing a block reference".to_owned()),
    }
}

/// What one gateway reports about a mined transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The transaction header the gateway returned.
    pub header: TxHeader,
    /// Height of the containing block.
    pub block_height: u64,
    /// `indep_hash` of the containing block.
    pub block_indep_hash: String,
    /// The block's timestamp, Unix seconds.
    pub block_timestamp: i64,
    /// Blocks the gateway counts on top of it.
    pub confirmations: u64,
}

/// One gateway's contribution to an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayOutcome {
    /// The gateway places the transaction in a block.
    Confirmed(Box<Observation>),
    /// The gateway knows the transaction but it is not mined.
    Pending,
    /// The gateway does not know the transaction.
    NotFound,
    /// The gateway gave no usable answer.
    Unusable(String),
}

/// A gateway and what it reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayReport {
    /// The gateway's normalised origin.
    pub gateway: String,
    /// Its outcome.
    pub outcome: GatewayOutcome,
}

impl GatewayReport {
    /// A report that is not a block observation.
    #[must_use]
    pub fn new(gateway: &str, outcome: GatewayOutcome) -> Self {
        Self {
            gateway: gateway.to_owned(),
            outcome,
        }
    }

    /// Build the report for a gateway whose status reply was
    /// [`StatusReply::Confirmed`], from its header and block responses.
    ///
    /// The block must be the one the status named, at the height it named,
    /// and must list the transaction; otherwise the gateway contradicts
    /// itself and its report is unusable.
    #[must_use]
    pub fn confirmed(
        gateway: &str,
        tx_id: &str,
        status: TxStatus,
        header: &Fetched,
        block: &Fetched,
    ) -> Self {
        let outcome = observation(tx_id, status, header, block)
            .map_or_else(GatewayOutcome::Unusable, |o| {
                GatewayOutcome::Confirmed(Box::new(o))
            });
        Self::new(gateway, outcome)
    }
}

/// A 200 response body, or why there is none.
fn ok_body<'a>(reply: &'a Fetched, what: &str) -> Result<&'a str, String> {
    match reply {
        Ok(reply) if reply.status == 200 => Ok(&reply.body),
        Ok(reply) => Err(format!("{what} request answered HTTP {}", reply.status)),
        Err(error) => Err(format!("{what} request failed: {error}")),
    }
}

fn observation(
    tx_id: &str,
    status: TxStatus,
    header: &Fetched,
    block: &Fetched,
) -> Result<Observation, String> {
    let header = TxHeader::from_gateway_json(ok_body(header, "header")?)
        .map_err(|error| error.to_string())?;
    let block: Value = serde_json::from_str(ok_body(block, "block")?)
        .map_err(|_| "block response is not JSON".to_owned())?;
    if block.get("indep_hash").and_then(Value::as_str) != Some(status.block_indep_hash.as_str()) {
        return Err("block response is not the block the status named".to_owned());
    }
    if block.get("height").and_then(Value::as_u64) != Some(status.block_height) {
        return Err("block height disagrees with the status".to_owned());
    }
    let lists_tx = block
        .get("txs")
        .and_then(Value::as_array)
        .is_some_and(|txs| txs.iter().any(|tx| tx.as_str() == Some(tx_id)));
    if !lists_tx {
        return Err("block does not list the transaction".to_owned());
    }
    let block_timestamp = block
        .get("timestamp")
        .and_then(Value::as_i64)
        .filter(|timestamp| (MIN_PLAUSIBLE_BLOCK_TIME..MAX_PLAUSIBLE_UNIX_SECS).contains(timestamp))
        .ok_or_else(|| "block has no plausible timestamp".to_owned())?;
    Ok(Observation {
        header,
        block_height: status.block_height,
        block_indep_hash: status.block_indep_hash,
        block_timestamp,
        confirmations: status.confirmations,
    })
}

/// The outcome of an evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingState {
    /// Enough gateways agree, deeply enough, on a block that contains a
    /// transaction committing to exactly these bytes. The only state with a
    /// time.
    Evidenced,
    /// The transaction has been seen but is not yet mined, not yet deep
    /// enough, or not yet reported by enough gateways. Ask again later.
    Pending,
    /// Enough gateways answered, and none knows the transaction. It may not
    /// have been posted yet, or it never was.
    NotOnChain,
    /// Too few gateways gave a usable answer to conclude anything.
    Unavailable,
    /// Gateways report different transactions or different blocks for this id.
    Conflict,
    /// The transaction with this id commits to other bytes: the artifact is
    /// not what that transaction stores.
    Invalid,
}

impl TimingState {
    /// A stable machine label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Evidenced => "evidenced",
            Self::Pending => "pending",
            Self::NotOnChain => "not_on_chain",
            Self::Unavailable => "unavailable",
            Self::Conflict => "conflict",
            Self::Invalid => "invalid",
        }
    }
}

/// The block a quorum of gateways agrees on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBound {
    /// The block's timestamp, Unix seconds: the upper bound on when the
    /// bytes existed, under the stated assumptions.
    pub block_time: i64,
    /// The block's height.
    pub block_height: u64,
    /// The block's `indep_hash`.
    pub block_indep_hash: String,
    /// The smallest confirmation count among the agreeing gateways.
    pub confirmations: u64,
    /// The gateways that agree.
    pub agreeing_gateways: Vec<String>,
}

/// How evidence compares with a deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineVerdict {
    /// The block time clears the deadline by more than the policy margin.
    Before,
    /// The block time is earlier than the deadline, but by no more than the
    /// margin: too close for a timestamp a miner chose.
    TooClose,
    /// The block time is at or after the deadline.
    NotBefore,
    /// There is no evidenced time to compare.
    Unknown,
}

impl DeadlineVerdict {
    /// A stable machine label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::TooClose => "too_close",
            Self::NotBefore => "not_before",
            Self::Unknown => "unknown",
        }
    }
}

/// The result of [`evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingEvidence {
    state: TimingState,
    reason: String,
    bound: Option<ChainBound>,
    gateways: Vec<(String, String)>,
    policy: TimingPolicy,
}

impl TimingEvidence {
    /// The state.
    #[must_use]
    pub const fn state(&self) -> TimingState {
        self.state
    }

    /// Why the state is what it is, in one sentence.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The agreed block. `Some` exactly when the state is
    /// [`TimingState::Evidenced`].
    #[must_use]
    pub const fn bound(&self) -> Option<&ChainBound> {
        self.bound.as_ref()
    }

    /// The policy the evaluation applied.
    #[must_use]
    pub const fn policy(&self) -> &TimingPolicy {
        &self.policy
    }

    /// Each distinct gateway consulted and a short label for what it said.
    #[must_use]
    pub fn gateways(&self) -> &[(String, String)] {
        &self.gateways
    }

    /// Evidence for an artifact no gateway was asked about, with the reason.
    /// Never [`TimingState::Evidenced`].
    #[must_use]
    pub fn unavailable(reason: impl Into<String>, policy: TimingPolicy) -> Self {
        Self {
            state: TimingState::Unavailable,
            reason: reason.into(),
            bound: None,
            gateways: Vec::new(),
            policy,
        }
    }

    /// Compare the evidence with `deadline` (Unix seconds).
    ///
    /// [`DeadlineVerdict::Before`] requires an evidenced block time `T` with
    /// `T + margin < deadline`. Equality is not "before".
    #[must_use]
    pub fn deadline_verdict(&self, deadline: i64) -> DeadlineVerdict {
        let Some(bound) = &self.bound else {
            return DeadlineVerdict::Unknown;
        };
        if self.state != TimingState::Evidenced {
            return DeadlineVerdict::Unknown;
        }
        if bound.block_time >= deadline {
            DeadlineVerdict::NotBefore
        } else if bound
            .block_time
            .saturating_add(self.policy.timestamp_margin_secs)
            < deadline
        {
            DeadlineVerdict::Before
        } else {
            DeadlineVerdict::TooClose
        }
    }

    /// The machine-readable report shared by `qub-verify` and `qub-mcp`.
    ///
    /// `deadline` adds a `deadline` member with the comparison. The `claim`
    /// member states, in words, the most the report supports.
    #[must_use]
    pub fn to_json(&self, tx_id: &str, deadline: Option<i64>) -> Value {
        let mut report = json!({
            "state": self.state.label(),
            "basis": "arweave_storage_transaction",
            "tx_id": tx_id,
            "reason": self.reason,
            "claim": self.claim(),
            "gateways": self
                .gateways
                .iter()
                .map(|(gateway, result)| json!({ "gateway": gateway, "result": result }))
                .collect::<Vec<_>>(),
            "policy": {
                "status": "provisional",
                "min_agreeing_gateways": self.policy.min_agreeing_gateways,
                "min_confirmations": self.policy.min_confirmations,
                "timestamp_margin_secs": self.policy.timestamp_margin_secs,
            },
        });
        if let Some(bound) = &self.bound {
            report["block_time"] = json!(bound.block_time);
            report["block_height"] = json!(bound.block_height);
            report["block_indep_hash"] = json!(bound.block_indep_hash);
            report["confirmations"] = json!(bound.confirmations);
            report["agreeing_gateways"] = json!(bound.agreeing_gateways);
        }
        if let Some(deadline) = deadline {
            report["deadline"] = json!({
                "deadline": deadline,
                "verdict": self.deadline_verdict(deadline).label(),
            });
        }
        report
    }

    /// The most this evidence supports, in words.
    #[must_use]
    pub fn claim(&self) -> String {
        match (&self.bound, self.state) {
            (Some(bound), TimingState::Evidenced) => format!(
                "These exact bytes are committed by an Arweave transaction that {} gateways \
                 place in block {} with timestamp {}. If those gateways report the Arweave \
                 chain correctly (they are not known to be independent of one another) and \
                 that block's miner-set timestamp is honest within the network's rules, the \
                 bytes existed no later than that time. This is not a statement about who \
                 created them or when before that.",
                bound.agreeing_gateways.len(),
                bound.block_height,
                bound.block_time
            ),
            _ => "No independent existence time is established for these bytes.".to_owned(),
        }
    }
}

/// `timing.state` for a private qub.
pub const STATE_UNSUPPORTED_PRIVATE: &str = "unsupported_private";
/// `timing.state` when the lookup was not made.
pub const STATE_NOT_CHECKED: &str = "not_checked";
/// Why no timing evidence is offered for a private qub.
pub const PRIVATE_REASON: &str = "this qub is private: timing evidence is offered for public \
    qubs only in this release. A private qub is stored wrapped, and a `.qub` bundle does not \
    carry the wrapped bytes its transaction commits to";

/// The report for an artifact whose storage time was not looked up, in the
/// same shape as [`TimingEvidence::to_json`]. It never carries a time, and a
/// `deadline` is always answered `unknown`.
#[must_use]
pub fn not_established_json(state: &str, reason: &str, deadline: Option<i64>) -> Value {
    let mut report = json!({
        "state": state,
        "reason": reason,
        "claim": "No independent existence time is established for these bytes.",
    });
    if let Some(deadline) = deadline {
        report["deadline"] = json!({
            "deadline": deadline,
            "verdict": DeadlineVerdict::Unknown.label(),
        });
    }
    report
}

/// A short label for a gateway's outcome.
fn outcome_label(outcome: &GatewayOutcome) -> String {
    match outcome {
        GatewayOutcome::Confirmed(observation) => format!(
            "confirmed in block {} ({} confirmations)",
            observation.block_height, observation.confirmations
        ),
        GatewayOutcome::Pending => "pending".to_owned(),
        GatewayOutcome::NotFound => "not found".to_owned(),
        GatewayOutcome::Unusable(reason) => format!("unusable: {reason}"),
    }
}

/// The distinct gateways' usable answers, counted.
struct Tally<'a> {
    /// Each distinct gateway and a short label for what it said.
    gateways: Vec<(String, String)>,
    /// Observations whose header is a self-consistent transaction with the
    /// requested id.
    confirmed: Vec<(&'a str, &'a Observation)>,
    pending: usize,
    not_found: usize,
}

impl<'a> Tally<'a> {
    /// Count each gateway once. A confirmed report whose header is not this
    /// transaction is recorded as unusable and counts for nothing.
    fn of(tx_id: &str, reports: &'a [GatewayReport]) -> Self {
        let mut tally = Self {
            gateways: Vec::new(),
            confirmed: Vec::new(),
            pending: 0,
            not_found: 0,
        };
        for report in reports {
            if tally
                .gateways
                .iter()
                .any(|(gateway, _)| gateway == &report.gateway)
            {
                continue;
            }
            let mut label = outcome_label(&report.outcome);
            match &report.outcome {
                GatewayOutcome::Confirmed(observation) => match observation.header.verify(tx_id) {
                    Ok(()) => tally.confirmed.push((&report.gateway, observation)),
                    Err(fault) => label = format!("unusable: {fault}"),
                },
                GatewayOutcome::Pending => tally.pending += 1,
                GatewayOutcome::NotFound => tally.not_found += 1,
                GatewayOutcome::Unusable(_) => {},
            }
            tally.gateways.push((report.gateway.clone(), label));
        }
        tally
    }

    /// True when two usable observations describe different transactions or
    /// different blocks. A difference is never resolved by majority.
    fn disagrees(&self) -> bool {
        self.confirmed.first().is_some_and(|(_, first)| {
            self.confirmed.iter().any(|(_, other)| {
                other.header != first.header
                    || other.block_height != first.block_height
                    || other.block_indep_hash != first.block_indep_hash
                    || other.block_timestamp != first.block_timestamp
            })
        })
    }

    /// The verdict when enough gateways agree on `first`'s block.
    fn agreed(
        &self,
        first: &Observation,
        policy: &TimingPolicy,
    ) -> (TimingState, String, Option<ChainBound>) {
        let confirmations = self
            .confirmed
            .iter()
            .map(|(_, observation)| observation.confirmations)
            .min()
            .unwrap_or(0);
        if confirmations < policy.min_confirmations {
            return (
                TimingState::Pending,
                format!(
                    "mined in block {}, but only {confirmations} of the required {} \
                     confirmations so far",
                    first.block_height, policy.min_confirmations
                ),
                None,
            );
        }
        let bound = ChainBound {
            block_time: first.block_timestamp,
            block_height: first.block_height,
            block_indep_hash: first.block_indep_hash.clone(),
            confirmations,
            agreeing_gateways: self
                .confirmed
                .iter()
                .map(|(gateway, _)| (*gateway).to_owned())
                .collect(),
        };
        (
            TimingState::Evidenced,
            format!(
                "{} gateways agree on block {} at least {confirmations} confirmations deep",
                self.confirmed.len(),
                first.block_height
            ),
            Some(bound),
        )
    }

    /// The verdict over everything counted.
    fn verdict(
        &self,
        stored: &[u8],
        policy: &TimingPolicy,
    ) -> (TimingState, String, Option<ChainBound>) {
        // A verified header is tied to its id by cryptography, not by a
        // gateway's word. If one does not commit to these bytes, they are
        // not this transaction's — below quorum, mid-conflict or otherwise.
        // Decided first, so that no gateway can turn "these are the wrong
        // bytes" into a softer "the gateways disagree".
        if let Some(fault) = self
            .confirmed
            .iter()
            .find_map(|(_, observation)| observation.header.commits_to(stored).err())
        {
            return (TimingState::Invalid, fault.to_string(), None);
        }
        if self.disagrees() {
            return (
                TimingState::Conflict,
                "gateways report different transactions or blocks for this id".to_owned(),
                None,
            );
        }
        let needed = policy.min_agreeing_gateways.max(1);
        if self.confirmed.len() >= needed
            && let Some((_, first)) = self.confirmed.first()
        {
            return self.agreed(first, policy);
        }
        let answered = self.confirmed.len() + self.pending + self.not_found;
        if answered < needed {
            return (
                TimingState::Unavailable,
                format!("only {answered} of the required {needed} gateways gave a usable answer"),
                None,
            );
        }
        if self.confirmed.is_empty() && self.pending == 0 {
            return (
                TimingState::NotOnChain,
                "no gateway knows this transaction: it has not been posted yet, or never was"
                    .to_owned(),
                None,
            );
        }
        (
            TimingState::Pending,
            format!(
                "{} gateway(s) report it mined and {} pending; {needed} must agree on a block",
                self.confirmed.len(),
                self.pending
            ),
            None,
        )
    }
}

/// Judge what the gateways reported about `tx_id` against `stored`, the bytes
/// the verifier holds.
///
/// A gateway that appears more than once counts once. A confirmed report
/// whose header is not a self-consistent transaction with this id is
/// discarded as unusable before anything is counted.
#[must_use]
pub fn evaluate(
    tx_id: &str,
    stored: &[u8],
    reports: &[GatewayReport],
    policy: &TimingPolicy,
) -> TimingEvidence {
    let tally = Tally::of(tx_id, reports);
    let (state, reason, bound) = tally.verdict(stored, policy);
    TimingEvidence {
        state,
        reason,
        bound,
        gateways: tally.gateways,
        policy: *policy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED: &str = include_str!("../tests/vectors/arweave_tx_v1.json");
    const MAINNET: &str = include_str!("../tests/vectors/arweave_mainnet_tx_v1.json");
    const POLICY: TimingPolicy = TimingPolicy::PROVISIONAL;
    const BLOCK_TIME: i64 = 1_791_000_000;
    const HASH_A: &str = "w3EayqSpTouZPTkTKaEC2kXQgZj5wQKxae7mbkfxUV0q8Fi8CJw-jacXB85SwoFj";
    const HASH_B: &str = "7By4OmqH2Bi57dICCDNXWCnKMgAqbb8HGo3IY3OPhjFpCglx6M3uHTLgXsKMkBvr";

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((i * 31 + 7) % 251).expect("below 251"))
            .collect()
    }

    /// A signed reference-client transaction and the bytes it commits to.
    struct Case {
        tx_id: String,
        header_json: String,
        stored: Vec<u8>,
    }

    fn case(index: usize) -> Case {
        let fixture: Value = serde_json::from_str(GENERATED).unwrap();
        let signed = &fixture["signed"][index];
        let len = usize::try_from(signed["data_len"].as_u64().unwrap()).unwrap();
        Case {
            tx_id: signed["header"]["id"].as_str().unwrap().to_owned(),
            header_json: signed["header"].to_string(),
            stored: pattern(len),
        }
    }

    #[allow(clippy::unnecessary_wraps)] // a `Fetched`, like every other reply here
    fn ok(body: impl Into<String>) -> Fetched {
        Ok(HttpReply {
            status: 200,
            body: body.into(),
        })
    }

    fn status(height: u64, hash: &str, confirmations: u64) -> TxStatus {
        TxStatus {
            block_height: height,
            block_indep_hash: hash.to_owned(),
            confirmations,
        }
    }

    fn block_json(height: u64, hash: &str, timestamp: i64, txs: &[&str]) -> String {
        json!({ "height": height, "indep_hash": hash, "timestamp": timestamp, "txs": txs })
            .to_string()
    }

    /// A gateway that places `case` in block 100 / `HASH_A` at `BLOCK_TIME`.
    fn confirming(gateway: &str, case: &Case, confirmations: u64) -> GatewayReport {
        GatewayReport::confirmed(
            gateway,
            &case.tx_id,
            status(100, HASH_A, confirmations),
            &ok(case.header_json.clone()),
            &ok(block_json(100, HASH_A, BLOCK_TIME, &[&case.tx_id])),
        )
    }

    fn report(gateway: &str, outcome: GatewayOutcome) -> GatewayReport {
        GatewayReport::new(gateway, outcome)
    }

    fn unusable(gateway: &str) -> GatewayReport {
        report(gateway, GatewayOutcome::Unusable("timed out".into()))
    }

    fn judge(case: &Case, reports: &[GatewayReport]) -> TimingEvidence {
        evaluate(&case.tx_id, &case.stored, reports, &POLICY)
    }

    #[test]
    fn agreeing_deep_gateways_evidence_the_block_time() {
        let c = case(0);
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 50),
                confirming("https://b", &c, 12),
                confirming("https://c", &c, 51),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Evidenced);
        let bound = evidence.bound().expect("evidenced carries a bound");
        assert_eq!(bound.block_time, BLOCK_TIME);
        assert_eq!(bound.block_height, 100);
        assert_eq!(bound.block_indep_hash, HASH_A);
        // The least optimistic gateway's count is the one reported.
        assert_eq!(bound.confirmations, 12);
        assert_eq!(
            bound.agreeing_gateways,
            ["https://a", "https://b", "https://c"]
        );
        assert_eq!(evidence.policy(), &POLICY);
        assert_eq!(evidence.gateways().len(), 3);
        assert!(evidence.claim().contains("no later than"));
    }

    #[test]
    fn a_quorum_survives_one_unusable_gateway() {
        let c = case(0);
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 50),
                unusable("https://b"),
                confirming("https://c", &c, 50),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Evidenced);
        assert_eq!(evidence.bound().unwrap().agreeing_gateways.len(), 2);
    }

    /// A correctly signed transaction that no gateway has ever seen — the
    /// signed-but-unpublished case — establishes no time at all, however
    /// valid its signature and however exactly it commits to the bytes.
    #[test]
    fn a_signed_but_unpublished_transaction_is_not_on_chain() {
        let c = case(0);
        let header = TxHeader::from_gateway_json(&c.header_json).unwrap();
        assert_eq!(header.verify(&c.tx_id), Ok(()));
        assert_eq!(header.commits_to(&c.stored), Ok(()));
        let evidence = judge(
            &c,
            &[
                report("https://a", GatewayOutcome::NotFound),
                report("https://b", GatewayOutcome::NotFound),
                report("https://c", GatewayOutcome::NotFound),
            ],
        );
        assert_eq!(evidence.state(), TimingState::NotOnChain);
        assert!(evidence.bound().is_none());
        assert_eq!(
            evidence.deadline_verdict(i64::MAX),
            DeadlineVerdict::Unknown
        );
        assert!(
            evidence
                .claim()
                .starts_with("No independent existence time")
        );
    }

    #[test]
    fn one_gateway_alone_is_never_enough() {
        let c = case(0);
        // One confirmation, the rest unreachable: nothing can be concluded.
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 50),
                unusable("https://b"),
                unusable("https://c"),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Unavailable);
        assert!(evidence.bound().is_none());
        // One confirmation while the others have not seen it: wait.
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 50),
                report("https://b", GatewayOutcome::NotFound),
                report("https://c", GatewayOutcome::NotFound),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Pending);
        assert!(evidence.bound().is_none());
    }

    #[test]
    fn listing_one_gateway_three_times_counts_once() {
        let c = case(0);
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 50),
                confirming("https://a", &c, 50),
                confirming("https://a", &c, 50),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Unavailable);
        assert_eq!(evidence.gateways().len(), 1);
    }

    #[test]
    fn unmined_and_shallow_transactions_are_pending() {
        let c = case(0);
        let evidence = judge(
            &c,
            &[
                report("https://a", GatewayOutcome::Pending),
                report("https://b", GatewayOutcome::Pending),
                report("https://c", GatewayOutcome::NotFound),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Pending);

        // Mined and agreed, one confirmation short at the least optimistic
        // gateway.
        let shallow = POLICY.min_confirmations - 1;
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 500),
                confirming("https://b", &c, shallow),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Pending);
        assert!(evidence.bound().is_none());
        assert_eq!(
            evidence.deadline_verdict(i64::MAX),
            DeadlineVerdict::Unknown
        );

        // Exactly the required depth is enough.
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, POLICY.min_confirmations),
                confirming("https://b", &c, POLICY.min_confirmations),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Evidenced);
    }

    #[test]
    fn too_few_answers_is_unavailable() {
        let c = case(0);
        let evidence = judge(
            &c,
            &[
                unusable("https://a"),
                unusable("https://b"),
                report("https://c", GatewayOutcome::NotFound),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Unavailable);
        assert_eq!(judge(&c, &[]).state(), TimingState::Unavailable);
    }

    #[test]
    fn gateways_that_disagree_are_a_conflict_not_a_vote() {
        let c = case(0);
        let other_block = GatewayReport::confirmed(
            "https://c",
            &c.tx_id,
            status(101, HASH_B, 50),
            &ok(c.header_json.clone()),
            &ok(block_json(101, HASH_B, BLOCK_TIME + 120, &[&c.tx_id])),
        );
        // Two agree, one names another block: still a conflict.
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 50),
                confirming("https://b", &c, 50),
                other_block,
            ],
        );
        assert_eq!(evidence.state(), TimingState::Conflict);
        assert!(evidence.bound().is_none());

        // Same block and height, different timestamp.
        let other_time = GatewayReport::confirmed(
            "https://b",
            &c.tx_id,
            status(100, HASH_A, 50),
            &ok(c.header_json.clone()),
            &ok(block_json(100, HASH_A, BLOCK_TIME - 1, &[&c.tx_id])),
        );
        let evidence = judge(&c, &[confirming("https://a", &c, 50), other_time]);
        assert_eq!(evidence.state(), TimingState::Conflict);

        // ONE differing field is enough, whichever it is. Same hash and
        // time at another height; then same height and time under another
        // hash.
        let differing = |height: u64, hash: &str| {
            GatewayReport::confirmed(
                "https://b",
                &c.tx_id,
                status(height, hash, 50),
                &ok(c.header_json.clone()),
                &ok(block_json(height, hash, BLOCK_TIME, &[&c.tx_id])),
            )
        };
        for other in [differing(101, HASH_A), differing(100, HASH_B)] {
            assert!(
                matches!(other.outcome, GatewayOutcome::Confirmed(_)),
                "the differing report must itself be usable"
            );
            let evidence = judge(&c, &[confirming("https://a", &c, 50), other]);
            assert_eq!(evidence.state(), TimingState::Conflict);
            assert!(evidence.bound().is_none());
        }
    }

    /// The transaction is on chain, deep and agreed — and stores other bytes.
    /// An altered artifact, or the wrong artifact for this id, is invalid.
    #[test]
    fn an_artifact_the_transaction_does_not_store_is_invalid() {
        let c = case(0);
        let mut altered = c.stored.clone();
        altered[10] ^= 0x01;
        let reports = [
            confirming("https://a", &c, 50),
            confirming("https://b", &c, 50),
        ];
        let evidence = evaluate(&c.tx_id, &altered, &reports, &POLICY);
        assert_eq!(evidence.state(), TimingState::Invalid);
        assert!(evidence.bound().is_none());
        assert_eq!(
            evidence.deadline_verdict(i64::MAX),
            DeadlineVerdict::Unknown
        );

        // A different length is the same verdict.
        let evidence = evaluate(&c.tx_id, &c.stored[1..], &reports, &POLICY);
        assert_eq!(evidence.state(), TimingState::Invalid);

        // The untouched bytes are fine: the plant above is what failed.
        assert_eq!(judge(&c, &reports).state(), TimingState::Evidenced);

        // One verified header is enough to know the bytes are wrong, and no
        // gateway can soften that: not by being the only one to answer, and
        // not by naming a different block so that it reads as a conflict.
        let alone = [confirming("https://a", &c, 50)];
        assert_eq!(
            evaluate(&c.tx_id, &altered, &alone, &POLICY).state(),
            TimingState::Invalid
        );
        // (With the right bytes, one gateway alone establishes nothing.)
        assert_eq!(judge(&c, &alone).state(), TimingState::Unavailable);
        let elsewhere = GatewayReport::confirmed(
            "https://c",
            &c.tx_id,
            status(101, HASH_B, 50),
            &ok(c.header_json.clone()),
            &ok(block_json(101, HASH_B, BLOCK_TIME + 120, &[&c.tx_id])),
        );
        let split = [
            confirming("https://a", &c, 50),
            confirming("https://b", &c, 50),
            elsewhere,
        ];
        assert_eq!(judge(&c, &split).state(), TimingState::Conflict);
        assert_eq!(
            evaluate(&c.tx_id, &altered, &split, &POLICY).state(),
            TimingState::Invalid
        );
    }

    /// A header for some other transaction, or one whose signature does not
    /// verify, is not this transaction however many gateways repeat it.
    #[test]
    fn headers_that_are_not_this_transaction_are_discarded() {
        let c = case(0);
        let other = case(1);
        let wrong_header = |gateway: &str| {
            GatewayReport::confirmed(
                gateway,
                &c.tx_id,
                status(100, HASH_A, 50),
                &ok(other.header_json.clone()),
                &ok(block_json(100, HASH_A, BLOCK_TIME, &[&c.tx_id])),
            )
        };
        let evidence = judge(
            &c,
            &[
                wrong_header("https://a"),
                wrong_header("https://b"),
                wrong_header("https://c"),
            ],
        );
        assert_eq!(evidence.state(), TimingState::Unavailable);
        assert!(evidence.gateways()[0].1.starts_with("unusable"));

        // A tampered signed field under the right id.
        let mut header: Value = serde_json::from_str(&c.header_json).unwrap();
        header["reward"] = Value::String("1".into());
        let forged = |gateway: &str| {
            GatewayReport::confirmed(
                gateway,
                &c.tx_id,
                status(100, HASH_A, 50),
                &ok(header.to_string()),
                &ok(block_json(100, HASH_A, BLOCK_TIME, &[&c.tx_id])),
            )
        };
        let evidence = judge(&c, &[forged("https://a"), forged("https://b")]);
        assert_eq!(evidence.state(), TimingState::Unavailable);
    }

    #[test]
    fn a_gateway_that_contradicts_itself_is_unusable() {
        let c = case(0);
        let build = |header: Fetched, block: Fetched| {
            GatewayReport::confirmed(
                "https://a",
                &c.tx_id,
                status(100, HASH_A, 50),
                &header,
                &block,
            )
            .outcome
        };
        let good_header = || ok(c.header_json.clone());
        let unusable_with = |outcome: GatewayOutcome, needle: &str| match outcome {
            GatewayOutcome::Unusable(reason) => {
                assert!(reason.contains(needle), "{reason:?} lacks {needle:?}");
            },
            other => panic!("expected unusable ({needle}), got {other:?}"),
        };
        unusable_with(
            build(
                good_header(),
                ok(block_json(100, HASH_A, BLOCK_TIME, &["some-other-tx"])),
            ),
            "does not list",
        );
        unusable_with(
            build(
                good_header(),
                ok(block_json(100, HASH_B, BLOCK_TIME, &[&c.tx_id])),
            ),
            "not the block",
        );
        unusable_with(
            build(
                good_header(),
                ok(block_json(99, HASH_A, BLOCK_TIME, &[&c.tx_id])),
            ),
            "height",
        );
        unusable_with(
            build(good_header(), ok(block_json(100, HASH_A, 0, &[&c.tx_id]))),
            "timestamp",
        );
        unusable_with(build(good_header(), ok("not json")), "not JSON");
        unusable_with(
            build(good_header(), Err("connection refused".into())),
            "connection refused",
        );
        unusable_with(
            build(
                good_header(),
                Ok(HttpReply {
                    status: 503,
                    body: String::new(),
                }),
            ),
            "HTTP 503",
        );
        unusable_with(
            build(
                ok("Pending"),
                ok(block_json(100, HASH_A, BLOCK_TIME, &[&c.tx_id])),
            ),
            "arweave tx header",
        );
        // The consistent pair is an observation.
        assert!(matches!(
            build(
                good_header(),
                ok(block_json(100, HASH_A, BLOCK_TIME, &[&c.tx_id]))
            ),
            GatewayOutcome::Confirmed(_)
        ));
    }

    fn evidenced_at(block_time: i64) -> TimingEvidence {
        let c = case(0);
        let at = |gateway: &str| {
            GatewayReport::confirmed(
                gateway,
                &c.tx_id,
                status(100, HASH_A, 50),
                &ok(c.header_json.clone()),
                &ok(block_json(100, HASH_A, block_time, &[&c.tx_id])),
            )
        };
        let evidence = judge(&c, &[at("https://a"), at("https://b")]);
        assert_eq!(evidence.state(), TimingState::Evidenced);
        evidence
    }

    /// "Before" needs the block time to clear the deadline by more than the
    /// margin; a late block is "not before"; anything in between is too close
    /// to call. Equality is never "before".
    #[test]
    fn deadline_comparison_is_strict_and_keeps_a_margin() {
        let margin = POLICY.timestamp_margin_secs;
        let evidence = evidenced_at(BLOCK_TIME);
        let verdict = |deadline: i64| evidence.deadline_verdict(deadline);
        assert_eq!(verdict(BLOCK_TIME + margin + 1), DeadlineVerdict::Before);
        assert_eq!(verdict(BLOCK_TIME + margin), DeadlineVerdict::TooClose);
        assert_eq!(verdict(BLOCK_TIME + 1), DeadlineVerdict::TooClose);
        assert_eq!(verdict(BLOCK_TIME), DeadlineVerdict::NotBefore);
        assert_eq!(verdict(BLOCK_TIME - 1), DeadlineVerdict::NotBefore);
        // A margin so large that adding it would wrap must saturate, not
        // turn "too close" into "before".
        let c = case(0);
        let wide = TimingPolicy {
            timestamp_margin_secs: i64::MAX,
            ..POLICY
        };
        let evidence = evaluate(
            &c.tx_id,
            &c.stored,
            &[
                confirming("https://a", &c, 50),
                confirming("https://b", &c, 50),
            ],
            &wide,
        );
        assert_eq!(evidence.state(), TimingState::Evidenced);
        assert_eq!(
            evidence.deadline_verdict(i64::MAX),
            DeadlineVerdict::TooClose
        );
    }

    /// A deadline must be Unix seconds. Milliseconds would put every block
    /// "before" it.
    #[test]
    fn a_deadline_that_cannot_be_seconds_is_refused() {
        assert_eq!(check_deadline(1), Ok(1));
        assert_eq!(check_deadline(1_800_000_000), Ok(1_800_000_000));
        assert_eq!(
            check_deadline(MAX_PLAUSIBLE_UNIX_SECS - 1),
            Ok(MAX_PLAUSIBLE_UNIX_SECS - 1)
        );
        for bad in [
            0,
            -1,
            i64::MIN,
            MAX_PLAUSIBLE_UNIX_SECS,
            1_800_000_000_000,
            i64::MAX,
        ] {
            assert!(check_deadline(bad).is_err(), "{bad}");
        }
        assert!(
            check_deadline(1_800_000_000_000)
                .unwrap_err()
                .contains("milliseconds")
        );
    }

    /// A gateway that reports a block time no Arweave block can have is not
    /// believed, however many agree with it.
    #[test]
    fn an_implausible_block_time_is_unusable() {
        let c = case(0);
        let at = |block_time: i64| {
            let report = |gateway: &str| {
                GatewayReport::confirmed(
                    gateway,
                    &c.tx_id,
                    status(100, HASH_A, 50),
                    &ok(c.header_json.clone()),
                    &ok(block_json(100, HASH_A, block_time, &[&c.tx_id])),
                )
            };
            judge(&c, &[report("https://a"), report("https://b")])
        };
        for implausible in [
            1,
            0,
            -5,
            MIN_PLAUSIBLE_BLOCK_TIME - 1,
            MAX_PLAUSIBLE_UNIX_SECS,
            1_791_000_000_000,
        ] {
            let evidence = at(implausible);
            assert_eq!(evidence.state(), TimingState::Unavailable, "{implausible}");
            assert!(evidence.bound().is_none());
        }
        for plausible in [MIN_PLAUSIBLE_BLOCK_TIME, MAX_PLAUSIBLE_UNIX_SECS - 1] {
            assert_eq!(at(plausible).state(), TimingState::Evidenced, "{plausible}");
        }
    }

    #[test]
    fn report_carries_a_time_only_when_evidenced() {
        let c = case(0);
        let evidence = evidenced_at(BLOCK_TIME);
        let report = evidence.to_json(&c.tx_id, Some(BLOCK_TIME + 10_000));
        assert_eq!(report["state"], "evidenced");
        assert_eq!(report["basis"], "arweave_storage_transaction");
        assert_eq!(report["block_time"], BLOCK_TIME);
        assert_eq!(report["block_height"], 100);
        assert_eq!(report["confirmations"], 50);
        assert_eq!(report["deadline"]["verdict"], "before");
        assert_eq!(report["deadline"]["deadline"], BLOCK_TIME + 10_000);
        assert_eq!(report["policy"]["status"], "provisional");
        assert_eq!(report["policy"]["min_agreeing_gateways"], 2);
        assert_eq!(report["policy"]["min_confirmations"], 10);
        assert_eq!(report["policy"]["timestamp_margin_secs"], 600);
        assert_eq!(report["gateways"].as_array().unwrap().len(), 2);
        assert!(evidence.to_json(&c.tx_id, None).get("deadline").is_none());

        let none = judge(&c, &[unusable("https://a")]);
        let report = none.to_json(&c.tx_id, Some(BLOCK_TIME));
        assert_eq!(report["state"], "unavailable");
        assert_eq!(report["deadline"]["verdict"], "unknown");
        for absent in ["block_time", "block_height", "confirmations"] {
            assert!(report.get(absent).is_none(), "{absent} must be absent");
        }
        assert_ne!(none.reason(), "");

        let direct = TimingEvidence::unavailable("not asked", POLICY);
        assert_eq!(direct.state(), TimingState::Unavailable);
        assert_eq!(direct.reason(), "not asked");
        assert_eq!(direct.gateways(), []);
    }

    #[test]
    fn a_lookup_that_was_not_made_reports_no_time() {
        let report = not_established_json(STATE_UNSUPPORTED_PRIVATE, PRIVATE_REASON, Some(5));
        assert_eq!(report["state"], "unsupported_private");
        assert_eq!(report["reason"], PRIVATE_REASON);
        assert_eq!(report["deadline"]["deadline"], 5);
        assert_eq!(report["deadline"]["verdict"], "unknown");
        assert!(report.get("block_time").is_none());
        assert!(
            report["claim"]
                .as_str()
                .unwrap()
                .starts_with("No independent existence time")
        );
        let bare = not_established_json(STATE_NOT_CHECKED, "skipped", None);
        assert_eq!(bare["state"], "not_checked");
        assert!(bare.get("deadline").is_none());
    }

    /// Each gateway's own answer is reported next to the verdict, so a
    /// reader can see which gateway said what.
    #[test]
    fn each_gateway_is_reported_with_what_it_said() {
        let c = case(0);
        let evidence = judge(
            &c,
            &[
                confirming("https://a", &c, 12),
                report("https://b", GatewayOutcome::Pending),
                report("https://c", GatewayOutcome::NotFound),
                unusable("https://d"),
            ],
        );
        let said: Vec<(&str, &str)> = evidence
            .gateways()
            .iter()
            .map(|(gateway, label)| (gateway.as_str(), label.as_str()))
            .collect();
        assert_eq!(
            said,
            [
                ("https://a", "confirmed in block 100 (12 confirmations)"),
                ("https://b", "pending"),
                ("https://c", "not found"),
                ("https://d", "unusable: timed out"),
            ]
        );
    }

    #[test]
    fn labels_are_stable() {
        let states = [
            (TimingState::Evidenced, "evidenced"),
            (TimingState::Pending, "pending"),
            (TimingState::NotOnChain, "not_on_chain"),
            (TimingState::Unavailable, "unavailable"),
            (TimingState::Conflict, "conflict"),
            (TimingState::Invalid, "invalid"),
        ];
        for (state, label) in states {
            assert_eq!(state.label(), label);
        }
        let verdicts = [
            (DeadlineVerdict::Before, "before"),
            (DeadlineVerdict::TooClose, "too_close"),
            (DeadlineVerdict::NotBefore, "not_before"),
            (DeadlineVerdict::Unknown, "unknown"),
        ];
        for (verdict, label) in verdicts {
            assert_eq!(verdict.label(), label);
        }
    }

    #[test]
    fn status_replies_are_classified() {
        let confirmed =
            json!({ "block_height": 7, "block_indep_hash": HASH_A, "number_of_confirmations": 3 });
        assert_eq!(
            read_status(&ok(confirmed.to_string())),
            StatusReply::Confirmed(status(7, HASH_A, 3))
        );
        let reply = |status: u16, body: &str| -> Fetched {
            Ok(HttpReply {
                status,
                body: body.to_owned(),
            })
        };
        assert_eq!(read_status(&reply(202, "Pending")), StatusReply::Pending);
        assert_eq!(
            read_status(&reply(404, "Not Found.")),
            StatusReply::NotFound
        );
        let unusable = |fetched: Fetched| matches!(read_status(&fetched), StatusReply::Unusable(_));
        assert!(unusable(reply(500, "")));
        assert!(unusable(reply(200, "Pending")));
        assert!(unusable(Err("timeout".into())));
        // A hash that is not a block id must never reach a URL.
        for bad in ["../../etc/passwd", "short", &format!("{HASH_A}x")] {
            let body = json!({
                "block_height": 7, "block_indep_hash": bad, "number_of_confirmations": 3
            });
            assert!(unusable(ok(body.to_string())), "{bad}");
        }
        // The right length is not enough: every character must be base64url,
        // or a gateway could steer the block request with `/`, `?`, `#`, `%`.
        for hostile in ['/', '.', '?', '#', '%', ' ', '+', '='] {
            let bad = format!("{}{hostile}", &HASH_A[..INDEP_HASH_LEN - 1]);
            assert_eq!(bad.len(), INDEP_HASH_LEN);
            let body = json!({
                "block_height": 7, "block_indep_hash": bad, "number_of_confirmations": 3
            });
            assert!(unusable(ok(body.to_string())), "{bad}");
        }
        // Both base64url punctuation characters are part of the alphabet.
        let both = format!("-_{}", &HASH_A[..INDEP_HASH_LEN - 2]);
        let body =
            json!({ "block_height": 7, "block_indep_hash": both, "number_of_confirmations": 3 });
        assert_eq!(
            read_status(&ok(body.to_string())),
            StatusReply::Confirmed(status(7, &both, 3))
        );
        let missing = json!({ "block_height": 7, "block_indep_hash": HASH_A });
        assert!(unusable(ok(missing.to_string())));
    }

    /// The recorded mainnet responses, fed through the same functions the
    /// tools use, produce an observation of the real block.
    #[test]
    fn recorded_mainnet_responses_form_an_observation() {
        let fixture: Value = serde_json::from_str(MAINNET).unwrap();
        let tx_id = fixture["header"]["id"].as_str().unwrap();
        let StatusReply::Confirmed(status) = read_status(&ok(fixture["status"].to_string())) else {
            panic!("recorded status is a confirmation");
        };
        let report = GatewayReport::confirmed(
            "https://arweave.net",
            tx_id,
            status,
            &ok(fixture["header"].to_string()),
            &ok(fixture["block"].to_string()),
        );
        let GatewayOutcome::Confirmed(observation) = &report.outcome else {
            panic!("recorded responses are consistent: {:?}", report.outcome);
        };
        assert_eq!(observation.block_height, 2_018_600);
        assert_eq!(observation.block_timestamp, 1_791_649_272);
        assert_eq!(observation.header.verify(tx_id), Ok(()));
    }

    /// However a server is spelled, it is one gateway: a quorum cannot be
    /// made by listing one origin twice.
    #[test]
    fn one_server_is_one_gateway() {
        // One spelling per origin: default ports, leading zeros and a
        // trailing dot all disappear.
        for (input, origin) in [
            ("https://Arweave.net:443", "https://arweave.net"),
            ("https://arweave.net.", "https://arweave.net"),
            ("https://arweave.net:0443", "https://arweave.net"),
            ("https://arweave.net:08443/", "https://arweave.net:8443"),
            ("http://localhost:80", "http://localhost"),
        ] {
            assert_eq!(normalise_gateway(input).unwrap(), origin, "{input}");
        }
        // So one server cannot be listed twice to make a quorum of one.
        assert_eq!(
            normalise_gateways(&[
                "https://one.example",
                "https://one.example:443",
                "https://ONE.example.",
            ])
            .unwrap(),
            ["https://one.example"]
        );
        assert_eq!(
            normalise_gateways(&[
                "http://127.0.0.1:9000",
                "http://localhost:9000",
                "http://[::1]:9000",
                "http://localhost:9001",
            ])
            .unwrap(),
            ["http://127.0.0.1:9000", "http://localhost:9001"]
        );
        // An address has one spelling. Every other way of writing 127.0.0.1
        // or ::1 is refused instead of being counted as another gateway.
        for alias in [
            "https://2130706433",
            "https://0x7f000001",
            "https://127.1",
            "https://0177.0.0.1",
            "https://127.0.0.01",
            "https://1.2.3",
            "https://localhost..",
            "https://a..b",
            "https://.a",
            "https://999.1.1.1",
        ] {
            assert!(normalise_gateway(alias).is_err(), "{alias}");
        }
        assert_eq!(
            normalise_gateway("https://[0:0:0:0:0:0:0:1]:9").unwrap(),
            "https://[::1]:9"
        );
        // All of 127.0.0.0/8 is this machine.
        assert_eq!(
            normalise_gateways(&[
                "http://127.0.0.1:9000",
                "http://127.0.0.2:9000",
                "http://[0::1]:9000",
            ])
            .unwrap(),
            ["http://127.0.0.1:9000"]
        );
        // The three loopback names are one machine with or without a port.
        assert_eq!(
            normalise_gateways(&["http://localhost", "http://[::1]", "http://127.0.0.1:80"])
                .unwrap(),
            ["http://localhost"]
        );
        // An IPv6 literal may embed an IPv4 address; nothing else gets in.
        assert_eq!(
            normalise_gateway("https://[::ffff:192.0.2.1]:8443").unwrap(),
            "https://[::ffff:192.0.2.1]:8443"
        );
        for refused in [
            "https://[a/b]",
            "https://[::zz]",
            "https://[1::2]x",
            "https://[?]",
        ] {
            assert!(normalise_gateway(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn gateway_urls_and_origins() {
        assert_eq!(
            status_url("https://arweave.net", "TX"),
            "https://arweave.net/tx/TX/status"
        );
        assert_eq!(
            header_url("https://arweave.net", "TX"),
            "https://arweave.net/tx/TX"
        );
        assert_eq!(
            block_url("https://arweave.net", "H"),
            "https://arweave.net/block/hash/H"
        );
        assert_eq!(
            normalise_gateway(" HTTPS://Arweave.NET/ ").unwrap(),
            "https://arweave.net"
        );
        assert_eq!(
            normalise_gateway("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalise_gateway("http://localhost:1").unwrap(),
            "http://localhost:1"
        );
        // IPv6 loopback, with and without a port: the brackets hold colons
        // that are not a port separator.
        assert_eq!(normalise_gateway("http://[::1]").unwrap(), "http://[::1]");
        assert_eq!(
            normalise_gateway("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        // Plain http off loopback is refused, and the refusal says what to do.
        let plain = normalise_gateway("http://arweave.net").unwrap_err();
        assert!(plain.contains("must use https"), "{plain}");
        for refused in [
            "http://arweave.net",
            "ftp://arweave.net",
            "arweave.net",
            "https://",
            "https://arweave.net/path",
            "https://user@arweave.net",
            "https://arweave.net?x=1",
            "http://127.0.0.1.evil.example",
            "https://a:b:c",
            "https://arweave.net:",
            "https://arweave.net:+443",
            "https://arweave.net:65536",
            "https://arweave.net:44x",
            "https://[::1",
            "https://[]",
            "https://.",
        ] {
            assert!(normalise_gateway(refused).is_err(), "{refused}");
        }
        assert_eq!(
            normalise_gateways(&[
                "https://a.example",
                "https://A.example/",
                "https://b.example"
            ])
            .unwrap(),
            ["https://a.example", "https://b.example"]
        );
        assert!(normalise_gateways::<&str>(&[]).is_err());
        assert!(normalise_gateways(&["https://a.example", "nope"]).is_err());
        let many: Vec<String> = (0..=MAX_GATEWAYS)
            .map(|i| format!("https://g{i}.example"))
            .collect();
        assert!(normalise_gateways(&many).is_err());
        // The limit itself is allowed.
        assert_eq!(
            normalise_gateways(&many[..MAX_GATEWAYS]).unwrap().len(),
            MAX_GATEWAYS
        );
        assert_eq!(normalise_gateways(&DEFAULT_GATEWAYS).unwrap().len(), 3);
    }
}
