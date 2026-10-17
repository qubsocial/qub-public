//! `qub-forecast-series` — the runnable forecast-series recipe.
//!
//! Drives the real `qub-mcp` server over stdio, exactly as an agent would, to
//! publish and check one declared forecast series: a manifest qub and one
//! forecast qub per slot (four qubs for the three-slot example). Everything is
//! published **public** — time-locked, not link-gated — because that is the
//! only kind for which a recipient can check, without trusting the author or
//! qub, that the sealed bytes existed before a deadline.
//!
//! ```text
//! qub-forecast-series example --plan plan.json [--first-deadline-in <secs>]
//!                             [--spacing <secs>] [--reveal-after <secs>]
//! qub-forecast-series check   --plan plan.json
//! qub-forecast-series submit  --plan plan.json
//! qub-forecast-series status  --plan plan.json
//! qub-forecast-series report  --plan plan.json [--outcomes outcomes.json]
//! ```
//!
//! - `example` writes a ready-to-run three-slot plan whose outcomes are
//!   public, unpredictable and checkable by anyone: the parity of future
//!   drand beacons. It never overwrites a file and publishes nothing.
//! - `check` validates the plan offline. Nothing is sealed or sent.
//! - `submit` publishes the manifest, then each forecast. It is resumable:
//!   progress is written to the state file after every step, each qub has a
//!   fixed `operation_id`, and `qub-mcp` journals every create — so running it
//!   again after a crash, a timeout or a rate limit continues where it stopped
//!   and never publishes a qub twice.
//! - `status` asks `check_status` about every published qub: lock state, and
//!   the timing evidence compared with that qub's deadline.
//! - `report` asks `verify_forecast_series` for the series report. Missed,
//!   late and unverifiable forecasts are part of it.
//!
//! Publishing needs `QUB_API_KEY` and `QUB_MCP_ALLOW_CREATE=true` in the
//! environment, as `create_qub` always does; `status` and `report` work
//! without a key (anonymous reads). The plan file holds the forecasts'
//! answers in plain text on this machine — it is the author's own copy.
//!
//! Exit codes: `0` done · `1` the step could not finish (the message says
//! why; `submit` can be run again) · `2` usage or plan error.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use qub_verify::series::{Forecast, Manifest, Slot};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};

/// Longest single wait the runner will sit out for a rate limit, in seconds.
const MAX_WAIT_SECS: u64 = 120;
/// Longest the runner will wait for a previous process to release one
/// operation after that process is interrupted.
const MAX_OPERATION_WAIT_SECS: u64 = 120;
/// Longest the runner will wait for the service to finish one accepted or
/// in-flight upload, in seconds.
const MAX_PENDING_WAIT_SECS: u64 = 120;
/// Delay between service-side operation-status polls, in seconds.
const PENDING_POLL_SECS: u64 = 5;
/// Attempts per qub before `submit` gives up and leaves the rest to a rerun.
const MAX_ATTEMPTS: u32 = 6;
/// Lead time, in seconds, below which `check` warns that a deadline leaves
/// little room for the storage transaction to be mined and confirmed.
const TIGHT_LEAD_SECS: i64 = 3600;

/// A usage or plan error (exit 2) or a step that could not finish (exit 1).
enum Failure {
    Usage(String),
    Step(String),
}

fn usage(message: impl Into<String>) -> Failure {
    Failure::Usage(message.into())
}

fn step(message: impl Into<String>) -> Failure {
    Failure::Step(message.into())
}

const USAGE: &str = "usage: qub-forecast-series <example|check|submit|status|report> \
     --plan <plan.json> [--state <state.json>] [--mcp <path-to-qub-mcp>] \
     [--outcomes <outcomes.json>] [--first-deadline-in <seconds>] [--spacing <seconds>] \
     [--reveal-after <seconds>]";

/// drand quicknet parameters, for the example plan's outcome rounds.
const QUICKNET_GENESIS: i64 = 1_692_803_367;
const QUICKNET_PERIOD: i64 = 3;
const QUICKNET_CHAIN: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
/// Default lead, in seconds, from now to the example's first deadline.
const EXAMPLE_FIRST_DEADLINE_IN: i64 = 2 * 3600;
/// Default seconds between the example's deadlines.
const EXAMPLE_SPACING: i64 = 3600;
/// Default seconds from each of the example's deadlines to its reveal.
const EXAMPLE_REVEAL_AFTER: i64 = 1800;

/// Parsed command line.
struct Args {
    command: String,
    plan: PathBuf,
    state: PathBuf,
    mcp: Option<PathBuf>,
    outcomes: Option<PathBuf>,
    /// `example` only: seconds from now to the first deadline.
    first_deadline_in: i64,
    /// `example` only: seconds between deadlines.
    spacing: i64,
    /// `example` only: seconds from each deadline to its reveal.
    reveal_after: i64,
}

fn parse_args(mut raw: impl Iterator<Item = String>) -> Result<Args, Failure> {
    let command = raw.next().ok_or_else(|| usage(USAGE))?;
    if !matches!(
        command.as_str(),
        "example" | "check" | "submit" | "status" | "report"
    ) {
        return Err(usage(format!("unknown command {command:?}\n{USAGE}")));
    }
    let mut plan = None;
    let mut state = None;
    let mut mcp = None;
    let mut outcomes = None;
    let mut first_deadline_in = EXAMPLE_FIRST_DEADLINE_IN;
    let mut spacing = EXAMPLE_SPACING;
    let mut reveal_after = EXAMPLE_REVEAL_AFTER;
    while let Some(flag) = raw.next() {
        let seconds = match flag.as_str() {
            "--first-deadline-in" => Some(&mut first_deadline_in),
            "--spacing" => Some(&mut spacing),
            "--reveal-after" => Some(&mut reveal_after),
            _ => None,
        };
        if let Some(seconds) = seconds {
            *seconds = raw
                .next()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| usage(format!("{flag} needs a positive number of seconds")))?;
            continue;
        }
        let slot = match flag.as_str() {
            "--plan" => &mut plan,
            "--state" => &mut state,
            "--mcp" => &mut mcp,
            "--outcomes" => &mut outcomes,
            other => return Err(usage(format!("unknown option {other:?}\n{USAGE}"))),
        };
        let value = raw
            .next()
            .ok_or_else(|| usage(format!("{flag} needs a value\n{USAGE}")))?;
        *slot = Some(PathBuf::from(value));
    }
    let plan = plan.ok_or_else(|| usage(format!("--plan is required\n{USAGE}")))?;
    // Default state file: beside the plan, `<plan stem>.state.json`.
    let state = state.unwrap_or_else(|| plan.with_extension("state.json"));
    Ok(Args {
        command,
        plan,
        state,
        mcp,
        outcomes,
        first_deadline_in,
        spacing,
        reveal_after,
    })
}

/// One slot of the plan: the declared slot plus the author's forecast.
struct PlannedSlot {
    slot: Slot,
    answer: String,
    probability_pct: Option<u8>,
}

/// A validated plan.
struct Plan {
    manifest: Manifest,
    manifest_reveal_at: i64,
    slots: Vec<PlannedSlot>,
}

fn read_json(path: &Path, what: &str) -> Result<Value, Failure> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| usage(format!("cannot read {what} {}: {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| usage(format!("{what} {} is not valid JSON: {e}", path.display())))
}

/// Load and validate a plan. The manifest is validated by building its body
/// and parsing it back through the same rules a verifier applies, so a plan
/// that passes here cannot produce a manifest a report would reject.
fn load_plan(path: &Path) -> Result<Plan, Failure> {
    let value = read_json(path, "plan")?;
    let text = |object: &Value, name: &str| -> Result<String, Failure> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| usage(format!("plan: `{name}` is missing or not a string")))
    };
    let time = |object: &Value, name: &str| -> Result<i64, Failure> {
        object
            .get(name)
            .and_then(Value::as_i64)
            .ok_or_else(|| usage(format!("plan: `{name}` is missing or not an integer")))
    };
    let raw_slots = value
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(|| usage("plan: `slots` is missing or not an array"))?;
    let mut slots = Vec::with_capacity(raw_slots.len());
    for raw in raw_slots {
        let probability_pct = match raw.get("probability_pct") {
            None | Some(Value::Null) => None,
            Some(pct) => Some(
                pct.as_u64()
                    .and_then(|pct| u8::try_from(pct).ok())
                    .ok_or_else(|| usage("plan: `probability_pct` must be an integer 0-100"))?,
            ),
        };
        slots.push(PlannedSlot {
            slot: Slot {
                slot: text(raw, "slot")?,
                question: text(raw, "question")?,
                outcome_source: text(raw, "outcome_source")?,
                deadline: time(raw, "deadline")?,
                reveal_at: time(raw, "reveal_at")?,
            },
            answer: text(raw, "answer")?,
            probability_pct,
        });
    }
    let manifest = Manifest {
        series_id: text(&value, "series_id")?,
        title: text(&value, "title")?,
        scoring: text(&value, "scoring")?,
        slots: slots.iter().map(|planned| planned.slot.clone()).collect(),
    };
    let manifest = Manifest::parse(&manifest.to_body()).map_err(|e| usage(format!("plan: {e}")))?;
    let manifest_reveal_at = time(&value, "manifest_reveal_at")?;
    qub_verify::timing::check_deadline(manifest_reveal_at)
        .map_err(|e| usage(format!("plan: `manifest_reveal_at`: {e}")))?;
    if manifest_reveal_at >= manifest.first_deadline() {
        return Err(usage(
            "plan: `manifest_reveal_at` must be before the first deadline, so the declared \
             slots are readable before any forecast is due",
        ));
    }
    let plan = Plan {
        manifest,
        manifest_reveal_at,
        slots,
    };
    // Every forecast body must also pass the verifier's rules. The manifest
    // id is not known yet; a well-formed placeholder stands in for it.
    for planned in &plan.slots {
        Forecast::parse(&plan.forecast(planned, &"A".repeat(43)).to_body())
            .map_err(|e| usage(format!("plan: slot `{}`: {e}", planned.slot.slot)))?;
    }
    Ok(plan)
}

impl Plan {
    fn forecast(&self, planned: &PlannedSlot, manifest_tx_id: &str) -> Forecast {
        Forecast {
            series_id: self.manifest.series_id.clone(),
            manifest_tx_id: manifest_tx_id.to_owned(),
            slot: planned.slot.slot.clone(),
            question: planned.slot.question.clone(),
            outcome_source: planned.slot.outcome_source.clone(),
            answer: planned.answer.clone(),
            probability_pct: planned.probability_pct,
        }
    }

    /// A digest of everything this plan would publish: the manifest, when it
    /// reveals, and each forecast.
    ///
    /// The state file is bound to it. Once anything is published, the terms
    /// are on permanent storage; a plan edited afterwards describes a
    /// different series, and checking the old publications against its
    /// deadlines would answer a question nobody published.
    fn digest(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(b"qub-forecast-series/plan/v1\0");
        hasher.update(self.manifest.to_body().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.manifest_reveal_at.to_be_bytes());
        for planned in &self.slots {
            hasher.update(b"\0");
            // The manifest id is not part of the plan; a fixed placeholder
            // stands in for it.
            hasher.update(self.forecast(planned, &"A".repeat(43)).to_body().as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// A stable `operation_id` for one qub of this series. Fixed per series
    /// and role, so a rerun resumes the journaled operation.
    fn operation_id(&self, role: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(b"qub-forecast-series/operation/v1\0");
        hasher.update(self.manifest.series_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(role.as_bytes());
        format!("fs-{}", &hex::encode(hasher.finalize())[..40])
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn out(line: &str) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.write_all(b"\n");
}

/// The state file: what has been published so far.
#[derive(Default)]
struct State {
    manifest: Option<Published>,
    forecasts: BTreeMap<String, Published>,
}

/// One published qub.
#[derive(Clone)]
struct Published {
    operation_id: String,
    tx_id: String,
    delivery_url: String,
}

impl Published {
    fn to_json(&self) -> Value {
        json!({
            "operation_id": self.operation_id,
            "tx_id": self.tx_id,
            "delivery_url": self.delivery_url,
        })
    }

    fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            operation_id: value.get("operation_id")?.as_str()?.to_owned(),
            tx_id: value.get("tx_id")?.as_str()?.to_owned(),
            delivery_url: value.get("delivery_url")?.as_str()?.to_owned(),
        })
    }
}

impl State {
    /// Load the state file. Absent means nothing is published yet; a file
    /// for another series, or one that cannot be read, is refused rather
    /// than overwritten.
    fn load(path: &Path, plan: &Plan) -> Result<Self, Failure> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let value = read_json(path, "state file")?;
        if value.get("series_id").and_then(Value::as_str) != Some(plan.manifest.series_id.as_str())
        {
            return Err(usage(format!(
                "state file {} belongs to another series; pass --state for this plan",
                path.display()
            )));
        }
        // The file records the plan it was started with. A plan that has
        // changed since — a deadline moved, an answer edited — is not the
        // one whose qubs were published.
        if value.get("plan_digest").and_then(Value::as_str) != Some(plan.digest().as_str()) {
            return Err(usage(format!(
                "the plan has changed since this series was started (state file {}). What was \
                 published carries the earlier terms and cannot be changed. Restore the plan \
                 as it was, or start a new series with a new `series_id`",
                path.display()
            )));
        }
        let malformed = || usage(format!("state file {} is malformed", path.display()));
        let manifest = match value.get("manifest") {
            None | Some(Value::Null) => None,
            Some(entry) => Some(Published::from_json(entry).ok_or_else(malformed)?),
        };
        let mut forecasts = BTreeMap::new();
        if let Some(entries) = value.get("forecasts").and_then(Value::as_object) {
            for (slot, entry) in entries {
                forecasts.insert(
                    slot.clone(),
                    Published::from_json(entry).ok_or_else(malformed)?,
                );
            }
        }
        Ok(Self {
            manifest,
            forecasts,
        })
    }

    /// Write the state file atomically (temporary file, then rename).
    fn save(&self, path: &Path, plan: &Plan) -> Result<(), Failure> {
        let value = json!({
            "series_id": plan.manifest.series_id,
            "plan_digest": plan.digest(),
            "manifest": self.manifest.as_ref().map(Published::to_json),
            "forecasts": self
                .forecasts
                .iter()
                .map(|(slot, published)| (slot.clone(), published.to_json()))
                .collect::<serde_json::Map<String, Value>>(),
        });
        let text = serde_json::to_string_pretty(&value)
            .map_err(|e| step(format!("cannot encode state: {e}")))?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, format!("{text}\n"))
            .and_then(|()| std::fs::rename(&temporary, path))
            .map_err(|e| step(format!("cannot write state file {}: {e}", path.display())))
    }
}

/// A running `qub-mcp` server spoken to over stdio.
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

/// What a tool call returned.
struct ToolReply {
    is_error: bool,
    /// The JSON payload when the tool's text is (or ends in) a JSON object.
    payload: Option<Value>,
    /// The raw text, for messages.
    text: String,
}

impl Mcp {
    /// Find and start `qub-mcp`: `--mcp`, else `QUB_MCP_BIN`, else the binary
    /// beside this one, else `qub-mcp` on `PATH`. Its environment is this
    /// process's: the operator's `QUB_*` settings apply unchanged.
    fn start(explicit: Option<&Path>) -> Result<Self, Failure> {
        let beside = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("qub-mcp")))
            .filter(|candidate| candidate.exists());
        let program = explicit
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("QUB_MCP_BIN").map(PathBuf::from))
            .or(beside)
            .unwrap_or_else(|| PathBuf::from("qub-mcp"));
        let mut child = Command::new(&program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| step(format!("cannot start {}: {e}", program.display())))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(step("qub-mcp started without stdio pipes"));
        };
        let mut mcp = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        };
        mcp.request(
            "initialize",
            &json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "qub-forecast-series", "version": env!("CARGO_PKG_VERSION") },
            }),
        )?;
        Ok(mcp)
    }

    /// Send one JSON-RPC request and return its `result`.
    fn request(&mut self, method: &str, params: &Value) -> Result<Value, Failure> {
        let id = self.next_id;
        self.next_id += 1;
        let frame = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.stdin
            .write_all(format!("{frame}\n").as_bytes())
            .and_then(|()| self.stdin.flush())
            .map_err(|e| step(format!("cannot write to qub-mcp: {e}")))?;
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .map_err(|e| step(format!("cannot read from qub-mcp: {e}")))?;
        if read == 0 {
            return Err(step("qub-mcp exited before answering"));
        }
        let response: Value = serde_json::from_str(&line)
            .map_err(|e| step(format!("qub-mcp answered with invalid JSON: {e}")))?;
        if response.get("id") != Some(&json!(id)) {
            return Err(step("qub-mcp answered a different request"));
        }
        if let Some(error) = response.get("error") {
            return Err(step(format!("qub-mcp protocol error: {error}")));
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Call one tool.
    fn call(&mut self, tool: &str, arguments: &Value) -> Result<ToolReply, Failure> {
        let result = self.request(
            "tools/call",
            &json!({ "name": tool, "arguments": arguments }),
        )?;
        let text = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // Read tools prefix their JSON with a one-line untrusted-content note.
        let payload = text
            .find('{')
            .and_then(|start| serde_json::from_str::<Value>(&text[start..]).ok());
        Ok(ToolReply {
            is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
            payload,
            text,
        })
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Publish one qub, sitting out rate limits and in-flight uploads. Returns
/// what was published, or the failure that stopped it (the operation stays
/// journaled in `qub-mcp`, so a rerun resumes it).
fn publish(
    mcp: &mut Mcp,
    label: &str,
    body: &str,
    unlock_at: i64,
    intent: &str,
    operation_id: &str,
) -> Result<Published, Failure> {
    let arguments = json!({
        "body": body,
        "unlock_at": unlock_at,
        "visibility": "public",
        "intent": intent,
        "operation_id": operation_id,
    });
    let mut attempt = 1;
    let mut operation_waited = 0;
    let mut pending_waited = 0;
    while attempt <= MAX_ATTEMPTS {
        let reply = mcp.call("create_qub", &arguments)?;
        let field = |name: &str| {
            reply
                .payload
                .as_ref()
                .and_then(|payload| payload.get(name))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let wait = if reply.is_error {
            // A killed recipe runner can leave its qub-mcp child finishing
            // this operation. That process still owns the journal lock, so
            // wait for it instead of turning a safe transient into a failed
            // series. This wait does not consume a publication attempt.
            if field("code") == "operation_in_progress" {
                if operation_waited == MAX_OPERATION_WAIT_SECS {
                    return Err(step(format!(
                        "{label}: create_qub is still owned by another process after waiting \
                         {MAX_OPERATION_WAIT_SECS}s. Nothing is lost: run `submit` again to resume \
                         this operation."
                    )));
                }
                operation_waited += 1;
                out(&format!(
                    "{label}: operation still in progress; waiting 1s before resuming"
                ));
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            // Only a refusal the server says to wait out is retried here.
            let retryable = field("code") == "upload_rejected" && field("status") == 429;
            if !retryable {
                return Err(step(format!("{label}: create_qub failed: {}", reply.text)));
            }
            field("retry_after_secs").as_u64().unwrap_or(30)
        } else if let (Some(tx_id), Some(delivery_url)) =
            (field("tx_id").as_str(), field("delivery_url").as_str())
        {
            if field("visibility") != "public" {
                return Err(step(format!(
                    "{label}: qub-mcp did not publish this qub as public; stopping"
                )));
            }
            return Ok(Published {
                operation_id: operation_id.to_owned(),
                tx_id: tx_id.to_owned(),
                delivery_url: delivery_url.to_owned(),
            });
        } else if matches!(
            field("state").as_str(),
            Some("pending" | "accepted_unconfirmed")
        ) {
            // The service has this operation already. Polling its durable
            // status is not another publication attempt, so a slow Worker
            // operation must not consume the retry budget used by 429s.
            if pending_waited == MAX_PENDING_WAIT_SECS {
                return Err(step(format!(
                    "{label}: the service is still processing this operation after waiting \
                     {MAX_PENDING_WAIT_SECS}s. Nothing is lost: run `submit` again to resume \
                     this operation."
                )));
            }
            let wait = PENDING_POLL_SECS.min(MAX_PENDING_WAIT_SECS - pending_waited);
            pending_waited += wait;
            out(&format!(
                "{label}: service operation still pending; waiting {wait}s before resuming"
            ));
            std::thread::sleep(Duration::from_secs(wait));
            continue;
        } else {
            // An older or unexpected non-error reply without a result gets
            // the bounded ordinary retry treatment.
            5
        };
        if attempt == MAX_ATTEMPTS {
            break;
        }
        let wait = wait.clamp(1, MAX_WAIT_SECS);
        out(&format!(
            "{label}: not finished yet (attempt {attempt}); waiting {wait}s before resuming"
        ));
        std::thread::sleep(Duration::from_secs(wait));
        attempt += 1;
    }
    Err(step(format!(
        "{label}: still not published after {MAX_ATTEMPTS} attempts. Nothing is lost: run \
         `submit` again to resume this operation."
    )))
}

/// The quicknet round whose beacon is published at `time`.
const fn quicknet_round_at(time: i64) -> i64 {
    (time - QUICKNET_GENESIS) / QUICKNET_PERIOD + 1
}

/// Write the example plan: three forecasts of the parity of future drand
/// beacons. The outcome of each is the last hex digit of one quicknet
/// round's `randomness` — published by drand at the slot's reveal time, not
/// knowable before it, and checkable by anyone afterwards.
fn run_example(args: &Args) -> Result<(), Failure> {
    if args.plan.exists() {
        return Err(usage(format!(
            "{} already exists; choose another --plan path",
            args.plan.display()
        )));
    }
    let start = now();
    let slots: Vec<Value> = ["one", "two", "three"]
        .iter()
        .zip(0_i64..)
        .map(|(slot, index)| {
            let deadline = start + args.first_deadline_in + index * args.spacing;
            let reveal_at = deadline + args.reveal_after;
            let round = quicknet_round_at(reveal_at);
            json!({
                "slot": slot,
                "question": format!(
                    "Is the last hex digit of the randomness of drand quicknet round {round} \
                     even or odd?"
                ),
                "outcome_source": format!("https://api.drand.sh/{QUICKNET_CHAIN}/public/{round}"),
                "deadline": deadline,
                "reveal_at": reveal_at,
                "answer": "even",
                "probability_pct": 50,
            })
        })
        .collect();
    let plan = json!({
        "series_id": format!("drand-parity-{start}"),
        "title": "Three forecasts of drand beacon parity",
        "scoring": "exact_match: `even` or `odd`, for the last hex digit of the `randomness` \
                    value the outcome source returns.",
        "manifest_reveal_at": start + 300,
        "slots": slots,
    });
    let text = serde_json::to_string_pretty(&plan)
        .map_err(|e| step(format!("cannot encode the example plan: {e}")))?;
    std::fs::write(&args.plan, format!("{text}\n"))
        .map_err(|e| step(format!("cannot write {}: {e}", args.plan.display())))?;
    out(&format!(
        "wrote {}: 3 slots, first deadline in {}s. Edit the answers, then run `check`.",
        args.plan.display(),
        args.first_deadline_in
    ));
    Ok(())
}

fn run_check(plan: &Plan) {
    let now = now();
    out(&format!(
        "plan ok: series `{}`, {} slot(s), {} qub(s) to publish",
        plan.manifest.series_id,
        plan.slots.len(),
        plan.slots.len() + 1
    ));
    for planned in &plan.slots {
        let lead = planned.slot.deadline - now;
        if lead <= 0 {
            out(&format!(
                "warning: slot `{}` deadline has already passed; a forecast published now \
                 will be reported late",
                planned.slot.slot
            ));
        } else if lead < TIGHT_LEAD_SECS {
            out(&format!(
                "warning: slot `{}` deadline is {lead}s away. Timing evidence needs the storage \
                 transaction mined and several blocks deep, plus a margin, before the deadline; \
                 no latency for that has been measured. Leave generous room.",
                planned.slot.slot
            ));
        }
    }
}

fn run_submit(plan: &Plan, args: &Args) -> Result<(), Failure> {
    let mut state = State::load(&args.state, plan)?;
    // Bind the state file to this plan BEFORE anything is published, so a
    // run that dies after its first upload is already tied to these terms.
    state.save(&args.state, plan)?;
    let mut mcp = Mcp::start(args.mcp.as_deref())?;

    let manifest = if let Some(published) = &state.manifest {
        out(&format!(
            "manifest: already published as {}",
            published.tx_id
        ));
        published.clone()
    } else {
        let published = publish(
            &mut mcp,
            "manifest",
            &plan.manifest.to_body(),
            plan.manifest_reveal_at,
            "announcement",
            &plan.operation_id("manifest"),
        )?;
        state.manifest = Some(published.clone());
        state.save(&args.state, plan)?;
        out(&format!("manifest: published as {}", published.tx_id));
        published
    };

    for planned in &plan.slots {
        let slot = &planned.slot.slot;
        if let Some(published) = state.forecasts.get(slot) {
            out(&format!(
                "slot `{slot}`: already published as {}",
                published.tx_id
            ));
            continue;
        }
        let published = publish(
            &mut mcp,
            &format!("slot `{slot}`"),
            &plan.forecast(planned, &manifest.tx_id).to_body(),
            planned.slot.reveal_at,
            "prediction",
            &plan.operation_id(&format!("slot/{slot}")),
        )?;
        out(&format!("slot `{slot}`: published as {}", published.tx_id));
        state.forecasts.insert(slot.clone(), published);
        state.save(&args.state, plan)?;
    }
    out(&format!(
        "submitted: {} qub(s) published. Accepted is not yet evidenced: run `status` until each \
         shows timing `evidenced` before its deadline.",
        plan.slots.len() + 1
    ));
    Ok(())
}

/// The published manifest, or the instruction to publish first.
fn published_manifest(state: &State) -> Result<&Published, Failure> {
    state
        .manifest
        .as_ref()
        .ok_or_else(|| step("nothing is published yet: run `submit` first"))
}

fn run_status(plan: &Plan, args: &Args) -> Result<(), Failure> {
    let state = State::load(&args.state, plan)?;
    let manifest = published_manifest(&state)?;
    let mut mcp = Mcp::start(args.mcp.as_deref())?;
    let mut rows = vec![(
        "manifest".to_owned(),
        manifest,
        plan.manifest.first_deadline(),
    )];
    for planned in &plan.slots {
        if let Some(published) = state.forecasts.get(&planned.slot.slot) {
            rows.push((
                format!("slot `{}`", planned.slot.slot),
                published,
                planned.slot.deadline,
            ));
        } else {
            out(&format!("slot `{}`: not published", planned.slot.slot));
        }
    }
    let mut report = Vec::new();
    for (label, published, deadline) in rows {
        let reply = mcp.call(
            "check_status",
            &json!({ "tx_id": published.tx_id, "deadline": deadline }),
        )?;
        let Some(payload) = reply.payload.filter(|_| !reply.is_error) else {
            out(&format!("{label}: check_status failed: {}", reply.text));
            continue;
        };
        let timing = &payload["timing"];
        out(&format!(
            "{label}: {} · timing {} · before deadline: {}{}",
            payload["status"].as_str().unwrap_or("?"),
            timing["state"].as_str().unwrap_or("?"),
            timing["deadline"]["verdict"].as_str().unwrap_or("?"),
            timing["block_time"]
                .as_i64()
                .map_or_else(String::new, |time| format!(" · block time {time}")),
        ));
        report.push(json!({ "label": label, "tx_id": published.tx_id, "result": payload }));
    }
    out(&serde_json::to_string_pretty(&json!({ "status": report })).unwrap_or_default());
    Ok(())
}

fn run_report(plan: &Plan, args: &Args) -> Result<(), Failure> {
    let state = State::load(&args.state, plan)?;
    let manifest = published_manifest(&state)?;
    let outcomes = match &args.outcomes {
        Some(path) => read_json(path, "outcomes")?,
        None => json!({}),
    };
    if !outcomes.is_object() {
        return Err(usage(
            "outcomes must be a JSON object of slot id to outcome",
        ));
    }
    let forecasts: Vec<&str> = state
        .forecasts
        .values()
        .map(|published| published.tx_id.as_str())
        .collect();
    let mut mcp = Mcp::start(args.mcp.as_deref())?;
    let reply = mcp.call(
        "verify_forecast_series",
        &json!({ "manifest": manifest.tx_id, "forecasts": forecasts, "outcomes": outcomes }),
    )?;
    let Some(report) = reply.payload.filter(|_| !reply.is_error) else {
        return Err(step(format!(
            "verify_forecast_series failed: {}",
            reply.text
        )));
    };
    out(&format!(
        "series `{}`: complete = {} · manifest {}",
        plan.manifest.series_id, report["complete"], report["manifest"]["state"]
    ));
    for slot in report["slots"].as_array().into_iter().flatten() {
        out(&format!(
            "slot `{}`: {}{}",
            slot["slot"].as_str().unwrap_or("?"),
            slot["status"].as_str().unwrap_or("?"),
            slot["outcome"]["result"]
                .as_str()
                .map_or_else(String::new, |result| format!(" · outcome {result}")),
        ));
    }
    out(&serde_json::to_string_pretty(&report).unwrap_or_default());
    Ok(())
}

fn run() -> Result<(), Failure> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.command == "example" {
        return run_example(&args);
    }
    let plan = load_plan(&args.plan)?;
    match args.command.as_str() {
        "check" => {
            run_check(&plan);
            Ok(())
        },
        "submit" => {
            run_check(&plan);
            run_submit(&plan, &args)
        },
        "status" => run_status(&plan, &args),
        _ => run_report(&plan, &args),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("qub-forecast-series: {message}");
            ExitCode::from(2)
        },
        Err(Failure::Step(message)) => {
            eprintln!("qub-forecast-series: {message}");
            ExitCode::from(1)
        },
    }
}
