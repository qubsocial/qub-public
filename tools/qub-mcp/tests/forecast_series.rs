// allow-test-network: loopback mocks only (see tests/support/mod.rs)
//! The declared forecast series, end to end, against the real binaries.
//!
//! Two halves, for the reason given in `public_mode.rs`: nothing offline can
//! take one artifact from locked to revealed.
//!
//! - **Publishing and recovery** runs the recipe runner (`qub-forecast-series`)
//!   driving the real `qub-mcp`: the four-qub series inside a ten-qub trial,
//!   resumed across a rate limit, a lost acknowledgement and a restart, with
//!   exactly four publications at the end.
//! - **The report** runs `verify_forecast_series` on series whose qubs were
//!   sealed by `qub_core::seal` to a real elapsed drand round, so the binary
//!   fetches, verifies, decrypts and judges real artifacts. The series here
//!   are deliberately imperfect: a missed slot, a late entry, a revision, a
//!   wrong outcome source, an entry never posted to the chain.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use qub_verify::series::{Forecast, Manifest, Slot};
use serde_json::{Value, json};
use support::{
    Agent, MARGIN, RUNNER_BIN, TempDir, UploadFault, View, World, elapsed_round, now,
    seal_revealed_private, seal_revealed_public, seal_revealed_public_with_a_failing_signature,
};

const KEY: &str = "qub_sk_trial_series";

// ---------------------------------------------------------------------------
// The report, on revealed series
// ---------------------------------------------------------------------------

/// A three-slot series whose every qub unlocked at the elapsed fixture round.
/// Deadlines sit well before that round so the margins have room.
struct Series {
    world: World,
    agent: Agent,
    manifest: Manifest,
    manifest_tx: String,
}

fn declared() -> Manifest {
    let reveal_at = elapsed_round().unlock_at;
    let slot = |id: &str, deadline: i64| Slot {
        slot: id.to_owned(),
        question: format!("Will event {id} happen?"),
        outcome_source: format!("https://outcomes.example/{id}"),
        deadline,
        reveal_at,
    };
    Manifest {
        series_id: "fixture-series".to_owned(),
        title: "Three declared forecasts".to_owned(),
        scoring: "exact_match: the answer equals the outcome source's value.".to_owned(),
        slots: vec![
            slot("one", reveal_at - 30_000),
            slot("two", reveal_at - 20_000),
            slot("three", reveal_at - 10_000),
        ],
    }
}

impl Series {
    /// Publish the manifest and report it mined at `manifest_block_time`.
    fn new(manifest_block_time: Option<i64>) -> Self {
        let world = World::start(KEY);
        let agent = Agent::new(&world, Some(KEY));
        let manifest = declared();
        let manifest_tx = world.store(seal_revealed_public(&manifest.to_body()), true);
        if let Some(block_time) = manifest_block_time {
            world.mine(&manifest_tx, block_time);
        }
        Self {
            world,
            agent,
            manifest,
            manifest_tx,
        }
    }

    /// A series whose manifest is evidenced long before the first deadline.
    fn well_declared() -> Self {
        Self::new(Some(declared().first_deadline() - 50_000))
    }

    fn forecast(&self, slot: usize, answer: &str) -> Forecast {
        let declared = &self.manifest.slots[slot];
        Forecast {
            series_id: self.manifest.series_id.clone(),
            manifest_tx_id: self.manifest_tx.clone(),
            slot: declared.slot.clone(),
            question: declared.question.clone(),
            outcome_source: declared.outcome_source.clone(),
            answer: answer.to_owned(),
            probability_pct: Some(65),
        }
    }

    /// Store a forecast as a public qub; `block_time` mines it.
    fn publish(&self, forecast: &Forecast, block_time: Option<i64>) -> String {
        let tx_id = self
            .world
            .store(seal_revealed_public(&forecast.to_body()), true);
        if let Some(block_time) = block_time {
            self.world.mine(&tx_id, block_time);
        }
        tx_id
    }

    /// A forecast for `slot` mined `lead` seconds before its deadline.
    fn on_time(&self, slot: usize, answer: &str, lead: i64) -> String {
        let deadline = self.manifest.slots[slot].deadline;
        self.publish(&self.forecast(slot, answer), Some(deadline - lead))
    }

    fn report(&self, forecasts: &[&str], outcomes: Option<Value>) -> Value {
        let mut arguments = json!({ "manifest": self.manifest_tx, "forecasts": forecasts });
        if let Some(outcomes) = outcomes {
            arguments["outcomes"] = outcomes;
        }
        self.agent.call("verify_forecast_series", &arguments).ok()
    }
}

fn status(report: &Value, slot: usize) -> &str {
    report["slots"][slot]["status"].as_str().unwrap()
}

/// The happy path: a manifest evidenced before the first deadline and one
/// on-time forecast per slot is complete, and each qub cost one read.
#[test]
fn a_complete_series_is_reported_complete() {
    let series = Series::well_declared();
    let one = series.on_time(0, "yes", 5000);
    let two = series.on_time(1, "no", 5000);
    let three = series.on_time(2, "yes", 5000);

    let report = series.report(
        &[&one, &two, &three],
        Some(json!({ "one": "yes", "two": "yes" })),
    );
    assert_eq!(report["schema"], "qub.forecast-series-report/v1");
    assert_eq!(report["series_id"], "fixture-series");
    assert_eq!(report["manifest"]["state"], "valid");
    assert_eq!(report["manifest"]["precedes_first_deadline"], "before");
    assert_eq!(report["manifest"]["timing"]["state"], "evidenced");
    assert_eq!(report["complete"], true);
    assert_eq!(report["summary"], json!({ "slots": 3, "on_time": 3 }));
    for slot in 0..3 {
        assert_eq!(status(&report, slot), "on_time");
        assert_eq!(report["slots"][slot]["entries"][0]["state"], "counted");
        assert_eq!(
            report["slots"][slot]["entries"][0]["deadline_verdict"],
            "before"
        );
    }
    assert_eq!(report["slots"][0]["counted_tx_id"], one);
    assert_eq!(report["slots"][0]["entries"][0]["answer"], "yes");
    assert_eq!(report["slots"][0]["entries"][0]["probability_pct"], 65);
    assert_eq!(report["rules"]["revisions"], "first_on_time");
    // Outcomes are the reporter's, and labelled so; an unsuccessful
    // prediction is shown as one.
    assert_eq!(report["slots"][0]["outcome"]["result"], "match");
    assert_eq!(report["slots"][1]["outcome"]["result"], "no_match");
    assert!(
        report["slots"][1]["outcome"]["provenance"]
            .as_str()
            .unwrap()
            .contains("not verified")
    );
    assert!(report["slots"][2].get("outcome").is_none());
    assert_eq!(report["unassigned"], json!([]));
    assert!(report["scope"].as_str().unwrap().contains("does not show"));
    // One counted read for the manifest and one for each forecast.
    assert_eq!(series.world.lock().authenticated_reads, 4);
}

/// The series a showcase would hide: one slot missed, one entry late, one
/// revised. Every one of them is in the report, and it is not complete.
#[test]
fn a_miss_a_late_entry_and_a_revision_are_all_preserved() {
    let series = Series::well_declared();
    // Slot one: an on-time entry, then a revision before the deadline.
    let first = series.on_time(0, "yes", 9000);
    let revision = series.on_time(0, "no", 3000);
    // Slot two: stored 50 seconds after its deadline.
    let late = series.publish(
        &series.forecast(1, "no"),
        Some(series.manifest.slots[1].deadline + 50),
    );
    // Slot three: nothing was ever submitted.

    // Offered in an order that would favour the revision if order mattered.
    let report = series.report(&[&revision, &late, &first], None);
    assert_eq!(report["complete"], false);

    assert_eq!(status(&report, 0), "on_time");
    assert_eq!(report["slots"][0]["revised"], true);
    assert_eq!(report["slots"][0]["counted_tx_id"], first);
    let entries = report["slots"][0]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["state"], "counted");
    assert_eq!(entries[0]["answer"], "yes");
    assert_eq!(entries[1]["state"], "superseded");
    assert_eq!(entries[1]["tx_id"], revision);
    assert_eq!(entries[1]["answer"], "no");

    assert_eq!(status(&report, 1), "late");
    assert_eq!(report["slots"][1]["counted_tx_id"], Value::Null);
    assert_eq!(report["slots"][1]["entries"][0]["state"], "late");
    assert_eq!(
        report["slots"][1]["entries"][0]["deadline_verdict"],
        "not_before"
    );

    assert_eq!(status(&report, 2), "missing");
    assert_eq!(report["slots"][2]["entries"], json!([]));

    assert_eq!(
        report["summary"],
        json!({ "slots": 3, "on_time": 1, "late": 1, "missing": 1 })
    );
}

/// An entry accepted by the service but never posted, one inside the margin,
/// and one whose gateways are down have no usable time. None is counted.
#[test]
fn entries_without_established_timing_are_not_counted() {
    let series = Series::well_declared();
    let unposted = series.publish(&series.forecast(0, "yes"), None);
    let close = series.on_time(1, "yes", MARGIN);
    let dark = series.on_time(2, "yes", 5000);
    series
        .world
        .set_views(&dark, [View::Down, View::Down, View::Down]);

    let report = series.report(&[&unposted, &close, &dark], None);
    assert_eq!(report["complete"], false);
    for (slot, state, verdict) in [
        (0, "not_on_chain", "unknown"),
        (1, "evidenced", "too_close"),
        (2, "unavailable", "unknown"),
    ] {
        assert_eq!(status(&report, slot), "timing_unknown", "slot {slot}");
        let entry = &report["slots"][slot]["entries"][0];
        assert_eq!(entry["state"], "timing_unknown", "slot {slot}");
        assert_eq!(entry["timing"]["state"], state, "slot {slot}");
        assert_eq!(entry["deadline_verdict"], verdict, "slot {slot}");
        assert_eq!(report["slots"][slot]["counted_tx_id"], Value::Null);
    }
    assert_eq!(
        report["summary"],
        json!({ "slots": 3, "timing_unknown": 3 })
    );
}

/// A forecast that names a friendlier outcome source than its slot declared
/// is invalid, however early it was stored.
#[test]
fn a_forecast_with_the_wrong_outcome_source_is_invalid() {
    let series = Series::well_declared();
    let cheat = Forecast {
        outcome_source: "https://friendlier.example/one".to_owned(),
        ..series.forecast(0, "yes")
    };
    let cheat = series.publish(&cheat, Some(series.manifest.slots[0].deadline - 5000));
    let report = series.report(&[&cheat], None);
    assert_eq!(status(&report, 0), "invalid");
    assert_eq!(report["slots"][0]["counted_tx_id"], Value::Null);
    assert!(
        report["slots"][0]["entries"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("outcome source")
    );
    assert_eq!(report["complete"], false);
}

/// Artifacts that are not forecasts of this manifest are set aside with a
/// reason, never slotted in: another series, a private qub without its key,
/// plain text, the manifest itself, and a duplicate.
#[test]
fn artifacts_that_do_not_belong_are_set_aside() {
    let series = Series::well_declared();
    let good = series.on_time(0, "yes", 5000);
    let other_series = Forecast {
        series_id: "someone-elses".to_owned(),
        ..series.forecast(1, "yes")
    };
    let other_series = series.publish(&other_series, Some(1));
    let plain = series
        .world
        .store(seal_revealed_public("just a note"), true);
    let (private_bytes, private_key) = seal_revealed_private(&series.forecast(2, "yes").to_body());
    let private = series.world.store(private_bytes, false);
    let private_url = format!("{}#{private_key}", series.world.delivery_url(&private));

    let report = series.report(
        &[
            &good,
            &other_series,
            &plain,
            &private,
            &good,
            &series.manifest_tx,
        ],
        None,
    );
    let reasons: Vec<&str> = report["unassigned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons.len(), 5, "{reasons:?}");
    assert!(reasons[0].contains("different series"), "{reasons:?}");
    assert!(reasons[1].contains("not a forecast"), "{reasons:?}");
    assert!(reasons[2].contains("wrapper_key_required"), "{reasons:?}");
    assert!(reasons[3].contains("more than once"), "{reasons:?}");
    assert!(reasons[4].contains("manifest itself"), "{reasons:?}");
    assert_eq!(status(&report, 0), "on_time");
    assert_eq!(report["slots"][0]["entries"].as_array().unwrap().len(), 1);

    // With its key the private forecast is readable — and, having no timing
    // evidence, still cannot be counted as on time.
    let report = series.report(&[&private_url], None);
    assert_eq!(status(&report, 2), "timing_unknown");
    assert_eq!(
        report["slots"][2]["entries"][0]["timing"]["state"],
        "not_checked"
    );
}

/// A manifest stored after the first deadline cannot make a series complete
/// even when every forecast is on time.
#[test]
fn the_manifest_must_predate_the_first_deadline() {
    let first_deadline = declared().first_deadline();
    for (block_time, verdict) in [
        (first_deadline + 10, "not_before"),
        (first_deadline - 1, "too_close"),
    ] {
        let series = Series::new(Some(block_time));
        let one = series.on_time(0, "yes", 5000);
        let two = series.on_time(1, "no", 5000);
        let three = series.on_time(2, "yes", 5000);
        let report = series.report(&[&one, &two, &three], None);
        assert_eq!(report["summary"]["on_time"], 3, "{verdict}");
        assert_eq!(report["manifest"]["state"], "valid", "{verdict}");
        assert_eq!(
            report["manifest"]["precedes_first_deadline"], verdict,
            "{verdict}"
        );
        assert_eq!(report["manifest"]["timing"]["state"], "evidenced");
        assert_eq!(report["complete"], false, "{verdict}");
    }
}

/// The manifest is read from the qub service. Until its own transaction is
/// evidenced, nothing ties those bytes to the id the forecasts name, so
/// nothing is judged against the deadlines in them.
#[test]
fn nothing_is_judged_against_an_unevidenced_manifest() {
    let series = Series::new(None);
    let one = series.on_time(0, "yes", 5000);
    let two = series.on_time(1, "no", 5000);
    let report = series.report(&[&one, &two], None);
    assert_eq!(report["manifest"]["state"], "unbound");
    assert_eq!(report["manifest"]["timing"]["state"], "not_on_chain");
    assert_eq!(report["manifest"]["precedes_first_deadline"], "unknown");
    assert_eq!(report["complete"], false);
    assert_eq!(report["summary"]["timing_unknown"], 3);
    assert!(report["summary"].get("on_time").is_none());
    for slot in 0..3 {
        assert_eq!(status(&report, slot), "timing_unknown");
        assert!(report["slots"][slot]["counted_tx_id"].is_null());
    }
    assert_eq!(
        report["slots"][0]["entries"][0]["deadline_verdict"],
        "unknown"
    );
}

/// The attack the rule above exists for. A forecast is stored 10 000 s
/// AFTER its real deadline. The service then answers reads of the manifest
/// with a different, validly sealed manifest whose deadline is later. The
/// forecast must not come out on time — whether or not the gateways know the
/// manifest's transaction.
#[test]
fn a_swapped_manifest_cannot_make_a_late_forecast_on_time() {
    for gateways_know_the_manifest in [true, false] {
        let real = declared();
        let series =
            Series::new(gateways_know_the_manifest.then(|| real.first_deadline() - 50_000));
        let late = series.publish(
            &series.forecast(0, "yes"),
            Some(real.slots[0].deadline + 10_000),
        );

        // Honest service: the forecast is late (or, with the manifest not
        // on chain, not judged at all).
        let honest = series.report(&[&late], None);
        assert_eq!(
            status(&honest, 0),
            if gateways_know_the_manifest {
                "late"
            } else {
                "timing_unknown"
            }
        );

        // The swap: same series and slots, every deadline moved as late
        // as a manifest allows (the slot's own reveal time).
        let mut forged = real.clone();
        for slot in &mut forged.slots {
            slot.deadline = slot.reveal_at;
        }
        // Late by the real deadline; comfortably early by the forged one.
        assert!(forged.slots[0].deadline > real.slots[0].deadline + 10_000 + MARGIN);
        series
            .world
            .lock()
            .artifacts
            .get_mut(&series.manifest_tx)
            .unwrap()
            .served = seal_revealed_public(&forged.to_body());

        let report = series.report(&[&late], None);
        assert_eq!(report["complete"], false);
        assert_ne!(report["manifest"]["state"], "valid");
        if gateways_know_the_manifest {
            // The chain shows the transaction stores other bytes.
            assert_eq!(report["manifest"]["state"], "invalid");
            assert_eq!(report["manifest"]["timing"]["state"], "invalid");
            assert!(report.get("slots").is_none());
            assert_eq!(report["unassigned"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(report["manifest"]["state"], "unbound");
            assert_eq!(status(&report, 0), "timing_unknown");
            assert!(report["slots"][0]["counted_tx_id"].is_null());
        }
        let text = report.to_string();
        assert!(!text.contains("\"on_time\""), "{text}");
        assert!(!text.contains("\"counted\""), "{text}");
    }
}

/// The service answers a read of an on-time forecast with ANOTHER validly
/// sealed forecast (a different answer). The gateways show the transaction
/// stores other bytes, so nothing in what was served is attributed to that
/// id: not a slot, and not an answer.
#[test]
fn a_swapped_forecast_is_not_attributed_to_its_transaction() {
    let series = Series::well_declared();
    let honest = series.on_time(0, "yes", 5000);
    let other = seal_revealed_public(&series.forecast(0, "no").to_body());
    series
        .world
        .lock()
        .artifacts
        .get_mut(&honest)
        .unwrap()
        .served = other;

    let report = series.report(&[&honest], None);
    assert_eq!(report["slots"][0]["entries"], json!([]));
    assert!(report["slots"][0]["counted_tx_id"].is_null());
    assert_eq!(status(&report, 0), "timing_unknown");
    let unassigned = &report["unassigned"][0];
    assert_eq!(unassigned["tx_id"], honest);
    assert_eq!(unassigned["timing"]["state"], "invalid");
    assert!(!report.to_string().contains("\"answer\""), "{report}");
    assert_eq!(report["complete"], false);
}

/// A manifest whose deadlines are in milliseconds would be "preceded" by any
/// block at all. Through the real tool it is an invalid manifest: no slots,
/// no verdict, however early its transaction was mined.
#[test]
fn a_manifest_in_milliseconds_earns_no_verdict() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let mut body: Value = serde_json::from_str(&declared().to_body()).unwrap();
    for slot in body["slots"].as_array_mut().unwrap() {
        for field in ["deadline", "reveal_at"] {
            let seconds = slot[field].as_i64().unwrap();
            slot[field] = json!(seconds * 1000);
        }
    }
    let manifest_tx = world.store(seal_revealed_public(&body.to_string()), true);
    // Mined well after the date the author meant, were it read in seconds.
    world.mine(&manifest_tx, declared().first_deadline() + 40_000);

    let report = agent
        .call(
            "verify_forecast_series",
            &json!({ "manifest": manifest_tx, "forecasts": [] }),
        )
        .ok();
    assert_eq!(report["manifest"]["state"], "invalid");
    assert_eq!(report["manifest"]["timing"]["state"], "evidenced");
    assert!(report["manifest"].get("precedes_first_deadline").is_none());
    assert!(report.get("slots").is_none());
    assert_eq!(report["complete"], false);
    assert!(!report.to_string().contains("\"before\""), "{report}");
}

/// A forecast whose authorship signature does not verify is not counted,
/// however early it was stored: `qub-verify` fails such a qub, and so does
/// the series report.
#[test]
fn a_forecast_with_a_failing_signature_is_not_counted() {
    let series = Series::well_declared();
    let body = series.forecast(0, "yes").to_body();
    let forged = series
        .world
        .store(seal_revealed_public_with_a_failing_signature(&body), true);
    series
        .world
        .mine(&forged, series.manifest.slots[0].deadline - 5000);

    // Control: read on its own, it decrypts and says its signature is bad.
    let read = series
        .agent
        .call("read_qub", &json!({ "tx_id": forged }))
        .ok();
    assert_eq!(read["status"], "unlocked");
    assert_eq!(read["content"]["state"], "signature_invalid");
    assert_eq!(read["content"]["body_hash_verified"], true);
    assert_eq!(read["content"]["signature_verified"], false);
    assert_eq!(read["tx_binding"], "evidenced");

    let report = series.report(&[&forged], None);
    // Not counted — and not "missing" either: an artifact was offered that
    // the report could not accept, and it may have been this slot's.
    assert_eq!(status(&report, 0), "timing_unknown");
    assert!(report["slots"][0]["counted_tx_id"].is_null());
    assert_eq!(report["slots"][0]["entries"], json!([]));
    let unassigned = &report["unassigned"][0];
    assert_eq!(unassigned["tx_id"], forged);
    assert!(
        unassigned["reason"]
            .as_str()
            .unwrap()
            .contains("authorship signature does not verify"),
        "{unassigned}"
    );
    assert_eq!(report["complete"], false);
}

/// A manifest that cannot be read assigns nothing; malformed arguments are
/// errors of the call.
#[test]
fn unreadable_manifests_and_bad_arguments() {
    let series = Series::well_declared();
    let one = series.on_time(0, "yes", 5000);

    let not_a_manifest = series
        .world
        .store(seal_revealed_public("not a manifest"), true);
    let report = series
        .agent
        .call(
            "verify_forecast_series",
            &json!({ "manifest": not_a_manifest, "forecasts": [one] }),
        )
        .ok();
    assert_eq!(report["manifest"]["state"], "invalid");
    assert_eq!(report["complete"], false);
    assert!(report.get("slots").is_none());

    let unknown = "A".repeat(43);
    let report = series
        .agent
        .call(
            "verify_forecast_series",
            &json!({ "manifest": unknown, "forecasts": [] }),
        )
        .ok();
    assert_eq!(report["manifest"]["state"], "unreadable");

    for bad in [
        json!({ "forecasts": [] }),
        json!({ "manifest": series.manifest_tx }),
        json!({ "manifest": "../etc/passwd", "forecasts": [] }),
        json!({ "manifest": series.manifest_tx, "forecasts": [42] }),
        json!({ "manifest": series.manifest_tx, "forecasts": ["has space"] }),
        json!({ "manifest": series.manifest_tx, "forecasts": [], "outcomes": [] }),
        json!({ "manifest": series.manifest_tx, "forecasts": [], "outcomes": { "one": 1 } }),
        json!({ "manifest": series.manifest_tx, "forecasts": vec!["A".repeat(43); 33] }),
    ] {
        let reply = series.agent.call("verify_forecast_series", &bad);
        assert!(reply.is_error, "{bad} must be refused: {}", reply.text);
    }
}

// ---------------------------------------------------------------------------
// Publishing the four-qub series with the recipe runner
// ---------------------------------------------------------------------------

/// A plan whose deadlines are in the future, so its qubs stay locked.
fn write_plan(dir: &Path) -> PathBuf {
    let start = now();
    let slot = |id: &str, offset: i64| {
        json!({
            "slot": id,
            "question": format!("Will event {id} happen?"),
            "outcome_source": format!("https://outcomes.example/{id}"),
            "deadline": start + offset,
            "reveal_at": start + offset + 3600,
            "answer": "yes",
            "probability_pct": 60,
        })
    };
    let plan = json!({
        "series_id": "runner-series",
        "title": "Runner series",
        "scoring": "exact_match: the answer equals the outcome source's value.",
        "manifest_reveal_at": start + 600,
        "slots": [slot("one", 86_400), slot("two", 2 * 86_400), slot("three", 3 * 86_400)],
    });
    let path = dir.join("plan.json");
    std::fs::write(&path, plan.to_string()).unwrap();
    path
}

/// The outcome of one runner invocation.
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Ran {
    /// The JSON document the runner prints after its summary lines.
    fn json(&self) -> Value {
        let start = self
            .stdout
            .find("\n{")
            .unwrap_or_else(|| panic!("no JSON in runner output:\n{}", self.stdout));
        serde_json::from_str(&self.stdout[start..])
            .unwrap_or_else(|e| panic!("runner JSON is invalid ({e}):\n{}", self.stdout))
    }
}

fn runner_with_mcp(agent: &Agent, command: &str, plan: &Path, extra: &[&str], mcp: &Path) -> Ran {
    let mut process = Command::new(RUNNER_BIN);
    agent.configure(&mut process);
    let output = process
        .arg(command)
        .arg("--plan")
        .arg(plan)
        .arg("--mcp")
        .arg(mcp)
        .args(extra)
        .output()
        .expect("spawn qub-forecast-series");
    Ran {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn runner(agent: &Agent, command: &str, plan: &Path, extra: &[&str]) -> Ran {
    runner_with_mcp(agent, command, plan, extra, Path::new(support::MCP_BIN))
}

fn state_of(plan: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(plan.with_extension("state.json")).unwrap())
        .unwrap()
}

/// A fresh setup publishes the whole four-qub series inside the trial, all
/// public, with the forecasts bound to the manifest that was published.
#[test]
fn the_runner_publishes_the_four_qub_series() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = write_plan(dir.path());

    let check = runner(&agent, "check", &plan, &[]);
    assert_eq!(check.code, Some(0), "{}", check.stderr);
    assert!(
        check.stdout.contains("4 qub(s) to publish"),
        "{}",
        check.stdout
    );
    assert_eq!(world.lock().uploads.len(), 0, "check publishes nothing");

    let submit = runner(&agent, "submit", &plan, &[]);
    assert_eq!(submit.code, Some(0), "{}\n{}", submit.stdout, submit.stderr);
    assert!(
        submit.stdout.contains("Accepted is not yet evidenced"),
        "{}",
        submit.stdout
    );
    let state = state_of(&plan);
    let manifest_tx = state["manifest"]["tx_id"].as_str().unwrap().to_owned();
    assert_eq!(world.lock().publications, 4);
    assert_eq!(world.lock().publication_limit - 4, 6, "six qubs left");
    let uploads = world.lock().uploads.clone();
    assert!(uploads.iter().all(|upload| upload.is_public == Some(true)));
    assert_eq!(uploads[0].intent.as_deref(), Some("announcement"));
    assert_eq!(uploads[1].intent.as_deref(), Some("prediction"));
    // What was uploaded is what the plan declared: the manifest parses, and
    // each forecast names the published manifest and its own slot's terms.
    let declared: Value = serde_json::from_str(&std::fs::read_to_string(&plan).unwrap()).unwrap();
    for (index, slot) in ["one", "two", "three"].iter().enumerate() {
        let tx_id = state["forecasts"][slot]["tx_id"].as_str().unwrap();
        assert!(world.artifact(tx_id).is_public);
        assert!(
            !state["forecasts"][slot]["delivery_url"]
                .as_str()
                .unwrap()
                .contains('#')
        );
        let upload = world.lock().uploads[index + 1].clone();
        assert_eq!(upload.unlock_at, declared["slots"][index]["reveal_at"]);
    }
    assert_eq!(
        world.lock().uploads[0].unlock_at,
        declared["manifest_reveal_at"]
    );

    // Accepted, not yet posted: the status says so for every qub.
    let status = runner(&agent, "status", &plan, &[]);
    assert_eq!(status.code, Some(0), "{}", status.stderr);
    let rows = status.json()["status"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 4);
    for row in &rows {
        assert_eq!(row["result"]["status"], "locked");
        assert_eq!(row["result"]["visibility"], "public");
        assert_eq!(row["result"]["timing"]["state"], "not_on_chain");
        assert_eq!(row["result"]["timing"]["deadline"]["verdict"], "unknown");
    }

    // Once the chain has them, well before their deadlines, the same
    // command reports evidence — per qub, against that qub's deadline.
    for row in &rows {
        world.mine(row["tx_id"].as_str().unwrap(), now() - 3600);
    }
    let status = runner(&agent, "status", &plan, &[]);
    for row in status.json()["status"].as_array().unwrap() {
        assert_eq!(row["result"]["timing"]["state"], "evidenced");
        assert_eq!(row["result"]["timing"]["deadline"]["verdict"], "before");
    }
    assert!(
        status.stdout.contains("timing evidenced"),
        "{}",
        status.stdout
    );

    // Before anything reveals, the report cannot read the manifest and says
    // so; it does not invent slots or completeness.
    let report = runner(&agent, "report", &plan, &[]);
    assert_eq!(report.code, Some(0), "{}", report.stderr);
    let report = report.json();
    assert_eq!(report["manifest"]["state"], "locked");
    assert_eq!(report["manifest"]["tx_id"], manifest_tx);
    assert_eq!(report["complete"], false);
    assert_eq!(report["unassigned"].as_array().unwrap().len(), 3);
}

/// Interrupted three ways — a rate limit, a lost acknowledgement, and the
/// runner started again from nothing but its state file — the series still
/// ends as exactly four publications, none of them twice.
#[test]
fn an_interrupted_submit_resumes_without_publishing_twice() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = write_plan(dir.path());
    // The manifest is rate limited once and the runner waits it out; the
    // first forecast is published and its acknowledgement is lost.
    world.lock().upload_faults = vec![
        UploadFault::RateLimited(1),
        UploadFault::Pass,
        UploadFault::CommitThenDrop,
    ];

    let first = runner(&agent, "submit", &plan, &[]);
    assert_eq!(first.code, Some(1), "{}\n{}", first.stdout, first.stderr);
    assert!(first.stdout.contains("waiting 1s"), "{}", first.stdout);
    assert!(first.stderr.contains("slot `one`"), "{}", first.stderr);
    assert_eq!(
        world.lock().publications,
        2,
        "manifest, and slot one unacknowledged"
    );
    let state = state_of(&plan);
    assert!(state["manifest"]["tx_id"].is_string());
    assert_eq!(
        state["forecasts"],
        json!({}),
        "nothing unconfirmed is recorded"
    );

    // Run it again: it resumes slot one from the journal, then finishes.
    let second = runner(&agent, "submit", &plan, &[]);
    assert_eq!(second.code, Some(0), "{}\n{}", second.stdout, second.stderr);
    assert!(
        second.stdout.contains("manifest: already published"),
        "{}",
        second.stdout
    );
    assert_eq!(world.lock().publications, 4);
    let state = state_of(&plan);
    assert_eq!(state["manifest"], state_of(&plan)["manifest"]);
    let recorded: Vec<&str> = ["one", "two", "three"]
        .iter()
        .map(|slot| state["forecasts"][slot]["tx_id"].as_str().unwrap())
        .collect();
    assert_eq!(world.lock().artifacts.len(), 4);
    for tx_id in &recorded {
        assert!(world.lock().artifacts.contains_key(*tx_id));
    }

    // A third run, and a run after losing the state file, publish nothing.
    let third = runner(&agent, "submit", &plan, &[]);
    assert_eq!(third.code, Some(0), "{}", third.stderr);
    std::fs::remove_file(plan.with_extension("state.json")).unwrap();
    let rebuilt = runner(&agent, "submit", &plan, &[]);
    assert_eq!(
        rebuilt.code,
        Some(0),
        "{}\n{}",
        rebuilt.stdout,
        rebuilt.stderr
    );
    assert_eq!(
        world.lock().publications,
        4,
        "the journal resumed every qub"
    );
    assert_eq!(state_of(&plan)["forecasts"], state["forecasts"]);
    assert_eq!(state_of(&plan)["manifest"], state["manifest"]);
}

/// A replacement runner can reach an operation while the killed runner's
/// child is still finishing it. The journal lock is transient: wait, ask
/// again with the same operation id, and then continue the series.
#[cfg(unix)]
#[test]
fn an_in_flight_operation_is_retried_after_the_runner_is_restarted() {
    use std::os::unix::fs::PermissionsExt as _;

    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series-operation-in-progress");
    let plan = write_plan(dir.path());
    let fake_mcp = dir.path().join("qub-mcp");
    std::fs::write(
        &fake_mcp,
        r#"#!/bin/sh
IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[{"type":"text","text":"{\"code\":\"operation_in_progress\"}"}]}}'
IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"delivery_url\":\"https://example.com/c/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"visibility\":\"public\"}"}]}}'
IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"delivery_url\":\"https://example.com/c/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"visibility\":\"public\"}"}]}}'
IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\",\"delivery_url\":\"https://example.com/c/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\",\"visibility\":\"public\"}"}]}}'
IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":6,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\",\"delivery_url\":\"https://example.com/c/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\",\"visibility\":\"public\"}"}]}}'
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_mcp).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fake_mcp, permissions).unwrap();

    let submit = runner_with_mcp(&agent, "submit", &plan, &[], &fake_mcp);
    assert_eq!(submit.code, Some(0), "{}\n{}", submit.stdout, submit.stderr);
    assert!(
        submit.stdout.contains("waiting 1s before resuming"),
        "{}",
        submit.stdout
    );
    let state = state_of(&plan);
    assert_eq!(
        state["manifest"]["tx_id"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(state["forecasts"].as_object().unwrap().len(), 3);
}

/// A service-side in-flight upload can outlive the six-attempt budget used
/// for rate limits. Its status polls are one operation, not new publications.
#[cfg(unix)]
#[test]
fn a_service_operation_pending_beyond_six_polls_is_resumed() {
    use std::os::unix::fs::PermissionsExt as _;

    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series-service-pending");
    let plan = write_plan(dir.path());
    let fake_mcp = dir.path().join("qub-mcp");
    let request_log = dir.path().join("requests.jsonl");
    let script = r#"#!/bin/sh
log='__REQUEST_LOG__'
receive() {
  IFS= read -r request || exit 1
  printf '%s\n' "$request" >> "$log"
}
receive
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":6,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":8,"result":{"content":[{"type":"text","text":"{\"state\":\"pending\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"delivery_url\":\"https://example.com/c/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"visibility\":\"public\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"delivery_url\":\"https://example.com/c/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"visibility\":\"public\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\",\"delivery_url\":\"https://example.com/c/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\",\"visibility\":\"public\"}"}]}}'
receive
printf '%s\n' '{"jsonrpc":"2.0","id":12,"result":{"content":[{"type":"text","text":"{\"tx_id\":\"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\",\"delivery_url\":\"https://example.com/c/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\",\"visibility\":\"public\"}"}]}}'
"#
    .replace("__REQUEST_LOG__", &request_log.display().to_string());
    std::fs::write(&fake_mcp, script).unwrap();
    let mut permissions = std::fs::metadata(&fake_mcp).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fake_mcp, permissions).unwrap();

    let submit = runner_with_mcp(&agent, "submit", &plan, &[], &fake_mcp);
    assert_eq!(submit.code, Some(0), "{}\n{}", submit.stdout, submit.stderr);
    assert_eq!(
        submit
            .stdout
            .matches("service operation still pending")
            .count(),
        7,
        "{}",
        submit.stdout
    );
    assert_eq!(state_of(&plan)["forecasts"].as_object().unwrap().len(), 3);

    let requests: Vec<Value> = std::fs::read_to_string(request_log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(requests.len(), 12);
    let first = &requests[1]["params"];
    for request in &requests[2..9] {
        assert_eq!(request["params"], *first);
    }
}

/// A trial with too few qubs left stops the series where it runs out, says
/// so, and leaves what was published published.
#[test]
fn an_exhausted_trial_stops_the_series_honestly() {
    let world = World::start(KEY);
    world.lock().publication_limit = 2;
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = write_plan(dir.path());

    let submit = runner(&agent, "submit", &plan, &[]);
    assert_eq!(submit.code, Some(1), "{}", submit.stdout);
    assert!(
        submit.stderr.contains("TRIAL_QUBS_EXHAUSTED"),
        "{}",
        submit.stderr
    );
    assert_eq!(world.lock().publications, 2);
    let state = state_of(&plan);
    assert!(state["forecasts"]["one"]["tx_id"].is_string());
    assert!(state["forecasts"].get("two").is_none());

    let status = runner(&agent, "status", &plan, &[]);
    assert_eq!(status.code, Some(0), "{}", status.stderr);
    assert!(
        status.stdout.contains("slot `two`: not published"),
        "{}",
        status.stdout
    );
    assert!(status.stdout.contains("slot `three`: not published"));
    assert_eq!(status.json()["status"].as_array().unwrap().len(), 2);
}

/// The example plan the runner writes is one it accepts, describes four
/// qubs, and is never written over an existing file.
#[test]
fn the_example_plan_is_ready_to_run() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = dir.path().join("example.json");

    let written = runner(&agent, "example", &plan, &["--first-deadline-in", "7200"]);
    assert_eq!(written.code, Some(0), "{}", written.stderr);
    let value: Value = serde_json::from_str(&std::fs::read_to_string(&plan).unwrap()).unwrap();
    let slots = value["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 3);
    let start = now();
    for (index, slot) in slots.iter().enumerate() {
        let deadline = slot["deadline"].as_i64().unwrap();
        let reveal_at = slot["reveal_at"].as_i64().unwrap();
        let offset = 7200 + 3600 * i64::try_from(index).unwrap();
        assert!(
            (deadline - start - offset).abs() <= 5,
            "slot {index}: {deadline}"
        );
        assert_eq!(reveal_at - deadline, 1800);
        // The outcome source is the drand round published at the reveal time.
        let round = (reveal_at - 1_692_803_367) / 3 + 1;
        assert!(
            slot["outcome_source"]
                .as_str()
                .unwrap()
                .ends_with(&format!("/public/{round}")),
            "{slot}"
        );
        assert!(
            slot["question"]
                .as_str()
                .unwrap()
                .contains(&round.to_string())
        );
    }
    assert!(value["manifest_reveal_at"].as_i64().unwrap() < slots[0]["deadline"].as_i64().unwrap());

    let check = runner(&agent, "check", &plan, &[]);
    assert_eq!(check.code, Some(0), "{}", check.stderr);
    assert!(
        check.stdout.contains("4 qub(s) to publish"),
        "{}",
        check.stdout
    );
    assert!(!check.stdout.contains("warning"), "{}", check.stdout);

    // A tight first deadline is accepted, with a warning.
    let tight = dir.path().join("tight.json");
    assert_eq!(
        runner(&agent, "example", &tight, &["--first-deadline-in", "900"]).code,
        Some(0)
    );
    let check = runner(&agent, "check", &tight, &[]);
    assert_eq!(check.code, Some(0));
    assert!(
        check.stdout.contains("warning: slot `one`"),
        "{}",
        check.stdout
    );

    // The spacing and the reveal delay can be compressed for a short run.
    let compact = dir.path().join("compact.json");
    let ran = runner(
        &agent,
        "example",
        &compact,
        &[
            "--first-deadline-in",
            "7200",
            "--spacing",
            "300",
            "--reveal-after",
            "120",
        ],
    );
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    let value: Value = serde_json::from_str(&std::fs::read_to_string(&compact).unwrap()).unwrap();
    let deadlines: Vec<i64> = value["slots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|slot| slot["deadline"].as_i64().unwrap())
        .collect();
    assert_eq!(deadlines[1] - deadlines[0], 300);
    assert_eq!(deadlines[2] - deadlines[1], 300);
    assert_eq!(
        value["slots"][0]["reveal_at"].as_i64().unwrap() - deadlines[0],
        120
    );

    // Never over an existing file; never a nonsensical lead.
    let again = runner(&agent, "example", &plan, &[]);
    assert_eq!(again.code, Some(2), "{}", again.stderr);
    assert!(again.stderr.contains("already exists"), "{}", again.stderr);
    let fresh = dir.path().join("fresh.json");
    for flag in ["--first-deadline-in", "--spacing", "--reveal-after"] {
        for bad in ["0", "-5", "soon"] {
            let ran = runner(&agent, "example", &fresh, &[flag, bad]);
            assert_eq!(ran.code, Some(2), "{flag} {bad}");
            assert!(!fresh.exists(), "{flag} {bad}");
        }
    }
    assert_eq!(
        world.lock().uploads.len(),
        0,
        "an example publishes nothing"
    );
}

/// One way of breaking a plan.
type PlanEdit<'a> = &'a dyn Fn(&mut Value);

/// What is published cannot be changed, so the plan cannot be either. A
/// deadline moved later in `plan.json` after publishing must not be the
/// deadline `status` judges against, and an edited answer must not be sent
/// under the same series.
#[test]
fn a_plan_changed_after_publishing_is_refused() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = write_plan(dir.path());
    let original = std::fs::read_to_string(&plan).unwrap();
    let edited = |change: &dyn Fn(&mut Value)| {
        let mut value: Value = serde_json::from_str(&original).unwrap();
        change(&mut value);
        std::fs::write(&plan, value.to_string()).unwrap();
    };

    assert_eq!(runner(&agent, "submit", &plan, &[]).code, Some(0));
    assert_eq!(world.lock().publications, 4);
    let state = state_of(&plan);
    assert_eq!(state["plan_digest"].as_str().unwrap().len(), 64);

    // The first forecast is mined 100 s AFTER its published deadline.
    let published_deadline =
        serde_json::from_str::<Value>(&original).unwrap()["slots"][0]["deadline"]
            .as_i64()
            .unwrap();
    let first = state["forecasts"]["one"]["tx_id"]
        .as_str()
        .unwrap()
        .to_owned();
    world.mine(&first, published_deadline + 100);
    let honest = runner(&agent, "status", &plan, &[]);
    assert_eq!(honest.code, Some(0), "{}", honest.stderr);
    let row = &honest.json()["status"][1];
    assert_eq!(row["result"]["timing"]["deadline"]["verdict"], "not_before");

    // Move that deadline a day later in the plan: every command refuses,
    // and no verdict of any kind is printed.
    edited(&|plan| {
        plan["slots"][0]["deadline"] = json!(published_deadline + 86_400);
        plan["slots"][0]["reveal_at"] = json!(published_deadline + 86_400 + 3600);
    });
    for command in ["status", "submit", "report"] {
        let ran = runner(&agent, command, &plan, &[]);
        assert_eq!(ran.code, Some(2), "{command}: {}", ran.stdout);
        assert!(ran.stderr.contains("plan has changed"), "{}", ran.stderr);
        assert!(!ran.stdout.contains("before"), "{command}: {}", ran.stdout);
    }
    // An edited answer is the same: nothing more is published.
    edited(&|plan| plan["slots"][2]["answer"] = json!("no"));
    assert_eq!(runner(&agent, "submit", &plan, &[]).code, Some(2));
    assert_eq!(world.lock().publications, 4);

    // The plan as published works again.
    std::fs::write(&plan, &original).unwrap();
    assert_eq!(runner(&agent, "status", &plan, &[]).code, Some(0));
}

/// The state file is bound to the plan before the first upload, so a run
/// that died part-way is already tied to the terms it started with.
#[test]
fn a_plan_changed_after_a_partial_submit_is_refused() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = write_plan(dir.path());
    let original = std::fs::read_to_string(&plan).unwrap();

    // Before anything at all is published the file already names the plan:
    // a run that dies on its very first upload is bound to these terms.
    world.lock().publication_limit = 0;
    let none = runner(&agent, "submit", &plan, &[]);
    assert_eq!(none.code, Some(1), "{}", none.stdout);
    assert_eq!(world.lock().publications, 0);
    let state = state_of(&plan);
    assert_eq!(state["plan_digest"].as_str().unwrap().len(), 64);
    assert!(state["manifest"].is_null());
    let mut early: Value = serde_json::from_str(&original).unwrap();
    early["title"] = json!("Another title");
    std::fs::write(&plan, early.to_string()).unwrap();
    let refused = runner(&agent, "submit", &plan, &[]);
    assert_eq!(refused.code, Some(2), "{}", refused.stdout);
    assert!(
        refused.stderr.contains("plan has changed"),
        "{}",
        refused.stderr
    );
    std::fs::write(&plan, &original).unwrap();

    // The allowance runs out after the manifest and one forecast.
    world.lock().publication_limit = 2;
    let partial = runner(&agent, "submit", &plan, &[]);
    assert_eq!(partial.code, Some(1), "{}", partial.stdout);
    assert_eq!(world.lock().publications, 2);
    let state = state_of(&plan);
    assert!(state["plan_digest"].is_string());
    assert!(state["manifest"].is_object());

    // Changing a not-yet-published forecast's deadline is still a change to
    // a manifest that is already on permanent storage.
    let mut value: Value = serde_json::from_str(&original).unwrap();
    let deadline = value["slots"][2]["deadline"].as_i64().unwrap();
    value["slots"][2]["deadline"] = json!(deadline + 5);
    std::fs::write(&plan, value.to_string()).unwrap();
    world.lock().publication_limit = 10;
    let refused = runner(&agent, "submit", &plan, &[]);
    assert_eq!(refused.code, Some(2), "{}", refused.stdout);
    assert!(
        refused.stderr.contains("plan has changed"),
        "{}",
        refused.stderr
    );
    assert_eq!(world.lock().publications, 2);

    // Restored, the same command finishes the series: four in all.
    std::fs::write(&plan, &original).unwrap();
    assert_eq!(runner(&agent, "submit", &plan, &[]).code, Some(0));
    assert_eq!(world.lock().publications, 4);
}

/// A plan whose times cannot be Unix seconds is refused before anything is
/// sealed: a millisecond deadline would be "met" by any block at all.
#[test]
fn a_plan_in_milliseconds_is_refused() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let plan = write_plan(dir.path());
    let original: Value = serde_json::from_str(&std::fs::read_to_string(&plan).unwrap()).unwrap();
    let edits: [(&str, PlanEdit); 3] = [
        ("deadline", &|plan| {
            let at = plan["slots"][0]["deadline"].as_i64().unwrap();
            plan["slots"][0]["deadline"] = json!(at * 1000);
            plan["slots"][0]["reveal_at"] = json!(at * 1000 + 1);
        }),
        ("reveal_at", &|plan| {
            let at = plan["slots"][1]["reveal_at"].as_i64().unwrap();
            plan["slots"][1]["reveal_at"] = json!(at * 1000);
        }),
        ("manifest_reveal_at", &|plan| {
            // Not a time at all; only the bound on this field can refuse it.
            plan["manifest_reveal_at"] = json!(0);
        }),
    ];
    for (label, edit) in edits {
        let mut value = original.clone();
        edit(&mut value);
        std::fs::write(&plan, value.to_string()).unwrap();
        for command in ["check", "submit"] {
            let ran = runner(&agent, command, &plan, &[]);
            assert_eq!(ran.code, Some(2), "{label} / {command}: {}", ran.stdout);
            assert!(ran.stderr.contains("plan:"), "{label}: {}", ran.stderr);
        }
    }
    assert_eq!(world.lock().uploads.len(), 0);
}

/// A plan that breaks a rule is refused before anything is sealed or sent.
#[test]
fn a_bad_plan_publishes_nothing() {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    let dir = TempDir::new("series");
    let good = write_plan(dir.path());
    let original: Value = serde_json::from_str(&std::fs::read_to_string(&good).unwrap()).unwrap();
    let edits: [(&str, PlanEdit); 6] = [
        ("reveal before deadline", &|plan| {
            let deadline = plan["slots"][0]["deadline"].as_i64().unwrap();
            plan["slots"][0]["reveal_at"] = json!(deadline - 1);
        }),
        ("manifest revealed after the first deadline", &|plan| {
            plan["manifest_reveal_at"] = plan["slots"][0]["deadline"].clone();
        }),
        ("duplicate slot", &|plan| {
            plan["slots"][1]["slot"] = json!("one");
        }),
        ("missing answer", &|plan| {
            plan["slots"][2].as_object_mut().unwrap().remove("answer");
        }),
        ("bad series id", &|plan| {
            plan["series_id"] = json!("Not An Id");
        }),
        ("probability out of range", &|plan| {
            plan["slots"][0]["probability_pct"] = json!(101);
        }),
    ];
    for (label, edit) in edits {
        let mut plan = original.clone();
        edit(&mut plan);
        let path = dir.path().join("bad.json");
        std::fs::write(&path, plan.to_string()).unwrap();
        for command in ["check", "submit"] {
            let ran = runner(&agent, command, &path, &[]);
            assert_eq!(ran.code, Some(2), "{label} / {command}: {}", ran.stderr);
            assert!(ran.stderr.contains("plan:"), "{label}: {}", ran.stderr);
        }
    }
    assert_eq!(world.lock().uploads.len(), 0);
    assert_eq!(runner(&agent, "status", &good, &[]).code, Some(1));
    assert_eq!(runner(&agent, "publish", &good, &[]).code, Some(2));

    // A state file from another series is refused, not overwritten.
    std::fs::write(
        good.with_extension("state.json"),
        json!({ "series_id": "another", "manifest": null, "forecasts": {} }).to_string(),
    )
    .unwrap();
    let ran = runner(&agent, "submit", &good, &[]);
    assert_eq!(ran.code, Some(2), "{}", ran.stderr);
    // Told apart from "your plan changed": the advice is a different one.
    assert!(ran.stderr.contains("another series"), "{}", ran.stderr);
    assert!(!ran.stderr.contains("plan has changed"), "{}", ran.stderr);
    assert_eq!(world.lock().uploads.len(), 0);
}
