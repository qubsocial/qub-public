// allow-test-network: loopback mocks only (see tests/support/mod.rs)
//! A qub whose unlock time has passed and whose drand beacon is not there
//! yet, through the real `qub-mcp` binary.
//!
//! The unlock time is a clock reading; the beacon is a fact. Between the two
//! a relay answers 404 for the round, and a relay that is failing answers
//! 5xx whatever the round. The read tools must keep those apart and must
//! not let either pass for a reveal:
//!
//! - **not published yet (404 from every relay)** — `read_qub` fails, says
//!   the round is not published yet and that a retry will work, and returns
//!   no body, no bundle and no content verdict;
//! - **an outage (5xx, or a relay that hangs up)** — `read_qub` fails and does
//!   NOT say "not published yet": the wait that fixes the first does nothing
//!   for the second;
//! - **in both** — `check_status`, which needs no beacon, still answers and
//!   claims no content; the SAME `read_qub` call succeeds once the beacon is
//!   served; a private qub read with its correct key leaks nothing in the
//!   meantime, and a missing or wrong key fails exactly as it does when the
//!   beacon is there.
//!
//! Every test also states what the services saw. A refused read is still a
//! read of the stored bytes: under an API key it is one counted read (the
//! README's "Reads and the read allowance"), and nothing but reads, gateway
//! lookups and beacon requests is ever sent.
//!
//! The qubs are sealed by `qub_core::seal` to a real elapsed quicknet round,
//! so when the mock does serve the beacon the binary really decrypts.

mod support;

use std::sync::atomic::Ordering;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use qub_core::export::QubBundle;
use qub_verify::series::{Forecast, Manifest, Slot};
use serde_json::{Value, json};
use support::{
    Agent, DrandFault, ToolReply, World, drand_mirror_answering, drand_mirror_hanging_up,
    elapsed_round, seal_revealed_private, seal_revealed_public,
};

const KEY: &str = "qub_sk_trial_drand_delay";

const PUBLIC_BODY: &str = "the outcome was tails, sealed in public";
const PRIVATE_BODY: &str = "for whoever holds the fragment, once the round is out";

/// Member names and markers that only a reveal may put in a tool's text.
const REVEAL_ONLY: [&str; 7] = [
    "\"body\"",
    "BEGIN USER CONTENT",
    "qub_bundle_b64url",
    "\"content\"",
    "verified",
    "created_at",
    "sender_label",
];

fn world_and_agent() -> (World, Agent) {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    (world, agent)
}

fn hold_back(world: &World, fault: DrandFault) {
    world.lock().drand_fault = Some(fault);
}

fn serve_the_beacon(world: &World) {
    world.lock().drand_fault = None;
}

/// A read that did not get its beacon: an error, and nothing in it that a
/// reveal would have carried.
fn assert_reveals_nothing(reply: &ToolReply, plaintext: &str, what: &str) {
    assert!(
        reply.is_error,
        "{what}: a read without its beacon must be an error: {}",
        reply.text
    );
    assert!(
        !reply.text.contains(plaintext),
        "{what}: the body leaked: {}",
        reply.text
    );
    for marker in REVEAL_ONLY {
        assert!(
            !reply.text.contains(marker),
            "{what}: {marker:?} in a refused read: {}",
            reply.text
        );
    }
}

/// Refused because the round is not published yet, and says so in the words
/// an agent can act on: wait, then retry.
fn assert_too_early(reply: &ToolReply, plaintext: &str, what: &str) {
    assert_reveals_nothing(reply, plaintext, what);
    assert!(reply.text.contains("status 404"), "{what}: {}", reply.text);
    assert!(
        reply.text.contains("not published yet") && reply.text.contains("retry"),
        "{what}: no \"not published yet — retry\" hint: {}",
        reply.text
    );
}

/// Refused because the beacon could not be fetched at all. `says` is how the
/// failure is named; "not published yet" would be a wrong diagnosis.
fn assert_outage(reply: &ToolReply, plaintext: &str, says: &str, what: &str) {
    assert_reveals_nothing(reply, plaintext, what);
    assert!(reply.text.contains(says), "{what}: {}", reply.text);
    assert!(
        !reply.text.contains("not published"),
        "{what}: an outage reported as \"too early\": {}",
        reply.text
    );
}

/// A successful reveal of `plaintext`, with the bundle that proves it.
fn assert_revealed(result: &Value, visibility: &str, plaintext: &str, tx_id: &str) {
    assert_eq!(result["status"], "unlocked", "{result}");
    assert_eq!(result["visibility"], visibility, "{result}");
    assert_eq!(result["tx_id"], tx_id, "{result}");
    assert_eq!(result["content"]["state"], "verified", "{result}");
    assert_eq!(result["content"]["body_hash_verified"], true, "{result}");
    assert!(
        result["body"]
            .as_str()
            .is_some_and(|body| body.contains(plaintext)),
        "{result}"
    );
    let bundle = QubBundle::from_cbor(
        &BASE64URL
            .decode(result["qub_bundle_b64url"].as_str().expect("a bundle"))
            .expect("base64url"),
    )
    .expect("bundle parses");
    assert_eq!(bundle.arweave_tx_id(), tx_id);
    assert_eq!(bundle.drand_round(), elapsed_round().round);
}

/// `check_status` on an unlocked qub: an answer, and no content in it.
fn assert_status_without_content(status: &Value, visibility: &str, tx_id: &str) {
    assert_eq!(status["status"], "unlocked", "{status}");
    assert_eq!(status["visibility"], visibility, "{status}");
    assert_eq!(status["tx_id"], tx_id, "{status}");
    assert_eq!(status["time_remaining_seconds"], 0, "{status}");
    assert_eq!(status["drand_round"], elapsed_round().round, "{status}");
    let text = status.to_string();
    for marker in REVEAL_ONLY {
        assert!(
            !text.contains(marker),
            "check_status claimed content ({marker:?}): {status}"
        );
    }
}

/// What the qub service saw, exactly; that nothing was published or even
/// attempted; and that no lookup at a service qub does not run carried the
/// API key.
fn assert_worker_saw(world: &World, expected: &[String]) {
    let inner = world.lock();
    assert_eq!(inner.worker_requests, expected);
    assert_eq!(inner.uploads.len(), 0, "an upload was sent");
    assert_eq!(inner.publications, 0, "something was published");
    assert!(inner.claims.is_empty(), "an operation was claimed");
    assert_eq!(
        inner.credentialed_lookups,
        Vec::<String>::new(),
        "a gateway or drand request carried the API key"
    );
}

fn counted_read(tx_id: &str) -> String {
    format!("GET /api/v1/qub/{tx_id}")
}

/// Reads journal nothing: the state directory the installation was given is
/// as empty as it started.
fn assert_no_local_state(agent: &Agent) {
    let entries: Vec<_> = std::fs::read_dir(agent.state_dir())
        .expect("the state directory exists")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(entries.is_empty(), "a read wrote local state: {entries:?}");
}

// ---------------------------------------------------------------------------
// A public qub
// ---------------------------------------------------------------------------

/// Unlock time passed, beacon not published: `read_qub` is refused with the
/// retry hint and no content, `check_status` still answers, and the same
/// `read_qub` call reads the qub once the beacon is served.
#[test]
fn a_public_read_before_the_beacon_is_published_is_refused_then_succeeds() {
    let (world, agent) = world_and_agent();
    let round = elapsed_round();
    let tx_id = world.store(seal_revealed_public(PUBLIC_BODY), true);
    let block_time = round.unlock_at - 20_000;
    world.mine(&tx_id, block_time);
    hold_back(&world, DrandFault::NotPublished);
    let arguments = json!({ "tx_id": tx_id });

    let late = agent.call("read_qub", &arguments);
    assert_too_early(&late, PUBLIC_BODY, "read_qub");
    assert_eq!(world.lock().drand_requests, 1, "the beacon was asked for");

    // The status is a matter of the clock and the stored bytes: it needs no
    // beacon, asks for none, and shows no content.
    let status = agent.call("check_status", &arguments).ok();
    assert_status_without_content(&status, "public", &tx_id);
    assert_eq!(status["unlock_at"], round.unlock_at);
    assert_eq!(status["timing"]["state"], "evidenced");
    assert_eq!(status["timing"]["block_time"], block_time);
    assert_eq!(status["tx_binding"], "evidenced");
    assert_eq!(world.lock().drand_requests, 1, "check_status asked drand");

    // The beacon arrives. The very same call now reads the qub.
    serve_the_beacon(&world);
    let read = agent.call("read_qub", &arguments).ok();
    assert_revealed(&read, "public", PUBLIC_BODY, &tx_id);
    assert_eq!(read["timing"]["state"], "evidenced");
    assert_eq!(world.lock().drand_requests, 2);

    // Three calls, three counted reads of this qub and nothing else at the
    // Worker; the gateways were asked about this transaction only.
    assert_worker_saw(&world, &vec![counted_read(&tx_id); 3]);
    let inner = world.lock();
    assert_eq!(inner.authenticated_reads, 3);
    assert_eq!(inner.anonymous_reads, 0);
    assert!(
        !inner.gateway_requests.is_empty(),
        "the gateway log can hold a hit"
    );
    let block = format!("/block/hash/{}", support::block_hash_at(block_time));
    for seen in &inner.gateway_requests {
        assert!(
            seen.contains(&format!("/tx/{tx_id}")) || seen.ends_with(&block),
            "an unexpected gateway request: {seen}"
        );
    }
    drop(inner);
    assert_no_local_state(&agent);
}

/// The beacon endpoint failing is an outage, not "too early": every 5xx, and
/// a relay that hangs up without answering, are reported as a failed fetch with no
/// "not published yet" hint and no content. Once drand answers, the read
/// succeeds.
#[test]
fn a_drand_outage_is_reported_as_an_outage_and_reveals_nothing() {
    let (world, agent) = world_and_agent();
    let tx_id = world.store(seal_revealed_public(PUBLIC_BODY), true);
    // No gateway is asked, so every request below is a read or a beacon.
    let arguments = json!({ "tx_id": tx_id, "check_timing": false });

    for status in [500_u16, 502, 503, 504] {
        hold_back(&world, DrandFault::Failing(status));
        let failed = agent.call("read_qub", &arguments);
        assert_outage(
            &failed,
            PUBLIC_BODY,
            &format!("drand fetch failed with status {status}"),
            &format!("read_qub, drand {status}"),
        );
    }
    assert_eq!(world.lock().drand_requests, 4);
    let status = agent.call("check_status", &arguments).ok();
    assert_status_without_content(&status, "public", &tx_id);
    assert_eq!(world.lock().drand_requests, 4, "check_status asked drand");

    // No HTTP answer at all — the relay hangs up: the same kind of failure,
    // by another route. (The binary may try a broken connection twice.)
    let (hanging_up, hung_up) = drand_mirror_hanging_up();
    let cut_off = Agent::new(&world, Some(KEY)).with_env("QUB_DRAND_ENDPOINTS", &hanging_up);
    let failed = cut_off.call("read_qub", &arguments);
    assert_outage(
        &failed,
        PUBLIC_BODY,
        "drand fetch failed",
        "read_qub, drand hanging up",
    );
    assert!(hung_up.load(Ordering::SeqCst) >= 1, "the relay was asked");
    assert_eq!(world.lock().drand_requests, 4);

    serve_the_beacon(&world);
    let read = agent.call("read_qub", &arguments).ok();
    assert_revealed(&read, "public", PUBLIC_BODY, &tx_id);
    assert_eq!(read["timing"]["state"], "not_checked");
    assert_eq!(world.lock().drand_requests, 5);

    // Four failed reads, a status, the hung-up one, the one that read.
    assert_worker_saw(&world, &vec![counted_read(&tx_id); 7]);
    let inner = world.lock();
    assert_eq!(inner.authenticated_reads, 7);
    assert_eq!(inner.anonymous_reads, 0);
    assert_eq!(inner.gateway_requests, Vec::<String>::new());
    drop(inner);
    assert_no_local_state(&agent);
    assert_no_local_state(&cut_off);
}

// ---------------------------------------------------------------------------
// A private qub
// ---------------------------------------------------------------------------

struct Private {
    world: World,
    agent: Agent,
    tx_id: String,
    key: String,
    /// `read_qub` / `check_status` arguments carrying the correct key.
    with_key: Value,
}

impl Private {
    fn new() -> Self {
        let (world, agent) = world_and_agent();
        let (stored, key) = seal_revealed_private(PRIVATE_BODY);
        let tx_id = world.store(stored, false);
        let with_key = json!({ "delivery_url": format!("{}#{key}", world.delivery_url(&tx_id)) });
        Self {
            world,
            agent,
            tx_id,
            key,
            with_key,
        }
    }

    /// A missing key is refused and a wrong key fails, by both tools, with
    /// nothing of the body in either answer — and without the beacon being
    /// asked for. Four counted reads.
    fn assert_the_key_still_decides(&self, when: &str) {
        let before = self.world.lock().drand_requests;
        let wrong = BASE64URL.encode([9u8; 32]);
        for tool in ["read_qub", "check_status"] {
            let missing = self.agent.call(tool, &json!({ "tx_id": self.tx_id }));
            assert_eq!(
                missing.error_code(),
                "wrapper_key_required",
                "{tool}, {when}"
            );
            assert!(!missing.text.contains(PRIVATE_BODY), "{tool}, {when}");
            let failed = self.agent.call(
                tool,
                &json!({ "tx_id": self.tx_id, "key_base64url": wrong }),
            );
            assert_eq!(failed.error_code(), "unwrap_failed", "{tool}, {when}");
            assert!(!failed.text.contains(PRIVATE_BODY), "{tool}, {when}");
        }
        assert_eq!(
            self.world.lock().drand_requests,
            before,
            "a read without the right key asked for the beacon ({when})"
        );
    }

    /// The correct key, while the beacon is held back: `check_status`
    /// answers without content and without asking drand. One counted read.
    fn assert_status_answers(&self) {
        let before = self.world.lock().drand_requests;
        let status = self.agent.call("check_status", &self.with_key).ok();
        assert_status_without_content(&status, "private", &self.tx_id);
        assert_eq!(status["timing"]["state"], "unsupported_private");
        assert_eq!(self.world.lock().drand_requests, before);
    }

    /// The beacon is served: the same call reveals, and the key rules are
    /// what they were. `reads` is every Worker read the test has made.
    fn assert_reads_once_served(&self, reads: usize) {
        serve_the_beacon(&self.world);
        let before = self.world.lock().drand_requests;
        let read = self.agent.call("read_qub", &self.with_key).ok();
        assert_revealed(&read, "private", PRIVATE_BODY, &self.tx_id);
        assert_eq!(read["timing"]["state"], "unsupported_private");
        assert_eq!(self.world.lock().drand_requests, before + 1);
        self.assert_the_key_still_decides("beacon served");

        assert_worker_saw(&self.world, &vec![counted_read(&self.tx_id); reads]);
        let inner = self.world.lock();
        assert_eq!(inner.authenticated_reads, reads);
        assert_eq!(inner.anonymous_reads, 0);
        // A private qub never causes a gateway lookup.
        assert_eq!(inner.gateway_requests, Vec::<String>::new());
        drop(inner);
        assert_no_local_state(&self.agent);
    }
}

/// The correct key opens the wrapper and no further: until the beacon is
/// published the read is refused with the retry hint, and neither the body
/// nor the key is in the refusal.
#[test]
fn a_private_read_before_the_beacon_is_published_reveals_nothing_then_succeeds() {
    let private = Private::new();
    hold_back(&private.world, DrandFault::NotPublished);

    let late = private.agent.call("read_qub", &private.with_key);
    assert_too_early(&late, PRIVATE_BODY, "read_qub with the key");
    assert!(
        !late.text.contains(&private.key),
        "the wrapper key is in the refusal: {}",
        late.text
    );
    assert_eq!(private.world.lock().drand_requests, 1);

    private.assert_the_key_still_decides("beacon not published");
    private.assert_status_answers();
    // 1 refused + 4 key cases + 1 status, then 1 read + 4 key cases.
    private.assert_reads_once_served(11);
}

/// The same with drand failing: an outage, said as one, and still nothing
/// of the qub in the answer.
#[test]
fn a_private_read_during_a_drand_outage_reveals_nothing_then_succeeds() {
    let private = Private::new();
    hold_back(&private.world, DrandFault::Failing(503));

    let failed = private.agent.call("read_qub", &private.with_key);
    assert_outage(
        &failed,
        PRIVATE_BODY,
        "drand fetch failed with status 503",
        "read_qub with the key",
    );
    assert!(
        !failed.text.contains(&private.key),
        "the wrapper key is in the refusal: {}",
        failed.text
    );
    assert_eq!(private.world.lock().drand_requests, 1);

    private.assert_the_key_still_decides("drand failing");
    private.assert_status_answers();
    private.assert_reads_once_served(11);
}

// ---------------------------------------------------------------------------
// What a refused read costs
// ---------------------------------------------------------------------------

/// The documented contract is one counted read per call, taken when the
/// stored bytes are fetched — so a read refused for want of a beacon has
/// already been counted, and retrying on a late beacon spends the allowance.
/// drand itself is never a read, and a recipient with no key is counted
/// against no one.
#[test]
fn a_read_refused_for_a_late_beacon_is_still_one_counted_read() {
    let (world, agent) = world_and_agent();
    let tx_id = world.store(seal_revealed_public(PUBLIC_BODY), true);
    world.lock().read_limit = 2;
    hold_back(&world, DrandFault::NotPublished);
    let arguments = json!({ "tx_id": tx_id, "check_timing": false });

    let late = agent.call("read_qub", &arguments);
    assert_too_early(&late, PUBLIC_BODY, "first read");
    assert_eq!(world.lock().authenticated_reads, 1, "the refused read");
    assert_eq!(world.lock().drand_requests, 1);

    serve_the_beacon(&world);
    let read = agent.call("read_qub", &arguments).ok();
    assert_revealed(&read, "public", PUBLIC_BODY, &tx_id);
    assert_eq!(world.lock().authenticated_reads, 2);
    assert_eq!(world.lock().drand_requests, 2);

    // The allowance of two is spent: one read that revealed nothing, one
    // that did. A third is refused by the service before any beacon is
    // asked for, and is not retried on the anonymous route.
    let refused = agent.call("read_qub", &arguments);
    assert_eq!(refused.error_code(), "TRIAL_READS_EXHAUSTED");
    assert_eq!(world.lock().authenticated_reads, 2);
    assert_eq!(world.lock().anonymous_reads, 0);
    assert_eq!(world.lock().drand_requests, 2);

    // A recipient with no key meets the same late beacon on the anonymous
    // route: the same refusal, and nobody's allowance is touched.
    hold_back(&world, DrandFault::NotPublished);
    let recipient = Agent::new(&world, None);
    let late = recipient.call("read_qub", &arguments);
    assert_too_early(&late, PUBLIC_BODY, "anonymous read");
    assert_eq!(world.lock().anonymous_reads, 1);
    assert_eq!(world.lock().authenticated_reads, 2);
    assert_eq!(world.lock().drand_requests, 3);

    let mut expected = vec![counted_read(&tx_id); 3];
    expected.push(format!("GET /api/v1/qub/{tx_id}/bytes"));
    assert_worker_saw(&world, &expected);
    assert_eq!(world.lock().gateway_requests, Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// More than one relay
// ---------------------------------------------------------------------------

/// "Too early" is decided by any relay that says the round is not out yet,
/// wherever it sits in the list. Taking only the last relay's answer made the
/// same four relays read as an outage in one order and as "retry in a few
/// seconds" in another; the app and the embed have always treated any 404
/// this way.
#[test]
fn the_too_early_diagnosis_does_not_depend_on_relay_order() {
    let world = World::start(KEY);
    let tx_id = world.store(seal_revealed_public(PUBLIC_BODY), true);
    let arguments = json!({ "tx_id": tx_id, "check_timing": false });
    let (behind_a, _) = drand_mirror_answering(404);
    let (behind_b, _) = drand_mirror_answering(404);
    let (down, _) = drand_mirror_answering(503);
    let asking = |relays: &[&str]| {
        Agent::new(&world, Some(KEY)).with_env("QUB_DRAND_ENDPOINTS", &relays.join(","))
    };
    for order in [
        [&behind_a, &behind_b, &down],
        [&down, &behind_a, &behind_b],
        [&behind_a, &down, &behind_b],
    ] {
        let relays: Vec<&str> = order.iter().map(|relay| relay.as_str()).collect();
        let read = asking(&relays).call("read_qub", &arguments);
        assert_too_early(&read, PUBLIC_BODY, &format!("relays {relays:?}"));
    }
}

/// A relay that is behind, or down, does not hold up a reveal another relay
/// can serve; a relay is not asked once an earlier one has answered. When
/// every relay is behind it is "too early"; when every relay is failing it
/// is an outage.
#[test]
fn a_lagging_or_failing_relay_does_not_block_a_reveal_another_can_serve() {
    let world = World::start(KEY);
    let tx_id = world.store(seal_revealed_public(PUBLIC_BODY), true);
    let arguments = json!({ "tx_id": tx_id, "check_timing": false });
    let (behind, behind_seen) = drand_mirror_answering(404);
    let (down, down_seen) = drand_mirror_answering(503);
    let asking = |relays: &[&str]| {
        Agent::new(&world, Some(KEY)).with_env("QUB_DRAND_ENDPOINTS", &relays.join(","))
    };

    // One behind, one down, one that has the beacon.
    let read = asking(&[&behind, &down, &world.drand_url])
        .call("read_qub", &arguments)
        .ok();
    assert_revealed(&read, "public", PUBLIC_BODY, &tx_id);
    assert_eq!(behind_seen.load(Ordering::SeqCst), 1);
    assert_eq!(down_seen.load(Ordering::SeqCst), 1);
    assert_eq!(world.lock().drand_requests, 1);

    // The relay that has it comes first: the others are not asked.
    let read = asking(&[&world.drand_url, &behind, &down])
        .call("read_qub", &arguments)
        .ok();
    assert_revealed(&read, "public", PUBLIC_BODY, &tx_id);
    assert_eq!(behind_seen.load(Ordering::SeqCst), 1);
    assert_eq!(down_seen.load(Ordering::SeqCst), 1);
    assert_eq!(world.lock().drand_requests, 2);

    // Every relay behind: not published yet, and every one was asked.
    let (also_behind, also_behind_seen) = drand_mirror_answering(404);
    let late = asking(&[&behind, &also_behind]).call("read_qub", &arguments);
    assert_too_early(&late, PUBLIC_BODY, "every relay behind");
    assert_eq!(behind_seen.load(Ordering::SeqCst), 2);
    assert_eq!(also_behind_seen.load(Ordering::SeqCst), 1);

    // Every relay failing: an outage.
    let (also_down, also_down_seen) = drand_mirror_answering(500);
    let failed = asking(&[&down, &also_down]).call("read_qub", &arguments);
    assert_outage(
        &failed,
        PUBLIC_BODY,
        "drand fetch failed with status 500",
        "every relay failing",
    );
    assert_eq!(down_seen.load(Ordering::SeqCst), 2);
    assert_eq!(also_down_seen.load(Ordering::SeqCst), 1);

    assert_eq!(world.lock().drand_requests, 2);
    assert_worker_saw(&world, &vec![counted_read(&tx_id); 4]);
}

// ---------------------------------------------------------------------------
// The third tool that reveals
// ---------------------------------------------------------------------------

/// `verify_forecast_series` reads each artifact the way `read_qub` does. With
/// the beacon held back it reports the manifest unreadable — for the reason
/// drand gave — assigns no forecast to any slot and is not complete; the
/// same call is complete once the beacon is served.
#[test]
fn a_series_checked_before_the_beacon_counts_nothing_then_completes() {
    const ANSWER: &str = "heads-not-tails";
    let (world, agent) = world_and_agent();
    let reveal_at = elapsed_round().unlock_at;
    let deadline = reveal_at - 20_000;
    let manifest = Manifest {
        series_id: "beacon-series".to_owned(),
        title: "One declared forecast".to_owned(),
        scoring: "exact_match: the answer equals the outcome source's value.".to_owned(),
        slots: vec![Slot {
            slot: "one".to_owned(),
            question: "Which side lands up?".to_owned(),
            outcome_source: "https://outcomes.example/one".to_owned(),
            deadline,
            reveal_at,
        }],
    };
    let manifest_tx = world.store(seal_revealed_public(&manifest.to_body()), true);
    world.mine(&manifest_tx, deadline - 50_000);
    let forecast = Forecast {
        series_id: manifest.series_id.clone(),
        manifest_tx_id: manifest_tx.clone(),
        slot: "one".to_owned(),
        question: manifest.slots[0].question.clone(),
        outcome_source: manifest.slots[0].outcome_source.clone(),
        answer: ANSWER.to_owned(),
        probability_pct: Some(70),
    };
    let forecast_tx = world.store(seal_revealed_public(&forecast.to_body()), true);
    world.mine(&forecast_tx, deadline - 5000);
    let arguments = json!({
        "manifest": manifest_tx,
        "forecasts": [forecast_tx],
        "outcomes": { "one": ANSWER },
    });

    for (fault, says) in [
        (DrandFault::NotPublished, "not published yet"),
        (DrandFault::Failing(503), "status 503"),
    ] {
        hold_back(&world, fault);
        let reply = agent.call("verify_forecast_series", &arguments);
        let report = reply.ok();
        assert_eq!(report["complete"], false, "{fault:?}: {report}");
        assert_eq!(
            report["manifest"]["state"], "unreadable",
            "{fault:?}: {report}"
        );
        let reason = report["manifest"]["reason"].as_str().unwrap_or_default();
        assert!(reason.contains(says), "{fault:?}: {reason}");
        assert_eq!(
            reason.contains("not published"),
            matches!(fault, DrandFault::NotPublished),
            "{fault:?}: {reason}"
        );
        assert!(report.get("slots").is_none(), "{fault:?}: {report}");
        assert!(report.get("summary").is_none(), "{fault:?}: {report}");
        assert_eq!(
            report["unassigned"].as_array().map(Vec::len),
            Some(1),
            "{fault:?}: {report}"
        );
        // The outcome the caller supplied is the only place the answer
        // could be echoed from; the forecast's own was never decrypted.
        assert!(!reply.text.contains("on_time"), "{fault:?}: {report}");
        assert!(!reply.text.contains("\"answer\""), "{fault:?}: {report}");
    }
    // Two artifacts per call, each asked of drand once.
    assert_eq!(world.lock().drand_requests, 4);

    serve_the_beacon(&world);
    let report = agent.call("verify_forecast_series", &arguments).ok();
    assert_eq!(report["manifest"]["state"], "valid", "{report}");
    assert_eq!(report["complete"], true, "{report}");
    assert_eq!(report["slots"][0]["status"], "on_time", "{report}");
    assert_eq!(report["slots"][0]["counted_tx_id"], forecast_tx);
    assert_eq!(report["slots"][0]["outcome"]["result"], "match");
    // Only now is the forecast's own answer in the report.
    assert_eq!(report["slots"][0]["entries"][0]["answer"], ANSWER);
    assert_eq!(world.lock().drand_requests, 6);

    // Three calls, two counted reads each, in order: manifest, forecast.
    let per_call = [counted_read(&manifest_tx), counted_read(&forecast_tx)];
    assert_worker_saw(
        &world,
        &[per_call.clone(), per_call.clone(), per_call].concat(),
    );
    assert_eq!(world.lock().authenticated_reads, 6);
    assert_eq!(world.lock().anonymous_reads, 0);
    assert_no_local_state(&agent);
}
