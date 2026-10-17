// allow-test-network: loopback mocks only (see tests/support/mod.rs)
//! Public mode through all three tools, run against the real `qub-mcp`
//! binary: `create_qub` with an explicit `visibility`, and `read_qub` /
//! `check_status` on public artifacts by URL or transaction id with no
//! wrapper key — before and after reveal — alongside the private equivalents
//! with the correct, a missing and a wrong key.
//!
//! The second half is about what a result may claim. `timing` is reported
//! from what gateways qub does not run say about the qub's own storage
//! transaction, and every way that evidence can be absent, late, altered or
//! contradictory is driven here: none of them may produce a pre-deadline
//! verdict.
//!
//! One thing these tests cannot do, and do not pretend to: take a single
//! artifact from locked to revealed. That needs a drand beacon that does not
//! exist yet, which nothing offline can supply. The locked half runs on
//! artifacts the binary itself creates; the revealed half on artifacts sealed
//! by the same `qub_core::seal` to a real elapsed round. The same-artifact
//! run belongs to the live staging lane.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use qub_core::export::QubBundle;
use qub_core::wire::SealedQubCbor;
use qub_core::wrapper::OuterWrapperCbor;
use serde_json::{Value, json};
use support::{
    Agent, MARGIN, MIN_CONFIRMATIONS, UploadFault, View, World, block_hash_at, elapsed_round, now,
    seal_revealed_private, seal_revealed_public,
};

const KEY: &str = "qub_sk_trial_public_mode";
/// A deadline no block in these tests comes near (2100-01-01).
const FAR_FUTURE: i64 = 4_102_444_800;

fn world_and_agent() -> (World, Agent) {
    let world = World::start(KEY);
    let agent = Agent::new(&world, Some(KEY));
    (world, agent)
}

fn create(agent: &Agent, body: &str, visibility: Option<&str>) -> Value {
    let mut arguments = json!({ "body": body, "unlock_at": now() + 3600 });
    if let Some(visibility) = visibility {
        arguments["visibility"] = json!(visibility);
    }
    agent.call("create_qub", &arguments).ok()
}

fn tx(result: &Value) -> String {
    result["tx_id"].as_str().expect("tx_id").to_owned()
}

// ---------------------------------------------------------------------------
// create_qub
// ---------------------------------------------------------------------------

/// An explicit public create uploads the bare sealed qub, marked public,
/// and returns a keyless link; the default stays private and wrapped.
#[test]
fn public_is_explicit_and_private_stays_the_default() {
    let (world, agent) = world_and_agent();

    let public = create(&agent, "a public forecast", Some("public"));
    assert_eq!(public["visibility"], "public");
    assert_eq!(public["wrapper_key_b64url"], Value::Null);
    let public_url = public["delivery_url"].as_str().unwrap();
    assert!(
        !public_url.contains('#'),
        "public link has no fragment: {public_url}"
    );
    assert_eq!(public_url, world.delivery_url(&tx(&public)));
    assert!(
        public["evidence_note"]
            .as_str()
            .unwrap()
            .contains("not yet independent evidence")
    );

    let private = create(&agent, "a private note", None);
    assert_eq!(private["visibility"], "private");
    let key = private["wrapper_key_b64url"]
        .as_str()
        .expect("private has a key");
    assert_eq!(
        private["delivery_url"].as_str().unwrap(),
        format!("{}#{key}", world.delivery_url(&tx(&private)))
    );
    let explicit = create(&agent, "another private note", Some("private"));
    assert_eq!(explicit["visibility"], "private");

    assert_eq!(world.lock().publications, 3);
    let uploads = world.lock().uploads.clone();
    let [public_upload, private_upload, explicit_upload] = &uploads[..] else {
        panic!("expected three uploads, saw {}", uploads.len());
    };
    // Public: `is_public: true`, and the bytes are a bare sealed qub whose
    // own visibility byte says public.
    assert_eq!(public_upload.is_public, Some(true));
    let sealed = SealedQubCbor::from_encoded(public_upload.bytes.clone())
        .unwrap()
        .parse()
        .expect("public upload is a bare SealedQubCbor");
    assert_eq!(sealed.visibility(), qub_core::types::VISIBILITY_PUBLIC);
    assert!(
        OuterWrapperCbor::from_encoded(public_upload.bytes.clone())
            .unwrap()
            .parse()
            .is_err(),
        "a public upload must not be wrapped"
    );
    // Private: no `is_public` member at all, and the bytes are a wrapper.
    for upload in [private_upload, explicit_upload] {
        assert_eq!(upload.is_public, None);
        assert!(
            OuterWrapperCbor::from_encoded(upload.bytes.clone())
                .unwrap()
                .parse()
                .is_ok(),
            "a private upload is an OuterWrapper"
        );
        assert!(
            SealedQubCbor::from_encoded(upload.bytes.clone())
                .unwrap()
                .parse()
                .is_err(),
            "a private upload must not be readable as a sealed qub"
        );
    }
}

/// `visibility` takes exactly two values. Anything else publishes nothing.
#[test]
fn an_unrecognised_visibility_publishes_nothing() {
    let (world, agent) = world_and_agent();
    for bad in [
        json!("Public"),
        json!("PUBLIC"),
        json!(true),
        json!(""),
        json!(null),
    ] {
        let reply = agent.call(
            "create_qub",
            &json!({ "body": "x", "unlock_at": now() + 3600, "visibility": bad }),
        );
        assert!(reply.is_error, "{bad}: {}", reply.text);
        assert!(
            reply.text.contains("visibility must be"),
            "{bad}: {}",
            reply.text
        );
    }
    assert_eq!(world.lock().publications, 0);
    assert_eq!(world.lock().uploads.len(), 0);
}

/// The mode is part of the operation: the same body asked for publicly and
/// privately are two operations, a repeat of either resumes that one, and
/// an `operation_id` cannot be reused across modes.
#[test]
fn visibility_cannot_silently_change_between_calls() {
    let (world, agent) = world_and_agent();
    let unlock_at = now() + 3600;
    let call = |visibility: &str, operation_id: Option<&str>| {
        let mut arguments =
            json!({ "body": "same body", "unlock_at": unlock_at, "visibility": visibility });
        if let Some(id) = operation_id {
            arguments["operation_id"] = json!(id);
        }
        agent.call("create_qub", &arguments)
    };

    let public = call("public", None).ok();
    let private = call("private", None).ok();
    assert_ne!(public["operation_id"], private["operation_id"]);
    assert_ne!(tx(&public), tx(&private));
    assert_eq!(world.lock().publications, 2);

    // Repeating each resumes its own operation: same qub, nothing new.
    let again = call("public", None).ok();
    assert_eq!(again["resumed"], true);
    assert_eq!(tx(&again), tx(&public));
    assert_eq!(again["visibility"], "public");
    assert_eq!(again["wrapper_key_b64url"], Value::Null);
    let again = call("private", None).ok();
    assert_eq!(tx(&again), tx(&private));
    assert_eq!(again["wrapper_key_b64url"], private["wrapper_key_b64url"]);
    assert_eq!(world.lock().publications, 2);

    // An explicit id names one request; the other mode is a conflict.
    let pinned = call("public", Some("pinned-operation")).ok();
    assert_eq!(pinned["visibility"], "public");
    let conflict = call("private", Some("pinned-operation"));
    assert_eq!(conflict.error_code(), "operation_id_conflict");
    assert_eq!(world.lock().publications, 3);

    let pending = agent.call("list_pending_operations", &json!({})).ok();
    assert_eq!(pending["pending"], json!([]));
}

/// A public create survives a lost acknowledgement like a private one: the
/// rerun recovers the same publication through the operation lookup.
#[test]
fn a_public_create_resumes_after_a_lost_acknowledgement() {
    let (world, agent) = world_and_agent();
    world.lock().upload_faults.push(UploadFault::CommitThenDrop);
    let arguments =
        json!({ "body": "lost ack", "unlock_at": now() + 3600, "visibility": "public" });

    let first = agent.call("create_qub", &arguments);
    assert_eq!(first.error_code(), "upload_failed");
    let listed = agent.call("list_pending_operations", &json!({})).ok();
    assert_eq!(listed["pending"][0]["visibility"], "public");
    assert_eq!(listed["pending"][0]["state"], "sent");

    let resumed = agent.call("create_qub", &arguments).ok();
    assert_eq!(resumed["resumed"], true);
    assert_eq!(resumed["visibility"], "public");
    assert!(!resumed["delivery_url"].as_str().unwrap().contains('#'));
    assert_eq!(world.lock().publications, 1, "one publication, not two");
    assert_eq!(world.lock().uploads.len(), 1, "the upload was not re-sent");
}

/// A server refusal reaches the caller with the server's code and wait
/// hint, and the operation resumes once the limit has passed.
#[test]
fn a_rate_limited_create_reports_the_wait_and_resumes() {
    let (world, agent) = world_and_agent();
    world.lock().upload_faults.push(UploadFault::RateLimited(7));
    let arguments =
        json!({ "body": "rate limited", "unlock_at": now() + 3600, "visibility": "public" });

    let refused = agent.call("create_qub", &arguments);
    assert_eq!(refused.error_code(), "upload_rejected");
    let error = refused.json();
    assert_eq!(error["status"], 429);
    assert_eq!(error["server_code"], "TRIAL_RATE_LIMITED");
    assert_eq!(error["retry_after_secs"], 7);
    assert_eq!(world.lock().publications, 0);

    let resumed = agent.call("create_qub", &arguments).ok();
    assert_eq!(resumed["operation_id"], error["operation_id"]);
    assert_eq!(world.lock().publications, 1);
}

/// The eleventh publication is refused by the server and nothing is stored;
/// what was already published stays readable.
#[test]
fn the_eleventh_publication_is_refused() {
    let (world, agent) = world_and_agent();
    world.lock().publication_limit = 2;
    let first = create(&agent, "one", Some("public"));
    create(&agent, "two", Some("public"));
    let refused = agent.call(
        "create_qub",
        &json!({ "body": "three", "unlock_at": now() + 3600, "visibility": "public" }),
    );
    assert_eq!(refused.error_code(), "upload_rejected");
    assert_eq!(refused.json()["server_code"], "TRIAL_QUBS_EXHAUSTED");
    assert_eq!(refused.json()["status"], 402);
    assert_eq!(world.lock().publications, 2);
    assert_eq!(world.lock().artifacts.len(), 2);

    let status = agent
        .call("check_status", &json!({ "tx_id": tx(&first) }))
        .ok();
    assert_eq!(status["status"], "locked");
}

// ---------------------------------------------------------------------------
// read_qub / check_status on what the binary created (still locked)
// ---------------------------------------------------------------------------

/// Both read tools take a public qub by fragment-less URL or by bare
/// transaction id, with no key, and say it is locked and public.
#[test]
fn both_tools_read_a_locked_public_qub_without_a_key() {
    let (world, agent) = world_and_agent();
    let created = create(&agent, "sealed until later", Some("public"));
    let tx_id = tx(&created);
    world.mine(&tx_id, now() - 10_000);

    let forms = [
        json!({ "delivery_url": created["delivery_url"] }),
        json!({ "tx_id": tx_id }),
    ];
    for tool in ["check_status", "read_qub"] {
        for arguments in &forms {
            let result = agent.call(tool, arguments).ok();
            assert_eq!(result["status"], "locked", "{tool} {arguments}");
            assert_eq!(result["visibility"], "public", "{tool} {arguments}");
            assert_eq!(result["tx_id"], tx_id, "{tool} {arguments}");
            assert_eq!(result["qub_id"], created["qub_id"], "{tool} {arguments}");
            assert_eq!(
                result["unlock_at"], created["unlock_at"],
                "{tool} {arguments}"
            );
            assert!(result["time_remaining_seconds"].as_i64().unwrap() > 0);
            assert_eq!(result["timing"]["state"], "evidenced", "{tool} {arguments}");
            assert!(result.get("note").is_none(), "{tool} {arguments}");
            // Locked means locked: no content in either tool's answer.
            assert!(result.get("body").is_none(), "{tool} {arguments}");
            assert!(
                result.get("qub_bundle_b64url").is_none(),
                "{tool} {arguments}"
            );
        }
    }
    let read = agent.call("read_qub", &forms[1]).ok();
    assert_eq!(read["content"], json!({ "state": "locked" }));
    // A locked qub needs no beacon: drand was never asked.
    assert_eq!(world.lock().drand_requests, 0);
    // Each call was one counted, authenticated read.
    assert_eq!(world.lock().authenticated_reads, 5);
    assert_eq!(world.lock().anonymous_reads, 0);
}

/// A key supplied for a public qub is reported as unnecessary, not obeyed.
#[test]
fn a_key_supplied_for_a_public_qub_is_ignored_and_said_so() {
    let (_world, agent) = world_and_agent();
    let created = create(&agent, "public", Some("public"));
    let spare = BASE64URL.encode([7u8; 32]);
    for arguments in [
        json!({ "tx_id": tx(&created), "key_base64url": spare }),
        json!({ "delivery_url": format!("{}#{spare}", created["delivery_url"].as_str().unwrap()) }),
    ] {
        let status = agent.call("check_status", &arguments).ok();
        assert_eq!(status["visibility"], "public");
        assert!(
            status["note"].as_str().unwrap().contains("ignored"),
            "{status}"
        );
    }
}

/// Making the key optional for public qubs must not open private ones: the
/// correct key works, a missing key is refused, a wrong key fails.
#[test]
fn a_private_qub_still_needs_its_key() {
    let (world, agent) = world_and_agent();
    let created = create(&agent, "private", None);
    let tx_id = tx(&created);
    let key = created["wrapper_key_b64url"].as_str().unwrap();
    // Even a perfectly mined transaction earns a private qub no timing.
    world.mine(&tx_id, now() - 10_000);
    let wrong = BASE64URL.encode([9u8; 32]);

    for tool in ["check_status", "read_qub"] {
        for arguments in [
            json!({ "delivery_url": created["delivery_url"] }),
            json!({ "tx_id": tx_id, "key_base64url": key }),
        ] {
            let result = agent.call(tool, &arguments).ok();
            assert_eq!(result["status"], "locked", "{tool}");
            assert_eq!(result["visibility"], "private", "{tool}");
            assert_eq!(result["timing"]["state"], "unsupported_private", "{tool}");
            assert!(result["timing"].get("block_time").is_none(), "{tool}");
        }
        for arguments in [
            json!({ "tx_id": tx_id }),
            json!({ "delivery_url": world.delivery_url(&tx_id) }),
        ] {
            let refused = agent.call(tool, &arguments);
            assert_eq!(
                refused.error_code(),
                "wrapper_key_required",
                "{tool} {arguments}"
            );
            // Nothing about the qub leaks through the refusal.
            assert!(!refused.text.contains(created["qub_id"].as_str().unwrap()));
        }
        let failed = agent.call(tool, &json!({ "tx_id": tx_id, "key_base64url": wrong }));
        assert_eq!(failed.error_code(), "unwrap_failed", "{tool}");
    }
    // A private qub never causes a gateway lookup.
    assert_eq!(world.lock().gateway_requests, Vec::<String>::new());

    // A deadline cannot be met by a private qub.
    let asked = agent
        .call(
            "check_status",
            &json!({ "delivery_url": created["delivery_url"], "deadline": now() + 99_999 }),
        )
        .ok();
    assert_eq!(asked["timing"]["deadline"]["verdict"], "unknown");
}

// ---------------------------------------------------------------------------
// Timing evidence: every state, on a qub the binary created
// ---------------------------------------------------------------------------

/// A helper for the timing scenarios: a locked public qub and its checker.
struct Published {
    world: World,
    agent: Agent,
    tx_id: String,
}

impl Published {
    fn new() -> Self {
        let (world, agent) = world_and_agent();
        let tx_id = tx(&create(&agent, "timing subject", Some("public")));
        Self {
            world,
            agent,
            tx_id,
        }
    }

    /// `check_status` and `read_qub` must agree on timing; return it.
    fn timing(&self, deadline: Option<i64>) -> Value {
        let mut arguments = json!({ "tx_id": self.tx_id });
        if let Some(deadline) = deadline {
            arguments["deadline"] = json!(deadline);
        }
        let status = self.agent.call("check_status", &arguments).ok();
        let read = self.agent.call("read_qub", &arguments).ok();
        assert_eq!(status["timing"], read["timing"], "the two tools must agree");
        status["timing"].clone()
    }

    fn verdict(&self, deadline: i64) -> String {
        self.timing(Some(deadline))["deadline"]["verdict"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// Accepted by the service and not yet on chain is not evidence of anything,
/// however far in the future the deadline is.
#[test]
fn an_accepted_upload_is_not_timing_evidence() {
    let published = Published::new();
    let timing = published.timing(Some(FAR_FUTURE));
    assert_eq!(timing["state"], "not_on_chain");
    assert_eq!(timing["deadline"]["verdict"], "unknown");
    assert!(timing.get("block_time").is_none());
    assert!(
        timing["claim"]
            .as_str()
            .unwrap()
            .starts_with("No independent existence time")
    );
    assert_eq!(timing["basis"], "arweave_storage_transaction");
    assert_eq!(timing["gateways"].as_array().unwrap().len(), 3);
}

#[test]
fn the_states_between_accepted_and_evidenced_carry_no_time() {
    let published = Published::new();
    let block_time = now() - 10_000;
    let mined = || View::mined(block_time);
    let shallow = View::mined_with(block_time, MIN_CONFIRMATIONS - 1);
    let cases: [([View; 3], &str); 6] = [
        ([View::Pending, View::Pending, View::Unknown], "pending"),
        ([mined(), View::Unknown, View::Unknown], "pending"),
        ([mined(), shallow, View::Unknown], "pending"),
        ([mined(), View::Down, View::Down], "unavailable"),
        ([View::Down, View::Down, View::Down], "unavailable"),
        ([View::Down, View::Down, View::Unknown], "unavailable"),
    ];
    for (views, state) in cases {
        published.world.set_views(&published.tx_id, views.clone());
        let timing = published.timing(Some(FAR_FUTURE));
        assert_eq!(timing["state"], state, "{views:?}");
        assert_eq!(timing["deadline"]["verdict"], "unknown", "{views:?}");
        assert!(timing.get("block_time").is_none(), "{views:?}");
    }
}

/// Two gateways agreeing, deep enough, is evidence — and the deadline
/// comparison is strict and keeps the policy margin.
#[test]
fn agreed_blocks_are_evidence_and_the_deadline_is_strict() {
    let published = Published::new();
    let block_time = now() - 10_000;
    published.world.set_views(
        &published.tx_id,
        [View::mined(block_time), View::mined(block_time), View::Down],
    );
    let timing = published.timing(None);
    assert_eq!(timing["state"], "evidenced");
    assert_eq!(timing["block_time"], block_time);
    assert_eq!(timing["confirmations"], 40);
    assert_eq!(timing["agreeing_gateways"].as_array().unwrap().len(), 2);
    assert_eq!(timing["policy"]["status"], "provisional");
    assert!(timing.get("deadline").is_none());
    assert!(
        timing["claim"]
            .as_str()
            .unwrap()
            .contains("If those gateways report the Arweave chain correctly")
    );
    // Evidenced timing is also what ties the bytes read to the id asked for.
    for tool in ["check_status", "read_qub"] {
        let result = published
            .agent
            .call(tool, &json!({ "tx_id": published.tx_id }))
            .ok();
        assert_eq!(result["tx_binding"], "evidenced", "{tool}");
    }

    assert_eq!(published.verdict(block_time + MARGIN + 1), "before");
    assert_eq!(published.verdict(block_time + MARGIN), "too_close");
    assert_eq!(published.verdict(block_time + 1), "too_close");
    // Stored at, or after, the deadline: late.
    assert_eq!(published.verdict(block_time), "not_before");
    assert_eq!(published.verdict(block_time - 3600), "not_before");
}

/// Gateways that disagree are not outvoted.
#[test]
fn disagreeing_gateways_are_a_conflict() {
    let published = Published::new();
    let block_time = now() - 10_000;
    published.world.set_views(
        &published.tx_id,
        [
            View::mined(block_time),
            View::mined(block_time),
            // A third gateway places it in an earlier block.
            View::mined_with(block_time - 5000, 99),
        ],
    );
    let timing = published.timing(Some(FAR_FUTURE));
    assert_eq!(timing["state"], "conflict");
    assert_eq!(timing["deadline"]["verdict"], "unknown");
    assert!(timing.get("block_time").is_none());
}

/// The bytes the service now serves are not the bytes its transaction
/// committed to: an altered artifact is invalid, however well mined.
#[test]
fn an_altered_artifact_is_invalid() {
    let published = Published::new();
    published.world.mine(&published.tx_id, now() - 10_000);
    assert_eq!(published.timing(None)["state"], "evidenced");

    // Swap in another public qub sealed by the same code: it parses, it is
    // public, it unlocks later — and it is not what the transaction stores.
    let other = tx(&create(
        &published.agent,
        "a different forecast",
        Some("public"),
    ));
    let replacement = published.world.artifact(&other).bytes;
    published
        .world
        .lock()
        .artifacts
        .get_mut(&published.tx_id)
        .unwrap()
        .served = replacement;

    // `check_status` shows no content, so it reports the mismatch.
    let arguments = json!({ "tx_id": published.tx_id, "deadline": FAR_FUTURE });
    let status = published.agent.call("check_status", &arguments).ok();
    assert_eq!(status["tx_binding"], "mismatch");
    let timing = &status["timing"];
    assert_eq!(timing["state"], "invalid");
    assert_eq!(timing["deadline"]["verdict"], "unknown");
    assert!(timing.get("block_time").is_none());

    // `read_qub` would be presenting those bytes as this transaction's
    // content. It refuses, and returns none of them.
    let read = published.agent.call("read_qub", &arguments);
    assert_eq!(read.error_code(), "artifact_mismatch");
    let refusal = read.json();
    assert_eq!(refusal["tx_id"], published.tx_id);
    assert_eq!(refusal["timing"]["state"], "invalid");
    for absent in ["body", "content", "qub_bundle_b64url", "status"] {
        assert!(refusal.get(absent).is_none(), "{absent} leaked: {refusal}");
    }
    assert!(!read.text.contains("a different forecast"));
}

/// Until the chain ties the bytes to the id, the result says so: content
/// can verify against its own commitment and still not be what `tx_id`
/// stores.
#[test]
fn unbound_bytes_are_reported_as_not_established() {
    let published = Published::new();
    for tool in ["check_status", "read_qub"] {
        let unmined = published
            .agent
            .call(tool, &json!({ "tx_id": published.tx_id }))
            .ok();
        assert_eq!(unmined["timing"]["state"], "not_on_chain", "{tool}");
        assert_eq!(unmined["tx_binding"], "not_established", "{tool}");
        let unchecked = published
            .agent
            .call(
                tool,
                &json!({ "tx_id": published.tx_id, "check_timing": false }),
            )
            .ok();
        assert_eq!(unchecked["tx_binding"], "not_established", "{tool}");
    }
}

/// A service that echoes the caller's `Authorization` header in an error
/// must not get the API key into the tool's output, which an agent keeps.
#[test]
fn a_reflected_api_key_never_reaches_the_tool_result() {
    let published = Published::new();
    published.world.lock().reflect_authorization = true;
    for tool in ["read_qub", "check_status"] {
        let failed = published
            .agent
            .call(tool, &json!({ "tx_id": published.tx_id }));
        assert!(failed.is_error, "{tool}: {}", failed.text);
        // The service's message did come through — minus the key.
        assert!(failed.text.contains("upstream said"), "{}", failed.text);
        assert!(!failed.text.contains(KEY), "{tool} leaked the API key");
        assert!(
            failed.text.contains("[redacted API key]"),
            "{}",
            failed.text
        );
    }
}

/// `check_timing: false` asks no gateway and says so.
#[test]
fn timing_lookups_can_be_skipped_and_never_use_the_api_key() {
    let published = Published::new();
    published.world.mine(&published.tx_id, now() - 10_000);
    let skipped = published
        .agent
        .call(
            "check_status",
            &json!({ "tx_id": published.tx_id, "check_timing": false, "deadline": FAR_FUTURE }),
        )
        .ok();
    assert_eq!(skipped["timing"]["state"], "not_checked");
    assert_eq!(skipped["timing"]["deadline"]["verdict"], "unknown");
    assert_eq!(
        published.world.lock().gateway_requests,
        Vec::<String>::new()
    );

    // With lookups on, every gateway is asked for status, header and block.
    let block_time = now() - 20_000;
    let block_hash = block_hash_at(block_time);
    published.world.mine(&published.tx_id, block_time);
    published.timing(None);
    let requests = published.world.lock().gateway_requests.clone();
    for index in 0..3 {
        for suffix in [
            format!("{index} /tx/{}/status", published.tx_id),
            format!("{index} /tx/{}", published.tx_id),
            format!("{index} /block/hash/{block_hash}"),
        ] {
            assert!(requests.contains(&suffix), "missing {suffix}: {requests:?}");
        }
    }
}

/// A gateway list the operator got wrong yields no evidence, not a guess.
#[test]
fn a_misconfigured_gateway_list_establishes_nothing() {
    let (world, agent) = world_and_agent();
    let tx_id = tx(&create(&agent, "subject", Some("public")));
    world.mine(&tx_id, now() - 10_000);
    for bad in [
        "http://gateway.example",
        "https://gateway.example/path",
        "nope",
    ] {
        let agent = Agent::new(&world, Some(KEY)).with_env("QUB_ARWEAVE_GATEWAYS", bad);
        let status = agent
            .call(
                "check_status",
                &json!({ "tx_id": tx_id, "deadline": FAR_FUTURE }),
            )
            .ok();
        assert_eq!(status["timing"]["state"], "unavailable", "{bad}");
        assert_eq!(status["timing"]["deadline"]["verdict"], "unknown", "{bad}");
        assert!(
            status["timing"]["reason"]
                .as_str()
                .unwrap()
                .contains("QUB_ARWEAVE_GATEWAYS"),
            "{bad}"
        );
    }
    // One gateway named three times is still one gateway.
    let only = world.gateway_urls[0].clone();
    let agent = Agent::new(&world, Some(KEY))
        .with_env("QUB_ARWEAVE_GATEWAYS", &format!("{only},{only},{only}"));
    let status = agent.call("check_status", &json!({ "tx_id": tx_id })).ok();
    assert_eq!(status["timing"]["state"], "unavailable");
    assert_eq!(status["timing"]["gateways"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// After reveal: real qubs sealed to an elapsed drand round
// ---------------------------------------------------------------------------

/// After reveal both tools work on a public qub without a key: `read_qub`
/// returns verified content and a bundle, `check_status` says unlocked, and
/// the content verdict stands apart from the timing verdict.
#[test]
fn both_tools_read_a_revealed_public_qub_without_a_key() {
    let (world, agent) = world_and_agent();
    let round = elapsed_round();
    let tx_id = world.store(seal_revealed_public("the outcome was heads"), true);
    let block_time = round.unlock_at - 20_000;
    world.mine(&tx_id, block_time);

    for arguments in [
        json!({ "tx_id": tx_id }),
        json!({ "delivery_url": world.delivery_url(&tx_id) }),
    ] {
        let status = agent.call("check_status", &arguments).ok();
        assert_eq!(status["status"], "unlocked");
        assert_eq!(status["visibility"], "public");
        assert_eq!(status["time_remaining_seconds"], 0);
        assert_eq!(status["unlock_at"], round.unlock_at);
        assert_eq!(status["drand_round"], round.round);
        assert_eq!(status["timing"]["state"], "evidenced");
        assert!(status.get("body").is_none(), "check_status never decrypts");

        let read = agent.call("read_qub", &arguments).ok();
        assert_eq!(read["status"], "unlocked");
        assert_eq!(read["visibility"], "public");
        assert_eq!(read["content"]["state"], "verified");
        assert_eq!(read["content"]["body_hash_verified"], true);
        assert!(
            read["body"]
                .as_str()
                .unwrap()
                .contains("the outcome was heads"),
            "{read}"
        );
        assert!(
            read["body"]
                .as_str()
                .unwrap()
                .contains("BEGIN USER CONTENT")
        );
        assert_eq!(read["timing"]["state"], "evidenced");
        assert_eq!(read["timing"]["block_time"], block_time);
        assert!(
            read["created_at_note"]
                .as_str()
                .unwrap()
                .contains("not evidence")
        );
        // The bundle is the real thing: it names this transaction and opens
        // to the same sealed qub.
        let bundle = QubBundle::from_cbor(
            &BASE64URL
                .decode(read["qub_bundle_b64url"].as_str().unwrap())
                .unwrap(),
        )
        .expect("bundle parses");
        assert_eq!(bundle.arweave_tx_id(), tx_id);
        assert_eq!(bundle.drand_round(), round.round);
        assert_eq!(
            bundle.sealed_cbor().as_bytes(),
            world.artifact(&tx_id).bytes
        );
    }
    // check_status needed no beacon; each read_qub fetched it once.
    assert_eq!(world.lock().drand_requests, 2);
}

/// Revealed content can be verified and still have no acceptable timing:
/// the two verdicts are independent, in both directions.
#[test]
fn revealed_content_does_not_imply_timing() {
    let (world, agent) = world_and_agent();
    let round = elapsed_round();
    let tx_id = world.store(seal_revealed_public("revealed, timing unknown"), true);
    let read = |deadline: i64| {
        agent
            .call("read_qub", &json!({ "tx_id": tx_id, "deadline": deadline }))
            .ok()
    };

    // Never posted: content verifies, timing does not exist.
    let unposted = read(FAR_FUTURE);
    assert_eq!(unposted["content"]["state"], "verified");
    assert_eq!(unposted["timing"]["state"], "not_on_chain");
    assert_eq!(unposted["timing"]["deadline"]["verdict"], "unknown");

    // Posted only after its own unlock time — a qub anyone could have made
    // once the beacon was public. Still verified content; never "before".
    world.mine(&tx_id, round.unlock_at + 86_400);
    let late = read(round.unlock_at);
    assert_eq!(late["content"]["state"], "verified");
    assert_eq!(late["timing"]["state"], "evidenced");
    assert_eq!(late["timing"]["deadline"]["verdict"], "not_before");

    // Gateways down: content still verifies offline of them.
    world.set_views(&tx_id, [View::Down, View::Down, View::Down]);
    let dark = read(FAR_FUTURE);
    assert_eq!(dark["content"]["state"], "verified");
    assert_eq!(dark["timing"]["state"], "unavailable");
}

/// The private equivalents after reveal: the right key reads, a missing key
/// is refused, a wrong key fails — and no timing is offered.
#[test]
fn a_revealed_private_qub_needs_its_key_and_gets_no_timing() {
    let (world, agent) = world_and_agent();
    let (stored, key) = seal_revealed_private("for the key holder only");
    let tx_id = world.store(stored, false);
    world.mine(&tx_id, elapsed_round().unlock_at - 20_000);
    let wrong = BASE64URL.encode([9u8; 32]);

    let with_key = json!({ "delivery_url": format!("{}#{key}", world.delivery_url(&tx_id)) });
    let read = agent.call("read_qub", &with_key).ok();
    assert_eq!(read["status"], "unlocked");
    assert_eq!(read["visibility"], "private");
    assert_eq!(read["content"]["state"], "verified");
    assert!(
        read["body"]
            .as_str()
            .unwrap()
            .contains("for the key holder only")
    );
    assert_eq!(read["timing"]["state"], "unsupported_private");
    let status = agent.call("check_status", &with_key).ok();
    assert_eq!(status["status"], "unlocked");
    assert_eq!(status["timing"]["state"], "unsupported_private");

    for tool in ["read_qub", "check_status"] {
        let missing = agent.call(tool, &json!({ "tx_id": tx_id }));
        assert_eq!(missing.error_code(), "wrapper_key_required", "{tool}");
        assert!(!missing.text.contains("for the key holder only"), "{tool}");
        let failed = agent.call(tool, &json!({ "tx_id": tx_id, "key_base64url": wrong }));
        assert_eq!(failed.error_code(), "unwrap_failed", "{tool}");
        assert!(!failed.text.contains("for the key holder only"), "{tool}");
    }
    assert_eq!(world.lock().gateway_requests, Vec::<String>::new());
}

/// A beacon that is not the genuine one for the round decrypts nothing.
#[test]
fn a_wrong_drand_signature_reveals_nothing() {
    let (world, agent) = world_and_agent();
    let tx_id = world.store(seal_revealed_public("needs the real beacon"), true);
    world.lock().drand_signature_override = Some("ab".repeat(48));
    let read = agent.call("read_qub", &json!({ "tx_id": tx_id }));
    assert!(read.is_error, "{}", read.text);
    assert!(read.text.contains("unlock failed"), "{}", read.text);
    assert!(!read.text.contains("needs the real beacon"));
    // check_status does not depend on the beacon at all.
    let status = agent.call("check_status", &json!({ "tx_id": tx_id })).ok();
    assert_eq!(status["status"], "unlocked");
}

/// When the trial's reads run out, the credentialed tools fail closed with
/// the server's code and do not fall back to the anonymous route; a
/// recipient with no key can still read and check the same qub.
#[test]
fn exhausted_reads_fail_closed_while_anonymous_verification_survives() {
    let (world, agent) = world_and_agent();
    let tx_id = world.store(seal_revealed_public("still verifiable"), true);
    world.mine(&tx_id, elapsed_round().unlock_at - 20_000);
    world.lock().read_limit = 1;

    assert_eq!(
        agent.call("check_status", &json!({ "tx_id": tx_id })).ok()["status"],
        "unlocked"
    );
    for tool in ["check_status", "read_qub"] {
        let refused = agent.call(tool, &json!({ "tx_id": tx_id }));
        assert_eq!(refused.error_code(), "TRIAL_READS_EXHAUSTED", "{tool}");
    }
    assert_eq!(world.lock().authenticated_reads, 1);
    assert_eq!(world.lock().anonymous_reads, 0, "no anonymous fallback");

    let recipient = Agent::new(&world, None);
    let read = recipient.call("read_qub", &json!({ "tx_id": tx_id })).ok();
    assert_eq!(read["content"]["state"], "verified");
    assert!(read["body"].as_str().unwrap().contains("still verifiable"));
    assert_eq!(read["timing"]["state"], "evidenced");
    assert_eq!(world.lock().anonymous_reads, 1);
    assert_eq!(world.lock().authenticated_reads, 1);
}

/// Bytes that are not a qub are refused by both tools, whatever was sent.
#[test]
fn stored_bytes_that_are_not_a_qub_are_refused() {
    let (world, agent) = world_and_agent();
    let tx_id = world.store(b"<html>gateway error</html>".to_vec(), true);
    for tool in ["check_status", "read_qub"] {
        let refused = agent.call(tool, &json!({ "tx_id": tx_id }));
        assert_eq!(refused.error_code(), "malformed_artifact", "{tool}");
    }
}
