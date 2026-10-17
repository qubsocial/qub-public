// allow-test-network: loopback mocks of Arweave gateways
//! Acceptance tests for `qub-verify --timing`, run against the real binary
//! and in-process HTTP mocks of Arweave gateways bound to `127.0.0.1`.
//!
//! The artifact is real: a public qub sealed to an elapsed drand quicknet
//! round, with that round's beacon (the standalone-viewer fixture), and a
//! storage transaction for exactly those bytes signed by the `arweave-js`
//! reference client (`tests/vectors/arweave_tx_v1.json`). What the mocks
//! stand in for is only what a gateway *reports* about that transaction —
//! which is the one thing the verifier does not check for itself.
//!
//! Each scenario asserts the verdict a recipient would see, and the ones that
//! must never show a pre-deadline result are the point: a transaction that
//! was signed but never published, one mined after the deadline, one that
//! stores other bytes, gateways that disagree, and gateways that cannot be
//! reached.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use qub_core::export::QubBundle;
use qub_core::wire::SealedQubCbor;
use serde_json::{Value, json};

const STANDALONE: &str =
    include_str!("../../../crates/qub-core/tests/vectors/standalone_pipeline_v1.json");
const TX_VECTORS: &str = include_str!("vectors/arweave_tx_v1.json");

const BLOCK_HASH: &str = "w3EayqSpTouZPTkTKaEC2kXQgZj5wQKxae7mbkfxUV0q8Fi8CJw-jacXB85SwoFj";
const OTHER_BLOCK_HASH: &str = "7By4OmqH2Bi57dICCDNXWCnKMgAqbb8HGo3IY3OPhjFpCglx6M3uHTLgXsKMkBvr";
/// Block time the mock gateways report by default.
const BLOCK_TIME: i64 = 1_790_000_000;
/// The provisional policy margin (`TimingPolicy::PROVISIONAL`).
const MARGIN: i64 = 600;

fn json_fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("fixture is valid JSON")
}

/// One case of the standalone-viewer fixture.
fn standalone_case(delivery: &str) -> Value {
    json_fixture(STANDALONE)["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["delivery"] == delivery)
        .cloned()
        .expect("fixture has the case")
}

/// A `.qub` bundle for one fixture case, naming `tx_id` as its storage
/// transaction. Returns the bundle bytes and the qub's unlock time.
fn bundle(delivery: &str, tx_id: &str) -> (Vec<u8>, i64) {
    let case = standalone_case(delivery);
    let hex_of = |name: &str| hex::decode(case[name].as_str().expect(name)).expect("hex");
    let sealed = SealedQubCbor::from_encoded(hex_of("sealed_cbor_hex")).expect("sealed CBOR");
    let bundle =
        QubBundle::new(sealed, hex_of("signature_hex"), tx_id.to_owned()).expect("bundle builds");
    (
        bundle.to_cbor().expect("bundle encodes"),
        case["sealed_unlock_at"].as_i64().expect("unlock_at"),
    )
}

/// The storage transaction of the public fixture qub: `(tx_id, header JSON)`.
fn public_tx() -> (String, String) {
    let header = &json_fixture(TX_VECTORS)["qub_public"]["header"];
    (
        header["id"].as_str().expect("id").to_owned(),
        header.to_string(),
    )
}

/// A signed transaction for unrelated bytes: `(tx_id, header JSON)`.
fn unrelated_tx() -> (String, String) {
    let header = &json_fixture(TX_VECTORS)["signed"][0]["header"];
    (
        header["id"].as_str().expect("id").to_owned(),
        header.to_string(),
    )
}

/// A canned response: status code and body.
type Canned = (u16, String);

/// An in-process gateway: answers each known path with its canned response,
/// anything else with 404. Lives until the test process exits.
fn gateway(routes: HashMap<String, Canned>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback gateway");
    let port = listener.local_addr().expect("local addr").port();
    let routes = Arc::new(routes);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let routes = Arc::clone(&routes);
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                // Drain the headers so the client sees a clean response.
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or_default();
                let (status, body) = routes
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| (404, "Not Found.".to_owned()));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// What one mock gateway reports about a mined transaction.
struct Mined<'a> {
    tx_id: &'a str,
    header: &'a str,
    block_hash: &'a str,
    height: u64,
    block_time: i64,
    confirmations: u64,
    /// Extra bytes in the block response, standing in for the
    /// proof-of-access data a real block header carries.
    block_padding: usize,
}

impl<'a> Mined<'a> {
    const fn new(tx_id: &'a str, header: &'a str) -> Self {
        Self {
            tx_id,
            header,
            block_hash: BLOCK_HASH,
            height: 1_900_000,
            block_time: BLOCK_TIME,
            confirmations: 40,
            block_padding: 0,
        }
    }

    fn gateway(&self) -> String {
        let mut routes = HashMap::new();
        routes.insert(
            format!("/tx/{}/status", self.tx_id),
            (
                200,
                json!({
                    "block_height": self.height,
                    "block_indep_hash": self.block_hash,
                    "number_of_confirmations": self.confirmations,
                })
                .to_string(),
            ),
        );
        routes.insert(format!("/tx/{}", self.tx_id), (200, self.header.to_owned()));
        routes.insert(
            format!("/block/hash/{}", self.block_hash),
            (
                200,
                json!({
                    "height": self.height,
                    "indep_hash": self.block_hash,
                    "timestamp": self.block_time,
                    "txs": ["some-other-transaction", self.tx_id],
                    "poa": "A".repeat(self.block_padding),
                })
                .to_string(),
            ),
        );
        gateway(routes)
    }
}

/// A gateway that has never heard of any transaction.
fn empty_gateway() -> String {
    gateway(HashMap::new())
}

/// A gateway that knows the transaction but has not mined it (HTTP 202).
fn pending_gateway(tx_id: &str) -> String {
    gateway(HashMap::from([(
        format!("/tx/{tx_id}/status"),
        (202, "Pending".to_owned()),
    )]))
}

/// A loopback origin nothing listens on.
fn dead_gateway() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

static NEXT_FILE: AtomicU32 = AtomicU32::new(0);

/// Write `bytes` to a unique temporary `.qub` path.
fn temp_bundle(bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "qub-verify-timing-{}-{}.qub",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, bytes).expect("write bundle");
    path
}

/// The outcome of one `qub-verify` run.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{}", self.stdout))
    }
}

fn finish(output: &Output) -> Run {
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A deadline no block in these tests comes near (2100-01-01).
const FAR_FUTURE: i64 = 4_102_444_800;

/// A `qub-verify` command that ignores any proxy configured in the
/// developer's environment, so loopback gateways are reached directly.
fn verifier() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_qub-verify"));
    for var in PROXY_VARS {
        command.env_remove(var);
    }
    command.env("NO_PROXY", "*").env("no_proxy", "*");
    command
}

const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// A loopback "proxy" that only counts the connections made to it and
/// closes them. With every proxy variable pointed here, any network request
/// the binary makes — to any host — shows up as a connection.
fn connection_counter() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind counter");
    let port = listener.local_addr().expect("addr").port();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    thread::spawn(move || {
        for stream in listener.incoming() {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (format!("http://127.0.0.1:{port}"), count)
}

/// Run the real binary on a bundle of the `delivery` fixture case naming
/// `tx_id`, with `--timing` against `gateways` plus `extra` arguments.
fn verify(delivery: &str, tx_id: &str, gateways: &[String], extra: &[&str]) -> Run {
    let (bytes, unlock_at) = bundle(delivery, tx_id);
    let path = temp_bundle(&bytes);
    let mut command = verifier();
    command
        .arg(&path)
        .arg("--now")
        .arg((unlock_at + 10).to_string())
        .arg("--timing");
    for gateway in gateways {
        command.arg("--gateway").arg(gateway);
    }
    command.args(extra);
    let output = command.output().expect("spawn qub-verify");
    let _ = std::fs::remove_file(&path);
    finish(&output)
}

fn deadline(at: i64) -> [String; 2] {
    ["--deadline".to_owned(), at.to_string()]
}

fn verify_with_deadline(tx_id: &str, gateways: &[String], at: i64, json: bool) -> Run {
    let [flag, value] = deadline(at);
    let mut extra = vec![flag.as_str(), value.as_str()];
    if json {
        extra.push("--json");
    }
    verify("bare", tx_id, gateways, &extra)
}

/// Three gateways that agree the public fixture's transaction is mined.
fn agreeing_gateways(tx_id: &str, header: &str) -> Vec<String> {
    (0..3)
        .map(|_| Mined::new(tx_id, header).gateway())
        .collect()
}

#[test]
fn evidenced_before_the_deadline_verifies() {
    let (tx_id, header) = public_tx();
    let gateways = agreeing_gateways(&tx_id, &header);

    let run = verify_with_deadline(&tx_id, &gateways, BLOCK_TIME + MARGIN + 1, true);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["verified"], true);
    assert_eq!(report["content_verified"], true);
    assert_eq!(report["timing"]["state"], "evidenced");
    assert_eq!(report["timing"]["basis"], "arweave_storage_transaction");
    assert_eq!(report["timing"]["tx_id"], tx_id);
    assert_eq!(report["timing"]["block_time"], BLOCK_TIME);
    assert_eq!(report["timing"]["confirmations"], 40);
    assert_eq!(
        report["timing"]["agreeing_gateways"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(report["timing"]["deadline"]["verdict"], "before");
    assert_eq!(report["timing"]["policy"]["status"], "provisional");

    // The same run as text names the state, the bound and the assumption.
    let [flag, value] = deadline(BLOCK_TIME + MARGIN + 1);
    let run = verify("bare", &tx_id, &gateways, &[&flag, &value]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("VERDICT: VERIFIED"), "{}", run.stdout);
    assert!(run.stdout.contains("evidenced"), "{}", run.stdout);
    assert!(
        run.stdout.contains(&BLOCK_TIME.to_string()),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("before the deadline"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("If those gateways report the Arweave chain correctly"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("not known to be independent of one another"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("provisional"), "{}", run.stdout);
    // The verdict is stated before the content and again after it, and the
    // content is fenced line by line.
    let verdicts: Vec<&str> = run
        .stdout
        .lines()
        .filter(|line| line.starts_with("VERDICT:"))
        .collect();
    assert_eq!(verdicts, ["VERDICT: VERIFIED", "VERDICT: VERIFIED"]);
    assert_eq!(run.stdout.lines().last(), Some("VERDICT: VERIFIED"));
}

/// An error message can quote the bundle. A map with one text key twice is
/// reported by naming the key — which is any text the bundle's author likes.
/// None of it may reach the terminal raw, on stderr any more than stdout.
#[test]
fn a_hostile_bundle_cannot_redraw_the_error_either() {
    let key = "\u{1b}[2J\u{1b}[HVERDICT: VERIFIED\n  timing          evidenced\n\u{1b}[8m";
    let mut bundle = vec![0xA2]; // a CBOR map of two entries
    for _ in 0..2 {
        bundle.push(0x78); // text string, one-byte length
        bundle.push(u8::try_from(key.len()).expect("short key"));
        bundle.extend_from_slice(key.as_bytes());
        bundle.push(0x00); // value: 0
    }
    let path = temp_bundle(&bundle);
    for extra in [&[][..], &["--json"][..]] {
        let output = verifier()
            .arg(&path)
            .args(extra)
            .output()
            .expect("spawn qub-verify");
        let run = finish(&output);
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        assert!(run.stdout.is_empty(), "{}", run.stdout);
        assert!(
            !run.stderr.chars().any(|c| c.is_control() && c != '\n'),
            "a control character reached the terminal: {:?}",
            run.stderr
        );
        assert_eq!(run.stderr.lines().count(), 1, "{:?}", run.stderr);
        // The key is still there to be read, as inert text.
        assert!(run.stderr.contains("\\u{1b}[2J"), "{}", run.stderr);
    }
    let _ = std::fs::remove_file(&path);
}

/// A bundle is untrusted input, and its transaction id is any string. One
/// carrying terminal escapes and a forged verdict must come out as inert
/// text on its own row: no escape byte reaches the terminal and no forged
/// line can pass for a line of the report.
#[test]
fn a_hostile_transaction_id_cannot_redraw_the_report() {
    let hostile = "\u{1b}[2J\u{1b}[HVERDICT: VERIFIED\n  timing          evidenced\n  deadline        \
                   1800000000: before the deadline\r\n\u{1b}[8m\u{202e}";
    let (real_tx, header) = public_tx();
    let gateways = agreeing_gateways(&real_tx, &header);
    let [flag, value] = deadline(BLOCK_TIME + MARGIN + 1);

    let run = verify("bare", hostile, &gateways, &[&flag, &value]);
    // No usable transaction id, so no time is established and the deadline
    // is unmet: the real verdict is NOT VERIFIED.
    assert_eq!(run.code, Some(1), "{}", run.stdout);
    assert!(
        !run.stdout.chars().any(|c| c.is_control() && c != '\n'),
        "a control character reached the terminal: {:?}",
        run.stdout
    );
    assert!(!run.stdout.contains('\u{202e}'));
    let verdicts: Vec<&str> = run
        .stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("VERDICT:"))
        .collect();
    assert_eq!(
        verdicts,
        ["VERDICT: NOT VERIFIED", "VERDICT: NOT VERIFIED"],
        "{}",
        run.stdout
    );
    // The forged text is still there to be read — on the id's own row.
    let id_row = run
        .stdout
        .lines()
        .find(|line| line.trim_start().starts_with("arweave_tx_id"))
        .expect("the id is reported");
    assert!(id_row.contains("\\u{1b}[2J"), "{id_row}");
    assert!(id_row.contains("before the deadline"), "{id_row}");
    assert_eq!(
        run.stdout
            .lines()
            .filter(|line| line.contains("before the deadline"))
            .count(),
        1,
        "{}",
        run.stdout
    );

    // The same bundle with no network step at all.
    let (bytes, unlock_at) = bundle("bare", hostile);
    let path = temp_bundle(&bytes);
    let output = verifier()
        .arg(&path)
        .args(["--now", &(unlock_at + 10).to_string()])
        .output()
        .expect("spawn qub-verify");
    let _ = std::fs::remove_file(&path);
    let offline = finish(&output);
    assert!(
        !offline.stdout.chars().any(|c| c.is_control() && c != '\n'),
        "{:?}",
        offline.stdout
    );
    assert_eq!(
        offline
            .stdout
            .lines()
            .filter(|line| line.contains("evidenced"))
            .count(),
        1,
        "only the id's own row may carry the forged word: {}",
        offline.stdout
    );
}

#[test]
fn timing_without_a_deadline_reports_the_bound_and_verifies() {
    let (tx_id, header) = public_tx();
    let run = verify(
        "bare",
        &tx_id,
        &agreeing_gateways(&tx_id, &header),
        &["--json"],
    );
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["verified"], true);
    assert_eq!(report["timing"]["state"], "evidenced");
    assert!(report["timing"].get("deadline").is_none());
}

/// A block at, or after, the deadline is never "before" — and neither is one
/// inside the margin.
#[test]
fn a_late_or_too_close_block_fails_the_deadline() {
    let (tx_id, header) = public_tx();
    let gateways = agreeing_gateways(&tx_id, &header);
    for (at, verdict) in [
        (BLOCK_TIME, "not_before"),
        (BLOCK_TIME - 500, "not_before"),
        (BLOCK_TIME + 1, "too_close"),
        (BLOCK_TIME + MARGIN, "too_close"),
    ] {
        let run = verify_with_deadline(&tx_id, &gateways, at, true);
        assert_eq!(run.code, Some(1), "deadline {at}: {}", run.stdout);
        let report = run.json();
        assert_eq!(report["verified"], false, "deadline {at}");
        // The content is still what it claims to be; only the deadline fails.
        assert_eq!(report["content_verified"], true, "deadline {at}");
        assert_eq!(report["timing"]["state"], "evidenced", "deadline {at}");
        assert_eq!(
            report["timing"]["deadline"]["verdict"], verdict,
            "deadline {at}"
        );
    }
    let run = verify_with_deadline(&tx_id, &gateways, BLOCK_TIME, false);
    assert_eq!(run.code, Some(1));
    assert!(
        run.stdout.contains("VERDICT: NOT VERIFIED"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("NOT before the deadline"),
        "{}",
        run.stdout
    );
}

/// The transaction verifies, commits to exactly these bytes — and no gateway
/// has ever seen it. Signed-but-unpublished establishes no time.
#[test]
fn a_signed_but_unpublished_transaction_never_meets_a_deadline() {
    let (tx_id, _header) = public_tx();
    let gateways = vec![empty_gateway(), empty_gateway(), empty_gateway()];

    let run = verify_with_deadline(&tx_id, &gateways, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["verified"], false);
    assert_eq!(report["content_verified"], true);
    assert_eq!(report["timing"]["state"], "not_on_chain");
    assert_eq!(report["timing"]["deadline"]["verdict"], "unknown");
    assert!(report["timing"].get("block_time").is_none());

    // Without a deadline the content verdict stands; the report still says
    // there is no time.
    let run = verify("bare", &tx_id, &gateways, &[]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("not_on_chain"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("No independent existence time is established"),
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains("block_time"), "{}", run.stdout);
}

/// The bundle names a transaction that really is mined — and stores other
/// bytes. That fails the verdict even with no deadline: the bundle's
/// provenance pointer is false.
#[test]
fn a_transaction_that_stores_other_bytes_is_invalid() {
    let (tx_id, header) = unrelated_tx();
    let gateways = agreeing_gateways(&tx_id, &header);

    let run = verify("bare", &tx_id, &gateways, &["--json"]);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["verified"], false);
    assert_eq!(report["content_verified"], true);
    assert_eq!(report["timing"]["state"], "invalid");
    assert!(report["timing"].get("block_time").is_none());

    let run = verify_with_deadline(&tx_id, &gateways, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1));
    assert_eq!(run.json()["timing"]["deadline"]["verdict"], "unknown");
}

/// A gateway serving another transaction's header under this id is not
/// believed, however many gateways do it.
#[test]
fn a_header_for_another_transaction_is_not_evidence() {
    let (tx_id, _header) = public_tx();
    let (_other_id, other_header) = unrelated_tx();
    let gateways = agreeing_gateways(&tx_id, &other_header);
    let run = verify_with_deadline(&tx_id, &gateways, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["timing"]["state"], "unavailable");
    assert_eq!(report["timing"]["deadline"]["verdict"], "unknown");
    let first = report["timing"]["gateways"][0]["result"].as_str().unwrap();
    assert!(first.starts_with("unusable"), "{first}");
}

/// A real block response is several hundred kilobytes (about 740 KiB when
/// the fixtures were recorded). One that size must be read; one past the cap
/// is refused instead of being buffered, and then establishes nothing.
#[test]
fn a_large_block_is_read_and_an_oversized_one_is_refused() {
    let (tx_id, header) = public_tx();
    let padded = |block_padding: usize| -> Vec<String> {
        (0..3)
            .map(|_| {
                Mined {
                    block_padding,
                    ..Mined::new(&tx_id, &header)
                }
                .gateway()
            })
            .collect()
    };

    let large = verify_with_deadline(&tx_id, &padded(2 * 1024 * 1024), FAR_FUTURE, true);
    assert_eq!(large.code, Some(0), "{}\n{}", large.stdout, large.stderr);
    assert_eq!(large.json()["timing"]["state"], "evidenced");

    let oversized = verify_with_deadline(&tx_id, &padded(5 * 1024 * 1024), FAR_FUTURE, true);
    assert_eq!(oversized.code, Some(1), "{}", oversized.stdout);
    let report = oversized.json();
    assert_eq!(report["timing"]["state"], "unavailable");
    assert_eq!(report["timing"]["deadline"]["verdict"], "unknown");
    assert!(
        report["timing"].to_string().contains("too large"),
        "{}",
        report["timing"]
    );
}

#[test]
fn unreachable_gateways_establish_nothing() {
    let (tx_id, header) = public_tx();
    let dead = vec![dead_gateway(), dead_gateway(), dead_gateway()];
    let run = verify_with_deadline(&tx_id, &dead, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["timing"]["state"], "unavailable");
    assert_eq!(report["timing"]["deadline"]["verdict"], "unknown");

    // One gateway confirming while the others are down is not a quorum.
    let one = vec![
        Mined::new(&tx_id, &header).gateway(),
        dead_gateway(),
        dead_gateway(),
    ];
    let run = verify_with_deadline(&tx_id, &one, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1));
    assert_eq!(run.json()["timing"]["state"], "unavailable");

    // Content verification does not depend on the network: with no deadline
    // the bundle still verifies and the report says timing is unavailable.
    let run = verify("bare", &tx_id, &dead, &["--json"]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert_eq!(run.json()["timing"]["state"], "unavailable");
}

#[test]
fn unmined_shallow_and_single_sightings_are_pending() {
    let (tx_id, header) = public_tx();
    let cases: [Vec<String>; 3] = [
        // Known to two gateways, mined by none.
        vec![
            pending_gateway(&tx_id),
            pending_gateway(&tx_id),
            empty_gateway(),
        ],
        // Mined at one gateway, unknown to the others.
        vec![
            Mined::new(&tx_id, &header).gateway(),
            empty_gateway(),
            empty_gateway(),
        ],
        // Mined and agreed, one confirmation short at one gateway.
        vec![
            Mined::new(&tx_id, &header).gateway(),
            Mined {
                confirmations: 9,
                ..Mined::new(&tx_id, &header)
            }
            .gateway(),
        ],
    ];
    for (index, gateways) in cases.iter().enumerate() {
        let run = verify_with_deadline(&tx_id, gateways, FAR_FUTURE, true);
        assert_eq!(run.code, Some(1), "case {index}: {}", run.stdout);
        let report = run.json();
        assert_eq!(report["timing"]["state"], "pending", "case {index}");
        assert_eq!(
            report["timing"]["deadline"]["verdict"], "unknown",
            "case {index}"
        );
        assert!(report["timing"].get("block_time").is_none(), "case {index}");
    }
    // Ten confirmations at the shallowest gateway is enough.
    let deep_enough = vec![
        Mined::new(&tx_id, &header).gateway(),
        Mined {
            confirmations: 10,
            ..Mined::new(&tx_id, &header)
        }
        .gateway(),
    ];
    let run = verify_with_deadline(&tx_id, &deep_enough, FAR_FUTURE, true);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert_eq!(run.json()["timing"]["confirmations"], 10);
}

/// Two gateways with an earlier block do not outvote a third that names a
/// different one.
#[test]
fn gateways_that_disagree_are_a_conflict() {
    let (tx_id, header) = public_tx();
    let gateways = vec![
        Mined::new(&tx_id, &header).gateway(),
        Mined::new(&tx_id, &header).gateway(),
        Mined {
            block_hash: OTHER_BLOCK_HASH,
            height: 1_900_001,
            block_time: BLOCK_TIME + 120,
            ..Mined::new(&tx_id, &header)
        }
        .gateway(),
    ];
    let run = verify_with_deadline(&tx_id, &gateways, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["timing"]["state"], "conflict");
    assert_eq!(report["timing"]["deadline"]["verdict"], "unknown");
    assert!(report["timing"].get("block_time").is_none());
}

/// Naming one gateway three times is one gateway.
#[test]
fn one_gateway_repeated_is_not_a_quorum() {
    let (tx_id, header) = public_tx();
    let only = Mined::new(&tx_id, &header).gateway();
    let gateways = vec![only.clone(), only.clone(), only];
    let run = verify_with_deadline(&tx_id, &gateways, FAR_FUTURE, true);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["timing"]["state"], "unavailable");
    assert_eq!(report["timing"]["gateways"].as_array().unwrap().len(), 1);
}

/// A private qub's content still verifies; no timing evidence is offered for
/// it, so it can never meet a deadline — and no gateway is asked.
#[test]
fn private_qubs_get_no_timing_evidence() {
    let (tx_id, header) = public_tx();
    // Gateways that would happily confirm: they must not matter.
    let gateways = agreeing_gateways(&tx_id, &header);

    let run = verify("wrapped", &tx_id, &gateways, &["--json"]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["verified"], true);
    assert_eq!(report["timing"]["state"], "unsupported_private");
    assert!(report["timing"].get("block_time").is_none());

    let [flag, value] = deadline(FAR_FUTURE);
    let run = verify("wrapped", &tx_id, &gateways, &[&flag, &value, "--json"]);
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["verified"], false);
    assert_eq!(report["content_verified"], true);
    assert_eq!(report["timing"]["deadline"]["verdict"], "unknown");

    let run = verify("wrapped", &tx_id, &gateways, &[]);
    assert!(
        run.stdout.contains("not offered for private qubs"),
        "{}",
        run.stdout
    );
}

/// Without `--timing` nothing about storage time is printed, and the options
/// that only make sense with it are usage errors.
#[test]
fn timing_is_opt_in() {
    let (tx_id, _header) = public_tx();
    let (bytes, unlock_at) = bundle("bare", &tx_id);
    let path = temp_bundle(&bytes);
    let now = (unlock_at + 10).to_string();
    let run = |extra: &[&str]| {
        let output = verifier()
            .arg(&path)
            .args(["--now", &now])
            .args(extra)
            .output()
            .expect("spawn qub-verify");
        finish(&output)
    };
    let offline = run(&["--json"]);
    assert_eq!(offline.code, Some(0), "{}", offline.stderr);
    let report = offline.json();
    assert!(report.get("timing").is_none());
    assert!(report.get("content_verified").is_none());
    assert!(!run(&[]).stdout.contains("storage time"));

    // Not printing a timing section is not the same as not looking: route
    // every request the binary could make through a counting proxy. Without
    // `--timing` there must be none at all; with it (and the built-in
    // gateways) there must be some, or the counter proves nothing.
    let (proxy, connections) = connection_counter();
    let through_proxy = |extra: &[&str]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_qub-verify"));
        command.env_remove("NO_PROXY").env_remove("no_proxy");
        for var in PROXY_VARS {
            command.env(var, &proxy);
        }
        let output = command
            .arg(&path)
            .args(["--now", &now, "--json"])
            .args(extra)
            .output()
            .expect("spawn qub-verify");
        finish(&output)
    };
    let silent = through_proxy(&[]);
    assert_eq!(silent.code, Some(0), "{}", silent.stderr);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "qub-verify made a network request without --timing"
    );
    let looked = through_proxy(&["--timing"]);
    assert_eq!(looked.code, Some(0), "{}", looked.stderr);
    assert!(
        connections.load(Ordering::SeqCst) > 0,
        "the counting proxy saw nothing even with --timing"
    );
    // Nothing reachable answered, so nothing is established.
    assert_eq!(looked.json()["timing"]["state"], "unavailable");

    assert_eq!(run(&["--deadline", "1"]).code, Some(2));
    // A deadline in milliseconds would put every block "before" it: refused
    // as a usage error, before anything is looked up.
    let millis = run(&["--timing", "--deadline", "1800000000000"]);
    assert_eq!(millis.code, Some(2), "{}", millis.stdout);
    assert!(millis.stderr.contains("milliseconds"), "{}", millis.stderr);
    assert_eq!(run(&["--timing", "--deadline", "0"]).code, Some(2));
    assert_eq!(run(&["--gateway", "http://127.0.0.1:1"]).code, Some(2));
    // A gateway that is not an https origin (or loopback) is refused before
    // any request is made.
    for bad in [
        "http://gateway.example",
        "https://gateway.example/path",
        "nope",
    ] {
        let refused = run(&["--timing", "--gateway", bad]);
        assert_eq!(refused.code, Some(2), "{bad}: {}", refused.stderr);
        assert!(
            refused.stderr.contains("gateway"),
            "{bad}: {}",
            refused.stderr
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// A bundle whose transaction id is not an id is never placed in a URL.
#[test]
fn a_malformed_transaction_id_is_not_looked_up() {
    let (tx_id, header) = public_tx();
    let gateways = agreeing_gateways(&tx_id, &header);
    let run = verify("bare", "../../not-a-tx-id", &gateways, &["--json"]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    let report = run.json();
    assert_eq!(report["timing"]["state"], "unavailable");
    assert_eq!(report["timing"]["gateways"].as_array().unwrap().len(), 0);
}
