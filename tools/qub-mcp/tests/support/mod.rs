// allow-test-network: loopback mocks of the Worker, Arweave gateways and drand
//! Shared harness for the public-mode and forecast-series tests: the real
//! `qub-mcp` binary on one side, and on the other a small world of in-process
//! HTTP mocks bound to `127.0.0.1`:
//!
//! - **the qub Worker** — the parts of its contract these flows touch:
//!   `POST /api/v1/upload` (public and private, one trial grant shared by
//!   every key, idempotent replay, a publication cap and an optional rate
//!   limit), `GET /api/v1/upload/operation`, the authenticated and counted
//!   `GET /api/v1/qub/{tx_id}`, and the anonymous `/bytes` route (which
//!   refuses a trial credential). Like the real Worker it signs an Arweave
//!   transaction for exactly the bytes it accepted and answers with that
//!   transaction's id; unlike it, it never posts anything anywhere.
//! - **three Arweave gateways**, each on its own port, each told per
//!   transaction what to report: unknown, pending, mined in some block, or
//!   down. Whether a transaction is "on chain" is entirely a property of
//!   what these report — which is exactly the part of the evidence the
//!   verifier cannot check for itself.
//! - **drand**, serving the one real quicknet beacon the fixtures use — or,
//!   when a test says so, not serving it yet (404) or failing (5xx).
//!
//! The cryptography is not mocked: transactions are RSA-PSS signed over the
//! real Arweave deep hash, qubs are sealed by `qub_core::seal` to a real
//! elapsed drand round, and the binary verifies and decrypts all of it.

#![allow(dead_code)]
// each test file uses its own part of the harness
// The mocks hold their state lock across each routing decision (that is the
// atomicity of the Worker's claim they model), and their routing reads more
// clearly as `match` than as `map_or_else` chains.
#![allow(clippy::significant_drop_tightening, clippy::option_if_let_else)]

mod test_wallet;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use qub_core::seal::{SealInput, seal};
use qub_core::tlock::DrandTimelockProvider;
use qub_core::types::{CONTENT_TYPE_TEXT, ComposeQub, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC};
use qub_core::wrapper::{OUTER_WRAPPER_KEY_LEN, OUTER_WRAPPER_NONCE_LEN, wrap_sealed_qub};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, rand_core};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};

pub const MCP_BIN: &str = env!("CARGO_BIN_EXE_qub-mcp");
pub const RUNNER_BIN: &str = env!("CARGO_BIN_EXE_qub-forecast-series");

const QUICKNET_GENESIS: i64 = 1_692_803_367;
const QUICKNET_PERIOD: u64 = 3;
const QUICKNET_CHAIN: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

const STANDALONE: &str =
    include_str!("../../../../crates/qub-core/tests/vectors/standalone_pipeline_v1.json");

/// The `TimingPolicy::PROVISIONAL` margin and depth the binary applies.
pub const MARGIN: i64 = 600;
pub const MIN_CONFIRMATIONS: u64 = 10;

/// The `indep_hash` of the mock chain's block with timestamp `block_time`.
/// One block per timestamp, as on a real chain: two transactions mined at
/// different times are in different blocks.
pub fn block_hash_at(block_time: i64) -> String {
    BASE64URL.encode(Sha384::digest(
        format!("mock-block-{block_time}").as_bytes(),
    ))
}

/// The height of that block.
pub fn block_height_at(block_time: i64) -> u64 {
    u64::try_from(block_time / 120).unwrap_or_default()
}

pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// The elapsed drand round the reveal tests use
// ---------------------------------------------------------------------------

/// The real, elapsed quicknet round of the standalone-viewer fixture, its
/// real beacon, and an unlock time that maps to it.
pub struct ElapsedRound {
    pub round: u64,
    pub signature_hex: String,
    pub unlock_at: i64,
}

pub fn elapsed_round() -> ElapsedRound {
    let fixture: Value = serde_json::from_str(STANDALONE).unwrap();
    let case = &fixture["cases"][0];
    ElapsedRound {
        round: case["round"].as_u64().unwrap(),
        signature_hex: case["signature_hex"].as_str().unwrap().to_owned(),
        unlock_at: case["sealed_unlock_at"].as_i64().unwrap(),
    }
}

/// Seal `body` as a PUBLIC qub that unlocked at the elapsed fixture round.
/// Returns the bytes a public upload stores: the bare `SealedQubCbor`.
pub fn seal_revealed_public(body: &str) -> Vec<u8> {
    seal_revealed(body, VISIBILITY_PUBLIC).0
}

/// Seal `body` as a PRIVATE qub that unlocked at the elapsed fixture round.
/// Returns the stored wrapper bytes and the base64url wrapper key.
pub fn seal_revealed_private(body: &str) -> (Vec<u8>, String) {
    let (sealed, qub_id) = seal_revealed(body, VISIBILITY_PRIVATE);
    let sealed = qub_core::wire::SealedQubCbor::from_encoded(sealed).unwrap();
    let key = [0x6Bu8; OUTER_WRAPPER_KEY_LEN];
    let wrapped =
        wrap_sealed_qub(&sealed, &qub_id, &key, &[0x21; OUTER_WRAPPER_NONCE_LEN]).expect("wrap");
    (wrapped.as_bytes().to_vec(), BASE64URL.encode(key))
}

/// A PUBLIC qub, unlocked at the elapsed fixture round, whose envelope
/// claims an ML-DSA-65 authorship signature and carries none: it decrypts,
/// its body matches its commitment, and its signature does NOT verify.
pub fn seal_revealed_public_with_a_failing_signature(body: &str) -> Vec<u8> {
    use qub_core::cbor::serialize_qub_envelope;
    use qub_core::hash::derive_envelope_hashes;
    use qub_core::tlock::TimelockProvider;
    use qub_core::types::{
        PROTOCOL_VERSION_1, QubEnvelopeBuilder, SIG_ALG_ML_DSA_65, SealedQubBuilder,
    };

    let round = elapsed_round();
    let created_at = round.unlock_at - 60;
    let body = body.as_bytes().to_vec();
    let (body_hash, qub_id) = derive_envelope_hashes(
        PROTOCOL_VERSION_1,
        CONTENT_TYPE_TEXT,
        created_at,
        round.unlock_at,
        None,
        round.round,
        &body,
        None,
    );
    let envelope = QubEnvelopeBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .content_type(CONTENT_TYPE_TEXT)
        .created_at(created_at)
        .unlock_at(round.unlock_at)
        .body(body)
        .body_hash(body_hash)
        .sig_alg(SIG_ALG_ML_DSA_65)
        .build()
        .expect("envelope");
    let envelope_cbor = serialize_qub_envelope(&envelope).expect("envelope CBOR");
    let ciphertext = DrandTimelockProvider::quicknet()
        .encrypt(&envelope_cbor, round.round)
        .expect("tlock encrypt");
    let sealed = SealedQubBuilder::new()
        .version(PROTOCOL_VERSION_1)
        .qub_id(qub_id)
        .visibility(VISIBILITY_PUBLIC)
        .unlock_at(round.unlock_at)
        .drand_chain_id(QUICKNET_CHAIN.to_owned())
        .drand_round(round.round)
        .tlock_ciphertext(ciphertext)
        .build()
        .expect("sealed qub");
    qub_core::wire::SealedQubCbor::from_sealed_qub(&sealed)
        .expect("sealed CBOR")
        .as_bytes()
        .to_vec()
}

fn seal_revealed(body: &str, visibility: u8) -> (Vec<u8>, [u8; 32]) {
    let round = elapsed_round();
    let mut draft = ComposeQub::new(CONTENT_TYPE_TEXT);
    draft.set_plaintext(body.as_bytes().to_vec());
    draft.set_unlock_at(round.unlock_at);
    draft.set_visibility(visibility);
    let tlock = DrandTimelockProvider::quicknet();
    let output = seal(SealInput {
        draft: &draft,
        // An author-supplied creation time; nothing may lean on it.
        now: round.unlock_at - 60,
        chain_genesis_time: QUICKNET_GENESIS,
        chain_period_seconds: QUICKNET_PERIOD,
        chain_id: QUICKNET_CHAIN.to_owned(),
        tlock: &tlock,
        signing: None,
    })
    .expect("seal to the elapsed round");
    assert_eq!(output.drand_round, round.round);
    (output.sealed_cbor.as_bytes().to_vec(), output.qub_id)
}

// ---------------------------------------------------------------------------
// Arweave transaction signing (what the Worker does with its upload wallet)
// ---------------------------------------------------------------------------

/// OS randomness behind the `rand_core` 0.6 traits `rsa` signs with.
struct OsRandom;

impl rand_core::RngCore for OsRandom {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS randomness");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for OsRandom {}

/// The mock upload wallet: a FIXED 2048-bit test key, checked in beside this
/// file (`test_wallet.rs`). It signs nothing but the fake transactions these tests mine on a
/// loopback mock; it has never held funds and protects nothing.
///
/// It is not generated at run time. nextest runs every test in a process of
/// its own, so "once per binary" was once per TEST: an unoptimised RSA-2048
/// key search in each of some forty processes. That starved the CI runner
/// until unrelated tests timed out waiting for the server they had spawned.
fn wallet() -> &'static RsaPrivateKey {
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    static WALLET: OnceLock<RsaPrivateKey> = OnceLock::new();
    WALLET.get_or_init(|| {
        let der = hex::decode(test_wallet::TEST_WALLET_PKCS1_DER_HEX).expect("wallet hex");
        RsaPrivateKey::from_pkcs1_der(&der).expect("test wallet")
    })
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn sha384(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).to_vec()
}

/// A deep-hash input, written out independently of the verifier's own.
enum Deep<'a> {
    Blob(&'a [u8]),
    List(Vec<Self>),
}

fn deep_hash(item: &Deep) -> Vec<u8> {
    match item {
        Deep::Blob(data) => {
            let tag = sha384(format!("blob{}", data.len()).as_bytes());
            sha384(&[tag, sha384(data)].concat())
        },
        Deep::List(items) => {
            let mut acc = sha384(format!("list{}", items.len()).as_bytes());
            for item in items {
                acc = sha384(&[acc, deep_hash(item)].concat());
            }
            acc
        },
    }
}

/// Sign a format-2 Arweave transaction for `data`, as the Worker's upload
/// wallet would. Returns `(tx_id, gateway header JSON)`.
pub fn sign_transaction(data: &[u8], is_public: bool) -> (String, String) {
    let owner = wallet().to_public_key().n().to_bytes_be();
    let data_root = qub_verify::arweave_tx::data_root(data);
    let data_size = data.len().to_string();
    let last_tx = [0x5Au8; 48];
    let mut tags: Vec<(&[u8], &[u8])> = vec![
        (b"Content-Type", b"application/cbor"),
        (b"App-Name", b"qub"),
    ];
    if is_public {
        tags.push((b"Visibility", b"public"));
    }
    let preimage = deep_hash(&Deep::List(vec![
        Deep::Blob(b"2"),
        Deep::Blob(&owner),
        Deep::Blob(b""),
        Deep::Blob(b"0"),
        Deep::Blob(b"1000"),
        Deep::Blob(&last_tx),
        Deep::List(
            tags.iter()
                .map(|(name, value)| Deep::List(vec![Deep::Blob(name), Deep::Blob(value)]))
                .collect(),
        ),
        Deep::Blob(data_size.as_bytes()),
        Deep::Blob(&data_root),
    ]));
    let signature = BlindedSigningKey::<Sha256>::new_with_salt_len(wallet().clone(), 32)
        .sign_with_rng(&mut OsRandom, &preimage)
        .to_vec();
    let tx_id = BASE64URL.encode(sha256(&signature));
    let header = json!({
        "format": 2,
        "id": tx_id,
        "last_tx": BASE64URL.encode(last_tx),
        "owner": BASE64URL.encode(&owner),
        "tags": tags
            .iter()
            .map(|(name, value)| json!({
                "name": BASE64URL.encode(name),
                "value": BASE64URL.encode(value),
            }))
            .collect::<Vec<_>>(),
        "target": "",
        "quantity": "0",
        "data": "",
        "data_size": data_size,
        "data_root": BASE64URL.encode(data_root),
        "reward": "1000",
        "signature": BASE64URL.encode(&signature),
    });
    (tx_id, header.to_string())
}

// ---------------------------------------------------------------------------
// The mock world
// ---------------------------------------------------------------------------

/// What one gateway reports about one transaction.
#[derive(Clone, Debug)]
pub enum View {
    /// 404: the gateway has never seen it.
    Unknown,
    /// 202: known, not mined.
    Pending,
    /// 503 to every request.
    Down,
    /// Mined in a block.
    Mined {
        block_time: i64,
        confirmations: u64,
        block_hash: String,
        height: u64,
    },
}

impl View {
    /// Mined in the block with timestamp `block_time`, well confirmed.
    pub fn mined(block_time: i64) -> Self {
        Self::mined_with(block_time, 40)
    }

    /// Mined in the block with timestamp `block_time`, this deep.
    pub fn mined_with(block_time: i64, confirmations: u64) -> Self {
        Self::Mined {
            block_time,
            confirmations,
            block_hash: block_hash_at(block_time),
            height: block_height_at(block_time),
        }
    }
}

/// One stored artifact.
#[derive(Clone)]
pub struct Artifact {
    /// The bytes the storage transaction commits to.
    pub bytes: Vec<u8>,
    /// What the read routes actually serve. Differs from `bytes` only when
    /// a test alters the artifact after publication.
    pub served: Vec<u8>,
    pub header: String,
    pub is_public: bool,
    pub views: [View; 3],
}

/// One `POST /api/v1/upload` as the Worker saw it.
#[derive(Clone)]
pub struct UploadSeen {
    pub idempotency_key: String,
    pub is_public: Option<bool>,
    pub bytes: Vec<u8>,
    pub unlock_at: i64,
    pub intent: Option<String>,
}

/// How the Worker treats the next upload POST.
#[derive(Clone, Copy)]
pub enum UploadFault {
    /// No fault: this upload is handled normally.
    Pass,
    /// 429 `TRIAL_RATE_LIMITED` with this `Retry-After`, nothing published.
    RateLimited(u64),
    /// Publish, then close the connection without answering: a lost ack.
    CommitThenDrop,
}

/// How drand answers while a test holds the fixture round's beacon back.
#[derive(Clone, Copy, Debug)]
pub enum DrandFault {
    /// 404: the round's time has come and this relay does not have its
    /// beacon yet. What a relay answers in the seconds after a round is due.
    NotPublished,
    /// This status (a 5xx): the relay is failing. Says nothing about the
    /// round.
    Failing(u16),
}

#[derive(Default)]
pub struct Inner {
    /// API keys the Worker accepts; all share one trial grant.
    pub keys: Vec<String>,
    pub artifacts: HashMap<String, Artifact>,
    /// Published operations by `Idempotency-Key`.
    pub claims: HashMap<String, String>,
    pub uploads: Vec<UploadSeen>,
    pub publication_limit: usize,
    pub publications: usize,
    pub read_limit: usize,
    pub authenticated_reads: usize,
    pub anonymous_reads: usize,
    /// Faults applied to successive new-upload POSTs, in order; once the
    /// list is empty every upload is handled normally.
    pub upload_faults: Vec<UploadFault>,
    /// Every request the Worker received, in order (`"<METHOD> <path>"`),
    /// whatever it went on to answer.
    pub worker_requests: Vec<String>,
    /// Requests each gateway received, in order (`"<index> <path>"`).
    pub gateway_requests: Vec<String>,
    pub drand_requests: usize,
    /// When set, drand serves this (wrong) signature for the fixture round.
    pub drand_signature_override: Option<String>,
    /// When set, drand answers every request with this fault instead of the
    /// beacon.
    pub drand_fault: Option<DrandFault>,
    /// Gateway and drand requests that arrived carrying an `Authorization`
    /// header (`"gateway <index> <path>"`, `"drand <path>"`). Neither service
    /// is qub's: no request to them may carry the API key.
    pub credentialed_lookups: Vec<String>,
    /// When set, an authenticated read fails with a body that reflects the
    /// caller's `Authorization` header, as a careless or hostile service
    /// might.
    pub reflect_authorization: bool,
}

pub struct World {
    inner: Arc<Mutex<Inner>>,
    pub worker_url: String,
    pub gateway_urls: [String; 3],
    pub drand_url: String,
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn bearer(&self) -> Option<&str> {
        self.headers.get("authorization")?.strip_prefix("Bearer ")
    }
}

enum Reply {
    /// Status, extra headers, content type, body.
    Send(u16, Vec<(String, String)>, &'static str, Vec<u8>),
    /// Close the connection without answering.
    Drop,
}

fn json_reply(status: u16, body: &Value) -> Reply {
    Reply::Send(
        status,
        Vec::new(),
        "application/json",
        body.to_string().into_bytes(),
    )
}

fn error_reply(status: u16, code: &str) -> Reply {
    json_reply(status, &json!({ "code": code, "error": code }))
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = HashMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

/// Serve `handler` on a fresh loopback port; returns its origin.
fn serve(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock");
    let port = listener.local_addr().unwrap().port();
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let handler = Arc::clone(&handler);
            thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
                let Some(request) = read_request(&stream) else {
                    return;
                };
                match handler(&request) {
                    Reply::Drop => {},
                    Reply::Send(status, extra, content_type, body) => {
                        let mut head = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n\
                             Content-Length: {}\r\nConnection: close\r\n",
                            body.len()
                        );
                        for (name, value) in extra {
                            head.push_str(&name);
                            head.push_str(": ");
                            head.push_str(&value);
                            head.push_str("\r\n");
                        }
                        head.push_str("\r\n");
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&body);
                    },
                }
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn is_device_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `GET /api/v1/upload/operation`.
fn worker_lookup(inner: &Inner, request: &Request) -> Reply {
    let Some(key) = request.headers.get("idempotency-key") else {
        return error_reply(400, "IDEMPOTENCY_KEY_REQUIRED");
    };
    let mut body = json!({ "scope": "grant", "scope_id": "mock-grant", "state": "unknown" });
    if let Some(tx_id) = inner.claims.get(key) {
        body["state"] = json!("published");
        body["tx_id"] = json!(tx_id);
    }
    json_reply(200, &body)
}

/// `POST /api/v1/upload`.
fn worker_upload(inner: &mut Inner, origin: &str, request: &Request) -> Reply {
    let Some(key) = request.headers.get("idempotency-key").cloned() else {
        return error_reply(400, "IDEMPOTENCY_KEY_REQUIRED");
    };
    let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
        return error_reply(400, "invalid_json");
    };
    if !body["device_id"].as_str().is_some_and(is_device_id) {
        return error_reply(400, "invalid_device_id");
    }
    let Some(bytes) = body["wrapped_cbor_base64"]
        .as_str()
        .and_then(|text| BASE64.decode(text).ok())
    else {
        return error_reply(400, "invalid_payload");
    };
    let is_public = body.get("is_public").and_then(Value::as_bool);
    inner.uploads.push(UploadSeen {
        idempotency_key: key.clone(),
        is_public,
        bytes: bytes.clone(),
        unlock_at: body["unlock_at"].as_i64().unwrap_or_default(),
        intent: body["intent"].as_str().map(str::to_owned),
    });
    let accepted = |tx_id: &str| {
        json_reply(
            200,
            &json!({ "tx_id": tx_id, "delivery_url": format!("{origin}/c/{tx_id}") }),
        )
    };
    // A replay of a published operation answers with it and spends
    // nothing, whatever else is going on.
    if let Some(tx_id) = inner.claims.get(&key) {
        return accepted(tx_id);
    }
    let fault = if inner.upload_faults.is_empty() {
        UploadFault::Pass
    } else {
        inner.upload_faults.remove(0)
    };
    if let UploadFault::RateLimited(retry_after) = fault {
        return Reply::Send(
            429,
            vec![("Retry-After".to_owned(), retry_after.to_string())],
            "application/json",
            json!({ "code": "TRIAL_RATE_LIMITED", "error": "slow down" })
                .to_string()
                .into_bytes(),
        );
    }
    if inner.publications >= inner.publication_limit {
        return error_reply(402, "TRIAL_QUBS_EXHAUSTED");
    }
    let public = is_public == Some(true);
    let (tx_id, header) = sign_transaction(&bytes, public);
    inner.publications += 1;
    inner.claims.insert(key, tx_id.clone());
    inner.artifacts.insert(
        tx_id.clone(),
        Artifact {
            served: bytes.clone(),
            bytes,
            header,
            is_public: public,
            // Acknowledged, not posted: no gateway knows it yet.
            views: [View::Unknown, View::Unknown, View::Unknown],
        },
    );
    if matches!(fault, UploadFault::CommitThenDrop) {
        return Reply::Drop;
    }
    accepted(&tx_id)
}

/// `GET /api/v1/qub/{tx_id}` and `GET /api/v1/qub/{tx_id}/bytes`.
fn worker_read(inner: &mut Inner, authorised: bool, rest: &str, request: &Request) -> Reply {
    if let Some(tx_id) = rest.strip_suffix("/bytes") {
        // The public bytes route: a trial credential is refused, an
        // anonymous caller is served.
        if request.bearer().is_some() {
            return error_reply(403, "TRIAL_CREDENTIAL_ON_PUBLIC_ROUTE");
        }
        inner.anonymous_reads += 1;
        return match inner.artifacts.get(tx_id) {
            Some(artifact) => Reply::Send(
                200,
                Vec::new(),
                "application/octet-stream",
                artifact.served.clone(),
            ),
            None => error_reply(502, "storage_fetch_failed"),
        };
    }
    if !authorised {
        return error_reply(401, "api_key_required");
    }
    if inner.reflect_authorization {
        let header = request
            .headers
            .get("authorization")
            .cloned()
            .unwrap_or_default();
        return json_reply(
            500,
            &json!({ "code": "INTERNAL", "error": format!("upstream said: Authorization: {header}") }),
        );
    }
    // Admission is counted before storage is touched.
    if inner.authenticated_reads >= inner.read_limit {
        return error_reply(402, "TRIAL_READS_EXHAUSTED");
    }
    inner.authenticated_reads += 1;
    match inner.artifacts.get(rest) {
        Some(artifact) => json_reply(
            200,
            &json!({
                "tx_id": rest,
                "wrapped_cbor_base64": BASE64.encode(&artifact.served),
                // The Worker relays a block timestamp of its own. Nothing
                // may treat it as evidence.
                "arweave_block_timestamp": 1,
            }),
        ),
        None => error_reply(404, "not_found"),
    }
}

fn worker(inner: &Arc<Mutex<Inner>>, origin: &str, request: &Request) -> Reply {
    let mut inner = inner.lock().unwrap();
    let authorised = request
        .bearer()
        .is_some_and(|key| inner.keys.iter().any(|known| known == key));
    let path = request.path.as_str();
    inner
        .worker_requests
        .push(format!("{} {path}", request.method));
    match (request.method.as_str(), path) {
        ("GET", "/api/v1/upload/operation") if authorised => worker_lookup(&inner, request),
        ("POST", "/api/v1/upload") if authorised => worker_upload(&mut inner, origin, request),
        ("GET" | "POST", "/api/v1/upload/operation" | "/api/v1/upload") => {
            error_reply(401, "api_key_required")
        },
        ("GET", _) if path.starts_with("/api/v1/qub/") => worker_read(
            &mut inner,
            authorised,
            &path["/api/v1/qub/".len()..],
            request,
        ),
        _ => error_reply(404, "not_found"),
    }
}

fn gateway(inner: &Arc<Mutex<Inner>>, index: usize, request: &Request) -> Reply {
    let mut inner = inner.lock().unwrap();
    let path = request.path.clone();
    inner.gateway_requests.push(format!("{index} {path}"));
    if request.headers.contains_key("authorization") {
        inner
            .credentialed_lookups
            .push(format!("gateway {index} {path}"));
    }
    // A block request names a hash, not a transaction: find which mined
    // transaction this gateway placed in that block.
    if let Some(hash) = path.strip_prefix("/block/hash/") {
        let mut txs = Vec::new();
        let mut block = None;
        for (tx_id, artifact) in &inner.artifacts {
            if let View::Mined {
                block_time,
                block_hash,
                height,
                ..
            } = &artifact.views[index]
                && block_hash == hash
            {
                txs.push(tx_id.clone());
                block = Some((*block_time, *height));
            }
        }
        return match block {
            Some((timestamp, height)) => json_reply(
                200,
                &json!({ "height": height, "indep_hash": hash, "timestamp": timestamp, "txs": txs }),
            ),
            None => error_reply(404, "not_found"),
        };
    }
    let Some(rest) = path.strip_prefix("/tx/") else {
        return error_reply(404, "not_found");
    };
    let (tx_id, wants_status) = rest
        .strip_suffix("/status")
        .map_or((rest, false), |tx_id| (tx_id, true));
    let Some(artifact) = inner.artifacts.get(tx_id) else {
        return Reply::Send(404, Vec::new(), "text/plain", b"Not Found.".to_vec());
    };
    match &artifact.views[index] {
        View::Unknown => Reply::Send(404, Vec::new(), "text/plain", b"Not Found.".to_vec()),
        View::Pending => Reply::Send(202, Vec::new(), "text/plain", b"Pending".to_vec()),
        View::Down => Reply::Send(503, Vec::new(), "text/plain", b"unavailable".to_vec()),
        View::Mined {
            confirmations,
            block_hash,
            height,
            ..
        } => {
            if wants_status {
                json_reply(
                    200,
                    &json!({
                        "block_height": height,
                        "block_indep_hash": block_hash,
                        "number_of_confirmations": confirmations,
                    }),
                )
            } else {
                Reply::Send(
                    200,
                    Vec::new(),
                    "application/json",
                    artifact.header.clone().into_bytes(),
                )
            }
        },
    }
}

fn drand(inner: &Arc<Mutex<Inner>>, request: &Request) -> Reply {
    let mut inner = inner.lock().unwrap();
    inner.drand_requests += 1;
    if request.headers.contains_key("authorization") {
        inner
            .credentialed_lookups
            .push(format!("drand {}", request.path));
    }
    match inner.drand_fault {
        Some(DrandFault::NotPublished) => return error_reply(404, "round not published"),
        Some(DrandFault::Failing(status)) => {
            return Reply::Send(status, Vec::new(), "text/plain", b"unavailable".to_vec());
        },
        None => {},
    }
    let round = elapsed_round();
    if request.path == format!("/{QUICKNET_CHAIN}/public/{}", round.round) {
        let signature = inner
            .drand_signature_override
            .clone()
            .unwrap_or(round.signature_hex);
        return json_reply(
            200,
            &json!({ "round": round.round, "signature": signature }),
        );
    }
    error_reply(404, "round not published")
}

/// A drand relay of its own, apart from the [`World`]'s: it answers every
/// request with `status` and nothing else — a mirror that is behind (404) or
/// down (5xx). Returns its origin and a count of the requests it received.
pub fn drand_mirror_answering(status: u16) -> (String, Arc<AtomicU32>) {
    let seen = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&seen);
    let origin = serve(move |_request| {
        counter.fetch_add(1, Ordering::SeqCst);
        Reply::Send(status, Vec::new(), "text/plain", b"mirror".to_vec())
    });
    (origin, seen)
}

/// A drand relay that reads each request and closes the connection without
/// answering: a failure in transport, with no HTTP status at all. (A port
/// nothing listens on would do the same, but a released port can be bound
/// again by a test running beside this one.) Returns its origin and a count
/// of the requests it received.
pub fn drand_mirror_hanging_up() -> (String, Arc<AtomicU32>) {
    let seen = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&seen);
    let origin = serve(move |_request| {
        counter.fetch_add(1, Ordering::SeqCst);
        Reply::Drop
    });
    (origin, seen)
}

impl World {
    /// Start the Worker, three gateways and drand. The Worker accepts
    /// `api_key`, with the trial's ten publications and ample reads.
    pub fn start(api_key: &str) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            keys: vec![api_key.to_owned()],
            publication_limit: 10,
            read_limit: 10_000,
            ..Inner::default()
        }));
        // The Worker needs its own origin for `delivery_url`, so bind it
        // through a cell the handler reads once the port is known.
        let origin = Arc::new(OnceLock::<String>::new());
        let worker_url = {
            let inner = Arc::clone(&inner);
            let origin = Arc::clone(&origin);
            serve(move |request| worker(&inner, origin.get().map_or("", String::as_str), request))
        };
        origin.set(worker_url.clone()).unwrap();
        let gateway_urls = [0, 1, 2].map(|index| {
            let inner = Arc::clone(&inner);
            serve(move |request| gateway(&inner, index, request))
        });
        let drand_url = {
            let inner = Arc::clone(&inner);
            serve(move |request| drand(&inner, request))
        };
        Self {
            inner,
            worker_url,
            gateway_urls,
            drand_url,
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    /// Put an artifact in storage as an earlier upload would have left it:
    /// accepted and signed, and unknown to every gateway.
    pub fn store(&self, bytes: Vec<u8>, is_public: bool) -> String {
        let (tx_id, header) = sign_transaction(&bytes, is_public);
        self.lock().artifacts.insert(
            tx_id.clone(),
            Artifact {
                served: bytes.clone(),
                bytes,
                header,
                is_public,
                views: [View::Unknown, View::Unknown, View::Unknown],
            },
        );
        tx_id
    }

    /// Set what each gateway reports about `tx_id`.
    pub fn set_views(&self, tx_id: &str, views: [View; 3]) {
        self.lock()
            .artifacts
            .get_mut(tx_id)
            .expect("known transaction")
            .views = views;
    }

    /// Every gateway reports `tx_id` mined at `block_time`, well confirmed.
    pub fn mine(&self, tx_id: &str, block_time: i64) {
        self.set_views(
            tx_id,
            [
                View::mined(block_time),
                View::mined(block_time),
                View::mined(block_time),
            ],
        );
    }

    pub fn artifact(&self, tx_id: &str) -> Artifact {
        self.lock().artifacts[tx_id].clone()
    }

    pub fn delivery_url(&self, tx_id: &str) -> String {
        format!("{}/c/{tx_id}", self.worker_url)
    }
}

// ---------------------------------------------------------------------------
// Driving the binaries
// ---------------------------------------------------------------------------

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A unique temporary directory, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "qub-mcp-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a tool call answered.
pub struct ToolReply {
    pub is_error: bool,
    pub text: String,
}

impl ToolReply {
    /// The JSON object in the tool's text (read tools prefix it with a
    /// one-line untrusted-content note).
    pub fn json(&self) -> Value {
        let start = self
            .text
            .find('{')
            .unwrap_or_else(|| panic!("no JSON in tool text: {}", self.text));
        serde_json::from_str(&self.text[start..])
            .unwrap_or_else(|e| panic!("tool text is not JSON ({e}): {}", self.text))
    }

    /// The JSON payload of a successful call.
    pub fn ok(&self) -> Value {
        assert!(!self.is_error, "tool call failed: {}", self.text);
        self.json()
    }

    /// The `code` of a structured tool error.
    pub fn error_code(&self) -> String {
        assert!(self.is_error, "tool call succeeded: {}", self.text);
        self.json()["code"]
            .as_str()
            .unwrap_or_else(|| panic!("error has no code: {}", self.text))
            .to_owned()
    }
}

/// An agent's `qub-mcp` installation: its own state directory, pointed at
/// one [`World`]. Every call starts a fresh process, so every scenario also
/// exercises a restart.
pub struct Agent {
    state: TempDir,
    env: Vec<(String, String)>,
    api_key: Option<String>,
}

impl Agent {
    pub fn new(world: &World, api_key: Option<&str>) -> Self {
        Self {
            state: TempDir::new("state"),
            env: vec![
                ("QUB_BASE_URL".into(), world.worker_url.clone()),
                ("QUB_ARWEAVE_GATEWAYS".into(), world.gateway_urls.join(",")),
                ("QUB_DRAND_ENDPOINTS".into(), world.drand_url.clone()),
                ("QUB_MCP_ALLOW_CREATE".into(), "1".into()),
            ],
            api_key: api_key.map(str::to_owned),
        }
    }

    /// This installation's state directory. It exists before the first
    /// call; what the binary puts in it is the binary's doing.
    pub fn state_dir(&self) -> &Path {
        self.state.path()
    }

    /// Replace one environment variable for this agent's processes.
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.retain(|(existing, _)| existing != name);
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Apply this agent's environment to a command.
    pub fn configure(&self, command: &mut Command) {
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "QUB_API_KEY",
            "QUB_MCP_MAX_UNLOCK_HORIZON_SECS",
        ] {
            command.env_remove(var);
        }
        command
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .env("QUB_MCP_STATE_DIR", self.state.path());
        for (name, value) in &self.env {
            command.env(name, value);
        }
        if let Some(key) = &self.api_key {
            command.env("QUB_API_KEY", key);
        }
    }

    /// Call one tool in a fresh `qub-mcp` process.
    pub fn call(&self, tool: &str, arguments: &Value) -> ToolReply {
        let mut command = Command::new(MCP_BIN);
        self.configure(&mut command);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qub-mcp");
        let frame = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        });
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{frame}\n").as_bytes())
            .expect("write frame");
        let output = child.wait_with_output().expect("qub-mcp exits");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.lines().next().unwrap_or_else(|| {
            panic!(
                "no response; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        let response: Value = serde_json::from_str(line).expect("response is JSON");
        let result = &response["result"];
        ToolReply {
            is_error: result["isError"] == true,
            text: result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        }
    }
}
