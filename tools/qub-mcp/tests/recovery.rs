// allow-test-network: loopback mock of the Worker
//! Restart-safety tests for `create_qub`, plus the authenticated read
//! path — run against the real `qub-mcp` binary and an in-process
//! HTTP/1.1 mock of the qub Worker bound to `127.0.0.1`.
//!
//! The mock models the parts of the Worker contract that decide whether a
//! retry can publish twice:
//!
//! - `device_id` must match `^[a-f0-9]{32}$` (400 otherwise);
//! - `Idempotency-Key` must match the Worker's `IDEMPOTENCY_KEY_PATTERN`,
//!   `^[A-Za-z0-9._-]{1,255}$` (400 otherwise), on upload and on lookup;
//! - idempotency claims keyed by `(scope, Idempotency-Key)`, where scope
//!   is the account grant for trial keys and the key itself for paid
//!   keys; a POST against a published claim REPLAYS it (no new
//!   publication), against an in-flight claim answers 409
//!   `IDEMPOTENCY_IN_FLIGHT`;
//! - an upload can be HELD (claimed, never answered — the client is then
//!   killed mid-request), COMMITTED-THEN-DROPPED (published, connection
//!   closed without a response: a lost acknowledgement) or DROPPED
//!   UNPROCESSED (the request never reached the server);
//! - `GET /api/v1/upload/operation`, answering with the caller's `scope_id`
//!   derived exactly as the Worker derives it (see [`worker_scope_id`]);
//! - `GET /api/v1/qub/{tx_id}` and the public `/bytes` route, with every
//!   request counted.
//!
//! Every scenario asserts the number of publications on the mock.

// The mock deliberately holds its state lock across each routing decision
// (that IS the atomicity of the Worker's idempotency claim it models), and
// its routing reads more clearly as `match` than as `map_or_else` chains.
#![allow(clippy::significant_drop_tightening, clippy::option_if_let_else)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const BIN_PATH: &str = env!("CARGO_BIN_EXE_qub-mcp");

/// Upper bound on every wait in this file.
const WAIT: Duration = Duration::from_secs(30);

// ===========================================================================
// Mock Worker
// ===========================================================================

/// How the mock treats the next upload that is not a replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UploadMode {
    /// Publish and answer 200.
    Normal,
    /// Claim (in flight) and never answer.
    Hold,
    /// Publish, then close the connection without answering.
    CommitThenDrop,
    /// Close the connection without processing the request at all: no
    /// claim, no publication. The request never reached the server.
    DropUnprocessed,
}

#[derive(Clone, Debug)]
enum Claim {
    InFlight,
    Abandoned,
    Published { tx_id: String, qub_id: String },
}

#[derive(Clone, Debug)]
struct Publication {
    scope: String,
    idempotency_key: String,
    tx_id: String,
    wrapped_b64: String,
}

/// The idempotency scope an API key resolves to.
#[derive(Clone, Debug)]
struct KeyScope {
    /// `scope` member of the lookup answer: `grant` or `key`.
    kind: &'static str,
    /// The mock's own claim-table scope (`grant:<id>` / `key:<raw key>`).
    scope: String,
    /// `scope_id` member of the lookup answer.
    scope_id: String,
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// `scope_id` exactly as the Worker derives it
/// (`uploadIdempotencyScopeId` in `workers/api/src/routes/upload.ts`):
/// lowercase hex SHA-256 of `"qub-upload-scope-v1" ‖ NUL ‖ shard`, where
/// the shard is `trial:<grant id>` for a trial key and the key hash
/// (SHA-256 hex of the raw key) for a paid one.
fn worker_scope_id(shard: &str) -> String {
    sha256_hex(&format!("qub-upload-scope-v1\0{shard}"))
}

/// The Worker's `IDEMPOTENCY_KEY_PATTERN`
/// (`workers/api/src/utils/validation.ts`): `^[A-Za-z0-9._-]{1,255}$`.
fn is_worker_idempotency_key(key: &str) -> bool {
    (1..=255).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The `Idempotency-Key` header, if present and well-formed.
fn idempotency_key_of(req: &Request) -> Option<String> {
    req.header("idempotency-key")
        .filter(|key| is_worker_idempotency_key(key))
        .map(str::to_owned)
}

fn trial_scope_id(grant: &str) -> String {
    worker_scope_id(&format!("trial:{grant}"))
}

fn paid_scope_id(raw_key: &str) -> String {
    worker_scope_id(&sha256_hex(raw_key))
}

#[derive(Default)]
struct Inner {
    /// API key → its idempotency scope.
    keys: HashMap<String, KeyScope>,
    claims: HashMap<(String, String), Claim>,
    publications: Vec<Publication>,
    /// `Idempotency-Key` of every upload POST that passed validation.
    upload_posts: Vec<String>,
    /// `device_id` of every upload POST.
    device_ids: Vec<String>,
    lookups: usize,
    qub_reads: usize,
    bytes_requests: usize,
    bytes_with_auth: usize,
    next_upload: Option<UploadMode>,
    lookup_force_unknown: bool,
    read_failure: Option<(u16, String, Option<String>)>,
    held: usize,
    release_holds: bool,
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

enum Action {
    Respond {
        status: u16,
        body: Vec<u8>,
        extra: Vec<(String, String)>,
    },
    Hold,
    Drop,
}

fn json_response(status: u16, body: &Value) -> Action {
    Action::Respond {
        status,
        body: serde_json::to_vec(body).unwrap(),
        extra: Vec::new(),
    }
}

fn error_response(status: u16, code: &str) -> Action {
    json_response(
        status,
        &json!({"code": code, "error": format!("mock: {code}")}),
    )
}

/// The test's handle on the mock. Dropping it releases held uploads.
struct Mock {
    server: Server,
    port: u16,
}

/// Connection-side state shared by the accept loop and its threads.
#[derive(Clone)]
struct Server {
    shared: Arc<(Mutex<Inner>, Condvar)>,
}

impl Mock {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock");
        let port = listener.local_addr().unwrap().port();
        let server = Server {
            shared: Arc::new((Mutex::new(Inner::default()), Condvar::new())),
        };
        let acceptor = server.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let conn = acceptor.clone();
                thread::spawn(move || conn.serve(stream));
            }
        });
        Self { server, port }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.server.lock()
    }

    fn add_trial_key(&self, key: &str, grant: &str) {
        self.lock().keys.insert(
            key.to_string(),
            KeyScope {
                kind: "grant",
                scope: format!("grant:{grant}"),
                scope_id: trial_scope_id(grant),
            },
        );
    }

    fn add_paid_key(&self, key: &str) {
        self.lock().keys.insert(
            key.to_string(),
            KeyScope {
                kind: "key",
                scope: format!("key:{key}"),
                scope_id: paid_scope_id(key),
            },
        );
    }

    fn set_next_upload(&self, mode: UploadMode) {
        self.lock().next_upload = Some(mode);
    }

    /// Wait (bounded) until `n` uploads are being held.
    fn wait_for_held(&self, n: usize) {
        let (lock, cvar) = &*self.server.shared;
        let deadline = Instant::now() + WAIT;
        let mut inner = lock.lock().unwrap();
        while inner.held < n {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out waiting for a held upload");
            inner = cvar.wait_timeout(inner, left).unwrap().0;
        }
    }

    /// The Worker fenced and refunded the claims whose isolate died.
    fn abandon_in_flight(&self) {
        for claim in self.lock().claims.values_mut() {
            if matches!(claim, Claim::InFlight) {
                *claim = Claim::Abandoned;
            }
        }
    }

    /// ANOTHER client has already published under `idempotency_key` in
    /// `api_key`'s scope: a different artifact, claiming the same qub id.
    /// This is what a second installation that derived the same key would
    /// have left on the server. Returns that publication's `tx_id`.
    fn publish_foreign(&self, api_key: &str, idempotency_key: &str, qub_id: &str) -> String {
        let mut inner = self.lock();
        let scope = inner.keys[api_key].scope.clone();
        let tx_id = format!("mocktx{:037}", inner.publications.len() + 1);
        inner.claims.insert(
            (scope.clone(), idempotency_key.to_string()),
            Claim::Published {
                tx_id: tx_id.clone(),
                qub_id: qub_id.to_string(),
            },
        );
        inner.publications.push(Publication {
            scope,
            idempotency_key: idempotency_key.to_string(),
            tx_id: tx_id.clone(),
            wrapped_b64: BASE64.encode(b"another installation's artifact"),
        });
        tx_id
    }

    fn publications(&self) -> Vec<Publication> {
        self.lock().publications.clone()
    }

    fn upload_posts(&self) -> Vec<String> {
        self.lock().upload_posts.clone()
    }
}

impl Server {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.shared.0.lock().unwrap()
    }

    fn serve(&self, mut stream: TcpStream) {
        stream.set_read_timeout(Some(WAIT)).ok();
        let Some(request) = read_request(&stream) else {
            return;
        };
        match self.route(&request) {
            Action::Respond {
                status,
                body,
                extra,
            } => {
                let mut head = format!(
                    "HTTP/1.1 {status} MOCK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (name, value) in extra {
                    let _ = write!(head, "{name}: {value}\r\n");
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            },
            Action::Hold => {
                let (lock, cvar) = &*self.shared;
                let deadline = Instant::now() + Duration::from_mins(2);
                let mut inner = lock.lock().unwrap();
                while !inner.release_holds && Instant::now() < deadline {
                    let left = deadline.saturating_duration_since(Instant::now());
                    inner = cvar.wait_timeout(inner, left).unwrap().0;
                }
                drop(inner);
                drop(stream);
            },
            Action::Drop => drop(stream),
        }
    }

    fn route(&self, req: &Request) -> Action {
        let path = req.path.split('?').next().unwrap_or("");
        match (req.method.as_str(), path) {
            ("POST", "/api/v1/upload") => self.upload(req),
            ("GET", "/api/v1/upload/operation") => self.lookup(req),
            ("GET", p) if p.starts_with("/api/v1/qub/") => {
                let rest = &p["/api/v1/qub/".len()..];
                match rest.strip_suffix("/bytes") {
                    Some(tx_id) => self.bytes(req, tx_id),
                    None => self.read(req, rest),
                }
            },
            _ => error_response(404, "NOT_FOUND"),
        }
    }

    fn scope_of(inner: &Inner, req: &Request) -> Option<KeyScope> {
        let key = req.header("authorization")?.strip_prefix("Bearer ")?;
        inner.keys.get(key).cloned()
    }

    fn upload(&self, req: &Request) -> Action {
        let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
            return error_response(400, "invalid_json");
        };
        let device_id = body["device_id"].as_str().unwrap_or("");
        if device_id.len() != 32
            || !device_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return error_response(400, "invalid_device_id");
        }
        let mut inner = self.lock();
        let Some(KeyScope { scope, .. }) = Self::scope_of(&inner, req) else {
            return error_response(401, "invalid_api_key");
        };
        let Some(idem) = idempotency_key_of(req) else {
            return error_response(400, "IDEMPOTENCY_KEY_INVALID");
        };
        if inner.next_upload == Some(UploadMode::DropUnprocessed) {
            inner.next_upload = None;
            return Action::Drop;
        }
        let qub_id = body["qub_id_hex"].as_str().unwrap_or("").to_string();
        inner.upload_posts.push(idem.clone());
        inner.device_ids.push(device_id.to_string());
        let claim_key = (scope.clone(), idem.clone());
        match inner.claims.get(&claim_key).cloned() {
            Some(Claim::Published {
                tx_id,
                qub_id: claimed,
            }) => {
                if claimed == qub_id {
                    json_response(
                        200,
                        &json!({"tx_id": tx_id, "qub_id_hex": qub_id, "replayed": true}),
                    )
                } else {
                    error_response(409, "IDEMPOTENCY_KEY_CONFLICT")
                }
            },
            Some(Claim::InFlight) => error_response(409, "IDEMPOTENCY_IN_FLIGHT"),
            Some(Claim::Abandoned) | None => {
                let mode = inner.next_upload.take().unwrap_or(UploadMode::Normal);
                if mode == UploadMode::Hold {
                    inner.claims.insert(claim_key, Claim::InFlight);
                    inner.held += 1;
                    self.shared.1.notify_all();
                    return Action::Hold;
                }
                let tx_id = format!("mocktx{:037}", inner.publications.len() + 1);
                inner.claims.insert(
                    claim_key,
                    Claim::Published {
                        tx_id: tx_id.clone(),
                        qub_id: qub_id.clone(),
                    },
                );
                inner.publications.push(Publication {
                    scope,
                    idempotency_key: idem,
                    tx_id: tx_id.clone(),
                    wrapped_b64: body["wrapped_cbor_base64"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                });
                if mode == UploadMode::CommitThenDrop {
                    Action::Drop
                } else {
                    json_response(200, &json!({"tx_id": tx_id, "qub_id_hex": qub_id}))
                }
            },
        }
    }

    fn lookup(&self, req: &Request) -> Action {
        let mut inner = self.lock();
        let Some(KeyScope {
            kind,
            scope,
            scope_id,
        }) = Self::scope_of(&inner, req)
        else {
            return error_response(401, "invalid_api_key");
        };
        let Some(idem) = idempotency_key_of(req) else {
            return error_response(400, "IDEMPOTENCY_KEY_INVALID");
        };
        inner.lookups += 1;
        let claim = if inner.lookup_force_unknown {
            None
        } else {
            inner.claims.get(&(scope, idem)).cloned()
        };
        // Like the Worker, every answer names the caller's scope.
        let mut body = json!({"scope": kind, "scope_id": scope_id});
        match claim {
            None => body["state"] = json!("unknown"),
            Some(Claim::InFlight) => body["state"] = json!("in_flight"),
            Some(Claim::Abandoned) => body["state"] = json!("abandoned_refunded"),
            Some(Claim::Published { tx_id, .. }) => {
                body["state"] = json!("published");
                body["tx_id"] = json!(tx_id);
            },
        }
        json_response(200, &body)
    }

    fn read(&self, req: &Request, tx_id: &str) -> Action {
        let mut inner = self.lock();
        if Self::scope_of(&inner, req).is_none() {
            return error_response(401, "invalid_api_key");
        }
        inner.qub_reads += 1;
        if let Some((status, code, retry_after)) = inner.read_failure.clone() {
            let Action::Respond { body, .. } = error_response(status, &code) else {
                unreachable!()
            };
            return Action::Respond {
                status,
                body,
                extra: retry_after
                    .map(|v| vec![("Retry-After".to_string(), v)])
                    .unwrap_or_default(),
            };
        }
        match inner.publications.iter().find(|p| p.tx_id == tx_id) {
            Some(p) => json_response(
                200,
                &json!({"tx_id": p.tx_id, "wrapped_cbor_base64": p.wrapped_b64}),
            ),
            None => error_response(404, "NOT_FOUND"),
        }
    }

    fn bytes(&self, req: &Request, tx_id: &str) -> Action {
        let mut inner = self.lock();
        inner.bytes_requests += 1;
        if req.header("authorization").is_some() {
            inner.bytes_with_auth += 1;
        }
        match inner.publications.iter().find(|p| p.tx_id == tx_id) {
            Some(p) => Action::Respond {
                status: 200,
                body: BASE64.decode(&p.wrapped_b64).unwrap(),
                extra: Vec::new(),
            },
            None => error_response(404, "NOT_FOUND"),
        }
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.server.shared.0.lock() {
            inner.release_holds = true;
        }
        self.server.shared.1.notify_all();
    }
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            return None;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

// ===========================================================================
// Harness
// ===========================================================================

/// A unique scratch state directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "qub-mcp-recovery-{tag}-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn ops(&self) -> PathBuf {
        self.0.join("ops")
    }

    /// Every parseable journal record.
    fn records(&self) -> Vec<Value> {
        let Ok(dir) = fs::read_dir(self.ops()) else {
            return Vec::new();
        };
        dir.filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
            .collect()
    }

    fn only_record(&self) -> Value {
        let records = self.records();
        assert_eq!(records.len(), 1, "expected exactly one journal record");
        records.into_iter().next().unwrap()
    }

    fn record_path(&self, record: &Value) -> PathBuf {
        self.ops()
            .join(format!("{}.json", record["operation_id"].as_str().unwrap()))
    }

    /// Damage the record as a torn write would: cut its last `n` bytes.
    /// The result is no longer JSON, but everything before the cut —
    /// the idempotency key and the wrapper key among it — is untouched.
    fn truncate_record(&self, record: &Value, n: usize) {
        let path = self.record_path(record);
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - n]).unwrap();
    }

    /// Rewrite the record as a qub-mcp from before `scope_id` existed
    /// would have left it.
    fn strip_scope_id(&self, record: &Value) {
        let mut old = record.clone();
        assert!(
            old.as_object_mut().unwrap().remove("scope_id").is_some(),
            "the record should have journaled a scope_id"
        );
        fs::write(
            self.record_path(record),
            serde_json::to_vec_pretty(&old).unwrap(),
        )
        .unwrap();
    }
}

impl TempDir {
    /// Overwrite the record's file with `edited`.
    fn write_record(&self, record: &Value, edited: &Value) {
        fs::write(
            self.record_path(record),
            serde_json::to_vec_pretty(edited).unwrap(),
        )
        .unwrap();
    }

    /// Rewrite the record as the qub-mcp from before the random key
    /// component would have journaled it: `Idempotency-Key` =
    /// `qub-<qub_id_hex>`. Returns that key.
    fn rewrite_with_legacy_key(&self, record: &Value) -> String {
        let legacy = format!("qub-{}", record["qub_id_hex"].as_str().unwrap());
        let mut old = record.clone();
        old["idempotency_key"] = json!(legacy);
        self.write_record(record, &old);
        legacy
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A running `qub-mcp` child, killed and reaped on drop.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    stdout_log: Arc<Mutex<String>>,
    stderr_thread: Option<JoinHandle<String>>,
    next_id: u64,
}

impl Mcp {
    fn spawn(base_url: &str, state: &TempDir, api_key: Option<&str>) -> Self {
        let mut cmd = Command::new(BIN_PATH);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("QUB_BASE_URL", base_url)
            .env("QUB_MCP_STATE_DIR", state.path())
            .env("QUB_MCP_ALLOW_CREATE", "1")
            .env("NO_PROXY", "*")
            .env("no_proxy", "*");
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            cmd.env_remove(var);
        }
        match api_key {
            Some(key) => cmd.env("QUB_API_KEY", key),
            None => cmd.env_remove("QUB_API_KEY"),
        };
        let mut child = cmd.spawn().expect("spawn qub-mcp");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();

        let (tx, rx) = mpsc::channel();
        let stdout_log = Arc::new(Mutex::new(String::new()));
        let log = Arc::clone(&stdout_log);
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                log.lock().unwrap().push_str(&line);
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr_thread = thread::spawn(move || {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            buf
        });
        Self {
            child,
            stdin,
            lines: rx,
            stdout_log,
            stderr_thread: Some(stderr_thread),
            next_id: 1,
        }
    }

    /// Send a `tools/call` frame without waiting for the answer.
    fn send(&mut self, tool: &str, arguments: &Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let frame = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        });
        let stdin = self.stdin.as_mut().unwrap();
        stdin
            .write_all(format!("{frame}\n").as_bytes())
            .expect("write frame");
        stdin.flush().unwrap();
        id
    }

    /// Call a tool and return its `result` object (bounded wait).
    fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        let id = self.send(tool, arguments);
        let line = self
            .lines
            .recv_timeout(WAIT)
            .unwrap_or_else(|e| panic!("no response to {tool} within {WAIT:?}: {e}"));
        let response: Value = serde_json::from_str(&line).expect("response is JSON");
        assert_eq!(response["id"], id, "response id mismatch: {response}");
        response["result"].clone()
    }

    /// Kill the process (as a crash would), reap it, and return
    /// `(stdout, stderr)` as seen so far.
    fn kill(mut self) -> (String, String) {
        self.reap()
    }

    fn reap(&mut self) -> (String, String) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stderr = self
            .stderr_thread
            .take()
            .map(|t| t.join().unwrap_or_default())
            .unwrap_or_default();
        let stdout = self.stdout_log.lock().unwrap().clone();
        (stdout, stderr)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.reap();
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn text(result: &Value) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content: {result}"))
        .to_string()
}

fn is_error(result: &Value) -> bool {
    result["isError"].as_bool().unwrap_or(false)
}

/// Parse the JSON payload of a tool result (skipping any prose prefix).
fn payload(result: &Value) -> Value {
    let text = text(result);
    let start = text
        .find('{')
        .unwrap_or_else(|| panic!("no JSON in: {text}"));
    serde_json::from_str(&text[start..]).unwrap_or_else(|e| panic!("bad JSON ({e}): {text}"))
}

fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

/// Block until the wall clock is within the first 100 ms of a second, so
/// that what follows has ~900 ms before the seconds counter ticks.
fn wait_for_second_start() {
    loop {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_millis();
        if millis < 100 {
            return;
        }
        thread::sleep(Duration::from_millis(u64::from(1000 - millis)));
    }
}

/// The `Idempotency-Key` of a new operation: `qub-<qub id>-<nonce>`, the
/// nonce being 32 lowercase hex characters.
fn assert_operation_key(key: &str, qub_id: &str) {
    let nonce = key
        .strip_prefix(&format!("qub-{qub_id}-"))
        .unwrap_or_else(|| panic!("{key} is not qub-<qub_id>-<nonce>"));
    assert!(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "{key}: the nonce must be 32 lowercase hex characters"
    );
}

/// True when the binary's own read path unwraps the publication `tx_id`
/// with `key` and finds the qub `qub_id` inside. Never prints the key.
fn key_opens_tx(mcp: &mut Mcp, tx_id: &Value, key: &Value, qub_id: &Value) -> bool {
    let read = mcp.call("read_qub", &json!({"tx_id": tx_id, "key_base64url": key}));
    !is_error(&read) && payload(&read)["qub_id"] == *qub_id
}

/// A create result must be THIS installation's publication: the journaled
/// wrapper key, a transaction holding the journaled ciphertext under the
/// journaled Idempotency-Key, and — the property a caller depends on —
/// the returned key opens the returned transaction.
///
/// Compares secrets with `assert!`, never `assert_eq!`: a failure must not
/// print a wrapper key.
fn assert_own_publication(who: &str, mcp: &mut Mcp, out: &Value, record: &Value, mock: &Mock) {
    assert!(
        out["wrapper_key_b64url"].is_string()
            && out["wrapper_key_b64url"] == record["wrapper_key_b64url"],
        "{who}: the result must carry the journaled wrapper key"
    );
    let tx_id = out["tx_id"].as_str().unwrap();
    assert!(
        key_opens_tx(
            mcp,
            &out["tx_id"],
            &out["wrapper_key_b64url"],
            &out["qub_id"]
        ),
        "{who}: the returned wrapper key does not open the returned transaction {tx_id}"
    );
    let published = mock
        .publications()
        .into_iter()
        .find(|p| p.tx_id == tx_id)
        .unwrap_or_else(|| panic!("{who}: {tx_id} is not a publication"));
    assert!(
        Some(published.wrapped_b64.as_str())
            == record["upload_body"]["wrapped_cbor_base64"].as_str(),
        "{who}: {tx_id} does not hold this installation's ciphertext"
    );
    assert_eq!(
        published.idempotency_key,
        record["idempotency_key"].as_str().unwrap(),
        "{who}: {tx_id} was published under another operation's Idempotency-Key"
    );
}

fn create_args(body: &str, unlock_at: i64) -> Value {
    json!({"body": body, "unlock_at": unlock_at, "intent": "prediction"})
}

fn assert_success(result: &Value) -> Value {
    assert!(!is_error(result), "expected success, got: {}", text(result));
    let out = payload(result);
    assert!(out["tx_id"].is_string(), "no tx_id: {out}");
    out
}

/// A resumed result must be THE journaled qub: same qub id, same wrapper
/// key, and the publication it names must carry the journaled ciphertext.
///
/// Checking the qub id alone is not enough: it is derived from content
/// and a seconds-resolution `created_at`, so a defective resume that
/// re-seals within the same second reproduces it while generating a NEW K
/// (and a new Idempotency-Key, so a second publication).
fn assert_same_qub(out: &Value, first_record: &Value, mock: &Mock) {
    assert_eq!(out["qub_id"], first_record["qub_id_hex"]);
    let key = first_record["wrapper_key_b64url"].as_str().unwrap();
    assert_eq!(
        out["wrapper_key_b64url"], key,
        "resume must return the journaled wrapper key"
    );
    assert!(
        out["delivery_url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("#{key}")),
        "delivery URL must carry the journaled key"
    );
    let tx_id = out["tx_id"].as_str().unwrap();
    let published = mock
        .publications()
        .into_iter()
        .find(|p| p.tx_id == tx_id)
        .expect("the result's tx_id is a publication");
    assert_eq!(
        published.wrapped_b64,
        first_record["upload_body"]["wrapped_cbor_base64"]
            .as_str()
            .unwrap(),
        "the published bytes must be the journaled ciphertext"
    );
}

// ===========================================================================
// Scenarios
// ===========================================================================

/// 0. The server cannot be reached at all. The scope the upload would be
///    sent under cannot be journaled, so NOTHING is sent: the record stays
///    `prepared`, and the retry sends it for the first time.
#[test]
fn unreachable_server_leaves_operation_prepared_then_publishes_once() {
    let state = TempDir::new("unreachable");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("server unreachable", now() + 3600);

    let mut first = Mcp::spawn(&closed_port_url(), &state, Some("paid-a"));
    let result = first.call("create_qub", &args);
    assert!(is_error(&result), "an unreachable server must fail");
    let err = payload(&result);
    assert_eq!(err["code"], "lookup_failed");
    let record = state.only_record();
    assert_eq!(record["state"], "prepared", "nothing was sent");
    assert_eq!(record["scope_id"], Value::Null);
    assert_eq!(err["operation_id"], record["operation_id"]);
    first.kill();

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&second.call("create_qub", &args));
    assert_eq!(mock.publications().len(), 1, "exactly one publication");
    assert_eq!(mock.upload_posts().len(), 1, "sent exactly once");
    assert_same_qub(&out, &record, &mock);
    assert_eq!(out["resumed"], true);
    assert_eq!(
        state.only_record()["scope_id"],
        paid_scope_id("paid-a").as_str(),
        "the scope is journaled with the first send"
    );
}

/// 1. Killed before the request reached the server: the record exists
///    (`sent`) but nothing was published. Restart → one publication.
#[test]
fn kill_before_request_sent_then_resume_publishes_once() {
    let state = TempDir::new("before-send");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::DropUnprocessed);
    let args = create_args("restart before send", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let result = first.call("create_qub", &args);
    assert!(is_error(&result), "a dropped upload must fail");
    let err = payload(&result);
    assert_eq!(err["code"], "upload_failed");
    let record = state.only_record();
    assert_eq!(record["state"], "sent");
    assert_eq!(record["scope_id"], paid_scope_id("paid-a").as_str());
    assert_eq!(err["operation_id"], record["operation_id"]);
    assert_eq!(mock.publications().len(), 0, "nothing was published");
    let key = record["wrapper_key_b64url"].as_str().unwrap().to_string();
    let (stdout, stderr) = first.kill();
    assert!(!stderr.contains(&key), "stderr leaked the wrapper key");
    assert!(
        !stdout.contains(&key),
        "an error result leaked the wrapper key"
    );

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&second.call("create_qub", &args));
    let publications = mock.publications();
    assert_eq!(publications.len(), 1, "exactly one publication");
    assert_eq!(out["tx_id"], publications[0].tx_id.as_str());
    assert_eq!(out["resumed"], true);
    assert_eq!(out["operation_id"], record["operation_id"]);
    assert_same_qub(&out, &record, &mock);
    // The key that went on the wire is the journaled one, in the
    // per-operation format.
    assert_eq!(
        publications[0].idempotency_key,
        record["idempotency_key"].as_str().unwrap()
    );
    assert_operation_key(
        &publications[0].idempotency_key,
        record["qub_id_hex"].as_str().unwrap(),
    );

    // A further identical call returns the stored result — no network.
    let posts_before = mock.upload_posts().len();
    let again = assert_success(&second.call("create_qub", &args));
    assert_eq!(again["tx_id"], out["tx_id"]);
    assert_eq!(again["resumed"], true);
    assert_eq!(mock.upload_posts().len(), posts_before);
    assert_eq!(mock.publications().len(), 1);
    assert_eq!(state.only_record()["state"], "completed");
}

/// 2. Killed while the server holds the upload; the Worker later fences
///    and refunds the dead claim. Restart → the same body is re-POSTed
///    under the same Idempotency-Key → one publication.
#[test]
fn kill_while_upload_held_then_resume_publishes_once() {
    let state = TempDir::new("held");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::Hold);
    let args = create_args("held upload", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    first.send("create_qub", &args);
    mock.wait_for_held(1);
    assert_eq!(state.only_record()["state"], "sent");
    let (_, stderr) = first.kill();
    mock.abandon_in_flight();

    let record = state.only_record();
    let key = record["wrapper_key_b64url"].as_str().unwrap();
    assert!(!stderr.contains(key));

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&second.call("create_qub", &args));
    assert_eq!(mock.publications().len(), 1, "exactly one publication");
    let posts = mock.upload_posts();
    assert_eq!(posts.len(), 2, "original POST + one resume POST");
    assert_eq!(posts[0], posts[1], "resume must reuse the Idempotency-Key");
    assert_same_qub(&out, &record, &mock);
    assert_eq!(out["resumed"], true);
}

/// 2a. Two processes sharing one state directory: the second must not seal
///     or send anything while the first owns the operation, and once the
///     first dies its lock is released and the second resumes the SAME qub.
#[test]
fn concurrent_processes_share_one_operation() {
    let state = TempDir::new("two-procs");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::Hold);
    let args = create_args("two processes", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    first.send("create_qub", &args);
    mock.wait_for_held(1);
    let record = state.only_record();

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let blocked = second.call("create_qub", &args);
    assert!(
        is_error(&blocked),
        "second process must not proceed: {blocked}"
    );
    assert!(
        text(&blocked).contains("operation_in_progress"),
        "unexpected refusal: {}",
        text(&blocked)
    );
    assert_eq!(
        mock.upload_posts().len(),
        1,
        "the second process sent nothing"
    );
    assert_eq!(
        state.only_record(),
        record,
        "the journal record was not rewritten"
    );

    // The owner crashes; the OS releases its lock.
    first.kill();
    mock.abandon_in_flight();
    let out = assert_success(&second.call("create_qub", &args));
    assert_eq!(mock.publications().len(), 1, "exactly one publication");
    assert_same_qub(&out, &record, &mock);
    assert_eq!(out["resumed"], true);
}

/// 2b. Even if the lookup (wrongly) reports `unknown` for an operation
///     that WAS published, the resume re-POST carries the original
///     Idempotency-Key and qub, so the server replays it: still one
///     publication and the original `tx_id`.
#[test]
fn resume_repost_is_a_replay_not_a_second_publication() {
    let state = TempDir::new("replay");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("replayed upload", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    let record = state.only_record();
    mock.lock().lookup_force_unknown = true;

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&second.call("create_qub", &args));
    let publications = mock.publications();
    assert_eq!(publications.len(), 1, "replay must not publish again");
    assert_eq!(out["tx_id"], publications[0].tx_id.as_str());
    assert_same_qub(&out, &record, &mock);
    let posts = mock.upload_posts();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
}

/// 3. Lost acknowledgement: the server published, the client never saw a
///    `tx_id`. Restart → resolved via lookup with no second POST.
#[test]
fn lost_ack_resumes_via_lookup_without_reposting() {
    let state = TempDir::new("lost-ack");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("lost ack", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let result = first.call("create_qub", &args);
    assert!(is_error(&result), "a dropped connection is not a success");
    let tx_id = mock.publications()[0].tx_id.clone();
    assert!(
        !text(&result).contains(&tx_id),
        "client must not have seen the tx_id"
    );
    first.kill();
    let record = state.only_record();

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&second.call("create_qub", &args));
    assert_eq!(out["tx_id"], tx_id.as_str());
    assert_same_qub(&out, &record, &mock);
    assert_eq!(mock.publications().len(), 1, "exactly one publication");
    assert_eq!(
        mock.upload_posts().len(),
        1,
        "no re-POST after a published lookup"
    );
    assert_eq!(
        mock.lock().lookups,
        2,
        "one lookup before the first send, one on resume"
    );
}

/// 4a. Trial keys share the account grant's idempotency scope, so a
///     rotated trial key resumes the same operation.
#[test]
fn rotated_trial_key_resumes_same_operation() {
    let state = TempDir::new("trial-rotate");
    let mock = Mock::start();
    mock.add_trial_key("trial-a", "g1");
    mock.add_trial_key("trial-b", "g1");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("trial rotation", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("trial-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    let record = state.only_record();
    assert_eq!(record["scope_id"], trial_scope_id("g1").as_str());
    // Force the re-POST path: the grant-scoped replay must still hold.
    mock.lock().lookup_force_unknown = true;

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("trial-b"));
    let out = assert_success(&second.call("create_qub", &args));
    let publications = mock.publications();
    assert_eq!(publications.len(), 1, "exactly one publication");
    assert_eq!(publications[0].scope, "grant:g1");
    assert_eq!(out["tx_id"], publications[0].tx_id.as_str());
    assert_same_qub(&out, &record, &mock);
}

/// 4b. Paid keys scope idempotency to the key: after a rotation the
///     server cannot recognise the operation, so resuming would publish a
///     second time. That requires explicit consent.
#[test]
fn rotated_paid_key_needs_explicit_recovery() {
    let state = TempDir::new("paid-rotate");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.add_paid_key("paid-b");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("paid rotation", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    assert_eq!(mock.publications().len(), 1);
    let record = state.only_record();

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-b"));
    let result = second.call("create_qub", &args);
    assert!(is_error(&result));
    assert_eq!(payload(&result)["code"], "needs_explicit_recovery");
    assert_eq!(mock.upload_posts().len(), 1, "no re-POST without consent");
    assert_eq!(mock.publications().len(), 1);
    assert_eq!(state.only_record()["state"], "sent", "record kept");

    let mut consent = args.clone();
    consent["allow_republish"] = json!(true);
    let out = assert_success(&second.call("create_qub", &consent));
    let publications = mock.publications();
    assert_eq!(
        publications.len(),
        2,
        "explicit republish under the new key"
    );
    let under_b: Vec<_> = publications
        .iter()
        .filter(|p| p.scope == "key:paid-b")
        .collect();
    assert_eq!(
        under_b.len(),
        1,
        "exactly one publication under the new key"
    );
    assert_eq!(out["tx_id"], under_b[0].tx_id.as_str());
    assert_same_qub(&out, &record, &mock);
}

/// An operation published (acknowledgement lost) under `first_key` is
/// resumed with `second_key`, which resolves to a DIFFERENT idempotency
/// scope. The server derives another operation id there, answers
/// `unknown`, and would execute a resend as a fresh publication — so the
/// resume must refuse until `allow_republish: true` says otherwise.
fn assert_other_scope_needs_consent(
    tag: &str,
    mock: &Mock,
    first_key: &str,
    second_key: &str,
    second_scope: &str,
) {
    let state = TempDir::new(tag);
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args(tag, now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some(first_key));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    assert_eq!(mock.publications().len(), 1);
    let record = state.only_record();

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some(second_key));
    let result = second.call("create_qub", &args);
    assert!(
        is_error(&result),
        "a resend in another scope needs consent: {}",
        text(&result)
    );
    assert_eq!(payload(&result)["code"], "needs_explicit_recovery");
    assert_eq!(mock.upload_posts().len(), 1, "no re-POST without consent");
    assert_eq!(mock.publications().len(), 1, "exactly one publication");
    assert_eq!(state.only_record(), record, "record left untouched");

    let mut consent = args.clone();
    consent["allow_republish"] = json!(true);
    let out = assert_success(&second.call("create_qub", &consent));
    let publications = mock.publications();
    assert_eq!(publications.len(), 2, "explicit republish in the new scope");
    let in_new_scope: Vec<_> = publications
        .iter()
        .filter(|p| p.scope == second_scope)
        .collect();
    assert_eq!(in_new_scope.len(), 1, "exactly one in the new scope");
    assert_eq!(out["tx_id"], in_new_scope[0].tx_id.as_str());
    assert_same_qub(&out, &record, mock);
}

/// 4c. Sent under a PAID key, resumed with a TRIAL key. That the current
///     key is grant-scoped says nothing about the scope of the original
///     send: the grant has never seen this operation.
#[test]
fn paid_operation_resumed_with_trial_key_needs_explicit_recovery() {
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.add_trial_key("trial-a", "g1");
    assert_other_scope_needs_consent("paid-to-trial", &mock, "paid-a", "trial-a", "grant:g1");
}

/// 4d. Sent under one trial grant, resumed with a key of ANOTHER grant.
///     Trial idempotency is per grant, not per "trial".
#[test]
fn trial_operation_resumed_under_another_grant_needs_explicit_recovery() {
    let mock = Mock::start();
    mock.add_trial_key("trial-a", "g1");
    mock.add_trial_key("trial-c", "g2");
    assert_other_scope_needs_consent("cross-grant", &mock, "trial-a", "trial-c", "grant:g2");
}

/// 4e. A record journaled before `scope_id` existed carries no scope to
///     compare, so only the very same API key is provably the same scope:
///     a rotated key of the same grant is refused (conservatively), the
///     original key resumes.
#[test]
fn journal_without_scope_id_resumes_only_under_the_same_key() {
    let state = TempDir::new("no-scope");
    let mock = Mock::start();
    mock.add_trial_key("trial-a", "g1");
    mock.add_trial_key("trial-b", "g1");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("journal without scope", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("trial-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    let record = state.only_record();
    state.strip_scope_id(&record);
    mock.lock().lookup_force_unknown = true;

    let mut rotated = Mcp::spawn(&mock.base_url(), &state, Some("trial-b"));
    let result = rotated.call("create_qub", &args);
    assert!(is_error(&result), "{}", text(&result));
    assert_eq!(payload(&result)["code"], "needs_explicit_recovery");
    assert_eq!(mock.upload_posts().len(), 1, "no re-POST without consent");
    rotated.kill();

    let mut same = Mcp::spawn(&mock.base_url(), &state, Some("trial-a"));
    let out = assert_success(&same.call("create_qub", &args));
    assert_eq!(mock.publications().len(), 1, "a replay, not a publication");
    assert_eq!(mock.upload_posts().len(), 2);
    assert_same_qub(&out, &record, &mock);
    assert_eq!(
        state.only_record()["scope_id"],
        trial_scope_id("g1").as_str(),
        "the resend journals the scope it went out under"
    );
}

/// 5. An `in_flight` lookup yields a pending (non-error) result and never
///    re-POSTs.
#[test]
fn in_flight_lookup_returns_pending_without_repost() {
    let state = TempDir::new("in-flight");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::Hold);
    let args = create_args("in flight", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    first.send("create_qub", &args);
    mock.wait_for_held(1);
    first.kill();

    let record = state.only_record();
    let key = record["wrapper_key_b64url"].as_str().unwrap().to_string();

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let result = second.call("create_qub", &args);
    assert!(
        !is_error(&result),
        "pending is not an error: {}",
        text(&result)
    );
    let out = payload(&result);
    assert_eq!(out["state"], "pending");
    assert_eq!(out["operation_id"], record["operation_id"]);
    assert!(
        !text(&result).contains(&key),
        "pending result leaked the key"
    );
    assert_eq!(mock.upload_posts().len(), 1, "no re-POST while in flight");
    assert_eq!(mock.publications().len(), 0);

    let listed = second.call("list_pending_operations", &json!({}));
    assert!(!is_error(&listed));
    assert!(!text(&listed).contains(&key), "listing leaked the key");
    let listed = payload(&listed);
    assert_eq!(listed["pending"][0]["operation_id"], record["operation_id"]);
    assert_eq!(listed["pending"][0]["state"], "sent");
    assert_eq!(listed["pending"].as_array().unwrap().len(), 1);
}

/// The refusal for an operation whose journal record is quarantined:
/// a stable code, the quarantined file named, and nothing else done.
fn assert_quarantine_refusal(result: &Value, quarantined: &Path) -> String {
    assert!(is_error(result), "expected a refusal: {}", text(result));
    let err = payload(result);
    assert_eq!(err["code"], "corrupt_operation_record");
    let path = quarantined.display().to_string();
    assert_eq!(err["quarantined_records"], json!([path]));
    let message = err["message"].as_str().unwrap().to_string();
    assert!(message.contains(&path), "{message}");
    assert!(message.contains("allow_republish"), "{message}");
    message
}

/// 6. A corrupt record with NO wrapper key left in it is quarantined and
///    reported as a lost key — and the identical retry is refused too: it
///    must not quietly start a new operation. Only explicit consent does.
#[test]
fn corrupt_keyless_record_is_quarantined_and_blocks_a_silent_restart() {
    let state = TempDir::new("corrupt");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    fs::create_dir_all(state.ops()).unwrap();
    fs::write(
        state.ops().join("corrupt-op-1.json"),
        b"{\"version\": 1, trunc",
    )
    .unwrap();
    let quarantined = state.ops().join("corrupt-op-1.json.corrupt");
    let mut args = create_args("corrupt", now() + 3600);
    args["operation_id"] = json!("corrupt-op-1");

    let mut mcp = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let message = assert_quarantine_refusal(&mcp.call("create_qub", &args), &quarantined);
    assert!(message.contains("UNRECOVERABLE"), "{message}");
    assert!(!message.contains("intact"), "{message}");
    assert!(quarantined.exists());
    assert!(!state.ops().join("corrupt-op-1.json").exists());
    assert_eq!(mock.upload_posts().len(), 0, "nothing sent");

    let listed = payload(&mcp.call("list_pending_operations", &json!({})));
    assert_eq!(listed["quarantined"][0], "corrupt-op-1.json.corrupt");

    // The identical retry: same refusal, still nothing sealed or sent.
    let message = assert_quarantine_refusal(&mcp.call("create_qub", &args), &quarantined);
    assert!(message.contains("UNRECOVERABLE"), "{message}");
    assert_eq!(mock.upload_posts().len(), 0, "the retry sent nothing");
    assert!(state.records().is_empty(), "the retry sealed nothing");

    // Explicit consent starts the new operation.
    let mut consent = args.clone();
    consent["allow_republish"] = json!(true);
    let out = assert_success(&mcp.call("create_qub", &consent));
    assert_eq!(mock.publications().len(), 1, "one consented publication");
    assert_eq!(out["resumed"], false);
    assert_same_qub(&out, &state.only_record(), &mock);
    assert!(quarantined.exists(), "the quarantined file is kept");
}

/// 6a. The reviewer's reproduction. A record truncated in its tail is not
///     JSON any more, but its wrapper key and Idempotency-Key are intact.
///     The server is asked first: the upload WAS published, so the call
///     returns its `tx_id` with the recovered key — not an error, and never
///     a second publication, however often it is repeated.
#[test]
fn truncated_record_with_intact_key_recovers_the_published_qub() {
    let state = TempDir::new("truncated-published");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("truncated but published", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    let record = state.only_record();
    let key = record["wrapper_key_b64url"].as_str().unwrap().to_string();
    let tx_id = mock.publications()[0].tx_id.clone();
    state.truncate_record(&record, 20);
    let quarantined = state.ops().join(format!(
        "{}.json.corrupt",
        record["operation_id"].as_str().unwrap()
    ));

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    for attempt in 1..=2 {
        let result = second.call("create_qub", &args);
        assert!(
            !is_error(&result),
            "attempt {attempt}: a published qub is recovered, not refused: {}",
            text(&result)
        );
        let out = payload(&result);
        assert_eq!(out["tx_id"], tx_id.as_str(), "attempt {attempt}");
        assert_eq!(out["recovered_from_quarantine"], true);
        assert_eq!(out["operation_id"], record["operation_id"]);
        assert_eq!(out["quarantined_record"], quarantined.display().to_string());
        let warning = out["warning"].as_str().unwrap();
        assert!(!warning.contains("UNRECOVERABLE"), "{warning}");
        assert!(
            !warning.contains(&key),
            "the warning must not carry the key"
        );
        assert_same_qub(&out, &record, &mock);
        assert_eq!(mock.publications().len(), 1, "attempt {attempt}");
        assert_eq!(
            mock.upload_posts().len(),
            1,
            "attempt {attempt}: no re-POST"
        );
    }
    assert!(quarantined.exists());
    assert!(
        fs::read_to_string(&quarantined).unwrap().contains(&key),
        "the quarantined file still holds the key"
    );
    assert!(state.records().is_empty(), "no new operation was sealed");
    let (_, stderr) = second.kill();
    assert!(!stderr.contains(&key), "stderr leaked the wrapper key");
}

/// 6b. The same damaged record, but the server cannot vouch for it (here
///     the lookup answers `unknown`, as it would under another key). The
///     tool must say the key is INTACT and where — never "unrecoverable",
///     never the key itself — and the identical retry must NOT publish a
///     second qub. Only `allow_republish: true` does.
#[test]
fn truncated_record_blocks_a_silent_second_publication() {
    let state = TempDir::new("truncated-unknown");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let args = create_args("truncated and unknown", now() + 3600);

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    assert_eq!(mock.publications().len(), 1);
    let record = state.only_record();
    let key = record["wrapper_key_b64url"].as_str().unwrap().to_string();
    state.truncate_record(&record, 20);
    let quarantined = state.ops().join(format!(
        "{}.json.corrupt",
        record["operation_id"].as_str().unwrap()
    ));
    mock.lock().lookup_force_unknown = true;

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    for attempt in 1..=2 {
        let result = second.call("create_qub", &args);
        let message = assert_quarantine_refusal(&result, &quarantined);
        assert!(
            message.contains("wrapper key is intact in that file"),
            "attempt {attempt}: {message}"
        );
        assert!(
            !message.contains("UNRECOVERABLE"),
            "attempt {attempt}: {message}"
        );
        assert!(
            !text(&result).contains(&key),
            "attempt {attempt}: the refusal must not carry the key"
        );
        assert_eq!(
            mock.publications().len(),
            1,
            "attempt {attempt}: an identical retry must not publish again"
        );
        assert_eq!(
            mock.upload_posts().len(),
            1,
            "attempt {attempt}: nothing sent"
        );
        assert!(
            state.records().is_empty(),
            "attempt {attempt}: nothing sealed"
        );
    }
    assert!(
        fs::read_to_string(&quarantined).unwrap().contains(&key),
        "the quarantined file still holds the key"
    );

    let mut consent = args.clone();
    consent["allow_republish"] = json!(true);
    let out = assert_success(&second.call("create_qub", &consent));
    assert_eq!(mock.publications().len(), 2, "one consented republication");
    assert_ne!(out["qub_id"], record["qub_id_hex"], "a NEW qub was sealed");
    assert_ne!(out["wrapper_key_b64url"], key.as_str());
    assert_eq!(out["resumed"], false);
    assert_same_qub(&out, &state.only_record(), &mock);
    assert!(quarantined.exists(), "the quarantined file is kept");
    let (_, stderr) = second.kill();
    assert!(!stderr.contains(&key), "stderr leaked the wrapper key");
}

/// 6c. A quarantined record still knows which request it was written for.
///     Reusing its explicit `operation_id` for a DIFFERENT request is a
///     conflict — with or without `allow_republish` — exactly as it is for
///     a live record: the other request's publication must never be
///     handed back as this one's.
#[test]
fn quarantined_record_of_another_request_is_a_conflict() {
    let state = TempDir::new("quarantine-conflict");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let mut args = create_args("the original request", now() + 3600);
    args["operation_id"] = json!("explicit-op-1");

    let mut first = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    assert!(is_error(&first.call("create_qub", &args)));
    first.kill();
    let record = state.only_record();
    let tx_id = mock.publications()[0].tx_id.clone();
    state.truncate_record(&record, 20);
    let quarantined = state.ops().join("explicit-op-1.json.corrupt");

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let mut other = create_args("a different request", now() + 3600);
    other["operation_id"] = json!("explicit-op-1");
    for allow_republish in [false, true] {
        other["allow_republish"] = json!(allow_republish);
        let result = second.call("create_qub", &other);
        assert!(is_error(&result), "{}", text(&result));
        let err = payload(&result);
        assert_eq!(err["code"], "operation_id_conflict");
        let message = err["message"].as_str().unwrap();
        assert!(
            message.contains(&quarantined.display().to_string()),
            "{message}"
        );
        assert!(!text(&result).contains(&tx_id), "{}", text(&result));
        assert_eq!(mock.publications().len(), 1);
        assert_eq!(mock.upload_posts().len(), 1, "nothing sent");
    }

    // The original request is still recovered from the same file.
    let out = payload(&second.call("create_qub", &args));
    assert_eq!(out["tx_id"], tx_id.as_str());
    assert_same_qub(&out, &record, &mock);
    assert_eq!(mock.publications().len(), 1);
}

/// 7. Permissions and secret hygiene on the happy path.
#[cfg(unix)]
#[test]
fn state_is_private_and_key_never_reaches_stderr() {
    use std::os::unix::fs::PermissionsExt as _;

    let state = TempDir::new("perms");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("permissions", now() + 3600);

    let mut mcp = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&mcp.call("create_qub", &args));
    let key = out["wrapper_key_b64url"].as_str().unwrap().to_string();
    assert_eq!(out["resumed"], false);
    let listed = mcp.call("list_pending_operations", &json!({}));
    assert!(!text(&listed).contains(&key));
    assert_eq!(payload(&listed)["pending"].as_array().unwrap().len(), 0);
    let (_, stderr) = mcp.kill();
    assert!(!stderr.contains(&key), "stderr leaked the wrapper key");

    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(state.path()), 0o700);
    assert_eq!(mode(&state.ops()), 0o700);
    for file in ["device_id", "operation_key"] {
        assert_eq!(mode(&state.path().join(file)), 0o600, "{file}");
    }
    for entry in fs::read_dir(state.ops()).unwrap() {
        let path = entry.unwrap().path();
        assert_eq!(mode(&path), 0o600, "{}", path.display());
    }

    // The installation device id is what was sent, and it is well-formed.
    let device_id = fs::read_to_string(state.path().join("device_id")).unwrap();
    assert_eq!(mock.lock().device_ids, vec![device_id.trim().to_string()]);
    assert_eq!(mock.publications().len(), 1);
}

/// 8. With a key, reads use only the authenticated API; rejections are
///    surfaced with the server code and never fall back to `/bytes`.
#[test]
fn authenticated_reads_never_fall_back_to_bytes() {
    let state = TempDir::new("reads");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("read me", now() + 3600);

    let mut mcp = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let created = assert_success(&mcp.call("create_qub", &args));
    let read_args = json!({"delivery_url": created["delivery_url"]});

    let read = mcp.call("read_qub", &read_args);
    assert!(!is_error(&read), "{}", text(&read));
    assert_eq!(payload(&read)["status"], "locked");
    assert_eq!(payload(&read)["qub_id"], created["qub_id"]);
    let status = mcp.call("check_status", &read_args);
    assert!(!is_error(&status), "{}", text(&status));
    assert_eq!(payload(&status)["status"], "locked");
    assert_eq!(mock.lock().qub_reads, 2);

    mock.lock().read_failure = Some((402, "TRIAL_READS_EXHAUSTED".to_string(), None));
    for tool in ["read_qub", "check_status"] {
        let result = mcp.call(tool, &read_args);
        assert!(is_error(&result), "{tool} must surface the 402");
        let err = payload(&result);
        assert_eq!(err["code"], "TRIAL_READS_EXHAUSTED", "{tool}");
        assert_eq!(err["status"], 402);
    }

    mock.lock().read_failure = Some((
        429,
        "RATE_LIMIT_API_KEY".to_string(),
        Some("17".to_string()),
    ));
    for tool in ["read_qub", "check_status"] {
        let result = mcp.call(tool, &read_args);
        assert!(is_error(&result), "{tool} must surface the 429");
        let err = payload(&result);
        assert_eq!(err["code"], "RATE_LIMIT_API_KEY", "{tool}");
        assert_eq!(err["retry_after"], "17", "{tool}");
    }

    let inner = mock.lock();
    assert_eq!(inner.qub_reads, 6);
    assert_eq!(
        inner.bytes_requests, 0,
        "the public bytes route must never be used"
    );
}

/// 8b. Without a key, reads use the anonymous public route and send no
///     credentials.
#[test]
fn anonymous_reads_use_public_bytes_without_credentials() {
    let state = TempDir::new("anon-reads");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("public read", now() + 3600);

    let mut creator = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let created = assert_success(&creator.call("create_qub", &args));
    creator.kill();

    let mut reader = Mcp::spawn(&mock.base_url(), &state, None);
    let read = reader.call(
        "read_qub",
        &json!({"delivery_url": created["delivery_url"]}),
    );
    assert!(!is_error(&read), "{}", text(&read));
    assert_eq!(payload(&read)["status"], "locked");
    let inner = mock.lock();
    assert_eq!(inner.bytes_requests, 1);
    assert_eq!(
        inner.bytes_with_auth, 0,
        "no credentials on the public route"
    );
    assert_eq!(inner.qub_reads, 0);
}

/// Distinct `operation_id`s are deliberate duplicates: two publications,
/// each paired with its own key and ciphertext — even when both are
/// requested within the same second, where the content-derived qub id
/// would otherwise be the same for both. Within ONE state directory the
/// second operation is re-sealed until its qub id is unused; across state
/// directories that guard sees nothing, which is what scenario 9 covers.
#[test]
fn distinct_operation_ids_publish_separate_qubs() {
    let state = TempDir::new("duplicates");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let base = create_args("same content twice", now() + 3600);
    let mut first_args = base.clone();
    first_args["operation_id"] = json!("duplicate-a");
    let mut second_args = base;
    second_args["operation_id"] = json!("duplicate-b");

    let mut mcp = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let first = assert_success(&mcp.call("create_qub", &first_args));
    let second = assert_success(&mcp.call("create_qub", &second_args));

    assert_eq!(mock.publications().len(), 2, "two deliberate publications");
    assert_ne!(first["qub_id"], second["qub_id"]);
    assert_ne!(first["tx_id"], second["tx_id"]);
    for (out, id) in [(&first, "duplicate-a"), (&second, "duplicate-b")] {
        let path = state.ops().join(format!("{id}.json"));
        let record: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_same_qub(out, &record, &mock);
    }
}

/// 9. The round-2 reviewer's reproduction. Two installations — two state
///    directories, so two journals that cannot see each other — seal the
///    same body with the same unlock time in the same second under one paid
///    key. The qub id is a function of exactly those inputs, so both derive
///    the SAME qub id for two different artifacts (two wrapper keys).
///
///    With an `Idempotency-Key` derived from the qub id, the second call was
///    answered with the first installation's transaction, paired with its
///    own wrapper key — which cannot open it — and only one publication
///    existed. Each operation must instead get its own key, its own
///    publication, and a wrapper key that opens the transaction it is
///    returned with.
///
///    The collision is forced, not hoped for: both calls are issued at the
///    start of a second, and the assertions run only on a pair whose
///    journaled qub ids ARE equal. A pair that straddled a second boundary
///    is discarded and the scenario repeated; the test fails if it never
///    obtains a collision, so it cannot pass without one.
#[test]
fn two_state_directories_sealing_the_same_qub_get_their_own_publications() {
    const ATTEMPTS: usize = 10;
    for _ in 0..ATTEMPTS {
        let mock = Mock::start();
        mock.add_paid_key("paid-a");
        let state_a = TempDir::new("same-second-a");
        let state_b = TempDir::new("same-second-b");
        let mut a = Mcp::spawn(&mock.base_url(), &state_a, Some("paid-a"));
        let mut b = Mcp::spawn(&mock.base_url(), &state_b, Some("paid-a"));

        wait_for_second_start();
        let args = create_args("one body, two installations", now() + 3600);
        let result_a = a.call("create_qub", &args);
        let result_b = b.call("create_qub", &args);
        let (record_a, record_b) = (state_a.only_record(), state_b.only_record());
        if record_a["qub_id_hex"] != record_b["qub_id_hex"] {
            continue;
        }
        let qub_id = record_a["qub_id_hex"].as_str().unwrap();

        // What each caller received: a result, for the colliding qub id,
        // whose wrapper key opens the transaction it came with.
        let out_a = assert_success(&result_a);
        let out_b = assert_success(&result_b);
        assert_eq!(out_a["qub_id"], qub_id);
        assert_eq!(out_b["qub_id"], qub_id);
        assert_own_publication("installation a", &mut a, &out_a, &record_a, &mock);
        assert_own_publication("installation b", &mut b, &out_b, &record_b, &mock);
        assert_eq!(
            mock.publications().len(),
            2,
            "two artifacts, two publications"
        );
        assert_ne!(out_a["tx_id"], out_b["tx_id"]);
        assert!(
            out_a["wrapper_key_b64url"] != out_b["wrapper_key_b64url"],
            "the two installations wrapped under different keys"
        );

        // Why: one qub id, two operations, two Idempotency-Keys.
        let key_a = record_a["idempotency_key"].as_str().unwrap();
        let key_b = record_b["idempotency_key"].as_str().unwrap();
        assert_ne!(
            key_a, key_b,
            "two installations sealing one qub id must not share an Idempotency-Key"
        );
        assert_operation_key(key_a, qub_id);
        assert_operation_key(key_b, qub_id);
        assert_eq!(
            mock.upload_posts(),
            vec![key_a.to_string(), key_b.to_string()],
            "each installation sent its own upload"
        );
        // The pairing check can fail: the other installation's transaction
        // is NOT opened by this one's key, although the qub id is the same.
        assert!(
            !key_opens_tx(
                &mut a,
                &out_b["tx_id"],
                &out_a["wrapper_key_b64url"],
                &out_a["qub_id"]
            ),
            "a's key must not open b's transaction"
        );
        assert!(
            !key_opens_tx(
                &mut b,
                &out_a["tx_id"],
                &out_b["wrapper_key_b64url"],
                &out_b["qub_id"]
            ),
            "b's key must not open a's transaction"
        );

        // Each installation's identical retry returns its own result.
        let again_a = assert_success(&a.call("create_qub", &args));
        let again_b = assert_success(&b.call("create_qub", &args));
        assert_eq!(again_a["tx_id"], out_a["tx_id"]);
        assert_eq!(again_b["tx_id"], out_b["tx_id"]);
        assert_eq!(mock.upload_posts().len(), 2, "a retry sends nothing");
        assert_eq!(mock.publications().len(), 2);
        return;
    }
    panic!(
        "no two state directories sealed the same qub id in {ATTEMPTS} attempts: \
         the scenario was never exercised"
    );
}

/// The refusal for a never-sent operation whose Idempotency-Key the server
/// reports as published: a stable code, nothing of the foreign publication
/// handed back, nothing sent.
fn assert_operation_conflict(result: &Value, record: &Value, foreign_tx: &str) {
    // A success result carries a wrapper key: name its tx_id, never its text.
    assert!(
        is_error(result),
        "expected a refusal, got a result naming tx_id {}",
        payload(result)["tx_id"]
    );
    let err = payload(result);
    assert_eq!(err["code"], "operation_conflict");
    assert_eq!(err["operation_id"], record["operation_id"]);
    let message = err["message"].as_str().unwrap();
    for needle in [
        "Idempotency-Key",
        "Nothing was sent",
        "distinct operation_id",
    ] {
        assert!(message.contains(needle), "missing {needle:?}: {message}");
    }
    assert!(
        !text(result).contains(foreign_tx),
        "the foreign transaction must not be handed to the caller"
    );
    assert!(
        !text(result).contains(record["wrapper_key_b64url"].as_str().unwrap()),
        "the refusal must not carry the wrapper key"
    );
}

/// 9a. A `prepared` operation — journaled, never sent — whose lookup
///     answers `published`. That publication cannot be this operation's:
///     nothing was ever sent for it. It must NOT be completed with that
///     transaction (its wrapper key cannot open it); it is refused with
///     `operation_conflict`, stably, with or without `allow_republish`, and
///     a distinct `operation_id` then publishes the request properly.
///
///     (The legitimate `published` answer — a `sent` record whose
///     acknowledgement was lost — is scenario 3, and still completes.)
#[test]
fn prepared_operation_refuses_a_publication_it_never_sent() {
    let state = TempDir::new("prepared-conflict");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("a key somebody else used", now() + 3600);

    // Journal the operation without sending anything.
    let mut first = Mcp::spawn(&closed_port_url(), &state, Some("paid-a"));
    assert_eq!(
        payload(&first.call("create_qub", &args))["code"],
        "lookup_failed"
    );
    first.kill();
    let record = state.only_record();
    assert_eq!(record["state"], "prepared", "nothing was sent");

    // Another installation has published under that very key.
    let foreign_tx = mock.publish_foreign(
        "paid-a",
        record["idempotency_key"].as_str().unwrap(),
        record["qub_id_hex"].as_str().unwrap(),
    );

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let mut consent = args.clone();
    consent["allow_republish"] = json!(true);
    for request in [&args, &args, &consent] {
        let result = second.call("create_qub", request);
        assert_operation_conflict(&result, &record, &foreign_tx);
        assert_eq!(mock.upload_posts().len(), 0, "nothing was sent");
        assert_eq!(mock.publications().len(), 1, "only the foreign one");
        assert_eq!(state.only_record(), record, "the record is untouched");
    }

    // A distinct operation_id seals and publishes the request for real.
    let mut fresh = args.clone();
    fresh["operation_id"] = json!("after-the-conflict");
    let out = assert_success(&second.call("create_qub", &fresh));
    assert_ne!(out["tx_id"], foreign_tx.as_str());
    assert_eq!(mock.publications().len(), 2);
    let fresh_record: Value =
        serde_json::from_slice(&fs::read(state.ops().join("after-the-conflict.json")).unwrap())
            .unwrap();
    assert_ne!(fresh_record["idempotency_key"], record["idempotency_key"]);
    assert_own_publication(
        "the fresh operation",
        &mut second,
        &out,
        &fresh_record,
        &mock,
    );
    let (_, stderr) = second.kill();
    for secret in [&record, &fresh_record] {
        assert!(
            !stderr.contains(secret["wrapper_key_b64url"].as_str().unwrap()),
            "stderr leaked a wrapper key"
        );
    }
}

/// 9b. The same rule for a QUARANTINED record that still says `prepared`:
///     the server's `published` answer for its Idempotency-Key is not its
///     own upload, so it must not be "recovered" with that transaction and
///     the salvaged wrapper key.
#[test]
fn quarantined_prepared_record_refuses_a_publication_it_never_sent() {
    let state = TempDir::new("quarantined-conflict");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("a quarantined, never-sent operation", now() + 3600);

    let mut first = Mcp::spawn(&closed_port_url(), &state, Some("paid-a"));
    assert_eq!(
        payload(&first.call("create_qub", &args))["code"],
        "lookup_failed"
    );
    first.kill();
    let record = state.only_record();
    assert_eq!(record["state"], "prepared");
    // Still JSON, no longer a loadable record: every field survives.
    let mut damaged = record.clone();
    damaged["version"] = json!(0);
    state.write_record(&record, &damaged);
    let quarantined = state.ops().join(format!(
        "{}.json.corrupt",
        record["operation_id"].as_str().unwrap()
    ));
    let foreign_tx = mock.publish_foreign(
        "paid-a",
        record["idempotency_key"].as_str().unwrap(),
        record["qub_id_hex"].as_str().unwrap(),
    );

    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let mut consent = args.clone();
    consent["allow_republish"] = json!(true);
    for request in [&args, &consent] {
        let result = second.call("create_qub", request);
        assert_operation_conflict(&result, &record, &foreign_tx);
        assert!(quarantined.exists(), "the record was quarantined, and kept");
        assert_eq!(mock.upload_posts().len(), 0, "nothing was sent");
        assert_eq!(mock.publications().len(), 1, "only the foreign one");
        assert!(state.records().is_empty(), "nothing was sealed");
    }
}

/// 10. A record journaled by the previous build carries the old
///     `Idempotency-Key`, `qub-<qub_id>`, with no random component. It must
///     still load and resume under exactly that key: first send, lost
///     acknowledgement, and completion by lookup.
#[test]
fn journal_with_the_previous_key_format_still_resumes() {
    let state = TempDir::new("legacy-key");
    let mock = Mock::start();
    mock.add_paid_key("paid-a");
    let args = create_args("journaled by the previous build", now() + 3600);

    let mut first = Mcp::spawn(&closed_port_url(), &state, Some("paid-a"));
    assert_eq!(
        payload(&first.call("create_qub", &args))["code"],
        "lookup_failed"
    );
    first.kill();
    let record = state.only_record();
    let legacy_key = state.rewrite_with_legacy_key(&record);
    assert_ne!(record["idempotency_key"], legacy_key.as_str());
    let record = state.only_record();
    assert_eq!(record["idempotency_key"], legacy_key.as_str());

    // First send under the legacy key; the acknowledgement is lost.
    mock.set_next_upload(UploadMode::CommitThenDrop);
    let mut second = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let result = second.call("create_qub", &args);
    assert!(is_error(&result), "a dropped connection is not a success");
    assert_eq!(payload(&result)["code"], "upload_failed");
    assert_eq!(mock.upload_posts(), vec![legacy_key.clone()]);
    assert_eq!(state.only_record()["state"], "sent");
    second.kill();

    // Resume: resolved by lookup under the same legacy key, no re-POST.
    let mut third = Mcp::spawn(&mock.base_url(), &state, Some("paid-a"));
    let out = assert_success(&third.call("create_qub", &args));
    let publications = mock.publications();
    assert_eq!(publications.len(), 1, "exactly one publication");
    assert_eq!(publications[0].idempotency_key, legacy_key);
    assert_eq!(out["tx_id"], publications[0].tx_id.as_str());
    assert_eq!(out["resumed"], true);
    assert_eq!(mock.upload_posts().len(), 1, "no re-POST");
    assert_same_qub(&out, &record, &mock);
    let completed = state.only_record();
    assert_eq!(completed["state"], "completed");
    assert_eq!(
        completed["idempotency_key"],
        legacy_key.as_str(),
        "a resumed record keeps the key it was journaled with"
    );
}
