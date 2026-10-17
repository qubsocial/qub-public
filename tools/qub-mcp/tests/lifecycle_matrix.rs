// allow-test-network: loopback mocks only (see tests/support/mod.rs)
//! The "MCP protocol and all tools" row of the uplift plan's coverage
//! contract (`docs/AGENT-BUILDER-UPLIFT-PLAN.md` §8), against the real
//! `qub-mcp` binary over stdio: initialise, discover the schemas, call every
//! advertised tool, invalid inputs, unknown tools, error envelopes, clean
//! stdout, missing credentials, the create-disabled default, explicit
//! enablement, horizon limits and a graceful restart — plus the trial
//! acceptance rows that are this binary's behaviour: a kill before and after
//! the service accepted the upload, a lost state directory, and a rejected
//! credential.
//!
//! Where the claim is that something was NOT done — no request, no journal —
//! the test watches the thing itself. Every request the binary makes to the
//! Worker passes through a recording [`Relay`]; the gateways and drand are
//! the mock world's, which counts what it receives. Each such test also
//! shows the positive case, so an empty log is known to be able to hold a hit.
//!
//! Expected values are the documented ones (`tools/qub-mcp/README.md`,
//! JSON-RPC 2.0, MCP 2024-11-05), not read back from the binary. The body-limit
//! parity test deliberately reads the README as one side of the contract.

// Each test is one scenario told in order; splitting them hides the order.
#![allow(clippy::too_many_lines)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use qub_verify::series::{Forecast, Manifest, Slot};
use serde_json::{Value, json};
use support::{
    MCP_BIN, TempDir, ToolReply, UploadFault, World, elapsed_round, now, seal_revealed_public,
};

const KEY: &str = "qub_sk_trial_lifecycle_matrix";

/// Upper bound on every wait in this file.
const WAIT: Duration = Duration::from_secs(30);

/// A deadline no block in these tests comes near (2100-01-01).
const FAR_FUTURE: i64 = 4_102_444_800;

/// The documented default unlock horizon: one year.
const YEAR: i64 = 365 * 24 * 60 * 60;

/// The request-line limit the binary documents (SEC-22): 1 MiB.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

const ALLOW_CREATE: &str = "QUB_MCP_ALLOW_CREATE";
const HORIZON: &str = "QUB_MCP_MAX_UNLOCK_HORIZON_SECS";

const FIVE_TOOLS: [&str; 5] = [
    "check_status",
    "create_qub",
    "list_pending_operations",
    "read_qub",
    "verify_forecast_series",
];

// ---------------------------------------------------------------------------
// A recording relay in front of the mock Worker
// ---------------------------------------------------------------------------

/// What the relay does with the first `POST /api/v1/upload` it sees.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// Forward everything.
    Nothing,
    /// Keep the upload from the Worker and never answer: the client is cut
    /// off before the service has accepted anything.
    BeforeTheWorker,
    /// Let the Worker accept and publish, then keep its answer: the client
    /// is cut off after acceptance and before the acknowledgement.
    AfterTheWorker,
}

struct RelayState {
    /// `host:port` of the Worker.
    upstream: String,
    hold: Hold,
    armed: AtomicBool,
    /// `"<METHOD> <path>"` of every request, in arrival order.
    seen: Mutex<Vec<String>>,
    /// Connections left unanswered until the test ends.
    parked: Mutex<Vec<TcpStream>>,
    held: mpsc::Sender<()>,
}

/// A loopback HTTP relay to the mock Worker that records every request the
/// binary sends it, and can hold one upload at a chosen point.
struct Relay {
    url: String,
    state: Arc<RelayState>,
    held: mpsc::Receiver<()>,
}

/// Read one HTTP/1.1 request: its `"<METHOD> <path>"` and its raw bytes.
fn read_raw_request(stream: &TcpStream) -> Option<(String, Vec<u8>)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut raw = Vec::new();
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    raw.extend_from_slice(request_line.as_bytes());
    let mut words = request_line.split_whitespace();
    let summary = format!("{} {}", words.next()?, words.next()?);
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            return None;
        }
        raw.extend_from_slice(header.as_bytes());
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    raw.extend_from_slice(&body);
    Some((summary, raw))
}

impl RelayState {
    fn serve(&self, mut client: TcpStream) {
        client.set_read_timeout(Some(WAIT)).ok();
        let Some((summary, raw)) = read_raw_request(&client) else {
            return;
        };
        let is_upload = summary == "POST /api/v1/upload";
        self.seen.lock().unwrap().push(summary);
        let hold = if is_upload && self.armed.swap(false, Ordering::SeqCst) {
            self.hold
        } else {
            Hold::Nothing
        };
        if hold == Hold::BeforeTheWorker {
            self.park(client);
            return;
        }
        let answer = self.forward(&raw);
        if hold == Hold::AfterTheWorker {
            self.park(client);
            return;
        }
        // An empty answer is the Worker closing without one: do the same.
        let _ = client.write_all(&answer);
    }

    /// Send `raw` to the Worker and return everything it answers.
    fn forward(&self, raw: &[u8]) -> Vec<u8> {
        let mut answer = Vec::new();
        if let Ok(mut worker) = TcpStream::connect(&self.upstream) {
            worker.set_read_timeout(Some(WAIT)).ok();
            if worker.write_all(raw).is_ok() {
                let _ = worker.read_to_end(&mut answer);
            }
        }
        answer
    }

    fn park(&self, client: TcpStream) {
        self.parked.lock().unwrap().push(client);
        let _ = self.held.send(());
    }
}

impl Relay {
    fn start(worker_url: &str, hold: Hold) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the relay");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (parked_tx, parked_rx) = mpsc::channel();
        let state = Arc::new(RelayState {
            upstream: worker_url
                .strip_prefix("http://")
                .expect("the mock Worker is a loopback http origin")
                .to_owned(),
            hold,
            armed: AtomicBool::new(hold != Hold::Nothing),
            seen: Mutex::new(Vec::new()),
            parked: Mutex::new(Vec::new()),
            held: parked_tx,
        });
        let accepting = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&accepting);
                thread::spawn(move || state.serve(stream));
            }
        });
        Self {
            url,
            state,
            held: parked_rx,
        }
    }

    fn requests(&self) -> Vec<String> {
        self.state.seen.lock().unwrap().clone()
    }

    /// Block (bounded) until the relay is holding the upload.
    fn wait_for_hold(&self) {
        self.held
            .recv_timeout(WAIT)
            .expect("the upload never reached the relay");
    }
}

// ---------------------------------------------------------------------------
// The bench: the mock world, the relay, and installations pointed at them
// ---------------------------------------------------------------------------

struct Bench {
    world: World,
    relay: Relay,
}

impl Bench {
    fn start() -> Self {
        Self::holding(Hold::Nothing)
    }

    fn holding(hold: Hold) -> Self {
        let world = World::start(KEY);
        let relay = Relay::start(&world.worker_url, hold);
        Self { world, relay }
    }

    /// Every request any service has received from anyone: the Worker's
    /// first, then the gateways', then a count for drand.
    fn traffic(&self) -> Vec<String> {
        let mut all = self.relay.requests();
        let (gateways, drand) = {
            let inner = self.world.lock();
            (inner.gateway_requests.clone(), inner.drand_requests)
        };
        all.extend(gateways.into_iter().map(|seen| format!("gateway {seen}")));
        if drand > 0 {
            all.push(format!("drand x{drand}"));
        }
        all
    }

    /// The README's copy-paste configuration: no key, publishing not enabled.
    fn reader(&self) -> Install {
        Install {
            home: TempDir::new("matrix"),
            vars: vec![
                ("QUB_BASE_URL".to_owned(), self.relay.url.clone()),
                (
                    "QUB_ARWEAVE_GATEWAYS".to_owned(),
                    self.world.gateway_urls.join(","),
                ),
                (
                    "QUB_DRAND_ENDPOINTS".to_owned(),
                    self.world.drand_url.clone(),
                ),
            ],
        }
    }

    /// An installation with the accepted key and publishing enabled.
    fn creator(&self) -> Install {
        self.reader().set("QUB_API_KEY", KEY).set(ALLOW_CREATE, "1")
    }

    fn publications(&self) -> usize {
        self.world.lock().publications
    }

    /// The delivery URL the binary builds for `tx_id` (its base is the relay).
    fn delivery_url(&self, tx_id: &str) -> String {
        format!("{}/c/{tx_id}", self.relay.url)
    }
}

/// One `qub-mcp` installation: an environment and a state directory the
/// test can look into. The directory is a child of `home` that nothing but
/// the binary creates.
struct Install {
    home: TempDir,
    vars: Vec<(String, String)>,
}

/// Everything the binary reads from its environment, so a test never
/// inherits the developer's.
const CONFIGURATION: [&str; 14] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "QUB_API_KEY",
    "QUB_BASE_URL",
    "QUB_ARWEAVE_GATEWAYS",
    "QUB_DRAND_ENDPOINTS",
    "QUB_MCP_STATE_DIR",
    "XDG_STATE_HOME",
    ALLOW_CREATE,
    HORIZON,
];

impl Install {
    fn set(mut self, name: &str, value: &str) -> Self {
        self.vars.retain(|(existing, _)| existing != name);
        self.vars.push((name.to_owned(), value.to_owned()));
        self
    }

    fn state_dir(&self) -> PathBuf {
        self.home.path().join("state")
    }

    fn start(&self) -> Session {
        let mut command = Command::new(MCP_BIN);
        for var in CONFIGURATION {
            command.env_remove(var);
        }
        command
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .env("QUB_MCP_STATE_DIR", self.state_dir());
        for (name, value) in &self.vars {
            command.env(name, value);
        }
        Session::start(command)
    }

    /// Every journal record, as written.
    fn records(&self) -> Vec<(PathBuf, Value)> {
        let Ok(entries) = std::fs::read_dir(self.state_dir().join("ops")) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .map(|path| {
                let record = serde_json::from_slice(&std::fs::read(&path).expect("read a record"))
                    .expect("a journal record is JSON");
                (path, record)
            })
            .collect()
    }

    fn only_record(&self) -> (PathBuf, Value) {
        let mut records = self.records();
        assert_eq!(records.len(), 1, "expected exactly one journal record");
        records.remove(0)
    }
}

// ---------------------------------------------------------------------------
// One running `qub-mcp`, spoken to over its stdio
// ---------------------------------------------------------------------------

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: mpsc::Receiver<String>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<String>>,
    next_id: u64,
    /// The tools this session has called.
    called: BTreeSet<String>,
}

/// A process that has ended, and everything it wrote.
struct Exited {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Exited {
    /// Every stdout line as a JSON-RPC frame. A line that is not one fails.
    fn frames(&self) -> Vec<Value> {
        self.stdout
            .lines()
            .map(|line| {
                let frame: Value = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line}"));
                assert_eq!(frame["jsonrpc"], "2.0", "not a JSON-RPC frame: {line}");
                frame
            })
            .collect()
    }
}

impl Session {
    fn start(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qub-mcp");
        let stdin = child.stdin.take();
        let out = child.stdout.take().expect("stdout pipe");
        let mut err = child.stderr.take().expect("stderr pipe");
        let (line_tx, frames) = mpsc::channel();
        let stdout = thread::spawn(move || {
            let mut reader = BufReader::new(out);
            let mut all = Vec::new();
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {},
                }
                all.extend_from_slice(&line);
                let text = String::from_utf8_lossy(&line);
                let _ = line_tx.send(text.trim_end_matches('\n').to_owned());
            }
            all
        });
        let stderr = thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            text
        });
        Self {
            child,
            stdin,
            frames,
            stdout: Some(stdout),
            stderr: Some(stderr),
            next_id: 1,
            called: BTreeSet::new(),
        }
    }

    /// Write one line to the server's stdin, exactly as given.
    fn write_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .expect("write to qub-mcp");
        stdin.flush().expect("flush to qub-mcp");
    }

    /// The next line the server writes to stdout, which must be a JSON
    /// object.
    fn next_frame(&self) -> Value {
        let line = self
            .frames
            .recv_timeout(WAIT)
            .unwrap_or_else(|e| panic!("no frame from qub-mcp within {WAIT:?}: {e}"));
        let frame: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line}"));
        assert!(frame.is_object(), "a frame is a JSON object: {line}");
        frame
    }

    /// Send a request under a fresh numeric id and return its response. The
    /// NEXT frame must be that response: anything written in between — an
    /// answer to a notification, a stray line — fails here.
    fn request(&mut self, method: &str, params: Option<Value>) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let mut frame = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if let Some(params) = params {
            frame["params"] = params;
        }
        self.write_line(&frame.to_string());
        let response = self.next_frame();
        assert_eq!(
            response["id"], id,
            "the next frame answers {id}: {response}"
        );
        response
    }

    /// Call a tool and return its result, which may be a tool error.
    fn call(&mut self, tool: &str, arguments: &Value) -> ToolReply {
        let response = self.request(
            "tools/call",
            Some(json!({ "name": tool, "arguments": arguments })),
        );
        assert!(
            response.get("error").is_none(),
            "{tool}: a JSON-RPC error, not a tool result: {response}"
        );
        self.called.insert(tool.to_owned());
        let result = &response["result"];
        ToolReply {
            is_error: result["isError"] == true,
            text: result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        }
    }

    /// The names `tools/list` advertises.
    fn advertised(&mut self) -> BTreeSet<String> {
        let listed = self.request("tools/list", None);
        listed["result"]["tools"]
            .as_array()
            .expect("tools is an array")
            .iter()
            .map(|tool| tool["name"].as_str().expect("a tool has a name").to_owned())
            .collect()
    }

    /// Close stdin, as a host that is done does, and wait for the exit.
    fn close(mut self) -> Exited {
        drop(self.stdin.take());
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("wait for qub-mcp") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "qub-mcp did not exit within {WAIT:?} of its stdin closing"
            );
            thread::sleep(Duration::from_millis(10));
        };
        self.collect(status)
    }

    /// Kill the process outright, as a crash or an OOM kill would.
    fn kill(mut self) -> Exited {
        self.child.kill().expect("kill qub-mcp");
        let status = self.child.wait().expect("reap qub-mcp");
        self.collect(status)
    }

    fn collect(&mut self, status: ExitStatus) -> Exited {
        let stdout = self
            .stdout
            .take()
            .map(|reader| reader.join().expect("stdout reader"))
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .map(|reader| reader.join().expect("stderr reader"))
            .unwrap_or_default();
        Exited {
            status,
            stdout: String::from_utf8(stdout).expect("stdout is UTF-8"),
            stderr,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn tx(result: &Value) -> String {
    result["tx_id"].as_str().expect("tx_id").to_owned()
}

/// A syntactically valid transaction id that no service knows.
fn unknown_tx() -> String {
    "A".repeat(43)
}

fn no_arguments() -> Value {
    json!({})
}

/// The top-level member names of a frame.
fn members(frame: &Value) -> BTreeSet<&str> {
    frame
        .as_object()
        .expect("a frame is an object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// A JSON-RPC 2.0 error response: `jsonrpc`, `id`, and an `error` object
/// with an integer `code` and a string `message` — and no `result`.
/// Returns the message.
fn assert_rpc_error(frame: &Value, code: i64, id: &Value) -> String {
    assert_eq!(
        members(frame),
        BTreeSet::from(["error", "id", "jsonrpc"]),
        "{frame}"
    );
    assert_eq!(frame["jsonrpc"], "2.0", "{frame}");
    assert_eq!(&frame["id"], id, "{frame}");
    let error = frame["error"].as_object().expect("error is an object");
    assert!(
        error
            .keys()
            .all(|name| matches!(name.as_str(), "code" | "message" | "data")),
        "{frame}"
    );
    assert_eq!(error["code"].as_i64(), Some(code), "{frame}");
    let message = error["message"].as_str().expect("message is a string");
    assert!(!message.is_empty(), "{frame}");
    message.to_owned()
}

/// A JSON-RPC 2.0 success response: `jsonrpc`, `id`, `result` — and no
/// `error`. Returns the result.
fn assert_rpc_result<'a>(frame: &'a Value, id: &Value) -> &'a Value {
    assert_eq!(
        members(frame),
        BTreeSet::from(["id", "jsonrpc", "result"]),
        "{frame}"
    );
    assert_eq!(frame["jsonrpc"], "2.0", "{frame}");
    assert_eq!(&frame["id"], id, "{frame}");
    &frame["result"]
}

/// An MCP tool result's one text block.
fn tool_text(result: &Value) -> &str {
    let content = result["content"].as_array().expect("content is an array");
    assert_eq!(content.len(), 1, "{result}");
    assert_eq!(content[0]["type"], "text", "{result}");
    content[0]["text"].as_str().expect("text is a string")
}

// ---------------------------------------------------------------------------
// Initialise and discover
// ---------------------------------------------------------------------------

/// The handshake an MCP host performs: `initialize`, the `initialized`
/// notification, then discovery — and a clean exit when the host is done.
#[test]
fn initialize_over_stdio_answers_the_documented_handshake() {
    let bench = Bench::start();
    let install = bench.reader();
    let mut session = install.start();

    // A string id, as a host may use: echoed as it was sent.
    session.write_line(
        &json!({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "lifecycle-matrix", "version": "0" },
            },
        })
        .to_string(),
    );
    let hello = session.next_frame();
    let result = assert_rpc_result(&hello, &json!("init-1"));
    assert_eq!(result["protocolVersion"], "2024-11-05");
    // Tools and nothing else: no resources, prompts or sampling.
    assert_eq!(result["capabilities"], json!({ "tools": {} }));
    assert_eq!(result["serverInfo"]["name"], "qub-mcp");
    assert!(
        result["serverInfo"]["version"]
            .as_str()
            .is_some_and(|version| !version.is_empty()),
        "{hello}"
    );

    // A notification carries no id and gets no answer: the next frame on
    // stdout is the answer to the request sent after it.
    session.write_line(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
    );
    let advertised = session.advertised();
    assert_eq!(advertised, FIVE_TOOLS.map(str::to_owned).into());

    let exited = session.close();
    assert_eq!(exited.status.code(), Some(0), "{}", exited.stderr);
    assert_eq!(exited.frames().len(), 2, "two requests, two frames");
    assert_eq!(
        bench.traffic(),
        Vec::<String>::new(),
        "a handshake calls no service"
    );
    assert!(
        !install.state_dir().exists(),
        "a handshake creates no state"
    );
}

/// One tool's inputs as the README's parameter tables give them.
struct Documented {
    name: &'static str,
    /// `(parameter, JSON type)`.
    inputs: &'static [(&'static str, &'static str)],
    required: &'static [&'static str],
}

const READ_INPUTS: &[(&str, &str)] = &[
    ("delivery_url", "string"),
    ("tx_id", "string"),
    ("key_base64url", "string"),
    ("deadline", "number"),
    ("check_timing", "boolean"),
];

const DOCUMENTED: [Documented; 5] = [
    Documented {
        name: "create_qub",
        inputs: &[
            ("body", "string"),
            ("unlock_at", "number"),
            ("visibility", "string"),
            ("sender_label", "string"),
            ("intent", "string"),
            ("operation_id", "string"),
            ("allow_republish", "boolean"),
        ],
        required: &["body", "unlock_at"],
    },
    Documented {
        name: "read_qub",
        inputs: READ_INPUTS,
        required: &[],
    },
    Documented {
        name: "check_status",
        inputs: READ_INPUTS,
        required: &[],
    },
    Documented {
        name: "verify_forecast_series",
        inputs: &[
            ("manifest", "string"),
            ("forecasts", "array"),
            ("outcomes", "object"),
        ],
        required: &["manifest", "forecasts"],
    },
    Documented {
        name: "list_pending_operations",
        inputs: &[],
        required: &[],
    },
];

/// `tools/list` over stdio publishes, for each of the five tools, exactly
/// the parameters the README documents — names, types, which are required,
/// and the closed value sets.
#[test]
fn tools_list_publishes_the_documented_schema_of_every_tool() {
    let bench = Bench::start();
    let mut session = bench.reader().start();
    let listed = session.request("tools/list", None);
    let tools = assert_rpc_result(&listed, &json!(1))["tools"]
        .as_array()
        .expect("tools is an array")
        .clone();
    assert_eq!(tools.len(), DOCUMENTED.len(), "{listed}");

    let schema_of = |name: &str| -> Value {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("{name} is not advertised"));
        assert!(
            tool["description"]
                .as_str()
                .is_some_and(|text| !text.trim().is_empty()),
            "{name} has no description"
        );
        tool["inputSchema"].clone()
    };
    for documented in &DOCUMENTED {
        let schema = schema_of(documented.name);
        assert_eq!(schema["type"], "object", "{}", documented.name);
        let actual: BTreeMap<String, String> = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{} has no properties object", documented.name))
            .iter()
            .map(|(name, property)| {
                let kind = property["type"].as_str().unwrap_or("<untyped>");
                (name.clone(), kind.to_owned())
            })
            .collect();
        let expected: BTreeMap<String, String> = documented
            .inputs
            .iter()
            .map(|(name, kind)| ((*name).to_owned(), (*kind).to_owned()))
            .collect();
        assert_eq!(actual, expected, "{}", documented.name);
        let required: Vec<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|names| names.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert_eq!(required, documented.required, "{}", documented.name);
    }

    let create = schema_of("create_qub");
    assert_eq!(
        create["properties"]["visibility"]["enum"],
        json!(["private", "public"])
    );
    assert_eq!(
        create["properties"]["intent"]["enum"],
        json!([
            "announcement",
            "thesis",
            "prediction",
            "letter",
            "secret",
            "commitment",
            "proof"
        ])
    );
    assert_eq!(
        create["properties"]["operation_id"]["pattern"],
        "^[A-Za-z0-9_-]{8,64}$"
    );
    let series = schema_of("verify_forecast_series");
    assert_eq!(
        series["properties"]["forecasts"]["items"],
        json!({ "type": "string" })
    );
    assert_eq!(series["properties"]["forecasts"]["maxItems"], 32);
    assert_eq!(
        series["properties"]["outcomes"]["additionalProperties"],
        json!({ "type": "string" })
    );

    // Discovery tells an agent that publishing is gated, before it tries.
    let description = tools
        .iter()
        .find(|tool| tool["name"] == "create_qub")
        .and_then(|tool| tool["description"].as_str())
        .unwrap_or_default();
    assert!(description.contains(ALLOW_CREATE), "{description}");
    assert_eq!(bench.traffic(), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// Every advertised tool, called
// ---------------------------------------------------------------------------

/// A one-slot series whose manifest and forecast unlocked at the elapsed
/// fixture round. Returns `(manifest tx, forecast tx)`, both evidenced: the
/// manifest long before the deadline, the forecast before it.
fn publish_a_complete_series(world: &World) -> (String, String) {
    let reveal_at = elapsed_round().unlock_at;
    let deadline = reveal_at - 20_000;
    let manifest = Manifest {
        series_id: "matrix-series".to_owned(),
        title: "One declared forecast".to_owned(),
        scoring: "exact_match: the answer equals the outcome source's value.".to_owned(),
        slots: vec![Slot {
            slot: "one".to_owned(),
            question: "Will the event happen?".to_owned(),
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
        answer: "yes".to_owned(),
        probability_pct: Some(70),
    };
    let forecast_tx = world.store(seal_revealed_public(&forecast.to_body()), true);
    world.mine(&forecast_tx, deadline - 5000);
    (manifest_tx, forecast_tx)
}

/// One session, one process: every tool `tools/list` advertises is called
/// and its result checked. A tool added to the list and not called here
/// fails the last assertion.
#[test]
fn every_advertised_tool_is_called_and_answers() {
    let bench = Bench::start();
    let install = bench.creator();
    let mut session = install.start();
    let advertised = session.advertised();
    let unlock_at = now() + 3600;

    // create_qub, both modes.
    let public = session
        .call(
            "create_qub",
            &json!({ "body": "matrix: public", "unlock_at": unlock_at, "visibility": "public" }),
        )
        .ok();
    assert_eq!(public["visibility"], "public");
    assert_eq!(public["resumed"], false);
    assert_eq!(public["wrapper_key_b64url"], Value::Null);
    assert_eq!(public["unlock_at"], unlock_at);
    let public_tx = tx(&public);
    assert_eq!(public["delivery_url"], bench.delivery_url(&public_tx));
    let private = session
        .call(
            "create_qub",
            &json!({
                "body": "matrix: private",
                "unlock_at": unlock_at,
                "intent": "prediction",
                "sender_label": "the matrix",
            }),
        )
        .ok();
    assert_eq!(private["visibility"], "private");
    let key = private["wrapper_key_b64url"].as_str().expect("a key");
    assert_eq!(BASE64URL.decode(key).map(|k| k.len()), Ok(32));
    assert_eq!(
        private["delivery_url"],
        format!("{}#{key}", bench.delivery_url(&tx(&private)))
    );
    {
        let inner = bench.world.lock();
        assert_eq!(inner.publications, 2);
        assert_eq!(inner.uploads[0].is_public, Some(true));
        assert_eq!(inner.uploads[1].is_public, None);
        assert_eq!(inner.uploads[1].intent.as_deref(), Some("prediction"));
        assert_eq!(inner.uploads[1].unlock_at, unlock_at);
    }

    // list_pending_operations: both creates completed, so nothing is listed.
    let listed = session
        .call("list_pending_operations", &no_arguments())
        .ok();
    assert_eq!(
        listed,
        json!({
            "state_dir": install.state_dir().display().to_string(),
            "pending": [],
            "unreadable": [],
            "quarantined": [],
        })
    );

    // check_status on the public qub, once the gateways report it mined.
    let block_time = now() - 10_000;
    bench.world.mine(&public_tx, block_time);
    let status = session
        .call(
            "check_status",
            &json!({ "tx_id": public_tx, "deadline": FAR_FUTURE }),
        )
        .ok();
    assert_eq!(status["status"], "locked");
    assert_eq!(status["visibility"], "public");
    assert_eq!(status["qub_id"], public["qub_id"]);
    assert_eq!(status["tx_binding"], "evidenced");
    assert_eq!(status["timing"]["state"], "evidenced");
    assert_eq!(status["timing"]["block_time"], block_time);
    assert_eq!(status["timing"]["deadline"]["verdict"], "before");

    // read_qub on the private qub (locked) and on a revealed public one.
    let locked = session
        .call(
            "read_qub",
            &json!({ "delivery_url": private["delivery_url"] }),
        )
        .ok();
    assert_eq!(locked["status"], "locked");
    assert_eq!(locked["visibility"], "private");
    assert_eq!(locked["qub_id"], private["qub_id"]);
    assert_eq!(locked["content"], json!({ "state": "locked" }));
    assert_eq!(locked["timing"]["state"], "unsupported_private");
    let revealed_tx = bench
        .world
        .store(seal_revealed_public("matrix: revealed"), true);
    let revealed = session
        .call("read_qub", &json!({ "tx_id": revealed_tx }))
        .ok();
    assert_eq!(revealed["status"], "unlocked");
    assert_eq!(revealed["content"]["state"], "verified");
    assert!(
        revealed["body"]
            .as_str()
            .is_some_and(|body| body.contains("matrix: revealed")),
        "{revealed}"
    );

    // verify_forecast_series on a complete, evidenced one-slot series.
    let (manifest_tx, forecast_tx) = publish_a_complete_series(&bench.world);
    let report = session
        .call(
            "verify_forecast_series",
            &json!({
                "manifest": manifest_tx,
                "forecasts": [forecast_tx],
                "outcomes": { "one": "yes" },
            }),
        )
        .ok();
    assert_eq!(report["schema"], "qub.forecast-series-report/v1");
    assert_eq!(report["series_id"], "matrix-series");
    assert_eq!(report["complete"], true);
    assert_eq!(report["summary"], json!({ "slots": 1, "on_time": 1 }));
    assert_eq!(report["slots"][0]["status"], "on_time");
    assert_eq!(report["slots"][0]["counted_tx_id"], forecast_tx);
    assert_eq!(report["slots"][0]["outcome"]["result"], "match");

    // One counted read per artifact read: status, two reads, two for the
    // series; none of them anonymous.
    {
        let inner = bench.world.lock();
        assert_eq!(inner.authenticated_reads, 5);
        assert_eq!(inner.anonymous_reads, 0);
        assert_eq!(inner.publications, 2);
    }
    assert_eq!(advertised, FIVE_TOOLS.map(str::to_owned).into());
    assert_eq!(
        session.called, advertised,
        "every advertised tool must be called by this test"
    );
    assert_eq!(session.close().status.code(), Some(0));
}

// ---------------------------------------------------------------------------
// Invalid inputs, unknown tools, error envelopes
// ---------------------------------------------------------------------------

/// `(arguments, what the refusal must say)` for `create_qub`.
fn invalid_create_inputs() -> Vec<(Value, &'static str)> {
    let at = now() + 3600;
    let with = |name: &str, value: Value| {
        let mut arguments = json!({ "body": "x", "unlock_at": at });
        arguments[name] = value;
        arguments
    };
    vec![
        (json!({}), "missing required parameter: body"),
        (
            json!({ "unlock_at": at }),
            "missing required parameter: body",
        ),
        (
            json!({ "body": 5, "unlock_at": at }),
            "missing required parameter: body",
        ),
        (
            json!({ "body": "x" }),
            "missing required parameter: unlock_at",
        ),
        (
            with("unlock_at", json!("soon")),
            "unlock_at must be an integer",
        ),
        (
            with("unlock_at", json!(1_900_000_000.5)),
            "unlock_at must be an integer",
        ),
        (with("intent", json!("gossip")), "unknown intent"),
        (with("intent", json!("verdict")), "system-only intent"),
        (with("intent", json!(7)), "intent must be a string"),
        (with("visibility", json!("Public")), "visibility must be"),
        (with("visibility", json!(true)), "visibility must be"),
        (
            with("sender_label", json!(7)),
            "sender_label must be a string",
        ),
        (
            with("operation_id", json!("short")),
            "operation_id must match",
        ),
        (
            with("operation_id", json!("has a space in it")),
            "operation_id must match",
        ),
        (
            with("operation_id", json!(12_345_678)),
            "operation_id must be a string",
        ),
        (
            with("allow_republish", json!("yes")),
            "allow_republish must be a boolean",
        ),
    ]
}

/// `(arguments, what the refusal must say)` for `read_qub` and
/// `check_status`, which take the same inputs.
fn invalid_read_inputs() -> Vec<(Value, &'static str)> {
    let tx_id = unknown_tx();
    let key = BASE64URL.encode([7u8; 32]);
    let url = format!("https://qub.social/c/{tx_id}");
    let with = |name: &str, value: Value| {
        let mut arguments = json!({ "tx_id": tx_id });
        arguments[name] = value;
        arguments
    };
    vec![
        (json!({}), "provide `delivery_url` or `tx_id`"),
        (
            json!({ "key_base64url": key }),
            "provide `delivery_url` or `tx_id`",
        ),
        (
            json!({ "delivery_url": url, "tx_id": tx_id }),
            "exactly one read form",
        ),
        (
            json!({ "delivery_url": url, "key_base64url": key }),
            "exactly one read form",
        ),
        (
            json!({ "delivery_url": 5 }),
            "delivery_url must be a string",
        ),
        (
            json!({ "delivery_url": format!("{url}#") }),
            "empty fragment",
        ),
        (
            json!({ "delivery_url": format!("{url}#AAAA") }),
            "wrapper key must be 32 bytes",
        ),
        (
            json!({ "delivery_url": "https://qub.social/c/" }),
            "no tx_id segment",
        ),
        (
            json!({ "delivery_url": "https://qub.social/c/a%2Fb" }),
            "invalid tx_id segment",
        ),
        (json!({ "tx_id": 5 }), "tx_id must be a string"),
        (json!({ "tx_id": "" }), "tx_id is invalid"),
        (json!({ "tx_id": "../../etc/passwd" }), "tx_id is invalid"),
        (json!({ "tx_id": "A".repeat(65) }), "tx_id is invalid"),
        (
            with("key_base64url", json!(5)),
            "key_base64url must be a string",
        ),
        (
            with("key_base64url", json!("not base64!")),
            "not valid base64url",
        ),
        (
            with("key_base64url", json!("AAAA")),
            "wrapper key must be 32 bytes",
        ),
        (
            with("deadline", json!("tomorrow")),
            "deadline must be a positive integer",
        ),
        (with("deadline", json!(0)), "deadline must be a positive"),
        (
            with("deadline", json!(1_900_000_000_000_i64)),
            "is it in milliseconds?",
        ),
        (
            with("check_timing", json!("no")),
            "check_timing must be a boolean",
        ),
    ]
}

/// `(arguments, what the refusal must say)` for `verify_forecast_series`.
fn invalid_series_inputs() -> Vec<(Value, &'static str)> {
    let tx_id = unknown_tx();
    vec![
        (json!({}), "missing required parameter: manifest"),
        (
            json!({ "forecasts": [] }),
            "missing required parameter: manifest",
        ),
        (
            json!({ "manifest": 5, "forecasts": [] }),
            "missing required parameter: manifest",
        ),
        (
            json!({ "manifest": "not an id", "forecasts": [] }),
            "manifest: tx_id is invalid",
        ),
        (
            json!({ "manifest": tx_id }),
            "missing required parameter: forecasts",
        ),
        (
            json!({ "manifest": tx_id, "forecasts": tx_id }),
            "missing required parameter: forecasts",
        ),
        (
            json!({ "manifest": tx_id, "forecasts": vec![tx_id.clone(); 33] }),
            "at most 32",
        ),
        (
            json!({ "manifest": tx_id, "forecasts": [5] }),
            "forecasts[0] must be a string",
        ),
        (
            json!({ "manifest": tx_id, "forecasts": [tx_id, "no/such"] }),
            "forecasts[1]: tx_id is invalid",
        ),
        (
            json!({ "manifest": tx_id, "forecasts": [], "outcomes": "yes" }),
            "outcomes must be an object",
        ),
        (
            json!({ "manifest": tx_id, "forecasts": [], "outcomes": { "one": 1 } }),
            "must be a string",
        ),
    ]
}

/// Every tool refuses its invalid inputs with a tool error that says what
/// is wrong — and does so before it contacts any service or writes any
/// state. `list_pending_operations` takes no parameters, so the only input
/// it can be given wrongly is an `arguments` that is not an object, which
/// every tool refuses as a JSON-RPC error.
#[test]
fn invalid_inputs_are_refused_by_every_tool_before_any_request() {
    let bench = Bench::start();
    let install = bench.creator();
    let mut session = install.start();

    let mut cases: Vec<(&str, Value, &str)> = Vec::new();
    for (arguments, says) in invalid_create_inputs() {
        cases.push(("create_qub", arguments, says));
    }
    for tool in ["read_qub", "check_status"] {
        for (arguments, says) in invalid_read_inputs() {
            cases.push((tool, arguments, says));
        }
    }
    for (arguments, says) in invalid_series_inputs() {
        cases.push(("verify_forecast_series", arguments, says));
    }
    for (tool, arguments, says) in &cases {
        let reply = session.call(tool, arguments);
        assert!(
            reply.is_error,
            "{tool} accepted {arguments}: {}",
            reply.text
        );
        assert!(
            reply.text.contains(says),
            "{tool} {arguments}: expected {says:?} in {:?}",
            reply.text
        );
    }

    for tool in FIVE_TOOLS {
        for arguments in [json!([]), json!("body"), json!(7), Value::Null] {
            let response = session.request(
                "tools/call",
                Some(json!({ "name": tool, "arguments": arguments })),
            );
            let id = response["id"].clone();
            let message = assert_rpc_error(&response, -32602, &id);
            assert!(message.contains("arguments must be an object"), "{message}");
        }
    }

    assert_eq!(
        bench.traffic(),
        Vec::<String>::new(),
        "an invalid input must be refused before any request"
    );
    assert_eq!(bench.publications(), 0);
    assert!(
        !install.state_dir().exists(),
        "an invalid input must be refused before any state is written"
    );

    // Inputs only sealing can judge: an empty body, one over the protocol's
    // 50 KB ceiling, an unlock time that has passed. By then the
    // installation has its state directory, but the refusal still comes
    // before any request, and no operation is journaled.
    let at = now() + 3600;
    for (arguments, says) in [
        (json!({ "body": "", "unlock_at": at }), "body is empty"),
        (
            json!({ "body": "x".repeat(60 * 1024), "unlock_at": at }),
            "body exceeds maximum size",
        ),
        (
            json!({ "body": "x", "unlock_at": now() - 60 }),
            "not in the future",
        ),
    ] {
        let reply = session.call("create_qub", &arguments);
        assert!(reply.is_error, "create_qub accepted an unsealable request");
        assert!(
            reply.text.contains(says),
            "expected {says:?}: {}",
            reply.text
        );
    }
    assert_eq!(
        bench.traffic(),
        Vec::<String>::new(),
        "an unsealable request must be refused before any request"
    );
    assert!(
        install.records().is_empty(),
        "an unsealable request must not be journaled"
    );

    // The log can hold a hit: a well-formed read does reach the Worker.
    let tx_id = unknown_tx();
    let reply = session.call("check_status", &json!({ "tx_id": tx_id }));
    assert_eq!(reply.error_code(), "not_found");
    assert_eq!(bench.traffic(), [format!("GET /api/v1/qub/{tx_id}")]);
}

/// The byte limit the advertised `create_qub` schema states for `body`
/// (`"At most 10,240 bytes …"`), read out of the description an agent is
/// given. The description must state exactly one.
fn advertised_body_limit(session: &mut Session) -> usize {
    let listed = session.request("tools/list", None);
    let description = listed["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .find(|tool| tool["name"] == "create_qub")
        .and_then(|tool| tool["inputSchema"]["properties"]["body"]["description"].as_str())
        .expect("create_qub describes its body")
        .to_owned();
    let words: Vec<&str> = description.split_whitespace().collect();
    let limits: Vec<usize> = words
        .windows(2)
        .filter(|pair| pair[1].starts_with("bytes"))
        .filter_map(|pair| pair[0].replace(',', "").parse().ok())
        .collect();
    assert_eq!(
        limits.len(),
        1,
        "the body description must state one limit in bytes: {description:?}"
    );
    limits[0]
}

/// The body row in the human-facing MCP documentation must state one byte
/// limit. Parsing the row rather than searching for the current number makes
/// a stale replacement fail for the value it actually documents.
fn readme_body_limit() -> usize {
    let row = include_str!("../README.md")
        .lines()
        .find(|line| line.starts_with("| `body` |"))
        .expect("README create_qub parameter table has a body row");
    let value = row
        .split_once("At most ")
        .expect("README body row states an 'At most … bytes' limit")
        .1
        .split_once(" bytes")
        .expect("README body row gives its limit in bytes")
        .0
        .replace(',', "");
    value
        .parse()
        .expect("README body limit is a decimal byte count")
}

#[test]
fn the_readme_body_limit_matches_the_advertised_and_enforced_limit() {
    let bench = Bench::start();
    let install = bench.creator();
    let mut session = install.start();
    let documented = readme_body_limit();

    assert_eq!(documented, advertised_body_limit(&mut session));
    assert_eq!(
        Some(documented),
        qub_core::types::max_body_size(qub_core::types::CONTENT_TYPE_TEXT, false)
    );
}

/// Discovery tells an agent how long a body may be, and the number it is
/// told is the one sealing enforces — in bytes of UTF-8, not characters. A
/// body of exactly the advertised size is sealed and published; one byte
/// more is refused before any request is made or any operation journaled.
///
/// The limit is read OUT OF the advertised description, so the sentence
/// cannot be dropped, and cannot drift from `qub_core`'s `max_body_size`,
/// without this failing.
#[test]
fn the_advertised_body_limit_is_exactly_what_sealing_accepts() {
    let bench = Bench::start();
    let install = bench.creator();
    let mut session = install.start();
    let limit = advertised_body_limit(&mut session);
    assert_eq!(
        Some(limit),
        qub_core::types::max_body_size(qub_core::types::CONTENT_TYPE_TEXT, false),
        "the advertised limit is not the one qub_core seals text to"
    );
    assert_eq!(limit % 2, 0, "the two-byte cases below need an even limit");
    let at = now() + 3600;
    let create = |session: &mut Session, body: String| {
        session.call(
            "create_qub",
            &json!({ "body": body, "unlock_at": at, "visibility": "public" }),
        )
    };

    // One byte over, in one-byte and in two-byte characters. The second is
    // well under the limit counted in characters: the limit is bytes.
    for (body, bytes) in [
        ("x".repeat(limit + 1), limit + 1),
        ("é".repeat(limit / 2 + 1), limit + 2),
    ] {
        assert_eq!(body.len(), bytes);
        let refused = create(&mut session, body);
        assert!(refused.is_error, "{bytes} bytes were accepted");
        assert!(
            refused
                .text
                .contains(&format!("{bytes} bytes > {limit} bytes")),
            "{bytes} bytes: {}",
            refused.text
        );
    }
    assert_eq!(
        bench.traffic(),
        Vec::<String>::new(),
        "an oversized body must be refused before any request"
    );
    assert!(
        install.records().is_empty(),
        "an oversized body must not be journaled"
    );
    assert_eq!(bench.publications(), 0);

    // Exactly the limit, again both ways: sealed, uploaded, published.
    for (index, body) in ["x".repeat(limit), "é".repeat(limit / 2)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(body.len(), limit);
        let created = create(&mut session, body).ok();
        assert_eq!(created["resumed"], false);
        assert_eq!(bench.publications(), index + 1);
        assert!(
            bench.world.lock().artifacts.contains_key(&tx(&created)),
            "the result names the publication"
        );
    }
    let per_create = ["GET /api/v1/upload/operation", "POST /api/v1/upload"];
    assert_eq!(bench.relay.requests(), per_create.repeat(2));
}

/// A tool name the server does not advertise is refused by name, does
/// nothing, and leaves the session serving.
///
/// MCP 2024-11-05 classes an unknown tool as a protocol error (`-32602`):
/// no tool ran, so there is no tool result to flag. The test pins that
/// envelope, that the name is reported, and that nothing whatever is done.
#[test]
fn an_unknown_tool_is_refused_and_does_nothing() {
    let bench = Bench::start();
    let install = bench.creator();
    let mut session = install.start();
    // Near-misses of the publishing tool included: none may reach it.
    for name in [
        "delete_qub",
        "seal",
        "CREATE_QUB",
        "create_qub ",
        "create-qub",
        "tools/list",
        "",
    ] {
        let response = session.request(
            "tools/call",
            Some(json!({
                "name": name,
                "arguments": { "body": "x", "unlock_at": now() + 3600 },
            })),
        );
        let id = response["id"].clone();
        let refusal = assert_rpc_error(&response, -32602, &id);
        assert!(
            refusal.to_lowercase().contains("unknown tool"),
            "{name:?}: {refusal}"
        );
        assert!(refusal.ends_with(name), "{name:?} is not named: {refusal}");
    }
    assert_eq!(
        session.advertised().len(),
        5,
        "the session is still serving"
    );
    assert_eq!(bench.traffic(), Vec::<String>::new());
    assert_eq!(bench.publications(), 0);
    assert!(!install.state_dir().exists());
}

/// `ping` is the protocol's liveness check: answered at once with an empty
/// result, before and after other traffic, without touching the service or
/// the state directory.
#[test]
fn ping_is_answered_with_an_empty_result_and_does_nothing() {
    let bench = Bench::start();
    let install = bench.creator();
    let mut session = install.start();
    for _ in 0..2 {
        let response = session.request("ping", None);
        let id = response["id"].clone();
        assert_eq!(assert_rpc_result(&response, &id), &json!({}));
        assert_eq!(session.advertised().len(), 5, "still serving after a ping");
    }
    // A ping with no id is a notification: nothing may be written for it.
    session.write_line(&json!({ "jsonrpc": "2.0", "method": "ping" }).to_string());
    let response = session.request("ping", None);
    let id = response["id"].clone();
    assert_eq!(assert_rpc_result(&response, &id), &json!({}));
    assert!(
        bench.relay.requests().is_empty(),
        "a ping reached the service"
    );
    assert!(!install.state_dir().exists(), "a ping created local state");
}

/// The two error shapes, on the wire. A protocol-level failure is a
/// JSON-RPC error object under the request's id (`null` when the id cannot
/// be known); a tool-level failure is a successful response whose result
/// has `isError: true` and one text block. Neither ends the session.
#[test]
fn errors_use_the_json_rpc_and_the_tool_result_envelopes() {
    let bench = Bench::start();
    let mut session = bench.creator().start();
    let null = Value::Null;

    // -32700: not JSON. The id cannot be known.
    session.write_line("this is not json at all");
    let message = assert_rpc_error(&session.next_frame(), -32700, &null);
    assert!(message.contains("parse error"), "{message}");

    // -32600: not a JSON-RPC 2.0 request, or an id of a type the
    // specification does not allow.
    session.write_line(&json!({ "jsonrpc": "1.0", "id": 7, "method": "tools/list" }).to_string());
    assert_rpc_error(&session.next_frame(), -32600, &json!(7));
    for id in [json!({ "a": 1 }), json!([1]), json!(true)] {
        session
            .write_line(&json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" }).to_string());
        assert_rpc_error(&session.next_frame(), -32600, &null);
    }
    // -32600: valid JSON that is not a request object. Not a parse error —
    // the text parsed — and the id is echoed when the line carried a usable
    // one, so the caller can match the refusal to what it sent.
    session.write_line(&json!({ "jsonrpc": "2.0", "id": 11 }).to_string());
    let message = assert_rpc_error(&session.next_frame(), -32600, &json!(11));
    assert!(message.contains("invalid request"), "{message}");
    for line in [
        json!([{ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }]),
        json!("tools/list"),
        json!(42),
        json!({ "jsonrpc": "2.0", "id": { "a": 1 } }),
    ] {
        session.write_line(&line.to_string());
        assert_rpc_error(&session.next_frame(), -32600, &null);
    }
    // -32600: a line over the documented 1 MiB limit is refused unparsed.
    session.write_line(&"x".repeat(MAX_REQUEST_BYTES + 1));
    let message = assert_rpc_error(&session.next_frame(), -32600, &null);
    assert!(message.contains("too large"), "{message}");

    // -32601: a method the server does not have.
    session.write_line(
        &json!({ "jsonrpc": "2.0", "id": "s-1", "method": "resources/list" }).to_string(),
    );
    let message = assert_rpc_error(&session.next_frame(), -32601, &json!("s-1"));
    assert!(message.contains("resources/list"), "{message}");

    // -32602: `tools/call` parameters of the wrong shape.
    for params in [
        None,
        Some(json!([])),
        Some(json!("read_qub")),
        Some(json!({ "arguments": {} })),
        Some(json!({ "name": 5, "arguments": {} })),
        Some(json!({ "name": "read_qub", "arguments": [] })),
    ] {
        let response = session.request("tools/call", params.clone());
        let id = response["id"].clone();
        let message = assert_rpc_error(&response, -32602, &id);
        assert!(message.contains("invalid params"), "{params:?}: {message}");
    }

    // An explicit `null` id is a request, not a notification: answered.
    session
        .write_line(&json!({ "jsonrpc": "2.0", "id": null, "method": "tools/list" }).to_string());
    let listed = session.next_frame();
    assert_eq!(
        assert_rpc_result(&listed, &null)["tools"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );

    // A tool error in plain words.
    let response = session.request(
        "tools/call",
        Some(json!({ "name": "read_qub", "arguments": {} })),
    );
    let id = response["id"].clone();
    let result = assert_rpc_result(&response, &id);
    assert_eq!(result["isError"], true);
    assert!(tool_text(result).contains("delivery_url"), "{result}");

    // A structured tool error: the service's refusal of a read, carrying
    // its code and status for the agent to branch on.
    let response = session.request(
        "tools/call",
        Some(json!({ "name": "check_status", "arguments": { "tx_id": unknown_tx() } })),
    );
    let id = response["id"].clone();
    let result = assert_rpc_result(&response, &id);
    assert_eq!(result["isError"], true);
    let refusal: Value = serde_json::from_str(tool_text(result)).expect("a JSON tool error");
    assert_eq!(refusal["code"], "not_found");
    assert_eq!(refusal["status"], 404);

    // A tool success carries no error flag.
    let response = session.request(
        "tools/call",
        Some(json!({ "name": "list_pending_operations", "arguments": {} })),
    );
    let id = response["id"].clone();
    let result = assert_rpc_result(&response, &id);
    assert_ne!(result["isError"], true);
    let listing: Value = serde_json::from_str(tool_text(result)).expect("a JSON tool result");
    assert_eq!(listing["pending"], json!([]));

    assert_eq!(session.close().status.code(), Some(0));
}

// ---------------------------------------------------------------------------
// Clean stdout
// ---------------------------------------------------------------------------

/// A server that is started and stopped without a request writes nothing to
/// stdout: its start-up notices — including the missing-key warning and the
/// journal retention sweep — go to stderr.
#[test]
fn a_server_with_nothing_to_answer_writes_nothing_to_stdout() {
    let bench = Bench::start();

    // No key: the warning path.
    let exited = bench.reader().start().close();
    assert_eq!(exited.status.code(), Some(0), "{}", exited.stderr);
    assert_eq!(exited.stdout, "", "stdout must be empty");
    assert!(
        exited.stderr.contains("qub-mcp: starting"),
        "{}",
        exited.stderr
    );
    assert!(
        exited.stderr.contains("QUB_API_KEY not set"),
        "{}",
        exited.stderr
    );
    assert!(exited.stderr.contains("stdin closed"), "{}", exited.stderr);

    // A journal with a completed record past its 30-day retention: the
    // sweep runs at start-up and reports on stderr.
    let install = bench.creator();
    let mut session = install.start();
    session
        .call(
            "create_qub",
            &json!({ "body": "long done", "unlock_at": now() + 3600, "visibility": "public" }),
        )
        .ok();
    session.close();
    let (path, mut record) = install.only_record();
    assert_eq!(record["state"], "completed");
    record["updated_at"] = json!(now() - 40 * 24 * 60 * 60);
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    let exited = install.start().close();
    assert_eq!(exited.status.code(), Some(0), "{}", exited.stderr);
    assert_eq!(exited.stdout, "", "stdout must be empty");
    assert!(
        exited
            .stderr
            .contains("pruned 1 completed operation record"),
        "{}",
        exited.stderr
    );
    assert!(!path.exists(), "the record was pruned");
}

/// Across a whole session — blank lines, notifications, successes that call
/// the network, a multi-line body, tool errors, protocol errors, an
/// oversized line — stdout carries one JSON-RPC frame per request that has
/// an answer, in order, and nothing else. Everything the server has to say
/// for itself is on stderr.
#[test]
fn stdout_carries_only_protocol_frames_through_a_whole_session() {
    let bench = Bench::start();
    let multiline = "line one\nline two\n{\"not\": \"a frame\"}\nqub-mcp: not a log line";
    let revealed_tx = bench.world.store(seal_revealed_public(multiline), true);
    let mut session = bench.creator().start();

    // Lines that have no answer.
    session.write_line("");
    session.write_line("   ");
    session.write_line(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
    );
    session.write_line(&json!({ "jsonrpc": "2.0", "method": "no/such/notification" }).to_string());

    // Requests 1–8, each answered once.
    session.request("initialize", Some(json!({})));
    session.request("tools/list", None);
    let created = session
        .call(
            "create_qub",
            &json!({ "body": "clean stdout", "unlock_at": now() + 3600, "visibility": "public" }),
        )
        .ok();
    session
        .call("check_status", &json!({ "tx_id": tx(&created) }))
        .ok();
    let read = session
        .call("read_qub", &json!({ "tx_id": revealed_tx }))
        .ok();
    assert!(
        read["body"]
            .as_str()
            .is_some_and(|body| body.contains(multiline)),
        "the body arrives whole, inside one frame: {read}"
    );
    assert!(session.call("read_qub", &no_arguments()).is_error);
    // An unknown tool is a protocol error, still one frame under its id.
    let unknown = session.request(
        "tools/call",
        Some(json!({ "name": "no_such_tool", "arguments": {} })),
    );
    assert_rpc_error(&unknown, -32602, &unknown["id"].clone());
    session.request("no/such/method", None);
    // Two lines whose id cannot be known.
    session.write_line("{ not json");
    session.next_frame();
    session.write_line(&"x".repeat(MAX_REQUEST_BYTES + 1));
    session.next_frame();

    let exited = session.close();
    assert_eq!(exited.status.code(), Some(0), "{}", exited.stderr);
    assert!(exited.stdout.ends_with('\n'), "every frame ends its line");
    let frames = exited.frames();
    let ids: Vec<Value> = frames.iter().map(|frame| frame["id"].clone()).collect();
    assert_eq!(
        ids,
        [
            json!(1),
            json!(2),
            json!(3),
            json!(4),
            json!(5),
            json!(6),
            json!(7),
            json!(8),
            Value::Null,
            Value::Null
        ],
        "one frame per answerable request, in order"
    );
    for frame in &frames {
        let names = members(frame);
        assert!(
            names == BTreeSet::from(["id", "jsonrpc", "result"])
                || names == BTreeSet::from(["error", "id", "jsonrpc"]),
            "not a response frame: {frame}"
        );
    }

    // The log is on stderr, and none of it is on stdout.
    for notice in [
        "qub-mcp: starting MCP server",
        "qub-mcp: received method=initialize",
        "qub-mcp: received method=tools/call",
        "qub-mcp: failed to parse request",
        "qub-mcp: dropping oversized request",
        "qub-mcp: stdin closed, shutting down",
    ] {
        assert!(
            exited.stderr.contains(notice),
            "missing {notice:?} on stderr"
        );
    }
    for line in exited.stderr.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            !exited.stdout.contains(line),
            "a log line reached stdout: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Without `QUB_API_KEY`, `create_qub` is refused with a message naming the
/// variable — nothing is sealed, journaled or sent — while the read tools
/// work, anonymously.
#[test]
fn create_without_an_api_key_is_refused_and_nothing_is_sent() {
    let bench = Bench::start();
    let install = bench.reader().set(ALLOW_CREATE, "1");
    let mut session = install.start();

    for visibility in ["private", "public"] {
        let refused = session.call(
            "create_qub",
            &json!({ "body": "no key", "unlock_at": now() + 3600, "visibility": visibility }),
        );
        assert!(refused.is_error, "{}", refused.text);
        assert!(refused.text.contains("QUB_API_KEY"), "{}", refused.text);
    }
    assert_eq!(bench.traffic(), Vec::<String>::new(), "nothing may be sent");
    assert_eq!(bench.publications(), 0);
    assert!(!install.state_dir().exists(), "nothing may be journaled");

    // The journal listing needs no key and creates nothing.
    let listed = session
        .call("list_pending_operations", &no_arguments())
        .ok();
    assert_eq!(listed["pending"], json!([]));
    assert!(!install.state_dir().exists());

    // A keyless read uses the anonymous public route. That route refuses
    // any credential, so a successful read here sent none.
    let tx_id = bench
        .world
        .store(seal_revealed_public("readable without a key"), true);
    let read = session
        .call(
            "read_qub",
            &json!({ "tx_id": tx_id, "check_timing": false }),
        )
        .ok();
    assert_eq!(read["content"]["state"], "verified");
    assert_eq!(
        bench.relay.requests(),
        [format!("GET /api/v1/qub/{tx_id}/bytes")]
    );
    assert_eq!(bench.world.lock().anonymous_reads, 1);
    assert_eq!(bench.world.lock().authenticated_reads, 0);

    let exited = session.close();
    assert!(
        exited.stderr.contains("QUB_API_KEY not set"),
        "the operator is told at start-up: {}",
        exited.stderr
    );
}

/// A key the service rejects: every credentialed tool reports the refusal
/// with the service's code and status, and none of them quietly retries
/// without the key — though the anonymous route would have served the very
/// same qub, as the last step shows.
#[test]
fn a_rejected_credential_is_reported_and_never_retried_anonymously() {
    let bench = Bench::start();
    let tx_id = bench.world.store(
        seal_revealed_public("public, and still not yours to count"),
        true,
    );
    bench.world.mine(&tx_id, elapsed_round().unlock_at - 20_000);
    let install = bench.creator().set("QUB_API_KEY", "qub_sk_revoked");
    let mut session = install.start();

    for tool in ["read_qub", "check_status"] {
        let refused = session.call(tool, &json!({ "tx_id": tx_id }));
        assert_eq!(refused.error_code(), "api_key_required", "{tool}");
        assert_eq!(refused.json()["status"], 401, "{tool}");
        assert!(!refused.text.contains("still not yours"), "{tool}");
    }
    // The series report reads through the same path: an unreadable
    // manifest, not a silently anonymous one.
    let report = session
        .call(
            "verify_forecast_series",
            &json!({ "manifest": tx_id, "forecasts": [tx_id] }),
        )
        .ok();
    assert_eq!(report["manifest"]["state"], "unreadable");
    assert_eq!(report["complete"], false);

    // A create under the rejected key gets as far as asking the service
    // which scope the key has, is refused there, and uploads nothing.
    let refused = session.call(
        "create_qub",
        &json!({ "body": "rejected key", "unlock_at": now() + 3600 }),
    );
    assert_eq!(refused.error_code(), "lookup_failed");
    assert!(refused.text.contains("401"), "{}", refused.text);
    assert_eq!(install.only_record().1["state"], "prepared");

    assert_eq!(
        bench.relay.requests(),
        [
            format!("GET /api/v1/qub/{tx_id}"),
            format!("GET /api/v1/qub/{tx_id}"),
            format!("GET /api/v1/qub/{tx_id}"),
            format!("GET /api/v1/qub/{tx_id}"),
            "GET /api/v1/upload/operation".to_owned(),
        ],
        "only the authenticated routes, once per read; never `/bytes`, never an upload"
    );
    {
        let inner = bench.world.lock();
        assert_eq!(inner.anonymous_reads, 0, "no anonymous fallback");
        assert_eq!(inner.authenticated_reads, 0, "no read was admitted");
        assert_eq!(inner.publications, 0);
        assert_eq!(inner.uploads.len(), 0);
    }

    // The fallback was there to be taken: a recipient with no key reads it.
    let mut recipient = bench.reader().start();
    let read = recipient.call("read_qub", &json!({ "tx_id": tx_id })).ok();
    assert_eq!(read["content"]["state"], "verified");
    assert_eq!(bench.world.lock().anonymous_reads, 1);
}

// ---------------------------------------------------------------------------
// The publishing gate and the horizon
// ---------------------------------------------------------------------------

/// With a valid key and no `QUB_MCP_ALLOW_CREATE` — or a value that is not
/// one of the documented truthy ones — `create_qub` is refused, and the
/// refusal is real: no request reaches any service and nothing is sealed.
/// The other tools are unaffected.
#[test]
fn create_is_disabled_until_the_operator_enables_it() {
    let bench = Bench::start();
    let unset = bench.reader().set("QUB_API_KEY", KEY);
    let mut installs = vec![("<unset>".to_owned(), unset)];
    for value in ["", "0", "false", "no", "off", "2", "enabled", "allow"] {
        let install = bench
            .reader()
            .set("QUB_API_KEY", KEY)
            .set(ALLOW_CREATE, value);
        installs.push((format!("{value:?}"), install));
    }

    for (label, install) in &installs {
        let mut session = install.start();
        assert!(
            session.advertised().contains("create_qub"),
            "{label}: the tool is still advertised"
        );
        for visibility in ["private", "public"] {
            let refused = session.call(
                "create_qub",
                &json!({ "body": "gated", "unlock_at": now() + 3600, "visibility": visibility }),
            );
            assert!(refused.is_error, "{label}: {}", refused.text);
            assert!(
                refused.text.contains("disabled"),
                "{label}: {}",
                refused.text
            );
            assert!(
                refused.text.contains(ALLOW_CREATE),
                "{label}: {}",
                refused.text
            );
        }
        // Not consulted on a resume either: there is nothing to resume.
        let listed = session
            .call("list_pending_operations", &no_arguments())
            .ok();
        assert_eq!(listed["pending"], json!([]), "{label}");
        assert_eq!(session.close().status.code(), Some(0), "{label}");
        assert!(
            !install.state_dir().exists(),
            "{label}: nothing is journaled"
        );
    }
    assert_eq!(
        bench.traffic(),
        Vec::<String>::new(),
        "a disabled create must send nothing"
    );
    assert_eq!(bench.publications(), 0);

    // The read tools work with create disabled.
    let tx_id = bench
        .world
        .store(seal_revealed_public("readable while create is off"), true);
    let mut session = installs[0].1.start();
    let status = session
        .call(
            "check_status",
            &json!({ "tx_id": tx_id, "check_timing": false }),
        )
        .ok();
    assert_eq!(status["status"], "unlocked");
    assert_eq!(bench.traffic(), [format!("GET /api/v1/qub/{tx_id}")]);
}

/// Each documented truthy value of `QUB_MCP_ALLOW_CREATE` enables
/// publishing: the scope lookup, then one upload, then one publication.
#[test]
fn explicit_enablement_publishes_exactly_once_per_request() {
    let bench = Bench::start();
    for (index, value) in ["1", "true", "yes", "on"].into_iter().enumerate() {
        let install = bench
            .reader()
            .set("QUB_API_KEY", KEY)
            .set(ALLOW_CREATE, value);
        let mut session = install.start();
        let arguments = json!({
            "body": format!("enabled by {value}"),
            "unlock_at": now() + 3600,
            "visibility": "public",
        });
        let created = session.call("create_qub", &arguments).ok();
        assert_eq!(created["resumed"], false, "{value}");
        assert_eq!(bench.publications(), index + 1, "{value}");
        assert!(
            bench.world.lock().artifacts.contains_key(&tx(&created)),
            "{value}: the result names the publication"
        );
        assert_eq!(install.only_record().1["state"], "completed", "{value}");

        // Asked again, the same request is the same publication.
        let again = session.call("create_qub", &arguments).ok();
        assert_eq!(again["resumed"], true, "{value}");
        assert_eq!(tx(&again), tx(&created), "{value}");
        assert_eq!(bench.publications(), index + 1, "{value}");
    }
    let per_create = ["GET /api/v1/upload/operation", "POST /api/v1/upload"];
    assert_eq!(bench.relay.requests(), per_create.repeat(4));
    assert_eq!(bench.world.lock().uploads.len(), 4);
}

/// `unlock_at` is capped at the configured horizon — one year unless
/// `QUB_MCP_MAX_UNLOCK_HORIZON_SECS` says otherwise — and a value that
/// cannot be a horizon leaves the default in force instead of lifting the
/// cap. A refused create sends nothing; one inside the cap publishes.
#[test]
fn the_unlock_horizon_bounds_every_create() {
    let bench = Bench::start();
    // (configured value, the horizon that must be in force)
    let cases = [
        (None, YEAR),
        (Some("7200"), 7200),
        (Some("0"), YEAR),
        (Some("-5"), YEAR),
        (Some("soon"), YEAR),
    ];
    for (published, (configured, horizon)) in cases.into_iter().enumerate() {
        let mut install = bench.creator();
        if let Some(value) = configured {
            install = install.set(HORIZON, value);
        }
        let mut session = install.start();
        let traffic_before = bench.traffic();

        for visibility in ["private", "public"] {
            let beyond = session.call(
                "create_qub",
                &json!({
                    "body": "too far out",
                    "unlock_at": now() + horizon + 600,
                    "visibility": visibility,
                }),
            );
            assert!(beyond.is_error, "{configured:?}: {}", beyond.text);
            assert!(
                beyond.text.contains("horizon"),
                "{configured:?}: {}",
                beyond.text
            );
            assert!(
                beyond.text.contains(&format!(" {horizon} seconds")),
                "{configured:?}: the refusal states the limit: {}",
                beyond.text
            );
            assert!(
                beyond.text.contains(HORIZON),
                "{configured:?}: {}",
                beyond.text
            );
        }
        assert_eq!(
            bench.traffic(),
            traffic_before,
            "{configured:?}: a refused create sends nothing"
        );
        assert!(
            !install.state_dir().exists(),
            "{configured:?}: nothing is sealed"
        );
        assert_eq!(bench.publications(), published, "{configured:?}");

        let unlock_at = now() + horizon - 600;
        let within = session
            .call(
                "create_qub",
                &json!({
                    "body": format!("inside the horizon {configured:?}"),
                    "unlock_at": unlock_at,
                    "visibility": "public",
                }),
            )
            .ok();
        assert_eq!(within["unlock_at"], unlock_at, "{configured:?}");
        let inner = bench.world.lock();
        assert_eq!(inner.publications, published + 1, "{configured:?}");
        assert_eq!(
            inner.uploads.last().map(|upload| upload.unlock_at),
            Some(unlock_at),
            "{configured:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

/// A host that closes the session gets a clean exit, and a server started
/// again on the same state directory still has every operation: the
/// completed one answers with its stored result, the one whose
/// acknowledgement was lost is still listed and resolves to the one
/// publication the service already holds.
#[test]
fn a_graceful_restart_keeps_every_operation() {
    let bench = Bench::start();
    let install = bench.creator();
    let unlock_at = now() + 3600;
    let private_request = json!({
        "body": "kept across a restart",
        "unlock_at": unlock_at,
        "sender_label": "matrix",
    });
    let public_request = json!({
        "body": "acknowledgement lost before the restart",
        "unlock_at": unlock_at,
        "visibility": "public",
    });

    let mut first = install.start();
    first.request("initialize", Some(json!({})));
    let private = first.call("create_qub", &private_request).ok();
    bench
        .world
        .lock()
        .upload_faults
        .push(UploadFault::CommitThenDrop);
    let lost = first.call("create_qub", &public_request);
    assert_eq!(lost.error_code(), "upload_failed");
    let unresolved = first.call("list_pending_operations", &no_arguments()).ok();
    assert_eq!(unresolved["pending"].as_array().map(Vec::len), Some(1));
    let operation_id = unresolved["pending"][0]["operation_id"].clone();
    assert_eq!(lost.json()["operation_id"], operation_id);

    let exited = first.close();
    assert_eq!(exited.status.code(), Some(0), "{}", exited.stderr);
    assert!(
        exited.stderr.contains("stdin closed, shutting down"),
        "{}",
        exited.stderr
    );
    assert_eq!(bench.publications(), 2);
    let requests_before = bench.relay.requests();
    assert_eq!(bench.world.lock().uploads.len(), 2);

    let mut second = install.start();
    let hello = second.request("initialize", Some(json!({})));
    assert_eq!(hello["result"]["protocolVersion"], "2024-11-05");
    let still = second.call("list_pending_operations", &no_arguments()).ok();
    assert_eq!(
        still["pending"], unresolved["pending"],
        "the journal survived"
    );
    assert_eq!(still["pending"][0]["state"], "sent");
    assert_eq!(still["pending"][0]["visibility"], "public");

    // The completed operation: its stored result, with no request at all.
    let again = second.call("create_qub", &private_request).ok();
    assert_eq!(again["resumed"], true);
    assert_eq!(tx(&again), tx(&private));
    assert!(
        again["wrapper_key_b64url"] == private["wrapper_key_b64url"]
            && again["delivery_url"] == private["delivery_url"],
        "the restart must return the same key and link"
    );
    assert_eq!(bench.relay.requests(), requests_before);

    // The unresolved one: found by lookup, never uploaded again.
    let recovered = second.call("create_qub", &public_request).ok();
    assert_eq!(recovered["resumed"], true);
    assert_eq!(recovered["operation_id"], operation_id);
    assert_eq!(recovered["visibility"], "public");
    let public_txs: Vec<String> = bench
        .world
        .lock()
        .artifacts
        .iter()
        .filter(|(_, stored)| stored.is_public)
        .map(|(tx_id, _)| tx_id.clone())
        .collect();
    assert_eq!(public_txs.len(), 1, "exactly one public publication");
    assert_eq!(tx(&recovered), public_txs[0]);
    assert_eq!(bench.publications(), 2, "the restart published nothing new");
    assert_eq!(bench.world.lock().uploads.len(), 2, "and uploaded nothing");
    assert_eq!(
        bench.relay.requests()[requests_before.len()..],
        ["GET /api/v1/upload/operation"]
    );
    let listed = second.call("list_pending_operations", &no_arguments()).ok();
    assert_eq!(listed["pending"], json!([]));

    // What was published before the restart opens with what it returned
    // after it.
    let status = second
        .call(
            "check_status",
            &json!({ "delivery_url": again["delivery_url"] }),
        )
        .ok();
    assert_eq!(status["status"], "locked");
    assert_eq!(status["visibility"], "private");
    assert_eq!(status["qub_id"], private["qub_id"]);
    assert_eq!(second.close().status.code(), Some(0));
}

/// The process is killed — not asked to stop — while its upload is in the
/// air. `hold` decides where the upload was at that moment; the restarted
/// server must end with the SAME qub, key and operation, one publication
/// and one accepted upload either way.
fn kill_mid_upload_then_restart(hold: Hold) {
    let accepted_before_the_kill = usize::from(hold == Hold::AfterTheWorker);
    let bench = Bench::holding(hold);
    let install = bench.creator();
    let arguments = json!({
        "body": "killed mid-upload",
        "unlock_at": now() + 3600,
        "intent": "prediction",
    });

    let mut first = install.start();
    first.write_line(
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "create_qub", "arguments": arguments },
        })
        .to_string(),
    );
    bench.relay.wait_for_hold();
    // Where things stand at the kill: the service has (or has not) accepted
    // the upload, and the journal already says it was sent.
    assert_eq!(bench.publications(), accepted_before_the_kill);
    assert_eq!(bench.world.lock().uploads.len(), accepted_before_the_kill);
    let (_, journaled) = install.only_record();
    assert_eq!(journaled["state"], "sent");
    assert_eq!(
        journaled["tx_id"],
        Value::Null,
        "no transaction id is known"
    );
    let key = journaled["wrapper_key_b64url"]
        .as_str()
        .expect("the journal holds the wrapper key")
        .to_owned();
    assert_eq!(BASE64URL.decode(&key).map(|k| k.len()), Ok(32));
    let killed = first.kill();
    assert!(!killed.status.success(), "the process was killed");
    assert_eq!(killed.stdout, "", "the client was never answered");
    assert!(
        !killed.stderr.contains(&key),
        "stderr leaked the wrapper key"
    );

    let mut second = install.start();
    let listed = second.call("list_pending_operations", &no_arguments());
    assert!(
        !listed.text.contains(&key),
        "the listing leaked the wrapper key"
    );
    assert_eq!(
        listed.ok()["pending"][0]["operation_id"],
        journaled["operation_id"]
    );

    let recovered = second.call("create_qub", &arguments).ok();
    assert_eq!(recovered["resumed"], true);
    assert_eq!(recovered["operation_id"], journaled["operation_id"]);
    assert_eq!(recovered["qub_id"], journaled["qub_id_hex"]);
    assert!(
        recovered["wrapper_key_b64url"] == journaled["wrapper_key_b64url"],
        "the restart must return the journaled wrapper key"
    );
    let tx_id = tx(&recovered);
    assert_eq!(
        recovered["delivery_url"],
        format!("{}#{key}", bench.delivery_url(&tx_id))
    );
    {
        let inner = bench.world.lock();
        assert_eq!(inner.publications, 1, "one publication, one debit");
        assert_eq!(inner.uploads.len(), 1, "the Worker accepted one upload");
        assert_eq!(
            Some(BASE64.encode(&inner.uploads[0].bytes).as_str()),
            journaled["upload_body"]["wrapped_cbor_base64"].as_str(),
            "the published bytes are the journaled artifact"
        );
        assert_eq!(
            Some(inner.uploads[0].idempotency_key.as_str()),
            journaled["idempotency_key"].as_str()
        );
        assert_eq!(inner.uploads[0].bytes, inner.artifacts[&tx_id].bytes);
    }
    let expected: &[&str] = if hold == Hold::AfterTheWorker {
        // Accepted before the kill: found by lookup, never sent again.
        &[
            "GET /api/v1/upload/operation",
            "POST /api/v1/upload",
            "GET /api/v1/upload/operation",
        ]
    } else {
        // Never reached the Worker: sent again, under the same key.
        &[
            "GET /api/v1/upload/operation",
            "POST /api/v1/upload",
            "GET /api/v1/upload/operation",
            "POST /api/v1/upload",
        ]
    };
    assert_eq!(bench.relay.requests(), expected);

    // The recovered link opens the recovered qub.
    let status = second
        .call(
            "check_status",
            &json!({ "delivery_url": recovered["delivery_url"] }),
        )
        .ok();
    assert_eq!(status["status"], "locked");
    assert_eq!(status["visibility"], "private");
    assert_eq!(status["qub_id"], recovered["qub_id"]);
    assert_eq!(install.only_record().1["state"], "completed");
    let listed = second.call("list_pending_operations", &no_arguments()).ok();
    assert_eq!(listed["pending"], json!([]));
}

#[test]
fn killed_before_the_upload_is_accepted_then_restarted_publishes_once() {
    kill_mid_upload_then_restart(Hold::BeforeTheWorker);
}

#[test]
fn killed_after_the_upload_is_accepted_then_restarted_publishes_once() {
    kill_mid_upload_then_restart(Hold::AfterTheWorker);
}

/// The whole state directory is gone after a publication whose
/// acknowledgement was lost. Nothing local can tie a new request to the old
/// one, so what the server must not do is pretend: it lists nothing, the new
/// create is reported as a NEW operation with its own transaction and key —
/// never as a resume — and the earlier private qub is not offered as
/// readable: without its lost key it is refused, and the new key does not
/// open it.
///
/// It IS a second publication. With no journal there is no local record
/// that could prevent one; this test pins what the result says about it.
#[test]
fn a_lost_state_directory_is_never_reported_as_a_resume() {
    let bench = Bench::start();
    let install = bench.creator();
    let arguments =
        json!({ "body": "sealed before the state was lost", "unlock_at": now() + 3600 });

    bench
        .world
        .lock()
        .upload_faults
        .push(UploadFault::CommitThenDrop);
    let mut first = install.start();
    assert_eq!(
        first.call("create_qub", &arguments).error_code(),
        "upload_failed"
    );
    first.close();
    let first_tx = {
        let inner = bench.world.lock();
        assert_eq!(inner.publications, 1);
        inner.artifacts.keys().next().expect("one artifact").clone()
    };
    let (_, lost_record) = install.only_record();
    let lost_key = lost_record["wrapper_key_b64url"]
        .as_str()
        .expect("the lost journal held the key")
        .to_owned();
    std::fs::remove_dir_all(install.state_dir()).expect("lose the state directory");

    let mut second = install.start();
    let listed = second.call("list_pending_operations", &no_arguments()).ok();
    assert_eq!(listed["pending"], json!([]));
    assert_eq!(listed["quarantined"], json!([]));
    assert!(
        !install.state_dir().exists(),
        "listing must not create the state directory"
    );

    let created = second.call("create_qub", &arguments);
    assert!(
        !created.text.contains(&first_tx),
        "the earlier transaction must not be offered as this result"
    );
    let created = created.ok();
    assert_eq!(
        created["resumed"], false,
        "not a resume, and not called one"
    );
    assert_ne!(tx(&created), first_tx);
    assert_ne!(created["operation_id"], lost_record["operation_id"]);
    let new_key = created["wrapper_key_b64url"].as_str().expect("a new key");
    assert!(new_key != lost_key, "a new qub has a new key");
    assert_eq!(
        bench.publications(),
        2,
        "with the journal gone this is a second publication, reported as a new one"
    );

    // The earlier private qub: no claim that it can still be read.
    for tool in ["read_qub", "check_status"] {
        let missing = second.call(tool, &json!({ "tx_id": first_tx }));
        assert_eq!(missing.error_code(), "wrapper_key_required", "{tool}");
        let wrong = second.call(
            tool,
            &json!({ "tx_id": first_tx, "key_base64url": new_key }),
        );
        assert_eq!(wrong.error_code(), "unwrap_failed", "{tool}");
    }
    // The new one opens with what was returned for it.
    let status = second
        .call(
            "check_status",
            &json!({ "delivery_url": created["delivery_url"] }),
        )
        .ok();
    assert_eq!(status["qub_id"], created["qub_id"]);
}
