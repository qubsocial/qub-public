//! Layer 5 of the MCP test suite — spawn the compiled `qub-mcp`
//! binary, write JSON-RPC frames to its stdin, parse responses from
//! its stdout, and assert the protocol surface end-to-end.
//!
//! Layers 1–4 (unit tests in `src/main.rs::tests`) verify the
//! handlers, helpers, schema, and qub-core round-trip in isolation.
//! This file verifies that the binary actually wires those handlers
//! into the JSON-RPC dispatcher and round-trips bytes over stdio
//! the way an MCP host would speak to it.
//!
//! The tests deliberately avoid every code path that requires a
//! reachable qub.social Worker — i.e. happy-path `create_qub` and
//! `read_qub`. Those hit real HTTP. Mocking the network from the
//! outside of the binary is out of scope; the worker's seal/upload
//! tests already cover the server-side contract, and the unit tests
//! cover the MCP-side seal pipeline.
//!
//! Each test spawns a fresh binary, writes its frames, drops stdin
//! (which causes the read loop in `main` to exit cleanly on EOF),
//! and reads stdout to completion. Tests run in parallel by default;
//! each owns its own process so there's no shared state to race on.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

const BIN_PATH: &str = env!("CARGO_BIN_EXE_qub-mcp");

/// Spawn the binary, send the supplied JSON-RPC frames (one per line),
/// close stdin so the read loop exits, and return the stdout lines.
///
/// `env_extra` lets a test set `QUB_API_KEY` etc. for the child process.
fn run_with_frames(frames: &[Value], env_extra: &[(&str, &str)]) -> Vec<Value> {
    let mut cmd = Command::new(BIN_PATH);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Default: no API key, so create_qub fails fast at the auth check.
    // Tests that need it set it via env_extra.
    cmd.env_remove("QUB_API_KEY");
    cmd.env("QUB_BASE_URL", "https://example.invalid"); // never reached in these tests
    for (k, v) in env_extra {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("spawn qub-mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin pipe");
        for frame in frames {
            let line = serde_json::to_string(frame).unwrap();
            stdin.write_all(line.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    // Drop stdin to send EOF — the binary's read loop exits and
    // the process terminates cleanly.
    drop(child.stdin.take());

    // Hard cap on stdout lines so a wedged binary doesn't hang the
    // test suite — the take(N) aborts the iterator after N lines no
    // matter how much the child produces.
    let stdout = child.stdout.take().expect("stdout pipe");
    let parsed: Vec<Value> = BufReader::new(stdout)
        .lines()
        .take(frames.len() + 4)
        .filter_map(Result::ok)
        .map(|l| serde_json::from_str(&l).expect("each stdout line is valid JSON"))
        .collect();

    // Bounded poll for child exit; kill if it doesn't finish in time.
    // Without this guard a hang in `main` would leak a process.
    for _ in 0..50 {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    parsed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn binary_responds_to_initialize_with_protocol_envelope() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let responses = run_with_frames(&[req], &[]);
    assert_eq!(responses.len(), 1, "expected exactly one response");
    let r = &responses[0];
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 1);
    assert!(r["result"]["protocolVersion"].is_string());
    assert!(r["result"]["serverInfo"]["name"].is_string());
    assert!(r["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn binary_lists_all_three_tools() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/list"
    });
    let responses = run_with_frames(&[req], &[]);
    assert_eq!(responses.len(), 1);
    let tools = responses[0]["result"]["tools"]
        .as_array()
        .expect("tools is an array");
    assert_eq!(tools.len(), 3);
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"create_qub"));
    assert!(names.contains(&"read_qub"));
    assert!(names.contains(&"check_status"));
}

#[test]
fn binary_returns_method_not_found_for_unknown_method() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "does/not/exist"
    });
    let responses = run_with_frames(&[req], &[]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], -32601);
    assert!(
        responses[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does/not/exist")
    );
}

#[test]
fn binary_returns_parse_error_on_malformed_input() {
    // Skip serde_json round-trip — write the malformed bytes directly.
    let mut child = Command::new(BIN_PATH)
        .env_remove("QUB_API_KEY")
        .env("QUB_BASE_URL", "https://example.invalid")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        // Not valid JSON — should trigger -32700 parse error.
        stdin.write_all(b"this is not json at all\n").unwrap();
    }
    drop(child.stdin.take());

    let stdout = child.stdout.take().unwrap();
    let line = BufReader::new(stdout)
        .lines()
        .next()
        .expect("at least one response line")
        .unwrap();
    let _ = child.wait();

    let parsed: Value = serde_json::from_str(&line).expect("parse-error response is valid JSON");
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["error"]["code"], -32700);
    assert!(
        parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("parse")
    );
}

#[test]
fn binary_returns_is_error_content_for_create_qub_without_api_key() {
    // QUB_MCP_ALLOW_CREATE opens the publishing gate so the call reaches
    // the api-key check (the path under test); unlock_at is kept within
    // the default one-year horizon so the ceiling check passes too.
    let unlock_at = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs(),
    )
    .expect("timestamp fits i64")
        + 3600;
    let req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "create_qub",
            "arguments": {
                "body": "test message",
                "unlock_at": unlock_at
            }
        }
    });
    let responses = run_with_frames(&[req], &[("QUB_MCP_ALLOW_CREATE", "1")]);
    assert_eq!(responses.len(), 1);
    let r = &responses[0];
    // Tool errors come back as a successful JSON-RPC response with
    // `isError: true` in the content envelope (per MCP spec).
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 11);
    assert_eq!(r["result"]["isError"], true);
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("QUB_API_KEY"), "content: {text}");
}

#[test]
fn binary_returns_is_error_content_for_read_qub_without_params() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "read_qub",
            "arguments": {}
        }
    });
    let responses = run_with_frames(&[req], &[]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["result"]["isError"], true);
    let text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    // Either form must be supplied — message should hint at both.
    assert!(
        text.contains("delivery_url") || text.contains("tx_id"),
        "content: {text}"
    );
}

#[test]
fn binary_round_trips_full_protocol_handshake() {
    // Mirrors what an MCP host actually does on connect: initialize,
    // notifications/initialized, then tools/list. All three frames in
    // one session — proves the binary stays alive across requests.
    let frames = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "notifications/initialized"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list"
        }),
    ];
    let responses = run_with_frames(&frames, &[]);
    assert_eq!(responses.len(), 3, "one response per frame");
    assert_eq!(responses[0]["id"], 1);
    assert!(responses[0]["result"]["protocolVersion"].is_string());
    assert_eq!(responses[1]["id"], 2);
    assert_eq!(responses[2]["id"], 3);
    assert_eq!(responses[2]["result"]["tools"].as_array().unwrap().len(), 3);
}
