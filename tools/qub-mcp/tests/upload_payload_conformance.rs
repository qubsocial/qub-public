//! Drift fix #2 — assert the JSON body the MCP would POST to
//! `/api/v1/upload` conforms to the Worker's documented
//! `UploadRequest` schema.
//!
//! The MCP and the Worker live in different languages and deploy on
//! different cadences. Today the MCP's `handle_create_qub` builds an
//! upload body inline and posts it; if the Worker tightens the
//! schema (new required field, narrower pattern) the MCP silently
//! breaks at runtime. This test pins the contract by parsing the
//! `UploadRequest` schema out of `workers/api/openapi.json` and
//! checking that the body the MCP constructs satisfies every
//! `required` and `pattern` constraint.
//!
//! Why no `jsonschema` crate dep? `UploadRequest`'s constraints reduce
//! to "is present" + a couple of regex patterns — handled inline
//! without pulling in a 10MB-ish validator. If the schema grows
//! genuinely complex (oneOf branches, conditional requirements)
//! the right move is to switch to `jsonschema` then.
//!
//! What this does NOT test:
//!   - the wire encoding of `wrapped_cbor_base64` (qub-core's
//!     wrapper tests cover that).
//!   - that the Worker actually accepts the body end-to-end (the
//!     Worker's own upload tests cover that).
//!
//! It tests the JOIN: the MCP's body shape matches the Worker's
//! documented expectations.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at tools/qub-mcp; go up two.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn upload_request_schema() -> Value {
    let path = workspace_root().join("workers/api/openapi.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let spec: Value = serde_json::from_str(&raw).expect("openapi.json is valid JSON");
    spec.pointer("/components/schemas/UploadRequest")
        .expect("UploadRequest schema must exist in openapi.json")
        .clone()
}

/// Construct the JSON body shape that `handle_create_qub` posts to
/// `/api/v1/upload`. Mirrors the inline `serde_json::json!` block in
/// `tools/qub-mcp/src/main.rs::handle_create_qub` — keep this
/// function in sync if the upload body shape changes.
///
/// Synthetic values for fields the MCP computes from real seal
/// output. They satisfy the regex patterns but are not derived from
/// any real seal — that's the qub-core wrapper tests' job.
fn synthetic_upload_body() -> Value {
    json!({
        "wrapped_cbor_base64": "AQID", // arbitrary base64 — schema only requires `type: string`
        "qub_id_hex": "0".repeat(64), // 64 lowercase-hex chars matches `^[0-9a-f]{64}$`
        "unlock_at": 2_000_000_000_i64,
        "device_id": "mcp-server",
        "content_size": 1234,
    })
}

#[test]
fn mcp_upload_body_carries_every_required_field() {
    let schema = upload_request_schema();
    let required: Vec<String> = schema["required"]
        .as_array()
        .expect("UploadRequest.required is an array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let body = synthetic_upload_body();
    let body_obj = body.as_object().expect("upload body must be a JSON object");

    let missing: Vec<&str> = required
        .iter()
        .filter(|k| !body_obj.contains_key(k.as_str()))
        .map(String::as_str)
        .collect();

    assert!(
        missing.is_empty(),
        "MCP's upload body is missing required field(s) per openapi.json UploadRequest schema: {missing:?}\n\n\
         If a new required field was added to the spec, update `handle_create_qub` in \
         tools/qub-mcp/src/main.rs to include it (and update `synthetic_upload_body` here).",
    );
}

#[test]
fn mcp_upload_body_field_types_match_schema() {
    let schema = upload_request_schema();
    let props = schema["properties"]
        .as_object()
        .expect("UploadRequest.properties is an object");
    let body = synthetic_upload_body();

    for (key, value) in body.as_object().unwrap() {
        let prop_schema = props
            .get(key)
            .unwrap_or_else(|| panic!("body field {key} is not declared in UploadRequest schema"));
        let expected_type = prop_schema["type"].as_str().unwrap_or("");
        let actual_ok = match expected_type {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            _ => true,
        };
        assert!(
            actual_ok,
            "field {key} has type mismatch: schema says {expected_type:?}, body has {value}",
        );
    }
}

#[test]
fn mcp_upload_body_qub_id_hex_matches_schema_pattern() {
    let schema = upload_request_schema();
    let pattern = schema["properties"]["qub_id_hex"]["pattern"]
        .as_str()
        .expect("qub_id_hex.pattern must exist");
    assert_eq!(
        pattern, "^[0-9a-f]{64}$",
        "schema pattern changed — update body builders accordingly"
    );

    // The actual MCP code uses `hex::encode(seal_output.qub_id)` which
    // produces exactly 64 lowercase-hex chars. Confirm the synthetic
    // value used in this test file mirrors that contract. Hand-coded
    // pattern check (64 lowercase-hex chars) avoids pulling a regex
    // crate just for this assertion.
    let body = synthetic_upload_body();
    let qub_id = body["qub_id_hex"].as_str().unwrap();
    assert_eq!(qub_id.len(), 64, "qub_id_hex must be 64 chars: {qub_id}");
    assert!(
        qub_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())),
        "qub_id_hex must be lowercase hex: {qub_id}"
    );
}
