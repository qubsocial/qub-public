//! Local state for `qub-mcp`: the installation device id, the
//! operation-id key, and the durable `create_qub` operation journal.
//!
//! # Why a journal exists
//!
//! `create_qub` generates the private-delivery wrapper key K locally and
//! the qub id from a fresh seal. Before this journal existed, a process
//! killed between the upload and the response lost K (the only read
//! capability) and a retry re-sealed with a NEW qub id — a different
//! `Idempotency-Key`, so a second paid publication. The journal records
//! the exact upload body, K and the idempotency key **before** the first
//! byte goes on the wire, so a retry after any crash resumes the same
//! operation instead of creating a new one.
//!
//! The idempotency key is generated once per operation and carries a random
//! component (see [`new_idempotency_key`]). The qub id alone does not name
//! an operation: it is a function of content and a seconds-resolution seal
//! time, so two installations sealing the same body in the same second
//! derive the same id for two different artifacts.
//!
//! # Layout
//!
//! ```text
//! <state dir>/            0700
//!   device_id             0600  32 lowercase hex — installation device id
//!   operation_key         0600  64 lowercase hex — 32-byte operation-id key
//!   ops/                  0700
//!     <operation_id>.json 0600  one `OperationRecord` per operation
//!     <operation_id>.json[.N].corrupt  an unreadable record, moved aside
//! ```
//!
//! A quarantined record is never deleted and never forgotten: while one
//! exists for an operation id, that id cannot silently start a new
//! operation (see [`StateDir::quarantined_records`]).
//!
//! The directory contains decryption keys. Every write is atomic
//! (temp file in the same directory, fsync, rename, fsync directory) so a
//! crash leaves either the old or the new record, never a torn one.

use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

/// Environment variable that overrides the state directory location.
pub const STATE_DIR_ENV: &str = "QUB_MCP_STATE_DIR";

/// Journal record schema version of a private operation. Unchanged since
/// the journal was introduced, so a private record written today can still
/// be resumed by an older `qub-mcp`.
pub const RECORD_VERSION: u32 = 1;

/// Journal record schema version of a public operation. A public record
/// holds no wrapper key, which a binary that only knows
/// [`RECORD_VERSION`] would read as a corrupt record and report as a lost
/// key; the higher version makes it answer "upgrade qub-mcp" and leave the
/// record alone instead.
pub const PUBLIC_RECORD_VERSION: u32 = 2;

/// Highest record version this binary reads.
const MAX_RECORD_VERSION: u32 = PUBLIC_RECORD_VERSION;

/// Completed records older than this are pruned at startup. Unresolved
/// records (`prepared` / `sent`) are never pruned: they may hold the only
/// copy of a wrapper key for a qub that is already published.
pub const COMPLETED_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

/// Length of the operation-id key, in bytes.
pub const OPERATION_KEY_LEN: usize = 32;

/// Length of the random per-operation component of an `Idempotency-Key`,
/// in bytes (128 bits, hex-encoded on the wire).
pub const OPERATION_NONCE_LEN: usize = 16;

/// Prefix of every `Idempotency-Key` this binary writes.
const IDEMPOTENCY_KEY_PREFIX: &str = "qub-";

const DEVICE_ID_FILE: &str = "device_id";
const OPERATION_KEY_FILE: &str = "operation_key";
const OPS_DIR: &str = "ops";
const RECORD_EXT: &str = ".json";
const CORRUPT_EXT: &str = ".corrupt";
const LOCK_EXT: &str = ".lock";

/// Domain-separation tag for the keyed operation-id hash.
const OPERATION_ID_DOMAIN: &[u8] = b"qub-mcp/operation-id/v1";

/// Extra field hashed into the operation id of a public request (see
/// [`operation_id_for`]).
const OPERATION_ID_PUBLIC: &[u8] = b"visibility:public";

/// How a qub is delivered (PROTOCOL.md §13 / §13.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Wrapped under a key K that rides in the delivery URL fragment. The
    /// default, and the only mode before public support existed.
    #[default]
    Private,
    /// Stored as bare `SealedQubCbor`: time-locked, not link-gated, no key.
    Public,
}

impl Visibility {
    /// Wire name, as used in tool arguments, results and the journal.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
        }
    }

    /// True for [`Visibility::Private`] (serde `skip_serializing_if`).
    #[allow(clippy::trivially_copy_pass_by_ref)] // signature fixed by serde
    const fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }
}

// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

/// Resolve the state directory from an environment lookup.
///
/// Precedence: `QUB_MCP_STATE_DIR`, then `$XDG_STATE_HOME/qub-mcp`, then
/// `$HOME/.local/state/qub-mcp`. Empty values are treated as unset, and a
/// relative `XDG_STATE_HOME` is ignored as the XDG Base Directory
/// specification requires.
pub fn resolve_state_dir(get: impl Fn(&str) -> Option<String>) -> Result<PathBuf, String> {
    let non_empty = |name: &str| get(name).filter(|v| !v.is_empty());
    if let Some(dir) = non_empty(STATE_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = non_empty("XDG_STATE_HOME").filter(|v| Path::new(v).is_absolute()) {
        return Ok(PathBuf::from(xdg).join("qub-mcp"));
    }
    if let Some(home) = non_empty("HOME") {
        return Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("qub-mcp"));
    }
    Err(format!(
        "cannot locate a state directory: set {STATE_DIR_ENV} (or XDG_STATE_HOME / HOME)"
    ))
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// True for exactly 32 lowercase hex characters — the Worker's
/// `device_id` shape (`^[a-f0-9]{32}$`).
pub fn is_device_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// True for a caller-supplied operation id: `^[A-Za-z0-9_-]{8,64}$`.
/// The charset also makes the id safe to use as a file name.
pub fn is_valid_operation_id(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Lowercase-hex SHA3-256 of `bytes`.
pub fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

/// Keyed operation id for a `create_qub` request.
///
/// `SHA3-256(domain ‖ len(key) ‖ key ‖ len(f₁) ‖ f₁ ‖ …)` over the
/// fields `body`, `unlock_at` (8-byte big-endian), `intent` (or `""`) and
/// `sender_label` (or `""`), every field length-prefixed with a
/// 64-bit big-endian length so no two distinct tuples share an encoding.
/// A public request appends one more field, a fixed tag: the same body
/// asked for publicly and privately are two different requests, and must
/// never resume one another. A private request hashes exactly what it
/// always did, so operations journaled before public mode existed keep
/// their ids.
///
/// **Why keyed.** The id becomes a file name in the journal. An unkeyed
/// hash of the body would let anyone who can list that directory test
/// guesses of a low-entropy sealed message (a prediction, a yes/no
/// answer) long before it unlocks. Prefixing a secret key makes the id a
/// MAC: SHA3 is a sponge with no length-extension weakness, so
/// `H(key ‖ m)` is a sound PRF/MAC, and without the key a guess cannot
/// be checked.
pub fn operation_id_for(
    key: &[u8; OPERATION_KEY_LEN],
    body: &str,
    unlock_at: i64,
    intent: Option<&str>,
    sender_label: Option<&str>,
    visibility: Visibility,
) -> String {
    let mut hasher = Sha3_256::new();
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    field(OPERATION_ID_DOMAIN);
    field(key);
    field(body.as_bytes());
    field(&unlock_at.to_be_bytes());
    field(intent.unwrap_or("").as_bytes());
    field(sender_label.unwrap_or("").as_bytes());
    if visibility == Visibility::Public {
        field(OPERATION_ID_PUBLIC);
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Operation records
// ---------------------------------------------------------------------------

/// Lifecycle of a journaled `create_qub` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Sealed and journaled; the upload has never been attempted.
    Prepared,
    /// An upload POST may have been sent; its outcome is unknown until
    /// a response or a server-side lookup resolves it.
    Sent,
    /// The server confirmed the publication; `tx_id` is known.
    Completed,
}

impl OperationState {
    /// Wire name, as serialised in the record.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Sent => "sent",
            Self::Completed => "completed",
        }
    }

    /// Inverse of [`as_str`](Self::as_str); `None` for any other string.
    pub fn from_wire(s: &str) -> Option<Self> {
        [Self::Prepared, Self::Sent, Self::Completed]
            .into_iter()
            .find(|state| state.as_str() == s)
    }
}

/// One journaled `create_qub` operation.
///
/// Holds the wrapper key, so `Debug` is hand-written and redacts it (and
/// the delivery URL, whose fragment is the same key).
#[derive(Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    /// Schema version — [`RECORD_VERSION`] for a private operation,
    /// [`PUBLIC_RECORD_VERSION`] for a public one.
    pub version: u32,
    /// Delivery mode. Absent (private) in every record written before
    /// public mode existed, and still omitted for private operations so
    /// their records are byte-for-byte what they were. Declared near the
    /// top so that [`salvage`] can still read it from a truncated record.
    #[serde(default, skip_serializing_if = "Visibility::is_private")]
    pub visibility: Visibility,
    /// Operation id (also the file stem).
    pub operation_id: String,
    /// Unix seconds when the record was first written.
    pub created_at: i64,
    /// Unix seconds of the last state change.
    pub updated_at: i64,
    /// `Idempotency-Key` header value, generated once by
    /// [`new_idempotency_key`] when the operation is first journaled and
    /// reused verbatim by every send, resend and lookup:
    /// `qub-<qub_id_hex>-<nonce_hex>`. A record journaled before the random
    /// component existed carries `qub-<qub_id_hex>` and keeps it.
    pub idempotency_key: String,
    /// Hex qub id of the sealed qub.
    pub qub_id_hex: String,
    /// Keyed digest of the originating request (same construction as the
    /// default operation id). Detects an explicit `operation_id` reused
    /// for a different request.
    pub request_digest: String,
    /// Secret: base64url-no-pad wrapper key K. Empty for a public
    /// operation, which has no key.
    pub wrapper_key_b64url: String,
    /// Declared unlock time, Unix seconds.
    pub unlock_at: i64,
    /// drand round the qub is bound to.
    pub drand_round: u64,
    /// Size of the uploaded wrapper, bytes.
    pub content_size: usize,
    /// Lowercase-hex SHA3-256 of the API key used for the last upload.
    pub api_key_sha3_256: String,
    /// The server's opaque idempotency-scope id (`scope_id` of the
    /// operation lookup) under which the upload was last sent. A resend is
    /// a replay of the same publication only while the current key still
    /// resolves to this value. `None` in records written before the field
    /// existed, and when the server named no scope.
    #[serde(default)]
    pub scope_id: Option<String>,
    /// Lifecycle state.
    pub state: OperationState,
    /// Storage transaction id once known.
    pub tx_id: Option<String>,
    /// Fragment-bearing delivery URL once known.
    pub delivery_url: Option<String>,
    /// The exact JSON request body sent to `/api/v1/upload` (ciphertext only).
    ///
    /// Declared LAST on purpose: it is by far the largest field, and the
    /// record is written in declaration order. A file cut short therefore
    /// loses this first and keeps the wrapper key, the `Idempotency-Key` and
    /// the state above it, which is what [`salvage`] reads.
    pub upload_body: Value,
}

impl fmt::Debug for OperationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationRecord")
            .field("version", &self.version)
            .field("visibility", &self.visibility)
            .field("operation_id", &self.operation_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("idempotency_key", &self.idempotency_key)
            .field("qub_id_hex", &self.qub_id_hex)
            .field("wrapper_key_b64url", &"[redacted]")
            .field("unlock_at", &self.unlock_at)
            .field("drand_round", &self.drand_round)
            .field("content_size", &self.content_size)
            .field("state", &self.state)
            .field("tx_id", &self.tx_id)
            .field(
                "delivery_url",
                &self.delivery_url.as_ref().map(|_| "[redacted]"),
            )
            .finish_non_exhaustive()
    }
}

/// Why a stored record could not be used.
#[derive(Debug)]
pub enum LoadError {
    /// The file is unreadable as a v1 record. Whether its wrapper key
    /// survives is a separate question, answered from the raw bytes by
    /// [`salvage`] — a record can be unparseable and still hold the key.
    Corrupt { reason: String },
    /// Written by a newer `qub-mcp`; left untouched.
    NewerVersion(u32),
    /// Filesystem error reading the record.
    Io(String),
}

/// Parse and validate a record's bytes.
fn parse_record(bytes: &[u8], expected_id: Option<&str>) -> Result<OperationRecord, LoadError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| LoadError::Corrupt {
        reason: format!("not valid JSON: {e}"),
    })?;
    if let Some(version) = value.get("version").and_then(Value::as_u64)
        && version > u64::from(MAX_RECORD_VERSION)
    {
        return Err(LoadError::NewerVersion(
            u32::try_from(version).unwrap_or(u32::MAX),
        ));
    }
    let key_ok = value
        .get(WRAPPER_KEY_FIELD)
        .and_then(Value::as_str)
        .is_some_and(is_wrapper_key_b64url);
    let corrupt = |reason: String| LoadError::Corrupt { reason };
    let record: OperationRecord =
        serde_json::from_value(value).map_err(|e| corrupt(format!("invalid record: {e}")))?;
    let public = record.visibility == Visibility::Public;
    let expected_version = if public {
        PUBLIC_RECORD_VERSION
    } else {
        RECORD_VERSION
    };
    if record.version != expected_version {
        return Err(corrupt(format!(
            "unsupported version {} for a {} operation",
            record.version,
            record.visibility.as_str()
        )));
    }
    if public {
        // A public qub has no key. A record that claims to be public and
        // carries one is not something this binary wrote.
        if !record.wrapper_key_b64url.is_empty() {
            return Err(corrupt(
                "a public operation must not carry a wrapper key".to_string(),
            ));
        }
    } else if !key_ok {
        return Err(corrupt("wrapper key is missing or malformed".to_string()));
    }
    if let Some(id) = expected_id
        && record.operation_id != id
    {
        return Err(corrupt(format!(
            "operation_id {:?} does not match its file name",
            record.operation_id
        )));
    }
    if idempotency_key_qub_id(&record.idempotency_key) != Some(record.qub_id_hex.as_str())
        || record.upload_body.get("qub_id_hex").and_then(Value::as_str)
            != Some(record.qub_id_hex.as_str())
    {
        return Err(corrupt(
            "idempotency key, qub id and upload body disagree".to_string(),
        ));
    }
    if record.state == OperationState::Completed && record.tx_id.is_none() {
        return Err(corrupt("completed record has no tx_id".to_string()));
    }
    Ok(record)
}

// ---------------------------------------------------------------------------
// Salvage from unreadable records
// ---------------------------------------------------------------------------

const WRAPPER_KEY_FIELD: &str = "wrapper_key_b64url";
const IDEMPOTENCY_KEY_FIELD: &str = "idempotency_key";
const REQUEST_DIGEST_FIELD: &str = "request_digest";
const STATE_FIELD: &str = "state";
const VISIBILITY_FIELD: &str = "visibility";

/// True for a well-formed wrapper key: 43 base64url characters, the
/// unpadded encoding of 32 bytes.
fn is_wrapper_key_b64url(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// True for exactly 64 lowercase hex characters — a qub id, or the keyed
/// request digest of [`operation_id_for`].
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// True for the random component of an `Idempotency-Key`: exactly
/// `2 × OPERATION_NONCE_LEN` lowercase hex characters.
fn is_operation_nonce_hex(s: &str) -> bool {
    s.len() == OPERATION_NONCE_LEN * 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A fresh `Idempotency-Key` for a new operation on the qub `qub_id_hex`:
/// `qub-<qub_id_hex>-<nonce_hex>`, where the nonce is
/// [`OPERATION_NONCE_LEN`] bytes from the OS CSPRNG.
///
/// **Why random.** The server treats the key as the identity of one
/// publication within an idempotency scope, and answers a repeat of it
/// with the first publication's transaction. A key derived from the qub
/// id alone is shared by every artifact with that id — and the id is a
/// function of content and a seconds-resolution seal time, so two
/// installations (two state directories) sealing the same body in the same
/// second under one paid key produced ONE key for two artifacts wrapped
/// under two different keys K. The second caller was handed the first
/// transaction, which its own K cannot open. No local check can rule that
/// out — the other journal is not visible from here — so the key itself
/// has to be unpredictable. The qub id stays in it only so that a key
/// read in a log says which qub it was for.
///
/// The result is 101 characters of `[a-z0-9-]`, inside the Worker's
/// `IDEMPOTENCY_KEY_PATTERN` (`^[A-Za-z0-9._-]{1,255}$`).
///
/// Call it ONCE per operation and journal the result: a retry that drew a
/// new key would be a new operation, and so a second publication.
pub fn new_idempotency_key(qub_id_hex: &str) -> Result<String, String> {
    let mut nonce = [0u8; OPERATION_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| format!("RNG failed: {e}"))?;
    Ok(format!(
        "{IDEMPOTENCY_KEY_PREFIX}{qub_id_hex}-{}",
        hex::encode(nonce)
    ))
}

/// The qub id named by an `Idempotency-Key` written by this binary, or
/// `None` when `key` is in neither of its two formats:
///
/// - `qub-<qub_id_hex>-<nonce_hex>` — written by [`new_idempotency_key`];
/// - `qub-<qub_id_hex>` — written before the random component existed.
///   Such a record must still load, resume and be salvaged: that key is the
///   one its upload was (or will be) sent under.
pub fn idempotency_key_qub_id(key: &str) -> Option<&str> {
    let rest = key.strip_prefix(IDEMPOTENCY_KEY_PREFIX)?;
    let (qub_id, nonce) = match rest.split_once('-') {
        Some((qub_id, nonce)) => (qub_id, Some(nonce)),
        None => (rest, None),
    };
    (is_lower_hex_64(qub_id) && nonce.is_none_or(is_operation_nonce_hex)).then_some(qub_id)
}

/// True when `needle` occurs in `haystack`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The value of the first `"name": "<value>"` string member in `bytes`,
/// read WITHOUT parsing the document — for a record that is no longer
/// valid JSON (a truncated write, a damaged tail). `None` when the member
/// is absent, cut short before its closing quote, or contains an escape.
fn raw_string_member<'a>(bytes: &'a [u8], name: &str) -> Option<&'a str> {
    fn skip_space(bytes: &[u8]) -> &[u8] {
        let n = bytes.iter().take_while(|c| c.is_ascii_whitespace()).count();
        &bytes[n..]
    }
    let needle = format!("\"{name}\"");
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())?;
    let rest = skip_space(&bytes[at + needle.len()..]);
    let rest = skip_space(rest.strip_prefix(b":")?);
    let rest = rest.strip_prefix(b"\"")?;
    let end = rest.iter().position(|&c| c == b'"')?;
    let value = std::str::from_utf8(&rest[..end]).ok()?;
    (!value.contains('\\')).then_some(value)
}

/// What can still be read out of a record that can no longer be loaded.
///
/// Holds the wrapper key, so it deliberately has no `Debug` impl.
pub struct Salvage {
    /// True when the bytes still say the operation was public. A public
    /// qub has no wrapper key, so a missing key is then not a loss.
    /// `false` covers both a private record and one whose visibility can
    /// no longer be read (it is written at the very top of a record, so
    /// that takes a record with almost nothing left).
    pub public: bool,
    /// Secret: the wrapper key K, when it is still intact in the bytes.
    /// `None` means the key is lost: if that qub was published privately,
    /// nobody can read it.
    pub wrapper_key_b64url: Option<String>,
    /// The `Idempotency-Key` the upload was (or would have been) sent
    /// with, when still intact — enough to ask the server what happened.
    pub idempotency_key: Option<String>,
    /// The keyed digest of the request the record was written for, when
    /// still intact — tells whether a caller reusing the operation id is
    /// asking for the same request.
    pub request_digest: Option<String>,
    /// The lifecycle state the record was last written in, when still
    /// intact. `Some(Prepared)` proves the record never sent its upload;
    /// `None` proves nothing either way: the bytes that held it are gone.
    /// (It is written ahead of the upload body, so that takes a record cut
    /// short before the body even begins.)
    pub state: Option<OperationState>,
}

/// Recover the wrapper key, the idempotency key, the request digest and
/// the lifecycle state from a record's bytes.
///
/// The fields are read from the parsed document when the bytes are still
/// JSON (a record that is well-formed but invalid), and otherwise scanned
/// out of the raw bytes: a record truncated in its tail is not JSON any
/// more, yet these fields sit near the top and are usually untouched. Each
/// is returned only if it is completely present and well-formed, so a key
/// cut in half is reported as lost, never as a shorter key.
pub fn salvage(bytes: &[u8]) -> Salvage {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let member = |name: &str| -> Option<String> {
        parsed
            .as_ref()
            .map_or_else(
                || raw_string_member(bytes, name),
                |value| value.get(name).and_then(Value::as_str),
            )
            .map(str::to_owned)
    };
    Salvage {
        public: member(VISIBILITY_FIELD).as_deref() == Some(Visibility::Public.as_str()),
        wrapper_key_b64url: member(WRAPPER_KEY_FIELD).filter(|k| is_wrapper_key_b64url(k)),
        idempotency_key: member(IDEMPOTENCY_KEY_FIELD)
            .filter(|k| idempotency_key_qub_id(k).is_some()),
        request_digest: member(REQUEST_DIGEST_FIELD).filter(|d| is_lower_hex_64(d)),
        state: member(STATE_FIELD).and_then(|s| OperationState::from_wire(&s)),
    }
}

/// A record that was moved aside because it could not be loaded.
///
/// Holds the wrapper key, so it deliberately has no `Debug` impl.
pub struct QuarantinedRecord {
    /// Where the quarantined file is.
    pub path: PathBuf,
    /// Why it cannot be loaded.
    pub reason: String,
    /// What its bytes still yield.
    pub salvage: Salvage,
}

/// True when `name` is a quarantine file of `operation_id`:
/// `<id>.json.corrupt` or `<id>.json.<n>.corrupt`. Operation ids contain
/// no `.`, so one id's files can never be taken for another's.
fn is_quarantine_of(name: &str, operation_id: &str) -> bool {
    name.strip_prefix(operation_id)
        .and_then(|rest| rest.strip_prefix(RECORD_EXT))
        .and_then(|rest| rest.strip_suffix(CORRUPT_EXT))
        .is_some_and(|n| {
            n.is_empty()
                || n.strip_prefix('.')
                    .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Summary of the journal for `list_pending_operations`.
#[derive(Debug, Default)]
pub struct JournalListing {
    /// Records not yet `completed`, sorted by `created_at`.
    pub pending: Vec<OperationRecord>,
    /// Record files that failed to parse (left in place).
    pub unreadable: Vec<String>,
    /// Previously quarantined `*.corrupt` files.
    pub quarantined: Vec<String>,
}

// ---------------------------------------------------------------------------
// State directory
// ---------------------------------------------------------------------------

/// An opened (created, permission-tightened) state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Create (if needed) and open the state directory and its `ops/`
    /// subdirectory, both mode 0700.
    pub fn open(root: &Path) -> Result<Self, String> {
        create_private_dir(root)
            .map_err(|e| format!("cannot create state directory {}: {e}", root.display()))?;
        let ops = root.join(OPS_DIR);
        create_private_dir(&ops)
            .map_err(|e| format!("cannot create journal directory {}: {e}", ops.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Open the state directory only if its journal already exists —
    /// for read-only callers that must not create state as a side effect.
    pub fn existing(root: &Path) -> Option<Self> {
        root.join(OPS_DIR).is_dir().then(|| Self {
            root: root.to_path_buf(),
        })
    }

    /// Root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ops_dir(&self) -> PathBuf {
        self.root.join(OPS_DIR)
    }

    /// Path of the record file for `operation_id`.
    pub fn record_path(&self, operation_id: &str) -> PathBuf {
        self.ops_dir().join(format!("{operation_id}{RECORD_EXT}"))
    }

    /// Take the exclusive cross-process lock for one operation, or `None`
    /// when another `qub-mcp` process holds it.
    ///
    /// Two processes sharing a state directory would otherwise both read
    /// "no record", each seal a different qub under the same operation id,
    /// and overwrite each other's journal entry — one would then be handed
    /// the other's publication together with its own, useless, wrapper key.
    /// The lock is held from before the first journal read until the
    /// operation's final transition. It is an advisory OS lock on a
    /// dot-file beside the record, so it is released when the holder exits
    /// or is killed; a crashed process can never leave it stuck.
    pub fn lock_operation(&self, operation_id: &str) -> Result<Option<OperationLock>, String> {
        let path = self.ops_dir().join(format!(".{operation_id}{LOCK_EXT}"));
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(OperationLock { _file: file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => Err(format!("cannot lock {}: {e}", path.display())),
        }
    }

    /// The installation device id, generated on first use.
    pub fn device_id(&self) -> Result<String, String> {
        let raw = self.read_or_create(DEVICE_ID_FILE, || {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|e| format!("RNG failed: {e}"))?;
            Ok(hex::encode(bytes))
        })?;
        if is_device_id(&raw) {
            Ok(raw)
        } else {
            Err(format!(
                "{} is malformed (expected 32 lowercase hex characters); \
                 delete it to generate a new device id",
                self.root.join(DEVICE_ID_FILE).display()
            ))
        }
    }

    /// The per-state-directory operation-id key, generated on first use.
    pub fn operation_key(&self) -> Result<[u8; OPERATION_KEY_LEN], String> {
        let raw = self.read_or_create(OPERATION_KEY_FILE, || {
            let mut bytes = [0u8; OPERATION_KEY_LEN];
            getrandom::fill(&mut bytes).map_err(|e| format!("RNG failed: {e}"))?;
            Ok(hex::encode(bytes))
        })?;
        let mut key = [0u8; OPERATION_KEY_LEN];
        hex::decode_to_slice(&raw, &mut key).map_err(|_| {
            // Regenerating silently would change every default operation
            // id and so defeat resume for in-flight operations.
            format!(
                "{} is malformed (expected {} hex characters); refusing to \
                 regenerate it because that would orphan pending operations",
                self.root.join(OPERATION_KEY_FILE).display(),
                OPERATION_KEY_LEN * 2
            )
        })?;
        Ok(key)
    }

    /// Read `name`, or atomically create it with `generate()` if absent.
    /// Two racing processes converge on whichever value linked first.
    fn read_or_create(
        &self,
        name: &str,
        generate: impl FnOnce() -> Result<String, String>,
    ) -> Result<String, String> {
        let path = self.root.join(name);
        match fs::read_to_string(&path) {
            Ok(s) => return Ok(s.trim().to_string()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        }
        let value = generate()?;
        create_once(&self.root, name, value.as_bytes())
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    /// Load the record for `operation_id`, if any.
    pub fn load_record(&self, operation_id: &str) -> Result<Option<OperationRecord>, LoadError> {
        let path = self.record_path(operation_id);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(LoadError::Io(format!(
                    "cannot read {}: {e}",
                    path.display()
                )));
            },
        };
        parse_record(&bytes, Some(operation_id)).map(Some)
    }

    /// Durably write `record` (atomic replace).
    pub fn save_record(&self, record: &OperationRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|e| format!("cannot encode operation record: {e}"))?;
        let name = format!("{}{RECORD_EXT}", record.operation_id);
        atomic_write(&self.ops_dir(), &name, &bytes).map_err(|e| {
            format!(
                "cannot write operation record {}: {e}",
                self.ops_dir().join(&name).display()
            )
        })
    }

    /// Move an unusable record aside to `<name>.corrupt` (never deleted:
    /// it may hold the only copy of a wrapper key). Returns the new path.
    pub fn quarantine(&self, operation_id: &str) -> Result<PathBuf, String> {
        let from = self.record_path(operation_id);
        let file = format!("{operation_id}{RECORD_EXT}");
        let mut to = self.ops_dir().join(format!("{file}{CORRUPT_EXT}"));
        let mut n = 1u32;
        while to.exists() {
            to = self.ops_dir().join(format!("{file}.{n}{CORRUPT_EXT}"));
            n += 1;
        }
        fs::rename(&from, &to).map_err(|e| format!("cannot quarantine {}: {e}", from.display()))?;
        sync_dir(&self.ops_dir()).map_err(|e| format!("cannot sync journal directory: {e}"))?;
        Ok(to)
    }

    /// Every quarantined record of `operation_id`, in file-name order,
    /// with what its bytes still yield.
    ///
    /// A quarantined record is the trace of an operation whose outcome is
    /// no longer known locally — it may have been published. While one
    /// exists, the caller must not treat the operation id as unused:
    /// starting afresh would seal and publish a second qub for a request
    /// that may already have one.
    pub fn quarantined_records(
        &self,
        operation_id: &str,
    ) -> Result<Vec<QuarantinedRecord>, String> {
        let mut entries: Vec<(String, PathBuf)> = self
            .entries()?
            .into_iter()
            .filter(|(name, _)| is_quarantine_of(name, operation_id))
            .collect();
        entries.sort();
        Ok(entries
            .into_iter()
            .map(|(_, path)| match fs::read(&path) {
                Ok(bytes) => QuarantinedRecord {
                    reason: match parse_record(&bytes, Some(operation_id)) {
                        Err(LoadError::Corrupt { reason } | LoadError::Io(reason)) => reason,
                        Err(LoadError::NewerVersion(version)) => {
                            format!("record version {version} is newer than this qub-mcp")
                        },
                        Ok(_) => "it was quarantined earlier".to_string(),
                    },
                    salvage: salvage(&bytes),
                    path,
                },
                Err(e) => QuarantinedRecord {
                    reason: format!("cannot read it: {e}"),
                    salvage: Salvage {
                        public: false,
                        wrapper_key_b64url: None,
                        idempotency_key: None,
                        request_digest: None,
                        state: None,
                    },
                    path,
                },
            })
            .collect())
    }

    /// List the journal without modifying it.
    pub fn list(&self) -> Result<JournalListing, String> {
        let mut listing = JournalListing::default();
        for (name, path) in self.entries()? {
            if name.ends_with(CORRUPT_EXT) {
                listing.quarantined.push(name);
            } else if let Some(stem) = name.strip_suffix(RECORD_EXT) {
                match fs::read(&path)
                    .map_err(|e| LoadError::Io(e.to_string()))
                    .and_then(|b| parse_record(&b, Some(stem)))
                {
                    Ok(r) if r.state != OperationState::Completed => listing.pending.push(r),
                    Ok(_) => {},
                    Err(_) => listing.unreadable.push(name),
                }
            }
        }
        listing
            .pending
            .sort_by(|a, b| (a.created_at, &a.operation_id).cmp(&(b.created_at, &b.operation_id)));
        listing.unreadable.sort();
        listing.quarantined.sort();
        Ok(listing)
    }

    /// True when a journaled operation already uses `qub_id_hex`.
    ///
    /// The qub id is derived from content and a seconds-resolution
    /// `created_at`, so two deliberate duplicates sealed in the same
    /// second share it. Callers re-seal until this is false, so that the
    /// operations of ONE installation never share a qub id: the id is the
    /// name a qub goes by in a `create_qub` result and in
    /// `list_pending_operations`, and the service's transparency-log leaf
    /// is derived from it — two separately published artifacts under one
    /// name cannot be told apart there.
    ///
    /// This is NOT what keeps two operations from sharing an
    /// `Idempotency-Key`, and it could not be: it sees one state directory,
    /// and a second installation sealing the same body in the same second
    /// is invisible to it. The key carries its own random component for
    /// that (see [`new_idempotency_key`]).
    ///
    /// Unreadable and quarantined records count too, by a raw search for
    /// the id: a quarantined operation may have been published, and a
    /// deliberate re-publication sealed within the same second must not
    /// reuse its qub id.
    pub fn qub_id_in_use(&self, qub_id_hex: &str) -> Result<bool, String> {
        for (name, path) in self.entries()? {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let record = name
                .strip_suffix(RECORD_EXT)
                .and_then(|stem| parse_record(&bytes, Some(stem)).ok());
            let in_use = match record {
                Some(record) => record.qub_id_hex == qub_id_hex,
                None => contains_bytes(&bytes, qub_id_hex.as_bytes()),
            };
            if in_use {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Delete `completed` records whose last update is older than
    /// [`COMPLETED_RETENTION_SECS`]. Unresolved and unreadable records
    /// are never touched. Returns the number pruned.
    pub fn prune_completed(&self, now: i64) -> Result<usize, String> {
        let cutoff = now.saturating_sub(COMPLETED_RETENTION_SECS);
        let mut pruned = 0;
        for (name, path) in self.entries()? {
            let Some(stem) = name.strip_suffix(RECORD_EXT) else {
                continue;
            };
            let Ok(record) = fs::read(&path)
                .map_err(|e| LoadError::Io(e.to_string()))
                .and_then(|b| parse_record(&b, Some(stem)))
            else {
                continue;
            };
            if record.state == OperationState::Completed && record.updated_at < cutoff {
                fs::remove_file(&path)
                    .map_err(|e| format!("cannot prune {}: {e}", path.display()))?;
                pruned += 1;
            }
        }
        if pruned > 0 {
            sync_dir(&self.ops_dir()).map_err(|e| format!("cannot sync journal directory: {e}"))?;
        }
        Ok(pruned)
    }

    /// `(file name, path)` for every regular file in `ops/`, skipping
    /// in-progress temp files.
    fn entries(&self) -> Result<Vec<(String, PathBuf)>, String> {
        let dir = self.ops_dir();
        let read = fs::read_dir(&dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let mut out = Vec::new();
        for entry in read {
            let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
            if !entry.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.starts_with('.') || Path::new(&name).extension().is_some_and(|e| e == "tmp") {
                continue;
            }
            out.push((name, entry.path()));
        }
        Ok(out)
    }
}

/// Held exclusive lock on one operation; released on drop or process exit.
#[derive(Debug)]
pub struct OperationLock {
    _file: fs::File,
}

// ---------------------------------------------------------------------------
// Filesystem primitives
// ---------------------------------------------------------------------------

/// Create `path` (and missing parents) as a private directory and tighten
/// an existing one to 0700.
fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to a fresh 0600 temp file in `dir` and fsync it.
fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let tmp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        hex::encode(nonce)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(tmp)
}

/// Atomically replace `dir/name` with `bytes`: temp file, fsync, rename,
/// fsync the directory.
pub fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = write_temp(dir, name, bytes)?;
    if let Err(e) = fs::rename(&tmp, dir.join(name)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir)
}

/// Atomically create `dir/name` with `bytes` only if it does not exist.
/// A concurrent creator wins silently; the caller re-reads the file.
fn create_once(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = write_temp(dir, name, bytes)?;
    let linked = fs::hard_link(&tmp, dir.join(name));
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => sync_dir(dir),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// fsync a directory so a rename / link inside it is durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique scratch directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "qub-mcp-state-unit-{}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn state_dir_precedence_explicit_then_xdg_then_home() {
        let all = env_of(&[
            ("QUB_MCP_STATE_DIR", "/explicit"),
            ("XDG_STATE_HOME", "/xdg"),
            ("HOME", "/home/u"),
        ]);
        assert_eq!(resolve_state_dir(all).unwrap(), PathBuf::from("/explicit"));

        let xdg = env_of(&[("XDG_STATE_HOME", "/xdg"), ("HOME", "/home/u")]);
        assert_eq!(
            resolve_state_dir(xdg).unwrap(),
            PathBuf::from("/xdg/qub-mcp")
        );

        let home = env_of(&[("HOME", "/home/u")]);
        assert_eq!(
            resolve_state_dir(home).unwrap(),
            PathBuf::from("/home/u/.local/state/qub-mcp")
        );

        // Empty values are unset; a relative XDG_STATE_HOME is ignored.
        let empties = env_of(&[
            ("QUB_MCP_STATE_DIR", ""),
            ("XDG_STATE_HOME", "relative/xdg"),
            ("HOME", "/home/u"),
        ]);
        assert_eq!(
            resolve_state_dir(empties).unwrap(),
            PathBuf::from("/home/u/.local/state/qub-mcp")
        );

        let err = resolve_state_dir(env_of(&[])).unwrap_err();
        assert!(err.contains(STATE_DIR_ENV), "{err}");
    }

    #[test]
    fn operation_id_is_stable_and_sensitive_to_every_input() {
        let key = [7u8; OPERATION_KEY_LEN];
        let base = operation_id_for(
            &key,
            "body",
            100,
            Some("letter"),
            Some("al"),
            Visibility::Private,
        );
        assert_eq!(
            base,
            operation_id_for(
                &key,
                "body",
                100,
                Some("letter"),
                Some("al"),
                Visibility::Private
            ),
            "equal inputs must give equal ids"
        );
        assert_eq!(base.len(), 64);
        assert!(is_valid_operation_id(&base));

        let variants = [
            operation_id_for(
                &key,
                "body2",
                100,
                Some("letter"),
                Some("al"),
                Visibility::Private,
            ),
            operation_id_for(
                &key,
                "body",
                101,
                Some("letter"),
                Some("al"),
                Visibility::Private,
            ),
            operation_id_for(
                &key,
                "body",
                100,
                Some("thesis"),
                Some("al"),
                Visibility::Private,
            ),
            operation_id_for(&key, "body", 100, None, Some("al"), Visibility::Private),
            operation_id_for(
                &key,
                "body",
                100,
                Some("letter"),
                Some("bo"),
                Visibility::Private,
            ),
            operation_id_for(&key, "body", 100, Some("letter"), None, Visibility::Private),
            operation_id_for(
                &[8u8; OPERATION_KEY_LEN],
                "body",
                100,
                Some("letter"),
                Some("al"),
                Visibility::Private,
            ),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(&base, v, "variant {i} must change the id");
        }

        // Length prefixes keep field boundaries unambiguous.
        assert_ne!(
            operation_id_for(&key, "ab", 1, Some("c"), None, Visibility::Private),
            operation_id_for(&key, "a", 1, Some("bc"), None, Visibility::Private),
        );
    }

    #[test]
    fn device_id_validator_matches_worker_pattern() {
        assert!(is_device_id(&"0123456789abcdef".repeat(2)));
        assert!(!is_device_id("mcp-server"));
        assert!(!is_device_id(&"A".repeat(32)));
        assert!(!is_device_id(&"a".repeat(31)));
        assert!(!is_device_id(&"a".repeat(33)));
    }

    #[test]
    fn generated_device_id_matches_pattern_and_persists() {
        let tmp = TempDir::new();
        let state = StateDir::open(&tmp.0).unwrap();
        let id = state.device_id().unwrap();
        assert!(is_device_id(&id), "{id} must match ^[a-f0-9]{{32}}$");
        assert_eq!(state.device_id().unwrap(), id, "device id must be stable");
        let key = state.operation_key().unwrap();
        assert_eq!(state.operation_key().unwrap(), key);
    }

    #[cfg(unix)]
    #[test]
    fn state_files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = TempDir::new();
        let state = StateDir::open(&tmp.0).unwrap();
        state.device_id().unwrap();
        state.operation_key().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&tmp.0), 0o700);
        assert_eq!(mode(&tmp.0.join(OPS_DIR)), 0o700);
        assert_eq!(mode(&tmp.0.join(DEVICE_ID_FILE)), 0o600);
        assert_eq!(mode(&tmp.0.join(OPERATION_KEY_FILE)), 0o600);
    }

    fn record(id: &str, state: OperationState, updated_at: i64) -> OperationRecord {
        let qub_id_hex = "ab".repeat(32);
        OperationRecord {
            version: RECORD_VERSION,
            visibility: Visibility::Private,
            operation_id: id.to_string(),
            created_at: updated_at,
            updated_at,
            idempotency_key: format!("qub-{qub_id_hex}-{}", "9".repeat(32)),
            qub_id_hex: qub_id_hex.clone(),
            request_digest: "d".repeat(64),
            upload_body: serde_json::json!({"qub_id_hex": qub_id_hex}),
            wrapper_key_b64url: "A".repeat(43),
            unlock_at: 1,
            drand_round: 2,
            content_size: 3,
            api_key_sha3_256: "e".repeat(64),
            scope_id: Some("f".repeat(64)),
            state,
            tx_id: (state == OperationState::Completed).then(|| "tx".to_string()),
            delivery_url: None,
        }
    }

    #[test]
    fn prune_removes_only_old_completed_records() {
        let tmp = TempDir::new();
        let state = StateDir::open(&tmp.0).unwrap();
        let now = 10 * COMPLETED_RETENTION_SECS;
        let old = now - COMPLETED_RETENTION_SECS - 1;
        state
            .save_record(&record("old-completed", OperationState::Completed, old))
            .unwrap();
        state
            .save_record(&record("new-completed", OperationState::Completed, now))
            .unwrap();
        state
            .save_record(&record("old-sent-rec", OperationState::Sent, old))
            .unwrap();
        state
            .save_record(&record("old-prepared", OperationState::Prepared, old))
            .unwrap();
        fs::write(state.record_path("garbage-rec"), b"{not json").unwrap();

        assert_eq!(state.prune_completed(now).unwrap(), 1);
        assert!(!state.record_path("old-completed").exists());
        for kept in [
            "new-completed",
            "old-sent-rec",
            "old-prepared",
            "garbage-rec",
        ] {
            assert!(state.record_path(kept).exists(), "{kept} must be kept");
        }

        let listing = state.list().unwrap();
        let pending: Vec<&str> = listing
            .pending
            .iter()
            .map(|r| r.operation_id.as_str())
            .collect();
        assert_eq!(pending, vec!["old-prepared", "old-sent-rec"]);
        assert_eq!(listing.unreadable, vec!["garbage-rec.json".to_string()]);
    }

    #[test]
    fn record_debug_redacts_wrapper_key() {
        let mut r = record("debug-test", OperationState::Completed, 1);
        r.wrapper_key_b64url = "SECRETSECRETSECRETSECRETSECRETSECRETSECRET1".to_string();
        r.delivery_url = Some(format!("https://x/c/tx#{}", r.wrapper_key_b64url));
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("SECRET"), "{dbg}");
        assert!(dbg.contains("[redacted]"));
    }

    #[test]
    fn missing_wrapper_key_is_corrupt_and_salvages_no_key() {
        let mut value = serde_json::to_value(record("lost-key", OperationState::Sent, 1)).unwrap();
        value.as_object_mut().unwrap().remove("wrapper_key_b64url");
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            parse_record(&bytes, Some("lost-key")),
            Err(LoadError::Corrupt { .. })
        ));
        let salvaged = salvage(&bytes);
        assert!(salvaged.wrapper_key_b64url.is_none(), "the key is lost");
        assert_eq!(
            salvaged.idempotency_key,
            Some(format!("qub-{}-{}", "ab".repeat(32), "9".repeat(32)))
        );
        assert_eq!(salvaged.state, Some(OperationState::Sent));
    }

    /// The Worker's `IDEMPOTENCY_KEY_PATTERN`: `^[A-Za-z0-9._-]{1,255}$`.
    fn matches_worker_idempotency_key_pattern(s: &str) -> bool {
        (1..=255).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }

    /// A new key names its qub, fits the Worker's pattern, and is never
    /// the same twice — the qub id alone must not determine it.
    #[test]
    fn new_idempotency_key_is_random_per_call_and_fits_the_worker_pattern() {
        let qub_id = "ab".repeat(32);
        let first = new_idempotency_key(&qub_id).unwrap();
        let second = new_idempotency_key(&qub_id).unwrap();
        assert_ne!(first, second, "one qub id must not give one key");
        for key in [&first, &second] {
            assert_eq!(key.len(), 4 + 64 + 1 + OPERATION_NONCE_LEN * 2, "{key}");
            assert!(matches_worker_idempotency_key_pattern(key), "{key}");
            assert_eq!(idempotency_key_qub_id(key), Some(qub_id.as_str()), "{key}");
            assert!(
                key.starts_with(&format!("qub-{qub_id}-")),
                "the qub id stays readable in the key: {key}"
            );
        }
        // The check above can fail: the pattern refuses what the Worker would.
        assert!(!matches_worker_idempotency_key_pattern(""));
        assert!(!matches_worker_idempotency_key_pattern("qub:colon"));
        assert!(!matches_worker_idempotency_key_pattern(&"a".repeat(256)));
    }

    /// Both formats this binary has written are recognised; nothing else is.
    #[test]
    fn idempotency_key_parser_accepts_exactly_the_two_written_formats() {
        let qub_id = "0123456789abcdef".repeat(4);
        let nonce = "fedcba9876543210".repeat(2);
        assert_eq!(
            idempotency_key_qub_id(&format!("qub-{qub_id}-{nonce}")),
            Some(qub_id.as_str())
        );
        assert_eq!(
            idempotency_key_qub_id(&format!("qub-{qub_id}")),
            Some(qub_id.as_str()),
            "a key journaled before the random component existed"
        );
        let rejected = [
            String::new(),
            "qub-".to_string(),
            qub_id.clone(),
            format!("QUB-{qub_id}"),
            format!("qub-{}", &qub_id[..63]),
            format!("qub-{qub_id}0"),
            format!("qub-{}", qub_id.to_uppercase()),
            // a nonce that is absent, short, long, not hex, or not alone
            format!("qub-{qub_id}-"),
            format!("qub-{qub_id}-{}", &nonce[..31]),
            format!("qub-{qub_id}-{nonce}0"),
            format!("qub-{qub_id}-{}", nonce.to_uppercase()),
            format!("qub-{qub_id}-{nonce}-{nonce}"),
            format!("qub-{qub_id}_{nonce}"),
        ];
        for key in &rejected {
            assert_eq!(idempotency_key_qub_id(key), None, "{key:?}");
        }
    }

    /// A record journaled with the previous key format (`qub-<qub_id>`)
    /// still loads and salvages — and in either format the key must name
    /// the record's own qub.
    #[test]
    fn record_with_the_previous_key_format_still_loads() {
        let mut legacy = record("legacy-key-op", OperationState::Sent, 1);
        legacy.idempotency_key = format!("qub-{}", legacy.qub_id_hex);
        let bytes = serde_json::to_vec_pretty(&legacy).unwrap();
        let loaded = parse_record(&bytes, Some("legacy-key-op")).unwrap();
        assert_eq!(loaded.idempotency_key, legacy.idempotency_key);
        assert_eq!(
            salvage(&bytes[..bytes.len() - 20])
                .idempotency_key
                .as_deref(),
            Some(legacy.idempotency_key.as_str()),
            "raw-byte salvage of a truncated legacy record"
        );

        let other_qub = "cd".repeat(32);
        for mismatched in [
            format!("qub-{other_qub}"),
            format!("qub-{other_qub}-{}", "9".repeat(32)),
            "not-a-qub-key".to_string(),
        ] {
            let mut bad = record("legacy-key-op", OperationState::Sent, 1);
            bad.idempotency_key = mismatched;
            let bytes = serde_json::to_vec(&bad).unwrap();
            assert!(
                matches!(
                    parse_record(&bytes, Some("legacy-key-op")),
                    Err(LoadError::Corrupt { .. })
                ),
                "{}",
                bad.idempotency_key
            );
        }
    }

    /// The upload body is written last, so a record cut short anywhere in
    /// it — by far the most likely place — still yields its key, its
    /// `Idempotency-Key` and its state.
    #[test]
    fn a_record_truncated_inside_its_upload_body_keeps_key_and_state() {
        let record = record("torn-op", OperationState::Sent, 1);
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        let body_at = text.find("\"upload_body\"").unwrap();
        for field in [
            "wrapper_key_b64url",
            "idempotency_key",
            "request_digest",
            "state",
        ] {
            let at = text.find(&format!("\"{field}\"")).unwrap();
            assert!(at < body_at, "{field} must be written before upload_body");
        }
        let torn = &bytes[..body_at + "\"upload_body\": {".len()];
        assert!(serde_json::from_slice::<serde_json::Value>(torn).is_err());
        let salvaged = salvage(torn);
        assert!(salvaged.wrapper_key_b64url.is_some(), "the key survives");
        assert_eq!(
            salvaged.idempotency_key.as_deref(),
            Some(record.idempotency_key.as_str())
        );
        assert_eq!(salvaged.state, Some(OperationState::Sent));
    }

    /// The lifecycle state is salvaged when it survives, and reported as
    /// unknown — never guessed — when the tail that holds it is gone.
    #[test]
    fn salvage_reads_the_state_only_when_it_is_intact() {
        for state in [
            OperationState::Prepared,
            OperationState::Sent,
            OperationState::Completed,
        ] {
            assert_eq!(OperationState::from_wire(state.as_str()), Some(state));
            let mut value = serde_json::to_value(record("state-op", state, 1)).unwrap();
            // Well-formed JSON that is not a loadable record.
            value["version"] = serde_json::json!(0);
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            assert!(matches!(
                parse_record(&bytes, Some("state-op")),
                Err(LoadError::Corrupt { .. })
            ));
            assert_eq!(salvage(&bytes).state, Some(state));
        }
        assert_eq!(OperationState::from_wire("published"), None);

        let bytes =
            serde_json::to_vec_pretty(&record("state-op", OperationState::Prepared, 1)).unwrap();
        let at = bytes
            .windows(7)
            .position(|w| w == b"\"state\"")
            .expect("the record has a state member");
        assert_eq!(
            salvage(&bytes[..at + 12]).state,
            None,
            "cut inside the state value"
        );
        assert_eq!(salvage(&bytes[..at]).state, None, "cut before the state");
    }

    /// A record cut off in its tail is not JSON any more, but the wrapper
    /// key and the idempotency key sit before the cut: they must be
    /// salvaged from the raw bytes, not written off with the document.
    #[test]
    fn truncated_record_still_yields_its_keys() {
        let mut full = record("cut-short", OperationState::Sent, 1);
        full.wrapper_key_b64url = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE".to_string();
        let bytes = serde_json::to_vec_pretty(&full).unwrap();
        let cut = &bytes[..bytes.len() - 20];
        assert!(matches!(
            parse_record(cut, Some("cut-short")),
            Err(LoadError::Corrupt { .. })
        ));
        let salvaged = salvage(cut);
        assert_eq!(
            salvaged.wrapper_key_b64url.as_deref(),
            Some(full.wrapper_key_b64url.as_str())
        );
        assert_eq!(
            salvaged.idempotency_key.as_deref(),
            Some(full.idempotency_key.as_str())
        );
        assert_eq!(
            salvaged.request_digest.as_deref(),
            Some(full.request_digest.as_str())
        );
    }

    /// A key that is itself cut, damaged or absent is LOST — never
    /// reported as a shorter or different key.
    #[test]
    fn salvage_reports_a_damaged_key_as_lost() {
        let key = "A".repeat(43);
        let idem = format!("qub-{}", "0".repeat(64));
        let intact =
            format!("{{\"idempotency_key\": \"{idem}\",\n \"wrapper_key_b64url\" : \"{key}\", tru");
        let salvaged = salvage(intact.as_bytes());
        assert_eq!(salvaged.wrapper_key_b64url.as_deref(), Some(key.as_str()));
        assert_eq!(salvaged.idempotency_key.as_deref(), Some(idem.as_str()));

        let lost = [
            // cut inside the key: no closing quote
            format!("{{\"wrapper_key_b64url\": \"{}", &key[..30]),
            // closed, but too short / too long
            format!("{{\"wrapper_key_b64url\": \"{}\", tru", &key[..42]),
            format!("{{\"wrapper_key_b64url\": \"{key}A\", tru"),
            // not base64url
            format!("{{\"wrapper_key_b64url\": \"{}+\", tru", &key[..42]),
            // not a string member
            "{\"wrapper_key_b64url\": null, tru".to_string(),
            // absent
            "{\"version\": 1, tru".to_string(),
        ];
        for bytes in &lost {
            assert!(
                salvage(bytes.as_bytes()).wrapper_key_b64url.is_none(),
                "must be lost: {bytes}"
            );
        }

        let upper = format!("qub-{}", "G".repeat(64));
        let short_nonce = format!("{idem}-{}", "0".repeat(31));
        for bad_idem in [
            "qub-short",
            "QUB-0000",
            upper.as_str(),
            short_nonce.as_str(),
        ] {
            let bytes = format!("{{\"idempotency_key\": \"{bad_idem}\", tru");
            assert!(salvage(bytes.as_bytes()).idempotency_key.is_none());
        }
    }

    #[test]
    fn quarantine_files_belong_to_exactly_one_operation() {
        assert!(is_quarantine_of("op-12345.json.corrupt", "op-12345"));
        assert!(is_quarantine_of("op-12345.json.1.corrupt", "op-12345"));
        assert!(is_quarantine_of("op-12345.json.27.corrupt", "op-12345"));
        for other in [
            "op-12345.json",
            "op-123456.json.corrupt",
            "xop-12345.json.corrupt",
            "op-12345.json..corrupt",
            "op-12345.json.x.corrupt",
            "op-12345.json.corrupt.bak",
        ] {
            assert!(!is_quarantine_of(other, "op-12345"), "{other}");
        }
    }

    #[test]
    fn quarantined_records_are_found_with_their_salvage() {
        let tmp = TempDir::new();
        let state = StateDir::open(&tmp.0).unwrap();
        assert!(
            state
                .quarantined_records("quarantine-a")
                .unwrap()
                .is_empty()
        );

        let full = record("quarantine-a", OperationState::Sent, 1);
        let bytes = serde_json::to_vec_pretty(&full).unwrap();
        fs::write(
            state.record_path("quarantine-a"),
            &bytes[..bytes.len() - 20],
        )
        .unwrap();
        let first = state.quarantine("quarantine-a").unwrap();
        fs::write(state.record_path("quarantine-a"), b"{nothing left").unwrap();
        let second = state.quarantine("quarantine-a").unwrap();
        fs::write(state.record_path("quarantine-b"), b"{other op").unwrap();
        state.quarantine("quarantine-b").unwrap();

        let found = state.quarantined_records("quarantine-a").unwrap();
        assert_eq!(found.len(), 2, "only this operation's files");
        assert_eq!(found[0].path, second, "sorted by file name");
        assert_eq!(found[1].path, first);
        assert!(found[0].salvage.wrapper_key_b64url.is_none());
        assert!(found[0].salvage.idempotency_key.is_none());
        assert_eq!(
            found[1].salvage.wrapper_key_b64url.as_deref(),
            Some(full.wrapper_key_b64url.as_str())
        );
        assert_eq!(
            found[1].salvage.idempotency_key.as_deref(),
            Some(full.idempotency_key.as_str())
        );
        assert!(
            found[1].reason.contains("not valid JSON"),
            "{}",
            found[1].reason
        );
    }

    /// A quarantined record's qub id is still taken: a re-publication
    /// sealed in the same second must not inherit its `Idempotency-Key`.
    #[test]
    fn qub_id_in_use_sees_quarantined_and_unreadable_records() {
        let tmp = TempDir::new();
        let state = StateDir::open(&tmp.0).unwrap();
        let qub_id = "ab".repeat(32);
        assert!(!state.qub_id_in_use(&qub_id).unwrap());

        let bytes =
            serde_json::to_vec_pretty(&record("in-use-op", OperationState::Sent, 1)).unwrap();
        fs::write(state.record_path("in-use-op"), &bytes[..bytes.len() - 20]).unwrap();
        assert!(state.qub_id_in_use(&qub_id).unwrap(), "unreadable record");
        state.quarantine("in-use-op").unwrap();
        assert!(state.qub_id_in_use(&qub_id).unwrap(), "quarantined record");
        assert!(!state.qub_id_in_use(&"cd".repeat(32)).unwrap());
    }

    /// Records written before `scope_id` existed still load.
    #[test]
    fn record_without_scope_id_loads_with_none() {
        let mut value =
            serde_json::to_value(record("no-scope-op", OperationState::Sent, 1)).unwrap();
        value.as_object_mut().unwrap().remove("scope_id");
        let bytes = serde_json::to_vec(&value).unwrap();
        let loaded = parse_record(&bytes, Some("no-scope-op")).unwrap();
        assert_eq!(loaded.scope_id, None);
    }

    #[test]
    fn newer_version_is_not_treated_as_corrupt() {
        let mut value = serde_json::to_value(record("future-op", OperationState::Sent, 1)).unwrap();
        value["version"] = serde_json::json!(MAX_RECORD_VERSION + 1);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            parse_record(&bytes, Some("future-op")),
            Err(LoadError::NewerVersion(version)) if version == MAX_RECORD_VERSION + 1
        ));
        // The highest version this binary reads is not "newer".
        value["version"] = serde_json::json!(MAX_RECORD_VERSION);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(!matches!(
            parse_record(&bytes, Some("future-op")),
            Err(LoadError::NewerVersion(_))
        ));
    }

    /// A public operation's record: version 2, no key.
    fn public_record(id: &str) -> OperationRecord {
        OperationRecord {
            version: PUBLIC_RECORD_VERSION,
            visibility: Visibility::Public,
            wrapper_key_b64url: String::new(),
            ..record(id, OperationState::Sent, 1)
        }
    }

    #[test]
    fn public_records_round_trip_without_a_key() {
        let original = public_record("public-op");
        let bytes = serde_json::to_vec(&original).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("\"visibility\":\"public\""), "{text}");
        let parsed = parse_record(&bytes, Some("public-op")).expect("public record loads");
        assert_eq!(parsed.visibility, Visibility::Public);
        assert_eq!(parsed.version, PUBLIC_RECORD_VERSION);
        assert_eq!(parsed.wrapper_key_b64url, "");
        assert!(format!("{parsed:?}").contains("Public"));
    }

    /// A private record is byte-for-byte what it was before public mode
    /// existed: no `visibility` member, version 1. An older `qub-mcp` can
    /// still resume it.
    #[test]
    fn private_records_are_unchanged_on_disk() {
        let private = record("private-op", OperationState::Sent, 1);
        let value = serde_json::to_value(&private).unwrap();
        assert!(value.get("visibility").is_none());
        assert_eq!(value["version"], RECORD_VERSION);
        // A record written before the field existed loads as private.
        let parsed = parse_record(&serde_json::to_vec(&value).unwrap(), Some("private-op"))
            .expect("legacy record loads");
        assert_eq!(parsed.visibility, Visibility::Private);
    }

    /// Version and visibility must agree, and a public record must not
    /// carry a key: each mismatch is a corrupt record, never a guess.
    #[test]
    fn records_whose_version_and_visibility_disagree_are_corrupt() {
        let corrupt = |value: Value, id: &str| {
            matches!(
                parse_record(&serde_json::to_vec(&value).unwrap(), Some(id)),
                Err(LoadError::Corrupt { .. })
            )
        };
        let public = serde_json::to_value(public_record("op-public")).unwrap();
        assert!(!corrupt(public.clone(), "op-public"));

        let mut public_v1 = public.clone();
        public_v1["version"] = serde_json::json!(RECORD_VERSION);
        assert!(corrupt(public_v1, "op-public"));

        let mut public_with_key = public;
        public_with_key["wrapper_key_b64url"] = serde_json::json!("A".repeat(43));
        assert!(corrupt(public_with_key, "op-public"));

        let private = serde_json::to_value(record("op-private", OperationState::Sent, 1)).unwrap();
        assert!(!corrupt(private.clone(), "op-private"));
        let mut private_v2 = private.clone();
        private_v2["version"] = serde_json::json!(PUBLIC_RECORD_VERSION);
        assert!(corrupt(private_v2, "op-private"));
        let mut private_keyless = private;
        private_keyless["wrapper_key_b64url"] = serde_json::json!("");
        assert!(corrupt(private_keyless, "op-private"));
    }

    /// `SHA3-256` over the length-prefixed fields, computed with Python's
    /// `hashlib` rather than this crate: `domain, key = [7; 32], "body",
    /// 100 (8-byte big-endian), "letter", "al"`.
    const PRIVATE_ID_KNOWN_ANSWER: &str =
        "2d137b211c05e820361ea3e9766af31fffa52adb7dd641fee89c681e3a5b8833";
    /// The same fields followed by `"visibility:public"`.
    const PUBLIC_ID_KNOWN_ANSWER: &str =
        "df81037fa5055b01e0e635b2185ad20ab1ddebf9954be07732cd9ff46d2dde55";

    /// The same body requested publicly and privately are different
    /// operations; a private request's id is exactly what it was before
    /// the visibility input existed (known answer computed independently).
    #[test]
    fn operation_id_separates_public_from_private() {
        let key = [7u8; OPERATION_KEY_LEN];
        let private = operation_id_for(
            &key,
            "body",
            100,
            Some("letter"),
            Some("al"),
            Visibility::Private,
        );
        let public = operation_id_for(
            &key,
            "body",
            100,
            Some("letter"),
            Some("al"),
            Visibility::Public,
        );
        assert_ne!(private, public);
        assert_eq!(private, PRIVATE_ID_KNOWN_ANSWER);
        assert_eq!(public, PUBLIC_ID_KNOWN_ANSWER);
    }

    #[test]
    fn salvage_reads_public_visibility_from_whole_and_truncated_records() {
        let bytes = serde_json::to_vec(&public_record("public-op")).unwrap();
        let whole = salvage(&bytes);
        assert!(whole.public);
        assert!(whole.wrapper_key_b64url.is_none());
        assert!(whole.idempotency_key.is_some());
        // Cut inside the upload body: no longer JSON, visibility still read.
        let cut = bytes.len() - 5;
        assert!(serde_json::from_slice::<Value>(&bytes[..cut]).is_err());
        assert!(salvage(&bytes[..cut]).public);
        // A private record, and one cut before the member, are not public.
        let private = serde_json::to_vec(&record("p", OperationState::Sent, 1)).unwrap();
        assert!(!salvage(&private).public);
        assert!(!salvage(&bytes[..12]).public);
    }

    #[test]
    fn visibility_wire_names() {
        assert_eq!(Visibility::Private.as_str(), "private");
        assert_eq!(Visibility::Public.as_str(), "public");
        assert_eq!(Visibility::default(), Visibility::Private);
    }
}
