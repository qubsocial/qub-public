//! Transparency-log wire types (PROTOCOL.md §16).
//!
//! The transparency log is a strictly-additive sidecar: it commits to existing
//! `SealedQub` bytes and identities without changing the `SealedQub` /
//! `QubEnvelope` wire format and without a protocol-version bump (§16.12). This
//! module defines its hand-written canonical-CBOR types — never `serde`, like
//! the rest of the wire format — so the Rust core and the TypeScript Worker /
//! `LogDO` agree byte-for-byte:
//!
//! - [`LogLeaf`] — the two committed leaf shapes (`kind=0x01` attested /
//!   `kind=0x02` asserted, §16.2). Its [`LogLeaf::leaf_hash`] feeds the
//!   [`crate::merkle`] tree.
//! - [`SignedTreeHead`] — the tree head an Arweave anchor commits (§16.6).
//! - [`AnchorBundle`] — the self-contained Arweave anchor body (§16.7).
//! - [`InclusionProof`] / [`ConsistencyProof`] — RFC 9162 proofs served by the
//!   Worker and consumed by the standalone verifier (§16.9).
//! - [`LogProfile`] — the pinned trust root (`anchor_owner` + receipt key),
//!   baked in like [`crate::tlock`]'s quicknet constants (§16.6).
//!
//! Hash domain separation (§16.3): leaf `0x00` and node `0x01` live in
//! [`crate::merkle`]; this module uses `0x03` for the Signed-Tree-Head hash.
//! `0x02` is reserved for the `LogDO`'s internal, never-published entry chain.

use ciborium::Value;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use crate::cbor::{
    CborError, ParsedMap, assert_canonical_key_order, encode_map, extract_bytes_bounded,
    extract_fixed_bytes, extract_i64, extract_optional_fixed_bytes, extract_optional_i64,
    extract_optional_u64, extract_text, extract_u8, extract_u64, i64_value, parse_top_level_map,
    parsed_map_from_entries, reject_structural_elements_in_map, reject_unknown_keys, text, to_nfc,
    u8_value, u64_value,
};
use crate::merkle;

// -----------------------------------------------------------------------------
// Version + kind + domain constants
// -----------------------------------------------------------------------------

/// Transparency-log format version (`LogLeaf` family). Independent of the
/// protocol version (§16.12), mirroring the wrapper-version independence.
pub const LOG_VERSION_1: u8 = 1;

/// Anchor (`AnchorBundle`) format version (§16.7).
pub const ANCHOR_FORMAT_1: u8 = 1;

/// [`InclusionProof`] / [`ConsistencyProof`] wire `ver` value (§16.9).
pub const PROOF_VERSION_1: u8 = 1;

/// `kind=0x01` — attested leaf (server-seal path; commits `body_hash` +
/// `drand_round` because the Worker derived them from plaintext).
pub const LEAF_KIND_ATTESTED: u8 = 0x01;

/// `kind=0x02` — asserted leaf (byte-blind upload path; commits neither
/// `body_hash` nor `drand_round` — the Worker never held them, §16.2).
pub const LEAF_KIND_ASSERTED: u8 = 0x02;

/// Domain prefix for the Signed-Tree-Head hash (§16.6).
///
/// `sth_hash = SHA3-256(0x03 || canonical_cbor(SignedTreeHead))`. Disjoint from
/// the merkle leaf/node prefixes (`0x00`/`0x01`) and the entry-chain prefix
/// (`0x02`).
pub const STH_HASH_PREFIX: u8 = 0x03;

/// Domain string for `log_id = SHA3-256("QUB_TLOG_V1" || anchor_owner)` (§16.6).
const LOG_ID_DOMAIN: &[u8] = b"QUB_TLOG_V1";

// Decode-bomb bounds for variable-length fields.
const MAX_LEAF_CBOR_SIZE: usize = 512; // a leaf is < ~200 bytes in practice
const MAX_STH_CBOR_SIZE: usize = 1024;
const MAX_PROOF_NODES: usize = 64; // a u64-sized tree has ≤ 64 levels
const MAX_ANCHOR_LEAVES: usize = 65_536; // generous vs LOG_BATCH_MAX_LEAVES (4096)
const MAX_CHAIN_HASH_LEN: usize = 128; // drand chain hash hex is 64 chars

// -----------------------------------------------------------------------------
// Canonical key tables (§3.1 order: encoded byte length asc, then bytewise)
// -----------------------------------------------------------------------------

/// `LogLeaf` keys. `ref`/`seq` are 4 bytes (`r`<`s`); `kind` 5; `chash` 6;
/// `body_hash`/`unlock_at` 10 (`b`<`u`); `drand_round`/`received_at` 12
/// (`d`<`r`). `body_hash`/`drand_round` present only on `kind=0x01`.
const LEAF_KEYS_CANONICAL: &[&str] = &[
    "ref",
    "seq",
    "kind",
    "chash",
    "body_hash",
    "unlock_at",
    "drand_round",
    "received_at",
];

/// `SignedTreeHead` keys: `prev`/`root`/`size` 5 (`p`<`r`<`s`); `batch` 6;
/// `log_id` 7; `first_seq` 10; `anchored_at` 12.
const STH_KEYS_CANONICAL: &[&str] = &[
    "prev",
    "root",
    "size",
    "batch",
    "log_id",
    "first_seq",
    "anchored_at",
];

/// `AnchorBundle` keys: `sth`/`ver` 4 (`s`<`v`); `leaves` 7; `chain_hash` 11;
/// `prev_anchor` 12 (optional — omitted at genesis).
const ANCHOR_KEYS_CANONICAL: &[&str] = &["sth", "ver", "leaves", "chain_hash", "prev_anchor"];

/// `InclusionProof` keys: `ver` 4; `leaf`/`root`/`size` 5 (`l`<`r`<`s`);
/// `audit`/`index` 6 (`a`<`i`); `anchor` 7.
const INCLUSION_KEYS_CANONICAL: &[&str] =
    &["ver", "leaf", "root", "size", "audit", "index", "anchor"];

/// `AnchorRef` (inclusion/consistency anchor sub-map) keys: `sth` 4; `txid` 5;
/// `batch` 6; `log_id` 7; `anchored_at` 12; `block_height` 13. The last two
/// are optional.
const ANCHOR_REF_KEYS_CANONICAL: &[&str] = &[
    "sth",
    "txid",
    "batch",
    "log_id",
    "anchored_at",
    "block_height",
];

/// `ConsistencyProof` keys: `ver` 4; `nodes` 6; `first_root`/`first_size` 11
/// (`r`<`s`); `second_root`/`second_size` 12; `first_anchor` 13;
/// `second_anchor` 14.
const CONSISTENCY_KEYS_CANONICAL: &[&str] = &[
    "ver",
    "nodes",
    "first_root",
    "first_size",
    "second_root",
    "second_size",
    "first_anchor",
    "second_anchor",
];

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors produced by transparency-log type encode / decode.
///
/// `#[non_exhaustive]`: match arms must include a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LogError {
    /// Canonical CBOR encoding / decoding failed.
    #[error("log CBOR error: {0}")]
    Cbor(#[from] CborError),

    /// The leaf `kind` byte is neither `0x01` nor `0x02`.
    #[error("unknown log leaf kind: {0:#04x}")]
    UnknownKind(u8),

    /// A field that must be present for the leaf's `kind` was absent, or a
    /// field that must be absent was present (§16.2).
    #[error("leaf field presence does not match kind {kind:#04x}: {detail}")]
    KindFieldMismatch {
        /// The offending leaf kind.
        kind: u8,
        /// What was wrong.
        detail: &'static str,
    },

    /// A 32-byte reference / content-address was all zeros (rejected by the
    /// §16.2 encoder discipline).
    #[error("{0} must not be all zeros")]
    ZeroDigest(&'static str),

    /// A timestamp field was not strictly positive (§16.2 encoder discipline).
    #[error("{0} must be a positive Unix timestamp")]
    NonPositiveTimestamp(&'static str),

    /// A version byte was not a supported value.
    #[error("unsupported log version: {0}")]
    UnsupportedVersion(u8),

    /// A CBOR value did not have the expected shape (array / map).
    #[error("unexpected CBOR shape for {field}: expected {expected}")]
    UnexpectedShape {
        /// Field name.
        field: &'static str,
        /// Expected shape.
        expected: &'static str,
    },

    /// A required field was missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A digest in a hash array (or fixed field) had the wrong length.
    #[error("wrong digest length for {0}: expected 32")]
    WrongDigestLength(&'static str),

    /// A variable-length collection exceeded its decode bound.
    #[error("{field} too large: {len} > {max}")]
    TooLarge {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// -----------------------------------------------------------------------------
// Local decode helpers (array of digests, array of byte strings, nested map)
// -----------------------------------------------------------------------------

fn find_value<'a>(map: &'a ParsedMap, key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Decode a required array of fixed 32-byte digests, bounding the count.
fn extract_digest_array(
    map: &ParsedMap,
    key: &'static str,
    max_len: usize,
) -> Result<Vec<[u8; 32]>, LogError> {
    match find_value(map, key) {
        Some(Value::Array(items)) => {
            if items.len() > max_len {
                return Err(LogError::TooLarge {
                    field: key,
                    len: items.len(),
                    max: max_len,
                });
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Value::Bytes(b) = item else {
                    return Err(LogError::UnexpectedShape {
                        field: key,
                        expected: "array of byte strings",
                    });
                };
                let arr: [u8; 32] = b
                    .as_slice()
                    .try_into()
                    .map_err(|_| LogError::WrongDigestLength(key))?;
                out.push(arr);
            }
            Ok(out)
        },
        Some(_) => Err(LogError::UnexpectedShape {
            field: key,
            expected: "array",
        }),
        None => Err(LogError::MissingField(key)),
    }
}

/// Decode a required array of variable-length byte strings, bounding both the
/// element count and each element's size.
fn extract_bytes_array(
    map: &ParsedMap,
    key: &'static str,
    max_len: usize,
    max_each: usize,
) -> Result<Vec<Vec<u8>>, LogError> {
    match find_value(map, key) {
        Some(Value::Array(items)) => {
            if items.len() > max_len {
                return Err(LogError::TooLarge {
                    field: key,
                    len: items.len(),
                    max: max_len,
                });
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Value::Bytes(b) = item else {
                    return Err(LogError::UnexpectedShape {
                        field: key,
                        expected: "array of byte strings",
                    });
                };
                if b.len() > max_each {
                    return Err(LogError::TooLarge {
                        field: key,
                        len: b.len(),
                        max: max_each,
                    });
                }
                out.push(b.clone());
            }
            Ok(out)
        },
        Some(_) => Err(LogError::UnexpectedShape {
            field: key,
            expected: "array",
        }),
        None => Err(LogError::MissingField(key)),
    }
}

/// Decode a required nested CBOR map, applying the same key discipline
/// (text keys, NFC, no duplicates) the top-level parser applies.
fn extract_nested_map(map: &ParsedMap, key: &'static str) -> Result<ParsedMap, LogError> {
    match find_value(map, key) {
        Some(Value::Map(entries)) => Ok(parsed_map_from_entries(entries)?),
        Some(_) => Err(LogError::UnexpectedShape {
            field: key,
            expected: "map",
        }),
        None => Err(LogError::MissingField(key)),
    }
}

fn digest_array_value(digests: &[[u8; 32]]) -> Value {
    Value::Array(digests.iter().map(|h| Value::Bytes(h.to_vec())).collect())
}

// -----------------------------------------------------------------------------
// LogProfile — pinned trust root (§16.6)
// -----------------------------------------------------------------------------

/// Placeholder `anchor_owner` (Arweave address — SHA-256 of the owner modulus).
///
/// **Replaced when the dedicated anchor wallet is provisioned**; swapping it is
/// a signed `LogProfile` bump shipped in a verifier update (§16.6 rotation).
const PLACEHOLDER_ANCHOR_OWNER: [u8; 32] = [0xAB; 32];

/// Placeholder receipt public key (RSA, opaque to qub-core — interpreted by the
/// standalone verifier). Empty until the receipt key is provisioned.
const PLACEHOLDER_RECEIPT_PUBKEY: &[u8] = &[];

/// The pinned transparency-log trust root (§16.6).
///
/// Holds the `anchor_owner` Arweave address a conforming verifier requires
/// (`anchor_tx.owner == anchor_owner`) and the pinned, cross-signed receipt
/// public key. Baked into the binary like the quicknet drand constants so the
/// verifier has no external trust input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogProfile {
    anchor_owner: [u8; 32],
    receipt_pubkey: Vec<u8>,
}

impl LogProfile {
    /// Construct a profile from explicit constants (used by tests and by a
    /// future rotation; production callers use [`LogProfile::qub`]).
    #[must_use]
    pub const fn new(anchor_owner: [u8; 32], receipt_pubkey: Vec<u8>) -> Self {
        Self {
            anchor_owner,
            receipt_pubkey,
        }
    }

    /// The pinned production profile.
    ///
    /// The constants are **placeholders** until the dedicated anchor wallet and
    /// receipt key are provisioned (`PLACEHOLDER_ANCHOR_OWNER`).
    #[must_use]
    pub fn qub() -> Self {
        Self::new(
            PLACEHOLDER_ANCHOR_OWNER,
            PLACEHOLDER_RECEIPT_PUBKEY.to_vec(),
        )
    }

    /// The pinned anchor-owner Arweave address (32-byte SHA-256 of the owner
    /// modulus). A conforming verifier requires `anchor_tx.owner` to hash to
    /// this value.
    #[must_use]
    pub const fn anchor_owner(&self) -> &[u8; 32] {
        &self.anchor_owner
    }

    /// Whether `anchor_owner` is still the build-time **placeholder** rather
    /// than a provisioned anchor wallet's address (§16.6).
    ///
    /// Real end-to-end anchor verification is **deploy-gated** until the
    /// dedicated anchor wallet is provisioned: while this returns `true`, a
    /// verifier cannot meaningfully enforce `anchor_tx.owner == anchor_owner`
    /// (no real wallet hashes to the placeholder), so the owner-pin check is
    /// reported as informational rather than treated as a hard failure. Once
    /// the wallet is provisioned (a signed `LogProfile` bump shipped in a
    /// verifier update), this returns `false` and the owner pin becomes
    /// enforcing.
    #[must_use]
    pub fn is_anchor_owner_placeholder(&self) -> bool {
        self.anchor_owner == PLACEHOLDER_ANCHOR_OWNER
    }

    /// The pinned receipt public key (RSA), opaque to qub-core.
    #[must_use]
    pub fn receipt_pubkey(&self) -> &[u8] {
        &self.receipt_pubkey
    }

    /// `log_id = SHA3-256("QUB_TLOG_V1" || anchor_owner)` (§16.6).
    #[must_use]
    pub fn log_id(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(LOG_ID_DOMAIN);
        hasher.update(self.anchor_owner);
        hasher.finalize().into()
    }
}

// -----------------------------------------------------------------------------
// LogLeaf (§16.2)
// -----------------------------------------------------------------------------

/// A transparency-log leaf in one of its two committed shapes (§16.2).
///
/// `kind=0x01` (attested) additionally commits `body_hash` + `drand_round`;
/// `kind=0x02` (asserted, the byte-blind default) commits neither. The encoder
/// rejects an all-zero `reference`/`chash` and non-positive timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLeaf {
    seq: u64,
    kind: u8,
    /// CBOR key `ref` (a Rust keyword, so the field is `reference`).
    reference: [u8; 32],
    chash: [u8; 32],
    unlock_at: i64,
    received_at: i64,
    body_hash: Option<[u8; 32]>,
    drand_round: Option<u64>,
}

impl LogLeaf {
    /// Build an **asserted** (`kind=0x02`) leaf — the byte-blind upload path.
    ///
    /// `reference` is the blinded id (`SHA3-256(qub_id || log_blind_secret)`)
    /// for private qubs or the raw `qub_id` for public ones; `chash` is the
    /// content address `SHA3-256(stored_bytes)`.
    ///
    /// # Errors
    ///
    /// [`LogError::ZeroDigest`] for an all-zero `reference`/`chash`;
    /// [`LogError::NonPositiveTimestamp`] for `unlock_at`/`received_at` ≤ 0.
    pub fn asserted(
        seq: u64,
        reference: [u8; 32],
        chash: [u8; 32],
        unlock_at: i64,
        received_at: i64,
    ) -> Result<Self, LogError> {
        let leaf = Self {
            seq,
            kind: LEAF_KIND_ASSERTED,
            reference,
            chash,
            unlock_at,
            received_at,
            body_hash: None,
            drand_round: None,
        };
        leaf.validate()?;
        Ok(leaf)
    }

    /// Build an **attested** (`kind=0x01`) leaf — the server-seal path, which
    /// derived `body_hash` + `drand_round` from plaintext.
    ///
    /// # Errors
    ///
    /// As [`LogLeaf::asserted`].
    pub fn attested(
        seq: u64,
        reference: [u8; 32],
        chash: [u8; 32],
        unlock_at: i64,
        received_at: i64,
        body_hash: [u8; 32],
        drand_round: u64,
    ) -> Result<Self, LogError> {
        let leaf = Self {
            seq,
            kind: LEAF_KIND_ATTESTED,
            reference,
            chash,
            unlock_at,
            received_at,
            body_hash: Some(body_hash),
            drand_round: Some(drand_round),
        };
        leaf.validate()?;
        Ok(leaf)
    }

    fn validate(&self) -> Result<(), LogError> {
        if self.reference == [0u8; 32] {
            return Err(LogError::ZeroDigest("ref"));
        }
        if self.chash == [0u8; 32] {
            return Err(LogError::ZeroDigest("chash"));
        }
        if self.unlock_at <= 0 {
            return Err(LogError::NonPositiveTimestamp("unlock_at"));
        }
        if self.received_at <= 0 {
            return Err(LogError::NonPositiveTimestamp("received_at"));
        }
        match self.kind {
            LEAF_KIND_ATTESTED => {
                if self.body_hash.is_none() || self.drand_round.is_none() {
                    return Err(LogError::KindFieldMismatch {
                        kind: self.kind,
                        detail: "attested leaf requires body_hash and drand_round",
                    });
                }
            },
            LEAF_KIND_ASSERTED => {
                if self.body_hash.is_some() || self.drand_round.is_some() {
                    return Err(LogError::KindFieldMismatch {
                        kind: self.kind,
                        detail: "asserted leaf must omit body_hash and drand_round",
                    });
                }
            },
            other => return Err(LogError::UnknownKind(other)),
        }
        Ok(())
    }

    /// Global 0-based sequence index (the position the inclusion proof commits).
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Leaf kind byte (`0x01` attested / `0x02` asserted).
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// The leaf reference id (CBOR key `ref`).
    #[must_use]
    pub const fn reference(&self) -> &[u8; 32] {
        &self.reference
    }

    /// Content address `SHA3-256(stored_bytes)`.
    #[must_use]
    pub const fn chash(&self) -> &[u8; 32] {
        &self.chash
    }

    /// Claimed unlock timestamp.
    #[must_use]
    pub const fn unlock_at(&self) -> i64 {
        self.unlock_at
    }

    /// Worker wall-clock at R2 ack (non-evidentiary, §16.6).
    #[must_use]
    pub const fn received_at(&self) -> i64 {
        self.received_at
    }

    /// `body_hash` (present only on `kind=0x01`).
    #[must_use]
    pub const fn body_hash(&self) -> Option<&[u8; 32]> {
        self.body_hash.as_ref()
    }

    /// `drand_round` (present only on `kind=0x01`).
    #[must_use]
    pub const fn drand_round(&self) -> Option<u64> {
        self.drand_round
    }

    /// Serialise to canonical CBOR (the exact bytes a leaf hash covers).
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if the CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, LogError> {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(LEAF_KEYS_CANONICAL.len());
        let mut keys: Vec<&str> = Vec::with_capacity(LEAF_KEYS_CANONICAL.len());

        map.push((text("ref"), Value::Bytes(self.reference.to_vec())));
        keys.push("ref");
        map.push((text("seq"), u64_value(self.seq)));
        keys.push("seq");
        map.push((text("kind"), u8_value(self.kind)));
        keys.push("kind");
        map.push((text("chash"), Value::Bytes(self.chash.to_vec())));
        keys.push("chash");
        if let Some(bh) = self.body_hash {
            map.push((text("body_hash"), Value::Bytes(bh.to_vec())));
            keys.push("body_hash");
        }
        map.push((text("unlock_at"), i64_value(self.unlock_at)));
        keys.push("unlock_at");
        if let Some(round) = self.drand_round {
            map.push((text("drand_round"), u64_value(round)));
            keys.push("drand_round");
        }
        map.push((text("received_at"), i64_value(self.received_at)));
        keys.push("received_at");

        assert_canonical_key_order(&keys);
        Ok(encode_map(map)?)
    }

    /// Parse a leaf from canonical CBOR, enforcing the §16.2 discipline.
    ///
    /// # Errors
    ///
    /// A [`LogError`] for malformed / non-canonical CBOR, an unknown kind, a
    /// kind/field-presence mismatch, an all-zero digest, or a non-positive
    /// timestamp.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LogError> {
        let map = parse_top_level_map(bytes)?;
        reject_structural_elements_in_map(&map)?;
        reject_unknown_keys(&map, LEAF_KEYS_CANONICAL, "LogLeaf")?;

        let seq = extract_u64(&map, "seq")?;
        let kind = extract_u8(&map, "kind")?;
        let reference = extract_fixed_bytes::<32>(&map, "ref")?;
        let chash = extract_fixed_bytes::<32>(&map, "chash")?;
        let unlock_at = extract_i64(&map, "unlock_at")?;
        let received_at = extract_i64(&map, "received_at")?;
        let body_hash = extract_optional_fixed_bytes::<32>(&map, "body_hash")?;
        let drand_round = extract_optional_u64(&map, "drand_round")?;

        let leaf = Self {
            seq,
            kind,
            reference,
            chash,
            unlock_at,
            received_at,
            body_hash,
            drand_round,
        };
        leaf.validate()?;
        Ok(leaf)
    }

    /// The RFC 6962 leaf hash `SHA3-256(0x00 || leaf_cbor)`.
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if encoding fails.
    pub fn leaf_hash(&self) -> Result<[u8; 32], LogError> {
        Ok(merkle::leaf_hash(&self.to_cbor()?))
    }
}

// -----------------------------------------------------------------------------
// SignedTreeHead (§16.6)
// -----------------------------------------------------------------------------

/// The tree head an Arweave anchor commits (§16.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    size: u64,
    root: [u8; 32],
    batch: u64,
    prev: [u8; 32],
    log_id: [u8; 32],
    first_seq: u64,
    anchored_at: i64,
}

impl SignedTreeHead {
    /// Construct a Signed Tree Head. `prev` is the prior `sth_hash` (32 zero
    /// bytes at genesis).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        size: u64,
        root: [u8; 32],
        batch: u64,
        prev: [u8; 32],
        log_id: [u8; 32],
        first_seq: u64,
        anchored_at: i64,
    ) -> Self {
        Self {
            size,
            root,
            batch,
            prev,
            log_id,
            first_seq,
            anchored_at,
        }
    }

    /// Cumulative tree size this head commits.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Cumulative Merkle root over leaves `0 .. size`.
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Batch number.
    #[must_use]
    pub const fn batch(&self) -> u64 {
        self.batch
    }

    /// Prior `sth_hash` (32 zero bytes at genesis).
    #[must_use]
    pub const fn prev(&self) -> &[u8; 32] {
        &self.prev
    }

    /// The `log_id` this head belongs to.
    #[must_use]
    pub const fn log_id(&self) -> &[u8; 32] {
        &self.log_id
    }

    /// First `seq` in this batch.
    #[must_use]
    pub const fn first_seq(&self) -> u64 {
        self.first_seq
    }

    /// Operator-asserted anchor wall-clock (non-evidentiary, §16.6).
    #[must_use]
    pub const fn anchored_at(&self) -> i64 {
        self.anchored_at
    }

    /// Serialise to canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if the CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, LogError> {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(STH_KEYS_CANONICAL.len());
        let mut keys: Vec<&str> = Vec::with_capacity(STH_KEYS_CANONICAL.len());

        map.push((text("prev"), Value::Bytes(self.prev.to_vec())));
        keys.push("prev");
        map.push((text("root"), Value::Bytes(self.root.to_vec())));
        keys.push("root");
        map.push((text("size"), u64_value(self.size)));
        keys.push("size");
        map.push((text("batch"), u64_value(self.batch)));
        keys.push("batch");
        map.push((text("log_id"), Value::Bytes(self.log_id.to_vec())));
        keys.push("log_id");
        map.push((text("first_seq"), u64_value(self.first_seq)));
        keys.push("first_seq");
        map.push((text("anchored_at"), i64_value(self.anchored_at)));
        keys.push("anchored_at");

        assert_canonical_key_order(&keys);
        Ok(encode_map(map)?)
    }

    /// Parse from canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError`] for malformed / non-canonical CBOR or a missing field.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LogError> {
        let map = parse_top_level_map(bytes)?;
        reject_structural_elements_in_map(&map)?;
        reject_unknown_keys(&map, STH_KEYS_CANONICAL, "SignedTreeHead")?;
        Ok(Self {
            size: extract_u64(&map, "size")?,
            root: extract_fixed_bytes::<32>(&map, "root")?,
            batch: extract_u64(&map, "batch")?,
            prev: extract_fixed_bytes::<32>(&map, "prev")?,
            log_id: extract_fixed_bytes::<32>(&map, "log_id")?,
            first_seq: extract_u64(&map, "first_seq")?,
            anchored_at: extract_i64(&map, "anchored_at")?,
        })
    }

    /// `sth_hash = SHA3-256(0x03 || canonical_cbor(SignedTreeHead))` (§16.6).
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if encoding fails.
    pub fn sth_hash(&self) -> Result<[u8; 32], LogError> {
        let mut hasher = Sha3_256::new();
        hasher.update([STH_HASH_PREFIX]);
        hasher.update(self.to_cbor()?);
        Ok(hasher.finalize().into())
    }
}

// -----------------------------------------------------------------------------
// AnchorRef — the anchor sub-map carried by proofs (§16.9)
// -----------------------------------------------------------------------------

/// The anchor reference embedded in an [`InclusionProof`] / [`ConsistencyProof`]
/// (§16.9). `block_height` / `anchored_at` are optional hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRef {
    txid: [u8; 32],
    batch: u64,
    sth: [u8; 32],
    log_id: [u8; 32],
    block_height: Option<u64>,
    anchored_at: Option<i64>,
}

impl AnchorRef {
    /// Construct an anchor reference.
    #[must_use]
    pub const fn new(
        txid: [u8; 32],
        batch: u64,
        sth: [u8; 32],
        log_id: [u8; 32],
        block_height: Option<u64>,
        anchored_at: Option<i64>,
    ) -> Self {
        Self {
            txid,
            batch,
            sth,
            log_id,
            block_height,
            anchored_at,
        }
    }

    /// Arweave anchor transaction id (raw 32-byte digest).
    #[must_use]
    pub const fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    /// Batch number.
    #[must_use]
    pub const fn batch(&self) -> u64 {
        self.batch
    }

    /// `sth_hash` of the committed tree head.
    #[must_use]
    pub const fn sth(&self) -> &[u8; 32] {
        &self.sth
    }

    /// `log_id` the anchor belongs to.
    #[must_use]
    pub const fn log_id(&self) -> &[u8; 32] {
        &self.log_id
    }

    /// Optional Arweave block height.
    #[must_use]
    pub const fn block_height(&self) -> Option<u64> {
        self.block_height
    }

    /// Optional anchor wall-clock.
    #[must_use]
    pub const fn anchored_at(&self) -> Option<i64> {
        self.anchored_at
    }

    /// Build the canonical nested-map [`Value`] for embedding in a proof map.
    fn to_value(&self) -> Value {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(ANCHOR_REF_KEYS_CANONICAL.len());
        let mut keys: Vec<&str> = Vec::with_capacity(ANCHOR_REF_KEYS_CANONICAL.len());

        map.push((text("sth"), Value::Bytes(self.sth.to_vec())));
        keys.push("sth");
        map.push((text("txid"), Value::Bytes(self.txid.to_vec())));
        keys.push("txid");
        map.push((text("batch"), u64_value(self.batch)));
        keys.push("batch");
        map.push((text("log_id"), Value::Bytes(self.log_id.to_vec())));
        keys.push("log_id");
        if let Some(at) = self.anchored_at {
            map.push((text("anchored_at"), i64_value(at)));
            keys.push("anchored_at");
        }
        if let Some(h) = self.block_height {
            map.push((text("block_height"), u64_value(h)));
            keys.push("block_height");
        }

        assert_canonical_key_order(&keys);
        Value::Map(map)
    }

    /// Decode from an already-validated nested [`ParsedMap`].
    fn from_map(map: &ParsedMap) -> Result<Self, LogError> {
        reject_unknown_keys(map, ANCHOR_REF_KEYS_CANONICAL, "AnchorRef")?;
        Ok(Self {
            txid: extract_fixed_bytes::<32>(map, "txid")?,
            batch: extract_u64(map, "batch")?,
            sth: extract_fixed_bytes::<32>(map, "sth")?,
            log_id: extract_fixed_bytes::<32>(map, "log_id")?,
            block_height: extract_optional_u64(map, "block_height")?,
            anchored_at: extract_optional_i64(map, "anchored_at")?,
        })
    }
}

// -----------------------------------------------------------------------------
// InclusionProof (§16.9)
// -----------------------------------------------------------------------------

/// An RFC 9162 inclusion proof served by `GET /api/v1/qub/:tx_id/proof` (§16.9).
///
/// `leaf` carries the **exact leaf CBOR**; the verifier recomputes the leaf
/// hash itself and never trusts a supplied hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    ver: u8,
    leaf: Vec<u8>,
    index: u64,
    size: u64,
    audit: Vec<[u8; 32]>,
    root: [u8; 32],
    anchor: AnchorRef,
}

impl InclusionProof {
    /// Construct an inclusion proof at [`PROOF_VERSION_1`].
    #[must_use]
    pub const fn new(
        leaf: Vec<u8>,
        index: u64,
        size: u64,
        audit: Vec<[u8; 32]>,
        root: [u8; 32],
        anchor: AnchorRef,
    ) -> Self {
        Self {
            ver: PROOF_VERSION_1,
            leaf,
            index,
            size,
            audit,
            root,
            anchor,
        }
    }

    /// Wire version.
    #[must_use]
    pub const fn ver(&self) -> u8 {
        self.ver
    }

    /// The exact leaf CBOR.
    #[must_use]
    pub fn leaf(&self) -> &[u8] {
        &self.leaf
    }

    /// Leaf index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Tree size the proof commits to.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Audit path (bottom-first sibling hashes).
    #[must_use]
    pub fn audit(&self) -> &[[u8; 32]] {
        &self.audit
    }

    /// Claimed Merkle root.
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Embedded anchor reference.
    #[must_use]
    pub const fn anchor(&self) -> &AnchorRef {
        &self.anchor
    }

    /// Recompute the leaf hash from `leaf`, fold the audit path, and check the
    /// derived root equals `root` (the Merkle leg of §16.9 standalone
    /// verification). Anchor authenticity (Arweave fetch + RSA-PSS) is the
    /// verifier's separate, online step.
    #[must_use]
    pub fn verify_root(&self) -> bool {
        let lh = merkle::leaf_hash(&self.leaf);
        merkle::verify_inclusion(&lh, self.index, self.size, &self.audit, &self.root)
    }

    /// Serialise to canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if the CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, LogError> {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(INCLUSION_KEYS_CANONICAL.len());
        let mut keys: Vec<&str> = Vec::with_capacity(INCLUSION_KEYS_CANONICAL.len());

        map.push((text("ver"), u8_value(self.ver)));
        keys.push("ver");
        map.push((text("leaf"), Value::Bytes(self.leaf.clone())));
        keys.push("leaf");
        map.push((text("root"), Value::Bytes(self.root.to_vec())));
        keys.push("root");
        map.push((text("size"), u64_value(self.size)));
        keys.push("size");
        map.push((text("audit"), digest_array_value(&self.audit)));
        keys.push("audit");
        map.push((text("index"), u64_value(self.index)));
        keys.push("index");
        map.push((text("anchor"), self.anchor.to_value()));
        keys.push("anchor");

        assert_canonical_key_order(&keys);
        Ok(encode_map(map)?)
    }

    /// Parse from canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError`] for malformed / non-canonical CBOR, an unsupported version,
    /// an oversized audit path, or a malformed anchor sub-map.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LogError> {
        let map = parse_top_level_map(bytes)?;
        reject_structural_elements_in_map(&map)?;

        let ver = extract_u8(&map, "ver")?;
        if ver != PROOF_VERSION_1 {
            return Err(LogError::UnsupportedVersion(ver));
        }
        reject_unknown_keys(&map, INCLUSION_KEYS_CANONICAL, "InclusionProof")?;
        let leaf = extract_bytes_bounded(&map, "leaf", MAX_LEAF_CBOR_SIZE)?;
        let root = extract_fixed_bytes::<32>(&map, "root")?;
        let size = extract_u64(&map, "size")?;
        let audit = extract_digest_array(&map, "audit", MAX_PROOF_NODES)?;
        let index = extract_u64(&map, "index")?;
        let anchor_map = extract_nested_map(&map, "anchor")?;
        let anchor = AnchorRef::from_map(&anchor_map)?;

        Ok(Self {
            ver,
            leaf,
            index,
            size,
            audit,
            root,
            anchor,
        })
    }
}

// -----------------------------------------------------------------------------
// ConsistencyProof (§16.9)
// -----------------------------------------------------------------------------

/// An RFC 9162 consistency proof served by `GET /api/v1/log/consistency` (§16.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    ver: u8,
    first_size: u64,
    second_size: u64,
    first_root: [u8; 32],
    second_root: [u8; 32],
    nodes: Vec<[u8; 32]>,
    first_anchor: AnchorRef,
    second_anchor: AnchorRef,
}

impl ConsistencyProof {
    /// Construct a consistency proof at [`PROOF_VERSION_1`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        first_size: u64,
        second_size: u64,
        first_root: [u8; 32],
        second_root: [u8; 32],
        nodes: Vec<[u8; 32]>,
        first_anchor: AnchorRef,
        second_anchor: AnchorRef,
    ) -> Self {
        Self {
            ver: PROOF_VERSION_1,
            first_size,
            second_size,
            first_root,
            second_root,
            nodes,
            first_anchor,
            second_anchor,
        }
    }

    /// Wire version.
    #[must_use]
    pub const fn ver(&self) -> u8 {
        self.ver
    }

    /// Older tree size.
    #[must_use]
    pub const fn first_size(&self) -> u64 {
        self.first_size
    }

    /// Newer tree size.
    #[must_use]
    pub const fn second_size(&self) -> u64 {
        self.second_size
    }

    /// Older root.
    #[must_use]
    pub const fn first_root(&self) -> &[u8; 32] {
        &self.first_root
    }

    /// Newer root.
    #[must_use]
    pub const fn second_root(&self) -> &[u8; 32] {
        &self.second_root
    }

    /// Consistency proof nodes.
    #[must_use]
    pub fn nodes(&self) -> &[[u8; 32]] {
        &self.nodes
    }

    /// Anchor reference for the older tree.
    #[must_use]
    pub const fn first_anchor(&self) -> &AnchorRef {
        &self.first_anchor
    }

    /// Anchor reference for the newer tree.
    #[must_use]
    pub const fn second_anchor(&self) -> &AnchorRef {
        &self.second_anchor
    }

    /// Verify the Merkle leg: that the older tree is a genuine prefix of the
    /// newer one (RFC 9162 / §16.9).
    #[must_use]
    pub fn verify(&self) -> bool {
        merkle::verify_consistency(
            self.first_size,
            self.second_size,
            &self.first_root,
            &self.second_root,
            &self.nodes,
        )
    }

    /// Serialise to canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if the CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, LogError> {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(CONSISTENCY_KEYS_CANONICAL.len());
        let mut keys: Vec<&str> = Vec::with_capacity(CONSISTENCY_KEYS_CANONICAL.len());

        map.push((text("ver"), u8_value(self.ver)));
        keys.push("ver");
        map.push((text("nodes"), digest_array_value(&self.nodes)));
        keys.push("nodes");
        map.push((text("first_root"), Value::Bytes(self.first_root.to_vec())));
        keys.push("first_root");
        map.push((text("first_size"), u64_value(self.first_size)));
        keys.push("first_size");
        map.push((text("second_root"), Value::Bytes(self.second_root.to_vec())));
        keys.push("second_root");
        map.push((text("second_size"), u64_value(self.second_size)));
        keys.push("second_size");
        map.push((text("first_anchor"), self.first_anchor.to_value()));
        keys.push("first_anchor");
        map.push((text("second_anchor"), self.second_anchor.to_value()));
        keys.push("second_anchor");

        assert_canonical_key_order(&keys);
        Ok(encode_map(map)?)
    }

    /// Parse from canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError`] for malformed / non-canonical CBOR, an unsupported version,
    /// an oversized node list, or a malformed anchor sub-map.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LogError> {
        let map = parse_top_level_map(bytes)?;
        reject_structural_elements_in_map(&map)?;

        let ver = extract_u8(&map, "ver")?;
        if ver != PROOF_VERSION_1 {
            return Err(LogError::UnsupportedVersion(ver));
        }
        reject_unknown_keys(&map, CONSISTENCY_KEYS_CANONICAL, "ConsistencyProof")?;
        let nodes = extract_digest_array(&map, "nodes", MAX_PROOF_NODES)?;
        let first_root = extract_fixed_bytes::<32>(&map, "first_root")?;
        let first_size = extract_u64(&map, "first_size")?;
        let second_root = extract_fixed_bytes::<32>(&map, "second_root")?;
        let second_size = extract_u64(&map, "second_size")?;
        let first_anchor = AnchorRef::from_map(&extract_nested_map(&map, "first_anchor")?)?;
        let second_anchor = AnchorRef::from_map(&extract_nested_map(&map, "second_anchor")?)?;

        Ok(Self {
            ver,
            first_size,
            second_size,
            first_root,
            second_root,
            nodes,
            first_anchor,
            second_anchor,
        })
    }
}

// -----------------------------------------------------------------------------
// AnchorBundle (§16.7)
// -----------------------------------------------------------------------------

/// The canonical-CBOR Arweave transaction body that **is** the Signed Tree Head
/// (§16.7).
///
/// Self-contained: it carries the batch's leaf-CBOR stream in `seq` order so a
/// monitor re-derives the root with zero qub dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBundle {
    ver: u8,
    sth: Vec<u8>,
    prev_anchor: Option<[u8; 32]>,
    chain_hash: String,
    leaves: Vec<Vec<u8>>,
}

impl AnchorBundle {
    /// Construct an anchor bundle at [`ANCHOR_FORMAT_1`]. `sth` is the canonical
    /// [`SignedTreeHead`] bytes; `prev_anchor` is the prior anchor tx id (raw
    /// 32 bytes), omitted at genesis.
    #[must_use]
    pub const fn new(
        sth: Vec<u8>,
        prev_anchor: Option<[u8; 32]>,
        chain_hash: String,
        leaves: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            ver: ANCHOR_FORMAT_1,
            sth,
            prev_anchor,
            chain_hash,
            leaves,
        }
    }

    /// Wire version.
    #[must_use]
    pub const fn ver(&self) -> u8 {
        self.ver
    }

    /// Canonical [`SignedTreeHead`] bytes.
    #[must_use]
    pub fn sth(&self) -> &[u8] {
        &self.sth
    }

    /// Prior anchor tx id (raw 32 bytes), `None` at genesis.
    #[must_use]
    pub const fn prev_anchor(&self) -> Option<&[u8; 32]> {
        self.prev_anchor.as_ref()
    }

    /// drand chain hash hex in force.
    #[must_use]
    pub fn chain_hash(&self) -> &str {
        &self.chain_hash
    }

    /// The batch's leaf-CBOR stream in `seq` order.
    #[must_use]
    pub fn leaves(&self) -> &[Vec<u8>] {
        &self.leaves
    }

    /// Serialise to canonical CBOR (the Arweave tx data).
    ///
    /// # Errors
    ///
    /// [`LogError::Cbor`] if the CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, LogError> {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(ANCHOR_KEYS_CANONICAL.len());
        let mut keys: Vec<&str> = Vec::with_capacity(ANCHOR_KEYS_CANONICAL.len());

        map.push((text("sth"), Value::Bytes(self.sth.clone())));
        keys.push("sth");
        map.push((text("ver"), u8_value(self.ver)));
        keys.push("ver");
        let leaves_val = Value::Array(
            self.leaves
                .iter()
                .map(|l| Value::Bytes(l.clone()))
                .collect(),
        );
        map.push((text("leaves"), leaves_val));
        keys.push("leaves");
        map.push((text("chain_hash"), Value::Text(to_nfc(&self.chain_hash))));
        keys.push("chain_hash");
        if let Some(prev) = self.prev_anchor {
            map.push((text("prev_anchor"), Value::Bytes(prev.to_vec())));
            keys.push("prev_anchor");
        }

        assert_canonical_key_order(&keys);
        Ok(encode_map(map)?)
    }

    /// Parse from canonical CBOR.
    ///
    /// # Errors
    ///
    /// [`LogError`] for malformed / non-canonical CBOR, an unsupported version,
    /// an oversized field, or a malformed leaf stream.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LogError> {
        let map = parse_top_level_map(bytes)?;
        reject_structural_elements_in_map(&map)?;

        let ver = extract_u8(&map, "ver")?;
        if ver != ANCHOR_FORMAT_1 {
            return Err(LogError::UnsupportedVersion(ver));
        }
        reject_unknown_keys(&map, ANCHOR_KEYS_CANONICAL, "AnchorBundle")?;
        let sth = extract_bytes_bounded(&map, "sth", MAX_STH_CBOR_SIZE)?;
        let prev_anchor = extract_optional_fixed_bytes::<32>(&map, "prev_anchor")?;
        let chain_hash = extract_text(&map, "chain_hash")?;
        if chain_hash.len() > MAX_CHAIN_HASH_LEN {
            return Err(LogError::TooLarge {
                field: "chain_hash",
                len: chain_hash.len(),
                max: MAX_CHAIN_HASH_LEN,
            });
        }
        let leaves = extract_bytes_array(&map, "leaves", MAX_ANCHOR_LEAVES, MAX_LEAF_CBOR_SIZE)?;

        Ok(Self {
            ver,
            sth,
            prev_anchor,
            chain_hash,
            leaves,
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_keys(bytes: &[u8]) -> Vec<String> {
        let v: Value = ciborium::de::from_reader(bytes).unwrap();
        match v {
            Value::Map(entries) => entries
                .into_iter()
                .map(|(k, _)| match k {
                    Value::Text(s) => s,
                    _ => panic!("non-text key"),
                })
                .collect(),
            _ => panic!("not a map"),
        }
    }

    fn sample_asserted() -> LogLeaf {
        LogLeaf::asserted(7, [0x11; 32], [0x22; 32], 1_800_000_000, 1_700_000_000).unwrap()
    }

    fn sample_attested() -> LogLeaf {
        LogLeaf::attested(
            9,
            [0x33; 32],
            [0x44; 32],
            1_800_000_000,
            1_700_000_000,
            [0x55; 32],
            4_695_445,
        )
        .unwrap()
    }

    fn sample_anchor_ref() -> AnchorRef {
        AnchorRef::new(
            [0x66; 32],
            3,
            [0x77; 32],
            LogProfile::qub().log_id(),
            Some(123_456),
            Some(1_700_000_500),
        )
    }

    // ---- canonical key order tables ----

    #[test]
    fn key_tables_are_canonical() {
        assert_canonical_key_order(LEAF_KEYS_CANONICAL);
        assert_canonical_key_order(STH_KEYS_CANONICAL);
        assert_canonical_key_order(ANCHOR_KEYS_CANONICAL);
        assert_canonical_key_order(INCLUSION_KEYS_CANONICAL);
        assert_canonical_key_order(ANCHOR_REF_KEYS_CANONICAL);
        assert_canonical_key_order(CONSISTENCY_KEYS_CANONICAL);
    }

    // ---- LogLeaf ----

    /// Accessor read-back for every projection on the log wire types.
    ///
    /// Mutation testing found 62 surviving mutants in this file and their
    /// shape was uniform: `FnValue` replacements on accessors — return
    /// `Default::default()`, `0`, `None`, `vec![]` — that no test ever
    /// read back. These types ARE exercised, through their CBOR
    /// round-trip, but a round-trip compares whole structs and never asks
    /// what an individual getter returns, so a getter could be replaced
    /// by a constant and the suite stayed green.
    ///
    /// Every value below is deliberately non-default and distinct from
    /// its neighbours, because the constants a mutant reaches for are
    /// exactly `0`, `1`, `None`, `false` and the empty collection. A
    /// field set to `1` would be killed by nothing.
    /// Bounds-check boundary. Both mutants on `len > max` survived, and
    /// they survived for complementary reasons: `>` → `>=` is invisible
    /// unless something of EXACTLY `max` is accepted, and `>` → `==` is
    /// invisible unless something STRICTLY LARGER than `max` is rejected.
    /// Neither case existed, so this bound on attacker-supplied input was
    /// pinned from neither side.
    ///
    /// `extract_bytes_array` bounds two things — the element COUNT and
    /// each element's SIZE — and both were unpinned.
    /// Length-bound boundary, pinned from both sides. `>` → `>=` is
    /// invisible unless something of EXACTLY the limit is accepted, and
    /// `>` → `==` is invisible unless something strictly larger is
    /// rejected. Neither case existed here.
    #[test]
    fn anchor_bundle_chain_hash_cap_is_pinned_both_sides() {
        let encode = |len: usize| {
            AnchorBundle::new(vec![0xAA; 4], None, "c".repeat(len), vec![vec![0x55]])
                .to_cbor()
                .expect("encode")
        };
        AnchorBundle::from_cbor(&encode(MAX_CHAIN_HASH_LEN))
            .expect("a chain_hash of exactly the cap must decode");
        assert!(matches!(
            AnchorBundle::from_cbor(&encode(MAX_CHAIN_HASH_LEN + 1)),
            Err(LogError::TooLarge { .. })
        ));
    }

    #[test]
    fn log_array_extractors_pin_both_sides_of_their_limits() {
        let digests = |n: usize| -> ParsedMap {
            vec![(
                "d".to_owned(),
                Value::Array(vec![Value::Bytes(vec![0u8; 32]); n]),
            )]
        };
        assert_eq!(
            extract_digest_array(&digests(3), "d", 3)
                .expect("exactly max digests is legal")
                .len(),
            3
        );
        assert!(matches!(
            extract_digest_array(&digests(4), "d", 3),
            Err(LogError::TooLarge { .. })
        ));

        let blobs = |count: usize, each: usize| -> ParsedMap {
            vec![(
                "b".to_owned(),
                Value::Array(vec![Value::Bytes(vec![0xAA; each]); count]),
            )]
        };
        // Element COUNT boundary.
        assert_eq!(
            blobs_ok(&blobs(3, 4), 3, 4).len(),
            3,
            "exactly max elements is legal"
        );
        assert!(matches!(
            extract_bytes_array(&blobs(4, 4), "b", 3, 4),
            Err(LogError::TooLarge { .. })
        ));
        // Per-element SIZE boundary.
        assert_eq!(
            blobs_ok(&blobs(2, 4), 3, 4)[0].len(),
            4,
            "an element of exactly max_each is legal"
        );
        assert!(matches!(
            extract_bytes_array(&blobs(2, 5), "b", 3, 4),
            Err(LogError::TooLarge { .. })
        ));
    }

    fn blobs_ok(map: &ParsedMap, max_len: usize, max_each: usize) -> Vec<Vec<u8>> {
        extract_bytes_array(map, "b", max_len, max_each).expect("within both limits")
    }

    #[test]
    fn log_type_accessors_read_back_what_was_constructed() {
        let profile = LogProfile::new([3u8; 32], vec![0xAB, 0xCD, 0xEF]);
        assert_eq!(profile.receipt_pubkey(), &[0xAB, 0xCD, 0xEF]);

        let sth = SignedTreeHead::new(97, [4u8; 32], 88, [5u8; 32], [6u8; 32], 77, 1_777_000_000);
        assert_eq!(sth.size(), 97);
        assert_eq!(sth.batch(), 88);
        assert_eq!(sth.first_seq(), 77);
        assert_eq!(sth.anchored_at(), 1_777_000_000);

        let anchor = AnchorRef::new(
            [7u8; 32],
            66,
            [8u8; 32],
            [9u8; 32],
            Some(55),
            Some(1_666_000_000),
        );
        assert_eq!(anchor.batch(), 66);
        assert_eq!(anchor.block_height(), Some(55));
        assert_eq!(anchor.anchored_at(), Some(1_666_000_000));

        let inclusion = InclusionProof::new(
            vec![0x11, 0x22],
            44,
            99,
            vec![[10u8; 32], [11u8; 32]],
            [12u8; 32],
            anchor.clone(),
        );
        assert_eq!(inclusion.ver(), PROOF_VERSION_1);
        assert_eq!(inclusion.leaf(), &[0x11, 0x22]);
        assert_eq!(inclusion.index(), 44);
        assert_eq!(inclusion.size(), 99);
        assert_eq!(inclusion.audit(), &[[10u8; 32], [11u8; 32]]);

        let consistency = ConsistencyProof::new(
            33,
            99,
            [13u8; 32],
            [14u8; 32],
            vec![[15u8; 32]],
            anchor.clone(),
            anchor,
        );
        assert_eq!(consistency.ver(), PROOF_VERSION_1);
        assert_eq!(consistency.first_size(), 33);
        assert_eq!(consistency.second_size(), 99);
        assert_eq!(consistency.nodes(), &[[15u8; 32]]);

        let bundle = AnchorBundle::new(
            vec![0x33, 0x44],
            Some([16u8; 32]),
            "chain-hash-value".to_owned(),
            vec![vec![0x55]],
        );
        assert_eq!(bundle.ver(), ANCHOR_FORMAT_1);
        assert_eq!(bundle.prev_anchor(), Some(&[16u8; 32]));
        assert_eq!(bundle.chain_hash(), "chain-hash-value");

        // LogLeaf's own projections, both kinds, with every numeric field
        // distinct so a `0`/`1` replacement cannot coincide with the truth.
        let attested = LogLeaf::attested(
            21,
            [17u8; 32],
            [18u8; 32],
            1_811_000_000,
            1_711_000_000,
            [19u8; 32],
            9_876_543,
        )
        .expect("valid attested leaf");
        assert_eq!(attested.seq(), 21);
        assert_eq!(attested.kind(), LEAF_KIND_ATTESTED);
        assert_eq!(attested.unlock_at(), 1_811_000_000);
        assert_eq!(attested.received_at(), 1_711_000_000);
        assert_eq!(attested.body_hash(), Some(&[19u8; 32]));
        assert_eq!(attested.drand_round(), Some(9_876_543));

        let asserted = LogLeaf::asserted(22, [20u8; 32], [21u8; 32], 1_822_000_000, 1_722_000_000)
            .expect("valid asserted leaf");
        assert_eq!(asserted.seq(), 22);
        assert_eq!(asserted.kind(), LEAF_KIND_ASSERTED);
        assert_eq!(asserted.unlock_at(), 1_822_000_000);
        assert_eq!(asserted.received_at(), 1_722_000_000);
        assert_eq!(asserted.body_hash(), None);
        assert_eq!(asserted.drand_round(), None);
    }

    /// `validate` requires `body_hash` and `drand_round` to be present
    /// together (attested) or absent together (asserted). Both checks are
    /// a `||` over the two fields, and mutation flipped BOTH to `&&`
    /// without a single test noticing.
    ///
    /// The reason no test could notice is worth recording: `LogLeaf::
    /// attested` and `LogLeaf::asserted` set the pair themselves, so
    /// neither constructor can produce the half-populated leaf this check
    /// exists for. Only a tampered wire leaf can — which is exactly the
    /// input the check defends against, and exactly what nothing tested.
    #[test]
    fn leaf_validate_rejects_half_populated_kind_fields() {
        let leaf = |kind, body_hash, drand_round| LogLeaf {
            seq: 1,
            kind,
            reference: [1u8; 32],
            chash: [2u8; 32],
            unlock_at: 1_800_000_000,
            received_at: 1_700_000_000,
            body_hash,
            drand_round,
        };
        for (label, candidate) in [
            (
                "attested without drand_round",
                leaf(LEAF_KIND_ATTESTED, Some([3u8; 32]), None),
            ),
            (
                "attested without body_hash",
                leaf(LEAF_KIND_ATTESTED, None, Some(42)),
            ),
            (
                "asserted carrying body_hash",
                leaf(LEAF_KIND_ASSERTED, Some([3u8; 32]), None),
            ),
            (
                "asserted carrying drand_round",
                leaf(LEAF_KIND_ASSERTED, None, Some(42)),
            ),
        ] {
            assert!(
                matches!(
                    candidate.validate(),
                    Err(LogError::KindFieldMismatch { .. })
                ),
                "{label} must be rejected by validate()",
            );
        }
    }

    #[test]
    fn asserted_leaf_roundtrip_and_keys() {
        let leaf = sample_asserted();
        let bytes = leaf.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&bytes),
            vec!["ref", "seq", "kind", "chash", "unlock_at", "received_at"]
        );
        assert_eq!(LogLeaf::from_cbor(&bytes).unwrap(), leaf);
    }

    #[test]
    fn attested_leaf_roundtrip_and_keys() {
        let leaf = sample_attested();
        let bytes = leaf.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&bytes),
            vec![
                "ref",
                "seq",
                "kind",
                "chash",
                "body_hash",
                "unlock_at",
                "drand_round",
                "received_at"
            ]
        );
        assert_eq!(LogLeaf::from_cbor(&bytes).unwrap(), leaf);
    }

    #[test]
    fn leaf_hash_is_domain_separated() {
        let leaf = sample_asserted();
        let bytes = leaf.to_cbor().unwrap();
        assert_eq!(leaf.leaf_hash().unwrap(), merkle::leaf_hash(&bytes));
        // 0x00 prefix means leaf_hash != plain SHA3-256(leaf_cbor).
        let mut plain = Sha3_256::new();
        plain.update(&bytes);
        let plain: [u8; 32] = plain.finalize().into();
        assert_ne!(leaf.leaf_hash().unwrap(), plain);
    }

    #[test]
    fn rejects_all_zero_ref_and_chash() {
        assert_eq!(
            LogLeaf::asserted(1, [0; 32], [1; 32], 10, 10).unwrap_err(),
            LogError::ZeroDigest("ref")
        );
        assert_eq!(
            LogLeaf::asserted(1, [1; 32], [0; 32], 10, 10).unwrap_err(),
            LogError::ZeroDigest("chash")
        );
    }

    #[test]
    fn rejects_non_positive_timestamps() {
        assert_eq!(
            LogLeaf::asserted(1, [1; 32], [2; 32], 0, 10).unwrap_err(),
            LogError::NonPositiveTimestamp("unlock_at")
        );
        assert_eq!(
            LogLeaf::asserted(1, [1; 32], [2; 32], 10, -1).unwrap_err(),
            LogError::NonPositiveTimestamp("received_at")
        );
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        // Hand-build a leaf map with kind=0x03.
        let map = vec![
            (text("ref"), Value::Bytes(vec![1u8; 32])),
            (text("seq"), u64_value(1)),
            (text("kind"), u8_value(3)),
            (text("chash"), Value::Bytes(vec![2u8; 32])),
            (text("unlock_at"), i64_value(10)),
            (text("received_at"), i64_value(10)),
        ];
        let bytes = encode_map(map).unwrap();
        assert_eq!(
            LogLeaf::from_cbor(&bytes).unwrap_err(),
            LogError::UnknownKind(3)
        );
    }

    #[test]
    fn decode_rejects_attested_missing_body_hash() {
        // kind=0x01 but no body_hash / drand_round.
        let map = vec![
            (text("ref"), Value::Bytes(vec![1u8; 32])),
            (text("seq"), u64_value(1)),
            (text("kind"), u8_value(LEAF_KIND_ATTESTED)),
            (text("chash"), Value::Bytes(vec![2u8; 32])),
            (text("unlock_at"), i64_value(10)),
            (text("received_at"), i64_value(10)),
        ];
        let bytes = encode_map(map).unwrap();
        assert!(matches!(
            LogLeaf::from_cbor(&bytes).unwrap_err(),
            LogError::KindFieldMismatch {
                kind: LEAF_KIND_ATTESTED,
                ..
            }
        ));
    }

    // ---- SignedTreeHead ----

    #[test]
    fn sth_roundtrip_keys_and_hash() {
        let sth = SignedTreeHead::new(
            5,
            [0xAA; 32],
            2,
            [0; 32],
            LogProfile::qub().log_id(),
            0,
            1_700_000_000,
        );
        let bytes = sth.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&bytes),
            vec![
                "prev",
                "root",
                "size",
                "batch",
                "log_id",
                "first_seq",
                "anchored_at"
            ]
        );
        assert_eq!(SignedTreeHead::from_cbor(&bytes).unwrap(), sth);
        // sth_hash is 0x03-prefixed, distinct from plain SHA3-256(cbor).
        let mut plain = Sha3_256::new();
        plain.update(&bytes);
        let plain: [u8; 32] = plain.finalize().into();
        assert_ne!(sth.sth_hash().unwrap(), plain);
    }

    // ---- InclusionProof ----

    #[test]
    fn inclusion_proof_roundtrip_and_verifies() {
        // Build a real 5-leaf tree, prove leaf 2.
        let leaves: Vec<LogLeaf> = (0u8..5)
            .map(|i| {
                LogLeaf::asserted(
                    u64::from(i),
                    [i + 1; 32],
                    [i + 100; 32],
                    1_800_000_000,
                    1_700_000_000,
                )
                .unwrap()
            })
            .collect();
        let leaf_cbors: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_cbor().unwrap()).collect();
        let leaf_hashes: Vec<[u8; 32]> = leaf_cbors.iter().map(|c| merkle::leaf_hash(c)).collect();
        let root = merkle::merkle_root(&leaf_hashes);
        let audit = merkle::inclusion_proof(2, &leaf_hashes).unwrap();

        let proof = InclusionProof::new(
            leaf_cbors[2].clone(),
            2,
            5,
            audit,
            root,
            sample_anchor_ref(),
        );
        assert!(proof.verify_root());

        let bytes = proof.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&bytes),
            vec!["ver", "leaf", "root", "size", "audit", "index", "anchor"]
        );
        let back = InclusionProof::from_cbor(&bytes).unwrap();
        assert_eq!(back, proof);
        assert!(back.verify_root());

        // Tamper the root → verify_root fails.
        let mut bad_root = root;
        bad_root[0] ^= 1;
        let bad = InclusionProof::new(
            leaf_cbors[2].clone(),
            2,
            5,
            merkle::inclusion_proof(2, &leaf_hashes).unwrap(),
            bad_root,
            sample_anchor_ref(),
        );
        assert!(!bad.verify_root());
    }

    #[test]
    fn inclusion_proof_rejects_bad_version() {
        let proof =
            InclusionProof::new(vec![1, 2, 3], 0, 1, vec![], [0xAB; 32], sample_anchor_ref());
        let mut p = proof;
        p.ver = 2;
        let bytes = p.to_cbor().unwrap();
        assert_eq!(
            InclusionProof::from_cbor(&bytes).unwrap_err(),
            LogError::UnsupportedVersion(2)
        );
    }

    // ---- ConsistencyProof ----

    /// `ConsistencyProof::verify` could be replaced with `true` — a
    /// verifier that accepts every proof, including forged ones — and the
    /// suite stayed green, because every existing assertion is
    /// `assert!(proof.verify())`. A function that only ever has its
    /// SUCCESS asserted is indistinguishable from one hardcoded to
    /// succeed, and for a verifier that is the whole point of it.
    ///
    /// Each case tampers with exactly one input, so a `false` here cannot
    /// be an accident of a malformed proof in general.
    #[test]
    fn consistency_proof_verify_rejects_tampered_input() {
        let leaf_hashes: Vec<[u8; 32]> = (0..7u8).map(|i| merkle::leaf_hash(&[i; 16])).collect();
        let nodes = merkle::consistency_proof(4, &leaf_hashes).unwrap();
        let (prefix, _) = leaf_hashes.split_at(4);
        let root4 = merkle::merkle_root(prefix);
        let root7 = merkle::merkle_root(&leaf_hashes);

        let proof = |first_root, second_root, nodes: Vec<[u8; 32]>| {
            ConsistencyProof::new(
                4,
                7,
                first_root,
                second_root,
                nodes,
                sample_anchor_ref(),
                sample_anchor_ref(),
            )
        };

        // Control: the genuine proof verifies, so the negatives below
        // cannot pass for the wrong reason.
        assert!(proof(root4, root7, nodes.clone()).verify());

        assert!(
            !proof([0xAA; 32], root7, nodes.clone()).verify(),
            "a wrong first root must not verify"
        );
        assert!(
            !proof(root4, [0xBB; 32], nodes.clone()).verify(),
            "a wrong second root must not verify"
        );
        let mut tampered = nodes;
        tampered[0] = [0xCC; 32];
        assert!(
            !proof(root4, root7, tampered).verify(),
            "a tampered audit node must not verify"
        );
        assert!(
            !proof(root4, root7, Vec::new()).verify(),
            "an emptied proof must not verify"
        );
    }

    #[test]
    fn consistency_proof_roundtrip_and_verifies() {
        let leaf_hashes: Vec<[u8; 32]> = (0..7u8).map(|i| merkle::leaf_hash(&[i; 16])).collect();
        let nodes = merkle::consistency_proof(4, &leaf_hashes).unwrap();
        let (prefix, _) = leaf_hashes.split_at(4);
        let root4 = merkle::merkle_root(prefix);
        let root7 = merkle::merkle_root(&leaf_hashes);

        let proof = ConsistencyProof::new(
            4,
            7,
            root4,
            root7,
            nodes,
            sample_anchor_ref(),
            sample_anchor_ref(),
        );
        assert!(proof.verify());

        let bytes = proof.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&bytes),
            vec![
                "ver",
                "nodes",
                "first_root",
                "first_size",
                "second_root",
                "second_size",
                "first_anchor",
                "second_anchor"
            ]
        );
        let back = ConsistencyProof::from_cbor(&bytes).unwrap();
        assert_eq!(back, proof);
        assert!(back.verify());
    }

    // ---- AnchorBundle ----

    #[test]
    fn anchor_bundle_roundtrip_genesis_and_full() {
        let sth = SignedTreeHead::new(
            2,
            [0xAA; 32],
            0,
            [0; 32],
            LogProfile::qub().log_id(),
            0,
            1_700_000_000,
        )
        .to_cbor()
        .unwrap();
        let leaf_cbors = vec![
            sample_asserted().to_cbor().unwrap(),
            sample_attested().to_cbor().unwrap(),
        ];

        // Genesis: prev_anchor omitted.
        let genesis = AnchorBundle::new(sth.clone(), None, "52db9ba7".into(), leaf_cbors.clone());
        let gbytes = genesis.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&gbytes),
            vec!["sth", "ver", "leaves", "chain_hash"]
        );
        assert_eq!(AnchorBundle::from_cbor(&gbytes).unwrap(), genesis);

        // Full: prev_anchor present.
        let full = AnchorBundle::new(sth, Some([0x99; 32]), "52db9ba7".into(), leaf_cbors);
        let fbytes = full.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&fbytes),
            vec!["sth", "ver", "leaves", "chain_hash", "prev_anchor"]
        );
        assert_eq!(AnchorBundle::from_cbor(&fbytes).unwrap(), full);
    }

    // ---- LogProfile ----

    #[test]
    fn log_id_is_deterministic_and_domain_separated() {
        let p = LogProfile::qub();
        let id = p.log_id();
        assert_eq!(id, LogProfile::qub().log_id());
        // Different anchor_owner → different log_id.
        let other = LogProfile::new([0xCD; 32], vec![]);
        assert_ne!(id, other.log_id());
    }

    #[test]
    fn placeholder_anchor_owner_is_detected() {
        // The pinned production profile is still the build-time placeholder
        // (the dedicated anchor wallet is not yet provisioned, §16.6).
        assert!(LogProfile::qub().is_anchor_owner_placeholder());
        // A provisioned (non-placeholder) owner reports false.
        assert!(!LogProfile::new([0xCD; 32], vec![]).is_anchor_owner_placeholder());
    }

    #[test]
    fn determinism_across_all_types() {
        assert_eq!(
            sample_asserted().to_cbor().unwrap(),
            sample_asserted().to_cbor().unwrap()
        );
        let sth = SignedTreeHead::new(1, [1; 32], 0, [0; 32], [2; 32], 0, 1);
        assert_eq!(sth.to_cbor().unwrap(), sth.to_cbor().unwrap());
    }
}
