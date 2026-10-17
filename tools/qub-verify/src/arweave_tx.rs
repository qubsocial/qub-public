//! Binding stored bytes to an Arweave L1 transaction (format 2).
//!
//! Every accepted qub publication is scheduled as its own Arweave transaction
//! whose id is the qub's `tx_id` (PROTOCOL.md §16.1, tier T3). PROTOCOL.md
//! §17.4 step 9 names "independently verify the referenced storage
//! transaction" as one of the two existence-time legs. This module is the
//! local half of that leg: given the transaction header a gateway returned and
//! the bytes a verifier already holds, it checks
//!
//! 1. `id == base64url(SHA-256(signature))` — the id is a function of the
//!    signature, never a label a gateway may attach;
//! 2. the RSA-PSS signature over the Arweave `deepHash` of the header fields,
//!    under the header's own `owner`; and
//! 3. `data_root == merkle_root(stored bytes)` and `data_size == len(bytes)`.
//!
//! **What this proves, and what it does not.** Together the three checks show
//! that the header is a well-formed transaction with this id that commits to
//! exactly these bytes. They do **not** show that the transaction is on the
//! Arweave chain, and they do not authenticate the header against the chain:
//! `owner` comes from the same response as the signature, and a signature
//! value can be made to verify under a purpose-built modulus. Which header
//! belongs to an id, which block holds it and what that block's time is are
//! all read from gateways qub does not run and judged by [`crate::timing`]. No
//! caller may turn a successful result here into a statement about time.
//!
//! The Merkle rules, the signature preimage and the salt lengths accepted are
//! those of the reference `arweave-js` client (`lib/merkle.ts`,
//! `Transaction.getSignatureData`, `webcrypto-driver.verify`); the fixtures in
//! `tests/vectors/` are produced by that client and by Arweave mainnet.
//! SHA-256 and SHA-384 here are Arweave-wire primitives only (§15 fence).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use rsa::pss::{Signature, VerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use serde_json::Value;
use sha2::Sha256;

use crate::ans104::{DeepHashChunk, deep_hash, sha256};

/// Largest chunk the Arweave data tree holds (256 KiB).
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Smallest final chunk before the last two chunks are rebalanced (32 KiB).
pub const MIN_CHUNK_SIZE: usize = 32 * 1024;
/// Width of the byte-offset "note" hashed into every tree node.
const NOTE_SIZE: usize = 32;
/// The only transaction format this verifier accepts. Format 1 carries its
/// data inline and signs it directly; qub has never written one.
pub const SUPPORTED_FORMAT: u64 = 2;
/// Upper bound on a transaction header's JSON text. A real header is about
/// 2 KiB; the cap stops a gateway handing the parser an arbitrarily large body.
pub const MAX_HEADER_JSON_BYTES: usize = 64 * 1024;
/// Smallest RSA modulus accepted for `owner`, in bits.
const MIN_MODULUS_BITS: usize = 2048;
/// Largest RSA modulus accepted for `owner`, in bits (Arweave wallets are 4096).
const MAX_MODULUS_BITS: usize = 4096;
/// RSA public exponent of every Arweave wallet.
const RSA_PUBLIC_EXPONENT: u32 = 65_537;
/// Length of a base64url transaction id (32 bytes, no padding).
const TX_ID_LEN: usize = 43;
/// Most tags a header may carry. Arweave bounds tags by total bytes (2048),
/// so a header with more entries than that is malformed.
const MAX_TAGS: usize = 2048;
/// Longest decoded `owner` or `signature`, in bytes.
const MAX_KEY_BYTES: usize = MAX_MODULUS_BITS / 8;

/// Why a gateway's transaction header could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxParseError(String);

impl TxParseError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl core::fmt::Display for TxParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "arweave tx header: {}", self.0)
    }
}

impl std::error::Error for TxParseError {}

/// Why a header does not establish the binding it was asked for.
///
/// The two groups matter to the caller. [`TxFault::is_header_fault`] faults
/// say the *response* is unusable (wrong id, bad signature, unsupported
/// format): a gateway returned something that is not this transaction.
/// The remaining faults say the header is a self-consistent transaction with
/// this id that commits to *other* bytes: the artifact is not what the
/// transaction stores.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxFault {
    /// The header declares a format other than [`SUPPORTED_FORMAT`].
    UnsupportedFormat(u64),
    /// The header's `id` is not the transaction id that was requested.
    IdMismatch,
    /// The header's `id` is not `base64url(SHA-256(signature))`.
    IdNotSignatureHash,
    /// `owner` is not an RSA modulus of an accepted size.
    BadOwner,
    /// The RSA-PSS signature does not verify over the header fields.
    SignatureInvalid,
    /// `data_size` differs from the length of the stored bytes.
    DataSizeMismatch {
        /// Length the header commits to.
        committed: u64,
        /// Length of the bytes held by the verifier.
        actual: u64,
    },
    /// `data_root` differs from the Merkle root of the stored bytes.
    DataRootMismatch,
}

impl TxFault {
    /// True when the fault is about the header itself rather than about the
    /// bytes it was compared with.
    #[must_use]
    pub const fn is_header_fault(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedFormat(_)
                | Self::IdMismatch
                | Self::IdNotSignatureHash
                | Self::BadOwner
                | Self::SignatureInvalid
        )
    }
}

impl core::fmt::Display for TxFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedFormat(format) => write!(
                f,
                "transaction format {format} is not supported (only format {SUPPORTED_FORMAT})"
            ),
            Self::IdMismatch => write!(f, "header is for a different transaction id"),
            Self::IdNotSignatureHash => {
                write!(f, "header id is not the SHA-256 of its signature")
            },
            Self::BadOwner => write!(f, "owner is not an RSA modulus of an accepted size"),
            Self::SignatureInvalid => write!(f, "transaction signature does not verify"),
            Self::DataSizeMismatch { committed, actual } => write!(
                f,
                "transaction commits to {committed} bytes, the artifact is {actual} bytes"
            ),
            Self::DataRootMismatch => write!(
                f,
                "transaction data root does not match the artifact's bytes"
            ),
        }
    }
}

impl std::error::Error for TxFault {}

/// The signed fields of an Arweave format-2 transaction header, as returned by
/// a gateway's `GET /tx/<id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxHeader {
    format: u64,
    id: String,
    owner: Vec<u8>,
    target: Vec<u8>,
    quantity: String,
    reward: String,
    last_tx: Vec<u8>,
    tags: Vec<(Vec<u8>, Vec<u8>)>,
    data_size: u64,
    data_root: [u8; 32],
    signature: Vec<u8>,
}

/// A required string member of the header object.
fn string_member<'a>(object: &'a Value, name: &str) -> Result<&'a str, TxParseError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| TxParseError::new(format!("`{name}` is missing or not a string")))
}

/// Decode an unpadded base64url member, bounded to `max` decoded bytes.
fn base64_member(object: &Value, name: &str, max: usize) -> Result<Vec<u8>, TxParseError> {
    let text = string_member(object, name)?;
    // Four characters carry three bytes; reject before decoding.
    if text.len() > max.saturating_mul(4).div_ceil(3) {
        return Err(TxParseError::new(format!("`{name}` is too long")));
    }
    BASE64URL
        .decode(text.as_bytes())
        .map_err(|_| TxParseError::new(format!("`{name}` is not unpadded base64url")))
}

/// A required member holding a non-negative decimal integer as text
/// (`quantity`, `reward`, `data_size`). Returned verbatim: the signature
/// covers the ASCII digits, so no normalisation is allowed.
fn decimal_member<'a>(object: &'a Value, name: &str) -> Result<&'a str, TxParseError> {
    let text = string_member(object, name)?;
    if text.is_empty() || text.len() > 32 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TxParseError::new(format!(
            "`{name}` is not a decimal integer"
        )));
    }
    Ok(text)
}

impl TxHeader {
    /// Parse the body of a gateway's `GET /tx/<id>` response.
    ///
    /// Parsing checks shape and bounds only. Nothing about the header is
    /// trusted until [`TxHeader::verify`] has run.
    ///
    /// # Errors
    ///
    /// [`TxParseError`] when the text is too large, is not a JSON object, or a
    /// signed field is missing, mistyped, over its bound or not base64url.
    pub fn from_gateway_json(text: &str) -> Result<Self, TxParseError> {
        if text.len() > MAX_HEADER_JSON_BYTES {
            return Err(TxParseError::new("response is too large"));
        }
        let object: Value = serde_json::from_str(text)
            .map_err(|_| TxParseError::new("response is not valid JSON"))?;
        if !object.is_object() {
            return Err(TxParseError::new("response is not a JSON object"));
        }
        let format = object
            .get("format")
            .and_then(Value::as_u64)
            .ok_or_else(|| TxParseError::new("`format` is missing or not an integer"))?;
        let id = string_member(&object, "id")?;
        if id.len() != TX_ID_LEN {
            return Err(TxParseError::new("`id` is not a transaction id"));
        }
        let data_root: [u8; 32] = base64_member(&object, "data_root", 32)?
            .try_into()
            .map_err(|_| TxParseError::new("`data_root` is not 32 bytes"))?;
        let data_size_text = decimal_member(&object, "data_size")?;
        let data_size = data_size_text
            .parse::<u64>()
            .map_err(|_| TxParseError::new("`data_size` does not fit 64 bits"))?;
        // The signature covers the decimal text, and it is re-rendered from
        // the number: only the canonical spelling can be the signed one.
        if data_size.to_string() != data_size_text {
            return Err(TxParseError::new(
                "`data_size` is not in canonical decimal form",
            ));
        }
        let raw_tags = object
            .get("tags")
            .and_then(Value::as_array)
            .ok_or_else(|| TxParseError::new("`tags` is missing or not an array"))?;
        if raw_tags.len() > MAX_TAGS {
            return Err(TxParseError::new("`tags` has too many entries"));
        }
        let mut tags = Vec::with_capacity(raw_tags.len());
        for tag in raw_tags {
            tags.push((
                base64_member(tag, "name", MAX_TAGS)?,
                base64_member(tag, "value", MAX_TAGS)?,
            ));
        }
        Ok(Self {
            format,
            id: id.to_owned(),
            owner: base64_member(&object, "owner", MAX_KEY_BYTES)?,
            target: base64_member(&object, "target", 32)?,
            quantity: decimal_member(&object, "quantity")?.to_owned(),
            reward: decimal_member(&object, "reward")?.to_owned(),
            last_tx: base64_member(&object, "last_tx", 64)?,
            tags,
            data_size,
            data_root,
            signature: base64_member(&object, "signature", MAX_KEY_BYTES)?,
        })
    }

    /// The transaction id the header declares.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The Merkle root of the data the transaction commits to.
    #[must_use]
    pub const fn data_root(&self) -> &[u8; 32] {
        &self.data_root
    }

    /// The length, in bytes, of the data the transaction commits to.
    #[must_use]
    pub const fn data_size(&self) -> u64 {
        self.data_size
    }

    /// The Arweave `deepHash` the signature is computed over (format 2).
    fn signature_preimage(&self) -> [u8; 48] {
        let format = self.format.to_string();
        let data_size = self.data_size.to_string();
        let tags = self
            .tags
            .iter()
            .map(|(name, value)| {
                DeepHashChunk::List(vec![DeepHashChunk::Blob(name), DeepHashChunk::Blob(value)])
            })
            .collect();
        deep_hash(&DeepHashChunk::List(vec![
            DeepHashChunk::Blob(format.as_bytes()),
            DeepHashChunk::Blob(&self.owner),
            DeepHashChunk::Blob(&self.target),
            DeepHashChunk::Blob(self.quantity.as_bytes()),
            DeepHashChunk::Blob(self.reward.as_bytes()),
            DeepHashChunk::Blob(&self.last_tx),
            DeepHashChunk::List(tags),
            DeepHashChunk::Blob(data_size.as_bytes()),
            DeepHashChunk::Blob(&self.data_root),
        ]))
    }

    /// Check that this header is a self-consistent format-2 transaction whose
    /// id is `tx_id`.
    ///
    /// # Errors
    ///
    /// A [`TxFault`] for which [`TxFault::is_header_fault`] is true.
    pub fn verify(&self, tx_id: &str) -> Result<(), TxFault> {
        if self.format != SUPPORTED_FORMAT {
            return Err(TxFault::UnsupportedFormat(self.format));
        }
        if self.id != tx_id {
            return Err(TxFault::IdMismatch);
        }
        if BASE64URL.encode(sha256(&self.signature)) != self.id {
            return Err(TxFault::IdNotSignatureHash);
        }
        if rsa_pss_verifies(&self.owner, &self.signature_preimage(), &self.signature)? {
            Ok(())
        } else {
            Err(TxFault::SignatureInvalid)
        }
    }

    /// Check that the header commits to exactly `stored`.
    ///
    /// Meaningful only for a header that already passed [`TxHeader::verify`].
    ///
    /// # Errors
    ///
    /// [`TxFault::DataSizeMismatch`] or [`TxFault::DataRootMismatch`].
    pub fn commits_to(&self, stored: &[u8]) -> Result<(), TxFault> {
        let actual = u64::try_from(stored.len()).unwrap_or(u64::MAX);
        if self.data_size != actual {
            return Err(TxFault::DataSizeMismatch {
                committed: self.data_size,
                actual,
            });
        }
        if self.data_root != data_root(stored) {
            return Err(TxFault::DataRootMismatch);
        }
        Ok(())
    }
}

/// RSA-PSS (SHA-256, MGF1-SHA-256) verification of `signature` over `message`
/// under the modulus `owner`.
///
/// The salt length is not fixed by Arweave: the Web Crypto driver signs with
/// 32 bytes, the Node driver with the maximum the modulus allows, and the
/// reference verifier accepts 0, 32 or that maximum. The same three are tried
/// here, so a transaction valid for the network is valid for this verifier.
fn rsa_pss_verifies(owner: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, TxFault> {
    let modulus = BigUint::from_bytes_be(owner);
    let bits = modulus.bits();
    // An Arweave wallet's modulus is a whole number of bytes (4096 bits).
    // Anything shorter than 2048 bits, or not byte-aligned, is not one. The
    // upper bound is the parser's: an owner longer than `MAX_KEY_BYTES`
    // never gets this far.
    if bits < MIN_MODULUS_BITS || !bits.is_multiple_of(8) {
        return Err(TxFault::BadOwner);
    }
    let key = RsaPublicKey::new(modulus, BigUint::from(RSA_PUBLIC_EXPONENT))
        .map_err(|_| TxFault::BadOwner)?;
    let Ok(signature) = Signature::try_from(signature) else {
        return Ok(false);
    };
    // RFC 8017 §9.1.1: the largest salt is emLen − hLen − 2, where
    // emLen = ceil((modBits − 1) / 8) — for a whole-byte modulus, modBits / 8.
    let digest_len = <Sha256 as sha2::Digest>::output_size();
    let max_salt = bits / 8 - digest_len - 2;
    Ok([digest_len, 0, max_salt].into_iter().any(|salt_len| {
        VerifyingKey::<Sha256>::new_with_salt_len(key.clone(), salt_len)
            .verify(message, &signature)
            .is_ok()
    }))
}

/// A node of the Arweave data tree: its id and the exclusive end offset of
/// the bytes beneath it.
struct Node {
    id: [u8; 32],
    max_byte_range: usize,
}

/// The 32-byte big-endian encoding of a byte offset.
fn note(offset: usize) -> [u8; NOTE_SIZE] {
    let mut out = [0u8; NOTE_SIZE];
    let bytes = offset.to_be_bytes();
    out[NOTE_SIZE - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// `SHA-256` of the concatenation of `parts`.
fn hash_all(parts: &[&[u8]]) -> [u8; 32] {
    let mut joined = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        joined.extend_from_slice(part);
    }
    sha256(&joined)
}

/// The Arweave `data_root` of `data`: the root of the chunk Merkle tree the
/// network stores a format-2 transaction's data under.
///
/// Chunks are 256 KiB, except that a final chunk under 32 KiB is avoided by
/// splitting the last two evenly. A leaf is
/// `H(H(H(chunk)) ‖ H(note(end)))`; a branch is
/// `H(H(left) ‖ H(right) ‖ H(note(left.end)))`; an unpaired node is carried up
/// unchanged. Data of an exact multiple of 256 KiB ends in an empty chunk,
/// exactly as the reference client builds it.
#[must_use]
pub fn data_root(data: &[u8]) -> [u8; 32] {
    let mut nodes: Vec<Node> = Vec::new();
    let mut leaf = |chunk: &[u8], end: usize| {
        nodes.push(Node {
            id: hash_all(&[&sha256(&sha256(chunk)), &sha256(&note(end))]),
            max_byte_range: end,
        });
    };
    let mut rest = data;
    let mut cursor = 0usize;
    while rest.len() >= MAX_CHUNK_SIZE {
        let remainder = rest.len() - MAX_CHUNK_SIZE;
        let chunk_size = if remainder > 0 && remainder < MIN_CHUNK_SIZE {
            rest.len().div_ceil(2)
        } else {
            MAX_CHUNK_SIZE
        };
        let (chunk, tail) = rest.split_at(chunk_size);
        cursor += chunk.len();
        leaf(chunk, cursor);
        rest = tail;
    }
    leaf(rest, cursor + rest.len());

    // Each pass halves the layer, so a tree over any `usize` number of leaves
    // is reduced in at most `usize::BITS` passes. Bounding the loop by that,
    // rather than by the layer's length alone, means no mistake in the
    // reduction below can keep it from terminating.
    for _ in 0..usize::BITS {
        if nodes.len() < 2 {
            break;
        }
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut layer = nodes.into_iter();
        while let Some(left) = layer.next() {
            next.push(match layer.next() {
                Some(right) => Node {
                    id: hash_all(&[
                        &sha256(&left.id),
                        &sha256(&right.id),
                        &sha256(&note(left.max_byte_range)),
                    ]),
                    max_byte_range: right.max_byte_range,
                },
                None => left,
            });
        }
        nodes = next;
    }
    // `leaf` always runs at least once, so the tree is never empty.
    nodes.first().map_or([0u8; 32], |root| root.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET: &str = include_str!("../tests/vectors/arweave_mainnet_tx_v1.json");
    const GENERATED: &str = include_str!("../tests/vectors/arweave_tx_v1.json");

    fn fixture(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture is valid JSON")
    }

    /// The deterministic byte pattern both the fixture generator and this
    /// test derive from a length, so the fixture need not carry megabytes.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((i * 31 + 7) % 251).expect("below 251"))
            .collect()
    }

    fn header_of(case: &Value) -> TxHeader {
        TxHeader::from_gateway_json(&case["header"].to_string()).expect("fixture header parses")
    }

    /// Re-encode a fixture header with one member replaced.
    fn with_member(case: &Value, name: &str, value: Value) -> TxHeader {
        let mut header = case["header"].clone();
        header[name] = value;
        TxHeader::from_gateway_json(&header.to_string()).expect("edited header parses")
    }

    /// A transaction mined on Arweave mainnet verifies: id binding, deep hash
    /// and RSA-PSS. Its signature uses the maximum salt length, which a
    /// verifier fixed at 32 bytes rejects.
    #[test]
    fn mainnet_transaction_header_verifies() {
        let case = fixture(MAINNET);
        let header = header_of(&case);
        let id = case["header"]["id"].as_str().unwrap();
        assert_eq!(header.verify(id), Ok(()));
        assert_eq!(header.id(), id);
        assert_eq!(header.data_size(), 3611);
    }

    /// Every signed field is covered by the signature: changing any one of
    /// them, and nothing else, must fail verification.
    #[test]
    fn every_signed_field_is_bound_by_the_signature() {
        let case = fixture(MAINNET);
        let id = case["header"]["id"].as_str().unwrap();
        let other_root = BASE64URL.encode([7u8; 32]);
        let edits: [(&str, Value); 6] = [
            ("data_root", Value::String(other_root)),
            ("data_size", Value::String("3612".into())),
            ("reward", Value::String("1".into())),
            ("quantity", Value::String("1".into())),
            ("target", Value::String(BASE64URL.encode([1u8; 32]))),
            ("last_tx", Value::String(BASE64URL.encode([2u8; 48]))),
        ];
        for (name, value) in edits {
            assert_eq!(
                with_member(&case, name, value).verify(id),
                Err(TxFault::SignatureInvalid),
                "editing `{name}` must break the signature"
            );
        }
        let mut tags = case["header"]["tags"].clone();
        tags[0]["value"] = Value::String(BASE64URL.encode(b"text/plain"));
        assert_eq!(
            with_member(&case, "tags", tags).verify(id),
            Err(TxFault::SignatureInvalid)
        );
        let mut fewer = case["header"]["tags"].clone();
        fewer.as_array_mut().unwrap().pop();
        assert_eq!(
            with_member(&case, "tags", fewer).verify(id),
            Err(TxFault::SignatureInvalid)
        );
    }

    #[test]
    fn id_must_be_the_requested_one_and_the_signature_hash() {
        let case = fixture(MAINNET);
        let header = header_of(&case);
        let other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(header.verify(other), Err(TxFault::IdMismatch));
        // A header relabelled with another id (and asked for under it) is not
        // the hash of its own signature.
        let relabelled = with_member(&case, "id", Value::String(other.into()));
        assert_eq!(relabelled.verify(other), Err(TxFault::IdNotSignatureHash));
    }

    #[test]
    fn other_formats_are_refused() {
        let case = fixture(MAINNET);
        let id = case["header"]["id"].as_str().unwrap();
        assert_eq!(
            with_member(&case, "format", Value::from(1)).verify(id),
            Err(TxFault::UnsupportedFormat(1))
        );
    }

    /// `arweave-js` signs with a salt of 32 bytes under Web Crypto (what the
    /// Worker runs) and with the modulus maximum under Node; its verifier also
    /// accepts 0. Each must verify here, and each binds its data.
    #[test]
    fn reference_client_signatures_verify_at_every_salt_length() {
        let cases = fixture(GENERATED);
        let signed = cases["signed"].as_array().expect("signed cases");
        let salts: Vec<&str> = signed
            .iter()
            .map(|case| case["salt"].as_str().unwrap())
            .collect();
        assert_eq!(salts, ["32", "0", "max"]);
        for case in signed {
            let header = header_of(case);
            let id = case["header"]["id"].as_str().unwrap();
            let salt = case["salt"].as_str().unwrap();
            assert_eq!(header.verify(id), Ok(()), "salt {salt}");
            let len = usize::try_from(case["data_len"].as_u64().unwrap()).unwrap();
            let data = pattern(len);
            assert_eq!(header.commits_to(&data), Ok(()), "salt {salt}");
        }
    }

    #[test]
    fn commits_to_rejects_other_bytes() {
        let cases = fixture(GENERATED);
        let case = &cases["signed"][0];
        let header = header_of(case);
        let len = usize::try_from(case["data_len"].as_u64().unwrap()).unwrap();
        let mut data = pattern(len);
        // Same length, one byte different: only the root can tell.
        data[len / 2] ^= 0x01;
        assert_eq!(header.commits_to(&data), Err(TxFault::DataRootMismatch));
        // One byte longer: caught by the size before any hashing.
        data.push(0);
        assert_eq!(
            header.commits_to(&data),
            Err(TxFault::DataSizeMismatch {
                committed: len as u64,
                actual: len as u64 + 1
            })
        );
        assert!(!TxFault::DataRootMismatch.is_header_fault());
        assert!(
            !TxFault::DataSizeMismatch {
                committed: 0,
                actual: 1
            }
            .is_header_fault()
        );
        assert!(TxFault::SignatureInvalid.is_header_fault());
    }

    /// The data root agrees with `arweave-js` at every chunking boundary:
    /// empty, one chunk, exactly one chunk (which adds an empty one), the
    /// rebalanced last pair, and an odd number of leaves.
    #[test]
    fn data_root_matches_the_reference_client() {
        let cases = fixture(GENERATED);
        let roots = cases["data_roots"].as_array().expect("data_roots");
        let lens: Vec<u64> = roots
            .iter()
            .map(|case| case["len"].as_u64().unwrap())
            .collect();
        // The partitions this test exists for must all be present.
        for required in [
            0,
            1,
            MAX_CHUNK_SIZE as u64 - 1,
            MAX_CHUNK_SIZE as u64,
            MAX_CHUNK_SIZE as u64 + 1,
            (MAX_CHUNK_SIZE + MIN_CHUNK_SIZE) as u64 - 1,
            (MAX_CHUNK_SIZE + MIN_CHUNK_SIZE) as u64,
            2 * MAX_CHUNK_SIZE as u64 + 5,
        ] {
            assert!(lens.contains(&required), "fixture lacks length {required}");
        }
        for case in roots {
            let len = usize::try_from(case["len"].as_u64().unwrap()).unwrap();
            assert_eq!(
                BASE64URL.encode(data_root(&pattern(len))),
                case["data_root"].as_str().unwrap(),
                "data_root for {len} bytes"
            );
        }
    }

    /// The owner must be a whole-byte RSA modulus of at least 2048 bits.
    /// Each rejected shape is refused before any signature arithmetic; the
    /// accepted ones get as far as a signature that does not verify.
    #[test]
    fn owner_modulus_must_be_an_accepted_size() {
        let case = fixture(MAINNET);
        let id = case["header"]["id"].as_str().unwrap();
        // An odd modulus of exactly `bits` bits.
        let modulus = |bits: usize| {
            let mut bytes = vec![0x01u8; bits.div_ceil(8)];
            bytes[0] = 1 << ((bits - 1) % 8);
            bytes
        };
        let verify = |owner: &[u8]| {
            with_member(&case, "owner", Value::String(BASE64URL.encode(owner))).verify(id)
        };
        for refused in [1024, 2040, 2047, 2049, 4089, 4095] {
            assert_eq!(
                verify(&modulus(refused)),
                Err(TxFault::BadOwner),
                "{refused}-bit modulus"
            );
        }
        assert_eq!(verify(&[]), Err(TxFault::BadOwner));
        // Whole-byte moduli from the minimum up are keys: the mainnet
        // signature simply does not verify under them.
        for accepted in [2048, 2056, 4096] {
            assert_eq!(
                verify(&modulus(accepted)),
                Err(TxFault::SignatureInvalid),
                "{accepted}-bit modulus"
            );
        }
    }

    #[test]
    fn malformed_headers_are_parse_errors() {
        let case = fixture(MAINNET);
        let reject = |edit: &dyn Fn(&mut Value)| {
            let mut header = case["header"].clone();
            edit(&mut header);
            TxHeader::from_gateway_json(&header.to_string()).is_err()
        };
        assert!(reject(&|h| {
            h.as_object_mut().unwrap().remove("signature");
        }));
        assert!(reject(&|h| h["data_size"] = Value::from(3611)));
        assert!(reject(&|h| h["data_size"] = Value::String("-1".into())));
        assert!(reject(&|h| h["data_size"] = Value::String("3611 ".into())));
        assert!(reject(&|h| h["data_size"] = Value::String("03611".into())));
        assert!(reject(
            &|h| h["data_root"] = Value::String(BASE64URL.encode([1u8; 31]))
        ));
        assert!(reject(&|h| h["owner"] = Value::String("not base64!".into())));
        assert!(reject(&|h| h["id"] = Value::String("short".into())));
        assert!(reject(&|h| h["format"] = Value::String("2".into())));
        assert!(reject(&|h| h["tags"] = Value::String("none".into())));
        assert!(TxHeader::from_gateway_json("[]").is_err());
        assert!(TxHeader::from_gateway_json("Pending").is_err());
        let oversized = format!("{{\"pad\":\"{}\"}}", "a".repeat(MAX_HEADER_JSON_BYTES));
        assert!(TxHeader::from_gateway_json(&oversized).is_err());
        // The unmodified header still parses: the rejections above are the
        // edits, not the fixture.
        assert!(!reject(&|_| {}));
    }

    /// The bounds on a header are exact: the largest accepted value parses,
    /// one past it does not.
    #[test]
    fn header_bounds_are_exact() {
        let case = fixture(MAINNET);
        let parses = |edit: &dyn Fn(&mut Value)| {
            let mut header = case["header"].clone();
            edit(&mut header);
            TxHeader::from_gateway_json(&header.to_string()).is_ok()
        };
        // Decimal fields: 1 to 32 ASCII digits, nothing else. (`reward` is
        // used because, unlike `data_size`, nothing else constrains it.)
        assert!(parses(&|h| h["reward"] = Value::String("7".into())));
        assert!(parses(&|h| h["reward"] = Value::String("9".repeat(32))));
        assert!(!parses(&|h| h["reward"] = Value::String("9".repeat(33))));
        assert!(!parses(&|h| h["reward"] = Value::String(String::new())));
        assert!(!parses(&|h| h["reward"] = Value::String("12a".into())));
        assert!(!parses(&|h| h["reward"] = Value::String("a".into())));
        assert!(!parses(&|h| h["quantity"] = Value::String("1.5".into())));

        // An owner or signature of up to 512 bytes (RSA-4096) parses; 513
        // bytes does not.
        let bytes = |len: usize| Value::String(BASE64URL.encode(vec![0x41u8; len]));
        for field in ["owner", "signature"] {
            assert!(parses(&|h| h[field] = bytes(MAX_KEY_BYTES)), "{field}");
            assert!(!parses(&|h| h[field] = bytes(MAX_KEY_BYTES + 1)), "{field}");
        }
        assert_eq!(MAX_KEY_BYTES, 512);

        // Tags: exactly MAX_TAGS entries parse, one more does not.
        let tags = |count: usize| {
            Value::Array(vec![
                serde_json::json!({ "name": "YQ", "value": "Yg" });
                count
            ])
        };
        assert!(parses(&|h| h["tags"] = tags(MAX_TAGS)));
        assert!(!parses(&|h| h["tags"] = tags(MAX_TAGS + 1)));

        // The response text: exactly the cap parses, one byte more does not.
        let text = case["header"].to_string();
        let padded = |len: usize| format!("{text}{}", " ".repeat(len - text.len()));
        assert!(TxHeader::from_gateway_json(&padded(MAX_HEADER_JSON_BYTES)).is_ok());
        assert!(TxHeader::from_gateway_json(&padded(MAX_HEADER_JSON_BYTES + 1)).is_err());
    }

    #[test]
    fn faults_and_parse_errors_render_a_message() {
        for fault in [
            TxFault::UnsupportedFormat(1),
            TxFault::IdMismatch,
            TxFault::IdNotSignatureHash,
            TxFault::BadOwner,
            TxFault::SignatureInvalid,
            TxFault::DataSizeMismatch {
                committed: 1,
                actual: 2,
            },
            TxFault::DataRootMismatch,
        ] {
            assert!(!fault.to_string().is_empty(), "{fault:?}");
        }
        assert!(
            TxParseError::new("x")
                .to_string()
                .contains("arweave tx header: x")
        );
    }

    #[test]
    fn note_is_a_32_byte_big_endian_offset() {
        let encoded = note(0x0102_0304);
        assert_eq!(&encoded[..28], &[0u8; 28]);
        assert_eq!(&encoded[28..], &[1, 2, 3, 4]);
    }
}
