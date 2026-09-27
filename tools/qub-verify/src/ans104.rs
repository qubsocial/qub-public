//! In-house ANS-104 `DataItem` verifier — the native mirror of the Worker's
//! `workers/api/src/crypto/ans104.ts`, scoped to the *verify* direction the
//! standalone verifier needs (PROTOCOL.md §16.6 / §16.8).
//!
//! The §16.6 trust model requires a conforming verifier to confirm an Arweave
//! transparency-log anchor's `owner == LogProfile.anchor_owner` and to derive
//! the transaction id from the transaction's own bytes (never trusting a
//! gateway `/raw/` response). Both reduce to: parse an ANS-104 `DataItem`,
//! recompute the Arweave `deepHash`, and verify its RSA-PSS signature against
//! the embedded owner modulus. This module is the native counterpart to the
//! TypeScript signer/verifier; the cross-language `ans104_v1.json` fixture
//! (TypeScript signs → Rust verifies) is the §16.8 both-directions gate.
//!
//! `rsa` + `sha2` are pulled in **here only**, never by the WASM crates
//! (`qub-core` / `qub-app`): SHA-384 is the Arweave-wire `deepHash` primitive,
//! quarantined as an Arweave-wire-only hash (§15 fence — qub trust hashing is
//! SHA3-256 throughout). RSA-PSS verification with `saltLength = 32` over a
//! SHA-256 message digest is byte-for-byte the scheme `crypto.subtle` signs
//! with on the Worker side.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use rsa::pss::{Signature, VerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest as _, Sha256, Sha384};

/// ANS-104 signature type for RSA (PSS) — the only scheme v1 emits or verifies.
pub const SIG_TYPE_RSA: u16 = 1;
/// RSA-4096 PSS signature length, in bytes.
pub const RSA_SIGNATURE_LEN: usize = 512;
/// RSA-4096 modulus (owner) length, in bytes.
pub const RSA_OWNER_LEN: usize = 512;
/// RSA public exponent (Arweave wallets are fixed `e = 65537`).
const RSA_PUBLIC_EXPONENT: u32 = 65_537;

/// Errors produced while parsing or verifying an ANS-104 `DataItem`.
///
/// `#[non_exhaustive]`: match arms must include a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ans104Error {
    /// The `DataItem` ended before a field that was expected.
    Truncated,
    /// The 2-byte signature type was not [`SIG_TYPE_RSA`].
    UnsupportedSigType(u16),
    /// An optional 32-byte field's presence flag was neither `0x00` nor `0x01`.
    InvalidPresenceFlag(u8),
    /// A declared length field exceeds the addressable / remaining range.
    LengthOverflow,
    /// The embedded owner is not a usable RSA modulus.
    BadOwnerModulus,
    /// The 512-byte signature could not be parsed as an RSA-PSS value.
    BadSignature,
}

impl core::fmt::Display for Ans104Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "ans104: truncated DataItem"),
            Self::UnsupportedSigType(t) => {
                write!(
                    f,
                    "ans104: unsupported signature type {t} (only RSA-PSS / type 1)"
                )
            },
            Self::InvalidPresenceFlag(flag) => {
                write!(
                    f,
                    "ans104: invalid optional-field presence flag {flag:#04x}"
                )
            },
            Self::LengthOverflow => write!(f, "ans104: length field exceeds the addressable range"),
            Self::BadOwnerModulus => write!(f, "ans104: owner is not a valid RSA modulus"),
            Self::BadSignature => write!(f, "ans104: signature is not a valid RSA-PSS value"),
        }
    }
}

impl std::error::Error for Ans104Error {}

// -----------------------------------------------------------------------------
// Arweave deepHash (recursive SHA-384) — mirrors ans104.ts `deepHash`
// -----------------------------------------------------------------------------

/// A deep-hash input: a leaf byte string or a (possibly nested) list, exactly
/// the shape the TypeScript `DeepHashChunk` models.
enum DeepHashChunk<'a> {
    Blob(&'a [u8]),
    List(Vec<Self>),
}

fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Arweave `deepHash`: `blob`/`list`-tagged recursive SHA-384 (§16.8). Byte-for-
/// byte equivalent to `ans104.ts`'s `deepHash` and to arweave-js's reference.
fn deep_hash(chunk: &DeepHashChunk) -> [u8; 48] {
    match chunk {
        DeepHashChunk::Blob(data) => {
            let mut tag = Vec::with_capacity(4 + 20);
            tag.extend_from_slice(b"blob");
            tag.extend_from_slice(data.len().to_string().as_bytes());
            let mut tagged = Vec::with_capacity(96);
            tagged.extend_from_slice(&sha384(&tag));
            tagged.extend_from_slice(&sha384(data));
            sha384(&tagged)
        },
        DeepHashChunk::List(items) => {
            let mut tag = Vec::with_capacity(4 + 20);
            tag.extend_from_slice(b"list");
            tag.extend_from_slice(items.len().to_string().as_bytes());
            let mut acc = sha384(&tag);
            for item in items {
                let mut buf = Vec::with_capacity(96);
                buf.extend_from_slice(&acc);
                buf.extend_from_slice(&deep_hash(item));
                acc = sha384(&buf);
            }
            acc
        },
    }
}

/// The ANS-104 `DataItem` signing chunks (the deep-hash preimage).
fn signing_chunks<'a>(
    sig_type_ascii: &'a [u8],
    owner: &'a [u8],
    target: &'a [u8],
    anchor: &'a [u8],
    encoded_tags: &'a [u8],
    data: &'a [u8],
) -> DeepHashChunk<'a> {
    DeepHashChunk::List(vec![
        DeepHashChunk::Blob(b"dataitem"),
        DeepHashChunk::Blob(b"1"),
        DeepHashChunk::Blob(sig_type_ascii),
        DeepHashChunk::Blob(owner),
        DeepHashChunk::Blob(target),
        DeepHashChunk::Blob(anchor),
        DeepHashChunk::Blob(encoded_tags),
        DeepHashChunk::Blob(data),
    ])
}

// -----------------------------------------------------------------------------
// DataItem parsing
// -----------------------------------------------------------------------------

/// Fields parsed out of a raw RSA (sigType 1) `DataItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDataItem {
    /// Signature type (always [`SIG_TYPE_RSA`] for a parsed item).
    pub sig_type: u16,
    /// The 512-byte RSA-PSS signature.
    pub signature: Vec<u8>,
    /// The 512-byte RSA modulus (Arweave "owner").
    pub owner: Vec<u8>,
    /// Optional 32-byte target (empty when absent).
    pub target: Vec<u8>,
    /// Optional 32-byte uniqueness anchor (empty when absent).
    pub anchor: Vec<u8>,
    /// Declared tag count (untrusted hint; the body is authoritative, §16.7).
    pub num_tags: u64,
    /// The Avro-encoded tag block.
    pub encoded_tags: Vec<u8>,
    /// The `DataItem` payload (e.g. the `AnchorBundle` CBOR).
    pub data: Vec<u8>,
}

/// A bounds-checked cursor over the `DataItem` bytes.
struct Cursor<'a> {
    raw: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, off: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Ans104Error> {
        let end = self.off.checked_add(n).ok_or(Ans104Error::LengthOverflow)?;
        if end > self.raw.len() {
            return Err(Ans104Error::Truncated);
        }
        let slice = &self.raw[self.off..end];
        self.off = end;
        Ok(slice)
    }

    fn u16_le(&mut self) -> Result<u16, Ans104Error> {
        let b = self.take(2)?;
        Ok(u16::from(b[0]) | (u16::from(b[1]) << 8))
    }

    fn u64_le(&mut self) -> Result<u64, Ans104Error> {
        let b = self.take(8)?;
        let mut value = 0u64;
        for i in (0..8).rev() {
            value = (value << 8) | u64::from(b[i]);
        }
        Ok(value)
    }

    /// Read an ANS-104 optional 32-byte field: `0x00` absent, `0x01 || 32B`.
    fn optional_field(&mut self) -> Result<Vec<u8>, Ans104Error> {
        let flag = self.take(1)?[0];
        match flag {
            0 => Ok(Vec::new()),
            1 => Ok(self.take(32)?.to_vec()),
            other => Err(Ans104Error::InvalidPresenceFlag(other)),
        }
    }
}

/// Parse a raw RSA (sigType 1) `DataItem` into its fields.
///
/// # Errors
///
/// [`Ans104Error::Truncated`] if the buffer ends early, [`Ans104Error::
/// UnsupportedSigType`] for a non-RSA item, [`Ans104Error::InvalidPresenceFlag`]
/// for a malformed optional field, or [`Ans104Error::LengthOverflow`] for a
/// declared length that overruns the buffer.
pub fn parse_data_item(raw: &[u8]) -> Result<ParsedDataItem, Ans104Error> {
    let mut cur = Cursor::new(raw);

    let sig_type = cur.u16_le()?;
    if sig_type != SIG_TYPE_RSA {
        return Err(Ans104Error::UnsupportedSigType(sig_type));
    }
    let signature = cur.take(RSA_SIGNATURE_LEN)?.to_vec();
    let owner = cur.take(RSA_OWNER_LEN)?.to_vec();
    let target = cur.optional_field()?;
    let anchor = cur.optional_field()?;

    let num_tags = cur.u64_le()?;
    let tags_len = cur.u64_le()?;
    let tags_len = usize::try_from(tags_len).map_err(|_| Ans104Error::LengthOverflow)?;
    let encoded_tags = cur.take(tags_len)?.to_vec();
    // The remainder is the payload.
    let data = raw.get(cur.off..).ok_or(Ans104Error::Truncated)?.to_vec();

    Ok(ParsedDataItem {
        sig_type,
        signature,
        owner,
        target,
        anchor,
        num_tags,
        encoded_tags,
        data,
    })
}

// -----------------------------------------------------------------------------
// DataItem verification
// -----------------------------------------------------------------------------

/// The result of verifying a `DataItem` against its embedded owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDataItem {
    /// Whether the RSA-PSS signature verifies over the recomputed deep hash.
    pub valid: bool,
    /// The `DataItem` id: `base64url(no-pad)` of `SHA-256(signature)`.
    pub id: String,
    /// Raw `SHA-256(signature)` — equals the Arweave transaction id bytes the
    /// anchor proof's `anchor.txid` field carries.
    pub id_raw: [u8; 32],
    /// The Arweave address `SHA-256(owner modulus)` — compared against
    /// `LogProfile.anchor_owner` (§16.6).
    pub owner_address: [u8; 32],
    /// The `DataItem` payload (the `AnchorBundle` CBOR for a transparency anchor).
    pub data: Vec<u8>,
}

/// Verify a raw `DataItem`: recompute the Arweave deep hash, verify the RSA-PSS
/// signature against the embedded owner modulus (`e = 65537`, `saltLength = 32`,
/// SHA-256), and derive its id + owner address.
///
/// The signature scheme is byte-for-byte the one `crypto.subtle.sign({ name:
/// "RSA-PSS", saltLength: 32 }, …)` produces over the deep hash on the Worker
/// side: `Verifier::verify` hashes the deep-hash output with SHA-256 internally
/// and verifies with a salt length equal to the SHA-256 digest size (32).
///
/// # Errors
///
/// Propagates any [`Ans104Error`] from [`parse_data_item`], plus
/// [`Ans104Error::BadOwnerModulus`] / [`Ans104Error::BadSignature`] if the
/// embedded owner or signature cannot be loaded as RSA values. A *parseable*
/// `DataItem` with a *wrong* signature is not an error — it returns
/// `Ok` with `valid == false`.
pub fn verify_data_item(raw: &[u8]) -> Result<VerifiedDataItem, Ans104Error> {
    let parsed = parse_data_item(raw)?;

    let sig_type_ascii = parsed.sig_type.to_string();
    let digest = deep_hash(&signing_chunks(
        sig_type_ascii.as_bytes(),
        &parsed.owner,
        &parsed.target,
        &parsed.anchor,
        &parsed.encoded_tags,
        &parsed.data,
    ));

    let modulus = BigUint::from_bytes_be(&parsed.owner);
    let exponent = BigUint::from(RSA_PUBLIC_EXPONENT);
    let public_key =
        RsaPublicKey::new(modulus, exponent).map_err(|_| Ans104Error::BadOwnerModulus)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature =
        Signature::try_from(parsed.signature.as_slice()).map_err(|_| Ans104Error::BadSignature)?;

    // `Verifier::verify` hashes `digest` with SHA-256, then runs EMSA-PSS-VERIFY
    // with salt_len = 32 — identical to the Worker's webcrypto RSA-PSS verify.
    let valid = verifying_key.verify(&digest, &signature).is_ok();

    let id_raw = sha256(&parsed.signature);
    let owner_address = sha256(&parsed.owner);
    let id = BASE64URL.encode(id_raw);

    Ok(VerifiedDataItem {
        valid,
        id,
        id_raw,
        owner_address,
        data: parsed.data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ASCII length tagging is load-bearing; a hand-computed leaf deep hash
    // pins it against accidental drift. arweave-js parity is the TypeScript
    // side's job (ans104.test.ts cross-checks against the arweave-js lib).
    /// `Cursor`'s little-endian readers are hand-rolled and their `<<`
    /// shifts survived mutation: nothing decoded a multi-byte value whose
    /// bytes actually differ, so `<<` and `>>` produced the same answer.
    /// These read attacker-supplied Arweave `DataItem` bytes.
    ///
    /// The `|` operators in the same two expressions are deliberately NOT
    /// asserted, because they CANNOT be distinguished: `b[0]` occupies the
    /// low 8 bits and `b[1] << 8` the high 8, so the operands never share
    /// a set bit and `|` is identical to `^` for every possible input.
    /// Those two survivors are equivalent mutants, not coverage gaps.
    #[test]
    fn cursor_reads_little_endian_multi_byte_values() {
        let raw = [0x34u8, 0x12];
        let mut c = Cursor::new(&raw);
        assert_eq!(c.u16_le().unwrap(), 0x1234);

        let raw = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut c = Cursor::new(&raw);
        assert_eq!(c.u64_le().unwrap(), 0x0807_0605_0403_0201);
    }

    /// `Display::fmt` replaced with `Ok(Default::default())` writes
    /// nothing and still reports success, so every error would render as
    /// an empty string in the verifier's output. Nothing asserted it.
    #[test]
    fn error_display_always_renders_a_message() {
        for err in [
            Ans104Error::Truncated,
            Ans104Error::UnsupportedSigType(7),
            Ans104Error::InvalidPresenceFlag(9),
            Ans104Error::LengthOverflow,
            Ans104Error::BadOwnerModulus,
            Ans104Error::BadSignature,
        ] {
            assert!(
                !err.to_string().is_empty(),
                "{err:?} must render a non-empty message"
            );
        }
    }

    #[test]
    fn deep_hash_blob_is_tagged_sha384() {
        let data = b"hello, transparency log";
        let mut tag = Vec::new();
        tag.extend_from_slice(b"blob");
        tag.extend_from_slice(data.len().to_string().as_bytes());
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&sha384(&tag));
        tagged.extend_from_slice(&sha384(data));
        let expected = sha384(&tagged);
        assert_eq!(deep_hash(&DeepHashChunk::Blob(data)), expected);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(parse_data_item(&[1, 0, 0, 0]), Err(Ans104Error::Truncated));
    }

    #[test]
    fn parse_rejects_non_rsa_sig_type() {
        // sigType = 2 (LE) then enough padding to read the field.
        let raw = [2u8, 0];
        assert_eq!(
            parse_data_item(&raw),
            Err(Ans104Error::UnsupportedSigType(2))
        );
    }

    #[test]
    fn parse_rejects_bad_presence_flag() {
        // sigType(2) + sig(512) + owner(512) + bad target flag (0x02).
        let mut raw = vec![1u8, 0];
        raw.extend_from_slice(&[0u8; RSA_SIGNATURE_LEN]);
        raw.extend_from_slice(&[0u8; RSA_OWNER_LEN]);
        raw.push(0x02);
        assert_eq!(
            parse_data_item(&raw),
            Err(Ans104Error::InvalidPresenceFlag(0x02))
        );
    }

    /// The §16.8 both-directions gate: a `DataItem` signed by the TypeScript
    /// writer (`ans104-vector.test.ts`, RSA-PSS via `crypto.subtle`) must verify
    /// byte-for-byte in this native verifier — same deep hash, same RSA-PSS
    /// semantics, same id + owner-address derivation. The payload is a real
    /// `AnchorBundle` whose Signed Tree Head + matching inclusion proof are also
    /// cross-checked, exercising the full §16.9 standalone-verifier chain.
    #[test]
    fn verifies_typescript_signed_fixture() {
        use qub_core::log::{AnchorBundle, InclusionProof, LogProfile, SignedTreeHead};

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/qub-core/tests/vectors/ans104_v1.json"
        );
        let raw_json = std::fs::read_to_string(path).expect("read ans104_v1.json fixture");
        let fixture: serde_json::Value =
            serde_json::from_str(&raw_json).expect("fixture is valid JSON");

        let hex_field = |ptr: &str| -> Vec<u8> {
            let s = fixture
                .pointer(ptr)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("missing fixture field {ptr}"));
            hex::decode(s).expect("fixture hex decodes")
        };

        // 1. The TS-signed DataItem verifies in Rust (deep hash + RSA-PSS).
        let raw = hex_field("/data_item/raw_hex");
        let verified = verify_data_item(&raw).expect("DataItem parses + key loads");
        assert!(verified.valid, "TS-signed DataItem must verify in Rust");
        assert_eq!(
            verified.id.as_str(),
            fixture["data_item"]["id"].as_str().unwrap(),
            "DataItem id (base64url SHA-256(signature)) must match across impls"
        );
        assert_eq!(verified.id_raw.to_vec(), hex_field("/data_item/id_raw_hex"));
        assert_eq!(
            verified.owner_address.to_vec(),
            hex_field("/data_item/owner_address_hex"),
            "Arweave owner address SHA-256(modulus) must match"
        );
        assert_eq!(verified.data, hex_field("/data_item/data_hex"));

        // A flipped payload byte must break verification (raw is unused after).
        let mut tampered = raw;
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(
            !verify_data_item(&tampered).expect("still parses").valid,
            "a tampered DataItem must not verify"
        );

        // 2. The payload is an AnchorBundle whose STH commits the tree.
        let anchor = AnchorBundle::from_cbor(&verified.data).expect("payload is an AnchorBundle");
        let sth = SignedTreeHead::from_cbor(anchor.sth()).expect("AnchorBundle carries an STH");
        assert_eq!(sth.root().to_vec(), hex_field("/tree/committed_root_hex"));
        assert_eq!(sth.size(), fixture["tree"]["size"].as_u64().unwrap());

        // 3. The committed inclusion proof verifies and points back at this anchor.
        let proof = InclusionProof::from_cbor(&hex_field("/inclusion_proof/proof_cbor_hex"))
            .expect("inclusion proof parses");
        assert!(proof.verify_root(), "inclusion proof Merkle leg must hold");
        assert_eq!(proof.root().to_vec(), hex_field("/tree/committed_root_hex"));
        assert_eq!(proof.anchor().txid().to_vec(), verified.id_raw.to_vec());
        assert_eq!(
            proof.anchor().log_id().to_vec(),
            LogProfile::qub().log_id().to_vec(),
            "anchor log_id must derive from the pinned anchor_owner"
        );
    }

    #[test]
    fn verify_rejects_garbage_owner_modulus() {
        // sigType(2) + sig(512) + owner(512 zero bytes) + no target/anchor +
        // num_tags(8)=0 + tags_len(8)=0 + empty data. An all-zero modulus is
        // not a valid RSA key, so verification setup fails cleanly.
        let mut raw = vec![1u8, 0];
        raw.extend_from_slice(&[0u8; RSA_SIGNATURE_LEN]);
        raw.extend_from_slice(&[0u8; RSA_OWNER_LEN]);
        raw.push(0x00); // target absent
        raw.push(0x00); // anchor absent
        raw.extend_from_slice(&[0u8; 8]); // num_tags
        raw.extend_from_slice(&[0u8; 8]); // tags_len
        assert_eq!(verify_data_item(&raw), Err(Ans104Error::BadOwnerModulus));
    }
}
