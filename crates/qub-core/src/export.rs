//! Portable `.qub` verification bundle (W7 / UP-C2).
//!
//! A `.qub` bundle is a self-contained, canonical-CBOR container that lets a
//! third party verify a revealed qub's timing and authorship **offline** — no
//! qub infrastructure, no Arweave fetch, no live drand call. It carries the
//! inner [`SealedQubCbor`] bytes plus the drand round signature that unlocks
//! them, so [`crate::unlock::unlock`] can run end-to-end against the bundle
//! alone.
//!
//! The bundle is not an Arweave wire object; it is an export / interchange
//! envelope. It still uses the project's hand-written canonical CBOR (never
//! `serde`, per `CLAUDE.md`) so two conforming implementations agree
//! byte-for-byte.
//!
//! # Why the embedded signature is sufficient
//!
//! Timelock decryption (tlock over drand quicknet) can only succeed with the
//! genuine drand beacon signature for the bound round — a value drand
//! publishes only once that round elapses. A forged signature is not a valid
//! BLS signature under the chain public key, so the IBE/AEAD step fails. The
//! presence of a signature that *decrypts* the ciphertext is therefore itself
//! proof that the bound round elapsed: the round must have elapsed for the
//! bundle to verify. Proving that the ciphertext existed by a particular time
//! additionally requires independently verified storage inclusion or a
//! transparency-log anchor.
//! No network round-trip is required to establish "this content was locked to
//! round R and round R has passed."
//!
//! # Forward-compatible inclusion proof
//!
//! [`QubBundle::inclusion_proof`] is an optional slot for the Merkle inclusion
//! proof emitted by the transparency log (W5). Bundle-only verification works
//! without it; once the log lands, populated proofs let a verifier additionally
//! confirm the qub was anchored, without changing the bundle format version.

use ciborium::Value;
use thiserror::Error;

use crate::cbor::{
    CborError, ParsedMap, assert_canonical_key_order, encode_map, extract_bytes_bounded,
    extract_optional_bytes, extract_optional_i64, extract_text, extract_u8, extract_u64, i64_value,
    parse_top_level_map, reject_structural_elements_in_map, reject_unknown_keys, text, to_nfc,
    u8_value, u64_value,
};
use crate::log::{InclusionProof, LogError};
use crate::tlock::TimelockProvider;
use crate::types::RevealedQub;
use crate::unlock::{UnlockError, UnlockInput, unlock};
use crate::wire::SealedQubCbor;

/// Current `.qub` bundle format version.
pub const QUB_BUNDLE_VERSION_1: u8 = 1;

/// Maximum size of the embedded sealed CBOR (the inner [`SealedQubCbor`]).
/// The sealed qub's `tlock_ciphertext` is itself capped at 128 KiB; this
/// leaves generous headroom for the surrounding map fields.
const MAX_SEALED_CBOR_SIZE: usize = 256 * 1024;

/// Maximum size of the drand round signature. quicknet (G1, unchained)
/// signatures are 48 bytes; the bound is loose so other chains fit too.
const MAX_SIGNATURE_SIZE: usize = 1024;

/// Maximum size of the optional Merkle inclusion proof (W5 slot).
const MAX_INCLUSION_PROOF_SIZE: usize = 64 * 1024;

/// Canonical key order for the `.qub` bundle map.
///
/// Keys are sorted by encoded byte length (ascending), then lexicographically
/// by byte value for same-length keys — the same rule the [`crate::cbor`]
/// serialisers follow. The three 15-byte keys order `d` < `i` < `s`.
const BUNDLE_KEYS_CANONICAL: &[&str] = &[
    "version",         // 7
    "sealed_at",       // 9  (optional)
    "drand_round",     // 11
    "arweave_tx_id",   // 13
    "drand_chain_id",  // 14
    "drand_signature", // 15
    "inclusion_proof", // 15 (optional)
    "sealed_qub_cbor", // 15
];

/// Errors produced when building, encoding, or decoding a [`QubBundle`].
///
/// `#[non_exhaustive]`: match arms must include a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ExportError {
    /// Canonical CBOR encoding / decoding of the bundle map failed.
    #[error("bundle CBOR error: {0}")]
    Cbor(#[from] CborError),

    /// The typed transparency-log inclusion proof carried in the
    /// `inclusion_proof` slot failed to encode or decode (W5 / §16.9).
    #[error("inclusion proof error: {0}")]
    InclusionProof(#[from] LogError),

    /// The bundle's version byte is not a supported value.
    #[error("unsupported .qub bundle version: {0}")]
    UnsupportedVersion(u8),

    /// The embedded sealed CBOR is not a valid [`SealedQubCbor`].
    #[error("embedded sealed CBOR is invalid: {0}")]
    SealedCbor(CborError),

    /// The drand round signature was empty.
    #[error("drand round signature is empty")]
    EmptySignature,

    /// The Arweave transaction id was empty.
    #[error("arweave_tx_id is empty")]
    EmptyTxId,

    /// A top-level convenience field disagrees with the embedded sealed qub
    /// (a tampered or malformed bundle).
    #[error("bundle field {0} disagrees with the embedded sealed qub")]
    Inconsistent(&'static str),

    /// A variable-length field exceeded its maximum allowed size.
    #[error("{field} exceeds maximum size: {size} bytes > {max} bytes")]
    FieldTooLarge {
        /// Name of the field.
        field: &'static str,
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },
}

/// A self-contained, offline-verifiable `.qub` bundle.
///
/// `drand_round` and `drand_chain_id` are projections of the embedded
/// [`SealedQubCbor`], carried at the top level so tooling can read them without
/// parsing the inner CBOR. They are derived (never independently set) by
/// [`QubBundle::new`], and [`QubBundle::from_cbor`] re-checks them against the
/// parsed sealed qub — a tampered top-level field is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QubBundle {
    version: u8,
    sealed_cbor: SealedQubCbor,
    drand_round: u64,
    drand_chain_id: String,
    drand_signature: Vec<u8>,
    arweave_tx_id: String,
    sealed_at: Option<i64>,
    inclusion_proof: Option<Vec<u8>>,
}

impl QubBundle {
    /// Builds a bundle from a sealed qub, the drand round signature that
    /// unlocks it, and the Arweave transaction id it was stored under.
    ///
    /// `drand_round` and `drand_chain_id` are read from `sealed_cbor` so the
    /// bundle's convenience fields cannot disagree with its payload.
    ///
    /// # Errors
    ///
    /// - [`ExportError::SealedCbor`] if `sealed_cbor` does not parse.
    /// - [`ExportError::EmptySignature`] if `drand_signature` is empty.
    /// - [`ExportError::EmptyTxId`] if `arweave_tx_id` is empty.
    pub fn new(
        sealed_cbor: SealedQubCbor,
        drand_signature: Vec<u8>,
        arweave_tx_id: String,
    ) -> Result<Self, ExportError> {
        if drand_signature.is_empty() {
            return Err(ExportError::EmptySignature);
        }
        if arweave_tx_id.is_empty() {
            return Err(ExportError::EmptyTxId);
        }
        let sealed = sealed_cbor.parse().map_err(ExportError::SealedCbor)?;
        Ok(Self {
            version: QUB_BUNDLE_VERSION_1,
            drand_round: sealed.drand_round(),
            drand_chain_id: sealed.drand_chain_id().to_owned(),
            sealed_cbor,
            drand_signature,
            arweave_tx_id,
            sealed_at: None,
            inclusion_proof: None,
        })
    }

    /// Sets the optional sealed-at timestamp (Unix seconds), returning `self`.
    #[must_use]
    pub const fn with_sealed_at(mut self, sealed_at: Option<i64>) -> Self {
        self.sealed_at = sealed_at;
        self
    }

    /// Sets the optional Merkle inclusion proof (W5), returning `self`.
    ///
    /// The 64 KiB decode cap is enforced at [`Self::to_cbor`] — an
    /// oversized proof fails the *encode*, not the eventual read on
    /// another device.
    #[must_use]
    pub fn with_inclusion_proof(mut self, inclusion_proof: Option<Vec<u8>>) -> Self {
        self.inclusion_proof = inclusion_proof;
        self
    }

    /// Sets the optional Merkle inclusion proof from a **typed**
    /// [`InclusionProof`] (W5 / §16.9), serialising it into the opaque
    /// `inclusion_proof` slot.
    ///
    /// The slot remains an opaque `bstr` on the wire (§17.5): a worker-served
    /// (TypeScript) proof and a qub-core (Rust) proof share byte-identical
    /// canonical CBOR, so this changes **no** bundle-format version — it only
    /// saves the caller a manual [`InclusionProof::to_cbor`]. The dual
    /// [`Self::inclusion_proof_typed`] parses it back.
    ///
    /// # Errors
    ///
    /// [`ExportError::InclusionProof`] if the proof fails to encode.
    pub fn with_inclusion_proof_typed(
        mut self,
        proof: &InclusionProof,
    ) -> Result<Self, ExportError> {
        self.inclusion_proof = Some(proof.to_cbor()?);
        Ok(self)
    }

    /// The bundle format version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// The embedded sealed qub in canonical CBOR wire form.
    #[must_use]
    pub const fn sealed_cbor(&self) -> &SealedQubCbor {
        &self.sealed_cbor
    }

    /// The drand round the qub is locked to.
    #[must_use]
    pub const fn drand_round(&self) -> u64 {
        self.drand_round
    }

    /// The drand chain identifier (hex).
    #[must_use]
    pub fn drand_chain_id(&self) -> &str {
        &self.drand_chain_id
    }

    /// The drand round signature that unlocks the qub.
    #[must_use]
    pub fn drand_signature(&self) -> &[u8] {
        &self.drand_signature
    }

    /// The Arweave transaction id the sealed bytes were stored under.
    #[must_use]
    pub fn arweave_tx_id(&self) -> &str {
        &self.arweave_tx_id
    }

    /// The optional sealed-at timestamp (Unix seconds).
    #[must_use]
    pub const fn sealed_at(&self) -> Option<i64> {
        self.sealed_at
    }

    /// The optional Merkle inclusion proof (W5) as raw opaque bytes.
    #[must_use]
    pub fn inclusion_proof(&self) -> Option<&[u8]> {
        self.inclusion_proof.as_deref()
    }

    /// Parses the optional Merkle inclusion proof as a **typed**
    /// [`InclusionProof`] (W5 / §16.9).
    ///
    /// Returns `Ok(None)` when the bundle carries no proof, `Ok(Some(proof))`
    /// when the slot holds a well-formed proof, and
    /// [`ExportError::InclusionProof`] when a proof is present but malformed —
    /// the three states a standalone verifier must distinguish (§17.5: an
    /// *absent* proof is "not anchored", never "invalid"; a *present but broken*
    /// proof is a genuine integrity signal).
    ///
    /// # Errors
    ///
    /// [`ExportError::InclusionProof`] if a present proof fails to decode.
    pub fn inclusion_proof_typed(&self) -> Result<Option<InclusionProof>, ExportError> {
        match &self.inclusion_proof {
            None => Ok(None),
            Some(bytes) => Ok(Some(InclusionProof::from_cbor(bytes)?)),
        }
    }

    /// Serialises the bundle to canonical CBOR bytes — the raw `.qub` file.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError::Cbor`] if the underlying CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ExportError> {
        let mut map: Vec<(Value, Value)> = Vec::with_capacity(BUNDLE_KEYS_CANONICAL.len());
        let mut keys_used: Vec<&str> = Vec::with_capacity(BUNDLE_KEYS_CANONICAL.len());

        map.push((text("version"), u8_value(self.version)));
        keys_used.push("version");

        if let Some(sealed_at) = self.sealed_at {
            map.push((text("sealed_at"), i64_value(sealed_at)));
            keys_used.push("sealed_at");
        }

        map.push((text("drand_round"), u64_value(self.drand_round)));
        keys_used.push("drand_round");

        map.push((
            text("arweave_tx_id"),
            Value::Text(to_nfc(&self.arweave_tx_id)),
        ));
        keys_used.push("arweave_tx_id");

        map.push((
            text("drand_chain_id"),
            Value::Text(to_nfc(&self.drand_chain_id)),
        ));
        keys_used.push("drand_chain_id");

        map.push((
            text("drand_signature"),
            Value::Bytes(self.drand_signature.clone()),
        ));
        keys_used.push("drand_signature");

        if let Some(proof) = &self.inclusion_proof {
            // Enforce the decode-side cap at encode: an oversized proof
            // would otherwise serialise and store, then fail
            // `from_cbor` on the reading device.
            if proof.len() > MAX_INCLUSION_PROOF_SIZE {
                return Err(ExportError::Cbor(CborError::PayloadTooLarge {
                    field: "inclusion_proof",
                    size: proof.len(),
                    max: MAX_INCLUSION_PROOF_SIZE,
                }));
            }
            map.push((text("inclusion_proof"), Value::Bytes(proof.clone())));
            keys_used.push("inclusion_proof");
        }

        map.push((
            text("sealed_qub_cbor"),
            Value::Bytes(self.sealed_cbor.as_bytes().to_vec()),
        ));
        keys_used.push("sealed_qub_cbor");

        assert_canonical_key_order(&keys_used);

        Ok(encode_map(map)?)
    }

    /// Parses a `.qub` bundle from canonical CBOR bytes.
    ///
    /// Applies the same structural discipline as the rest of the wire format
    /// (canonical encoding, no tags/floats, no duplicate keys), bounds every
    /// variable-length field, and re-checks the top-level `drand_round` /
    /// `drand_chain_id` against the embedded sealed qub.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`ExportError`] for a missing/oversized field,
    /// an unsupported version, an invalid embedded sealed qub, or a top-level
    /// field that disagrees with the sealed payload.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ExportError> {
        let map: ParsedMap = parse_top_level_map(bytes)?;
        reject_structural_elements_in_map(&map)?;
        reject_unknown_keys(&map, BUNDLE_KEYS_CANONICAL, "QubBundle")?;

        let version = extract_u8(&map, "version")?;
        if version != QUB_BUNDLE_VERSION_1 {
            return Err(ExportError::UnsupportedVersion(version));
        }

        let sealed_bytes = extract_bytes_bounded(&map, "sealed_qub_cbor", MAX_SEALED_CBOR_SIZE)?;
        let sealed_cbor =
            SealedQubCbor::from_encoded(sealed_bytes).map_err(ExportError::SealedCbor)?;
        let sealed = sealed_cbor.parse().map_err(ExportError::SealedCbor)?;

        let drand_round = extract_u64(&map, "drand_round")?;
        let drand_chain_id = extract_text(&map, "drand_chain_id")?;
        let drand_signature = extract_bytes_bounded(&map, "drand_signature", MAX_SIGNATURE_SIZE)?;
        if drand_signature.is_empty() {
            return Err(ExportError::EmptySignature);
        }

        let arweave_tx_id = extract_text(&map, "arweave_tx_id")?;
        if arweave_tx_id.is_empty() {
            return Err(ExportError::EmptyTxId);
        }

        let sealed_at = extract_optional_i64(&map, "sealed_at")?;

        let inclusion_proof = extract_optional_bytes(&map, "inclusion_proof")?;
        if let Some(proof) = inclusion_proof.as_ref()
            && proof.len() > MAX_INCLUSION_PROOF_SIZE
        {
            return Err(ExportError::FieldTooLarge {
                field: "inclusion_proof",
                size: proof.len(),
                max: MAX_INCLUSION_PROOF_SIZE,
            });
        }

        // Defence in depth: the top-level convenience fields must match the
        // payload they describe, so a hand-edited bundle cannot claim a
        // different round/chain than the bytes it actually carries.
        if sealed.drand_round() != drand_round {
            return Err(ExportError::Inconsistent("drand_round"));
        }
        if sealed.drand_chain_id() != drand_chain_id {
            return Err(ExportError::Inconsistent("drand_chain_id"));
        }

        Ok(Self {
            version,
            sealed_cbor,
            drand_round,
            drand_chain_id,
            drand_signature,
            arweave_tx_id,
            sealed_at,
            inclusion_proof,
        })
    }

    /// Verifies the bundle by driving the standard unlock path with the
    /// embedded signature — the offline equivalent of opening the qub.
    ///
    /// On success the returned [`RevealedQub`] carries the recovered body plus
    /// every verification verdict (`body_hash_verified`, `signature_verified`,
    /// `cosigner_verified`) and timing fields the caller reports.
    ///
    /// # Errors
    ///
    /// Propagates any [`UnlockError`] from [`crate::unlock::unlock`] — a still
    /// locked qub (`now < unlock_at`), a body-hash mismatch, a round/chain
    /// binding failure, or a tlock decryption failure (e.g. a wrong or forged
    /// signature).
    pub fn open(
        &self,
        now: i64,
        chain_genesis_time: i64,
        chain_period_seconds: u64,
        tlock: &dyn TimelockProvider,
    ) -> Result<RevealedQub, UnlockError> {
        unlock(UnlockInput {
            sealed_cbor: &self.sealed_cbor,
            round_signature: &self.drand_signature,
            now,
            chain_genesis_time,
            chain_period_seconds,
            arweave_tx_id: self.arweave_tx_id.clone(),
            tlock,
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PROTOCOL_VERSION_1, SealedQubBuilder, VISIBILITY_PUBLIC};

    fn sample_sealed_cbor() -> SealedQubCbor {
        let sealed = SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id([5u8; 32])
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(1_800_000_000)
            .drand_chain_id("52db9ba7".into())
            .drand_round(1_234_567)
            .tlock_ciphertext(vec![0xAB, 0xCD, 0xEF])
            .build()
            .unwrap();
        SealedQubCbor::from_sealed_qub(&sealed).unwrap()
    }

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

    #[test]
    fn bundle_canonical_order_is_sorted() {
        assert_canonical_key_order(BUNDLE_KEYS_CANONICAL);
    }

    /// Accessor read-back for `QubBundle`. `drand_signature` and
    /// `version` were `FnValue` survivors: the bundle is exercised
    /// through its CBOR round-trip, which compares whole structs and so
    /// never observes an individual getter returning a constant.
    ///
    /// The signature bytes are deliberately more than one byte and not
    /// all-zero, because `vec![]`, `vec![0]` and `vec![1]` are exactly
    /// the replacements a mutant substitutes.
    /// Length-bound boundary, pinned from both sides. `>` → `>=` is
    /// invisible unless something of EXACTLY the limit is accepted, and
    /// `>` → `==` is invisible unless something strictly larger is
    /// rejected. Neither case existed here.
    ///
    /// The same cap is enforced twice — at encode, so an oversized proof
    /// cannot be written, and at decode, so one cannot be read back — and
    /// both sites were unpinned.
    /// The size CONSTANTS themselves were mutable without detection —
    /// `256 * 1024` to `256 + 1024`, `64 * 1024` to `64 + 1024` — which
    /// collapses a 256 KiB limit to 1,280 bytes and a 64 KiB limit to
    /// 1,088.
    ///
    /// The boundary test beside this one CANNOT catch that, and the
    /// reason is worth internalising: it is written in terms of the
    /// constant, so when the constant shrinks the test shrinks with it and
    /// still passes. Pinning a limit requires at least one assertion
    /// phrased in CONCRETE units that the limit must accommodate.
    ///
    /// 4 KiB is used for both: comfortably inside the real limits and
    /// comfortably outside the collapsed ones.
    #[test]
    fn realistic_payloads_fit_the_size_limits() {
        let big_sealed = {
            let sealed = SealedQubBuilder::new()
                .version(PROTOCOL_VERSION_1)
                .qub_id([5u8; 32])
                .visibility(VISIBILITY_PUBLIC)
                .unlock_at(1_800_000_000)
                .drand_chain_id("52db9ba7".into())
                .drand_round(1_234_567)
                .tlock_ciphertext(vec![0xAB; 4096])
                .build()
                .unwrap();
            SealedQubCbor::from_sealed_qub(&sealed).unwrap()
        };
        assert!(
            big_sealed.len() > 4000,
            "sample must exceed the collapsed limit"
        );

        let bundle = QubBundle::new(big_sealed, vec![0xDE, 0xAD], "tx".to_owned())
            .unwrap()
            .with_inclusion_proof(Some(vec![0u8; 4096]));

        let encoded = bundle.to_cbor().expect("a 4 KiB proof must encode");
        QubBundle::from_cbor(&encoded).expect("a 4 KiB proof and a 4 KiB sealed qub must decode");
    }

    #[test]
    fn inclusion_proof_cap_is_pinned_at_encode_and_decode() {
        let bundle = |n: usize| {
            QubBundle::new(sample_sealed_cbor(), vec![0xDE, 0xAD], "tx".to_owned())
                .unwrap()
                .with_inclusion_proof(Some(vec![0u8; n]))
        };

        // Encode side: exactly the cap is legal, one over is refused.
        let encoded = bundle(MAX_INCLUSION_PROOF_SIZE)
            .to_cbor()
            .expect("a proof of exactly the cap must encode");
        assert!(matches!(
            bundle(MAX_INCLUSION_PROOF_SIZE + 1).to_cbor(),
            Err(ExportError::Cbor(CborError::PayloadTooLarge { .. }))
        ));

        // Decode side: the bytes just produced must read back.
        QubBundle::from_cbor(&encoded).expect("a proof of exactly the cap must decode");
    }

    #[test]
    fn bundle_accessors_read_back_what_was_constructed() {
        let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let bundle =
            QubBundle::new(sample_sealed_cbor(), sig.clone(), "tx-id-value".to_owned()).unwrap();
        assert_eq!(bundle.version(), QUB_BUNDLE_VERSION_1);
        assert_eq!(bundle.drand_signature(), sig.as_slice());
    }

    #[test]
    fn new_derives_round_and_chain_from_sealed() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1, 2, 3], "tx-abc".into()).unwrap();
        assert_eq!(bundle.version(), QUB_BUNDLE_VERSION_1);
        assert_eq!(bundle.drand_round(), 1_234_567);
        assert_eq!(bundle.drand_chain_id(), "52db9ba7");
        assert_eq!(bundle.arweave_tx_id(), "tx-abc");
        assert_eq!(bundle.sealed_at(), None);
        assert_eq!(bundle.inclusion_proof(), None);
    }

    #[test]
    fn roundtrip_minimal() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![9, 9, 9], "tx-min".into()).unwrap();
        let bytes = bundle.to_cbor().unwrap();
        let back = QubBundle::from_cbor(&bytes).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn roundtrip_full() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![7; 48], "tx-full".into())
            .unwrap()
            .with_sealed_at(Some(1_700_000_000))
            .with_inclusion_proof(Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        let bytes = bundle.to_cbor().unwrap();
        let back = QubBundle::from_cbor(&bytes).unwrap();
        assert_eq!(bundle, back);
        assert_eq!(back.sealed_at(), Some(1_700_000_000));
        assert_eq!(back.inclusion_proof(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn determinism() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1, 2, 3], "tx".into()).unwrap();
        assert_eq!(bundle.to_cbor().unwrap(), bundle.to_cbor().unwrap());
    }

    #[test]
    fn emitted_key_order_minimal() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1], "tx".into()).unwrap();
        let bytes = bundle.to_cbor().unwrap();
        assert_eq!(
            parsed_keys(&bytes),
            vec![
                "version",
                "drand_round",
                "arweave_tx_id",
                "drand_chain_id",
                "drand_signature",
                "sealed_qub_cbor",
            ]
        );
    }

    #[test]
    fn emitted_key_order_full() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1], "tx".into())
            .unwrap()
            .with_sealed_at(Some(42))
            .with_inclusion_proof(Some(vec![1, 2]));
        let bytes = bundle.to_cbor().unwrap();
        assert_eq!(parsed_keys(&bytes), BUNDLE_KEYS_CANONICAL.to_vec());
    }

    #[test]
    fn empty_signature_rejected() {
        let err = QubBundle::new(sample_sealed_cbor(), vec![], "tx".into()).unwrap_err();
        assert_eq!(err, ExportError::EmptySignature);
    }

    #[test]
    fn empty_tx_id_rejected() {
        let err = QubBundle::new(sample_sealed_cbor(), vec![1], String::new()).unwrap_err();
        assert_eq!(err, ExportError::EmptyTxId);
    }

    #[test]
    fn unsupported_version_rejected() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1], "tx".into()).unwrap();
        let mut bundle = bundle;
        bundle.version = 99;
        let bytes = bundle.to_cbor().unwrap();
        let err = QubBundle::from_cbor(&bytes).unwrap_err();
        assert_eq!(err, ExportError::UnsupportedVersion(99));
    }

    #[test]
    fn tampered_round_rejected() {
        // Hand-build a bundle whose top-level drand_round disagrees with the
        // sealed payload (1_234_567), and confirm from_cbor rejects it.
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1], "tx".into()).unwrap();
        let mut bundle = bundle;
        bundle.drand_round = 999;
        let bytes = bundle.to_cbor().unwrap();
        let err = QubBundle::from_cbor(&bytes).unwrap_err();
        assert_eq!(err, ExportError::Inconsistent("drand_round"));
    }

    #[test]
    fn garbage_bytes_rejected() {
        assert!(matches!(
            QubBundle::from_cbor(&[0xFF, 0xFF, 0xFF]),
            Err(ExportError::Cbor(_))
        ));
    }

    // ---- typed inclusion proof through the opaque slot (§17.5) ----

    /// Builds a real 5-leaf tree and a verifying inclusion proof for leaf 2.
    fn sample_inclusion_proof() -> InclusionProof {
        use crate::log::{AnchorRef, LogLeaf, LogProfile};
        use crate::merkle;

        let leaf_cbors: Vec<Vec<u8>> = (0u8..5)
            .map(|i| {
                LogLeaf::asserted(
                    u64::from(i),
                    [i + 1; 32],
                    [i + 100; 32],
                    1_800_000_000,
                    1_700_000_000,
                )
                .unwrap()
                .to_cbor()
                .unwrap()
            })
            .collect();
        let leaf_hashes: Vec<[u8; 32]> = leaf_cbors.iter().map(|c| merkle::leaf_hash(c)).collect();
        let root = merkle::merkle_root(&leaf_hashes);
        let audit = merkle::inclusion_proof(2, &leaf_hashes).unwrap();
        let anchor = AnchorRef::new(
            [0x66; 32],
            2,
            [0x77; 32],
            LogProfile::qub().log_id(),
            None,
            None,
        );
        InclusionProof::new(leaf_cbors[2].clone(), 2, 5, audit, root, anchor)
    }

    #[test]
    fn typed_inclusion_proof_round_trips_through_slot() {
        let proof = sample_inclusion_proof();
        assert!(proof.verify_root());

        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1, 2, 3], "tx".into())
            .unwrap()
            .with_inclusion_proof_typed(&proof)
            .unwrap();

        // The opaque slot holds exactly the proof's own canonical CBOR.
        assert_eq!(
            bundle.inclusion_proof(),
            Some(proof.to_cbor().unwrap().as_slice())
        );

        // Survives a full bundle encode/decode and parses back identically.
        let bytes = bundle.to_cbor().unwrap();
        let back = QubBundle::from_cbor(&bytes).unwrap();
        let recovered = back.inclusion_proof_typed().unwrap().unwrap();
        assert_eq!(recovered, proof);
        assert!(recovered.verify_root());
    }

    #[test]
    fn inclusion_proof_typed_none_when_absent() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1], "tx".into()).unwrap();
        assert!(bundle.inclusion_proof_typed().unwrap().is_none());
    }

    #[test]
    fn inclusion_proof_typed_rejects_malformed_slot() {
        let bundle = QubBundle::new(sample_sealed_cbor(), vec![1], "tx".into())
            .unwrap()
            .with_inclusion_proof(Some(vec![0xFF, 0xFF, 0xFF]));
        assert!(matches!(
            bundle.inclusion_proof_typed(),
            Err(ExportError::InclusionProof(_))
        ));
    }
}
