//! Wire-format newtypes for canonical CBOR bytes of protocol artifacts.
//!
//! These newtypes provide compile-time safety around the canonical CBOR
//! encoding of [`SealedQub`] and [`QubEnvelope`] values. They exist to
//! prevent accidental confusion between CBOR-encoded bytes and raw bytes,
//! JSON, plaintext, or any other byte-oriented representation.
//!
//! Construction is deliberately restricted: there is **no** `From<Vec<u8>>`
//! implementation. Callers must use either [`SealedQubCbor::from_encoded`] /
//! [`QubEnvelopeCbor::from_encoded`] to wrap bytes that were already produced
//! by the canonical serialiser, or the convenience constructors
//! [`SealedQubCbor::from_sealed_qub`] / [`QubEnvelopeCbor::from_qub_envelope`]
//! which serialise a typed value directly.
//!
//! See PROTOCOL.md §5 for the normative specification.
//!
//! # Examples
//!
//! End-to-end: take a typed [`SealedQub`], cross the wire, recover the
//! typed value. The raw bytes would flow over the network or to Arweave
//! in a real deployment.
//!
//! ```
//! use qub_core::types::{SealedQubBuilder, PROTOCOL_VERSION_1, VISIBILITY_PUBLIC};
//! use qub_core::wire::SealedQubCbor;
//!
//! let sealed = SealedQubBuilder::new()
//!     .version(PROTOCOL_VERSION_1)
//!     .qub_id([0x11; 32])
//!     .visibility(VISIBILITY_PUBLIC)
//!     .unlock_at(1_736_294_400)
//!     .drand_chain_id("example-chain".into())
//!     .drand_round(4_675_285)
//!     .tlock_ciphertext(vec![0xAA; 64])
//!     .build()
//!     .unwrap();
//!
//! // Encode once, send the bytes, recover the typed value.
//! let wire = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
//! let raw_bytes: &[u8] = wire.as_bytes();
//! # let _ = raw_bytes; // pretend we wrote this to Arweave
//!
//! let received = SealedQubCbor::from_encoded(wire.into_bytes()).unwrap();
//! assert_eq!(received.parse().unwrap(), sealed);
//! ```

use crate::cbor::{
    CborError, deserialize_qub_envelope, deserialize_sealed_qub, serialize_qub_envelope,
    serialize_sealed_qub,
};
use crate::types::{QubEnvelope, SealedQub};

/// Returns `true` if `byte` is a valid CBOR definite-length map header.
///
/// Canonical CBOR forbids indefinite-length containers, so only the
/// definite-length map headers `0xA0..=0xBB` are accepted here.
pub(crate) const fn is_cbor_map_header(byte: u8) -> bool {
    // 0xA0..=0xB7 → map with 0..=23 pairs (immediate length)
    // 0xB8        → map with 1-byte length
    // 0xB9        → map with 2-byte length
    // 0xBA        → map with 4-byte length
    // 0xBB        → map with 8-byte length
    matches!(byte, 0xA0..=0xBB)
}

/// Canonical CBOR bytes of a [`SealedQub`].
///
/// Constructed only through CBOR serialisation — there is deliberately no
/// `From<Vec<u8>>` implementation. See the [module documentation](self) for
/// construction rules.
///
/// # Examples
///
/// Round-trip: serialise a typed value, inspect the bytes, parse back:
///
/// ```
/// use qub_core::types::{SealedQubBuilder, PROTOCOL_VERSION_1, VISIBILITY_PUBLIC};
/// use qub_core::wire::SealedQubCbor;
///
/// let sealed = SealedQubBuilder::new()
///     .version(PROTOCOL_VERSION_1)
///     .qub_id([0x11; 32])
///     .visibility(VISIBILITY_PUBLIC)
///     .unlock_at(1_736_294_400)
///     .drand_chain_id("example-chain".into())
///     .drand_round(4_675_285)
///     .tlock_ciphertext(vec![0xAA; 64])
///     .build()
///     .unwrap();
///
/// let wire = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
/// assert!(!wire.is_empty());
/// assert_eq!(wire.len(), wire.as_bytes().len());
///
/// // parse() recovers the original typed value.
/// assert_eq!(wire.parse().unwrap(), sealed);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedQubCbor(Vec<u8>);

impl SealedQubCbor {
    /// Wraps CBOR bytes that have been produced by [`serialize_sealed_qub`].
    ///
    /// Performs a lightweight structural check: the input must be non-empty
    /// and its first byte must be a valid CBOR definite-length map header.
    /// Full structural validation (field presence, types, canonicalisation)
    /// happens at parse time via [`Self::parse`].
    ///
    /// # Errors
    ///
    /// Returns [`CborError::NotAMap`] if `bytes` is empty or does not begin
    /// with a CBOR map header.
    ///
    /// # Examples
    ///
    /// ```
    /// use qub_core::cbor::CborError;
    /// use qub_core::wire::SealedQubCbor;
    ///
    /// // Empty input rejected.
    /// assert!(matches!(
    ///     SealedQubCbor::from_encoded(vec![]),
    ///     Err(CborError::NotAMap),
    /// ));
    ///
    /// // Non-map first byte rejected (0x01 is a CBOR unsigned integer).
    /// assert!(matches!(
    ///     SealedQubCbor::from_encoded(vec![0x01, 0x02]),
    ///     Err(CborError::NotAMap),
    /// ));
    ///
    /// // Indefinite-length map header (0xBF) is forbidden by canonical CBOR.
    /// assert!(matches!(
    ///     SealedQubCbor::from_encoded(vec![0xBF]),
    ///     Err(CborError::NotAMap),
    /// ));
    ///
    /// // An empty definite-length map (0xA0) passes the structural check
    /// // but will fail at parse time because required fields are absent.
    /// let wire = SealedQubCbor::from_encoded(vec![0xA0]).unwrap();
    /// assert!(wire.parse().is_err());
    /// ```
    pub fn from_encoded(bytes: Vec<u8>) -> Result<Self, CborError> {
        match bytes.first() {
            Some(&b) if is_cbor_map_header(b) => Ok(Self(bytes)),
            _ => Err(CborError::NotAMap),
        }
    }

    /// Serialises a [`SealedQub`] to its canonical CBOR wire format.
    ///
    /// # Errors
    ///
    /// Propagates any [`CborError`] raised by [`serialize_sealed_qub`].
    pub fn from_sealed_qub(sealed: &SealedQub) -> Result<Self, CborError> {
        let bytes = serialize_sealed_qub(sealed)?;
        Ok(Self(bytes))
    }

    /// Parses these CBOR bytes back into a [`SealedQub`].
    ///
    /// # Errors
    ///
    /// Propagates any [`CborError`] raised by [`deserialize_sealed_qub`].
    pub fn parse(&self) -> Result<SealedQub, CborError> {
        deserialize_sealed_qub(&self.0)
    }

    /// Returns the raw CBOR bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consumes the wrapper and returns the raw CBOR bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length of the CBOR bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the CBOR bytes are empty.
    ///
    /// This is always `false` for values produced via [`Self::from_encoded`]
    /// or [`Self::from_sealed_qub`]; it exists purely as the conventional
    /// companion to [`Self::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Canonical CBOR bytes of a [`QubEnvelope`].
///
/// Constructed only through CBOR serialisation — there is deliberately no
/// `From<Vec<u8>>` implementation. See the [module documentation](self) for
/// construction rules.
///
/// # Examples
///
/// Round-trip a full envelope via the wire-format newtype:
///
/// ```
/// use qub_core::hash::derive_envelope_hashes;
/// use qub_core::types::{QubEnvelopeBuilder, CONTENT_TYPE_TEXT, PROTOCOL_VERSION_1};
/// use qub_core::wire::QubEnvelopeCbor;
///
/// let body = b"Hello, future.".to_vec();
/// let (body_hash, qub_id) = derive_envelope_hashes(
///     PROTOCOL_VERSION_1,
///     CONTENT_TYPE_TEXT,
///     1_735_689_600,
///     1_736_294_400,
///     None, // outcome_at
///     4_695_445, // drand_round
///     &body,
///     None, // title
/// );
/// let envelope = QubEnvelopeBuilder::new()
///     .version(PROTOCOL_VERSION_1)
///     .qub_id(qub_id)
///     .content_type(CONTENT_TYPE_TEXT)
///     .created_at(1_735_689_600)
///     .unlock_at(1_736_294_400)
///     .body(body)
///     .body_hash(body_hash)
///     .build()
///     .unwrap();
///
/// let wire = QubEnvelopeCbor::from_qub_envelope(&envelope).unwrap();
/// assert_eq!(wire.parse().unwrap(), envelope);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QubEnvelopeCbor(Vec<u8>);

impl QubEnvelopeCbor {
    /// Wraps CBOR bytes that have been produced by [`serialize_qub_envelope`].
    ///
    /// Performs a lightweight structural check: the input must be non-empty
    /// and its first byte must be a valid CBOR definite-length map header.
    /// Full structural validation (field presence, types, canonicalisation)
    /// happens at parse time via [`Self::parse`].
    ///
    /// # Errors
    ///
    /// Returns [`CborError::NotAMap`] if `bytes` is empty or does not begin
    /// with a CBOR map header.
    ///
    /// # Examples
    ///
    /// ```
    /// use qub_core::cbor::CborError;
    /// use qub_core::wire::QubEnvelopeCbor;
    ///
    /// // Non-map input is rejected at construction time.
    /// assert!(matches!(
    ///     QubEnvelopeCbor::from_encoded(vec![]),
    ///     Err(CborError::NotAMap),
    /// ));
    /// assert!(matches!(
    ///     QubEnvelopeCbor::from_encoded(vec![0x01, 0x02]),
    ///     Err(CborError::NotAMap),
    /// ));
    /// ```
    pub fn from_encoded(bytes: Vec<u8>) -> Result<Self, CborError> {
        match bytes.first() {
            Some(&b) if is_cbor_map_header(b) => Ok(Self(bytes)),
            _ => Err(CborError::NotAMap),
        }
    }

    /// Serialises a [`QubEnvelope`] to its canonical CBOR wire format.
    ///
    /// # Errors
    ///
    /// Propagates any [`CborError`] raised by [`serialize_qub_envelope`].
    pub fn from_qub_envelope(envelope: &QubEnvelope) -> Result<Self, CborError> {
        let bytes = serialize_qub_envelope(envelope)?;
        Ok(Self(bytes))
    }

    /// Parses these CBOR bytes back into a [`QubEnvelope`].
    ///
    /// # Errors
    ///
    /// Propagates any [`CborError`] raised by [`deserialize_qub_envelope`].
    pub fn parse(&self) -> Result<QubEnvelope, CborError> {
        deserialize_qub_envelope(&self.0)
    }

    /// Returns the raw CBOR bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consumes the wrapper and returns the raw CBOR bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length of the CBOR bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the CBOR bytes are empty.
    ///
    /// This is always `false` for values produced via [`Self::from_encoded`]
    /// or [`Self::from_qub_envelope`]; it exists purely as the conventional
    /// companion to [`Self::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::derive_envelope_hashes;
    use crate::types::{
        CONTENT_TYPE_TEXT, PROTOCOL_VERSION_1, QubEnvelopeBuilder, SealedQubBuilder,
        VISIBILITY_PUBLIC,
    };

    fn sample_envelope() -> QubEnvelope {
        let body = b"Hello, future.".to_vec();
        let (body_hash, qub_id) = derive_envelope_hashes(
            PROTOCOL_VERSION_1,
            CONTENT_TYPE_TEXT,
            1_735_689_600,
            1_736_294_400,
            None,
            4_695_445,
            &body,
            None,
        );
        QubEnvelopeBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(qub_id)
            .content_type(CONTENT_TYPE_TEXT)
            .created_at(1_735_689_600)
            .unlock_at(1_736_294_400)
            .body(body)
            .body_hash(body_hash)
            .build()
            .expect("valid envelope")
    }

    fn sample_sealed() -> SealedQub {
        let env = sample_envelope();
        SealedQubBuilder::new()
            .version(PROTOCOL_VERSION_1)
            .qub_id(*env.qub_id())
            .visibility(VISIBILITY_PUBLIC)
            .unlock_at(env.unlock_at())
            .drand_chain_id("a".repeat(64))
            .drand_round(4_675_285)
            .tlock_ciphertext(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .build()
            .expect("valid sealed")
    }

    /// Accessor read-back on the CBOR wire newtype.
    ///
    /// These four projections — `as_bytes`, `into_bytes`, `len`,
    /// `is_empty` — accounted for a large share of this repository's 230
    /// surviving mutants, and always for the same reason: the newtypes
    /// are exercised end-to-end through `from_*` / `parse`, but a
    /// round-trip compares whole values and never asks a getter what it
    /// returns. Each could be replaced by `vec![]`, `0`, `1` or `true`
    /// with the suite still green.
    ///
    /// The `len() > 1` assertion is load-bearing rather than decorative:
    /// `0` and `1` are the two constants a mutant substitutes, so a
    /// sample shorter than two bytes would prove nothing.
    #[test]
    fn wire_newtype_accessors_read_back() {
        let encoded = SealedQubCbor::from_sealed_qub(&sample_sealed()).unwrap();
        let bytes = encoded.as_bytes().to_vec();
        assert!(
            bytes.len() > 1,
            "sample must exceed the 0/1 replacement constants"
        );
        assert_eq!(encoded.len(), bytes.len());
        assert!(!encoded.is_empty());
        assert_eq!(encoded.into_bytes(), bytes);

        let envelope = QubEnvelopeCbor::from_qub_envelope(&sample_envelope()).unwrap();
        let env_bytes = envelope.as_bytes().to_vec();
        assert!(env_bytes.len() > 1);
        assert_eq!(envelope.len(), env_bytes.len());
        assert!(!envelope.is_empty());
        assert_eq!(envelope.into_bytes(), env_bytes);
    }

    #[test]
    fn sealed_cbor_round_trip_via_newtype() {
        let sealed = sample_sealed();
        let encoded = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
        let decoded = encoded.parse().unwrap();
        assert_eq!(sealed, decoded);
    }

    #[test]
    fn envelope_cbor_round_trip_via_newtype() {
        let env = sample_envelope();
        let encoded = QubEnvelopeCbor::from_qub_envelope(&env).unwrap();
        let decoded = encoded.parse().unwrap();
        assert_eq!(env, decoded);
    }

    #[test]
    fn from_encoded_rejects_empty_input() {
        assert!(matches!(
            SealedQubCbor::from_encoded(vec![]),
            Err(CborError::NotAMap)
        ));
        assert!(matches!(
            QubEnvelopeCbor::from_encoded(vec![]),
            Err(CborError::NotAMap)
        ));
    }

    #[test]
    fn from_encoded_rejects_non_map_header() {
        // 0x01 is a CBOR unsigned integer, not a map.
        assert!(matches!(
            SealedQubCbor::from_encoded(vec![0x01, 0x02]),
            Err(CborError::NotAMap)
        ));
        assert!(matches!(
            QubEnvelopeCbor::from_encoded(vec![0x01, 0x02]),
            Err(CborError::NotAMap)
        ));
    }

    #[test]
    fn from_encoded_accepts_empty_map_byte() {
        // 0xA0 = empty definite-length map. Structurally valid as a CBOR
        // map header; will fail at parse time because required fields are
        // absent, but that is the documented contract.
        let ok = SealedQubCbor::from_encoded(vec![0xA0]).unwrap();
        assert_eq!(ok.as_bytes(), &[0xA0]);
        assert!(ok.parse().is_err());

        let ok = QubEnvelopeCbor::from_encoded(vec![0xA0]).unwrap();
        assert_eq!(ok.as_bytes(), &[0xA0]);
        assert!(ok.parse().is_err());
    }

    #[test]
    fn from_encoded_accepts_all_definite_map_headers() {
        for b in 0xA0u8..=0xBBu8 {
            assert!(
                SealedQubCbor::from_encoded(vec![b]).is_ok(),
                "byte {b:#04x}"
            );
            assert!(
                QubEnvelopeCbor::from_encoded(vec![b]).is_ok(),
                "byte {b:#04x}"
            );
        }
    }

    #[test]
    fn from_encoded_rejects_indefinite_map_header() {
        // 0xBF is the CBOR indefinite-length map header — forbidden by
        // canonical CBOR and rejected by the lightweight structural check.
        assert!(matches!(
            SealedQubCbor::from_encoded(vec![0xBF]),
            Err(CborError::NotAMap)
        ));
    }

    #[test]
    fn from_encoded_accepts_real_serialised_bytes() {
        let sealed = sample_sealed();
        let bytes = serialize_sealed_qub(&sealed).unwrap();
        let wrapped = SealedQubCbor::from_encoded(bytes.clone()).unwrap();
        assert_eq!(wrapped.as_bytes(), &bytes[..]);
        assert_eq!(wrapped.parse().unwrap(), sealed);
    }

    #[test]
    fn sealed_len_matches_bytes_and_is_not_empty() {
        let sealed = sample_sealed();
        let w = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
        let byte_count = w.as_bytes().len();
        assert!(!w.is_empty());
        assert_eq!(w.len(), byte_count);
        // len must be > 1 — a sealed qub is never trivially small.
        assert!(w.len() > 1, "sealed CBOR must be larger than 1 byte");
    }

    #[test]
    #[allow(clippy::len_zero)] // intentional: testing is_empty agrees with len
    fn sealed_is_empty_consistent_with_len() {
        let sealed = sample_sealed();
        let w = SealedQubCbor::from_sealed_qub(&sealed).unwrap();
        // is_empty must agree with len: non-zero len means not empty.
        assert_eq!(w.is_empty(), w.len() == 0);
        assert!(!w.is_empty());
    }

    #[test]
    fn envelope_len_matches_bytes_and_is_not_empty() {
        let env = sample_envelope();
        let w = QubEnvelopeCbor::from_qub_envelope(&env).unwrap();
        let byte_count = w.as_bytes().len();
        assert!(!w.is_empty());
        assert_eq!(w.len(), byte_count);
        assert!(w.len() > 1, "envelope CBOR must be larger than 1 byte");
    }

    #[test]
    #[allow(clippy::len_zero)] // intentional: testing is_empty agrees with len
    fn envelope_is_empty_consistent_with_len() {
        let env = sample_envelope();
        let w = QubEnvelopeCbor::from_qub_envelope(&env).unwrap();
        // is_empty must agree with len: non-zero len means not empty.
        assert_eq!(w.is_empty(), w.len() == 0);
        assert!(!w.is_empty());
    }

    #[test]
    fn into_bytes_returns_original_bytes() {
        let env = sample_envelope();
        let bytes = serialize_qub_envelope(&env).unwrap();
        let w = QubEnvelopeCbor::from_encoded(bytes.clone()).unwrap();
        assert_eq!(w.into_bytes(), bytes);
    }
}
