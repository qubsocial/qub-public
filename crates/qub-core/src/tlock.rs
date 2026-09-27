//! Timelock encryption/decryption for qub payloads.
//!
//! This module provides the [`TimelockProvider`] trait, which abstracts
//! over a timelock cryptosystem so the rest of `qub-core` (and higher-level
//! apps) can encrypt a `QubEnvelope` against a future drand round without
//! depending directly on a particular implementation crate.
//!
//! Two providers are supplied:
//!
//! * [`DrandTimelockProvider`] — the production implementation backed by
//!   [`tlock_age`] and a drand BLS12-381 chain (quicknet by default).
//!   Available when the `tlock-drand` feature is enabled (on by default).
//! * `MockTimelockProvider` — a **non-cryptographic** round-trip-stable
//!   stub used by tests and for wiring up integration tests that do not
//!   want to pay the cost of real IBE operations. Available under the
//!   `test-utils` feature or under `cfg(test)`.
//!
//! See PROTOCOL.md §7 step 10 (seal) and §8 step 7b (unlock) for the
//! normative flow this module implements.
//!
//! # Example
//!
//! ```
//! use qub_core::tlock::{DrandTimelockProvider, TimelockProvider};
//!
//! // drand quicknet — round 1000 has already passed, so the round
//! // signature is publicly known and the round-trip can be verified
//! // entirely offline. See tests in this module for the actual
//! // hardcoded signature.
//! let provider = DrandTimelockProvider::quicknet();
//! let ciphertext = provider.encrypt(b"hello qub", 1_000).unwrap();
//! assert!(!ciphertext.is_empty());
//! ```

/// Errors returned by a [`TimelockProvider`].
///
/// Errors are deliberately coarse and carry only a descriptive string,
/// never wrapped error values from the underlying crate. This keeps
/// `TimelockError` `Clone + PartialEq + Eq` and independent of the
/// specific timelock implementation, which matters because the concrete
/// library may be swapped in the future (see PDD §13.1 risk:
/// "tlock-rs maintenance risk").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimelockError {
    /// Encryption failed. Typically indicates an invalid configured
    /// chain public key or an internal failure of the IBE primitive.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed. Typically indicates a malformed ciphertext,
    /// a round signature that does not match the round the ciphertext
    /// was encrypted for, or ciphertext tampering.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// The configured chain public key or chain hash could not be
    /// parsed into a usable form (bad hex, wrong length, not a valid
    /// BLS point, etc.).
    #[error("invalid chain public key: {0}")]
    InvalidChainKey(String),

    /// The supplied drand round signature was rejected by the
    /// underlying primitive (wrong length, not a valid BLS point,
    /// etc.).
    #[error("invalid round signature: {0}")]
    InvalidSignature(String),
}

/// drand chain-migration version for **quicknet** (`0`).
///
/// quicknet is the only chain qub uses today (period 3s, scheme
/// `bls-unchained-g1-rfc9380`, chain hash
/// `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`).
/// `SealedQub::drand_chain_version()` returns `None` for every qub
/// sealed to date; both `None` (wire-absent) and `Some(0)` mean
/// quicknet. The field + this constant exist so a future chain
/// migration ("quicknet deprecated") can be expressed on the wire by
/// bumping to `Some(1)` etc. without a breaking CBOR format change
/// (W3 / UP-B4). It is deliberately NOT part of the `qub_id` preimage
/// (like `drand_chain_id`), so its addition never alters an existing
/// qub's identity.
pub const DRAND_CHAIN_VERSION_QUICKNET: u8 = 0;

/// Trait for timelock encryption/decryption.
///
/// Abstracts over the underlying timelock implementation so it can be
/// swapped — for example to plug in a mock during tests, or to migrate
/// off [`tlock_age`] if its maintenance story changes.
///
/// Implementations are expected to be stateless with respect to
/// plaintext/ciphertext; any chain-specific configuration (public key,
/// chain hash) is captured at construction time.
pub trait TimelockProvider {
    /// Encrypt `plaintext` so that it can only be decrypted once the
    /// drand network has published the signature for `round`.
    ///
    /// Implementations must use fresh randomness per call; encrypting
    /// the same plaintext twice for the same round must yield distinct
    /// ciphertexts (IBE encryption is randomised).
    fn encrypt(&self, plaintext: &[u8], round: u64) -> Result<Vec<u8>, TimelockError>;

    /// Decrypt a ciphertext previously produced by [`Self::encrypt`]
    /// using the BLS round signature fetched from the drand network.
    ///
    /// The `round_signature` must correspond to the same round the
    /// ciphertext was encrypted for. A mismatched signature, a
    /// corrupted ciphertext, or any other failure yields
    /// [`TimelockError::DecryptionFailed`] (or
    /// [`TimelockError::InvalidSignature`] if the signature is
    /// obviously malformed).
    fn decrypt(&self, ciphertext: &[u8], round_signature: &[u8]) -> Result<Vec<u8>, TimelockError>;

    /// The hex-encoded drand chain hash this provider decrypts for, when
    /// it is bound to a specific chain.
    ///
    /// Returns `None` for providers with no chain identity (the test
    /// mock) — [`crate::unlock::unlock`] then skips the chain-binding
    /// check (SEC-20). The default implementation returns `None`;
    /// chain-backed providers override it.
    fn chain_hash_hex(&self) -> Option<String> {
        None
    }

    /// The drand round a `ciphertext` is bound to, read from the tlock
    /// stanza **without** needing the round signature.
    ///
    /// This is the *cryptographically meaningful* round — the one that
    /// actually gates decryption — as opposed to any advisory
    /// `drand_round` metadata carried alongside the ciphertext. The
    /// unlock path cross-checks it against `unlock_round(unlock_at)` so
    /// a malicious or tampered qub cannot bind its ciphertext to an
    /// already-past round while displaying a future countdown (C1).
    ///
    /// Returns `Ok(None)` for providers that cannot expose a round (the
    /// non-cryptographic test mock); [`crate::unlock::unlock`] then
    /// skips the round-binding check, mirroring [`Self::chain_hash_hex`].
    /// Returns [`TimelockError::DecryptionFailed`] if the ciphertext
    /// header cannot be parsed. The default implementation returns
    /// `Ok(None)`; chain-backed providers override it.
    ///
    /// # Errors
    ///
    /// Returns [`TimelockError::DecryptionFailed`] when the ciphertext
    /// is not a well-formed tlock-age artifact.
    fn ciphertext_round(&self, _ciphertext: &[u8]) -> Result<Option<u64>, TimelockError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// drand-backed provider
// ---------------------------------------------------------------------------

#[cfg(feature = "tlock-drand")]
mod drand {
    use super::{TimelockError, TimelockProvider};
    use ark_bls12_381::{Bls12_381, G1Affine, G2Affine, g1};
    use ark_ec::{
        AffineRepr,
        hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
        pairing::Pairing,
        short_weierstrass::Projective,
    };
    use ark_ff::field_hashers::DefaultFieldHasher;
    use ark_serialize::CanonicalDeserialize;
    use sha2::{Digest, Sha256};

    /// drand quicknet hash-to-curve domain-separation tag (RFC 9380),
    /// matching the `bls-unchained-g1-rfc9380` scheme — signatures live
    /// on G1, so the per-round message is hashed to G1 under this DST.
    /// Identical to the Worker's `DRAND_QUICKNET_DST` and `tlock`'s
    /// internal `G1_DOMAIN`; the three must stay in lockstep.
    const QUICKNET_G1_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    /// drand chain parameters used by [`DrandTimelockProvider`].
    ///
    /// These are the public, well-known parameters published by a drand
    /// chain's `/info` endpoint. They are captured at provider
    /// construction time and are required by [`tlock_age`] for both
    /// encrypt and decrypt operations (PROTOCOL.md §7 step 10,
    /// §8 step 7b).
    #[derive(Debug, Clone)]
    pub struct DrandChainInfo {
        /// Raw chain hash bytes (32 bytes for drand v2 chains).
        pub chain_hash: Vec<u8>,
        /// Raw BLS public key bytes. The curve group (G1 vs G2) is
        /// inferred from the byte length by the underlying `tlock`
        /// primitive.
        pub public_key: Vec<u8>,
    }

    impl DrandChainInfo {
        /// Parse chain info from hex-encoded strings.
        ///
        /// # Errors
        ///
        /// Returns [`TimelockError::InvalidChainKey`] if either input
        /// is not valid hexadecimal.
        pub fn from_hex(chain_hash_hex: &str, public_key_hex: &str) -> Result<Self, TimelockError> {
            let chain_hash = hex::decode(chain_hash_hex.trim()).map_err(|e| {
                TimelockError::InvalidChainKey("chain_hash hex: ".to_string() + &e.to_string())
            })?;
            let public_key = hex::decode(public_key_hex.trim()).map_err(|e| {
                TimelockError::InvalidChainKey("public_key hex: ".to_string() + &e.to_string())
            })?;
            Ok(Self {
                chain_hash,
                public_key,
            })
        }
    }

    /// drand + BLS12-381 timelock provider backed by [`tlock_age`].
    ///
    /// The underlying crate implements the IBE-based tlock scheme
    /// described in <https://eprint.iacr.org/2023/189>, hybrid-wrapped
    /// with age encryption for arbitrary-length plaintexts. Output
    /// ciphertexts are raw (non-armored) age bytes with a tlock stanza
    /// carrying the round number and chain hash.
    #[derive(Debug, Clone)]
    pub struct DrandTimelockProvider {
        info: DrandChainInfo,
    }

    impl DrandTimelockProvider {
        /// Create a provider from already-decoded chain info.
        #[must_use]
        pub const fn new(info: DrandChainInfo) -> Self {
            Self { info }
        }

        /// Convenience: construct from hex-encoded chain hash and
        /// public key, as returned by a drand `/info` endpoint.
        ///
        /// # Errors
        ///
        /// Returns [`TimelockError::InvalidChainKey`] if either
        /// parameter is not valid hexadecimal.
        pub fn from_hex(chain_hash_hex: &str, public_key_hex: &str) -> Result<Self, TimelockError> {
            Ok(Self::new(DrandChainInfo::from_hex(
                chain_hash_hex,
                public_key_hex,
            )?))
        }

        /// Provider preconfigured for drand **quicknet**
        /// (period 3s, scheme `bls-unchained-g1-rfc9380`).
        ///
        /// Chain hash:
        /// `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.
        #[must_use]
        // SEC-15: the arguments are compile-time hex literals, valid by
        // construction, so `from_hex` cannot fail here.
        #[allow(clippy::expect_used)]
        pub fn quicknet() -> Self {
            // These values are public drand network parameters and
            // will never change for this chain id. Hex is well-formed
            // by construction, so the unwrap is infallible.
            Self::from_hex(
                "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
                "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c\
                 8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb\
                 5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
            )
            .expect("quicknet hex constants are well-formed")
        }

        /// The chain info this provider was constructed with.
        #[must_use]
        pub const fn chain_info(&self) -> &DrandChainInfo {
            &self.info
        }

        /// Verify a fetched drand round signature against this provider's
        /// pinned chain public key (L3).
        ///
        /// quicknet is `bls-unchained-g1-rfc9380`: the per-round message
        /// `m = SHA-256(round_be_u64)` is hashed to **G1** under
        /// `QUICKNET_G1_DST`, the signature `σ` is a compressed G1
        /// point, and the public key `pk` is a compressed G2 point.
        /// BLS verification is the pairing equality
        /// `e(σ, g₂) == e(H(m), pk)`.
        ///
        /// The WASM viewer calls this on the fetched round signature
        /// **before** handing it to [`TimelockProvider::decrypt`], so a
        /// tampered or wrong-round signature is rejected with a clear
        /// error instead of being fed into the IBE (and producing
        /// garbage / a confusing decrypt failure). BLS unforgeability
        /// already protects the timelock itself; this closes the parity
        /// gap with the Worker's `verifyRoundSignature` and keeps
        /// attacker-influenced bytes off the decrypt path.
        ///
        /// # Errors
        ///
        /// Returns [`TimelockError::InvalidSignature`] if `signature` is
        /// not a valid compressed G1 point or does not verify, and
        /// [`TimelockError::InvalidChainKey`] if the configured public
        /// key is not a valid compressed G2 point.
        pub fn verify_round_signature(
            &self,
            round: u64,
            signature: &[u8],
        ) -> Result<(), TimelockError> {
            // Per-round identity: SHA-256 over the big-endian round, then
            // hashed to G1 — mirroring the Worker and drand itself.
            let digest = Sha256::digest(round.to_be_bytes());

            let mapper = MapToCurveBasedHasher::<
                Projective<g1::Config>,
                DefaultFieldHasher<Sha256, 128>,
                WBMap<g1::Config>,
            >::new(QUICKNET_G1_DST)
            .map_err(|e| TimelockError::InvalidSignature(format!("hash-to-curve init: {e}")))?;
            let message_point = mapper
                .hash(digest.as_slice())
                .map_err(|e| TimelockError::InvalidSignature(format!("hash-to-curve: {e}")))?;

            // Compressed-point deserialisation runs the on-curve +
            // prime-order-subgroup checks, so an off-curve / small-subgroup
            // forgery is rejected here before the pairing.
            let sig = G1Affine::deserialize_compressed(signature)
                .map_err(|e| TimelockError::InvalidSignature(format!("signature point: {e}")))?;
            let pubkey = G2Affine::deserialize_compressed(self.info.public_key.as_slice())
                .map_err(|e| TimelockError::InvalidChainKey(format!("public key point: {e}")))?;

            // e(σ, g₂) == e(H(m), pk).
            let lhs = Bls12_381::pairing(sig, G2Affine::generator());
            let rhs = Bls12_381::pairing(message_point, pubkey);
            if lhs == rhs {
                Ok(())
            } else {
                Err(TimelockError::InvalidSignature(
                    "round signature does not verify against the pinned chain public key"
                        .to_string(),
                ))
            }
        }
    }

    impl TimelockProvider for DrandTimelockProvider {
        fn encrypt(&self, plaintext: &[u8], round: u64) -> Result<Vec<u8>, TimelockError> {
            let mut ciphertext = Vec::new();
            tlock_age::encrypt(
                &mut ciphertext,
                plaintext,
                &self.info.chain_hash,
                &self.info.public_key,
                round,
            )
            .map_err(|e| TimelockError::EncryptionFailed(e.to_string()))?;
            Ok(ciphertext)
        }

        fn decrypt(
            &self,
            ciphertext: &[u8],
            round_signature: &[u8],
        ) -> Result<Vec<u8>, TimelockError> {
            let mut plaintext = Vec::new();
            tlock_age::decrypt(
                &mut plaintext,
                ciphertext,
                &self.info.chain_hash,
                round_signature,
            )
            .map_err(|e| TimelockError::DecryptionFailed(e.to_string()))?;
            Ok(plaintext)
        }

        fn chain_hash_hex(&self) -> Option<String> {
            Some(hex::encode(&self.info.chain_hash))
        }

        fn ciphertext_round(&self, ciphertext: &[u8]) -> Result<Option<u64>, TimelockError> {
            // `decrypt_header` parses the age/tlock stanza and returns the
            // bound round without any network access or round signature
            // (PROTOCOL.md §8 step 7c). A malformed artifact yields a
            // decryption error rather than a panic.
            let header = tlock_age::decrypt_header(ciphertext)
                .map_err(|e| TimelockError::DecryptionFailed(e.to_string()))?;
            Ok(Some(header.round()))
        }
    }
}

#[cfg(feature = "tlock-drand")]
pub use drand::{DrandChainInfo, DrandTimelockProvider};

// ---------------------------------------------------------------------------
// Mock provider (tests + integration)
// ---------------------------------------------------------------------------

/// Non-cryptographic mock timelock provider for tests.
///
/// # Safety
///
/// **This is not encryption.** It applies a trivially reversible byte
/// transformation. It MUST NOT be used outside of test code. The
/// `test-utils` feature flag MUST NOT be enabled in release builds.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MockTimelockProvider;

#[cfg(any(test, feature = "test-utils"))]
impl TimelockProvider for MockTimelockProvider {
    fn encrypt(&self, plaintext: &[u8], _round: u64) -> Result<Vec<u8>, TimelockError> {
        Ok(plaintext.iter().map(|b| b.wrapping_add(42)).collect())
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        _round_signature: &[u8],
    ) -> Result<Vec<u8>, TimelockError> {
        Ok(ciphertext.iter().map(|b| b.wrapping_sub(42)).collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Mock provider ----------------------------------------------------

    #[test]
    fn mock_roundtrip_various_sizes() {
        let provider = MockTimelockProvider;
        for size in [0usize, 1, 16, 100, 1024, 10 * 1024, 50 * 1024] {
            let pt: Vec<u8> = (0..size).map(|i| u8::try_from(i & 0xff).unwrap()).collect();
            let ct = provider.encrypt(&pt, 42).unwrap();
            let recovered = provider.decrypt(&ct, &[]).unwrap();
            assert_eq!(recovered, pt, "mock round-trip failed at size {size}");
        }
    }

    #[test]
    fn mock_ciphertext_differs_from_plaintext() {
        let provider = MockTimelockProvider;
        let pt = b"hello world";
        let ct = provider.encrypt(pt, 1).unwrap();
        assert_ne!(ct.as_slice(), pt.as_slice());
    }

    #[test]
    fn timelock_error_display_all_variants() {
        let variants: Vec<TimelockError> = vec![
            TimelockError::EncryptionFailed("enc fail".into()),
            TimelockError::DecryptionFailed("dec fail".into()),
            TimelockError::InvalidChainKey("bad hex".into()),
            TimelockError::InvalidSignature("bad sig".into()),
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display should produce output for {v:?}");
        }
        assert_eq!(variants.len(), 4, "all TimelockError variants exercised");
    }

    // -- Trait object usage -----------------------------------------------

    #[test]
    fn trait_object_mock() {
        let provider: Box<dyn TimelockProvider> = Box::new(MockTimelockProvider);
        let ct = provider.encrypt(b"trait object", 7).unwrap();
        let pt = provider.decrypt(&ct, &[]).unwrap();
        assert_eq!(pt.as_slice(), b"trait object");
    }

    #[cfg(feature = "tlock-drand")]
    #[test]
    fn trait_object_drand() {
        let _provider: Box<dyn TimelockProvider> = Box::new(DrandTimelockProvider::quicknet());
    }

    // -- chain identity (SEC-20) ------------------------------------------

    #[test]
    fn mock_provider_has_no_chain_identity() {
        // The mock opts out of the unlock-time chain-binding check.
        assert_eq!(MockTimelockProvider.chain_hash_hex(), None);
    }

    #[test]
    fn mock_provider_exposes_no_ciphertext_round() {
        // The mock opts out of the unlock-time round-binding check (C1).
        let ct = MockTimelockProvider.encrypt(b"x", 1234).unwrap();
        assert_eq!(MockTimelockProvider.ciphertext_round(&ct), Ok(None));
    }

    #[cfg(feature = "tlock-drand")]
    #[test]
    fn drand_provider_reports_its_chain_hash() {
        assert_eq!(
            DrandTimelockProvider::quicknet()
                .chain_hash_hex()
                .as_deref(),
            Some("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"),
        );
    }

    // -- Real tlock tests (no network) ------------------------------------
    //
    // All drand chain info and round signatures are hardcoded from
    // well-known public values. Round 1000 on quicknet has already
    // passed; the signature is public and never changes.

    #[cfg(feature = "tlock-drand")]
    mod real_tlock {
        use super::*;

        // drand quicknet — scheme bls-unchained-g1-rfc9380
        // https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/1000
        const QUICKNET_ROUND: u64 = 1000;
        const QUICKNET_ROUND_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

        fn provider() -> DrandTimelockProvider {
            DrandTimelockProvider::quicknet()
        }

        fn round_signature() -> Vec<u8> {
            hex::decode(QUICKNET_ROUND_SIG_HEX).unwrap()
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn verify_accepts_the_genuine_round_signature() {
            // L3: the real quicknet round-1000 signature must verify
            // against the pinned chain public key. This is the cross-impl
            // anchor — the same vector the Worker's verifyRoundSignature
            // test uses.
            let p = provider();
            assert_eq!(
                p.verify_round_signature(QUICKNET_ROUND, &round_signature()),
                Ok(())
            );
        }

        #[test]
        fn verify_rejects_a_bit_flipped_signature() {
            let p = provider();
            let mut sig = round_signature();
            sig[0] ^= 0x01;
            let err = p
                .verify_round_signature(QUICKNET_ROUND, &sig)
                .expect_err("a tampered signature must not verify");
            assert!(matches!(err, TimelockError::InvalidSignature(_)));
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn verify_rejects_the_signature_for_a_different_round() {
            // The genuine round-1000 signature must not verify as round
            // 1001 — binding the signature to its round is the whole point.
            let p = provider();
            let err = p
                .verify_round_signature(QUICKNET_ROUND + 1, &round_signature())
                .expect_err("right signature, wrong round must not verify");
            assert!(matches!(err, TimelockError::InvalidSignature(_)));
        }

        #[test]
        fn verify_rejects_a_malformed_signature() {
            // Wrong length / not a compressed G1 point fails at
            // deserialisation, before the pairing.
            let p = provider();
            let err = p
                .verify_round_signature(QUICKNET_ROUND, b"too short")
                .expect_err("malformed signature bytes must be rejected");
            assert!(matches!(err, TimelockError::InvalidSignature(_)));
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn roundtrip_small() {
            let p = provider();
            let pt = b"hello qub, from the future";
            let ct = p.encrypt(pt, QUICKNET_ROUND).unwrap();
            assert_ne!(ct.as_slice(), pt.as_slice());
            let recovered = p.decrypt(&ct, &round_signature()).unwrap();
            assert_eq!(recovered.as_slice(), pt);
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn roundtrip_various_sizes() {
            let p = provider();
            let sig = round_signature();
            for size in [1usize, 16, 100, 1024, 8 * 1024] {
                let pt: Vec<u8> = (0..size).map(|i| u8::try_from(i & 0xff).unwrap()).collect();
                let ct = p.encrypt(&pt, QUICKNET_ROUND).unwrap();
                let recovered = p.decrypt(&ct, &sig).unwrap();
                assert_eq!(recovered, pt, "real round-trip failed at size {size}");
            }
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn encryption_is_non_deterministic() {
            // IBE encryption uses fresh randomness per call.
            let p = provider();
            let pt = b"same plaintext, same round";
            let ct_a = p.encrypt(pt, QUICKNET_ROUND).unwrap();
            let ct_b = p.encrypt(pt, QUICKNET_ROUND).unwrap();
            assert_ne!(
                ct_a, ct_b,
                "two encryptions of the same plaintext must differ"
            );
            // Both must still decrypt.
            let sig = round_signature();
            assert_eq!(p.decrypt(&ct_a, &sig).unwrap().as_slice(), pt);
            assert_eq!(p.decrypt(&ct_b, &sig).unwrap().as_slice(), pt);
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn ciphertext_round_reads_bound_round() {
            // C1: the stanza round must be recoverable without a
            // signature so unlock can cross-check it against
            // unlock_round(unlock_at).
            let p = provider();
            let ct = p.encrypt(b"bound to round 1000", QUICKNET_ROUND).unwrap();
            assert_eq!(p.ciphertext_round(&ct), Ok(Some(QUICKNET_ROUND)));
        }

        #[test]
        fn ciphertext_round_rejects_garbage() {
            let p = provider();
            let err = p
                .ciphertext_round(b"not a tlock artifact")
                .expect_err("garbage header must not parse");
            assert!(matches!(err, TimelockError::DecryptionFailed(_)));
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn wrong_signature_fails() {
            let p = provider();
            let ct = p.encrypt(b"bound to round 1000", QUICKNET_ROUND).unwrap();
            // A valid-length but wrong signature (bit-flipped).
            let mut bad = round_signature();
            bad[0] ^= 0x01;
            let err = p
                .decrypt(&ct, &bad)
                .expect_err("decryption with wrong signature must fail");
            assert!(matches!(
                err,
                TimelockError::DecryptionFailed(_) | TimelockError::InvalidSignature(_)
            ));
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn tampered_ciphertext_fails() {
            let p = provider();
            let mut ct = p.encrypt(b"integrity matters", QUICKNET_ROUND).unwrap();
            // Flip a byte well past the age header so we hit the
            // AEAD payload region rather than malforming the framing.
            let flip_idx = ct.len() - 1;
            ct[flip_idx] ^= 0xff;
            let err = p
                .decrypt(&ct, &round_signature())
                .expect_err("tampered ciphertext must not decrypt");
            assert!(matches!(err, TimelockError::DecryptionFailed(_)));
        }

        #[test]
        fn invalid_hex_chain_key_rejected() {
            let err = DrandTimelockProvider::from_hex("not-hex!!", "deadbeef")
                .expect_err("bad chain hash hex must be rejected");
            assert!(matches!(err, TimelockError::InvalidChainKey(_)));
        }
    }
}
