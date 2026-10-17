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
    /// Both inputs are attacker-influenced: the ciphertext comes from
    /// the qub's author by way of a gateway, the signature from a relay
    /// or a bundle. Implementations MUST return an error, never panic,
    /// on any bytes. A signature that is not the beacon of the round the
    /// ciphertext names yields [`TimelockError::InvalidSignature`]; a
    /// ciphertext that the beacon does not open, a malformed one, or any
    /// other failure yields [`TimelockError::DecryptionFailed`].
    ///
    /// [`DrandTimelockProvider`]'s exact contract, in order. Steps 1 and
    /// 3 are qub's implementation rule for this crate's dependencies, not
    /// protocol requirements: PROTOCOL.md §8 step 7 asks for the beacon
    /// verified (step 2 here) and the ciphertext decrypted.
    ///
    /// 1. the ciphertext is a binary age v1 file whose header holds
    ///    exactly one `tlock` stanza for this provider's chain, read with
    ///    age-core 0.11's strict stanza grammar (stanzas of other types,
    ///    such as the "grease" stanza age adds to every header, are
    ///    skipped), with a canonical decimal round and a body that is
    ///    exactly the 128 bytes `U || V || W`; otherwise
    ///    `DecryptionFailed("tlock header: …")`;
    /// 2. the signature is exactly 48 bytes and BLS-verifies as the
    ///    beacon of that round; otherwise `InvalidSignature`;
    /// 3. tlock's IBE consistency check, replayed here without its panic,
    ///    holds: with `sigma` and the message recovered under the
    ///    beacon, `U == r·G₂`; otherwise `DecryptionFailed` with
    ///    "tlock ciphertext is not consistent with the round's beacon";
    /// 4. only then does `tlock_age` decrypt, and an age header-MAC or
    ///    payload failure is `DecryptionFailed`.
    ///
    /// Passing step 3 under a verified beacon is what shows the body was
    /// really encrypted to the round it names; the round in the stanza
    /// is otherwise only a label. The no-panic guarantee rests on steps
    /// 1 and 3 matching tlock 0.0.10 and age-core 0.11 exactly: a bump of
    /// either crate has to re-establish it (`tlock::tests::real_tlock`
    /// and the `decrypt_tlock` fuzz target are where it is tested).
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

    /// The drand round a `ciphertext`'s tlock stanza names, read
    /// **without** needing the round signature.
    ///
    /// It is a label, not a proof. The round that gates decryption is
    /// the identity the body was encrypted to, and only
    /// [`Self::decrypt`]'s IBE consistency check, under that round's
    /// verified beacon, can show the two agree. Before that beacon
    /// exists, nobody can. The unlock path cross-checks the label
    /// against `unlock_round(unlock_at)` so that a qub naming an
    /// already-past round while displaying a future countdown is
    /// refused (C1); one that names the displayed round but was
    /// encrypted to another is refused at decryption instead.
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
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, g1};
    use ark_ec::{
        AffineRepr, CurveGroup,
        hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
        pairing::Pairing,
        short_weierstrass::Projective,
    };
    use ark_ff::{PrimeField, field_hashers::DefaultFieldHasher};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    use sha2::{Digest, Sha256};

    /// drand quicknet hash-to-curve domain-separation tag (RFC 9380),
    /// matching the `bls-unchained-g1-rfc9380` scheme — signatures live
    /// on G1, so the per-round message is hashed to G1 under this DST.
    /// Identical to the Worker's `DRAND_QUICKNET_DST` and `tlock`'s
    /// internal `G1_DOMAIN`; the three must stay in lockstep.
    const QUICKNET_G1_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    /// A quicknet beacon: a compressed G1 point.
    const G1_COMPRESSED_LEN: usize = 48;
    /// The IBE ciphertext `U` for a G1-signature chain: a compressed G2 point.
    const G2_COMPRESSED_LEN: usize = 96;
    /// tlock's `V` and `W`, each one 16-byte block.
    const IBE_BLOCK_LEN: usize = 16;
    /// A tlock stanza body: `U || V || W` (tlock 0.0.10 `decrypt` reads
    /// exactly these 128 bytes and ignores anything after them).
    const TLOCK_BODY_LEN: usize = G2_COMPRESSED_LEN + 2 * IBE_BLOCK_LEN;

    /// The age v1 magic line.
    const AGE_V1_MAGIC: &[u8] = b"age-encryption.org/v1\n";
    /// The line that ends an age v1 header's stanzas.
    const AGE_MAC_PREFIX: &[u8] = b"--- ";
    /// tlock's recipient stanza tag.
    const TLOCK_TAG: &[u8] = b"tlock";

    /// The refusal for a stanza body the beacon does not open.
    pub(super) const IBE_INCONSISTENT: &str =
        "tlock ciphertext is not consistent with the round's beacon";
    /// The refusal for a header that does not hold exactly one tlock stanza.
    pub(super) const ONE_STANZA: &str = "expected exactly one tlock stanza";

    /// The one tlock stanza of an age v1 header.
    struct TlockStanza {
        round: u64,
        body: [u8; TLOCK_BODY_LEN],
    }

    fn header_error(why: &str) -> TimelockError {
        TimelockError::DecryptionFailed(format!("tlock header: {why}"))
    }

    /// `(line, rest)` for the bytes before and after the next `\n`.
    fn split_line(input: &[u8]) -> Result<(&[u8], &[u8]), TimelockError> {
        let mut parts = input.splitn(2, |&b| b == b'\n');
        match (parts.next(), parts.next()) {
            (Some(line), Some(rest)) => Ok((line, rest)),
            _ => Err(header_error("truncated")),
        }
    }

    /// age's base64 alphabet (RFC 4648, no padding).
    const fn is_base64_char(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
    }

    /// The last line of an age stanza body, as age-core 0.11's strict
    /// `wrapped_encoded_data` accepts it: short (0..=63 columns), a valid
    /// base64 length, and no trailing bits.
    const fn is_canonical_last_line(line: &[u8]) -> bool {
        match (line.len() % 4, line.last()) {
            (0, _) => true,
            (2, Some(c)) => matches!(c, b'A' | b'Q' | b'g' | b'w'),
            (3, Some(c)) => matches!(
                c,
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            ),
            _ => false,
        }
    }

    /// Parse an age v1 header and return its one tlock stanza.
    ///
    /// Each stanza is read with age-core 0.11's **strict** grammar
    /// (`age_stanza`): an argument line of single-space-separated
    /// printable strings, then base64 body lines of exactly 64 columns
    /// ended by one canonical short line. age parses a header that passes
    /// here into exactly these stanzas, because its strict alternative is
    /// tried first and succeeds on the same bytes, so the stanza checked
    /// below is the only one `tlock_age` can hand to tlock's IBE: `tlock_age`'s
    /// `Identity` declines every stanza whose tag is not `tlock`.
    ///
    /// Stanzas of other types are allowed and skipped: age 0.11 adds a
    /// random "grease" stanza to every header it writes, so every qub
    /// sealed by this crate carries one. More than one tlock stanza is
    /// refused, since `tlock_age` reads the LAST one's round as the header
    /// round and tries the IBE on EVERY one.
    fn parse_tlock_header(
        ciphertext: &[u8],
        chain_hash: &[u8],
    ) -> Result<TlockStanza, TimelockError> {
        let mut rest = ciphertext
            .strip_prefix(AGE_V1_MAGIC)
            .ok_or_else(|| header_error("not an age v1 file"))?;
        let mut found: Option<TlockStanza> = None;
        while !rest.starts_with(AGE_MAC_PREFIX) {
            let (line, after) = split_line(rest)?;
            rest = after;
            let args: Vec<&[u8]> = line
                .strip_prefix(b"-> ")
                .ok_or_else(|| header_error("not a recipient stanza"))?
                .split(|&b| b == b' ')
                .collect();
            if args
                .iter()
                .any(|a| a.is_empty() || !a.iter().all(|c| (33..=126).contains(c)))
            {
                return Err(header_error("malformed stanza arguments"));
            }

            let mut text = Vec::new();
            loop {
                let (line, after) = split_line(rest)?;
                rest = after;
                if line.len() > 64 || !line.iter().all(|&c| is_base64_char(c)) {
                    return Err(header_error("malformed stanza body"));
                }
                text.extend_from_slice(line);
                if line.len() < 64 {
                    if !is_canonical_last_line(line) {
                        return Err(header_error("malformed stanza body"));
                    }
                    break;
                }
            }

            if let Some((&TLOCK_TAG, tlock_args)) = args.split_first() {
                if found.is_some() {
                    return Err(header_error(ONE_STANZA));
                }
                found = Some(tlock_stanza(tlock_args, &text, chain_hash)?);
            }
        }
        found.ok_or_else(|| header_error(ONE_STANZA))
    }

    /// The tlock stanza's `round chain_hash` arguments and its body.
    fn tlock_stanza(
        args: &[&[u8]],
        text: &[u8],
        chain_hash: &[u8],
    ) -> Result<TlockStanza, TimelockError> {
        let [round, hash] = args else {
            return Err(header_error("tlock stanza needs a round and a chain hash"));
        };
        // Canonical decimal only: what every encoder writes, and the same
        // value `str::parse::<u64>` gives tlock_age.
        let round_value = std::str::from_utf8(round)
            .ok()
            .and_then(|r| r.parse::<u64>().ok())
            .filter(|r| r.to_string().as_bytes() == *round)
            .ok_or_else(|| header_error("tlock round is not a canonical integer"))?;
        if hex::decode(hash).ok().as_deref() != Some(chain_hash) {
            return Err(header_error("tlock stanza is for another chain"));
        }
        let body = STANDARD_NO_PAD
            .decode(text)
            .ok()
            .filter(|b| STANDARD_NO_PAD.encode(b).as_bytes() == text)
            .ok_or_else(|| header_error("tlock body is not canonical base64"))?;
        let body: [u8; TLOCK_BODY_LEN] = body
            .try_into()
            .map_err(|_| header_error("tlock body is not U || V || W"))?;
        Ok(TlockStanza {
            round: round_value,
            body,
        })
    }

    /// drand's `expand_message` for the IBE scalar, as tlock 0.0.10's
    /// `ExpandMsgDrand` computes it: the first `SHA-256(i_le16 || h)`, top
    /// bit cleared and read little-endian, that is a canonical scalar.
    fn drand_scalar(h: &[u8]) -> Fr {
        for i in 1..u16::MAX {
            let mut d: [u8; 32] = Sha256::new()
                .chain_update(i.to_le_bytes())
                .chain_update(h)
                .finalize()
                .into();
            d[0] >>= 1;
            d.reverse();
            if Fr::deserialize_compressed(&d[..]).is_ok() {
                return Fr::from_le_bytes_mod_order(&d);
            }
        }
        // tlock leaves its buffer zeroed when no candidate fits.
        Fr::from_le_bytes_mod_order(&[0u8; 32])
    }

    /// The first 16 bytes of `a XOR b` (`a` may be a longer digest, as in
    /// tlock, which XORs with its first 16 bytes).
    fn xor_block(a: &[u8], b: &[u8]) -> [u8; IBE_BLOCK_LEN] {
        let mut out = [0u8; IBE_BLOCK_LEN];
        for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
            *o = x ^ y;
        }
        out
    }

    /// tlock 0.0.10's IBE decryption (`ibe::decrypt`), replayed without
    /// its panic. tlock ends it in `assert_eq!(c.u, r_g)`, so ANY body
    /// that is not a valid encryption under `signature`'s identity aborts
    /// the process; here the same comparison is a refusal. The steps and
    /// byte orders are tlock's own, so a body this accepts is one on which
    /// tlock's assertion holds:
    ///
    /// 1. `sigma = V XOR SHA-256("IBE-H2" || rev(compress(e(σ, U))))[..16]`
    /// 2. `msg = W XOR SHA-256("IBE-H4" || sigma)[..16]`
    /// 3. `r = expand_drand(SHA-256("IBE-H3" || sigma || msg))`
    /// 4. require `U == r·G₂`
    fn check_ibe_consistency(
        signature: &G1Affine,
        body: &[u8; TLOCK_BODY_LEN],
    ) -> Result<(), TimelockError> {
        let inconsistent = || TimelockError::DecryptionFailed(IBE_INCONSISTENT.to_string());
        let (u, v_w) = body.split_at(G2_COMPRESSED_LEN);
        let (v, w) = v_w.split_at(IBE_BLOCK_LEN);
        let u = G2Affine::deserialize_compressed(u).map_err(|_| inconsistent())?;

        let mut gid = Vec::new();
        Bls12_381::pairing(*signature, u)
            .serialize_compressed(&mut gid)
            .map_err(|_| inconsistent())?;
        gid.reverse();
        let h2 = Sha256::new()
            .chain_update(b"IBE-H2")
            .chain_update(&gid)
            .finalize();
        let sigma = xor_block(h2.as_slice(), v);

        let h4 = Sha256::new()
            .chain_update(b"IBE-H4")
            .chain_update(sigma)
            .finalize();
        let msg = xor_block(h4.as_slice(), w);

        let h3 = Sha256::new()
            .chain_update(b"IBE-H3")
            .chain_update(sigma)
            .chain_update(msg)
            .finalize();
        let r_g = (G2Affine::generator() * drand_scalar(&h3)).into_affine();
        if r_g == u {
            Ok(())
        } else {
            Err(inconsistent())
        }
    }

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
    ///
    /// Decryption supports G1-signature chains only (quicknet's
    /// `bls-unchained-g1-rfc9380`): the beacon check and the IBE replay
    /// in [`TimelockProvider::decrypt`] both assume a 48-byte G1 beacon
    /// and a 96-byte G2 `U`.
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
        /// [`TimelockProvider::decrypt`] also calls it itself, for the
        /// round its ciphertext names.
        ///
        /// # Errors
        ///
        /// Returns [`TimelockError::InvalidSignature`] if `signature` is
        /// not exactly one 48-byte compressed G1 point or does not
        /// verify, and
        /// [`TimelockError::InvalidChainKey`] if the configured public
        /// key is not a valid compressed G2 point.
        pub fn verify_round_signature(
            &self,
            round: u64,
            signature: &[u8],
        ) -> Result<(), TimelockError> {
            // Exactly one compressed G1 point. A slice reader ignores bytes
            // past the 48 the point needs, and tlock picks the curve group
            // of the signature (and of `U`) from its LENGTH.
            if signature.len() != G1_COMPRESSED_LEN {
                return Err(TimelockError::InvalidSignature(format!(
                    "a quicknet beacon is {G1_COMPRESSED_LEN} bytes, got {}",
                    signature.len()
                )));
            }
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
            // Nothing attacker-supplied may reach tlock's IBE before it is
            // known to pass: tlock 0.0.10 ends the IBE in `assert_eq!`
            // (`ibe.rs`, `U = G^r`), so a beacon of another round, a
            // relabelled stanza or a tampered body PANICS there, and the
            // release profile aborts. The beacon comes from a relay and the
            // ciphertext from the qub's author or a gateway. So: one tlock
            // stanza, read with age's own grammar; the beacon verified for
            // its round; and the IBE replayed here, panic-free, on exactly
            // the body tlock will see. Only a body that passes is handed on.
            let stanza = parse_tlock_header(ciphertext, &self.info.chain_hash)?;
            self.verify_round_signature(stanza.round, round_signature)?;
            let signature = G1Affine::deserialize_compressed(round_signature)
                .map_err(|e| TimelockError::InvalidSignature(format!("signature point: {e}")))?;
            check_ibe_consistency(&signature, &stanza.body)?;

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
            // The round LABEL of the one tlock stanza, read by the same
            // parser `decrypt` uses, without any network access or round
            // signature (PROTOCOL.md §8 step 6a). It is a label: only
            // `decrypt`'s IBE check, with the round's beacon, shows the body
            // was really encrypted to it. A malformed artifact, or one with
            // more than one tlock stanza, yields a decryption error.
            Ok(Some(
                parse_tlock_header(ciphertext, &self.info.chain_hash)?.round,
            ))
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
        use super::super::drand::{IBE_INCONSISTENT, ONE_STANZA};
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
        fn a_genuine_beacon_of_another_round_is_refused_without_a_panic() {
            // A valid G1 point that is not the bound round's beacon reaches
            // tlock's IBE `assert_eq!` unless decrypt verifies it first: the
            // round-1000 beacon on a round-1001 ciphertext panicked here.
            let p = provider();
            let ct = p
                .encrypt(b"bound to round 1001", QUICKNET_ROUND + 1)
                .unwrap();
            let err = p
                .decrypt(&ct, &round_signature())
                .expect_err("another round's beacon must not decrypt");
            assert!(matches!(err, TimelockError::InvalidSignature(_)));
        }

        // -- Attacker-built ciphertexts that reach tlock's IBE ------------
        //
        // tlock 0.0.10 ends its IBE decryption in `assert_eq!(c.u, r_g)`,
        // and tlock_age runs it on the stanza body whatever the stanza's
        // round label says. Each construction below panicked there (the
        // release profile aborts) until `decrypt` checked the IBE itself.
        // Each uses the GENUINE round-1000 beacon, so the beacon check
        // passes and only the ciphertext side can refuse.

        /// `haystack` with the one occurrence of `from` replaced by `to`.
        fn replace_once(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
            let at = haystack
                .windows(from.len())
                .position(|w| w == from)
                .expect("pattern present");
            assert!(
                haystack[at + 1..].windows(from.len()).all(|w| w != from),
                "pattern must occur once"
            );
            [&haystack[..at], to, &haystack[at + from.len()..]].concat()
        }

        /// The byte range of the tlock stanza: its argument line and its
        /// three body lines (a 128-byte body is 171 base64 columns: 64, 64
        /// and 43).
        fn stanza_range(ct: &[u8]) -> std::ops::Range<usize> {
            let start = ct
                .windows(9)
                .position(|w| w == b"-> tlock ")
                .expect("tlock stanza");
            let newlines: Vec<usize> = (start..ct.len())
                .filter(|&i| ct[i] == b'\n')
                .take(4)
                .collect();
            assert_eq!(newlines[3] - newlines[2] - 1, 43, "the V/W line");
            start..newlines[3] + 1
        }

        /// `ct` with one base64 character changed in the tlock stanza
        /// body's last line, which encodes bytes 96..128: V and W.
        fn tamper_v_w(ct: &[u8]) -> Vec<u8> {
            let end = stanza_range(ct).end;
            let at = end - 1 - 43 + 20;
            let mut out = ct.to_vec();
            out[at] = if out[at] == b'A' { b'B' } else { b'A' };
            out
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn a_ciphertext_relabelled_to_the_beacons_round_is_refused_without_a_panic() {
            // Encrypted to round 1001, labelled round 1000: the round-1000
            // beacon verifies for the label, and the IBE runs with the
            // wrong key.
            let p = provider();
            let ct = p.encrypt(b"really round 1001", QUICKNET_ROUND + 1).unwrap();
            let relabelled = replace_once(&ct, b"-> tlock 1001 ", b"-> tlock 1000 ");
            assert_eq!(p.ciphertext_round(&relabelled), Ok(Some(QUICKNET_ROUND)));
            let err = p
                .decrypt(&relabelled, &round_signature())
                .expect_err("a relabelled ciphertext must not decrypt");
            assert_eq!(
                err,
                TimelockError::DecryptionFailed(IBE_INCONSISTENT.to_string())
            );
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn a_ciphertext_with_tampered_v_or_w_is_refused_without_a_panic() {
            let p = provider();
            let ct = p.encrypt(b"bound to round 1000", QUICKNET_ROUND).unwrap();
            let tampered = tamper_v_w(&ct);
            assert_ne!(tampered, ct);
            let err = p
                .decrypt(&tampered, &round_signature())
                .expect_err("a tampered ciphertext must not decrypt");
            assert_eq!(
                err,
                TimelockError::DecryptionFailed(IBE_INCONSISTENT.to_string())
            );
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn a_ciphertext_with_more_than_one_stanza_is_refused_without_a_panic() {
            // tlock_age reads the LAST tlock stanza's round as the header
            // round, and tries EVERY stanza when decrypting. A genuine
            // round-1000 stanza last, behind a round-1001 body labelled
            // 1000, verified one stanza and ran the IBE on the other.
            let p = provider();
            let honest = p.encrypt(b"bound to round 1000", QUICKNET_ROUND).unwrap();
            let other = p.encrypt(b"really round 1001", QUICKNET_ROUND + 1).unwrap();
            let decoy = replace_once(
                &other[stanza_range(&other)],
                b"-> tlock 1001 ",
                b"-> tlock 1000 ",
            );
            let at = stanza_range(&honest).start;
            let two = [&honest[..at], &decoy[..], &honest[at..]].concat();
            let err = p
                .decrypt(&two, &round_signature())
                .expect_err("two stanzas must not decrypt");
            assert_eq!(
                err,
                TimelockError::DecryptionFailed(format!("tlock header: {ONE_STANZA}"))
            );
            assert_eq!(
                p.ciphertext_round(&two),
                Err(TimelockError::DecryptionFailed(format!(
                    "tlock header: {ONE_STANZA}"
                )))
            );
        }

        // -- The header parser's refusals ----------------------------------
        //
        // Each takes an honest round-1000 ciphertext, breaks one rule of
        // the header, and requires the parser's own refusal. The message
        // is asserted exactly: with the rule removed, a later check (age's
        // header MAC, tlock_age's chain check, the base64 backstop) still
        // refuses, so only the message shows which fence held.

        fn honest() -> Vec<u8> {
            provider()
                .encrypt(b"bound to round 1000", QUICKNET_ROUND)
                .unwrap()
        }

        /// The refusal `decrypt` gives, which `ciphertext_round` must share.
        fn header_refusal(ct: &[u8]) -> TimelockError {
            let p = provider();
            let err = p
                .decrypt(ct, &round_signature())
                .expect_err("a malformed header must be refused");
            assert_eq!(p.ciphertext_round(ct), Err(err.clone()));
            err
        }

        fn header_err(why: &str) -> TimelockError {
            TimelockError::DecryptionFailed(format!("tlock header: {why}"))
        }

        /// The three body lines of the tlock stanza, as ranges without
        /// their newlines.
        fn body_lines(ct: &[u8]) -> [std::ops::Range<usize>; 3] {
            let nl: Vec<usize> = stanza_range(ct).filter(|&i| ct[i] == b'\n').collect();
            [nl[0] + 1..nl[1], nl[1] + 1..nl[2], nl[2] + 1..nl[3]]
        }

        #[test]
        fn a_non_canonical_round_is_refused() {
            let ct = honest();
            for label in [&b"-> tlock 01000 "[..], b"-> tlock +1000 "] {
                let bad = replace_once(&ct, b"-> tlock 1000 ", label);
                assert_eq!(
                    header_refusal(&bad),
                    header_err("tlock round is not a canonical integer")
                );
            }
        }

        #[test]
        fn a_stanza_for_another_chain_is_refused() {
            let ct = honest();
            let chain = hex::encode(provider().chain_info().chain_hash.clone());
            let bad = replace_once(&ct, chain.as_bytes(), "00".repeat(32).as_bytes());
            assert_eq!(
                header_refusal(&bad),
                header_err("tlock stanza is for another chain")
            );
        }

        #[test]
        fn a_body_that_is_not_u_v_w_is_refused() {
            use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
            let ct = honest();
            let lines = body_lines(&ct);
            let text: Vec<u8> = lines.iter().flat_map(|r| ct[r.clone()].to_vec()).collect();
            let body = STANDARD_NO_PAD.decode(&text).unwrap();
            assert_eq!(body.len(), 128);
            for len in [127, 129] {
                let mut other = body.clone();
                other.resize(len, 0x5a);
                let encoded = STANDARD_NO_PAD.encode(&other);
                let mut wrapped = Vec::new();
                for chunk in encoded.as_bytes().chunks(64) {
                    wrapped.extend_from_slice(chunk);
                    wrapped.push(b'\n');
                }
                if encoded.len().is_multiple_of(64) {
                    wrapped.push(b'\n');
                }
                let bad = [&ct[..lines[0].start], &wrapped[..], &ct[lines[2].end + 1..]].concat();
                assert_eq!(
                    header_refusal(&bad),
                    header_err("tlock body is not U || V || W"),
                    "a {len}-byte body"
                );
            }
        }

        #[test]
        fn a_last_body_line_of_invalid_base64_length_is_refused() {
            // 43 columns become 41: a length of 1 mod 4 encodes no bytes.
            let ct = honest();
            let last = body_lines(&ct)[2].clone();
            let bad = [&ct[..last.end - 2], &ct[last.end..]].concat();
            assert_eq!(header_refusal(&bad), header_err("malformed stanza body"));
        }

        #[test]
        fn a_last_body_line_with_trailing_bits_is_refused() {
            // A 43-column line (3 mod 4) may end only in a character whose
            // two low bits are zero; `B` leaves one set.
            let mut bad = honest();
            let last = body_lines(&bad)[2].clone();
            bad[last.end - 1] = b'B';
            assert_eq!(header_refusal(&bad), header_err("malformed stanza body"));
        }

        #[test]
        fn a_stanza_argument_outside_the_age_charset_is_refused() {
            let ct = honest();
            let bad = replace_once(&ct, b"-> tlock 1000 ", b"-> tlock 1000\x7f ");
            assert_eq!(
                header_refusal(&bad),
                header_err("malformed stanza arguments")
            );
        }

        #[test]
        fn a_body_line_longer_than_64_columns_is_refused() {
            let ct = honest();
            let first = body_lines(&ct)[0].clone();
            assert_eq!(first.len(), 64);
            let bad = [&ct[..first.end], &ct[first.end + 1..]].concat();
            assert_eq!(header_refusal(&bad), header_err("malformed stanza body"));
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
        )]
        fn an_honest_ciphertext_still_decrypts_byte_identically() {
            let p = provider();
            let sig = round_signature();
            for pt in [
                Vec::new(),
                b"x".to_vec(),
                (0..=255u8).cycle().take(5000).collect::<Vec<u8>>(),
            ] {
                let ct = p.encrypt(&pt, QUICKNET_ROUND).unwrap();
                // age 0.11 writes a random "grease" stanza beside the tlock
                // one, so stanzas of other types must stay accepted.
                let stanzas = ct.windows(4).filter(|w| w == b"\n-> ").count();
                assert_eq!(stanzas, 2, "a tlock stanza and age's grease stanza");
                assert_eq!(p.ciphertext_round(&ct), Ok(Some(QUICKNET_ROUND)));
                assert_eq!(p.decrypt(&ct, &sig).unwrap(), pt);
            }
        }

        #[test]
        fn a_beacon_with_trailing_bytes_is_refused() {
            // A slice reader ignores bytes past the 48 a G1 point needs; tlock
            // picks the curve group from the signature's LENGTH. Only an
            // exact 48-byte signature is a quicknet beacon.
            let p = provider();
            let mut long = round_signature();
            long.push(0);
            assert!(matches!(
                p.verify_round_signature(QUICKNET_ROUND, &long),
                Err(TimelockError::InvalidSignature(_))
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
