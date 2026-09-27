//! Authorship signing primitives — ML-DSA-65 (FIPS 204).
//!
//! This module implements the `sig_input` preimage construction from
//! `PROTOCOL.md` §9.3 and wraps `fips204::ml_dsa_65` keygen / sign /
//! verify so the seal and unlock pipelines can bolt on author
//! signatures without pulling the underlying crate into every caller.
//!
//! # Why pre-hash into a 32-byte digest
//!
//! `PROTOCOL.md` §9.3 defines `sig_input = SHA3-256(domain_separator
//! || version || qub_id || body_hash || unlock_at || org_id_present)`.
//! The ML-DSA-65 signing API in `fips204` takes an arbitrary message
//! plus a "context" string. We pass the 32-byte `sig_input` hash as
//! the message (with an empty context) — this binds the signature to
//! the full qub preimage while keeping the `try_sign` input short and
//! deterministic.
//!
//! # Preimage versions (V1 / V2)
//!
//! The original V1 preimage did not cover `sender_label` or `reply_to`,
//! so a post-round attacker could rewrite either field and re-encrypt
//! while the signature still verified. Newly-created signatures use the
//! domain-separated V2 preimage ([`compute_sig_input_v2`]), which folds
//! both fields in; verification tries V2 first and falls back to V1 for
//! signatures created before the rollout (see [`crate::unlock`]). The
//! pact staging / cosign flow also signs V2 (both author and cosigner);
//! the Worker's pact verification mirrors the V2-then-V1 fallback so
//! pacts staged or cosigned by pre-V2 clients remain acceptable.
//!
//! # Determinism and the seed API
//!
//! `fips204`'s default `try_keygen` / `try_sign` entry points require
//! `default-rng`, which transitively pulls in `rand_core`/`getrandom
//! 0.2` and conflicts with the workspace's `getrandom 0.3 + wasm_js`
//! backend. To avoid the conflict we use the seeded variants
//! (`KG::keygen_from_seed` and `PrivateKey::try_sign_with_seed`) and
//! draw 32-byte seeds via `getrandom::fill` directly. The caller
//! observes the same API either way — seeds never escape this module.
//!
//! # Verification
//!
//! Verification is public-data-only and is the single most expensive
//! check in the unlock pipeline. It therefore runs after every cheap
//! structural check (`body_hash`, `qub_id`, `unlock_at` equality).
//! See [`crate::unlock`] for the integration point.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use sha3::{Digest, Sha3_256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::types::{QubEnvelope, QubError};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Domain separator for `QUB_AUTHOR_SIG_V1` (`PROTOCOL.md` §9.3).
///
/// The 17 ASCII bytes of the literal string `"QUB_AUTHOR_SIG_V1"`. The
/// §9.3 prose annotates this as "18 bytes" and the individual-signing
/// preimage as "92 bytes" — those are typos; the authoritative byte
/// list in the same section enumerates 17 bytes and the individual
/// preimage is `17 + 1 + 32 + 32 + 8 + 1 = 91` bytes.
///
/// The V1 preimage does **not** cover `sender_label` or `reply_to`;
/// newly-created signatures use the V2 preimage
/// ([`AUTHOR_SIG_DOMAIN_SEPARATOR_V2`]), which does. Verification
/// accepts both (V2 first, V1 as the legacy fallback — see
/// [`crate::unlock`]).
pub const AUTHOR_SIG_DOMAIN_SEPARATOR: &[u8; 17] = b"QUB_AUTHOR_SIG_V1";

/// Domain separator for `QUB_AUTHOR_SIG_V2` (`PROTOCOL.md` §9.3).
///
/// The 17 ASCII bytes of the literal string `"QUB_AUTHOR_SIG_V2"`. The
/// V2 preimage extends V1 with two fixed-width fields so the signature
/// also covers the mutable envelope text: `sender_label_hash` (SHA3-256
/// of the NFC-normalised label, or 32 zero bytes when absent — same
/// absent-sentinel convention as [`crate::hash::title_hash`]) and
/// `reply_to_or_zero` (the 32-byte parent `qub_id`, or 32 zero bytes
/// when absent). Without this a post-round attacker could rewrite
/// `sender_label` / `reply_to` and re-encrypt while keeping
/// `signature_verified = Some(true)`.
pub const AUTHOR_SIG_DOMAIN_SEPARATOR_V2: &[u8; 17] = b"QUB_AUTHOR_SIG_V2";

/// Total size of the individual-signing `sig_input` preimage, in bytes.
///
/// `17` (domain separator) `+ 1` (version) `+ 32` (`qub_id`) `+ 32`
/// (`body_hash`) `+ 8` (`unlock_at`) `+ 1` (`org_id_present`) `= 91`.
pub const SIG_INPUT_PREIMAGE_LEN: usize = 91;

/// Total size of the individual-signing V2 `sig_input` preimage, in
/// bytes: the 91-byte V1 layout plus `sender_label_hash` (32) and
/// `reply_to_or_zero` (32) `= 155`.
pub const SIG_INPUT_V2_PREIMAGE_LEN: usize = 155;

/// `sig_alg` registry value for an unsigned qub (`PROTOCOL.md` §9.2).
pub const SIG_ALG_UNSIGNED: u8 = 0x00;

/// `sig_alg` registry value for ML-DSA-65 (`PROTOCOL.md` §9.2).
pub const SIG_ALG_ML_DSA_65: u8 = 0x01;

/// ML-DSA-65 public-key size, in bytes.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = ml_dsa_65::PK_LEN;

/// ML-DSA-65 signature size, in bytes.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = ml_dsa_65::SIG_LEN;

/// ML-DSA-65 secret-key size, in bytes.
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = ml_dsa_65::SK_LEN;

/// Phase 2 `org_id_present` byte — always `0x00` (individual signing).
///
/// `PROTOCOL.md` §9.3 reserves `0x01` for Phase 4+ org-delegated
/// signing; in that mode a 32-byte `org_id` follows. Phase 2 never
/// emits `0x01`, so the preimage length is fixed at
/// [`SIG_INPUT_PREIMAGE_LEN`].
const ORG_ID_PRESENT_INDIVIDUAL: u8 = 0x00;

// -----------------------------------------------------------------------------
// Upload-author proof-of-possession challenge
// -----------------------------------------------------------------------------

/// Domain separator for the upload-time author proof-of-possession.
///
/// Exactly 20 ASCII bytes; mirrored byte-for-byte by the Worker's
/// `buildUploadAuthorChallenge` (`workers/api/src/utils/upload-proofs.ts`).
pub const UPLOAD_AUTHOR_POP_DOMAIN: &[u8; 20] = b"QUB_UPLOAD_AUTHOR_V1";

/// Build the upload-author proof-of-possession challenge bytes.
///
/// The general upload route is byte-blind, so it cannot verify the in-envelope
/// authorship signature. This detached proof lets
/// the Worker confirm the uploader holds the secret key for the asserted
/// `Author` fingerprint before publishing pre-reveal attribution
/// (`FD-QUB-UPLOAD-001`): it binds the fingerprint to `chash`, the
/// SHA3-256 of the selected payload bytes the Worker actually received, so a
/// proof captured from one upload can't be replayed onto another.
///
/// Layout (84 bytes, raw — signed directly via ML-DSA-65, not pre-hashed):
///
/// ```text
/// "QUB_UPLOAD_AUTHOR_V1"  ||  // 20 bytes
/// author_fingerprint      ||  // [u8; 32] = SHA3-256(author pubkey)
/// chash                       // [u8; 32] = SHA3-256(selected upload bytes)
/// ```
#[must_use]
pub fn build_upload_author_pop_challenge(
    author_fingerprint: &[u8; 32],
    chash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(UPLOAD_AUTHOR_POP_DOMAIN.len() + 32 + 32);
    out.extend_from_slice(UPLOAD_AUTHOR_POP_DOMAIN);
    out.extend_from_slice(author_fingerprint);
    out.extend_from_slice(chash);
    out
}

// -----------------------------------------------------------------------------
// sig_input preimage
// -----------------------------------------------------------------------------

/// Compute the **legacy V1** `sig_input` hash.
///
/// **Retired from verification (security-audit-2026-07-14).** V1 omits
/// `sender_label` and `reply_to`; production signs and verifies the V2
/// preimage only ([`compute_sig_input_v2`], [`verify_envelope_signature`]).
/// This builder is kept solely so tests can assert a V1-preimage signature
/// is now *rejected*. Do not use it on any signing or verification path.
///
/// Implements the historical `PROTOCOL.md` §9.3 V1 preimage for individual
/// (non-org) signing:
///
/// ```text
/// sig_input = SHA3-256(
///     "QUB_AUTHOR_SIG_V1"  ||  // 17 bytes
///     version              ||  // u8, 1 byte
///     qub_id               ||  // [u8; 32]
///     body_hash            ||  // [u8; 32]
///     unlock_at            ||  // i64 big-endian, 8 bytes
///     org_id_present           // u8, 1 byte: 0x00 = individual
/// )
/// ```
///
/// The returned 32-byte hash is the value passed as the "message" to
/// `sign` / `verify` below.
#[must_use]
pub fn compute_sig_input(
    version: u8,
    qub_id: &[u8; 32],
    body_hash: &[u8; 32],
    unlock_at: i64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(AUTHOR_SIG_DOMAIN_SEPARATOR);
    hasher.update([version]);
    hasher.update(qub_id);
    hasher.update(body_hash);
    hasher.update(unlock_at.to_be_bytes());
    hasher.update([ORG_ID_PRESENT_INDIVIDUAL]);
    hasher.finalize().into()
}

/// Compute the V2 `sig_input` hash for authorship signing.
///
/// Extends the V1 preimage ([`compute_sig_input`]) so the signature also
/// covers the mutable envelope text fields (`PROTOCOL.md` §9.3):
///
/// ```text
/// sig_input_v2 = SHA3-256(
///     "QUB_AUTHOR_SIG_V2"  ||  // 17 bytes
///     version              ||  // u8, 1 byte
///     qub_id               ||  // [u8; 32]
///     body_hash            ||  // [u8; 32]
///     unlock_at            ||  // i64 big-endian, 8 bytes
///     org_id_present       ||  // u8, 1 byte: 0x00 = individual
///     sender_label_hash    ||  // [u8; 32]: SHA3-256(NFC(sender_label)),
///                              //   or 32 zero bytes when absent
///     reply_to_or_zero         // [u8; 32]: parent qub_id, or 32 zero
///                              //   bytes when absent
/// )
/// ```
///
/// All fields are fixed-width, so the preimage is exactly
/// [`SIG_INPUT_V2_PREIMAGE_LEN`] bytes and unambiguous without length
/// prefixes. The `sender_label_hash` absent sentinel mirrors
/// [`crate::hash::title_hash`]: 32 zero bytes are not a valid SHA3-256
/// output for any input, so "absent" can never collide with a present
/// label (including the empty string, which the wire format cannot
/// carry anyway).
///
/// Newly-created signatures ([`sign_envelope`] and the pact staging /
/// cosign flow) always use V2; verification tries V2 first and falls
/// back to the V1 preimage for signatures created before the V2
/// rollout (see [`crate::unlock`]).
///
/// # Examples
///
/// Cross-stack test vectors — the TypeScript mirror
/// (`workers/api/src/crypto/__tests__/sig.test.ts`) MUST produce these
/// exact digests for these inputs:
///
/// ```
/// use qub_core::signing::compute_sig_input_v2;
///
/// // Present sender_label + reply_to.
/// assert_eq!(
///     compute_sig_input_v2(
///         1,
///         &[0x11; 32],
///         &[0x22; 32],
///         1_800_000_000,
///         Some("Alice"),
///         Some(&[0x42; 32]),
///     ),
///     [
///         0x40, 0x23, 0x45, 0xf2, 0xe6, 0xa6, 0xf5, 0x21, 0x74, 0x80,
///         0x2f, 0x76, 0x7c, 0xfc, 0x41, 0x75, 0x1e, 0x85, 0x41, 0x22,
///         0x1d, 0x82, 0xe8, 0xfd, 0xbf, 0xec, 0x80, 0xf8, 0x13, 0xcf,
///         0x1c, 0x33,
///     ],
/// );
///
/// // Absent sender_label + reply_to (both 32-zero-byte sentinels).
/// assert_eq!(
///     compute_sig_input_v2(1, &[0x11; 32], &[0x22; 32], 1_800_000_000, None, None),
///     [
///         0x40, 0xfc, 0xe3, 0xc8, 0x6e, 0x13, 0x27, 0x42, 0xdc, 0x35,
///         0xd8, 0x46, 0xda, 0x83, 0x7e, 0x69, 0x52, 0x25, 0x1a, 0x68,
///         0x3c, 0xc4, 0x9d, 0xcb, 0x87, 0x40, 0xf7, 0x07, 0x1e, 0xfd,
///         0xd5, 0x5c,
///     ],
/// );
/// ```
#[must_use]
pub fn compute_sig_input_v2(
    version: u8,
    qub_id: &[u8; 32],
    body_hash: &[u8; 32],
    unlock_at: i64,
    sender_label: Option<&str>,
    reply_to: Option<&[u8; 32]>,
) -> [u8; 32] {
    let sender_label_hash: [u8; 32] = sender_label.map_or([0u8; 32], |label| {
        let nfc: String = label.nfc().collect();
        let mut hasher = Sha3_256::new();
        hasher.update(nfc.as_bytes());
        hasher.finalize().into()
    });

    let mut hasher = Sha3_256::new();
    hasher.update(AUTHOR_SIG_DOMAIN_SEPARATOR_V2);
    hasher.update([version]);
    hasher.update(qub_id);
    hasher.update(body_hash);
    hasher.update(unlock_at.to_be_bytes());
    hasher.update([ORG_ID_PRESENT_INDIVIDUAL]);
    hasher.update(sender_label_hash);
    hasher.update(reply_to.copied().unwrap_or([0u8; 32]));
    hasher.finalize().into()
}

// -----------------------------------------------------------------------------
// Keygen
// -----------------------------------------------------------------------------

/// Generate a new ML-DSA-65 keypair.
///
/// Returns `(public_key, secret_key)` as byte vectors of length
/// [`ML_DSA_65_PUBLIC_KEY_SIZE`] and [`ML_DSA_65_SECRET_KEY_SIZE`]
/// respectively. The seed is drawn from the platform RNG via
/// `getrandom`; on `wasm32-unknown-unknown` this uses the `wasm_js`
/// backend configured in the workspace.
///
/// # Errors
///
/// Returns [`QubError::SigningFailed`] if the platform RNG fails.
/// Keygen itself is infallible given a valid seed.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), QubError> {
    // Zeroizing: the 32-byte seed is the full entropy of the keypair —
    // scrub it from the heap as soon as keygen returns (SEC-5).
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| QubError::SigningFailed("RNG failed"))?;
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
}

// -----------------------------------------------------------------------------
// Sign
// -----------------------------------------------------------------------------

/// Sign a `sig_input` digest with an ML-DSA-65 secret key.
///
/// The `secret_key` must be exactly [`ML_DSA_65_SECRET_KEY_SIZE`]
/// bytes. Returns the 3,309-byte signature as a `Vec<u8>`.
///
/// # Errors
///
/// - [`QubError::WrongSignatureLength`] if `secret_key` is the wrong
///   length.
/// - [`QubError::SigningFailed`] if the platform RNG fails or
///   `fips204` reports an internal error.
pub fn sign(secret_key: &[u8], sig_input: &[u8; 32]) -> Result<Vec<u8>, QubError> {
    if secret_key.len() != ML_DSA_65_SECRET_KEY_SIZE {
        return Err(QubError::WrongSignatureLength {
            field: "secret_key",
            expected: ML_DSA_65_SECRET_KEY_SIZE,
            actual: secret_key.len(),
        });
    }

    // SerDes::try_from_bytes wants an owned fixed-size array. Zeroizing
    // scrubs our copy of the secret key from the heap on scope exit
    // (SEC-5); the deref-copy handed to `try_from_bytes` is ephemeral.
    let mut sk_bytes = Zeroizing::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]);
    sk_bytes.copy_from_slice(secret_key);
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(*sk_bytes).map_err(QubError::SigningFailed)?;

    // Zeroizing: scrub the per-signature seed once signing completes.
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| QubError::SigningFailed("RNG failed"))?;

    let sig = sk
        .try_sign_with_seed(&seed, sig_input, &[])
        .map_err(QubError::SigningFailed)?;
    Ok(sig.to_vec())
}

/// Derive the ML-DSA-65 public key from its secret key.
///
/// Portable-key unlock (SIG-1) recovers only the secret key from the blob;
/// this reconstructs the public key — and thus the full signing record —
/// locally, with no server round-trip. The recovered key's fingerprint can
/// then be checked against the blob's `primary_fingerprint` for integrity.
///
/// # Errors
///
/// - [`QubError::WrongSignatureLength`] if `secret_key` is the wrong length.
/// - [`QubError::SigningFailed`] if the bytes are not a valid ML-DSA-65 key.
pub fn public_key_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, QubError> {
    if secret_key.len() != ML_DSA_65_SECRET_KEY_SIZE {
        return Err(QubError::WrongSignatureLength {
            field: "secret_key",
            expected: ML_DSA_65_SECRET_KEY_SIZE,
            actual: secret_key.len(),
        });
    }
    let mut sk_bytes = Zeroizing::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]);
    sk_bytes.copy_from_slice(secret_key);
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(*sk_bytes).map_err(QubError::SigningFailed)?;
    Ok(sk.get_public_key().into_bytes().to_vec())
}

// -----------------------------------------------------------------------------
// Verify
// -----------------------------------------------------------------------------

/// Verify an ML-DSA-65 signature over a `sig_input` digest.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
/// structurally well-formed but fails cryptographic verification, and
/// an error if the inputs are the wrong length or the public key
/// cannot be decoded.
///
/// # Errors
///
/// - [`QubError::WrongSignatureLength`] if `public_key` or `signature`
///   is the wrong length for ML-DSA-65.
/// - [`QubError::SigningFailed`] if `fips204` cannot decode
///   `public_key`.
pub fn verify(public_key: &[u8], sig_input: &[u8; 32], signature: &[u8]) -> Result<bool, QubError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(QubError::WrongSignatureLength {
            field: "public_key",
            expected: ML_DSA_65_PUBLIC_KEY_SIZE,
            actual: public_key.len(),
        });
    }
    if signature.len() != ML_DSA_65_SIGNATURE_SIZE {
        return Err(QubError::WrongSignatureLength {
            field: "signature",
            expected: ML_DSA_65_SIGNATURE_SIZE,
            actual: signature.len(),
        });
    }

    let mut pk_bytes = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
    pk_bytes.copy_from_slice(public_key);
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(QubError::SigningFailed)?;

    let mut sig_bytes = [0u8; ML_DSA_65_SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(signature);

    Ok(pk.verify(sig_input, &sig_bytes, &[]))
}

/// Verify an envelope's author or cosigner signature against the exact
/// protocol fields carried by that envelope.
///
/// Signatures MUST commit to the V2 preimage, which covers `sender_label`
/// and `reply_to` alongside the base fields. The legacy V1 preimage (which
/// omitted those two fields) is **no longer accepted**: it was retired once
/// the pre-V2 migration window closed (security-audit-2026-07-14 — the V1
/// downgrade path was an accepted but unnecessary attack surface, and no
/// reference flow has produced a V1 signature since V2 shipped). The V1
/// builder [`compute_sig_input`] is retained only as a negative-test helper.
///
/// Structural key/signature errors are treated as a failed verification,
/// not propagated. This helper deliberately accepts the whole
/// [`QubEnvelope`] so callers cannot accidentally verify a denormalised
/// JSON projection that differs from the bytes the author actually signed.
#[must_use]
pub fn verify_envelope_signature(
    envelope: &QubEnvelope,
    public_key: &[u8],
    signature: &[u8],
) -> bool {
    let sig_input_v2 = compute_sig_input_v2(
        envelope.version(),
        envelope.qub_id(),
        envelope.body_hash(),
        envelope.unlock_at(),
        envelope.sender_label(),
        envelope.reply_to(),
    );
    verify(public_key, &sig_input_v2, signature).unwrap_or(false)
}

// -----------------------------------------------------------------------------
// Convenience: sign_envelope
// -----------------------------------------------------------------------------

/// Sign the content of a `QubEnvelope` (by its constituent fields),
/// returning `(sig_alg, signature, pubkey)`.
///
/// Convenience wrapper used by [`crate::seal`]: it computes the V2
/// `sig_input` ([`compute_sig_input_v2`]) from the supplied fields —
/// covering `sender_label` and `reply_to` in addition to the V1 fields
/// — signs it with `secret_key`, and bundles the algorithm byte,
/// signature bytes, and a copy of `public_key` into a single tuple
/// ready to be spliced onto the `QubEnvelopeBuilder`.
///
/// # Errors
///
/// Forwards any error from [`sign`] — see that function's docs for
/// the full set of failure modes.
#[allow(clippy::too_many_arguments)]
pub fn sign_envelope(
    version: u8,
    qub_id: &[u8; 32],
    body_hash: &[u8; 32],
    unlock_at: i64,
    sender_label: Option<&str>,
    reply_to: Option<&[u8; 32]>,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<(u8, Vec<u8>, Vec<u8>), QubError> {
    let sig_input = compute_sig_input_v2(
        version,
        qub_id,
        body_hash,
        unlock_at,
        sender_label,
        reply_to,
    );
    let signature = sign(secret_key, &sig_input)?;
    Ok((SIG_ALG_ML_DSA_65, signature, public_key.to_vec()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_author_pop_challenge_layout() {
        // 20-byte domain || 32-byte fingerprint || 32-byte chash = 84.
        // Pinned so the Worker's buildUploadAuthorChallenge stays in lockstep.
        assert_eq!(UPLOAD_AUTHOR_POP_DOMAIN, b"QUB_UPLOAD_AUTHOR_V1");
        assert_eq!(UPLOAD_AUTHOR_POP_DOMAIN.len(), 20);
        let fp = [0x11u8; 32];
        let chash = [0x22u8; 32];
        let c = build_upload_author_pop_challenge(&fp, &chash);
        assert_eq!(c.len(), 84);
        assert_eq!(&c[..20], UPLOAD_AUTHOR_POP_DOMAIN);
        assert_eq!(&c[20..52], &fp);
        assert_eq!(&c[52..84], &chash);
    }

    #[test]
    fn domain_separator_matches_spec() {
        // PROTOCOL.md §9.3 byte list (authoritative — the "18 bytes"
        // prose annotation in the same section is a typo).
        let expected: [u8; 17] = [
            0x51, 0x55, 0x42, 0x5F, 0x41, 0x55, 0x54, 0x48, 0x4F, 0x52, 0x5F, 0x53, 0x49, 0x47,
            0x5F, 0x56, 0x31,
        ];
        assert_eq!(AUTHOR_SIG_DOMAIN_SEPARATOR, &expected);
        assert_eq!(AUTHOR_SIG_DOMAIN_SEPARATOR.len(), 17);
    }

    #[test]
    fn sig_input_is_32_bytes() {
        let h = compute_sig_input(1, &[0u8; 32], &[0u8; 32], 1);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn sig_input_deterministic() {
        let a = compute_sig_input(1, &[7u8; 32], &[9u8; 32], 1_800_000_000);
        let b = compute_sig_input(1, &[7u8; 32], &[9u8; 32], 1_800_000_000);
        assert_eq!(a, b);
    }

    #[test]
    fn sig_input_v2_domain_separated_from_v1() {
        // With no sender_label and no reply_to, the V2 preimage differs
        // from V1 only by the domain separator and the two 32-byte zero
        // sentinels — the hashes must still differ (domain separation).
        let v1 = compute_sig_input(1, &[7u8; 32], &[9u8; 32], 1_800_000_000);
        let v2 = compute_sig_input_v2(1, &[7u8; 32], &[9u8; 32], 1_800_000_000, None, None);
        assert_ne!(v1, v2);
    }

    #[test]
    fn sig_input_v2_covers_sender_label_and_reply_to() {
        let base = compute_sig_input_v2(1, &[7u8; 32], &[9u8; 32], 1_800_000_000, None, None);
        let with_label = compute_sig_input_v2(
            1,
            &[7u8; 32],
            &[9u8; 32],
            1_800_000_000,
            Some("Alice"),
            None,
        );
        let with_other_label = compute_sig_input_v2(
            1,
            &[7u8; 32],
            &[9u8; 32],
            1_800_000_000,
            Some("Mallory"),
            None,
        );
        let with_reply = compute_sig_input_v2(
            1,
            &[7u8; 32],
            &[9u8; 32],
            1_800_000_000,
            None,
            Some(&[0x42; 32]),
        );
        let with_other_reply = compute_sig_input_v2(
            1,
            &[7u8; 32],
            &[9u8; 32],
            1_800_000_000,
            None,
            Some(&[0x43; 32]),
        );
        assert_ne!(base, with_label);
        assert_ne!(with_label, with_other_label);
        assert_ne!(base, with_reply);
        assert_ne!(with_reply, with_other_reply);
    }

    #[test]
    fn sig_input_v2_sender_label_is_nfc_equivalent() {
        // Precomposed vs decomposed forms NFC-normalise identically, so
        // the sig_input must match — mirroring title_hash semantics.
        let precomposed =
            compute_sig_input_v2(1, &[7u8; 32], &[9u8; 32], 1_800_000_000, Some("café"), None);
        let decomposed = compute_sig_input_v2(
            1,
            &[7u8; 32],
            &[9u8; 32],
            1_800_000_000,
            Some("cafe\u{0301}"),
            None,
        );
        assert_eq!(precomposed, decomposed);
    }

    #[test]
    fn v2_domain_separator_matches_spec() {
        assert_eq!(AUTHOR_SIG_DOMAIN_SEPARATOR_V2, b"QUB_AUTHOR_SIG_V2");
        assert_eq!(AUTHOR_SIG_DOMAIN_SEPARATOR_V2.len(), 17);
        assert_eq!(SIG_INPUT_V2_PREIMAGE_LEN, SIG_INPUT_PREIMAGE_LEN + 64);
    }

    #[test]
    fn generate_keypair_has_expected_sizes() {
        let (pk, sk) = generate_keypair().expect("keygen");
        assert_eq!(pk.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), ML_DSA_65_SECRET_KEY_SIZE);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn public_key_derives_from_secret() {
        let (pk, sk) = generate_keypair().expect("keygen");
        assert_eq!(public_key_from_secret(&sk).expect("derive"), pk);
    }

    #[test]
    fn public_key_from_secret_rejects_wrong_length() {
        assert!(public_key_from_secret(&[0u8; 10]).is_err());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let sig_input = compute_sig_input(1, &[1u8; 32], &[2u8; 32], 1_800_000_000);
        let sig = sign(&sk, &sig_input).expect("sign");
        assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_SIZE);
        assert!(verify(&pk, &sig_input, &sig).expect("verify"));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn verify_rejects_wrong_key() {
        let (_pk_a, sk_a) = generate_keypair().expect("keygen A");
        let (pk_b, _sk_b) = generate_keypair().expect("keygen B");
        let sig_input = compute_sig_input(1, &[1u8; 32], &[2u8; 32], 1_800_000_000);
        let sig = sign(&sk_a, &sig_input).expect("sign");
        assert!(!verify(&pk_b, &sig_input, &sig).expect("verify"));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "interprets safe ML-DSA / BLS12-381 code for minutes; see MIRI_CRYPTO in docs/TESTING-FRAMEWORK.md"
    )]
    fn verify_rejects_tampered_input() {
        let (pk, sk) = generate_keypair().expect("keygen");
        let good = compute_sig_input(1, &[1u8; 32], &[2u8; 32], 1_800_000_000);
        let bad = compute_sig_input(1, &[1u8; 32], &[2u8; 32], 1_800_000_001);
        let sig = sign(&sk, &good).expect("sign");
        assert!(!verify(&pk, &bad, &sig).expect("verify"));
    }

    #[test]
    fn sign_rejects_wrong_secret_key_length() {
        let err = sign(&[0u8; 10], &[0u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            QubError::WrongSignatureLength {
                field: "secret_key",
                expected: ML_DSA_65_SECRET_KEY_SIZE,
                actual: 10,
            }
        ));
    }

    #[test]
    fn verify_rejects_wrong_public_key_length() {
        let err = verify(&[0u8; 10], &[0u8; 32], &[0u8; ML_DSA_65_SIGNATURE_SIZE]).unwrap_err();
        assert!(matches!(
            err,
            QubError::WrongSignatureLength {
                field: "public_key",
                ..
            }
        ));
    }

    #[test]
    fn verify_rejects_wrong_signature_length() {
        let err = verify(&[0u8; ML_DSA_65_PUBLIC_KEY_SIZE], &[0u8; 32], &[0u8; 10]).unwrap_err();
        assert!(matches!(
            err,
            QubError::WrongSignatureLength {
                field: "signature",
                ..
            }
        ));
    }
}
