//! Portable signing-key envelope (SIG-1 Phase 1).
//!
//! Lets one human's ML-DSA-65 signing key follow their account across
//! devices without the server ever holding the plaintext key. The key is
//! sealed under **envelope encryption**:
//!
//! ```text
//! random KEK ──AES-256-GCM(aad = account_id)──> wraps the ML-DSA secret key
//! KEK        ──AES-256-GCM(per factor)────────> wrapped once per unlock factor
//! ```
//!
//! A new device recovers the KEK from **any one** enrolled factor, then
//! unwraps the secret key. Adding a factor re-wraps the same KEK; the
//! secret-key ciphertext is written exactly once. See
//! `tasks/portable-keys-design.md` §3.
//!
//! # Factors
//!
//! - **Passkey (PRF).** The unlock secret is the 32-byte `WebAuthn` PRF
//!   output for a synced passkey (Spike S1 confirmed it is stable across a
//!   user's synced devices). The `credential_id` identifies the passkey and
//!   is bound as AEAD AAD.
//! - **Recovery code.** A high-entropy (≥128-bit) random code the user
//!   keeps. It is the cross-ecosystem bridge and the fallback for browsers
//!   without PRF.
//!
//! # Key derivation
//!
//! Both factor inputs are **already high-entropy and uniform** (a PRF/HMAC
//! output, or a 128-bit random code), so a memory-hard or HKDF-extract step
//! buys nothing. The factor key is derived with a single domain-separated
//! SHA3-256 — sound for uniform input, and SHA3 is not length-extendable.
//! (A *user-chosen passphrase* would be low-entropy and would need Argon2id;
//! that is the reserved method-3 variant, not built here.)
//!
//! # Honest-commitments note
//!
//! This is the deliberate, minimised exception to "the key never leaves the
//! device": it leaves only as `account_id`-bound AES-256-GCM ciphertext plus
//! per-factor wrapped KEKs. The server stores those bytes and can never
//! decrypt them — it holds no passphrase, recovery code, PRF output, or
//! plaintext key. Threat scope matches the device-local at-rest wrap: this
//! does not defend against same-origin XSS (the CSP layer owns that).

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use ciborium::Value;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cbor::{
    CborError, assert_canonical_key_order, encode_map, extract_text, extract_u8,
    parse_top_level_map, parsed_map_from_entries, reject_structural_elements_in_map,
    reject_unknown_keys, text, to_nfc, u8_value,
};
use crate::signing::ML_DSA_65_SECRET_KEY_SIZE;
use crate::wire::is_cbor_map_header;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Blob format version. AES-256-GCM envelope, SHA3-256 factor KDF.
pub const PORTABLE_KEY_VERSION_1: u8 = 0x01;

/// KEK / factor-key length, in bytes (AES-256).
pub const PORTABLE_KEK_LEN: usize = 32;

/// AES-256-GCM nonce length, in bytes (96 bits).
pub const PORTABLE_NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length, in bytes (128 bits).
pub const PORTABLE_TAG_LEN: usize = 16;

/// `WebAuthn` PRF "first" output length, in bytes.
pub const PRF_OUTPUT_LEN: usize = 32;

/// Per-recovery-wrap salt length, in bytes. Domain-separates the factor-key
/// derivation across blobs so the same code never yields the same key twice.
pub const RECOVERY_SALT_LEN: usize = 16;

/// Minimum recovery-code input length. The recovery flow generates uniformly
/// random bytes, so 16 bytes is the documented 128-bit floor.
pub const MIN_RECOVERY_CODE_LEN: usize = 16;

/// Internal factor-key length (AES-256).
const FK_LEN: usize = PORTABLE_KEK_LEN;

/// Domain separator for the passkey-PRF factor key.
const PRF_FK_DOMAIN: &[u8] = b"qub/portable-key/prf-fk/v1";

/// Domain separator for the recovery-code factor key.
const RECOVERY_FK_DOMAIN: &[u8] = b"qub/portable-key/recovery-fk/v1";

/// AEAD AAD for a recovery-code KEK wrap. (The passkey wrap uses the
/// `credential_id` as AAD.)
const RECOVERY_WRAP_AAD: &[u8] = b"qub/portable-key/recovery";

/// Domain separator for a portable-key create/replacement proof. Mirrors
/// `KEYBLOB_STORE_CHALLENGE_DOMAIN` in the Worker.
pub const KEYBLOB_STORE_CHALLENGE_DOMAIN: &[u8; 20] = b"QUB_KEYBLOB_STORE_V1";

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors produced by the portable-key envelope.
///
/// `#[non_exhaustive]`: additional variants may be added in minor releases.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PortableKeyError {
    /// AEAD encryption failed. Unreachable for a well-formed 32-byte key,
    /// 12-byte nonce, and bounded plaintext; surfaced defensively.
    #[error("portable key: AEAD encryption failed")]
    EncryptFailed,

    /// Unlock failed: wrong factor secret, wrong credential, or a tampered
    /// blob. `aes-gcm` collapses these into one error so timing channels
    /// cannot distinguish them.
    #[error("portable key: unlock failed (wrong factor secret or tampered blob)")]
    UnlockFailed,

    /// No enrolled wrap matches the supplied factor (e.g. this passkey's
    /// `credential_id` was never enrolled, or there is no recovery wrap).
    /// Distinct from [`PortableKeyError::UnlockFailed`] so a caller can try
    /// another factor; `credential_id` is not secret.
    #[error("portable key: no enrolled wrap matches the supplied factor")]
    NoMatchingWrap,

    /// The secret key is not [`ML_DSA_65_SECRET_KEY_SIZE`] bytes.
    #[error("portable key: secret key must be {expected} bytes, got {actual}")]
    BadSecretKeyLen {
        /// Expected length.
        expected: usize,
        /// Actual length supplied.
        actual: usize,
    },

    /// `create_blob` was called with no factors — the key would be
    /// unrecoverable.
    #[error("portable key: at least one unlock factor is required")]
    NoFactors,

    /// The account identifier is AEAD-bound and must identify an account.
    #[error("portable key: account_id must not be empty")]
    EmptyAccountId,

    /// A passkey wrap without a credential id can never be selected safely.
    #[error("portable key: passkey credential_id must not be empty")]
    EmptyCredentialId,

    /// Recovery codes must carry at least 128 bits of source material.
    #[error("portable key: recovery code must be at least {min} bytes, got {actual}")]
    RecoveryCodeTooShort {
        /// Minimum accepted byte length.
        min: usize,
        /// Actual supplied byte length.
        actual: usize,
    },

    /// CBOR encoding or decoding of the blob failed (malformed,
    /// non-canonical, wrong field type/length, duplicate key, etc.).
    #[error("portable key: CBOR error: {0}")]
    Cbor(#[from] CborError),

    /// The blob version byte is not [`PORTABLE_KEY_VERSION_1`].
    #[error("portable key: unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// The `wraps` field was present but not a CBOR array.
    #[error("portable key: `wraps` is not a CBOR array")]
    WrapsNotAnArray,

    /// A `wraps` element was not a CBOR map.
    #[error("portable key: wrap entry is not a CBOR map")]
    WrapNotAMap,

    /// A wrap carried an unrecognised `method` discriminant.
    #[error("portable key: unknown wrap method: {0}")]
    UnknownWrapMethod(u8),

    /// More than [`MAX_WRAPS`] wrap entries — a malformed or hostile blob.
    #[error("portable key: too many wraps: {count} (max {max})")]
    TooManyWraps {
        /// Number of wraps found.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// -----------------------------------------------------------------------------
// Wrap entries + blob
// -----------------------------------------------------------------------------

/// One way to recover the KEK. The KEK is wrapped once per enrolled factor;
/// any single one unlocks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapEntry {
    /// KEK wrapped under the passkey-PRF factor key. `credential_id`
    /// identifies the passkey and is bound as AEAD AAD.
    PasskeyPrf {
        /// `WebAuthn` credential id of the enrolled passkey.
        credential_id: Vec<u8>,
        /// AEAD nonce for this wrap.
        wrap_iv: [u8; PORTABLE_NONCE_LEN],
        /// AES-256-GCM ciphertext of the KEK (with 16-byte tag).
        kek_ciphertext: Vec<u8>,
    },
    /// KEK wrapped under the recovery-code factor key.
    RecoveryCode {
        /// Per-wrap KDF salt.
        salt: [u8; RECOVERY_SALT_LEN],
        /// AEAD nonce for this wrap.
        wrap_iv: [u8; PORTABLE_NONCE_LEN],
        /// AES-256-GCM ciphertext of the KEK (with 16-byte tag).
        kek_ciphertext: Vec<u8>,
    },
}

/// In-memory portable signing-key blob.
///
/// Public construction is via [`create_blob`], which validates the account and
/// factors before encrypting. [`PortableKeyBlobCbor::parse`] is the only public
/// path for restoring a serialized blob; the unchecked parts constructor stays
/// crate-private so downstream callers cannot hand-craft contradictory state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableKeyBlob {
    version: u8,
    account_id: String,
    primary_fingerprint: [u8; 32],
    sk_iv: [u8; PORTABLE_NONCE_LEN],
    sk_ciphertext: Vec<u8>,
    wraps: Vec<WrapEntry>,
}

impl PortableKeyBlob {
    /// Blob format version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Account this blob belongs to (also the secret-key wrap's AAD).
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The canonical fingerprint this blob is the signing key for.
    #[must_use]
    pub const fn primary_fingerprint(&self) -> &[u8; 32] {
        &self.primary_fingerprint
    }

    /// AEAD nonce for the secret-key wrap.
    #[must_use]
    pub const fn sk_iv(&self) -> &[u8; PORTABLE_NONCE_LEN] {
        &self.sk_iv
    }

    /// AES-256-GCM ciphertext of the ML-DSA secret key (with 16-byte tag).
    #[must_use]
    pub fn sk_ciphertext(&self) -> &[u8] {
        &self.sk_ciphertext
    }

    /// The enrolled KEK wraps.
    #[must_use]
    pub fn wraps(&self) -> &[WrapEntry] {
        &self.wraps
    }

    /// Reassemble a blob from already-encrypted parts.
    ///
    /// For the CBOR decoder only — it does no encryption and assumes the
    /// parts came from a prior [`create_blob`]. Callers must not hand-craft
    /// ciphertext.
    #[must_use]
    pub(crate) const fn from_parts(
        version: u8,
        account_id: String,
        primary_fingerprint: [u8; 32],
        sk_iv: [u8; PORTABLE_NONCE_LEN],
        sk_ciphertext: Vec<u8>,
        wraps: Vec<WrapEntry>,
    ) -> Self {
        Self {
            version,
            account_id,
            primary_fingerprint,
            sk_iv,
            sk_ciphertext,
            wraps,
        }
    }
}

// -----------------------------------------------------------------------------
// Create / unlock inputs
// -----------------------------------------------------------------------------

/// Inputs to [`create_blob`] common to every factor.
///
/// `kek` and `sk_iv` are caller-supplied so the function is deterministic
/// and testable without an RNG; production callers generate them via
/// `getrandom` (wasm) or `crypto.getRandomValues` (Worker).
// No `Debug`: holds the plaintext secret key + KEK (secret-no-debug gate).
#[derive(Clone, Copy)]
pub struct PortableKeyInputs<'a> {
    /// The ML-DSA-65 secret key bytes to seal.
    pub secret_key: &'a [u8],
    /// Account identifier — bound as AAD on the secret-key wrap.
    pub account_id: &'a str,
    /// The account's canonical signing fingerprint.
    pub primary_fingerprint: &'a [u8; 32],
    /// Random 256-bit key-encryption key.
    pub kek: &'a [u8; PORTABLE_KEK_LEN],
    /// AEAD nonce for the secret-key wrap.
    pub sk_iv: &'a [u8; PORTABLE_NONCE_LEN],
}

/// A factor to enrol when creating (or extending) a blob. Per-wrap nonces
/// and salts are caller-supplied for testability.
// No `Debug`: carries the PRF output / recovery code (secret material).
#[derive(Clone)]
pub enum NewFactor<'a> {
    /// Enrol a passkey via its PRF output.
    PasskeyPrf {
        /// `WebAuthn` credential id of the passkey.
        credential_id: Vec<u8>,
        /// The passkey's 32-byte PRF output for the agreed salt.
        prf_output: &'a [u8; PRF_OUTPUT_LEN],
        /// AEAD nonce for this wrap.
        wrap_iv: [u8; PORTABLE_NONCE_LEN],
    },
    /// Enrol a high-entropy recovery code.
    RecoveryCode {
        /// The recovery code bytes (≥128-bit entropy).
        code: &'a [u8],
        /// Per-wrap KDF salt.
        salt: [u8; RECOVERY_SALT_LEN],
        /// AEAD nonce for this wrap.
        wrap_iv: [u8; PORTABLE_NONCE_LEN],
    },
}

/// A factor secret presented to [`unlock_blob`].
// No `Debug`: carries the PRF output / recovery code (secret material).
#[derive(Clone, Copy)]
pub enum FactorSecret<'a> {
    /// Unlock with a passkey's PRF output for a specific credential.
    PasskeyPrf {
        /// The credential id whose wrap to use.
        credential_id: &'a [u8],
        /// The passkey's 32-byte PRF output.
        prf_output: &'a [u8; PRF_OUTPUT_LEN],
    },
    /// Unlock with the recovery code.
    RecoveryCode(&'a [u8]),
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Derive the per-account `WebAuthn` PRF salt from the canonical signing
/// fingerprint.
///
/// This is the input handed to the browser's `prf.eval.first`; the
/// authenticator domain-separates it again internally. Keying it on the
/// account's canonical fingerprint makes the salt **stable and identical on
/// every device** (the fingerprint is the one canonical key) and distinct per
/// account. 32 bytes.
#[must_use]
pub fn prf_salt(primary_fingerprint: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"qub/portable-key/prf-salt/v1");
    hasher.update(primary_fingerprint);
    hasher.finalize().into()
}

/// Build the current-key proof-of-possession challenge for a portable-key
/// blob create or replacement.
///
/// The fixed-width preimage binds the immutable account, canonical signing
/// fingerprint, exact canonical-CBOR blob bytes, compare-and-swap revision,
/// and freshness timestamp:
///
/// ```text
/// QUB_KEYBLOB_STORE_V1           20 bytes
/// SHA3-256(account_id UTF-8)     32 bytes
/// primary_fingerprint            32 bytes
/// SHA3-256(blob)                 32 bytes
/// expected_revision (u64 BE)      8 bytes
/// timestamp (i64 BE)              8 bytes
/// ```
///
/// The Worker reconstructs these bytes before ML-DSA-65 verification. A
/// signature therefore cannot authorize a different blob, account, revision,
/// or timestamp.
#[must_use]
pub fn build_keyblob_store_challenge(
    account_id: &str,
    primary_fingerprint: &[u8; 32],
    blob: &[u8],
    expected_revision: u64,
    timestamp: i64,
) -> Vec<u8> {
    let account_hash: [u8; 32] = Sha3_256::digest(account_id.as_bytes()).into();
    let blob_hash: [u8; 32] = Sha3_256::digest(blob).into();
    let mut out = Vec::with_capacity(132);
    out.extend_from_slice(KEYBLOB_STORE_CHALLENGE_DOMAIN);
    out.extend_from_slice(&account_hash);
    out.extend_from_slice(primary_fingerprint);
    out.extend_from_slice(&blob_hash);
    out.extend_from_slice(&expected_revision.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// Seal a secret key into a portable blob, wrapping the KEK under each
/// supplied factor.
///
/// # Errors
///
/// - [`PortableKeyError::BadSecretKeyLen`] if `secret_key` is not
///   [`ML_DSA_65_SECRET_KEY_SIZE`] bytes.
/// - [`PortableKeyError::NoFactors`] if `factors` is empty.
/// - [`PortableKeyError::EncryptFailed`] if AEAD encryption fails.
pub fn create_blob(
    inputs: &PortableKeyInputs<'_>,
    factors: &[NewFactor<'_>],
) -> Result<PortableKeyBlob, PortableKeyError> {
    if inputs.secret_key.len() != ML_DSA_65_SECRET_KEY_SIZE {
        return Err(PortableKeyError::BadSecretKeyLen {
            expected: ML_DSA_65_SECRET_KEY_SIZE,
            actual: inputs.secret_key.len(),
        });
    }
    if factors.is_empty() {
        return Err(PortableKeyError::NoFactors);
    }
    let account_id = to_nfc(inputs.account_id);
    if account_id.is_empty() {
        return Err(PortableKeyError::EmptyAccountId);
    }
    // Enforce the decode-side caps at construction: a blob with 33+
    // wraps or an oversized account_id would serialise and store fine,
    // then fail `parse()` on the recovery device — the portable key
    // would be unrecoverable despite a successful enrolment.
    if factors.len() > MAX_WRAPS {
        return Err(PortableKeyError::TooManyWraps {
            count: factors.len(),
            max: MAX_WRAPS,
        });
    }
    let account_chars = account_id.chars().count();
    if account_chars > MAX_ACCOUNT_ID_CHARS {
        return Err(CborError::PayloadTooLarge {
            field: "account_id",
            size: account_chars,
            max: MAX_ACCOUNT_ID_CHARS,
        }
        .into());
    }

    for factor in factors {
        match factor {
            NewFactor::PasskeyPrf { credential_id, .. } => {
                if credential_id.is_empty() {
                    return Err(PortableKeyError::EmptyCredentialId);
                }
                if credential_id.len() > MAX_CREDENTIAL_ID {
                    return Err(CborError::PayloadTooLarge {
                        field: "credential_id",
                        size: credential_id.len(),
                        max: MAX_CREDENTIAL_ID,
                    }
                    .into());
                }
            },
            NewFactor::RecoveryCode { code, .. } if code.len() < MIN_RECOVERY_CODE_LEN => {
                return Err(PortableKeyError::RecoveryCodeTooShort {
                    min: MIN_RECOVERY_CODE_LEN,
                    actual: code.len(),
                });
            },
            NewFactor::RecoveryCode { .. } => {},
        }
    }

    // 1. Wrap the secret key under the KEK, bound to the account.
    let sk_ciphertext = seal(
        inputs.kek,
        inputs.sk_iv,
        account_id.as_bytes(),
        inputs.secret_key,
    )?;

    // 2. Wrap the KEK under each factor.
    let mut wraps = Vec::with_capacity(factors.len());
    for factor in factors {
        match factor {
            NewFactor::PasskeyPrf {
                credential_id,
                prf_output,
                wrap_iv,
            } => {
                let fk = derive_prf_fk(prf_output);
                let kek_ciphertext = seal(&fk[..], wrap_iv, credential_id, inputs.kek)?;
                wraps.push(WrapEntry::PasskeyPrf {
                    credential_id: credential_id.clone(),
                    wrap_iv: *wrap_iv,
                    kek_ciphertext,
                });
            },
            NewFactor::RecoveryCode {
                code,
                salt,
                wrap_iv,
            } => {
                let fk = derive_recovery_fk(salt, code);
                let kek_ciphertext = seal(&fk[..], wrap_iv, RECOVERY_WRAP_AAD, inputs.kek)?;
                wraps.push(WrapEntry::RecoveryCode {
                    salt: *salt,
                    wrap_iv: *wrap_iv,
                    kek_ciphertext,
                });
            },
        }
    }

    Ok(PortableKeyBlob {
        version: PORTABLE_KEY_VERSION_1,
        account_id,
        primary_fingerprint: *inputs.primary_fingerprint,
        sk_iv: *inputs.sk_iv,
        sk_ciphertext,
        wraps,
    })
}

/// Recover the secret key from a blob using one factor secret.
///
/// Returns the plaintext ML-DSA secret key in a [`Zeroizing`] buffer.
///
/// # Errors
///
/// - [`PortableKeyError::NoMatchingWrap`] if no enrolled wrap matches the
///   factor type / credential.
/// - [`PortableKeyError::UnlockFailed`] if a matching wrap is present but
///   the secret is wrong or the blob was tampered with.
pub fn unlock_blob(
    blob: &PortableKeyBlob,
    factor: &FactorSecret<'_>,
) -> Result<Zeroizing<Vec<u8>>, PortableKeyError> {
    let kek = recover_kek(blob, factor)?;
    open(
        &kek[..],
        &blob.sk_iv,
        blob.account_id.as_bytes(),
        &blob.sk_ciphertext,
    )
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

fn recover_kek(
    blob: &PortableKeyBlob,
    factor: &FactorSecret<'_>,
) -> Result<Zeroizing<[u8; PORTABLE_KEK_LEN]>, PortableKeyError> {
    let mut matched = false;
    for wrap in &blob.wraps {
        match (wrap, factor) {
            (
                WrapEntry::PasskeyPrf {
                    credential_id,
                    wrap_iv,
                    kek_ciphertext,
                },
                FactorSecret::PasskeyPrf {
                    credential_id: want,
                    prf_output,
                },
            ) if credential_id.as_slice() == *want => {
                matched = true;
                let fk = derive_prf_fk(prf_output);
                if let Ok(kek) = open(&fk[..], wrap_iv, credential_id, kek_ciphertext) {
                    return into_kek(&kek);
                }
            },
            (
                WrapEntry::RecoveryCode {
                    salt,
                    wrap_iv,
                    kek_ciphertext,
                },
                FactorSecret::RecoveryCode(code),
            ) => {
                matched = true;
                let fk = derive_recovery_fk(salt, code);
                if let Ok(kek) = open(&fk[..], wrap_iv, RECOVERY_WRAP_AAD, kek_ciphertext) {
                    return into_kek(&kek);
                }
            },
            _ => {},
        }
    }
    Err(if matched {
        PortableKeyError::UnlockFailed
    } else {
        PortableKeyError::NoMatchingWrap
    })
}

/// Derive the passkey factor key. The PRF output is uniform high-entropy, so
/// a single domain-separated SHA3-256 is a sound KDF (see module docs).
fn derive_prf_fk(prf_output: &[u8; PRF_OUTPUT_LEN]) -> Zeroizing<[u8; FK_LEN]> {
    let mut hasher = Sha3_256::new();
    hasher.update(PRF_FK_DOMAIN);
    hasher.update(prf_output);
    Zeroizing::new(hasher.finalize().into())
}

/// Derive the recovery-code factor key. The code is high-entropy; `salt`
/// domain-separates the derivation per blob.
fn derive_recovery_fk(salt: &[u8; RECOVERY_SALT_LEN], code: &[u8]) -> Zeroizing<[u8; FK_LEN]> {
    let mut hasher = Sha3_256::new();
    hasher.update(RECOVERY_FK_DOMAIN);
    hasher.update(salt);
    hasher.update(code);
    Zeroizing::new(hasher.finalize().into())
}

fn into_kek(plaintext: &[u8]) -> Result<Zeroizing<[u8; PORTABLE_KEK_LEN]>, PortableKeyError> {
    if plaintext.len() != PORTABLE_KEK_LEN {
        return Err(PortableKeyError::UnlockFailed);
    }
    let mut kek = Zeroizing::new([0u8; PORTABLE_KEK_LEN]);
    kek.copy_from_slice(plaintext);
    Ok(kek)
}

fn seal(
    key: &[u8],
    iv: &[u8; PORTABLE_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PortableKeyError> {
    if key.len() != PORTABLE_KEK_LEN {
        return Err(PortableKeyError::EncryptFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PortableKeyError::EncryptFailed)?;
    cipher
        .encrypt(
            iv.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PortableKeyError::EncryptFailed)
}

fn open(
    key: &[u8],
    iv: &[u8; PORTABLE_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PortableKeyError> {
    if key.len() != PORTABLE_KEK_LEN {
        return Err(PortableKeyError::UnlockFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PortableKeyError::UnlockFailed)?;
    cipher
        .decrypt(
            iv.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| PortableKeyError::UnlockFailed)
}

// -----------------------------------------------------------------------------
// CBOR wire format
// -----------------------------------------------------------------------------
//
// Hand-written canonical CBOR per the no-serde rule (ARCHITECTURE.md §Wire
// format). The blob is a definite-length map; `wraps` is an array of
// definite-length maps. Canonical key order = encoded-byte-length ascending,
// then lexicographic, matching `crate::cbor`'s convention.

/// `method` discriminant for a passkey-PRF wrap.
const WRAP_METHOD_PASSKEY_PRF: u8 = 1;

/// `method` discriminant for a recovery-code wrap.
const WRAP_METHOD_RECOVERY_CODE: u8 = 2;

/// Decode bound: maximum `account_id` length, in code points (RFC 5321).
const MAX_ACCOUNT_ID_CHARS: usize = 254;

/// Decode bound: maximum `credential_id` length, in bytes (`WebAuthn` ids
/// are ≤ 1023 bytes).
const MAX_CREDENTIAL_ID: usize = 1024;

/// Decode bound: maximum secret-key ciphertext length, in bytes.
const MAX_SK_CIPHERTEXT: usize = ML_DSA_65_SECRET_KEY_SIZE + 64;

/// Decode bound: maximum KEK ciphertext length, in bytes.
const MAX_KEK_CIPHERTEXT: usize = PORTABLE_KEK_LEN + 64;

/// Decode bound: maximum number of wrap entries.
pub const MAX_WRAPS: usize = 32;

impl PortableKeyBlob {
    /// Serialise to canonical CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PortableKeyError::Cbor`] if CBOR encoding fails (unreachable
    /// for a well-formed blob).
    pub fn to_cbor(&self) -> Result<PortableKeyBlobCbor, PortableKeyError> {
        Ok(PortableKeyBlobCbor(serialize_blob(self)?))
    }
}

fn serialize_wrap(wrap: &WrapEntry) -> Value {
    match wrap {
        WrapEntry::PasskeyPrf {
            credential_id,
            wrap_iv,
            kek_ciphertext,
        } => {
            // Canonical order: method(7) < wrap_iv(8) < credential_id(14) < kek_ciphertext(15).
            let map = vec![
                (text("method"), u8_value(WRAP_METHOD_PASSKEY_PRF)),
                (text("wrap_iv"), Value::Bytes(wrap_iv.to_vec())),
                (text("credential_id"), Value::Bytes(credential_id.clone())),
                (text("kek_ciphertext"), Value::Bytes(kek_ciphertext.clone())),
            ];
            assert_canonical_key_order(&["method", "wrap_iv", "credential_id", "kek_ciphertext"]);
            Value::Map(map)
        },
        WrapEntry::RecoveryCode {
            salt,
            wrap_iv,
            kek_ciphertext,
        } => {
            // Canonical order: salt(5) < method(7) < wrap_iv(8) < kek_ciphertext(15).
            let map = vec![
                (text("salt"), Value::Bytes(salt.to_vec())),
                (text("method"), u8_value(WRAP_METHOD_RECOVERY_CODE)),
                (text("wrap_iv"), Value::Bytes(wrap_iv.to_vec())),
                (text("kek_ciphertext"), Value::Bytes(kek_ciphertext.clone())),
            ];
            assert_canonical_key_order(&["salt", "method", "wrap_iv", "kek_ciphertext"]);
            Value::Map(map)
        },
    }
}

fn serialize_blob(blob: &PortableKeyBlob) -> Result<Vec<u8>, CborError> {
    let wraps = Value::Array(blob.wraps.iter().map(serialize_wrap).collect());
    // Canonical order: sk_iv(6) < wraps(6) < version(8) < account_id(11)
    //               < sk_ciphertext(14) < primary_fingerprint(20).
    let map = vec![
        (text("sk_iv"), Value::Bytes(blob.sk_iv.to_vec())),
        (text("wraps"), wraps),
        (text("version"), u8_value(blob.version)),
        (text("account_id"), text(&to_nfc(&blob.account_id))),
        (
            text("sk_ciphertext"),
            Value::Bytes(blob.sk_ciphertext.clone()),
        ),
        (
            text("primary_fingerprint"),
            Value::Bytes(blob.primary_fingerprint.to_vec()),
        ),
    ];
    assert_canonical_key_order(&[
        "sk_iv",
        "wraps",
        "version",
        "account_id",
        "sk_ciphertext",
        "primary_fingerprint",
    ]);
    encode_map(map)
}

fn deserialize_wrap(value: &Value) -> Result<WrapEntry, PortableKeyError> {
    let Value::Map(entries) = value else {
        return Err(PortableKeyError::WrapNotAMap);
    };
    let map = parsed_map_from_entries(entries)?;
    let method = extract_u8(&map, "method")?;
    match method {
        WRAP_METHOD_PASSKEY_PRF => {
            reject_unknown_keys(
                &map,
                &["method", "wrap_iv", "credential_id", "kek_ciphertext"],
                "WrapEntry::PasskeyPrf",
            )?;
            let credential_id = extract_bytes_bounded(&map, "credential_id", MAX_CREDENTIAL_ID)?;
            if credential_id.is_empty() {
                return Err(PortableKeyError::EmptyCredentialId);
            }
            let kek_ciphertext = extract_bytes_bounded(&map, "kek_ciphertext", MAX_KEK_CIPHERTEXT)?;
            let expected = PORTABLE_KEK_LEN + PORTABLE_TAG_LEN;
            if kek_ciphertext.len() != expected {
                return Err(CborError::WrongLength {
                    field: "kek_ciphertext",
                    expected,
                    actual: kek_ciphertext.len(),
                }
                .into());
            }
            Ok(WrapEntry::PasskeyPrf {
                credential_id,
                wrap_iv: extract_fixed_bytes::<PORTABLE_NONCE_LEN>(&map, "wrap_iv")?,
                kek_ciphertext,
            })
        },
        WRAP_METHOD_RECOVERY_CODE => {
            reject_unknown_keys(
                &map,
                &["salt", "method", "wrap_iv", "kek_ciphertext"],
                "WrapEntry::RecoveryCode",
            )?;
            let kek_ciphertext = extract_bytes_bounded(&map, "kek_ciphertext", MAX_KEK_CIPHERTEXT)?;
            let expected = PORTABLE_KEK_LEN + PORTABLE_TAG_LEN;
            if kek_ciphertext.len() != expected {
                return Err(CborError::WrongLength {
                    field: "kek_ciphertext",
                    expected,
                    actual: kek_ciphertext.len(),
                }
                .into());
            }
            Ok(WrapEntry::RecoveryCode {
                salt: extract_fixed_bytes::<RECOVERY_SALT_LEN>(&map, "salt")?,
                wrap_iv: extract_fixed_bytes::<PORTABLE_NONCE_LEN>(&map, "wrap_iv")?,
                kek_ciphertext,
            })
        },
        other => Err(PortableKeyError::UnknownWrapMethod(other)),
    }
}

fn deserialize_blob(bytes: &[u8]) -> Result<PortableKeyBlob, PortableKeyError> {
    let map = parse_top_level_map(bytes)?;
    // Allows the expected `wraps` array-of-maps (it recurses arrays + maps),
    // rejecting only forbidden tags/floats at any depth.
    reject_structural_elements_in_map(&map)?;
    reject_unknown_keys(
        &map,
        &[
            "sk_iv",
            "wraps",
            "version",
            "account_id",
            "sk_ciphertext",
            "primary_fingerprint",
        ],
        "PortableKeyBlob",
    )?;

    let version = extract_u8(&map, "version")?;
    if version != PORTABLE_KEY_VERSION_1 {
        return Err(PortableKeyError::UnsupportedVersion(version));
    }

    let account_id = extract_text(&map, "account_id")?;
    if account_id.is_empty() {
        return Err(PortableKeyError::EmptyAccountId);
    }
    let chars = account_id.chars().count();
    if chars > MAX_ACCOUNT_ID_CHARS {
        return Err(CborError::PayloadTooLarge {
            field: "account_id",
            size: chars,
            max: MAX_ACCOUNT_ID_CHARS,
        }
        .into());
    }

    let primary_fingerprint = extract_fixed_bytes::<32>(&map, "primary_fingerprint")?;
    let sk_iv = extract_fixed_bytes::<PORTABLE_NONCE_LEN>(&map, "sk_iv")?;
    let sk_ciphertext = extract_bytes_bounded(&map, "sk_ciphertext", MAX_SK_CIPHERTEXT)?;
    let expected_sk_ciphertext = ML_DSA_65_SECRET_KEY_SIZE + PORTABLE_TAG_LEN;
    if sk_ciphertext.len() != expected_sk_ciphertext {
        return Err(CborError::WrongLength {
            field: "sk_ciphertext",
            expected: expected_sk_ciphertext,
            actual: sk_ciphertext.len(),
        }
        .into());
    }

    let wraps_value = find_value(&map, "wraps").ok_or(CborError::MissingField("wraps"))?;
    let Value::Array(items) = wraps_value else {
        return Err(PortableKeyError::WrapsNotAnArray);
    };
    if items.len() > MAX_WRAPS {
        return Err(PortableKeyError::TooManyWraps {
            count: items.len(),
            max: MAX_WRAPS,
        });
    }
    if items.is_empty() {
        return Err(PortableKeyError::NoFactors);
    }
    let mut wraps = Vec::with_capacity(items.len());
    for item in items {
        wraps.push(deserialize_wrap(item)?);
    }

    Ok(PortableKeyBlob::from_parts(
        version,
        account_id,
        primary_fingerprint,
        sk_iv,
        sk_ciphertext,
        wraps,
    ))
}

// Local extractors operating on the parsed-map slice — mirror the
// file-private ones in `crate::cbor` (reproduced rather than widening their
// visibility, matching `wrapper.rs`).

fn find_value<'a>(map: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

const fn cbor_type_name(v: &Value) -> &'static str {
    match v {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
        _ => "unknown",
    }
}

fn extract_bytes(map: &[(String, Value)], key: &'static str) -> Result<Vec<u8>, CborError> {
    match find_value(map, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(other) => Err(CborError::UnexpectedType {
            field: key,
            expected: "bytes",
            actual: cbor_type_name(other),
        }),
        None => Err(CborError::MissingField(key)),
    }
}

fn extract_bytes_bounded(
    map: &[(String, Value)],
    key: &'static str,
    max_size: usize,
) -> Result<Vec<u8>, CborError> {
    let bytes = extract_bytes(map, key)?;
    if bytes.len() > max_size {
        return Err(CborError::PayloadTooLarge {
            field: key,
            size: bytes.len(),
            max: max_size,
        });
    }
    Ok(bytes)
}

fn extract_fixed_bytes<const N: usize>(
    map: &[(String, Value)],
    key: &'static str,
) -> Result<[u8; N], CborError> {
    let bytes = extract_bytes(map, key)?;
    if bytes.len() != N {
        return Err(CborError::WrongLength {
            field: key,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Canonical CBOR bytes of a [`PortableKeyBlob`].
///
/// Construction is restricted to serialising a blob
/// ([`PortableKeyBlob::to_cbor`]) or wrapping bytes the canonical serialiser
/// already produced ([`Self::from_encoded`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableKeyBlobCbor(Vec<u8>);

impl PortableKeyBlobCbor {
    /// Wrap bytes produced by the canonical serialiser. Performs a
    /// lightweight check (non-empty, first byte is a CBOR map header); full
    /// validation happens in [`Self::parse`].
    ///
    /// # Errors
    ///
    /// Returns [`PortableKeyError::Cbor`] with [`CborError::NotAMap`] if
    /// `bytes` is empty or does not begin with a CBOR map header.
    pub fn from_encoded(bytes: Vec<u8>) -> Result<Self, PortableKeyError> {
        match bytes.first() {
            Some(&b) if is_cbor_map_header(b) => Ok(Self(bytes)),
            _ => Err(PortableKeyError::Cbor(CborError::NotAMap)),
        }
    }

    /// Parse these CBOR bytes back into a [`PortableKeyBlob`].
    ///
    /// # Errors
    ///
    /// Returns a [`PortableKeyError`] for malformed, non-canonical, wrong-
    /// version, or out-of-bounds input.
    pub fn parse(&self) -> Result<PortableKeyBlob, PortableKeyError> {
        deserialize_blob(&self.0)
    }

    /// Raw CBOR bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the raw CBOR bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length of the CBOR bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the CBOR bytes are empty (always `false` for constructed
    /// values).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "alice@example.com";
    const CRED: &[u8] = b"credential-id-A";
    const PRF: &[u8; PRF_OUTPUT_LEN] = &[0x11; PRF_OUTPUT_LEN];
    const CODE: &[u8] = b"R3C0V3RY-C0D3-128BIT-RANDOM-XYZ";

    fn sk() -> Vec<u8> {
        vec![0xAB; ML_DSA_65_SECRET_KEY_SIZE]
    }

    fn inputs<'a>(secret: &'a [u8], kek: &'a [u8; 32], iv: &'a [u8; 12]) -> PortableKeyInputs<'a> {
        PortableKeyInputs {
            secret_key: secret,
            account_id: ACCOUNT,
            primary_fingerprint: &[0x42; 32],
            kek,
            sk_iv: iv,
        }
    }

    fn passkey_factor() -> NewFactor<'static> {
        NewFactor::PasskeyPrf {
            credential_id: CRED.to_vec(),
            prf_output: PRF,
            wrap_iv: [0x01; 12],
        }
    }

    fn recovery_factor() -> NewFactor<'static> {
        NewFactor::RecoveryCode {
            code: CODE,
            salt: [0x07; RECOVERY_SALT_LEN],
            wrap_iv: [0x02; 12],
        }
    }

    fn build(factors: &[NewFactor<'_>]) -> PortableKeyBlob {
        let secret = sk();
        let kek = [0xC3; 32];
        let iv = [0x09; 12];
        create_blob(&inputs(&secret, &kek, &iv), factors).unwrap()
    }

    /// Accessor read-back for the portable-key blob and its wire
    /// newtype — the largest `FnValue` cluster outside `log.rs`. The blob
    /// is exercised through create/round-trip, which compares whole
    /// values and never asks a getter what it returns.
    ///
    /// `version()` is deliberately NOT asserted here: the blob's version
    /// is 1, and the mutant substitutes `1`, so no test can distinguish
    /// them. That is an equivalent mutant, not a coverage gap.
    /// `cbor_type_name` feeds the `actual:` field of the decoder's
    /// `UnexpectedType` error — the part of the message that tells a
    /// caller what they actually sent. Every one of its nine arms was a
    /// surviving mutant, because a `_ => "unknown"` catch-all absorbs any
    /// deleted arm: the decoder would still reject the input, just stop
    /// naming what it got. Two files carry an independent copy of this
    /// helper, so both are pinned.
    /// Bounds-check boundary for this file's own copy of
    /// `extract_bytes_bounded`. `>` → `>=` is invisible unless something
    /// of EXACTLY `max` is accepted; `>` → `==` is invisible unless
    /// something strictly larger is rejected. Neither existed.
    /// The wrap-count and account-id caps, pinned from both sides at BOTH
    /// the construction and the decode site. The comment on `create_blob`
    /// explains why they are enforced twice — a blob that serialises but
    /// cannot `parse()` leaves the portable key unrecoverable on the
    /// recovery device — yet neither site had a boundary test, so all
    /// eight mutants across the four comparisons survived.
    /// Re-encode a valid blob with one byte-string field swapped for an
    /// oversized one, leaving every other field and the canonical key
    /// order intact — so only the bound under test can reject it.
    /// `nested` walks into each `wraps` entry instead of the top level.
    fn blob_cbor_with_inflated(field: &str, len: usize, nested: bool) -> Vec<u8> {
        let bytes = build(&[passkey_factor()])
            .to_cbor()
            .expect("encode")
            .into_bytes();
        let value: Value = ciborium::de::from_reader(bytes.as_slice()).expect("decode");
        let Value::Map(mut entries) = value else {
            panic!("a blob encodes as a map")
        };
        let mut replaced = false;
        for (key, val) in &mut entries {
            let Some(name) = key.as_text() else { continue };
            if nested && name == "wraps" {
                let Value::Array(items) = val else {
                    panic!("wraps is an array")
                };
                for item in items {
                    let Value::Map(pairs) = item else {
                        panic!("a wrap is a map")
                    };
                    for (k, v) in pairs {
                        if k.as_text() == Some(field) {
                            *v = Value::Bytes(vec![0xCD; len]);
                            replaced = true;
                        }
                    }
                }
            } else if !nested && name == field {
                *val = Value::Bytes(vec![0xCD; len]);
                replaced = true;
            }
        }
        assert!(replaced, "{field} not found — the fixture changed shape");
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut out).expect("re-encode");
        out
    }

    /// These two decode bounds are `<constant> + 64`, and mutating `+` to
    /// `*` does not merely widen them — it makes them enormous:
    /// `MAX_SK_CIPHERTEXT` goes from 4,096 to 258,048 and
    /// `MAX_KEK_CIPHERTEXT` from 96 to 2,048. Both mutants survived because
    /// nothing ever fed an oversized field, so the bound was never
    /// observed doing its job at all.
    ///
    /// Each length below sits ABOVE the real bound and BELOW the mutated
    /// one, which is the only window that separates them.
    #[test]
    fn decode_bounds_reject_oversized_ciphertext_fields() {
        // Real bound 4,096; mutated bound 258,048.
        let bytes = blob_cbor_with_inflated("sk_ciphertext", 5_000, false);
        let err = PortableKeyBlobCbor::from_encoded(bytes)
            .expect("still a map")
            .parse()
            .expect_err("an oversized sk_ciphertext must be refused");
        assert!(
            format!("{err}").contains("sk_ciphertext"),
            "expected the sk_ciphertext bound to reject, got {err:?}"
        );

        // Real bound 96; mutated bound 2,048.
        let bytes = blob_cbor_with_inflated("kek_ciphertext", 500, true);
        let err = PortableKeyBlobCbor::from_encoded(bytes)
            .expect("still a map")
            .parse()
            .expect_err("an oversized kek_ciphertext must be refused");
        assert!(
            format!("{err}").contains("kek_ciphertext"),
            "expected the kek_ciphertext bound to reject, got {err:?}"
        );
    }

    #[test]
    fn portable_key_caps_are_pinned_both_sides() {
        let secret = sk();
        let kek = [0xC3; 32];
        let iv = [0x09; 12];
        let factors = |n: usize| -> Vec<NewFactor<'static>> {
            (0..n)
                .map(|i| {
                    let tag = u8::try_from(i % 251).unwrap();
                    NewFactor::PasskeyPrf {
                        credential_id: vec![tag; 8],
                        prf_output: PRF,
                        wrap_iv: [tag; 12],
                    }
                })
                .collect()
        };
        let build = |account: &str, n: usize| {
            create_blob(
                &PortableKeyInputs {
                    secret_key: &secret,
                    account_id: account,
                    primary_fingerprint: &[0x42; 32],
                    kek: &kek,
                    sk_iv: &iv,
                },
                &factors(n),
            )
        };

        // Wrap-count cap, construction side.
        let at_wrap_cap = build(ACCOUNT, MAX_WRAPS).expect("exactly MAX_WRAPS is legal");
        assert!(matches!(
            build(ACCOUNT, MAX_WRAPS + 1),
            Err(PortableKeyError::TooManyWraps { .. })
        ));

        // Account-id cap, construction side.
        let at_account_cap = build(&"a".repeat(MAX_ACCOUNT_ID_CHARS), 1)
            .expect("an account_id of exactly the cap is legal");
        assert!(
            build(&"a".repeat(MAX_ACCOUNT_ID_CHARS + 1), 1).is_err(),
            "one character over the cap must be refused"
        );

        // Decode side: both at-cap blobs must read back, or the caps
        // disagree and enrolment produces an unrecoverable key.
        at_wrap_cap
            .to_cbor()
            .expect("encode")
            .parse()
            .expect("a blob at the wrap cap must decode");
        at_account_cap
            .to_cbor()
            .expect("encode")
            .parse()
            .expect("a blob at the account-id cap must decode");
    }

    #[test]
    fn extract_bytes_bounded_pins_both_sides_of_the_limit() {
        let map = |n: usize| -> Vec<(String, Value)> {
            vec![("k".to_owned(), Value::Bytes(vec![0xAA; n]))]
        };
        assert_eq!(
            extract_bytes_bounded(&map(8), "k", 8)
                .expect("exactly max is legal")
                .len(),
            8
        );
        assert!(matches!(
            extract_bytes_bounded(&map(9), "k", 8),
            Err(CborError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn cbor_type_name_names_every_variant() {
        assert_eq!(cbor_type_name(&Value::Integer(7.into())), "integer");
        assert_eq!(cbor_type_name(&Value::Bytes(vec![1, 2])), "bytes");
        assert_eq!(cbor_type_name(&Value::Text("x".to_owned())), "text");
        assert_eq!(cbor_type_name(&Value::Array(vec![Value::Null])), "array");
        assert_eq!(
            cbor_type_name(&Value::Map(vec![(Value::Null, Value::Null)])),
            "map"
        );
        assert_eq!(
            cbor_type_name(&Value::Tag(42, Box::new(Value::Null))),
            "tag"
        );
        assert_eq!(cbor_type_name(&Value::Bool(true)), "bool");
        assert_eq!(cbor_type_name(&Value::Null), "null");
        assert_eq!(cbor_type_name(&Value::Float(1.5)), "float");
    }

    #[test]
    fn portable_key_accessors_read_back() {
        let blob = build(&[passkey_factor()]);
        assert_eq!(blob.account_id(), ACCOUNT);
        assert!(
            blob.sk_ciphertext().len() > 1,
            "ciphertext must exceed the 0/1 replacement constants"
        );
        assert!(!blob.wraps().is_empty());

        let cbor = blob.to_cbor().expect("blob encodes");
        let bytes = cbor.as_bytes().to_vec();
        assert!(bytes.len() > 1);
        assert_eq!(cbor.len(), bytes.len());
        assert!(!cbor.is_empty());
        assert_eq!(cbor.into_bytes(), bytes);
    }

    #[test]
    fn round_trip_via_passkey() {
        let blob = build(&[passkey_factor()]);
        let unlocked = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: PRF,
            },
        )
        .unwrap();
        assert_eq!(&unlocked[..], &sk()[..]);
    }

    #[test]
    fn round_trip_via_recovery() {
        let blob = build(&[recovery_factor()]);
        let unlocked = unlock_blob(&blob, &FactorSecret::RecoveryCode(CODE)).unwrap();
        assert_eq!(&unlocked[..], &sk()[..]);
    }

    #[test]
    fn both_factors_unlock_the_same_key() {
        let blob = build(&[passkey_factor(), recovery_factor()]);
        let via_pk = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: PRF,
            },
        )
        .unwrap();
        let via_rc = unlock_blob(&blob, &FactorSecret::RecoveryCode(CODE)).unwrap();
        assert_eq!(&via_pk[..], &sk()[..]);
        assert_eq!(&via_rc[..], &via_pk[..]);
    }

    #[test]
    fn wrong_prf_output_fails() {
        let blob = build(&[passkey_factor()]);
        let err = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: &[0x22; PRF_OUTPUT_LEN],
            },
        )
        .unwrap_err();
        assert_eq!(err, PortableKeyError::UnlockFailed);
    }

    #[test]
    fn wrong_recovery_code_fails() {
        let blob = build(&[recovery_factor()]);
        let err = unlock_blob(&blob, &FactorSecret::RecoveryCode(b"wrong-code")).unwrap_err();
        assert_eq!(err, PortableKeyError::UnlockFailed);
    }

    #[test]
    fn unknown_credential_has_no_matching_wrap() {
        let blob = build(&[passkey_factor()]);
        let err = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: b"some-other-credential",
                prf_output: PRF,
            },
        )
        .unwrap_err();
        assert_eq!(err, PortableKeyError::NoMatchingWrap);
    }

    #[test]
    fn recovery_factor_absent_has_no_matching_wrap() {
        let blob = build(&[passkey_factor()]);
        let err = unlock_blob(&blob, &FactorSecret::RecoveryCode(CODE)).unwrap_err();
        assert_eq!(err, PortableKeyError::NoMatchingWrap);
    }

    #[test]
    fn tampered_sk_ciphertext_fails() {
        let mut blob = build(&[passkey_factor()]);
        let mid = blob.sk_ciphertext.len() / 2;
        blob.sk_ciphertext[mid] ^= 0xFF;
        let err = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: PRF,
            },
        )
        .unwrap_err();
        assert_eq!(err, PortableKeyError::UnlockFailed);
    }

    #[test]
    fn swapped_account_id_aad_fails() {
        // account_id is the secret-key wrap's AAD; changing it after the
        // fact must fail the AEAD.
        let mut blob = build(&[passkey_factor()]);
        blob.account_id = "mallory@example.com".to_owned();
        let err = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: PRF,
            },
        )
        .unwrap_err();
        assert_eq!(err, PortableKeyError::UnlockFailed);
    }

    #[test]
    fn swapped_credential_id_aad_fails() {
        // credential_id is the passkey wrap's AAD. Editing it (while still
        // presenting a matching factor) must fail the KEK unwrap.
        let mut blob = build(&[passkey_factor()]);
        if let WrapEntry::PasskeyPrf { credential_id, .. } = &mut blob.wraps[0] {
            credential_id[0] ^= 0xFF;
        }
        let edited = match &blob.wraps[0] {
            WrapEntry::PasskeyPrf { credential_id, .. } => credential_id.clone(),
            WrapEntry::RecoveryCode { .. } => unreachable!(),
        };
        let err = unlock_blob(
            &blob,
            &FactorSecret::PasskeyPrf {
                credential_id: &edited,
                prf_output: PRF,
            },
        )
        .unwrap_err();
        assert_eq!(err, PortableKeyError::UnlockFailed);
    }

    #[test]
    fn create_is_deterministic_for_fixed_randomness() {
        let a = build(&[passkey_factor(), recovery_factor()]);
        let b = build(&[passkey_factor(), recovery_factor()]);
        assert_eq!(a, b);
    }

    #[test]
    fn bad_secret_key_length_rejected() {
        let kek = [0xC3; 32];
        let iv = [0x09; 12];
        let short = [0u8; 10];
        let err = create_blob(&inputs(&short, &kek, &iv), &[passkey_factor()]).unwrap_err();
        assert_eq!(
            err,
            PortableKeyError::BadSecretKeyLen {
                expected: ML_DSA_65_SECRET_KEY_SIZE,
                actual: 10,
            }
        );
    }

    #[test]
    fn prf_salt_is_deterministic_and_fingerprint_specific() {
        assert_eq!(prf_salt(&[0x11; 32]), prf_salt(&[0x11; 32]));
        assert_ne!(prf_salt(&[0x11; 32]), prf_salt(&[0x22; 32]));
    }

    #[test]
    fn keyblob_store_challenge_layout_and_bindings() {
        let fingerprint = [0x42; 32];
        let challenge = build_keyblob_store_challenge("account-1", &fingerprint, b"blob", 7, 11);
        assert_eq!(challenge.len(), 132);
        assert_eq!(&challenge[..20], KEYBLOB_STORE_CHALLENGE_DOMAIN);
        assert_eq!(&challenge[52..84], &fingerprint);
        assert_eq!(&challenge[116..124], &7u64.to_be_bytes());
        assert_eq!(&challenge[124..132], &11i64.to_be_bytes());

        assert_ne!(
            challenge,
            build_keyblob_store_challenge("account-2", &fingerprint, b"blob", 7, 11)
        );
        assert_ne!(
            challenge,
            build_keyblob_store_challenge("account-1", &fingerprint, b"other", 7, 11)
        );
        assert_ne!(
            challenge,
            build_keyblob_store_challenge("account-1", &fingerprint, b"blob", 8, 11)
        );
        assert_ne!(
            challenge,
            build_keyblob_store_challenge("account-1", &fingerprint, b"blob", 7, 12)
        );
    }

    #[test]
    fn no_factors_rejected() {
        let secret = sk();
        let kek = [0xC3; 32];
        let iv = [0x09; 12];
        let err = create_blob(&inputs(&secret, &kek, &iv), &[]).unwrap_err();
        assert_eq!(err, PortableKeyError::NoFactors);
    }

    #[test]
    fn create_rejects_identifiers_and_recovery_codes_that_cannot_form_valid_factors() {
        let secret = sk();
        let kek = [0xC3; 32];
        let iv = [0x09; 12];

        let mut empty_account = inputs(&secret, &kek, &iv);
        empty_account.account_id = "";
        assert_eq!(
            create_blob(&empty_account, &[passkey_factor()]),
            Err(PortableKeyError::EmptyAccountId),
        );

        let empty_credential = NewFactor::PasskeyPrf {
            credential_id: Vec::new(),
            prf_output: PRF,
            wrap_iv: [0x01; 12],
        };
        assert_eq!(
            create_blob(&inputs(&secret, &kek, &iv), &[empty_credential]),
            Err(PortableKeyError::EmptyCredentialId),
        );

        let short_code = NewFactor::RecoveryCode {
            code: b"too-short",
            salt: [0x07; RECOVERY_SALT_LEN],
            wrap_iv: [0x02; 12],
        };
        assert_eq!(
            create_blob(&inputs(&secret, &kek, &iv), &[short_code]),
            Err(PortableKeyError::RecoveryCodeTooShort {
                min: MIN_RECOVERY_CODE_LEN,
                actual: 9,
            }),
        );
    }

    #[test]
    fn create_normalises_account_id_before_using_it_as_aead_aad() {
        let secret = sk();
        let kek = [0xC3; 32];
        let iv = [0x09; 12];
        let blob = create_blob(
            &PortableKeyInputs {
                secret_key: &secret,
                account_id: "cafe\u{301}@example.com",
                primary_fingerprint: &[0x42; 32],
                kek: &kek,
                sk_iv: &iv,
            },
            &[passkey_factor()],
        )
        .expect("NFD account id is normalised at construction");
        assert_eq!(blob.account_id(), "caf\u{e9}@example.com");

        // Serialisation always emits NFC. Before construction normalised the
        // AEAD AAD too, this round-trip changed the account bytes and left the
        // otherwise-valid blob permanently undecryptable.
        let restored = reparse(&blob);
        let unlocked = unlock_blob(
            &restored,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: PRF,
            },
        )
        .expect("normalised account id remains valid AEAD AAD");
        assert_eq!(&unlocked[..], &secret[..]);
    }

    // --- CBOR wire format ---

    fn reparse(blob: &PortableKeyBlob) -> PortableKeyBlob {
        let bytes = blob.to_cbor().unwrap().into_bytes();
        PortableKeyBlobCbor::from_encoded(bytes)
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn cbor_round_trips_and_still_unlocks() {
        let blob = build(&[passkey_factor(), recovery_factor()]);
        let restored = reparse(&blob);
        assert_eq!(restored, blob);

        // The recovered blob still unlocks via both factors.
        let via_pk = unlock_blob(
            &restored,
            &FactorSecret::PasskeyPrf {
                credential_id: CRED,
                prf_output: PRF,
            },
        )
        .unwrap();
        let via_rc = unlock_blob(&restored, &FactorSecret::RecoveryCode(CODE)).unwrap();
        assert_eq!(&via_pk[..], &sk()[..]);
        assert_eq!(&via_rc[..], &sk()[..]);
    }

    #[test]
    fn cbor_is_deterministic() {
        let a = build(&[passkey_factor(), recovery_factor()]);
        let b = build(&[passkey_factor(), recovery_factor()]);
        assert_eq!(
            a.to_cbor().unwrap().as_bytes(),
            b.to_cbor().unwrap().as_bytes()
        );
    }

    #[test]
    fn from_encoded_rejects_non_map() {
        // 0x80 is a CBOR empty array, not a map.
        let err = PortableKeyBlobCbor::from_encoded(vec![0x80]).unwrap_err();
        assert!(matches!(err, PortableKeyError::Cbor(CborError::NotAMap)));
        let err = PortableKeyBlobCbor::from_encoded(vec![]).unwrap_err();
        assert!(matches!(err, PortableKeyError::Cbor(CborError::NotAMap)));
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let good = build(&[passkey_factor()]);
        let weird = PortableKeyBlob::from_parts(
            0x02,
            good.account_id().to_owned(),
            *good.primary_fingerprint(),
            *good.sk_iv(),
            good.sk_ciphertext().to_vec(),
            good.wraps().to_vec(),
        );
        let bytes = weird.to_cbor().unwrap().into_bytes();
        let err = PortableKeyBlobCbor::from_encoded(bytes)
            .unwrap()
            .parse()
            .unwrap_err();
        assert_eq!(err, PortableKeyError::UnsupportedVersion(0x02));
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut bytes = build(&[passkey_factor()]).to_cbor().unwrap().into_bytes();
        bytes.push(0x00); // junk after the canonical value
        let err = PortableKeyBlobCbor::from_encoded(bytes)
            .unwrap()
            .parse()
            .unwrap_err();
        assert!(matches!(
            err,
            PortableKeyError::Cbor(CborError::DecodingFailed(_))
        ));
    }

    #[test]
    fn parse_rejects_oversized_credential_id() {
        let good = build(&[passkey_factor()]);
        let oversized = PortableKeyBlob::from_parts(
            good.version(),
            good.account_id().to_owned(),
            *good.primary_fingerprint(),
            *good.sk_iv(),
            good.sk_ciphertext().to_vec(),
            vec![WrapEntry::PasskeyPrf {
                credential_id: vec![0u8; MAX_CREDENTIAL_ID + 1],
                wrap_iv: [0x01; 12],
                kek_ciphertext: vec![0u8; PORTABLE_KEK_LEN + PORTABLE_TAG_LEN],
            }],
        );
        let bytes = oversized.to_cbor().unwrap().into_bytes();
        let err = PortableKeyBlobCbor::from_encoded(bytes)
            .unwrap()
            .parse()
            .unwrap_err();
        assert!(matches!(
            err,
            PortableKeyError::Cbor(CborError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn parse_rejects_zero_wraps_and_impossible_ciphertext_lengths() {
        let good = build(&[passkey_factor()]);
        let no_wraps = PortableKeyBlob::from_parts(
            good.version(),
            good.account_id().to_owned(),
            *good.primary_fingerprint(),
            *good.sk_iv(),
            good.sk_ciphertext().to_vec(),
            Vec::new(),
        );
        assert_eq!(
            no_wraps.to_cbor().unwrap().parse(),
            Err(PortableKeyError::NoFactors),
        );

        let short_secret_ciphertext = PortableKeyBlob::from_parts(
            good.version(),
            good.account_id().to_owned(),
            *good.primary_fingerprint(),
            *good.sk_iv(),
            vec![0; ML_DSA_65_SECRET_KEY_SIZE + PORTABLE_TAG_LEN - 1],
            good.wraps().to_vec(),
        );
        assert!(matches!(
            short_secret_ciphertext.to_cbor().unwrap().parse(),
            Err(PortableKeyError::Cbor(CborError::WrongLength {
                field: "sk_ciphertext",
                ..
            }))
        ));

        let short_kek_ciphertext = PortableKeyBlob::from_parts(
            good.version(),
            good.account_id().to_owned(),
            *good.primary_fingerprint(),
            *good.sk_iv(),
            good.sk_ciphertext().to_vec(),
            vec![WrapEntry::PasskeyPrf {
                credential_id: CRED.to_vec(),
                wrap_iv: [0x01; 12],
                kek_ciphertext: vec![0; PORTABLE_KEK_LEN + PORTABLE_TAG_LEN - 1],
            }],
        );
        assert!(matches!(
            short_kek_ciphertext.to_cbor().unwrap().parse(),
            Err(PortableKeyError::Cbor(CborError::WrongLength {
                field: "kek_ciphertext",
                ..
            }))
        ));
    }
}
