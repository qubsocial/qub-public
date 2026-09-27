//! qub handle namespace — Layer 1 display identifier.
//!
//! Normalisation, reserved-word check, auto-allocation shape detection,
//! and proof-of-possession challenge builders for the handle rename and
//! delete ceremonies defined in `docs/IDENTITY.md` §3.2.5 and
//! `docs/IDENTITY.md` §3.2.5.
//!
//! # Why this lives in `qub-core`
//!
//! Normalisation and challenge construction must be byte-for-byte
//! identical on every caller: the Leptos creator app (rename UI), the
//! MCP tooling (`tools/qub-mcp/`), and any future Rust-based signer. A
//! single authoritative module prevents the client from constructing a
//! preimage the Worker will refuse.
//!
//! The Cloudflare Worker is TypeScript and therefore ships its own
//! mirror of these rules — tests on both sides assert the byte layouts
//! match.

use crate::handle_reserved::is_reserved_lower;
use crate::handle_wordlist::{ADJECTIVES, NOUNS};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};
use unicode_script::{Script, UnicodeScript};

/// Minimum handle length in characters (code points).
pub const HANDLE_MIN_LEN: usize = 3;

/// Maximum handle length in characters (code points).
pub const HANDLE_MAX_LEN: usize = 20;

/// Domain separator for the rename proof-of-possession preimage.
///
/// Exactly 29 ASCII bytes — matches the `QUB_IDENTITY_*` family used by
/// every other attestation challenge. V2 length-prefixes both variable-width
/// handle fields so two different `(current, new)` pairs cannot share the
/// same concatenated preimage.
pub const HANDLE_RENAME_DOMAIN: &[u8; 29] = b"QUB_IDENTITY_HANDLE_RENAME_V2";

/// Domain separator for the delete proof-of-possession preimage.
///
/// Exactly 29 ASCII bytes.
///
/// `_V2` binds the current handle value into the preimage (auth-flow
/// review Finding 5) so a delete signature is tied to a specific
/// handle and cannot clear a different (newer) handle.
pub const HANDLE_DELETE_DOMAIN: &[u8; 29] = b"QUB_IDENTITY_HANDLE_DELETE_V2";

/// Domain separator for the profile-set proof-of-possession preimage.
///
/// Exactly 27 ASCII bytes. Used by
/// [`crate::handle::build_profile_set_challenge`] and the matching
/// `buildProfileSetChallenge` in
/// `workers/api/src/routes/attestation.ts`. The two builders MUST emit
/// byte-identical output for the same inputs — see the parity test
/// in `crates/qub-core/tests/handle.rs`.
///
/// `_V2` binds a field-presence bitmask into the preimage so an omitted
/// field ("keep existing") and a cleared field (empty string) sign to
/// different bytes (auth-flow review Finding 1).
pub const PROFILE_SET_DOMAIN: &[u8; 27] = b"QUB_IDENTITY_PROFILE_SET_V2";

/// Domain separator for the avatar-set proof-of-possession preimage.
///
/// Exactly 26 ASCII bytes. Used by
/// [`crate::handle::build_avatar_set_challenge`] and the matching
/// `buildAvatarSetChallenge` in `workers/api/src/routes/attestation.ts`.
/// The two builders MUST emit byte-identical output for the same
/// inputs — see the parity test in `crates/qub-core/tests/handle.rs`.
pub const AVATAR_SET_DOMAIN: &[u8; 26] = b"QUB_IDENTITY_AVATAR_SET_V1";

/// Reason a candidate handle failed [`normalise_handle`].
///
/// The V2 multi-script validator (`docs/IDENTITY.md` §3.2.6) distinguishes
/// between several rejection reasons that V1 lumped into a single
/// "charset" bucket; the new variants let the UI surface a specific,
/// actionable message.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(clippy::module_name_repetitions)]
pub enum HandleValidationError {
    /// Fewer than [`HANDLE_MIN_LEN`] code points after stripping `@`
    /// (either before or after Unicode normalisation).
    TooShort,
    /// More than [`HANDLE_MAX_LEN`] code points after stripping `@`
    /// (either before or after Unicode normalisation).
    TooLong,
    /// Contains a Unicode control / format / private-use / surrogate
    /// character, a zero-width or bidi-control character, or a
    /// variation selector. See `docs/IDENTITY.md` §3.2.6.5.
    InvisibleChar,
    /// Contains a code point outside the allowed script set
    /// (Latin / Greek / Cyrillic / Arabic / Hebrew / Devanagari /
    /// Bengali / Thai / Han / Hiragana / Katakana / Hangul) or outside
    /// the Common-script subset (ASCII digits and underscore only).
    /// Covers hyphens, native digit forms, emoji, math symbols, and
    /// every other unsupported character. See `docs/IDENTITY.md`
    /// §3.2.6.2 and §3.2.6.4.
    DisallowedScript,
    /// Mixes two or more allowed scripts in a combination not on the
    /// UTS #39 Moderately-Restrictive exception list. See
    /// `docs/IDENTITY.md` §3.2.6.3.
    MixedScript,
    /// Leading code point is a combining mark (general category
    /// `Mn` / `Mc` / `Me`). See `docs/IDENTITY.md` §3.2.6.4.
    LeadingMark,
    /// First character is `[0-9]` — forbidden to avoid confusion with
    /// the short-URL namespace (digits prefix tx-ids).
    StartsDigit,
    /// Matches the reserved-word deny list.
    Reserved,
    /// Every script character is a modifier/iteration mark (general
    /// category `Lm`) — e.g. an all-`ー` or all-tatweel handle. A
    /// handle must contain at least one base letter so it has a
    /// determinate visual identity. See `docs/IDENTITY.md` §3.2.6.4.
    NoBaseLetter,
}

/// Normalise a user-supplied handle to its canonical form.
///
/// Implements the V2 multi-script handle pipeline from
/// `docs/IDENTITY.md` §3.2.6. The pipeline is a strict superset of the
/// V1 ASCII rule: every V1 handle round-trips through V2 unchanged.
///
/// Pipeline (first failing step wins the error variant):
/// 1. Strip a single leading `@`.
/// 2. Reject if the pre-normalisation length is outside
///    `[HANDLE_MIN_LEN, HANDLE_MAX_LEN]` code points.
/// 3. Apply Unicode **NFC** normalisation.
/// 4. Lowercase via Unicode default casing
///    ([`str::to_lowercase`] — never locale-specific).
/// 5. Re-apply NFC (lowercasing can break NFC stability in some scripts).
/// 6. Re-check length 3-20 code points.
/// 7. Reject any invisible / control / format / private-use / surrogate
///    character or variation selector
///    ([`HandleValidationError::InvisibleChar`]).
/// 8. Reject any code point outside the allowed-script allowlist
///    ([`HandleValidationError::DisallowedScript`]).
/// 9. Reject if the leading code point is an ASCII digit
///    ([`HandleValidationError::StartsDigit`]) or a combining mark
///    ([`HandleValidationError::LeadingMark`]).
/// 10. Reject handles whose UTS #39 resolved script set (intersection
///     of augmented per-character `Script_Extensions` sets) is empty
///     ([`HandleValidationError::MixedScript`]).
/// 11. Reject handles with no base letter — every script character is
///     a modifier letter ([`HandleValidationError::NoBaseLetter`]).
/// 12. Reject handles on the reserved-word deny list
///     ([`HandleValidationError::Reserved`]).
///
/// The Worker normalises defensively before every read and every write;
/// the client normalises before submit for inline UI validation. Both
/// sides must agree — this function is the source of truth.
///
/// # Errors
///
/// Returns the first rule that failed in the order above.
pub fn normalise_handle(input: &str) -> Result<String, HandleValidationError> {
    let trimmed = input.strip_prefix('@').unwrap_or(input);

    let pre_count = trimmed.chars().count();
    if pre_count < HANDLE_MIN_LEN {
        return Err(HandleValidationError::TooShort);
    }
    if pre_count > HANDLE_MAX_LEN {
        return Err(HandleValidationError::TooLong);
    }

    // NFC → Unicode-default-lowercase → NFC. The second NFC pass guards
    // against cased scripts where lowercasing produces a non-NFC
    // byte sequence (rare, but free to defend against).
    let nfc: String = trimmed.nfc().collect();
    let lower: String = nfc.to_lowercase();
    let normalised: String = lower.nfc().collect();

    let post_count = normalised.chars().count();
    if post_count < HANDLE_MIN_LEN {
        return Err(HandleValidationError::TooShort);
    }
    if post_count > HANDLE_MAX_LEN {
        return Err(HandleValidationError::TooLong);
    }

    let mut scripts = ScriptResolution::default();
    let mut first = true;

    for ch in normalised.chars() {
        match classify(ch) {
            CharClass::Invisible => return Err(HandleValidationError::InvisibleChar),
            CharClass::Disallowed => return Err(HandleValidationError::DisallowedScript),
            CharClass::Mark => {
                if first {
                    return Err(HandleValidationError::LeadingMark);
                }
                // Combining marks attach to the preceding character's
                // script — they do not contribute to the script set.
            },
            CharClass::Common => {
                if first && ch.is_ascii_digit() {
                    return Err(HandleValidationError::StartsDigit);
                }
            },
            CharClass::Script(bits) => {
                scripts.add(bits, ch);
            },
        }
        first = false;
    }

    if !scripts.is_single_script() {
        return Err(HandleValidationError::MixedScript);
    }

    if !scripts.has_base_letter() {
        return Err(HandleValidationError::NoBaseLetter);
    }

    // Reserved / brand deny-list check. NFC is CANONICAL — it does not
    // fold compatibility characters, so fullwidth Latin (U+FF41..=U+FF5A)
    // and the Latin ligatures (U+FB00..=U+FB06) survive `normalised` as
    // visually near-identical lookalikes that never equal the ASCII
    // reserved entries. NFKC folds them, so reject when EITHER the
    // canonical (NFC) form OR its compatibility (NFKC) fold is reserved —
    // closing the confusable-spelling phishing bypass of platform-reserved
    // words like `admin` / `official`. (Brand words are enforced
    // server-side in the Worker's larger deny list.) Must stay in lockstep
    // with `normaliseHandle` in `workers/api/src/routes/handle-alloc.ts`.
    let nfkc_folded: String = normalised.nfkc().collect::<String>().to_lowercase();
    if is_reserved_lower(&normalised) || is_reserved_lower(&nfkc_folded) {
        return Err(HandleValidationError::Reserved);
    }

    Ok(normalised)
}

/// UTS #39 resolved-script-set tracker.
///
/// Each script-bearing character contributes its **`Script_Extensions`**
/// membership (restricted to the twelve allowed scripts) as a bitset,
/// augmented with the UTS #39 writing-system groups (Hiragana /
/// Katakana / Han → Japanese; Han / Hangul → Korean). The handle's
/// resolved set is the intersection of the augmented per-character
/// sets; a handle is single-script iff the intersection is non-empty.
///
/// This is the semantics the Worker mirror implements with
/// `\p{Script_Extensions=…}` classes — plain `Script` classification
/// diverges on shared characters (U+30FC ー is Script=Common but
/// `Script_Extensions={Hiragana, Katakana}`), which used to reject
/// ordinary Japanese loanwords like `コーヒー`.
///
/// Accepted combinations follow from the augmentation: any single
/// script, Han + kana (Japanese), kana-only mixes (Japanese), and
/// Han + Hangul (Korean). Cross-system mixes (Latin + Cyrillic,
/// Greek + Latin, Hiragana + Hangul, …) resolve to the empty set.
/// See `docs/IDENTITY.md` §3.2.6.3.
#[derive(Debug, Clone, Copy)]
struct ScriptResolution {
    /// Intersection of augmented per-character script sets. Starts as
    /// all-ones so the first character initialises it.
    resolved: u16,
    /// True once any script-bearing character was seen.
    saw_script: bool,
    /// True once a base letter (general category Lu/Ll/Lt/Lo/Nl) was
    /// seen. Modifier letters (Lm — chōonpu, tatweel, iteration
    /// marks) may accompany base letters but cannot stand alone.
    saw_base_letter: bool,
}

/// UTS #39 augmentation group: Japanese (Hiragana / Katakana / Han).
const GROUP_JAPANESE: u16 = 1 << 12;
/// UTS #39 augmentation group: Korean (Han / Hangul).
const GROUP_KOREAN: u16 = 1 << 13;

const HAN_BIT: u16 = 1 << ScriptIdx::Han as u16;
const HIRAGANA_BIT: u16 = 1 << ScriptIdx::Hiragana as u16;
const KATAKANA_BIT: u16 = 1 << ScriptIdx::Katakana as u16;
const HANGUL_BIT: u16 = 1 << ScriptIdx::Hangul as u16;

/// Augment a per-character script bitset with its writing-system
/// groups per UTS #39 §5.1 (Jpan for Han/Hiragana/Katakana, Kore for
/// Han/Hangul).
const fn augment(bits: u16) -> u16 {
    let mut out = bits;
    if bits & (HAN_BIT | HIRAGANA_BIT | KATAKANA_BIT) != 0 {
        out |= GROUP_JAPANESE;
    }
    if bits & (HAN_BIT | HANGUL_BIT) != 0 {
        out |= GROUP_KOREAN;
    }
    out
}

impl Default for ScriptResolution {
    fn default() -> Self {
        Self {
            resolved: u16::MAX,
            saw_script: false,
            saw_base_letter: false,
        }
    }
}

impl ScriptResolution {
    fn add(&mut self, bits: u16, c: char) {
        self.resolved &= augment(bits);
        self.saw_script = true;
        if matches!(
            c.general_category(),
            GeneralCategory::UppercaseLetter
                | GeneralCategory::LowercaseLetter
                | GeneralCategory::TitlecaseLetter
                | GeneralCategory::OtherLetter
                | GeneralCategory::LetterNumber
        ) {
            self.saw_base_letter = true;
        }
    }

    /// True if the resolved script set is non-empty (or no script
    /// characters were seen — a purely Common handle of digits and
    /// underscores).
    const fn is_single_script(self) -> bool {
        !self.saw_script || self.resolved != 0
    }

    /// True if the handle carries at least one base letter (or no
    /// script characters at all).
    const fn has_base_letter(self) -> bool {
        !self.saw_script || self.saw_base_letter
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
enum ScriptIdx {
    Latin = 0,
    Greek = 1,
    Cyrillic = 2,
    Arabic = 3,
    Hebrew = 4,
    Devanagari = 5,
    Bengali = 6,
    Thai = 7,
    Han = 8,
    Hiragana = 9,
    Katakana = 10,
    Hangul = 11,
}

/// The twelve allowed scripts, paired with their bitset indices. Order
/// matches the Worker's `SCRIPT_REGEXES` table in
/// `workers/api/src/routes/handle-alloc.ts` — both sides test
/// **`Script_Extensions`** membership per script.
const ALLOWED_SCRIPTS: [(Script, ScriptIdx); 12] = [
    (Script::Latin, ScriptIdx::Latin),
    (Script::Greek, ScriptIdx::Greek),
    (Script::Cyrillic, ScriptIdx::Cyrillic),
    (Script::Arabic, ScriptIdx::Arabic),
    (Script::Hebrew, ScriptIdx::Hebrew),
    (Script::Devanagari, ScriptIdx::Devanagari),
    (Script::Bengali, ScriptIdx::Bengali),
    (Script::Thai, ScriptIdx::Thai),
    (Script::Han, ScriptIdx::Han),
    (Script::Hiragana, ScriptIdx::Hiragana),
    (Script::Katakana, ScriptIdx::Katakana),
    (Script::Hangul, ScriptIdx::Hangul),
];

/// Bitset of allowed scripts whose **`Script_Extensions`** set contains
/// `c`. Zero means the character belongs to none of the twelve.
fn script_extension_bits(c: char) -> u16 {
    let ext = c.script_extension();
    let mut bits = 0u16;
    for (script, idx) in ALLOWED_SCRIPTS {
        if ext.contains_script(script) {
            bits |= 1u16 << idx as u16;
        }
    }
    bits
}

#[derive(Debug)]
enum CharClass {
    /// ASCII digit or underscore — allowed but does not contribute to
    /// the script set.
    Common,
    /// An allowed-script character: the bitset of allowed scripts in
    /// its `Script_Extensions` set (non-zero).
    Script(u16),
    /// Combining mark (Mn / Mc / Me). Permitted except at handle start.
    Mark,
    /// Cf / Cc / Co / Cs / variation selector / tag — never allowed.
    Invisible,
    /// Any other code point (emoji, math, disallowed scripts, native
    /// digit forms, ASCII punctuation, etc.).
    Disallowed,
}

fn classify(c: char) -> CharClass {
    // ASCII fast path. Must precede the unicode lookups so the
    // Common-script restriction (only ASCII digits + underscore) is
    // enforced — Script_Extensions would otherwise report digits and
    // underscore as every-script members.
    if c.is_ascii() {
        if c.is_ascii_lowercase() {
            return CharClass::Script(1u16 << ScriptIdx::Latin as u16);
        }
        if c.is_ascii_digit() || c == '_' {
            return CharClass::Common;
        }
        if c.is_ascii_control() {
            return CharClass::Invisible;
        }
        return CharClass::Disallowed;
    }

    if is_invisible_codepoint(c) {
        return CharClass::Invisible;
    }

    // Arabic tatweel: an alphabetic (Lm) stretch mark with
    // Script_Extensions covering Arabic. UTS #39 marks it
    // Identifier_Status=Restricted — it carries no letter identity and
    // exists purely to elongate the baseline, which makes it a
    // near-duplicate spoof primitive (`محمد` vs `محـمد`). Rejected
    // outright, like ZWJ.
    if c == '\u{0640}' {
        return CharClass::Disallowed;
    }

    if is_combining_mark(c) {
        return CharClass::Mark;
    }

    // Only **alphabetic** code points whose Script_Extensions set
    // intersects the allowed-script list qualify. Alphabetic-only
    // rejects native digit forms (general category Nd in Arabic,
    // Devanagari, Bengali, Thai, etc.) without rejecting legitimate
    // ideographs that happen to have a numeric value (e.g. Han `一` is
    // Lo + Numeric, accepted; Arabic-Indic `٠` is Nd, rejected).
    // Script_Extensions (not plain Script) is what admits shared
    // characters like U+30FC ー (Script=Common,
    // Script_Extensions={Hiragana, Katakana}) that ordinary Japanese
    // words depend on. See `docs/IDENTITY.md` §3.2.6.4.
    if c.is_alphabetic() {
        let bits = script_extension_bits(c);
        if bits != 0 {
            return CharClass::Script(bits);
        }
    }

    CharClass::Disallowed
}

/// True if `c` is one of the codepoint classes Andre Perry's 2026-05-22
/// review flagged as hostile in user-controlled display text:
///
/// - C0 / DEL controls (U+0000-U+001F, U+007F),
/// - C1 controls (U+0080-U+009F),
/// - Bidi overrides (U+202A-U+202E) and isolates (U+2066-U+2069),
/// - Zero-width space + LRM + RLM (U+200B, U+200E, U+200F),
/// - BOM / ZWNBSP (U+FEFF),
/// - Tag block (U+E0000-U+E007F).
///
/// Tighter than `is_invisible_codepoint` (which additionally rejects
/// ZWJ, ZWNJ, variation selectors, and private-use planes) — those
/// have legitimate uses in international text and emoji sequences, and
/// rejecting them in `pact` term values or `sender_label` would break
/// Devanagari, Arabic, and emoji.
pub fn is_hostile_text_codepoint(c: char) -> bool {
    let u = c as u32;
    if u <= 0x1F || u == 0x7F {
        return true;
    }
    if (0x0080..=0x009F).contains(&u) {
        return true;
    }
    // Zero-width space ONLY. ZWJ/ZWNJ (U+200C/D) carry Devanagari and
    // emoji semantics; LRM/RLM (U+200E/F) are legitimate paragraph-
    // direction marks used by every RTL locale. The brand-blocklist
    // bypass Andre called out (Finding 15) is specifically about ZWSP.
    if u == 0x200B {
        return true;
    }
    if (0x202A..=0x202E).contains(&u) {
        return true;
    }
    if (0x2066..=0x2069).contains(&u) {
        return true;
    }
    if u == 0xFEFF {
        return true;
    }
    if (0xE0000..=0xE007F).contains(&u) {
        return true;
    }
    false
}

/// True if any codepoint in `s` matches [`is_hostile_text_codepoint`].
pub fn contains_hostile_text_codepoint(s: &str) -> bool {
    s.chars().any(is_hostile_text_codepoint)
}

/// True if `c` is in one of the invisible / control / private-use /
/// surrogate / variation-selector / tag ranges blocked by
/// `docs/IDENTITY.md` §3.2.6.5.
///
/// ASCII control characters are handled separately in
/// [`classify`]'s ASCII fast-path.
fn is_invisible_codepoint(c: char) -> bool {
    let u = c as u32;
    // C1 control (U+0080–U+009F). C0 (U+0000–U+001F, U+007F) is the
    // ASCII fast path's responsibility.
    if (0x0080..=0x009F).contains(&u) {
        return true;
    }
    // Zero-width / bidi-control / formatting Cf characters and BOM.
    if matches!(u, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF) {
        return true;
    }
    // Variation selectors VS1–VS16 and VS17–VS256.
    if (0xFE00..=0xFE0F).contains(&u) || (0xE0100..=0xE01EF).contains(&u) {
        return true;
    }
    // Tag characters U+E0000–U+E007F.
    if (0xE0000..=0xE007F).contains(&u) {
        return true;
    }
    // Hangul filler codepoints. Category Lo / alphabetic / Script=Hangul,
    // so without this carve-out `classify` accepts them as ordinary
    // Hangul letters — yet all four render as blank, enabling an
    // all-invisible handle or an invisible near-duplicate of any
    // Han/Hangul handle. Must stay in lockstep with the Worker's list
    // in `workers/api/src/routes/handle-alloc.ts`.
    if matches!(u, 0x115F | 0x1160 | 0x3164 | 0xFFA0) {
        return true;
    }
    // Private-use BMP and supplementary planes.
    if (0xE000..=0xF8FF).contains(&u)
        || (0xF_0000..=0xF_FFFD).contains(&u)
        || (0x10_0000..=0x10_FFFD).contains(&u)
    {
        return true;
    }
    false
}

/// True if the handle matches the auto-allocation shape.
///
/// Two shapes are considered auto-allocated:
/// - `<word>_<word>_<3 digits>` where each word is `[a-z]+`
/// - `qub_<8 hex chars>` (the fingerprint-derived fallback)
///
/// Used by the Worker to decide between the engagement gate (auto
/// current handle) and the cooldown gate (user-chosen current handle)
/// during rename, and to pick the tombstone TTL on release.
///
/// A user who happens to pick a handle matching `<word>_<word>_\d{3}`
/// (for example `my_cool_123`) will be classified as auto. This is
/// documented in the auto-allocation policy and is an accepted design
/// trade-off in exchange for the simpler shape-detection path.
#[must_use]
pub fn is_auto_allocated_shape(handle: &str) -> bool {
    matches_wordword_digits(handle) || matches_qub_hex(handle)
}

fn matches_wordword_digits(handle: &str) -> bool {
    let parts: Vec<&str> = handle.split('_').collect();
    // Destructure rather than length-check + index (SEC-15).
    let [adj, noun, digits] = parts.as_slice() else {
        return false;
    };
    if adj.is_empty() || !adj.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    if noun.is_empty() || !noun.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    true
}

fn matches_qub_hex(handle: &str) -> bool {
    let Some(rest) = handle.strip_prefix("qub_") else {
        return false;
    };
    rest.len() == 8
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the proof-of-possession preimage for a handle rename.
///
/// Byte layout (`docs/IDENTITY.md` §3.2.5.3):
///
/// ```text
/// HANDLE_RENAME_DOMAIN (29)
///   || fingerprint (32)
///   || current_handle_len_u64_be (8)
///   || current_handle.as_bytes() (variable)
///   || new_handle_len_u64_be (8)
///   || new_handle.as_bytes() (variable)
///   || timestamp.to_be_bytes() (8)
/// ```
///
/// Both handles are included in the preimage so a signature valid for
/// `A → B` cannot be replayed for `A → C` or for a rename *away* from
/// a different current handle. The explicit lengths are necessary because
/// bare concatenation is ambiguous (`"abc" || "defg"` equals
/// `"abcd" || "efg"`). The server normalises both before rebuilding the
/// challenge, so callers should pass normalised handles.
#[must_use]
pub fn build_rename_challenge(
    fingerprint: &[u8; 32],
    current_handle: &str,
    new_handle: &str,
    timestamp: i64,
) -> Vec<u8> {
    let current_bytes = current_handle.as_bytes();
    let new_bytes = new_handle.as_bytes();
    let mut out = Vec::with_capacity(
        HANDLE_RENAME_DOMAIN.len() + 32 + 8 + current_bytes.len() + 8 + new_bytes.len() + 8,
    );
    out.extend_from_slice(HANDLE_RENAME_DOMAIN);
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(&(current_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(current_bytes);
    out.extend_from_slice(&(new_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(new_bytes);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// Build the proof-of-possession preimage for a handle delete.
///
/// Byte layout (`docs/IDENTITY.md` §3.2.5.4):
///
/// ```text
/// HANDLE_DELETE_DOMAIN (29) || fingerprint (32) || utf8(current_handle) || timestamp_be (8)
/// ```
///
/// `current_handle` is bound into the preimage (the 8-byte timestamp
/// tail keeps the variable-length handle unambiguous) so a delete
/// signature is tied to a specific handle value. Without it a captured
/// delete blob (or a stale sibling fingerprint's signature) could clear
/// a newer, different handle within the timestamp window (auth-flow
/// review Finding 5). The server normalises the handle before rebuilding
/// the challenge, so callers should pass the normalised handle.
#[must_use]
pub fn build_delete_challenge(
    fingerprint: &[u8; 32],
    current_handle: &str,
    timestamp: i64,
) -> Vec<u8> {
    let handle_bytes = current_handle.as_bytes();
    let mut out = Vec::with_capacity(HANDLE_DELETE_DOMAIN.len() + 32 + handle_bytes.len() + 8);
    out.extend_from_slice(HANDLE_DELETE_DOMAIN);
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(handle_bytes);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// Build the proof-of-possession preimage for a profile set
/// (`display_name` + `url`).
///
/// Byte layout:
///
/// ```text
/// PROFILE_SET_DOMAIN          (27)
/// || fingerprint               (32)
/// || prev_updated_at_be         (8)   CAS token — guards against replay
/// || display_name_len_u16_be    (2)
/// || utf8_nfc(display_name)     (variable)
/// || url_len_u16_be             (2)
/// || utf8(url)                  (variable)
/// || timestamp_be               (8)
/// ```
///
/// `display_name` is NFC-normalised here before length-prefixing so
/// the client and server agree on the exact byte sequence regardless
/// of which Unicode form the user typed.
///
/// `prev_updated_at` MUST mirror the server's current
/// `record.profile?.updated_at ?? 0` at sign time. The signed
/// challenge therefore cannot be replayed across an intervening
/// edit — the server rejects with `profile_stale` on mismatch.
///
/// Each field is `Option<&str>`: `None` means "omitted — keep the
/// existing value", `Some("")` means "clear this field", and
/// `Some(value)` means "set to value". A presence bitmask byte
/// (`bit0 = display_name present`, `bit1 = url present`) is bound into
/// the preimage right after `prev_updated_at`, so omit and clear sign
/// to DIFFERENT bytes. Without it, both encoded to a zero-length field
/// and a captured "set name only" request could be tampered to also
/// clear `url` without invalidating the signature (auth-flow review
/// Finding 1). An absent field still encodes a `0` length prefix and no
/// bytes; the presence bit is what disambiguates it from a clear.
///
/// # Panics
///
/// Panics if either string exceeds `u16::MAX` bytes after encoding.
/// In practice the server caps display names at 50 graphemes with a
/// 200-code-point ceiling, and URLs at 512 chars — both well below
/// the limit.
#[must_use]
// SEC-15: `display_name` / `url` are length-capped far below u16::MAX
// upstream (see the doc above), so the `u16::try_from` length-prefix
// conversions below cannot fail; the `expect`s are infallible.
#[allow(clippy::expect_used)]
pub fn build_profile_set_challenge(
    fingerprint: &[u8; 32],
    prev_updated_at: i64,
    display_name: Option<&str>,
    url: Option<&str>,
    timestamp: i64,
) -> Vec<u8> {
    let dn_nfc: Option<String> = display_name.map(|s| s.nfc().collect());
    let dn_bytes: &[u8] = dn_nfc.as_deref().map_or(&[], str::as_bytes);
    let url_bytes: &[u8] = url.map_or(&[], str::as_bytes);

    let dn_len = u16::try_from(dn_bytes.len()).expect("display_name within u16 bytes");
    let url_len = u16::try_from(url_bytes.len()).expect("url within u16 bytes");

    let mut presence: u8 = 0;
    if display_name.is_some() {
        presence |= 0b0000_0001;
    }
    if url.is_some() {
        presence |= 0b0000_0010;
    }

    let mut out = Vec::with_capacity(
        PROFILE_SET_DOMAIN.len() + 32 + 8 + 1 + 2 + dn_bytes.len() + 2 + url_bytes.len() + 8,
    );
    out.extend_from_slice(PROFILE_SET_DOMAIN);
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(&prev_updated_at.to_be_bytes());
    out.push(presence);
    out.extend_from_slice(&dn_len.to_be_bytes());
    out.extend_from_slice(dn_bytes);
    out.extend_from_slice(&url_len.to_be_bytes());
    out.extend_from_slice(url_bytes);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// Build the proof-of-possession preimage for an avatar set.
///
/// Byte layout:
///
/// ```text
/// AVATAR_SET_DOMAIN     (26)
/// || fingerprint         (32)
/// || image_hash          (32)   SHA3-256 of the uploaded image bytes;
///                                all-zero for a removal
/// || timestamp_be         (8)
/// ```
///
/// Unlike [`build_profile_set_challenge`] there is no CAS token: the
/// avatar write is last-writer-wins (a single binary has no merge), and
/// `image_hash` binds the signature to the exact bytes being uploaded.
#[must_use]
pub fn build_avatar_set_challenge(
    fingerprint: &[u8; 32],
    image_hash: &[u8; 32],
    timestamp: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(AVATAR_SET_DOMAIN.len() + 32 + 32 + 8);
    out.extend_from_slice(AVATAR_SET_DOMAIN);
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(image_hash);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// Adjective wordlist used for auto-allocation (`<adj>_<noun>_<3 digits>`).
///
/// Re-exported so the Worker test suite can snapshot this list and
/// assert the TypeScript mirror in `workers/api/src/routes/handle-alloc.ts`
/// stays in sync.
#[must_use]
pub const fn adjectives() -> &'static [&'static str] {
    ADJECTIVES
}

/// Noun wordlist used for auto-allocation.
#[must_use]
pub const fn nouns() -> &'static [&'static str] {
    NOUNS
}

/// Percent-encode a (possibly multi-script) handle for use as a URL
/// path segment.
///
/// Encodes every byte outside the RFC 3986 unreserved set
/// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`). The TypeScript mirror in
/// `workers/api/src/utils/handle-url.ts` uses
/// [`encodeURIComponent`][mdn] which has the same exact set, so both
/// sides produce byte-identical URLs for the same handle. The
/// cross-implementation fixture at
/// `crates/qub-core/tests/vectors/handle_url_v1.json` is the canonical
/// contract; the Workers vitest suite asserts byte equality.
///
/// `docs/IDENTITY.md` §3.2.6.9 mandates that every `/u/<handle>`,
/// `og:url`, and `Location` redirect carrying a handle goes through
/// this helper so the Worker router and the Leptos router both decode
/// percent-encoded UTF-8 into the exact bytes the validator accepted.
///
/// [mdn]: https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
#[must_use]
pub fn encode_handle_for_url(handle: &str) -> String {
    utf8_percent_encode(handle, HANDLE_PATH).to_string()
}

/// Bytes encoded by [`encode_handle_for_url`].
///
/// Encodes the C0 control set, DEL (`\u{7F}`), and the reserved /
/// sub-delimiter / gen-delimiter ASCII punctuation defined by RFC 3986
/// section 2.2 — i.e. everything except A–Z a–z 0–9 `-` `_` `.` `~`
/// (the RFC 3986 unreserved set). Non-ASCII bytes always encode via
/// UTF-8 byte expansion. The unreserved set is exactly what
/// `encodeURIComponent` on the TS side leaves untouched, so both
/// sides produce identical URLs.
const HANDLE_PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_accepts_simple_lower() {
        assert_eq!(normalise_handle("markharper").unwrap(), "markharper");
    }

    #[test]
    fn normalise_strips_leading_at() {
        assert_eq!(normalise_handle("@markharper").unwrap(), "markharper");
    }

    #[test]
    fn normalise_folds_ascii_uppercase() {
        assert_eq!(normalise_handle("MarkHarper").unwrap(), "markharper");
    }

    #[test]
    fn normalise_rejects_too_short() {
        assert_eq!(normalise_handle("ab"), Err(HandleValidationError::TooShort));
    }

    #[test]
    fn normalise_rejects_too_long() {
        assert_eq!(
            normalise_handle(&"a".repeat(HANDLE_MAX_LEN + 1)),
            Err(HandleValidationError::TooLong)
        );
    }

    #[test]
    fn normalise_accepts_boundary_lengths() {
        assert!(normalise_handle(&"a".repeat(HANDLE_MIN_LEN)).is_ok());
        assert!(normalise_handle(&"a".repeat(HANDLE_MAX_LEN)).is_ok());
    }

    #[test]
    fn normalise_rejects_hyphen() {
        assert_eq!(
            normalise_handle("mark-harper"),
            Err(HandleValidationError::DisallowedScript)
        );
    }

    #[test]
    fn normalise_rejects_dot() {
        assert_eq!(
            normalise_handle("mark.harper"),
            Err(HandleValidationError::DisallowedScript)
        );
    }

    #[test]
    fn normalise_rejects_space() {
        assert_eq!(
            normalise_handle("mark harper"),
            Err(HandleValidationError::DisallowedScript)
        );
    }

    /// V2 accepts Latin-with-diacritic handles (`märk` is valid Latin script).
    #[test]
    fn normalise_accepts_latin_diacritic() {
        assert_eq!(normalise_handle("märk").unwrap(), "märk");
    }

    /// Vietnamese is Latin-with-diacritics, NFC-normalised.
    #[test]
    fn normalise_accepts_vietnamese() {
        assert_eq!(normalise_handle("nguyễn").unwrap(), "nguyễn");
    }

    /// Greek single-script handle.
    #[test]
    fn normalise_accepts_greek() {
        // Greek alpha-rho-iota-sigma-tau-omicron-sigma
        assert_eq!(normalise_handle("αριστος").unwrap(), "αριστος");
    }

    /// Cyrillic single-script handle.
    #[test]
    fn normalise_accepts_cyrillic() {
        assert_eq!(normalise_handle("николай").unwrap(), "николай");
    }

    /// Arabic single-script handle (RTL).
    #[test]
    fn normalise_accepts_arabic() {
        assert_eq!(normalise_handle("محمد").unwrap(), "محمد");
    }

    /// Han (Chinese / single-script CJK) handle.
    #[test]
    fn normalise_accepts_han_only() {
        assert_eq!(normalise_handle("小明同学").unwrap(), "小明同学");
    }

    /// Han + Hiragana — Japanese exception in §3.2.6.3.
    #[test]
    fn normalise_accepts_japanese_han_hiragana() {
        // たろう (taro, hiragana) + 小林 (Kobayashi, Han)
        assert_eq!(normalise_handle("たろう小林").unwrap(), "たろう小林");
    }

    /// Hangul (Korean syllables).
    #[test]
    fn normalise_accepts_hangul() {
        assert_eq!(normalise_handle("민준이").unwrap(), "민준이");
    }

    /// Devanagari (Hindi).
    #[test]
    fn normalise_accepts_devanagari() {
        assert_eq!(normalise_handle("राम").unwrap(), "राम");
    }

    /// Bengali (Bangla).
    #[test]
    fn normalise_accepts_bengali() {
        assert_eq!(normalise_handle("রাহুল").unwrap(), "রাহুল");
    }

    /// Thai single-script handle.
    #[test]
    fn normalise_accepts_thai() {
        assert_eq!(normalise_handle("สมชาย").unwrap(), "สมชาย");
    }

    /// Latin + Cyrillic is the canonical homograph attack — must reject.
    #[test]
    fn normalise_rejects_latin_cyrillic_mix() {
        // 'm', 'а' (Cyrillic U+0430, looks like Latin 'a'), 'r', 'k'
        assert_eq!(
            normalise_handle("m\u{0430}rk"),
            Err(HandleValidationError::MixedScript)
        );
    }

    /// Mixed Greek + Latin — forbidden.
    #[test]
    fn normalise_rejects_greek_latin_mix() {
        assert_eq!(
            normalise_handle("αlpha"),
            Err(HandleValidationError::MixedScript)
        );
    }

    /// Native digit forms are not in the Common allowlist (only ASCII
    /// digits are accepted from Common script).
    #[test]
    fn normalise_rejects_arabic_indic_digit() {
        // Arabic-Indic digit '5' (U+0665) inside an otherwise-Arabic handle
        assert_eq!(
            normalise_handle("محمد\u{0665}"),
            Err(HandleValidationError::DisallowedScript)
        );
    }

    /// Zero-width joiner cannot be used to spoof an existing handle.
    #[test]
    fn normalise_rejects_zwj() {
        assert_eq!(
            normalise_handle("mar\u{200D}k"),
            Err(HandleValidationError::InvisibleChar)
        );
    }

    /// Right-to-left override mid-handle is blocked.
    #[test]
    fn normalise_rejects_rlo() {
        assert_eq!(
            normalise_handle("mar\u{202E}k"),
            Err(HandleValidationError::InvisibleChar)
        );
    }

    /// Variation selectors are invisible — blocked.
    #[test]
    fn normalise_rejects_variation_selector() {
        assert_eq!(
            normalise_handle("mark\u{FE0F}er"),
            Err(HandleValidationError::InvisibleChar)
        );
    }

    /// Katakana loanwords with the chōonpu (U+30FC, Script=Common but
    /// `Script_Extensions={Hiragana, Katakana}`) are ordinary Japanese —
    /// the resolved-script-set semantics must accept them.
    #[test]
    fn normalise_accepts_katakana_with_choonpu() {
        for h in ["コーヒー", "サーバー", "ラーメン", "みんなー"] {
            assert_eq!(normalise_handle(h).unwrap(), h, "{h} must normalise");
        }
    }

    /// Hiragana + Katakana without Han resolves to the Japanese
    /// writing-system group — allowed per UTS #39 augmented sets.
    #[test]
    fn normalise_accepts_hiragana_katakana_mix() {
        assert_eq!(normalise_handle("かなカナ").unwrap(), "かなカナ");
    }

    /// An all-chōonpu handle has no base letter — renders as bare
    /// dashes and must not be claimable.
    #[test]
    fn normalise_rejects_modifier_only_handle() {
        assert_eq!(
            normalise_handle("ーーー"),
            Err(HandleValidationError::NoBaseLetter)
        );
    }

    /// Arabic tatweel is a UTS #39 Restricted stretch mark — rejected
    /// both alone and embedded in an otherwise-valid Arabic handle.
    #[test]
    fn normalise_rejects_tatweel() {
        assert_eq!(
            normalise_handle("\u{0640}\u{0640}\u{0640}"),
            Err(HandleValidationError::DisallowedScript)
        );
        assert_eq!(
            normalise_handle("مح\u{0640}مد"),
            Err(HandleValidationError::DisallowedScript)
        );
    }

    /// Hiragana + Hangul is a cross-writing-system mix — still
    /// rejected under the resolved-script-set semantics.
    #[test]
    fn normalise_rejects_hiragana_hangul_mix() {
        assert_eq!(
            normalise_handle("かな민준"),
            Err(HandleValidationError::MixedScript)
        );
    }

    /// UTS #39 §5.1 augmentation, from the ACCEPTING side — the side no
    /// test covered.
    ///
    /// Every existing mixed-script test asserts a REJECTION (Latin +
    /// Cyrillic, Greek + Latin, Hiragana + Hangul). But `augment` exists
    /// only to make certain mixes LEGAL: Han joins the Japanese group with
    /// Hiragana/Katakana, and the Korean group with Hangul, so that 漢民준
    /// resolves to a non-empty script set. A test that only ever checks
    /// rejections cannot observe an augmentation bit going missing —
    /// dropping one makes MORE things rejected, and every assertion still
    /// passes.
    ///
    /// That blind spot left three mutants alive: `GROUP_KOREAN` and
    /// `HANGUL_BIT` shifted to zero, and `HAN_BIT | HANGUL_BIT` turned
    /// into `HAN_BIT & HANGUL_BIT` (which is zero — the bits are
    /// disjoint). All three delete the Korean group, and all three die
    /// here.
    ///
    /// Four sibling mutants in `augment` and `classify` are EQUIVALENT and
    /// no test can kill them: `|` → `^` between any two script-bit
    /// constants is identical because the bits are disjoint by
    /// construction, and `1u16 << ScriptIdx::Latin` shifts by zero, so
    /// `<<` and `>>` agree.
    #[test]
    fn normalise_accepts_augmentation_group_mixes() {
        for handle in [
            "漢민준", // Han + Hangul  -> Korean group
            "민준漢", // ...either order
            "漢かな", // Han + Hiragana -> Japanese group
            "漢カナ", // Han + Katakana -> Japanese group
        ] {
            assert_eq!(
                normalise_handle(handle),
                Ok(handle.to_owned()),
                "{handle} shares a UTS #39 augmentation group and must be accepted"
            );
        }
    }

    /// Hangul fillers are alphabetic Script=Hangul but render blank —
    /// an all-filler handle must not be claimable.
    #[test]
    fn normalise_rejects_all_hangul_filler_handle() {
        assert_eq!(
            normalise_handle("\u{3164}\u{3164}\u{3164}"),
            Err(HandleValidationError::InvisibleChar)
        );
    }

    /// A Hangul filler embedded in a real Hangul handle would mint an
    /// invisible near-duplicate of the unadorned handle — blocked.
    #[test]
    fn normalise_rejects_embedded_hangul_fillers() {
        for filler in ['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}'] {
            assert_eq!(
                normalise_handle(&format!("민준{filler}이")),
                Err(HandleValidationError::InvisibleChar),
                "filler U+{:04X} must be rejected",
                filler as u32
            );
        }
    }

    /// Private-use codepoints carry no assigned glyph, so what a viewer
    /// sees is font-dependent — usually blank, sometimes a fallback box.
    /// A handle built from them is either invisible outright or an
    /// unpredictable near-duplicate of a real handle, which is the spoof
    /// `is_invisible_codepoint` exists to stop.
    ///
    /// One representative per end of each of the three ranges, because
    /// they are three separate `||` arms and mutation testing found BOTH
    /// operators between them survived the entire suite: no test supplied
    /// a private-use codepoint at all, so the arms were never observed.
    /// Coverage could not see this — every line already executed.
    #[test]
    fn normalise_rejects_private_use_codepoints() {
        for pua in [
            '\u{E000}',   // BMP private use area, first
            '\u{F8FF}',   // BMP private use area, last
            '\u{F0000}',  // Supplementary PUA-A, first
            '\u{FFFFD}',  // Supplementary PUA-A, last
            '\u{100000}', // Supplementary PUA-B, first
            '\u{10FFFD}', // Supplementary PUA-B, last
        ] {
            assert_eq!(
                normalise_handle(&format!("min{pua}jun")),
                Err(HandleValidationError::InvisibleChar),
                "private-use U+{:04X} must be rejected",
                pua as u32
            );
        }
    }

    /// Combining mark at the start has no base to attach to.
    #[test]
    fn normalise_rejects_leading_combining_mark() {
        // U+0301 = combining acute accent
        assert_eq!(
            normalise_handle("\u{0301}mark"),
            Err(HandleValidationError::LeadingMark)
        );
    }

    /// Emoji — not in any allowed script (Symbol category).
    #[test]
    fn normalise_rejects_emoji() {
        assert_eq!(
            normalise_handle("mark\u{1F600}"),
            Err(HandleValidationError::DisallowedScript)
        );
    }

    /// Decomposed input gets composed by NFC.
    #[test]
    fn normalise_nfc_composes_decomposed() {
        // "ma" + "r" + "k" + decomposed 'é' (e + combining acute)
        let decomposed = "mark\u{0065}\u{0301}";
        // After NFC the e+◌́ composes to é (U+00E9).
        assert_eq!(normalise_handle(decomposed).unwrap(), "mark\u{00E9}");
    }

    #[test]
    fn normalise_rejects_starting_digit() {
        assert_eq!(
            normalise_handle("1mark"),
            Err(HandleValidationError::StartsDigit)
        );
    }

    #[test]
    fn normalise_rejects_reserved() {
        assert_eq!(
            normalise_handle("admin"),
            Err(HandleValidationError::Reserved)
        );
    }

    #[test]
    fn normalise_is_idempotent() {
        let once = normalise_handle("@MarkHarper").unwrap();
        let twice = normalise_handle(&once).unwrap();
        assert_eq!(once, twice);
    }

    /// V2 idempotence on a Cyrillic handle.
    #[test]
    fn normalise_is_idempotent_cyrillic() {
        let once = normalise_handle("николай").unwrap();
        let twice = normalise_handle(&once).unwrap();
        assert_eq!(once, twice);
    }

    /// Greek capital sigma lowercases to medial sigma (locale-independent).
    #[test]
    fn normalise_folds_greek_uppercase() {
        // Greek capital alpha-rho-iota-sigma-tau-omicron-sigma
        let upper = "ΑΡΙΣΤΟΣ";
        let lower = "αριστος";
        assert_eq!(normalise_handle(upper).unwrap(), lower);
    }

    #[test]
    fn auto_shape_matches_allocator_output() {
        assert!(is_auto_allocated_shape("quiet_fox_482"));
        assert!(is_auto_allocated_shape("a_b_000"));
        assert!(is_auto_allocated_shape("qub_deadbeef"));
    }

    #[test]
    fn auto_shape_rejects_user_handles() {
        assert!(!is_auto_allocated_shape("markharper"));
        assert!(!is_auto_allocated_shape("mark_harper"));
        assert!(!is_auto_allocated_shape("quiet_fox_4820")); // 4 digits
        assert!(!is_auto_allocated_shape("quiet_fox_48")); // 2 digits
        assert!(!is_auto_allocated_shape("quiet_fox_abc")); // non-digit suffix
        assert!(!is_auto_allocated_shape("quiet__482")); // empty noun
        assert!(!is_auto_allocated_shape("_fox_482")); // empty adj
        assert!(!is_auto_allocated_shape("qub_DEADBEEF")); // uppercase hex rejected (lower-case-only)
        assert!(!is_auto_allocated_shape("qub_deadbeeg")); // 'g' not hex
        assert!(!is_auto_allocated_shape("qub_dead")); // short hex
    }

    #[test]
    fn rename_challenge_byte_layout() {
        let fp = [0x42u8; 32];
        let challenge = build_rename_challenge(&fp, "old", "new", 0x01);
        // 29 (domain) + 32 (fp) + 8 + 3 (old) + 8 + 3 (new) + 8 (ts) = 91
        assert_eq!(challenge.len(), 91);
        assert_eq!(&challenge[..29], HANDLE_RENAME_DOMAIN);
        assert_eq!(&challenge[29..61], &fp);
        assert_eq!(&challenge[61..69], &3u64.to_be_bytes());
        assert_eq!(&challenge[69..72], b"old");
        assert_eq!(&challenge[72..80], &3u64.to_be_bytes());
        assert_eq!(&challenge[80..83], b"new");
        assert_eq!(&challenge[83..91], &1i64.to_be_bytes());
    }

    #[test]
    fn rename_challenge_lengths_count_utf8_bytes() {
        let fp = [0x24u8; 32];
        let current = "αβ"; // two scalar values, four UTF-8 bytes
        let new = "猫"; // one scalar value, three UTF-8 bytes
        let challenge = build_rename_challenge(&fp, current, new, -2);

        assert_eq!(&challenge[61..69], &4u64.to_be_bytes());
        assert_eq!(&challenge[69..73], current.as_bytes());
        assert_eq!(&challenge[73..81], &3u64.to_be_bytes());
        assert_eq!(&challenge[81..84], new.as_bytes());
        assert_eq!(&challenge[84..92], &(-2i64).to_be_bytes());
    }

    #[test]
    fn delete_challenge_byte_layout() {
        let fp = [0x42u8; 32];
        let challenge = build_delete_challenge(&fp, "alice", 0x01);
        // 29 (domain) + 32 (fp) + 5 ("alice") + 8 (ts) = 74
        assert_eq!(challenge.len(), 74);
        assert_eq!(&challenge[..29], HANDLE_DELETE_DOMAIN);
        assert_eq!(&challenge[29..61], &fp);
        assert_eq!(&challenge[61..66], b"alice");
        assert_eq!(&challenge[66..74], &1i64.to_be_bytes());
    }

    #[test]
    fn delete_challenge_injective_in_handle() {
        // A delete signature for handle "alice" must not be valid for a
        // delete of handle "alicx" (Finding 5).
        let fp = [0x42u8; 32];
        let a = build_delete_challenge(&fp, "alice", 1);
        let b = build_delete_challenge(&fp, "alicx", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn rename_challenge_injective_in_current() {
        let fp = [0x42u8; 32];
        let a = build_rename_challenge(&fp, "old1", "new", 1);
        let b = build_rename_challenge(&fp, "old2", "new", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn rename_challenge_injective_in_new() {
        let fp = [0x42u8; 32];
        let a = build_rename_challenge(&fp, "old", "new1", 1);
        let b = build_rename_challenge(&fp, "old", "new2", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn rename_challenge_injective_in_fingerprint() {
        let a = build_rename_challenge(&[0x01; 32], "old", "new", 1);
        let b = build_rename_challenge(&[0x02; 32], "old", "new", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn rename_challenge_injective_in_timestamp() {
        let fp = [0x42u8; 32];
        let a = build_rename_challenge(&fp, "old", "new", 1);
        let b = build_rename_challenge(&fp, "old", "new", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separators_are_29_bytes() {
        assert_eq!(HANDLE_RENAME_DOMAIN.len(), 29);
        assert_eq!(HANDLE_DELETE_DOMAIN.len(), 29);
    }

    // ─── URL encoding (docs/IDENTITY.md §3.2.6.9) ──────────────────

    #[test]
    fn encode_handle_for_url_preserves_v1_ascii() {
        // V1 ASCII handles must round-trip unchanged; otherwise every
        // existing /u/<handle> link in the wild would silently churn
        // on hover-preview / share-card refresh.
        assert_eq!(encode_handle_for_url("markharper"), "markharper");
        assert_eq!(encode_handle_for_url("orange_fox_612"), "orange_fox_612");
        assert_eq!(encode_handle_for_url("qub_deadbeef"), "qub_deadbeef");
    }

    #[test]
    fn encode_handle_for_url_preserves_rfc3986_unreserved() {
        // ALPHA / DIGIT / "-" / "_" / "." / "~" — the set
        // encodeURIComponent leaves untouched.
        assert_eq!(encode_handle_for_url("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn encode_handle_for_url_encodes_arabic() {
        // محمد (Arabic — V2 multi-script allows it; URL needs encoding).
        assert_eq!(encode_handle_for_url("محمد"), "%D9%85%D8%AD%D9%85%D8%AF");
    }

    #[test]
    fn encode_handle_for_url_encodes_greek() {
        // μαρκος
        assert_eq!(
            encode_handle_for_url("μαρκος"),
            "%CE%BC%CE%B1%CF%81%CE%BA%CE%BF%CF%82"
        );
    }

    #[test]
    fn encode_handle_for_url_encodes_cyrillic() {
        // марк
        assert_eq!(encode_handle_for_url("марк"), "%D0%BC%D0%B0%D1%80%D0%BA");
    }

    #[test]
    fn encode_handle_for_url_encodes_hangul() {
        // 마르크
        assert_eq!(
            encode_handle_for_url("마르크"),
            "%EB%A7%88%EB%A5%B4%ED%81%AC"
        );
    }

    #[test]
    fn encode_handle_for_url_encodes_han_hiragana_mix() {
        // たろう小林 — Han+Hiragana exception per UTS #39 MR.
        assert_eq!(
            encode_handle_for_url("たろう小林"),
            "%E3%81%9F%E3%82%8D%E3%81%86%E5%B0%8F%E6%9E%97"
        );
    }

    #[test]
    fn encode_handle_for_url_encodes_supplementary_plane() {
        // 𝕞 (Mathematical Double-Struck Small M, U+1D55E) — surrogate
        // pair on the JS side. UTF-8 byte expansion is 4 bytes.
        assert_eq!(encode_handle_for_url("𝕞"), "%F0%9D%95%9E");
    }

    #[test]
    fn encode_handle_for_url_encodes_path_reserved_ascii() {
        // Defensive: even though the V2 validator rejects these, the
        // encoder must escape them if it ever sees them (so a bug in
        // an upstream caller produces a 404 rather than a path-traversal
        // surface).
        assert_eq!(encode_handle_for_url("a/b"), "a%2Fb");
        assert_eq!(encode_handle_for_url("a?b"), "a%3Fb");
        assert_eq!(encode_handle_for_url("a#b"), "a%23b");
        assert_eq!(encode_handle_for_url("a b"), "a%20b");
        assert_eq!(encode_handle_for_url("a%b"), "a%25b");
    }

    #[test]
    fn encode_handle_for_url_round_trips_through_percent_decode() {
        // For every fixture, percent_decode reverses encode_handle_for_url
        // back to the original bytes.
        for handle in [
            "markharper",
            "orange_fox_612",
            "محمد",
            "μαρκος",
            "марк",
            "마르크",
            "たろう小林",
            "𝕞",
        ] {
            let encoded = encode_handle_for_url(handle);
            let decoded = percent_encoding::percent_decode_str(&encoded)
                .decode_utf8()
                .expect("encoded form is valid percent-encoded UTF-8");
            assert_eq!(decoded, handle, "round-trip failed for {handle}");
        }
    }
}
