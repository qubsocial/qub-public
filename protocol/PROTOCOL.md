qub is a protocol for cryptographic temporal commitments: a system for sealing words to a future date and later verifying exactly what was sealed, which drand round gated its release, and—when a storage transaction or transparency-log proof is available—an independently timestamped upper bound on when the ciphertext was committed.

Three primitives make it work. **drand** is a decentralised randomness beacon—the reveal date is enforced cryptographically rather than by qub's goodwill. **Durable storage** preserves acknowledged sealed bytes while the current publication paths schedule individual permanent-storage transactions; successful general-upload log appends can additionally join batched, anchored commitments. **ML-DSA-65** is a post-quantum digital signature—when authorship is enabled, the qub is tied to a key pair whose secret never leaves the author's device.

Together these primitives make a statement that is time-locked and tamper-evident, optionally attributable, and independently timestampable—a receipt whose value grows as the world's ability to fabricate the past improves.

The remainder of this document is the normative specification required for interoperable implementations.

______________________________________________________________________

# qub Protocol Specification

| Field | Value |
| ----------- | ----------------------------- |
| **Document release** | 1.0.0 (`protocol-v1.0.0`) |
| **Wire protocol** | `0x01` |
| **Outer wrapper** | `0x01` |
| **Effective date** | 2026-09-23 |
| **Status** | **Current** |
| **Reviewed through** | 2026-09-23 |

This document is the normative protocol specification for the qub timed commitment system. It defines data structures, serialisation rules, derivation formulas, and verification procedures required for interoperable implementations.

Scope: the protocol layer is intentionally language-neutral — the qub body is opaque plaintext / markdown / pact bytes, and locale-aware rendering is the viewer's responsibility (qub.social web app, `<qub-embed>` iframe, MCP clients, etc.).

______________________________________________________________________

## 1. Notation and Conventions

| Notation | Meaning |
| ------------------ | ----------------------------------------------- |
| `u8`, `u64`, `i64` | Unsigned/signed integers of specified bit width |
| `[u8; N]` | Fixed-length byte array of N bytes |
| `Vec<u8>` | Variable-length byte array |
| `Option<T>` | Value of type T, or absent |
| `String` | UTF-8 text string, NFC normalised |
| `||` | Byte concatenation |
| `SHA3-256(x)` | NIST SHA3-256 hash of byte string x (FIPS 202) |
| `ceil(x)` | Ceiling function: smallest integer ≥ x |
| CBOR | Concise Binary Object Representation (RFC 8949) |
| big-endian | Most significant byte first |

All integers in preimage constructions are encoded as **big-endian** fixed-width byte arrays (i64 → 8 bytes, u8 → 1 byte) unless otherwise specified.

All timestamps are **Unix seconds in UTC**.

______________________________________________________________________

## 2. Data Structures

### 2.1 ComposeQub (Creator In-Memory State)

Not serialised to CBOR. Not written to permanent storage. Local to the creator app.

```text
ComposeQub {
    draft_id:       [u8; 16],        // Random, generated locally
    created_at:     i64,             // Unix seconds UTC
    unlock_at:      Option<i64>,     // Unix seconds UTC; None while composing
    visibility:     u8,              // 0x00 = private; 0x01 = public
    content_type:   u8,              // 0x01 text; 0x03 pact; 0x04 verdict
    plaintext:      Vec<u8>,         // Raw body bytes (UTF-8 for text)
    sender_label:   Option<String>,  // Display name; V2-signed when authorship is enabled
    title:          Option<String>,  // Plaintext countdown title; bound via title_hash
    reply_to:       Option<[u8; 32]>,// Parent qub_id; V2-signed when authorship is enabled
    outcome_at:     Option<i64>,     // Optional future judgment time; bound to qub_id
    status:         DraftStatus,     // Composing | Sealed | Uploaded | Failed
}
```

### 2.2 QubEnvelope (Decrypted Payload)

Serialised using canonical CBOR (§3). Encrypted inside the `SealedQub`. This is the structure that proves content integrity after decryption.

```text
QubEnvelope {
    version:             u8,              // Protocol major version (0x01 for v1)
    qub_id:              [u8; 32],        // Derived (see §4.1)
    content_type:        u8,              // Content type registry (see §6)
    created_at:          i64,             // Unix seconds UTC
    unlock_at:           i64,             // Unix seconds UTC
    outcome_at:          Option<i64>,     // When reality renders judgment; bound to qub_id
    sender_label:        Option<String>,  // Not in qub_id; V2-signed when authorship is enabled
    reply_to:            Option<[u8; 32]>,// Parent qub_id; not in qub_id; V2-signed when present
    body:                Vec<u8>,         // UTF-8 text or canonical CBOR pact/verdict body
    body_hash:           [u8; 32],        // SHA3-256(body) (see §4.2)
    sig_alg:             u8,              // Signature algorithm (see §9.2)
    author_signature:    Option<Vec<u8>>, // Set when sig_alg != 0x00
    author_pubkey:       Option<Vec<u8>>, // Set when sig_alg != 0x00
    cosigner_pubkey:     Option<Vec<u8>>, // Set for cosigned pact bilateral agreements
    cosigner_signature:  Option<Vec<u8>>, // Set for cosigned pact bilateral agreements
}
```

**Baseline (unsigned text qub):** `version` = `0x01`, `content_type` = `0x01`, `sig_alg` = `0x00`; signature and cosigner fields are absent. Other optional metadata fields may be present.

**Other v1 configurations:** `content_type` = `0x03` (pact body, see §6.1); `sig_alg` = `0x01` (ML-DSA-65) with `author_signature` and `author_pubkey` present (see §9.3); `cosigner_pubkey` and `cosigner_signature` present together for cosigned pacts (see §9.7); `reply_to` set to the parent qub's `qub_id` for reply-chain qubs (see §9.3 for the signature-scope implications).

### 2.3 SealedQub (Canonical Wire Format)

Serialised using canonical CBOR (§3). This is the inner wire artifact: public delivery stores these bytes bare, while private delivery wraps them in `OuterWrapper` before storage (§13).

```text
SealedQub {
    version:           u8,              // Protocol major version (0x01 for v1)
    qub_id:            [u8; 32],        // Same as QubEnvelope.qub_id
    visibility:        u8,              // 0x00 = private/wrapped; 0x01 = public/bare
    unlock_at:         i64,             // Unix seconds UTC
    outcome_at:        Option<i64>,     // Surfaced on the verdict-watch CTA
                                        //   before reveal; mirrors QubEnvelope.outcome_at;
                                        //   bound to qub_id via the §4.1 preimage.
    drand_chain_id:    String,          // drand chain hash (hex string)
    drand_round:       u64,             // Target drand round number
    drand_chain_version: Option<u8>,    // W3 — chain-migration version. Absent / 0 = quicknet
                                        //   (the only chain today). Lets a future chain swap
                                        //   be expressed on the wire without a breaking format
                                        //   change. NOT part of the §4.1 qub_id preimage, so its
                                        //   addition never alters an existing qub's identity.
    tlock_ciphertext:  Vec<u8>,         // tlock-encrypted QubEnvelope CBOR bytes
    recipient_pubkey:  Option<[u8; 32]>,// Reserved field; accepted by canonical CBOR
                                        //   but not interpreted by the v1 reference viewer
    title:             Option<String>,  // Plaintext title surfaced on the viewer
                                        //   countdown before reveal. Bound to qub_id
                                        //   via title_hash (§4.1). 1..=100 NFC code
                                        //   points, no hostile/control code points.
}
```

### 2.4 RevealedQub (Viewer Application State)

Not serialised to CBOR. Local to the viewer app. Constructed after successful decryption and verification.

```text
RevealedQub {
    qub_id:              [u8; 32],
    arweave_tx_id:       String,
    visibility:          u8,
    content_type:        u8,
    created_at:          i64,
    unlock_at:           i64,
    outcome_at:          Option<i64>,       // Carried from both wire layers; drives the verdict-watch block
    drand_chain_id:      String,
    drand_round:         u64,
    sender_label:        Option<String>,
    title:               Option<String>,    // Carried forward from SealedQub.title
    reply_to:            Option<[u8; 32]>,
    body:                Vec<u8>,
    body_hash:           [u8; 32],
    body_hash_verified:  bool,
    author_signature:    Option<Vec<u8>>,
    author_pubkey:       Option<Vec<u8>>,
    signature_verified:  Option<bool>,
    cosigner_pubkey:     Option<Vec<u8>>,
    cosigner_signature:  Option<Vec<u8>>,
    cosigner_verified:   Option<bool>,
}
```

______________________________________________________________________

## 3. Canonical CBOR Profile

All `SealedQub` and `QubEnvelope` serialisation MUST conform to this profile. Two implementations given the same logical structure MUST produce identical bytes.

### 3.1 Encoding Rules

| Rule | Specification |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standard | RFC 8949 §4.2.1 (Core Deterministic Encoding Requirements) |
| Map key ordering | Sorted by **encoded byte length** first (shorter before longer), then **lexicographically** (byte-by-byte for same-length encodings) |
| Integer encoding | Shortest form: 0–23 in initial byte; 24–255 in 2 bytes; 256–65535 in 3 bytes; etc. |
| Length encoding | **Definite lengths only.** No indefinite-length arrays, maps, byte strings, or text strings (additional info = 31 is forbidden). |
| Tags | **No CBOR tags** (major type 6 is forbidden). |
| Floating-point | **No floats** (major types 7 values 0xF9–0xFB are forbidden). |
| Text strings | UTF-8 encoded, **NFC normalised** (Unicode Normalization Form C). |
| Byte strings | Raw bytes. No base64 encoding at the CBOR layer. |
| Duplicate keys | **Reject with error.** Parsers MUST NOT silently accept duplicate map keys. |
| Unknown keys | **Reject with error.** Parsers MUST NOT tolerate map keys outside the type's canonical key set — two distinct canonical byte strings must never decode to the same value (`encode(decode(x)) == x`), and for signed payloads an extra key would be hidden content both signatures commit to. Schema evolution goes through `version`, never extra keys. |
| Simple values | Only `true` (0xF5), `false` (0xF4), and `null` (0xF6) are permitted. |
| Optional fields | Absent optional fields are **omitted** from the CBOR map entirely (not encoded as `null`). Present optional fields are included in sorted key order. |

### 3.2 Verified Canonical Key Orders

These key orders are normative. Implementations MUST emit keys in exactly this order. Debug assertions SHOULD verify ordering in non-release builds.

**QubEnvelope (version 0x01, unsigned, all optional fields absent):**

```text
"body"                (5 encoded bytes)
"qub_id"              (7 encoded bytes)
"sig_alg"             (8 encoded bytes)
"version"             (8 encoded bytes)
"reply_to"            (9 encoded bytes)   ← only if present (reply chains)
"body_hash"           (10 encoded bytes)
"unlock_at"           (10 encoded bytes)
"created_at"          (11 encoded bytes)
"outcome_at"          (11 encoded bytes)  ← only if present (verdict mechanic)
"content_type"        (13 encoded bytes)
"sender_label"        (13 encoded bytes)  ← only if present
"author_pubkey"       (14 encoded bytes)  ← only if present
"cosigner_pubkey"     (16 encoded bytes)  ← only if present (pact cosign)
"author_signature"    (17 encoded bytes)  ← only if present
"cosigner_signature"  (19 encoded bytes)  ← only if present (pact cosign)
```

**QubEnvelope key order derivation:** each key is a CBOR text string. Encoded length = 1 byte header + string length (for strings under 24 bytes). Sort by total encoded length first, then lexicographically for same-length keys.

**SealedQub (version 0x01, public, no recipient):**

```text
"title"             (6 encoded bytes)   ← only if present
"qub_id"            (7 encoded bytes)
"version"           (8 encoded bytes)
"unlock_at"         (10 encoded bytes)
"outcome_at"        (11 encoded bytes)  ← only if present (verdict mechanic)
"visibility"        (11 encoded bytes)
"drand_round"       (12 encoded bytes)
"drand_chain_id"    (15 encoded bytes)
"recipient_pubkey"  (17 encoded bytes)  ← only if present
"tlock_ciphertext"  (17 encoded bytes)
"drand_chain_version" (20 encoded bytes) ← only if present (W3; absent = quicknet)
```

**PactTerms (pact body, content_type `0x03`):**

```text
"notes"         (6 encoded bytes)  ← only if present
"terms"         (6 encoded bytes)
"title"         (6 encoded bytes)
"party_a"       (8 encoded bytes)
"party_b"       (8 encoded bytes)
"pact_version"  (13 encoded bytes)
```

**PactTerm (row of the `terms` array):**

```text
"key"    (4 encoded bytes)
"value"  (6 encoded bytes)
```

**PartyIdentifier (party_a / party_b map):**

```text
"label"    (6 encoded bytes)
"contact"  (8 encoded bytes)  ← only if present
```

### 3.3 Byte Encoding Reference

| Type | CBOR encoding | Example |
| ---------------------------------- | ---------------------------------------------------------- | ----------------- |
| SHA3-256 hash (32 bytes) | `0x58 0x20` + 32 bytes | body_hash, qub_id |
| Timestamps (i64) | Major type 0 (positive) or 1 (negative), shortest encoding | Unix seconds |
| Version (u8, value 1) | `0x01` (single byte) | |
| Content type (u8, value 1) | `0x01` (single byte) | |
| sig_alg (u8, value 0) | `0x00` (single byte) | |
| ML-DSA-65 signature (3,309 bytes) | `0x59 0x0C 0xED` + 3,309 bytes | author_signature, cosigner_signature |
| ML-DSA-65 public key (1,952 bytes) | `0x59 0x07 0xA0` + 1,952 bytes | author_pubkey, cosigner_pubkey |

______________________________________________________________________

## 4. Normative Derivations

### 4.1 qub_id

The `qub_id` uniquely identifies a qub and binds the QubEnvelope to the SealedQub. It is derived deterministically from envelope content.

```text
qub_id = SHA3-256(
    "QUB_ID_V2"          ||  // domain separator: ASCII bytes [0x51 0x55 0x42 0x5F 0x49 0x44 0x5F 0x56 0x32] (9 bytes) + 0x00 padding (1 byte) = 10 bytes
    version              ||  // u8 (1 byte)
    content_type         ||  // u8 (1 byte)
    created_at           ||  // i64 big-endian (8 bytes)
    unlock_at            ||  // i64 big-endian (8 bytes)
    outcome_at_or_zero   ||  // i64 big-endian (8 bytes; 0 when outcome_at is absent)
    drand_round          ||  // u64 big-endian (8 bytes)
    body_hash            ||  // [u8; 32] (32 bytes)
    title_hash               // [u8; 32] (32 bytes; absent-sentinel = [0u8; 32])
)
// Total preimage: 108 bytes → 32-byte output
```

**Domain separator encoding:** The string `"QUB_ID_V2"` is 9 ASCII bytes. A single `0x00` padding byte is appended to reach 10 bytes for alignment. Implementations MUST use exactly these 10 bytes: `[0x51, 0x55, 0x42, 0x5F, 0x49, 0x44, 0x5F, 0x56, 0x32, 0x00]`.

**`outcome_at` encoding:** A pre-release implementation revision extended the preimage from 92 to 100 bytes to fold the optional `outcome_at` field into the binding. Absent `outcome_at` is encoded as 8 zero bytes; the protocol validators reject `outcome_at <= 0` everywhere so this sentinel cannot collide with a legitimate value. See §3.2 (wire format) and the in-tree `tasks/verdict-uplift-plan.md` for the verdict mechanic that motivates this field.

**`drand_round` encoding:** A later pre-release implementation revision extended the preimage from 100 to 108 bytes to fold `drand_round` (the target drand round, §4.3) into the binding, and bumped the domain separator to `QUB_ID_V2`. This binds the timelock round into the qub identity: a gateway cannot rebind the ciphertext to a different (e.g. already-past) round than the displayed `unlock_at` implies. The unlock procedure (§8) additionally verifies that the round baked into the tlock ciphertext stanza matches `unlock_round(unlock_at)`, so the displayed unlock time is provably the round that gates decryption.

**Properties:**

- Changing any field bound by the preimage—`version`, `content_type`, `created_at`, `unlock_at`, `outcome_at`, `drand_round`, the raw `body` bytes (through `body_hash`), or `title` (through `title_hash`)—produces a different `qub_id`.
- The qub_id is computed before encryption. Both QubEnvelope and SealedQub carry the same qub_id. The viewer verifies they match after decryption.
- `qub_id` does not depend on `sender_label`, `reply_to`, signature bytes, or signing public keys. Under the current V2 signing construction, however, `sender_label` and `reply_to` are authenticated directly by `sender_label_hash` and `reply_to_or_zero` (§9.3) whenever signatures are present.
- Changing the SealedQub `title` (with everything else fixed) changes `qub_id` via `title_hash`. A gateway therefore cannot swap the plaintext title displayed on the countdown without invalidating the qub identity.
- Changing the SealedQub `outcome_at` (with everything else fixed) changes `qub_id` via the preimage. A gateway cannot swap the pre-reveal verdict-on date displayed on the countdown without invalidating the qub identity.
- Changing `drand_round` (with everything else fixed) changes `qub_id` via the preimage. A gateway cannot rebind the timelock ciphertext to a different round without invalidating the qub identity; combined with the §8 unlock-time stanza-round check, the displayed `unlock_at` is the round that actually gates decryption.

### 4.2 body_hash

```text
body_hash = SHA3-256(body)
```

Where `body` is the raw `Vec<u8>` content payload. For text qubs, this is the UTF-8 encoded qub body.

### 4.2.1 title_hash

```text
title_hash = SHA3-256(NFC(title).utf8_bytes)   if title is present
title_hash = [0u8; 32]                         if title is absent
```

Where `title` is the optional plaintext title surfaced on the viewer countdown before reveal (see §3.2). NFC normalisation runs at hash time so the digest is stable across visually-equivalent code-point sequences. The all-zeros sentinel is reserved for the absent case; an empty string is rejected at the canonical CBOR boundary as a non-canonical encoding of "absent" (the canonical encoding omits the field entirely).

### 4.3 Unlock-Round Mapping

```text
drand_round = floor((unlock_at - chain_genesis_time) / chain_period_seconds) + 1
```

| Parameter | Source | Example |
| ---------------------- | --------------------------------- | -------------------------------------- |
| `unlock_at` | User-chosen Unix seconds UTC | `1735689600` (2025-01-01 00:00:00 UTC) |
| `chain_genesis_time` | drand chain info (`genesis_time`) | `1595431050` |
| `chain_period_seconds` | drand chain info (`period`) | `30` |

This is the reference tlock mapping (drand's `CurrentRound`). drand publishes round `N` at `chain_genesis_time + (N - 1) * chain_period_seconds`, so the formula selects the **round current at `unlock_at`** — the round whose signature is the first one a viewer arriving at `unlock_at` can use.

**Alignment property (the case that matters in practice):** when `(unlock_at - chain_genesis_time)` is exactly divisible by `chain_period_seconds`, the selected round's signature is published **exactly at `unlock_at`, never before it**. This always holds for the reference deployment: quicknet's genesis time (`1692803367`) is divisible by its 3-second period, and the reference apps pin unlock times to whole minutes. For a non-aligned `unlock_at`, the selected round's signature publishes strictly less than one period before `unlock_at` — the temporal precision of the commitment is one beacon period.

**Legacy pre-release mapping and unlock-side tolerance:** the original mapping was `ceil((unlock_at - chain_genesis_time) / chain_period_seconds)`, which—for the period-aligned case above—selected the round published one full period **before** `unlock_at`, making the ciphertext decryptable early by exactly one period. The two mappings differ by exactly `+1` when the delta divides the period, and agree otherwise. Because `drand_round` is folded into the immutable `qub_id` preimage (§4.1), artifacts sealed under the legacy mapping cannot be re-derived; verifiers performing the §8 step 6a round cross-check MUST therefore accept a stored `drand_round` equal to **either** the derived round **or** the derived round minus one (and MUST require the tlock stanza round to equal the stored round exactly). The tolerance widens the earliest gating signature by at most one period. The pact staging service applies the same tolerance when it re-derives a staged pact's `qub_id` (at stage and at co-sign): if the current mapping's round does not reproduce the committed `qub_id` and the delta divides the period, it retries with the round minus one, and it seals the finalized pact to whichever round the `qub_id` actually binds—never blindly to the recomputed round, which would make the artifact permanently underivable.

**Validation:** `unlock_at` MUST be in the future at seal time. `unlock_at` MUST NOT be more than 10 years from `created_at` (to limit long-horizon drand dependency risk; the UI SHOULD warn for unlock dates beyond 2 years).

______________________________________________________________________

## 5. Wire Format Newtypes

Wire format newtypes provide compile-time safety against confusing CBOR bytes with JSON, raw plaintext, or other byte encodings.

| Type | Contains | Produced By | Consumed By |
| ----------------- | ----------------------------- | -------------------------- | ----------------------------------------- |
| `SealedQubCbor` | Canonical CBOR of SealedQub | `serialize_sealed_qub()` | Inner wire artifact; stored bare for public delivery or wrapped for private delivery, then recovered by the viewer |
| `QubEnvelopeCbor` | Canonical CBOR of QubEnvelope | `serialize_qub_envelope()` | tlock encrypt input, tlock decrypt output |

### 5.1 Construction Rules

```rust
// Production code — only through CBOR serialisers:
let sealed = SealedQubCbor::from_encoded(cbor_bytes);

// There is deliberately NO From<Vec<u8>> implementation.
// You cannot accidentally wrap arbitrary bytes in a wire format type.

// Accessing raw bytes:
let bytes: &[u8] = sealed.as_bytes();
let bytes: Vec<u8> = sealed.into_bytes();
```

### 5.2 Validation on Construction

`from_encoded()` SHOULD validate that the input begins with a valid CBOR map header. Full structural validation happens at parse time, not construction time, to avoid double-parsing.

______________________________________________________________________

## 6. Content Type Registry

| Value | Type | Max Body Size | Notes |
| ------ | --------------------------------------- | ----------------------- | --------------------------------------------------------------------- |
| `0x00` | Reserved (invalid) | — | MUST NOT be used |
| `0x01` | Plain text (UTF-8, restricted Markdown) | 50 KB paid / 10 KB free | See §10 for rendering rules. The free / paid split is enforced by the upload service; the protocol-layer hard ceiling is 50 KB. |
| `0x02` | Reserved (future) | — | Allocated for a future content type; not valid in v1. Viewers MUST reject per the rule below. |
| `0x03` | Pact (bilateral agreement, CBOR body) | 100 KB | Body is canonical CBOR `PactTerms` (§6.1). Cosigner signing per §9.7. |
| `0x04` | Verdict (creator self-grading, CBOR body) | 8 KB | Body is canonical CBOR `VerdictBody` (§6.2). Emitted only by the system-side `verdict` intent. Parent relationship is on the `Parent-Tx-Id` Arweave tag, not on the body. See verdict-uplift-plan §3.4. |

Viewers MUST reject unknown content types with a clear user-visible error. Viewers MUST NOT attempt to render unknown types as text.

### 6.1 Pact Body (`content_type = 0x03`)

A pact body is the canonical CBOR encoding of a `PactTerms` value:

```text
PactTerms {
    pact_version:  u8,                    // 0x01 for structured/v1
    title:         String,                // ≤ 200 bytes, NFC
    terms:         Vec<PactTerm>,         // ≤ 20 rows
    party_a:       PartyIdentifier,       // initiator
    party_b:       PartyIdentifier,       // counter-signer
    notes:         Option<String>,        // ≤ 5,000 bytes, NFC; absent key if none
}

PactTerm       { key: String (≤ 100 bytes), value: String (≤ 2,000 bytes) } // NFC
PartyIdentifier{ label: String (≤ 100 bytes), contact: Option<String (≤ 320 bytes)> }
```

Canonical CBOR key orders for all three maps are given in §3.2. Total serialised pact CBOR MUST NOT exceed 100 KB (matches §6).

**Schema discriminator.** The first row in `terms` for a `structured/v1` pact MUST be `{ key: "pact_schema", value: "structured/v1" }`. Rows without this marker are "custom" pacts and receive no structured validation or schema-aware rendering.

**Frozen acknowledgement slots.** `structured/v1` pacts carry exactly four acknowledgement rows under these keys:

```text
"initiator_standard_terms"
"initiator_capacity_terms"
"counterparty_standard_terms"
"counterparty_capacity_terms"
```

The `value` for each is one of eight frozen English strings chosen by the `(role, kind)` pair, where `role ∈ { seller, buyer, provider, client }` and `kind ∈ { standard, capacity }`. The strings themselves are **normative protocol data** — both parties' ML-DSA-65 signatures commit to the exact bytes via `body_hash`. They are NOT localised; the signed body is language-neutral. Any wording change requires a new schema version (`structured/v2`).

The eight strings, their lookup (`acknowledgement_for(role, kind)`), and the rationale for each are pinned by the reference implementation. Conforming implementations MUST emit byte-identical acknowledgement values; golden-fixture SHA3-256 body-hash tests covering all four role combinations catch any drift.

**Viewer display order.** The acknowledgement strings contain phrases such as "described above", which presume the description / scope rows render ahead of the acknowledgements. Viewers MUST render the `terms` array in CBOR order; reordering breaks the prose semantics.

**Counter-party contact.** When Party B's `contact` is a valid email address, the qub upload service auto-dispatches a review / co-sign invite email at stage time and binds the eventual co-sign to verification of that same address (§9.7). Pacts whose Party B contact is absent can still be co-signed, but only through an out-of-band channel — the service refuses co-sign requests that cannot produce a matching 15-minute email-verification marker.

### 6.2 Verdict Body (`content_type = 0x04`)

A verdict body is the canonical CBOR encoding of a `VerdictBody` value:

```text
VerdictBody {
    verdict_version: u8,                  // 0x01 for structured/v1
    outcome:         u8,                  // 1=Right · 2=Partial · 3=Wrong · 4=Unfalsifiable
    reflection:      Option<String>,      // ≤ 2,000 bytes NFC; "what changed, what did you learn"
    evidence_url:    Option<String>,      // ≤ 2,048 bytes; HTTPS only; absent key when omitted
}
```

Canonical CBOR key order:

```text
"outcome"          (8 encoded bytes)
"reflection"       (11 encoded bytes)  ← only if present
"evidence_url"     (13 encoded bytes)  ← only if present
"verdict_version"  (16 encoded bytes)
```

Total serialised verdict CBOR MUST NOT exceed **8 KB** (matches the registry row above).

**Outcome enum.** The wire byte is intent-neutral; the four buckets `Right` / `Partial` / `Wrong` / `Unfalsifiable` cover every verdict-bearing intent's outcome space. Per-intent labels ("Called it" / "Kept it" / "Shipped" / "Confirmed" for `Right`, etc.) are a viewer-side rendering concern resolved against the parent qub's intent — the wire stays language- and intent-neutral. Values outside `1..=4` MUST be rejected at decode.

**Parent linkage.** A verdict qub does NOT carry the parent reference in its body. The parent qub's Arweave transaction id is emitted as the `Parent-Tx-Id` storage tag at upload time (§7 storage-tag layer). This keeps the body a self-contained signed statement of self-assessment; the audit chain ("right about what?") is established via the Arweave-tag lookup.

**Evidence URL safety (normative).** When `evidence_url` is present, validators (compose-side, wire-side, Worker edge) MUST enforce:

1. **HTTPS only.** The string MUST start with the byte sequence `https://`. Any other scheme — `http`, `ftp`, `javascript`, `data`, `file`, etc. — is rejected.
1. **Length cap.** ≤ 2,048 bytes (browser URL practical limit).
1. **NFC + hostile-codepoint check.** Same rule as `title` and `reflection` — bidi-override / zero-width / tag-block / BOM / C0 / C1 codepoints are rejected. Definition matches the Rust `crate::handle::contains_hostile_text_codepoint` and the TS `workers/api/src/utils/unicode.ts::isHostileCodepoint` (keep in lockstep).
1. **No whitespace, no ASCII controls.** Whitespace / DEL / sub-`0x20` bytes anywhere in the URL are rejected — closes the `\n`/`\t` injection vector the bidi rule doesn't cover.
1. **Non-empty host segment.** Everything between `https://` and the first `/`, `?`, or `#` MUST be non-empty.

**No server-side fetching.** The Worker MUST NOT proxy, fetch, or preview the URL. The protocol stores a string; rendering happens viewer-side with `rel="nofollow noopener noreferrer" target="_blank"` and a visible host displayed alongside the link text.

**Reflection.** Optional creator-written reflection text ("what changed, what did you learn"). Same NFC + hostile-codepoint validation as `title`. Empty / whitespace-only input collapses to absent at construction time.

**Schema version.** v1 supports `verdict_version = 0x01` only. Future schema revisions bump this byte and land alongside a new protocol version per §12.

______________________________________________________________________

## 7. Seal Protocol

The complete seal sequence. Each step is normative.

```text
 1. User composes plaintext and metadata in ComposeQub.
 2. Validate:
    a. body is non-empty.
    b. body size ≤ max for content_type and user tier (see §6).
    c. unlock_at is in the future.
    d. unlock_at ≤ created_at + 10 years.
    e. content_type is a known, supported value.
    f. visibility is 0x00 (private) or 0x01 (public).
 3. Compute body_hash = SHA3-256(body).
 4. Set created_at = current Unix seconds UTC.
 5. Select drand chain. Load chain_genesis_time and chain_period_seconds, and
    compute drand_round = floor((unlock_at - chain_genesis_time) / chain_period_seconds) + 1
    (§4.3). (Computed here, before qub_id, because drand_round is bound into the
    qub_id preimage—§4.1.)
 6. Compute qub_id (see §4.1), folding in drand_round from step 5.
 7. Construct QubEnvelope with all fields.
 8. Serialise QubEnvelope using canonical CBOR → bytes B.
    Assert: serialised output matches canonical profile (§3).
 9. Compute C = tlock_encrypt(B, drand_round, drand_chain_public_key).
10. Construct SealedQub with tlock_ciphertext = C and matching qub_id, version,
    visibility, unlock_at, drand_chain_id, and drand_round.
11. Serialise SealedQub using canonical CBOR → SealedQubCbor.
12. Select the delivery shape from visibility:
    a. Private (0x00): generate K = 32 random bytes and N = 12 random bytes
       using a CSPRNG. Compute W = wrap_sealed_qub(SealedQubCbor,
       qub_id=qub_id, key=K, nonce=N) per §13. Upload payload = W.
    b. Public (0x01): upload payload = bare SealedQubCbor; do not generate K.
13. Display seal-time disclosure. User confirms.
14. Validate upload eligibility via the qub upload service (bot-detection, entitlement, rate limits).
15. Submit the selected upload payload to the qub upload service. For a private
    browser seal, the service is byte-blind to the inner SealedQubCbor and never
    receives K. The Builder `/api/v1/seal` route is an explicit exception: it
    receives plaintext and caller-supplied K in memory, then persists neither.
16. Receive arweave_tx_id from the service. For private delivery, construct
    `<origin>/c/<arweave_tx_id>#<base64url(K)>` (or the equivalent short-code
    path). For public delivery, omit the fragment. Browsers do not transmit URL
    fragments to servers, so K from the browser-seal path is not observed by
    qub.social or any storage gateway.
```

**Storage tag layer (out-of-band).** The qub upload service attaches a deliberately small set of storage transaction tags alongside the selected upload payload. `Content-Type=application/octet-stream` is normatively required. The reference service additionally attaches three optional tags when the creator chooses to surface them: `Intent` (allowlist-validated compose intent—`announcement`, `thesis`, `prediction`, `letter`, `secret`, `commitment`, `proof`, or system-emitted `verdict`), `Author` (creator's §9.3 pubkey fingerprint as 64-char lowercase hex), and `Parent-Tx-Id` (parent qub's storage transaction id for reply chains, 43-char base64url).

The `Author` tag is **opt-in per qub**: the reference creator app attaches it only when the user explicitly enables public attribution at seal time. When the toggle is off — the default — no `Author` tag is written and the qub is unattributed on the chain: nothing in permanent storage links the upload to a creator's handle, email, or other qubs. When the toggle is on, the `Author` fingerprint resolves to the creator's chosen `@handle` via the §9.5 attestation chain. Reply-chain relationships and `Intent` are non-identifying. For private delivery, the outer wrapper (§13) encrypts the recognisable inner `SealedQub` artifact so harvesting stored wrappers and obtaining public drand signatures is still insufficient to recover the body without K; storage tags remain deliberately public metadata.

The reference service intentionally does NOT attach `App-Name`, `App-Version`, or `Type` tags: any such single-value filter would return the entire qub corpus to a GraphQL query, which is inconsistent with the wrapper's body-only confidentiality scope.

A conforming verifier MUST NOT depend on any storage tag for §11 third-party verification; the body hash / qub_id / signature commit only to the inner CBOR, never to the tag set.

______________________________________________________________________

## 8. Unlock Protocol

The complete unlock sequence. Each step is normative.

```text
 1. Viewer opens delivery URL. Extract arweave_tx_id from the path and retain
    the optional URL fragment. Do not assume a missing fragment is an error:
    public/bare delivery intentionally has no K.
 2. Check denylist. If tx_id is denylisted → display block message. Stop.
 3. Fetch the stored bytes (with multi-gateway fallback).
 3a. Resolve the delivery shape structurally:
    a. If the bytes parse as OuterWrapper, require a well-formed 32-byte K in
       the URL fragment, require wrapper version 0x01, and unwrap per §13.
       Any missing/malformed K or AEAD failure is a terminal error.
    b. Otherwise require the bytes to parse as bare SealedQubCbor; no K is
       required. If neither shape parses, report an integrity error.
 4. Parse SealedQubCbor → SealedQub.
 5. Validate: SealedQub.version is known (0x01), visibility is known, and the
    delivery shape matches it (wrapped = 0x00 private; bare = 0x01 public).
    Reject any mismatch or unknown value.
 6. If current time < SealedQub.unlock_at → display countdown. Poll or wait.
 6a. Round-binding check. Recompute expected_round from
    SealedQub.unlock_at per §4.3. Reject unless SealedQub.drand_round ==
    expected_round OR SealedQub.drand_round == expected_round - 1 (the
    legacy pre-release mapping—see §4.3), AND the round baked into the tlock
    ciphertext stanza (read via the age/tlock header, no signature required)
    == SealedQub.drand_round exactly. The stanza round is the one that
    actually gates decryption; without this check a malicious creator could
    bind the ciphertext to an already-past round while displaying a future
    countdown, so anyone reading the stored bytes could decrypt before
    unlock_at. Implementations with no chain identity (test mocks) skip this
    check.
 7. Once current time ≥ SealedQub.unlock_at:
    a. Fetch drand round signature for SealedQub.drand_round from drand network.
    b. Compute B = tlock_decrypt(SealedQub.tlock_ciphertext, round_signature).
 8. Parse B → QubEnvelope.
 9. Validate QubEnvelope.version is known.
10. Verify: SHA3-256(QubEnvelope.body) == QubEnvelope.body_hash.
    Fail → integrity error.
11. Verify: QubEnvelope.qub_id == SealedQub.qub_id.
    Fail → integrity error.
12. Verify: QubEnvelope.unlock_at == SealedQub.unlock_at.
    Fail → integrity error.
12a. Verify: QubEnvelope.outcome_at == SealedQub.outcome_at (both absent, or
    both present and equal). Fail → integrity error.
12b. Content re-derivation. Recompute qub_id per §4.1 from the decrypted
    fields — (QubEnvelope.version, content_type, created_at, unlock_at,
    outcome_at, SealedQub.drand_round, QubEnvelope.body_hash,
    title_hash(SealedQub.title)) — and verify it equals SealedQub.qub_id.
    Fail → integrity error. The pairwise checks in steps 10-12a only prove
    the two layers agree with EACH OTHER; a forger who rewrites a bound
    field consistently on both surfaces (a pre-reveal title swap, or a
    post-round body swap with a recomputed body_hash re-encrypted to the
    same round under the same qub_id) passes them all. Only re-deriving
    the identity from content closes this.
13. Verify: QubEnvelope.content_type is known and renderable.
    Known values: 0x01 (text), 0x03 (pact), 0x04 (verdict).
    Unknown → display error.
14. If QubEnvelope.sig_alg != 0x00 → verify author signature (see §9.4).
15. If cosigner_pubkey or cosigner_signature present → verify cosigner (see §9.7).
16. Render content using the appropriate renderer (see §10 for text and §6 for pact/verdict).
17. Construct RevealedQub for display.
```

______________________________________________________________________

## 9. Authorship Signing

### 9.1 Rationale

Qubs are stored in permanent storage. Authorship signatures must remain unforgeable indefinitely, which is why v1.0 uses the post-quantum ML-DSA-65 scheme (FIPS 204) rather than a classical scheme whose security may degrade within the qub’s permanent lifetime.

### 9.2 Algorithm Registry

| `sig_alg` | Scheme | Key Size | Signature Size | Status |
| --------- | ----------------------- | ----------- | -------------- | ------ |
| `0x00` | No signature (unsigned) | — | — | Active |
| `0x01` | ML-DSA-65 (FIPS 204) | 1,952 bytes | 3,309 bytes | Active |
| `0x02` | Ed25519 | 32 bytes | 64 bytes | Reserved constant; unsupported in protocol v1 |

Protocol-v1 viewers MUST reject every value outside `{0x00, 0x01}`, including
the reserved `0x02` value. Reservation prevents accidental reuse; it is not
activation. Activating it requires the governed change described in §15.

### 9.3 Signed Preimage Construction

Two preimage versions have existed. **All signatures MUST use V2, and verifiers MUST accept V2 only.** The legacy V1 preimage (documented below for historical reference) was accepted as a verification-only fallback during the V2 migration; that fallback has been **retired** and a V1-only signature is now rejected.

**V2 (current — produced by all new author signing, and by both signatures of the pact staging / cosign flow):**

```text
sig_input = SHA3-256(
    "QUB_AUTHOR_SIG_V2"  ||    // domain separator (17 bytes)
    version              ||    // u8 (1 byte)
    qub_id               ||    // [u8; 32] (32 bytes)
    body_hash            ||    // [u8; 32] (32 bytes)
    unlock_at            ||    // i64 big-endian (8 bytes)
    0x00                 ||    // u8 (1 byte): MUST be 0x00 in v1.x
    sender_label_hash    ||    // [u8; 32]: SHA3-256(NFC(sender_label)),
                               //   or 32 zero bytes when absent
    reply_to_or_zero           // [u8; 32]: parent qub_id, or 32 zero
                               //   bytes when absent
)

// Total preimage: 155 bytes → 32-byte hash

signature = Sign(author_secret_key, sig_input)
```

`sender_label_hash` follows the same absent-sentinel convention as `title_hash` (§4.2.1): 32 zero bytes are not a valid SHA3-256 output, so "absent" can never collide with a present label. All fields are fixed-width, so the preimage is unambiguous without length prefixes.

**V1 (legacy — RETIRED; no longer produced and no longer accepted on verification):**

```text
sig_input = SHA3-256(
    "QUB_AUTHOR_SIG_V1"  ||    // domain separator (17 bytes)
    version              ||    // u8 (1 byte)
    qub_id               ||    // [u8; 32] (32 bytes)
    body_hash            ||    // [u8; 32] (32 bytes)
    unlock_at            ||    // i64 big-endian (8 bytes)
    0x00                       // u8 (1 byte): MUST be 0x00 in v1.0
)

// Total preimage: 91 bytes → 32-byte hash
```

The V1 preimage omitted `sender_label` and `reply_to`. It was accepted as a
verification-only fallback during the migration to V2; that fallback has since
been **retired** — verifiers MUST accept the V2 preimage only. The definition
is retained here for historical reference and to explain the domain separator
below. A signature that verifies only against V1 MUST be treated as a
verification failure.

**Domain separators:** `"QUB_AUTHOR_SIG_V1"` / `"QUB_AUTHOR_SIG_V2"` are 17 ASCII bytes each (`[0x51, 0x55, 0x42, 0x5F, 0x41, 0x55, 0x54, 0x48, 0x4F, 0x52, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x56, 0x31/0x32]`). No padding. The differing separator domain-separates the two constructions, so a signature over one preimage can never verify as the other.

**org_id_present byte:** the byte following `unlock_at` MUST be `0x00`. The reference implementation exposes this as the constant `ORG_ID_PRESENT_INDIVIDUAL = 0x00` in `crates/qub-core/src/signing.rs`; viewers reconstructing `sig_input` for verification MUST emit the same byte.

**Signature scope — what is and isn't covered.** The V2 `sig_input` commits directly to `version`, `qub_id`, `body_hash`, `unlock_at`, `sender_label`, and `reply_to` (plus the fixed domain separator and `org_id_present` byte). `qub_id` is itself derived from `version`, `content_type`, `created_at`, `unlock_at`, `outcome_at`, `drand_round`, and `body_hash` via the §4.1 preimage, so any change to those fields produces a different `qub_id` and invalidates the signature transitively. The authenticated surface is therefore:

| Field | Authenticated by signature | How |
| ------------------------- | :-: | --- |
| `version` | ✓ | Direct input to `sig_input` |
| `qub_id` | ✓ | Direct input |
| `body_hash` | ✓ | Direct input |
| `unlock_at` | ✓ | Direct input |
| `sender_label` | ✓ | Direct input via `sender_label_hash` (V2 preimage — the only accepted form) |
| `reply_to` | ✓ | Direct input via `reply_to_or_zero` (V2 preimage — the only accepted form) |
| `content_type` | ✓ | Transitively, via `qub_id` preimage |
| `created_at` | ✓ | Transitively, via `qub_id` preimage |
| `outcome_at` | ✓ | Transitively, via `qub_id` preimage |
| `drand_round` | ✓ | Transitively, via `qub_id` preimage |
| `body` | ✓ | Transitively, via `body_hash = SHA3-256(body)` |
| `author_pubkey` | — (implicit) | Key that verified the signature is the author, by definition |
| `cosigner_pubkey` / `cosigner_signature` | — | Independently signed over the same `sig_input` (see §9.7) |
| `drand_chain_id`, `tlock_ciphertext`, `visibility` | — | Outer `SealedQub` fields, not inside the envelope — covered by their own structural invariants (round / chain consistency) but not by the author signature. (`drand_round` is now bound transitively via the `qub_id` preimage — see above.) |

**Why V2 is the only accepted preimage.**

- Under the retired V1 preimage, a party with write access to the stored bytes could swap `sender_label` ("Alice" → "Mallory") or re-parent `reply_to` — and re-encrypt post-round — without invalidating the author signature, because neither field was in the signed preimage. V2 covers both, so any change to either field flips verification to "failed". Because verifiers now accept V2 only, this swap is closed for every signature: a signature that binds neither field (i.e. only verifies against V1) is rejected outright rather than downgraded to.
- The `author_pubkey` inside the envelope remains the true identity anchor — viewers MUST derive the display identity from `author_pubkey` (via the §9.5 attestation layer) rather than trusting `sender_label`.

Implementations that display `sender_label` or `reply_to` to end users MUST surface the authenticated identity (pubkey fingerprint, attestation) as the primary identity signal, not the label.

### 9.4 Verification Procedure

```text
1. Read sig_alg from QubEnvelope.
2. If sig_alg == 0x00 → unsigned. No verification. Display "unsigned qub."
3. If sig_alg is unknown → reject. Display "unrecognised signature scheme."
4. Extract author_signature and author_pubkey. If either is absent → integrity error.
5. Reconstruct sig_input using fields from QubEnvelope (V2 formula, §9.3).
6. Verify(author_pubkey, sig_input, author_signature). The V2 preimage is the
   only accepted form — the legacy V1 fallback is retired (§9.3), so a
   signature that does not verify against V2 fails, full stop.
7. If verification succeeds → display "signed by [key fingerprint]."
8. If verification fails → display "signature verification failed."
```

Signature verification is the most expensive operation (especially ML-DSA-65). It SHOULD be performed after all cheaper checks (hash, qub_id, unlock_at) have passed.

### 9.5 Identity Attestations

Identity attestations — the mapping of `author_pubkey` to human-recognisable identity claims such as a qub handle, email address, social handle, or passkey credential — are a **viewer-side progressive enhancement** and are **not required** for signature verification. Viewers that resolve attestations to a display identity MUST apply the precedence:

```text
handle > email > social > fingerprint
```

The fingerprint fallback is the lowercase hex of `SHA3-256(author_pubkey)`; it is always available for any signed qub. Viewers MAY abbreviate it for display — the reference viewer renders `qub:` followed by the first and last four bytes (`qub:<8 hex>…<8 hex>`).

A conforming verifier can complete every check in §9.4 without contacting the qub API, without any network beyond permanent storage and drand, and without any server-side lookup. Attestation resolution is a separate best-effort step performed only after signature verification has succeeded.

### 9.6 Size Impact

| | Ed25519 | ML-DSA-65 |
| ------------------------------ | -------- | ----------- |
| Signature | 64 bytes | 3,309 bytes |
| Public key | 32 bytes | 1,952 bytes |
| Total per qub | 96 bytes | 5,261 bytes |
| Storage cost delta (at ~$5/MB) | ~$0.0005 | ~$0.026 |

For a text qub of 500–2,000 bytes, ML-DSA-65 roughly triples the stored size. The absolute cost is negligible.

### 9.7 Cosigner Verification (Pact Bilateral Agreements)

For bilateral agreements (`content_type` = `0x03`), a second signature layer proves both parties consented to the same terms.

**Envelope fields:**

- `cosigner_pubkey`: ML-DSA-65 public key of the counter-signer (Party B).
- `cosigner_signature`: Signature over the same `sig_input` as the author (§9.3).

Both fields MUST be present together or both absent. If exactly one is present, viewers MUST report an integrity error.

**Verification procedure:**

```text
1. If cosigner_pubkey absent and cosigner_signature absent → no cosigner. Done.
2. If exactly one is present → integrity error.
3. Verify cosigner_pubkey != author_pubkey (prevent self-cosigning).
   Fail → display "cosigner pubkey must differ from author."
4. Reconstruct sig_input using the same formula as §9.3 (V2 only — the
   legacy V1 fallback is retired; all pact clients produce V2 signatures).
5. Verify(cosigner_pubkey, sig_input, cosigner_signature).
6. Success → display "co-signed by [cosigner fingerprint]."
7. Failure → display "co-signature verification failed."
```

**Properties:**

- The cosigner signs the identical `sig_input` as the author — both parties commit to the same `qub_id`, `body_hash`, and `unlock_at` (and, under V2, the same `sender_label_hash` and `reply_to_or_zero`).
- To let the counter-signer reconstruct the V2 preimage without access to the raw envelope bytes, the staging service enforces at stage time that a pact envelope's `sender_label` equals `pact_terms.party_a.label` and that `reply_to` is absent. Both hold for every reference-client pact; violating envelopes are rejected at staging.
- `qub_id` derivation (§4.1) does NOT include cosigner fields. Adding a cosigner to an existing envelope does not change the `qub_id`.
- A pact can be author-signed only (one-sided commitment), cosigner-only (unusual), or both (full bilateral proof).

**Email-binding gate (operational).** When a staged pact carries a Party B email contact (§6.1), the qub upload service MUST refuse the co-sign request unless a short-lived email-verification marker exists matching both the staging id and the normalised-email hash of that contact. The marker is written by `/api/v1/auth/verify` when the magic-link token carries a `staging_id` and the verified address matches `SHA-256(normalise_email(party_b.contact))` — where `normalise_email(addr)` preserves the local-part case and lowercases only the domain part (per RFC 5321 §2.3.11), and `SHA-256` here is the NIST FIPS 180-4 hash (distinct from the SHA3-256 used in §4 derivations) — and expires 900 seconds (15 minutes) after issue. This is an operational anti-impersonation gate, NOT part of the on-chain qub proof — a third-party verifier replaying §11 needs only permanent storage and drand, without any server-side lookup. The marker exists server-side only and is never part of the signed body.

**Size impact (ML-DSA-65 author + cosigner):**

| Component | Size |
| ------------------------- | ---------------- |
| Author signature | 3,309 bytes |
| Author public key | 1,952 bytes |
| Cosigner signature | 3,309 bytes |
| Cosigner public key | 1,952 bytes |
| **Total crypto overhead** | **10,522 bytes** |
| Storage cost delta | ~$0.05 |

______________________________________________________________________

## 10. Markdown Rendering and Sanitisation

This section is security-critical. The viewer renders text qubs (`content_type` = `0x01`) using a restricted Markdown subset.

### 10.1 Allowed Elements

- Headings: `#` through `####` (no `#####` or `######`)
- Emphasis: bold (`**`), italic (`*`), strikethrough (`~~`)
- Lists: ordered (`1.`) and unordered (`-`, `*`)
- Blockquotes (`>`)
- Code: inline spans (\`\`\`) and fenced blocks (\`\`\`\`\`)
- Horizontal rules (`---`)
- Line breaks (two trailing spaces or blank line)
- Paragraphs

### 10.2 Forbidden Elements

| Element | Handling |
| ------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Raw HTML (`<div>`, `<script>`, etc.) | Stripped entirely. No HTML passes through. |
| Images (`![alt](url)`) | Stripped. Image syntax is removed from output. |
| Links (`[text](url)`) | URL rendered as visible plain text. Not auto-linked. Not clickable without explicit user action. |
| Dangerous URL schemes | `javascript:`, `data:`, `vbscript:`, `file:` — stripped. |
| Iframes, embeds, objects | Stripped. |
| HTML entities | Decoded to display characters only if safe. |

### 10.3 Implementation

Implementations MUST use a **strict allowlist parser**, not a blocklist. The recommended approach:

1. Parse Markdown using `pulldown-cmark` (or equivalent).
1. Walk the AST and drop any node not in the allowlist (§10.1).
1. For link nodes: emit the URL as visible text, not as a clickable `<a>` element.
1. Convert the filtered AST into a **typed intermediate representation** (e.g., a `MarkdownNode` enum with only safe variants). Raw HTML is structurally unrepresentable in this IR.
1. Render from the typed IR to the target view layer (e.g., reactive view components, DOM nodes). No HTML string concatenation or `innerHTML` at any point.

Blocklist approaches are fragile because new Markdown extensions or parser quirks can introduce unfiltered elements. The typed-AST approach makes XSS structurally impossible — there is no variant that can carry arbitrary HTML.

### 10.4 Size and Structure Limits

- Maximum rendered heading depth: `####` (H4). `#####` and deeper are rendered as bold text.
- No limit on paragraph count (body size limits in §6 are the constraint).
- Fenced code blocks: no syntax highlighting in MVP. Rendered as monospace preformatted text.

______________________________________________________________________

## 11. Third-Party Verification

Any third party holding the stored bytes (and K for a private/wrapped qub) can
verify the cryptographic artifact without qub cooperation. An independently
timestamped **existence** claim additionally requires either verified
per-qub permanent-storage inclusion or a verified §16 transparency-log proof.

```text
1. Obtain the stored bytes. For a private delivery, also obtain K from the
   delivery-link fragment.
2. Resolve the delivery shape (§8 step 3a): unwrap OuterWrapper with K, or
   accept bare SealedQubCbor. Require shape/visibility agreement.
3. Parse SealedQubCbor → SealedQub; validate protocol version, visibility,
   content type, chain identity, and structural bounds.
4. Recompute expected_round from unlock_at (§4.3); require the stored round
   (allowing the documented legacy minus-one case) and ciphertext-stanza round
   to agree exactly as §8 step 6a specifies.
5. Obtain the drand signature for SealedQub.drand_round and verify its BLS
   signature against the pinned chain public key.
6. tlock_decrypt(tlock_ciphertext, round_signature) → QubEnvelope CBOR bytes.
7. Parse → QubEnvelope.
8. Verify SHA3-256(body) == body_hash.
9. Verify envelope/sealed equality for qub_id, unlock_at, and outcome_at.
10. Recompute qub_id from the decrypted fields, sealed drand_round, and title;
    require it to equal the carried qub_id (§4.1).
11. If sig_alg != 0x00, verify the V2 author signature (§9.4). If cosigner
    fields are present, verify their pairing, key separation, and signature
    (§9.7).
12. For an existence-time claim, independently verify either:
    a. the permanent-storage transaction's data-to-id binding, owner, block
       inclusion, and block timestamp; or
    b. a §16 inclusion proof through its pinned anchor and anchor block time.
13. Report each verified claim separately; do not collapse an absent storage
    or anchor proof into a successful timing verdict.
```

**What verification proves:**

| Proof input | What it establishes |
| ----------- | ------------------- |
| Valid bundle / sealed artifact + drand signature | The recovered body matches `body_hash`; the metadata bound into `qub_id` is intact; the ciphertext is bound to the declared drand round; and that round has elapsed. This does **not** establish when the ciphertext was created. |
| Valid V2 author/cosigner signature | The holder(s) of the corresponding secret key(s) authenticated the signed surface in §9.3. |
| Independently verified per-qub storage transaction | The exact stored ciphertext existed no later than its block timestamp. |
| Valid anchored transparency-log proof | The leaf-kind-specific claim in §16.11, including an upper-bound commitment time from the anchor block. |

**What verification does NOT prove:**

| Non-proof | Why |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Authorship | The `sender_label` is decorative. Without `sig_alg` ≥ `0x01`, anyone could have sealed this content. |
| Intent | The artifact proves bytes and cryptographic relationships, not what the creator subjectively meant. |
| Pre-existing commitment from `.qub` alone | A creator can assemble a valid bundle after the bound round has elapsed. The embedded drand signature proves that the round elapsed, not that the ciphertext existed before it. |
| Exact seal-button time | A storage or anchor block timestamp is an independently verifiable upper bound, and may lag the user's local action. `sealed_at` / `received_at` assertions are non-evidentiary. |

The implemented transparency log (§16) extends verification across qubs with
tamper-evident **ordering** and a trustless **upper-bound commitment time** (the
anchor block time), scoped by leaf kind (§16.11). It does not add authorship or
intent; for the default byte-blind upload path it does not itself prove
`body_hash` or `drand_round`, which continue to come from the artifact checks.

______________________________________________________________________

## 12. Versioning and Release Control

Document releases, the inner wire protocol, and the outer wrapper are separate
version spaces. A document-only clarification therefore does not silently
change bytes, and a future wire migration cannot masquerade as an editorial
revision.

### 12.1 Document Release Version

This specification uses semantic document releases (`MAJOR.MINOR.PATCH`) and
an immutable Git tag named `protocol-v<release>`.

- **PATCH**: accuracy or editorial correction that does not change conforming bytes or required behaviour.
- **MINOR**: backward-compatible normative addition, new registry entry, or new independently versioned sidecar format.
- **MAJOR**: incompatible normative change, including a new required wire interpretation.

Release status is one of **Draft** (not yet normative), **Current** (the sole
recommended implementation target), or **Superseded** (retained for historical
verification). The unversioned `/protocol` route displays the Current release;
the release tag preserves its exact source and every locale published with it.
Changing status or release number requires updating this table and the release
history in the same reviewed change.

| Document release | Effective date | Status | Wire protocol | Wrapper | Source |
| ---------------- | -------------- | ------ | ------------- | ------- | ------ |
| 1.0.0 | 2026-09-23 | **Current** | `0x01` | `0x01` | `protocol-v1.0.0` |

### 12.2 Protocol Version

The `version` field (u8) in both `SealedQub` and `QubEnvelope` identifies the major protocol version.

- Viewers MUST reject unknown major versions with a clear error.
- Within a known major version, decoders MUST reject unknown map keys (§3.1) — schema evolution happens by introducing a new `version`, not by adding keys existing decoders would skip. (Earlier revisions of this spec allowed tolerating unknown optional fields; that clause is withdrawn — it made `encode(decode(x))` non-injective and opened a hidden-signed-content vector on pact payloads.)
- Content types (`content_type`) and signature schemes (`sig_alg`) are version-gated: new values may only be introduced alongside a new protocol version or explicit registry update.

### 12.3 Protocol Version History

| Version | Value | Description |
| ------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| v1 | `0x01` | Private/wrapped and public/bare delivery; text (`0x01`), pact (`0x03`), and verdict (`0x04`) bodies; ML-DSA-65 V2 author/cosigner signing; drand quicknet tlock; SHA3-256. |

### 12.4 Forward Compatibility

A v1 viewer encountering a QubEnvelope with unknown CBOR map keys (keys not in the §3.2 canonical order) MUST reject it with a decode error (§3.1). Forward compatibility rides on the `version` field, not on key tolerance: future additions — even minor metadata — ship under a new `version` value, which a v1 viewer rejects with a clear "newer protocol" error rather than silently dropping content the signatures commit to.

A v1 viewer encountering `sig_alg` = `0x01` (ML-DSA-65) but lacking ML-DSA-65 verification support SHOULD display the qub content with a “signature present but not verifiable” notice, not reject the qub entirely. The reference implementation today rejects every `sig_alg` value other than `0x00` and `0x01` because the v1 registry contains no other valid algorithm — strict rejection and soft-fail are observationally identical until a third algorithm is registered. The soft-fail behaviour above becomes load-bearing once §9.2 admits a new entry, and the reference viewer will be updated to soft-fail at that point.

### 12.5 Outer Wrapper Version

The OuterWrapper described in §13 carries its own `version` byte, **independent** of `SealedQub.version` and `QubEnvelope.version`. The two version spaces evolve separately: a future post-quantum-safe symmetric replacement bumps the wrapper byte without touching the inner protocol version, and a future protocol-layer addition (e.g., a new envelope field) bumps the inner version without touching the wrapper byte.

| `OUTER_WRAPPER_VERSION_*` | Value | Algorithm | Status |
| ------------- | ------ | --------- | ------ |
| `OUTER_WRAPPER_VERSION_1` | `0x01` | AES-256-GCM with 12-byte nonce, 16-byte authentication tag, AAD bound to `qub_id` | Active for private delivery |
| — | `0x02`–`0xFF` | Reserved | Future |

Viewers MUST reject unknown wrapper versions with a clear error. The protocol intentionally keeps the wrapper version space narrow until a concrete migration driver appears (e.g., NIST guidance favouring a different AEAD); a `0x02` slot will be allocated in the same revision that introduces the algorithm.

______________________________________________________________________

## 13. Outer Encryption Wrapper

### 13.1 Rationale

The protocol layers (`QubEnvelope` → tlock → `SealedQub`) make a sealed qub **time-locked**: the body is unreadable until `unlock_at` and the drand round signature has been published. After unlock, however, the round signature is public and the canonical CBOR shape of `SealedQub` is recognisable, so a harvester who indexed permanent-storage transactions could bulk-decrypt the entire qub corpus.

For private delivery, the outer encryption wrapper closes that channel by interposing an additional symmetric AEAD layer between the canonical `SealedQubCbor` and the stored bytes. In the browser-seal path, the 256-bit key `K` lives **only** in the URL fragment of the delivery URL and on user devices; browsers do not transmit URL fragments to servers, so qub.social, every storage gateway, and every CDN in front of either is observationally blind to `K`. A private qub's stored representation is therefore opaque ciphertext whose plaintext is irrecoverable without the URL the creator chose to share. Public delivery deliberately omits this layer (§13.8).

Net effect:

- **Enumeration resistance for private delivery.** `OuterWrapper` remains recognisable structured CBOR—it is not literally indistinguishable from random bytes—but its ciphertext field hides the recognisable inner `SealedQub` shape. The documented harvester strategy of "GraphQL-query for bare qub-shaped uploads, bulk-decrypt with public drand signatures" does not terminate with plaintext without K.
- **Crypto-shredding privacy posture for the default private browser flow.** qub.social cannot decrypt those stored artifacts from its default server-side data. Explicit recovery, public delivery, and trusted server-side sealing have different disclosed trust boundaries.
- **Two-tier confidentiality ladder.** Default = link-controlled access (this section). Recipient-encrypted private qubs (a reserved Phase-2 feature, not yet specified) layer on top as the second tier.

### 13.2 Layering

```text
plaintext body                       ← QubEnvelope.body (§2.2)
  ↓ canonical CBOR (§3)
envelope CBOR
  ↓ tlock encrypt to drand round (§7 step 10)
tlock_ciphertext (inside SealedQub) (§2.3)
  ↓ canonical CBOR (§3)
SealedQubCbor bytes                  ← inner wire artifact
  ├─ public (visibility=0x01) ───────────────▶ stored directly (§13.8)
  └─ private (visibility=0x00)
       ↓ AES-256-GCM(K, nonce, AAD=qub_id) (§7 step 12, this section)
     OuterWrapper CBOR bytes         ← stored private payload
```

Seal and unlock at the protocol layer (§7, §8) are unchanged below the wrapper boundary; the wrapper attaches at the call site of `seal()` and detaches at the call site of `unlock()`.

### 13.3 OuterWrapper Data Structure

```rust
struct OuterWrapper {
    version:    u8,           // 0x01, see §12.5
    qub_id:     [u8; 32],     // copied from inner SealedQub; AEAD AAD
    nonce:      [u8; 12],     // 96-bit AEAD nonce
    ciphertext: Vec<u8>,      // AES-256-GCM(K, nonce, SealedQubCbor, AAD=qub_id) || 16-byte tag
}
```

**Field invariants.**

- `version` MUST equal `0x01` for v1.0 wrapper bytes.
- `qub_id` MUST equal the `qub_id` field of the SealedQub recovered after unwrapping. Both reference `wrap_sealed_qub` and `unwrap_sealed_qub` parse the inner CBOR and enforce this equality directly; the AAD binding separately makes post-wrap tampering with the outer `qub_id` fail authentication.
- `nonce` MUST be 96 bits (12 bytes), generated fresh by a CSPRNG for every wrap operation. Reusing a nonce under the same key permits AEAD nonce-reuse attacks that recover the plaintext; producers MUST treat (`key`, `nonce`) pairs as one-shot.
- `ciphertext` is the AES-256-GCM output: ciphertext bytes concatenated with the 16-byte authentication tag. `ciphertext.len() == SealedQubCbor.len() + 16` exactly.

**CBOR encoding.** Canonical CBOR per §3, with the same key-ordering rule (sorted by encoded byte length ascending, then lexicographically). The four keys are:

| Key | Encoded bytes | Order |
| --- | ------------: | ----: |
| `nonce` | 6 | 1 |
| `qub_id` | 7 | 2 |
| `version` | 8 | 3 |
| `ciphertext` | 11 | 4 |

The first byte of the OuterWrapper CBOR is therefore the definite-length map header for a 4-entry map (`0xA4`).

### 13.4 AAD Binding to `qub_id`

The wrapper binds `qub_id` as AEAD additional authenticated data. This is the load-bearing structural defence against three classes of attack:

| Attack | Defence |
| ------ | ------- |
| Move ciphertext under a different `qub_id` field in the wrapper | AAD mismatch → AEAD authentication fails |
| Mix the URL fragment of qub A with the stored bytes of qub B | Wrong key (and independently bound AAD) → AEAD authentication fails |
| Tamper with the `qub_id` field of the wrapper after upload | AAD mismatch → AEAD authentication fails |

Carrying `qub_id` in the wrapper plaintext does not weaken enumeration immunity meaningfully — `qub_id` is itself a SHA3-256 hash of the §4.1 preimage with no recoverable preimage from the digest, and an enumerator who already harvested the wrapper bytes learns nothing from the visible `qub_id` that they could not infer from the existence of the upload itself.

### 13.5 Wrap and Unwrap Algorithms

```text
wrap_sealed_qub(SealedQubCbor S, qub_id Q, key K, nonce N):
    require K.len() == 32 and N.len() == 12 and Q.len() == 32
    I := canonical_cbor_decode(S) as SealedQub
    require I.qub_id == Q               // reject mismatched caller AAD
    C := AES_256_GCM_encrypt(key=K, nonce=N, msg=S, aad=Q)
    // C includes the 16-byte authentication tag at the end
    return canonical_cbor_encode(OuterWrapper{
        version:    0x01,
        qub_id:     Q,
        nonce:      N,
        ciphertext: C,
    })

unwrap_sealed_qub(OuterWrapper bytes W, key K):
    require K.len() == 32
    O := canonical_cbor_decode(W) as OuterWrapper
    require O.version == 0x01           // §12.5
    P := AES_256_GCM_decrypt(
            key=K, nonce=O.nonce, ciphertext=O.ciphertext, aad=O.qub_id
         )
    // any AEAD failure → DECRYPT_FAILED, indistinguishable to caller
    S := canonical_cbor_decode(P) as SealedQub
    require S.qub_id == O.qub_id       // explicit inner/outer cross-check
    return P                            // P is the validated SealedQubCbor
```

**Failure-mode collapse.** Wrong `K`, wrong nonce, AAD mismatch, and tampered ciphertext all produce the same `DECRYPT_FAILED` error. This is a deliberate AEAD property: distinguishing the failure mode would create a side channel a remote attacker could probe by sending malformed wrappers and timing the response. Reference implementations MUST collapse all AEAD failures to a single error shape.

### 13.6 Key Material and Distribution

The wrapping key `K` is a 256-bit uniform random value generated per-qub by a CSPRNG. The reference implementations source it from:

- WASM creator: `getrandom` (WebCrypto under the `wasm_js` backend).
- Server-side seal API caller: its local CSPRNG; the caller supplies and retains
  `K` as `wrapper_key_b64url`. The Worker uses `K` in memory for the wrapper but
  MUST NOT persist it. This lets an idempotent retry recover a redacted response
  using the caller's retained capability instead of depending on a one-shot
  server-generated secret.

Distribution: `K` MUST be encoded as URL-safe base64 (RFC 4648 §5, no padding) and appended to the delivery URL as the fragment component:

```text
delivery_url = <origin>/c/<arweave_tx_id>#<base64url(K)>
```

The fragment is never transmitted to any server by a conforming browser. Recovery channels (server-side history index, opt-in email auto-send) that persist the full delivery URL — including the fragment — beyond the user's device are an explicit trade against the default crypto-shredding posture and MUST be gated on explicit user consent.

**Fragment loss.** If a user loses the URL fragment and has no recovery channel, the qub is unreadable. This is the load-bearing trade-off of the design and MUST be disclosed to the user at seal time. The MVP strengthens the seal-time disclosure with explicit "save this URL" copy and a verified-email recovery channel for users who opt in.

### 13.7 Out-of-Scope for this Section

- Authorship signing (§9) is unchanged: signatures are computed inside the inner `QubEnvelope` and are recovered after unwrap → tlock decrypt → CBOR parse.
- Recipient-public-key encryption (the reserved `recipient_pubkey` field) is a future feature distinct from today's private, link-capability-gated wrapper mode.
- The current server-side pact co-sign flow emits public/bare `SealedQubCbor` with visibility `0x01`; it cannot satisfy the browser-only K-secrecy model because final sealing occurs after server-mediated co-sign. A future private-pact producer may use the same wrapper, which is byte-blind to inner content type.

### 13.8 Public qubs (wrapper omission)

The outer wrapper is **optional at the delivery layer**. A creator may seal a qub as **public**, in which case the canonical `SealedQubCbor` enters the storage pipeline **directly**, with no `OuterWrapper` layer and no key `K`:

```text
SealedQubCbor bytes  ──(public)──▶  stored as-is
SealedQubCbor bytes  ──(private)─▶  AES-256-GCM(K, …) ▶ OuterWrapper ▶ stored
```

A public qub is **time-locked but not link-gated**: it stays unreadable until its drand round publishes (the tlock layer is unchanged), but after unlock anyone who has the storage transaction id can decrypt it — no URL fragment is required, because there is no `K`. This is the deliberate trade for surfaces the server must drive: reveal-notification emails, fragment-less oEmbed/auto-embed links, and richer post-reveal SEO all need a link that works without a secret the server never holds (§13.6). A private qub can still use the explicit `<qub-embed src="full_delivery_url">` form when the publisher supplies its complete fragment-bearing capability.

Consequences a producer MUST account for:

- **No enumeration immunity.** Public qubs forgo the §13.1 enumeration-immunity property by construction. The reference upload service stamps a `Visibility: public` permanent-storage tag on them (and only them) so they are intentionally discoverable; private qubs carry no such tag and keep their byte-indistinguishability.
- **Plaintext title exposed at seal time.** The §3.2 `title` field is plaintext inside `SealedQubCbor`. Under the wrapper it is hidden until a viewer supplies `K`; without the wrapper it is world-readable on permanent storage **from the moment of upload**, before unlock. Conforming creator apps MUST disclose this at seal time.
- **Detection is structural and cross-checked.** A conforming viewer/embed distinguishes the two stored shapes by parse: bytes that parse as `OuterWrapper` take the unwrap-with-`K` path; bytes that parse as a bare `SealedQubCbor` are accepted directly. The recovered inner value MUST agree (`0x00` for wrapped/private, `0x01` for bare/public). `qub_id` does not bind visibility, but the canonical `SealedQub` bytes do carry it, so the public and private inner encodings are not byte-identical.

Private (wrapped) remains the default; public is an explicit per-qub creator choice.

______________________________________________________________________

## 14. Test Vectors

### 14.1 qub_id Derivation

```text
Input:
  version      = 0x01
  content_type = 0x01
  created_at   = 1735689600 (2025-01-01 00:00:00 UTC)
  unlock_at    = 1736294400 (2025-01-08 00:00:00 UTC)
  outcome_at   = absent
  drand_round  = 4695446  (= floor((1736294400 - 1595431050) / 30) + 1, §4.3 mapping, drand mainnet params §14.2)
  body         = "Hello, future."  (UTF-8, 14 bytes)
  title        = absent

Intermediate:
  body_hash  = SHA3-256("Hello, future.")
             = 76ab8b3f843c6ed4f2d0fd75b9f457b4
               ad49dd4450f9c22723ae430e3af3211d
  title_hash = [0u8; 32]   (title absent — §4.2.1 sentinel)

Domain separator (10 bytes):
  [0x51, 0x55, 0x42, 0x5F, 0x49, 0x44, 0x5F, 0x56, 0x32, 0x00]

Preimage (108 bytes—current protocol v1):
  domain_separator    ||  // 10 bytes
  0x01                ||  // version
  0x01                ||  // content_type
  0x0000000067748580  ||  // created_at as i64 big-endian (1735689600)
  0x00000000677DC000  ||  // unlock_at as i64 big-endian (1736294400)
  0x0000000000000000  ||  // outcome_at_or_zero (outcome_at absent)
  0x000000000047A596  ||  // drand_round as u64 big-endian (4695446)
  body_hash           ||  // 32 bytes
  title_hash              // 32 bytes (all-zeros sentinel; title absent)

Expected output:
  qub_id = SHA3-256(preimage)
         = 4a84e3dfaec32954949c30073f8e6506
           fd3204c1bb97f9162b81c7587afe412e
```

Implementations MUST produce identical `body_hash` and `qub_id` values for this input. This test vector SHOULD be the first unit test written. The canonical values above were computed by the reference implementation and MUST match bit-for-bit. Historical pre-launch prototype layouts (no live qubs depended on the first two) used 92 bytes before `outcome_at` (`3d9fc2390eab043d38a1669ed3b71be76f9eefe872b9569ab1aaa027b88392b0`) and 100 bytes after adding `outcome_at_or_zero` (`b0d032898ad629795150fdcb3f84e518f59ed05b7a2a82bc24ebdb87f52144ed`). The current 108-byte layout then added `drand_round` and the `QUB_ID_V2` domain separator. An early 108-byte vector used the legacy `ceil` round mapping (`drand_round = 4695445`) and produced `3a9fcb31b750d985c262fada6d4f777fd6a28be831d941d85c131f5a4bbaf8a4`—still a valid `qub_id` for that round input, while the example above follows the §4.3 current-round mapping.

### 14.2 Unlock-Round Mapping

```text
Input:
  unlock_at           = 1735689600
  chain_genesis_time  = 1595431050
  chain_period_seconds = 30

Calculation:
  (1735689600 - 1595431050) / 30 = 4675285.0
  floor(4675285.0) + 1 = 4675286

drand_round = 4675286
```

Round 4675286 publishes at `1595431050 + (4675286 - 1) * 30 = 1735689600`—exactly at `unlock_at`, never before. (The legacy pre-release `ceil` mapping gave `4675285`, published at `1735689570`—30 seconds early; verifiers accept that legacy round per §4.3.)

### 14.3 Canonical CBOR Round-Trip

Implementations MUST verify that `serialize(parse(serialize(qub))) == serialize(qub)` for all valid inputs. This is a property test, not a single vector.

### 14.4 PactTerms CBOR (content_type 0x03)

```text
Input:
  pact_version = 1
  title        = "Scooter deposit"
  terms        = [
    { key: "Item",    value: "Honda Metropolitan scooter" },
    { key: "Price",   value: "$100" },
    { key: "Deposit", value: "$10" }
  ]
  party_a      = { label: "Alice" }
  party_b      = { label: "Bob", contact: "bob@example.com" }
  notes        = absent

Canonical CBOR key order (PactTerms):
  "notes"(6) < "terms"(6) < "title"(6) < "party_a"(8) < "party_b"(8) < "pact_version"(13)

Canonical CBOR key order (PactTerm):
  "key"(4) < "value"(6)

Canonical CBOR key order (PartyIdentifier):
  "label"(6) < "contact"(8)
```

The canonical CBOR bytes and SHA3-256 `body_hash` are computed by the reference implementation. Implementations MUST produce byte-identical CBOR for this input.

Implementations MUST also verify that `serialize(parse(serialize(pact))) == serialize(pact)` for all valid `PactTerms` inputs (property test).

### 14.5 Outer Wrapper Cross-Language Vectors

The outer wrapper (§13) has a separate canonical fixture at [`crates/qub-core/tests/vectors/wrapper_v1.json`](../../crates/qub-core/tests/vectors/wrapper_v1.json). Each case fixes a `(key, nonce, qub_id, sealed_cbor)` tuple as opaque hex inputs and asserts a specific `expected_wrapper_hex` output. Both reference implementations consume the same JSON file:

- Rust: `crates/qub-core/tests/wrapper_vectors.rs` (`cargo test -p qub-core --test wrapper_vectors`).
- TypeScript: `workers/api/src/crypto/__tests__/wrapper.test.ts` (`npm test`).

The fixture currently pins three low-level wrapper cases. They test deterministic `OuterWrapper` encoding and AEAD interoperability independently of the §13.8 delivery-shape invariant; in particular, the historical name `basic-text-public` and its inner `visibility = 0x01` do **not** make the resulting wrapped bytes a conforming public delivery. A producer MUST still store public inner bytes bare and wrap only private (`0x00`) inner bytes.

| Case | Coverage |
| ---- | -------- |
| `basic-text-public` | Historical low-level fixture name. Smallest realistic `SealedQub` shape, with no optional fields; tests wrapper bytes only and is not a conforming §13.8 stored delivery. |
| `with-recipient-pubkey` | `SealedQub` with `recipient_pubkey` set (reserved future path). Exercises a different inner CBOR key set; its distinct fixture content independently yields a different `qub_id` (`recipient_pubkey` itself is not in the §4.1 preimage). |
| `longer-body` | ~4 KiB body — exercises multi-byte CBOR length prefixes inside both the inner envelope and the outer ciphertext. |

Implementations MUST produce byte-identical `expected_wrapper_hex` for the recorded inputs. Regenerating the fixture requires `QUB_REGEN_VECTORS=1 cargo test -p qub-core --test wrapper_vectors` and is reserved for deliberate format changes.

______________________________________________________________________

## 15. Crypto Profile Governance (Future)

This section is informative for v1 and becomes normative the first time a second algorithm enters any of qub's cryptographic primitives.

### 15.1 Current Posture

Protocol v1 binds exactly one algorithm per primitive:

- **Signature**: ML-DSA-65 (`sig_alg = 0x01`; 1952-byte public key, 3309-byte signature) and unsigned (`sig_alg = 0x00`). The codebase reserves `0x02` for Ed25519, but protocol v1 does not activate it; a v1 verifier MUST reject every `sig_alg` outside `{0x00, 0x01}`.
- **Timelock**: drand quicknet only — the chain hash, public key, genesis time, and period are fixed network parameters carried by the reference `DrandTimelockProvider::quicknet()` (`crates/qub-core/src/tlock.rs`) and `config/drand-endpoints.json`.
- **Outer wrapper**: AES-256-GCM v1 only (§13).

Verifiers currently hardcode key and signature lengths per active primitive. The `sig_alg` and wrapper-version bytes are explicit selectors, but v1 performs no in-band negotiation and admits only the active values above.

### 15.2 Intended Shape

When a second algorithm enters the protocol, the verifier will be configured for a named `CryptoProfile` (e.g., `ExqubV1`) listing the exact set of permitted values per primitive — sig_algs, drand chains, wrapper versions, content types. The profile is fixed at verify time, never negotiated in-band. Any value outside the active profile is rejected.

This guarantees that adding ML-DSA-87 or activating Ed25519 cannot retroactively weaken existing verifier configurations: a v1 verifier remains a v1 verifier even after a v2 profile is published.

### 15.3 Trigger Conditions

Promote §15 to normative status when any of the following is proposed:

- A second `sig_alg` byte (Ed25519 activation, ML-DSA-87, or any new entry in the §9 registry).
- A second drand chain in production use.
- A second outer-wrapper version.
- A rotation of the transparency-log trust root — the `LogProfile.anchor_owner` address or the pinned receipt-key public key (§16.6). The `LogProfile` joins the §15.2 profile surface as a governed primitive: a rotation is a signed `LogProfile` bump shipped in a verifier update (planned rotations cross-sign outgoing → incoming; compromise-driven rotations cannot, and rely on this bump with the prev-anchor fork check bounding interim damage). The transparency-log version spaces (`LOG_VERSION`, `ANCHOR_FORMAT`) evolve as independent siblings, exactly as the §12.5 wrapper version is independent of the protocol version.

Until then §15 is a placeholder that fixes the migration shape so future PRs land against a known target rather than re-litigating the negotiation surface from scratch.

______________________________________________________________________

## 16. Transparency Log and Durability Tiers (Implemented — review complete)

> **Status.** This section is **implemented** (W5/UP-B1, Stages 1–8), with the producer and trust-root scope stated here. The wire formats, hashing, and verifier paths are live: the core Merkle + canonical-CBOR types (`qub-core`), the TypeScript mirror + ANS-104 bundler (`workers/api/src/crypto/`), the single-writer `LogDO` + coordinate-keyed R2 node store, the `/upload` log-append attempt, the daily anchor + bundler-drain crons, the `GET /api/v1/qub/:tx_id/proof` (inclusion) and `GET /api/v1/log/consistency` (RFC 9162) proof endpoints, the typed inclusion proof carried in the `.qub` bundle (§17.5), the native ANS-104 anchor verifier (`tools/qub-verify`), and the dual self-published-heads hook (§16.6). A successful `/upload` is always R2-durable but is log-covered only when `LOG_DO` is configured and the inline append succeeds; only then does its response carry `log_seq`, `receipt`, and `anchor_status`. If `RECEIPT_SK` is absent or invalid, that receipt's `sig_b64url` is empty and supplies no non-repudiation. The current `/seal` and pact publication paths schedule individual Arweave transactions but do not append a log leaf. No code currently performs the `/upload` comment's proposed later reconciliation after an append failure. The W5 external review is complete: §16.15 records design decisions and launch constraints, but those constraints do not expand the producer coverage just stated. **Three trust/deployment items remain gated**: (a) the dedicated anchor wallet (`ANCHOR_JWK`; `LogProfile.anchor_owner` is still the `[0xAB; 32]` placeholder); (b) the receipt signing key **and matching public-key pin** (`RECEIPT_SK` is optional and `LogProfile.receipt_pubkey` is currently empty); and (c) the self-published-heads GitHub repository + token (§16.6). Until the anchor/profile pins are provisioned, a standalone verifier reports proof status honestly rather than claiming a fully anchored, pinned verification. The design is strictly additive and there is **no change to the `SealedQub` / `QubEnvelope` wire format**.

### 16.1 Rationale and Durability Tiers

The current publication paths decouple acknowledgement from Arweave confirmation: they derive and sign an individual transaction, persist the artifact and exact submission state in R2, then post asynchronously. The transparency log adds an independently anchored ordering layer for the subset of general `/upload` requests whose `LogDO` append succeeds:

| Tier | Name | Guarantee | When |
| ---- | ---- | --------- | ---- |
| T1 | R2-first synchronous ack | Durability floor — sealed bytes and exact publication state are written to durable storage before success is returned. | Implemented across current publication paths. |
| T2 | Batched transparency-log inclusion | Append-only, tamper-evident commitment + total ordering once included and anchored. | Current producer: successful `LogDO` appends from `/upload`; response carries the receipt tuple. Not universal. |
| T3 | Per-qub Arweave permanence | An individual Arweave transaction for the qub. | Currently prepared for every accepted publication and posted asynchronously; the exact signed transaction remains in the drainable outbox until delivered. |

The tiers describe distinct evidence and durability properties, not the current commercial plan. The present code still schedules an individual Arweave transaction for every accepted publication; it does not expose T3 only as a paid upsell. API-key/account quota ceilings remain separate application controls.

**Durability honesty.** The T1 write is synchronous, so a successful response establishes application-level durability without waiting for an Arweave gateway. It does not itself establish an independent timestamp. A confirmed individual transaction supplies its block-time upper bound. For a response carrying the complete T2 receipt tuple, the next confirmed anchor can supply the log proof described below. If the tuple is absent, no surface may imply that this qub is already in the transparency log. Anchor and publication latency have no protocol-level numeric SLA.

### 16.2 LogLeaf Structure (two committed shapes)

A log entry is a `LogLeaf`, encoded as hand-written canonical CBOR under the §3.1 profile (definite-length, no tags, no floats, shortest-form integers, NFC text, optional fields omitted when absent, keys ordered by encoded-byte length ascending then bytewise). The §3.1 `parse → re-encode → compare` canonical guard is applied **on the encode path before hashing** (not only on decode), so two implementations cannot disagree on the leaf bytes through an integer-width or key-order difference. All integers are `u8` / `u64` / `i64`; all digests are 32-byte byte strings (`bstr[32]`). A stored Arweave transaction id is a raw 32-byte SHA-256 digest carried as `bstr[32]`, **never** a base64url text string (matches §3.3).

The leaf has **two shapes selected by a `kind` byte**, because the general upload path is byte-blind: `POST /api/v1/upload` deliberately treats both accepted payload shapes as opaque and receives `qub_id` and `unlock_at` only as *untrusted client assertions*. On the default private path, `body_hash`, `drand_round`, `created_at`, and `drand_chain_version` are additionally hidden inside the §13 outer wrapper, whose key the Worker never holds. The type system also defines an attested shape for a producer that derives `body_hash` / `drand_round` itself. The current `/seal` route has those values but does not call `LogDO`, so production currently emits only asserted (`0x02`) leaves from successful general-upload appends. The split keeps every committed value honest without pretending the attested producer is wired:

| Key | Enc. len | Type | Presence | Meaning |
| --- | -------- | ---- | -------- | ------- |
| `seq` | 4 | `u64` | required | Global 0-based leaf index; the position the inclusion proof commits to. |
| `kind` | 5 | `u8` | required | `0x01` attested-capable (defined, not currently emitted) or `0x02` asserted (client-seal / byte-blind upload). |
| `ref` | 4 | `bstr[32]` | required | Leaf reference id. Attested → raw `qub_id`. Asserted → the **blinded** id `SHA3-256(qub_id ‖ log_blind_secret)` (§16.2.1). |
| `chash` | 6 | `bstr[32]` | required | Content address `SHA3-256(stored_bytes)` — the one content tie the Worker can always honestly compute, on both paths. |
| `unlock_at` | 10 | `i64` | required | Copied (attested) or asserted (asserted); validated `> 0` before it enters the leaf. |
| `received_at` | 12 | `i64` | required | Worker wall-clock at R2-ack. **Non-evidentiary** (operator-asserted; §16.6). Present for self-description, never a proof. Validated `> 0`. |
| `body_hash` | 10 | `bstr[32]` | `kind=0x01` only | Omitted on `0x02` — the Worker lacks it under §13. |
| `drand_round` | 12 | `u64` | `kind=0x01` only | Omitted on `0x02`. |

A `kind=0x02` leaf deliberately commits neither `body_hash` nor `drand_round`: it attests *the commitment and ordering of an opaque ciphertext at content-address `chash`, claiming `qub_id` and `unlock_at`* — not its plaintext or round. The plaintext/round legs for an asserted qub come from the existing §11 `.qub`-bundle verification, not from the log (§16.11). `drand_chain_version` is not in the leaf (it is inside the wrapper on the default path); chain granularity lives on the anchor (§16.7). Encoder discipline: reject an all-zero `ref` or `chash`, and reject non-positive `unlock_at` / `received_at`, mirroring the `outcome_at > 0` sentinel guard in `cbor.rs`.

#### 16.2.1 Private-qub blinding

The log must not become the enumeration oracle that the §13 outer wrapper exists to prevent (§13.1). For a private (wrapped) qub the `asserted` leaf commits the **blinded** identifier `SHA3-256(qub_id ‖ log_blind_secret)`, where `log_blind_secret` is a server-held secret, and omits `body_hash`. A third party cannot tie such a leaf to a specific `qub_id`; the qub's holder, who has the delivery URL and therefore `qub_id`, can recompute the blind to confirm their own inclusion. A public qub (already enumerable, already carrying the `Visibility: public` Arweave tag per §13.8) commits the raw `qub_id`. This is the one place standalone verifiability deliberately yields to a load-bearing privacy invariant; the standalone tie for private qubs is `chash` (§16.9).

**`log_blind_secret` custody (resolved — §16.15 Q4).** The blind protects *leaf unlinkability*, not plaintext confidentiality (the §13 wrapper holds that independently). On a `log_blind_secret` compromise, for any `qub_id` the adversary already holds or can reconstruct (every qub whose bundle/URL it has, plus any low-entropy or public `qub_id`) it recomputes the leaf `ref` in **one hash** and links it — this is direct linkage of a known population, not a brute-force over an unknown space. Classify `log_blind_secret` as a correlation/Sybil-grade secret in the same custody tier as other server secrets, and rotate forward only (a rotation re-blinds future leaves; it cannot retroactively unlink already-anchored ones).

### 16.3 Leaf and Node Hashing

RFC 6962 §2.1 domain-separated hashing with SHA-256 replaced by SHA3-256:

```text
leaf_hash      = SHA3-256(0x00 || canonical_cbor(LogLeaf))
node_hash(l,r) = SHA3-256(0x01 || l || r)
empty tree     = SHA3-256("")          // defined but never anchored
```

Domain prefix bytes `0x02` (entry chain, §16.4) and `0x03` (STH hash, §16.6) are reserved and disjoint from these. They are single bytes and so cannot collide with the existing 10-byte ASCII domain separators (`QUB_ID_V2`, etc.). The tree is the RFC 6962 **left-full unbalanced** tree (each interior split at the largest power of two strictly less than the subtree leaf count), which lets inclusion and consistency proofs share one audit-path algorithm. The reference spec carries explicit left/right derivation pseudocode and pins a **non-power-of-two (5-leaf) test vector** so the right-edge promotion case — which a 4-leaf vector hides — is exercised.

### 16.4 Hash Chaining (internal)

The LogDO maintains an internal entry chain for crash-consistency only. It is **never published and never verifier-facing**:

```text
entry_chain[seq] = SHA3-256(0x02 || entry_chain[seq-1] || leaf_hash[seq])
entry_chain[-1]  = SHA3-256("QUB_TLOG_GENESIS_V1")
```

The published append-only authority is the **cumulative Merkle root + its anchor** (§16.5–16.6), never the raw order in which the operator happens to serve leaves: the chain recomputes for any order served, so only the anchored root pins canonical position.

### 16.5 Cumulative Merkle Tree and Batching

There is **one ever-growing RFC 6962 tree** over all leaves in `seq` order — not isolated per-batch trees. (A carry-leaf-chained per-batch construction was rejected: it is not a true prefix relation, so its "consistency proofs" are unsound.) The cumulative tree gives genuine RFC 9162 consistency proofs and lets a single recent anchor prove inclusion for any older qub.

The `LogDO` Durable Object is the **single writer** (`blockConcurrencyWhile`, mirroring `QuotaDO` / `EntitlementDO`) — appending to a shared log is read-modify-write on shared state and so MUST go through a DO, never KV. It caches the tree's right-edge frontier (`O(log n)` hashes) so closing a batch is `O(batch)`. A **batch** is the set of leaves anchored together; its implemented triggers are a `tree_size` advance of at least `LOG_BATCH_MAX_LEAVES` (default 4096), age reaching the anchor cadence, or an explicit administrative/cron force-close. `root_i` is the cumulative Merkle Tree Hash over leaves `0 .. tree_size_i`.

### 16.6 Signed Tree Head via Arweave Anchor

The Arweave anchor transaction **is** the Signed Tree Head and **replaces** an operator signature *for the tree head itself*: the daily anchor needs no qub key because the Arweave tx `owner` is the signature. The moat thesis holds — the immutable substrate, not a qub-held secret, is load-bearing for the anchored root.

The log design calls for one warm successful-append **receipt key** (§16.10), pinned in `LogProfile` and cross-signed by `anchor_owner`. The current implementation has not completed that trust-root provisioning: `RECEIPT_SK` is optional, an absent/invalid key yields `sig_b64url: ""`, and the compiled `LogProfile.receipt_pubkey` is empty. Such a receipt can describe the appended leaf but is **not** a non-repudiable signed receipt. The stronger design claim applies only after a verifier release pins the matching public key and the anchor owner cross-signs it. A publication response without the complete receipt tuple makes no log-acceptance claim; one with an empty signature makes an append-position claim but no signature-verification claim.

The `SignedTreeHead` is canonical CBOR (keys by encoded length): `size:u64`, `root:bstr[32]`, `batch:u64`, `prev:bstr[32]` (prior `sth_hash`; genesis = 32 zero bytes), `log_id:bstr[32]`, `first_seq:u64`, `anchored_at:i64`. Its hash is `sth_hash = SHA3-256(0x03 || canonical_cbor(SignedTreeHead))`.

**Pinned trust root.** `log_id = SHA3-256("QUB_TLOG_V1" || anchor_owner_address)`. A conforming verifier MUST require `anchor_tx.owner == LogProfile.anchor_owner`, where `anchor_owner` (and the receipt-key public key) is baked into `qub_core` as the `LogProfile` — alongside the quicknet constants already in `DrandTimelockProvider::quicknet()` — and distributed with the verifier binary. The verifier MUST also verify the Arweave tx **data → tx_id binding locally** rather than trusting a gateway `/raw/` response. This closes the rogue-wallet equivocation hole: "anchored on Arweave" is meaningless until the verifier pins *which* wallet.

**Rotation is a §15 governance *extension*, not a reuse (resolved — §16.15 Q3).** §15.2's profile surface currently enumerates only sig_algs / drand chains / wrapper versions / content types, and §15.3's triggers list none of these — `LogProfile` / `anchor_owner` is **not** yet in §15's surface. Rotation governance must therefore be *built*: §15.3 is extended (below) to add the `LogProfile` trigger, and a rotation is a signed `LogProfile` bump shipped in a verifier update. A **planned** rotation carries an outgoing → incoming cross-signature; a **compromise-driven** rotation cannot (the outgoing key is untrusted/unavailable precisely then) and falls back to the §15-governed bump, with the prev-anchor fork check (below) bounding damage in the interim.

**Equivocation window (first-class trust parameter).** A leaf is equivocation-resistant only once its covering anchor is Arweave-**confirmed**. The window is `received_at → anchor confirmation` (cadence + Arweave finality, with no protocol latency guarantee). Before trust-root provisioning, the current implementation supplies qub's operational integrity plus whatever unsigned append metadata is present; it does not supply the planned non-repudiation guarantee. Three accountability artifacts define the completed design (the witness model is §16.15 Q2's resolution):

1. **Seal receipt (provisioning-dependent)** — the SCT analogue returned when an upload's log append succeeds (§16.10). It becomes non-repudiable only when `sig_b64url` is non-empty **and** the matching public key/anchor-owner relationship is pinned in the verifier. The currently empty production profile pin cannot support that verdict. This control does not apply to an omitted receipt tuple or an unsigned receipt.
1. **Published monitor methodology + prev-chain walk** — the anchor `prev` chain is walked head→genesis; a fork (two anchors at one `size` with different `root`, or a broken `prev`) is publishable proof of misbehaviour. Equivocation detection is a stated operational commitment, not a silent assumption.
1. **Dual self-published heads** — each new head `{sth_hash, tree_size}` is posted to a dedicated qub-owned **public, append-only GitHub repository** (the load-bearing tamper-evident self-publication leg), with a social post as best-effort corroboration only. A failed posting MUST page (not fail silent). *Implemented (Stage 8) as the `publishHead` hook on the anchor cron (`workers/api/src/utils/heads-publish.ts`): a `PUT` to the contents API without a `sha` is append-only (a `422` means the head is already published, never an overwrite); opt-in / deploy-gated on `PUBLISH_HEAD_GITHUB_{TOKEN,OWNER,REPO}` and inert until the repository is provisioned. A hard GitHub failure pages via the `health_alert` channel and bumps a durable fail metric (`m:tlog_publish_head_fail`); the Arweave anchor itself never rolls back on a publish failure. "Not fail silent" is guaranteed by that durable metric — which ops MUST dashboard-alert on — even if the best-effort email page cannot be delivered. Two honest limitations follow from "anchor-on-advance" (the cron only publishes when the size advances): a transient GitHub failure leaves a **gap** in the published-heads sequence for that size — bounded, not silent (it pages), and because each head commits a superset tree, a §16.9 consistency proof bridges the gap; crucially, that consistency proof is computed from the **authoritative Arweave-anchored tree, not from the GitHub surface**, so a GitHub gap never weakens verifiability. A catch-up backfill that fills published-heads gaps is a deferred enhancement.*

**Honesty bound (binding constraint).** Because qub controls both planned posting surfaces, this is **self-published**, not independently witnessed. No product, marketing, or legal surface may claim the log is "independently witnessed". After the receipt/profile/head gates are provisioned, the permitted claim is that **equivocation is detectable and a successfully signed append leaves a non-repudiable receipt**. Before then, that claim is unavailable. A true independent third-party witness is deferred to a future §15 governance bump.

`received_at` is operator-asserted and **no claim may lean on it** — it is never surfaced as proof or as dispute corroboration on any product / legal / API / proof-rendering surface. The Arweave anchor block time `T` is the only trustless timestamp (an upper bound on "logged by"). Any monitor sanity check on `received_at` MUST compare against `T`, not against the operator-controlled `anchored_at` STH field; such a check is a guard against an honest operator's clock bug only, **not** an accountability control against a malicious operator (§16.15 Q5).

### 16.7 Anchor Transaction Format and Cadence

The `AnchorBundle` is the canonical-CBOR Arweave transaction body, written via the §16.8 bundler: `ver:u8`, `sth:bstr` (canonical `SignedTreeHead` bytes), `prev_anchor:bstr` (prior anchor tx id raw bytes; omitted at genesis), `chain_hash:tstr` (the drand chain in force — quicknet), and the **batch's leaf-CBOR stream in `seq` order** so the anchor is self-contained: a monitor re-derives `root` from the body with zero qub dependency. (If the leaf stream becomes large at high volume, a future revision may commit only a leaf range by reference; noted, not adopted in v1.)

Arweave tags are intentionally enumerable — the log is *meant* to be found, unlike private qubs: `App-Name: qub-tlog`, `Anchor-Format: 1`, `Log-Id: <hex>`, `Batch: <n>`, `Tree-Size: <n>`, `Root: <hex>`, `Prev-Anchor: <tx>`, `Content-Type: application/cbor`. Tags are **untrusted hints**; the CBOR body is the sole authority.

**Cadence:** daily by default, revisited with volume (the size trigger auto-shortens the effective cadence under load). The current producer does not implement a paid-seal force-anchor hook. The **anchor wallet** is dedicated and low-velocity, separate from the upload wallet — it MUST be its **own JWK** (a distinct key, not a logical role on the upload wallet) so an upload-wallet compromise cannot forge anchors — with a hard per-day anchor-transaction budget. The custody posture is stated plainly: a **narrow-scope hot key with a tight circuit breaker and low balance**, not "cold" — a wallet that auto-signs daily cannot be cold, and the spec does not pretend otherwise.

### 16.8 ANS-104 Bundler

An in-house ANS-104 DataItem encoder and deep-hash signer, roughly 300 lines, **Web Crypto only, zero npm dependencies** (both Turbo SDKs fail the `npm ci --ignore-scripts` supply-chain gate). DataItem byte layout:

```text
signatureType (2, LE) || raw_signature || owner || target(flag+0|32) || anchor(flag+0|32) || num_tags(8, LE) || tags_len(8, LE) || avro_tags || data
```

Signing is Arweave `deepHash` — a recursive **SHA-384** digest (Arweave's wire requirement, `crypto.subtle.digest("SHA-384")`) over `["dataitem", "1", sig_type, owner, target, anchor, encoded_tags, data]` — then RSA-PSS over the deep hash with the wallet JWK via `crypto.subtle`; `id = base64url(SHA-256(signature))`. The SHA-384 here is **quarantined as an Arweave-wire-only primitive, never a qub trust primitive** (§15 records the fence; qub trust hashing is SHA3-256 throughout).

The ANS-104 code path serves the deferred fallback/drain machinery and writes `AnchorBundle` DataItems. The ordinary publication path first creates an exact signed Arweave transaction and keeps its JSON in a durable outbox; direct posting is a latency optimisation, and the drain path retries the same transaction before applying its bundler fallback. **Signature scheme (resolved — §16.15 Q8): v1 signs with RSA-PSS (signature type 1)** reusing the existing Arweave wallet JWK mechanism (zero new long-lived key custody, serving the "one fewer secret" thesis); Ed25519 is deferred to the §15 PQ-migration path.

The hand-rolled deep hash is the highest-risk, lowest-natural-coverage code in W5, so its gating is **non-negotiable** (§16.15 Q8):

1. The cross-language fixture `tlog_v1.json` (Rust + TS, the §14.5 `wrapper_v1.json` pattern) covers deep-hash, DataItem bytes + id, leaf hashes, a 5-leaf root + audit path, an STH hash, an inclusion proof, and a consistency proof — in **both the sign and the verify directions** (the verify direction matters because §16.6's local tx → tx_id check pulls the deep hash into every *standalone verifier*, not just the writer).
1. A one-time interop round-trip through a reference ANS-104 bundler, consumed as **static test data only — never an npm runtime dependency** (the Web-Crypto-only / no-install-scripts posture stands).
1. The deep-hash + RSA-PSS path must round-trip through the **same `crypto.subtle` primitives** production uses, so the in-house encoder is byte-compatible.
1. An ongoing **post-bundle acceptance monitor** confirms each anchor / fallback DataItem actually achieves Arweave acceptance, with an alarm + circuit breaker — because the deep hash also serves the Arweave-unavailability fallback queue, so a silent regression would fill that queue with network-rejected items during the exact outage it exists to cover.

### 16.9 Inclusion and Consistency Proofs

Both are RFC 9162, SHA3-256, served as canonical CBOR.

**InclusionProof** — `GET /api/v1/qub/:tx_id/proof`: `ver:u8`, `leaf:bstr` (the exact leaf CBOR — the verifier recomputes `leaf_hash` itself and never trusts a supplied hash), `index:u64`, `size:u64`, `audit:[bstr[32]]`, `root:bstr[32]`, `anchor:{ txid:bstr[32], batch:u64, sth:bstr[32], log_id:bstr[32], block_height?:u64, anchored_at?:i64 }`.

**ConsistencyProof** — `GET /api/v1/log/consistency?first=<size_a>&second=<size_b>`: `ver:u8`, `first_size:u64`, `second_size:u64`, `first_root:bstr[32]`, `second_root:bstr[32]`, `nodes:[bstr[32]]`, `first_anchor`, `second_anchor`. A single unambiguous key list, pinned by test vector.

**Standalone verification** (no qub server, extends §11):

```text
1.  Parse .qub bundle → SealedQub; recompute qub_id (§4.1).
2.  Read leaf.kind.
3a. kind=0x01 (attested):
      assert leaf.ref == qub_id
      assert leaf.body_hash   == SHA3-256(body)
      assert leaf.drand_round == unlock_round(unlock_at)
3b. kind=0x02 (asserted):
      assert leaf.ref == SHA3-256(qub_id || blind)   // holder supplies blind
      OR treat ref as opaque and bind via leaf.chash == SHA3-256(stored_bytes)
4.  Recompute leaf_hash = SHA3-256(0x00 || leaf); fold `audit` per RFC 6962
    using index/size; require derived root == proof.root.
5.  Fetch anchor.txid from any gateway; verify the tx data → tx_id binding
    (do not trust a gateway /raw/ response); REQUIRE anchor_tx.owner ==
    LogProfile.anchor_owner.
6.  Parse AnchorBundle; require committed root == proof.root and size ==
    proof.size; read the Arweave block time T.
7.  Emit the claim scoped by leaf.kind (§16.11).
```

**Proof-serving storage MUST be coordinate-keyed (resolved — §16.15 Q7, blocking precondition).** Cold-leaf proof generation is correctness-neutral **only if** the R2 audit material is a **persistent Merkle-node store keyed by absolute tree coordinate `(level, index)`** — not per-`batch` node deltas. With a coordinate-keyed store, any `(leaf i, size N)` audit path is a set of `O(log N)` direct R2 `GET`s with **no recomputation across batch boundaries**; with a batch-keyed store it is not, which is the storage-layout gap this resolution closes. The leaf bodies are likewise content-addressable by `seq`. A W5 test vector MUST prove a **genesis-era cold leaf against a much-later root using only R2 + Arweave with the LogDO storage wiped**, so the reclamation-safety claim in §16.13 is backed rather than asserted. The `O(log N)` sequential R2 `GET`s belong **only** on the asynchronous proof endpoint — never on the seal hot path (§16.10) or a per-tick cron.

### 16.10 R2-First Ack Ordering

The implemented `POST /api/v1/upload` sequence is:

1. Front-half gates (auth, validation, idempotency shard key) — unchanged.
1. Create, tag, and sign the exact individual Arweave transaction. This derives `tx_id` locally, although transaction creation may fetch reward/anchor metadata from a gateway. A preparation failure still fails the request before acknowledgement.
1. **Synchronously** write the selected artifact at `qub-cache/<tx_id>` and persist the stable creation-operation/outbox records. These are the durability and retry floor; failures before settlement return 503.
1. When `LOG_DO` is configured, **synchronously attempt** `LogDO.append(leaf)`. The single writer assigns `seq`, extends the entry chain, and updates the frontier. The append RPC does only that; batch close runs off-path on the alarm. An append transport/application failure is currently **fail-soft**: the response can still succeed without `log_seq`, `receipt`, or `anchor_status`. Despite an implementation comment, no automatic later log reconciliation is wired today.
1. Return the acknowledgement. Include `{ log_seq, anchor_status: "pending", receipt }` only when the append returned the complete successful tuple. `receipt.sig_b64url` is empty when the receipt signer is unavailable; clients MUST NOT call that value signed or non-repudiable. Absence of the tuple means durable publication only, not transparency-log acceptance.
1. Use one deferred task to post the exact signed transaction. Success removes the outbox; failure leaves it for the bounded drain cron and must not change the already acknowledged `tx_id`. Provisional metadata and other best-effort sidecars are also deferred.

**Latency boundary.** The request path includes front-half authority/quota work, transaction preparation/signing, durable R2 writes, and (when configured) the `LogDO` attempt. `< 300 ms` appears in the design review as an operational target, not a protocol guarantee; the current transaction-preparation step may perform a gateway metadata request. Latency alarms and launch gates are operational controls, not evidence available to a verifier.

### 16.11 Trust Model — the precise claim, scoped by leaf kind

For **`kind=0x01` (attested):** *"This content — body matching `body_hash`, identified by `qub_id` — was committed to qub's append-only log at position `seq` and existed no later than Arweave block time `T`; it was cryptographically unreadable until drand round `R = unlock_round(unlock_at)`."* This is the full `{tlock round binding + Merkle inclusion + anchored root}` triple.

For **`kind=0x02` (asserted, the default):** *"An opaque ciphertext with content-address `chash`, claiming `qub_id` and `unlock_at`, was committed to the append-only log at position `seq` and existed no later than Arweave block time `T`."* The round and body legs are supplied by the existing §11 `.qub`-bundle verification (`qub_core::unlock`), **not** by the log; what the log adds over a bare per-qub transaction is tamper-evident ordering, a trustless upper-bound commitment time, and equivocation resistance.

Both claims exclude, per §11: authorship without `sig_alg ≥ 0x01`, intent, and sub-anchor-granularity timing. Neither lets any claim lean on `received_at`.

**Claim ceiling (binding launch constraint — resolved §16.15 Q1).** For an asserted (`kind=0x02`) leaf, the scoped claim above is the **ceiling** on what any product, marketing, terms, or proof-rendering surface may assert. No surface may state or imply that *the log* proves the content or the unlock round of a byte-blind upload — the log proves *ordering + a trustless upper-bound commitment time of an opaque ciphertext*. Content and round proof come exclusively from the existing §11 `.qub`-bundle verification, which is log-independent. A publication with no successful append/receipt has no log claim at all.

### 16.12 Versioning and W3 Coordination

There is **no `SealedQub` wire bump** and therefore **no protocol-version bump** (§12.2): the log is a sidecar that commits to existing fields and bytes, so it does not enter the §12.3 protocol-version history. W3's optional `drand_chain_version` is untouched and remains the only optional `SealedQub` field. The log instead introduces its own independent version spaces — `LOG_VERSION_1`, `ANCHOR_FORMAT_1`, `InclusionProof.ver` — mirroring the §12.5 wrapper-version independence (the wrapper carries a version byte independent of the protocol version, and the log versions follow the same separation).

**Proof delivery is fetched by default, with an optional ride-along.** A proof cannot exist at seal time (the anchor has not been written yet), so the seal-time `.qub` bundle stays proof-free. W7's verifier fetches `GET …/proof` once, or in fully-offline mode reconstructs the proof from the public `AnchorBundle` via an Arweave query on `Log-Id`. The `.qub` bundle (W7) reserves an **optional `inclusion_proof` member** — absent at seal, populated by a post-anchor re-export for cold archival — following the same "optional, omitted by default, additive" pattern as W3's `drand_chain_version`.

### 16.13 Retention

Retention windows for the LogDO open tail, the R2 proof-serving substrate, the anchor circuit-breaker counters, and the bundler fallback queue are specified in `docs/DATA-RETENTION.md`. Principle: the log's hot per-entry storage (LogDO) is reclaimable post-anchor; its audit material — the coordinate-keyed `(level, index)` Merkle-node store + the `seq`-addressed leaf bodies (§16.9) + the Arweave anchors — is permanent. Reclaiming a cold leaf from the DO never invalidates an issued proof, because a proof resolves against that permanent R2 node store and the Arweave anchor, not the DO (and the §16.9 wiped-DO test vector proves it).

### 16.14 Test Vectors

W5 ships the cross-language fixture `tlog_v1.json` (§16.8) plus worked vectors: a `kind=0x01` and a `kind=0x02` leaf → `leaf_hash`; the 5-leaf cumulative root; one inclusion proof; one consistency proof; one `AnchorBundle`; and one DataItem id. These live alongside the §14.5 outer-wrapper vectors and are exercised by both the Rust (`qub-core`) and TypeScript (Worker) implementations.

### 16.15 Review Decisions (W5 — resolved)

The W5 external review (an adversarial design pass + owner sign-off) is complete. Each decision below is settled and reflected in the §16 text above; the **binding launch constraints** are restated at the end. Implementation may proceed under them.

1. **Default-path (`kind=0x02`) leaf honesty — RESOLVED.** Ship the two-leaf-kind split as specified: `kind=0x02` commits neither `body_hash` nor `drand_round`. No `*_body_hash` field on the byte-blind path (it would be the most legible false "verified" signal for integrators and is a convenience §11 already provides from the bundle). Do **not** require server-seal for log-attested qubs (that would force plaintext through the Worker and destroy the crypto-shredding moat). Any self-describing short-circuit belongs in the `.qub` bundle / proof envelope as a verifier-recomputed field, never a leaf field. Owner-confirmed claim ceiling: §16.11.
1. **Equivocation / omission accountability — DESIGN RESOLVED, PROVISIONING INCOMPLETE.** The design requires the seal-receipt key to be pinned in `LogProfile` and cross-signed by `anchor_owner`, plus monitor methodology, prev-chain walk, and dual self-published heads. The compiled profile and deployment hooks are still placeholders/optional as detailed in §16.6, so the stronger *detectable + receipted* claim is not current until those gates close. It must never be marketed as *independently witnessed*. A true third-party witness is deferred to a §15 governance bump.
1. **Pinned anchor-owner trust root + rotation — RESOLVED.** Adopt the `LogProfile` pin (§16.6); the verifier checks `anchor_tx.owner == anchor_owner` and verifies the tx data → tx_id binding locally. Rotation governance is a §15 **extension to build** (§15.3 trigger added), not a reuse; planned rotations cross-sign, compromise-driven rotations fall back to the §15 bump with the fork check bounding damage.
1. **Private-qub leaf blinding — RESOLVED.** Keep blinding for private qubs (`ref = SHA3-256(qub_id ‖ log_blind_secret)`), raw `qub_id` for public qubs (already §16.2.1), `chash` as the standalone tie. `log_blind_secret` is a correlation/Sybil-grade secret, rotate-forward only (§16.2.1).
1. **`received_at` — RESOLVED.** Keep it in the leaf, committed but explicitly non-evidentiary; never surfaced as proof or dispute corroboration on any surface. Any monitor sanity check compares against the Arweave block time `T`, not the operator-controlled `anchored_at` (§16.6).
1. **Tiered provable-timing — DESIGN RESOLUTION, NOT CURRENT ROUTING.** The reviewed design assigns anchor-block timing to the batched tier and exact-hour proof to paid T3, with no numeric SLA for the former. The current routes have not wired that commercial distinction: they schedule an individual transaction for every accepted publication, and log coverage remains conditional as stated in §16.1/§16.10. Product copy must describe the implementation, not this future tier split.
1. **Cumulative tree on Workers — RESOLVED.** Single cumulative RFC 9162 tree + frontier-cached single-writer LogDO (comfortable headroom vs the ~1k writes/sec DO ceiling; defer Merkle-of-shard-roots sharding until near it). The coordinate-keyed `(level, index)` R2 node store + wiped-DO cold-leaf test vector are implemented (§16.9). `< 300 ms` remains a design/operational target, not a protocol promise (§16.10).
1. **ANS-104 signature scheme + deep-hash — RESOLVED.** RSA-PSS (sig type 1, reusing the dedicated anchor-wallet JWK); Ed25519 deferred to the §15 PQ path. The hand-rolled SHA-384 deep hash is gated on the both-directions cross-impl fixture, a static-only reference-bundler interop check, the shared-`crypto.subtle` round-trip, and the post-bundle Arweave-acceptance monitor (§16.8).

**Binding launch constraints** (carry into implementation + product/legal review):

- **Claim ceiling (Q1/Q6).** No surface may say *the log proves* an asserted leaf's content or unlock round; the permitted claim for a successfully anchored `kind=0x02` leaf is *ordered, tamper-evidently, with a trustless upper-bound commitment time*. A response without a receipt tuple has no log claim. No timestamp copy carries a numeric latency guarantee.
- **Witness honesty (Q2).** Market equivocation as *detectable + receipted*, never *independently witnessed*.
- **Receipt + anchor keys (Q2/Q8).** Before the non-repudiation/anchored-verification claims ship, provision and compile-pin the receipt public key, cross-sign it with the provisioned anchor owner, and keep the anchor wallet as its own JWK distinct from the upload wallet.
- **Deep-hash gate (Q8).** No anchor or T3 tx ships until the both-directions fixture + interop check pass; the acceptance monitor pages on failure.
- **Storage precondition (Q7).** Coordinate-keyed node store + wiped-DO cold-leaf vector are prerequisites for the "reclamation never invalidates a proof" guarantee.

______________________________________________________________________

## 17. Portable Verification Bundle (`.qub`)

> **Status.** This section is **implemented** (W7 / UP-C2): `qub_core::export` produces and parses the bundle, and `tools/qub-verify` is a public, self-contained CLI that verifies one offline. §11 and §16.9 already refer to "the `.qub` bundle" as the unit a standalone verifier consumes; this section specifies its bytes and the verification walkthrough. It is strictly additive — the bundle packages existing §11 inputs and changes no on-chain wire format.

### 17.1 Purpose

§11 establishes that any third party can verify a qub's cryptographic artifact without qub cooperation. The `.qub` bundle makes that verification **portable and offline**: it packages the sealed CBOR and the drand round signature that unlocks it into a single self-contained artifact, so a recipient can verify content integrity, round binding, and any authorship signatures with **no network call at all** (no storage fetch, no live drand request, no qub API). A bundle alone does not prove when its ciphertext was created; an independently verified storage transaction or anchored log proof supplies that separate existence-time claim (§11, §17.5).

### 17.2 Bundle Format

A `QubBundle` is hand-written canonical CBOR under the §3.1 profile (definite-length, no tags, no floats, shortest-form integers, NFC text, optional fields omitted when absent, keys ordered by encoded-byte length ascending then bytewise). The three 15-character keys order `d` < `i` < `s`. A raw `.qub` file is exactly these bytes; for URL or copy-paste transport the same bytes are base64url(no-pad).

| Key | Enc. len | Type | Presence | Meaning |
| --- | -------- | ---- | -------- | ------- |
| `version` | 8 | `u8` | required | Bundle format version (`0x01`). |
| `sealed_at` | 10 | `i64` | optional | Creator-asserted seal time (Unix seconds); self-descriptive, non-evidentiary. |
| `drand_round` | 12 | `u64` | required | The round the qub is locked to. A projection of the embedded sealed qub. |
| `arweave_tx_id` | 14 | `tstr` | required | The transaction id the sealed bytes were stored under (provenance pointer). |
| `drand_chain_id` | 15 | `tstr` | required | The drand chain (hex). A projection of the embedded sealed qub. |
| `drand_signature` | 16 | `bstr` | required | The drand beacon signature for `drand_round` — the value that unlocks the ciphertext. |
| `inclusion_proof` | 16 | `bstr` | optional | The §16 transparency-log Merkle inclusion proof, after an anchored proof is available (§17.5). |
| `sealed_qub_cbor` | 16 | `bstr` | required | The inner `SealedQubCbor` bytes (post-§13-unwrap), i.e. the §11 verification input. |

`drand_round` and `drand_chain_id` are convenience projections of `sealed_qub_cbor`, carried so tooling can read them without parsing the inner CBOR. They are derived on construction and **re-checked on decode** against the parsed sealed qub; a bundle whose top-level field disagrees with its payload is rejected. Encoder discipline mirrors the rest of the wire format: reject an empty `drand_signature` or `arweave_tx_id`, and bound every variable-length field.

### 17.3 What the embedded drand signature proves

The bundle carries the drand signature rather than requiring the verifier to fetch it. Timelock decryption (tlock over the drand chain, §8) can only succeed with the **genuine** beacon signature for the bound round—a value the chain publishes only once that round elapses, and which is a valid BLS signature under the chain's public key. A forged or wrong signature fails BLS verification or IBE/AEAD decryption. A bundle that decrypts therefore proves: **the ciphertext is bound to round R, and round R has elapsed**. The verifier pins the chain (`DrandTimelockProvider::quicknet()`) and applies the §11 round-binding check, so a bundle cannot claim a round its ciphertext is not bound to.

This is a release-condition proof, not a creation timestamp. After round R has
elapsed, anyone can create a new ciphertext for R and package its already-public
signature. Therefore the bundle alone MUST NOT be described as proof that the
ciphertext or content existed before R, before `unlock_at`, or before any event.

### 17.4 Offline verification walkthrough

`qub-verify <file.qub>` runs the standard §11 procedure entirely from the bundle, driving `qub_core::unlock::unlock` with a pinned `DrandTimelockProvider`:

```text
1. Parse the .qub bytes → QubBundle (canonical-CBOR guard; bound every field;
   re-check drand_round / drand_chain_id against the embedded sealed qub).
2. BLS-verify bundle.drand_signature for the pinned chain and round, then
   tlock_decrypt(sealed.tlock_ciphertext, bundle.drand_signature) → QubEnvelope.
3. Verify SHA3-256(body) == body_hash               (§11 step 8).
4. Verify QubEnvelope.qub_id   == SealedQub.qub_id   (§11 step 9).
5. Verify QubEnvelope.unlock_at == SealedQub.unlock_at (§11 step 10).
6. Verify ciphertext round == unlock_round(unlock_at) and the chain binding.
7. If sig_alg != 0x00: verify author_signature (and any cosigner; §9.4).
8. Report integrity, round-elapsed/round-binding, authorship, and cosigner
   verdicts separately, plus the recovered body. Do not report a commitment
   timestamp unless step 9 succeeds.
9. Optional existence-time leg: verify an included §16 proof through its pinned
   anchor, or independently verify the referenced storage transaction. Report
   its block time as an upper bound on ciphertext existence.
```

The CLI exits `0` (verified), `1` (verification failed — still locked, body-hash mismatch, broken round/chain binding, or a signature that fails to verify), or `2` (usage / malformed bundle). A `--json` report carries the same verdicts for automation. Because the bundle is self-contained, the verifier crate (`qub-core`) and the CLI (`qub-verify`) are the only software a third party needs; both are public and reuse the protocol's existing verification path — no bespoke crypto.

### 17.5 Relationship to the transparency log

`inclusion_proof` is an optional slot for the §16 Merkle inclusion proof. Bundle-only verification (§17.4) is complete for **integrity, round binding / round elapsed, and optional authorship**, but intentionally has no independently timestamped existence claim. A populated, fully anchor-verified `inclusion_proof` adds the leaf-kind-specific commitment and upper-bound time from §16.11 without changing the bundle format version. An absent proof means only "no proof included"—not "invalid" and not necessarily "not anchored."

In the reference implementation the slot is now **typed**: `qub_core::export::QubBundle::inclusion_proof_typed()` returns an `Option<InclusionProof>` carrying the full §16.9 structure (leaf, audit path, anchored root, and `AnchorRef`) through the same opaque CBOR field — no bundle-format version bump. The standalone `qub-verify` CLI consumes it via its `--anchor` leg, and — until the anchor wallet is provisioned (§16, Status) — reports a populated-but-placeholder-owner proof as *inclusion-only* rather than fully *anchored-verified*.
