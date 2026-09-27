---
authority: L
status: current
reviewed-on: 2026-05-23
cadence: null
coupled-to:
  - crates/qub-core/src/**
---

# qub-core

Cryptographic protocol library for the qub timelock message system. Implements canonical CBOR serialisation, SHA3-256 hashing, and drand timelock encryption. Pure computation — no I/O, no UI.

Compiles for both native (Rust) and WebAssembly (`wasm32-unknown-unknown`) targets.

## What it does

A creator composes a message and chooses an unlock time. `seal()` encrypts the message using drand's BLS12-381 identity-based encryption so it can only be decrypted once drand publishes the corresponding round signature. `unlock()` reverses the process, verifying content integrity along the way.

## Public API

### Entry points

- **`seal::seal(SealInput) -> SealOutput`** — Validate, hash, encrypt, produce `SealedQubCbor` ready for upload
- **`unlock::unlock(UnlockInput) -> RevealedQub`** — Parse, decrypt, verify integrity, return plaintext

### Protocol types

| Type | Role |
|------|------|
| `ComposeQub` | Creator-side in-memory draft (never serialised) |
| `QubEnvelope` | Decrypted payload proving content integrity (CBOR-encoded, encrypted) |
| `SealedQub` | On-wire artifact stored on Arweave (contains encrypted envelope + metadata) |
| `RevealedQub` | Viewer-side application state after decryption and verification |
| `PactTerms` | Structured bilateral agreement body (content type `0x03`) — title, rows, parties, notes |

### Wire format newtypes

- `SealedQubCbor` — Safe wrapper around canonical CBOR bytes of a `SealedQub`
- `QubEnvelopeCbor` — Safe wrapper around canonical CBOR bytes of a `QubEnvelope`
- `PactTermsCbor` — Safe wrapper around canonical CBOR bytes of a `PactTerms` body

No `From<Vec<u8>>` — these can only be constructed through the serialisation API.

### Hash functions

- `body_hash(body)` — SHA3-256 of raw body bytes
- `qub_id(version, content_type, created_at, unlock_at, body_hash)` — Domain-separated SHA3-256 producing a unique 32-byte message identifier
- `unlock_round(unlock_at, genesis_time, period)` — Computes the drand round number for an unlock timestamp

### Authorship signing

- `signing::sign(sk, input)` / `signing::verify(pk, input, sig)` — ML-DSA-65 (FIPS 204) post-quantum signatures
- `signing::compute_sig_input(version, qub_id, body_hash, unlock_at)` — Domain-separated signing input covering the integrity-critical envelope fields
- `PubkeyFingerprint` — Stable 8-byte identifier of a public key for display and attestation records

### Pact protocol (`pact` module)

Structured bilateral agreements. Two-party pacts use the same timelock
envelope as single-author qubs but set `content_type = 0x03` and carry
a `PactTerms` body with both signatures attached.

- `serialize_pact_terms` / `parse_pact_terms` — Canonical CBOR for the body
- `validate_pact_terms` — Field-level validation (length caps, party shape)
- `acknowledgement_for(PactRole, AcknowledgementKind) -> &'static str` — Pure lookup over the eight frozen `structured/v1` acknowledgement strings (`GOODS_SELLER_STANDARD` etc.); the bytes both parties sign
- Term-key constants — `INITIATOR_STANDARD_TERMS`, `INITIATOR_CAPACITY_TERMS`, `COUNTERPARTY_STANDARD_TERMS`, `COUNTERPARTY_CAPACITY_TERMS`

The eight frozen strings are English-only by design — the signed body
is language-neutral, and `crates/qub-core/tests/golden_pact_hashes.rs`
pins the SHA3-256 body hash of a canonical fixture for each role combo
so any accidental byte-level change fails the build. See
`docs/PACT-FROZEN-STRINGS.md`
for the freeze policy.

### Timelock providers

- `TimelockProvider` trait — Abstracts encryption/decryption
- `DrandTimelockProvider::quicknet()` — Production provider using drand BLS12-381 + age encryption (feature `tlock-drand`)
- `MockTimelockProvider` — Non-cryptographic stub for tests (feature `test-utils`)

## Modules

| Module | Responsibility |
|--------|----------------|
| `types` | Domain types, builders, validation, `QubError` |
| `cbor` | Canonical CBOR serialisation per PROTOCOL.md section 5 |
| `hash` | Normative hash derivations per PROTOCOL.md section 4 |
| `signing` | ML-DSA-65 (FIPS 204) signature trait, pubkey fingerprint, `compute_sig_input` |
| `tlock` | Timelock encryption trait and implementations |
| `seal` | Seal protocol (PROTOCOL.md section 7, steps 2-12) |
| `unlock` | Unlock protocol (PROTOCOL.md section 8, steps 4-15) |
| `pact` | Structured bilateral agreements: `PactTerms`, canonical CBOR, frozen acknowledgement strings |
| `wire` | Safe newtypes for CBOR byte buffers |

## Feature flags

| Feature | Default | Purpose |
|---------|---------|---------|
| `tlock-drand` | Yes | Enables `DrandTimelockProvider` (production drand + BLS12-381) |
| `test-utils` | No | Exposes `MockTimelockProvider` for external crate tests |

## Design decisions

- **No serde on protocol types** — `ComposeQub`, `QubEnvelope`, `SealedQub`, and `RevealedQub` use hand-written canonical CBOR. Never add `#[derive(Serialize, Deserialize)]` to these types.
- **Canonical CBOR** — Deterministic serialisation (sorted keys, no indefinite-length containers) for cryptographic integrity.
- **No I/O** — Pure computation only. Network, storage, and UI are the caller's responsibility.
- **Wire-format safety** — Newtypes prevent accidental confusion between raw bytes and validated CBOR.

## Tests

Native tests covering:

- Canonical CBOR roundtrips and property-based tests (proptest)
- Hash determinism and protocol test vectors from PROTOCOL.md
- Seal / unlock happy paths with both mock and real drand fixtures
- Tamper detection (body hash mismatch, wrong signature, modified ciphertext)
- ML-DSA-65 sign / verify round-trips + domain separation
- Pact canonical CBOR round-trips, validation, and frozen-acknowledgement tampering (`tests/golden_pact_hashes.rs` — four role-combo body hashes + sensitivity self-test)
- Defensive edge cases (zero periods, past timestamps, oversized bodies)

```bash
cargo nextest run -p qub-core
```
