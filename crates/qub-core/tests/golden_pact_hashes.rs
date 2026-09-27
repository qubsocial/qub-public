//! Golden CBOR body-hash tests for `structured/v1` pacts.
//!
//! The eight frozen acknowledgement strings in `qub_core::pact` are
//! signed verbatim into every structured pact's CBOR body. These tests
//! pin the SHA3-256 `body_hash` of a canonical fixture for each of the
//! four role combinations (Goods/Seller, Goods/Buyer, Services/Provider,
//! Services/Client). Any byte-level change to a frozen string — or to
//! the CBOR serialisation itself — will break the fixture hash and
//! force a conscious decision to bump to `structured/v2`.
//!
//! # First-run / rotation procedure
//!
//! 1. Write the four golden tests with `__PENDING__` as the expected hex.
//! 2. Run:
//!    ```sh
//!    cargo test -p qub-core --test golden_pact_hashes \
//!      -- --nocapture 2>&1 | grep GOLDEN_HASH
//!    ```
//! 3. Copy the four emitted lines — each prints its real hash via
//!    `eprintln!` regardless of assertion-failure format.
//! 4. Replace `__PENDING__` with the real values.
//! 5. Run again — all green. Commit the real hashes in a single
//!    commit. Never push a `__PENDING__` placeholder.
//!
//! # Term-display order note
//!
//! The viewer's term-display order must mirror the CBOR term order in
//! this fixture; if you diverge, re-review the acknowledgement prose
//! (`"described above"` presumes the description appears above).

use qub_core::hash::body_hash;
use qub_core::pact::{
    AcknowledgementKind, COUNTERPARTY_CAPACITY_TERMS, COUNTERPARTY_STANDARD_TERMS,
    INITIATOR_CAPACITY_TERMS, INITIATOR_STANDARD_TERMS, PactRole, PactTerm, PactTerms,
    PactTermsBuilder, PartyIdentifier, acknowledgement_for, serialize_pact_terms,
};

// ---------------------------------------------------------------------------
// Fixture data
// ---------------------------------------------------------------------------

const FIX_TITLE: &str = "Golden test fixture";
const FIX_DESCRIPTION: &str = "Test item for golden hash verification";
const FIX_SCOPE: &str = "Test service scope for golden hash verification";
const FIX_PRICE_AMOUNT: &str = "100.00";
const FIX_PRICE_CURRENCY: &str = "AUD";
const FIX_HANDOVER_DATE: &str = "2026-06-01";
const FIX_COMPLETION_DATE: &str = "2026-06-15";
const FIX_PARTY_A: (&str, &str) = ("Alice", "alice@example.com");
const FIX_PARTY_B: (&str, &str) = ("Bob", "bob@example.com");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum FixtureKind {
    Goods,
    Services,
}

fn term(key: &str, value: &str) -> PactTerm {
    PactTerm::new(key.to_string(), value.to_string())
}

fn party(p: (&str, &str)) -> PartyIdentifier {
    PartyIdentifier::new(p.0.to_string(), Some(p.1.to_string()))
}

/// Counterparty role — flip of the initiator's.
const fn counterpart(role: PactRole) -> PactRole {
    match role {
        PactRole::Seller => PactRole::Buyer,
        PactRole::Buyer => PactRole::Seller,
        PactRole::Provider => PactRole::Client,
        PactRole::Client => PactRole::Provider,
    }
}

fn build_golden_terms(kind: FixtureKind, initiator: PactRole) -> PactTerms {
    let cp = counterpart(initiator);

    let mut terms: Vec<PactTerm> = vec![
        term("pact_schema", "structured/v1"),
        term(
            "pact_type",
            match kind {
                FixtureKind::Goods => "goods",
                FixtureKind::Services => "services",
            },
        ),
        term(
            "initiator_role",
            match initiator {
                PactRole::Seller => "seller",
                PactRole::Buyer => "buyer",
                PactRole::Provider => "provider",
                PactRole::Client => "client",
            },
        ),
    ];

    match kind {
        FixtureKind::Goods => {
            terms.push(term("description", FIX_DESCRIPTION));
        },
        FixtureKind::Services => {
            terms.push(term("scope_of_work", FIX_SCOPE));
            terms.push(term("frequency", "once"));
        },
    }

    terms.push(term("price_amount", FIX_PRICE_AMOUNT));
    terms.push(term("price_currency", FIX_PRICE_CURRENCY));

    match kind {
        FixtureKind::Goods => terms.push(term("handover_date", FIX_HANDOVER_DATE)),
        FixtureKind::Services => terms.push(term("completion_date", FIX_COMPLETION_DATE)),
    }

    terms.push(term(
        INITIATOR_STANDARD_TERMS,
        acknowledgement_for(initiator, AcknowledgementKind::Standard),
    ));
    terms.push(term(
        INITIATOR_CAPACITY_TERMS,
        acknowledgement_for(initiator, AcknowledgementKind::Capacity),
    ));
    terms.push(term(
        COUNTERPARTY_STANDARD_TERMS,
        acknowledgement_for(cp, AcknowledgementKind::Standard),
    ));
    terms.push(term(
        COUNTERPARTY_CAPACITY_TERMS,
        acknowledgement_for(cp, AcknowledgementKind::Capacity),
    ));

    PactTermsBuilder::new()
        .pact_version(1)
        .title(FIX_TITLE.to_string())
        .terms(terms)
        .party_a(party(FIX_PARTY_A))
        .party_b(party(FIX_PARTY_B))
        .notes(None)
        .build()
        .expect("fixture builder must succeed")
}

fn golden_hash(kind: FixtureKind, initiator: PactRole) -> String {
    let pact = build_golden_terms(kind, initiator);
    let cbor = serialize_pact_terms(&pact).expect("canonical CBOR must serialise");
    hex::encode(body_hash(&cbor))
}

// ---------------------------------------------------------------------------
// Golden hash tests
// ---------------------------------------------------------------------------

#[test]
fn golden_hash_goods_seller() {
    let hex = golden_hash(FixtureKind::Goods, PactRole::Seller);
    eprintln!("GOLDEN_HASH goods_seller = {hex}");
    assert_eq!(
        hex, "9dd317a64b00ec4c4f6106df67a322138e88813f7b68e7037bb769ce9b9cb34d",
        "Frozen string change detected for Goods/Seller.\n\
         If intentional, this requires structured/v2.\n\
         See docs/PACT-FROZEN-STRINGS.md"
    );
}

#[test]
fn golden_hash_goods_buyer() {
    let hex = golden_hash(FixtureKind::Goods, PactRole::Buyer);
    eprintln!("GOLDEN_HASH goods_buyer = {hex}");
    assert_eq!(
        hex, "cad43b1ec744dda90edcd81880ec83e86eba82ebe5178f61d90a9ed9706d7e3c",
        "Frozen string change detected for Goods/Buyer.\n\
         If intentional, this requires structured/v2.\n\
         See docs/PACT-FROZEN-STRINGS.md"
    );
}

#[test]
fn golden_hash_services_provider() {
    let hex = golden_hash(FixtureKind::Services, PactRole::Provider);
    eprintln!("GOLDEN_HASH services_provider = {hex}");
    assert_eq!(
        hex, "d2c59f12b5a8846b064fe1b004dbca3660cbd0408079b069b96a84371c6979eb",
        "Frozen string change detected for Services/Provider.\n\
         If intentional, this requires structured/v2.\n\
         See docs/PACT-FROZEN-STRINGS.md"
    );
}

#[test]
fn golden_hash_services_client() {
    let hex = golden_hash(FixtureKind::Services, PactRole::Client);
    eprintln!("GOLDEN_HASH services_client = {hex}");
    assert_eq!(
        hex, "7810659e97b5a238a3ebf22e135b1e294c4615139312d3fba19c5b557713bf0e",
        "Frozen string change detected for Services/Client.\n\
         If intentional, this requires structured/v2.\n\
         See docs/PACT-FROZEN-STRINGS.md"
    );
}

// ---------------------------------------------------------------------------
// Sensitivity self-test
// ---------------------------------------------------------------------------
//
// Proves the golden-hash mechanism actually catches string tampering.
// If this fails, all four golden tests above are worthless.

#[test]
fn golden_hash_detects_string_tampering() {
    // Normal fixture — exactly what the golden tests hash.
    let normal = build_golden_terms(FixtureKind::Goods, PactRole::Seller);

    // Tampered fixture — rebuild from scratch with the initiator
    // standard-terms value mutated by a single trailing byte. PactTerms
    // fields are private and there's no `terms_mut()` accessor (by
    // design — the type is immutable once built), so we take the
    // existing term list, swap the target row, and build again.
    let mut tampered_rows: Vec<PactTerm> = normal
        .terms()
        .iter()
        .map(|t| PactTerm::new(t.key().to_string(), t.value().to_string()))
        .collect();
    let row = tampered_rows
        .iter_mut()
        .find(|t| t.key() == INITIATOR_STANDARD_TERMS)
        .expect("initiator_standard_terms row present in fixture");
    let tampered_value = format!("{} ", row.value());
    *row = PactTerm::new(INITIATOR_STANDARD_TERMS.to_string(), tampered_value);

    let tampered = PactTermsBuilder::new()
        .pact_version(normal.pact_version())
        .title(normal.title().to_string())
        .terms(tampered_rows)
        .party_a(PartyIdentifier::new(
            normal.party_a().label().to_string(),
            normal.party_a().contact().map(str::to_string),
        ))
        .party_b(PartyIdentifier::new(
            normal.party_b().label().to_string(),
            normal.party_b().contact().map(str::to_string),
        ))
        .notes(normal.notes().map(str::to_string))
        .build()
        .expect("tampered builder must succeed");

    let h1 = body_hash(&serialize_pact_terms(&normal).unwrap());
    let h2 = body_hash(&serialize_pact_terms(&tampered).unwrap());
    assert_ne!(h1, h2, "hash must change when a frozen string changes");
}
