//! Canonical list of compose intents.
//!
//! qub allows a creator to tag a qub with one of a small fixed set of
//! "intents" (announcement, thesis, prediction, letter, secret,
//! commitment, proof) — UX hints that drive hero copy, default
//! durations, and viral-loop CTAs. The intent travels with the upload
//! as the public `Intent` Arweave tag and surfaces on the viewer
//! countdown, the OG card, the share-text composer, and lifecycle
//! emails.
//!
//! An eighth identifier — `verdict` — is system-emitted, not
//! user-selectable. It tags the chained creator-self-grading qub that
//! follows a verdict-bearing parent (prediction / commitment /
//! announcement / thesis). Reached only via the `/verdict/{tx_id}`
//! flow; the `IntentSelector` pill row filters it out.
//!
//! This module is the **single source of truth** for the canonical
//! string list. Every consumer — `qub-app`'s rich `Intent` enum, the
//! `qub-mcp` MCP server's `tools/list` JSON Schema, the Worker's
//! GraphQL-tag allowlist, and the `OpenAPI` spec's `intent` enum — must
//! agree on this list. A regression test in `crates/qub-app` asserts
//! `Intent::ALL.map(as_str)` permutes [`INTENT_NAMES`]; a regression
//! test in `workers/api` asserts `ALLOWED_INTENTS` equals
//! [`INTENT_NAMES`] (read directly from this Rust source); the MCP's
//! own test (`tools/qub-mcp/src/main.rs::tests`) asserts its
//! `KNOWN_INTENTS` import here matches the schema enum it advertises.
//!
//! When adding a new intent: amend [`INTENT_NAMES`] here, then update
//! the rich qub-app `Intent` enum, the `OpenAPI` `intent` enum, the
//! qub-app i18n keys (`creator.intent.*`, `creator.hero.<name>.{1..5}`),
//! and run `npm test` in `workers/api` to confirm the cross-impl
//! checks still pass.

/// Canonical compose-intent identifiers, in declaration order.
///
/// Order matters only for stable display in admin/inspector tools —
/// the order here mirrors the `OpenAPI` spec's `intent` enum so the
/// rendered `/openapi` page reads the same as this module. The qub-app
/// has its own preferred display order on the compose pill row
/// (`Intent::ALL`); the relationship between the two orderings is
/// asserted in qub-app's tests.
pub const INTENT_NAMES: [&str; 8] = [
    "announcement",
    "thesis",
    "prediction",
    "letter",
    "secret",
    "commitment",
    "proof",
    "verdict",
];

/// Returns `true` if `s` is one of the canonical intent strings.
///
/// Use this in any code path that takes a string from an external
/// boundary (HTTP body, URL parameter, MCP tool argument) before
/// committing to act on it. Mirrors the rejection semantics of
/// `qub-app`'s `Intent::parse` (which returns `Option<Intent>`) for
/// callers that don't need the rich enum.
#[must_use]
pub fn is_known_intent(s: &str) -> bool {
    INTENT_NAMES.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_names_has_eight_unique_entries() {
        assert_eq!(INTENT_NAMES.len(), 8);
        let mut seen = std::collections::HashSet::new();
        for name in INTENT_NAMES {
            assert!(seen.insert(name), "duplicate intent name: {name}");
        }
    }

    #[test]
    fn intent_names_are_lowercase_ascii() {
        for name in INTENT_NAMES {
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase()),
                "intent {name} contains non-lowercase-ASCII characters"
            );
        }
    }

    #[test]
    fn is_known_intent_accepts_each_canonical_name() {
        for name in INTENT_NAMES {
            assert!(
                is_known_intent(name),
                "is_known_intent({name}) returned false"
            );
        }
    }

    #[test]
    fn is_known_intent_rejects_unknown() {
        for bad in ["", "ANNOUNCEMENT", "rumour", "predictionx", "predictio"] {
            assert!(
                !is_known_intent(bad),
                "is_known_intent({bad}) should be false"
            );
        }
    }
}
