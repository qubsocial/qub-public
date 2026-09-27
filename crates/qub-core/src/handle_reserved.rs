//! Reserved-word deny list for handle normalisation.
//!
//! Source-controlled, manually-reviewed list (see `docs/IDENTITY.md` §3.2.5
//! §2.5). Keep sorted — callers binary-search. Every entry MUST be the
//! canonical normalised form (lower-case ASCII, no leading `@`, 3-20
//! code points, `[a-z0-9_]`) so the list itself satisfies
//! [`crate::handle::normalise_handle`] when tested.
//!
//! The Worker duplicates this **core** list in TypeScript; both sides
//! ship tests that snapshot the shared contents so drift is visible in
//! PR review. The Worker additionally enforces a server-side brand deny
//! list (~200 third-party brand names) that this crate deliberately
//! does not mirror — the server is authoritative for allocation, so a
//! client-side miss on a brand name surfaces as a later server
//! rejection, never a successful claim (IDENTITY.md §3.2.6.6).

/// Sorted, lower-case reserved-word deny list.
///
/// Categories (from `docs/IDENTITY.md` §3.2.5 §2.5):
/// - Protocol nouns — words that describe the qub object model.
/// - App routes — any path the creator app routes on, so `/@api` can
///   never clash with `/api`.
/// - Platform footguns — words that confer apparent official status.
/// - Brand words — names the project keeps for its own future use.
/// - Profanity — a minimal, hand-picked set. This is not a moderation
///   product; Phase 2 covers the obvious entries only.
pub const RESERVED_HANDLES: &[&str] = &[
    // Keep sorted!
    "about",
    "abuse",
    "account",
    "admin",
    "administrator",
    "anthropic",
    "api",
    "auth",
    "billing",
    "claude",
    "compose",
    "contact",
    "dev",
    "developer",
    "drafts",
    "embed",
    "help",
    "history",
    "identity",
    "info",
    "legal",
    "mark",
    "mod",
    "moderator",
    "notify",
    "official",
    "owner",
    "pact",
    "pacts",
    "payments",
    "pricing",
    "privacy",
    "protocol",
    "qub",
    "qubs",
    "reveal",
    "root",
    "seal",
    "sealed",
    "security",
    "settings",
    "sign",
    "signature",
    "signed",
    "staff",
    "support",
    "svailsa",
    "system",
    "team",
    "terms",
    "upload",
    "user",
    "username",
];

/// True if `handle` (already lower-cased) is on the reserved list.
///
/// Caller must pass a normalised handle — this function does NOT call
/// [`crate::handle::normalise_handle`] itself.
#[must_use]
pub fn is_reserved_lower(handle: &str) -> bool {
    RESERVED_HANDLES.binary_search(&handle).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_sorted_and_deduped() {
        for window in RESERVED_HANDLES.windows(2) {
            assert!(
                window[0] < window[1],
                "reserved list out of order or duplicated around {:?} / {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn list_entries_are_lowercase_ascii() {
        for entry in RESERVED_HANDLES {
            assert!(
                entry
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "reserved list entry {entry:?} contains unexpected byte"
            );
            assert!(
                !entry.is_empty() && entry.len() <= crate::handle::HANDLE_MAX_LEN,
                "reserved list entry {entry:?} violates length bounds"
            );
        }
    }

    #[test]
    fn is_reserved_finds_known_entries() {
        assert!(is_reserved_lower("admin"));
        assert!(is_reserved_lower("qub"));
        assert!(is_reserved_lower("mark"));
        assert!(is_reserved_lower("svailsa"));
    }

    #[test]
    fn is_reserved_rejects_non_entries() {
        assert!(!is_reserved_lower("markharper"));
        assert!(!is_reserved_lower("quiet_fox_482"));
        assert!(!is_reserved_lower(""));
    }
}
