#![doc = "qub core protocol library.\n\n`qub-core` defines the wire format, canonical CBOR encoding, hashing, and\nshared domain types used by both the creator and viewer applications. It\ncontains no UI or I/O code and is designed to compile for both native\n(tests) and `wasm32-unknown-unknown` (browser) targets."]
// SEC-15: qub-core decodes untrusted protocol bytes (CBOR envelopes,
// tlock ciphertext, pact terms). A panic on that path is a
// denial-of-service bug, so the panic-prone constructs are denied in
// non-test code — every reachable use must be a `Result`, a `.get()`,
// or carry a justified `#[allow(...)]`. Tests stay exempt (`cfg(test)`):
// `unwrap`/`expect`/`panic` are the normal idiom for asserting in tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod cbor;
pub mod export;
pub mod handle;
pub mod handle_reserved;
pub mod handle_wordlist;
pub mod hash;
pub mod intent;
pub mod log;
pub mod merkle;
pub mod pact;
pub mod portable_key;
pub mod seal;
pub mod signing;
pub mod tlock;
pub mod txid;
pub mod types;
pub mod unlock;
pub mod verdict;
pub mod wire;
pub mod wrapper;
