//! Verification library behind the `qub-verify` CLI.
//!
//! Everything here is pure: bytes and already-fetched responses in, typed
//! verdicts out. No module performs I/O, so the same code serves the
//! standalone CLI and the `qub-mcp` server, and every verdict can be
//! reproduced from recorded inputs.
//!
//! - [`anchor`] / [`ans104`] — the transparency-log anchor leg (PROTOCOL.md
//!   §16.9), unchanged in scope: it authenticates a signed anchor `DataItem`
//!   and never, on its own, establishes when anything reached Arweave.
//! - [`arweave_tx`] — binds stored bytes to an Arweave L1 transaction: the
//!   data root, the signature preimage and the transaction id.
//! - [`timing`] — turns what Arweave gateways that qub does not run report about that
//!   transaction into a fail-closed existence-time verdict.
//! - [`series`] — the declared forecast-series schema and its report.

pub mod anchor;
pub mod ans104;
pub mod arweave_tx;
pub mod series;
pub mod timing;
