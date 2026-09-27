# Contributing

Thank you for helping keep the qub protocol open and verifiable.

## What lives where

Most of this repository is a **mirror** of qub's private development
repository. These paths are overwritten on every sync:

- `protocol/PROTOCOL.md`
- `crates/` (the `qub-core` crate, its tests, vectors and fuzz targets)
- `tools/` (the `qub-verify` CLI)
- `standalone/` (the reference viewer)
- `Cargo.toml`, `Cargo.lock`, `rustfmt.toml`

Pull requests that touch them are still welcome — they are reviewed
here, applied upstream, and arrive back with the next sync commit
(`Sync from lagstyr/qub@<rev>`). The PR is then closed with a pointer to
that commit.

Everything else — `README.md`, `.github/`, `deny.toml`,
`rust-toolchain.toml`, this file — is maintained directly in this
repository and can be merged here.

## Most valuable contributions

- **Independent implementations.** A reader or verifier written from
  `protocol/PROTOCOL.md` alone, in any language, that agrees with the
  test vectors in `crates/qub-core/tests/vectors/`. Disagreements are
  bugs in the spec or in `qub-core`, and we want to hear about both.
- **Specification review.** Ambiguities, under-specified edge cases, or
  places where the spec and `qub-core` disagree.
- **Vectors.** New cases for the existing vector files.

## Before opening a PR

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The lint policy is strict (`clippy::all` + `clippy::pedantic` deny) and
protocol types use hand-written canonical CBOR — never add serde derives
to them.

## Security issues

Do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
