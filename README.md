# qub — public reference implementation

**qub** seals a message so that nobody — not its author, not qub.social,
not anyone — can read it before a chosen moment, and so that anyone can
prove afterwards exactly what was sealed. It combines
[drand](https://drand.love) timelock encryption, content-addressed
commitments (SHA3-256), optional post-quantum authorship signatures
(ML-DSA-65, FIPS 204), and permanent storage on
[Arweave](https://arweave.org).

This repository exists so that **the protocol outlives the company.**
Everything needed to read and verify a qub is here, under Apache-2.0,
with no dependency on qub.social or any server it runs:

| Path | What it is |
|---|---|
| [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) | The normative specification — wire format, hashing, seal/unlock procedures, verification |
| [`crates/qub-core`](crates/qub-core) | The Rust reference implementation of the protocol (native + `wasm32`) |
| [`tools/qub-verify`](tools/qub-verify) | Offline CLI that verifies a `.qub` export bundle end to end (PROTOCOL.md §11, §17) |
| [`standalone/`](standalone) | A single-file, dependency-free web page that recovers a qub from Arweave + drand in any browser |

## Recovering a qub without qub.social

A qub link looks like `https://qub.social/c/<tx_id>#<key>`. The
`<tx_id>` is an Arweave transaction id; the part after `#` (present only
for **private** qubs) is the AES-256-GCM key that unwraps the stored
bytes. Public qubs have no `#` part. Everything else comes from public
infrastructure: the stored bytes from any Arweave gateway, and the
decryption key from the drand network once the unlock time has passed.

### In a browser

```sh
git clone https://github.com/qubsocial/qub-public
cd qub-public
python3 -m http.server 8000
# open http://localhost:8000/standalone/
```

The page first runs its self-tests (it should report
`11 / 11 self-tests verified`), then accepts a qub link — from any host —
or a bare `tx_id` under **Phase 4**. It fetches the bytes and the drand
round signature, verifies the round binding, body hash and `qub_id`, and
shows the body. The key in the link never leaves the page.

The page is plain HTML + JavaScript with one vendored library
(`standalone/lib/tlock-bundle.js`, a bundle of
[tlock-js](https://github.com/drand/tlock-js)); it has no build step and
can be hosted anywhere static files can.

It does **not** verify ML-DSA-65 authorship signatures or
transparency-log proofs — signed qubs are labelled "present but not
verified". Use `qub-verify` for those.

### From the command line

`qub-verify` checks a `.qub` export bundle — the self-contained file a
qub's holder can download — entirely offline:

```sh
cargo run --release -p qub-verify -- --help
cargo run --release -p qub-verify -- path/to/message.qub
```

It verifies the drand BLS round signature carried in the bundle, the
round binding, the body hash, the `qub_id` binding, and authorship /
cosigner signatures; given the bundle's Arweave anchor with
`--anchor <DataItem>`, it also verifies the transparency-log proof.
`--json` emits a machine-readable report. Exit code `0` means verified.

### By hand

Everything above is specified in
[`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) — §8 (unlock), §11
(third-party verification), §13 (the outer wrapper) and §14 (test
vectors). A third implementation needs nothing else.

## Building

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it
on first use.

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check -p qub-core --target wasm32-unknown-unknown --locked
```

Headless test of the standalone page (Arweave and drand are mocked from
the pinned fixture; no network needed beyond installing the browser):

```sh
npm install --no-save playwright@1.56.1
npx playwright install chromium
node standalone/selftest.mjs
```

Test vectors in `crates/qub-core/tests/vectors/` are shared with qub's
TypeScript implementation; `standalone_pipeline_v1.json` is produced by
an independent JavaScript generator and unlocked by `qub-core` in its
test suite.

## How this repository is maintained

`protocol/`, `crates/`, `tools/`, `standalone/`, `Cargo.toml`,
`Cargo.lock` and `rustfmt.toml` are **mirrored** from qub's private
development repository and are overwritten on each sync — the sync
commit names the upstream revision. Issues and pull requests against
them are welcome; accepted changes are applied upstream and arrive here
with the next sync. Everything else (this README, CI, policies) is
maintained here directly. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
