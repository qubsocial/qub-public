# Security Policy

qub's value is that its guarantees are provable: content cannot be read
before its unlock time, and cannot be altered without detection. A
vulnerability here can undermine claims people have already relied on,
so we treat reports accordingly.

## Reporting a vulnerability

**Please do not open a public issue.** Email **support@qub.social** with
the subject prefix `[SECURITY]`. A PGP key is published at
<https://qub.social/.well-known/security.txt>, or can be requested by
email. You can also use GitHub's private vulnerability reporting on this
repository.

Please include a description and impact, reproduction steps or a proof
of concept, the affected path, and the commit you tested.

We aim to acknowledge within 3 business days (Sydney time), assess
within 10, and coordinate disclosure — by default within 90 days of the
report or on release of a fix, whichever is first. Reporters are
credited with permission.

## In scope

- `protocol/PROTOCOL.md` — any flaw in the specified construction.
- `crates/qub-core` — premature decryption; altering content or bound
  metadata while `body_hash` / `qub_id` still verify; canonical-CBOR
  parsing differentials; signature verification bypass; round-binding
  bypass; outer-wrapper (AES-256-GCM) misuse.
- `tools/qub-verify` — any input it reports as verified that the
  protocol requires rejecting.
- `standalone/` — the same, plus script injection from qub content or
  leakage of the link key off the page.

## Out of scope

qub.social's hosted services are covered by the policy at
<https://qub.social/.well-known/security.txt>, not this repository.
Vulnerabilities in drand, Arweave or third-party crates should go to
those projects (tell us too if qub is affected).
