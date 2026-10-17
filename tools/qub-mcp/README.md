---
authority: L
status: current
reviewed-on: 2026-10-11
cadence: null
coupled-to:
  - tools/qub-mcp/src/**
---

# qub-mcp

MCP (Model Context Protocol) server for qub — enables AI agents to create, read, and check the status of time-locked qubs, and to check a declared forecast series.

Plaintext is encrypted locally using the same `qub-core` cryptographic library as the web app. **Plaintext is never sent to the qub service**; `read_qub` returns decrypted content to the MCP's caller.

A qub is **private by default**: wrapped under a key that exists only in its delivery URL. Public mode is explicit and per qub (`visibility: "public"`): the qub is still unreadable until it unlocks, but it is not link-gated. See [Public and private](#public-and-private).

Three different things can be true of a qub, and the tools report them separately — none implies another:

| | What it means | Where it is reported |
|---|---|---|
| **Reveal** | The drand round the qub is locked to has been published | `status`: `locked` / `unlocked` |
| **Content** | The decrypted body matches the commitment sealed into the qub | `content.state` (from `read_qub`, after unlock) |
| **Timing evidence** | Independent Arweave gateways place the qub's own storage transaction in a block, which bounds when the sealed bytes existed | `timing.state` — see [Timing evidence](#timing-evidence) |

An accepted upload is none of the three.

## Tools

### `create_qub`

Create a new time-locked qub with client-side sealing.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `body` | string | yes | Message content (UTF-8 plaintext or restricted Markdown). At most 10,240 bytes (10 KB) through this tool, whatever the key's plan; a longer body is refused before anything is sent. |
| `unlock_at` | number | yes | Unix timestamp (seconds) when the message becomes readable |
| `visibility` | string | no | `private` (default) or `public`. Anything else is refused. See [Public and private](#public-and-private). Permanent, and part of the operation identity. |
| `sender_label` | string | no | Decorative sender label |
| `intent` | string | no | One of `announcement`, `thesis`, `prediction`, `letter`, `secret`, `commitment`, `proof`. Attached to the upload as the Arweave `Intent` tag — feeds the viewer's `?from={intent}` viral-loop CTA, the per-intent OG card description, and intent-aware lifecycle email subjects. Unknown values are rejected by the MCP server before the upload request goes out. |
| `operation_id` | string | no | `^[A-Za-z0-9_-]{8,64}$`. Identity of this create operation. Omit it and identical requests resume one operation; pass a new value to deliberately create a separate qub with the same content. See [Restart safety](#restart-safety-and-the-operation-journal). |
| `allow_republish` | boolean | no | Default `false`. Explicit consent to a possible **second paid publication** of this request. Consulted only where `create_qub` would otherwise refuse: `needs_explicit_recovery` ([another idempotency scope](#key-rotation-and-idempotency-scope)) and `corrupt_operation_record` ([a quarantined journal record](#a-damaged-journal-record)). |

Returns `operation_id`, `resumed` (`true` when the result came from an earlier, journaled attempt), `visibility`, `tx_id` (the id of the qub's own storage transaction), `qub_id`, `drand_round`, `delivery_url`, `wrapper_key_b64url` (`null` for a public qub), `content_size`, `unlock_at`, and an `evidence_note` saying that an accepted create is not yet evidence of when the qub existed. A result with `"state": "pending"` means the server is still processing the upload: call `create_qub` again later with the same arguments. A result with `"recovered_from_quarantine": true` was rebuilt from a [damaged journal record](#a-damaged-journal-record): it carries `tx_id`, `qub_id`, `quarantined_record` and a `warning`, plus `delivery_url` and `wrapper_key_b64url` when the key survived (`null` when it did not). For a private qub the `delivery_url` includes the AES-256-GCM wrapper key K as a URL fragment (`#<base64url(K)>`, Protocol §13.6), so it is immediately shareable; the qub service never receives K on this MCP upload path — only the local operation journal keeps a copy. The viewer still fetches stored bytes and the public drand signature, but needs no further secret exchange. For embeds, pass the full `delivery_url` through the `src` attribute (see below); a tx id alone cannot open a private wrapped qub. A public qub's `delivery_url` has no fragment and is complete as it stands.

A server refusal is returned as `upload_rejected` with the server's `status`, its `server_code` (for example `TRIAL_RATE_LIMITED` or `TRIAL_QUBS_EXHAUSTED`) and, when the server sent `Retry-After`, `retry_after_secs`. The operation stays journaled; repeat the call to resume it.

`reply_to` (parent qub_id, for reply-chain qubs) is not yet exposed via MCP — agents that need to author reply qubs should use the HTTP API directly. Tracked as a follow-up.

Requires `QUB_API_KEY` to be set.

> **Publishing is gated.** A successful create is paid (or spends trial allowance) and irreversible at the application layer: the exact bytes are durably acknowledged, a transparency-log append is attempted, and an individual permanent-storage transaction is scheduled. An AI agent can be steered by prompt injection in any document it processes, so `create_qub` is **disabled by default**. The operator must set `QUB_MCP_ALLOW_CREATE` to a truthy value (`1`, `true`, `yes`, `on`) to enable it; `read_qub` and `check_status` are unaffected. `unlock_at` is also capped at a future horizon (default one year, override with `QUB_MCP_MAX_UNLOCK_HORIZON_SECS`) so an injected prompt cannot schedule content to surface far in the future.

### `read_qub`

Fetch a qub's status, its timing evidence and — once unlocked — its content. Works for public and private qubs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delivery_url` | string | one input form | Delivery URL. A private qub's must include `#<base64url(K)>`; a public qub's has no fragment |
| `tx_id` | string | alternate form | Storage transaction ID. Enough on its own for a public qub |
| `key_base64url` | string | with `tx_id`, private only | 32-byte wrapper key in unpadded base64url |
| `deadline` | number | no | Unix seconds. Adds `timing.deadline.verdict`: is the storage block time before this? |
| `check_timing` | boolean | no | Default `true`. `false` skips the gateway lookups (`timing.state` is then `not_checked`) |

The tool fetches the stored bytes (see [Reads and the read allowance](#reads-and-the-read-allowance)) and decides public or private **from the bytes**, not from what the caller sent: bytes that parse as an `OuterWrapper` are private and need K; bytes that parse as a bare `SealedQubCbor` are public and need none; the visibility byte sealed inside must agree with the shape found. A private qub read without its key fails with `wrapper_key_required`; with the wrong key, `unwrap_failed`. Nothing is decrypted in either case. A key supplied for a public qub is ignored and the result says so.

Every result carries `status`, `visibility`, `tx_id`, `qub_id`, `unlock_at`, `time_remaining_seconds`, `drand_round`, `timing` and `tx_binding`.

`tx_binding` answers a question the other fields do not: are the bytes that were read the bytes `tx_id` stores? They come from the qub service, and only the chain can tie them to the id. It is `evidenced` when the gateways show the transaction stores exactly these bytes, `not_established` otherwise, and `mismatch` when they show it stores others. On a mismatch `read_qub` fails with `artifact_mismatch` and returns no content; `check_status`, which shows none, reports it. A `verified` body with `tx_binding: not_established` is internally consistent and nothing more.

While locked, `content.state` is `locked`. Once unlocked, the tool decrypts locally and adds `content.state` (`verified` when the body matches its commitment and any authorship signature and co-signature are valid; otherwise `signature_invalid` or `cosignature_invalid`), the body inside explicit untrusted-data delimiters, the author-supplied `created_at` (labelled as not being evidence), and `qub_bundle_b64url`, a portable `.qub` bundle (Protocol §17). Base64url-decode it and run `qub-verify <file>` (or `qub-verify --base64url <token>`) to verify content integrity, round binding, and signatures without qub infrastructure; add `--timing` to check the storage transaction against the gateways yourself.

### `check_status`

Check a qub's lock status and timing evidence without decrypting its content.

Same parameters as `read_qub`, the same public/private rules (a private qub still needs its key) and the same read accounting. Returns `status`, `visibility`, `tx_id`, `qub_id`, `unlock_at`, `time_remaining_seconds`, `drand_round` and `timing`. It never fetches the drand beacon.

### `verify_forecast_series`

Check a declared forecast series — one manifest qub and the qubs offered as its forecasts. See [Forecast series](#forecast-series).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `manifest` | string | yes | Transaction ID or delivery URL of the manifest |
| `forecasts` | string[] | yes | Transaction IDs or delivery URLs of the qubs offered as forecasts (at most 32) |
| `outcomes` | object | no | Slot id → observed outcome. Reporter-supplied; echoed and labelled as not verified |

Each artifact is read through the same path as `read_qub`, so each costs one read under an API key.

### `list_pending_operations`

No parameters. Lists journaled `create_qub` operations that have not completed (state `prepared` — sealed but never sent — or `sent` — outcome not yet confirmed), oldest first, with `operation_id`, `state`, `created_at`, `updated_at`, `qub_id_hex`, `unlock_at` and `visibility`. It also names record files it could not parse (`unreadable`) and quarantined ones (`quarantined`). It **never** returns wrapper keys, and never creates the state directory. Resume an operation by calling `create_qub` again with the same arguments (or the same `operation_id`).

## Public and private

| | Private (default) | Public (`visibility: "public"`) |
|---|---|---|
| Stored bytes | `OuterWrapper` — the sealed qub encrypted under K | the bare `SealedQubCbor` |
| Readable before `unlock_at` | no | no |
| Readable after `unlock_at` | by anyone holding the delivery URL with its `#key` | by anyone holding the transaction id |
| Delivery URL | `…/c/<tx_id>#<base64url(K)>` | `…/c/<tx_id>` |
| Discoverable on permanent storage | no (byte-indistinguishable, untagged) | yes (tagged `Visibility: public`) |
| Timing evidence from the tools | not offered in this release | yes |

Choose public when someone else must be able to check, without trusting you or qub, that the sealed bytes existed before a deadline — a forecast, a bid, a pre-registration. Choose private for everything else. The choice is made at creation, is permanent, and is part of the operation identity: the same body requested publicly and privately are two different operations, and an `operation_id` cannot be reused across the two.

## Timing evidence

Every accepted qub is scheduled as its own Arweave transaction, and `tx_id` is that transaction's id. For a **public** qub, `read_qub` and `check_status` ask Arweave gateways — not qub — about that transaction and report what they find as `timing`:

| `timing.state` | Meaning | Carries a time? |
|---|---|---|
| `evidenced` | Enough gateways agree, deeply enough, on a block containing a transaction that commits to exactly the bytes read | yes: `block_time` |
| `pending` | Seen, but not yet mined, not yet deep enough, or not yet reported by enough gateways. Ask again later | no |
| `not_on_chain` | Enough gateways answered and none knows the transaction. It has not been posted yet, or never was | no |
| `unavailable` | Too few gateways gave a usable answer | no |
| `conflict` | Gateways report different blocks or different transactions for this id. Never settled by majority | no |
| `invalid` | The transaction with this id commits to other bytes: what was read is not what it stores | no |
| `unsupported_private` | The qub is private | no |
| `not_checked` | `check_timing` was `false` | no |

`deadline` must be Unix **seconds**; a value that can only be milliseconds is refused, because every block would be "before" it. With `deadline`, `timing.deadline.verdict` is `before` (the block time clears the deadline by more than the margin), `too_close` (earlier, but within the margin), `not_before` (at or after it), or `unknown` (no evidenced time). Only `evidenced` can yield `before`.

**What is checked, and what is assumed.** Checked locally, trusting no one: the bytes hash to the transaction's data root, the transaction's signature covers that root, and the id is the hash of that signature. Read from gateways, and therefore assumed: which transaction an id names, that a block contains it, and that block's timestamp and depth. A light client cannot validate Arweave consensus, so no single gateway is believed — but the claim is never stronger than "the agreeing gateways report the chain correctly". None of the default gateways is run by qub, but they are not shown to be separate sources: two of the three are AR.IO gateway nodes, software that by default answers chain queries by forwarding them to another node, so "two gateways agree" may be one upstream answering twice. A gateway that has not seen the transaction lowers the count; it does not veto the ones that have. Listing the same server twice does not help: origins are compared after normalisation (default ports, a trailing dot, every loopback name, and one canonical spelling per IP address — other spellings are refused), though two public names for one server cannot be told apart. A byte mismatch needs no quorum: one verified header for the id is proof by itself, so `invalid` is decided before anything else. A block timestamp is chosen by its miner within the network's rules: it is an evidence bound, not a wall-clock measurement. `timing.claim` states the claim in words; quote that, not more.

**The thresholds are provisional.** Two agreeing gateways, ten confirmations and a 600-second margin are conservative placeholders. They are the values approved for the pilot, as provisional: no publication-to-confirmation latency has been measured for this product yet, and they are to be revisited when one has. Every result prints the policy it applied.

**What is never timing evidence:** an accepted `create_qub`, the service's own acknowledgement or receipt, the author-supplied `created_at`, an elapsed drand round, or a timestamp relayed by the qub API. A transaction that was signed and acknowledged but never mined is `not_on_chain`.

The gateways consulted default to `arweave.net`, `ar-io.dev` and `permagate.io`; `QUB_ARWEAVE_GATEWAYS` replaces the list. Gateway lookups send no API key and are not reads. A recipient can run the same check without this server: `qub-verify --timing [--deadline <unix>] <file.qub>`.

## Forecast series

A forecast series is a convention carried inside ordinary qub bodies as JSON (`"schema": "qub.forecast-series/v1"`); it needs no protocol field and no server feature.

- The **manifest** declares, before any outcome is known, what will be forecast: a `series_id`, a `title`, the `scoring` rule, `"revisions": "first_on_time"`, and one **slot** per forecast — `slot`, `question`, `outcome_source`, `deadline` and `reveal_at` (never before the deadline, so no forecast can be read while its slot is still open).
- **Times are Unix seconds.** A `deadline` or `reveal_at` that can only be milliseconds is refused with the rest of the body: any block would be "before" it.
- **Scoring.** `scoring` is text for people, with one exception: if it starts with the token `exact_match` (alone, or followed by `:` and a description), a report scores each counted answer against the outcome supplied to it by string equality (`match` / `no_match`). Under any other text the report echoes the outcome as `unscored` and says `rules.scoring_applied: "none"`; it never applies a rule it does not implement.
- Each **forecast** names the manifest by `manifest_tx_id` and fills one slot: `series_id`, `slot`, the slot's `question` and `outcome_source` restated, an `answer`, and optionally `probability_pct` (0–100).

Unknown members are refused in both, so a body cannot carry a second, unreported answer.

`verify_forecast_series` reads the manifest and the offered qubs and reports each declared slot:

| Slot `status` | Meaning |
|---|---|
| `on_time` | One entry is evidenced before the deadline and counted |
| `late` | The only entries were stored at or after the deadline |
| `timing_unknown` | An entry exists, but its storage time is not established (or is too close to call) |
| `invalid` | The entry contradicts its slot: another outcome source or question, or a different unlock time |
| `ambiguous` | Two on-time entries share a block; no order can be established |
| `awaiting_reveal` | A still-locked qub that unlocks at this slot's reveal time was offered |
| `open` / `missing` | No entry, before / after the deadline |

A missed, late or contradictory forecast is shown, never dropped. Under the only revision rule in v1, the first on-time entry counts and any later one is listed as `superseded`. `complete` is `true` only when the manifest itself is evidenced before the first deadline and every slot has a counted entry.

**The manifest must be evidenced before anything is judged.** Its slots and deadlines are read from the qub service, like everything else. Until the manifest's own transaction is shown, on chain, to store exactly those bytes, every slot reads `timing_unknown` and the manifest's `state` is `unbound`: a service that answered with a different manifest could otherwise move a deadline. If the gateways show the transaction stores other bytes, the manifest is `invalid` and no slot is assigned. A forecast names its manifest by transaction id, which is what ties the two together. A forecast whose authorship signature or co-signature fails is unreadable to the report and counts for nothing.

**The same goes for each forecast.** One whose transaction the gateways show stores other bytes than were read is set aside with no slot and no answer, as is one that could not be read. While such an artifact is outstanding, an empty slot past its deadline reads `timing_unknown` instead of `missing`: the report cannot know the unread artifact was not that slot's.

The report covers the slots one manifest declares and the artifacts it was given. It cannot show that the author made no other manifest, and it does not verify outcomes.

### The runnable recipe

`qub-forecast-series` is a second binary in this package that drives `qub-mcp` over stdio, exactly as an agent would, to publish and check one series — four qubs for the three-slot example, which leaves six of a ten-qub trial. The walkthrough is in [`recipes/forecast-series/`](recipes/forecast-series/README.md):

```bash
qub-forecast-series example --plan plan.json  # write a ready-to-run three-slot plan
qub-forecast-series check   --plan plan.json  # validate offline; nothing is sent
qub-forecast-series submit  --plan plan.json  # publish the manifest, then each forecast
qub-forecast-series status  --plan plan.json  # lock state + timing evidence per qub
qub-forecast-series report  --plan plan.json [--outcomes outcomes.json]
```

`submit` is resumable: it records progress in `<plan>.state.json`, gives every qub a fixed `operation_id`, waits out a rate limit the server asks it to wait out, and stops with exit code `1` on anything else — run it again and it continues, never publishing a qub twice. Even with the state file lost, the `qub-mcp` journal resumes each operation.

## Restart safety and the operation journal

`create_qub` generates the wrapper key K locally, and K is the only way to read a private qub. Each create is therefore a **journaled operation**: before any network call, the server writes the sealed upload body (ciphertext only — never the plaintext), K (a public qub has none), and the operation's `Idempotency-Key` to a record on disk. It then asks the service which idempotency scope the API key belongs to (`GET /api/v1/upload/operation`, which spends no read), journals that `scope_id`, and only then sends the upload with that key. The record is marked `completed` once the server confirms a `tx_id`. If the scope cannot be obtained — the service is unreachable, say — **nothing is sent**: the record stays `prepared` and the call fails with `lookup_failed`; repeat it later.

The `Idempotency-Key` is `qub-<qub_id_hex>-<nonce>`: the qub id, then 32 hex characters drawn at random **once**, when the operation is first journaled. Every send, resend and lookup of that operation reads the key back from its record, so a retry never draws a new one. The random part is what makes the key name one operation. The qub id alone does not: it is derived from the content, the unlock time and the second of sealing, so two installations sealing the same message in the same second derive the same qub id for two different artifacts, each wrapped under its own K. With a key built from the qub id only, the service would answer the second with the first one's transaction — which the second's K cannot open. (A record journaled by an earlier `qub-mcp` carries `qub-<qub_id_hex>`, with no nonce; it still resumes, under exactly that key.)

If the process is killed, the connection drops, or the response is lost, call `create_qub` again with **the same arguments**. The operation id defaults to a keyed SHA3-256 of `(body, unlock_at, intent, sender_label)` — plus a fixed tag when the request is public — so an identical call finds the same record and resumes it:

- a `completed` record returns the stored result (`"resumed": true`) without any network call;
- otherwise the server is asked what happened to that `Idempotency-Key` (`GET /api/v1/upload/operation`): a published operation returns its `tx_id`; an in-flight one returns `"state": "pending"` and is never re-sent; an unknown or abandoned one is re-sent with the **same body and the same `Idempotency-Key`** — but only when the current key is in the [same idempotency scope](#key-rotation-and-idempotency-scope) the upload was first sent under, which is what makes the resend a replay of one publication rather than a second one;
- if the lookup itself fails, nothing is re-sent — retry later.

A `published` answer completes only an operation that **was sent** (the record is marked `sent`, durably, before the upload leaves, so a lost acknowledgement is always resolved this way). A record still `prepared` never sent anything, so a publication the service reports under its `Idempotency-Key` is somebody else's upload — a different artifact, which this operation's K cannot open. That is refused with `operation_conflict`: the foreign `tx_id` is not returned, nothing is sent, the record is left as it is, and the identical call keeps failing the same way, with or without `allow_republish`. Call `create_qub` again with a distinct `operation_id` to seal and publish the request under a new key.

Identical requests therefore publish **once**, unless you say otherwise: to publish the same content twice on purpose, give each call its own `operation_id`. Reusing an `operation_id` with a different body, unlock time, intent, sender label or visibility is rejected (`operation_id_conflict`).

Two `qub-mcp` processes sharing one state directory cannot run the same operation at once. Each takes a per-operation file lock (`ops/.<operation_id>.lock`) before reading the journal; the one that does not get it returns `operation_in_progress`, having sealed and sent nothing. Call again shortly with the same arguments to collect the other process's result.

Errors from a journaled operation are JSON with a `code` and the `operation_id`. Two mean that a resend could not be proven to be a replay. In both, nothing was sealed or sent, repeating the identical call keeps failing the same way, and only `"allow_republish": true` goes ahead:

- `needs_explicit_recovery` — the operation was sent under another idempotency scope. See [Key rotation and idempotency scope](#key-rotation-and-idempotency-scope).
- `corrupt_operation_record` — the operation's journal record is unreadable. See [A damaged journal record](#a-damaged-journal-record).

### Key rotation and idempotency scope

The service treats a repeated `Idempotency-Key` as the same upload only within one **idempotency scope**: the account's grant for **trial** keys, the individual key for **paid** keys. It names the scope with an opaque `scope_id` — identical for every key of one trial grant, different between two grants, between a grant and a paid key, and between two paid keys. `create_qub` journals the `scope_id` an upload is first sent under and compares it on every resume:

- **Same scope** — for example a rotated trial key on the same grant — resumes normally: the resend is a replay.
- **Different scope** — a rotated paid key, a key of another trial grant, a trial key in place of a paid one or the reverse — is refused with `needs_explicit_recovery`. In the new scope the server cannot see the original upload, so it answers `unknown` whether or not that upload was published, and a resend there would be a **second paid publication**. Check the original key's account first; to re-upload anyway, repeat the call with `"allow_republish": true`.

An operation recorded as `prepared` was never sent, so it can be sent under any key (unless the service already reports a publication under its `Idempotency-Key` — see `operation_conflict` above). A record journaled by an older `qub-mcp`, before `scope_id` existed (or against a service that names no scope), resumes automatically only under the very same API key; any other key needs `allow_republish`.

### A damaged journal record

A record that cannot be parsed is renamed to `<operation_id>.json.corrupt` (never deleted, never overwritten) and stays attached to its operation: while that file is in `ops/`, the operation id is **not** free, and calling `create_qub` again with the same arguments does not start a new operation.

`create_qub` first reads what it can out of the damaged bytes. A record cut short in its tail is no longer valid JSON, but its `Idempotency-Key`, state and wrapper key are written ahead of the upload body (the largest field, deliberately last) and so sit near the top and usually survive:

- If the `Idempotency-Key` survives, the server is asked about it. If the upload **was published**, the call succeeds: it returns the `tx_id` with `"recovered_from_quarantine": true`, and the `delivery_url` and `wrapper_key_b64url` if the key survived too. Repeating the call returns the same answer; nothing is ever sent. The one exception is a damaged record that still reads `"state": "prepared"`: it never sent its upload, so that publication is not its own and the call fails with `operation_conflict`, as it does for a readable record.
- Otherwise the call fails with `corrupt_operation_record`. The error names the quarantined file and says whether the wrapper key is **intact in that file** (it is then in its `wrapper_key_b64url` field — the tool never prints it in an error) or **lost**, in which case the qub's content is unrecoverable if it was published.

To seal and publish a **new** qub for the same request, pass `"allow_republish": true` (a second paid publication if the original was published, for example under another key) or use a different `operation_id`. To clear the state, move the quarantined file out of `ops/` — do not delete it while it holds a key you need. If the damaged record still shows that it was written for a different request than the one now using its `operation_id`, the call is an `operation_id_conflict`, as it would be for a readable record.

### The state directory

The journal lives in a per-user state directory:

1. `QUB_MCP_STATE_DIR`, if set;
2. otherwise `$XDG_STATE_HOME/qub-mcp`;
3. otherwise `$HOME/.local/state/qub-mcp`.

```text
<state dir>/            0700
  device_id             0600  installation device id (32 lowercase hex), sent as `device_id` on upload
  operation_key         0600  random 32-byte key for default operation ids
  ops/                  0700
    <operation_id>.json 0600  one record per operation
    <operation_id>.json.corrupt   an unreadable record, moved aside (may still hold its key)
```

**This directory contains decryption keys.** Every record of a private qub holds its wrapper key, so anyone who can read the directory can read those qubs once they unlock. (A public qub's record holds no key; it is written with a higher record version so that an older `qub-mcp` answers "upgrade" instead of misreading it.) Keep it private, exclude it from shared backups and synced folders, and treat it like a credential store. The default operation id is keyed with `operation_key` so that the file names themselves cannot be used to test guesses of a low-entropy sealed message (a prediction, a yes/no answer) before it unlocks.

**If this directory is lost, so is everything it remembered.** Deleting it, restoring an older copy, or pointing `QUB_MCP_STATE_DIR` somewhere else leaves `qub-mcp` with no record of the operations it journaled there, and a new `operation_key`. An identical `create_qub` is then a **new operation**: it publishes again and spends another qub, and the result says so (`"resumed": false`, a new `tx_id`) — it is never reported as a resume, and the earlier publication is not mentioned because nothing local knows of it. The service cannot join the two either: each operation's `Idempotency-Key` carries a random nonce that lived only in the lost record. An earlier **private** qub whose record is gone cannot be opened by anyone who did not keep its delivery URL. Losing only `operation_key`, or only one record file, has the same effect for the operations concerned. Nothing here can be recovered by the tool; keep the directory, and keep the delivery URLs you are given.

Writes are atomic (temp file, fsync, rename, fsync the directory). At startup, `completed` records older than 30 days are pruned; unresolved and unreadable records are never pruned. The directory is created only when `create_qub` first runs.

## Reads and the read allowance

With `QUB_API_KEY` set, `read_qub` and `check_status` read through the authenticated API (`GET /api/v1/qub/<tx_id>`). **Each call counts one read against the key's plan allowance.** If the server refuses — for example `402` with a `TRIAL_*` code such as `TRIAL_READS_EXHAUSTED` when a trial's read allowance is spent, `403`, `429` (with `retry_after` when the server sends `Retry-After`), or `503` — the tool returns an error carrying the server's `code` and `status`. It never falls back to another route after a refusal.

Without `QUB_API_KEY`, reads use the anonymous public route (`GET /api/v1/qub/<tx_id>/bytes`) and send no credentials. That route rejects trial credentials (`TRIAL_CREDENTIAL_ON_PUBLIC_ROUTE`), so the MCP never sends a key to it. A recipient needs no key to read or check a public qub, and can still do both after its author's trial is exhausted.

Arweave gateway and drand lookups go to those services directly. They carry no API key and never count as reads.

## Embedding qubs

Use the full delivery URL returned by `create_qub` as the `src` attribute of the `<qub-embed>` web component. For a private qub, the fragment is essential because it carries K:

```html
<script async src="https://qub.social/embed/v1.js"></script>
<qub-embed src="https://qub.social/c/<tx_id>#<base64url(K)>"></qub-embed>
```

The loader upgrades the custom element into a sandboxed iframe and threads the fragment into the iframe's own URL without sending it to the server. The iframe fetches the stored bytes, fetches the drand signature once unlock arrives, and unwraps/decrypts in the viewer's browser. A public qub uses the same `src` form without a fragment. The legacy `qub="<tx_id>"` attribute cannot open a private qub and should not be emitted.

During countdown, the iframe re-polls `/api/v1/qub/<tx_id>/meta` every 30 seconds so the watching count climbs live (matching the qub.social viewer). The countdown's 1-second tick and the 30-second meta refresh are independent intervals, so the seconds digit stays smooth across refreshes. As each second elapses only the digit that actually changed cross-fades — the rest stay still — so the embedded timer reads as a calm pulse rather than a flicker. State-kind transitions (loading → countdown → unlocking → revealed) fade the incoming card in over 150ms; within-state re-renders don't re-fade. The lime dot next to the "qub" footer wordmark pulses gently during countdown so the embed never reads as frozen. The watching line itself reads "N watching this reveal" rather than the older "N people watching" — active framing, communicates what the number represents. Polling halts in the last minute before unlock to avoid racing the reveal transition.

Transient fetch or decrypt failures (drand beacon slow, Arweave gateway hiccup) surface a friendly error card inside the iframe with a **Try again** button and a collapsible "Show details" disclosure preserving the raw exception text. Agents that expose the embed to end-users don't need to handle retries themselves — the iframe recovers in-place without a full page reload. The footer CTA is also intent-aware: if the `create_qub` call set an intent (e.g. `prediction`), the embed's "seal your own" button reads "Make your own prediction" rather than the generic label.

For agents building "create + share" flows, deriving the embed snippet from `delivery_url` preserves the private wrapper key while covering both the shareable link and publisher surface.

**Pinned loader URL for production.** The `https://qub.social/embed.js` path is an alias for the current major version. Agents emitting long-lived embed snippets should prefer `https://qub.social/embed/v1.js` — it pins to the v1 attribute surface + postMessage contract, so a future v2 ships without disrupting already-published embeds. The v1 attribute and security contract is summarised in this section so the public mirror has no private-repository documentation dependency.

**Locale passthrough.** The embed honours the publisher's host-page `<html lang>` automatically, and accepts a `<qub-embed lang="…">` attribute (BCP 47) for explicit override. `qub-mcp` itself is locale-neutral — locale flows from the viewer's browser or the publisher's page, not from the MCP call — so agents don't need to plumb a locale parameter through the `create_qub` side. Partial locales fall back to English via the same candidate chain the server uses for notify-emails.

## Setup

### Install

Install the tested release source from qub's public mirror:

```bash
cargo install --locked --git https://github.com/qubsocial/qub-public qub-mcp
```

Cargo places the `qub-mcp` binary in its normal binary directory (usually
`~/.cargo/bin`). To build a checkout instead, run
`cargo build --release -p qub-mcp` from the public workspace root.

### Configuration

Add to your MCP client config (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "qub": {
      "command": "qub-mcp",
      "env": {
        "QUB_API_KEY": "qub_sk_...",
        "QUB_BASE_URL": "https://qub.social",
        "QUB_MCP_ALLOW_CREATE": "false"
      }
    }
  }
}
```

This copy-paste configuration is intentionally read-only. Change
`QUB_MCP_ALLOW_CREATE` to `true` only after reviewing the publishing and prompt
injection warning above.

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QUB_API_KEY` | For `create_qub` | — | API key (`qub_sk_...` format) |
| `QUB_BASE_URL` | No | `https://qub.social` | Base URL for API calls |
| `QUB_MCP_ALLOW_CREATE` | To enable `create_qub` | _unset_ (publishing disabled) | Truthy value (`1`/`true`/`yes`/`on`) opts the server in to publishing. `read_qub` / `check_status` work regardless. |
| `QUB_MCP_MAX_UNLOCK_HORIZON_SECS` | No | `31536000` (1 year) | Maximum future horizon for a `create_qub` `unlock_at`. |
| `QUB_MCP_STATE_DIR` | No | `$XDG_STATE_HOME/qub-mcp`, else `$HOME/.local/state/qub-mcp` | Operation journal and installation device id. Contains wrapper keys — see [The state directory](#the-state-directory). |
| `QUB_ARWEAVE_GATEWAYS` | No | `https://arweave.net,https://ar-io.dev,https://permagate.io` | Comma-separated Arweave gateway origins consulted for [timing evidence](#timing-evidence). Each must be an `https` origin; at least two distinct gateways must agree. |
| `QUB_DRAND_ENDPOINTS` | No | the public drand mirrors | Comma-separated drand HTTP origins. A round signature is verified against the pinned quicknet key before it decrypts anything, so a wrong endpoint can deny a read but cannot forge one. |
| `QUB_MCP_BIN` | No | the `qub-mcp` beside `qub-forecast-series`, else on `PATH` | Read by `qub-forecast-series` only: which `qub-mcp` to drive. |

## Protocol

- **MCP version**: 2024-11-05
- **Transport**: JSON-RPC 2.0 over stdin/stdout
- **Encryption**: drand timelock (BLS12-381 IBE on quicknet, 3s rounds)
- **Serialisation**: Canonical CBOR (RFC 8949)
- **Storage**: synchronous durable object/outbox storage, an attempted `/upload` transparency-log append whose receipt is conditional, and deferred posting of the individual permanent-storage transaction

## How it works

1. `create_qub` builds a `ComposeQub` draft from the provided parameters
1. Calls `qub_core::seal::seal()` to encrypt the content using drand timelock encryption
1. Private: wraps the sealed CBOR with AES-256-GCM using a fresh local K. Public: uses the sealed CBOR as it is
1. Journals the exact upload body, K (if any) and a fresh per-operation `Idempotency-Key` to the state directory
1. Asks `GET /api/v1/upload/operation` for the key's idempotency `scope_id` and journals it
1. Uploads the bytes via `POST /api/v1/upload` with that `Idempotency-Key` (and `is_public: true` for a public qub)
1. Returns the storage transaction id and a shareable delivery URL — fragment-bearing when private — and marks the operation completed

The drand quicknet chain (genesis 1692803367, period 3s) determines which round corresponds to the unlock time. The message can only be decrypted once drand publishes the signature for that round.
