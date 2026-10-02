---
authority: L
status: current
reviewed-on: 2026-10-02
cadence: null
coupled-to:
  - tools/qub-mcp/src/**
---

# qub-mcp

MCP (Model Context Protocol) server for qub — enables AI agents to create, read, and check the status of time-locked qubs.

Plaintext is encrypted locally using the same `qub-core` cryptographic library as the web app. **Plaintext never leaves your machine.**

## Tools

### `create_qub`

Create a new time-locked qub with client-side sealing.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `body` | string | yes | Message content (UTF-8 plaintext or restricted Markdown) |
| `unlock_at` | number | yes | Unix timestamp (seconds) when the message becomes readable |
| `sender_label` | string | no | Decorative sender label |
| `intent` | string | no | One of `announcement`, `thesis`, `prediction`, `letter`, `secret`, `commitment`, `proof`. Attached to the upload as the Arweave `Intent` tag — feeds the viewer's `?from={intent}` viral-loop CTA, the per-intent OG card description, and intent-aware lifecycle email subjects. Unknown values are rejected by the MCP server before the upload request goes out. |

Returns `tx_id` (the content-addressed storage transaction identifier), `qub_id`, `drand_round`, `delivery_url`, `wrapper_key_b64url`, and `content_size`. The `delivery_url` includes the AES-256-GCM wrapper key K as a URL fragment (`#<base64url(K)>`, Protocol §13.6), so it is immediately shareable; qub does not persist K on this MCP upload path. The viewer still fetches stored bytes and the public drand signature, but needs no further secret exchange. For embeds, pass the full `delivery_url` through the `src` attribute (see below); a tx id alone cannot open a private wrapped qub.

`reply_to` (parent qub_id, for reply-chain qubs) is not yet exposed via MCP — agents that need to author reply qubs should use the HTTP API directly. Tracked as a follow-up.

Requires `QUB_API_KEY` to be set.

> **Publishing is gated.** A successful create is paid and irreversible at the application layer: the exact bytes are durably acknowledged, appended to the transparency log, and scheduled for permanent-storage publication. An AI agent can be steered by prompt injection in any document it processes, so `create_qub` is **disabled by default**. The operator must set `QUB_MCP_ALLOW_CREATE` to a truthy value (`1`, `true`, `yes`, `on`) to enable it; `read_qub` and `check_status` are unaffected. `unlock_at` is also capped at a future horizon (default one year, override with `QUB_MCP_MAX_UNLOCK_HORIZON_SECS`) so an injected prompt cannot schedule content to surface far in the future.

### `read_qub`

Fetch a qub's full status and content (if unlocked).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delivery_url` | string | one input form | Full private delivery URL, including `#<base64url(K)>` (preferred) |
| `tx_id` | string | alternate form | Storage transaction ID; use together with `key_base64url` |
| `key_base64url` | string | alternate form | 32-byte wrapper key in unpadded base64url; required with `tx_id` |

The tool fetches the private OuterWrapper bytes, unwraps locally, and returns countdown metadata while locked. Once unlocked, it returns locally decrypted content inside explicit untrusted-data delimiters plus `qub_bundle_b64url`, a portable `.qub` bundle (Protocol §17). Base64url-decode it and run `qub-verify <file>` (or `qub-verify --base64url <token>`) to verify content integrity, round binding, and signatures without qub infrastructure. The embedded drand signature proves that the bound round elapsed; proving when the ciphertext already existed requires a separately verified storage or anchored-log proof.

### `check_status`

Check qub timing without fetching full content.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delivery_url` | string | one input form | Full private delivery URL, including its fragment key |
| `tx_id` | string | alternate form | Storage transaction ID; use together with `key_base64url` |
| `key_base64url` | string | alternate form | Wrapper key; required with `tx_id` |

Returns `status` ("locked" or "unlocked"), `unlock_at`, `time_remaining_seconds`, `drand_round`, and `tx_id`.

## Embedding qubs

Use the full delivery URL returned by `create_qub` as the `src` attribute of the `<qub-embed>` web component. For an MCP-created private qub, the fragment is essential because it carries K:

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

## Protocol

- **MCP version**: 2024-11-05
- **Transport**: JSON-RPC 2.0 over stdin/stdout
- **Encryption**: drand timelock (BLS12-381 IBE on quicknet, 3s rounds)
- **Serialisation**: Canonical CBOR (RFC 8949)
- **Storage**: synchronous durable object/outbox storage, an attempted `/upload` transparency-log append whose receipt is conditional, and deferred posting of the individual permanent-storage transaction

## How it works

1. `create_qub` builds a `ComposeQub` draft from the provided parameters
1. Calls `qub_core::seal::seal()` to encrypt the content using drand timelock encryption
1. Wraps the sealed CBOR with AES-256-GCM using a fresh local K, then base64-encodes and uploads the wrapper via `POST /api/v1/upload`
1. Returns the storage transaction id and a shareable fragment-bearing delivery URL

The drand quicknet chain (genesis 1692803367, period 3s) determines which round corresponds to the unlock time. The message can only be decrypted once drand publishes the signature for that round.
