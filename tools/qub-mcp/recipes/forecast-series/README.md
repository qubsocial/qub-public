# Recipe: a declared forecast series with receipts

Publish one manifest and three forecasts — four qubs — so that someone else can later check, without trusting you or qub, **what** you forecast and that each forecast **existed before its deadline**.

It fits inside the free Builder trial (10 qubs; this uses 4) and needs nothing but the two binaries in this package.

## What you end up with

- A **manifest** that declares the series before any outcome is known: three slots, each with a question, the place the outcome will be read, a deadline and a reveal time.
- Three **forecasts**, one per slot, each unreadable until its reveal time.
- A **report** that says, per slot, whether a forecast was on time, late, missing, or not checkable — including the ones that make you look bad.

Everything is published as a *public* qub: time-locked, but not link-gated. That is deliberate. It is what lets a recipient tie the sealed bytes to an Arweave transaction and read that transaction's block time from gateways qub does not run.

## What this does and does not show

It shows that particular sealed bytes are committed by an Arweave transaction that gateways qub does not run place in a block before your deadline, and — after reveal — that those bytes decrypt to your forecast.

It does not show that your forecast is right, that you made no other series, or that you did not keep a copy of your own answer. The block time is an upper bound under the assumption that the agreeing gateways report the chain correctly; it is not a wall-clock measurement, and the thresholds the tools apply are provisional. Outcomes in a report are whatever the person running it supplies.

## Before you start

1. **A trial key.** Sign in at `/developer` on qub.social, choose *Try Builder free*, and copy the key it shows you once. (If enrolment is not open, that page says so.)

1. **The binaries.**

   ```bash
   cargo install --locked --git https://github.com/qubsocial/qub-public qub-mcp
   ```

   This installs `qub-mcp` and `qub-forecast-series` side by side.

1. **The environment.** Publishing is off unless you turn it on:

   ```bash
   export QUB_API_KEY=qub_sk_...
   export QUB_MCP_ALLOW_CREATE=true
   ```

## Steps

### 1. Write a plan

```bash
qub-forecast-series example --plan plan.json
```

This writes a three-slot plan whose outcomes anyone can check and nobody can know in advance: whether the last hex digit of a future [drand](https://drand.love) beacon is even or odd. The first deadline is two hours away (`--first-deadline-in <seconds>` changes that); each forecast reveals thirty minutes after its deadline, at the moment its beacon is published.

Open `plan.json` and change the `answer` fields to your own forecasts — or replace the questions altogether. The file holds your answers in plain text: it is your copy, and it stays on your machine.

**Leave room before each deadline.** A qub is acknowledged at once, but its transaction then has to be posted, mined and buried several blocks deep before the tools will call it evidenced, and the deadline comparison keeps a margin on top. How long that takes has not been measured, so nobody can tell you what is enough. Minutes are not; choose deadlines you can afford to wait a long time before.

### 2. Check it

```bash
qub-forecast-series check --plan plan.json
```

Nothing is sealed or sent. It refuses a plan that breaks a rule — a slot that reveals before its deadline, a manifest that would become readable only after the first deadline, a duplicate slot — and warns about tight deadlines.

### 3. Publish

```bash
qub-forecast-series submit --plan plan.json
```

The manifest goes first, then each forecast, which names the manifest's transaction. Progress is written to `plan.state.json` after every step.

If it stops — a crash, a dropped connection, a rate limit it gave up waiting for — **run the same command again**. It continues where it stopped and never publishes a qub twice. This is four of your ten trial qubs; publishing is permanent.

**Do not edit `plan.json` once you have run `submit`.** What is published carries the plan's terms and cannot be changed, so the runner records a digest of the plan in `plan.state.json` before its first upload and refuses `submit`, `status` and `report` if the plan no longer matches. A moved deadline would otherwise be checked against qubs that never declared it. To change the terms, start a new series with a new `series_id`.

### 4. Wait for evidence

```bash
qub-forecast-series status --plan plan.json
```

For each qub it prints the lock state, the timing state and the verdict against that qub's deadline:

```text
manifest: locked · timing not_on_chain · before deadline: unknown
slot `one`: locked · timing pending · before deadline: unknown
slot `two`: locked · timing evidenced · before deadline: before · block time 1791650000
```

*Accepted is not evidenced.* Right after `submit` everything reads `not_on_chain`. Run `status` again until each line reads `evidenced` and `before`. A line that settles on `not_before` or `too_close` means that forecast missed its deadline; the report will say so, and it should.

### 5. Report

After the reveal times have passed:

```bash
qub-forecast-series report --plan plan.json --outcomes outcomes.json
```

The report scores a slot (`match` / `no_match`) only when the manifest's `scoring` starts with the token `exact_match`, the one rule it implements: the counted answer equals the outcome you supply. Under any other scoring text the outcome is echoed and left `unscored`.

`outcomes.json` maps slot ids to what actually happened, for example `{ "one": "even", "two": "odd", "three": "odd" }`. For the example plan, fetch each slot's `outcome_source` and look at the last character of `randomness`.

The report gives each slot a status — `on_time`, `late`, `timing_unknown`, `missing`, `invalid`, `ambiguous` — and says `complete: true` only if the manifest was evidenced before the first deadline and every slot has a counted on-time forecast.

The manifest comes first in more than one sense. Until the manifest's own transaction is evidenced, the report judges nothing against it — every slot reads `timing_unknown` — because the slots and deadlines would otherwise rest on whatever bytes the service handed over.

## Giving someone the receipt

Send them the manifest's link and the forecasts' links from `plan.state.json`. They need no key and no account:

- With an MCP client: `verify_forecast_series` with those links, or `read_qub` on any one of them.
- Without one: `read_qub` returns a `.qub` bundle per forecast; `qub-verify --timing --deadline <unix> <file.qub>` checks the content offline and the storage block time against the gateways, using no qub service at all.

Every result states its own claim in words (`timing.claim`). Quote that, not more.

## Doing the same thing from an agent

The runner only calls MCP tools; an agent can call them directly:

1. `create_qub` with `visibility: "public"`, the manifest body and its reveal time.
1. `create_qub` for each forecast, with `manifest_tx_id` set to the manifest's `tx_id`.
1. `check_status` with `deadline` until `timing.deadline.verdict` is `before`.
1. `verify_forecast_series` once the forecasts have revealed.

The body formats are in the [qub-mcp README](../../README.md#forecast-series).
