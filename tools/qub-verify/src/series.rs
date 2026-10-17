//! Declared forecast series: one manifest qub and the forecasts it announces.
//!
//! A series is an application convention carried entirely inside ordinary qub
//! bodies as JSON — no protocol field, wire type or server feature is involved.
//! The **manifest** declares, before any outcome is known, which forecasts will
//! be made: a slot per forecast with its question, where the outcome will be
//! read, the submission deadline and the reveal time. Each **forecast** names
//! the manifest by transaction id and fills one slot.
//!
//! [`evaluate_series`] turns a manifest, the artifacts offered as its
//! forecasts and each one's timing evidence into a report that keeps what a
//! cherry-picked showcase would hide: a slot nobody filled is `missing`, an
//! entry stored after its deadline is `late`, an entry whose timing cannot be
//! established says so, an entry that contradicts its slot is `invalid`, and a
//! second entry for a slot is listed as `superseded`, never dropped.
//!
//! **Scope of the claim.** A report covers the slots one manifest declares and
//! the artifacts it was given. It cannot show that the author made no other
//! manifest, and it does not verify outcomes: an outcome is whatever the
//! reporter supplies, and is labelled that way.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::timing::{DeadlineVerdict, TimingEvidence, TimingState};

/// Schema identifier carried by every manifest and forecast body.
pub const SCHEMA: &str = "qub.forecast-series/v1";
/// Schema identifier of a report.
pub const REPORT_SCHEMA: &str = "qub.forecast-series-report/v1";
/// The only revision rule in v1: the first entry evidenced before the slot's
/// deadline counts; any later entry is shown as superseded.
pub const REVISIONS_FIRST_ON_TIME: &str = "first_on_time";
/// Most slots a manifest may declare.
pub const MAX_SLOTS: usize = 16;
/// Longest free-text field (question, outcome source, answer, title), in
/// Unicode scalar values.
pub const MAX_TEXT_CHARS: usize = 500;
/// Longest scoring-rule text, in Unicode scalar values.
pub const MAX_SCORING_CHARS: usize = 1000;
/// Length of an Arweave transaction id.
const TX_ID_LEN: usize = 43;

/// One declared forecast slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// Slot identifier, unique within the manifest.
    pub slot: String,
    /// The question the forecast answers.
    pub question: String,
    /// Where the outcome will be read once known.
    pub outcome_source: String,
    /// Unix seconds by which the forecast must be independently evidenced.
    pub deadline: i64,
    /// Unix seconds at which the forecast becomes readable. Never before
    /// `deadline`, so no forecast can be read while it can still be submitted.
    pub reveal_at: i64,
}

/// A series manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Series identifier chosen by the author.
    pub series_id: String,
    /// Human title.
    pub title: String,
    /// How forecasts will be scored, in the author's words. Echoed, never
    /// executed.
    pub scoring: String,
    /// The declared slots.
    pub slots: Vec<Slot>,
}

/// A forecast for one slot of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forecast {
    /// The series the forecast belongs to.
    pub series_id: String,
    /// Transaction id of the manifest it answers.
    pub manifest_tx_id: String,
    /// The slot it fills.
    pub slot: String,
    /// The slot's question, restated so one forecast is self-describing.
    pub question: String,
    /// The slot's outcome source, restated for the same reason.
    pub outcome_source: String,
    /// The forecast itself.
    pub answer: String,
    /// Optional probability the author assigns to `answer`, in whole percent.
    pub probability_pct: Option<u8>,
}

/// True for a series or slot identifier: 1–64 of `[a-z0-9-]`, not starting
/// or ending with a hyphen.
fn is_identifier(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

/// True for the shape of an Arweave transaction id.
fn is_tx_id(text: &str) -> bool {
    text.len() == TX_ID_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A JSON object with exactly the members `allowed` (`required` first, then
/// optional ones), or why not. Unknown members are refused: a body that could
/// carry a second, unreported answer is not a forecast.
fn object_with<'a>(
    value: &'a Value,
    what: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{what} is not a JSON object"))?;
    for name in required {
        if !object.contains_key(*name) {
            return Err(format!("{what} is missing `{name}`"));
        }
    }
    if let Some(unknown) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(format!("{what} has an unknown member `{unknown}`"));
    }
    Ok(object)
}

/// A non-empty string member of at most `max` characters, without control
/// characters.
fn text_member(object: &Map<String, Value>, name: &str, max: usize) -> Result<String, String> {
    let text = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{name}` is not a string"))?;
    if text.trim().is_empty() {
        return Err(format!("`{name}` is empty"));
    }
    if text.chars().count() > max {
        return Err(format!("`{name}` is longer than {max} characters"));
    }
    if text.chars().any(char::is_control) {
        return Err(format!("`{name}` contains a control character"));
    }
    Ok(text.to_owned())
}

/// A Unix-seconds member. A value that can only be milliseconds is refused:
/// as a deadline it would put every block "before" it.
fn time_member(object: &Map<String, Value>, name: &str) -> Result<i64, String> {
    object
        .get(name)
        .and_then(Value::as_i64)
        .and_then(|time| crate::timing::check_deadline(time).ok())
        .ok_or_else(|| format!("`{name}` is not a plausible integer of Unix seconds"))
}

/// Check the `schema` and `kind` members every body carries.
fn check_kind(object: &Map<String, Value>, kind: &str) -> Result<(), String> {
    if object.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(format!("`schema` is not {SCHEMA:?}"));
    }
    if object.get("kind").and_then(Value::as_str) != Some(kind) {
        return Err(format!("`kind` is not {kind:?}"));
    }
    Ok(())
}

impl Manifest {
    /// Parse and validate a manifest body.
    ///
    /// # Errors
    ///
    /// A description of the first rule the body breaks.
    pub fn parse(body: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(body).map_err(|_| "manifest is not JSON".to_owned())?;
        let object = object_with(
            &value,
            "manifest",
            &[
                "schema",
                "kind",
                "series_id",
                "title",
                "revisions",
                "scoring",
                "slots",
            ],
            &[],
        )?;
        check_kind(object, "manifest")?;
        if object.get("revisions").and_then(Value::as_str) != Some(REVISIONS_FIRST_ON_TIME) {
            return Err(format!("`revisions` is not {REVISIONS_FIRST_ON_TIME:?}"));
        }
        let series_id = text_member(object, "series_id", 64)?;
        if !is_identifier(&series_id) {
            return Err("`series_id` must be 1-64 of [a-z0-9-]".to_owned());
        }
        let raw_slots = object
            .get("slots")
            .and_then(Value::as_array)
            .ok_or_else(|| "`slots` is not an array".to_owned())?;
        if raw_slots.is_empty() || raw_slots.len() > MAX_SLOTS {
            return Err(format!("`slots` must hold 1 to {MAX_SLOTS} entries"));
        }
        let mut slots: Vec<Slot> = Vec::with_capacity(raw_slots.len());
        for raw in raw_slots {
            let slot = Slot::parse(raw)?;
            if slots.iter().any(|known| known.slot == slot.slot) {
                return Err(format!("slot `{}` is declared twice", slot.slot));
            }
            slots.push(slot);
        }
        Ok(Self {
            series_id,
            title: text_member(object, "title", MAX_TEXT_CHARS)?,
            scoring: text_member(object, "scoring", MAX_SCORING_CHARS)?,
            slots,
        })
    }

    /// The body to seal for this manifest.
    #[must_use]
    pub fn to_body(&self) -> String {
        json!({
            "schema": SCHEMA,
            "kind": "manifest",
            "series_id": self.series_id,
            "title": self.title,
            "revisions": REVISIONS_FIRST_ON_TIME,
            "scoring": self.scoring,
            "slots": self.slots.iter().map(Slot::to_json).collect::<Vec<_>>(),
        })
        .to_string()
    }

    /// The earliest slot deadline — the moment the manifest must predate.
    #[must_use]
    pub fn first_deadline(&self) -> i64 {
        self.slots
            .iter()
            .map(|slot| slot.deadline)
            .min()
            .unwrap_or(i64::MAX)
    }
}

impl Slot {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = object_with(
            value,
            "slot",
            &[
                "slot",
                "question",
                "outcome_source",
                "deadline",
                "reveal_at",
            ],
            &[],
        )?;
        let slot = text_member(object, "slot", 64)?;
        if !is_identifier(&slot) {
            return Err("a slot id must be 1-64 of [a-z0-9-]".to_owned());
        }
        let deadline = time_member(object, "deadline")?;
        let reveal_at = time_member(object, "reveal_at")?;
        if reveal_at < deadline {
            return Err(format!(
                "slot `{slot}` reveals before its deadline, so it could be read while still open"
            ));
        }
        Ok(Self {
            slot,
            question: text_member(object, "question", MAX_TEXT_CHARS)?,
            outcome_source: text_member(object, "outcome_source", MAX_TEXT_CHARS)?,
            deadline,
            reveal_at,
        })
    }

    fn to_json(&self) -> Value {
        json!({
            "slot": self.slot,
            "question": self.question,
            "outcome_source": self.outcome_source,
            "deadline": self.deadline,
            "reveal_at": self.reveal_at,
        })
    }
}

impl Forecast {
    /// Parse and validate a forecast body.
    ///
    /// # Errors
    ///
    /// A description of the first rule the body breaks.
    pub fn parse(body: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(body).map_err(|_| "forecast is not JSON".to_owned())?;
        let object = object_with(
            &value,
            "forecast",
            &[
                "schema",
                "kind",
                "series_id",
                "manifest_tx_id",
                "slot",
                "question",
                "outcome_source",
                "answer",
            ],
            &["probability_pct"],
        )?;
        check_kind(object, "forecast")?;
        let manifest_tx_id = text_member(object, "manifest_tx_id", TX_ID_LEN)?;
        if !is_tx_id(&manifest_tx_id) {
            return Err("`manifest_tx_id` is not a transaction id".to_owned());
        }
        let probability_pct = match object.get("probability_pct") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|pct| u8::try_from(pct).ok())
                    .filter(|pct| *pct <= 100)
                    .ok_or_else(|| {
                        "`probability_pct` is not an integer from 0 to 100".to_owned()
                    })?,
            ),
        };
        Ok(Self {
            series_id: text_member(object, "series_id", 64)?,
            manifest_tx_id,
            slot: text_member(object, "slot", 64)?,
            question: text_member(object, "question", MAX_TEXT_CHARS)?,
            outcome_source: text_member(object, "outcome_source", MAX_TEXT_CHARS)?,
            answer: text_member(object, "answer", MAX_TEXT_CHARS)?,
            probability_pct,
        })
    }

    /// The body to seal for this forecast.
    #[must_use]
    pub fn to_body(&self) -> String {
        let mut body = json!({
            "schema": SCHEMA,
            "kind": "forecast",
            "series_id": self.series_id,
            "manifest_tx_id": self.manifest_tx_id,
            "slot": self.slot,
            "question": self.question,
            "outcome_source": self.outcome_source,
            "answer": self.answer,
        });
        if let Some(pct) = self.probability_pct {
            body["probability_pct"] = json!(pct);
        }
        body.to_string()
    }
}

/// What could be read of an artifact offered to a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryContent {
    /// Still time-locked: nothing but its unlock time is known.
    Locked,
    /// Unlocked, and its content verified against its commitment.
    Revealed(String),
    /// Could not be read or did not verify; the reason is shown as given.
    Unreadable(String),
}

/// One artifact offered to a report, with everything already established
/// about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its storage transaction id.
    pub tx_id: String,
    /// The unlock time sealed into it, when the artifact could be parsed.
    pub unlock_at: Option<i64>,
    /// What could be read of it.
    pub content: EntryContent,
    /// Its timing evidence. `None` when none was sought or none is offered
    /// for this kind of artifact (a private one).
    pub timing: Option<TimingEvidence>,
}

impl Entry {
    fn verdict(&self, deadline: i64) -> DeadlineVerdict {
        self.timing
            .as_ref()
            .map_or(DeadlineVerdict::Unknown, |timing| {
                timing.deadline_verdict(deadline)
            })
    }

    fn block_time(&self) -> Option<i64> {
        self.timing
            .as_ref()
            .and_then(TimingEvidence::bound)
            .map(|bound| bound.block_time)
    }

    fn timing_state(&self) -> &'static str {
        self.timing
            .as_ref()
            .map_or("not_checked", |timing| timing.state().label())
    }

    fn timing_json(&self) -> Value {
        let mut timing = json!({ "state": self.timing_state() });
        if let Some(time) = self.block_time() {
            timing["block_time"] = json!(time);
        }
        if let Some(evidence) = &self.timing
            && evidence.state() != TimingState::Evidenced
        {
            timing["reason"] = json!(evidence.reason());
        }
        timing
    }
}

/// How one entry stands against the slot it claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// Evidenced before the deadline and consistent with the slot.
    OnTime,
    /// Evidenced at or after the deadline.
    Late,
    /// Consistent with the slot, but its timing is not established.
    TimingUnknown,
    /// Contradicts the slot it claims.
    Invalid,
}

/// A revealed forecast matched to a slot.
struct Candidate<'a> {
    entry: &'a Entry,
    forecast: Forecast,
    standing: Standing,
    reason: Option<String>,
}

/// Why nothing is judged against a manifest that is not bound to its
/// transaction.
const UNBOUND_REASON: &str = "the manifest read for this series is not shown to be what its \
    transaction stores, so the slot and deadline it declares cannot be relied on";

fn judge_candidate<'a>(
    entry: &'a Entry,
    forecast: Forecast,
    slot: &Slot,
    manifest_bound: bool,
) -> Candidate<'a> {
    if !manifest_bound {
        return Candidate {
            entry,
            forecast,
            standing: Standing::TimingUnknown,
            reason: Some(UNBOUND_REASON.to_owned()),
        };
    }
    let mismatch = if forecast.outcome_source != slot.outcome_source {
        Some("names a different outcome source than its slot declares")
    } else if forecast.question != slot.question {
        Some("restates a different question than its slot declares")
    } else if entry.unlock_at != Some(slot.reveal_at) {
        Some("unlocks at a different time than its slot declares")
    } else {
        None
    };
    let (standing, reason) = mismatch.map_or_else(
        || match entry.verdict(slot.deadline) {
            DeadlineVerdict::Before => (Standing::OnTime, None),
            DeadlineVerdict::NotBefore => (
                Standing::Late,
                Some("its storage block is at or after the deadline".to_owned()),
            ),
            DeadlineVerdict::TooClose => (
                Standing::TimingUnknown,
                Some("its storage block is too close to the deadline to call".to_owned()),
            ),
            DeadlineVerdict::Unknown => (
                Standing::TimingUnknown,
                Some(format!(
                    "no independent storage time is established ({})",
                    entry.timing_state()
                )),
            ),
        },
        |reason| (Standing::Invalid, Some(reason.to_owned())),
    );
    Candidate {
        entry,
        forecast,
        standing,
        reason,
    }
}

/// `deadline` is `None` when the manifest that declares it is not bound to
/// its transaction: no verdict is given against a deadline nobody can vouch
/// for.
fn candidate_json(candidate: &Candidate, state: &str, deadline: Option<i64>) -> Value {
    let verdict = deadline.map_or(DeadlineVerdict::Unknown, |at| candidate.entry.verdict(at));
    let mut entry = json!({
        "tx_id": candidate.entry.tx_id,
        "state": state,
        "answer": candidate.forecast.answer,
        "timing": candidate.entry.timing_json(),
        "deadline_verdict": verdict.label(),
    });
    if let Some(pct) = candidate.forecast.probability_pct {
        entry["probability_pct"] = json!(pct);
    }
    if let Some(reason) = &candidate.reason {
        entry["reason"] = json!(reason);
    }
    entry
}

/// What limits the verdicts a slot may be given.
#[derive(Clone, Copy)]
struct Judging {
    /// The manifest is shown to be what its transaction stores.
    manifest_bound: bool,
    /// An offered artifact could not be read as what its transaction stores.
    unresolved: bool,
    /// The manifest declares the one scoring rule this report applies.
    exact_match: bool,
}

/// Evaluate one slot. Returns its JSON and its status label.
fn slot_report(
    slot: &Slot,
    mut candidates: Vec<Candidate>,
    awaiting_reveal: bool,
    outcome: Option<&String>,
    now: i64,
    judging: Judging,
) -> (Value, &'static str) {
    let Judging {
        manifest_bound,
        unresolved,
        exact_match,
    } = judging;
    // Deterministic order: earliest evidenced first, unevidenced last.
    candidates.sort_by(|a, b| {
        let key = |c: &Candidate| {
            (
                c.entry.block_time().unwrap_or(i64::MAX),
                c.entry.tx_id.clone(),
            )
        };
        key(a).cmp(&key(b))
    });
    let on_time: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.standing == Standing::OnTime)
        .map(|(index, _)| index)
        .collect();
    // Two on-time entries in one block have no order anyone can establish.
    let tied = on_time.len() > 1
        && candidates[on_time[0]].entry.block_time() == candidates[on_time[1]].entry.block_time();
    let counted = if tied { None } else { on_time.first().copied() };
    let has = |standing: Standing| candidates.iter().any(|c| c.standing == standing);

    let status = if !manifest_bound {
        // Not even `open` or `missing`: those are read off the deadline too.
        "timing_unknown"
    } else if tied {
        "ambiguous"
    } else if counted.is_some() {
        "on_time"
    } else if has(Standing::Late) {
        "late"
    } else if has(Standing::TimingUnknown) {
        "timing_unknown"
    } else if has(Standing::Invalid) {
        "invalid"
    } else if awaiting_reveal {
        "awaiting_reveal"
    } else if now < slot.deadline {
        "open"
    } else if unresolved {
        // An artifact was offered that could not be read. It may be this
        // slot's forecast, so "nothing was submitted" is not known.
        "timing_unknown"
    } else {
        "missing"
    };

    let entries: Vec<Value> = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let state = match candidate.standing {
                Standing::OnTime if Some(index) == counted => "counted",
                Standing::OnTime if tied => "tied",
                Standing::OnTime => "superseded",
                Standing::Late => "late",
                Standing::TimingUnknown => "timing_unknown",
                Standing::Invalid => "invalid",
            };
            candidate_json(candidate, state, manifest_bound.then_some(slot.deadline))
        })
        .collect();

    let mut report = json!({
        "slot": slot.slot,
        "question": slot.question,
        "outcome_source": slot.outcome_source,
        "deadline": slot.deadline,
        "reveal_at": slot.reveal_at,
        "status": status,
        "revised": on_time.len() > 1,
        "counted_tx_id": counted.map(|index| candidates[index].entry.tx_id.clone()),
        "entries": entries,
    });
    if let Some(outcome) = outcome {
        // Only the one rule this report implements is ever applied. Under
        // any other declared rule the outcome is echoed and left unscored:
        // a comparison the manifest did not declare is not its result.
        let result = counted.filter(|_| exact_match).map_or("unscored", |index| {
            if candidates[index].forecast.answer.trim() == outcome.trim() {
                "match"
            } else {
                "no_match"
            }
        });
        report["outcome"] = json!({
            "value": outcome,
            "provenance": "supplied by the reporter; not verified",
            "result": result,
        });
    }
    (report, status)
}

/// Where an artifact offered to a report belongs.
enum Placement {
    /// A revealed forecast for the declared slot at this index.
    Slot(usize, Forecast),
    /// Still time-locked: it cannot be assigned to a slot yet.
    Sealed,
    /// Not a forecast for this manifest; the reason is reported.
    SetAside(String),
    /// Could not be read as what its transaction stores, so it may or may
    /// not be a forecast for this manifest; the reason is reported.
    Unresolved(String),
}

/// Decide where one offered artifact belongs.
fn place(entry: &Entry, manifest_tx_id: &str, declared: &Manifest) -> Placement {
    // Bytes the chain shows are NOT this transaction's say nothing about
    // it: not which slot it fills, and not what it answers.
    if entry.timing.as_ref().map(TimingEvidence::state) == Some(TimingState::Invalid) {
        return Placement::Unresolved(
            "the bytes read for this artifact are not the bytes its transaction stores".to_owned(),
        );
    }
    let body = match &entry.content {
        EntryContent::Revealed(body) => body,
        EntryContent::Locked => return Placement::Sealed,
        EntryContent::Unreadable(reason) => {
            return Placement::Unresolved(format!("unreadable: {reason}"));
        },
    };
    let forecast = match Forecast::parse(body) {
        Ok(forecast) => forecast,
        Err(reason) => return Placement::SetAside(format!("not a forecast: {reason}")),
    };
    let same_series = forecast.series_id == declared.series_id;
    let same_manifest = forecast.manifest_tx_id == manifest_tx_id;
    if !(same_series && same_manifest) {
        return Placement::SetAside("a forecast for a different series or manifest".to_owned());
    }
    match declared
        .slots
        .iter()
        .position(|slot| slot.slot == forecast.slot)
    {
        Some(index) => Placement::Slot(index, forecast),
        None => Placement::SetAside(format!(
            "names slot `{}`, which this manifest does not declare",
            forecast.slot
        )),
    }
}

/// The one scoring rule a report applies by itself: the counted answer
/// equals the supplied outcome, ignoring surrounding whitespace.
///
/// A manifest declares it by starting its `scoring` text with this token —
/// alone, or followed by `:` and a description. Any other `scoring` text is
/// prose for people: the report echoes it and scores nothing.
pub const SCORING_EXACT_MATCH: &str = "exact_match";

/// True when `scoring` declares [`SCORING_EXACT_MATCH`].
#[must_use]
pub fn declares_exact_match(scoring: &str) -> bool {
    scoring
        .strip_prefix(SCORING_EXACT_MATCH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
}

/// The scope statement every report carries.
const SCOPE: &str = "This report covers only the slots this manifest declares and only the \
    artifacts it was given. It does not show that no other series or forecasts exist, and it \
    does not verify outcomes.";

/// Every offered artifact, unassigned for one shared reason.
fn set_aside_all(forecasts: &[Entry], reason: &str) -> Value {
    json!(
        forecasts
            .iter()
            .map(|entry| json!({ "tx_id": entry.tx_id, "reason": reason }))
            .collect::<Vec<_>>()
    )
}

/// The offered artifacts, sorted.
struct Assignment<'a> {
    /// Candidates per declared slot, in slot order.
    per_slot: Vec<Vec<Candidate<'a>>>,
    /// Whatever fits no slot, with the reason.
    unassigned: Vec<Value>,
    /// Still time-locked: their slots are unknown until they reveal.
    sealed: Vec<&'a Entry>,
    /// True when an offered artifact could not be read as what its
    /// transaction stores. It might be any slot's forecast, so no empty
    /// slot can be called `missing`.
    unresolved: bool,
}

/// Sort the offered artifacts into the declared slots.
fn assign<'a>(
    manifest: &Entry,
    forecasts: &'a [Entry],
    declared: &Manifest,
    manifest_bound: bool,
) -> Assignment<'a> {
    let mut per_slot: Vec<Vec<Candidate>> = declared.slots.iter().map(|_| Vec::new()).collect();
    let mut unassigned: Vec<Value> = Vec::new();
    let mut sealed: Vec<&Entry> = Vec::new();
    let mut unresolved = false;
    let mut seen: Vec<&str> = vec![&manifest.tx_id];
    for entry in forecasts {
        let placement = if entry.tx_id == manifest.tx_id {
            Placement::SetAside("this is the manifest itself, not a forecast".to_owned())
        } else if seen.contains(&entry.tx_id.as_str()) {
            Placement::SetAside("listed more than once; counted once".to_owned())
        } else {
            seen.push(&entry.tx_id);
            place(entry, &manifest.tx_id, declared)
        };
        let reason = match placement {
            Placement::Slot(index, forecast) => {
                per_slot[index].push(judge_candidate(
                    entry,
                    forecast,
                    &declared.slots[index],
                    manifest_bound,
                ));
                continue;
            },
            Placement::Sealed => {
                sealed.push(entry);
                "still time-locked; its slot is unknown until it reveals".to_owned()
            },
            Placement::SetAside(reason) => reason,
            Placement::Unresolved(reason) => {
                unresolved = true;
                reason
            },
        };
        unassigned.push(json!({
            "tx_id": entry.tx_id,
            "reason": reason,
            "timing": entry.timing_json(),
        }));
    }
    Assignment {
        per_slot,
        unassigned,
        sealed,
        unresolved,
    }
}

/// Build the report for a manifest and the artifacts offered as its forecasts.
///
/// `outcomes` maps slot ids to outcomes supplied by whoever runs the report;
/// `now` is the reporter's clock, used only to tell an `open` slot from a
/// `missing` one.
#[must_use]
pub fn evaluate_series(
    manifest: &Entry,
    forecasts: &[Entry],
    outcomes: &BTreeMap<String, String>,
    now: i64,
) -> Value {
    let mut report = json!({
        "schema": REPORT_SCHEMA,
        "scope": SCOPE,
        "complete": false,
    });

    let parsed = match &manifest.content {
        EntryContent::Revealed(body) => Manifest::parse(body).map_err(|e| ("invalid", e)),
        EntryContent::Locked => Err((
            "locked",
            "the manifest is still time-locked; its slots cannot be read yet".to_owned(),
        )),
        EntryContent::Unreadable(reason) => Err(("unreadable", reason.clone())),
    };
    let declared = match parsed {
        Ok(declared) => declared,
        Err((state, reason)) => {
            report["manifest"] = json!({
                "tx_id": manifest.tx_id,
                "state": state,
                "reason": reason,
                "timing": manifest.timing_json(),
            });
            report["unassigned"] = set_aside_all(
                forecasts,
                "the manifest could not be read, so no slot can be assigned",
            );
            return report;
        },
    };

    // The slots and deadlines are whatever the bytes read for the manifest
    // say. Those bytes come from the same service the forecaster used, so
    // they count only once the manifest's own transaction is shown, on
    // chain, to store exactly them. A forecast names its manifest by
    // transaction id, which is what ties the two together.
    let manifest_state = manifest.timing.as_ref().map(TimingEvidence::state);
    if manifest_state == Some(TimingState::Invalid) {
        report["manifest"] = json!({
            "tx_id": manifest.tx_id,
            "state": "invalid",
            "reason": "the bytes read for the manifest are not the bytes its transaction stores",
            "timing": manifest.timing_json(),
        });
        report["unassigned"] = set_aside_all(
            forecasts,
            "the manifest is not the one its transaction stores, so no slot can be assigned",
        );
        return report;
    }
    let manifest_bound = manifest_state == Some(TimingState::Evidenced);

    let precedes = manifest.verdict(declared.first_deadline());
    report["series_id"] = json!(declared.series_id);
    report["title"] = json!(declared.title);
    let exact_match = declares_exact_match(&declared.scoring);
    report["rules"] = json!({
        "revisions": REVISIONS_FIRST_ON_TIME,
        "scoring": declared.scoring,
        "scoring_applied": if exact_match { SCORING_EXACT_MATCH } else { "none" },
    });
    report["manifest"] = json!({
        "tx_id": manifest.tx_id,
        "state": if manifest_bound { "valid" } else { "unbound" },
        "timing": manifest.timing_json(),
        "precedes_first_deadline": precedes.label(),
    });
    if !manifest_bound {
        report["manifest"]["reason"] = json!(UNBOUND_REASON);
    }

    let Assignment {
        per_slot,
        unassigned,
        sealed,
        unresolved,
    } = assign(manifest, forecasts, &declared, manifest_bound);

    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut slots = Vec::with_capacity(declared.slots.len());
    for (slot, candidates) in declared.slots.iter().zip(per_slot) {
        let awaiting = sealed
            .iter()
            .any(|entry| entry.unlock_at == Some(slot.reveal_at));
        let (slot_json, status) = slot_report(
            slot,
            candidates,
            awaiting,
            outcomes.get(&slot.slot),
            now,
            Judging {
                manifest_bound,
                unresolved,
                exact_match,
            },
        );
        *counts.entry(status).or_insert(0) += 1;
        slots.push(slot_json);
    }
    let all_on_time = counts.get("on_time").copied().unwrap_or(0) == declared.slots.len() as u64;
    report["complete"] = json!(all_on_time && precedes == DeadlineVerdict::Before);
    let mut summary = json!({ "slots": declared.slots.len() });
    for (status, count) in counts {
        summary[status] = json!(count);
    }
    report["summary"] = summary;
    report["slots"] = json!(slots);
    report["unassigned"] = json!(unassigned);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timing::{GatewayOutcome, GatewayReport, HttpReply, TimingPolicy, TxStatus};

    const GENERATED: &str = include_str!("../tests/vectors/arweave_tx_v1.json");
    const MANIFEST_TX: &str = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM";
    const HASH: &str = "w3EayqSpTouZPTkTKaEC2kXQgZj5wQKxae7mbkfxUV0q8Fi8CJw-jacXB85SwoFj";
    const T0: i64 = 1_800_000_000;
    const MARGIN: i64 = TimingPolicy::PROVISIONAL.timestamp_margin_secs;

    fn tx(tag: char) -> String {
        tag.to_string().repeat(43)
    }

    fn slot(id: &str, deadline: i64) -> Slot {
        Slot {
            slot: id.to_owned(),
            question: format!("question {id}"),
            outcome_source: format!("https://outcomes.example/{id}"),
            deadline,
            reveal_at: deadline + 3600,
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            series_id: "demo-series".to_owned(),
            title: "Three forecasts".to_owned(),
            scoring: "exact_match: the answer equals the outcome source's value".to_owned(),
            slots: vec![
                slot("one", T0 + 10_000),
                slot("two", T0 + 20_000),
                slot("three", T0 + 30_000),
            ],
        }
    }

    fn forecast(slot: &Slot, answer: &str) -> Forecast {
        Forecast {
            series_id: "demo-series".to_owned(),
            manifest_tx_id: MANIFEST_TX.to_owned(),
            slot: slot.slot.clone(),
            question: slot.question.clone(),
            outcome_source: slot.outcome_source.clone(),
            answer: answer.to_owned(),
            probability_pct: Some(70),
        }
    }

    /// Timing evidence with the given block time, built through the real
    /// evaluator from a reference-client transaction.
    fn evidenced(block_time: i64) -> TimingEvidence {
        let evidence = judged(block_time, false);
        assert_eq!(evidence.state(), TimingState::Evidenced);
        evidence
    }

    /// The same transaction, deep and agreed — judged against bytes it does
    /// not store.
    fn mismatched() -> TimingEvidence {
        let evidence = judged(T0, true);
        assert_eq!(evidence.state(), TimingState::Invalid);
        evidence
    }

    fn judged(block_time: i64, alter: bool) -> TimingEvidence {
        let fixture: Value = serde_json::from_str(GENERATED).unwrap();
        let signed = &fixture["signed"][0];
        let id = signed["header"]["id"].as_str().unwrap();
        let len = usize::try_from(signed["data_len"].as_u64().unwrap()).unwrap();
        let mut stored: Vec<u8> = (0..len)
            .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
            .collect();
        if alter {
            stored[0] ^= 0x01;
        }
        let ok = |body: String| Ok(HttpReply { status: 200, body });
        let at = |gateway: &str| {
            GatewayReport::confirmed(
                gateway,
                id,
                TxStatus {
                    block_height: 9,
                    block_indep_hash: HASH.to_owned(),
                    confirmations: 99,
                },
                &ok(signed["header"].to_string()),
                &ok(json!({
                    "height": 9, "indep_hash": HASH, "timestamp": block_time, "txs": [id]
                })
                .to_string()),
            )
        };
        crate::timing::evaluate(
            id,
            &stored,
            &[at("https://a"), at("https://b")],
            &TimingPolicy::PROVISIONAL,
        )
    }

    fn not_on_chain() -> TimingEvidence {
        let evidence = crate::timing::evaluate(
            "x",
            b"",
            &[
                GatewayReport::new("https://a", GatewayOutcome::NotFound),
                GatewayReport::new("https://b", GatewayOutcome::NotFound),
            ],
            &TimingPolicy::PROVISIONAL,
        );
        assert_eq!(evidence.state(), TimingState::NotOnChain);
        evidence
    }

    fn manifest_entry(timing: Option<TimingEvidence>) -> Entry {
        Entry {
            tx_id: MANIFEST_TX.to_owned(),
            unlock_at: Some(T0),
            content: EntryContent::Revealed(manifest().to_body()),
            timing,
        }
    }

    fn entry(tag: char, slot: &Slot, answer: &str, block_time: Option<i64>) -> Entry {
        Entry {
            tx_id: tx(tag),
            unlock_at: Some(slot.reveal_at),
            content: EntryContent::Revealed(forecast(slot, answer).to_body()),
            timing: block_time.map(evidenced),
        }
    }

    fn run(manifest: &Entry, forecasts: &[Entry], now: i64) -> Value {
        evaluate_series(manifest, forecasts, &BTreeMap::new(), now)
    }

    fn slot_status(report: &Value, index: usize) -> &str {
        report["slots"][index]["status"].as_str().unwrap()
    }

    /// An entry's timing says why it is not evidenced — and says nothing
    /// extra when it is.
    #[test]
    fn an_entry_explains_timing_that_is_not_evidenced() {
        let unsettled = manifest_entry(Some(not_on_chain())).timing_json();
        assert_eq!(unsettled["state"], "not_on_chain");
        assert!(
            unsettled["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "{unsettled}"
        );
        assert!(unsettled.get("block_time").is_none());

        let settled = manifest_entry(Some(evidenced(T0 - 10_000))).timing_json();
        assert_eq!(settled["state"], "evidenced");
        assert_eq!(settled["block_time"], T0 - 10_000);
        assert!(settled.get("reason").is_none(), "{settled}");

        let unchecked = manifest_entry(None).timing_json();
        assert_eq!(unchecked, json!({ "state": "not_checked" }));
    }

    #[test]
    fn bodies_round_trip() {
        let declared = manifest();
        assert_eq!(Manifest::parse(&declared.to_body()), Ok(declared.clone()));
        let made = forecast(&declared.slots[0], "yes");
        assert_eq!(Forecast::parse(&made.to_body()), Ok(made.clone()));
        let bare = Forecast {
            probability_pct: None,
            ..made
        };
        assert!(!bare.to_body().contains("probability_pct"));
        assert_eq!(Forecast::parse(&bare.to_body()), Ok(bare));
        assert_eq!(declared.first_deadline(), T0 + 10_000);
    }

    /// A complete series: manifest evidenced before the first deadline, one
    /// on-time entry per slot.
    #[test]
    fn a_full_on_time_series_is_complete() {
        let declared = manifest();
        let forecasts = [
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
            entry('b', &declared.slots[1], "no", Some(T0 + 11_000)),
            entry('c', &declared.slots[2], "yes", Some(T0 + 21_000)),
        ];
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert_eq!(report["schema"], REPORT_SCHEMA);
        assert_eq!(report["complete"], true);
        assert_eq!(report["manifest"]["state"], "valid");
        assert_eq!(report["manifest"]["precedes_first_deadline"], "before");
        assert_eq!(report["summary"]["on_time"], 3);
        assert_eq!(report["summary"]["slots"], 3);
        for index in 0..3 {
            assert_eq!(slot_status(&report, index), "on_time");
            assert_eq!(report["slots"][index]["revised"], false);
        }
        assert_eq!(report["slots"][0]["counted_tx_id"], tx('a'));
        assert_eq!(report["slots"][0]["entries"][0]["state"], "counted");
        assert_eq!(report["slots"][0]["entries"][0]["answer"], "yes");
        assert_eq!(report["slots"][0]["entries"][0]["probability_pct"], 70);
        assert_eq!(
            report["slots"][0]["entries"][0]["timing"]["block_time"],
            T0 + 1000
        );
        assert_eq!(report["unassigned"], json!([]));
        assert!(report["scope"].as_str().unwrap().contains("only the slots"));
    }

    /// A missed slot, a late entry and an entry with no established time are
    /// each reported as what they are, and the series is not complete.
    #[test]
    fn misses_late_and_unknown_timing_are_preserved() {
        let declared = manifest();
        let late_time = declared.slots[1].deadline + 5;
        let forecasts = [
            // slot one: never submitted.
            entry('b', &declared.slots[1], "no", Some(late_time)),
            Entry {
                timing: Some(not_on_chain()),
                ..entry('c', &declared.slots[2], "yes", None)
            },
        ];
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert_eq!(report["complete"], false);
        assert_eq!(slot_status(&report, 0), "missing");
        assert_eq!(report["slots"][0]["entries"], json!([]));
        assert_eq!(report["slots"][0]["counted_tx_id"], Value::Null);
        assert_eq!(slot_status(&report, 1), "late");
        assert_eq!(report["slots"][1]["entries"][0]["state"], "late");
        assert_eq!(
            report["slots"][1]["entries"][0]["deadline_verdict"],
            "not_before"
        );
        assert_eq!(slot_status(&report, 2), "timing_unknown");
        assert_eq!(
            report["slots"][2]["entries"][0]["timing"]["state"],
            "not_on_chain"
        );
        assert!(
            report["slots"][2]["entries"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("not_on_chain")
        );
        assert_eq!(report["summary"]["missing"], 1);
        assert_eq!(report["summary"]["late"], 1);
        assert_eq!(report["summary"]["timing_unknown"], 1);
        assert!(report["summary"].get("on_time").is_none());
    }

    #[test]
    fn a_slot_before_its_deadline_is_open_not_missing() {
        let declared = manifest();
        let report = run(&manifest_entry(Some(evidenced(T0))), &[], T0 + 5);
        assert_eq!(slot_status(&report, 0), "open");
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[],
            declared.slots[0].deadline,
        );
        assert_eq!(slot_status(&report, 0), "missing");
        assert_eq!(slot_status(&report, 1), "open");
    }

    /// An entry within the policy margin of its deadline is not counted as
    /// on time, and not called late either.
    #[test]
    fn an_entry_too_close_to_the_deadline_is_not_counted() {
        let declared = manifest();
        let close = declared.slots[0].deadline - MARGIN;
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[entry('a', &declared.slots[0], "yes", Some(close))],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "timing_unknown");
        assert_eq!(
            report["slots"][0]["entries"][0]["deadline_verdict"],
            "too_close"
        );
        // One second earlier clears the margin.
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[entry('a', &declared.slots[0], "yes", Some(close - 1))],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "on_time");
    }

    /// A retrospective revision cannot replace the first on-time entry, and is
    /// shown rather than hidden.
    #[test]
    fn a_revision_is_shown_as_superseded() {
        let declared = manifest();
        let forecasts = [
            entry('z', &declared.slots[0], "no", Some(T0 + 2000)),
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
        ];
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "on_time");
        assert_eq!(report["slots"][0]["revised"], true);
        assert_eq!(report["slots"][0]["counted_tx_id"], tx('a'));
        let entries = report["slots"][0]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["state"], "counted");
        assert_eq!(entries[0]["answer"], "yes");
        assert_eq!(entries[1]["state"], "superseded");
        assert_eq!(entries[1]["answer"], "no");
        // A late revision after an on-time entry stays visible as late.
        let forecasts = [
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
            entry(
                'z',
                &declared.slots[0],
                "no",
                Some(declared.slots[0].deadline + 1),
            ),
        ];
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "on_time");
        assert_eq!(report["slots"][0]["entries"][1]["state"], "late");
        assert_eq!(report["slots"][0]["revised"], false);
    }

    #[test]
    fn two_on_time_entries_in_one_block_are_ambiguous() {
        let declared = manifest();
        let forecasts = [
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
            entry('b', &declared.slots[0], "no", Some(T0 + 1000)),
        ];
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "ambiguous");
        assert_eq!(report["slots"][0]["counted_tx_id"], Value::Null);
        assert_eq!(report["slots"][0]["entries"][0]["state"], "tied");
        assert_eq!(report["slots"][0]["entries"][1]["state"], "tied");
        assert_eq!(report["complete"], false);
    }

    /// An entry that contradicts its slot is invalid whatever its timing.
    #[test]
    fn entries_that_contradict_their_slot_are_invalid() {
        let declared = manifest();
        let slot = &declared.slots[0];
        let with = |edit: &dyn Fn(&mut Forecast)| {
            let mut made = forecast(slot, "yes");
            edit(&mut made);
            Entry {
                tx_id: tx('a'),
                unlock_at: Some(slot.reveal_at),
                content: EntryContent::Revealed(made.to_body()),
                timing: Some(evidenced(T0 + 1000)),
            }
        };
        let wrong_source = with(&|f| f.outcome_source = "https://friendlier.example".into());
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[wrong_source],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "invalid");
        assert!(
            report["slots"][0]["entries"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("outcome source")
        );
        assert_eq!(report["slots"][0]["counted_tx_id"], Value::Null);

        let wrong_question = with(&|f| f.question = "an easier question".into());
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[wrong_question],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "invalid");

        // Readable before the declared reveal time.
        let early_reveal = Entry {
            unlock_at: Some(slot.reveal_at - 1),
            ..with(&|_| {})
        };
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[early_reveal],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "invalid");
        assert!(
            report["slots"][0]["entries"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("unlocks")
        );
        // The unedited entry is on time: the edits are what failed.
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[with(&|_| {})],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "on_time");
    }

    #[test]
    fn foreign_duplicate_and_unreadable_artifacts_are_set_aside() {
        let declared = manifest();
        let other_series = Entry {
            content: EntryContent::Revealed(
                Forecast {
                    series_id: "another-series".into(),
                    ..forecast(&declared.slots[0], "yes")
                }
                .to_body(),
            ),
            ..entry('a', &declared.slots[0], "yes", Some(T0 + 1000))
        };
        let other_manifest = Entry {
            content: EntryContent::Revealed(
                Forecast {
                    manifest_tx_id: tx('Q'),
                    ..forecast(&declared.slots[0], "yes")
                }
                .to_body(),
            ),
            ..entry('b', &declared.slots[0], "yes", Some(T0 + 1000))
        };
        let unknown_slot = Entry {
            content: EntryContent::Revealed(
                Forecast {
                    slot: "nine".into(),
                    ..forecast(&declared.slots[0], "yes")
                }
                .to_body(),
            ),
            ..entry('c', &declared.slots[0], "yes", Some(T0 + 1000))
        };
        let not_a_forecast = Entry {
            content: EntryContent::Revealed("hello".into()),
            ..entry('d', &declared.slots[0], "yes", Some(T0 + 1000))
        };
        let unreadable = Entry {
            content: EntryContent::Unreadable("private artifact: wrapper key required".into()),
            ..entry('e', &declared.slots[0], "yes", None)
        };
        let good = entry('f', &declared.slots[0], "yes", Some(T0 + 1000));
        let forecasts = [
            other_series,
            other_manifest,
            unknown_slot,
            not_a_forecast,
            unreadable,
            good.clone(),
            good,
            manifest_entry(None),
        ];
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        let unassigned = report["unassigned"].as_array().unwrap();
        let reasons: Vec<&str> = unassigned
            .iter()
            .map(|entry| entry["reason"].as_str().unwrap())
            .collect();
        assert_eq!(unassigned.len(), 7, "{reasons:?}");
        assert!(reasons[0].contains("different series"));
        assert!(reasons[1].contains("different series or manifest"));
        assert!(reasons[2].contains("does not declare"));
        assert!(reasons[3].contains("not a forecast"));
        assert!(reasons[4].contains("wrapper key required"));
        assert!(reasons[5].contains("more than once"));
        assert!(reasons[6].contains("manifest itself"));
        // The one good entry is counted exactly once.
        assert_eq!(report["slots"][0]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(slot_status(&report, 0), "on_time");
    }

    #[test]
    fn a_sealed_entry_marks_its_slot_as_awaiting_reveal() {
        let declared = manifest();
        let sealed = Entry {
            tx_id: tx('a'),
            unlock_at: Some(declared.slots[1].reveal_at),
            content: EntryContent::Locked,
            timing: Some(evidenced(T0 + 1000)),
        };
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[sealed],
            declared.slots[1].deadline + 1,
        );
        assert_eq!(slot_status(&report, 0), "missing");
        assert_eq!(slot_status(&report, 1), "awaiting_reveal");
        assert_eq!(slot_status(&report, 2), "open");
        assert!(
            report["unassigned"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("time-locked")
        );
        assert_eq!(report["unassigned"][0]["timing"]["state"], "evidenced");
    }

    /// A manifest stored after the first deadline, or with no established
    /// time, can never make a series complete — even with every slot on time.
    #[test]
    fn the_manifest_must_be_evidenced_before_the_first_deadline() {
        let declared = manifest();
        let forecasts = [
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
            entry('b', &declared.slots[1], "no", Some(T0 + 11_000)),
            entry('c', &declared.slots[2], "yes", Some(T0 + 21_000)),
        ];
        let late = manifest_entry(Some(evidenced(declared.first_deadline())));
        let report = run(&late, &forecasts, T0 + 99_999);
        assert_eq!(report["manifest"]["precedes_first_deadline"], "not_before");
        assert_eq!(report["complete"], false);
        assert_eq!(report["summary"]["on_time"], 3);

        assert_eq!(report["manifest"]["state"], "valid");
    }

    /// The manifest is read from the same service the forecaster used. Until
    /// its own transaction is shown to store exactly those bytes, the slots
    /// and deadlines in it are hearsay: nothing is judged against them, in
    /// either direction.
    #[test]
    fn nothing_is_judged_against_a_manifest_not_bound_to_its_transaction() {
        let declared = manifest();
        let forecasts = [
            // On time, late, and absent, by the deadlines as served.
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
            entry(
                'b',
                &declared.slots[1],
                "no",
                Some(declared.slots[1].deadline + 5),
            ),
        ];
        // Control: bound, the same inputs are judged.
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "on_time");
        assert_eq!(slot_status(&report, 1), "late");
        assert_eq!(slot_status(&report, 2), "missing");

        for unbound in [Some(not_on_chain()), None] {
            let state = unbound
                .as_ref()
                .map_or("not_checked", |timing| timing.state().label());
            let report = run(&manifest_entry(unbound), &forecasts, T0 + 99_999);
            assert_eq!(report["manifest"]["state"], "unbound", "{state}");
            assert_eq!(report["manifest"]["timing"]["state"], state);
            assert_eq!(report["manifest"]["precedes_first_deadline"], "unknown");
            assert!(report["manifest"]["reason"].as_str().is_some());
            assert_eq!(report["complete"], false);
            for index in 0..3 {
                assert_eq!(slot_status(&report, index), "timing_unknown", "{state}");
                assert!(report["slots"][index]["counted_tx_id"].is_null());
            }
            assert_eq!(report["summary"]["timing_unknown"], 3);
            assert!(report["summary"].get("on_time").is_none());
            for index in 0..2 {
                let entry = &report["slots"][index]["entries"][0];
                assert_eq!(entry["state"], "timing_unknown", "{state}");
                assert_eq!(entry["deadline_verdict"], "unknown", "{state}");
                assert_eq!(entry["reason"], UNBOUND_REASON);
            }
        }
    }

    /// The bytes served for a forecast's id are another forecast, and the
    /// chain shows it: nothing in them is attributed to that id — no slot,
    /// no answer — and the slot it might have filled is not called missing.
    #[test]
    fn a_swapped_forecast_is_set_aside_with_no_answer() {
        let declared = manifest();
        let swapped = Entry {
            timing: Some(mismatched()),
            ..entry('a', &declared.slots[0], "no", None)
        };
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[swapped],
            T0 + 99_999,
        );
        assert_eq!(report["slots"][0]["entries"].as_array().unwrap().len(), 0);
        assert!(report["slots"][0]["counted_tx_id"].is_null());
        let unassigned = &report["unassigned"][0];
        assert_eq!(unassigned["tx_id"], tx('a'));
        assert_eq!(unassigned["timing"]["state"], "invalid");
        assert!(
            unassigned["reason"]
                .as_str()
                .unwrap()
                .contains("not the bytes its transaction stores")
        );
        assert!(unassigned.get("answer").is_none());
        assert!(!report.to_string().contains("\"answer\""));
        // Every slot is past its deadline and empty, and none is "missing":
        // the unread artifact could belong to any of them.
        for index in 0..3 {
            assert_eq!(slot_status(&report, index), "timing_unknown");
        }
        assert!(report["summary"].get("missing").is_none());
        assert_eq!(report["complete"], false);

        // The same goes for an artifact that could not be read at all …
        let unreadable = Entry {
            tx_id: tx('b'),
            unlock_at: None,
            content: EntryContent::Unreadable("storage_fetch_failed".to_owned()),
            timing: None,
        };
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[unreadable],
            T0 + 99_999,
        );
        assert_eq!(slot_status(&report, 0), "timing_unknown");
        // … while a slot whose deadline has not passed is simply open,
        let report = run(
            &manifest_entry(Some(evidenced(T0))),
            &[Entry {
                tx_id: tx('b'),
                unlock_at: None,
                content: EntryContent::Unreadable("x".to_owned()),
                timing: None,
            }],
            declared.slots[0].deadline - 1,
        );
        assert_eq!(slot_status(&report, 0), "open");
        // and with nothing unread, an empty slot past its deadline is missing.
        let report = run(&manifest_entry(Some(evidenced(T0))), &[], T0 + 99_999);
        assert_eq!(slot_status(&report, 0), "missing");
    }

    /// The manifest's transaction is on chain and stores OTHER bytes than the
    /// ones read: whoever served them swapped the manifest. Nothing in it is
    /// used.
    #[test]
    fn a_swapped_manifest_assigns_nothing() {
        let declared = manifest();
        let forecasts = [entry('a', &declared.slots[0], "yes", Some(T0 + 1000))];
        let report = run(&manifest_entry(Some(mismatched())), &forecasts, T0 + 99_999);
        assert_eq!(report["manifest"]["state"], "invalid");
        assert_eq!(report["manifest"]["timing"]["state"], "invalid");
        assert_eq!(report["complete"], false);
        assert!(report.get("slots").is_none());
        assert!(report.get("summary").is_none());
        assert!(report.get("series_id").is_none());
        assert_eq!(report["unassigned"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn an_unreadable_manifest_assigns_nothing() {
        let declared = manifest();
        let forecasts = [entry('a', &declared.slots[0], "yes", Some(T0 + 1000))];
        let cases = [
            (EntryContent::Locked, "locked"),
            (
                EntryContent::Unreadable("fetch failed".into()),
                "unreadable",
            ),
            (EntryContent::Revealed("{}".into()), "invalid"),
        ];
        for (content, state) in cases {
            let manifest = Entry {
                content,
                ..manifest_entry(Some(evidenced(T0)))
            };
            let report = run(&manifest, &forecasts, T0 + 99_999);
            assert_eq!(report["manifest"]["state"], state);
            assert_eq!(report["complete"], false);
            assert!(report.get("slots").is_none());
            assert_eq!(report["unassigned"].as_array().unwrap().len(), 1);
        }
    }

    #[test]
    fn outcomes_are_labelled_as_reporter_supplied() {
        let declared = manifest();
        let forecasts = [
            entry('a', &declared.slots[0], "yes", Some(T0 + 1000)),
            entry('b', &declared.slots[1], "no", Some(T0 + 11_000)),
        ];
        let outcomes: BTreeMap<String, String> = [
            ("one".to_owned(), " yes ".to_owned()),
            ("two".to_owned(), "yes".to_owned()),
            ("three".to_owned(), "yes".to_owned()),
        ]
        .into();
        let report = evaluate_series(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            &outcomes,
            T0 + 99_999,
        );
        assert_eq!(report["slots"][0]["outcome"]["result"], "match");
        assert_eq!(report["slots"][1]["outcome"]["result"], "no_match");
        // A missed forecast is not scored as wrong or right.
        assert_eq!(report["slots"][2]["outcome"]["result"], "unscored");
        assert!(
            report["slots"][0]["outcome"]["provenance"]
                .as_str()
                .unwrap()
                .contains("not verified")
        );
        assert_eq!(report["rules"]["scoring_applied"], "exact_match");
        let unscored = run(
            &manifest_entry(Some(evidenced(T0))),
            &forecasts,
            T0 + 99_999,
        );
        assert!(unscored["slots"][0].get("outcome").is_none());
    }

    /// The report implements one scoring rule. Under any other declared
    /// rule it must not pretend to apply it: "within 5 of the observed
    /// number", answer 20, outcome 22 is a hit by the manifest's rule and
    /// would be `no_match` by string equality.
    #[test]
    fn a_rule_the_report_does_not_implement_is_not_scored() {
        for (scoring, applied) in [
            ("exact_match", true),
            ("exact_match: last hex digit, even or odd", true),
            ("exact_matching is not the token", false),
            ("Exact match against the source", false),
            ("within 5 of the observed number", false),
            (" exact_match", false),
        ] {
            assert_eq!(declares_exact_match(scoring), applied, "{scoring:?}");
        }

        let declared = Manifest {
            scoring: "within 5 of the observed number".to_owned(),
            ..manifest()
        };
        let manifest_entry = Entry {
            content: EntryContent::Revealed(declared.to_body()),
            ..manifest_entry(Some(evidenced(T0)))
        };
        let forecasts = [entry('a', &declared.slots[0], "20", Some(T0 + 1000))];
        let outcomes: BTreeMap<String, String> = [("one".to_owned(), "22".to_owned())].into();
        let report = evaluate_series(&manifest_entry, &forecasts, &outcomes, T0 + 99_999);
        assert_eq!(slot_status(&report, 0), "on_time");
        assert_eq!(report["rules"]["scoring_applied"], "none");
        assert_eq!(
            report["rules"]["scoring"],
            "within 5 of the observed number"
        );
        let outcome = &report["slots"][0]["outcome"];
        assert_eq!(outcome["value"], "22");
        assert_eq!(outcome["result"], "unscored");
        // Even an identical string is not scored under a rule that is prose.
        let same: BTreeMap<String, String> = [("one".to_owned(), "20".to_owned())].into();
        let report = evaluate_series(&manifest_entry, &forecasts, &same, T0 + 99_999);
        assert_eq!(report["slots"][0]["outcome"]["result"], "unscored");
    }

    /// Every time in a manifest is Unix seconds. A millisecond deadline
    /// would be met by any block at all, so the body is refused before it
    /// can be compared with anything.
    #[test]
    fn times_that_cannot_be_unix_seconds_are_refused() {
        let edit = |change: &dyn Fn(&mut Value)| {
            let mut body: Value = serde_json::from_str(&manifest().to_body()).unwrap();
            change(&mut body);
            Manifest::parse(&body.to_string())
        };
        assert!(edit(&|_| {}).is_ok());
        for bad in [
            json!(1_800_010_000_000_i64),
            json!(crate::timing::MAX_PLAUSIBLE_UNIX_SECS),
            json!(0),
            json!(-1),
        ] {
            assert!(
                edit(&|b| b["slots"][0]["deadline"] = bad.clone()).is_err(),
                "deadline {bad}"
            );
            assert!(
                edit(&|b| b["slots"][0]["reveal_at"] = bad.clone()).is_err(),
                "reveal_at {bad}"
            );
        }
        // And so a manifest with one can never earn a verdict: it is
        // reported as invalid, with no slots.
        let mut body: Value = serde_json::from_str(&manifest().to_body()).unwrap();
        for slot in body["slots"].as_array_mut().unwrap() {
            let deadline = slot["deadline"].as_i64().unwrap();
            slot["deadline"] = json!(deadline * 1000);
            slot["reveal_at"] = json!(deadline * 1000);
        }
        let millis = Entry {
            content: EntryContent::Revealed(body.to_string()),
            ..manifest_entry(Some(evidenced(T0 + 40_000)))
        };
        let report = run(&millis, &[], T0 + 99_999);
        assert_eq!(report["manifest"]["state"], "invalid");
        assert!(report["manifest"].get("precedes_first_deadline").is_none());
        assert!(report.get("slots").is_none());
        assert!(!report.to_string().contains("\"before\""));
    }

    #[test]
    fn manifests_that_break_a_rule_are_refused() {
        let edit = |change: &dyn Fn(&mut Value)| {
            let mut body: Value = serde_json::from_str(&manifest().to_body()).unwrap();
            change(&mut body);
            Manifest::parse(&body.to_string())
        };
        assert!(edit(&|_| {}).is_ok());
        assert!(edit(&|b| b["schema"] = json!("qub.forecast-series/v2")).is_err());
        assert!(edit(&|b| b["kind"] = json!("forecast")).is_err());
        assert!(edit(&|b| b["revisions"] = json!("latest")).is_err());
        assert!(edit(&|b| b["series_id"] = json!("Has Spaces")).is_err());
        assert!(edit(&|b| b["series_id"] = json!("-lead")).is_err());
        assert!(edit(&|b| b["title"] = json!("   ")).is_err());
        assert!(edit(&|b| b["title"] = json!("a\u{0007}b")).is_err());
        assert!(edit(&|b| b["title"] = json!("x".repeat(MAX_TEXT_CHARS + 1))).is_err());
        assert!(edit(&|b| b["title"] = json!("x".repeat(MAX_TEXT_CHARS))).is_ok());
        assert!(edit(&|b| b["slots"] = json!([])).is_err());
        assert!(edit(&|b| b["extra"] = json!(1)).is_err());
        assert!(
            edit(&|b| {
                b.as_object_mut().unwrap().remove("scoring");
            })
            .is_err()
        );
        assert!(edit(&|b| b["slots"][1]["slot"] = json!("one")).is_err());
        assert!(edit(&|b| b["slots"][0]["deadline"] = json!(0)).is_err());
        assert!(edit(&|b| b["slots"][0]["deadline"] = json!("soon")).is_err());
        assert!(edit(&|b| b["slots"][0]["hidden"] = json!("x")).is_err());
        // Revealing before the deadline would let a forecast be read while
        // the slot is still open; revealing exactly at it is allowed.
        assert!(
            edit(&|b| {
                let deadline = b["slots"][0]["deadline"].as_i64().unwrap();
                b["slots"][0]["reveal_at"] = json!(deadline - 1);
            })
            .is_err()
        );
        assert!(
            edit(&|b| {
                let deadline = b["slots"][0]["deadline"].as_i64().unwrap();
                b["slots"][0]["reveal_at"] = json!(deadline);
            })
            .is_ok()
        );
        let too_many: Vec<Value> = (0..=MAX_SLOTS)
            .map(|i| {
                json!({
                    "slot": format!("s{i}"), "question": "q", "outcome_source": "o",
                    "deadline": T0, "reveal_at": T0
                })
            })
            .collect();
        assert!(edit(&|b| b["slots"] = json!(too_many)).is_err());
        // The limit itself is allowed: exactly MAX_SLOTS slots parse.
        let at_the_limit = &too_many[..MAX_SLOTS];
        let parsed = edit(&|b| b["slots"] = json!(at_the_limit)).expect("MAX_SLOTS slots");
        assert_eq!(parsed.slots.len(), MAX_SLOTS);
        assert!(Manifest::parse("not json").is_err());
        assert!(Manifest::parse("[]").is_err());
    }

    #[test]
    fn forecasts_that_break_a_rule_are_refused() {
        let declared = manifest();
        let edit = |change: &dyn Fn(&mut Value)| {
            let mut body: Value =
                serde_json::from_str(&forecast(&declared.slots[0], "yes").to_body()).unwrap();
            change(&mut body);
            Forecast::parse(&body.to_string())
        };
        assert!(edit(&|_| {}).is_ok());
        assert!(edit(&|b| b["kind"] = json!("manifest")).is_err());
        assert!(edit(&|b| b["manifest_tx_id"] = json!("short")).is_err());
        assert!(edit(&|b| b["manifest_tx_id"] = json!("!".repeat(43))).is_err());
        // Every character of the base64url alphabet is part of an id.
        assert!(edit(&|b| b["manifest_tx_id"] = json!("-".repeat(43))).is_ok());
        assert!(edit(&|b| b["manifest_tx_id"] = json!("_".repeat(43))).is_ok());
        assert!(edit(&|b| b["manifest_tx_id"] = json!("a".repeat(44))).is_err());
        assert!(edit(&|b| b["manifest_tx_id"] = json!("a".repeat(42))).is_err());
        assert!(edit(&|b| b["answer"] = json!("")).is_err());
        assert!(edit(&|b| b["probability_pct"] = json!(101)).is_err());
        assert!(edit(&|b| b["probability_pct"] = json!(100)).is_ok());
        assert!(edit(&|b| b["probability_pct"] = json!(0)).is_ok());
        assert!(edit(&|b| b["probability_pct"] = json!(-1)).is_err());
        assert!(edit(&|b| b["probability_pct"] = json!("70")).is_err());
        // A second answer smuggled in an unknown member is not a forecast.
        assert!(edit(&|b| b["answer_b"] = json!("no")).is_err());
        assert!(
            edit(&|b| {
                b.as_object_mut().unwrap().remove("outcome_source");
            })
            .is_err()
        );
        assert!(Forecast::parse("{").is_err());
    }
}
