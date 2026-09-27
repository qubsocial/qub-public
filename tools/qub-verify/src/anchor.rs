//! Typed transparency-log anchored verification for the standalone verifier
//! (PROTOCOL.md §16.9 / §16.11).
//!
//! When a `.qub` bundle carries an `inclusion_proof` (§17.5), this module turns
//! the opaque slot into a typed verdict. The §16.9 standalone-verification
//! algorithm has two tiers of trust, and this module keeps them honest:
//!
//! - **Self-consistency (always checkable, never trust-bearing on its own).**
//!   The Merkle leg (`verify_root`) only proves the leaf folds to the root
//!   *carried inside the same proof*; the `log_id` is a public constant derived
//!   from the baked-in `anchor_owner`. Both are attacker-settable in a fabricated
//!   proof, so neither — nor a kind=0x02 *opaque* leaf, which is tied to the qub
//!   by nothing offline — proves anchoring on its own.
//! - **Anchoring (trust-bearing).** Only the RSA-PSS-signed Arweave anchor
//!   transaction, verified against the *pinned* `anchor_owner` (§16.9 steps 5-6),
//!   binds the root to qub's append-only log. That requires the `--anchor`
//!   `DataItem` **and** a provisioned (non-placeholder) owner pin, **and** the leaf
//!   must bind to *this* qub (attested, or asserted with `ref == qub_id`).
//!
//! Four outcomes, mapping the §17.5 contract honestly:
//! [`AnchorState::Absent`] (no proof — "not anchored", never invalid),
//! [`AnchorState::InclusionOnly`] (proof present + self-consistent, but anchoring
//! of *this* qub is not proven offline — not a failure),
//! [`AnchorState::Verified`] (anchoring of this qub cryptographically proven), and
//! [`AnchorState::Broken`] (present but a hard check failed — a genuine integrity
//! signal that fails the overall verdict).

use qub_core::export::QubBundle;
use qub_core::hash;
use qub_core::log::{
    AnchorBundle, LEAF_KIND_ASSERTED, LEAF_KIND_ATTESTED, LogLeaf, LogProfile, SignedTreeHead,
};
use qub_core::types::RevealedQub;

use crate::ans104;

/// How an anchored proof's leaf bound back to the revealed qub (§16.11 scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// `kind=0x01` attested leaf, fully bound: `ref == qub_id`, `body_hash` and
    /// `drand_round` all match the revealed qub.
    Attested,
    /// `kind=0x02` asserted leaf whose `ref` equals the (public) `qub_id`.
    AssertedPublic,
    /// `kind=0x02` asserted leaf with an opaque / blinded `ref` — tied to *this*
    /// qub by nothing offline (a private qub commits `SHA3-256(qub_id ‖
    /// log_blind_secret)`, and the §16.9 step-3b `chash` tie needs the outer
    /// wrapped bytes the bundle does not carry, §13). Not a fault, but it can
    /// never prove anchoring *of this qub*.
    AssertedOpaque,
}

impl Binding {
    /// A stable machine label for the JSON report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Attested => "attested",
            Self::AssertedPublic => "asserted_public",
            Self::AssertedOpaque => "asserted_opaque",
        }
    }

    /// Whether this binding ties the leaf to *this* qub (§16.9 step 3). An
    /// opaque asserted leaf does not.
    #[must_use]
    pub const fn binds_to_qub(self) -> bool {
        matches!(self, Self::Attested | Self::AssertedPublic)
    }
}

/// Whether the pinned-owner check could be enforced (§16.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerPin {
    /// `LogProfile.anchor_owner` is still the build-time placeholder — the
    /// owner pin is informational until the anchor wallet is provisioned, so
    /// anchoring cannot be *proven* (only self-described).
    Placeholder,
    /// Provisioned owner: the anchor's owner address matches the pin.
    Match,
    /// Provisioned owner: the anchor's owner address does **not** match (fault).
    Mismatch,
}

impl OwnerPin {
    /// A stable machine label for the JSON report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Placeholder => "placeholder",
            Self::Match => "match",
            Self::Mismatch => "mismatch",
        }
    }
}

/// The result of the optional Arweave anchor-transaction leg (`--anchor`).
// Four independent verdict bits (signature / committed root / committed size /
// txid match) — each a distinct §16.9 check, none a state machine; a bitfield
// or sub-struct would obscure the report rather than clarify it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct AnchorTxReport {
    /// The anchor `DataItem`'s RSA-PSS signature verified.
    pub signature_valid: bool,
    /// The `AnchorBundle`'s Signed Tree Head commits the proof's `root`.
    pub committed_root_ok: bool,
    /// The Signed Tree Head's `size` equals the proof's `size`.
    pub committed_size_ok: bool,
    /// The anchor `DataItem` id equals the proof's `anchor.txid`.
    pub txid_match: bool,
    /// The pinned-owner verdict.
    pub owner_pin: OwnerPin,
}

impl AnchorTxReport {
    /// Whether this anchor leg is *trust-bearing* — every structural check
    /// passed AND the owner matches a **provisioned** pin. A placeholder owner
    /// (the pre-launch deploy-gate state) is never trust-bearing (§16.6).
    #[must_use]
    pub const fn is_trust_bearing(&self) -> bool {
        self.signature_valid
            && self.committed_root_ok
            && self.committed_size_ok
            && self.txid_match
            && matches!(self.owner_pin, OwnerPin::Match)
    }
}

/// The facts behind a present (non-broken) inclusion proof.
#[derive(Debug, Clone)]
pub struct AnchorDetails {
    /// Leaf kind (`0x01` attested / `0x02` asserted).
    kind: u8,
    /// Leaf index proven.
    index: u64,
    /// Tree size the proof commits to.
    size: u64,
    /// How the leaf bound to the revealed qub.
    binding: Binding,
    /// Anchor transaction id (hex) the proof points at.
    txid_hex: String,
    /// The Arweave anchor leg, present only when `--anchor` was supplied.
    anchor_tx: Option<AnchorTxReport>,
}

impl AnchorDetails {
    /// Leaf kind (`0x01` attested / `0x02` asserted).
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// Leaf index proven.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Tree size the proof commits to.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// How the leaf bound to the revealed qub.
    #[must_use]
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    /// Whether the leaf ties to *this* qub (§16.9 step 3).
    #[must_use]
    pub const fn bound_to_qub(&self) -> bool {
        self.binding.binds_to_qub()
    }

    /// Whether the anchor transaction is trust-bearing under the provisioned
    /// owner pin.
    #[must_use]
    pub fn anchor_confirmed(&self) -> bool {
        self.anchor_tx
            .as_ref()
            .is_some_and(AnchorTxReport::is_trust_bearing)
    }

    /// Anchor transaction id (hex) the proof points at.
    #[must_use]
    pub fn txid_hex(&self) -> &str {
        &self.txid_hex
    }

    /// The optional Arweave anchor verification report.
    #[must_use]
    pub const fn anchor_tx(&self) -> Option<&AnchorTxReport> {
        self.anchor_tx.as_ref()
    }
}

/// The anchored-verification verdict for a bundle.
#[derive(Debug, Clone)]
pub enum AnchorState {
    /// No inclusion proof in the bundle (§17.5: "not anchored", never invalid).
    Absent,
    /// Proof present and self-consistent (Merkle leg + `log_id` + leaf parse),
    /// but anchoring of *this* qub is **not** cryptographically proven offline —
    /// because no trust-bearing Arweave anchor was verified (no `--anchor`, or
    /// the owner pin is the deploy-gated placeholder) and/or the leaf `ref` is
    /// opaque. Per §17.5 this is **not** a failure: the bundle's own
    /// timing/authorship verification stands on its own.
    InclusionOnly(AnchorDetails),
    /// Proof present, the Arweave anchor transaction is verified against the
    /// pinned owner, **and** the leaf binds to *this* qub — anchoring proven
    /// (§16.9 steps 1-7 satisfied).
    Verified(AnchorDetails),
    /// Proof present but a hard check failed — a genuine integrity signal that
    /// fails the overall verdict.
    Broken(String),
}

impl AnchorState {
    /// Whether this state must fail the overall verification verdict. Only a
    /// [`Self::Broken`] proof does (§17.5); an unanchored-but-consistent proof
    /// ([`Self::InclusionOnly`]) does not.
    #[must_use]
    pub const fn is_broken(&self) -> bool {
        matches!(self, Self::Broken(_))
    }
}

fn broken(message: impl Into<String>) -> AnchorState {
    AnchorState::Broken(message.into())
}

/// Verify a bundle's anchored proof against the revealed qub and the **pinned**
/// production [`LogProfile`], optionally including the Arweave anchor leg.
///
/// `anchor_data_item` is the raw bytes of the anchor's ANS-104 `DataItem` (the
/// `--anchor` input); `None` skips §16.9 steps 5-6 (anchoring then cannot be
/// proven offline → [`AnchorState::InclusionOnly`]).
#[must_use]
pub fn verify_anchored(
    bundle: &QubBundle,
    revealed: &RevealedQub,
    anchor_data_item: Option<&[u8]>,
) -> AnchorState {
    verify_anchored_with_profile(bundle, revealed, anchor_data_item, &LogProfile::qub())
}

/// [`verify_anchored`] against an explicit trust profile. Production always uses
/// the pinned [`LogProfile::qub`]; tests inject a provisioned profile to
/// exercise the post-deploy-gate trust-bearing path.
#[must_use]
fn verify_anchored_with_profile(
    bundle: &QubBundle,
    revealed: &RevealedQub,
    anchor_data_item: Option<&[u8]>,
    profile: &LogProfile,
) -> AnchorState {
    // §17.5: distinguish absent / present-well-formed / present-malformed.
    let proof = match bundle.inclusion_proof_typed() {
        Ok(None) => return AnchorState::Absent,
        Ok(Some(proof)) => proof,
        Err(err) => return broken(format!("inclusion proof is malformed: {err}")),
    };

    // §16.9 step 4 — the Merkle leg. Self-consistent only (the root is carried
    // inside the proof); trust comes from the anchor leg below.
    if !proof.verify_root() {
        return broken("Merkle audit path does not reproduce the committed root");
    }

    // The proof's anchor must claim the pinned log (catches misconfiguration; a
    // public constant, so not adversarially binding on its own).
    if proof.anchor().log_id() != &profile.log_id() {
        return broken("anchor log_id does not match the pinned LogProfile");
    }

    // §16.9 steps 2-3 — bind the leaf to the revealed qub, scoped by kind.
    let leaf = match LogLeaf::from_cbor(proof.leaf()) {
        Ok(leaf) => leaf,
        Err(err) => return broken(format!("leaf CBOR is malformed: {err}")),
    };
    let binding = match bind_leaf(&leaf, revealed) {
        Ok(binding) => binding,
        Err(message) => return broken(message),
    };

    // §16.9 steps 5-6 — the optional Arweave anchor leg.
    let anchor_tx = match anchor_data_item {
        None => None,
        Some(raw) => {
            let report = verify_anchor_tx(raw, &proof, profile);
            if let Err(message) = anchor_tx_fault(&report) {
                return broken(message);
            }
            Some(report)
        },
    };

    select_state(
        leaf.kind(),
        proof.index(),
        proof.size(),
        binding,
        hex::encode(proof.anchor().txid()),
        anchor_tx,
    )
}

/// Classify a present, non-broken proof into [`AnchorState::Verified`] vs
/// [`AnchorState::InclusionOnly`] (PROTOCOL.md §16.9 step 7 / §16.11 ceiling).
///
/// Anchoring of *this* qub is proven only when the leaf binds to this qub AND a
/// trust-bearing Arweave anchor was verified. Everything else is self-consistent
/// but unproven.
fn select_state(
    kind: u8,
    index: u64,
    size: u64,
    binding: Binding,
    txid_hex: String,
    anchor_tx: Option<AnchorTxReport>,
) -> AnchorState {
    let details = AnchorDetails {
        kind,
        index,
        size,
        binding,
        txid_hex,
        anchor_tx,
    };
    if details.bound_to_qub() && details.anchor_confirmed() {
        AnchorState::Verified(details)
    } else {
        AnchorState::InclusionOnly(details)
    }
}

/// Bind a parsed leaf to the revealed qub per its kind (§16.9 step 3 / §16.11).
fn bind_leaf(leaf: &LogLeaf, revealed: &RevealedQub) -> Result<Binding, String> {
    match leaf.kind() {
        LEAF_KIND_ATTESTED => {
            let ref_ok = leaf.reference() == revealed.qub_id();
            let body_hash = hash::body_hash(revealed.body());
            let body_hash_ok = leaf.body_hash() == Some(&body_hash);
            let round_ok = leaf.drand_round() == Some(revealed.drand_round());
            if ref_ok && body_hash_ok && round_ok {
                Ok(Binding::Attested)
            } else {
                Err(format!(
                    "attested leaf does not bind to the revealed qub \
                     (ref_ok={ref_ok}, body_hash_ok={body_hash_ok}, drand_round_ok={round_ok})"
                ))
            }
        },
        LEAF_KIND_ASSERTED => {
            // Public qubs commit the raw qub_id; private qubs commit a blinded
            // ref untieable offline (§16.2.1). An opaque ref is a scope limit,
            // never a failure — but it can never prove anchoring of THIS qub.
            if leaf.reference() == revealed.qub_id() {
                Ok(Binding::AssertedPublic)
            } else {
                Ok(Binding::AssertedOpaque)
            }
        },
        other => Err(format!("unknown leaf kind {other:#04x}")),
    }
}

/// Verify the Arweave anchor `DataItem` and check it commits the proof (§16.9
/// steps 5-6). Never panics: a malformed anchor yields an all-false report.
fn verify_anchor_tx(
    raw: &[u8],
    proof: &qub_core::log::InclusionProof,
    profile: &LogProfile,
) -> AnchorTxReport {
    let Ok(verified) = ans104::verify_data_item(raw) else {
        return AnchorTxReport {
            signature_valid: false,
            committed_root_ok: false,
            committed_size_ok: false,
            txid_match: false,
            owner_pin: OwnerPin::Placeholder,
        };
    };

    // Parse the AnchorBundle from the DataItem payload, then its Signed Tree
    // Head, and check it commits the proof's root + size.
    let (committed_root_ok, committed_size_ok) = AnchorBundle::from_cbor(&verified.data)
        .and_then(|anchor| SignedTreeHead::from_cbor(anchor.sth()))
        .map_or((false, false), |sth| {
            (sth.root() == proof.root(), sth.size() == proof.size())
        });

    let txid_match = &verified.id_raw == proof.anchor().txid();
    let owner_pin = if profile.is_anchor_owner_placeholder() {
        OwnerPin::Placeholder
    } else if &verified.owner_address == profile.anchor_owner() {
        OwnerPin::Match
    } else {
        OwnerPin::Mismatch
    };

    AnchorTxReport {
        signature_valid: verified.valid,
        committed_root_ok,
        committed_size_ok,
        txid_match,
        owner_pin,
    }
}

/// Reduce an anchor-leg report to a hard fault (if any). A placeholder owner pin
/// is informational, not a fault (§16.6 deploy-gating) — it yields an
/// unproven-but-not-broken verdict, handled by [`select_state`].
fn anchor_tx_fault(report: &AnchorTxReport) -> Result<(), String> {
    if !report.signature_valid {
        return Err("anchor DataItem RSA-PSS signature is invalid".to_owned());
    }
    if !report.committed_root_ok || !report.committed_size_ok {
        return Err("anchor AnchorBundle does not commit the proof's root/size".to_owned());
    }
    if !report.txid_match {
        return Err("anchor DataItem id does not match the proof's anchor.txid".to_owned());
    }
    if matches!(report.owner_pin, OwnerPin::Mismatch) {
        return Err("anchor owner does not match the pinned anchor_owner".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_tx() -> AnchorTxReport {
        AnchorTxReport {
            signature_valid: true,
            committed_root_ok: true,
            committed_size_ok: true,
            txid_match: true,
            owner_pin: OwnerPin::Match,
        }
    }

    fn placeholder_tx() -> AnchorTxReport {
        AnchorTxReport {
            owner_pin: OwnerPin::Placeholder,
            ..match_tx()
        }
    }

    fn classify(binding: Binding, anchor_tx: Option<AnchorTxReport>) -> AnchorState {
        select_state(0x01, 2, 5, binding, "deadbeef".to_owned(), anchor_tx)
    }

    /// A `RevealedQub` whose body, `qub_id` and `drand_round` are all
    /// distinct known values, so a leaf can be made to disagree on
    /// exactly one of them.
    /// `OwnerPin::label` feeds the JSON report a third party reads, and
    /// both `FnValue` replacements ("" and "xyzzy") survived: nothing
    /// asserted the strings. A report field that silently became empty
    /// would be a machine-readable lie.
    #[test]
    fn owner_pin_labels_are_stable() {
        assert_eq!(OwnerPin::Placeholder.label(), "placeholder");
        assert_eq!(OwnerPin::Match.label(), "match");
        assert_eq!(OwnerPin::Mismatch.label(), "mismatch");
    }

    fn revealed_for_binding() -> RevealedQub {
        let body = b"body bytes".to_vec();
        let bh = hash::body_hash(&body);
        RevealedQub::new(
            [7u8; 32],
            "tx".to_owned(),
            1,
            1,
            1_700_000_000,
            1_800_000_000,
            None,
            "chain".to_owned(),
            12_345,
            None,
            None,
            None,
            body,
            bh,
            true,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// An attested leaf binds only when ALL THREE of `ref`, `body_hash`
    /// and `drand_round` agree with the revealed qub — that is what makes
    /// this leaf evidence about THIS qub rather than some other one.
    ///
    /// Mutation flipped both `&&`s to `||` and the whole suite stayed
    /// green: nothing exercised exactly one of the three failing. Under
    /// either mutant the offline verifier — which nothing downstream
    /// re-checks, because there IS no downstream — would report a leaf as
    /// bound on a single field agreeing. Each case below fails exactly one
    /// fact and holds the other two, which is the only shape that can
    /// tell `&&` from `||`.
    #[test]
    fn attested_leaf_binds_only_when_all_three_facts_agree() {
        let revealed = revealed_for_binding();
        let bh = hash::body_hash(revealed.body());
        let leaf = |reference, body_hash, drand_round| {
            LogLeaf::attested(
                1,
                reference,
                [9u8; 32],
                1_800_000_000,
                1_700_000_000,
                body_hash,
                drand_round,
            )
            .expect("consistent attested leaf")
        };

        // Control: all three agree, so the binding must hold. Without this
        // the negative cases below could pass for the wrong reason.
        assert!(matches!(
            bind_leaf(
                &leaf(*revealed.qub_id(), bh, revealed.drand_round()),
                &revealed
            ),
            Ok(Binding::Attested)
        ));

        for (label, candidate) in [
            ("reference", leaf([1u8; 32], bh, revealed.drand_round())),
            (
                "body_hash",
                leaf(*revealed.qub_id(), [2u8; 32], revealed.drand_round()),
            ),
            (
                "drand_round",
                leaf(*revealed.qub_id(), bh, revealed.drand_round() + 1),
            ),
        ] {
            assert!(
                bind_leaf(&candidate, &revealed).is_err(),
                "{label} disagreeing on its own must break the binding",
            );
        }
    }

    /// `!committed_root_ok || !committed_size_ok` is one check over two
    /// independent facts. Mutation flipped it to `&&`, which accepts the
    /// anchor whenever EITHER commitment still agrees — and no test ever
    /// failed one of the pair on its own.
    #[test]
    fn anchor_tx_fault_rejects_either_commitment_failing_alone() {
        for (label, report) in [
            (
                "root disagrees while size agrees",
                AnchorTxReport {
                    committed_root_ok: false,
                    ..match_tx()
                },
            ),
            (
                "size disagrees while root agrees",
                AnchorTxReport {
                    committed_size_ok: false,
                    ..match_tx()
                },
            ),
        ] {
            assert!(
                anchor_tx_fault(&report).is_err(),
                "{label} must still be a hard fault",
            );
        }
    }

    // ---- §16.9 step-7 state selection (the §16.11 claim ceiling) ----

    #[test]
    fn verified_requires_bound_leaf_and_trust_bearing_anchor() {
        // The ONLY combination that proves anchoring of this qub.
        assert!(matches!(
            classify(Binding::Attested, Some(match_tx())),
            AnchorState::Verified(d) if d.bound_to_qub() && d.anchor_confirmed()
        ));
        assert!(matches!(
            classify(Binding::AssertedPublic, Some(match_tx())),
            AnchorState::Verified(_)
        ));
    }

    #[test]
    fn no_anchor_leg_is_inclusion_only_even_when_bound() {
        // A bound leaf with no verified anchor (the common no-`--anchor` case) is
        // self-consistent but NOT proven anchoring — the §2 high finding.
        assert!(matches!(
            classify(Binding::Attested, None),
            AnchorState::InclusionOnly(d) if d.bound_to_qub() && !d.anchor_confirmed()
        ));
    }

    #[test]
    fn placeholder_owner_is_inclusion_only_even_with_anchor() {
        // A structurally-valid anchor against the deploy-gated placeholder owner
        // is informational, never trust-bearing (§16.6).
        assert!(matches!(
            classify(Binding::Attested, Some(placeholder_tx())),
            AnchorState::InclusionOnly(d) if !d.anchor_confirmed()
        ));
    }

    #[test]
    fn opaque_leaf_is_inclusion_only_even_with_trust_bearing_anchor() {
        // An opaque asserted leaf is tied to this qub by nothing offline, so even
        // a fully-verified anchor cannot promote it to Verified (the §3 finding).
        assert!(matches!(
            classify(Binding::AssertedOpaque, Some(match_tx())),
            AnchorState::InclusionOnly(d) if !d.bound_to_qub() && d.anchor_confirmed()
        ));
    }

    // ---- the provisioned owner-pin gate (the sole post-deploy anchor barrier) ----

    fn fixture() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/qub-core/tests/vectors/ans104_v1.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture"))
            .expect("fixture json")
    }

    fn fixture_hex(fx: &serde_json::Value, ptr: &str) -> Vec<u8> {
        hex::decode(
            fx.pointer(ptr)
                .and_then(serde_json::Value::as_str)
                .expect("field"),
        )
        .expect("hex")
    }

    fn fixture_proof(fx: &serde_json::Value) -> qub_core::log::InclusionProof {
        qub_core::log::InclusionProof::from_cbor(&fixture_hex(
            fx,
            "/inclusion_proof/proof_cbor_hex",
        ))
        .expect("proof parses")
    }

    #[test]
    fn anchor_tx_owner_pin_matches_provisioned_owner() {
        // Drive the OwnerPin::Match arm + the trust-bearing fold that becomes the
        // sole anchor-forgery barrier once the wallet is provisioned (the §1
        // finding): a profile pinned to the fixture's own owner address confirms.
        let fx = fixture();
        let raw = fixture_hex(&fx, "/data_item/raw_hex");
        let owner: [u8; 32] = fixture_hex(&fx, "/data_item/owner_address_hex")
            .try_into()
            .expect("32-byte owner address");
        let profile = LogProfile::new(owner, vec![]);
        assert!(!profile.is_anchor_owner_placeholder());

        let report = verify_anchor_tx(&raw, &fixture_proof(&fx), &profile);
        assert_eq!(report.owner_pin, OwnerPin::Match);
        assert!(report.is_trust_bearing());
        assert!(anchor_tx_fault(&report).is_ok());
    }

    #[test]
    fn anchor_tx_owner_pin_rejects_wrong_provisioned_owner() {
        // A provisioned profile pinned to a DIFFERENT owner must reject the
        // anchor as a hard fault (the post-deploy false-accept barrier).
        let fx = fixture();
        let raw = fixture_hex(&fx, "/data_item/raw_hex");
        let profile = LogProfile::new([0xCD; 32], vec![]);

        let report = verify_anchor_tx(&raw, &fixture_proof(&fx), &profile);
        assert_eq!(report.owner_pin, OwnerPin::Mismatch);
        assert!(!report.is_trust_bearing());
        assert!(anchor_tx_fault(&report).is_err());
    }

    #[test]
    fn anchor_tx_fault_rejects_invalid_signature() {
        // Fail-closed: a non-verifying DataItem is a hard fault, never silently
        // accepted.
        let report = AnchorTxReport {
            signature_valid: false,
            ..match_tx()
        };
        assert!(anchor_tx_fault(&report).is_err());
    }
}
