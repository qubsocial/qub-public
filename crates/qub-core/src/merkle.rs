//! RFC 6962 / RFC 9162 Merkle tree over SHA3-256 — the transparency-log
//! tree primitive (PROTOCOL.md §16.3, §16.5, §16.9).
//!
//! qub's transparency log is one ever-growing RFC 6962 **left-full
//! unbalanced** tree over all leaves in `seq` order. This module provides the
//! reference, slice-based implementation: leaf/node hashing, the cumulative
//! Merkle Tree Hash (root), inclusion-proof generation + standalone
//! verification, and consistency-proof generation + standalone verification.
//!
//! RFC 6962 is defined with SHA-256; qub substitutes **SHA3-256** throughout
//! (the same substitution the rest of the protocol makes — `body_hash`,
//! `qub_id`, signing inputs are all SHA3-256). The domain-separation prefix
//! bytes follow RFC 6962 §2.1:
//!
//! ```text
//! leaf_hash      = SHA3-256(0x00 || leaf_cbor)
//! node_hash(l,r) = SHA3-256(0x01 || l || r)
//! empty tree     = SHA3-256("")          // defined but never anchored
//! ```
//!
//! The prefix bytes `0x02` (`LogDO` internal entry chain) and `0x03` (Signed
//! Tree Head hash) are reserved for [`crate::log`] and are disjoint from the
//! `0x00` / `0x01` used here.
//!
//! # Worker parity
//!
//! The Worker's `LogDO` maintains the tree **incrementally** via a cached
//! right-edge frontier (`O(log n)` hashes). That incremental construction MUST
//! produce byte-identical roots and proofs to this reference; the cross-language
//! fixture `tlog_v1.json` (PROTOCOL.md §16.8/§16.14) is the binding gate.

use sha3::{Digest, Sha3_256};

/// RFC 6962 leaf-hash domain prefix.
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;

/// RFC 6962 internal-node-hash domain prefix.
pub const MERKLE_NODE_PREFIX: u8 = 0x01;

/// Leaf hash: `SHA3-256(0x00 || leaf_cbor)` (RFC 6962 §2.1, SHA3 substitution).
///
/// `leaf_cbor` is the canonical-CBOR encoding of a [`crate::log::LogLeaf`].
#[must_use]
pub fn leaf_hash(leaf_cbor: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([MERKLE_LEAF_PREFIX]);
    hasher.update(leaf_cbor);
    hasher.finalize().into()
}

/// Internal-node hash: `SHA3-256(0x01 || left || right)` (RFC 6962 §2.1).
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([MERKLE_NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The Merkle Tree Hash of the empty tree: `SHA3-256("")`.
///
/// Defined by RFC 6962 §2.1 for completeness; an empty tree is never anchored
/// by qub (a batch always carries ≥ 1 leaf).
#[must_use]
pub fn empty_root() -> [u8; 32] {
    Sha3_256::new().finalize().into()
}

/// Largest power of two strictly less than `n` (RFC 6962 split point).
///
/// Caller guarantees `n >= 2`. Returns the `k` such that `2^j == k < n` and
/// `2k >= n`.
const fn largest_pow2_lt(n: usize) -> usize {
    let mut k: usize = 1;
    // `k * 2 < n` keeps doubling; for n >= 2 this terminates with k in [1, n).
    while k.wrapping_mul(2) < n {
        k = k.wrapping_mul(2);
    }
    k
}

/// Cumulative Merkle Tree Hash over the given **leaf hashes** in `seq` order.
///
/// `leaf_hashes` are already-computed [`leaf_hash`] values (not raw leaf CBOR).
/// Implements RFC 6962 §2.1 `MTH`: an empty input yields [`empty_root`]; a
/// single leaf yields that leaf hash; otherwise the tree splits at the largest
/// power of two below the leaf count.
#[must_use]
pub fn merkle_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    mth(leaf_hashes)
}

/// RFC 6962 `MTH` over a slice of leaf hashes.
fn mth(hashes: &[[u8; 32]]) -> [u8; 32] {
    match hashes {
        [] => empty_root(),
        [single] => *single,
        _ => {
            let k = largest_pow2_lt(hashes.len());
            let (left, right) = hashes.split_at(k);
            node_hash(&mth(left), &mth(right))
        },
    }
}

/// Generate the RFC 6962 inclusion (audit) path for `index` in a tree of the
/// given leaf hashes.
///
/// Returns `None` if `index` is out of range. The returned path is the list of
/// sibling hashes from the leaf up to (but excluding) the root, bottom-first —
/// exactly what [`verify_inclusion`] consumes.
#[must_use]
pub fn inclusion_proof(index: usize, leaf_hashes: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    if index >= leaf_hashes.len() {
        return None;
    }
    Some(path(index, leaf_hashes))
}

/// RFC 6962 §2.1.1 `PATH(m, D[n])`.
fn path(m: usize, hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if hashes.len() <= 1 {
        return Vec::new();
    }
    let k = largest_pow2_lt(hashes.len());
    let (left, right) = hashes.split_at(k);
    if m < k {
        let mut p = path(m, left);
        p.push(mth(right));
        p
    } else {
        let mut p = path(m - k, right);
        p.push(mth(left));
        p
    }
}

/// Verify an inclusion proof: recompute the root from `leaf_hash` at `index` in
/// a tree of `size` leaves, folding the `audit` path, and compare against
/// `expected_root`.
///
/// This is the standalone verifier's core — it needs only the leaf hash, the
/// coordinates `(index, size)`, the audit path, and the claimed root; it never
/// needs the whole tree. Returns `false` for out-of-range coordinates, a
/// wrong-length audit path, or a root mismatch.
#[must_use]
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    index: u64,
    size: u64,
    audit: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    let mut hash = *leaf_hash;
    let mut idx = index;
    let mut last = size - 1;
    let mut iter = audit.iter();
    // BOUNDED BY CONSTRUCTION, not by trusting `last` to reach 0. `last` is a
    // u64 shifted right once per level, so a well-formed walk finishes within
    // `u64::BITS` levels — for `size == u64::MAX` it needs exactly that many,
    // so the bound is tight rather than arbitrary. Stating it as the loop bound
    // means no single operator in this walk can turn an attacker-supplied proof
    // into a loop that never returns. Mutation testing found precisely that:
    // flipping `>` to `>=` here — and three operators in `verify_consistency` —
    // produced HANGS rather than wrong answers, and RQ-SPECIFICATION §4.2
    // counts a `timeout_nontermination` as a finding against the CODE.
    //
    // The exit test lives inside the loop, and the "did we actually finish"
    // test below it, so that both remain reachable and therefore killable; a
    // `while` loop with a separate counter would have made the guard
    // unreachable on every well-formed input, which is an equivalent mutant.
    for _ in 0..u64::BITS {
        if last == 0 {
            break;
        }
        if idx & 1 == 1 {
            // Right child: sibling is on the left.
            let Some(sibling) = iter.next() else {
                return false;
            };
            hash = node_hash(sibling, &hash);
        } else if idx < last {
            // Left child with a right sibling.
            let Some(sibling) = iter.next() else {
                return false;
            };
            hash = node_hash(&hash, sibling);
        }
        // else: idx == last and even — a left child promoted to the next level
        // with no sibling at this level; consume no audit node.
        idx >>= 1;
        last >>= 1;
    }
    // Ran out of levels before the walk completed: the coordinates cannot
    // describe any tree, so fail closed rather than accept a partial fold.
    if last != 0 {
        return false;
    }
    iter.next().is_none() && hash == *expected_root
}

/// Generate the RFC 6962 consistency proof that the tree of size `m` is a
/// prefix of the tree formed by `leaf_hashes` (size `n`).
///
/// Returns `None` unless `0 < m <= n`. An `m == n` proof is empty.
#[must_use]
pub fn consistency_proof(m: usize, leaf_hashes: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    let n = leaf_hashes.len();
    if m == 0 || m > n {
        return None;
    }
    Some(subproof(m, leaf_hashes, true))
}

/// RFC 6962 §2.1.2 `SUBPROOF(m, D[n], b)`.
fn subproof(count: usize, hashes: &[[u8; 32]], with_root: bool) -> Vec<[u8; 32]> {
    let len = hashes.len();
    if count == len {
        if with_root {
            return Vec::new();
        }
        return vec![mth(hashes)];
    }
    let split = largest_pow2_lt(len);
    let (left, right) = hashes.split_at(split);
    if count <= split {
        let mut proof = subproof(count, left, with_root);
        proof.push(mth(right));
        proof
    } else {
        let mut proof = subproof(count - split, right, false);
        proof.push(mth(left));
        proof
    }
}

/// Verify a consistency proof per RFC 6962 §2.1.2.
///
/// Confirms that `first_hash` (the root of the size-`first` tree) and
/// `second_hash` (the root of the size-`second` tree) are consistent given
/// `proof` — i.e. the first tree is a genuine prefix of the second. Returns
/// `false` on any inconsistency, wrong proof length, or `first > second`.
#[must_use]
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &[u8; 32],
    second_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_hash == second_hash;
    }
    if first == 0 {
        // The empty tree is a prefix of every tree; RFC carries no nodes.
        return proof.is_empty();
    }

    // Step 1: if `first` is an exact power of two, prepend `first_hash`.
    let mut full: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        full.push(*first_hash);
    }
    full.extend_from_slice(proof);

    let Some((seed, rest)) = full.split_first() else {
        return false;
    };
    let mut fr = *seed;
    let mut sr = *seed;

    // Steps 2-3: fn / sn, then shift out the common low one-bits.
    let mut fnv = first - 1;
    let mut sn = second - 1;
    // Bounded for the reason spelled out in `verify_inclusion`: shifting a u64
    // clears it within `u64::BITS` steps, and three operators in this function
    // become non-terminating when flipped. A hang on attacker-supplied input is
    // a denial of service, not a failed check.
    for _ in 0..u64::BITS {
        if fnv & 1 == 0 {
            break;
        }
        fnv >>= 1;
        sn >>= 1;
    }

    // Step 5: fold the remaining nodes.
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fnv & 1 == 1 || fnv == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnv & 1 == 0 {
                // Same bound, same reason: `|| fnv == 0` flipped to `&&` made
                // this inner walk unable to ever break.
                for _ in 0..u64::BITS {
                    fnv >>= 1;
                    sn >>= 1;
                    if fnv & 1 == 1 || fnv == 0 {
                        break;
                    }
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnv >>= 1;
        sn >>= 1;
    }

    // Step 6.
    fr == *first_hash && sr == *second_hash && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6962 §2.1 defines the empty tree's hash as the hash of the
    /// empty string. Both `FnValue` replacements ([0; 32], [1; 32])
    /// survived because nothing ever asserted the value.
    ///
    /// The expected digest is the PUBLISHED SHA3-256 of the empty input
    /// (FIPS 202), not a value read back off this implementation — an
    /// implementation-derived oracle would kill the mutants while proving
    /// nothing about correctness (RQ-SPECIFICATION §4.6).
    #[test]
    fn empty_root_is_the_published_sha3_256_of_the_empty_string() {
        let expected: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(empty_root(), expected);
    }

    /// Deterministic leaf hashes `leaf_hash(b"leaf-<i>")` for i in 0..n.
    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(merkle_root(&[]), empty_root());
        let one = leaves(1);
        assert_eq!(merkle_root(&one), one[0]);
    }

    #[test]
    fn largest_pow2_lt_values() {
        assert_eq!(largest_pow2_lt(2), 1);
        assert_eq!(largest_pow2_lt(3), 2);
        assert_eq!(largest_pow2_lt(4), 2);
        assert_eq!(largest_pow2_lt(5), 4);
        assert_eq!(largest_pow2_lt(8), 4);
        assert_eq!(largest_pow2_lt(9), 8);
    }

    /// The §16.3 five-leaf vector exercises the right-edge promotion case a
    /// power-of-two tree hides. Root = node(node(node(h0,h1),node(h2,h3)),h4).
    #[test]
    fn five_leaf_root_structure() {
        let h = leaves(5);
        let n01 = node_hash(&h[0], &h[1]);
        let n23 = node_hash(&h[2], &h[3]);
        let n0123 = node_hash(&n01, &n23);
        let expected = node_hash(&n0123, &h[4]);
        assert_eq!(merkle_root(&h), expected);
    }

    /// Largest tree size the exhaustive round-trip tests walk. Under Miri,
    /// 9 still reaches every shape the proof code branches on — powers of two
    /// (1, 2, 4, 8), right-edge splits (3, 5, 6, 7) and a fourth level (9) —
    /// and Miri is checking those code paths for UB, not re-deriving the
    /// arithmetic; the full walk (O(n²) SHA3 calls) cost it over 40 minutes.
    const EXHAUSTIVE_MAX: usize = if cfg!(miri) { 9 } else { 33 };

    /// Inclusion proofs round-trip for every leaf in trees of size
    /// `1..=EXHAUSTIVE_MAX`, including the non-power-of-two right-edge cases.
    #[test]
    fn inclusion_roundtrip_all_sizes() {
        for n in 1..=EXHAUSTIVE_MAX {
            let h = leaves(n);
            let root = merkle_root(&h);
            for (i, leaf) in h.iter().enumerate() {
                let audit = inclusion_proof(i, &h).expect("in range");
                assert!(
                    verify_inclusion(leaf, i as u64, n as u64, &audit, &root),
                    "inclusion failed n={n} i={i}",
                );
                // A wrong root must be rejected.
                let mut bad = root;
                bad[0] ^= 0x01;
                assert!(!verify_inclusion(leaf, i as u64, n as u64, &audit, &bad));
            }
        }
    }

    #[test]
    fn inclusion_out_of_range() {
        let h = leaves(4);
        assert!(inclusion_proof(4, &h).is_none());
        let root = merkle_root(&h);
        assert!(!verify_inclusion(&h[0], 4, 4, &[], &root));
    }

    /// A truncated or extended audit path must be rejected.
    #[test]
    fn inclusion_wrong_path_length() {
        let h = leaves(5);
        let root = merkle_root(&h);
        let mut audit = inclusion_proof(0, &h).expect("in range");
        audit.push([0u8; 32]);
        assert!(!verify_inclusion(&h[0], 0, 5, &audit, &root));
    }

    /// Consistency proofs round-trip for every `0 < m <= n <= 17` pair
    /// (`<= EXHAUSTIVE_MAX` under Miri).
    #[test]
    fn consistency_roundtrip_all_pairs() {
        for n in 1..=EXHAUSTIVE_MAX.min(17) {
            let h = leaves(n);
            let root_n = merkle_root(&h);
            for m in 1..=n {
                let proof = consistency_proof(m, &h).expect("0 < m <= n");
                let (prefix, _) = h.split_at(m);
                let root_m = merkle_root(prefix);
                assert!(
                    verify_consistency(m as u64, n as u64, &root_m, &root_n, &proof),
                    "consistency failed m={m} n={n}",
                );
                // Tampering either root must break it.
                let mut bad = root_m;
                bad[0] ^= 0x01;
                assert!(!verify_consistency(
                    m as u64, n as u64, &bad, &root_n, &proof
                ));
            }
        }
    }

    #[test]
    fn consistency_equal_sizes_is_empty() {
        let h = leaves(7);
        let root = merkle_root(&h);
        let proof = consistency_proof(7, &h).expect("m == n");
        assert!(proof.is_empty());
        assert!(verify_consistency(7, 7, &root, &root, &proof));
        // Non-empty proof at equal sizes is rejected.
        assert!(!verify_consistency(7, 7, &root, &root, &[[0u8; 32]]));
    }

    #[test]
    fn consistency_rejects_first_gt_second() {
        let h = leaves(4);
        let root = merkle_root(&h);
        assert!(!verify_consistency(5, 4, &root, &root, &[]));
    }

    #[test]
    fn consistency_out_of_range() {
        let h = leaves(4);
        assert!(consistency_proof(0, &h).is_none());
        assert!(consistency_proof(5, &h).is_none());
    }

    // ---- adversarial: verifiers must REJECT forgeries, not just accept valid proofs ----

    /// An audit path for leaf `i` must not verify a *different* leaf hash.
    #[test]
    fn inclusion_rejects_wrong_leaf() {
        let h = leaves(6);
        let root = merkle_root(&h);
        let audit = inclusion_proof(2, &h).expect("in range");
        // Correct leaf at index 2 verifies; a different leaf at the same
        // coordinates must not.
        assert!(verify_inclusion(&h[2], 2, 6, &audit, &root));
        assert!(!verify_inclusion(&h[3], 2, 6, &audit, &root));
    }

    /// A correct audit path presented at the wrong index must fail.
    #[test]
    fn inclusion_rejects_wrong_index() {
        let h = leaves(7);
        let root = merkle_root(&h);
        let audit = inclusion_proof(5, &h).expect("in range");
        assert!(verify_inclusion(&h[5], 5, 7, &audit, &root));
        assert!(!verify_inclusion(&h[5], 4, 7, &audit, &root));
        assert!(!verify_inclusion(&h[5], 6, 7, &audit, &root));
    }

    /// A genuine consistency proof for tree A must not validate against an
    /// unrelated tree B's roots — the proof binds to specific roots.
    #[test]
    fn consistency_rejects_cross_tree() {
        let genuine = leaves(8);
        let foreign: Vec<[u8; 32]> = (0..8)
            .map(|i| leaf_hash(format!("OTHER-{i}").as_bytes()))
            .collect();
        let proof = consistency_proof(4, &genuine).expect("0 < m <= n");
        let (genuine_prefix, _) = genuine.split_at(4);
        let genuine_old = merkle_root(genuine_prefix);
        let genuine_new = merkle_root(&genuine);
        let (foreign_prefix, _) = foreign.split_at(4);
        let foreign_old = merkle_root(foreign_prefix);
        let foreign_new = merkle_root(&foreign);
        // Genuine pair verifies; substituting either foreign root fails.
        assert!(verify_consistency(4, 8, &genuine_old, &genuine_new, &proof));
        assert!(!verify_consistency(
            4,
            8,
            &foreign_old,
            &genuine_new,
            &proof
        ));
        assert!(!verify_consistency(
            4,
            8,
            &genuine_old,
            &foreign_new,
            &proof
        ));
        assert!(!verify_consistency(
            4,
            8,
            &foreign_old,
            &foreign_new,
            &proof
        ));
    }

    /// A tampered audit node (interior sibling flipped) must fail inclusion.
    #[test]
    fn inclusion_rejects_tampered_audit_node() {
        let h = leaves(9);
        let root = merkle_root(&h);
        let mut audit = inclusion_proof(0, &h).expect("in range");
        let last = audit.len() - 1;
        audit[last][0] ^= 0x01;
        assert!(!verify_inclusion(&h[0], 0, 9, &audit, &root));
    }
}
