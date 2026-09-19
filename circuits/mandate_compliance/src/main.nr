// Aegis — mandate compliance circuit
//
// Proves: the payments committed in `root` sum to at most `total_cap`, all fell
// inside [window_start, window_end], all went to counterparties in
// `allowlist_root`, and none was counted twice — without revealing any
// individual payment.
//
// SOUNDNESS NOTES. Read before touching anything below.
//
// 1. RANGE CHECKS. Sums are field elements and field arithmetic wraps. Without
//    an explicit bound on every amount AND on the running sum, an attacker
//    picks amounts that overflow so that `sum <= cap` holds vacuously. USDC has
//    6 decimals, so 2^64 is a generous ceiling. This is the most likely place
//    to introduce a silent soundness bug.
//
// 2. LEAF DISTINCTNESS. Without constraint 6, a prover supplies the same cheap
//    leaf 128 times and proves essentially nothing.
//
// 3. PADDING. Slots beyond `leaf_count` must contribute exactly zero to the sum
//    and must not be able to satisfy the inclusion check. Getting this wrong
//    turns the count into an attacker-chosen parameter.

global MAX_LEAVES: u32 = 128;
global TREE_DEPTH: u32 = 7;
global MAX_AMOUNT: Field = 18446744073709551616; // 2^64

fn main(
    // --- public ---
    root: pub Field,
    total_cap: pub Field,
    window_start: pub u64,
    window_end: pub u64,
    allowlist_root: pub Field,
    mandate_id: pub Field,
    leaf_count: pub u32,

    // --- private ---
    amounts: [Field; MAX_LEAVES],
    counterparties: [Field; MAX_LEAVES],
    timestamps: [u64; MAX_LEAVES],
    salts: [Field; MAX_LEAVES],
    merkle_paths: [[Field; TREE_DEPTH]; MAX_LEAVES],
    leaf_indices: [u32; MAX_LEAVES],
    allowlist_paths: [[Field; TREE_DEPTH]; MAX_LEAVES],
) {
    // TODO(phase4) constraint 1: leaf_i == poseidon(amount, cpty, ts, salt)
    // TODO(phase4) constraint 2: merkle_verify(leaf_i, path_i, index_i) == root
    // TODO(phase4) constraint 3: sum(amounts[0..leaf_count]) <= total_cap
    //              with range checks on each amount AND the running sum
    // TODO(phase4) constraint 4: window_start <= ts_i <= window_end
    // TODO(phase4) constraint 5: merkle_verify(cpty_i, allowlist_path_i) == allowlist_root
    // TODO(phase4) constraint 6: all leaf_indices distinct
    // TODO(phase4) constraint 7: slots >= leaf_count contribute zero
    assert(leaf_count <= MAX_LEAVES);
}

#[test]
fn test_honest_proof_verifies() {}

#[test(should_fail)]
fn test_overflow_attack_rejected() {
    // amounts chosen so the field-element sum wraps below total_cap
}

#[test(should_fail)]
fn test_duplicate_leaf_indices_rejected() {
    // same cheap leaf supplied repeatedly
}

#[test(should_fail)]
fn test_out_of_window_timestamp_rejected() {}

#[test(should_fail)]
fn test_counterparty_outside_allowlist_rejected() {}
