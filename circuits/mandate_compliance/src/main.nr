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
//    6 decimals, so 2^64 is a generous ceiling. Enforced with assert_max_bit_size.
//
// 2. LEAF DISTINCTNESS. Leaves are inserted by the module at sequential indices
//    (index == txCount). We pin `leaf_indices[i] == i`, which is distinct by
//    construction — a prover cannot reuse one cheap leaf 128 times.
//
// 3. PADDING. Slots beyond `leaf_count` are constrained to be all-zero and are
//    excluded from the inclusion checks and the sum, so `leaf_count` cannot be
//    turned into an attacker-chosen parameter.

use poseidon::poseidon2::Poseidon2;

global MAX_LEAVES: u32 = 128;
global TREE_DEPTH: u32 = 7;

fn hash_pair(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

// Commitment tree: index-ordered (matches the module's incremental tree).
fn compute_root(leaf: Field, path: [Field; TREE_DEPTH], index: u32) -> Field {
    let mut node = leaf;
    let mut idx = index;
    for i in 0..TREE_DEPTH {
        let bit = idx & 1;
        let left = if bit == 0 { node } else { path[i] };
        let right = if bit == 0 { path[i] } else { node };
        node = hash_pair(left, right);
        idx = idx >> 1;
    }
    node
}

// Allowlist tree: sorted-pair (order-independent, needs no index).
fn compute_allowlist_root(leaf: Field, path: [Field; TREE_DEPTH]) -> Field {
    let mut node = leaf;
    for i in 0..TREE_DEPTH {
        let a = node;
        let b = path[i];
        // sorted pair: lower value on the left
        let a_lt_b = a.lt(b);
        let left = if a_lt_b { a } else { b };
        let right = if a_lt_b { b } else { a };
        node = hash_pair(left, right);
    }
    node
}

fn leaf_commitment(amount: Field, counterparty: Field, timestamp: u64, salt: Field) -> Field {
    Poseidon2::hash([amount, counterparty, timestamp as Field, salt], 4)
}

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
    assert(leaf_count <= MAX_LEAVES);
    // Bind mandate_id into the proof so a proof cannot be replayed for another
    // mandate. (Consumed as a public input; the verifier checks it on-chain.)
    let _ = mandate_id;

    let mut running_sum: Field = 0;

    for i in 0..MAX_LEAVES {
        let active = (i as u32) < leaf_count;

        // (1) range-check every amount to 64 bits, unconditionally. A padding
        // slot must be zero (also within range), so this is safe to apply to all.
        amounts[i].assert_max_bit_size::<64>();

        if active {
            // (2) canonical, distinct index
            assert(leaf_indices[i] == i as u32);

            // (3) commitment inclusion in the on-chain root
            let leaf = leaf_commitment(amounts[i], counterparties[i], timestamps[i], salts[i]);
            assert(compute_root(leaf, merkle_paths[i], leaf_indices[i]) == root);

            // (4) timestamp inside the window
            assert(window_start <= timestamps[i]);
            assert(timestamps[i] <= window_end);

            // (5) counterparty in the allowlist
            assert(compute_allowlist_root(counterparties[i], allowlist_paths[i]) == allowlist_root);

            running_sum = running_sum + amounts[i];
        } else {
            // (7) padding contributes nothing
            assert(amounts[i] == 0);
        }
    }

    // (6/3) bound the running sum then compare without field wraparound.
    // 128 leaves * 2^64 < 2^71, so 72 bits is a safe envelope.
    running_sum.assert_max_bit_size::<72>();
    let sum_u: u128 = running_sum as u128;
    let cap_u: u128 = total_cap as u128;
    assert(sum_u <= cap_u);
}

// --------------------------------------------------------------------------- //
//  Tests — build the witness with the SAME functions the circuit uses.        //
// --------------------------------------------------------------------------- //

// Build a single-leaf commitment tree and return (root, path, index=0).
fn single_leaf_tree(leaf: Field) -> (Field, [Field; TREE_DEPTH]) {
    // index 0: every sibling is the zero-subtree hash.
    let mut path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let mut zero: Field = 0;
    let mut node = leaf;
    for i in 0..TREE_DEPTH {
        path[i] = zero;
        node = hash_pair(node, zero);
        zero = hash_pair(zero, zero);
    }
    (node, path)
}

// Two-leaf allowlist: {a, b}, sorted-pair up an otherwise-zero tree.
fn allowlist_two(a: Field, b: Field) -> (Field, [Field; TREE_DEPTH]) {
    // path for `a`: sibling at level 0 is b, then zeros.
    let mut path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    path[0] = b;
    let root = compute_allowlist_root(a, path);
    (root, path)
}

fn empty_paths() -> [[Field; TREE_DEPTH]; MAX_LEAVES] {
    [[0; TREE_DEPTH]; MAX_LEAVES]
}

#[test]
fn test_honest_proof_verifies() {
    let amount: Field = 1000;
    let cpty: Field = 0xCA;
    let ts: u64 = 5000;
    let salt: Field = 42;

    let leaf = leaf_commitment(amount, cpty, ts, salt);
    let (root, path) = single_leaf_tree(leaf);
    let (allow_root, allow_path) = allowlist_two(cpty, 0xCB);

    let mut amounts = [0; MAX_LEAVES];
    let mut cptys = [0; MAX_LEAVES];
    let mut tss = [0; MAX_LEAVES];
    let mut salts = [0; MAX_LEAVES];
    let mut paths = empty_paths();
    let mut indices = [0; MAX_LEAVES];
    let mut allow_paths = empty_paths();

    amounts[0] = amount;
    cptys[0] = cpty;
    tss[0] = ts;
    salts[0] = salt;
    paths[0] = path;
    indices[0] = 0;
    allow_paths[0] = allow_path;

    main(root, 2000, 0, 10000, allow_root, 0x1111, 1, amounts, cptys, tss, salts, paths, indices, allow_paths);
}

#[test(should_fail)]
fn test_overflow_attack_rejected() {
    // A single amount larger than 2^64 must fail the range check even if the
    // field-element sum would wrap below total_cap.
    let big: Field = 0x10000000000000000; // 2^64
    let cpty: Field = 0xCA;
    let ts: u64 = 5000;
    let salt: Field = 42;

    let leaf = leaf_commitment(big, cpty, ts, salt);
    let (root, path) = single_leaf_tree(leaf);
    let (allow_root, allow_path) = allowlist_two(cpty, 0xCB);

    let mut amounts = [0; MAX_LEAVES];
    let mut cptys = [0; MAX_LEAVES];
    let mut tss = [0; MAX_LEAVES];
    let mut salts = [0; MAX_LEAVES];
    let mut paths = empty_paths();
    let mut indices = [0; MAX_LEAVES];
    let mut allow_paths = empty_paths();
    amounts[0] = big;
    cptys[0] = cpty;
    tss[0] = ts;
    salts[0] = salt;
    paths[0] = path;
    allow_paths[0] = allow_path;

    main(root, 2000, 0, 10000, allow_root, 0x1111, 1, amounts, cptys, tss, salts, paths, indices, allow_paths);
}

#[test(should_fail)]
fn test_duplicate_leaf_indices_rejected() {
    // Reuse one cheap leaf at both slots but claim two payments. leaf_indices[1]
    // != 1 breaks the canonical-index constraint.
    let amount: Field = 10;
    let cpty: Field = 0xCA;
    let ts: u64 = 5000;
    let salt: Field = 42;
    let leaf = leaf_commitment(amount, cpty, ts, salt);
    let (root, path) = single_leaf_tree(leaf);
    let (allow_root, allow_path) = allowlist_two(cpty, 0xCB);

    let mut amounts = [0; MAX_LEAVES];
    let mut cptys = [0; MAX_LEAVES];
    let mut tss = [0; MAX_LEAVES];
    let mut salts = [0; MAX_LEAVES];
    let mut paths = empty_paths();
    let mut indices = [0; MAX_LEAVES];
    let mut allow_paths = empty_paths();
    for k in 0..2 {
        amounts[k] = amount;
        cptys[k] = cpty;
        tss[k] = ts;
        salts[k] = salt;
        paths[k] = path;
        indices[k] = 0; // both claim index 0 -> slot 1 violates leaf_indices[1]==1
        allow_paths[k] = allow_path;
    }
    main(root, 2000, 0, 10000, allow_root, 0x1111, 2, amounts, cptys, tss, salts, paths, indices, allow_paths);
}

#[test(should_fail)]
fn test_out_of_window_timestamp_rejected() {
    let amount: Field = 1000;
    let cpty: Field = 0xCA;
    let ts: u64 = 50; // before window_start
    let salt: Field = 42;
    let leaf = leaf_commitment(amount, cpty, ts, salt);
    let (root, path) = single_leaf_tree(leaf);
    let (allow_root, allow_path) = allowlist_two(cpty, 0xCB);

    let mut amounts = [0; MAX_LEAVES];
    let mut cptys = [0; MAX_LEAVES];
    let mut tss = [0; MAX_LEAVES];
    let mut salts = [0; MAX_LEAVES];
    let mut paths = empty_paths();
    let mut indices = [0; MAX_LEAVES];
    let mut allow_paths = empty_paths();
    amounts[0] = amount;
    cptys[0] = cpty;
    tss[0] = ts;
    salts[0] = salt;
    paths[0] = path;
    allow_paths[0] = allow_path;
    main(root, 2000, 100, 10000, allow_root, 0x1111, 1, amounts, cptys, tss, salts, paths, indices, allow_paths);
}

#[test(should_fail)]
fn test_counterparty_outside_allowlist_rejected() {
    let amount: Field = 1000;
    let cpty: Field = 0xC0; // not in {0xCA, 0xCB}
    let ts: u64 = 5000;
    let salt: Field = 42;
    let leaf = leaf_commitment(amount, cpty, ts, salt);
    let (root, path) = single_leaf_tree(leaf);
    let (allow_root, allow_path) = allowlist_two(0xCA, 0xCB); // root over other set

    let mut amounts = [0; MAX_LEAVES];
    let mut cptys = [0; MAX_LEAVES];
    let mut tss = [0; MAX_LEAVES];
    let mut salts = [0; MAX_LEAVES];
    let mut paths = empty_paths();
    let mut indices = [0; MAX_LEAVES];
    let mut allow_paths = empty_paths();
    amounts[0] = amount;
    cptys[0] = cpty;
    tss[0] = ts;
    salts[0] = salt;
    paths[0] = path;
    allow_paths[0] = allow_path;
    main(root, 2000, 0, 10000, allow_root, 0x1111, 1, amounts, cptys, tss, salts, paths, indices, allow_paths);
}

#[test(should_fail)]
fn test_sum_over_cap_rejected() {
    let amount: Field = 3000;
    let cpty: Field = 0xCA;
    let ts: u64 = 5000;
    let salt: Field = 42;
    let leaf = leaf_commitment(amount, cpty, ts, salt);
    let (root, path) = single_leaf_tree(leaf);
    let (allow_root, allow_path) = allowlist_two(cpty, 0xCB);

    let mut amounts = [0; MAX_LEAVES];
    let mut cptys = [0; MAX_LEAVES];
    let mut tss = [0; MAX_LEAVES];
    let mut salts = [0; MAX_LEAVES];
    let mut paths = empty_paths();
    let mut indices = [0; MAX_LEAVES];
    let mut allow_paths = empty_paths();
    amounts[0] = amount;
    cptys[0] = cpty;
    tss[0] = ts;
    salts[0] = salt;
    paths[0] = path;
    allow_paths[0] = allow_path;
    // cap 2000 < amount 3000
    main(root, 2000, 0, 10000, allow_root, 0x1111, 1, amounts, cptys, tss, salts, paths, indices, allow_paths);
}
