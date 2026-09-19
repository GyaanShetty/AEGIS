## Phase 4 — ZK attestation

```
Implement Phase 4: the attestation circuit and verifier.

Circuit (Noir), `circuits/mandate_compliance/`:

  Public inputs:  root, totalCap, windowStart, windowEnd, allowlistRoot,
                  mandateId, leafCount
  Private inputs: amounts[128], counterparties[128], timestamps[128],
                  salts[128], merklePaths[128], leafIndices[128]

  Constraints:
    1. for each i < leafCount:
         leaf_i == Poseidon(amounts[i], counterparties[i], timestamps[i], salts[i])
    2. for each i < leafCount:
         merkle_verify(leaf_i, merklePaths[i], leafIndices[i]) == root
    3. sum(amounts[0..leafCount]) <= totalCap
    4. for each i: windowStart <= timestamps[i] <= windowEnd
    5. for each i: merkle_verify(counterparties[i], ...) == allowlistRoot
    6. all leafIndices distinct
    7. padding beyond leafCount contributes zero and cannot affect 3

  Constraint 3 is the soundness-critical one. Sums are field elements. Add
  explicit range checks on every amount (USDC is 6 decimals — bound amounts to
  2^64) so a crafted overflow cannot make the inequality vacuous. Same for the
  running sum. Write a test that attempts this attack and confirm the circuit
  rejects it.

  Constraint 6 matters too: without it a prover reuses one cheap leaf 128 times
  and proves nothing. Test that attack as well.

Then:
- `AttestationVerifier.sol` — verifies the proof, checks the public root equals
  the module's current published root for that mandate and period, checks the
  public cap/window/allowlistRoot match the on-chain mandate, emits
  MandateCompliant(mandateId, periodEnd, root).
- `prover/` — CLI that pulls leaves from the indexer, generates the proof,
  submits it.

Benchmark and report: proof time at N = 8/16/32/64/128, proof size, on-chain
verification gas. I expect verification gas to be flat in N — confirm it is and
tell me if it isn't.
```
