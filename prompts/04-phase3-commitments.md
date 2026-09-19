## Phase 3 — commitments

```
Implement Phase 3: payment commitments and the on-chain Merkle tree.

In `SpendPolicyModule.sol`, on each authorised payment, compute
  leaf = Poseidon(amount, counterparty, timestamp, salt)
and insert it into an incremental Merkle tree (fixed depth 7, so 128 leaves per
mandate period). Store and expose the current root. Emit
LeafInserted(mandateId, index, leaf) — and note the salt must come from the
module's own entropy, not from the agent.

This insertion MUST be atomic with the spend accounting. There is no path
through the module where a payment is authorised and a leaf is not appended.
Write a test that tries to find one.

Use an audited Poseidon implementation for Solidity — pick one, tell me which
and why. Benchmark the gas delta versus the Phase 1 module.

Then build `indexer/` — reads LeafInserted and Spend events via viem, rebuilds
the tree off-chain, and asserts its computed root matches the on-chain root.
That assertion is the bridge to the prover; if it ever drifts, the proof step
is dead.
```
