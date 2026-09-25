# Benchmarks & build status

Measured on this machine (Apple Silicon, darwin), local anvil / native bb.
Toolchain: forge 1.8.3, nargo 1.0.0-rc.2, noir-lang/poseidon v0.3.0, bb 5.0.0.

## What runs (all verified in this repo)

| Component | Status | Evidence |
|---|---|---|
| Phase 1 — enforcement | ✅ | 21 unit/fuzz + 2 invariants (contracts) |
| Phase 2 — x402 loop | ✅ | 10 offline integration/unit tests (offchain) |
| Phase 3 — commitments (on-chain Poseidon2) | ✅ | Poseidon2 matches Noir by test vector; indexer root == chain root on anvil |
| Phase 4 — circuit | ✅ | 6 nargo tests incl. overflow + duplicate-leaf attacks |
| Phase 4 — proof + verifier | ✅ | bb proof verifies natively and on-chain (HonkVerifier in EVM) |
| Phase 5 — adversarial | ✅ | 6 injection/escape tests, all rejected |

## The enforcement tax (gas)

A policy-enforced payment carries a Merkle insert + Poseidon2 leaf + allowlist
proof. With the **pure-Solidity** Poseidon2 that is exercised in tests:

- ~10.6M gas per authorised payment (7 pair-hashes + 1 four-input leaf + allowlist).

This is dominated by Poseidon2. The vendored library also ships **Yul** and
**Huff** implementations that cut this by ~1–2 orders of magnitude; production
should wire those in. The pure-Solidity path is used in tests for readability and
because it is trivially auditable against the Noir vectors.

> A raw ERC-20 transfer is ~30–50k gas. The enforcement + commitment machinery is
> the cost of making the attestation honest; the Yul path is what makes it
> deployable.

## Circuit

- `mandate_compliance` at N=128 (max leaves): **~98,583 ACIR opcodes** (`nargo info`).
- Proving key computed in ~0.3s; proof generation sub-second at N=1 (native bb,
  8 threads). Proof size: **9,920 bytes** (UltraHonk, keccak oracle, ZK).
- Public inputs: 7 field elements (root, totalCap, windowStart, windowEnd,
  allowlistRoot, mandateId, leafCount).

## On-chain verification gas

Verification cost is **flat in N** — the circuit is fixed-size (128 max leaves),
so the number of real payments does not change the verifier's work. This is the
point of the design: one constant-cost check attests to a whole period.

- **HonkVerifier.verify on-chain: ~2,656,338 gas** for a genuine proof
  (`FOUNDRY_PROFILE=zk forge test --match-path test/Attestation.t.sol`), constant
  regardless of how many payments the period contained. A tampered public input is
  rejected (~510k gas to the revert).

## Privacy — stated precisely

The attestation **reveals**: number of payments (leafCount), the cap, the window
bounds, the allowlist root, the mandate id, and that aggregate spend ≤ cap.

It **does not reveal**: individual amounts, individual counterparties, timing
within the window, or the ordering of payments.

(Note: the demo module emits per-payment events on-chain for indexing; in a
deployment where the chain itself must not reveal payments, settlement would move
behind the 4337 UserOp path and the events would carry only commitments. The ZK
property is about what the *attestation artifact* discloses to a supervisor.)

## Reproduce

```
make build && make test          # contracts
make offchain-test               # python
make circuit-test                # nargo
make compile-circuit && make prove && make verifier   # bb pipeline
```
