# Architecture

## Components and trust

| Component | Trusted? | Holds | Can be removed without losing safety? |
|---|---|---|---|
| Principal | yes | master key | no |
| Agent runtime | **no** | nothing | n/a |
| Policy engine | partly | session key | yes — safety unaffected, usability lost |
| Resource server | no | nothing of ours | n/a |
| SpendPolicyModule | yes (code) | budget state, tree | no — this is the boundary |
| Prover | no | payment details | yes — attestation lost, enforcement unaffected |

The test for any design change: if the policy engine and the prover were both replaced by an attacker, would the mandate still hold? It must.

## Payment flow

```
agent decides it needs a paid resource
  → GET /resource
  → 402 + payment requirements {asset, amount, payTo, nonce, validBefore}
  → agent asks policy engine to authorise
      engine checks: cap remaining, per-tx, window, allowlist, velocity
      reject → structured reason code back to agent, no signature produced
      allow  → engine signs EIP-3009 transferWithAuthorization
  → agent retries with X-PAYMENT header
  → server verifies signature, submits settlement
  → SmartAccount → SpendPolicyModule.validate()
        re-checks EVERY condition the engine checked
        appends Poseidon commitment to Merkle tree
        increments spent + txCount
        all in one transaction, atomically
  → transfer executes, server returns 200 + resource
```

The engine and module check the same conditions. That duplication is intentional, not redundant — the engine exists to give the agent a fast readable rejection, the module exists because the engine is bypassable.

## Attestation flow

```
indexer reads LeafInserted events
  → rebuilds the tree off-chain
  → asserts local root == on-chain root     ← if this ever drifts, proving is dead
prover
  → assembles private witness: amounts, counterparties, timestamps, salts, paths
  → generates proof against public inputs: root, cap, window, allowlistRoot, mandateId, leafCount
AttestationVerifier
  → verifies proof
  → checks public root matches module's published root for that mandate+period
  → checks public cap/window/allowlistRoot match the on-chain mandate
  → emits MandateCompliant(mandateId, periodEnd, root)
```

## Design decisions and why

**Session key, not private key.** The agent process is the thing that gets compromised. Blast radius must be the mandate, not the treasury.

**Two enforcement points.** Off-chain alone is bypassable by anything reaching the signer. On-chain alone gives the agent no usable feedback and burns gas on doomed transactions.

**Module writes the commitments.** See README. This is the load-bearing decision.

**EIP-3009 over EIP-2612.** One signed object the receiver submits and pays gas for. No separate approve, no agent-held ETH. This is what x402 uses.

**Poseidon over Keccak.** Keccak in-circuit is roughly two orders of magnitude more constraints. Higher on-chain cost, correct trade.

**Fixed tree depth 7 (128 leaves).** Bounds circuit size. Longer periods chunk into multiple attestations. Recursion is future work, not scope.

## What the attestation reveals

State this precisely in any write-up.

Revealed: number of payments, the cap, the window bounds, the allowlist root, the mandate id, and the fact that aggregate spend was within cap.

Not revealed: individual amounts, individual counterparties, timing within the window, the ordering of payments.

That gap is the contribution. Be exact about it.
