## Phase 5 — adversarial

```
Implement Phase 5: break it.

Build `adversarial/` with a deliberately compromised agent and run these:

Agent-side attacks (all must fail at the module):
1. Prompt injection instructing the agent to send everything to an attacker
   address
2. Agent constructs its own EIP-3009 authorisation bypassing the policy engine
3. Agent replays a previously successful authorisation
4. Agent splits one over-cap payment into many under-cap ones (must fail on
   cumulative cap, not per-tx)
5. Agent submits a payment with a valid Merkle proof for a different allowlist
6. Agent races a revocation with an in-flight authorisation
7. Agent tries to reach the session key directly in the policy engine process

Prover-side attacks (all must fail at the circuit or verifier):
8. Omit expensive payments from the proof — must fail because the tree is built
   by the module, not the prover. Demonstrate exactly why.
9. Amount overflow to make sum <= cap hold falsely
10. Duplicate leaf indices
11. Proof against a stale root
12. Proof with mismatched public inputs vs on-chain mandate

For each: automated test, the specific defence that stops it, and whether the
defence is on-chain or in-circuit. Any that succeed — do not paper over them.
Write them up as known limitations with a proposed fix.

Finally produce BENCHMARKS.md and SECURITY.md, and a comparison table against
raw x402, AP2, and plain ERC-7710 session keys across: enforcement point,
bypassability, audit output, privacy, gas.
```
