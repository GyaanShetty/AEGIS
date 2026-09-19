# Claude Code — build prompt

Paste the section you need. Do not paste all of it at once; Claude Code works better with one phase at a time and a plan step before each.

---

## Kickoff prompt (paste first, alone)

```
We're building AEGIS: a spend-authority and zero-knowledge compliance layer for
autonomous AI agents that pay in stablecoins.

Core idea: a principal grants an agent a bounded, revocable spending mandate
(cap, time window, counterparty allowlist, per-tx limit, rate limit). Every
payment is enforced against that mandate on-chain by a validation module on an
ERC-4337 smart account. The module commits each authorised payment into an
incremental Merkle tree. At period end, a ZK circuit proves the aggregate spend
stayed within mandate — without revealing individual payments — and a verifier
contract emits a compliance attestation.

Threat model, and this drives every design decision: the agent process is
UNTRUSTED. Assume it is prompt-injected. It holds a session key, never the
principal's key. The off-chain policy engine is a usability layer; the on-chain
module is the actual security boundary. Nothing the agent says can widen its
mandate.

Stack: Solidity + Foundry, Base Sepolia, ERC-4337 (eth-infinitism reference),
EIP-3009 USDC for gasless authorised transfers, x402 for the payment handshake,
Poseidon hashing, Noir for circuits, Python for the agent runtime and policy
engine.

Before writing any code:
1. Read the x402 spec, EIP-3009, ERC-4337, and ERC-7710. Summarise for me how
   the pieces fit and flag anything in my design that conflicts with them.
2. Propose a repo layout.
3. Give me a phase plan with explicit acceptance criteria per phase.

Do not scaffold yet. Plan first, then wait for me.
```

---

## Phase 1 — delegation + enforcement

```
Implement Phase 1: mandate issuance and on-chain enforcement.

Contracts:

1. `Mandate.sol` — library defining the mandate struct and its EIP-712 typehash.
   Fields: mandateId, principal, agentSessionKey, token, totalCap,
   perTxCap, windowStart, windowEnd, allowlistRoot, maxTxCount,
   revocationNonce.

2. `SpendPolicyModule.sol` — ERC-4337 validation module. On each userOp it MUST:
   - recover the session key signature and confirm it matches the mandate
   - reject if block.timestamp outside [windowStart, windowEnd]
   - reject if mandate's revocationNonce != the principal's current nonce
   - reject if amount > perTxCap
   - reject if spent[mandateId] + amount > totalCap
   - reject if counterparty not proven against allowlistRoot (Merkle proof
     supplied in the userOp)
   - reject if txCount[mandateId] >= maxTxCount
   - increment spent and txCount ATOMICALLY with the transfer
   Revocation: principal can bump revocationNonce, invalidating all in-flight
   authorisations for that mandate immediately.

3. `AgentAccount.sol` — minimal ERC-4337 account wired to the module.

Requirements:
- Custom errors, not require strings.
- Every state mutation emits an event with enough data for an off-chain indexer
  to reconstruct full history.
- No unbounded loops.

Tests (Foundry) — I want these specifically, not just happy path:
- spend exactly at cap succeeds; one wei over reverts
- two payments that individually pass but together exceed cap: second reverts
- payment at windowEnd succeeds, windowEnd+1 reverts
- revocation invalidates a signature that was valid one block earlier
- counterparty not in allowlist reverts even with a well-formed proof of a
  different leaf
- replayed userOp reverts
- fuzz totalCap/perTxCap/amount for arithmetic edge cases, including amounts
  near type(uint256).max

Write the tests first, watch them fail, then implement. Report the failures to
me before you implement.
```

---

## Phase 2 — x402 loop and policy engine

```
Implement Phase 2: the payment handshake and off-chain policy layer.

a) `server/` — FastAPI resource server, x402-gated.
   - GET /data returns 402 with a payment-requirements JSON body
     (scheme, network, asset, amount, payTo, resource, maxTimeoutSeconds)
   - on retry with an X-PAYMENT header, verify the EIP-3009 authorisation,
     settle it on Base Sepolia, then return 200 with the resource
   - idempotency: same authorisation nonce must never settle twice
   - if settlement succeeds but resource generation fails, that is a refund
     case — handle it explicitly, don't silently keep the money

b) `policy/` — the pre-signature policy engine.
   - receives a payment intent from the agent
   - evaluates against the active mandate: cap remaining, per-tx, window,
     allowlist, velocity (max N payments per rolling T)
   - on reject: structured error with a machine-readable reason code
   - on allow: constructs and signs the EIP-3009 authorisation with the
     session key, then hands back only the signed object
   - the agent NEVER touches the session key directly — the engine holds it
   - persist a local ledger of decisions (SQLite)

c) `agent/` — the agent runtime.
   - tool-calling loop, one tool: `fetch_paid_resource(url)`
   - handles 402 → request authorisation from policy engine → retry
   - handles policy rejection gracefully (surfaces it to the model as a tool
     error, does not retry blindly)

Critical: the policy engine must be a separate process from the agent, talking
over a narrow API. If they share memory, the threat model is broken. Enforce
that in the architecture, not just in comments.

Then: write an integration test where the agent makes payments until it hits
its cap, and confirm both engine and module reject the payment that crosses it.
```

---

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

---

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

---

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

---

## Standing instructions (worth putting in CLAUDE.md)

```
- Tests before implementation. Show me failing tests before you write the fix.
- Never claim something works without running it and showing the output.
- The agent process is untrusted. If a design decision makes sense only when
  the agent behaves, it is wrong — flag it instead of building it.
- Custom errors over require strings. Events on every state mutation.
- When you hit a fork in the design, stop and give me the options with
  trade-offs. Do not silently pick one.
- Do not add dependencies without telling me what they are and why.
- Flag anything security-critical you are unsure about rather than guessing.
```
