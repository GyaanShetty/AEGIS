# AEGIS — Verifiable Spend Authority for Autonomous Agents

A delegation, enforcement, and zero-knowledge attestation layer for stablecoin payments made by AI agents.

---

## 1. The problem

An autonomous agent that can pay for things needs a wallet. Today there are two options and both are bad.

**Option A — give the agent a private key.** It can now spend everything. A prompt injection, a bad tool description, a hallucinated loop, or a compromised host and the funds are gone. There is no bound on the damage.

**Option B — put a human in the loop for every payment.** This destroys the entire point. An agent making 4,000 API calls at $0.002 each cannot ask permission 4,000 times.

What is missing is the middle: a way for a principal (a person, or a company) to grant an agent *bounded, scoped, revocable* spending authority, have that bound enforced by something the agent cannot talk its way past, and then afterwards **prove to a third party that the bound held** — without publishing every individual payment.

That third leg is the one nobody has built. It is also the one that matters for anything regulated.

### Why the third leg matters

Financial supervision assumes a payer you can identify and a spend pattern you can audit. An agent breaks both. The payer is a model instance acting under delegated authority; the "customer" in Know Your Customer is the principal, but the *actor* is not. Meanwhile the payment stream is high-frequency, low-value, and machine-generated — exactly the shape that looks like structuring to any conventional monitoring system.

So there are two parties who want assurance and cannot currently get it:

- The **principal**, who wants to know their agent did not exceed mandate, and wants that as evidence, not as a log file they wrote themselves.
- The **counterparty or supervisor**, who wants to know payments came from a legitimately delegated authority under an enforced cap — without receiving a full transaction-by-transaction dump of a company's operational spending.

Zero-knowledge proofs resolve exactly this tension. Prove the aggregate property, reveal nothing else.

---

## 2. What Aegis is

Three layers, each independently useful, strongest together.

**Layer 1 — Delegation.** A principal issues a scoped mandate to an agent: spend cap, time window, allowed counterparties, per-transaction limit, rate limit. Signed, expiring, revocable mid-flight. The agent holds a session key, never the principal's key.

**Layer 2 — Enforcement.** Every payment is validated twice. Off-chain, by a policy engine that sits between the agent and the signer. On-chain, by a validation module on the agent's smart account that will revert anything outside mandate. Defence in depth: the off-chain engine gives good errors and fast failure, the on-chain module is the thing that cannot be argued with.

**Layer 3 — Attestation.** Every settled payment is committed to an append-only Merkle tree. At the end of a period, a ZK circuit proves: *the sum of all payments under mandate M is ≤ cap, every counterparty was in the allowlist, every timestamp was inside the window, and the committed tree matches the root the enforcement module published.* A verifier contract checks the proof and emits a compliance attestation. The individual payments are never revealed.

That final attestation is the product. Everything before it is plumbing that makes it honest.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  PRINCIPAL (human / org)                                     │
│  • owns ERC-4337 smart account                               │
│  • signs mandate (EIP-712): cap, window, allowlist, limits   │
│  • can revoke at any time                                    │
└───────────────┬──────────────────────────────────────────────┘
                │ mandate + session key
                ▼
┌──────────────────────────────────────────────────────────────┐
│  AGENT RUNTIME                                               │
│  • LLM + tools (MCP / function calling)                      │
│  • holds session key ONLY                                    │
│  • discovers priced endpoints via HTTP 402                   │
└───────────────┬──────────────────────────────────────────────┘
                │ intent: pay X to Y for Z
                ▼
┌──────────────────────────────────────────────────────────────┐
│  POLICY ENGINE  (off-chain, pre-signature)                   │
│  • evaluates intent against mandate                          │
│  • budget ledger, velocity window, allowlist check           │
│  • anomaly scoring                                           │
│  • REJECT → structured error back to agent                   │
│  • ALLOW  → construct EIP-3009 authorization, sign           │
└───────────────┬──────────────────────────────────────────────┘
                │ X-PAYMENT header (signed authorization)
                ▼
┌──────────────────────────────────────────────────────────────┐
│  RESOURCE SERVER  (x402-gated API)                           │
│  402 → requirements → verify → settle → 200 + resource       │
└───────────────┬──────────────────────────────────────────────┘
                │ settlement
                ▼
┌──────────────────────────────────────────────────────────────┐
│  ON-CHAIN  (Base / Base Sepolia)                             │
│                                                              │
│  SmartAccount (ERC-4337)                                     │
│    └── SpendPolicyModule   ← hard enforcement, reverts       │
│          • per-mandate budget counter                        │
│          • counterparty allowlist root                       │
│          • expiry + revocation                               │
│          • appends Poseidon commitment of each payment       │
│          • maintains incremental Merkle root                 │
│                                                              │
│  AttestationVerifier                                         │
│    • verifies Groth16 / PLONK proof                          │
│    • checks public root == module's published root           │
│    • emits MandateCompliant(mandateId, period, root)         │
└──────────────────────────────────────────────────────────────┘
                ▲
                │ proof
┌───────────────┴──────────────────────────────────────────────┐
│  PROVER  (off-chain, run by principal or agent operator)     │
│  Circuit inputs:                                             │
│    private: [amount, counterparty, timestamp, salt] × N      │
│             Merkle paths                                     │
│    public:  root, cap, windowStart, windowEnd,               │
│             allowlistRoot, mandateId                         │
│  Constraints:                                                │
│    1. each leaf = Poseidon(amount, cpty, ts, salt)           │
│    2. each leaf ∈ tree(root)                                 │
│    3. Σ amount ≤ cap                                         │
│    4. ∀ i: windowStart ≤ ts_i ≤ windowEnd                    │
│    5. ∀ i: cpty_i ∈ tree(allowlistRoot)                      │
│    6. no duplicate leaf indices                              │
└──────────────────────────────────────────────────────────────┘
```

### Why each piece is where it is

**Session key, not private key.** The agent process is the untrusted component. Assume it will be prompt-injected. The blast radius must be the mandate, not the treasury.

**Two enforcement points.** Off-chain alone is bypassable by anything that can reach the signer. On-chain alone gives the agent no usable feedback and wastes gas on doomed transactions. Both.

**Commitments written by the enforcement module, not the agent.** This is the load-bearing design decision. If the agent (or its operator) built the commitment tree, the proof would only show *"I can produce a set of payments summing under cap"* — trivially satisfiable by omitting the inconvenient ones. Because the on-chain module appends the commitment as a side effect of authorising the payment, the tree is complete by construction. The proof then means something.

**EIP-3009 over EIP-2612.** `transferWithAuthorization` gives you a single signed object that the receiver submits and pays gas for. No separate approve. No agent-held ETH for gas. This is what x402 uses and it is the right primitive for machine payments.

**Poseidon, not Keccak.** Keccak inside a SNARK circuit is roughly two orders of magnitude more constraints. Poseidon is designed for this. The on-chain cost is higher than Keccak but that is the correct trade here.

---

## 4. Scope

### In scope (build this)

- Mandate issuance + EIP-712 signing, revocation
- Session key derivation and scoping
- Policy engine: cap, per-tx limit, window, allowlist, velocity
- ERC-4337 account with a spend-policy validation module
- Incremental Merkle tree of payment commitments, on-chain root
- x402 client (agent side) and x402 resource server (test counterparty)
- ZK circuit + verifier contract for period attestation
- Two demo agents and a priced API to pay
- Adversarial test suite: a prompt-injected agent that tries to exceed mandate and fails

### Explicitly out of scope

- Fiat on/off ramps
- Production key custody (TEE/MPC) — note the requirement, stub the implementation
- Cross-chain
- Identity/reputation registry — integrate ERC-8004 as a reference, do not rebuild it
- Recursive proofs for unbounded N — fix a max payment count per period, note the extension

### Non-obvious hard parts

1. **Circuit size vs. payment count.** N payments = N Merkle inclusion proofs. At a 20-deep tree and Poseidon, this grows fast. Fix N=64 or 128 per attestation period, chunk longer periods, mention recursion as future work.
2. **Front-running the commitment.** The module must append the commitment atomically with the spend, in the same transaction. Any gap is a hole.
3. **Revocation races.** A revocation and an in-flight authorization can cross. Nonce-based invalidation on the module, not just an expiry check.
4. **Amount rounding.** USDC has 6 decimals. Every sum in the circuit is a field element. Enforce range checks or a crafted overflow makes "sum ≤ cap" vacuous. This is the single most likely place to introduce a soundness bug.
5. **Nullifiers for duplicate leaves.** Without an explicit uniqueness constraint over leaf indices, a prover can use the same cheap payment 64 times and prove almost nothing.

---

## 5. Market and significance

Framed honestly — treat all sizing as directional and verify current figures before you cite them anywhere.

**The tailwind is real and recent.** Agentic commerce went from speculation to shipped protocols inside about a year: x402 (Coinbase), AP2 (Google), ACP (OpenAI/Stripe), ERC-8004 for agent identity. Stablecoin settlement volume is now large enough that the payment rails argument is no longer theoretical, and the regulatory perimeter in the US and EU firmed up over 2025. The infrastructure question moved from *"will agents pay?"* to *"under what controls?"*

**The gap is specific.** Every one of those protocols solves *how an agent transmits a payment*. None solves *how a principal bounds an agent and proves the bound held*. x402 has no mandate concept. AP2 has mandates but they are attested, not cryptographically enforced, and there is no privacy-preserving audit output. Existing smart-account session-key work (ERC-7710/7715, Safe modules) gives you enforcement but no attestation.

**Who pays for this.**
- Enterprises deploying agents with budgets — they need an auditable control, not a trust exercise. This is the immediate buyer.
- Agent platforms — spend safety is a differentiator and a liability shield.
- Auditors and supervisors — a verifiable attestation is cheaper to check than a transaction dump is to review.
- Insurers, eventually — you cannot price agent-misbehaviour risk without a bounded, provable exposure.

**Why it holds up as a standalone project.** It is a genuine gap with a working artefact attached, it does not depend on any other body of work to make sense, and the demo carries itself: a prompt-injected agent trying and failing to drain a wallet, followed by a proof that it never did. That reads as well to an examiner as to an engineer as to a hiring manager.

Positioned plainly, this is **payment infrastructure and safety tooling for autonomous agents**. It is not a DeFi project — there is no lending, trading, liquidity provision, or yield anywhere in it. It uses stablecoins and smart accounts as rails, nothing more. Say that up front rather than letting someone else point it out; the scope is clear and defensible on its own terms.

**Publication angles.** Formalising delegated spend authority for non-human actors; privacy-preserving compliance attestation for machine-generated micropayment streams; the attribution problem when the actor is a model instance and the accountable party is its principal. The third is the thinnest in the literature and the most interesting — existing financial-supervision models assume a payer you can identify, and an agent quietly breaks that assumption.

---

## 6. Build phases

**Phase 0 — Foundation (week 1–2).** Foundry project. ERC-20 with EIP-3009 (test USDC). Basic ERC-4337 account. Deploy to Base Sepolia. Prove the plumbing works end to end with one manual payment.

**Phase 1 — Delegation + enforcement (week 3–5).** Mandate struct, EIP-712 hashing, session key. SpendPolicyModule: budget counter, per-tx cap, window, allowlist root, revocation nonce. Fuzz the limits.

**Phase 2 — x402 loop (week 6–7).** Resource server returning 402 with requirements. Agent client that parses, signs, retries. Policy engine in front of the signer. Now an actual agent is paying for actual API calls under actual limits.

**Phase 3 — Commitments (week 8–9).** Poseidon-hash each payment inside the module. Incremental Merkle tree, published root. Off-chain indexer reconstructing leaves from events.

**Phase 4 — ZK attestation (week 10–13).** Circuit in Circom or Noir. Constraints 1–6 above. Trusted setup or use a universal one. Verifier contract. Full period proof verifying on-chain.

**Phase 5 — Adversarial + write-up (week 14–16).** Prompt-injection agent. Attempted mandate escapes. Gas benchmarks. Proof time vs N curve. Comparison table against x402 / AP2 / raw session keys. Paper.

Phases 0–2 alone are a complete, defensible project. Phases 3–4 are what make it research.

---

## 7. Stack

| Layer | Choice | Why |
|---|---|---|
| Contracts | Solidity + Foundry | Fuzzing and fork testing are first-class |
| Account | ERC-4337 (eth-infinitism reference) | Module pattern is what you need |
| Chain | Base Sepolia → Base | Where x402 lives, cheap, EIP-3009 USDC |
| Circuits | Noir (or Circom) | Noir is far faster to write; Circom has more examples |
| Hash | Poseidon | SNARK-friendly |
| Agent | Python + MCP or LangChain | Tool-calling loop, easy to inject faults into |
| Policy engine | FastAPI + SQLite | Keep it boring, it is not the research |
| Indexer | viem + event logs | No subgraph needed at this scale |
| Analysis | Slither, forge coverage | Required for any credible security claim |

---

## 8. Evaluation

Do not just demo it. Measure:

- Gas per policy-enforced payment vs. a raw ERC-20 transfer (the enforcement tax)
- Proof generation time as N grows: 8, 16, 32, 64, 128
- On-chain verification gas, fixed regardless of N (state this — it is the point)
- Policy engine rejection latency
- Adversarial results: number of distinct mandate-escape attempts, number that succeeded (target: zero, and explain each attempt)
- Privacy claim stated precisely: what the attestation leaks (N, cap, window, allowlist root, aggregate bound) and what it does not (individual amounts, individual counterparties, timing within window)

That last line is the difference between a ZK project and a project with ZK in it. Be exact about it.

---

## 9. Prior art to read before writing code

- x402 specification and the Coinbase facilitator implementation
- EIP-3009, EIP-2612, Permit2
- ERC-4337, ERC-7710, ERC-7715
- ERC-8004 (agent identity/reputation)
- Google AP2 mandate model
- Tornado Cash circuits — the canonical Merkle-inclusion-in-ZK reference, read it for structure not for purpose
- Semaphore — for the nullifier pattern
- Any recent work on privacy-preserving proof-of-reserves; the aggregate-bound proof is structurally similar

Check each of these for whether someone has already combined delegation with ZK attestation before you commit. Search terms: "verifiable spend limit", "zero knowledge budget proof", "agent payment mandate enforcement", "private proof of solvency".
