# Roadmap

Sixteen weeks. Phases 0–2 are a complete, demoable project on their own. Phases 3–4 are the research contribution. Build in order and you always have something finished to show.

## Phase 0 — Foundation (wk 1–2)
Foundry project. Test USDC with EIP-3009. Minimal ERC-4337 account. Deployed to Base Sepolia. One payment end to end, manually.

**Done when:** a payment settles on testnet and you can explain every step.

## Phase 1 — Delegation + enforcement (wk 3–5)
Mandate struct and EIP-712 hashing. Session key. SpendPolicyModule with budget counter, per-tx cap, window, allowlist root, revocation nonce.

**Done when:** every test in the phase-1 prompt passes, including the fuzz tests on arithmetic edges.

## Phase 2 — x402 loop (wk 6–7)
Resource server returning 402. Agent client. Policy engine in front of the signer, as a separate process.

**Done when:** an agent pays for real API calls unattended until it hits its cap, and both engine and module reject the payment that crosses it.

*Milestone: this is already a defensible project. Everything after is upside.*

## Phase 3 — Commitments (wk 8–9)
Poseidon commitment per payment, appended atomically inside the module. Incremental Merkle tree, published root. Off-chain indexer reconstructing and matching.

**Done when:** indexer root equals on-chain root across a few hundred payments, and you have failed to find a path where a payment settles without a leaf.

## Phase 4 — ZK attestation (wk 10–13)
Circuit, constraints, verifier contract, prover CLI.

**Done when:** a full period proof verifies on-chain, and the overflow and duplicate-leaf attacks both fail against your own circuit.

**Risk:** this is where projects stall. Circuit debugging is unpredictable. If week 12 arrives and the circuit isn't sound, ship Phases 0–3 and present the attestation as designed with partial implementation. Decide that in advance, not in a panic.

## Phase 5 — Adversarial + write-up (wk 14–16)
Prompt-injected agent. All twelve attacks from the threat model. Benchmarks. Comparison table. Paper.

**Done when:** every attack in `03-threat-model.md` has an automated test and a stated outcome, including any that succeeded.

## Cut lines, decided now

If behind at week 9 — drop the LLM agent, keep the algorithmic one.
If behind at week 12 — drop the circuit, keep commitments, write the attestation up as design.
Never cut — the adversarial suite. It is what makes the safety claim credible, and it is cheap.
