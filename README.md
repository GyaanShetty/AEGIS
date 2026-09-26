# Aegis

Bounded spending authority and verifiable compliance for autonomous AI agents paying in stablecoins.

An owner grants an agent a scoped, revocable spending mandate. Every payment is enforced on-chain by a module the agent cannot reach or argue with. Each authorised payment is committed to a Merkle tree by that module. At period end, a zero-knowledge proof shows the aggregate spend stayed within mandate — without revealing individual payments.

## What this is not

Not a DeFi project. No lending, trading, liquidity provision, or yield. Stablecoins and smart accounts are used as payment rails, nothing more. This is payment infrastructure and agent safety tooling.

## The one idea that matters

The commitment tree is built by the enforcement module, not by the agent or its operator.

If the operator assembled the list of payments, the proof would only show "I can produce some set of payments summing under cap" — satisfiable by omitting the inconvenient ones. Because the module appends each commitment as an unavoidable side effect of authorising the payment, the tree is complete by construction. Only then does the proof mean anything.

## Layout

```
docs/        design documents — read 01 first
prompts/     Claude Code build prompts, one per phase
contracts/   Foundry project (Solidity)
circuits/    Noir circuit for the attestation proof
offchain/    policy engine, agent runtime, x402 server, indexer, prover
CLAUDE.md    standing instructions for Claude Code
```

## Start here

1. Read `docs/01-project-spec.md` end to end.
2. Work through `docs/04-prior-art-checklist.md`. An hour now beats a surprise in month three.
3. Paste `prompts/01-kickoff.md` into Claude Code. Let it plan before it writes anything.

## Status

All five phases implemented and tested. See `docs/08-benchmarks.md` for numbers.

| Phase | What | Verification |
|---|---|---|
| 1 — Delegation + enforcement | `Mandate` EIP-712, `SpendPolicyModule`, `AgentAccount`, `TestUSDC` (EIP-3009) | 21 unit/fuzz + 2 invariants |
| 2 — x402 loop | policy engine (holds the key), x402 server, key-free agent | 10 offline integration tests |
| 3 — Commitments | on-chain Poseidon2 tree + allowlist, indexer root reconstruction | Poseidon2 matches Noir by test vector; indexer root == chain root on anvil |
| 4 — ZK attestation | Noir circuit, UltraHonk proof, generated Solidity verifier, `AttestationVerifier` | 6 circuit tests (incl. 2 attacks); proof verifies on-chain @ ~2.66M gas |
| 5 — Adversarial | prompt-injection escape attempts | 6 tests, all rejected |

Toolchain: Foundry, Noir (`nargo` 1.0.0-rc.2 + `noir-lang/poseidon`), Barretenberg `bb` 5.0.0.

**Key design decisions made during the build** (see commit messages and NatSpec):
- Session signatures bind to the mandate's current `txCount` as an implicit, monotonic nonce (the fixed interface carries no nonce field).
- The whole system agrees on **Poseidon2** (BN254) for both the commitment tree and the allowlist, on-chain and in-circuit; the Solidity impl is verified byte-for-byte against Noir test vectors before it is trusted.
- Commitment salt is deterministic in `(module, mandateId, index)` — module-controlled (agent cannot influence it) yet reconstructable by the prover.
- Pure-Solidity Poseidon2 costs ~10.6M gas/payment; a Yul/Huff variant ships in the vendored lib for production.

### Reproduce

```
make build && make test          # contracts (Foundry)
make offchain-test               # policy / x402 / adversarial (pytest)
make circuit-test                # Noir circuit
make compile-circuit && make prove && make verifier   # bb proving pipeline
FOUNDRY_PROFILE=zk forge test --match-path test/Attestation.t.sol   # on-chain proof verification
```
