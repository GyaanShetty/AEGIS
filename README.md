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

Scaffold. Contracts are interfaces and stubs with the intended behaviour documented in NatSpec. Nothing is implemented. That is deliberate — the stubs encode the design so the build has something to be checked against.
