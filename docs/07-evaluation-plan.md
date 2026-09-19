# Evaluation plan

Decide what you're measuring before you build, so you instrument as you go rather than retrofitting.

## Quantitative

| Metric | How | Why it matters |
|---|---|---|
| Gas per enforced payment vs raw ERC-20 transfer | Foundry gas reports | the enforcement tax — is this viable at real payment sizes? |
| Gas delta from commitment insertion | Phase 1 module vs Phase 3 module | isolates the cost of provability |
| Proof generation time at N = 8/16/32/64/128 | prover CLI, wall clock, fixed hardware | the practical ceiling on period length |
| Proof size | bytes | calldata cost |
| On-chain verification gas | Foundry | should be **flat in N**. Confirm. If it isn't, something is wrong. |
| Policy engine rejection latency | p50/p99 | does enforcement slow the agent meaningfully? |
| Minimum viable payment size | gas cost ÷ payment | below this, per-payment settlement is uneconomic |

## Adversarial

For each of the fourteen attacks in the threat model: automated test, outcome, and the specific defence that stopped it and where it lives.

Target is zero successes. If any succeed, report them as known limitations with a proposed fix. Do not quietly drop them — a paper that names its own failures is stronger than one that doesn't.

## Privacy

State exactly what the attestation leaks and what it hides. See the end of `02-architecture.md`. Vague privacy claims are the most common weakness in work like this.

## Comparison

Build this table. It is the clearest single artefact for a reader.

| | raw x402 | AP2 | ERC-7710 session keys | Aegis |
|---|---|---|---|---|
| bounded authority | | | | |
| enforcement point | | | | |
| bypassable by compromised agent | | | | |
| revocable mid-flight | | | | |
| audit output | | | | |
| privacy of audit output | | | | |
| gas overhead | | | | |

Fill it from the actual specs, not from memory.

## Honest reporting

Report what the guard blocked that it should not have. Report proof times that make period lengths impractical. Report the minimum payment size honestly even if it's higher than you'd like. A result with stated limits is a result. A result without them reads as unexamined.
