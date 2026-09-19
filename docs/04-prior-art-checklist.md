# Prior-art checklist

Do this before writing code. Budget one to two hours. The risk you are pricing is finding a shipped equivalent in month three.

## Read in full

- [ ] x402 specification and the reference facilitator implementation
- [ ] EIP-3009 (`transferWithAuthorization`)
- [ ] EIP-2612 and Permit2 — understand why 3009 is the right pick here
- [ ] ERC-4337 account abstraction, particularly validation modules
- [ ] ERC-7710 / ERC-7715 delegation and session-key standards
- [ ] ERC-8004 agent identity and reputation
- [ ] Google AP2 mandate model — closest conceptual relative, note what it does not enforce
- [ ] Tornado Cash circuits — canonical Merkle-inclusion-in-ZK reference. Read for structure.
- [ ] Semaphore — nullifier pattern

## Search

Run each, record what you find, note the closest hit even when it isn't a match.

- [ ] "verifiable spend limit"
- [ ] "zero knowledge budget proof"
- [ ] "agent payment mandate enforcement"
- [ ] "private proof of solvency" / "privacy preserving proof of reserves"
- [ ] "session key spending limit smart account"
- [ ] "x402 spend policy"
- [ ] "delegated authority zero knowledge attestation"
- [ ] AP2 + ZK, x402 + ZK

Venues worth a pass: IEEE S&P, CCS, USENIX Security, Financial Cryptography, eprint.iacr.org.

## The three questions

1. Has anyone combined **enforcement** with **privacy-preserving attestation** for agent payments? Enforcement alone exists. Attestation alone exists. The combination is the claim.
2. Does anything already build the commitment tree inside the enforcement path? This is the soundness hinge — if someone has done it, read how carefully.
3. If a near-match exists, is the difference substantive or cosmetic? Be honest. A cosmetic difference is not a project.

## Outcome

Write the answer into this file. If the direction survives, say what specifically is unclaimed and why. If it does not, say so early — killing a direction in week one is a good outcome, not a failure.
