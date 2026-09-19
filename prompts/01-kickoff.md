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
