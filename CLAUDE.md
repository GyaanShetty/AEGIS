# Standing instructions

## Project

Aegis: bounded spending authority and ZK compliance attestation for AI agents paying in stablecoins. Read `docs/01-project-spec.md` before doing anything.

## Threat model — this drives every decision

The agent process is **untrusted**. Assume it is buggy, prompt-injected, or hostile.

- The agent holds a session key, never the principal's key.
- The off-chain policy engine is a usability layer. It is **not** a security boundary.
- The on-chain module is the only thing that actually enforces anything.
- If a guarantee holds only when the agent behaves, it is not a guarantee. Flag it rather than building it.

## Working rules

- Tests before implementation. Show me failing tests before you write the fix.
- Never claim something works without running it and pasting the output.
- Read specs and source, not blog posts, for anything security-relevant. Especially EIP-3009, ERC-4337, and the x402 spec.
- On a design fork, stop and give me the options with trade-offs. Do not pick silently.
- No new dependencies without telling me what and why.
- Flag anything security-critical you are unsure about instead of guessing.

## Solidity conventions

- Custom errors, not require strings.
- Events on every state mutation, carrying enough data for an off-chain indexer to reconstruct full history.
- No unbounded loops.
- NatSpec on every external function.
- Checks-effects-interactions.

## Soundness tripwires — get these wrong and the whole thing is decorative

1. **Commitment atomicity.** There must be no path where a payment is authorised and a leaf is not appended, in the same transaction. If you find one, stop and tell me.
2. **Range checks on amounts.** Circuit sums are field elements. Without explicit bounds on every amount and on the running sum, a crafted overflow makes `sum <= cap` vacuously true.
3. **Leaf uniqueness.** Without a distinctness constraint over leaf indices, a prover reuses one cheap leaf N times and proves nothing.
4. **Salt provenance.** Commitment salts come from the module's own entropy, never from the agent.
5. **Revocation races.** Nonce-based invalidation, not just expiry. A revocation and an in-flight authorisation can cross.
