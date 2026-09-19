# Threat model

## Assumptions

**Trusted:** the principal and their key; correctness of deployed contract code; the underlying chain's consensus; the stablecoin issuer not arbitrarily freezing (note: they can, and that is a stated residual risk).

**Untrusted:** the agent process and everything it reads; the resource server; the network; the prover; anyone who can reach the policy engine API.

## Attacks and defences

| # | Attack | Defence | Where enforced |
|---|---|---|---|
| A1 | Prompt injection redirects funds to attacker | counterparty allowlist, Merkle-proven | module |
| A2 | Agent constructs its own EIP-3009 authorisation, skipping the engine | agent never holds the session key | architecture |
| A3 | Replay of a past successful authorisation | nonce invalidation in EIP-3009 + module | module |
| A4 | Split one over-cap payment into many small ones | cumulative budget counter, not just per-tx cap | module |
| A5 | Valid Merkle proof against a different allowlist | allowlist root bound into the signed mandate | module |
| A6 | Race a revocation with an in-flight authorisation | revocation nonce, not expiry alone | module |
| A7 | Extract session key from policy engine process | process isolation; production needs TEE/MPC (stubbed) | deployment |
| A8 | Prover omits expensive payments from the proof | tree is built by the module, not the prover | in-circuit + module |
| A9 | Amount overflow makes `sum <= cap` vacuous | explicit range checks, amounts bounded to 2^64 | in-circuit |
| A10 | Duplicate leaf indices to pad a cheap proof | distinctness constraint over indices | in-circuit |
| A11 | Proof against a stale root | verifier checks root equals module's current published root | verifier |
| A12 | Public inputs mismatched against real mandate | verifier cross-checks cap, window, allowlistRoot on-chain | verifier |
| A13 | Resource server takes payment, returns nothing | idempotency keys and explicit refund path | server |
| A14 | Agent spams rejections to exhaust engine | rate limit, and velocity cap in mandate | engine + module |

A8 through A12 are the ones that make the proof meaningful. A2 and A8 are the two most commonly gotten wrong in comparable systems — test both explicitly.

## Residual risks — say these out loud

- Stablecoin issuer can freeze funds. Nothing here prevents that.
- Contract bugs. The module is the boundary; a bug in it is total.
- Trusted setup, if using a scheme that needs one. Document which and why.
- Key custody is stubbed, not solved. Production needs a TEE or MPC signer.
- Availability: a tripped rate limit or a stale oracle stops legitimate work too. Safety and liveness trade here.
- The proof bounds aggregate spend. It says nothing about whether the spending was *wise*.

## What Aegis does not claim

It does not prevent the agent from wasting its entire mandate on useless purchases. It does not verify the agent got what it paid for. It does not identify the agent. It bounds authorised spend and proves the bound held. That is the whole claim, and keeping it narrow is what makes it credible.
