# Glossary

**Mandate** — a signed permission slip from principal to agent: cap, window, allowlist, per-transaction limit, rate limit. The unit of authority.

**Principal** — the human or organisation that owns the funds and issues the mandate. Accountable party.

**Session key** — a scoped key the agent uses to authorise payments within a mandate. Cannot move funds outside it. Revocable independently of the principal's key.

**Policy engine** — off-chain service that evaluates payment intent against the mandate and, if allowed, signs. Holds the session key. Usability layer, not a security boundary.

**Spend policy module** — the on-chain validation module. The actual security boundary. Re-checks everything and appends the commitment.

**x402** — revival of HTTP status 402 Payment Required. Server returns 402 with payment requirements, client retries with a signed payment in an `X-PAYMENT` header.

**EIP-3009** — `transferWithAuthorization`. A signed object the receiver submits and pays gas for. One signature, no separate approve, no agent-held gas.

**Commitment** — a Poseidon hash of a payment's details plus a salt. Binds the payment without revealing it.

**Merkle tree / root** — the accumulated commitments. The root is a single value standing for the whole set. Published on-chain by the module.

**Nullifier** — a value preventing the same secret being used twice. Here: enforcing leaf-index distinctness so a prover can't reuse one cheap payment.

**Attestation** — the emitted result of a verified proof: this mandate, this period, this root, compliant.

**Poseidon** — a hash function designed to be cheap inside ZK circuits. Keccak costs roughly 100x more constraints.

**Range check** — a circuit constraint bounding a value's size. Without one, field arithmetic wraps and inequalities become meaningless.

**Soundness** — the property that a false statement cannot be proven. Most ZK bugs are soundness bugs, and they fail silently.
