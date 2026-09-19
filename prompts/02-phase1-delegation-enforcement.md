## Phase 1 — delegation + enforcement

```
Implement Phase 1: mandate issuance and on-chain enforcement.

Contracts:

1. `Mandate.sol` — library defining the mandate struct and its EIP-712 typehash.
   Fields: mandateId, principal, agentSessionKey, token, totalCap,
   perTxCap, windowStart, windowEnd, allowlistRoot, maxTxCount,
   revocationNonce.

2. `SpendPolicyModule.sol` — ERC-4337 validation module. On each userOp it MUST:
   - recover the session key signature and confirm it matches the mandate
   - reject if block.timestamp outside [windowStart, windowEnd]
   - reject if mandate's revocationNonce != the principal's current nonce
   - reject if amount > perTxCap
   - reject if spent[mandateId] + amount > totalCap
   - reject if counterparty not proven against allowlistRoot (Merkle proof
     supplied in the userOp)
   - reject if txCount[mandateId] >= maxTxCount
   - increment spent and txCount ATOMICALLY with the transfer
   Revocation: principal can bump revocationNonce, invalidating all in-flight
   authorisations for that mandate immediately.

3. `AgentAccount.sol` — minimal ERC-4337 account wired to the module.

Requirements:
- Custom errors, not require strings.
- Every state mutation emits an event with enough data for an off-chain indexer
  to reconstruct full history.
- No unbounded loops.

Tests (Foundry) — I want these specifically, not just happy path:
- spend exactly at cap succeeds; one wei over reverts
- two payments that individually pass but together exceed cap: second reverts
- payment at windowEnd succeeds, windowEnd+1 reverts
- revocation invalidates a signature that was valid one block earlier
- counterparty not in allowlist reverts even with a well-formed proof of a
  different leaf
- replayed userOp reverts
- fuzz totalCap/perTxCap/amount for arithmetic edge cases, including amounts
  near type(uint256).max

Write the tests first, watch them fail, then implement. Report the failures to
me before you implement.
```
