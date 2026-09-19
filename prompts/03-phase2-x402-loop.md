## Phase 2 — x402 loop and policy engine

```
Implement Phase 2: the payment handshake and off-chain policy layer.

a) `server/` — FastAPI resource server, x402-gated.
   - GET /data returns 402 with a payment-requirements JSON body
     (scheme, network, asset, amount, payTo, resource, maxTimeoutSeconds)
   - on retry with an X-PAYMENT header, verify the EIP-3009 authorisation,
     settle it on Base Sepolia, then return 200 with the resource
   - idempotency: same authorisation nonce must never settle twice
   - if settlement succeeds but resource generation fails, that is a refund
     case — handle it explicitly, don't silently keep the money

b) `policy/` — the pre-signature policy engine.
   - receives a payment intent from the agent
   - evaluates against the active mandate: cap remaining, per-tx, window,
     allowlist, velocity (max N payments per rolling T)
   - on reject: structured error with a machine-readable reason code
   - on allow: constructs and signs the EIP-3009 authorisation with the
     session key, then hands back only the signed object
   - the agent NEVER touches the session key directly — the engine holds it
   - persist a local ledger of decisions (SQLite)

c) `agent/` — the agent runtime.
   - tool-calling loop, one tool: `fetch_paid_resource(url)`
   - handles 402 → request authorisation from policy engine → retry
   - handles policy rejection gracefully (surfaces it to the model as a tool
     error, does not retry blindly)

Critical: the policy engine must be a separate process from the agent, talking
over a narrow API. If they share memory, the threat model is broken. Enforce
that in the architecture, not just in comments.

Then: write an integration test where the agent makes payments until it hits
its cap, and confirm both engine and module reject the payment that crosses it.
```
