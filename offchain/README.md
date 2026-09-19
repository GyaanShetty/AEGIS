# Off-chain components

```
policy/    policy engine — holds the session key, signs or refuses
agent/     agent runtime — proposes payments, never holds the key
server/    x402-gated resource server (the thing being paid)
indexer/   rebuilds the commitment tree from events, checks it against chain
prover/    generates the period attestation proof
```

## The one architectural rule

`agent/` and `policy/` run as **separate processes** communicating over a narrow HTTP API. The agent must have no in-process route to the session key.

If they share memory, the threat model collapses: a prompt injection that gets code execution in the agent also gets the key, and every guarantee in this project evaporates. Keep them apart structurally, not by convention.

## Running

```
uvicorn policy.main:app --port 8001
uvicorn server.main:app --port 8002
python -m agent.run
```
