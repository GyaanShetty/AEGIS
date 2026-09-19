"""Rebuilds the commitment tree from LeafInserted events.

The assertion below is the bridge between enforcement and proving. If the
locally reconstructed root ever diverges from the on-chain root, the prover
cannot produce a valid proof and something upstream is broken. Fail loudly.

TODO(phase3)
"""


def rebuild_and_verify(mandate_id: str) -> bytes:
    raise NotImplementedError
