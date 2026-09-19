"""Assembles the witness and generates the period attestation proof.

The prover is UNTRUSTED. It cannot cheat by omitting payments, because it does
not build the tree — the on-chain module does. If you ever find yourself letting
the prover choose which leaves exist, stop: that is the whole security argument
gone.

TODO(phase4)
"""


def prove_period(mandate_id: str, period_end: int):
    raise NotImplementedError
