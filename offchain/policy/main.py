"""Policy engine — evaluates payment intent against the mandate, then signs.

This is a USABILITY layer, not a security boundary. Everything checked here is
checked again on-chain. The point of doing it here is to give the agent a fast,
readable rejection instead of a reverted transaction and a wasted fee.

Never let a check exist only here.
"""

from enum import Enum


class Reason(str, Enum):
    OK = "ok"
    TOTAL_CAP_EXCEEDED = "total_cap_exceeded"
    PER_TX_CAP_EXCEEDED = "per_tx_cap_exceeded"
    OUTSIDE_WINDOW = "outside_window"
    COUNTERPARTY_NOT_ALLOWED = "counterparty_not_allowed"
    VELOCITY_EXCEEDED = "velocity_exceeded"
    MANDATE_REVOKED = "mandate_revoked"
    ANOMALOUS = "anomalous"


def evaluate(intent, mandate, ledger):
    """Return (allowed: bool, reason: Reason).

    TODO(phase2): cap remaining, per-tx, window, allowlist, velocity over a
    rolling window, simple anomaly score.
    """
    raise NotImplementedError


def authorise(intent, mandate, ledger, session_key):
    """Evaluate, and on allow produce a signed EIP-3009 authorisation.

    Returns ONLY the signed object. The session key never leaves this process.

    TODO(phase2): build the EIP-712 payload for transferWithAuthorization
    (from, to, value, validAfter, validBefore, nonce) and sign it.
    """
    raise NotImplementedError
