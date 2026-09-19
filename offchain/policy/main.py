"""Policy engine — evaluates payment intent against the mandate, then signs.

This is a USABILITY layer, not a security boundary. Everything checked here is
checked again on-chain by SpendPolicyModule. The point of doing it here is to
give the agent a fast, readable rejection instead of a reverted transaction and
a wasted fee. Never let a check exist ONLY here.

The session key lives in THIS process and is never returned over the API. The
agent talks to this engine over HTTP and receives only signed authorisations or
structured rejections.
"""

from __future__ import annotations

import os
import time

from fastapi import FastAPI
from pydantic import BaseModel

from common.eip3009 import Authorization, sign_authorization
from common.types import LedgerState, Mandate, PaymentIntent, Reason
from policy.ledger import Ledger


def evaluate(intent: PaymentIntent, mandate: Mandate, state: LedgerState, now: int | None = None):
    """Return (allowed: bool, reason: Reason). Mirrors the on-chain module checks."""
    now = now if now is not None else int(time.time())

    if mandate.revoked:
        return False, Reason.MANDATE_REVOKED
    if now < mandate.window_start or now > mandate.window_end:
        return False, Reason.OUTSIDE_WINDOW
    if intent.amount > mandate.per_tx_cap:
        return False, Reason.PER_TX_CAP_EXCEEDED
    if state.spent + intent.amount > mandate.total_cap:
        return False, Reason.TOTAL_CAP_EXCEEDED
    if state.tx_count >= mandate.max_tx_count:
        return False, Reason.TX_COUNT_EXCEEDED
    if not mandate.allows(intent.counterparty):
        return False, Reason.COUNTERPARTY_NOT_ALLOWED

    # velocity: at most velocity_max allowed payments per rolling velocity_window
    window_start = now - mandate.velocity_window
    recent = sum(1 for t in state.timestamps if t >= window_start)
    if recent >= mandate.velocity_max:
        return False, Reason.VELOCITY_EXCEEDED

    return True, Reason.OK


def authorise(
    intent: PaymentIntent,
    mandate: Mandate,
    state: LedgerState,
    session_key: str,
    chain_id: int,
    payer: str,
    valid_seconds: int = 300,
    now: int | None = None,
) -> tuple[bool, Reason, Authorization | None]:
    """Evaluate, and on allow produce a signed EIP-3009 authorisation.

    Returns (allowed, reason, authorization|None). The session key never leaves.
    """
    now = now if now is not None else int(time.time())
    allowed, reason = evaluate(intent, mandate, state, now)
    if not allowed:
        return False, reason, None

    auth = sign_authorization(
        private_key=session_key,
        token=mandate.token,
        chain_id=chain_id,
        from_=payer,
        to=intent.counterparty,
        value=intent.amount,
        valid_after=0,
        valid_before=now + valid_seconds,
    )
    return True, Reason.OK, auth


# --------------------------------------------------------------------------- #
#  HTTP surface — the narrow API the agent talks to. No key ever crosses it.  #
# --------------------------------------------------------------------------- #


class AuthoriseRequest(BaseModel):
    mandate_id: str
    counterparty: str
    amount: int
    resource: str = ""


class AuthoriseResponse(BaseModel):
    allowed: bool
    reason: str
    authorization: dict | None = None


def build_app(mandate: Mandate, session_key: str, payer: str, chain_id: int, ledger: Ledger | None = None):
    app = FastAPI(title="Aegis Policy Engine")
    ledger = ledger or Ledger()

    def _state(mandate_id: str) -> LedgerState:
        rows = ledger.conn.execute(
            "SELECT ts FROM decisions WHERE mandate_id=? AND allowed=1", (mandate_id,)
        ).fetchall()
        return LedgerState(
            spent=ledger.spent(mandate_id),
            tx_count=ledger.tx_count(mandate_id),
            timestamps=[int(r[0]) for r in rows],
        )

    @app.post("/authorise", response_model=AuthoriseResponse)
    def _authorise(req: AuthoriseRequest):
        intent = PaymentIntent(
            mandate_id=req.mandate_id,
            counterparty=req.counterparty,
            amount=req.amount,
            token=mandate.token,
            resource=req.resource,
        )
        state = _state(req.mandate_id)
        allowed, reason, auth = authorise(
            intent, mandate, state, session_key, chain_id, payer
        )
        ledger.record(req.mandate_id, req.counterparty, req.amount, reason, allowed)
        return AuthoriseResponse(
            allowed=allowed,
            reason=reason.value,
            authorization=auth.to_dict() if auth else None,
        )

    @app.get("/health")
    def _health():
        return {"ok": True}

    app.state.ledger = ledger
    return app
