"""x402-gated resource server — the counterparty being paid.

Flow:
  GET /data                      -> 402 + payment requirements
  GET /data  (X-PAYMENT header)  -> verify + settle -> 200 + resource

Two things are easy to get wrong here and both lose money:
  - idempotency: the same authorisation nonce must never settle twice
  - refunds: if settlement succeeds but the resource fails to generate, that is
    a refund case. Handle it explicitly; do not silently keep the payment.
"""

from __future__ import annotations

import base64
import json
import time

from fastapi import FastAPI, Header, Response
from fastapi.responses import JSONResponse

from common.eip3009 import Authorization
from common.settle import MockSettler, SettleError

PRICE = 1000  # base units (0.001 USDC at 6 decimals)


def payment_requirements(resource: str, pay_to: str, asset: str, network: str = "base-sepolia") -> dict:
    """402 body: scheme, network, asset, amount, payTo, resource, maxTimeoutSeconds."""
    return {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": network,
                "asset": asset,
                "amount": str(PRICE),
                "payTo": pay_to,
                "resource": resource,
                "maxTimeoutSeconds": 300,
                "mimeType": "application/json",
            }
        ],
    }


def _decode_payment(header: str) -> Authorization:
    raw = json.loads(base64.b64decode(header).decode())
    a = raw["authorization"] if "authorization" in raw else raw
    return Authorization(
        from_=a["from"],
        to=a["to"],
        value=int(a["value"]),
        valid_after=int(a["validAfter"]),
        valid_before=int(a["validBefore"]),
        nonce=a["nonce"],
        v=int(a["v"]),
        r=a["r"],
        s=a["s"],
        signature=a["signature"],
    )


def build_app(settler: MockSettler, pay_to: str, asset: str, resource_ok=True):
    app = FastAPI(title="Aegis Resource Server")

    @app.get("/data")
    def data(x_payment: str | None = Header(default=None)):
        resource_url = "/data"
        if x_payment is None:
            return JSONResponse(
                status_code=402,
                content=payment_requirements(resource_url, pay_to, asset),
            )

        try:
            auth = _decode_payment(x_payment)
        except Exception:
            return JSONResponse(status_code=400, content={"error": "malformed X-PAYMENT"})

        # amount and payTo must match the price/recipient we quoted
        if auth.to.lower() != pay_to.lower() or auth.value != PRICE:
            return JSONResponse(status_code=402, content={"error": "authorization does not match requirements"})

        try:
            tx = settler.settle(auth)
        except SettleError as e:
            return JSONResponse(status_code=402, content={"error": str(e)})

        # resource generation — if this fails after settlement, refund explicitly
        if not resource_ok:
            settler.refund(auth)
            return JSONResponse(status_code=500, content={"error": "resource generation failed; payment refunded"})

        return JSONResponse(
            status_code=200,
            content={"resource": "the paid data", "settlement": tx, "ts": int(time.time())},
            headers={"X-PAYMENT-RESPONSE": base64.b64encode(json.dumps({"tx": tx}).encode()).decode()},
        )

    return app
