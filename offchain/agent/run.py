"""Agent runtime.

Holds no key. Proposes payments. Receives rejections as structured tool errors
and is expected to reason about them rather than retry blindly.

Assume this process is compromised. Nothing here is trusted. Its ONLY route to a
signature is an HTTP call to the policy engine, which may say no. There is no
in-process path to the session key — that is the whole point.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import httpx


class PaymentRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(f"payment rejected: {reason}")
        self.reason = reason


@dataclass
class Clients:
    server: httpx.Client        # the x402 resource server
    policy: httpx.Client        # the policy engine (holds the key)
    mandate_id: str


def _encode_payment(authorization: dict) -> str:
    return base64.b64encode(json.dumps({"authorization": authorization}).encode()).decode()


def fetch_paid_resource(url: str, clients: Clients) -> dict:
    """Tool exposed to the model.

    GET url; if 402, parse requirements, ask the policy engine to authorise, and
    retry with an X-PAYMENT header. A policy rejection is surfaced to the caller
    as a structured error, not retried blindly.
    """
    resp = clients.server.get(url)
    if resp.status_code != 402:
        return resp.json()

    reqs = resp.json()["accepts"][0]

    auth_resp = clients.policy.post(
        "/authorise",
        json={
            "mandate_id": clients.mandate_id,
            "counterparty": reqs["payTo"],
            "amount": int(reqs["amount"]),
            "resource": reqs.get("resource", url),
        },
    ).json()

    if not auth_resp["allowed"]:
        raise PaymentRejected(auth_resp["reason"])

    header = _encode_payment(auth_resp["authorization"])
    retry = clients.server.get(url, headers={"X-PAYMENT": header})
    if retry.status_code != 200:
        raise PaymentRejected(retry.json().get("error", f"http {retry.status_code}"))
    return retry.json()


def spend_until_stopped(url: str, clients: Clients, max_attempts: int = 100) -> list:
    """Naive loop: keep buying the resource until the policy engine says no.

    Models an agent working through a task list. The first rejection is where the
    mandate bit; we surface it and stop rather than hammering.
    """
    results = []
    for _ in range(max_attempts):
        try:
            results.append({"ok": fetch_paid_resource(url, clients)})
        except PaymentRejected as e:
            results.append({"rejected": e.reason})
            break
    return results
