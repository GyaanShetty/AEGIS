"""Phase 2 tests — the x402 loop, policy engine, and settlement.

Runs fully offline: the resource server settles against MockSettler, the agent
talks to the policy engine and the server through the HTTP boundary (Starlette
TestClient), never sharing memory with the key. The policy engine holds the
session key; the agent only ever receives signed authorisations or rejections.
"""

from __future__ import annotations

import time

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from agent.run import Clients, PaymentRejected, fetch_paid_resource, spend_until_stopped
from common.eip3009 import recover_authorizer, sign_authorization
from common.settle import MockSettler, SettleError
from common.types import Mandate
from policy.main import build_app as build_policy
from server.main import PRICE, build_app as build_server

CHAIN_ID = 84532  # Base Sepolia
TOKEN = "0x0000000000000000000000000000000000000abc"
SERVER_ADDR = "0x000000000000000000000000000000000000cafe"

SESSION_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def _session():
    acct = Account.from_key(SESSION_PK)
    return acct.address


def _mandate(total_cap, per_tx_cap=10**9, allow_server=True):
    return Mandate(
        mandate_id="0x" + "11" * 32,
        principal="0x00000000000000000000000000000000000000a1",
        agent_session_key=_session(),
        token=TOKEN,
        total_cap=total_cap,
        per_tx_cap=per_tx_cap,
        window_start=0,
        window_end=2**63,
        allowlist={SERVER_ADDR} if allow_server else set(),
        max_tx_count=128,
        velocity_max=1000,
        velocity_window=60,
    )


def _clients(mandate):
    payer = _session()
    policy_app = build_policy(mandate, SESSION_PK, payer, CHAIN_ID)
    settler = MockSettler(TOKEN, CHAIN_ID, balances={payer: 10**9})
    server_app = build_server(settler, SERVER_ADDR, TOKEN)
    policy_c = TestClient(policy_app, base_url="http://policy")
    server_c = TestClient(server_app, base_url="http://server")
    clients = Clients(server=server_c, policy=policy_c, mandate_id=mandate.mandate_id)
    return clients, settler, payer


# --------------------------------------------------------------------------- #
#  EIP-3009 primitives                                                         #
# --------------------------------------------------------------------------- #


def test_eip3009_sign_and_recover_roundtrip():
    payer = _session()
    auth = sign_authorization(SESSION_PK, TOKEN, CHAIN_ID, payer, SERVER_ADDR, 1000, 0, 2**63)
    assert recover_authorizer(TOKEN, CHAIN_ID, auth).lower() == payer.lower()


def test_settler_rejects_tampered_amount():
    payer = _session()
    s = MockSettler(TOKEN, CHAIN_ID, balances={payer: 10**9})
    auth = sign_authorization(SESSION_PK, TOKEN, CHAIN_ID, payer, SERVER_ADDR, 1000, 0, 2**63)
    auth.value = 2000  # tamper after signing
    with pytest.raises(SettleError):
        s.settle(auth)


def test_settler_idempotent_nonce():
    payer = _session()
    s = MockSettler(TOKEN, CHAIN_ID, balances={payer: 10**9})
    auth = sign_authorization(SESSION_PK, TOKEN, CHAIN_ID, payer, SERVER_ADDR, 1000, 0, 2**63)
    s.settle(auth)
    with pytest.raises(SettleError):
        s.settle(auth)  # same nonce must never settle twice


# --------------------------------------------------------------------------- #
#  x402 loop                                                                   #
# --------------------------------------------------------------------------- #


def test_first_get_returns_402():
    clients, _, _ = _clients(_mandate(total_cap=10 * PRICE))
    resp = clients.server.get("/data")
    assert resp.status_code == 402
    assert resp.json()["accepts"][0]["amount"] == str(PRICE)


def test_single_paid_fetch_succeeds():
    clients, settler, payer = _clients(_mandate(total_cap=10 * PRICE))
    out = fetch_paid_resource("/data", clients)
    assert out["resource"] == "the paid data"
    assert settler.balance(SERVER_ADDR) == PRICE
    assert settler.balance(payer) == 10**9 - PRICE


def test_agent_pays_until_cap_then_policy_rejects():
    # cap allows exactly 3 payments; the 4th must be rejected by the engine.
    cap = 3 * PRICE
    clients, settler, payer = _clients(_mandate(total_cap=cap))
    results = spend_until_stopped("/data", clients, max_attempts=10)

    ok = [r for r in results if "ok" in r]
    rejected = [r for r in results if "rejected" in r]
    assert len(ok) == 3, f"expected 3 successful payments, got {len(ok)}"
    assert len(rejected) == 1
    assert rejected[0]["rejected"] == "total_cap_exceeded"
    # settled exactly the cap, no more
    assert settler.balance(SERVER_ADDR) == cap


def test_counterparty_not_in_allowlist_rejected():
    clients, _, _ = _clients(_mandate(total_cap=10 * PRICE, allow_server=False))
    with pytest.raises(PaymentRejected) as e:
        fetch_paid_resource("/data", clients)
    assert e.value.reason == "counterparty_not_allowed"


def test_per_tx_cap_rejected():
    clients, _, _ = _clients(_mandate(total_cap=10 * PRICE, per_tx_cap=PRICE - 1))
    with pytest.raises(PaymentRejected) as e:
        fetch_paid_resource("/data", clients)
    assert e.value.reason == "per_tx_cap_exceeded"


def test_refund_on_resource_failure():
    payer = _session()
    mandate = _mandate(total_cap=10 * PRICE)
    policy_app = build_policy(mandate, SESSION_PK, payer, CHAIN_ID)
    settler = MockSettler(TOKEN, CHAIN_ID, balances={payer: 10**9})
    server_app = build_server(settler, SERVER_ADDR, TOKEN, resource_ok=False)
    policy_c = TestClient(policy_app, base_url="http://policy")
    server_c = TestClient(server_app, base_url="http://server")
    clients = Clients(server=server_c, policy=policy_c, mandate_id=mandate.mandate_id)

    with pytest.raises(PaymentRejected):
        fetch_paid_resource("/data", clients)
    # settlement happened then was refunded: balances are whole again
    assert settler.balance(SERVER_ADDR) == 0
    assert settler.balance(payer) == 10**9


def test_agent_module_has_no_session_key():
    # Structural check: the agent module must not import or hold the key.
    import agent.run as agent_mod

    src = open(agent_mod.__file__).read()
    assert "sign_authorization" not in src
    assert "SESSION_PK" not in src
    assert "private_key" not in src
