"""Settlement backends for EIP-3009 authorisations.

`MockSettler` verifies and settles in-memory: it recovers the authoriser, checks
the signature binds to `from`, enforces validity window and nonce idempotency,
and moves balances. It makes the whole x402 loop testable with no chain.

`Web3Settler` submits `transferWithAuthorization` to a real EIP-3009 token on
Base Sepolia. It is the same verification, done by the token contract.
"""

from __future__ import annotations

import time

from common.eip3009 import Authorization, recover_authorizer


class SettleError(Exception):
    pass


class MockSettler:
    def __init__(self, token: str, chain_id: int, balances: dict[str, int] | None = None):
        self.token = token
        self.chain_id = chain_id
        self.balances: dict[str, int] = {k.lower(): v for k, v in (balances or {}).items()}
        self._used_nonces: set[tuple[str, str]] = set()

    def balance(self, addr: str) -> int:
        return self.balances.get(addr.lower(), 0)

    def verify(self, auth: Authorization, now: int | None = None) -> str:
        now = now if now is not None else int(time.time())
        if not (auth.valid_after < now < auth.valid_before):
            raise SettleError("authorization not within validity window")
        signer = recover_authorizer(self.token, self.chain_id, auth)
        if signer.lower() != auth.from_.lower():
            raise SettleError("signature does not match `from`")
        return signer

    def settle(self, auth: Authorization, now: int | None = None) -> str:
        key = (auth.from_.lower(), auth.nonce.lower())
        if key in self._used_nonces:
            raise SettleError("authorization nonce already used")  # idempotency
        self.verify(auth, now)
        frm, to = auth.from_.lower(), auth.to.lower()
        if self.balances.get(frm, 0) < auth.value:
            raise SettleError("insufficient balance")
        self._used_nonces.add(key)
        self.balances[frm] = self.balances.get(frm, 0) - auth.value
        self.balances[to] = self.balances.get(to, 0) + auth.value
        return "0xmock_" + auth.nonce[2:18]

    def refund(self, auth: Authorization) -> None:
        """Reverse a settled authorisation (resource-generation failure case)."""
        frm, to = auth.from_.lower(), auth.to.lower()
        self.balances[to] = self.balances.get(to, 0) - auth.value
        self.balances[frm] = self.balances.get(frm, 0) + auth.value
