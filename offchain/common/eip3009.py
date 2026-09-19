"""EIP-3009 transferWithAuthorization: build, sign, verify.

This is the payment primitive x402 uses. A single signed object the receiver
submits and pays gas for — no separate approve, no agent-held ETH. The session
key signs it inside the policy engine; the key never leaves that process.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_typed_data


@dataclass
class Authorization:
    """A signed EIP-3009 transferWithAuthorization, ready for a server to submit."""
    from_: str
    to: str
    value: int
    valid_after: int
    valid_before: int
    nonce: str          # 0x bytes32
    v: int
    r: str
    s: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "from": self.from_,
            "to": self.to,
            "value": self.value,
            "validAfter": self.valid_after,
            "validBefore": self.valid_before,
            "nonce": self.nonce,
            "v": self.v,
            "r": self.r,
            "s": self.s,
            "signature": self.signature,
        }


def _typed_data(token: str, chain_id: int, msg: dict) -> dict:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": "Test USD Coin",
            "version": "2",
            "chainId": chain_id,
            "verifyingContract": token,
        },
        "message": msg,
    }


def new_nonce() -> str:
    return "0x" + secrets.token_hex(32)


def sign_authorization(
    private_key: str,
    token: str,
    chain_id: int,
    from_: str,
    to: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: str | None = None,
) -> Authorization:
    nonce = nonce or new_nonce()
    msg = {
        "from": from_,
        "to": to,
        "value": value,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": nonce,
    }
    signable = encode_typed_data(full_message=_typed_data(token, chain_id, msg))
    signed = Account.sign_message(signable, private_key)
    return Authorization(
        from_=from_,
        to=to,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
        v=signed.v,
        r="0x" + signed.r.to_bytes(32, "big").hex(),
        s="0x" + signed.s.to_bytes(32, "big").hex(),
        signature=signed.signature.hex(),
    )


def recover_authorizer(token: str, chain_id: int, auth: Authorization) -> str:
    msg = {
        "from": auth.from_,
        "to": auth.to,
        "value": auth.value,
        "validAfter": auth.valid_after,
        "validBefore": auth.valid_before,
        "nonce": auth.nonce,
    }
    signable = encode_typed_data(full_message=_typed_data(token, chain_id, msg))
    return Account.recover_message(signable, signature=auth.signature)
