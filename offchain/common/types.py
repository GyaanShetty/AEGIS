"""Shared types for the Aegis off-chain stack.

These mirror the on-chain Mandate (contracts/src/libraries/Mandate.sol). The
policy engine checks the SAME conditions the module checks; this module is a
usability layer, never a security boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Reason(str, Enum):
    OK = "ok"
    TOTAL_CAP_EXCEEDED = "total_cap_exceeded"
    PER_TX_CAP_EXCEEDED = "per_tx_cap_exceeded"
    OUTSIDE_WINDOW = "outside_window"
    COUNTERPARTY_NOT_ALLOWED = "counterparty_not_allowed"
    VELOCITY_EXCEEDED = "velocity_exceeded"
    MANDATE_REVOKED = "mandate_revoked"
    TX_COUNT_EXCEEDED = "tx_count_exceeded"
    ANOMALOUS = "anomalous"


@dataclass
class Mandate:
    mandate_id: str            # 0x-prefixed bytes32
    principal: str             # address
    agent_session_key: str     # address of the session key (EIP-3009 payer)
    token: str                 # stablecoin address
    total_cap: int             # cumulative ceiling (base units, 6 decimals)
    per_tx_cap: int            # per-payment ceiling
    window_start: int          # unix seconds
    window_end: int
    allowlist: set[str]        # permitted counterparty addresses (lowercased)
    max_tx_count: int
    revoked: bool = False
    # velocity: at most `velocity_max` payments per `velocity_window` seconds
    velocity_max: int = 1_000_000
    velocity_window: int = 60

    def allows(self, counterparty: str) -> bool:
        return counterparty.lower() in {a.lower() for a in self.allowlist}


@dataclass
class PaymentIntent:
    mandate_id: str
    counterparty: str          # payTo address
    amount: int                # base units
    token: str
    resource: str = ""         # what is being bought (for the ledger / anomaly)


@dataclass
class LedgerState:
    """Running local view of a mandate's spend. The on-chain module is the source
    of truth; this exists to reject fast and explain why."""
    spent: int = 0
    tx_count: int = 0
    timestamps: list[int] = field(default_factory=list)
