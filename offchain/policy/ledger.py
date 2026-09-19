"""SQLite ledger of policy decisions. A local, fast view used to reject early.

The on-chain module is the source of truth. This ledger can be wrong (e.g. a
settlement that never landed) without compromising safety — the module re-checks
everything. It exists so the agent gets a readable "no" instead of a revert.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id TEXT NOT NULL,
    counterparty TEXT NOT NULL,
    amount INTEGER NOT NULL,
    reason TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    ts INTEGER NOT NULL
);
"""


class Ledger:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(_SCHEMA)
        self.conn.commit()

    def record(self, mandate_id, counterparty, amount, reason, allowed, ts=None):
        ts = ts if ts is not None else int(time.time())
        with closing(self.conn.cursor()) as c:
            c.execute(
                "INSERT INTO decisions(mandate_id,counterparty,amount,reason,allowed,ts) VALUES (?,?,?,?,?,?)",
                (mandate_id, counterparty.lower(), amount, str(reason), 1 if allowed else 0, ts),
            )
        self.conn.commit()

    def spent(self, mandate_id: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM decisions WHERE mandate_id=? AND allowed=1",
            (mandate_id,),
        ).fetchone()
        return int(row[0])

    def tx_count(self, mandate_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE mandate_id=? AND allowed=1", (mandate_id,)
        ).fetchone()
        return int(row[0])

    def count_since(self, mandate_id: str, since_ts: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE mandate_id=? AND allowed=1 AND ts>=?",
            (mandate_id, since_ts),
        ).fetchone()
        return int(row[0])
