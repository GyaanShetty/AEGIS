"""Rebuilds the commitment tree from LeafInserted events.

The assertion here is the bridge between enforcement and proving. If the locally
reconstructed root ever diverges from the on-chain root, the prover cannot
produce a valid proof and something upstream is broken. Fail loudly.

Hashing is delegated to the module's own pure views (hashLeaf/hashPair/
zeroSubtree) via eth_call, so the indexer uses the EXACT Poseidon2 the module
committed with — there is no risk of a third, divergent hash implementation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict

from eth_abi import encode as abi_encode
from eth_utils import keccak
from web3 import Web3

TREE_DEPTH = 7
MAX_LEAVES = 1 << TREE_DEPTH  # 128

# Minimal ABI for the views and events we touch.
MODULE_ABI = json.loads(
    """[
  {"type":"function","stateMutability":"pure","name":"hashLeaf",
   "inputs":[{"name":"amount","type":"uint256"},{"name":"counterparty","type":"address"},
             {"name":"ts","type":"uint64"},{"name":"salt","type":"bytes32"}],
   "outputs":[{"type":"bytes32"}]},
  {"type":"function","stateMutability":"pure","name":"hashPair",
   "inputs":[{"name":"a","type":"bytes32"},{"name":"b","type":"bytes32"}],"outputs":[{"type":"bytes32"}]},
  {"type":"function","stateMutability":"pure","name":"zeroSubtree",
   "inputs":[{"name":"level","type":"uint8"}],"outputs":[{"type":"bytes32"}]},
  {"type":"function","stateMutability":"view","name":"currentRoot",
   "inputs":[{"name":"mandateId","type":"bytes32"}],"outputs":[{"type":"bytes32"}]},
  {"type":"function","stateMutability":"view","name":"txCount",
   "inputs":[{"name":"mandateId","type":"bytes32"}],"outputs":[{"type":"uint32"}]},
  {"type":"event","anonymous":false,"name":"LeafInserted","inputs":[
     {"name":"mandateId","type":"bytes32","indexed":true},
     {"name":"index","type":"uint32","indexed":false},
     {"name":"leaf","type":"bytes32","indexed":false},
     {"name":"newRoot","type":"bytes32","indexed":false}]},
  {"type":"event","anonymous":false,"name":"PaymentAuthorised","inputs":[
     {"name":"mandateId","type":"bytes32","indexed":true},
     {"name":"counterparty","type":"address","indexed":true},
     {"name":"amount","type":"uint256","indexed":false},
     {"name":"spentTotal","type":"uint256","indexed":false},
     {"name":"txCount","type":"uint32","indexed":false}]}
]"""
)


@dataclass
class LeafRecord:
    index: int
    amount: int
    counterparty: str
    timestamp: int
    salt: str          # 0x bytes32
    leaf: str          # 0x bytes32


class Indexer:
    def __init__(self, w3: Web3, module_addr: str):
        self.w3 = w3
        self.module = w3.eth.contract(address=Web3.to_checksum_address(module_addr), abi=MODULE_ABI)
        self._zeros = [self.module.functions.zeroSubtree(i).call() for i in range(TREE_DEPTH + 1)]

    def _hash_pair(self, a: bytes, b: bytes) -> bytes:
        return self.module.functions.hashPair(a, b).call()

    def collect_leaves(self, mandate_id: str, from_block: int = 0) -> list[LeafRecord]:
        mid = bytes.fromhex(mandate_id[2:])
        leaf_logs = self.module.events.LeafInserted().get_logs(
            argument_filters={"mandateId": mid}, from_block=from_block
        )
        pay_logs = self.module.events.PaymentAuthorised().get_logs(
            argument_filters={"mandateId": mid}, from_block=from_block
        )
        # pair each leaf (by index) with its payment (same order) and block ts
        pays_by_txcount = {int(l["args"]["txCount"]) - 1: l for l in pay_logs}

        records: list[LeafRecord] = []
        for log in sorted(leaf_logs, key=lambda l: int(l["args"]["index"])):
            idx = int(log["args"]["index"])
            pay = pays_by_txcount[idx]
            block = self.w3.eth.get_block(log["blockNumber"])
            ts = int(block["timestamp"])
            amount = int(pay["args"]["amount"])
            cpty = pay["args"]["counterparty"]
            # salt = keccak(abi.encode(module, mandateId, index)) — matches _salt().
            salt = keccak(
                abi_encode(["address", "bytes32", "uint32"], [self.module.address, mid, idx])
            )
            leaf = self.module.functions.hashLeaf(amount, cpty, ts, salt).call()
            assert leaf == log["args"]["leaf"], (
                f"leaf mismatch at index {idx}: reconstructed {leaf.hex()} != event {log['args']['leaf'].hex()}"
            )
            records.append(
                LeafRecord(idx, amount, cpty, ts, "0x" + salt.hex(), "0x" + leaf.hex())
            )
        return records

    def build_tree(self, leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
        """Return (root, paths) for a full zero-padded depth-7 tree.

        Index-ordered, matching the module's incremental tree and the circuit's
        compute_root (sibling on the right when the index bit is 0).
        """
        level = list(leaves) + [self._zeros[0]] * (MAX_LEAVES - len(leaves))
        layers = [level]
        for _ in range(TREE_DEPTH):
            nxt = [self._hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
            layers.append(nxt)
            level = nxt
        root = layers[TREE_DEPTH][0]

        paths: list[list[bytes]] = []
        for leaf_i in range(len(leaves)):
            path = []
            idx = leaf_i
            for d in range(TREE_DEPTH):
                path.append(layers[d][idx ^ 1])
                idx >>= 1
            paths.append(path)
        return root, paths

    def rebuild_and_verify(self, mandate_id: str, from_block: int = 0):
        records = self.collect_leaves(mandate_id, from_block)
        leaves = [bytes.fromhex(r.leaf[2:]) for r in records]
        root, paths = self.build_tree(leaves)
        onchain = self.module.functions.currentRoot(bytes.fromhex(mandate_id[2:])).call()
        if root != onchain:
            raise AssertionError(
                f"ROOT DRIFT: local {root.hex()} != on-chain {onchain.hex()} — proving is dead"
            )
        return {
            "root": "0x" + root.hex(),
            "leaf_count": len(records),
            "records": [asdict(r) for r in records],
            "paths": [["0x" + p.hex() for p in paths[i]] for i in range(len(records))],
        }
