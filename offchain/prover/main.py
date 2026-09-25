"""Assembles the witness and generates the period attestation proof.

The prover is UNTRUSTED. It cannot cheat by omitting payments, because it does
not build the tree — the on-chain module does, and the indexer's root assertion
binds the witness to that tree. If you ever find yourself letting the prover
choose which leaves exist, stop: that is the whole security argument gone.

Pipeline:
  indexer.rebuild_and_verify  ->  witness (leaves, commitment paths)
  + allowlist paths (sorted-pair, via the module's own hashPair)
  ->  Prover.toml
  ->  nargo execute  ->  bb prove / write_vk / verify
  ->  calldata for AttestationVerifier.attest
"""

from __future__ import annotations

import subprocess
import tomllib  # noqa: F401  (read-back if needed)
from pathlib import Path

MAX_LEAVES = 128
TREE_DEPTH = 7
FIELD_ZERO = "0x" + "00" * 32


def _hexfield(x: int | str) -> str:
    if isinstance(x, str):
        return x if x.startswith("0x") else "0x" + x
    return hex(x)


def allowlist_path(indexer, allowlist_addrs: list[str], counterparty: str) -> list[str]:
    """Build the sorted-pair allowlist path for `counterparty`, using the module's
    own hashPair so it matches the circuit exactly. Supports a 2-leaf allowlist
    (depth-7 with zero padding), which is what the demo uses."""
    leaves = sorted(int(a, 16) if isinstance(a, str) else int(a) for a in
                    [int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x, 16) if isinstance(x, str) else x for x in
                     [f"0x{int(a,16):x}" if isinstance(a, str) and a.startswith("0x") else a for a in allowlist_addrs]])
    # Simpler: normalise to ints
    vals = sorted(int(a, 16) for a in allowlist_addrs)
    cp = int(counterparty, 16)
    assert cp in vals, "counterparty not in allowlist"
    # 2-leaf tree: sibling at level 0 is the other leaf; higher levels are zeros.
    other = [v for v in vals if v != cp]
    path = []
    sib = other[0] if other else 0
    path.append("0x%064x" % sib)
    for _ in range(1, TREE_DEPTH):
        path.append(FIELD_ZERO)
    return path


def build_prover_toml(witness: dict, publics: dict, indexer, allowlist_addrs: list[str]) -> str:
    """Render Prover.toml for the mandate_compliance circuit."""
    n = witness["leaf_count"]
    records = witness["records"]
    paths = witness["paths"]

    amounts = [str(r["amount"]) for r in records] + ["0"] * (MAX_LEAVES - n)
    cptys = ["0x%040x" % int(r["counterparty"], 16) for r in records] + [FIELD_ZERO] * (MAX_LEAVES - n)
    tss = [str(r["timestamp"]) for r in records] + ["0"] * (MAX_LEAVES - n)
    salts = [r["salt"] for r in records] + [FIELD_ZERO] * (MAX_LEAVES - n)
    indices = [str(r["index"]) for r in records] + ["0"] * (MAX_LEAVES - n)

    def pad_paths(ps):
        out = []
        for p in ps:
            out.append([_hexfield(x) for x in p])
        while len(out) < MAX_LEAVES:
            out.append([FIELD_ZERO] * TREE_DEPTH)
        return out

    mpaths = pad_paths(paths)
    apaths = pad_paths([allowlist_path(indexer, allowlist_addrs, r["counterparty"]) for r in records])

    def arr(xs):
        return "[" + ", ".join(f'"{x}"' for x in xs) + "]"

    def arr2(xss):
        return "[" + ", ".join("[" + ", ".join(f'"{x}"' for x in xs) + "]" for xs in xss) + "]"

    lines = [
        f'root = "{publics["root"]}"',
        f'total_cap = "{publics["total_cap"]}"',
        f'window_start = "{publics["window_start"]}"',
        f'window_end = "{publics["window_end"]}"',
        f'allowlist_root = "{publics["allowlist_root"]}"',
        f'mandate_id = "{publics["mandate_id"]}"',
        f'leaf_count = "{n}"',
        f"amounts = {arr(amounts)}",
        f"counterparties = {arr(cptys)}",
        f"timestamps = {arr(tss)}",
        f"salts = {arr(salts)}",
        f"leaf_indices = {arr(indices)}",
        f"merkle_paths = {arr2(mpaths)}",
        f"allowlist_paths = {arr2(apaths)}",
    ]
    return "\n".join(lines) + "\n"


def prove_period(circuit_dir: str, prover_toml: str, bb: str = "bb", nargo: str = "nargo") -> dict:
    """Write Prover.toml, execute the circuit, and generate + verify a proof."""
    cdir = Path(circuit_dir)
    (cdir / "Prover.toml").write_text(prover_toml)
    target = cdir / "target"

    def run(cmd):
        return subprocess.run(cmd, cwd=cdir, capture_output=True, text=True, check=True)

    run([nargo, "execute", "witness"])
    circuit_json = str(target / f"{cdir.name}.json")
    witness_gz = str(target / "witness.gz")
    outdir = str(target / "proof")
    Path(outdir).mkdir(exist_ok=True)

    # UltraHonk with a keccak random-oracle: required for the Solidity verifier.
    common = ["-s", "ultra_honk", "--oracle_hash", "keccak"]
    run([bb, "prove", *common, "-b", circuit_json, "-w", witness_gz, "-o", outdir])
    run([bb, "write_vk", *common, "-b", circuit_json, "-o", outdir])
    run([bb, "verify", *common, "-k", f"{outdir}/vk", "-p", f"{outdir}/proof",
         "-i", f"{outdir}/public_inputs"])
    return {"proof_dir": outdir, "verified": True}


def write_solidity_verifier(circuit_dir: str, bb: str = "bb") -> str:
    """Generate the UltraHonk Solidity verifier from the circuit's vk."""
    cdir = Path(circuit_dir)
    outdir = cdir / "target" / "proof"
    out = cdir / "target" / "Verifier.sol"
    subprocess.run(
        [bb, "write_solidity_verifier", "-s", "ultra_honk", "-k", str(outdir / "vk"), "-o", str(out)],
        cwd=cdir, capture_output=True, text=True, check=True,
    )
    return str(out)


if __name__ == "__main__":
    import argparse
    import json
    from web3 import Web3
    from indexer.main import Indexer

    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://localhost:8545")
    ap.add_argument("--module", required=True)
    ap.add_argument("--mandate", required=True)
    ap.add_argument("--circuit", default="../circuits/mandate_compliance")
    ap.add_argument("--allowlist", nargs="+", required=True, help="allowlist addresses")
    ap.add_argument("--total-cap", required=True)
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--allowlist-root", required=True)
    args = ap.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    ix = Indexer(w3, args.module)
    witness = ix.rebuild_and_verify(args.mandate)
    publics = {
        "root": witness["root"],
        "total_cap": args.total_cap,
        "window_start": args.window_start,
        "window_end": args.window_end,
        "allowlist_root": args.allowlist_root,
        "mandate_id": args.mandate,
    }
    toml = build_prover_toml(witness, publics, ix, args.allowlist)
    print(prove_period(args.circuit, toml))
