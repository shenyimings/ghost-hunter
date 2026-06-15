"""
For each canonical proxy_trap revert reason, locate and save the malicious contract bytecode.

Three attack sub-mechanisms:
  1. Direct contract  — trapped_address IS the malicious contract (attacker == trapped)
  2. Malicious singleton — impl at slot 0 was swapped; attacker deployed impl before the attack
  3. Malicious fallback handler — normal GnosisSafe impl, but FH reverts

Output: results/rq2/proxy_trap/
  bytecodes/<sha256_prefix>.hex   — raw bytecode per unique contract
  catalog.json                    — per-reason entry with contract address, type, size
"""

import json
import os
import sys
import time
import hashlib
from pathlib import Path
from collections import defaultdict

import pandas as pd
import requests
from web3 import Web3

API_KEY = os.getenv("ETHERSCAN_API_KEY") or ""
if not API_KEY:
    # Check .env in repo root
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("ETHERSCAN_API_KEY="):
                API_KEY = line.split("=", 1)[1].strip()

if not API_KEY:
    print("ERROR: ETHERSCAN_API_KEY not set", file=sys.stderr)
    sys.exit(1)

POLYGON_CHAIN = "137"
API_URL = "https://api.etherscan.io/v2/api"
FH_SLOT = hex(int(Web3.keccak(text="fallback_manager.handler.address").hex(), 16))
NORMAL_IMPL = "0xe51abdf814f8854941b9fe8e3a4f65cab4e7a4a8"

OUT_DIR = Path(__file__).resolve().parent / "results" / "proxy_trap"
OUT_DIR.mkdir(parents=True, exist_ok=True)
BYTECODE_DIR = OUT_DIR / "bytecodes"
BYTECODE_DIR.mkdir(exist_ok=True)


def api(params: dict, retries=3) -> dict:
    for attempt in range(retries):
        try:
            r = requests.get(
                API_URL,
                params={**params, "chainid": POLYGON_CHAIN, "apikey": API_KEY},
                timeout=20,
            )
            return r.json()
        except Exception as e:
            if attempt == retries - 1:
                return {"result": None, "error": str(e)}
            time.sleep(1)
    return {}


def get_code(addr: str) -> bytes:
    res = api({"module": "proxy", "action": "eth_getCode", "address": addr, "tag": "latest"})
    raw = res.get("result") or ""
    if not raw or raw == "0x":
        return b""
    try:
        return bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    except Exception:
        return b""


def get_storage(addr: str, slot: str) -> str:
    res = api({"module": "proxy", "action": "eth_getStorageAt", "address": addr, "position": slot, "tag": "latest"})
    return res.get("result") or ""


def storage_to_addr(raw: str) -> str:
    if not raw or raw == "0x" + "0" * 64:
        return ""
    return ("0x" + raw[-40:]).lower()


def get_impl(addr: str) -> str:
    return storage_to_addr(get_storage(addr, "0x0"))


def get_fh(addr: str) -> str:
    return storage_to_addr(get_storage(addr, FH_SLOT))


def save_bytecode(code: bytes, label: str) -> str:
    h = hashlib.sha256(code).hexdigest()[:16]
    path = BYTECODE_DIR / f"{h}.hex"
    path.write_text("0x" + code.hex())
    return h


def get_attacker_deploys(attacker: str, block: int, window: int = 2000) -> list[dict]:
    """Return list of {contractAddress, blockNumber} deployed by attacker near block."""
    res = api({
        "module": "account", "action": "txlist",
        "address": attacker,
        "startblock": str(max(0, block - window)),
        "endblock": str(block + 100),
        "sort": "asc", "page": "1", "offset": "50",
    })
    txs = res.get("result") or []
    deploys = []
    for tx in txs:
        if tx.get("to") == "" or not tx.get("to"):
            receipt = api({"module": "proxy", "action": "eth_getTransactionReceipt", "txhash": tx["hash"]})
            ca = (receipt.get("result") or {}).get("contractAddress", "")
            if ca:
                deploys.append({"contractAddress": ca.lower(), "blockNumber": int(tx["blockNumber"])})
            time.sleep(0.2)
    return deploys


def canonical_reason(reasons: list) -> str:
    return " | ".join(sorted(set(reasons)))


def load_events():
    base = Path(__file__).resolve().parent.parent / "results"
    events = []
    for fname, ver in [("all_v1.parquet", "v1"), ("all_v2.parquet", "v2")]:
        df = pd.read_parquet(base / fname)
        pt = df[df["matched_rule"] == "proxy_trap"]
        for _, row in pt.iterrows():
            try:
                rr = json.loads(row["rule_result"])
                events.append({
                    "version": ver,
                    "block_num": int(row["block_num"]),
                    "tx_hash": row["tx_hash"],
                    "revert_reasons": rr.get("revert_reasons", []),
                    "canon": canonical_reason(rr.get("revert_reasons", [])),
                    "proxy_trap_side": rr.get("proxy_trap_side", ""),
                    "trapped": rr.get("trapped_address", "").lower(),
                    "attacker": rr.get("attacker", "").lower(),
                })
            except Exception:
                continue
    return events


def analyze_trapped(trapped: str, attacker: str, block: int) -> dict | None:
    """Return {mechanism, contract_addr, code} for the malicious contract."""
    time.sleep(0.25)

    # === Case 1: direct contract (attacker == trapped) ===
    if trapped.lower() == attacker.lower():
        code = get_code(trapped)
        if code:
            return {"mechanism": "direct_contract", "contract_addr": trapped, "code": code}
        return None

    # === Case 2 / 3: proxy — check slot 0 (impl) and FH ===
    impl = get_impl(trapped)
    fh = get_fh(trapped)

    # Sub-case: malicious impl (slot 0 ≠ normal impl)
    if impl and impl.lower() != NORMAL_IMPL.lower():
        code = get_code(impl)
        if code and len(code) < 20000:  # reasonable size for malicious impl
            return {"mechanism": "malicious_singleton", "contract_addr": impl, "code": code}

    # Sub-case: malicious fallback handler
    if fh and fh != "0x" + "0" * 40:
        fh_code = get_code(fh)
        if fh_code:
            return {"mechanism": "malicious_fallback_handler", "contract_addr": fh, "code": fh_code}

    # Sub-case: impl was restored — find from attacker's deploy history
    deploys = get_attacker_deploys(attacker, block)
    for d in deploys:
        code = get_code(d["contractAddress"])
        if code and 50 < len(code) < 10000:
            return {
                "mechanism": "malicious_singleton (recovered from deploy)",
                "contract_addr": d["contractAddress"],
                "code": code,
                "deploy_block": d["blockNumber"],
            }

    return None


def main():
    print("Loading proxy_trap events...")
    events = load_events()
    print(f"  Total: {len(events):,}")

    groups: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        groups[ev["canon"]].append(ev)

    print(f"  Distinct canonical reasons: {len(groups)}\n")

    catalog = []
    seen_addrs: dict[str, str] = {}  # contract_addr → sha256

    for canon, evlist in sorted(groups.items(), key=lambda x: -len(x[1])):
        count = len(evlist)
        unique_trapped = len(set(e["trapped"] for e in evlist))
        v1 = sum(1 for e in evlist if e["version"] == "v1")
        v2 = sum(1 for e in evlist if e["version"] == "v2")

        print(f"[{count:6,}] {canon}")

        # Pick one representative event (prefer proxy over direct)
        proxy_events = [e for e in evlist if e["trapped"] != e["attacker"]]
        direct_events = [e for e in evlist if e["trapped"] == e["attacker"]]
        chosen = (proxy_events or direct_events)[0]

        result = analyze_trapped(chosen["trapped"], chosen["attacker"], chosen["block_num"])

        entry = {
            "canonical_reason": canon,
            "total_events": count,
            "v1_events": v1,
            "v2_events": v2,
            "unique_trapped_addresses": unique_trapped,
            "sample_trapped": chosen["trapped"],
            "sample_attacker": chosen["attacker"],
            "sample_block": chosen["block_num"],
            "mechanism": None,
            "malicious_contract": None,
            "bytecode_hash": None,
            "bytecode_size_bytes": None,
        }

        if result:
            code = result["code"]
            addr = result["contract_addr"]
            mechanism = result["mechanism"]

            if addr in seen_addrs:
                bh = seen_addrs[addr]
            else:
                bh = save_bytecode(code, canon)
                seen_addrs[addr] = bh

            entry.update({
                "mechanism": mechanism,
                "malicious_contract": addr,
                "bytecode_hash": bh,
                "bytecode_size_bytes": len(code),
            })
            print(f"         → {mechanism}: {addr} ({len(code)}B, hash={bh})")
        else:
            print(f"         → NOT FOUND (manual investigation needed)")

        catalog.append(entry)
        print()

    # Save catalog
    catalog_path = OUT_DIR / "catalog.json"
    catalog_path.write_text(json.dumps(catalog, indent=2))
    print(f"Saved catalog to {catalog_path}")

    found = sum(1 for e in catalog if e["mechanism"])
    print(f"Found malicious contract for {found}/{len(catalog)} reason groups.")
    print(f"Unique bytecodes saved: {len(seen_addrs)} in {BYTECODE_DIR}")


if __name__ == "__main__":
    main()
