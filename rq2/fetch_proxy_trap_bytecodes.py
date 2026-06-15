"""
Analyze proxy_trap events from all_v1.parquet and all_v2.parquet:
  1. Group by canonical revert_reason
  2. For each group, find the trapped_address proxy implementation
     (reads GnosisSafe slot-0 and EIP-1967 slot via Polygonscan API)
  3. Fetch the implementation contract bytecode
  4. Save results to results/rq2/proxy_trap/
"""

import asyncio
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import aiohttp
import pandas as pd

POLYGONSCAN_API = "https://api.polygonscan.com/api"
ALCHEMY_BASE = "https://polygon-mainnet.g.alchemy.com/v2"

# Storage slots to probe for proxy implementation
GNOSIS_IMPL_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076635172ac473174b6a675a6"

RESULTS_DIR = Path(__file__).resolve().parent / "results" / "proxy_trap"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def load_api_keys():
    keys = {}
    # Try env first, then .env file in repo root
    env_path = Path(__file__).resolve().parent.parent / ".env"
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env_vars[k.strip()] = v.strip()

    keys["etherscan"] = os.getenv("ETHERSCAN_API_KEY") or env_vars.get("ETHERSCAN_API_KEY", "")
    keys["alchemy"] = os.getenv("ALCHEMY_API_KEY") or env_vars.get("ALCHEMY_API_KEY", "")
    return keys


def canonical_reason(reasons: list[str]) -> str:
    """Create a stable canonical key from a list of revert reason strings."""
    return " | ".join(sorted(set(reasons)))


def load_proxy_trap_events():
    """Load all proxy_trap events from both parquets."""
    base = Path(__file__).resolve().parent.parent / "results"
    events = []
    for fname, version in [("all_v1.parquet", "v1"), ("all_v2.parquet", "v2")]:
        df = pd.read_parquet(base / fname)
        pt = df[df["matched_rule"] == "proxy_trap"].copy()
        for _, row in pt.iterrows():
            try:
                rr = json.loads(row["rule_result"])
                events.append({
                    "version": version,
                    "block_num": row["block_num"],
                    "tx_hash": row["tx_hash"],
                    "revert_reasons": rr.get("revert_reasons", []),
                    "canonical_reason": canonical_reason(rr.get("revert_reasons", [])),
                    "proxy_trap_side": rr.get("proxy_trap_side", ""),
                    "trapped_address": rr.get("trapped_address", "").lower(),
                    "attacker": rr.get("attacker", "").lower(),
                })
            except Exception:
                continue
    return events


async def eth_get_storage_at(session, addr: str, slot: str, block: str, api_key: str) -> str | None:
    """Read a storage slot from Polygonscan's eth_getStorageAt proxy."""
    params = {
        "module": "proxy",
        "action": "eth_getStorageAt",
        "address": addr,
        "position": slot,
        "tag": block,
        "apikey": api_key,
    }
    try:
        async with session.get(POLYGONSCAN_API, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            data = await resp.json(content_type=None)
            result = data.get("result", "")
            if result and result != "0x" and result != "0x" + "0" * 64:
                return result
    except Exception:
        pass
    return None


async def eth_get_code(session, addr: str, api_key: str) -> str | None:
    """Get contract bytecode from Polygonscan proxy."""
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": addr,
        "tag": "latest",
        "apikey": api_key,
    }
    try:
        async with session.get(POLYGONSCAN_API, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            data = await resp.json(content_type=None)
            result = data.get("result", "")
            if result and result not in ("0x", ""):
                return result
    except Exception:
        pass
    return None


async def get_proxy_implementation(session, proxy_addr: str, block_hex: str, api_key: str) -> str | None:
    """Try to find the implementation address of a proxy contract."""
    # Try GnosisSafe slot 0 first
    raw = await eth_get_storage_at(session, proxy_addr, GNOSIS_IMPL_SLOT, block_hex, api_key)
    if raw and len(raw) >= 42:
        # Storage returns 32-byte hex; extract address from last 20 bytes
        addr = "0x" + raw[-40:]
        if addr != "0x" + "0" * 40:
            return addr.lower()

    # Try EIP-1967 slot
    raw = await eth_get_storage_at(session, proxy_addr, EIP1967_IMPL_SLOT, block_hex, api_key)
    if raw and len(raw) >= 42:
        addr = "0x" + raw[-40:]
        if addr != "0x" + "0" * 40:
            return addr.lower()

    return None


def slot_to_block_hex(block_num) -> str:
    try:
        return hex(int(block_num))
    except Exception:
        return "latest"


async def process_group(session, canon_reason: str, group_events: list[dict], api_key: str, semaphore: asyncio.Semaphore):
    """For one canonical reason group, sample trapped addresses and fetch bytecodes."""
    async with semaphore:
        # Collect unique trapped addresses (up to 10 per group to sample)
        seen_trapped = {}
        for ev in group_events:
            addr = ev["trapped_address"]
            if addr not in seen_trapped:
                seen_trapped[addr] = ev
            if len(seen_trapped) >= 10:
                break

        implementations = {}  # impl_addr -> bytecode

        for proxy_addr, ev in seen_trapped.items():
            block_hex = slot_to_block_hex(ev["block_num"])
            impl_addr = await get_proxy_implementation(session, proxy_addr, block_hex, api_key)
            if not impl_addr:
                # Also try at latest (implementation might still be there)
                impl_addr = await get_proxy_implementation(session, proxy_addr, "latest", api_key)
            if not impl_addr:
                continue

            if impl_addr in implementations:
                continue

            bytecode = await eth_get_code(session, impl_addr, api_key)
            if bytecode and bytecode != "0x":
                implementations[impl_addr] = bytecode
            await asyncio.sleep(0.25)  # Polygonscan rate limit ~5 req/s

        return canon_reason, implementations


async def main():
    keys = load_api_keys()
    if not keys["etherscan"]:
        print("ERROR: ETHERSCAN_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    api_key = keys["etherscan"]

    print("Loading proxy_trap events from parquets...")
    events = load_proxy_trap_events()
    print(f"  Total proxy_trap events: {len(events):,}")

    # Group by canonical_reason
    groups: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        groups[ev["canonical_reason"]].append(ev)

    # Summary stats
    print(f"\n  Distinct canonical revert reasons: {len(groups)}")
    print("\n  Count breakdown:")
    for reason, evlist in sorted(groups.items(), key=lambda x: -len(x[1])):
        # Count unique trapped addresses
        unique_trapped = len(set(e["trapped_address"] for e in evlist))
        print(f"    {len(evlist):7,} events  {unique_trapped:4} unique proxies  [{reason}]")

    # Save the summary
    summary = []
    for reason, evlist in sorted(groups.items(), key=lambda x: -len(x[1])):
        unique_trapped = set(e["trapped_address"] for e in evlist)
        unique_attackers = set(e["attacker"] for e in evlist)
        v1 = sum(1 for e in evlist if e["version"] == "v1")
        v2 = sum(1 for e in evlist if e["version"] == "v2")
        # First and last block
        blocks = [int(e["block_num"]) for e in evlist if e["block_num"]]
        summary.append({
            "canonical_reason": reason,
            "total_events": len(evlist),
            "v1_events": v1,
            "v2_events": v2,
            "unique_trapped_addresses": len(unique_trapped),
            "unique_attackers": len(unique_attackers),
            "first_block": min(blocks) if blocks else None,
            "last_block": max(blocks) if blocks else None,
            "sample_trapped_addresses": list(unique_trapped)[:5],
            "sample_tx_hashes": [e["tx_hash"] for e in evlist[:3]],
        })

    summary_path = RESULTS_DIR / "revert_reason_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\nSaved summary to {summary_path}")

    print("\nFetching proxy implementations and bytecodes via Polygonscan...")
    semaphore = asyncio.Semaphore(3)  # max 3 concurrent groups

    async with aiohttp.ClientSession() as session:
        tasks = [
            process_group(session, reason, evlist, api_key, semaphore)
            for reason, evlist in groups.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Organize: by canonical_reason → list of {impl_addr, bytecode_hash, bytecode}
    bytecode_catalog = {}
    all_bytecodes = {}  # hash → bytecode (deduplicated across groups)

    for result in results:
        if isinstance(result, Exception):
            print(f"  ERROR: {result}")
            continue
        canon_reason, implementations = result
        group_entries = []
        for impl_addr, bytecode in implementations.items():
            try:
                raw = bytecode[2:] if bytecode.startswith("0x") else bytecode
                # Strip any non-hex characters (shouldn't happen but defensive)
                raw = raw.strip()
                bcode_bytes = bytes.fromhex(raw)
                bcode_hash = hashlib.sha256(bcode_bytes).hexdigest()[:16]
                all_bytecodes[bcode_hash] = bytecode
                group_entries.append({
                    "impl_address": impl_addr,
                    "bytecode_hash": bcode_hash,
                    "bytecode_size_bytes": len(bcode_bytes),
                })
            except Exception as e:
                print(f"  WARN: failed to hash bytecode for {impl_addr}: {e} (raw prefix: {bytecode[:40]!r})")
        bytecode_catalog[canon_reason] = group_entries

    # Save individual bytecode files
    bytecode_dir = RESULTS_DIR / "bytecodes"
    bytecode_dir.mkdir(exist_ok=True)
    for bcode_hash, bytecode in all_bytecodes.items():
        (bytecode_dir / f"{bcode_hash}.hex").write_text(bytecode)

    print(f"\nSaved {len(all_bytecodes)} unique implementation bytecodes to {bytecode_dir}")

    # Save catalog
    catalog_path = RESULTS_DIR / "bytecode_catalog.json"
    catalog_path.write_text(json.dumps(bytecode_catalog, indent=2))
    print(f"Saved bytecode catalog to {catalog_path}")

    # Print catalog summary
    print("\n=== Bytecode Catalog ===")
    for reason, entries in bytecode_catalog.items():
        if entries:
            print(f"\n  Reason: [{reason}]")
            for e in entries:
                print(f"    impl {e['impl_address']}  hash={e['bytecode_hash']}  size={e['bytecode_size_bytes']}B")
        else:
            print(f"\n  Reason: [{reason}]  → no implementation found")


if __name__ == "__main__":
    asyncio.run(main())
