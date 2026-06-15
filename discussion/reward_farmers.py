#!/usr/bin/env python3
"""
Reproduce the reward-farming finding for the Polymarket Ghost Fills incident.

Usage:
  uv run reproduce_reward_farmers.py                  # V1 era (2026-02-10..04-28)
  uv run reproduce_reward_farmers.py --window v2      # V2 window (2026-04-28..05-06)
  uv run reproduce_reward_farmers.py --start-block N --end-block M --out foo.csv

Requires ETHERSCAN_API_KEY in .env (Etherscan v2 multichain key) and
results/attackers_all_pnl.csv (cols: rank,address,attack_type,total_attacks,
last_active_utc,realized_pnl,markets_traded).
"""
import argparse
import collections
import os
import sys
import time

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()

API = "https://api.etherscan.io/v2/api"
CHAIN_ID = 137  # Polygon
KEY = os.environ.get("ETHERSCAN_API_KEY", "")

DISTRIBUTORS = {
    "c288": "0xc288480574783bd7615170660d71753378159c47",  # primary, since 2023
    "f7cd": "0xf7cd89be08af4d4d6b1522852ced49fc10169f64",  # second, since 2026-02-10
}

# Pre-resolved block boundaries (Polygon, getblocknobytime "before").
WINDOWS = {
    "v1": (82823381, 86107178),  # 2026-02-10 .. 2026-04-28 (V2 cutover)
    "v2": (86107178, 86498453),  # 2026-04-28 .. 2026-05-07 (covers 04-28..05-06)
}

ATTACKERS_CSV = "results/attackers_all_pnl.csv"


def fetch_distributor(addr: str, start: int, end: int) -> tuple[dict, dict, dict]:
    """Cursor-walk every outgoing transfer of `addr` in [start, end].

    Returns (recv{addr->usd}, days{addr->#distinct days}, token_counts).
    Both USDC.e and pUSD are 6-decimal $1 stablecoins, summed as USD.
    """
    addr = addr.lower()
    recv = collections.defaultdict(float)
    ndays = collections.defaultdict(set)
    toks = collections.Counter()
    seen = set()
    sess = requests.Session()
    cursor = start

    while cursor < end:
        resp = None
        for _ in range(6):
            try:
                resp = sess.get(API, params={
                    "chainid": CHAIN_ID, "module": "account", "action": "tokentx",
                    "address": addr, "startblock": cursor, "endblock": end,
                    "sort": "asc", "offset": 10000, "page": 1, "apikey": KEY,
                }, timeout=60).json()
                break
            except Exception:
                time.sleep(2)
        if resp is None:
            sys.exit(f"FATAL: repeated fetch failure at cursor {cursor} for {addr}")

        res = resp.get("result", [])
        if not isinstance(res, list) or not res:
            break

        maxblk = cursor
        for x in res:
            blk = int(x["blockNumber"])
            maxblk = max(maxblk, blk)
            if x["from"].lower() != addr:
                continue
            k = (x["hash"], x["to"].lower(), x["value"])
            if k in seen:
                continue
            seen.add(k)
            to = x["to"].lower()
            usd = int(x["value"]) / 10 ** int(x["tokenDecimal"])
            recv[to] += usd
            ndays[to].add(time.strftime("%Y-%m-%d", time.gmtime(int(x["timeStamp"]))))
            toks[x["tokenSymbol"]] += 1

        if len(res) < 10000:
            break
        cursor = maxblk  # re-include boundary block; dedup handles overlap
        time.sleep(0.1)

    return dict(recv), {a: len(d) for a, d in ndays.items()}, dict(toks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", choices=["v1", "v2"], default="v1")
    ap.add_argument("--start-block", type=int)
    ap.add_argument("--end-block", type=int)
    ap.add_argument("--out")
    args = ap.parse_args()

    if not KEY:
        sys.exit("Set ETHERSCAN_API_KEY in .env")

    start, end = WINDOWS[args.window]
    if args.start_block:
        start = args.start_block
    if args.end_block:
        end = args.end_block
    out_path = args.out or f"results/attacker_reward_farmers_{args.window}.csv"

    # 1) fetch + merge both distributors
    recv = collections.defaultdict(float)
    days = collections.defaultdict(int)
    print(f"window {args.window}: blocks {start}..{end}")
    for name, addr in DISTRIBUTORS.items():
        r, d, toks = fetch_distributor(addr, start, end)
        print(f"  {name}: {len(r)} recipients, ${sum(r.values()):,.2f}, tokens={toks}")
        for a, v in r.items():
            recv[a] += v
        for a, n in d.items():
            days[a] = max(days[a], n)
    total = sum(recv.values())
    print(f"merged: {len(recv)} recipients, ${total:,.2f} distributed")

    # 2) join recipients against the attacker list
    ap_df = pd.read_csv(ATTACKERS_CSV)
    ap_df["addr"] = ap_df["address"].str.lower()
    ap_df["reward_usd"] = ap_df["addr"].map(recv)
    hit = ap_df[ap_df["reward_usd"].notna()].copy()
    hit["reward_usd"] = hit["reward_usd"].round(4)
    hit["reward_days"] = hit["addr"].map(days)

    cols = ["rank", "address", "attack_type", "total_attacks", "last_active_utc",
            "realized_pnl", "markets_traded", "reward_usd", "reward_days"]
    out = hit[cols].sort_values("reward_usd", ascending=False)
    out.to_csv(out_path, index=False)

    # 3) report
    print(f"\nattacker addresses receiving rewards: {len(out)}  "
          f"total ${out.reward_usd.sum():,.2f} ({100*out.reward_usd.sum()/total:.2f}% of pool)")
    print("\nby attack_type:")
    bt = out.groupby("attack_type").agg(
        addrs=("address", "size"), reward=("reward_usd", "sum"),
        pnl=("realized_pnl", "sum"), mkts_med=("markets_traded", "median"),
    ).round(2).sort_values("reward", ascending=False)
    print(bt.to_string())

    farmers = out[out.markets_traded.fillna(0) <= 1]
    print(f"\nzero-trade pure farmers (markets_traded<=1): {len(farmers)} addrs, "
          f"${farmers.reward_usd.sum():,.2f}")
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
