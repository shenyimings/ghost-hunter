#!/usr/bin/env python3
"""Summary statistics for the RQ3 cross-chain contract-reuse dataset.

Input : forks_jaccard_gt0.5_final.json
        A list of verified contracts whose function-selector set has Jaccard
        similarity >= 0.5 against one of the four official Polymarket exchange
        contracts. Each record carries chain_id, address, max_jaccard,
        tx_count_total, and is_active_after_20260506 (active on/after the
        2026-05-06 end of the study window).

Output: counts requested for the RQ3 section.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "forks_jaccard_gt0.5_final.json")

# Official Polymarket production deployments to drop before measuring third-party
# reuse. The four selector-set reference contracts are already absent from the
# export (self-matches were excluded); this list catches other official
# deployments that the selector scan still surfaces.
EXCLUDE = {
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0",  # Polygon FeeModule, 329M txs
}


def main():
    with open(SRC) as f:
        rows = json.load(f)

    rows = [r for r in rows if r["address"].lower() not in EXCLUDE]

    n_total = len(rows)
    chains = {r["chain_id"] for r in rows}

    # tx_count_total may arrive as int or string; coerce defensively.
    def tx(r):
        return int(r.get("tx_count_total") or 0)

    n_tx_gt100 = sum(1 for r in rows if tx(r) > 100)

    active = [r for r in rows if r.get("is_active_after_20260506")]
    n_active = len(active)

    busiest = max(rows, key=tx)
    avg_tx_active = (sum(tx(r) for r in active) / n_active) if n_active else 0.0

    print(f"1. Chains covered           : {len(chains)}")
    print(f"   Contracts total          : {n_total}")
    print(f"2. Contracts with >100 txs  : {n_tx_gt100}")
    print(f"   Active after 2026-05-06  : {n_active}")
    print(f"3. Busiest contract tx_count: {tx(busiest):,}")
    print(f"   -> {busiest['address']} on chain {busiest['chain_id']} "
          f"({busiest['contract_name']})")
    print(f"   Avg tx of active contracts: {avg_tx_active:,.1f}")

    print()
    print("Chain ids:", ", ".join(sorted(chains, key=int)))


if __name__ == "__main__":
    main()
