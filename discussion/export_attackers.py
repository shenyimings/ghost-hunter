import csv
import json
import os
from collections import Counter

import pandas as pd

V1 = "../results/all_v1.parquet"
V2 = "../results/all_v2.parquet"
KEEP = {"proxy_trap", "nonce_bump", "approve_revoke", "balance_drain"}
OUT = "attackers_matching_participants.csv"


def participant(matched_rule: str, rule_result: dict) -> str | None:
    if matched_rule == "proxy_trap":
        a = rule_result.get("trapped_address")
    else:
        a = rule_result.get("attacker")
    return a.lower() if a else None


def process_parquet(path: str, agg: dict) -> tuple[int, int]:
    df = pd.read_parquet(path)
    df = df[df["matched_rule"].isin(KEEP)].copy()

    seen = skipped = 0
    for _, row in df.iterrows():
        mr = row["matched_rule"]
        try:
            rr = json.loads(row["rule_result"])
        except (json.JSONDecodeError, TypeError):
            skipped += 1
            continue

        addr = participant(mr, rr)
        if not addr:
            skipped += 1
            continue

        seen += 1
        ts = str(row.get("timestamp") or "")
        tx = str(row.get("tx_hash") or "")
        key = (addr, mr)
        cur = agg.get(key)
        if cur is None:
            agg[key] = [1, ts, tx]
        else:
            cur[0] += 1
            if ts > cur[1]:
                cur[1], cur[2] = ts, tx

    return seen, skipped


def main() -> None:
    agg: dict[tuple[str, str], list] = {}
    total_seen = total_skipped = 0

    for path in [V1, V2]:
        print(f"processing {path} ...", flush=True)
        s, sk = process_parquet(path, agg)
        total_seen += s
        total_skipped += sk
        print(f"  seen={s:,}  skipped={sk:,}", flush=True)

    rows = sorted(agg.items(), key=lambda kv: -kv[1][0])
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["address", "attack_type", "last_active_utc", "revert_tx", "total_attacks"]
        )
        for (addr, mr), (cnt, ts, tx) in rows:
            w.writerow([addr, mr, ts, tx, cnt])

    by_type: Counter = Counter()
    addrs_by_type: dict[str, set] = {}
    for (addr, mr), v in agg.items():
        by_type[mr] += v[0]
        addrs_by_type.setdefault(mr, set()).add(addr)
    uniq_addr = {a for a, _ in agg}
    print(
        f"\nkept attack records: {total_seen:,}  skipped (no addr): {total_skipped:,}"
    )
    print(f"rows (address,type): {len(agg):,}   unique addresses: {len(uniq_addr):,}")
    print("per type  (unique_addresses / total_reverts):")
    for mr in KEEP:
        print(f"  {mr:16} {len(addrs_by_type.get(mr, set())):>8,} / {by_type[mr]:>9,}")
    multi = sum(1 for v in Counter(a for a, _ in agg).values() if v > 1)
    print(f"addresses appearing under >1 attack_type: {multi:,}")
    print(f"written -> {OUT}")


if __name__ == "__main__":
    main()
