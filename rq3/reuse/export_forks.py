"""Export third-party Polymarket forks from the BigQuery Jaccard dump.

Filters:
  1. max_jaccard > 0.5            (the user's variant threshold)
  2. drop testnets               (chainlist.org isTestnet == true)
  3. drop Polymarket official     (ONLY the 5 canonical official addresses;
                                   third-party forks on Polygon itself are kept)
  4. dedup by (chain_id, address), keeping the highest jaccard
"""
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

THRESH = 0.5
# the ONLY official Polymarket contracts to exclude (everything else, incl.
# Polygon-deployed third-party forks, is kept)
OFFICIAL_ADDRS = {
    "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e",  # CTF Exchange
    "0xc5d563a36ae78145c45a50134d48a1215220f80a",  # NegRisk CTF Exchange
    "0x56c79347e95530c01a2fc76e732f9566da16e113",  # Fee Module
    "0x78769d50be1763ed1ca0d5e878d93f05aabff29e",  # NegRisk Fee Module V1
    "0xb768891e3130f6df18214ac804d4db76c2c37730",  # NegRisk Fee Module V2
}

d = json.load(open(os.path.join(HERE, "jaccard_0_1.json")))
testnet = set(json.load(open(os.path.join(HERE, "testnet_ids.json"))))

best = {}
dropped = Counter()
for r in d:
    if float(r["max_jaccard"]) <= THRESH:
        dropped["jaccard<=0.5"] += 1
        continue
    if r["chain_id"] in testnet:
        dropped["testnet"] += 1
        continue
    if r["address"].lower() in OFFICIAL_ADDRS:
        dropped["polymarket_official"] += 1
        continue
    key = (r["chain_id"], r["address"].lower())
    if key not in best or float(r["max_jaccard"]) > float(best[key]["max_jaccard"]):
        best[key] = r

forks = sorted(best.values(), key=lambda r: -float(r["max_jaccard"]))
json.dump(forks, open(os.path.join(HERE, "forks_jaccard_gt0.5.json"), "w"), indent=1)

print(f"input rows: {len(d)}")
print(f"dropped: {dict(dropped)}")
print(f"unique fork contracts exported: {len(forks)}")
print(f"\nby chain:")
for c, n in Counter(r["chain_id"] for r in forks).most_common():
    print(f"  chain {c:>8}: {n}")
print(f"\nby contract_name:")
for nm, n in Counter(r["contract_name"] for r in forks).most_common(20):
    print(f"  {n:>4}  {nm}")
print(f"\njaccard buckets:")
for lo in [1.0, 0.9, 0.8, 0.7, 0.6, 0.5]:
    hi = lo + 0.1
    n = sum(1 for r in forks if lo <= float(r["max_jaccard"]) < (hi if lo < 1.0 else 1.01))
    print(f"  [{lo:.1f},{'1.01' if lo==1.0 else f'{hi:.1f}'}): {n}")
