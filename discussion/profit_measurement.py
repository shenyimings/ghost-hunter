"""Profit measurement for the Discussion section.

Computes the headline numbers behind Section "Profit Measurement":

  1. Lower-bound realized profit of the attacker population.
     We sum ONLY realized_pnl > 0 across the de-duplicated attacker set.
     realized_pnl is the corrected ledger; lbapi_pnl is the Polymarket
     leaderboard figure, which is skewed by Ghost Fills and is NOT used.

  2. The "phantom companion" population behind the risk-free-prediction
     strategy: addresses that never settled a successful match (no redeems,
     Polymarket-reported PnL ~ 0) and whose Cancellation Attacks land
     exclusively in 5-minute crypto up/down markets. Their real gains are
     harvested by a separate companion address and cannot be measured here.

  3. The case-study figures for the worked example attacker 0xc393…b18f.

Inputs (all relative to this file):
  attackers_all_pnl.csv              one row per de-duplicated attacker
  ../results/all_v1.parquet            per-revert records (V1, token_id)
  ../results/all_v2.parquet            per-revert records (V2, condition_id)
  ../results/market_mappings_v1.parquet  token_id  -> market metadata  (regenerate via scripts/condition_mappings_v1.py)
  ../results/market_mappings_v2.parquet  condition_id -> market metadata  (regenerate via scripts/condition_mappings_v1.py)

Run:  uv run python profit_measurement.py
"""

import json
import pathlib

import pandas as pd

HERE = pathlib.Path(__file__).parent
RESULTS = HERE / ".." / "results"
PNL_CSV = HERE / "attackers_all_pnl.csv"

# Attack vectors that GhostHunter attributes to a deliberate actor.
# balance_drain_normal_gas / custom_error / unclassified are benign or unknown.
ATTACK_RULES = {"nonce_bump", "balance_drain", "approve_revoke", "proxy_trap"}

CASE_STUDY = "0xc39319fc46cb229eeacf3763cce5977766b3b18f"


def is_crypto(tags, slug) -> bool:
    """A 5-minute crypto up/down market: tagged Crypto, or an *-updown-* slug."""
    try:
        if any("crypto" in str(t).lower() for t in tags):
            return True
    except TypeError:
        pass
    return "updown" in str(slug).lower()


def attacker_of(rule_result: str) -> str:
    if not isinstance(rule_result, str) or not rule_result:
        return ""
    try:
        a = json.loads(rule_result).get("attacker", "")
    except (ValueError, AttributeError):
        return ""
    return a.lower() if isinstance(a, str) and a.startswith("0x") else ""


def load_market_crypto_flags():
    """Return (token_id -> is_crypto) for V1 and (condition_id -> is_crypto) for V2."""
    mm1 = pd.read_parquet(
        RESULTS / "market_mappings_v1.parquet",
        columns=["token_id", "slug", "event_tags"],
    )
    mm1["is_crypto"] = [is_crypto(t, s) for t, s in zip(mm1.event_tags, mm1.slug)]
    v1_flag = mm1.drop_duplicates("token_id").set_index("token_id").is_crypto

    mm2 = pd.read_parquet(
        RESULTS / "market_mappings_v2.parquet",
        columns=["condition_id", "slug", "event_tags"],
    )
    mm2["is_crypto"] = [is_crypto(t, s) for t, s in zip(mm2.event_tags, mm2.slug)]
    v2_flag = mm2.drop_duplicates("condition_id").set_index("condition_id").is_crypto
    return v1_flag, v2_flag


def load_attacks(v1_flag, v2_flag) -> pd.DataFrame:
    """Per-revert attack records with attacker address and a crypto-market flag."""
    v1 = pd.read_parquet(
        RESULTS / "all_v1.parquet",
        columns=["token_id", "matched_rule", "rule_result"],
    )
    v1 = v1[v1.matched_rule.isin(ATTACK_RULES)].copy()
    v1["attacker"] = v1.rule_result.map(attacker_of)
    v1["is_crypto"] = v1.token_id.map(v1_flag).fillna(False)

    v2 = pd.read_parquet(
        RESULTS / "all_v2.parquet",
        columns=["condition_id", "matched_rule", "rule_result"],
    )
    v2 = v2[v2.matched_rule.isin(ATTACK_RULES)].copy()
    v2["attacker"] = v2.rule_result.map(attacker_of)
    v2["is_crypto"] = v2.condition_id.map(v2_flag).fillna(False)

    cols = ["attacker", "is_crypto"]
    atk = pd.concat([v1[cols], v2[cols]], ignore_index=True)
    return atk[atk.attacker != ""]


def main():
    pnl = pd.read_csv(PNL_CSV)
    total_attacks = pnl.total_attacks.sum()

    # ---- (1) lower-bound realized profit -----------------------------------
    profitable = pnl[pnl.realized_pnl > 0]
    total_profit = profitable.realized_pnl.sum()

    print("=" * 64)
    print("PROFIT MEASUREMENT")
    print("=" * 64)
    print(f"distinct attacker addresses          : {pnl.address.nunique():,}")
    print(f"addresses with realized_pnl > 0      : {len(profitable):,}")
    print(f"lower-bound realized profit (sum >0) : ${total_profit:,.0f}")

    # ---- (2) phantom-companion population ----------------------------------
    # Per attacker: did every attributed Cancellation Attack land in a
    # 5-minute crypto market?
    v1_flag, v2_flag = load_market_crypto_flags()
    atk = load_attacks(v1_flag, v2_flag)
    by_addr = atk.groupby("attacker").is_crypto.agg(["mean", "size"])
    crypto_only = set(by_addr[by_addr["mean"] == 1.0].index)

    decoy_crypto = pnl[pnl.address.isin(crypto_only)]
    n = len(decoy_crypto)
    share = decoy_crypto.total_attacks.sum() / total_attacks

    print("\n" + "-" * 64)
    print("PHANTOM COMPANIONS (risk-free prediction, crypto-only decoys)")
    print("-" * 64)
    print(f"addresses, no redeem + flat PnL, crypto-only attacks : {n:,}")
    print(f"  share of all attributed attacks                    : {share:.1%}")
    print(f"  ({n / pnl.address.nunique():.1%} of distinct attacker addresses)")

    # ---- (3) worked-example attacker ---------------------------------------
    row = pnl[pnl.address == CASE_STUDY]
    print("\n" + "-" * 64)
    print(f"CASE STUDY  {CASE_STUDY}")
    print("-" * 64)
    if not row.empty:
        r = row.iloc[0]
        print(f"  markets traded (predictions): {int(r.markets_traded)}")
        print(f"  cancellation attacks        : {int(r.total_attacks)}")
        print(f"  realized profit             : ${r.realized_pnl:,.0f}")
    cs = atk[atk.attacker == CASE_STUDY]
    if len(cs):
        print(
            f"  attacks in crypto markets   : {cs.is_crypto.mean():.1%} "
            f"({len(cs)} attributed reverts)"
        )


if __name__ == "__main__":
    main()
