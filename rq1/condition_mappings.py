from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import pandas as pd
import requests

GAMMA_URL = "https://gamma-api.polymarket.com/markets"
BATCH_SIZE = 50  # keeps URL under ~4 KB
REQUEST_TIMEOUT = 30
RETRY_SLEEP = 2.0
MAX_RETRIES = 5


def fetch_batch(condition_ids: list[str], closed: bool) -> list[dict]:
    params = [("condition_ids", c) for c in condition_ids]
    params.append(("limit", str(len(condition_ids) + 10)))
    params.append(("closed", "true" if closed else "false"))

    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(GAMMA_URL, params=params, timeout=REQUEST_TIMEOUT)
            if r.status_code == 429:
                time.sleep(RETRY_SLEEP * (attempt + 1) * 2)
                continue
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            if attempt == MAX_RETRIES - 1:
                print(f"  ! batch failed after {MAX_RETRIES} retries: {e}")
                return []
            time.sleep(RETRY_SLEEP * (attempt + 1))
    return []


def extract_row(m: dict) -> dict:
    events = m.get("events") or []
    event = events[0] if events else {}
    clob_rewards = m.get("clobRewards") or []
    reward = clob_rewards[0] if clob_rewards else {}

    def _maybe_json(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return v
        return v

    return {
        "condition_id": m.get("conditionId"),
        "market_id": m.get("id"),
        "question": m.get("question"),
        "slug": m.get("slug"),
        "neg_risk": m.get("negRisk"),
        "neg_risk_request_id": m.get("negRiskRequestID") or None,
        "active": m.get("active"),
        "closed": m.get("closed"),
        "archived": m.get("archived"),
        "accepting_orders": m.get("acceptingOrders"),
        "start_date": m.get("startDate"),
        "end_date": m.get("endDate"),
        "outcomes": _maybe_json(m.get("outcomes")),
        "outcome_prices": _maybe_json(m.get("outcomePrices")),
        "clob_token_ids": _maybe_json(m.get("clobTokenIds")),
        "volume_num": m.get("volumeNum"),
        "liquidity_num": m.get("liquidityNum"),
        "rewards_min_size": m.get("rewardsMinSize"),
        "rewards_max_spread": m.get("rewardsMaxSpread"),
        "rewards_daily_rate": reward.get("rewardsDailyRate"),
        "fees_enabled": m.get("feesEnabled"),
        "maker_base_fee": m.get("makerBaseFee"),
        "taker_base_fee": m.get("takerBaseFee"),
        "event_id": event.get("id"),
        "event_slug": event.get("slug"),
        "event_ticker": event.get("ticker"),
        "event_title": event.get("title"),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="output-prod/all_v2.dedup.parquet")
    ap.add_argument("--output", default="output-prod/condition_mappings.parquet")
    ap.add_argument(
        "--checkpoint-every", type=int, default=20,
        help="Write partial parquet every N batches (for resume)."
    )
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(in_path, columns=["condition_id"])
    cids = sorted(c for c in df["condition_id"].dropna().unique() if c)
    print(f"Loaded {len(cids):,} unique condition_ids from {in_path}")

    done_rows: list[dict] = []
    done_set: set[str] = set()
    if out_path.exists():
        existing = pd.read_parquet(out_path)
        done_rows = existing.to_dict("records")
        done_set = set(existing["condition_id"].dropna().tolist())
        print(f"Resuming: {len(done_set):,} already mapped")

    todo = [c for c in cids if c not in done_set]
    print(f"To fetch: {len(todo):,}")

    rows: list[dict] = list(done_rows)
    found_this_run = 0

    for i in range(0, len(todo), BATCH_SIZE):
        batch = todo[i:i + BATCH_SIZE]
        markets: dict[str, dict] = {}
        for closed in (False, True):
            for m in fetch_batch(batch, closed=closed):
                cid = m.get("conditionId")
                if cid:
                    markets[cid] = m

        for cid in batch:
            if cid in markets:
                rows.append(extract_row(markets[cid]))
                found_this_run += 1
            else:
                rows.append({"condition_id": cid})

        done = min(i + BATCH_SIZE, len(todo))
        print(
            f"  [{done:>6}/{len(todo)}] batch ok, "
            f"found {len(markets)}/{len(batch)} this batch "
            f"(run total found: {found_this_run})"
        )

        if ((i // BATCH_SIZE) + 1) % args.checkpoint_every == 0:
            pd.DataFrame(rows).to_parquet(out_path, index=False)
            print(f"    checkpoint: wrote {len(rows):,} rows -> {out_path}")

        time.sleep(0.1)

    out_df = pd.DataFrame(rows).drop_duplicates(subset=["condition_id"], keep="last")
    out_df.to_parquet(out_path, index=False)

    hit = out_df["question"].notna().sum() if "question" in out_df.columns else 0
    print(
        f"\nDone. Wrote {len(out_df):,} rows ({hit:,} with market metadata, "
        f"{len(out_df) - hit:,} unresolved) -> {out_path}"
    )


if __name__ == "__main__":
    main()
