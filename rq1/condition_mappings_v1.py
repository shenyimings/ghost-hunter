from __future__ import annotations

import argparse
import gc
import json
import time
from pathlib import Path

import pandas as pd
import requests

GAMMA_MARKETS = "https://gamma-api.polymarket.com/markets"
GAMMA_EVENTS = "https://gamma-api.polymarket.com/events"
BATCH_SIZE = 50
REQUEST_TIMEOUT = 30
RETRY_SLEEP = 2.0
MAX_RETRIES = 5


def _get_with_retry(url: str, params: list[tuple]) -> list:
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            if r.status_code == 429:
                time.sleep(RETRY_SLEEP * (attempt + 1) * 2)
                continue
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            if attempt == MAX_RETRIES - 1:
                print(f"  ! request failed after {MAX_RETRIES} retries: {e}")
                return []
            time.sleep(RETRY_SLEEP * (attempt + 1))
    return []


def fetch_batch(ids: list[str], query_param: str, closed: bool) -> list[dict]:
    params = [(query_param, x) for x in ids]
    params.append(("limit", str(len(ids) + 10)))
    params.append(("closed", "true" if closed else "false"))
    return _get_with_retry(GAMMA_MARKETS, params)


def fetch_event_tags(event_ids: list[str]) -> dict[str, list[str] | None]:
    if not event_ids:
        return {}
    params = [("id", str(eid)) for eid in event_ids]
    params.append(("limit", str(len(event_ids) + 10)))
    out: dict[str, list[str] | None] = {}
    for ev in _get_with_retry(GAMMA_EVENTS, params):
        eid = str(ev.get("id")) if ev.get("id") is not None else None
        if not eid:
            continue
        out[eid] = _labels(ev.get("tags"))
    return out


def _maybe_json(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v
    return v


def _labels(items) -> list[str] | None:
    if not isinstance(items, list):
        return None
    out = [x.get("label") for x in items if isinstance(x, dict) and x.get("label")]
    return out or None


def extract_market_base(m: dict) -> dict:
    events = m.get("events") or []
    event = events[0] if events else {}
    clob_rewards = m.get("clobRewards") or []
    reward = clob_rewards[0] if clob_rewards else {}

    return {
        # identity
        "condition_id": m.get("conditionId"),
        "market_id": m.get("id"),
        "question": m.get("question"),
        "slug": m.get("slug"),
        # NegRisk structure
        "neg_risk": m.get("negRisk"),
        "neg_risk_request_id": m.get("negRiskRequestID") or None,
        "market_group": m.get("marketGroup"),
        "group_item_title": m.get("groupItemTitle"),
        # lifecycle
        "active": m.get("active"),
        "closed": m.get("closed"),
        "archived": m.get("archived"),
        "accepting_orders": m.get("acceptingOrders"),
        "start_date": m.get("startDate"),
        "end_date": m.get("endDate"),
        "closed_time": m.get("closedTime"),
        "game_start_time": m.get("gameStartTime"),
        "event_start_time": m.get("eventStartTime"),
        # outcomes
        "outcomes": _maybe_json(m.get("outcomes")),
        "outcome_prices": _maybe_json(m.get("outcomePrices")),
        # volume / liquidity (basic)
        "volume_num": m.get("volumeNum"),
        "liquidity_num": m.get("liquidityNum"),
        # rewards
        "rewards_min_size": m.get("rewardsMinSize"),
        "rewards_max_spread": m.get("rewardsMaxSpread"),
        "rewards_daily_rate": reward.get("rewardsDailyRate"),
        # fees
        "fees_enabled": m.get("feesEnabled"),
        "maker_base_fee": m.get("makerBaseFee"),
        "taker_base_fee": m.get("takerBaseFee"),
        # market typology
        "market_type": m.get("marketType"),
        "format_type": m.get("formatType"),
        "sports_market_type": m.get("sportsMarketType"),
        # taxonomy
        "market_tags": _labels(m.get("tags")),
        # event-level
        "event_id": event.get("id"),
        "event_slug": event.get("slug"),
        "event_ticker": event.get("ticker"),
        "event_title": event.get("title"),
        "event_tags": _labels(event.get("tags")),
        "event_closed_time": event.get("closedTime"),
        "event_enable_neg_risk": event.get("enableNegRisk"),
        "event_neg_risk_market_id": event.get("negRiskMarketID"),
    }


def expand_for_v1(m: dict) -> list[dict]:
    base = extract_market_base(m)
    outcomes = base["outcomes"]
    outcome_prices = base["outcome_prices"]
    clob_token_ids = _maybe_json(m.get("clobTokenIds")) or []

    rows = []
    for i, tid in enumerate(clob_token_ids):
        outcome_label = outcomes[i] if isinstance(outcomes, list) and i < len(outcomes) else None
        outcome_price = outcome_prices[i] if isinstance(outcome_prices, list) and i < len(outcome_prices) else None
        rows.append({
            "token_id": tid,
            "outcome_index": i,
            "outcome_label": outcome_label,
            "outcome_price": outcome_price,
            **base,
        })
    return rows


def run(
    version: str,
    input_path: str,
    output_path: str,
    id_column: str,
    query_param: str,
    checkpoint_every: int,
) -> None:
    in_path = Path(input_path)
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    key = "token_id" if version == "v1" else "condition_id"

    df = pd.read_parquet(in_path, columns=[id_column])
    ids = sorted(x for x in df[id_column].dropna().unique() if x)
    print(f"[{version}] Loaded {len(ids):,} unique {id_column}s from {in_path}")
    del df
    gc.collect()

    done_rows: list[dict] = []
    done_set: set[str] = set()
    if out_path.exists():
        existing = pd.read_parquet(out_path)
        done_rows = existing.to_dict("records")
        done_set = set(existing[key].dropna().tolist())
        print(f"[{version}] Resuming: {len(done_set):,} already mapped")
        del existing
        gc.collect()

    todo = [x for x in ids if x not in done_set]
    print(f"[{version}] To fetch: {len(todo):,}")

    rows: list[dict] = list(done_rows)
    del done_rows
    found_this_run = 0
    event_tags_cache: dict[str, list[str] | None] = {}

    for i in range(0, len(todo), BATCH_SIZE):
        batch = todo[i:i + BATCH_SIZE]
        new_rows_start = len(rows)

        if version == "v1":
            key_map: dict[str, dict] = {}
            for closed in (False, True):
                for m in fetch_batch(batch, query_param, closed):
                    for row in expand_for_v1(m):
                        tid = row.get("token_id")
                        if tid:
                            key_map[tid] = row
            for tid in batch:
                if tid in key_map:
                    rows.append(key_map[tid])
                    found_this_run += 1
                else:
                    rows.append({"token_id": tid})
            n_found = sum(1 for t in batch if t in key_map)
        else:
            mkt_map: dict[str, dict] = {}
            for closed in (False, True):
                for m in fetch_batch(batch, query_param, closed):
                    cid = m.get("conditionId")
                    if cid:
                        mkt_map[cid] = m
            for cid in batch:
                if cid in mkt_map:
                    rows.append(extract_market_base(mkt_map[cid]))
                    found_this_run += 1
                else:
                    rows.append({"condition_id": cid})
            n_found = len(mkt_map)

        new_eids = {
            str(r["event_id"]) for r in rows[new_rows_start:]
            if r.get("event_id") is not None and str(r["event_id"]) not in event_tags_cache
        }
        if new_eids:
            event_tags_cache.update(fetch_event_tags(sorted(new_eids)))
        for r in rows[new_rows_start:]:
            eid = r.get("event_id")
            if eid is not None:
                r["event_tags"] = event_tags_cache.get(str(eid))

        done = min(i + BATCH_SIZE, len(todo))
        print(
            f"[{version}]   [{done:>6}/{len(todo)}] found {n_found}/{len(batch)} "
            f"(run total: {found_this_run})"
        )

        if ((i // BATCH_SIZE) + 1) % checkpoint_every == 0:
            pd.DataFrame(rows).to_parquet(out_path, index=False)
            print(f"[{version}]     checkpoint: wrote {len(rows):,} rows -> {out_path}")

        time.sleep(0.1)

    out_df = pd.DataFrame(rows).drop_duplicates(subset=[key], keep="last")
    out_df.to_parquet(out_path, index=False)

    hit = out_df["question"].notna().sum() if "question" in out_df.columns else 0
    print(
        f"[{version}] Done. Wrote {len(out_df):,} rows ({hit:,} with metadata, "
        f"{len(out_df) - hit:,} unresolved) -> {out_path}\n"
    )
    del rows, out_df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint-every", type=int, default=20)
    ap.add_argument("--skip-v1", action="store_true")
    ap.add_argument("--skip-v2", action="store_true")
    args = ap.parse_args()

    if not args.skip_v1:
        run(
            version="v1",
            input_path="results/all_v1.parquet",
            output_path="results/market_mappings_v1.parquet",
            id_column="token_id",
            query_param="clob_token_ids",
            checkpoint_every=args.checkpoint_every,
        )
        gc.collect()

    if not args.skip_v2:
        run(
            version="v2",
            input_path="results/all_v2.parquet",
            output_path="results/market_mappings_v2.parquet",
            id_column="condition_id",
            query_param="condition_ids",
            checkpoint_every=args.checkpoint_every,
        )
        gc.collect()


if __name__ == "__main__":
    main()
