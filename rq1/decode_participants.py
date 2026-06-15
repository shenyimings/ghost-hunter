#!/usr/bin/env python
"""Decode participant / order fields for every reverted matchOrders (RQ1).

The engine-output Findings (``results/all_v{1,2}.parquet``) only carry decoded
participant fields for a subset of rows (``taker_maker`` / ``taker_signer`` for
unclassified rows, ``attacker`` / ``trapped_address`` for classified ones). RQ1's
"affected markets, users, and order patterns" analysis needs a *uniform* per-tx
view of who was involved (taker + every maker) and how big the order was, for
**all** ~1.95M reverts.

This is the one expensive step in the RQ1 pipeline — decoding 2M calldata blobs —
so it lives here as a standalone script rather than inside ``statistic.ipynb``.
It reads the raw sharded Dune dumps in ``parquets/{v1,v2}/`` (one row per reverted
matchOrders, carrying ``tx_input``), ABI-decodes each blob with the project's
``decode_match_orders`` (see ``src/ghost_hunter/core/decoder.py``), and persists a
single tidy parquet to ``results/rq1_participants.parquet``.

Run:
    uv run rq1/decode_participants.py            # all shards, all workers
    uv run rq1/decode_participants.py --limit 5  # smoke-test 5 shards

Output schema (one row per reverted matchOrders):
    tx_hash            str        reverted matchOrders tx hash (lower-case)
    version            str        'v1' | 'v2'
    contract_label     str        human contract label (ctf_v1, neg_risk_v2, ...)
    decoded            bool       False if the calldata could not be decoded
    taker_maker        str        taker order .maker
    taker_signer       str        taker order .signer
    taker_side         int        0=BUY, 1=SELL (taker order)
    num_makers         int        number of maker orders matched
    maker_makers       list[str]  every maker order .maker
    maker_signers      list[str]  every maker order .signer
    token_id           str        V1: taker order CTF token id (dec, as str)
    condition_id       str        V2: bytes32 condition id (hex)
    n_participants     int        distinct addresses across taker + makers
    participants       list[str]  the distinct address set (for user-level rollups)
    taker_fill         float      taker_fill_amount, human units (raw/1e6)
    maker_fill_total   float      Σ maker_fill_amounts, human units
    collateral_at_risk float      taker_fill + Σ maker_fill, human units
    taker_fee          float      taker_fee_amount, human units
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

# --- make the project package importable (src/ layout, not pip-installed) ----
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ghost_hunter.core.decoder import decode_match_orders  # noqa: E402
from ghost_hunter.core.models import DecodedMatchOrdersV2  # noqa: E402

# Contract address -> human label (mirrors models.labelS / notebook CONTRACT_LABELS).
CONTRACT_LABELS = {
    "0xe111180000d2663c0091e4f400237545b87b996b": "ctf_v2",
    "0xe2222d279d744050d28e00520010520000310f59": "neg_risk_v2",
    "0xb768891e3130f6df18214ac804d4db76c2c37730": "neg_risk_fee_module_v1",
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0": "ctf_fee_module_v1",
    "0xc5d563a36ae78145c45a50134d48a1215220f80a": "neg_risk_v1",
    "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e": "ctf_v1",
}

USDC_DECIMALS = 1_000_000  # both USDC.e (V1) and pUSD (V2) use 6 decimals

PARQUETS = REPO_ROOT / "parquets"
OUT_PATH = REPO_ROOT / "results" / "rq1_participants.parquet"
PARTS_DIR = REPO_ROOT / "results" / "rq1" / "participants_parts"


def _decode_row(tx_hash: str, contract: str, tx_input: str) -> dict:
    """Decode one reverted matchOrders calldata blob into a participant record."""
    contract = (contract or "").lower()
    rec: dict = {
        "tx_hash": (tx_hash or "").lower(),
        "contract_label": CONTRACT_LABELS.get(contract, contract),
        "decoded": False,
        "taker_maker": None,
        "taker_signer": None,
        "taker_side": None,
        "num_makers": 0,
        "maker_makers": [],
        "maker_signers": [],
        "token_id": None,
        "condition_id": None,
        "n_participants": 0,
        "participants": [],
        "taker_fill": 0.0,
        "maker_fill_total": 0.0,
        "collateral_at_risk": 0.0,
        "taker_fee": 0.0,
    }
    try:
        d = decode_match_orders(tx_input, contract)
    except Exception:
        d = None
    if d is None:
        return rec

    is_v2 = isinstance(d, DecodedMatchOrdersV2)
    rec["version"] = "v2" if is_v2 else "v1"
    rec["decoded"] = True

    t = d.taker_order
    rec["taker_maker"] = t.maker
    rec["taker_signer"] = t.signer
    rec["taker_side"] = int(t.side)
    rec["num_makers"] = len(d.maker_orders)
    rec["maker_makers"] = [m.maker for m in d.maker_orders]
    rec["maker_signers"] = [m.signer for m in d.maker_orders]

    if is_v2:
        rec["condition_id"] = d.condition_id
    else:
        rec["token_id"] = str(t.token_id)

    parts = {t.maker, t.signer}
    for m in d.maker_orders:
        parts.add(m.maker)
        parts.add(m.signer)
    parts.discard(None)
    rec["participants"] = sorted(parts)
    rec["n_participants"] = len(parts)

    rec["taker_fill"] = d.taker_fill_amount / USDC_DECIMALS
    rec["maker_fill_total"] = sum(d.maker_fill_amounts) / USDC_DECIMALS
    rec["collateral_at_risk"] = rec["taker_fill"] + rec["maker_fill_total"]
    rec["taker_fee"] = d.taker_fee_amount / USDC_DECIMALS
    return rec


def _process_shard(shard: str, version: str) -> str:
    """Decode every row of one raw shard; write a partial parquet, return its path."""
    df = pd.read_parquet(shard, columns=["transaction_hash", "contract_address", "tx_input"])
    recs = [
        _decode_row(h, c, i)
        for h, c, i in zip(df["transaction_hash"], df["contract_address"], df["tx_input"])
    ]
    out = pd.DataFrame.from_records(recs)
    out["version"] = out.get("version", version).fillna(version)
    PARTS_DIR.mkdir(parents=True, exist_ok=True)
    part = PARTS_DIR / f"{version}__{Path(shard).name}.parquet"
    out.to_parquet(part, index=False)
    return str(part)


def _gather_shards() -> list[tuple[str, str]]:
    shards: list[tuple[str, str]] = []
    for version, sub in (("v1", "v1"), ("v2", "v2")):
        d = PARQUETS / sub
        if not d.exists():
            continue
        for p in sorted(d.glob(f"polymarket_ctf_exchange_{version}_*")):
            shards.append((str(p), version))
    return shards


def main() -> None:
    ap = argparse.ArgumentParser(description="Decode participant fields for all reverts (RQ1).")
    ap.add_argument("--workers", type=int, default=None, help="process pool size (default: CPU count)")
    ap.add_argument("--limit", type=int, default=None, help="only process the first N shards (smoke test)")
    args = ap.parse_args()

    shards = _gather_shards()
    if args.limit:
        shards = shards[: args.limit]

    if not shards:
        print(
            f"[decode_participants] No raw shards found under {PARQUETS}/. "
            "This directory is .gitignored and holds the Dune dumps that carry tx_input.\n"
            "Re-fetch the raw reverted-matchOrders shards (see scripts/get_revert_match_orders.py) "
            "into parquets/v1/ and parquets/v2/, then re-run this script.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[decode_participants] decoding {len(shards)} shards -> {OUT_PATH}")
    parts: list[str] = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_process_shard, s, v): (s, v) for s, v in shards}
        for i, fut in enumerate(as_completed(futs), 1):
            s, _ = futs[fut]
            parts.append(fut.result())
            print(f"  [{i}/{len(shards)}] done {Path(s).name}")

    combined = pd.concat((pd.read_parquet(p) for p in parts), ignore_index=True)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    combined.to_parquet(OUT_PATH, index=False)

    n = len(combined)
    dec = int(combined["decoded"].sum())
    print(f"[decode_participants] wrote {n:,} rows ({dec:,} decoded, {n - dec:,} failed) -> {OUT_PATH}")


if __name__ == "__main__":
    main()
