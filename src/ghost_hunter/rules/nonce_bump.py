from __future__ import annotations

from pathlib import Path

import polars as pl

from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult

_FEE_MODULE_TO_EXCHANGE: dict[str, str] = {
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0": "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e",  # ctf
    "0xb768891e3130f6df18214ac804d4db76c2c37730": "0xc5d563a36ae78145c45a50134d48a1215220f80a",  # neg_risk
}
_EXCHANGES = set(_FEE_MODULE_TO_EXCHANGE.values())

_LOOKBACK = 5

_NONCE_PARQUET = (
    Path(__file__).resolve().parents[3]
    / "parquets"
    / "nonce"
    / "polymarket_ctf_exchange_v1_increment_nonce"
)

# 4-byte selectors used in branches (2) and (3).
_SEL_EXEC_TRANSACTION = "6a761202"
_SEL_MULTISEND = "8d80ff0a"
_SEL_INCREMENT_NONCE = "627cdcb9"

_MULTISEND_WHITELIST = {
    "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761",  # Polymarket Gnosis Safe MultiSend
    "0x40a2accbd92bca938b02010e17a5b8929b49130d",  # Safe MultiSendCallOnly v1.3.0
    "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",  # Safe MultiSendCallOnly v1.4.1
    "0x998739bfdaadde7c933b942a68053933098f9eda",  # Safe MultiSend v1.3.0
    "0x8d29be29923b68abfdd21e541b9374737b49cdad",  # legacy
}


class NonceBumpResult(BaseRuleResult):
    attacker: str  # EOA that paid for the bump (tx.from of the causal tx)
    causal_tx: str  # hash of the bump tx
    causal_block: int
    exchange: str  # CTF or NegRisk exchange the bump was issued against
    gas_ratio: float  # bump_gas_fee / revert_gas_fee; 0 if revert gas is 0
    via: str  # "naive" | "proxy_exec" | "multisend"


# --------------------------------------------------------------------------
# Branch 2/3: ABI decoders for execTransaction and MultiSend
# --------------------------------------------------------------------------
def _parse_exec_transaction(inp_hex: str) -> tuple[str, int, bytes] | None:
    if inp_hex.startswith("0x"):
        inp_hex = inp_hex[2:]
    try:
        raw = bytes.fromhex(inp_hex)
    except ValueError:
        return None
    if len(raw) < 4 + 32 * 10:
        return None
    if raw[:4].hex() != _SEL_EXEC_TRANSACTION:
        return None
    body = raw[4:]
    inner_to = "0x" + body[12:32].hex()
    data_off = int.from_bytes(body[64:96], "big")
    operation = body[127]
    if data_off + 32 > len(body):
        return None
    data_len = int.from_bytes(body[data_off:data_off + 32], "big")
    start = data_off + 32
    if start + data_len > len(body):
        return None
    return inner_to.lower(), operation, body[start:start + data_len]


def _multisend_first_increment_nonce_exchange(call_data: bytes) -> str | None:
    if len(call_data) < 4 + 32 + 32 or call_data[:4].hex() != _SEL_MULTISEND:
        return None
    args = call_data[4:]
    off = int.from_bytes(args[0:32], "big")
    if off + 32 > len(args):
        return None
    blob_len = int.from_bytes(args[off:off + 32], "big")
    blob = args[off + 32:off + 32 + blob_len]
    if len(blob) < blob_len:
        return None
    i = 0
    while i < len(blob):
        if i + 1 + 20 + 32 + 32 > len(blob):
            return None
        i += 1                                          # operation (uint8)
        sub_to = "0x" + blob[i:i + 20].hex(); i += 20
        i += 32                                         # value
        d_len = int.from_bytes(blob[i:i + 32], "big"); i += 32
        if i + d_len > len(blob):
            return None
        sub_data = blob[i:i + d_len]; i += d_len
        if (
            sub_to.lower() in _EXCHANGES
            and len(sub_data) >= 4
            and sub_data[:4].hex() == _SEL_INCREMENT_NONCE
        ):
            return sub_to.lower()
    return None


def _hidden_bump_classify(input_hex: str) -> tuple[str, str] | None:
    parsed = _parse_exec_transaction(input_hex)
    if parsed is None:
        return None
    inner_to, operation, inner_data = parsed

    if (
        inner_to in _EXCHANGES
        and len(inner_data) >= 4
        and inner_data[:4].hex() == _SEL_INCREMENT_NONCE
    ):
        return inner_to, "proxy_exec"

    if operation == 1 and inner_to in _MULTISEND_WHITELIST:
        ex = _multisend_first_increment_nonce_exchange(inner_data)
        if ex is not None:
            return ex, "multisend"
    return None


# --------------------------------------------------------------------------
# Rule
# --------------------------------------------------------------------------
class NonceBumpRule(BaseRule):
    def __init__(self) -> None:
        if _NONCE_PARQUET.exists():
            df = pl.read_parquet(_NONCE_PARQUET).with_columns(
                pl.col("from_address").str.to_lowercase(),
                pl.col("contract_address").str.to_lowercase(),
            )
            self._nonce_df: pl.DataFrame | None = df
        else:
            self._nonce_df = None

    async def run(self, ctx: TxContext) -> NonceBumpResult | None:
        exchange = _FEE_MODULE_TO_EXCHANGE.get(ctx.tx.contract_address)
        if exchange is None:
            return None  # V2 or non-V1 fee module

        makers = sorted({
            ctx.decoded.taker_order.maker.lower(),
            *(o.maker.lower() for o in ctx.decoded.maker_orders),
        })
        participants: set[str] = set(makers)
        participants.add(ctx.decoded.taker_order.signer.lower())
        for o in ctx.decoded.maker_orders:
            participants.add(o.signer.lower())

        block = ctx.tx.block_number
        revert_fee = ctx.tx.gas_fee_wei

        # ------------------------------------------------------------------
        # Branch 1: naive direct EOA bump (parquet, 5-block window)
        # ------------------------------------------------------------------
        if self._nonce_df is not None:
            hits = self._nonce_df.filter(
                (pl.col("block_number") >= block - _LOOKBACK)
                & (pl.col("block_number") <= block)
                & (pl.col("contract_address") == exchange)
                & (pl.col("from_address").is_in(list(participants)))
            )
            if not hits.is_empty():
                row = hits.sort("block_number", descending=True).row(0, named=True)
                gas_ratio = row["gas_fee_wei"] / revert_fee if revert_fee else 0.0
                return NonceBumpResult(
                    attacker=row["from_address"],
                    causal_tx=row["transaction_hash"],
                    causal_block=row["block_number"],
                    exchange=exchange,
                    gas_ratio=round(gas_ratio, 3),
                    via="naive",
                )

        # ------------------------------------------------------------------
        # Branches 2/3: proxy_exec or multisend hidden bump.
        # No 5-block ceiling — wrapping incrementNonce inside execTransaction
        # is never legitimate liquidity management.
        # ------------------------------------------------------------------
        best: dict | None = None  # {block, hash, from, exchange, via, fee_wei}
        for proxy in makers:
            try:
                txs = await ctx.get_txlist(proxy, 0, block)
            except Exception:
                continue
            for t in txs:
                # Only incoming execTransaction calls (signer → proxy).
                if (t.get("to") or "").lower() != proxy:
                    continue
                inp = (t.get("input") or "").lower()
                if not inp.startswith("0x" + _SEL_EXEC_TRANSACTION):
                    continue
                if _SEL_INCREMENT_NONCE not in inp:
                    continue
                hit = _hidden_bump_classify(inp)
                if hit is None:
                    continue
                ex, via = hit
                if ex != exchange:
                    continue
                try:
                    blk = int(t["blockNumber"])
                except (KeyError, ValueError, TypeError):
                    continue
                if blk > block:
                    continue
                if best is None or blk > best["block"]:
                    try:
                        fee_wei = int(t.get("gasUsed") or 0) * int(t.get("gasPrice") or 0)
                    except (TypeError, ValueError):
                        fee_wei = 0
                    best = {
                        "block": blk,
                        "hash": t["hash"],
                        "from": (t.get("from") or "").lower(),
                        "exchange": ex,
                        "via": via,
                        "fee_wei": fee_wei,
                    }

        if best is None:
            return None

        blk = best["block"]
        h = best["hash"]
        sender = best["from"]
        ex = best["exchange"]
        via = best["via"]
        gas_ratio = best["fee_wei"] / revert_fee if revert_fee else 0.0

        return NonceBumpResult(
            attacker=sender,
            causal_tx=h,
            causal_block=blk,
            exchange=ex,
            gas_ratio=round(gas_ratio, 3),
            via=via,
        )
