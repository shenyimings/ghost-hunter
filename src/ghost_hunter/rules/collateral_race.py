# Only for test-use

from __future__ import annotations

from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult

# Collateral token addresses (Polygon mainnet, lower-case).
_PUSD = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"   # V2 collateral
_USDC_E = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"  # V1 collateral
# ConditionalTokens (ERC1155) — same contract for V1 and V2.
_CTF = "0x4d97dcd97ec945f40cf65f87097ace5ea0476045"

_V2_CONTRACTS = frozenset(
    {
        "0xe111180000d2663c0091e4f400237545b87b996b",
        "0xe2222d279d744050d28e00520010520000310f59",
    }
)


_SETTLEMENT_TARGETS = frozenset(
    {
        "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e",  # ctf_exchange V1
        "0xc5d563a36ae78145c45a50134d48a1215220f80a",  # neg_risk_ctf_exchange V1
        "0xe111180000d2663c0091e4f400237545b87b996b",  # ctf_v2
        "0xe2222d279d744050d28e00520010520000310f59",  # neg_risk_v2
    }
)

_SEL_TRANSFER_FROM = "23b872dd"   # ERC20 transferFrom — USDC/pUSD leg
_SEL_SAFE_TRANSFER = "f242432a"   # ERC1155 safeTransferFrom — CTF leg

_SEL_ERC20_BALANCE_OF = "70a08231"
_SEL_ERC1155_BALANCE_OF = "00fdd58e"

_TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_TOPIC_TRANSFER_SINGLE = (
    "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
)


def _is_amount_failure(reason: str) -> bool:
    r = reason.lower()
    if "allowance" in r:
        return False
    return (
        "exceeds balance" in r
        or "transfer_from_failed" in r
        or "transferfromfailed" in r
        or "insufficientbalance" in r
        or "subtraction overflow" in r
    )


def _pad(addr: str) -> str:
    return "0x" + addr.removeprefix("0x").lower().zfill(64)


def _block_num(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16 if value.startswith("0x") else 10)


class CollateralRaceResult(BaseRuleResult):
    leg: str                  # "usdc" (BUY) | "ctf" (SELL)
    attacker: str             # wallet that over-committed and lost the race
    role: str                 # "taker" | "maker" | "unknown"
    this_commitment: int      # collateral this single order required (raw 6-dec / shares)
    balance_before: int       # attacker's balance at block B-1 (raw 6-dec / shares)
    race_confirmed: bool      
    concurrent_settlements: int  # # of the wallet's settlements before this tx in block B
    total_drained: int        


class CollateralRaceRule(BaseRule):
    async def run(self, ctx: TxContext) -> CollateralRaceResult | None:
        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)

        failing = next(
            (
                f
                for f in frames
                if f.error
                and f.selector in (_SEL_TRANSFER_FROM, _SEL_SAFE_TRANSFER)
                and _is_amount_failure(f.revert_reason)
            ),
            None,
        )
        if failing is None:
            return None

        token_id: int | None = None
        if failing.selector == _SEL_TRANSFER_FROM:
            leg = "usdc"
            args = failing.transfer_from_args()
            if args is None:
                return None
            failing_from, _to, this_commitment = args
            token = _PUSD if ctx.tx.contract_address in _V2_CONTRACTS else _USDC_E
            data = "0x" + _SEL_ERC20_BALANCE_OF + _pad(failing_from)[2:]
        else:  
            leg = "ctf"
            args = failing.safe_transfer_from_args()
            if args is None:
                return None
            failing_from, _to, token_id, this_commitment = args
            token = _CTF
            data = (
                "0x"
                + _SEL_ERC1155_BALANCE_OF
                + _pad(failing_from)[2:]
                + f"{token_id:064x}"
            )


        raw = await ctx.eth_call(token, data, block=ctx.tx.block_number - 1)
        balance_before = int(raw, 16) if raw and raw != "0x" else 0
        if balance_before < this_commitment:
            return None  

        race_confirmed = False
        concurrent_settlements = 0
        total_drained = 0
        try:
            logs = await self._settlement_logs(ctx, leg, failing_from, token)
        except Exception:
            logs = None  

        if logs is not None:
            concurrent_settlements, total_drained = self._sum_settlements(
                logs, leg, ctx.tx.transaction_index, token_id
            )
            if balance_before - total_drained >= this_commitment:
                return None
            race_confirmed = True

        return CollateralRaceResult(
            leg=leg,
            attacker=failing_from,
            role=self._role(ctx, failing_from),
            this_commitment=this_commitment,
            balance_before=balance_before,
            race_confirmed=race_confirmed,
            concurrent_settlements=concurrent_settlements,
            total_drained=total_drained,
        )

    @staticmethod
    async def _settlement_logs(
        ctx: TxContext, leg: str, failing_from: str, token: str
    ) -> list[dict]:
        b = ctx.tx.block_number
        if leg == "usdc":
            topics: list[str | None] = [_TOPIC_TRANSFER, _pad(failing_from)]
        else:  
            topics = [_TOPIC_TRANSFER_SINGLE, None, _pad(failing_from)]
        return await ctx.get_logs(b, b, topics, address=token)

    @staticmethod
    def _sum_settlements(
        logs: list[dict], leg: str, this_tx_index: int, token_id: int | None
    ) -> tuple[int, int]:
        count = 0
        total = 0
        for lg in logs:
            if _block_num(lg.get("transactionIndex", "0x0")) >= this_tx_index:
                continue
            topics = lg.get("topics", [])
            if leg == "usdc":
                if len(topics) < 3:
                    continue
                to = "0x" + topics[2][-40:].lower()
                if to not in _SETTLEMENT_TARGETS:
                    continue
                total += int(lg["data"], 16)
            else:  
                if len(topics) < 4:
                    continue
                to = "0x" + topics[3][-40:].lower()
                if to not in _SETTLEMENT_TARGETS:
                    continue
                d = lg["data"][2:] if lg["data"].startswith("0x") else lg["data"]
                lid = int(d[:64], 16)
                if token_id is not None and lid != token_id:
                    continue
                total += int(d[64:128], 16)
            count += 1
        return count, total

    @staticmethod
    def _role(ctx: TxContext, addr: str) -> str:
        a = addr.lower()
        if a == ctx.decoded.taker_order.maker.lower():
            return "taker"
        if any(a == m.maker.lower() for m in ctx.decoded.maker_orders):
            return "maker"
        return "unknown"
