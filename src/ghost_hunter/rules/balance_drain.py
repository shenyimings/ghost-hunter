from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult

# keccak256("Transfer(address,address,uint256)")
_TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

_PUSD = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"
_USDC_E = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"

_V2_CONTRACTS = frozenset(
    {
        "0xe111180000d2663c0091e4f400237545b87b996b",
        "0xe2222d279d744050d28e00520010520000310f59",
    }
)

# V1 Fee Module → underlying Exchange that pulls collateral via transferFrom.
_V1_FEE_MODULE_TO_EXCHANGE: dict[str, str] = {
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0": "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e",
    "0xb768891e3130f6df18214ac804d4db76c2c37730": "0xc5d563a36ae78145c45a50134d48a1215220f80a",
}

# Transfers TO these official contracts are normal market operations (splitPosition,
# settlement, position wrapping, fee collection) — never a drain.
_OFFICIAL_TO_ADDRS = frozenset(
    {
        "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",  # ConditionalTokens (CTF) – splitPosition
        "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e",  # CTF Exchange V1 – settlement
        "0xc5d563a36ae78145c45a50134d48a1215220f80a",  # NegRisk CTF Exchange V1 – settlement
        "0xd91e80cf2e7be2e162c6513ced06f1dd0da35296",  # NegRiskAdapter – position wrapping
        "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0",  # CTF Exchange Fee Module
        "0xe111180000d2663c0091e4f400237545b87b996b",  # CTF Exchange V2 – settlement
        "0xe2222d279d744050d28e00520010520000310f59",  # NegRisk CTF Exchange V2 – settlement
    }
)

_LOOKBACK = 5  # blocks before the revert


def _parse_block_number(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16 if value.startswith("0x") else 10)


class BalanceDrainResult(BaseRuleResult):
    attacker: str  # maker address that drained collateral
    causal_tx: (
        str | None
    )  
    drained_amount: int  # raw 6-decimal units; 0 when causal_tx is None
    causal_block: int | None  # None when causal_tx is None
    gas_ratio: float  # drain_gas_fee / revert_gas_fee; 0 if unavailable


class BalanceDrainRule(BaseRule):
    async def run(self, ctx: TxContext) -> BalanceDrainResult | None:
        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)
        errored = [f for f in frames if f.error]


        def _is_balance_failure(reason: str) -> bool:
            r = reason.lower()
            return (
                "transferfromfailed" in r
                or "insufficientbalance" in r
                or "exceeds balance" in r
            )

        if not any(_is_balance_failure(f.revert_reason) for f in errored):
            return None

        collateral = _PUSD if ctx.tx.contract_address in _V2_CONTRACTS else _USDC_E
        exchange = _V1_FEE_MODULE_TO_EXCHANGE.get(
            ctx.tx.contract_address, ctx.tx.contract_address
        )


        failing_frame = next(
            (f for f in errored if f.selector == "23b872dd"),
            None,
        )
        failing_addr = (
            failing_frame.failing_transfer_address() if failing_frame else None
        )

        if failing_addr is not None:
            # Narrow the log scan to just the pinpointed maker.
            search_addresses = {failing_addr}
        else:
            # Fallback: check all makers + taker (should be rare).
            search_addresses = {o.maker for o in ctx.decoded.maker_orders}
            search_addresses.add(ctx.decoded.taker_order.maker)

        # Fetch collateral Transfer logs in the lookback window (pre-revert only).
        logs = await ctx.get_logs_etherscan(
            collateral,
            ctx.tx.block_number - _LOOKBACK,
            ctx.tx.block_number,
            _TOPIC_TRANSFER,
        )


        best: tuple[int, str, int, str] | None = None  # (block, from, amount, tx)
        for log in logs:
            from_addr = "0x" + log["topics"][1][-40:].lower()
            if from_addr not in search_addresses:
                continue
            to_addr = "0x" + log["topics"][2][-40:].lower()
            if to_addr in _OFFICIAL_TO_ADDRS:
                continue
            block_num = _parse_block_number(log["blockNumber"])
            if best is None or block_num >= best[0]:
                best = (
                    block_num,
                    from_addr,
                    int(log["data"], 16),
                    log["transactionHash"],
                )

        if best is not None:
            block_num, from_addr, amount, drain_tx = best

            gas_ratio = 0.0
            if ctx.tx.gas_fee_wei:
                txs = await ctx.get_txlist(from_addr, block_num, block_num)
                drain_tx_lc = drain_tx.lower()
                tx = next(
                    (t for t in txs if t.get("hash", "").lower() == drain_tx_lc), None
                )
                if tx:
                    drain_fee = int(tx.get("gasUsed", "0")) * int(
                        tx.get("gasPrice", "0")
                    )
                    gas_ratio = drain_fee / ctx.tx.gas_fee_wei

            gas_ratio = round(gas_ratio, 3)
            if gas_ratio <= 1.0:
                return None

            return BalanceDrainResult(
                attacker=from_addr,
                causal_tx=drain_tx,
                drained_amount=amount,
                causal_block=block_num,
                gas_ratio=gas_ratio,
            )


        # attacker = failing_addr or (
        #     next(iter(search_addresses)) if len(search_addresses) == 1 else None
        # )
        # if attacker is None:
        #     return None

        # data = "0x70a08231" + attacker[2:].zfill(64)
        # raw = await ctx.eth_call(collateral, data, block=ctx.tx.block_number - 1)
        # balance_before = int(raw, 16) if raw and raw != "0x" else 0

        # if failing_frame is not None:
        #     args = failing_frame.transfer_from_args()
        #     this_commitment = args[2] if args else 0
        # else:
        #     this_commitment = 1  # unknown — proceed when balance is 0

        # if balance_before >= this_commitment:
        #     # Still fundable at B-1 → not a pre-block drain; defer to other rules.
        #     return None

        # return BalanceDrainResult(
        #     attacker=attacker,
        #     causal_tx=None,
        #     drained_amount=0,
        #     causal_block=None,
        #     gas_ratio=0.0,
        # )
