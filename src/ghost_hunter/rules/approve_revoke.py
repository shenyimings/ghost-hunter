from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult

# keccak256("Approval(address,address,uint256)")
_TOPIC_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

# Collateral token addresses (Polygon mainnet, lower-case)
_PUSD = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"  # V2
_USDC_E = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"  # V1

_V2_CONTRACTS = frozenset(
    {
        "0xe111180000d2663c0091e4f400237545b87b996b",
        "0xe2222d279d744050d28e00520010520000310f59",
    }
)


_V1_FEE_MODULE_TO_EXCHANGE: dict[str, str] = {
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0": "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e",
    "0xb768891e3130f6df18214ac804d4db76c2c37730": "0xc5d563a36ae78145c45a50134d48a1215220f80a",
}


def _spender_for(contract_address: str) -> str:
    """Address used as ``msg.sender`` of the failing transferFrom — the
    address the maker must have allowance for."""
    return _V1_FEE_MODULE_TO_EXCHANGE.get(contract_address, contract_address)


def _pad_topic(addr: str) -> str:
    return "0x" + addr.lower().removeprefix("0x").zfill(64)


_LOOKBACK = 5  # blocks before the revert


def _block_num(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16 if value.startswith("0x") else 10)


class ApproveRevokeResult(BaseRuleResult):
    attacker: str  # maker address that changed the approval
    causal_tx: str  # hash of the approve/revoke tx
    approve_amount: int  # 0 = full revoke
    is_revoke: bool
    causal_block: int


class ApproveRevokeRule(BaseRule):
    async def run(self, ctx: TxContext) -> ApproveRevokeResult | None:
        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)
        errored = [f for f in frames if f.error]

        def _is_allowance_failure(reason: str) -> bool:
            return "allowance" in reason.lower()

        failing_frame = next(
            (
                f
                for f in errored
                if f.selector == "23b872dd" and _is_allowance_failure(f.revert_reason)
            ),
            None,
        )
        if failing_frame is None and not any(
            _is_allowance_failure(f.revert_reason) for f in errored
        ):
            return None

        collateral = _PUSD if ctx.tx.contract_address in _V2_CONTRACTS else _USDC_E
        spender = _spender_for(ctx.tx.contract_address)
        spender_topic = _pad_topic(spender)

        failing_addr = (
            failing_frame.failing_transfer_address() if failing_frame else None
        )
        if failing_addr is not None:
            candidates: list[str] = [failing_addr]
        else:
            seen: set[str] = set()
            candidates = []
            for addr in [ctx.decoded.taker_order.maker] + [
                o.maker for o in ctx.decoded.maker_orders
            ]:
                if addr not in seen:
                    seen.add(addr)
                    candidates.append(addr)

        from_block = ctx.tx.block_number - _LOOKBACK
        to_block = ctx.tx.block_number

        for owner in candidates:
            owner_topic = _pad_topic(owner)
            logs = await ctx.get_logs_etherscan(
                collateral,
                from_block,
                to_block,
                _TOPIC_APPROVAL,
                topic1=owner_topic,
                topic2=spender_topic,
            )
            if not logs:
                continue
            logs_sorted = sorted(
                logs, key=lambda lg: _block_num(lg.get("blockNumber", 0)), reverse=True
            )
            log = logs_sorted[0]
            amount = int(log["data"], 16)
            return ApproveRevokeResult(
                attacker=owner,
                causal_tx=log["transactionHash"],
                approve_amount=amount,
                is_revoke=(amount == 0),
                causal_block=_block_num(log["blockNumber"]),
            )

        return None
