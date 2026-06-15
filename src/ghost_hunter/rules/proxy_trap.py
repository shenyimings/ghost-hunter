from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult

# onERC1155Received(address,address,uint256,uint256,bytes) → 0xf23a6e61
_SEL_ON_ERC1155_RECV = "f23a6e61"


class ProxyTrapResult(BaseRuleResult):
    proxy_trap_side: str  # "taker" | "maker" | "unknown"
    trapped_address: str  # wallet whose receiver callback reverts
    attacker: str  # signer who controls the trapped wallet


class ProxyTrapRule(BaseRule):
    async def run(self, ctx: TxContext) -> ProxyTrapResult | None:
        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)
        errored = [f for f in frames if f.error]

        def _is_trap_error(err: str) -> bool:
            e = err.lower()
            return (
                "revert" in e        # "Reverted" / "execution reverted"
                or "out of gas" in e
                or "out of stack" in e
                or "stack overflow" in e
            )

        trap_frame = next(
            (
                f
                for f in errored
                if f.selector == _SEL_ON_ERC1155_RECV and _is_trap_error(f.error)
            ),
            None,
        )
        if trap_frame is None:
            return None

        trapped_addr = trap_frame.call_to
        taker_maker = ctx.decoded.taker_order.maker
        maker_signer = {o.maker: o.signer for o in ctx.decoded.maker_orders}

        if trapped_addr == taker_maker:
            return ProxyTrapResult(
                proxy_trap_side="taker",
                trapped_address=trapped_addr,
                attacker=ctx.decoded.taker_order.signer,
            )
        if trapped_addr in maker_signer:
            return ProxyTrapResult(
                proxy_trap_side="maker",
                trapped_address=trapped_addr,
                attacker=maker_signer[trapped_addr],
            )
        return ProxyTrapResult(
            proxy_trap_side="unknown",
            trapped_address=trapped_addr,
            attacker=trapped_addr,
        )
