from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult


class UnclassifiedResult(BaseRuleResult):
    note: str = "no rule matched"
    num_makers: int
    taker_maker: str  
    taker_signer: str  
    cause_addr: str = ""  


class UnclassifiedRule(BaseRule):
    async def run(self, ctx: TxContext) -> UnclassifiedResult | None:
        cause_addr = ""
        try:
            frames = await ctx.simulate_execution(ctx.tx.transaction_hash)
            for f in frames:
                if not f.error:
                    continue
                addr = f.failing_transfer_address()
                if addr:
                    cause_addr = addr
                    break
                if f.selector == "f23a6e61":
                    cause_addr = f.call_to
                    break
        except Exception:
            pass  

        return UnclassifiedResult(
            num_makers=len(ctx.decoded.maker_orders),
            taker_maker=ctx.decoded.taker_order.maker,
            taker_signer=ctx.decoded.taker_order.signer,
            cause_addr=cause_addr,
        )
