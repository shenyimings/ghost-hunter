from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult


class FeeExceedsMaxRateResult(BaseRuleResult):
    note: str = "FeeExceedsMaxRate"


class FeeExceedsMaxRateRule(BaseRule):
    async def run(self, ctx: TxContext) -> FeeExceedsMaxRateResult | None:
        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)
        errored = [f for f in frames if f.error]

        if any("FeeExceedsMaxRate" in f.revert_reason for f in errored):
            return FeeExceedsMaxRateResult()
        return None
