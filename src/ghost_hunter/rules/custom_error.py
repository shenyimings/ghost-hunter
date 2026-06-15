
from __future__ import annotations

from ghost_hunter.core.context import TxContext
from ghost_hunter.core.models import BaseRule, BaseRuleResult

_DELEGATED_SUBSTRINGS = (
    "transferfromfailed",
    "transfer_from_failed",
    "insufficientallowance",
    "insufficientbalance",
    "exceeds allowance",
    "exceeds balance",
    "feeexceedsmaxrate",
    "subtraction overflow",
)


def _is_delegated(reason: str) -> bool:
    r = reason.lower()
    return any(s in r for s in _DELEGATED_SUBSTRINGS)


class CustomErrorResult(BaseRuleResult):
    revert_reason: str  
    failing_selector: str  
    failing_call_from: str  
    failing_call_to: str  


class CustomErrorRule(BaseRule):
    async def run(self, ctx: TxContext) -> CustomErrorResult | None:
        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)

        for f in frames:
            if not f.error:
                continue
            reason = f.revert_reason
            if not reason or _is_delegated(reason):
                continue
            return CustomErrorResult(
                revert_reason=reason,
                failing_selector=f.selector,
                failing_call_from=f.call_from,
                failing_call_to=f.call_to,
            )

        return None
