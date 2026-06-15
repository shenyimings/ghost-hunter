from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, TypedDict

from eth_abi import decode as abi_decode
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Contract address → human-readable label
# ---------------------------------------------------------------------------

labelS: dict[str, str] = {
    "0xe111180000d2663c0091e4f400237545b87b996b": "ctf_v2",
    "0xe2222d279d744050d28e00520010520000310f59": "neg_risk_v2",
    "0xb768891e3130f6df18214ac804d4db76c2c37730": "neg_risk_fee_module_v1",
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0": "ctf_fee_module_v1",
    "0xc5d563a36ae78145c45a50134d48a1215220f80a": "neg_risk_v1",
    "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e": "ctf_v1",
}

_V2_CONTRACTS = frozenset(
    {
        "0xe111180000d2663c0091e4f400237545b87b996b",
        "0xe2222d279d744050d28e00520010520000310f59",
    }
)


# ---------------------------------------------------------------------------
# Raw input (one row from a reverted-matchOrders parquet)
# ---------------------------------------------------------------------------


class RawTx(BaseModel):
    block_number: int
    contract_address: str
    transaction_hash: str
    block_timestamp: datetime
    transaction_index: int
    tx_input: str
    gas_used: int
    effective_gas_price: int  # wei/gas
    gas_fee_wei: int  # total gas cost in wei

    @field_validator("contract_address", "transaction_hash", mode="before")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()

    @field_validator("block_timestamp", mode="before")
    @classmethod
    def _coerce_ts(cls, v) -> datetime:
        # parquets may store timestamp as unix-seconds int (V1/nonce)
        # or as a pandas/polars datetime object (V2)
        if isinstance(v, (int, float)):
            return datetime.utcfromtimestamp(v)
        if isinstance(v, datetime):
            return v
        # polars Datetime → Python datetime is handled by pydantic automatically
        return v  # type: ignore[return-value]

    @field_validator("gas_fee_wei", mode="before")
    @classmethod
    def _coerce_wei(cls, v) -> int:
        # V2 parquets store this as Decimal(76,38)
        if isinstance(v, Decimal):
            return int(v)
        return int(v)

    # @property
    # def is_v2(self) -> bool:
    #     return self.contract_address in _V2_CONTRACTS

    @property
    def label(self) -> str:
        return labelS.get(self.contract_address, self.contract_address)

    @property
    def gas_fee_gwei(self) -> float:
        return self.gas_fee_wei / 1e9


# ---------------------------------------------------------------------------
# Decoded Order structs (V1 vs V2 differ in field set)
# ---------------------------------------------------------------------------


class OrderV1(BaseModel):
    """Polymarket CLOB V1 Order (pre-2026-04-28). Nonce-based uniqueness."""

    salt: int
    maker: str
    signer: str
    taker: str
    token_id: int
    maker_amount: int
    taker_amount: int
    expiration: int
    nonce: int
    fee_rate_bps: int
    side: int  # 0=BUY, 1=SELL
    signature_type: int  # 0=EOA, 1=POLY_PROXY, 2=POLY_GNOSIS_SAFE
    signature: bytes


class OrderV2(BaseModel):
    """Polymarket CLOB V2 Order (from 2026-04-28). Timestamp-based uniqueness."""

    salt: int
    maker: str
    signer: str
    token_id: int
    maker_amount: int
    taker_amount: int
    side: int
    signature_type: int
    timestamp: int  # ms
    metadata: bytes  # bytes32
    builder: bytes  # bytes32
    signature: bytes


# ---------------------------------------------------------------------------
# Decoded matchOrders calldata
# ---------------------------------------------------------------------------


def _buy_side_collateral(
    taker_side: int,
    taker_fill: int,
    maker_sides: list[int],
    maker_fills: list[int],
) -> int:

    if taker_side == 1 and all(s == 1 for s in maker_sides):
        return taker_fill
    usd = taker_fill if taker_side == 0 else 0
    usd += sum(f for s, f in zip(maker_sides, maker_fills) if s == 0)
    return usd


def _match_type(taker_side: int, maker_sides: list[int]) -> str:

    sides = {taker_side, *maker_sides}
    if sides == {0}:
        return "mint"
    if sides == {1}:
        return "merge"
    maker_set = set(maker_sides)
    if len(maker_set) == 1 and taker_side != next(iter(maker_set)):
        return "normal"
    return "mixed"


class DecodedMatchOrdersV1(BaseModel):
    taker_order: OrderV1
    maker_orders: list[OrderV1]
    taker_fill_amount: int
    taker_receive_amount: int
    maker_fill_amounts: list[int]
    taker_fee_amount: int
    maker_fee_amounts: list[int]

    @property
    def condition_id(self) -> str | None:
        return None  # V1 matchOrders has no conditionId param

    @property
    def affected_amount(self) -> int:
        return _buy_side_collateral(
            self.taker_order.side,
            self.taker_fill_amount,
            [o.side for o in self.maker_orders],
            self.maker_fill_amounts,
        )

    @property
    def match_type(self) -> str:
        """``mint`` / ``merge`` / ``normal`` / ``mixed`` — see ``_match_type``."""
        return _match_type(self.taker_order.side, [o.side for o in self.maker_orders])


class DecodedMatchOrdersV2(BaseModel):
    condition_id: str  # "0x<hex>" bytes32
    taker_order: OrderV2
    maker_orders: list[OrderV2]
    taker_fill_amount: int
    maker_fill_amounts: list[int]
    taker_fee_amount: int
    maker_fee_amounts: list[int]

    @property
    def affected_amount(self) -> int:
        """USDC (pUSD) collateral that would actually move — see ``DecodedMatchOrdersV1.affected_amount``."""
        return _buy_side_collateral(
            self.taker_order.side,
            self.taker_fill_amount,
            [o.side for o in self.maker_orders],
            self.maker_fill_amounts,
        )

    @property
    def match_type(self) -> str:
        """``mint`` / ``merge`` / ``normal`` / ``mixed`` — see ``_match_type``."""
        return _match_type(self.taker_order.side, [o.side for o in self.maker_orders])


# Union type used throughout the engine
DecodedMatchOrders = DecodedMatchOrdersV1 | DecodedMatchOrdersV2


@dataclass
class CallFrame:

    index: int  # position in execution order (0 = root call)
    call_type: str  # "CALL", "DELEGATECALL", "STATICCALL", "CREATE"
    call_from: str  # caller address, lower-cased
    call_to: str  # callee address, lower-cased
    selector: str  # 4-byte hex without 0x, e.g. "f23a6e61"; "" if no input
    error: str  # parity error string; "" if the call succeeded
    revert_reason: str  # decoded error name; "" if no error or unrecognised

    # --- rich fields (populated by simulate_execution, default-safe for tests) ---
    gas: int = 0  # gas limit allocated to this call
    gas_used: int = 0  # gas actually consumed
    value: int = 0  # ETH value transferred in this call (wei)
    input_data: str = ""  # full calldata hex with 0x prefix (selector + args)
    output_data: str = ""  # raw return/revert data hex with 0x prefix

    def transfer_from_args(self) -> tuple[str, str, int] | None:

        if self.selector != "23b872dd" or len(self.input_data) < 202:
            return None
        try:
            inp = self.input_data
            from_addr = "0x" + inp[34:74]
            to_addr = "0x" + inp[98:138]
            amount = int(inp[138:202], 16)
            return from_addr, to_addr, amount
        except (ValueError, IndexError):
            return None

    def safe_transfer_from_args(self) -> tuple[str, str, int, int] | None:

        if self.selector != "f242432a" or len(self.input_data) < 266:
            return None
        try:
            inp = self.input_data
            from_addr = "0x" + inp[34:74]
            to_addr = "0x" + inp[98:138]
            token_id = int(inp[138:202], 16)
            value = int(inp[202:266], 16)
            return from_addr, to_addr, token_id, value
        except (ValueError, IndexError):
            return None

    def on_erc1155_received_args(self) -> tuple[str, str, int, int] | None:
        if self.selector != "f23a6e61" or len(self.input_data) < 266:
            return None
        try:
            inp = self.input_data
            operator = "0x" + inp[34:74]
            from_addr = "0x" + inp[98:138]
            token_id = int(inp[138:202], 16)
            value = int(inp[202:266], 16)
            return operator, from_addr, token_id, value
        except (ValueError, IndexError):
            return None

    def failing_transfer_address(self) -> str | None:
        if not self.error:
            return None
        args = self.transfer_from_args() or self.safe_transfer_from_args()
        return args[0] if args else None

    def decoded_error_args(self) -> dict | None:
        if not self.output_data or self.output_data in ("", "0x"):
            return None
        if len(self.output_data) < 10:
            return None
        sel = self.output_data[2:10]
        raw_args = self.output_data[10:]
        if not raw_args:
            return None
        try:
            b = bytes.fromhex(raw_args)
            if sel == "e450d38c":  # ERC20InsufficientBalance(address,uint256,uint256)
                sender, balance, needed = abi_decode(
                    ["address", "uint256", "uint256"], b
                )
                return {"sender": sender.lower(), "balance": balance, "needed": needed}
            if sel == "fb8f41b2":  # ERC20InsufficientAllowance(address,uint256,uint256)
                spender, allowance, needed = abi_decode(
                    ["address", "uint256", "uint256"], b
                )
                return {
                    "spender": spender.lower(),
                    "allowance": allowance,
                    "needed": needed,
                }
            if (
                sel == "f4d678b8"
            ):  # ERC1155InsufficientBalance(address,uint256,uint256,uint256)
                sender, token_id, balance, needed = abi_decode(
                    ["address", "uint256", "uint256", "uint256"], b
                )
                return {
                    "sender": sender.lower(),
                    "token_id": token_id,
                    "balance": balance,
                    "needed": needed,
                }
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Rule interface
# ---------------------------------------------------------------------------


class RuleMeta(TypedDict):
    id: str
    priority: int  # lower = higher priority; 9999 = last resort
    description: str


class BaseRuleResult(BaseModel):
    """Base for all rule-specific result models.

    Subclass and add fields. The engine serialises this with model_dump()
    and stores it verbatim in Finding.rule_result.

    revert_reasons is populated by the engine after the rule matches, from
    the cached simulate_execution call (no extra RPC cost when the rule
    already called it).
    """

    revert_reasons: list[str] = Field(default_factory=list)


class BaseRule(ABC):
    """Abstract base for all rules.

    Every concrete rule must:
      - define a class-level ``meta: RuleMeta``
      - implement ``async def run(ctx) -> BaseRuleResult | None``

    Returning None means "this rule does not apply"; the engine tries the
    next rule in priority order.  Returning a BaseRuleResult subclass means
    "this rule matched; stop here."
    """

    meta: RuleMeta  # set at class level on each concrete rule

    @abstractmethod
    async def run(self, ctx: Any) -> BaseRuleResult | None: ...


# ---------------------------------------------------------------------------
# Engine output record
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """One output record per reverted matchOrders transaction."""

    # Serialize with short aliases (block_num, tx_hash) to keep JSONL compact.
    # Internal code always uses the full canonical names.
    model_config = ConfigDict(populate_by_name=True)

    # --- identity ---
    id: str  # "{block_number}-{label}-{transaction_hash_prefix}"
    block_number: int = Field(serialization_alias="block_num")
    label: str  # e.g. "ctf_v2"
    contract_address: str = Field(exclude=True)
    transaction_hash: str = Field(serialization_alias="tx_hash")

    # --- decoded from calldata ---
    # V2 carries conditionId at the top of matchOrders calldata. V1 doesn't —
    # so for V1 reverts we emit the taker order's CTF token_id instead. Exactly
    # one of these two is populated per finding.
    condition_id: str | None  # bytes32 hex (V2 only)
    token_id: str | None  # decimal CTF position id as string (V1 only)
    affected_amount: float  # raw 6-decimal USDC/pUSD
    # affected_amount_human: float   # / 1e6

    # --- from raw tx ---
    gas_fee_gwei: float
    timestamp: datetime

    # is_v2: bool

    # --- rule match ---
    matched_rule: str
    rule_result: dict[str, Any]

    @classmethod
    def build(
        cls,
        raw: RawTx,
        decoded: DecodedMatchOrders,
        rule: BaseRule,
        result: BaseRuleResult,
    ) -> Finding:
        amt = decoded.affected_amount
        return cls(
            id=f"{raw.block_number}-{raw.label}-{raw.transaction_hash[:12]}",
            block_number=raw.block_number,
            label=raw.label,
            contract_address=raw.contract_address,
            transaction_hash=raw.transaction_hash,
            condition_id=decoded.condition_id,
            token_id=(
                str(decoded.taker_order.token_id)
                if decoded.condition_id is None
                else None
            ),
            affected_amount=round(amt / 1e6, 6),
            # affected_amount=amt,
            # affected_amount_human=round(amt / 1e6, 6),
            gas_fee_gwei=round(raw.gas_fee_gwei, 3),
            timestamp=raw.block_timestamp,
            # is_v2=raw.is_v2,
            matched_rule=rule.meta["id"],
            rule_result=result.model_dump(),
        )
