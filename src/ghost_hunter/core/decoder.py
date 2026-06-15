"""
ABI-decode matchOrders() calldata for V1 and V2 contracts.

Uses eth_abi.decode directly with hard-coded type strings — no web3.py
contract objects required.  This is ~7x faster than decode_function_input()
because eth_abi's codec is compiled while web3.py's ABI parser is pure Python.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from eth_abi import decode as abi_decode

from .models import (
    DecodedMatchOrders,
    DecodedMatchOrdersV1,
    DecodedMatchOrdersV2,
    OrderV1,
    OrderV2,
)

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parents[3] / "config.yml"

# ---------------------------------------------------------------------------
# Pre-compiled eth_abi type strings (avoids web3.py overhead)
# ---------------------------------------------------------------------------

# V2 Order struct: salt, maker, signer, tokenId, makerAmount, takerAmount,
#                  side, signatureType, timestamp, metadata, builder, signature
_ORDER_V2 = (
    "(uint256,address,address,uint256,uint256,uint256,uint8,uint8,uint256,bytes32,bytes32,bytes)"
)
# matchOrders V2 params: conditionId, takerOrder, makerOrders,
#                        takerFillAmount, makerFillAmounts,
#                        takerFeeAmount, makerFeeAmounts
_V2_TYPES = [
    "bytes32", _ORDER_V2, _ORDER_V2 + "[]",
    "uint256", "uint256[]", "uint256", "uint256[]",
]

# V1 Order struct: salt, maker, signer, taker, tokenId, makerAmount,
#                  takerAmount, expiration, nonce, feeRateBps,
#                  side, signatureType, signature
_ORDER_V1 = (
    "(uint256,address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,uint8,uint8,bytes)"
)
# matchOrders V1 params: takerOrder, makerOrders, takerFillAmount,
#                        takerReceiveAmount, makerFillAmounts,
#                        takerFeeAmount, makerFeeAmounts
_V1_TYPES = [
    _ORDER_V1, _ORDER_V1 + "[]",
    "uint256", "uint256", "uint256[]", "uint256", "uint256[]",
]


# ---------------------------------------------------------------------------
# Revert-output decoder
# ---------------------------------------------------------------------------

def _load_revert_selector_map() -> dict[str, str]:
    base: dict[str, str] = {}
    try:
        with open(_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        base = {str(k): str(v) for k, v in cfg.get("revert_errors", {}).items()}
    except Exception as exc:
        logger.warning("Could not load revert_errors from config.yml: %s", exc)

    # Token-contract errors (pUSD / USDC.e / CTF) not present in config.yml
    base.setdefault("13be252b", "InsufficientAllowance()")
    base.setdefault("fb8f41b2", "ERC20InsufficientAllowance(address,uint256,uint256)")
    base.setdefault("e450d38c", "ERC20InsufficientBalance(address,uint256,uint256)")
    base.setdefault("f4d678b8", "ERC1155InsufficientBalance(address,uint256,uint256,uint256)")
    return base


_REVERT_SELECTOR_MAP: dict[str, str] = _load_revert_selector_map()


def decode_revert_output(hex_data: str) -> str:
    if not hex_data or hex_data == "0x":
        return ""
    b = bytes.fromhex(hex_data.removeprefix("0x"))
    if len(b) < 4:
        return f"0x{b.hex()}"
    sel = b[:4].hex()
    if sel == "08c379a0":
        try:
            (msg,) = abi_decode(["string"], b[4:])
            return f"Error({msg!r})"
        except Exception:
            pass
    if sel == "4e487b71":
        try:
            (code,) = abi_decode(["uint256"], b[4:])
            return f"Panic(0x{code:x})"
        except Exception:
            pass
    if sel in _REVERT_SELECTOR_MAP:
        return _REVERT_SELECTOR_MAP[sel]
    return f"CustomError(0x{sel})"

# 4-byte selectors (no 0x prefix, lower-case)
_SEL_V1 = "2287e350"   # matchOrders() on neg_risk_fee_module / ctf_exchange_fee_module
_SEL_V2 = "3c2b4399"   # matchOrders() on ctf_exchange_v2 / neg_risk_ctf_exchange_v2


def _to_order_v1(t: tuple) -> OrderV1:
    """Map an eth_abi-decoded V1 Order tuple to OrderV1."""
    return OrderV1(
        salt=t[0],
        maker=t[1].lower(),
        signer=t[2].lower(),
        taker=t[3].lower(),
        token_id=t[4],
        maker_amount=t[5],
        taker_amount=t[6],
        expiration=t[7],
        nonce=t[8],
        fee_rate_bps=t[9],
        side=t[10],
        signature_type=t[11],
        signature=bytes(t[12]),
    )


def _to_order_v2(t: tuple) -> OrderV2:
    return OrderV2(
        salt=t[0],
        maker=t[1].lower(),
        signer=t[2].lower(),
        token_id=t[3],
        maker_amount=t[4],
        taker_amount=t[5],
        side=t[6],
        signature_type=t[7],
        timestamp=t[8],
        metadata=bytes(t[9]),
        builder=bytes(t[10]),
        signature=bytes(t[11]),
    )


def decode_match_orders(tx_input: str, contract_address: str) -> DecodedMatchOrders | None:
    sel = tx_input[2:10].lower() if tx_input.startswith("0x") else tx_input[:8].lower()
    raw = bytes.fromhex(tx_input[10:] if tx_input.startswith("0x") else tx_input[8:])

    if sel == _SEL_V2:
        try:
            condition_id_b, taker_t, maker_ts, taker_fill, maker_fills, taker_fee, maker_fees = (
                abi_decode(_V2_TYPES, raw)
            )
            return DecodedMatchOrdersV2(
                condition_id="0x" + bytes(condition_id_b).hex(),
                taker_order=_to_order_v2(taker_t),
                maker_orders=[_to_order_v2(t) for t in maker_ts],
                taker_fill_amount=taker_fill,
                maker_fill_amounts=list(maker_fills),
                taker_fee_amount=taker_fee,
                maker_fee_amounts=list(maker_fees),
            )
        except Exception as exc:
            logger.debug("V2 decode failed for %s: %s", tx_input[:18], exc)
            return None

    if sel == _SEL_V1:
        try:
            taker_t, maker_ts, taker_fill, taker_receive, maker_fills, taker_fee, maker_fees = (
                abi_decode(_V1_TYPES, raw)
            )
            return DecodedMatchOrdersV1(
                taker_order=_to_order_v1(taker_t),
                maker_orders=[_to_order_v1(t) for t in maker_ts],
                taker_fill_amount=taker_fill,
                taker_receive_amount=taker_receive,
                maker_fill_amounts=list(maker_fills),
                taker_fee_amount=taker_fee,
                maker_fee_amounts=list(maker_fees),
            )
        except Exception as exc:
            logger.debug("V1 decode failed for %s: %s", tx_input[:18], exc)
            return None

    logger.debug("Unrecognised selector %s on %s", sel, contract_address)
    return None
