# Only for test-use

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest
import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ghost_hunter.core.context import SharedCache, TxContext
from ghost_hunter.core.decoder import decode_match_orders
from ghost_hunter.core.models import RawTx
from ghost_hunter.rules.collateral_race import (
    _CTF,
    _SEL_ERC1155_BALANCE_OF,
    _SEL_ERC20_BALANCE_OF,
    _TOPIC_TRANSFER,
    _TOPIC_TRANSFER_SINGLE,
    _USDC_E,
    CollateralRaceResult,
    CollateralRaceRule,
)

_EXCHANGE_V1 = "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e"

REPO_ROOT = Path(__file__).parent.parent
PARQUET_V1_0 = REPO_ROOT / "parquets" / "v1" / "polymarket_ctf_exchange_v1_000000000000"

load_dotenv(REPO_ROOT / ".env")
_ALCHEMY_KEY = os.getenv("ALCHEMY_API_KEY")
_NETWORK_AVAILABLE = pytest.mark.skipif(
    not _ALCHEMY_KEY, reason="ALCHEMY_API_KEY not set"
)
_P_V1_AVAILABLE = pytest.mark.skipif(
    not PARQUET_V1_0.exists(), reason="parquets/v1/000 not present"
)


# ---------------------------------------------------------------------------
# Offline helpers
# ---------------------------------------------------------------------------


def _error_string_output(msg: str) -> str:
    b = msg.encode()
    body = b.hex().ljust(((len(b) + 31) // 32) * 64, "0")
    return "0x" + "08c379a0" + f"{32:064x}" + f"{len(b):064x}" + body


def _frame(*, selector: str, input_data: str, output: str, error: str = "Reverted") -> dict:
    return {
        "type": "call",
        "action": {
            "callType": "call",
            "from": "0xaaa",
            "to": "0xbbb",
            "input": input_data,
            "gas": "0x0",
            "value": "0x0",
        },
        "result": {"gasUsed": "0x0", "output": output},
        "subtraces": 0,
        "traceAddress": [],
        "error": error,
    }


def _transfer_from_input(from_addr: str, amount: int) -> str:
    return (
        "0x23b872dd"
        + from_addr.removeprefix("0x").lower().zfill(64)  # from
        + "00" * 32  # to
        + f"{amount:064x}"  # amount
    )


def _safe_transfer_from_input(from_addr: str, token_id: int, value: int) -> str:
    return (
        "0xf242432a"
        + from_addr.removeprefix("0x").lower().zfill(64)  # from
        + "00" * 32  # to
        + f"{token_id:064x}"  # id
        + f"{value:064x}"  # value
    )


def _pad(addr: str) -> str:
    return "0x" + addr.removeprefix("0x").lower().zfill(64)


def _balance_key(token: str, sel: str, owner: str, block: int, token_id: int | None = None) -> str:
    data = "0x" + sel + owner.removeprefix("0x").lower().zfill(64)
    if token_id is not None:
        data += f"{token_id:064x}"
    return repr(("eth_call", token.lower(), data.lower(), block))


def _logs_key(token: str, topics: list, block: int) -> str:
    return repr(("get_logs", token.lower(), block, block, tuple(topics)))


def _usdc_settlement_log(from_addr: str, to_addr: str, amount: int, tx_index: int) -> dict:
    return {
        "topics": [_TOPIC_TRANSFER, _pad(from_addr), _pad(to_addr)],
        "data": "0x" + f"{amount:064x}",
        "transactionIndex": hex(tx_index),
    }


def _ctf_settlement_log(
    from_addr: str, to_addr: str, token_id: int, value: int, tx_index: int
) -> dict:
    return {
        "topics": [_TOPIC_TRANSFER_SINGLE, _pad("0x0"), _pad(from_addr), _pad(to_addr)],
        "data": "0x" + f"{token_id:064x}" + f"{value:064x}",
        "transactionIndex": hex(tx_index),
    }


_THIS_TX_INDEX = 100


def _load_v1_decoded():
    row = pq.read_table(PARQUET_V1_0).slice(0, 1).to_pylist()[0]
    raw = RawTx(**{**row, "transaction_index": _THIS_TX_INDEX})
    decoded = decode_match_orders(raw.tx_input, raw.contract_address)
    assert decoded is not None
    return raw, decoded


def _make_ctx(raw, decoded, *, sim_calls, extra_cache):
    cache = SharedCache()
    cache._data[repr(("trace_replay", raw.transaction_hash.lower()))] = sim_calls
    cache._data.update(extra_cache)

    class _MockEtherscan:
        async def get_txlist(self, *a, **kw):
            return []

        async def get_logs(self, *a, **kw):
            return []

    class _MockAlchemy:
        async def trace_replay_transaction(self, tx_hash):
            return sim_calls

    class _MockClients:
        alchemy = _MockAlchemy()
        etherscan = _MockEtherscan()

    return TxContext(raw, decoded, _MockClients(), cache)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Offline tests
# ---------------------------------------------------------------------------


@_P_V1_AVAILABLE
def test_usdc_leg_confirmed_by_concurrent_settlements():
    raw, decoded = _load_v1_decoded()
    taker = decoded.taker_order.maker
    block = raw.block_number
    commitment = 9_220_000  # ~9.22 USDC.e
    balance = 23_760_000    # fundable alone, not across the concurrent batch

    sim_calls = [
        _frame(selector="", input_data="0x", output=_error_string_output("TRANSFER_FROM_FAILED")),
        _frame(
            selector="23b872dd",
            input_data=_transfer_from_input(taker, commitment),
            output=_error_string_output("ERC20: transfer amount exceeds balance"),
        ),
    ]
    logs = [
        _usdc_settlement_log(taker, _EXCHANGE_V1, 9_200_000, tx_index=50),
        _usdc_settlement_log(taker, _EXCHANGE_V1, 9_200_000, tx_index=60),
    ]
    topics = [_TOPIC_TRANSFER, _pad(taker)]
    extra = {
        _balance_key(_USDC_E, _SEL_ERC20_BALANCE_OF, taker, block - 1): "0x"
        + f"{balance:064x}",
        _logs_key(_USDC_E, topics, block): logs,
    }
    ctx = _make_ctx(raw, decoded, sim_calls=sim_calls, extra_cache=extra)
    result = asyncio.run(CollateralRaceRule().run(ctx))

    assert isinstance(result, CollateralRaceResult)
    assert result.leg == "usdc"
    assert result.role == "taker"
    assert result.attacker == taker
    assert result.this_commitment == commitment
    assert result.balance_before == balance
    assert result.race_confirmed is True
    assert result.concurrent_settlements == 2
    assert result.total_drained == 18_400_000


@_P_V1_AVAILABLE
def test_ctf_leg_confirmed_filters_token_and_target():
    raw, decoded = _load_v1_decoded()
    taker = decoded.taker_order.maker
    block = raw.block_number
    token_id = 0x8d6b84fa9d0d0170
    commitment = 20_000_000  # 20 CTF shares
    balance = 97_800_000     # fundable alone, not across 5 concurrent

    sim_calls = [
        _frame(selector="", input_data="0x", output=_error_string_output("SafeMath: subtraction overflow")),
        _frame(
            selector="f242432a",
            input_data=_safe_transfer_from_input(taker, token_id, commitment),
            output=_error_string_output("SafeMath: subtraction overflow"),
        ),
    ]
    logs = [
        _ctf_settlement_log(taker, _EXCHANGE_V1, token_id, 20_000_000, tx_index=50),
        _ctf_settlement_log(taker, _EXCHANGE_V1, token_id, 20_000_000, tx_index=60),
        _ctf_settlement_log(taker, _EXCHANGE_V1, token_id, 20_000_000, tx_index=70),
        _ctf_settlement_log(taker, _EXCHANGE_V1, token_id, 19_000_000, tx_index=80),
        _ctf_settlement_log(taker, _EXCHANGE_V1, 0xdeadbeef, 50_000_000, tx_index=55),
        _ctf_settlement_log(taker, "0x000000000000000000000000000000000000dEaD", token_id, 50_000_000, tx_index=65),
        _ctf_settlement_log(taker, _EXCHANGE_V1, token_id, 20_000_000, tx_index=120),
    ]
    topics = [_TOPIC_TRANSFER_SINGLE, None, _pad(taker)]
    extra = {
        _balance_key(_CTF, _SEL_ERC1155_BALANCE_OF, taker, block - 1, token_id): "0x"
        + f"{balance:064x}",
        _logs_key(_CTF, topics, block): logs,
    }
    ctx = _make_ctx(raw, decoded, sim_calls=sim_calls, extra_cache=extra)
    result = asyncio.run(CollateralRaceRule().run(ctx))

    assert isinstance(result, CollateralRaceResult)
    assert result.leg == "ctf"
    assert result.race_confirmed is True
    assert result.concurrent_settlements == 4       # only same-tokenId, to exchange, before this tx
    assert result.total_drained == 79_000_000       # 20+20+20+19
    assert result.balance_before - result.total_drained < result.this_commitment


@_P_V1_AVAILABLE
def test_defers_when_drain_is_not_settlement():
    raw, decoded = _load_v1_decoded()
    taker = decoded.taker_order.maker
    block = raw.block_number
    commitment = 9_220_000
    balance = 23_760_000

    sim_calls = [
        _frame(
            selector="23b872dd",
            input_data=_transfer_from_input(taker, commitment),
            output=_error_string_output("ERC20: transfer amount exceeds balance"),
        ),
    ]
    logs = [
        _usdc_settlement_log(taker, "0x000000000000000000000000000000000000dEaD", 20_000_000, tx_index=50),
        _usdc_settlement_log(taker, _EXCHANGE_V1, 10_000, tx_index=60),
    ]
    topics = [_TOPIC_TRANSFER, _pad(taker)]
    extra = {
        _balance_key(_USDC_E, _SEL_ERC20_BALANCE_OF, taker, block - 1): "0x"
        + f"{balance:064x}",
        _logs_key(_USDC_E, topics, block): logs,
    }
    ctx = _make_ctx(raw, decoded, sim_calls=sim_calls, extra_cache=extra)
    result = asyncio.run(CollateralRaceRule().run(ctx))
    assert result is None


@_P_V1_AVAILABLE
def test_falls_back_when_logs_unavailable():
    raw, decoded = _load_v1_decoded()
    taker = decoded.taker_order.maker
    block = raw.block_number
    commitment = 9_220_000
    balance = 23_760_000

    sim_calls = [
        _frame(
            selector="23b872dd",
            input_data=_transfer_from_input(taker, commitment),
            output=_error_string_output("ERC20: transfer amount exceeds balance"),
        ),
    ]
    extra = {
        _balance_key(_USDC_E, _SEL_ERC20_BALANCE_OF, taker, block - 1): "0x"
        + f"{balance:064x}"
    }
    ctx = _make_ctx(raw, decoded, sim_calls=sim_calls, extra_cache=extra)
    result = asyncio.run(CollateralRaceRule().run(ctx))

    assert isinstance(result, CollateralRaceResult)
    assert result.race_confirmed is False
    assert result.concurrent_settlements == 0
    assert result.total_drained == 0


@_P_V1_AVAILABLE
def test_defers_when_underfunded_from_start():
    raw, decoded = _load_v1_decoded()
    taker = decoded.taker_order.maker
    block = raw.block_number
    commitment = 9_220_000
    balance = 900_000  # 0.9 USDC.e — never enough for even one order

    sim_calls = [
        _frame(
            selector="23b872dd",
            input_data=_transfer_from_input(taker, commitment),
            output=_error_string_output("ERC20: transfer amount exceeds balance"),
        ),
    ]
    extra = {
        _balance_key(_USDC_E, _SEL_ERC20_BALANCE_OF, taker, block - 1): "0x"
        + f"{balance:064x}"
    }
    ctx = _make_ctx(raw, decoded, sim_calls=sim_calls, extra_cache=extra)
    result = asyncio.run(CollateralRaceRule().run(ctx))
    assert result is None


@_P_V1_AVAILABLE
def test_defers_on_allowance_failure():
    raw, decoded = _load_v1_decoded()
    taker = decoded.taker_order.maker
    sim_calls = [
        _frame(
            selector="23b872dd",
            input_data=_transfer_from_input(taker, 9_220_000),
            output=_error_string_output("ERC20: transfer amount exceeds allowance"),
        ),
    ]
    ctx = _make_ctx(raw, decoded, sim_calls=sim_calls, extra_cache={})
    result = asyncio.run(CollateralRaceRule().run(ctx))
    assert result is None


# ---------------------------------------------------------------------------
# Network tests — real reverted matchOrders
# ---------------------------------------------------------------------------


def _build_raw_from_chain(tx_hash: str) -> RawTx:
    rpc = f"https://polygon-mainnet.g.alchemy.com/v2/{_ALCHEMY_KEY}"

    def _call(method, params):
        r = requests.post(
            rpc, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).json()
        return r["result"]

    tx = _call("eth_getTransactionByHash", [tx_hash])
    rx = _call("eth_getTransactionReceipt", [tx_hash])
    blk = _call("eth_getBlockByNumber", [tx["blockNumber"], False])

    gas_used = int(rx["gasUsed"], 16)
    eff_price = int(rx["effectiveGasPrice"], 16)
    return RawTx(
        block_number=int(tx["blockNumber"], 16),
        contract_address=tx["to"],
        transaction_hash=tx_hash,
        block_timestamp=int(blk["timestamp"], 16),
        transaction_index=int(tx["transactionIndex"], 16),
        tx_input=tx["input"],
        gas_used=gas_used,
        effective_gas_price=eff_price,
        gas_fee_wei=gas_used * eff_price,
    )


_REAL_RACES = [
    (
        "0x69fd5dd989f7f262667af5028abb7276bd6c764913f61719c91ff2d68da246d3",
        "ctf",
        "block 84713991: taker 0x6022473d, 5 concurrent SELL orders totalling 99.0 CTF vs 97.80 held",
    ),
    (
        "0x640cc54e633c48d119d96abde11f4ae86aeb3dd09d94cbb92d4c146aeff7596b",
        "usdc",
        "block 84713791: taker 0x850a2701, 7 concurrent BUY orders @ ~9.22 vs 23.76 held",
    ),
]


@_NETWORK_AVAILABLE
@pytest.mark.parametrize("tx_hash,expected_leg,description", _REAL_RACES)
def test_real_revert_hits_collateral_race(tx_hash, expected_leg, description):
    from ghost_hunter.core.client import Clients

    async def _run():
        raw = _build_raw_from_chain(tx_hash)
        decoded = decode_match_orders(raw.tx_input, raw.contract_address)
        assert decoded is not None, f"decode failed: {description}"
        async with Clients() as clients:
            ctx = TxContext(raw, decoded, clients, SharedCache())
            return await CollateralRaceRule().run(ctx)

    result = asyncio.run(_run())
    assert isinstance(result, CollateralRaceResult), f"no match: {description}"
    assert result.leg == expected_leg, f"wrong leg for {description}"
    assert result.balance_before >= result.this_commitment
    assert result.race_confirmed is True, f"left inequality unconfirmed: {description}"
    assert result.concurrent_settlements > 0
    assert result.balance_before - result.total_drained < result.this_commitment
