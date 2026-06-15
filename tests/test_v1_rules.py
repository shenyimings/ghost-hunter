from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from dotenv import load_dotenv
from eth_abi import encode as abi_encode

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ghost_hunter.core.context import SharedCache, TxContext
from ghost_hunter.core.decoder import decode_match_orders
from ghost_hunter.core.models import RawTx

sys.path.insert(0, str(Path(__file__).parent))

from test_rules import (  # noqa: E402
    _TOPIC_APPROVAL,
    _fake_frame,
    _make_ctx,
    _pad_addr,
)

REPO_ROOT = Path(__file__).parent.parent
RULES_DIR = REPO_ROOT / "src" / "ghost_hunter" / "rules"

V1_PARQUET_0 = REPO_ROOT / "parquets" / "v1" / "polymarket_ctf_exchange_v1_000000000000"
V1_PARQUET_31 = REPO_ROOT / "parquets" / "v1" / "polymarket_ctf_exchange_v1_000000000031"
NONCE_PARQUET = (
    REPO_ROOT / "parquets" / "nonce" / "polymarket_ctf_exchange_v1_increment_nonce"
)

_V1_P0_AVAILABLE = pytest.mark.skipif(
    not V1_PARQUET_0.exists(), reason="parquets/v1/000 not present"
)
_V1_P31_AVAILABLE = pytest.mark.skipif(
    not V1_PARQUET_31.exists(), reason="parquets/v1/031 not present"
)
_NONCE_AVAILABLE = pytest.mark.skipif(
    not NONCE_PARQUET.exists(), reason="parquets/nonce/... not present"
)

load_dotenv(REPO_ROOT / ".env")
_NETWORK_AVAILABLE = pytest.mark.skipif(
    not os.getenv("ALCHEMY_API_KEY"), reason="ALCHEMY_API_KEY not set"
)

# V1 constants
_USDC_E = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"
_TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_NEG_RISK_EXCHANGE_V1 = "0xc5d563a36ae78145c45a50134d48a1215220f80a"
_NEG_RISK_FEE_MODULE_V1 = "0xb768891e3130f6df18214ac804d4db76c2c37730"
_CTF_FEE_MODULE_V1 = "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0"


# Known target tx hashes for network integration tests.
_TX_NONCE_BUMP = "0xf040155a8eeb43fbc3169bbd67d861d234cbded2178473fbc330b2b2a2537e6e"
_TX_ALLOWANCE = "0xeec50c2e88606c243adba4d8c11537807dab799f4c528517c4fa3fe05ccb3516"
_TX_BALANCE_DRAIN = "0x2fd6306a62f3c9323bfeb12104b9e3c3814157c02383b23311b4e4210ea45f55"


def _find_row(parquet_path: Path, tx_hash: str):
    table = pq.read_table(parquet_path)
    hashes = table.column("transaction_hash").to_pylist()
    if tx_hash not in hashes:
        pytest.skip(f"{tx_hash} not in {parquet_path.name}")
    idx = hashes.index(tx_hash)
    row = table.slice(idx, 1).to_pylist()[0]
    raw = RawTx(**row)
    decoded = decode_match_orders(raw.tx_input, raw.contract_address)
    assert decoded is not None, f"V1 decode failed for {tx_hash}"
    return raw, decoded


def _error_string_output(msg: str) -> str:
    body = abi_encode(["string"], [msg])
    return "0x08c379a0" + body.hex()


# ---------------------------------------------------------------------------
# nonce_bump rule
# ---------------------------------------------------------------------------


@_V1_P0_AVAILABLE
@_NONCE_AVAILABLE
def test_nonce_bump_matches_known_v1_tx():
    from ghost_hunter.rules.nonce_bump import NonceBumpResult, NonceBumpRule

    raw, decoded = _find_row(V1_PARQUET_0, _TX_NONCE_BUMP)

    ctx = _make_ctx(raw, decoded)
    result = asyncio.run(NonceBumpRule().run(ctx))

    assert isinstance(result, NonceBumpResult)
    assert result.attacker == "0x064a890200bbd7d98d05ed4323e0c9b2a6a72f50"
    assert result.exchange == _NEG_RISK_EXCHANGE_V1
    assert result.causal_block <= raw.block_number
    assert result.causal_block >= raw.block_number - 5
    assert result.gas_ratio > 0


@_V1_P0_AVAILABLE
@_NONCE_AVAILABLE
def test_nonce_bump_no_match_when_not_in_window():
    from ghost_hunter.rules.nonce_bump import NonceBumpRule

    raw, decoded = _find_row(V1_PARQUET_0, _TX_ALLOWANCE)
    ctx = _make_ctx(raw, decoded)
    result = asyncio.run(NonceBumpRule().run(ctx))
    assert result is None


@_V1_P0_AVAILABLE
@_NONCE_AVAILABLE
def test_nonce_bump_makes_zero_rpc_calls():
    from ghost_hunter.rules.nonce_bump import NonceBumpRule
    from test_rules import _MockAlchemy, _MockClients

    raw, decoded = _find_row(V1_PARQUET_0, _TX_NONCE_BUMP)
    mock_alchemy = _MockAlchemy()
    cache = SharedCache()
    ctx = TxContext(raw, decoded, _MockClients(alchemy=mock_alchemy), cache)  # type: ignore[arg-type]

    result = asyncio.run(NonceBumpRule().run(ctx))
    assert result is not None
    assert mock_alchemy.sim_call_count == 0


# ---------------------------------------------------------------------------
# custom_error rule
# ---------------------------------------------------------------------------


@_V1_P0_AVAILABLE
def test_custom_error_matches_invalid_nonce():
    from ghost_hunter.rules.custom_error import CustomErrorResult, CustomErrorRule

    raw, decoded = _find_row(V1_PARQUET_0, _TX_NONCE_BUMP)
    sim_calls = [_fake_frame(error="Reverted", output="0x756688fe")]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(CustomErrorRule().run(ctx))
    assert isinstance(result, CustomErrorResult)
    assert result.revert_reason == "InvalidNonce()"


@_V1_P0_AVAILABLE
def test_custom_error_skips_transfer_from_failed():
    from ghost_hunter.rules.custom_error import CustomErrorRule

    raw, decoded = _find_row(V1_PARQUET_0, _TX_ALLOWANCE)
    sim_calls = [_fake_frame(error="Reverted", output="0x7939f424")]  # TransferFromFailed
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(CustomErrorRule().run(ctx))
    assert result is None


@_V1_P0_AVAILABLE
def test_custom_error_skips_insufficient_allowance():
    from ghost_hunter.rules.custom_error import CustomErrorRule

    raw, decoded = _find_row(V1_PARQUET_0, _TX_ALLOWANCE)
    sim_calls = [_fake_frame(error="Reverted", output="0x13be252b")]  # InsufficientAllowance
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(CustomErrorRule().run(ctx))
    assert result is None


# ---------------------------------------------------------------------------
# approve_revoke on V1 (USDC.e)
# ---------------------------------------------------------------------------


@_V1_P0_AVAILABLE
def test_approve_revoke_v1_usdce():
    from ghost_hunter.rules.approve_revoke import (
        _LOOKBACK,
        ApproveRevokeResult,
        ApproveRevokeRule,
    )

    raw, decoded = _find_row(V1_PARQUET_0, _TX_ALLOWANCE)
    failing_addr = decoded.taker_order.maker
    block = raw.block_number

    transfer_from_input = (
        "0x23b872dd"
        + failing_addr.removeprefix("0x").lower().zfill(64)
        + "00" * 32
        + "00" * 32
    )
    sim_calls = [
        _fake_frame(
            error="Reverted",
            output=_error_string_output("ERC20: transfer amount exceeds allowance"),
        )
    ]
    inner = _fake_frame(
        selector="23b872dd",
        error="Reverted",
        output=_error_string_output("ERC20: transfer amount exceeds allowance"),
    )
    inner["action"]["input"] = transfer_from_input
    sim_calls.append(inner)

    fake_log = {
        "address": _USDC_E,
        "topics": [
            _TOPIC_APPROVAL,
            _pad_addr(failing_addr),
            _pad_addr(_NEG_RISK_EXCHANGE_V1),
        ],
        "data": "0x" + "0" * 64,
        "blockNumber": hex(block - 1),
        "transactionHash": "0x55e4652e955596015056d38ab956b71901f9e7b93242db44727339ad793d05d2",
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }
    log_key = repr(
        (
            "etherscan_logs",
            _USDC_E.lower(),
            block - _LOOKBACK,
            block,
            _TOPIC_APPROVAL.lower(),
            _pad_addr(failing_addr).lower(),
            _pad_addr(_NEG_RISK_EXCHANGE_V1).lower(),
        )
    )
    ctx = _make_ctx(
        raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: [fake_log]}
    )
    result = asyncio.run(ApproveRevokeRule().run(ctx))
    assert isinstance(result, ApproveRevokeResult)
    assert result.attacker == failing_addr
    assert result.is_revoke is True
    assert result.approve_amount == 0
    assert result.causal_tx.lower() == fake_log["transactionHash"]


# ---------------------------------------------------------------------------
# balance_drain on V1 (USDC.e)
# ---------------------------------------------------------------------------


@_V1_P31_AVAILABLE
def test_balance_drain_v1_usdce():
    from ghost_hunter.rules.balance_drain import (
        _LOOKBACK,
        BalanceDrainResult,
        BalanceDrainRule,
    )

    raw, decoded = _find_row(V1_PARQUET_31, _TX_BALANCE_DRAIN)
    maker_addr = decoded.maker_orders[0].maker
    block = raw.block_number
    drained = 2_004_000_000  # ~2004 USDC.e in 6-decimals

    sim_calls = [_fake_frame(error="Reverted", output="0x7939f424")]
    fake_log = {
        "address": _USDC_E,
        "topics": [
            _TOPIC_TRANSFER,
            _pad_addr(maker_addr),
            _pad_addr("0xdeadbeef" + "00" * 16),
        ],
        "data": "0x" + f"{drained:064x}",
        "blockNumber": hex(block - 1),
        "transactionHash": "0xv1draintx0000000000000000000000000000000000000000000000000000000",
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }
    log_key = repr(
        ("etherscan_logs", _USDC_E, block - _LOOKBACK, block, _TOPIC_TRANSFER.lower(), "", "")
    )
    ctx = _make_ctx(
        raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: [fake_log]}
    )
    result = asyncio.run(BalanceDrainRule().run(ctx))

    assert isinstance(result, BalanceDrainResult)
    assert result.attacker == maker_addr
    assert result.drained_amount == drained


# ---------------------------------------------------------------------------
# Engine end-to-end: rule priority on V1 rows
# ---------------------------------------------------------------------------


@_V1_P0_AVAILABLE
@_NONCE_AVAILABLE
def test_engine_classifies_known_nonce_bump_as_nonce_bump():
    from ghost_hunter.core.engine import _load_rules

    raw, decoded = _find_row(V1_PARQUET_0, _TX_NONCE_BUMP)
    rules = _load_rules(RULES_DIR)
    ctx = _make_ctx(raw, decoded)

    async def _run():
        for rule in rules:
            try:
                result = await rule.run(ctx)
            except Exception:
                result = None
            if result is not None:
                return rule.meta["id"]
        return None

    assert asyncio.run(_run()) == "nonce_bump"
