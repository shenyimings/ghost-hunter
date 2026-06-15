from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ghost_hunter.core.context import SharedCache, TxContext
from ghost_hunter.core.decoder import decode_match_orders
from ghost_hunter.core.models import RawTx

REPO_ROOT = Path(__file__).parent.parent
RULES_DIR = REPO_ROOT / "src" / "ghost_hunter" / "rules"
PARQUET_0 = (
    REPO_ROOT / "parquets" / "v2-test" / "polymarket_ctf_exchange_v2_000000000000"
)
PARQUET_17 = (
    REPO_ROOT / "parquets" / "v2-test" / "polymarket_ctf_exchange_v2_000000000017"
)
PARQUET_V2_2 = REPO_ROOT / "parquets" / "v2" / "polymarket_ctf_exchange_v2_000000000002"
PARQUET_V1_0 = REPO_ROOT / "parquets" / "v1" / "polymarket_ctf_exchange_v1_000000000000"

_P0_AVAILABLE = pytest.mark.skipif(
    not PARQUET_0.exists(), reason="parquets/v2-test/000 not present"
)
_P17_AVAILABLE = pytest.mark.skipif(
    not PARQUET_17.exists(), reason="parquets/v2-test/017 not present"
)
load_dotenv(Path(__file__).parent.parent / ".env")
_NETWORK_AVAILABLE = pytest.mark.skipif(
    not os.getenv("ALCHEMY_API_KEY"), reason="ALCHEMY_API_KEY not set"
)

_PUSD = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"
_TOPIC_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
_TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_SEL_ON_ERC1155_RECV = "f23a6e61"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_row(parquet_path: Path, idx: int = 0) -> tuple[RawTx, object]:
    row = pq.read_table(parquet_path).slice(idx, 1).to_pylist()[0]
    raw = RawTx(**row)
    decoded = decode_match_orders(raw.tx_input, raw.contract_address)
    assert decoded is not None, f"decode failed for row {idx} of {parquet_path.name}"
    return raw, decoded


def _pad_addr(addr: str) -> str:
    return "0x" + addr.lower().removeprefix("0x").zfill(64)


class _MockAlchemy:

    def __init__(self, sim_result: list[dict] | None = None):
        self._sim_result = sim_result or []
        self.sim_call_count = 0

    async def trace_replay_transaction(self, tx_hash: str) -> list[dict]:
        self.sim_call_count += 1
        return self._sim_result

    async def eth_get_transaction_receipt(self, tx_hash: str) -> dict | None:
        return None


class _MockEtherscan:
    async def get_txlist(self, *a, **kw) -> list[dict]:
        return []

    async def get_logs(self, *a, **kw) -> list[dict]:
        return []


@pytest.fixture
def all_rules_enabled(monkeypatch):
    from ghost_hunter.core import engine as _engine

    original = _engine._load_rule_configs

    def _patched(*args, **kwargs):
        cfgs = original(*args, **kwargs)
        return {k: {**v, "enabled": True} for k, v in cfgs.items()}

    monkeypatch.setattr(_engine, "_load_rule_configs", _patched)


class _MockClients:
    def __init__(self, alchemy: _MockAlchemy | None = None):
        self.alchemy = alchemy or _MockAlchemy()
        self.etherscan = _MockEtherscan()


def _make_ctx(
    raw: RawTx,
    decoded,
    *,
    sim_raw_calls: list[dict] | None = None,
    extra_cache: dict | None = None,
) -> TxContext:
    cache = SharedCache()

    if sim_raw_calls is not None:
        key = repr(("trace_replay", raw.transaction_hash.lower()))
        cache._data[key] = sim_raw_calls

    if extra_cache:
        cache._data.update(extra_cache)

    return TxContext(raw, decoded, _MockClients(), cache)  # type: ignore[arg-type]


def _fake_frame(
    *,
    frm: str = "0xaaa",
    to: str = "0xbbb",
    selector: str = "",
    error: str = "",
    output: str = "0x",
    call_type: str = "call",
) -> dict:
    inp = ("0x" + selector + "00" * 60) if selector else "0x"
    trace: dict = {
        "type": "call",
        "action": {
            "callType": call_type,
            "from": frm,
            "to": to,
            "input": inp,
            "gas": "0x0",
            "value": "0x0",
        },
        "result": {
            "gasUsed": "0x0",
            "output": output if error else (output if output != "0x" else "0x1"),
        },
        "subtraces": 0,
        "traceAddress": [],
    }
    if error:
        trace["error"] = error
    return trace


# ---------------------------------------------------------------------------
# proxy_trap
# ---------------------------------------------------------------------------


@_P17_AVAILABLE
def test_proxy_trap_taker_side():
    from ghost_hunter.rules.proxy_trap import ProxyTrapResult, ProxyTrapRule

    raw, decoded = _load_row(PARQUET_17)
    taker_maker = decoded.taker_order.maker

    sim_calls = [
        _fake_frame(
            error="Reverted", output="0x7939f424"
        ),  # root: TransferFromFailed
        _fake_frame(selector=_SEL_ON_ERC1155_RECV, to=taker_maker, error="Out of gas"),
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(ProxyTrapRule().run(ctx))

    assert isinstance(result, ProxyTrapResult)
    assert result.proxy_trap_side == "taker"
    assert result.trapped_address == taker_maker
    assert result.attacker == decoded.taker_order.signer


@_P17_AVAILABLE
def test_proxy_trap_maker_side():
    from ghost_hunter.rules.proxy_trap import ProxyTrapResult, ProxyTrapRule

    raw, decoded = _load_row(PARQUET_17)
    maker_addr = decoded.maker_orders[0].maker
    maker_signer = decoded.maker_orders[0].signer

    sim_calls = [
        _fake_frame(error="Reverted", output="0x7939f424"),
        _fake_frame(selector=_SEL_ON_ERC1155_RECV, to=maker_addr, error="Out of gas"),
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(ProxyTrapRule().run(ctx))

    assert isinstance(result, ProxyTrapResult)
    assert result.proxy_trap_side == "maker"
    assert result.trapped_address == maker_addr
    assert result.attacker == maker_signer


@_P17_AVAILABLE
def test_proxy_trap_no_match_no_oog():
    from ghost_hunter.rules.proxy_trap import ProxyTrapRule

    raw, decoded = _load_row(PARQUET_17)
    sim_calls = [
        _fake_frame(error="Reverted", output="0x7939f424"),
        _fake_frame(
            selector="23b872dd", error="Reverted", output="0x13be252b"
        ),
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(ProxyTrapRule().run(ctx))
    assert result is None


@_P17_AVAILABLE
def test_proxy_trap_stack_overflow_variant():
    from ghost_hunter.rules.proxy_trap import ProxyTrapResult, ProxyTrapRule

    raw, decoded = _load_row(PARQUET_17)
    taker_maker = decoded.taker_order.maker

    sim_calls = [
        _fake_frame(error="Reverted", output="0x7939f424"),
        _fake_frame(
            selector=_SEL_ON_ERC1155_RECV, to=taker_maker, error="Out of stack"
        ),
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(ProxyTrapRule().run(ctx))
    assert isinstance(result, ProxyTrapResult)
    assert result.proxy_trap_side == "taker"


# ---------------------------------------------------------------------------
# approve_revoke
# ---------------------------------------------------------------------------


def _approve_input(spender: str, amount: int) -> str:
    return (
        "0x095ea7b3"
        + spender.removeprefix("0x").lower().zfill(64)
        + f"{amount:064x}"
    )


def _transfer_from_frame(from_addr: str, revert_output: str) -> dict:
    inp = (
        "0x23b872dd"
        + from_addr.removeprefix("0x").lower().zfill(64)
        + "00" * 32  # to
        + "00" * 32  # amount
    )
    return {
        "type": "call",
        "action": {
            "callType": "call",
            "from": "0xaaa",
            "to": "0xbbb",
            "input": inp,
            "gas": "0x0",
            "value": "0x0",
        },
        "result": {"gasUsed": "0x0", "output": revert_output},
        "subtraces": 0,
        "traceAddress": [],
        "error": "Reverted",
    }


def _approval_log(owner: str, spender: str, amount: int, block: int, tx_hash: str) -> dict:
    return {
        "address": _PUSD,
        "topics": [_TOPIC_APPROVAL, _pad_addr(owner), _pad_addr(spender)],
        "data": "0x" + f"{amount:064x}",
        "blockNumber": hex(block),
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }


def _logs_cache_key(token: str, frm: int, to: int, topic1: str, topic2: str) -> str:
    return repr(
        (
            "etherscan_logs",
            token.lower(),
            frm,
            to,
            _TOPIC_APPROVAL.lower(),
            topic1.lower(),
            topic2.lower(),
        )
    )


@_P17_AVAILABLE
def test_approve_revoke_matches_revoke():
    from ghost_hunter.rules.approve_revoke import (
        _LOOKBACK,
        ApproveRevokeResult,
        ApproveRevokeRule,
    )

    raw, decoded = _load_row(PARQUET_17)
    maker_addr = decoded.maker_orders[0].maker
    exchange = raw.contract_address
    block = raw.block_number

    sim_calls = [
        _fake_frame(error="Reverted", output="0x7939f424"),  # TransferFromFailed root
        _transfer_from_frame(maker_addr, "0x13be252b"),  # InsufficientAllowance inner
    ]

    log = _approval_log(
        maker_addr,
        exchange,
        0,
        block - 5,
        "0xcausal0000000000000000000000000000000000000000000000000000000000",
    )
    log_key = _logs_cache_key(
        _PUSD,
        block - _LOOKBACK,
        block,
        _pad_addr(maker_addr),
        _pad_addr(exchange),
    )
    ctx = _make_ctx(
        raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: [log]}
    )
    result = asyncio.run(ApproveRevokeRule().run(ctx))

    assert isinstance(result, ApproveRevokeResult)
    assert result.attacker == maker_addr
    assert result.is_revoke is True
    assert result.approve_amount == 0


@_P17_AVAILABLE
def test_approve_revoke_non_zero_amount():
    from ghost_hunter.rules.approve_revoke import (
        _LOOKBACK,
        ApproveRevokeResult,
        ApproveRevokeRule,
    )

    raw, decoded = _load_row(PARQUET_17)
    maker_addr = decoded.maker_orders[0].maker
    exchange = raw.contract_address
    block = raw.block_number
    amount = 1000 * 10**6

    sim_calls = [
        _fake_frame(error="Reverted", output="0x13be252b"),
        _transfer_from_frame(maker_addr, "0x13be252b"),
    ]
    log = _approval_log(
        maker_addr,
        exchange,
        amount,
        block - 3,
        "0xcausal1111111111111111111111111111111111111111111111111111111111",
    )
    log_key = _logs_cache_key(
        _PUSD,
        block - _LOOKBACK,
        block,
        _pad_addr(maker_addr),
        _pad_addr(exchange),
    )
    ctx = _make_ctx(
        raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: [log]}
    )
    result = asyncio.run(ApproveRevokeRule().run(ctx))

    assert isinstance(result, ApproveRevokeResult)
    assert result.is_revoke is False
    assert result.approve_amount == amount


@_P17_AVAILABLE
def test_approve_revoke_no_allowance_failure():
    from ghost_hunter.rules.approve_revoke import ApproveRevokeRule

    raw, decoded = _load_row(PARQUET_17)
    sim_calls = [_fake_frame(error="Reverted", output="0x7939f424")]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(ApproveRevokeRule().run(ctx))
    assert result is None


@_P17_AVAILABLE
def test_approve_revoke_no_approval_log():
    from ghost_hunter.rules.approve_revoke import _LOOKBACK, ApproveRevokeRule

    raw, decoded = _load_row(PARQUET_17)
    maker_addr = decoded.maker_orders[0].maker
    exchange = raw.contract_address
    block = raw.block_number

    sim_calls = [
        _fake_frame(error="Reverted", output="0x13be252b"),
        _transfer_from_frame(maker_addr, "0x13be252b"),
    ]
    log_key = _logs_cache_key(
        _PUSD,
        block - _LOOKBACK,
        block,
        _pad_addr(maker_addr),
        _pad_addr(exchange),
    )
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: []})
    result = asyncio.run(ApproveRevokeRule().run(ctx))
    assert result is None


# ---------------------------------------------------------------------------
# balance_drain
# ---------------------------------------------------------------------------


@_P17_AVAILABLE
def test_balance_drain_matches():
    """TransferFromFailed + Transfer-out from maker → balance_drain."""
    from ghost_hunter.rules.balance_drain import (
        _LOOKBACK,
        _TOPIC_TRANSFER,
        BalanceDrainResult,
        BalanceDrainRule,
    )

    raw, decoded = _load_row(PARQUET_17)
    maker_addr = decoded.maker_orders[0].maker
    block = raw.block_number
    drain_amount = 5000 * 10**6

    sim_calls = [
        _fake_frame(
            error="Reverted", output="0x7939f424"
        ),  # TransferFromFailed
    ]

    fake_log = {
        "address": _PUSD,
        "topics": [
            _TOPIC_TRANSFER,
            _pad_addr(maker_addr),
            _pad_addr("0xdead1234" + "00" * 12),
        ],
        "data": "0x" + f"{drain_amount:064x}",
        "blockNumber": hex(block - 3),
        "transactionHash": "0xdrain000000000000000000000000000000000000000000000000000000000000",
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }
    log_key = repr(("etherscan_logs", _PUSD, block - _LOOKBACK, block, _TOPIC_TRANSFER.lower(), "", ""))
    # no txlist match → gas_ratio stays 0
    ctx = _make_ctx(
        raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: [fake_log]}
    )
    result = asyncio.run(BalanceDrainRule().run(ctx))

    assert isinstance(result, BalanceDrainResult)
    assert result.attacker == maker_addr
    assert result.drained_amount == drain_amount
    assert result.causal_block == block - 3


@_P17_AVAILABLE
def test_balance_drain_ignores_transfer_to_exchange():
    """A Transfer TO the exchange (normal settlement) is not flagged as drain."""
    from ghost_hunter.rules.balance_drain import (
        _LOOKBACK,
        _TOPIC_TRANSFER,
        BalanceDrainRule,
    )

    raw, decoded = _load_row(PARQUET_17)
    maker_addr = decoded.maker_orders[0].maker
    exchange = raw.contract_address
    block = raw.block_number

    sim_calls = [
        _fake_frame(error="Reverted", output="0x7939f424"),
    ]

    # This transfer goes TO the exchange — not a drain
    fake_log = {
        "address": _PUSD,
        "topics": [_TOPIC_TRANSFER, _pad_addr(maker_addr), _pad_addr(exchange)],
        "data": "0x" + f"{1000 * 10**6:064x}",
        "blockNumber": hex(block - 1),
        "transactionHash": "0xnotadrain000000000000000000000000000000000000000000000000000000",
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }
    log_key = repr(("etherscan_logs", _PUSD, block - _LOOKBACK, block, _TOPIC_TRANSFER.lower(), "", ""))
    ctx = _make_ctx(
        raw, decoded, sim_raw_calls=sim_calls, extra_cache={log_key: [fake_log]}
    )
    result = asyncio.run(BalanceDrainRule().run(ctx))
    assert result is None


@_P17_AVAILABLE
def test_balance_drain_no_transfer_from_failed():
    """Root revert is not TransferFromFailed → balance_drain returns None."""
    from ghost_hunter.rules.balance_drain import BalanceDrainRule

    raw, decoded = _load_row(PARQUET_17)
    sim_calls = [
        _fake_frame(
            error="Reverted", output="0x3c97aa59"
        ),  # FeeExceedsMaxRate
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(BalanceDrainRule().run(ctx))
    assert result is None


# ---------------------------------------------------------------------------
# fee_exceeds_max_rate
# ---------------------------------------------------------------------------


@_P0_AVAILABLE
def test_fee_exceeds_max_rate_matches():
    from ghost_hunter.rules.fee_exceeds_max_rate import (
        FeeExceedsMaxRateResult,
        FeeExceedsMaxRateRule,
    )

    raw, decoded = _load_row(PARQUET_0)
    sim_calls = [
        _fake_frame(
            error="Reverted", output="0x3c97aa59"
        ),  # FeeExceedsMaxRate
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(FeeExceedsMaxRateRule().run(ctx))

    assert isinstance(result, FeeExceedsMaxRateResult)
    assert "FeeExceedsMaxRate" in result.note


@_P0_AVAILABLE
def test_fee_exceeds_max_rate_no_match():
    from ghost_hunter.rules.fee_exceeds_max_rate import FeeExceedsMaxRateRule

    raw, decoded = _load_row(PARQUET_0)
    sim_calls = [
        _fake_frame(
            error="Reverted", output="0x7939f424"
        ),  # TransferFromFailed
    ]
    ctx = _make_ctx(raw, decoded, sim_raw_calls=sim_calls)
    result = asyncio.run(FeeExceedsMaxRateRule().run(ctx))
    assert result is None


# ---------------------------------------------------------------------------
# Priority ordering — rule loading
# ---------------------------------------------------------------------------


def test_rule_priority_order(all_rules_enabled):
    """Rules are loaded in ascending priority (fee_exceeds_max_rate first, unclassified last)."""
    from ghost_hunter.core.engine import _load_rules

    rules = _load_rules(RULES_DIR)
    ids = [r.meta["id"] for r in rules]
    priorities = [r.meta["priority"] for r in rules]

    assert priorities == sorted(priorities), "rules must be sorted by priority"
    assert ids[0] == "nonce_bump", "nonce_bump (parquet-only, zero-RPC) must be first"
    assert ids[-1] == "unclassified", "unclassified fallback must be last"

    # fee_exceeds_max_rate should come after the three attack rules
    fee_idx = ids.index("fee_exceeds_max_rate")
    for attack_id in ("proxy_trap", "approve_revoke", "balance_drain"):
        assert ids.index(attack_id) > fee_idx, (
            f"{attack_id} must have higher priority number than fee_exceeds_max_rate"
        )
    # custom_error short-circuits the dynamic collateral-detection rules,
    # but proxy_trap should still run first (its outer revert is TransferFromFailed).
    ce_idx = ids.index("custom_error")
    assert ids.index("proxy_trap") < ce_idx, "proxy_trap must run BEFORE custom_error"
    for attack_id in ("approve_revoke", "balance_drain"):
        assert ids.index(attack_id) > ce_idx, (
            f"{attack_id} must run AFTER custom_error"
        )


# ---------------------------------------------------------------------------
# Network integration tests: known tx_hashes
# ---------------------------------------------------------------------------


_KNOWN_CLASSIFICATIONS = [
    (
        "0xf09ea8cdf37d6f2fae0489cde3e6270ca15660fe8528f51505101e31c237a423",
        "fee_exceeds_max_rate",
        "parquet 0: benign FeeExceedsMaxRate",
    ),
    (
        "0xb52e35fd590a5c3d304214539bd652a183c93dc27ec8f881601d6a3a0881052b",
        "proxy_trap",
        "parquet 17: proxy_trap — onERC1155Received burns all gas",
    ),
    (
        "0x2e5dadb94bf2c2ea4f2458e05c2a1b46711590800fd303494462e3e3a12ba367",
        "approve_revoke",
        "parquet 17: approve_revoke — InsufficientAllowance after approval change",
    ),
    (
        "0xeec50c2e88606c243adba4d8c11537807dab799f4c528517c4fa3fe05ccb3516",
        "approve_revoke",
        "V1 parquet 0: approve(NegRisk,0) by 0x5d7a...0e09 one block before revert",
    ),
    (
        "0xf040155a8eeb43fbc3169bbd67d861d234cbded2178473fbc330b2b2a2537e6e",
        "nonce_bump",
        "V1 parquet 0: incrementNonce by 0x064a...f50 within 5-block window",
    ),
]


@_NETWORK_AVAILABLE
@pytest.mark.parametrize("tx_hash,expected_rule,description", _KNOWN_CLASSIFICATIONS)
def test_known_tx_classification(tx_hash: str, expected_rule: str, description: str, all_rules_enabled):
    from ghost_hunter.core.client import Clients
    from ghost_hunter.core.engine import _load_rules

    async def _run():
        rules = _load_rules(RULES_DIR)
        async with Clients() as clients:
            # Find the parquet row for this tx
            for parquet in (PARQUET_0, PARQUET_17, PARQUET_V2_2, PARQUET_V1_0):
                if not parquet.exists():
                    continue
                rows = pq.read_table(parquet).to_pylist()
                row = next((r for r in rows if r["transaction_hash"] == tx_hash), None)
                if row:
                    raw = RawTx(**row)
                    decoded = decode_match_orders(raw.tx_input, raw.contract_address)
                    if decoded is None:
                        return None
                    cache = SharedCache()
                    ctx = TxContext(raw, decoded, clients, cache)
                    for rule in rules:
                        result = await rule.run(ctx)
                        if result is not None:
                            return rule.meta["id"]
            return None

    matched_rule = asyncio.run(_run())
    assert matched_rule == expected_rule, (
        f"{description}: expected rule={expected_rule!r}, got={matched_rule!r}"
    )


# ---------------------------------------------------------------------------
# Network bulk test: 1000 rows per parquet
# ---------------------------------------------------------------------------


@_NETWORK_AVAILABLE
@_P0_AVAILABLE
def test_bulk_parquet_0_mostly_fee_exceeds_max_rate(tmp_path, all_rules_enabled):
    _run_bulk(
        PARQUET_0, tmp_path, expected_dominant="fee_exceeds_max_rate", min_fraction=0.5
    )


@_NETWORK_AVAILABLE
@_P17_AVAILABLE
def test_bulk_parquet_17_mostly_proxy_trap_or_approve_revoke(tmp_path, all_rules_enabled):
    from ghost_hunter.core.engine import Engine

    table = pq.read_table(PARQUET_17).slice(0, 50)
    small_dir = tmp_path / "p17"
    small_dir.mkdir()
    pq.write_table(table, small_dir / "sample.parquet")

    output = tmp_path / "findings17.jsonl"
    engine = Engine(parquet_root=small_dir, output_path=output, rules_dir=RULES_DIR)
    total = asyncio.run(engine.run())

    assert total > 0
    output_files = sorted(tmp_path.glob("findings*.jsonl"))
    lines = "".join(f.read_text() for f in output_files).strip().splitlines()
    counts: dict[str, int] = {}
    for line in lines:
        rule = json.loads(line)["matched_rule"]
        counts[rule] = counts.get(rule, 0) + 1

    attack_count = counts.get("proxy_trap", 0) + counts.get("approve_revoke", 0)
    fraction = attack_count / total
    assert fraction >= 0.5, (
        f"Expected ≥50% proxy_trap/approve_revoke in parquet 17, "
        f"got {fraction:.1%}. Breakdown: {counts}"
    )


def _run_bulk(
    parquet: Path, tmp_path: Path, expected_dominant: str, min_fraction: float
):
    from ghost_hunter.core.engine import Engine

    table = pq.read_table(parquet).slice(0, 50)
    small_dir = tmp_path / "p"
    small_dir.mkdir()
    pq.write_table(table, small_dir / "sample.parquet")

    output = tmp_path / "findings.jsonl"
    engine = Engine(parquet_root=small_dir, output_path=output, rules_dir=RULES_DIR)
    total = asyncio.run(engine.run())

    assert total > 0
    output_files = sorted(tmp_path.glob("findings*.jsonl"))
    lines = "".join(f.read_text() for f in output_files).strip().splitlines()
    counts: dict[str, int] = {}
    for line in lines:
        rule = json.loads(line)["matched_rule"]
        counts[rule] = counts.get(rule, 0) + 1

    dominant_count = counts.get(expected_dominant, 0)
    fraction = dominant_count / total
    assert fraction >= min_fraction, (
        f"Expected ≥{min_fraction:.0%} {expected_dominant!r}, "
        f"got {fraction:.1%}. Breakdown: {counts}"
    )
