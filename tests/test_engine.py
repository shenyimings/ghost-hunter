from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import pyarrow.parquet as pq
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ghost_hunter.core.decoder import decode_match_orders, decode_revert_output
from ghost_hunter.core.engine import Engine, ScanState, _discover_parquets, _load_rules
from ghost_hunter.core.models import CallFrame, Finding, RawTx, labelS


REPO_ROOT = Path(__file__).parent.parent
RULES_DIR = REPO_ROOT / "src" / "ghost_hunter" / "rules"
PARQUET_V2_DIR = REPO_ROOT / "parquets" / "v2"

_FIRST_PARQUET = PARQUET_V2_DIR / "polymarket_ctf_exchange_v2_000000000000"

_SAMPLE_ROW: dict | None = None
if _FIRST_PARQUET.exists():
    _SAMPLE_ROW = pq.read_table(_FIRST_PARQUET).slice(0, 1).to_pylist()[0]

V2_CONTRACT = "0xe111180000d2663c0091e4f400237545b87b996b"

_PARQUET_AVAILABLE = pytest.mark.skipif(
    _SAMPLE_ROW is None, reason="parquets/v2 not present"
)


def _make_raw_tx(**overrides) -> RawTx:
    if _SAMPLE_ROW is not None:
        base = dict(_SAMPLE_ROW)
    else:
        base = dict(
            block_number=86109591,
            contract_address=V2_CONTRACT,
            transaction_hash="0x84b692504ce53506119b60bfebc4fd411b489f1a197e85ce980a2dc4afbfa55d",
            block_timestamp=datetime(2026, 4, 28, 1, 20, 26),
            transaction_index=194,
            tx_input="0x3c2b4399",  # placeholder when parquet absent
            gas_used=144873,
            effective_gas_price=222778059503,
            gas_fee_wei=32274525814378119,
        )
    base.update(overrides)
    return RawTx(**base)


# ---------------------------------------------------------------------------
# Unit tests: RawTx model
# ---------------------------------------------------------------------------


def test_raw_tx_label_and_v2_flag():
    raw = _make_raw_tx(contract_address=V2_CONTRACT)
    assert raw.label == "ctf_v2"


def test_raw_tx_unknown_contract():
    raw = _make_raw_tx(contract_address="0xdeadbeef00000000000000000000000000000001")
    assert raw.label == "0xdeadbeef00000000000000000000000000000001"


def test_raw_tx_gas_gwei():
    raw = _make_raw_tx(gas_fee_wei=1_500_000_000)
    assert raw.gas_fee_gwei == pytest.approx(1.5, rel=1e-6)


def test_raw_tx_decimal_gas_fee_wei():
    raw = _make_raw_tx(gas_fee_wei=Decimal("32274525814378119.000000"))
    assert raw.gas_fee_wei == 32274525814378119


def test_raw_tx_unix_timestamp():
    # V1/nonce parquets store block_timestamp as unix-seconds int
    raw = _make_raw_tx(block_timestamp=1745800000)
    assert isinstance(raw.block_timestamp, datetime)


def test_labels_all_lowercase():
    for addr in labelS:
        assert addr == addr.lower(), f"Key not lowercase: {addr}"


# ---------------------------------------------------------------------------
# Unit tests: decoder
# ---------------------------------------------------------------------------


@_PARQUET_AVAILABLE
def test_decode_v2_condition_id():
    decoded = decode_match_orders(
        _SAMPLE_ROW["tx_input"], _SAMPLE_ROW["contract_address"]
    )
    assert decoded is not None
    assert decoded.condition_id.startswith("0x")
    assert len(decoded.condition_id) == 66  # "0x" + 64 hex chars


@_PARQUET_AVAILABLE
def test_decode_v2_taker_maker_address():
    decoded = decode_match_orders(
        _SAMPLE_ROW["tx_input"], _SAMPLE_ROW["contract_address"]
    )
    assert decoded is not None
    assert decoded.taker_order.maker.startswith("0x")
    assert len(decoded.taker_order.maker) == 42


@_PARQUET_AVAILABLE
def test_decode_v2_maker_count():
    decoded = decode_match_orders(
        _SAMPLE_ROW["tx_input"], _SAMPLE_ROW["contract_address"]
    )
    assert decoded is not None
    assert len(decoded.maker_orders) >= 1


@_PARQUET_AVAILABLE
def test_decode_v2_affected_amount():
    decoded = decode_match_orders(
        _SAMPLE_ROW["tx_input"], _SAMPLE_ROW["contract_address"]
    )
    assert decoded is not None
    assert decoded.affected_amount > 0


def test_decode_unknown_contract_returns_none():
    result = decode_match_orders(
        "0x3c2b4399" + "00" * 100, "0xdeadbeef00000000000000000000000000000001"
    )
    assert result is None


def test_decode_garbage_input_returns_none():
    result = decode_match_orders("0xdeadbeef", V2_CONTRACT)
    assert result is None


# ---------------------------------------------------------------------------
# Unit tests: rule loading
# ---------------------------------------------------------------------------


@pytest.fixture
def all_rules_enabled(monkeypatch):
    from ghost_hunter.core import engine as _engine

    original = _engine._load_rule_configs

    def _patched(*args, **kwargs):
        cfgs = original(*args, **kwargs)
        return {k: {**v, "enabled": True} for k, v in cfgs.items()}

    monkeypatch.setattr(_engine, "_load_rule_configs", _patched)


def test_load_rules_finds_template(all_rules_enabled):
    rules = _load_rules(RULES_DIR)
    ids = [r.meta["id"] for r in rules]
    assert "unclassified" in ids


def test_rules_sorted_by_priority(all_rules_enabled):
    rules = _load_rules(RULES_DIR)
    priorities = [r.meta["priority"] for r in rules]
    assert priorities == sorted(priorities)


def test_template_rule_is_last(all_rules_enabled):
    rules = _load_rules(RULES_DIR)
    assert rules[-1].meta["id"] == "unclassified"


# ---------------------------------------------------------------------------
# Unit test: Finding.build
# ---------------------------------------------------------------------------


@_PARQUET_AVAILABLE
def test_finding_build():
    from ghost_hunter.core.models import BaseRule, BaseRuleResult, RuleMeta

    class _MockResult(BaseRuleResult):
        note: str = "test"

    class _MockRule(BaseRule):
        meta: RuleMeta = {"id": "mock", "priority": 1, "description": "test"}

        async def run(self, ctx):
            return None

    raw = _make_raw_tx()
    decoded = decode_match_orders(raw.tx_input, raw.contract_address)
    assert decoded is not None

    finding = Finding.build(raw, decoded, _MockRule(), _MockResult())

    assert finding.block_number == raw.block_number
    assert finding.label == "ctf_v2"
    assert finding.matched_rule == "mock"
    assert finding.condition_id == decoded.condition_id
    assert finding.affected_amount == pytest.approx(
        decoded.affected_amount / 1e6, rel=1e-6
    )
    assert finding.rule_result == {"note": "test", "revert_reasons": []}
    assert finding.id.startswith(f"{raw.block_number}-ctf_v2-")


# ---------------------------------------------------------------------------
# Integration test: engine processes real parquets offline
# ---------------------------------------------------------------------------


@_PARQUET_AVAILABLE
def test_engine_offline_template_rule(tmp_path: Path, all_rules_enabled):
    table = pq.read_table(_FIRST_PARQUET).slice(0, 10)
    small_dir = tmp_path / "parquets"
    small_dir.mkdir()
    pq.write_table(table, small_dir / "sample.parquet")

    output = tmp_path / "findings.jsonl"
    engine = Engine(
        parquet_root=small_dir,
        output_path=output,
        rules_dir=RULES_DIR,
    )
    total = asyncio.run(engine.run())

    assert total > 0, "Engine produced no findings"
    output_files = sorted(tmp_path.glob("findings*.jsonl"))
    assert len(output_files) > 0, "No output JSONL files written"

    lines = "".join(f.read_text() for f in output_files).strip().splitlines()
    assert len(lines) == total

    for line in lines[:5]:
        record = json.loads(line)
        assert "id" in record
        assert "matched_rule" in record
        assert record["matched_rule"]
        assert record["condition_id"] is not None
        assert record["affected_amount"] > 0


# ---------------------------------------------------------------------------
# Resume: rewind on restart so an interrupted parquet doesn't produce dups
# ---------------------------------------------------------------------------


@_PARQUET_AVAILABLE
def test_engine_resume_rewinds_partial_file(tmp_path: Path):
    full = pq.read_table(_FIRST_PARQUET)
    small_dir = tmp_path / "parquets"
    small_dir.mkdir()
    pq.write_table(full.slice(0, 5), small_dir / "a.parquet")
    pq.write_table(full.slice(5, 5), small_dir / "b.parquet")

    output = tmp_path / "findings.jsonl"

    engine_a = Engine(
        parquet_root=small_dir,
        output_path=output,
        rules_dir=RULES_DIR,
        resume=True,
    )
    asyncio.run(
        engine_a.run(parquet_files=[small_dir / "a.parquet"]),
    )

    state_path = tmp_path / "findings.scan_state.json"
    state = json.loads(state_path.read_text())
    assert str((small_dir / "a.parquet").resolve()) in state["completed"]
    boundary_offset = state["last_complete_offset"]
    boundary_chunk = state["last_complete_chunk"]

    chunk_file = tmp_path / f"findings_{boundary_chunk:03d}.jsonl"
    a_bytes = chunk_file.read_bytes()
    assert len(a_bytes) == boundary_offset

    with open(chunk_file, "ab") as f:
        f.write(b'{"id":"stale-from-interrupted-B","label":"ctf_v2"}\n')

    engine_b = Engine(
        parquet_root=small_dir,
        output_path=output,
        rules_dir=RULES_DIR,
        resume=True,
    )
    asyncio.run(engine_b.run())

    out_files = sorted(tmp_path.glob("findings_*.jsonl"))
    lines = []
    for p in out_files:
        lines.extend(p.read_text().splitlines())

    ids = [json.loads(line)["id"] for line in lines if line]
    assert "stale-from-interrupted-B" not in ids, (
        "Rewind failed: stale finding from interrupted run still present"
    )
    assert len(ids) == len(set(ids)), (
        f"Duplicate ids after resume: total={len(ids)} unique={len(set(ids))}"
    )


def test_scan_state_mark_done_snapshots_boundary(tmp_path: Path):
    state_path = tmp_path / "x.scan_state.json"
    state = ScanState.load_or_create(state_path)
    parquet = tmp_path / "fake.parquet"
    parquet.write_bytes(b"")

    state.mark_done(parquet, chunk=2, chunk_size=12345, total_findings=99)

    reloaded = ScanState.load_or_create(state_path)
    assert reloaded.is_done(parquet)
    assert reloaded.last_complete_chunk == 2
    assert reloaded.last_complete_offset == 12345
    assert reloaded.total_findings == 99


# ---------------------------------------------------------------------------
# Unit tests: decode_revert_output
# ---------------------------------------------------------------------------


def test_decode_revert_output_empty():
    assert decode_revert_output("") == ""
    assert decode_revert_output("0x") == ""


def test_decode_revert_output_error_string():
    import eth_abi

    encoded = "08c379a0" + eth_abi.encode(["string"], ["only owner"]).hex()
    result = decode_revert_output("0x" + encoded)
    assert result == "Error('only owner')"


def test_decode_revert_output_panic():
    import eth_abi

    encoded = "4e487b71" + eth_abi.encode(["uint256"], [0x11]).hex()
    result = decode_revert_output("0x" + encoded)
    assert result == "Panic(0x11)"


def test_decode_revert_output_known_exchange_error():
    result = decode_revert_output("0x7939f424")
    assert result == "TransferFromFailed()"


def test_decode_revert_output_known_token_error():
    result = decode_revert_output("0x13be252b")
    assert result == "InsufficientAllowance()"


def test_decode_revert_output_unknown_selector():
    result = decode_revert_output("0xdeadbeef")
    assert result == "CustomError(0xdeadbeef)"


# ---------------------------------------------------------------------------
# Unit tests: CallFrame dataclass
# ---------------------------------------------------------------------------


def test_call_frame_fields():
    f = CallFrame(
        index=0,
        call_type="CALL",
        call_from="0xabc",
        call_to="0xdef",
        selector="7939f424",
        error="Reverted",
        revert_reason="TransferFromFailed()",
    )
    assert f.index == 0
    assert f.call_type == "CALL"
    assert f.selector == "7939f424"
    assert f.revert_reason == "TransferFromFailed()"


def test_call_frame_no_error():
    f = CallFrame(
        index=1,
        call_type="STATICCALL",
        call_from="0xabc",
        call_to="0xdef",
        selector="70a08231",
        error="",
        revert_reason="",
    )
    assert f.error == ""
    assert f.revert_reason == ""


# ---------------------------------------------------------------------------
# Cross-rule cache sharing (offline)
# ---------------------------------------------------------------------------


class _MockAlchemy:

    def __init__(self, sim_result: list[dict]):
        self._sim_result = sim_result
        self.sim_call_count = 0

    async def trace_replay_transaction(self, tx_hash: str) -> list[dict]:
        self.sim_call_count += 1
        return self._sim_result


class _MockClients:
    def __init__(self, alchemy: _MockAlchemy):
        self.alchemy = alchemy
        self.etherscan = None  # not accessed in this test


@_PARQUET_AVAILABLE
def test_simulate_execution_shared_across_rules():
    from ghost_hunter.core.context import SharedCache, TxContext

    fake_calls = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": "0xoperator",
                "to": "0xexchange",
                "input": "0x3c2b4399",
                "gas": "0x0",
                "value": "0x0",
            },
            "result": {"gasUsed": "0x0", "output": "0x"},
            "subtraces": 0,
            "traceAddress": [],
        }
    ]
    mock_alchemy = _MockAlchemy(fake_calls)
    mock_clients = _MockClients(mock_alchemy)

    async def _run():
        cache = SharedCache()
        raw = _make_raw_tx()
        decoded = decode_match_orders(raw.tx_input, raw.contract_address)
        ctx = TxContext(raw, decoded, mock_clients, cache)  # type: ignore[arg-type]

        frames_a = await ctx.simulate_execution(raw.transaction_hash)
        frames_b = await ctx.simulate_execution(raw.transaction_hash)
        return frames_a, frames_b, mock_alchemy.sim_call_count, len(cache)

    frames_a, frames_b, call_count, cache_size = asyncio.run(_run())

    assert call_count == 1, "network fetch should happen exactly once"
    assert frames_a == frames_b, "both calls must return identical frames"
    assert cache_size == 1, "cache should hold exactly one entry"


# ---------------------------------------------------------------------------
# Network tests: simulate_execution via live Alchemy RPC
# (skipped when ALCHEMY_API_KEY is absent — safe in offline CI)
# ---------------------------------------------------------------------------

import os as _os

from dotenv import load_dotenv as _load_dotenv

_load_dotenv(Path(__file__).parent.parent / ".env")
_NETWORK_AVAILABLE = pytest.mark.skipif(
    not _os.getenv("ALCHEMY_API_KEY"),
    reason="ALCHEMY_API_KEY not set — skipping live RPC tests",
)

_KNOWN_REVERTS: list[tuple[str, str, str]] = [
    (
        "0xf09ea8cdf37d6f2fae0489cde3e6270ca15660fe8528f51505101e31c237a423",
        "FeeExceedsMaxRate()",
        "benign contract bug — root call throws FeeExceedsMaxRate directly",
    ),
    (
        "0xb52e35fd590a5c3d304214539bd652a183c93dc27ec8f881601d6a3a0881052b",
        "out of gas",  # trace_transaction returns lowercase error strings
        "proxy_trap — onERC1155Received burns all gas (reentrancy sentry)",
    ),
    (
        "0x2e5dadb94bf2c2ea4f2458e05c2a1b46711590800fd303494462e3e3a12ba367",
        "InsufficientAllowance()",
        "approve_revoke — pUSD transferFrom reverts with InsufficientAllowance",
    ),
    (
        "0x0e3700e6783fb3e0466efec955afc5992251be5deeb392c45cfefaece5b35301",
        "Insufficient",
        "balance_drain — pUSD transferFrom reverts with insufficient balance",
    ),
]


@_NETWORK_AVAILABLE
@pytest.mark.parametrize("tx_hash,expected_fragment,description", _KNOWN_REVERTS)
def test_simulate_execution_known_revert(
    tx_hash: str, expected_fragment: str, description: str
):
    from ghost_hunter.core.client import Clients
    from ghost_hunter.core.context import SharedCache, TxContext

    async def _run():
        async with Clients() as clients:
            raw = _make_raw_tx(tx_hash=tx_hash)
            ctx = TxContext(raw, None, clients, SharedCache())  # type: ignore[arg-type]
            return await ctx.simulate_execution(tx_hash)

    frames = asyncio.run(_run())

    assert len(frames) > 0, f"No frames returned for {tx_hash}"
    assert all(isinstance(f, CallFrame) for f in frames)

    errored = [f for f in frames if f.error]
    assert len(errored) > 0, f"No errored frames for {tx_hash}"

    combined = " ".join(f"{f.error} {f.revert_reason}" for f in errored)
    assert expected_fragment in combined, (
        f"Expected {expected_fragment!r} in errored frames for {description}\n"
        f"Got: {[(f.error, f.revert_reason) for f in errored]}"
    )


@_NETWORK_AVAILABLE
def test_simulate_execution_cached(tmp_path):
    from ghost_hunter.core.client import Clients
    from ghost_hunter.core.context import SharedCache, TxContext

    tx_hash = "0x2e5dadb94bf2c2ea4f2458e05c2a1b46711590800fd303494462e3e3a12ba367"

    async def _run():
        async with Clients() as clients:
            raw = _make_raw_tx(tx_hash=tx_hash)
            cache = SharedCache()
            ctx = TxContext(raw, None, clients, cache)  # type: ignore[arg-type]
            frames1 = await ctx.simulate_execution(tx_hash)
            frames2 = await ctx.simulate_execution(tx_hash)
            cache_size = len(cache)
            return frames1, frames2, cache_size

    frames1, frames2, cache_size = asyncio.run(_run())
    assert frames1 == frames2
    assert cache_size == 1
