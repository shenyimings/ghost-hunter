"""
Per-transaction runtime context passed to every rule.

Design goals:
  - Block-pinned: every primitive defaults to the block of the revert tx.
  - Content-addressed cache (SharedCache): two rules calling get_code(addr, block)
    share one RPC round-trip — the second call returns from cache immediately.
  - Dogpile prevention: per-key asyncio.Lock ensures only one in-flight fetch
    per cache key even under high concurrency.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from .client import Clients
from .decoder import decode_revert_output
from .models import CallFrame, DecodedMatchOrders, RawTx

logger = logging.getLogger(__name__)


class SharedCache:

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._key_locks: dict[str, asyncio.Lock] = {}
        self._meta_lock = asyncio.Lock()

    async def get_or_fetch(self, key: tuple, fetch_fn: Callable) -> Any:
        k = repr(key)
        if k in self._data:
            return self._data[k]

        # Ensure only one coroutine fetches a given key (dogpile prevention)
        async with self._meta_lock:
            if k not in self._key_locks:
                self._key_locks[k] = asyncio.Lock()
            lock = self._key_locks[k]

        async with lock:
            if k not in self._data:
                self._data[k] = await fetch_fn()
            return self._data[k]

    def clear(self) -> None:
        self._data.clear()
        self._key_locks.clear()

    def evict(self, key: tuple) -> None:
        k = repr(key)
        self._data.pop(k, None)
        self._key_locks.pop(k, None)

    def has(self, key: tuple) -> bool:
        return repr(key) in self._data

    def __len__(self) -> int:
        return len(self._data)


class TxContext:

    def __init__(
        self,
        raw: RawTx,
        decoded: DecodedMatchOrders,
        clients: Clients,
        cache: SharedCache,
    ) -> None:
        self.tx = raw
        self.decoded = decoded
        self._clients = clients
        self._cache = cache

    # ------------------------------------------------------------------
    # Alchemy RPC primitives
    # ------------------------------------------------------------------

    async def get_code(self, address: str, block: int | None = None) -> str:
        b: int | str = block if block is not None else self.tx.block_number
        key = ("get_code", address.lower(), b)
        return await self._cache.get_or_fetch(
            key, lambda: self._clients.alchemy.eth_get_code(address, b)
        )

    async def eth_call(self, to: str, data: str, block: int | None = None) -> str:
        b: int | str = block if block is not None else self.tx.block_number
        key = ("eth_call", to.lower(), data.lower(), b)
        return await self._cache.get_or_fetch(
            key, lambda: self._clients.alchemy.eth_call(to, data, b)
        )

    async def get_storage_at(
        self, address: str, slot: str, block: int | None = None
    ) -> str:
        b: int | str = block if block is not None else self.tx.block_number
        key = ("get_storage_at", address.lower(), slot.lower(), b)
        return await self._cache.get_or_fetch(
            key, lambda: self._clients.alchemy.eth_get_storage_at(address, slot, b)
        )

    async def get_tx_receipt(self, tx_hash: str) -> dict | None:
        key = ("tx_receipt", tx_hash.lower())
        return await self._cache.get_or_fetch(
            key,
            lambda: self._clients.alchemy.eth_get_transaction_receipt(tx_hash),
        )

    async def get_logs(
        self,
        from_block: int,
        to_block: int,
        topics: list[str | None],
        address: str | None = None,
    ) -> list[dict]:
        key = (
            "get_logs",
            address and address.lower(),
            from_block,
            to_block,
            tuple(topics),
        )
        return await self._cache.get_or_fetch(
            key,
            lambda: self._clients.alchemy.eth_get_logs(
                from_block, to_block, topics, address
            ),
        )

    # ------------------------------------------------------------------
    # Etherscan primitives
    # ------------------------------------------------------------------

    async def get_txlist(
        self,
        address: str,
        start_block: int,
        end_block: int,
        *,
        internal: bool = False,
    ) -> list[dict]:
        key = ("txlist", address.lower(), start_block, end_block, internal)
        return await self._cache.get_or_fetch(
            key,
            lambda: self._clients.etherscan.get_txlist(
                address, start_block, end_block, internal=internal
            ),
        )

    async def get_logs_etherscan(
        self,
        address: str,
        from_block: int,
        to_block: int,
        topic0: str,
        topic1: str | None = None,
        topic2: str | None = None,
    ) -> list[dict]:
        key = (
            "etherscan_logs",
            address.lower(),
            from_block,
            to_block,
            topic0.lower(),
            (topic1 or "").lower(),
            (topic2 or "").lower(),
        )
        return await self._cache.get_or_fetch(
            key,
            lambda: self._clients.etherscan.get_logs(
                address, from_block, to_block, topic0, topic1, topic2
            ),
        )

    # ------------------------------------------------------------------
    # Revert analysis
    # ------------------------------------------------------------------

    async def simulate_execution(self, tx_hash: str) -> list[CallFrame]:
        key = ("trace_replay", tx_hash.lower())
        raw_traces: list[dict] = await self._cache.get_or_fetch(
            key,
            lambda: self._clients.alchemy.trace_replay_transaction(tx_hash),
        )
        return [_trace_to_frame(i, t) for i, t in enumerate(raw_traces)]


def _hex_int(v: str | int | None) -> int:
    if v is None or v == "":
        return 0
    if isinstance(v, int):
        return v
    try:
        return int(v, 16)
    except (ValueError, TypeError):
        return 0


def _trace_to_frame(i: int, t: dict) -> CallFrame:
    action = t.get("action") or {}
    result = t.get("result") or {}
    trace_type = (t.get("type") or "").lower()
    error = t.get("error") or ""

    if trace_type == "create":
        inp = (action.get("init") or "").lower()
        to_addr = ((result.get("address") if isinstance(result, dict) else "") or "").lower()
        call_type = "CREATE"
    else:
        inp = (action.get("input") or "").lower()
        to_addr = (action.get("to") or "").lower()
        call_type = (action.get("callType") or trace_type or "").upper()

    output = ((result.get("output") if isinstance(result, dict) else "") or "").lower()
    sel = inp[2:10] if inp.startswith("0x") and len(inp) >= 10 else ""

    return CallFrame(
        index=i,
        call_type=call_type,
        call_from=(action.get("from") or "").lower(),
        call_to=to_addr,
        selector=sel,
        error=error,
        revert_reason=decode_revert_output(output) if error else "",
        gas=_hex_int(action.get("gas")),
        gas_used=_hex_int(result.get("gasUsed") if isinstance(result, dict) else None),
        value=_hex_int(action.get("value")),
        input_data=inp,
        output_data=output,
    )
