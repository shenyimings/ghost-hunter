"""
Etherscan V2 (Polygon via chainid=137) and Alchemy RPC clients with:
  - Round-robin key pool across all API keys from .env
  - Per-key bounded concurrency (semaphore)
  - Exponential backoff with full jitter on retries

Key discovery: reads PREFIX, PREFIX_2, PREFIX_3, … until the sequence breaks.
  ETHERSCAN_API_KEY, ETHERSCAN_API_KEY_2,
  ALCHEMY_API_KEY,   ALCHEMY_API_KEY_2,
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Callable

import aiohttp
import yaml

logger = logging.getLogger(__name__)

_ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"
_POLYGON_CHAIN_ID = "137"
_CONFIG_PATH = Path(__file__).parents[3] / "config.yml"


def _load_key_pool_config() -> tuple[int, int]:
    """Return (etherscan_max_concurrent_per_key, alchemy_max_concurrent_per_key)."""
    try:
        with open(_CONFIG_PATH) as f:
            perf = yaml.safe_load(f).get("performance", {})
        return (
            int(perf.get("etherscan_max_concurrent_per_key", 5)),
            int(perf.get("alchemy_max_concurrent_per_key", 1)),
        )
    except Exception:
        return (5, 1)


_ALCHEMY_RPC_BASE = "https://polygon-mainnet.g.alchemy.com/v2"


_ALCHEMY_BACKOFF_SECONDS = (1.0, 2.0, 5.0, 15.0, 30.0)
_ALCHEMY_MAX_KEY_ROTATIONS = 2


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------


def _load_keys(prefix: str) -> list[str]:
    """Collect PREFIX, PREFIX_2, PREFIX_3, … from environment."""
    keys: list[str] = []
    first = os.getenv(prefix)
    if first:
        keys.append(first)
    i = 2
    while True:
        v = os.getenv(f"{prefix}_{i}")
        if not v:
            break
        keys.append(v)
        i += 1
    return keys


# ---------------------------------------------------------------------------
# Key pool
# ---------------------------------------------------------------------------


class KeyPool:

    def __init__(self, keys: list[str], max_concurrent_per_key: int = 3):
        if not keys:
            raise ValueError("No API keys provided to KeyPool")
        self._keys = keys
        self._sems = [asyncio.Semaphore(max_concurrent_per_key) for _ in keys]
        self._idx = 0
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[str, None]:
        """Yield the next API key, holding its semaphore slot for the duration."""
        async with self._lock:
            i = self._idx % len(self._keys)
            self._idx += 1
        async with self._sems[i]:
            yield self._keys[i]

    def __len__(self) -> int:
        return len(self._keys)


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------


class RetryableError(Exception):
    """Raised inside a factory to signal the call should be retried."""


async def retry_async(
    factory: Callable[[], Any],
    *,
    max_attempts: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 70.0,
) -> Any:
    """Call ``factory()`` up to ``max_attempts`` times with exponential backoff + full jitter."""
    for attempt in range(max_attempts):
        try:
            return await factory()
        except RetryableError as exc:
            if attempt == max_attempts - 1:
                raise
            cap = min(base_delay * (2**attempt), max_delay)
            delay = random.uniform(0, cap)
            logger.debug(
                "retry %d/%d in %.2fs: %s", attempt + 1, max_attempts, delay, exc
            )
            await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Etherscan V2 client (Polygon via chainid=137)
# ---------------------------------------------------------------------------


class EtherscanClient:
    """Etherscan V2 API wrapper pinned to Polygon (chainid=137)."""

    def __init__(self, pool: KeyPool, session: aiohttp.ClientSession):
        self._pool = pool
        self._session = session

    async def _get(self, params: dict) -> dict:
        async def _call() -> dict:
            async with self._pool.acquire() as key:
                p = {**params, "chainid": _POLYGON_CHAIN_ID, "apikey": key}
                async with self._session.get(
                    _ETHERSCAN_V2_BASE,
                    params=p,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 429:
                        raise RetryableError("HTTP 429 from Etherscan")
                    resp.raise_for_status()
                    data: dict = await resp.json()
                    # Etherscan returns status=0 for API-level errors
                    if data.get("status") == "0":
                        msg = str(data.get("result", ""))
                        status_msg = str(data.get("message", ""))
                        combined_msg = f"{msg} {status_msg}".lower()
                        if (
                            "no records found" in combined_msg
                            or "no transactions found" in combined_msg
                        ):
                            return {**data, "result": []}
                        if "rate limit" in combined_msg or "max rate" in combined_msg:
                            raise RetryableError(msg)
                        raise ValueError(f"Etherscan error: {msg}")
                    return data

        return await retry_async(_call)

    async def get_txlist(
        self,
        address: str,
        start_block: int,
        end_block: int,
        *,
        internal: bool = False,
    ) -> list[dict]:
        action = "txlistinternal" if internal else "txlist"
        data = await self._get(
            {
                "module": "account",
                "action": action,
                "address": address,
                "startblock": start_block,
                "endblock": end_block,
                "sort": "asc",
            }
        )
        result = data.get("result", [])
        return result if isinstance(result, list) else []

    async def get_logs(
        self,
        address: str,
        from_block: int,
        to_block: int,
        topic0: str,
        topic1: str | None = None,
        topic2: str | None = None,
    ) -> list[dict]:

        params: dict = {
            "module": "logs",
            "action": "getLogs",
            "address": address,
            "fromBlock": from_block,
            "toBlock": to_block,
            "topic0": topic0,
        }
        if topic1 is not None:
            params["topic1"] = topic1
            params["topic0_1_opr"] = "and"
        if topic2 is not None:
            params["topic2"] = topic2
            # Etherscan requires explicit AND operator between any two topics
            # that both appear in the query.
            if topic1 is not None:
                params["topic1_2_opr"] = "and"
            else:
                params["topic0_2_opr"] = "and"
        data = await self._get(params)
        result = data.get("result", [])
        return result if isinstance(result, list) else []


# ---------------------------------------------------------------------------
# Alchemy JSON-RPC client (Polygon)
# ---------------------------------------------------------------------------


class AlchemyClient:

    def __init__(self, pool: KeyPool, session: aiohttp.ClientSession):
        self._pool = pool
        self._session = session
        self._rpc_id = 0

    async def _do_request(self, key: str, method: str, params: list) -> Any:
        """Single HTTP attempt against one key. Raises RetryableError on 429
        and other transient errors; raises ValueError on non-retryable RPC errors."""
        url = f"{_ALCHEMY_RPC_BASE}/{key}"
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": method,
            "params": params,
        }
        try:
            async with self._session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status == 429:
                    raise RetryableError(f"HTTP 429 from Alchemy ({method})")
                if resp.status in (400, 403):
                    try:
                        data = await resp.json()
                        if "error" in data and data["error"].get("code") == -32600:
                            raise RetryableError(
                                f"Alchemy API restriction ({resp.status}): {data['error'].get('message')}"
                            )
                    except RetryableError:
                        raise
                    except Exception:
                        pass
                resp.raise_for_status()
                data: dict = await resp.json()
                if "error" in data:
                    err = data["error"]
                    # -32005: limit exceeded; -32016: pending block; 429: rate limit
                    if err.get("code") in (-32005, -32016, 429):
                        raise RetryableError(str(err))
                    raise ValueError(f"RPC error on {method}: {err}")
                return data["result"]
        except asyncio.TimeoutError as exc:
            raise RetryableError(f"Alchemy timeout ({method})") from exc

    async def _rpc(self, method: str, params: list) -> Any:
        last_exc: Exception | None = None
        for _rotation in range(_ALCHEMY_MAX_KEY_ROTATIONS + 1):
            async with self._pool.acquire() as key:
                for attempt, cap in enumerate(_ALCHEMY_BACKOFF_SECONDS):
                    try:
                        return await self._do_request(key, method, params)
                    except RetryableError as exc:
                        last_exc = exc
                        is_last_attempt = attempt == len(_ALCHEMY_BACKOFF_SECONDS) - 1
                        if is_last_attempt:
                            break  # rotate to next key
                        await asyncio.sleep(random.uniform(0, cap))
        raise RetryableError(
            f"Alchemy {method}: exhausted backoff across "
            f"{_ALCHEMY_MAX_KEY_ROTATIONS + 1} keys ({last_exc})"
        )

    async def eth_get_code(self, address: str, block: int | str = "latest") -> str:
        block_param = hex(block) if isinstance(block, int) else block
        return await self._rpc("eth_getCode", [address, block_param])

    async def eth_call(self, to: str, data: str, block: int | str = "latest") -> str:
        block_param = hex(block) if isinstance(block, int) else block
        return await self._rpc("eth_call", [{"to": to, "data": data}, block_param])

    async def eth_get_logs(
        self,
        from_block: int,
        to_block: int,
        topics: list[str | None],
        address: str | None = None,
    ) -> list[dict]:
        filter_obj: dict = {
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "topics": topics,
        }
        if address:
            filter_obj["address"] = address
        return await self._rpc("eth_getLogs", [filter_obj])

    async def eth_get_transaction_receipt(self, tx_hash: str) -> dict | None:
        return await self._rpc("eth_getTransactionReceipt", [tx_hash])

    async def eth_get_storage_at(
        self, address: str, slot: str, block: int | str = "latest"
    ) -> str:
        block_param = hex(block) if isinstance(block, int) else block
        return await self._rpc("eth_getStorageAt", [address, slot, block_param])

    async def trace_replay_transaction(self, tx_hash: str) -> list[dict]:
        result = await self._rpc("trace_transaction", [tx_hash])
        if result is None:
            return []
        return result


# ---------------------------------------------------------------------------
# Combined client container (async context manager)
# ---------------------------------------------------------------------------


class Clients:

    def __init__(self):
        from dotenv import load_dotenv

        load_dotenv()

        etherscan_keys = _load_keys("ETHERSCAN_API_KEY")
        alchemy_keys = _load_keys("ALCHEMY_API_KEY")
        logger.info(
            "API key pools: %d Etherscan, %d Alchemy",
            len(etherscan_keys),
            len(alchemy_keys),
        )

        etherscan_concurrency, alchemy_concurrency = _load_key_pool_config()
        self._etherscan_pool = KeyPool(
            etherscan_keys, max_concurrent_per_key=etherscan_concurrency
        )
        self._alchemy_pool = KeyPool(
            alchemy_keys, max_concurrent_per_key=alchemy_concurrency
        )

        self._session: aiohttp.ClientSession | None = None
        self.etherscan: EtherscanClient  # set in __aenter__
        self.alchemy: AlchemyClient  # set in __aenter__

    async def __aenter__(self) -> Clients:
        connector = aiohttp.TCPConnector(limit=200, limit_per_host=50)
        self._session = aiohttp.ClientSession(connector=connector)
        self.etherscan = EtherscanClient(self._etherscan_pool, self._session)
        self.alchemy = AlchemyClient(self._alchemy_pool, self._session)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()
