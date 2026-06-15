from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import yaml

from .client import Clients
from .context import SharedCache, TxContext
from .decoder import decode_match_orders
from .models import BaseRule, Finding, RawTx

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent.parent / "rules"
_CONFIG_PATH = Path(__file__).parents[3] / "config.yml"
_DEFAULT_FLUSH_EVERY_N = 5000
_DEFAULT_MAX_OUTPUT_MB = 500


def _load_performance_config() -> tuple[int, int, int]:
    try:
        with open(_CONFIG_PATH) as f:
            perf = yaml.safe_load(f).get("performance", {})
        return (
            int(perf.get("max_concurrent", 10)),
            int(perf.get("flush_every_n", _DEFAULT_FLUSH_EVERY_N)),
            int(perf.get("max_output_mb", _DEFAULT_MAX_OUTPUT_MB)),
        )
    except Exception:
        return (10, _DEFAULT_FLUSH_EVERY_N, _DEFAULT_MAX_OUTPUT_MB)


# ---------------------------------------------------------------------------
# Persistent scan state (--resume mode)
# ---------------------------------------------------------------------------


class ScanState:

    def __init__(self, path: Path) -> None:
        self.path = path
        self.completed: set[str] = set()  # absolute resolved paths
        self.last_complete_chunk: int = 0
        self.last_complete_offset: int = 0
        self.total_findings: int = 0

    @classmethod
    def load_or_create(cls, path: Path) -> "ScanState":
        state = cls(path)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                state.completed = set(data.get("completed", []))
                state.last_complete_chunk = int(data.get("last_complete_chunk", 0))
                state.last_complete_offset = int(data.get("last_complete_offset", 0))
                state.total_findings = int(data.get("total_findings", 0))
                logger.info(
                    "Resuming: %d completed parquet file(s), chunk %03d @ %d bytes, "
                    "%d findings accumulated so far",
                    len(state.completed),
                    state.last_complete_chunk,
                    state.last_complete_offset,
                    state.total_findings,
                )
            except Exception as exc:
                logger.warning(
                    "Could not parse state file %s (%s) — starting fresh", path, exc
                )
        else:
            logger.info("No existing state file found — starting fresh run")
        return state

    def save(self) -> None:
        data = {
            "completed": sorted(self.completed),
            "last_complete_chunk": self.last_complete_chunk,
            "last_complete_offset": self.last_complete_offset,
            "total_findings": self.total_findings,
        }
        self.path.write_text(json.dumps(data, indent=2))

    def is_done(self, path: Path) -> bool:
        return str(path.resolve()) in self.completed

    def mark_done(
        self, path: Path, chunk: int, chunk_size: int, total_findings: int
    ) -> None:
        self.completed.add(str(path.resolve()))
        self.last_complete_chunk = chunk
        self.last_complete_offset = chunk_size
        self.total_findings = total_findings
        self.save()


# ---------------------------------------------------------------------------
# Rule discovery
# ---------------------------------------------------------------------------


def _load_rule_configs(config_path: Path = _CONFIG_PATH) -> dict:
    try:
        with open(config_path) as f:
            return yaml.safe_load(f).get("rules", {})
    except Exception:
        return {}


def _load_rules(rules_dir: Path = _RULES_DIR) -> list[BaseRule]:
    rule_configs = _load_rule_configs()

    # Make sure the package root is on sys.path so imports work
    pkg_root = str(rules_dir.parent.parent)
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)

    rules: list[BaseRule] = []
    for path in sorted(rules_dir.glob("*.py")):
        if path.name.startswith("__"):
            continue
        rule_id = path.stem
        if rule_id not in rule_configs:
            logger.debug(
                "Rule file %s has no entry in config.yml rules: — skipping", path.name
            )
            continue
        rc = rule_configs[rule_id]
        if not rc.get("enabled", True):
            logger.info("Rule %s disabled in config.yml — skipping", rule_id)
            continue

        module_name = f"ghost_hunter.rules.{path.stem}"
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:
            logger.error("Failed to import rule module %s: %s", path.name, exc)
            continue
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                obj is not BaseRule
                and issubclass(obj, BaseRule)
                and not inspect.isabstract(obj)
            ):
                instance = obj()
                instance.meta = {
                    "id": rule_id,
                    "priority": rc["priority"],
                    "description": rc.get("description", ""),
                }
                rules.append(instance)

    rules.sort(key=lambda r: r.meta["priority"])
    logger.info(
        "Loaded %d rules (priority order): %s",
        len(rules),
        [r.meta["id"] for r in rules],
    )
    return rules


# ---------------------------------------------------------------------------
# Parquet discovery + reading
# ---------------------------------------------------------------------------


def _discover_parquets(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                files.append(p)
    return files


def _iter_row_batches(path: Path, batch_size: int) -> Any:
    pf = pq.ParquetFile(path)
    for batch in pf.iter_batches(batch_size=batch_size):
        yield batch.to_pylist()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class Engine:
    def __init__(
        self,
        parquet_root: Path,
        output_path: Path,
        *,
        resume: bool = False,
        rules_dir: Path = _RULES_DIR,
    ) -> None:
        self.parquet_root = parquet_root
        self.output_path = output_path
        self.resume = resume
        self._rules_dir = rules_dir
        self._rules: list[BaseRule] = []
        self.max_concurrent, self._flush_every_n, self._max_output_mb = (
            _load_performance_config()
        )
        self._chunk: int = 0
        self._state: ScanState | None = None

    # ------------------------------------------------------------------
    # Output path helpers
    # ------------------------------------------------------------------

    def _chunk_path(self, chunk: int) -> Path:
        """Return the file path for a given chunk index."""
        if self._max_output_mb <= 0:
            return self.output_path
        stem = self.output_path.stem
        suffix = self.output_path.suffix or ".jsonl"
        return self.output_path.parent / f"{stem}_{chunk:03d}{suffix}"

    def _state_path(self) -> Path:
        return self.output_path.parent / f"{self.output_path.stem}.scan_state.json"

    def _current_output_path(self) -> Path:
        return self._chunk_path(self._chunk)

    def _rewind_to_boundary(self, chunk: int, offset: int) -> None:
        active = self._chunk_path(chunk)
        if active.exists():
            with open(active, "r+b") as f:
                f.truncate(offset)
        else:
            active.parent.mkdir(parents=True, exist_ok=True)
            active.write_text("")

        # Remove any later chunks created after the last mark_done.
        if self._max_output_mb > 0:
            i = chunk + 1
            while True:
                p = self._chunk_path(i)
                if not p.exists():
                    break
                p.unlink()
                logger.info("Removed orphan chunk from interrupted run: %s", p.name)
                i += 1

    # ------------------------------------------------------------------
    # Public run method
    # ------------------------------------------------------------------

    async def run(
        self,
        parquet_dirs: list[Path] | None = None,
        parquet_files: list[Path] | None = None,
    ) -> int:
        self._rules = _load_rules(self._rules_dir)
        if not self._rules:
            raise RuntimeError("No rules loaded — nothing to do")

        # Build the full file list: discovered from dirs + explicitly named files.
        if parquet_dirs is None and not parquet_files:
            roots = [self.parquet_root]
        else:
            roots = parquet_dirs or []
        paths = _discover_parquets(roots)
        if parquet_files:
            seen = set(paths)
            extra = [p for p in parquet_files if p not in seen]
            paths = extra + paths
        logger.info(
            "Scanning %d parquet file(s) (%d from dirs, %d explicit)",
            len(paths),
            len(paths) - len(parquet_files or []),
            len(parquet_files or []),
        )

        # Ensure output directory exists.
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.resume:
            # Load or create persistent state; restore chunk counter to the
            # last completed-file boundary and discard anything written past
            # it (those rows came from a parquet file that didn't finish, and
            # would be re-emitted as duplicates when its processing restarts).
            self._state = ScanState.load_or_create(self._state_path())
            self._chunk = self._state.last_complete_chunk
            self._rewind_to_boundary(
                self._state.last_complete_chunk,
                self._state.last_complete_offset,
            )
            logger.info(
                "Resume mode: output chunk %03d → %s (truncated to %d bytes)",
                self._chunk,
                self._current_output_path(),
                self._state.last_complete_offset,
            )
        else:
            # Fresh run: truncate/create the first output file.
            self._chunk = 0
            self._current_output_path().write_text("")

        buffer: list[Finding] = []
        total = self._state.total_findings if self._state is not None else 0
        sem = asyncio.Semaphore(self.max_concurrent)
        cache = SharedCache()

        async with Clients() as clients:
            for path in paths:
                if self._state is not None and self._state.is_done(path):
                    logger.info("Skipping (already completed): %s", path.name)
                    continue

                try:
                    batch_iter = _iter_row_batches(path, self._flush_every_n)
                except Exception as exc:
                    logger.debug(
                        "Skipping %s (not a valid parquet): %s", path.name, exc
                    )
                    continue

                logger.debug("Streaming batches from %s", path.name)
                for chunk in batch_iter:
                    tasks = [
                        self._process_row(row, clients, cache, sem) for row in chunk
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for r in results:
                        if isinstance(r, BaseException):
                            logger.error("Row processing error: %s", r)
                        elif r is not None:
                            buffer.append(r)

                    self._flush(buffer)
                    total += len(buffer)
                    buffer.clear()
                    cache.clear()

                if self._state is not None:
                    out = self._current_output_path()
                    try:
                        chunk_size = out.stat().st_size
                    except OSError:
                        chunk_size = 0
                    self._state.mark_done(path, self._chunk, chunk_size, total)

        logger.info(
            "Scan complete: %d findings from %d files",
            total,
            len(paths),
        )
        return total

    # ------------------------------------------------------------------
    # Row processing
    # ------------------------------------------------------------------

    async def _process_row(
        self,
        row: dict[str, Any],
        clients: Clients,
        cache: SharedCache,
        sem: asyncio.Semaphore,
    ) -> Finding | None:
        async with sem:
            try:
                raw = RawTx(**row)
            except Exception as exc:
                logger.debug("Skipping malformed row: %s", exc)
                return None

            decoded = decode_match_orders(raw.tx_input, raw.contract_address)
            if decoded is None:
                return None

            ctx = TxContext(raw, decoded, clients, cache)
            try:
                return await self._try_rules(ctx, raw, decoded)
            finally:
                cache.evict(("trace_replay", raw.transaction_hash.lower()))

    async def _try_rules(
        self,
        ctx: TxContext,
        raw: RawTx,
        decoded: Any,
    ) -> Finding | None:
        for rule in self._rules:
            try:
                result = await rule.run(ctx)
            except Exception as exc:
                logger.warning(
                    "Rule %s raised on %s: %s",
                    rule.meta["id"],
                    raw.transaction_hash,
                    exc,
                )
                result = None

            if result is not None:
                trace_key = ("trace_replay", ctx.tx.transaction_hash.lower())
                if ctx._cache.has(trace_key):
                    try:
                        frames = await ctx.simulate_execution(ctx.tx.transaction_hash)
                        result.revert_reasons = list(
                            dict.fromkeys(
                                f.revert_reason or f.error for f in frames if f.error
                            )
                        )
                    except Exception as exc:
                        logger.warning(
                            "revert_reasons population failed for %s: %s",
                            raw.transaction_hash,
                            exc,
                        )
                return Finding.build(raw, decoded, rule, result)

        return None

    # ------------------------------------------------------------------
    # Output flush + chunk rotation
    # ------------------------------------------------------------------

    def _flush(self, findings: list[Finding]) -> None:
        out = self._current_output_path()
        with open(out, "a") as f:
            for finding in findings:
                f.write(
                    finding.model_dump_json(by_alias=True, exclude_none=True) + "\n"
                )

        logger.info("Flushed %d findings → %s", len(findings), out)

        # Check whether the current chunk has grown past the size limit.
        if self._max_output_mb > 0:
            limit_bytes = self._max_output_mb * 1024 * 1024
            try:
                current_size = out.stat().st_size
            except OSError:
                current_size = 0
            if current_size >= limit_bytes:
                self._chunk += 1
                logger.info(
                    "Chunk %s reached %.1f MB — rolling over to chunk %03d",
                    out.name,
                    current_size / (1024 * 1024),
                    self._chunk,
                )
                next_out = self._current_output_path()
                if not next_out.exists():
                    next_out.write_text("")
