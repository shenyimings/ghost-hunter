# GhostHunter

[![Paper](https://img.shields.io/badge/Paper-arXiv-b31b1b)](http://arxiv.org/abs/2606.16852)
![Visitors](https://visitor-badge.laobi.icu/badge?page_id=shenyimings.ghost-hunter&left_text=visitors&logo=github)
![Python](https://img.shields.io/badge/Python-3.12+-blue)

Research artifact for *The Ghosts of Polymarket: When Off-Chain Matches Meet On-Chain Reverts*.

> [!WARNING]
> **Ethics Statement.**
> This repository selectively open-sources the *methodology* part: detection rules, analysis scripts, and reproducible SQL queries, but **does not** include raw detection outputs, attacker address lists, or any other data that could be used to identify or target specific entities. We also omit Polymarket market slug/name mappings, as some market titles reference politically or religiously sensitive topics.

GhostHunter is a lightweight on-chain transaction analysis engine that detects and classifies reverted Polymarket CLOB `matchOrders` on Polygon. It decodes calldata, replays execution traces, and runs a prioritized rule chain to attribute each revert to an attack vector: *Proxy Trap*, *Nonce Bump*, *Allowance Revoke*, or *Balance Drain*.

## Repository Layout

```
src/ghost_hunter/       Detection engine (decoder, trace context, rule loader, rules)
main.py                 CLI entry point
config.yml              Contract addresses, selectors, revert decoders, rule config
tests/                  Unit tests

rq1/                    RQ1 analysis scripts + BigQuery SQL (v1.sql, v2.sql)
rq2/                    RQ2 analysis script + proxy-trap bytecode collectors
rq3/                    RQ3 cross-chain reuse: SQL sweeps + reuse analysis scripts
discussion/             Profit measurement and liquidity-reward analysis scripts
```

## Setup

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync
```

Create a `.env` file with your API keys (needed for the scanner and some analysis scripts):

```
ETHERSCAN_API_KEY=...
ALCHEMY_API_KEY=...
```

Multiple keys can be added by suffixing with `_2`, `_3`, etc.

## Reproducing the Results

### Step 1: Collect Reverted Transactions (BigQuery)

GhostHunter operates on parquet files of reverted `matchOrders()` transactions. Use the provided SQL to query Google BigQuery's `bigquery-public-data.crypto_polygon.transactions` table:

```bash
# V1 matchOrders (selector 0x2287e350, 2025-08-15 to 2026-04-28)
# → see rq1/v1.sql

# V2 matchOrders (selector 0x3c2b4399, from 2026-04-28)
# → see rq1/v2.sql
```

Export the results as parquet files into a local directory (e.g. `parquets/v1/`, `parquets/v2/`).

### Step 2: Run GhostHunter

```bash
# Scan V1 reverts
uv run main.py scan --parquet-dir parquets/v1 --output output/v1_findings.jsonl

# Scan V2 reverts
uv run main.py scan --parquet-dir parquets/v2 --output output/v2_findings.jsonl
```

Each finding includes the transaction hash, block number, decoded order data, matched rule, and classification details.

### Step 3: Run Analysis Scripts

```bash
uv run python rq1/rq1_analysis.py        # RQ1: prevalence tables + daily revert figure
uv run python rq2/rq2_analysis.py        # RQ2: per-vector breakdown + stacked figure
uv run python discussion/profit_measurement.py
```

To export the attacker address list from the findings:

```bash
uv run python discussion/export_attackers.py
```

### Step 4: RQ3 Cross-Chain Reuse

RQ3 uses Dune Analytics SQL to sweep for contract reuse across chains. The queries are in `rq3/sql/` (numbered 01–09). Run them on [Dune](https://dune.com) and export the results as CSV into `rq3/csv/`. Then:

```bash
uv run python rq3/reuse/analyze_reuse.py
```

### Scanner Options

- `--parquet-dir <dir>` — Directory to scan recursively for parquet files. Repeatable.
- `--parquet-file <file>` — Single parquet file to scan. Repeatable.
- `--output <path>` — Output JSONL file path. Defaults to `output/findings.jsonl`.
- `-v, --verbose` — Enable debug logging.

## Configuration

`config.yml` defines the rule priority chain, contract addresses, method selectors, revert error decoders, and performance settings. The default rule order is:

1. **Proxy Trap** — onERC1155Received callback revert
2. **Nonce Bump** — V1 incrementNonce() invalidation
3. **Allowance Revoke** — collateral approval change
4. **Balance Drain** — collateral transfer-out with gas_ratio > 1

## License

MIT

> [!NOTE]
> This artifact is released for academic research only.
