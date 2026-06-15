"""RQ1 — Prevalence of Ghost Fills.

Extracted from scripts/statistic.ipynb (cells 1-15). Self-contained: run with
    uv run python rq1/rq1_analysis.py
from the artifact root. Reads results/all_v{1,2}.parquet, results/market_mappings_v{1,2}.parquet
(regenerate the latter via rq1/condition_mappings_v1.py), rq1/dune_daily_*.csv and
results/rq1/participants_parts/ (the participant decode; needs the raw shards to rebuild,
so the §6.2 user cell only runs if that data is present).
Outputs (CSVs + rq1_reverts_daily.pdf) land in results/rq1/.
"""

"""Shared context: paths, data-model cheatsheets, and the global plotting palette.

Downstream cells / notebooks SHOULD import from here rather than redefining paths
or recreating the palette. Flip ``PALETTE['mode']`` between "bw" and "color" to
switch every chart's color scheme in one place.
"""


import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Path map — all artefacts referenced from anywhere in the notebook.
# Paths are relative to repo root; this script lives in rq1/.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

PATHS = {
    # Raw sharded Dune dumps (one row per reverted matchOrders / incrementNonce)
    "raw_v1_shards":  sorted((REPO_ROOT / "parquets" / "v1").glob("polymarket_ctf_exchange_v1_*")),
    "raw_v2_shards":  sorted((REPO_ROOT / "parquets" / "v2").glob("polymarket_ctf_exchange_v2_*")),
    "raw_nonce":      REPO_ROOT / "parquets" / "nonce" / "polymarket_ctf_exchange_v1_increment_nonce",
    # Classified engine output (Findings; carries revert_reasons + rule_result)
    "findings_v1":    REPO_ROOT / "results" / "all_v1.parquet",
    "findings_v2":    REPO_ROOT / "results" / "all_v2.parquet",
    # Gamma metadata (slug, neg_risk, rewards_*, event_title, ...)
    "market_map_v1":  REPO_ROOT / "results" / "market_mappings_v1.parquet",
    "market_map_v2":  REPO_ROOT / "results" / "market_mappings_v2.parquet",
}

# ---------------------------------------------------------------------------
# Data-model cheatsheets. Mirror src/ghost_hunter/core/models.py and the
# extract_market_base() flattener in scripts/condition_mappings_v1.py.
# Comments are deliberately one-liners; consult the source for nuance.
# ---------------------------------------------------------------------------

# RawTx — one row in parquets/{v1,v2}/* and parquets/nonce/*
RAW_TX_SCHEMA = {
    "block_number":        "int   — Polygon block height of the reverted tx",
    "contract_address":    "str   — exchange contract hit; resolved via labelS in models.py",
    "transaction_hash":    "str   — 0x-prefixed tx hash, lower-cased",
    "block_timestamp":     "ts    — V1/nonce: unix-seconds int; V2: us-precision datetime",
    "transaction_index":   "int   — position of tx inside the block",
    "tx_input":            "str   — raw calldata hex (selector + ABI-encoded args)",
    "gas_used":            "int   — gas actually consumed by the reverted tx",
    "effective_gas_price": "int   — wei per gas (post EIP-1559 effective price)",
    "gas_fee_wei":         "dec   — gas_used * effective_gas_price; Decimal(76,38) in V1/V2 shards, int64 in nonce shard",
    "from_address":        "str   — (nonce parquet only) signer that called incrementNonce()",
}

# Finding — one row in results/all_v{1,2}.parquet (engine output)
FINDING_SCHEMA = {
    "id":              "str    — '{block_num}-{label}-{tx_hash[:12]}'",
    "block_num":       "int    — Polygon block height",
    "label":           "str    — human contract label, e.g. 'ctf_v2', 'neg_risk_v1'",
    "tx_hash":         "str    — reverted matchOrders tx hash",
    "token_id":        "str    — V1 only: taker order CTF token id (dec)",
    "condition_id":    "str    — V2 only: bytes32 hex from matchOrders calldata",
    "affected_amount": "float  — total collateral at stake in human USDC/pUSD (raw/1e6)",
    "gas_fee_gwei":    "float  — gas cost of the reverted tx in gwei",
    "timestamp":       "str    — ISO8601 datetime (UTC) of the block",
    "matched_rule":    "str    — attack_vector classification: proxy_trap | nonce_bump | balance_drain | balance_drain_normal_gas | approve_revoke | collateral_race | custom_error | fee_exceeds_max_rate | unclassified",
    "rule_result":     "str    — JSON blob; .revert_reasons is the decoded error list (first entry is the primary), plus rule-specific fields (num_makers, taker_signer, cause_addr, gas_ratio, qualifying_makers, ...)",
}

# Market mapping — selected columns from results/market_mappings_v{1,2}.parquet
MARKET_MAP_SCHEMA = {
    "token_id":                  "str       — (V1 key) one row per CLOB token id (YES + NO ⇒ 2 rows per market)",
    "condition_id":              "str       — (V2 key) bytes32 condition id",
    "slug":                      "str       — Polymarket market slug (human-readable URL fragment)",
    "question":                  "str       — natural-language market question",
    "neg_risk":                  "bool      — True ⇒ market is part of a NegRisk multi-outcome group",
    "neg_risk_request_id":       "str       — NegRisk group request id (links sub-markets)",
    "lifecycle_flags":           "bool      — closed / archived / active / accepting_orders",
    "lifecycle_timestamps":      "str ISO   — start_date / end_date / closed_time / game_start_time / event_start_time",
    "outcomes":                  "list[str] — outcome labels, e.g. ['Yes','No']",
    "outcome_prices":            "list[str] — last outcome prices (string, 0..1)",
    "volume_num":                "float     — cumulative market volume (USD)",
    "liquidity_num":             "float     — current orderbook liquidity (USD)",
    "rewards_min_size":          "float     — min size (USDC/pUSD) for an order to score liquidity rewards",
    "rewards_max_spread":        "float     — max |order_price − mid| (cents) for the order to score",
    "rewards_daily_rate":        "float     — daily reward pool (USDC); usually only populated for sports markets",
    "typology":                  "str/num   — market_type / format_type / sports_market_type",
    "event_id":                  "str       — parent event id",
    "event_slug,event_title,event_ticker": "str  — parent event metadata",
    "event_tags":                "list[str] — taxonomy tags (fetched separately via /events)",
    "event_enable_neg_risk":     "bool      — True ⇒ event uses NegRisk umbrella",
    "event_neg_risk_market_id":  "str       — NegRisk meta-market id",
}

# Contract → label map (copied from models.labelS for quick reference)
CONTRACT_LABELS = {
    "0xe111180000d2663c0091e4f400237545b87b996b": "ctf_v2",
    "0xe2222d279d744050d28e00520010520000310f59": "neg_risk_v2",
    "0xb768891e3130f6df18214ac804d4db76c2c37730": "neg_risk_fee_module_v1",
    "0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0": "ctf_fee_module_v1",
    "0xc5d563a36ae78145c45a50134d48a1215220f80a": "neg_risk_v1",
    "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e": "ctf_v1",
}

# CLOB V1 → V2 cutover (use as a vertical line / regime split on time series)
V2_CUTOVER = pd.Timestamp("2026-04-27 00:00", tz="UTC")

# ---------------------------------------------------------------------------
# Global plotting palette. Change ONE thing — PALETTE['mode'] — to flip every
# downstream figure between IEEE-default monochrome and a curated academic
# colour scheme.
# ---------------------------------------------------------------------------

PALETTE = {
    # Switch this and rerun the plotting cells.
    "mode": "color",          # "bw" | "color"

    # Monochrome ramp — light → dark grey, terminating in pure black.
    # Designed for stacked area / bar / line charts that read cleanly when
    # printed on greyscale.
    "bw_ramp":   ["#ffffff", "#d9d9d9", "#bdbdbd", "#969696", "#737373",
                   "#525252", "#252525", "#000000"],
    "bw_line":   "#000000",   # default line / annotation colour
    "bw_accent": "#525252",   # secondary annotation

    # Academic colour palette (Okabe–Ito + Wong, colour-blind safe, widely used
    # in security papers e.g. USENIX, IEEE S&P). Saturated enough to stand out
    # in slides without looking like a default matplotlib chart.
    "colors":    ["#0072B2", "#D55E00", "#009E73", "#E69F00",
                   "#CC79A7", "#56B4E9", "#F0E442", "#000000"],
    "accent":    "#2C3E50",   # for callouts (V2 cutover line, etc.)
    "muted":     "#888888",
}


def get_palette(n: int) -> list[str]:
    """Return n colors honouring the current PALETTE['mode'].

    In bw mode the ramp skips pure white (illegible on white bg) and walks
    light→dark so stacked layers read as a tonal gradient. In color mode the
    Okabe–Ito list is repeated if n exceeds its length.
    """
    if PALETTE["mode"] == "bw":
        ramp = PALETTE["bw_ramp"][1:]   # drop pure white
        if n <= len(ramp):
            idx = np.linspace(0, len(ramp) - 1, n).round().astype(int)
            return [ramp[i] for i in idx]
        return [ramp[i % len(ramp)] for i in range(n)]
    cols = PALETTE["colors"]
    return [cols[i % len(cols)] for i in range(n)]


def apply_ieee_style() -> None:
    """Set matplotlib rcParams to IEEE S&P-friendly defaults."""
    mpl.rcParams.update({
        "text.usetex":     False,
        "font.family":       "serif",
        "font.size":         9,
        "axes.titlesize":    9,
        "axes.labelsize":    9,
        "xtick.labelsize":   7,
        "ytick.labelsize":   7,
        "legend.fontsize":   7,
        "axes.spines.top":   False,
        "axes.spines.right": False,
        "axes.linewidth":    0.6,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "lines.linewidth":   1.0,
        "figure.dpi":        120,
        "savefig.dpi":       300,
        "savefig.bbox":      "tight",
        "savefig.pad_inches": 0.00,
        "pdf.fonttype":      42,
        "ps.fonttype":       42,
    })


apply_ieee_style()
print(f"Palette mode: {PALETTE['mode']!r} | V1 shards: {len(PATHS['raw_v1_shards'])} | V2 shards: {len(PATHS['raw_v2_shards'])}")


# ======================================================================
# # RQ1 — Prevalence of Ghost Fills
# 
# **RQ1 is a phenomenon-level question, not an attribution one.** A *Ghost Fill* is **any** off-chain-matched order whose on-chain `matchOrders` reverts — whether the revert came from a deliberate *Cancellation Attack* or from benign behaviour (an expired order, a lost settlement race, a fee-config error). Every cell below therefore counts **all** reverts and classifies them by **on-chain failure surface (revert reason)**, never by `attack_vector`. Attribution to attacks is RQ2's job; the `matched_rule` column is deliberately *not* used here.
# 
# Sub-questions mirror the paper's RQ1 subsections:
# 1. **§6.1** Overall volume, failure-surface mix, and the revert **rate** over time (denominator from `scripts/rq1/dune_daily_matchorders_total_*.csv`).
# 2. **§6.2** Affected markets, users, and order patterns.
# 3. **§6.3** Estimated financial impact (collateral at risk + operator gas burned).
# 
# > **Data note.** Findings (`results/all_v{1,2}.parquet`) carry the join keys, `affected_amount`, gas, and revert reasons — enough for §6.1, §6.2 (markets) and §6.3. The full per-tx **participant** decode for the user-level part of §6.2 is produced separately by `scripts/rq1/decode_participants.py` → `results/rq1_participants.parquet`; the user cell uses it if present, else falls back to the partial participant fields in `rule_result`.
# ======================================================================


# ======================================================================
# ## Figure 1 — Reverted-`matchOrders` volume over time, by primary revert reason
# 
# **Question**: how is the total revert volume distributed across the V1/V2 timeline, and which on-chain failure modes dominate at any given moment?
# 
# **Source**: `results/all_v1.parquet` + `results/all_v2.parquet` (the engine output — the raw shards in `parquets/` do not carry `revert_reasons`). We union the two, parse `rule_result.revert_reasons[0]` as the **primary** revert reason, and bin by **calendar day** of `timestamp`. The x-axis is tick-labelled by month for legibility, but the underlying resolution is daily so day-to-day spikes (incident bursts, single-attacker flurries) stay visible. A short centred rolling mean rounds the silhouettes into a "hill" shape without erasing the bursts.
# 
# **Encoding choice**: top-5 reasons only (through `CustomError(0x92bbf6e8)`); the rest are dropped to keep the chart legible. Areas are **overlaid** (not stacked) — each filled at low alpha with a thin high-alpha outline — so simultaneous reasons read as overlapping silhouettes rather than one obscuring another. Drawing uses `seaborn` for the styling baseline (`sns.set_theme`, palette injection) and `matplotlib` for the fill primitives. The V1→V2 cutover line at **2026-04-28** marks the regime split.
# ======================================================================


import math
import matplotlib.dates as mdates
import seaborn as sns

# Union the two Findings parquets, extract the primary revert reason per row.

def _load_findings(path: Path, version: str) -> pd.DataFrame:
    df = pd.read_parquet(path, columns=["timestamp", "matched_rule", "rule_result"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    # nonce_bump findings come with revert_reasons=[] (the engine doesn't replay
    # the matchOrders for them — the bump itself is the causal evidence). Synth
    # "InvalidNonce()" so they don't silently fall through as "(none)".
    def _primary(rule: str, payload: str) -> str:
        try:
            rs = json.loads(payload).get("revert_reasons") or []
        except Exception:
            return "(parse_error)"
        if rs:
            return rs[0]
        if rule == "nonce_bump":
            return "InvalidNonce()"
        return "(none)"
    df["revert_reason"] = [_primary(r, p) for r, p in zip(df["matched_rule"], df["rule_result"])]
    df["version"] = version
    return df[["timestamp", "matched_rule", "revert_reason", "version"]]


findings = pd.concat([
    _load_findings(PATHS["findings_v1"], "v1"),
    _load_findings(PATHS["findings_v2"], "v2"),
], ignore_index=True).dropna(subset=["timestamp"])

# Map raw revert reasons -> failure-surface buckets. Collapses the OZ/custom
# variants of the same on-chain cause so the chart shows mechanisms, not
# error-string flavours.
REASON_BUCKETS = {
    "CustomError(0x92bbf6e8)":                 "onERC1155Received()",
    "Reverted":                                "onERC1155Received()",
    "Error('TRANSFER_FROM_FAILED')":           "TransferFromFailed()",
    "TransferFromFailed()":                    "TransferFromFailed()",
    "Error('SafeMath: subtraction overflow')": "TransferFromFailed()",
    "FeeExceedsMaxRate()":                     "FeeExceedsMaxRate()",
    "InvalidNonce()":                          "InvalidNonce()",
    "Error('rejected')":                     "onERC1155Received()",
}
BUCKET_ORDER = ["onERC1155Received()", "TransferFromFailed()", "FeeExceedsMaxRate()", "InvalidNonce()", "Others"]

findings["bucket"] = findings["revert_reason"].map(REASON_BUCKETS).fillna("Others")
print(f"Total reverts loaded: {len(findings):,}")
print("Bucket counts:")
print(findings["bucket"].value_counts().to_string())


# Draw
# Clip to 2025-12-01 onward.
START = pd.Timestamp("2025-12-01")
fsub = findings.copy()
fsub["day"] = fsub["timestamp"].dt.tz_convert("UTC").dt.floor("D").dt.tz_localize(None)
fsub = fsub[fsub["day"] >= START]

# Daily count per bucket on a continuous calendar (gaps = 0).
daily = fsub.groupby(["day", "bucket"]).size().unstack(fill_value=0)
full_idx = pd.date_range(daily.index.min(), daily.index.max(), freq="D")
daily = daily.reindex(full_idx, fill_value=0)
daily.index.name = "day"
for b in BUCKET_ORDER:
    if b not in daily.columns:
        daily[b] = 0
daily = daily[BUCKET_ORDER]

# Short centred rolling mean -> rounded "hill" silhouettes without erasing spikes.
SMOOTH_WINDOW = 1  # days
smoothed = daily.rolling(window=SMOOTH_WINDOW, center=True, min_periods=1).mean()

# Largest series drawn first (sits behind); smaller ones overlay on top.
order = smoothed.sum().sort_values(ascending=False).index.tolist()
colors = get_palette(len(order))

# --- seaborn baseline + matplotlib fills ---
sns.set_theme(
    style="white",
    rc={
        "font.family": "serif",
        # "font.serif": ["Times New Roman", "Times", "DejaVu Serif", "serif"],
        "font.size":   mpl.rcParams["font.size"],
    },
)

sns.set_palette(colors)

FILL_ALPHA = 0.25
EDGE_ALPHA = 0.8
EDGE_WIDTH = 1
FLOOR = 500            # log-axis floor: areas are measured up from 1,000

# Two-column-wide landscape figure.
fig, ax = plt.subplots(figsize=(7.16, 3.0))
for reason, color in zip(order, colors):
    x = smoothed.index.values
    y = np.clip(smoothed[reason].values, FLOOR, None)
    ax.fill_between(x, FLOOR, y, color=color, alpha=FILL_ALPHA, linewidth=0, zorder=2)
    ax.plot(x, y, color=color, alpha=EDGE_ALPHA, linewidth=EDGE_WIDTH,
            solid_joinstyle="round", solid_capstyle="round",
            label=reason, zorder=3)

# --- LEFT axis: log scale 10^3 .. 10^5; areas confined to the lower ~85% ---
ax.set_yscale("log")
data_max = float(np.nanmax(smoothed[BUCKET_ORDER].values))
lo_exp = 3
hi_exp = lo_exp + (math.log10(data_max) - lo_exp) / 0.85   # data peak sits at ~85% height
ax.set_ylim(FLOOR, 10 ** hi_exp)
yticks = [10 ** e for e in range(lo_exp, int(math.floor(hi_exp)) + 1)]
ax.set_yticks(yticks)
ax.tick_params(axis="y", labelsize=8)

ax.set_ylabel("Reverted matchOrders [log]",fontsize=9)

# V2 cutover marker — label on the LEFT of the line.
cutover = V2_CUTOVER.tz_convert(None).to_pydatetime()
ax.axvline(cutover, color="#222222", linestyle="--", linewidth=0.7, alpha=0.7, zorder=4)
ax.text(cutover, ax.get_ylim()[1] * 0.45, "V2 cutover ",
        fontsize=7.5, va="top", ha="right", color="#222222")

# X axis: bi-monthly major ticks (~5 gridlines) at daily resolution underneath.
ax.xaxis.set_major_locator(mdates.MonthLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
ax.xaxis.set_minor_locator(mdates.MonthLocator())
ax.tick_params(axis="x", labelsize=8.5)
for label in ax.get_xticklabels():
    label.set_rotation(0)
    label.set_horizontalalignment("center")
ax.set_xlim(left=START,right=smoothed.index.max())
ax.margins(x=0)

# Sparse grey background grid, drawn behind the areas.
ax.set_axisbelow(True)
ax.grid(True, which="major", color="#bbbbbb", linewidth=0.6, alpha=0.8, zorder=0)

# Full box: all four spines visible (top included).
for s in ax.spines.values():
    s.set_visible(True)
    s.set_linewidth(0.6)

# --- RIGHT axis (ax2): total matchOrders line, confined to the top ~15% band ---
_CSV = REPO_ROOT / "rq1" / "dune_daily_matchorders_total_20250815_20260506.csv"
_tot = pd.read_csv(_CSV)
_tot["day"] = pd.to_datetime(_tot["day_utc"])
_tot = (_tot[_tot["day"] >= START].set_index("day")["total_tx"]
            .reindex(daily.index).interpolate(limit_direction="both"))
_tot_s = _tot.rolling(window=7, center=True, min_periods=1).mean()

ax2 = ax.twinx()
# Map the volume line into the top band [_lo, _hi] of the axes via the ax2 limits.
_m, _M = float(_tot_s.min()), float(_tot_s.max())
_lo, _hi = 0.84, 0.985
_span = (_M - _m) / (_hi - _lo)
_B = _m - _lo * _span
ax2.set_ylim(_B, _B + _span)
ax2.plot(_tot_s.index, _tot_s.values, color=PALETTE["accent"], linewidth=1.0,
         alpha=0.9, zorder=5, label="Total matchOrders")
# Real, positive, in-band ticks only.
_ticks = np.linspace(_m, _M, 3)
ax2.set_yticks(_ticks)
ax2.set_yticklabels([f"{t/1e6:.1f}M" for t in _ticks])
ax2.set_ylabel("Total matchOrders", rotation=270, labelpad=0,fontsize=9)
ax2.tick_params(axis="y", labelsize=7.5)
ax2.spines["top"].set_visible(True)
ax2.spines["right"].set_visible(True)
ax2.margins(x=0)

# --- single-row legend outside the plot area, above the axes ---
_h1, _l1 = ax.get_legend_handles_labels()
_h2, _l2 = ax2.get_legend_handles_labels()
fig.tight_layout(rect=[0, 0, 1, 0.91])   # reserve the top strip for the legend
fig.legend(_h1 + _h2, _l1 + _l2,
           loc="upper center", bbox_to_anchor=(0.5, 1.0),
           ncol=len(_l1) + len(_l2), frameon=False, fontsize=7,
           columnspacing=1.2, handletextpad=0.5)

fig.savefig(str(REPO_ROOT / "results" / "rq1" / "rq1_reverts_daily.pdf"))
plt.show()


# RQ1 master loader -> `gf` (one row per reverted matchOrders = one Ghost Fill).
# Self-contained: re-reads the Findings so RQ1 cells can run independently of Fig 1.
import json
RESULTS = REPO_ROOT / "results"
RQ1_OUT = REPO_ROOT / "rq1" / "results"; RQ1_OUT.mkdir(parents=True, exist_ok=True)

def _primary_reason(rule: str, payload: str) -> str:
    """First decoded revert reason; nonce_bump rows carry [] (the bump itself is
    the evidence, the matchOrders isn't replayed) so we synth InvalidNonce()."""
    try:
        rs = json.loads(payload).get("revert_reasons") or []
    except Exception:
        return "(parse_error)"
    if rs:
        return rs[0]
    return "InvalidNonce()" if rule == "nonce_bump" else "(none)"

def _load(path, version, key_col):
    df = pd.read_parquet(path, columns=[
        "block_num", "label", "tx_hash", key_col,
        "affected_amount", "gas_fee_gwei", "timestamp", "matched_rule", "rule_result"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["revert_reason"] = [_primary_reason(r, p) for r, p in zip(df["matched_rule"], df["rule_result"])]
    df["version"] = version
    df["join_key"] = df[key_col].astype(str)
    if version == "v2":
        df["join_key"] = df["join_key"].str.lower()
    return df

gf = pd.concat([
    _load(PATHS["findings_v1"], "v1", "token_id"),
    _load(PATHS["findings_v2"], "v2", "condition_id"),
], ignore_index=True).dropna(subset=["timestamp"])
gf["day"] = gf["timestamp"].dt.tz_convert("UTC").dt.floor("D").dt.tz_localize(None)

print(f"Ghost Fills (reverted matchOrders) loaded: {len(gf):,}")
print(gf.groupby("version").size().rename("reverts").to_string())
print("\nPer-contract:")
print(gf.groupby(["version", "label"]).size().rename("reverts").to_string())
print(f"\nStudy window: {gf.timestamp.min()}  ->  {gf.timestamp.max()}")


# ======================================================================
# ## §6.1 — Overall volume, failure-surface mix, and revert rate
# 
# **Failure-surface classification.** We bucket the raw revert reasons by the on-chain mechanism that failed — *not* by who caused it. Collateral-transfer failures (`TRANSFER_FROM_FAILED`, `TransferFromFailed`, the OZ SafeMath underflow that is the ERC1155 balance check) read as one surface; ERC1155-callback reverts (`Reverted`, the `0x92bbf6e8` custom error, out-of-gas) as another; nonce invalidation, fee-config errors, and order-lifecycle/validation reverts (expired, already-filled, bad signature) as their own surfaces. The last group is benign-by-construction but still a Ghost Fill.
# ======================================================================


# Failure-surface buckets (mechanism, NOT attack vector).
REASON_BUCKET = {
    # ERC20 collateral transfer fails (balance/allowance) + ERC1155 balance underflow
    "Error('TRANSFER_FROM_FAILED')":           "Collateral transfer fails",
    "TransferFromFailed()":                    "Collateral transfer fails",
    "Error('SafeMath: subtraction overflow')": "Collateral transfer fails",
    "Panic(0x11)":                             "Collateral transfer fails",
    # ERC1155 token-delivery callback reverts
    "Reverted":                                "ERC1155 callback",
    "CustomError(0x92bbf6e8)":                 "ERC1155 callback",
    "out of gas":                              "ERC1155 callback",
    "Error('rejected')":                    "ERC1155 callback",
    "Error('Rejected')":                      "ERC1155 callback",
    "Error('ERC1155: need operator approval for 3rd party transfers.')": "ERC1155 callback",
    "Error('invalidated')":                    "ERC1155 callback",

    # order nonce invalidated
    "InvalidNonce()":                          "Order validation (user-side)",
    # platform fee computation
    "FeeExceedsMaxRate()":                     "Fee computation",
    "CustomError(0xcd4e6167)":                 "Fee computation",
    # benign order-lifecycle / validation
    "InvalidComplement()":                     "Order validation (operator-side)",
    "OrderExpired()":                          "Order validation (operator-side)",
    "OrderFilledOrCancelled()":                "Order validation (operator-side)",
    "MakingGtRemaining()":                     "Order validation (operator-side)",
    "InvalidSignature()":                      "Order validation (operator-side)",
    "Error(\"ECDSA: invalid signature 's' value\")": "Order validation (operator-side)",
    "MismatchedTokenIds()":                    "Order validation (operator-side)",
    "TooLittleTokensReceived()":               "Order validation (operator-side)",
    "NotAdmin()":                              "Order validation (operator-side)",

    "CustomError(0x1663f706)":                 "Condition token",
    "InvalidComplement()":                     "Condition token",
    "Error('condition not prepared yet')":         "Condition token",
}
gf["surface"] = gf["revert_reason"].map(REASON_BUCKET).fillna("Other / unknown")

# Collateral failures: the PRIMARY reason ("TRANSFER_FROM_FAILED") is the
# 0x/Solmate wrapper masking the real cause, but the SECONDARY decoded reason in
# revert_reasons reveals whether *balance* or *allowance* failed. Classify from
# the reason list alone -- no matched_rule (that attribution belongs to RQ2).
def _collateral_cause(payload: str) -> str:
    try:
        rs = " | ".join(json.loads(payload).get("revert_reasons") or []).lower()
    except Exception:
        rs = ""
    if "allowance" in rs:
        return "Allowance"
    if "balance" in rs or "subtraction overflow" in rs or "panic(0x11)" in rs:
        return "Balance"
    return "Other / unknown"

_coll = gf["surface"] == "Collateral transfer fails"
gf.loc[_coll, "surface"] = [_collateral_cause(p) for p in gf.loc[_coll, "rule_result"]]

# Which raw revert reasons land in the catch-all bucket?
_other = gf.loc[gf["surface"] == "Other / unknown", "revert_reason"].value_counts()
print("=== Revert reasons in 'Other / unknown' ===")
print(_other.to_string() if len(_other) else "(none)")
print()

def _share_table(df, by):
    t = df.groupby(by).size().rename("reverts").to_frame()
    t["pct"] = (100 * t["reverts"] / t["reverts"].sum()).round(2)
    return t.sort_values("reverts", ascending=False)

print("=== Failure surface (all reverts) ===")
print(_share_table(gf, "surface").to_string())
print("\n=== Failure surface x version ===")
piv = gf.pivot_table(index="surface", columns="version", values="tx_hash",
                     aggfunc="count", fill_value=0)
piv["total"] = piv.sum(axis=1)
print(piv.sort_values("total", ascending=False).to_string())

print("\n=== Top-15 raw revert reasons ===")
print(_share_table(gf, "revert_reason").head(15).to_string())

# Persist for the paper.
_share_table(gf, "surface").to_csv(RQ1_OUT / "rq1_failure_surface.csv")
piv.sort_values("total", ascending=False).to_csv(RQ1_OUT / "rq1_failure_surface_by_version.csv")
_share_table(gf, "revert_reason").to_csv(RQ1_OUT / "rq1_revert_reasons.csv")
print(f"\n[saved] -> {RQ1_OUT}/rq1_failure_surface*.csv, rq1_revert_reasons.csv")


# All revert reasons, clustered by the §6.1 failure-surface map (see the
# `REASON_BUCKET` cell above). This is the full enumeration behind the top-15
# table: every distinct revert_reason, its count/share, and the surface bucket
# it collapses into. Reasons with no mapping land in "Other / unknown" and are
# flagged here so the catch-all stays auditable.
all_reasons = (
    gf.groupby("revert_reason")
      .agg(reverts=("tx_hash", "size"), surface=("surface", lambda s: s.mode().iat[0]))
      .sort_values("reverts", ascending=False)
)
all_reasons["pct"]    = (100 * all_reasons["reverts"] / all_reasons["reverts"].sum()).round(3)
all_reasons["mapped"] = all_reasons["surface"].ne("Other / unknown")

n_map, n_unmap = int(all_reasons["mapped"].sum()), int((~all_reasons["mapped"]).sum())
print(f"Distinct revert reasons: {len(all_reasons)}  (mapped: {n_map}, unmapped: {n_unmap})\n")

with pd.option_context("display.max_rows", None, "display.width", 160):
    print("=== All revert reasons (by frequency) ===")
    print(all_reasons[["reverts", "pct", "surface"]].to_string())

# Cluster-level rollup: share of each failure surface + how many distinct
# reason strings collapse into it.
cluster = (
    gf.groupby("surface")
      .agg(reverts=("tx_hash", "size"), n_reasons=("revert_reason", "nunique"))
      .sort_values("reverts", ascending=False)
)
cluster["pct"] = (100 * cluster["reverts"] / cluster["reverts"].sum()).round(2)
print("\n=== Clustered by failure surface ===")
print(cluster[["reverts", "pct", "n_reasons"]].to_string())

all_reasons.to_csv(RQ1_OUT / "rq1_all_revert_reasons.csv")
print(f"\n[saved] -> {RQ1_OUT}/rq1_all_revert_reasons.csv")


# ======================================================================
# ## §6.2 — Affected markets, users, and order patterns
# 
# We attach Gamma market metadata to each ghost fill via `token_id` (V1) / `condition_id` (V2) — both join at 100% coverage — and report which markets, events, and categories concentrate ghost fills, plus the NegRisk-vs-binary split. The user-level rollup uses `results/rq1_participants.parquet` when present; otherwise it reports a best-effort count from the partial participant fields in `rule_result` and flags the gap.
# ======================================================================


try:
    # Attach market metadata and roll up by market / event / category.
    mv1 = pd.read_parquet(PATHS["market_map_v1"])
    mv2 = pd.read_parquet(PATHS["market_map_v2"])
    
    KEEP = ["slug", "question", "neg_risk", "event_id", "event_title",
            "event_tags", "volume_num", "liquidity_num",
            "rewards_min_size", "rewards_max_spread"]
    m1 = (mv1.assign(join_key=mv1["token_id"].astype(str))
             .drop_duplicates("join_key")[["join_key"] + KEEP])
    m2 = (mv2.assign(join_key=mv2["condition_id"].astype(str).str.lower())
             .drop_duplicates("join_key")[["join_key"] + KEEP])
    mkt = pd.concat([m1, m2], ignore_index=True).drop_duplicates("join_key")
    
    gfm = gf.merge(mkt, on="join_key", how="left")
    cov = gfm["slug"].notna().mean()
    print(f"Market-metadata join coverage: {cov:.3%}  ({gfm['slug'].notna().sum():,}/{len(gfm):,})")
    
    print(f"\nDistinct markets hit: {gfm['slug'].nunique():,} | distinct events: {gfm['event_id'].nunique():,}")
    print("\nNegRisk vs binary (by ghost-fill count):")
    print(gfm.groupby(gfm["neg_risk"].fillna('unknown')).size().rename("reverts").to_string())
    
    print("\n=== Top-20 markets by ghost-fill count ===")
    top_mkt = (gfm.groupby(["slug", "event_title"])
                  .agg(reverts=("tx_hash", "count"),
                       at_risk_usd=("affected_amount", lambda s: s[s < 1e9].sum()),
                       neg_risk=("neg_risk", "first"),
                       volume=("volume_num", "first"))
                  .sort_values("reverts", ascending=False).head(20))
    print(top_mkt.to_string())
    
    print("\n=== Top-15 events by ghost-fill count ===")
    top_ev = (gfm.groupby("event_title").agg(reverts=("tx_hash","count"),
                  markets=("slug","nunique")).sort_values("reverts", ascending=False).head(15))
    print(top_ev.to_string())
    
    # Category via event_tags (list column; market_tags is empty in Gamma) -> explode.
    tags = gfm[["tx_hash", "event_tags"]].copy()
    tags["event_tags"] = tags["event_tags"].apply(
        lambda x: list(x) if isinstance(x, (list, tuple, np.ndarray)) else [])
    tag_counts = (tags.explode("event_tags").dropna(subset=["event_tags"])
                      .groupby("event_tags").size().rename("reverts")
                      .sort_values(ascending=False).head(25))
    print("\n=== Top-25 event tags (categories) ===")
    print(tag_counts.to_string())
    
    top_mkt.to_csv(RQ1_OUT / "rq1_top_markets.csv")
    top_ev.to_csv(RQ1_OUT / "rq1_top_events.csv")
    tag_counts.to_csv(RQ1_OUT / "rq1_top_tags.csv")
    print(f"\n[saved] -> {RQ1_OUT}/rq1_top_markets.csv, rq1_top_events.csv, rq1_top_tags.csv")
except FileNotFoundError as _e:
    print(f"[skip] needs market_mappings parquet (regenerate via rq1/condition_mappings_v1.py): {_e}")


# Affected users — full analysis from the per-tx participant decode.
import glob as _glob
PARTS = sorted(_glob.glob(str(RESULTS / "rq1" / "participants_parts" / "*.parquet")))
PART_FILE = RESULTS / "rq1_participants.parquet"

if not PARTS and not PART_FILE.exists():
    print("[partial] no participant decode found -> run rq1/decode_participants.py")
else:
    # Light scalar load for the whole population; iterate for the heavy list cols.
    SCALAR = ["tx_hash", "version", "taker_maker", "taker_signer", "taker_side",
              "num_makers", "n_participants", "taker_fill", "maker_fill_total", "decoded"]
    src_files = PARTS if PARTS else [str(PART_FILE)]
    pt = pd.concat([pd.read_parquet(f, columns=SCALAR) for f in src_files], ignore_index=True)
    pt = pt[pt["decoded"]].copy()
    print(f"Decoded reverts: {len(pt):,} (of {len(gf):,} total)")

    # --- distinct participants: accumulate sets per file to bound memory ---
    takers, makers = set(), set()
    for f in src_files:
        d = pd.read_parquet(f, columns=["taker_maker", "maker_makers", "decoded"])
        d = d[d["decoded"]]
        takers.update(a for a in d["taker_maker"].dropna().values)
        for lst in d["maker_makers"].values:
            if lst is not None:
                makers.update(lst)
    everyone = takers | makers
    print(f"\nDistinct taker accounts : {len(takers):,}")
    print(f"Distinct maker accounts : {len(makers):,}")
    print(f"Distinct participants   : {len(everyone):,}  (taker ∪ maker)")

    # --- order patterns ---
    print(f"\nTaker side (0=BUY, 1=SELL):")
    print((pt["taker_side"].value_counts(normalize=True).mul(100).round(1)
              .rename("pct").to_string()))
    print(f"\nMakers matched per ghost fill (num_makers):")
    print(pt["num_makers"].describe(percentiles=[.5, .9, .99]).round(2).to_string())

    # --- concentration: are ghost fills hitting a few takers or the whole market? ---
    tm = pt["taker_maker"].value_counts()
    print(f"\nGhost-fill concentration by taker account ({len(tm):,} distinct takers):")
    for n in (10, 100, 1000):
        print(f"  top-{n:<4} takers = {100*tm.head(n).sum()/tm.sum():5.1f}% of decoded reverts")

    # --- top affected accounts (by ghost-fill count, taker side) ---
    top_takers = (pt.groupby("taker_maker")
                    .agg(reverts=("tx_hash", "count"),
                         versions=("version", "nunique"))
                    .sort_values("reverts", ascending=False).head(20))
    print("\n=== Top-20 taker accounts by ghost-fill count ===")
    print(top_takers.to_string())

    # persist
    tm.head(2000).rename("reverts").to_frame().to_csv(RQ1_OUT / "rq1_taker_revert_counts_top2000.csv")
    top_takers.to_csv(RQ1_OUT / "rq1_top_takers.csv")
    pd.Series({"distinct_takers": len(takers), "distinct_makers": len(makers),
               "distinct_participants": len(everyone),
               "decoded_reverts": len(pt)}).to_csv(RQ1_OUT / "rq1_user_summary.csv")
    print(f"\n[saved] -> {RQ1_OUT}/rq1_user_summary.csv, rq1_top_takers.csv, rq1_taker_revert_counts_top2000.csv")


# ======================================================================
# ## §6.3 — Estimated financial impact
# 
# `affected_amount` is the collateral at stake in a ghost fill, in human USDC.e/pUSD units (both 6-decimals, ≈ \$1). A handful of V1 rows carry overflow garbage (≈1e71) from malformed calldata; we drop values above a sanity cap before summing. We report the at-risk distribution (the long-tail percentile view) and, separately, the **operator gas burned** on these doomed settlements — a direct platform-side cost.
# ======================================================================


# Estimated financial impact.
#
# Collateral at risk = the full USD value the match promised to move, read
# directly from the engine's `affected_amount` (taker + Σ maker fills, in human
# USDC/pUSD; the corrected results parquets carry both legs in USD). The only
# cleanup is dropping a few rows whose on-chain calldata carried uint256-overflow
# amounts (garbage test traffic, not a decode error) — a single real Polymarket
# match never approaches the cap below.
SANITY_CAP = 1e7  # USD; real max match is ~$2.8M, the overflow rows sit at >= 3e12

clean = gf[gf["affected_amount"].between(0, SANITY_CAP, inclusive="right")].copy()
dropped = int(len(gf) - len(clean))
print(f"Dropped {dropped} overflow-garbage rows (>= {SANITY_CAP:.0e}); {len(clean):,} remain.")
imp = clean.rename(columns={"affected_amount": "usd"})

print("\n=== Collateral at risk (USD, taker + maker legs) — distribution by version ===")
dist = imp.groupby("version")["usd"].describe(percentiles=[.5, .75, .9, .99, .999]).round(2)
dist["sum"] = imp.groupby("version")["usd"].sum().round(0)
print(dist.to_string())
total_usd = imp["usd"].sum()
print(f"\nTotal collateral at risk: ${total_usd:,.0f}")
print(f"Largest single ghosted match: ${imp['usd'].max():,.0f}")
print("Overall percentiles (USD):")
print(imp["usd"].describe(percentiles=[.5, .75, .9, .99, .999]).round(2).to_string())

print("\n=== Operator gas burned on reverted settlements ===")
pol = gf["gas_fee_gwei"].fillna(0) / 1e9   # gwei -> POL (Polygon gas token)
print(f"Total gas burned: {pol.sum():,.2f} POL across {len(gf):,} reverts "
      f"(mean {pol.mean():.4f} POL/tx, median {pol.median():.4f} POL/tx)")
print("NOTE: multiply by the POL/USD rate at tx time for a USD figure (not applied here).")
print("\nGas burned by version (POL):")
print((gf.groupby("version")["gas_fee_gwei"].sum() / 1e9).round(2).to_string())

dist.to_csv(RQ1_OUT / "rq1_collateral_at_risk.csv")
print(f"\n[saved] -> {RQ1_OUT}/rq1_collateral_at_risk.csv")


# Fig 1 — Daily reverted-matchOrders volume (single area, no failure-surface
# split), with three trend overlays. Four series share two physical spines, each
# split into vertical bands (no extra offset axes — ticks sit on the borders):
#   LEFT  (counts) : reverted matchOrders (area) -> bottom 70% | total matchOrders -> top 30%
#   RIGHT          : revert rate (dashed)        -> bottom 40% | affected collateral -> top 30%
import math
import matplotlib.dates as mdates
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

START = pd.Timestamp("2025-08-21")

# --- (1) reverted matchOrders per day (one gf row = one ghost fill) ---
reverts = gf.loc[gf["day"] >= START].groupby("day").size()
days = pd.date_range(START, reverts.index.max(), freq="D")
reverts = reverts.reindex(days, fill_value=0)

# --- (2) total matchOrders + daily revert rate (Dune daily totals) ---
_CSV = REPO_ROOT / "rq1" / "dune_daily_matchorders_total_20250815_20260506.csv"
_tot = pd.read_csv(_CSV)
_tot["day"] = pd.to_datetime(_tot["day_utc"])
total = _tot.set_index("day")["total_tx"].reindex(days).interpolate(limit_direction="both")
rate_pct = 100 * reverts / total                                  # daily revert rate (%)
total_s = total.rolling(1, center=True, min_periods=1).mean()

# --- (3) affected collateral per day, from the engine's affected_amount ---
# Full USD collateral the match promised to move (taker + Σ maker legs); drop the
# uint256-overflow garbage rows, sum per day, then smooth into a trend line.
COLL_CAP, ROLL = 1e7, 1
coll = (gf.loc[gf["affected_amount"].between(0, COLL_CAP, inclusive="right")]
            .groupby("day")["affected_amount"].sum().reindex(days, fill_value=0))
coll_s = coll.rolling(ROLL, center=True, min_periods=1).mean()

# --- band-mapping: place a series into vertical fraction [lo, hi] of an axes ---
def _band(axis, vmin, vmax, lo, hi):
    span = (vmax - vmin) / (hi - lo)
    axis.set_ylim(vmin - lo * span, vmin - lo * span + span)

C_REVERT = PALETTE["colors"][0]      # blue
C_TOTAL  = PALETTE["accent"]         # dark slate
C_RATE   = "#B22222"                 # red
C_COLL   = "#E69F00"                 # amber
B_REV  = (0.0, 0.70)                 # reverts        -> bottom 70% (left)
B_RATE = (0.0, 0.40)                 # revert rate    -> bottom 40% (right)
B_TOP  = (0.72, 0.99)                # total / collateral -> top ~30%

sns.set_theme(style="white", rc={"font.family": "serif",
                                 "font.size": mpl.rcParams["font.size"]})

fig, ax = plt.subplots(figsize=(6.4, 3.2))

# LEFT-bottom: reverted matchOrders — area, log scale from 10^3 (cf. RQ2 fig).
FLOOR_REV = 1e3
ax.set_yscale("log")
_rev_y = np.clip(reverts.values.astype(float), FLOOR_REV, None)
ax.fill_between(days, FLOOR_REV, _rev_y, color=C_REVERT, alpha=0.25, linewidth=0, zorder=2)
ax.plot(days, _rev_y, color=C_REVERT, linewidth=1.0, zorder=3)
# Place the [10^3, max] log range into the bottom 70% band (log-space _band).
_lo, _hi = math.log10(FLOOR_REV), math.log10(float(reverts.max()))
_span = (_hi - _lo) / (B_REV[1] - B_REV[0])
ax.set_ylim(10 ** (_lo - B_REV[0] * _span), 10 ** (_lo - B_REV[0] * _span + _span))
# Decade ticks within the data range.
_yt = [10 ** e for e in range(int(_lo), int(math.floor(_hi)) + 1)]
ax.set_yticks(_yt)
ax.set_yticklabels([f"{t/1e3:.0f}k" for t in _yt])
ax.set_ylabel("Reverts [log]", color=C_REVERT, fontsize=9, loc="bottom")
ax.tick_params(axis="y", labelsize=8, colors=C_REVERT)

# LEFT-top: total matchOrders — ticks on the same left border (no offset spine).
ax_tot = ax.twinx()
ax_tot.yaxis.set_label_position("left"); ax_tot.yaxis.set_ticks_position("left")
ax_tot.plot(days, total_s.values, color=C_TOTAL, linewidth=1.0, alpha=0.9, zorder=4)
_band(ax_tot, float(total_s.min()), float(total_s.max()), *B_TOP)
_tt = np.linspace(float(total_s.min()), float(total_s.max()), 2)
ax_tot.set_yticks(_tt)
ax_tot.set_yticklabels([f"{t/1e6:.1f}M" for t in _tt])
ax_tot.set_ylabel("Total", color=C_TOTAL, fontsize=9, loc="top")
ax_tot.tick_params(axis="y", labelsize=7.5, colors=C_TOTAL)

# RIGHT-bottom: revert rate — dashed trend, bottom 40%.
ax_rate = ax.twinx()
ax_rate.plot(days, rate_pct.values, color=C_RATE, linewidth=0.9, linestyle="--",
             alpha=0.85, zorder=6)
_band(ax_rate, 0, float(rate_pct.max()), *B_RATE)
_rrt = np.linspace(0, float(rate_pct.max()), 3)
ax_rate.set_yticks(_rrt)
ax_rate.set_yticklabels([f"{v:.0f}%" for v in _rrt])
ax_rate.set_ylabel("Revert Rate", color=C_RATE, rotation=270, labelpad=10,
                   fontsize=9, y=0.2)
ax_rate.tick_params(axis="y", labelsize=7.5, colors=C_RATE)
ax_rate.spines["right"].set_color(C_RATE)

# RIGHT-top: affected collateral — ticks on the same right border, top 30%.
ax_coll = ax.twinx()
ax_coll.plot(days, coll_s.values, color=C_COLL, linewidth=1.2, zorder=5)
_band(ax_coll, 0, float(coll_s.max()), *B_TOP)
_ct = np.linspace(0, float(coll_s.max()), 2)
ax_coll.set_yticks(_ct)
ax_coll.set_yticklabels([f"${t/1e6:.0f}M" for t in _ct])
ax_coll.set_ylabel("Affected collateral", color=C_COLL, rotation=270, labelpad=8,
                   fontsize=9, y=0.72)
ax_coll.tick_params(axis="y", labelsize=7.5, colors=C_COLL)

# V2 cutover marker.
cutover = V2_CUTOVER.tz_convert(None).to_pydatetime()
ax.axvline(cutover, color="#222222", linestyle="--", linewidth=0.7, alpha=0.7, zorder=7)
ax.text(cutover, 0.62, "V2 cutover ", fontsize=7.5, va="top", ha="right",
        color="#222222", transform=ax.get_xaxis_transform())

# X axis — monthly ticks at daily resolution.
ax.xaxis.set_major_locator(mdates.MonthLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
ax.xaxis.set_minor_locator(mdates.MonthLocator())
ax.tick_params(axis="x", labelsize=8.5)
ax.set_xlim(START, days.max()); ax.margins(x=0)
ax.set_axisbelow(True)
ax.grid(True, which="major", color="#bbbbbb", linewidth=0.6, alpha=0.8, zorder=0)
for s in ax.spines.values():
    s.set_visible(True); s.set_linewidth(0.6)

# Single-row legend above the axes.
handles = [
    Patch(facecolor=mpl.colors.to_rgba(C_REVERT, 0.25), edgecolor=C_REVERT,
          label="Reverted matchOrders"),
    Line2D([0], [0], color=C_TOTAL, lw=1.0, label="Total matchOrders"),
    Line2D([0], [0], color=C_RATE, lw=0.9, ls="--", label="Revert rate"),
    Line2D([0], [0], color=C_COLL, lw=1.2, label="Affected collateral"),
]
fig.tight_layout(rect=[0, 0, 1, 0.92])
fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.98),
           ncol=4, frameon=False, fontsize=7, columnspacing=1.2, handletextpad=0.5)

fig.savefig(str(REPO_ROOT / "results" / "rq1" / "rq1_reverts_daily.pdf"), bbox_inches="tight")
plt.show()

