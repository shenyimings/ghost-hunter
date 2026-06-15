"""RQ2 — Cancellation Attack vectors over time.

Extracted from scripts/statistic.ipynb (cells 16-27), with the minimal RQ1
preamble (Ghost-Fill loader `gf` + revert-rate `rate_pct`) inlined so it runs
standalone:
    uv run python rq2/rq2_analysis.py
from the artifact root. Reads results/all_v{1,2}.parquet and rq1/dune_daily_*.csv.
The per-vector market-mix cell needs results/market_mappings_v{1,2}.parquet
(regenerate via rq1/condition_mappings_v1.py); it is wrapped so the rest still runs.
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
# Paths are relative to repo root; this notebook lives in scripts/.
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
# RQ1 data preamble (loader + revert rate) — needed by the RQ2 figure
# ======================================================================
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


# --- shared preamble: revert-rate trend (rate_pct) reused by the RQ2 figure ---
# Mirrors the rate computation in the RQ1 Fig-1 cell so this script is standalone.
import seaborn as sns
_START = pd.Timestamp("2025-08-21")
reverts = gf.loc[gf["day"] >= _START].groupby("day").size()
days = pd.date_range(_START, reverts.index.max(), freq="D")
reverts = reverts.reindex(days, fill_value=0)
_CSV = REPO_ROOT / "rq1" / "dune_daily_matchorders_total_20250815_20260506.csv"
_tot = pd.read_csv(_CSV)
_tot["day"] = pd.to_datetime(_tot["day_utc"])
total = _tot.set_index("day")["total_tx"].reindex(days).interpolate(limit_direction="both")
rate_pct = 100 * reverts / total                                  # daily revert rate (%)


# ======================================================================
# # RQ2 — Cancellation Attack vectors over time
# 
# The RQ1 Fig 1 cut reverts by *failure surface* (the on-chain mechanism that failed). Here we re-cut the same daily volume by the **four attack vectors** GhostHunter attributes (`nonce_bump`, `balance_drain`, `approve_revoke`, `proxy_trap`), dropping the total-matchOrders reference line. The headline is the V1→V2 regime shift: `Nonce Bump` disappears at the cutover while the other three persist.
# ======================================================================


# RQ2 main figure (two-column): daily Cancellation-Attack volume by attack vector.
# Same overlapping log-scale silhouettes as Fig 1, coloured by the four attack
# vectors instead of failure surface, with the §6.1 revert-rate trend overlaid.
import math
import matplotlib.dates as mdates

RQ2_OUT = REPO_ROOT / "rq2" / "results"; RQ2_OUT.mkdir(parents=True, exist_ok=True)

ATTACK_VECTOR = {
    "nonce_bump":               "Nonce Bump",
    "balance_drain":            "Balance Drain",
    # "balance_drain_normal_gas": "Balance Drain",
    "approve_revoke":           "Allowance Revoke",
    "proxy_trap":               "Proxy Trap",
}
VECTOR_ORDER = ["Proxy Trap", "Balance Drain", "Allowance Revoke", "Nonce Bump"]

av = gf.copy()
av["vector"] = av["matched_rule"].map(ATTACK_VECTOR)
av = av[av["vector"].notna()]            # keep only the four attack vectors
print("Attack-vector counts:")
print(av["vector"].value_counts().to_string())

START = pd.Timestamp("2026-01-01")
av = av[av["day"] >= START]
daily_v = av.groupby(["day", "vector"]).size().unstack(fill_value=0)
daily_v = daily_v.reindex(pd.date_range(START, daily_v.index.max(), freq="D"), fill_value=0)
for v in VECTOR_ORDER:
    if v not in daily_v.columns:
        daily_v[v] = 0
daily_v = daily_v[VECTOR_ORDER]
sm_v = daily_v.rolling(window=1, center=True, min_periods=1).mean()

order_v = sm_v.sum().sort_values(ascending=False).index.tolist()   # largest behind
# colors_v = get_palette(len(order_v))
colors_v = sns.color_palette("muted", len(order_v))

FILL_ALPHA, EDGE_ALPHA, EDGE_WIDTH, FLOOR = 0.4, 0.75, 0.5, 100
fig, ax = plt.subplots(figsize=(3.5, 2.7))     # single column
for vec, color in zip(order_v, colors_v):
    x = sm_v.index.values
    y = np.clip(sm_v[vec].values, FLOOR, None)
    ax.fill_between(x, FLOOR, y, color=color, alpha=FILL_ALPHA, linewidth=0, zorder=2)
    ax.plot(x, y, color=color, alpha=EDGE_ALPHA, linewidth=EDGE_WIDTH,
            solid_joinstyle="round", solid_capstyle="round", label=vec, zorder=3)

ax.set_yscale("log")
data_max = float(np.nanmax(sm_v[VECTOR_ORDER].values))
hi_exp = 2 + (math.log10(data_max) - 2) / 0.99
ax.set_ylim(FLOOR, 10 ** hi_exp)
ax.set_yticks([10 ** e for e in range(2, int(math.floor(hi_exp)) + 1)])
ax.tick_params(axis="y", labelsize=7.5)
ax.tick_params(axis="x", labelsize=7.5)

ax.set_ylabel("Reverted matchOrders [log]",fontsize=8.5)

cutover = V2_CUTOVER.tz_convert(None).to_pydatetime()
ax.axvline(cutover, color="#222222", linestyle="--", linewidth=0.6, alpha=0.6, zorder=4)
ax.text(cutover, ax.get_ylim()[1] * 0.8, "V2 cutover ", fontsize=7, va="top", ha="right", color="#222222")

ax.xaxis.set_major_locator(mdates.MonthLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
ax.xaxis.set_minor_locator(mdates.MonthLocator())
ax.set_xlim(left=START, right=sm_v.index.max()); ax.margins(x=0)
ax.set_axisbelow(True)
ax.grid(True, which="major", color="#cccccc", linewidth=0.5, alpha=0.8, zorder=0)

# Right axis -- revert-rate trend (dashed red), bottom ~45% band. RAW DAILY so the
# true single-day peak (~8.5% on 2026-05-02) is visible; a 7-day mean would
# flatten it to ~5.8%.
ridx = sm_v.index
_rate_s = rate_pct.reindex(ridx)
Rmax = float(np.nanmax(_rate_s.values))
ax_rate = ax.twinx()
ax_rate.set_ylim(0, Rmax / 0.8)
ax_rate.plot(_rate_s.index, _rate_s.values, color="#B22222", linewidth=0.9,
             linestyle="--", alpha=0.8, zorder=6, label="Revert rate")
_rt = np.linspace(0, math.floor(Rmax) if Rmax >= 1 else Rmax, 3)
ax_rate.set_yticks(_rt)
ax_rate.set_yticklabels([f"{v:.0f}%" if Rmax >= 1 else f"{v:.1f}%" for v in _rt])
ax_rate.tick_params(axis="y", labelsize=7, colors="#B22222")
ax_rate.set_ylabel("Revert rate",rotation=270, labelpad=10,fontsize=8.5,color="#B22222")
ax_rate.spines["right"].set_color("#B22222")
ax_rate.margins(x=0)

# handles, labels = ax.get_legend_handles_labels()
# rh, rl = ax_rate.get_legend_handles_labels()
# handles += rh; labels += rl
# fig.tight_layout(rect=[0, 0, 1, 0.84])
# fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.95),
#            ncol=3, frameon=False, fontsize=6.5, columnspacing=1.0, handletextpad=0.4)

from matplotlib.patches import Patch
from matplotlib.colors import to_rgba


custom_handles = []
for vec, color in zip(order_v, colors_v):
    fc = to_rgba(color, alpha=FILL_ALPHA)  
    ec = to_rgba(color, alpha=EDGE_ALPHA)  
    p = Patch(facecolor=fc, edgecolor=ec, linewidth=EDGE_WIDTH, label=vec)
    custom_handles.append(p)

rh, rl = ax_rate.get_legend_handles_labels()
handles = custom_handles + rh
labels = [h.get_label() for h in custom_handles] + rl


for s in ax.spines.values():
    s.set_linewidth(0.6)
for s in ax_rate.spines.values():
    s.set_linewidth(0.6)  


fig.tight_layout(rect=[0, 0, 1, 0.84])
fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.95),
           ncol=3, frameon=False, fontsize=6.5, columnspacing=1.0, handletextpad=0.4)

fig.savefig(RQ2_OUT / "fig_attack_vectors_daily.pdf", bbox_inches="tight", pad_inches=0.02)
fig.savefig(str(REPO_ROOT / "rq2" / "results" / "rq2_reverts_daily.pdf"), bbox_inches="tight", pad_inches=0.02)
plt.show()




# RQ2 per-vector attribution table (counts / attackers / USD / market mix).
ATTACK = {"proxy_trap": "Proxy Trap", "nonce_bump": "Nonce Bump",
          "balance_drain": "Balance Drain", "approve_revoke": "Allowance Revoke"}
av2 = gf.copy()
av2["vector"] = av2["matched_rule"].map(ATTACK)
av2 = av2[av2["vector"].notna()].copy()

# join_key for market metadata (token_id on V1, lower-cased condition_id on V2)
key = np.where(av2["version"].eq("v1"),
               av2["token_id"].astype(str),
               av2["condition_id"].astype(str).str.lower())
av2["join_key"] = key

counts = av2.pivot_table(index="vector", columns="version", values="tx_hash",
                         aggfunc="size", fill_value=0)
counts["total"] = counts.sum(axis=1)

def _attacker(p):
    try: d = json.loads(p)
    except Exception: return None
    a = d.get("attacker"); 
    return (a[0] if a else None) if isinstance(a, list) else a
av2["attacker"] = av2["rule_result"].map(_attacker)
attackers = av2.groupby("vector")["attacker"].nunique()

# collateral (USD, taker + maker legs) straight from the corrected affected_amount
usd = (av2.loc[av2["affected_amount"].between(0, 1e7, inclusive="right")]
          .groupby("vector")["affected_amount"].sum())

summary = counts.join(attackers.rename("attackers")).join((usd/1e6).round(1).rename("usd_M"))
print("=== Per-vector summary (Table 2) ==="); print(summary.to_string())
print(f"\nAttack-attributed: {len(av2):,} / {len(gf):,} = {100*len(av2)/len(gf):.1f}%")
print(f"Total attack collateral: ${usd.sum():,.0f}")
print(f"proxy_trap side split:\n{av2[av2.vector=='Proxy Trap']['rule_result'].map(lambda p: json.loads(p).get('proxy_trap_side')).value_counts().to_string()}")


try:
    # Market-type distribution per vector (NegRisk share + crypto short-horizon tags).
    mv1 = pd.read_parquet(PATHS["market_map_v1"]); mv2 = pd.read_parquet(PATHS["market_map_v2"])
    mv1["join_key"] = mv1["token_id"].astype(str)
    mv2["join_key"] = mv2["condition_id"].astype(str).str.lower()
    COLS = ["join_key","neg_risk","event_tags"]
    mkt2 = pd.concat([mv1.drop_duplicates("join_key")[COLS],
                      mv2.drop_duplicates("join_key")[COLS]]).drop_duplicates("join_key")
    a3 = av2.merge(mkt2, on="join_key", how="left")
    
    def _has(tags, kw):
        try: return any(kw.lower() in str(t).lower() for t in tags)
        except TypeError: return False
    
    print("NegRisk share per vector (%):")
    print((100*a3.dropna(subset=["neg_risk"]).groupby("vector")["neg_risk"].mean()).round(1).to_string())
    
    rows = []
    tagged = a3[a3["event_tags"].notna()]
    for vec in ["Proxy Trap","Nonce Bump","Balance Drain","Allowance Revoke"]:
        sub = tagged[tagged["vector"].eq(vec)]
        rows.append({"vector": vec, "n": len(sub),
                     **{kw: round(100*sub["event_tags"].map(lambda t:_has(t,kw)).mean(),1)
                        for kw in ["Crypto","Up or Down","5M","Bitcoin"]}})
    print("\nCrypto short-horizon tag share per vector (%):")
    print(pd.DataFrame(rows).to_string(index=False))
    
    # baseline over ALL ghost fills
    gtag = gf.assign(join_key=key if False else (np.where(gf["version"].eq("v1"),
            gf["token_id"].astype(str), gf["condition_id"].astype(str).str.lower())))
    gtag = gtag.merge(mkt2, on="join_key", how="left")
    gt = gtag[gtag["event_tags"].notna()]
    print("\nBASELINE (all ghost fills):")
    print(f"  NegRisk {100*gtag.dropna(subset=['neg_risk'])['neg_risk'].mean():.1f}%  "
          + "  ".join(f"{kw} {100*gt['event_tags'].map(lambda t:_has(t,kw)).mean():.1f}%"
                      for kw in ["Crypto","5M"]))
except FileNotFoundError as _e:
    print(f"[skip] needs market_mappings parquet (regenerate via rq1/condition_mappings_v1.py): {_e}")



import json
import pandas as pd

_cols = ["matched_rule", "rule_result", "block_num", "timestamp", "tx_hash"]
_pt = pd.concat(
    [pd.read_parquet(str(REPO_ROOT / "results" / "all_v1.parquet"), columns=_cols),
     pd.read_parquet(str(REPO_ROOT / "results" / "all_v2.parquet"), columns=_cols)],
    ignore_index=True,
)
_pt = _pt[_pt["matched_rule"].eq("proxy_trap")].copy()
print(f"total proxy_trap reverts: {len(_pt):,}  (sanity expect 791,284)")

def _field(rr, k):
    try:
        return json.loads(rr).get(k)
    except Exception:
        return None

_pt["trapped_address"] = _pt["rule_result"].map(lambda r: _field(r, "trapped_address"))
_pt["attacker"]        = _pt["rule_result"].map(lambda r: _field(r, "attacker"))

# 1) Reverts per distinct trapped_address
_tc = _pt["trapped_address"].value_counts()
print(f"\n=== Reverts per distinct trapped_address ===")
print(f"distinct trapped addresses: {_tc.size:,}")
print(f"max: {int(_tc.iloc[0]):,} reverts -> {_tc.index[0]}")
print("top-10:")
print(_tc.head(10).to_string())

# 2) Reverts per distinct attacker
_ac = _pt["attacker"].value_counts()
print(f"\n=== Reverts per distinct attacker ===")
print(f"distinct attackers: {_ac.size:,}")
print(f"max: {int(_ac.iloc[0]):,} reverts -> {_ac.index[0]}")
print("top-10:")
print(_ac.head(10).to_string())

# 3) Burst for the single most destructive trap (top trapped_address)
_top = _tc.index[0]
_sub = _pt[_pt["trapped_address"].eq(_top)].copy()
_sub["ts"] = pd.to_datetime(_sub["timestamp"], utc=True)
_sub = _sub.sort_values(["block_num", "ts"]).reset_index(drop=True)

print(f"\n=== Burst analysis for top trap {_top} ===")
print(f"reverts attributed to this trap: {len(_sub):,}")
print(f"block range: {int(_sub['block_num'].min())} -> {int(_sub['block_num'].max())} "
      f"({int(_sub['block_num'].max() - _sub['block_num'].min())} blocks)")
print(f"wall-clock span: {_sub['ts'].min()} -> {_sub['ts'].max()} "
      f"(= {_sub['ts'].max() - _sub['ts'].min()})")

# busiest single block
_bb = _sub["block_num"].value_counts()
print(f"busiest single block: {int(_bb.index[0])} with {int(_bb.iloc[0])} reverts")

# busiest ~7-block (~14 s) sliding window over consecutive block heights
_counts = _sub["block_num"].value_counts().sort_index()
_bidx = _counts.index.values
_bval = _counts.values
_best, _best_win = 0, None
for _b0 in _bidx:
    _lo, _hi = _b0, _b0 + 6  # 7 consecutive block heights, inclusive
    _s = int(_bval[(_bidx >= _lo) & (_bidx <= _hi)].sum())
    if _s > _best:
        _best, _best_win = _s, (int(_lo), int(_hi))
_wsub = _sub[(_sub["block_num"] >= _best_win[0]) & (_sub["block_num"] <= _best_win[1])]
print(f"busiest 7-block window: {_best} reverts in blocks {_best_win[0]}-{_best_win[1]} "
      f"(span {_wsub['ts'].max() - _wsub['ts'].min()}, "
      f"{_wsub['ts'].min()} -> {_wsub['ts'].max()})")




import json, glob
from pathlib import Path
import pandas as pd
R = REPO_ROOT / "results"
def _att(p):
    try: d = json.loads(p)
    except Exception: return None
    a = d.get("attacker"); return (a[0] if a else None) if isinstance(a, list) else a
def _load(p, v):
    d = pd.read_parquet(p, columns=["tx_hash", "matched_rule", "rule_result"])
    d = d[d.matched_rule.isin(["balance_drain", "approve_revoke"])].copy()
    d["attacker"] = d.rule_result.map(_att); d["version"] = v
    return d[["tx_hash", "matched_rule", "attacker"]]
fnd = pd.concat([_load(R/"all_v1.parquet","v1"), _load(R/"all_v2.parquet","v2")], ignore_index=True)
parts = sorted(glob.glob(str(R/"rq1"/"participants_parts"/"*.parquet")))
cols = ["tx_hash","taker_maker","taker_signer","maker_makers","maker_signers"]
pp = pd.concat([pd.read_parquet(f, columns=cols) for f in parts], ignore_index=True).drop_duplicates("tx_hash")
m = fnd.merge(pp, on="tx_hash", how="left")
def _n(x): return str(x).lower() if x is not None else None
def _side(r):
    a = _n(r["attacker"])
    if a is None: return "no_attacker"
    tk = {_n(r["taker_maker"]), _n(r["taker_signer"])}
    mk = set()
    for c in ["maker_makers","maker_signers"]:
        v = r[c]
        if v is not None:
            try: mk |= {_n(x) for x in v}
            except TypeError: pass
    if a in tk and a not in mk: return "taker"
    if a in mk and a not in tk: return "maker"
    if a in tk and a in mk:     return "both"
    return "neither"
m["side"] = m.apply(_side, axis=1)
for rule in ["balance_drain","approve_revoke"]:
    s = m[m.matched_rule==rule]["side"].value_counts()
    tot = s.sum()
    print(f"{rule} (n={tot}):  taker {100*s.get('taker',0)/tot:.0f}%  maker {100*s.get('maker',0)/tot:.0f}%  "
          f"(raw {dict(s)})")
for addr,label in [("0x9dd9aea70b0f4aca6a3300ceb15c45a5029cae23","BD rep 0x9DD9"),
                   ("0x25399e01f2ca76e93dbde7d762fe45cf063f6739","AR rep 0x2539")]:
    sub = m[m.attacker.str.lower()==addr]
    print(f"{label}: n={len(sub)} sides={dict(sub.side.value_counts())}")



POL_USD = 0.098                      # POL price on 2026-05-06
ATTACK_RULES = {"nonce_bump", "balance_drain", "approve_revoke", "proxy_trap"}

_pol = gf["gas_fee_gwei"].fillna(0) / 1e9            # gwei -> POL, per tx
_mask = gf["matched_rule"].isin(ATTACK_RULES)

total_pol  = _pol.sum()
attack_pol = _pol[_mask].sum()

print(f"Total reverts          : {len(gf):,}")
print(f"Attack-attributed      : {_mask.sum():,}  ({100*_mask.sum()/len(gf):.2f}%)")
print()
print(f"Total gas burned       : {total_pol:,.2f} POL  = {total_pol/1e6:.4f} M  -> ${total_pol*POL_USD:,.0f}")
print(f"Attack gas burned      : {attack_pol:,.2f} POL  = {attack_pol/1e6:.4f} M  -> ${attack_pol*POL_USD:,.0f}")
print(f"Attack share of gas    : {100*attack_pol/total_pol:.2f}%")
print()
print("Per-vector POL (count, POL burned):")
print((gf.loc[_mask]
         .assign(pol=_pol[_mask])
         .groupby("matched_rule")["pol"].agg(["count", "sum"])
         .sort_values("sum", ascending=False)
         .to_string()))
print()
print(f"=> main.tex macro:  \\attackGasBurned = {attack_pol/1e6:.2f} M POL")
print(f"=> USD @ ${POL_USD}/POL = ${attack_pol*POL_USD:,.0f}")

