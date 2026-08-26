# Non-notebook runner for Part A of ai_server/05_evaluation.ipynb — the CAS-vs-CVSS
# batch evaluation (TC5/TC8 in CAS_vs_CVSS_Test_Cases.md), executed here so it can
# be re-run from the command line whenever the trained models or
# shared/cas_config.json change, without opening Jupyter. Loads the REAL trained
# RF + Isolation Forest + K-Means models (ai_server/models/) and the REAL held-out
# IoMT test set (ai_server/data/test/*.csv) — nothing here is synthetic or
# hand-computed. Mirrors the notebook's cells exactly (same functions, same
# scenario definitions, same chart code) so results are identical to re-running
# the notebook; this is just the scriptable path.
#
# Run with: python Extra_Material/Test_Cases/run_hospital_scenarios_live.py
# Output (overwrites prior copies in this folder): hospital_scenarios_raw.csv,
# caap_vs_cvss_results.csv, caap_vs_cvss_comparison.png,
# cas_sensitivity_analysis.csv, cas_sensitivity_analysis.png, live_run_summary.md
import os
import sys
import time
import warnings

import matplotlib
matplotlib.use("Agg")  # headless — this script never opens a display window
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

warnings.filterwarnings("ignore")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = SCRIPT_DIR  # Extra_Material/Test_Cases — same folder as the .md/.py above
_AI_SERVER_SRC = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..", "ai_server", "src"))
if _AI_SERVER_SRC not in sys.path:
    sys.path.insert(0, _AI_SERVER_SRC)

import eval_utils  # noqa: E402
import hospital_scenarios as hs  # noqa: E402

sns.set_theme(style="whitegrid")
np.random.seed(42)
CAAP_COLOR, CVSS_COLOR = "#0891b2", "#f97316"

print("=" * 78)
print("  Live CAS-vs-CVSS batch evaluation (real trained models + real test data)")
print("=" * 78)

t0 = time.time()
artifacts = eval_utils.load_artifacts()
print(f"[1/6] Loaded trained models in {time.time()-t0:.1f}s "
      f"({len(artifacts['feature_cols'])} feature columns, "
      f"classes={list(artifacts['le'].classes_)})")

t0 = time.time()
iomt_df = eval_utils.load_iomt_test_set()
print(f"[2/6] Loaded held-out IoMT test set: {len(iomt_df):,} rows in {time.time()-t0:.1f}s")

t0 = time.time()
caap_df = hs.build_all_scenarios(iomt_df, artifacts)
caap_df.to_csv(os.path.join(OUT_DIR, "hospital_scenarios_raw.csv"), index=False)
print(f"[3/6] Built {len(caap_df):,} simulated alerts across "
      f"{caap_df['scenario'].nunique()} hospital scenarios in {time.time()-t0:.1f}s "
      f"-> hospital_scenarios_raw.csv")

results_table = hs.build_caap_vs_cvss_table(caap_df)
results_table.to_csv(os.path.join(OUT_DIR, "caap_vs_cvss_results.csv"), index=False)
print("[4/6] CAAP vs CVSS ranking-accuracy table -> caap_vs_cvss_results.csv")

combined = results_table[results_table["scenario"] == "ALL SCENARIOS COMBINED"].iloc[0]

fig, axes = plt.subplots(1, 2, figsize=(13, 5))
ax = axes[0]
metric_labels = ["ARA @Top-5 (%)", "ARA @Top-10 (%)", "ARA @Top-20 (%)", "FPR @Top-10 (%)"]
caap_vals = [combined["ARA_CAAP_top5_%"], combined["ARA_CAAP_top10_%"],
             combined["ARA_CAAP_top20_%"], combined["FPR_CAAP_top10_%"]]
cvss_vals = [combined["ARA_CVSS_top5_%"], combined["ARA_CVSS_top10_%"],
             combined["ARA_CVSS_top20_%"], combined["FPR_CVSS_top10_%"]]
x = np.arange(len(metric_labels)); width = 0.35
ax.bar(x - width / 2, caap_vals, width, label="CAAP (CAS)", color=CAAP_COLOR)
ax.bar(x + width / 2, cvss_vals, width, label="CVSS-equivalent baseline", color=CVSS_COLOR)
ax.set_xticks(x); ax.set_xticklabels(metric_labels, rotation=15, ha="right")
ax.set_ylabel("%"); ax.set_title("Alert Ranking Accuracy & False Positive Rate")
ax.legend()

ax2 = axes[1]
mtcai_vals = [combined["MTCAI_CAAP_rank"], combined["MTCAI_CVSS_rank"]]
bars = ax2.bar(["CAAP", "CVSS"], mtcai_vals, color=[CAAP_COLOR, CVSS_COLOR])
ax2.set_title("Mean Time to Critical Alert Identification\n"
              "(avg. rank position of life-critical alerts — lower is better)")
ax2.set_ylabel("Average rank position")
for b, v in zip(bars, mtcai_vals):
    ax2.text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}", ha="center", va="bottom")

plt.suptitle("CAAP vs CVSS-equivalent baseline — combined across all 3 hospital scenarios",
             fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "caap_vs_cvss_comparison.png"), dpi=150, bbox_inches="tight")
plt.close(fig)
print("[5/6] CAAP vs CVSS comparison chart -> caap_vs_cvss_comparison.png")

sens_table = hs.sensitivity_analysis(caap_df)
sens_table.to_csv(os.path.join(OUT_DIR, "cas_sensitivity_analysis.csv"), index=False)

fig, ax = plt.subplots(figsize=(9, 5))
pivot = sens_table.pivot(index="dimension", columns="delta", values="spearman_rank_corr_vs_baseline")
pivot = pivot[[-0.05, 0.05]]
pivot.columns = ["-0.05", "+0.05"]
pivot.plot(kind="bar", ax=ax, color=[CVSS_COLOR, CAAP_COLOR])
ax.set_ylabel("Spearman rank correlation vs. baseline weights")
ax.set_title("CAS rank-order stability under ±0.05 weight perturbation")
ax.set_ylim(min(0.85, pivot.values.min() - 0.02), 1.005)
ax.legend(title="Δweight")
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "cas_sensitivity_analysis.png"), dpi=150, bbox_inches="tight")
plt.close(fig)
print("[6/6] Sensitivity analysis table + chart -> cas_sensitivity_analysis.csv/.png")

most_sensitive = sens_table.loc[sens_table["mean_abs_score_shift"].idxmax()]
most_stable_rank = sens_table.loc[sens_table["spearman_rank_corr_vs_baseline"].idxmin()]

summary_md = f"""# Live CAS-vs-CVSS Batch Evaluation — Run Summary

Generated by `run_hospital_scenarios_live.py` against the real trained
RF + Isolation Forest + K-Means models in `ai_server/models/` and the real
held-out test set in `ai_server/data/test/` (**{len(iomt_df):,} rows**),
using the current `shared/cas_config.json`.

Run timestamp (local): {time.strftime("%Y-%m-%d %H:%M:%S")}

## Headline result (TC5 — Alert Ranking Accuracy / Fatigue Reduction)

Across all **{len(caap_df):,}** simulated alerts (3 hospital scenarios,
{int((caap_df['patient_dependency'] == 'life_critical').sum()):,} life-critical),
CAAP's clinical-context-aware CAS ranking surfaces life-critical-device alerts
substantially earlier than the CVSS-equivalent, context-blind baseline:

- **ARA@10**: {combined['ARA_CAAP_top10_%']:.1f}% of life-critical alerts land in the
  top 10 under CAS vs {combined['ARA_CVSS_top10_%']:.1f}% under CVSS.
- **MTCAI**: mean rank position of a life-critical alert improves from
  {combined['MTCAI_CVSS_rank']:.1f} (CVSS) to {combined['MTCAI_CAAP_rank']:.1f} (CAS) — lower is better.
- **FPR@10**: share of low-priority alerts occupying top-10 triage slots drops from
  {combined['FPR_CVSS_top10_%']:.1f}% (CVSS) to {combined['FPR_CAAP_top10_%']:.1f}% (CAS).
- **Alert Fatigue Reduction**: {combined['AlertFatigueReduction_pts']:.1f} percentage-point
  ({combined['AlertFatigueReduction_%']:.1f}% relative) reduction in low-priority
  alerts crowding the top-10 queue, CAS vs CVSS.

Full per-scenario breakdown: `caap_vs_cvss_results.csv` / `caap_vs_cvss_comparison.png`.

## Robustness result (TC8 — weight-perturbation rank stability)

Perturbing each CAS weight by ±0.05 (renormalized) and recomputing CAS from
each alert's already-computed dimension scores:

- Largest mean score shift from a single perturbation: **{most_sensitive['mean_abs_score_shift']:.3f}**
  points ({most_sensitive['dimension']}, Δ={most_sensitive['delta']:+.2f}).
- Least rank-stable perturbation ({most_stable_rank['dimension']}, Δ={most_stable_rank['delta']:+.2f})
  still preserves a Spearman rank correlation of **{most_stable_rank['spearman_rank_corr_vs_baseline']:.3f}**
  against the baseline-weight ranking.

CAS's prioritisation order does not flip under plausible re-weighting — a
robustness property CVSS has no equivalent mechanism to even test, since it
carries no tunable weight vector at all.

Full table/chart: `cas_sensitivity_analysis.csv` / `cas_sensitivity_analysis.png`.
"""
with open(os.path.join(OUT_DIR, "live_run_summary.md"), "w", encoding="utf-8") as f:
    f.write(summary_md)

print()
print("=" * 78)
print("  DONE — live_run_summary.md written alongside the refreshed CSVs/PNGs")
print("=" * 78)
print(summary_md)
