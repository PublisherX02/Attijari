"""e8_statistical_tests.py -- Experiment 8: Statistical Significance Tests

Research Question:
    Are the observed performance differences between trust configurations
    statistically significant, and how robust are the reported metrics?

Analyses performed:
    1. Bootstrap 95% Confidence Intervals for accuracy, precision, recall, F1
       across all 4 E6 configurations (10,000 resamples).
    2. McNemar's Test for pairwise comparison of configuration predictions
       (6 pairs from 4 configs).
    3. Bootstrap CIs for Corpus Validation results (overall + per-source).
    4. Cohen's Kappa for inter-configuration agreement.

Output: data/experiments/e8_statistical_tests/
  - bootstrap_ci.png        (forest plot with CI error bars)
  - mcnemar_significance.png (heatmap of p-values)
  - corpus_ci.png           (CI for corpus validation)
  - results_<ts>.json
  - statistical_tests_<ts>.tex
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from itertools import combinations
from pathlib import Path
from typing import Any

# Allow running as standalone script or as module
_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from experiments.shared import (
    get_output_dir,
    paper_style,
    COLORS,
    save_results,
    save_latex,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXPERIMENT_NAME = "e8_statistical_tests"

CONFIG_KEYS = ["llm_only", "flat", "trust_hierarchy", "full_pipeline"]
CONFIG_NAMES = {
    "llm_only": "LLM Only",
    "flat": "LLM + Signals (Flat)",
    "trust_hierarchy": "LLM + Signals (Trust Hierarchy)",
    "full_pipeline": "Full Pipeline (Production)",
}
CONFIG_COLORS = {
    "llm_only": "#e74c3c",
    "flat": "#e67e22",
    "trust_hierarchy": "#2ecc71",
    "full_pipeline": "#3498db",
}

METRICS = ["accuracy", "precision", "recall", "f1"]
METRIC_LABELS = {"accuracy": "Accuracy", "precision": "Precision",
                 "recall": "Recall", "f1": "F1"}

N_BOOTSTRAP = 10_000
CI_ALPHA = 0.05  # 95% CI

_ROOT = Path(__file__).resolve().parent.parent.parent
EXPERIMENTS_DIR = _ROOT / "data" / "experiments"


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def _find_latest_json(directory: Path, prefix: str) -> Path:
    """Find the most recent JSON file matching a prefix in a directory."""
    candidates = sorted(directory.glob(f"{prefix}*.json"))
    if not candidates:
        raise FileNotFoundError(
            f"No {prefix}*.json files found in {directory}")
    return candidates[-1]


def load_e6_results(path: Path | None = None) -> dict:
    """Load E6 trust hierarchy results."""
    if path is None:
        e6_dir = EXPERIMENTS_DIR / "e6_trust_hierarchy"
        path = _find_latest_json(e6_dir, "results_")
    print(f"  [LOAD] E6 results: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_corpus_validation(path: Path | None = None) -> dict:
    """Load corpus validation results."""
    if path is None:
        cv_dir = EXPERIMENTS_DIR / "corpus_validation"
        path = _find_latest_json(cv_dir, "corpus_validation_")
    print(f"  [LOAD] Corpus validation: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Bootstrap helpers
# ---------------------------------------------------------------------------

def _compute_metric(y_true: np.ndarray, y_pred: np.ndarray,
                    metric: str) -> float:
    """Compute a single metric from binary arrays (1=malicious, 0=benign)."""
    if metric == "accuracy":
        return float(np.mean(y_true == y_pred))
    # For precision, recall, f1: positive class = malicious = 1
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    if metric == "precision":
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0
    if metric == "recall":
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if metric == "f1":
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    raise ValueError(f"Unknown metric: {metric}")


def bootstrap_ci(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    metric: str,
    n_bootstrap: int = N_BOOTSTRAP,
    alpha: float = CI_ALPHA,
    rng: np.random.Generator | None = None,
) -> dict:
    """Compute bootstrap confidence interval for a metric.

    Returns dict with keys: point, ci_low, ci_high, std, samples.
    """
    if rng is None:
        rng = np.random.default_rng(42)

    n = len(y_true)
    point = _compute_metric(y_true, y_pred, metric)

    boot_values = np.empty(n_bootstrap)
    for i in range(n_bootstrap):
        idx = rng.integers(0, n, size=n)
        boot_values[i] = _compute_metric(y_true[idx], y_pred[idx], metric)

    ci_low = float(np.percentile(boot_values, 100 * alpha / 2))
    ci_high = float(np.percentile(boot_values, 100 * (1 - alpha / 2)))

    return {
        "point": point,
        "ci_low": ci_low,
        "ci_high": ci_high,
        "std": float(np.std(boot_values)),
        "n_bootstrap": n_bootstrap,
    }


# ---------------------------------------------------------------------------
# McNemar's test
# ---------------------------------------------------------------------------

def mcnemar_test(correct_a: np.ndarray, correct_b: np.ndarray) -> dict:
    """McNemar's test comparing two classifiers.

    correct_a, correct_b: boolean arrays indicating correct predictions.
    Returns dict with b, c (discordant counts), chi2, p_value, method.
    """
    # b = A correct, B wrong; c = A wrong, B correct
    b = int(np.sum(correct_a & ~correct_b))
    c = int(np.sum(~correct_a & correct_b))

    if b + c == 0:
        return {"b": b, "c": c, "chi2": 0.0, "p_value": 1.0,
                "method": "no_discordance", "significant": False}

    # Use exact binomial test if discordant count < 25
    if b + c < 25:
        try:
            from scipy.stats import binom_test  # type: ignore
            p_value = binom_test(b, b + c, 0.5)
        except ImportError:
            # Manual two-sided binomial test using normal approximation
            p_value = _manual_binom_test(b, b + c)
        method = "exact_binomial"
        chi2 = float((b - c) ** 2) / (b + c)
    else:
        # Chi-squared with continuity correction
        chi2 = float((abs(b - c) - 1) ** 2) / (b + c)
        try:
            from scipy.stats import chi2 as chi2_dist  # type: ignore
            p_value = float(1 - chi2_dist.cdf(chi2, df=1))
        except ImportError:
            p_value = _manual_chi2_p(chi2)
        method = "chi2_continuity"

    return {
        "b": b,
        "c": c,
        "chi2": chi2,
        "p_value": p_value,
        "method": method,
        "significant": p_value < 0.05,
    }


def _manual_binom_test(k: int, n: int) -> float:
    """Two-sided binomial test p-value (fallback without scipy)."""
    from math import comb
    # P(X <= k) + P(X >= n-k) under H0: p=0.5
    p = 0.0
    threshold = comb(n, k) * (0.5 ** n)
    for i in range(n + 1):
        prob = comb(n, i) * (0.5 ** n)
        if prob <= threshold + 1e-12:
            p += prob
    return min(p, 1.0)


def _manual_chi2_p(x: float) -> float:
    """Approximate chi2(df=1) survival function (fallback without scipy)."""
    # Use complementary error function approximation
    import math
    if x <= 0:
        return 1.0
    # chi2(1) survival = 2 * Phi(-sqrt(x))
    z = math.sqrt(x)
    # Abramowitz and Stegun approximation for erfc
    t = 1.0 / (1.0 + 0.3275911 * z / math.sqrt(2))
    coeffs = [0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429]
    poly = sum(c * t ** (i + 1) for i, c in enumerate(coeffs))
    erfc_val = poly * math.exp(-z * z / 2)
    return max(0.0, min(1.0, erfc_val))


# ---------------------------------------------------------------------------
# Cohen's Kappa
# ---------------------------------------------------------------------------

def cohens_kappa(pred_a: np.ndarray, pred_b: np.ndarray) -> float:
    """Compute Cohen's Kappa between two sets of predictions."""
    n = len(pred_a)
    if n == 0:
        return 0.0
    # Observed agreement
    po = float(np.mean(pred_a == pred_b))
    # Expected agreement by chance
    a1 = np.mean(pred_a == 1)
    a0 = 1 - a1
    b1 = np.mean(pred_b == 1)
    b0 = 1 - b1
    pe = float(a1 * b1 + a0 * b0)
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


# ---------------------------------------------------------------------------
# Extract arrays from E6 data
# ---------------------------------------------------------------------------

def _extract_arrays(per_config: dict) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """Extract (y_true, y_pred) binary arrays for each config.

    Returns dict of config_key -> (y_true, y_pred) where 1=malicious, 0=benign.
    """
    result = {}
    for cfg_key in CONFIG_KEYS:
        if cfg_key not in per_config:
            continue
        outcomes = per_config[cfg_key]
        y_true = np.array([1 if o["expected"] == "malicious" else 0
                           for o in outcomes])
        y_pred = np.array([1 if o["verdict_binary"] == "malicious" else 0
                           for o in outcomes])
        result[cfg_key] = (y_true, y_pred)
    return result


# ---------------------------------------------------------------------------
# Analysis 1: Bootstrap CIs for E6 configurations
# ---------------------------------------------------------------------------

def run_bootstrap_analysis(per_config: dict) -> dict:
    """Compute bootstrap CIs for all metrics across all configs."""
    arrays = _extract_arrays(per_config)
    rng = np.random.default_rng(42)

    results = {}
    for cfg_key, (y_true, y_pred) in arrays.items():
        cfg_results = {}
        for metric in METRICS:
            ci = bootstrap_ci(y_true, y_pred, metric, rng=rng)
            cfg_results[metric] = ci
            print(f"    {CONFIG_NAMES[cfg_key]:40s} | {metric:10s}: "
                  f"{ci['point']:.3f} [{ci['ci_low']:.3f}, {ci['ci_high']:.3f}]")
        results[cfg_key] = cfg_results
    return results


# ---------------------------------------------------------------------------
# Analysis 2: McNemar's pairwise tests
# ---------------------------------------------------------------------------

def run_mcnemar_analysis(per_config: dict) -> dict:
    """Run McNemar's test for all pairs of configurations."""
    arrays = _extract_arrays(per_config)
    available = [k for k in CONFIG_KEYS if k in arrays]

    pairwise = {}
    for cfg_a, cfg_b in combinations(available, 2):
        y_true_a, y_pred_a = arrays[cfg_a]
        y_true_b, y_pred_b = arrays[cfg_b]

        # Both configs should have same y_true (same corpus)
        correct_a = (y_true_a == y_pred_a)
        correct_b = (y_true_b == y_pred_b)

        result = mcnemar_test(correct_a, correct_b)
        pair_key = f"{cfg_a}_vs_{cfg_b}"
        pairwise[pair_key] = result

        sig_marker = "*" if result["significant"] else ""
        print(f"    {CONFIG_NAMES[cfg_a]:30s} vs {CONFIG_NAMES[cfg_b]:30s}: "
              f"p={result['p_value']:.4f}{sig_marker} "
              f"(b={result['b']}, c={result['c']}, method={result['method']})")

    return pairwise


# ---------------------------------------------------------------------------
# Analysis 3: Bootstrap CIs for corpus validation
# ---------------------------------------------------------------------------

def run_corpus_validation_ci(cv_data: dict) -> dict:
    """Compute bootstrap CIs for corpus validation results."""
    per_email = cv_data.get("per_email", [])
    if not per_email:
        print("  [WARN] No per_email data in corpus validation results")
        return {}

    rng = np.random.default_rng(42)

    # Overall
    y_true = np.array([1 if e["expected"] == "malicious" else 0
                       for e in per_email])
    y_pred = np.array([1 if e["predicted"] == "malicious" else 0
                       for e in per_email])

    overall = {}
    print("  Overall corpus validation CIs:")
    for metric in METRICS:
        ci = bootstrap_ci(y_true, y_pred, metric, rng=rng)
        overall[metric] = ci
        print(f"    {metric:10s}: {ci['point']:.3f} "
              f"[{ci['ci_low']:.3f}, {ci['ci_high']:.3f}]")

    # Per source
    sources = sorted(set(e.get("source", "unknown") for e in per_email))
    per_source = {}
    for source in sources:
        source_emails = [e for e in per_email if e.get("source") == source]
        if len(source_emails) < 5:
            print(f"  [SKIP] {source}: only {len(source_emails)} samples, "
                  f"too few for bootstrap")
            continue

        yt = np.array([1 if e["expected"] == "malicious" else 0
                       for e in source_emails])
        yp = np.array([1 if e["predicted"] == "malicious" else 0
                       for e in source_emails])

        source_cis = {}
        print(f"  {source} CIs:")
        for metric in METRICS:
            ci = bootstrap_ci(yt, yp, metric, rng=rng)
            source_cis[metric] = ci
            print(f"    {metric:10s}: {ci['point']:.3f} "
                  f"[{ci['ci_low']:.3f}, {ci['ci_high']:.3f}]")
        per_source[source] = source_cis

    return {"overall": overall, "per_source": per_source}


# ---------------------------------------------------------------------------
# Analysis 4: Cohen's Kappa
# ---------------------------------------------------------------------------

def run_kappa_analysis(per_config: dict) -> dict:
    """Compute Cohen's Kappa for all pairs of configurations."""
    arrays = _extract_arrays(per_config)
    available = [k for k in CONFIG_KEYS if k in arrays]

    kappa_results = {}
    for cfg_a, cfg_b in combinations(available, 2):
        _, pred_a = arrays[cfg_a]
        _, pred_b = arrays[cfg_b]
        k = cohens_kappa(pred_a, pred_b)
        pair_key = f"{cfg_a}_vs_{cfg_b}"
        kappa_results[pair_key] = k
        print(f"    {CONFIG_NAMES[cfg_a]:30s} vs {CONFIG_NAMES[cfg_b]:30s}: "
              f"kappa={k:.4f}")

    return kappa_results


# ---------------------------------------------------------------------------
# Plot 1: Forest plot -- Bootstrap CIs
# ---------------------------------------------------------------------------

def _plot_bootstrap_ci(bootstrap_results: dict, output_dir: Path) -> None:
    paper_style()
    fig, axes = plt.subplots(1, len(METRICS), figsize=(16, 5), sharey=True)

    available_cfgs = [k for k in CONFIG_KEYS if k in bootstrap_results]
    y_positions = np.arange(len(available_cfgs))

    for ax_idx, metric in enumerate(METRICS):
        ax = axes[ax_idx]
        for i, cfg_key in enumerate(available_cfgs):
            ci = bootstrap_results[cfg_key][metric]
            point = ci["point"]
            low = ci["ci_low"]
            high = ci["ci_high"]
            color = CONFIG_COLORS[cfg_key]

            # Error bar
            ax.errorbar(
                point, i,
                xerr=[[point - low], [high - point]],
                fmt="o", color=color, ecolor=color,
                elinewidth=2.0, capsize=5, capthick=1.5,
                markersize=8, markeredgecolor="black", markeredgewidth=0.5,
                zorder=5,
            )
            # Annotate value
            ax.text(
                high + 0.008, i,
                f"{point:.3f}",
                va="center", fontsize=8, color=color,
            )

        ax.set_xlabel(METRIC_LABELS[metric], fontsize=11, fontweight="bold")
        ax.set_yticks(y_positions)
        if ax_idx == 0:
            ax.set_yticklabels(
                [CONFIG_NAMES[k] for k in available_cfgs], fontsize=9)
        ax.axvline(x=1.0, color="gray", linestyle="--", linewidth=0.5,
                   alpha=0.5)
        ax.set_xlim(
            max(0, min(bootstrap_results[k][metric]["ci_low"]
                       for k in available_cfgs) - 0.05),
            1.05,
        )
        ax.grid(axis="x", alpha=0.3, linewidth=0.5)

    fig.suptitle(
        "Bootstrap 95% Confidence Intervals by Configuration\n"
        "(10,000 resamples, percentile method)",
        fontweight="bold", fontsize=13,
    )
    plt.tight_layout(rect=[0, 0, 1, 0.92])
    out = output_dir / "bootstrap_ci.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Plot 2: McNemar significance heatmap
# ---------------------------------------------------------------------------

def _plot_mcnemar_heatmap(
    mcnemar_results: dict,
    kappa_results: dict,
    output_dir: Path,
) -> None:
    paper_style()
    available_cfgs = [k for k in CONFIG_KEYS]
    n = len(available_cfgs)

    # Build p-value matrix (lower triangle) and kappa matrix (upper triangle)
    p_matrix = np.ones((n, n))
    kappa_matrix = np.full((n, n), np.nan)

    for i, cfg_a in enumerate(available_cfgs):
        for j, cfg_b in enumerate(available_cfgs):
            if i == j:
                continue
            pair_key = f"{cfg_a}_vs_{cfg_b}"
            pair_key_rev = f"{cfg_b}_vs_{cfg_a}"
            # p-values (symmetric)
            if pair_key in mcnemar_results:
                p_matrix[i][j] = mcnemar_results[pair_key]["p_value"]
                p_matrix[j][i] = mcnemar_results[pair_key]["p_value"]
            elif pair_key_rev in mcnemar_results:
                p_matrix[i][j] = mcnemar_results[pair_key_rev]["p_value"]
                p_matrix[j][i] = mcnemar_results[pair_key_rev]["p_value"]
            # kappa
            if pair_key in kappa_results:
                kappa_matrix[i][j] = kappa_results[pair_key]
                kappa_matrix[j][i] = kappa_results[pair_key]
            elif pair_key_rev in kappa_results:
                kappa_matrix[i][j] = kappa_results[pair_key_rev]
                kappa_matrix[j][i] = kappa_results[pair_key_rev]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Left: p-value heatmap
    import matplotlib.colors as mcolors
    # Custom colormap: green (significant) to red (not significant)
    cmap_p = plt.cm.RdYlGn_r  # type: ignore[attr-defined]
    labels_short = [CONFIG_NAMES[k].split("(")[0].strip()
                    for k in available_cfgs]

    mask_diag = np.eye(n, dtype=bool)
    p_display = np.ma.array(p_matrix, mask=mask_diag)

    im1 = ax1.imshow(p_display, cmap=cmap_p, vmin=0, vmax=1, aspect="auto")
    ax1.set_xticks(range(n))
    ax1.set_yticks(range(n))
    ax1.set_xticklabels(labels_short, rotation=45, ha="right", fontsize=8)
    ax1.set_yticklabels(labels_short, fontsize=8)
    ax1.set_title("McNemar's Test p-values\n(p < 0.05 = significant difference)",
                  fontweight="bold", fontsize=11)

    # Annotate cells
    for i in range(n):
        for j in range(n):
            if i == j:
                ax1.text(j, i, "--", ha="center", va="center",
                         fontsize=9, color="gray")
            else:
                p = p_matrix[i][j]
                sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "ns"
                color = "white" if p < 0.3 else "black"
                ax1.text(j, i, f"{p:.3f}\n{sig}", ha="center", va="center",
                         fontsize=8, color=color, fontweight="bold")

    plt.colorbar(im1, ax=ax1, shrink=0.8, label="p-value")

    # Right: Kappa heatmap
    kappa_display = np.ma.array(kappa_matrix, mask=mask_diag)
    im2 = ax2.imshow(kappa_display, cmap="YlGnBu", vmin=0, vmax=1,
                     aspect="auto")
    ax2.set_xticks(range(n))
    ax2.set_yticks(range(n))
    ax2.set_xticklabels(labels_short, rotation=45, ha="right", fontsize=8)
    ax2.set_yticklabels(labels_short, fontsize=8)
    ax2.set_title("Cohen's Kappa (Inter-Configuration Agreement)",
                  fontweight="bold", fontsize=11)

    for i in range(n):
        for j in range(n):
            if i == j:
                ax2.text(j, i, "--", ha="center", va="center",
                         fontsize=9, color="gray")
            elif not np.isnan(kappa_matrix[i][j]):
                k_val = kappa_matrix[i][j]
                # Interpret kappa
                if k_val >= 0.81:
                    interp = "almost\nperfect"
                elif k_val >= 0.61:
                    interp = "substantial"
                elif k_val >= 0.41:
                    interp = "moderate"
                elif k_val >= 0.21:
                    interp = "fair"
                else:
                    interp = "slight"
                color = "white" if k_val > 0.6 else "black"
                ax2.text(j, i, f"{k_val:.3f}\n({interp})",
                         ha="center", va="center", fontsize=7, color=color)

    plt.colorbar(im2, ax=ax2, shrink=0.8, label="Kappa")

    plt.tight_layout()
    out = output_dir / "mcnemar_significance.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Plot 3: Corpus validation CIs
# ---------------------------------------------------------------------------

def _plot_corpus_ci(corpus_ci: dict, output_dir: Path) -> None:
    paper_style()

    overall = corpus_ci.get("overall", {})
    per_source = corpus_ci.get("per_source", {})

    if not overall:
        print("  [SKIP] No corpus CI data to plot")
        return

    # Combine: overall + per-source, one subplot per metric
    sources = ["Overall"] + sorted(per_source.keys())
    n_sources = len(sources)

    fig, axes = plt.subplots(1, len(METRICS), figsize=(16, max(4, n_sources * 0.6 + 2)),
                             sharey=True)

    source_colors = [COLORS[0]] + [COLORS[(i + 1) % len(COLORS)]
                                    for i in range(len(per_source))]
    y_positions = np.arange(n_sources)

    for ax_idx, metric in enumerate(METRICS):
        ax = axes[ax_idx]

        for i, source in enumerate(sources):
            if source == "Overall":
                ci = overall.get(metric)
            else:
                ci = per_source.get(source, {}).get(metric)

            if ci is None:
                continue

            point = ci["point"]
            low = ci["ci_low"]
            high = ci["ci_high"]
            color = source_colors[i]

            ax.errorbar(
                point, i,
                xerr=[[point - low], [high - point]],
                fmt="s" if source == "Overall" else "o",
                color=color, ecolor=color,
                elinewidth=2.0, capsize=5, capthick=1.5,
                markersize=9 if source == "Overall" else 7,
                markeredgecolor="black", markeredgewidth=0.5,
                zorder=5,
            )
            ax.text(
                high + 0.01, i,
                f"{point:.3f}",
                va="center", fontsize=8, color=color,
            )

        ax.set_xlabel(METRIC_LABELS[metric], fontsize=11, fontweight="bold")
        ax.set_yticks(y_positions)
        if ax_idx == 0:
            ax.set_yticklabels(sources, fontsize=9)
        ax.axvline(x=1.0, color="gray", linestyle="--", linewidth=0.5,
                   alpha=0.5)
        # Dynamic x-axis range
        all_lows = []
        for source in sources:
            ci_data = overall.get(metric) if source == "Overall" else per_source.get(source, {}).get(metric)
            if ci_data:
                all_lows.append(ci_data["ci_low"])
        ax.set_xlim(max(0, min(all_lows) - 0.08) if all_lows else 0, 1.08)
        ax.grid(axis="x", alpha=0.3, linewidth=0.5)

        # Horizontal line separating overall from sources
        if n_sources > 1:
            ax.axhline(y=0.5, color="gray", linestyle=":", linewidth=0.8,
                       alpha=0.5)

    fig.suptitle(
        "Corpus Validation: Bootstrap 95% Confidence Intervals\n"
        "(Overall and per data source)",
        fontweight="bold", fontsize=13,
    )
    plt.tight_layout(rect=[0, 0, 1, 0.92])
    out = output_dir / "corpus_ci.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# LaTeX output
# ---------------------------------------------------------------------------

def _build_latex(
    bootstrap_results: dict,
    mcnemar_results: dict,
    kappa_results: dict,
    corpus_ci: dict,
) -> list[str]:
    """Build a comprehensive LaTeX document with all statistical results."""
    lines = []

    # Table 1: Bootstrap CIs for E6 configurations
    lines += [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Bootstrap 95\% Confidence Intervals by Configuration (10,000 resamples)}",
        r"\label{tab:e8_bootstrap_ci}",
        r"\begin{tabular}{l c c c c}",
        r"\hline",
        r"Configuration & Accuracy & Precision & Recall & F1 \\",
        r"\hline",
    ]
    for cfg_key in CONFIG_KEYS:
        if cfg_key not in bootstrap_results:
            continue
        name = CONFIG_NAMES[cfg_key].replace("&", r"\&")
        cells = []
        for metric in METRICS:
            ci = bootstrap_results[cfg_key][metric]
            cells.append(
                f"{ci['point']:.3f} [{ci['ci_low']:.3f}, {ci['ci_high']:.3f}]"
            )
        lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    lines += [r"\hline", r"\end{tabular}", r"\end{table}", ""]

    # Table 2: McNemar's test results
    lines += [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{McNemar's Test: Pairwise Configuration Comparisons}",
        r"\label{tab:e8_mcnemar}",
        r"\begin{tabular}{l l r r r c}",
        r"\hline",
        r"Config A & Config B & $b$ & $c$ & $p$-value & Sig. \\",
        r"\hline",
    ]
    for pair_key, result in mcnemar_results.items():
        parts = pair_key.split("_vs_")
        name_a = CONFIG_NAMES.get(parts[0], parts[0]).replace("&", r"\&")
        name_b = CONFIG_NAMES.get(parts[1], parts[1]).replace("&", r"\&")
        sig = r"$\ast$" if result["significant"] else "ns"
        lines.append(
            f"{name_a} & {name_b} & "
            f"{result['b']} & {result['c']} & "
            f"{result['p_value']:.4f} & {sig} \\\\"
        )
    lines += [r"\hline", r"\end{tabular}", r"\end{table}", ""]

    # Table 3: Cohen's Kappa
    lines += [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Cohen's Kappa: Inter-Configuration Agreement}",
        r"\label{tab:e8_kappa}",
        r"\begin{tabular}{l l r l}",
        r"\hline",
        r"Config A & Config B & $\kappa$ & Interpretation \\",
        r"\hline",
    ]
    for pair_key, kappa in kappa_results.items():
        parts = pair_key.split("_vs_")
        name_a = CONFIG_NAMES.get(parts[0], parts[0]).replace("&", r"\&")
        name_b = CONFIG_NAMES.get(parts[1], parts[1]).replace("&", r"\&")
        if kappa >= 0.81:
            interp = "Almost Perfect"
        elif kappa >= 0.61:
            interp = "Substantial"
        elif kappa >= 0.41:
            interp = "Moderate"
        elif kappa >= 0.21:
            interp = "Fair"
        else:
            interp = "Slight"
        lines.append(f"{name_a} & {name_b} & {kappa:.4f} & {interp} \\\\")
    lines += [r"\hline", r"\end{tabular}", r"\end{table}", ""]

    # Table 4: Corpus validation CIs (if available)
    overall = corpus_ci.get("overall", {})
    per_source = corpus_ci.get("per_source", {})
    if overall:
        lines += [
            r"\begin{table}[h]",
            r"\centering",
            r"\caption{Corpus Validation: Bootstrap 95\% Confidence Intervals}",
            r"\label{tab:e8_corpus_ci}",
            r"\begin{tabular}{l c c c c}",
            r"\hline",
            r"Source & Accuracy & Precision & Recall & F1 \\",
            r"\hline",
        ]
        # Overall row
        cells = []
        for metric in METRICS:
            ci = overall.get(metric, {})
            if ci:
                cells.append(
                    f"{ci['point']:.3f} [{ci['ci_low']:.3f}, {ci['ci_high']:.3f}]")
            else:
                cells.append("--")
        lines.append(r"\textbf{Overall} & " + " & ".join(cells) + r" \\")
        lines.append(r"\hline")

        # Per source
        for source, source_cis in per_source.items():
            cells = []
            for metric in METRICS:
                ci = source_cis.get(metric, {})
                if ci:
                    cells.append(
                        f"{ci['point']:.3f} [{ci['ci_low']:.3f}, {ci['ci_high']:.3f}]")
                else:
                    cells.append("--")
            safe_name = source.replace("_", r"\_")
            lines.append(f"{safe_name} & " + " & ".join(cells) + r" \\")

        lines += [r"\hline", r"\end{tabular}", r"\end{table}"]

    return lines


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment 8 -- Statistical Significance Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--e6-results", type=str, default=None,
        help="Path to E6 results JSON (default: latest in data/experiments/e6_trust_hierarchy/)",
    )
    parser.add_argument(
        "--corpus-results", type=str, default=None,
        help="Path to corpus validation JSON (default: latest in data/experiments/corpus_validation/)",
    )
    parser.add_argument(
        "--n-bootstrap", type=int, default=N_BOOTSTRAP,
        help=f"Number of bootstrap resamples (default: {N_BOOTSTRAP})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    print("=" * 64)
    print("Experiment 8 -- Statistical Significance Tests")
    print("=" * 64)
    print(f"  Bootstrap resamples: {args.n_bootstrap}")

    global N_BOOTSTRAP
    N_BOOTSTRAP = args.n_bootstrap

    output_dir = get_output_dir(EXPERIMENT_NAME)

    # ---------------------------------------------------------------
    # Load data
    # ---------------------------------------------------------------
    print()
    print("Loading experiment data...")
    e6_path = Path(args.e6_results) if args.e6_results else None
    e6_data = load_e6_results(e6_path)

    cv_path = Path(args.corpus_results) if args.corpus_results else None
    try:
        cv_data = load_corpus_validation(cv_path)
    except FileNotFoundError as exc:
        print(f"  [WARN] {exc} -- skipping corpus validation CIs")
        cv_data = None

    per_config = e6_data["per_config"]
    meta = e6_data.get("meta", {})
    print(f"  E6 corpus: {meta.get('n_emails', '?')} emails "
          f"({meta.get('n_malicious', '?')} malicious, "
          f"{meta.get('n_benign', '?')} benign)")

    # ---------------------------------------------------------------
    # Analysis 1: Bootstrap CIs for E6
    # ---------------------------------------------------------------
    print()
    print("-" * 64)
    print("Analysis 1: Bootstrap 95% Confidence Intervals (E6)")
    print("-" * 64)
    bootstrap_results = run_bootstrap_analysis(per_config)

    # ---------------------------------------------------------------
    # Analysis 2: McNemar's Test
    # ---------------------------------------------------------------
    print()
    print("-" * 64)
    print("Analysis 2: McNemar's Test (pairwise)")
    print("-" * 64)
    mcnemar_results = run_mcnemar_analysis(per_config)

    # ---------------------------------------------------------------
    # Analysis 3: Corpus validation CIs
    # ---------------------------------------------------------------
    corpus_ci: dict = {}
    if cv_data:
        print()
        print("-" * 64)
        print("Analysis 3: Bootstrap CIs for Corpus Validation")
        print("-" * 64)
        corpus_ci = run_corpus_validation_ci(cv_data)

    # ---------------------------------------------------------------
    # Analysis 4: Cohen's Kappa
    # ---------------------------------------------------------------
    print()
    print("-" * 64)
    print("Analysis 4: Cohen's Kappa (inter-configuration agreement)")
    print("-" * 64)
    kappa_results = run_kappa_analysis(per_config)

    # ---------------------------------------------------------------
    # Save raw results
    # ---------------------------------------------------------------
    print()
    print("Saving results...")
    all_results = {
        "experiment": EXPERIMENT_NAME,
        "timestamp": datetime.now().isoformat(),
        "n_bootstrap": N_BOOTSTRAP,
        "e6_source": str(e6_path or "latest"),
        "corpus_source": str(cv_path or "latest"),
        "meta": meta,
        "bootstrap_ci": {
            cfg_key: {
                metric: {k: v for k, v in ci.items()}
                for metric, ci in cfg_cis.items()
            }
            for cfg_key, cfg_cis in bootstrap_results.items()
        },
        "mcnemar": mcnemar_results,
        "cohens_kappa": kappa_results,
        "corpus_validation_ci": corpus_ci,
    }
    save_results(all_results, output_dir, "results")

    # ---------------------------------------------------------------
    # Visualisations
    # ---------------------------------------------------------------
    print()
    print("Generating visualisations...")
    _plot_bootstrap_ci(bootstrap_results, output_dir)
    _plot_mcnemar_heatmap(mcnemar_results, kappa_results, output_dir)
    if corpus_ci:
        _plot_corpus_ci(corpus_ci, output_dir)

    # ---------------------------------------------------------------
    # LaTeX tables
    # ---------------------------------------------------------------
    print()
    print("Generating LaTeX tables...")
    latex_lines = _build_latex(
        bootstrap_results, mcnemar_results, kappa_results, corpus_ci)
    save_latex(latex_lines, output_dir, "statistical_tests")

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    print()
    print("=" * 64)
    print("Experiment 8 complete.")
    print(f"  Output dir: {output_dir}")
    print()

    # Print key findings
    print("Key findings:")
    for cfg_key in CONFIG_KEYS:
        if cfg_key not in bootstrap_results:
            continue
        f1 = bootstrap_results[cfg_key]["f1"]
        print(f"  {CONFIG_NAMES[cfg_key]:40s} F1={f1['point']:.3f} "
              f"[{f1['ci_low']:.3f}, {f1['ci_high']:.3f}]")

    sig_pairs = [k for k, v in mcnemar_results.items() if v["significant"]]
    if sig_pairs:
        print(f"\n  Significant differences (p<0.05): {len(sig_pairs)} of "
              f"{len(mcnemar_results)} pairs")
        for pair_key in sig_pairs:
            parts = pair_key.split("_vs_")
            print(f"    - {CONFIG_NAMES.get(parts[0], parts[0])} vs "
                  f"{CONFIG_NAMES.get(parts[1], parts[1])}: "
                  f"p={mcnemar_results[pair_key]['p_value']:.4f}")
    else:
        print(f"\n  No significant differences found among "
              f"{len(mcnemar_results)} pairs (p>=0.05)")


if __name__ == "__main__":
    main()
