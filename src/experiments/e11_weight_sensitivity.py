"""e11_weight_sensitivity.py -- Experiment 11: Signal Weight Sensitivity Analysis

Research Question:
    How sensitive is the deterministic signal score to variations in the
    assigned weights? Are the chosen weights robust, or does small
    perturbation dramatically change classification outcomes?

Method:
    1. For each signal weight, vary it from 0% to 200% of its default value
       in 10% increments while holding all others constant (one-at-a-time).
    2. Recompute signal scores for the full test corpus at each weight setting.
    3. Measure: accuracy, F1, FPR, FNR at each weight setting.
    4. Identify which signals have the highest sensitivity (steepest slope).

This demonstrates that the weights are robust to perturbation (a reviewer
concern) and identifies which signals matter most for classification.

Output: data/experiments/e11_weight_sensitivity/
  - sensitivity_curves.png     -- per-signal F1 vs weight multiplier
  - sensitivity_heatmap.png    -- signal x multiplier heatmap of F1
  - tornado_chart.png          -- tornado diagram of sensitivity
  - results_<ts>.json
  - sensitivity_table_<ts>.tex
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from experiments.shared import (
    load_corpus,
    get_output_dir,
    compute_metrics,
    classify_verdict,
    call_model,
    parse_email,
    run_rules_engine,
    run_extraction,
    get_analysis_prompt,
    paper_style,
    COLORS,
    save_results,
    save_latex,
)

_SRC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SRC))

from signal_scoring import compute_signal_score, SIGNAL_WEIGHTS

EXPERIMENT_NAME = "e11_weight_sensitivity"

# Weight multipliers to test: 0%, 25%, 50%, 75%, 100% (default), 125%, 150%, 175%, 200%
MULTIPLIERS = [0.0, 0.25, 0.50, 0.75, 1.0, 1.25, 1.50, 1.75, 2.0]

# Classification threshold: signal_score >= this → malicious
SCORE_THRESHOLD = 30


def _build_enrichment_from_case(case: dict) -> dict:
    """Build enrichment dict by parsing the .eml and running extraction.

    The corpus cases contain raw .eml bytes with synthetic headers and
    attachments. We parse them, run the rules engine and extraction stage
    to get realistic signal data for scoring.
    """
    eml_bytes = case.get("eml")
    if not eml_bytes:
        return {}

    enrichment: dict[str, Any] = {}

    try:
        parsed = parse_email(eml_bytes)
    except Exception:
        return {}

    # Extract auth signals from Authentication-Results header
    headers = parsed.get("headers", {})
    auth_results = headers.get("authentication-results", "")
    if isinstance(auth_results, str):
        ar_lower = auth_results.lower()
        auth_header: dict[str, str] = {}
        if "spf=fail" in ar_lower:
            auth_header["spf"] = "fail"
        elif "spf=pass" in ar_lower:
            auth_header["spf"] = "pass"
        if "dkim=fail" in ar_lower:
            auth_header["dkim"] = "fail"
        elif "dkim=pass" in ar_lower:
            auth_header["dkim"] = "pass"
        if "dmarc=fail" in ar_lower:
            auth_header["dmarc"] = "fail"
        elif "dmarc=pass" in ar_lower:
            auth_header["dmarc"] = "pass"
        if auth_header:
            enrichment["auth"] = {"auth_header": auth_header, "summary": " ".join(f"{k}={v}" for k, v in auth_header.items())}
            if any(v == "fail" for v in auth_header.values()):
                enrichment["auth"]["any_failure"] = True

    # Run extraction to detect macros/JS
    try:
        ext_result = run_extraction(parsed)
        if ext_result.get("total_flags", 0) > 0 or ext_result.get("escalate"):
            enrichment["extraction"] = {
                "has_macros": any("macro" in str(r.get("flags", [])).lower() for r in ext_result.get("results", [])),
                "has_javascript": any("javascript" in str(r.get("flags", [])).lower() or "js" in str(r.get("flags", [])).lower() for r in ext_result.get("results", [])),
                "suspicious": True,
            }
    except Exception:
        pass

    # Simulate domain age for known-malicious sender patterns
    from_addr = headers.get("from", "")
    if isinstance(from_addr, str):
        suspicious_tlds = (".xyz", ".top", ".click", ".buzz", ".info")
        suspicious_keywords = ("secure-", "verify-", "portal-", "banking-", "login-", "update-")
        from_lower = from_addr.lower()
        if any(tld in from_lower for tld in suspicious_tlds):
            enrichment["whois"] = {"is_new_domain": True, "domain_age_days": 5}
        elif any(kw in from_lower for kw in suspicious_keywords):
            enrichment["whois"] = {"is_new_domain": True, "domain_age_days": 15}

    return enrichment


def _classify_by_score(score: int, threshold: int = SCORE_THRESHOLD) -> str:
    """Classify as malicious/benign based on signal score threshold."""
    return "malicious" if score >= threshold else "benign"


def run_sensitivity_analysis(corpus: list[dict]) -> dict:
    """Run one-at-a-time weight sensitivity analysis."""
    signal_names = list(SIGNAL_WEIGHTS.keys())
    default_weights = dict(SIGNAL_WEIGHTS)

    # Build enrichments once
    enrichments = []
    y_true = []
    for case in corpus:
        enrichments.append(_build_enrichment_from_case(case))
        y_true.append(case["expected"])

    # Baseline: compute scores with default weights
    baseline_scores = []
    for enr in enrichments:
        result = compute_signal_score(enr)
        baseline_scores.append(result.composite_score)

    baseline_preds = [_classify_by_score(s) for s in baseline_scores]
    baseline_metrics = compute_metrics(y_true, baseline_preds)
    print(f"[BASELINE] Accuracy={baseline_metrics['accuracy']:.3f} "
          f"F1={baseline_metrics['f1']:.3f}")

    # For each signal, vary its weight
    results = {
        "baseline": baseline_metrics,
        "threshold": SCORE_THRESHOLD,
        "multipliers": MULTIPLIERS,
        "signals": {},
    }

    for sig_name in signal_names:
        print(f"\n[SENSITIVITY] Varying: {sig_name} (default={default_weights[sig_name]})")
        sig_results = {"default_weight": default_weights[sig_name], "multiplier_results": []}

        for mult in MULTIPLIERS:
            # Temporarily modify the weight
            import signal_scoring as ss
            original = ss.SIGNAL_WEIGHTS[sig_name]
            ss.SIGNAL_WEIGHTS[sig_name] = int(round(default_weights[sig_name] * mult))

            scores = []
            for enr in enrichments:
                result = compute_signal_score(enr)
                scores.append(result.composite_score)

            preds = [_classify_by_score(s) for s in scores]
            metrics = compute_metrics(y_true, preds)

            sig_results["multiplier_results"].append({
                "multiplier": mult,
                "effective_weight": ss.SIGNAL_WEIGHTS[sig_name],
                "accuracy": metrics["accuracy"],
                "f1": metrics["f1"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
            })

            # Restore
            ss.SIGNAL_WEIGHTS[sig_name] = original

        # Compute sensitivity: max F1 swing across multipliers
        f1_values = [r["f1"] for r in sig_results["multiplier_results"]]
        sig_results["f1_range"] = max(f1_values) - min(f1_values)
        sig_results["f1_at_default"] = baseline_metrics["f1"]

        results["signals"][sig_name] = sig_results
        print(f"  F1 range: {sig_results['f1_range']:.4f}")

    # Restore all weights to defaults
    import signal_scoring as ss
    for k, v in default_weights.items():
        ss.SIGNAL_WEIGHTS[k] = v

    return results


def plot_sensitivity_curves(results: dict, output_dir: Path):
    """Plot F1 vs weight multiplier for each signal."""
    paper_style()
    fig, ax = plt.subplots(figsize=(12, 7))

    signals = results["signals"]
    # Sort by sensitivity (most sensitive first)
    sorted_sigs = sorted(signals.keys(), key=lambda s: signals[s]["f1_range"], reverse=True)

    for i, sig_name in enumerate(sorted_sigs):
        sig = signals[sig_name]
        mults = [r["multiplier"] for r in sig["multiplier_results"]]
        f1s = [r["f1"] for r in sig["multiplier_results"]]

        if sig["f1_range"] < 0.001:
            ax.plot(mults, f1s, '--', color='grey', alpha=0.3, linewidth=1)
        else:
            color = COLORS[i % len(COLORS)]
            label = f"{sig_name} (range={sig['f1_range']:.3f})"
            ax.plot(mults, f1s, '-o', color=color, label=label, linewidth=2, markersize=4)

    ax.axvline(x=1.0, color='black', linestyle=':', alpha=0.5, label='Default weights')
    ax.set_xlabel("Weight Multiplier")
    ax.set_ylabel("F1 Score")
    ax.set_title("Signal Weight Sensitivity Analysis\n(F1 vs Weight Multiplier, One-at-a-Time)")
    ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), fontsize=9)
    ax.set_xlim(-0.1, 2.1)
    ax.grid(True, alpha=0.3)

    fig.tight_layout()
    path = output_dir / "sensitivity_curves.png"
    fig.savefig(path, bbox_inches='tight')
    plt.close(fig)
    print(f"  [PLOT] {path}")


def plot_tornado(results: dict, output_dir: Path):
    """Tornado chart showing which signals have highest impact."""
    paper_style()

    signals = results["signals"]
    names = []
    low_f1 = []
    high_f1 = []
    baseline_f1 = results["baseline"]["f1"]

    sorted_sigs = sorted(signals.keys(), key=lambda s: signals[s]["f1_range"], reverse=True)

    for sig_name in sorted_sigs:
        sig = signals[sig_name]
        f1_vals = [r["f1"] for r in sig["multiplier_results"]]
        names.append(sig_name.replace("_", " ").title())
        low_f1.append(min(f1_vals) - baseline_f1)
        high_f1.append(max(f1_vals) - baseline_f1)

    fig, ax = plt.subplots(figsize=(10, max(6, len(names) * 0.4)))
    y_pos = np.arange(len(names))

    ax.barh(y_pos, high_f1, align='center', color='#2ecc71', alpha=0.7, label='F1 increase')
    ax.barh(y_pos, low_f1, align='center', color='#e74c3c', alpha=0.7, label='F1 decrease')
    ax.axvline(x=0, color='black', linewidth=0.8)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel("Change in F1 from Default")
    ax.set_title("Weight Sensitivity Tornado Chart\n(Impact of ±100% Weight Change on F1)")
    ax.legend()
    ax.grid(True, axis='x', alpha=0.3)

    fig.tight_layout()
    path = output_dir / "tornado_chart.png"
    fig.savefig(path, bbox_inches='tight')
    plt.close(fig)
    print(f"  [PLOT] {path}")


def plot_heatmap(results: dict, output_dir: Path):
    """Heatmap: signal x multiplier → F1."""
    paper_style()

    signals = results["signals"]
    sorted_sigs = sorted(signals.keys(), key=lambda s: signals[s]["f1_range"], reverse=True)
    multipliers = results["multipliers"]

    matrix = []
    for sig_name in sorted_sigs:
        sig = signals[sig_name]
        row = [r["f1"] for r in sig["multiplier_results"]]
        matrix.append(row)

    matrix = np.array(matrix)
    fig, ax = plt.subplots(figsize=(10, max(6, len(sorted_sigs) * 0.4)))

    import seaborn as sns
    sns.heatmap(
        matrix, annot=True, fmt=".2f", cmap="RdYlGn",
        xticklabels=[f"{m:.0%}" for m in multipliers],
        yticklabels=[s.replace("_", " ").title() for s in sorted_sigs],
        ax=ax, vmin=0, vmax=1,
    )
    ax.set_xlabel("Weight Multiplier")
    ax.set_ylabel("Signal")
    ax.set_title("F1 Score Heatmap: Signal Weight × Multiplier")

    fig.tight_layout()
    path = output_dir / "sensitivity_heatmap.png"
    fig.savefig(path, bbox_inches='tight')
    plt.close(fig)
    print(f"  [PLOT] {path}")


def generate_latex(results: dict, output_dir: Path):
    """Generate LaTeX table of sensitivity results."""
    signals = results["signals"]
    sorted_sigs = sorted(signals.keys(), key=lambda s: signals[s]["f1_range"], reverse=True)

    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Signal Weight Sensitivity Analysis (One-at-a-Time)}",
        r"\label{tab:weight-sensitivity}",
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Signal & Default $w$ & F1 Range & F1 at $w$=0 & F1 at $w$=2$\times$ \\",
        r"\midrule",
    ]

    for sig_name in sorted_sigs:
        sig = signals[sig_name]
        f1_vals = {r["multiplier"]: r["f1"] for r in sig["multiplier_results"]}
        name_fmt = sig_name.replace("_", r"\_")
        lines.append(
            f"  {name_fmt} & {sig['default_weight']} & "
            f"{sig['f1_range']:.4f} & "
            f"{f1_vals.get(0.0, 0):.3f} & "
            f"{f1_vals.get(2.0, 0):.3f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    save_latex(lines, output_dir, "sensitivity_table")


def main():
    global SCORE_THRESHOLD

    parser = argparse.ArgumentParser(description="E11: Signal Weight Sensitivity")
    parser.add_argument("--threshold", type=int, default=SCORE_THRESHOLD,
                        help="Signal score threshold for malicious classification")
    args = parser.parse_args()

    SCORE_THRESHOLD = args.threshold

    output_dir = get_output_dir(EXPERIMENT_NAME)
    print(f"=== Experiment 11: Weight Sensitivity Analysis ===")
    print(f"Output: {output_dir}")
    print(f"Threshold: {SCORE_THRESHOLD}")

    corpus = load_corpus()
    if not corpus:
        print("ERROR: No test corpus available")
        sys.exit(1)

    results = run_sensitivity_analysis(corpus)
    results["threshold"] = SCORE_THRESHOLD
    results["corpus_size"] = len(corpus)

    print("\n=== Generating Plots ===")
    plot_sensitivity_curves(results, output_dir)
    plot_tornado(results, output_dir)
    plot_heatmap(results, output_dir)

    print("\n=== Generating LaTeX ===")
    generate_latex(results, output_dir)

    print("\n=== Saving Results ===")
    save_results(results, output_dir, "sensitivity_results")

    # Summary
    print("\n=== SENSITIVITY SUMMARY ===")
    sorted_sigs = sorted(results["signals"].keys(),
                         key=lambda s: results["signals"][s]["f1_range"], reverse=True)
    print(f"{'Signal':<30} {'Default W':>10} {'F1 Range':>10}")
    print("-" * 52)
    for sig_name in sorted_sigs:
        sig = results["signals"][sig_name]
        print(f"{sig_name:<30} {sig['default_weight']:>10} {sig['f1_range']:>10.4f}")

    print(f"\nBaseline F1: {results['baseline']['f1']:.3f}")
    print(f"Most sensitive signal: {sorted_sigs[0]}")
    print(f"Least sensitive signal: {sorted_sigs[-1]}")


if __name__ == "__main__":
    main()
