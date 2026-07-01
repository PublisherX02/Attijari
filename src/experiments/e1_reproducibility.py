"""e1_reproducibility.py -- Experiment 1: LLM Verdict Reproducibility

Research Question: Are LLM-generated security verdicts reproducible?

Method: Run the same email through the same model N times at different
temperatures. Measure verdict variance, confidence variance, and flip rate
(how often the verdict changes across runs).

Output: data/experiments/e1_reproducibility/
  - verdict_stability.png
  - flip_rate_by_temperature.png
  - stability_distribution.png
  - results_<ts>.json
  - flip_rate_table_<ts>.tex
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXPERIMENT_NAME = "e1_reproducibility"
VERDICT_ORDER = ["accepter", "rejeter", "escalader", "error"]
VERDICT_COLORS = {
    "accepter": "#2ecc71",   # green
    "rejeter":  "#e74c3c",   # red
    "escalader": "#f39c12",  # yellow/orange
    "error":    "#95a5a6",   # grey
}
# Integer codes used in the heatmap matrix
VERDICT_CODE = {"accepter": 0, "escalader": 1, "rejeter": 2, "error": 3}
VERDICT_LABEL = {v: k for k, v in VERDICT_CODE.items()}


# ---------------------------------------------------------------------------
# LLM call + response parsing
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict:
    """Extract the first JSON object from an LLM response string."""
    # Try to find a {...} block
    match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError("No JSON object found in response")


def call_once(
    prompt: str,
    provider: str,
    model: str,
    temperature: float,
) -> dict[str, Any]:
    """Make a single LLM call and return parsed verdict fields.

    On any failure returns a sentinel dict with verdict="error".
    """
    try:
        raw = call_model(prompt, provider=provider, model=model,
                         temperature=temperature)
        data = _extract_json(raw)
        verdict = str(data.get("verdict", "error")).lower().strip()
        # Normalise variants that models sometimes emit
        if verdict in ("accept", "accepted", "clean", "safe", "benign", "recu"):
            verdict = "accepter"
        elif verdict in ("reject", "rejected", "block"):
            verdict = "rejeter"
        elif verdict in ("escalate", "escalate_to_human", "escalade"):
            verdict = "escalader"
        elif verdict not in VERDICT_CODE:
            verdict = "error"
        confidence = float(data.get("confiance", data.get("confidence", 0.5)))
        score = int(data.get("score_risque", data.get("risk_score", 50)))
        return {"verdict": verdict, "confidence": confidence,
                "score_risque": score, "raw": raw[:500]}
    except Exception as exc:
        return {"verdict": "error", "confidence": 0.0,
                "score_risque": -1, "raw": str(exc)[:500]}


# ---------------------------------------------------------------------------
# Per-email stability analysis
# ---------------------------------------------------------------------------

def analyse_email_stability(
    runs: list[dict],
) -> dict[str, Any]:
    """Compute stability stats for the N runs on a single email."""
    verdicts = [r["verdict"] for r in runs]
    confidences = [r["confidence"] for r in runs
                   if r["verdict"] != "error"]
    counter = Counter(verdicts)
    dominant, dominant_count = counter.most_common(1)[0]
    n = len(runs)
    agreement_rate = dominant_count / n
    # Flip rate: fraction of consecutive pairs that differ
    flips = sum(1 for a, b in zip(verdicts, verdicts[1:]) if a != b)
    flip_rate = flips / max(len(verdicts) - 1, 1)
    return {
        "verdicts": verdicts,
        "dominant_verdict": dominant,
        "agreement_rate": agreement_rate,
        "flip_rate": flip_rate,
        "verdict_distribution": dict(counter),
        "confidence_mean": float(np.mean(confidences)) if confidences else 0.0,
        "confidence_std": float(np.std(confidences)) if confidences else 0.0,
        "n_errors": counter.get("error", 0),
    }


# ---------------------------------------------------------------------------
# Corpus-wide experiment runner
# ---------------------------------------------------------------------------

def run_experiment(
    corpus: list[dict],
    provider: str,
    model: str,
    temperatures: list[float],
    n_runs: int,
) -> dict[str, Any]:
    """Run the full reproducibility experiment.

    For each email and each temperature, call the LLM n_runs times.
    Returns a structured result dict.
    """
    results: list[dict] = []
    total = len(corpus) * len(temperatures)
    done = 0

    for case in corpus:
        email_id = case.get("id", case.get("path", str(done)))
        expected = case.get("expected", "unknown")

        # Build the analysis prompt once per email
        raw_bytes = case.get("raw_bytes")
        if raw_bytes:
            parsed = parse_email(raw_bytes)
        else:
            # Synthetic / dict-based case — build a minimal parsed structure
            parsed = {
                "body_text": case.get("body", case.get("text", "")),
                "headers": {
                    "from": case.get("from", "unknown"),
                    "to": case.get("to", "unknown"),
                    "subject": case.get("subject", ""),
                    "date": case.get("date", ""),
                },
                "attachments": [],
                "auth": {},
                "analysis": {},
            }
        prompt = get_analysis_prompt(parsed, include_signals=True)

        per_temp: dict[str, Any] = {}
        for temp in temperatures:
            done += 1
            print(f"  [{done}/{total}] email={email_id!r}  temp={temp}  "
                  f"running {n_runs} calls...")
            runs = [
                call_once(prompt, provider, model, temperature=temp)
                for _ in range(n_runs)
            ]
            stats = analyse_email_stability(runs)
            per_temp[str(temp)] = {"runs": runs, "stats": stats}
            # Brief inline summary
            print(f"    agreement={stats['agreement_rate']:.0%}  "
                  f"dominant={stats['dominant_verdict']}  "
                  f"flip_rate={stats['flip_rate']:.2f}  "
                  f"conf_std={stats['confidence_std']:.3f}")

        results.append({
            "email_id": str(email_id),
            "expected": expected,
            "per_temperature": per_temp,
        })

    # Corpus-wide aggregates
    aggregates = _aggregate(results, temperatures, n_runs)
    return {"results": results, "aggregates": aggregates,
            "meta": {"provider": provider, "model": model,
                     "n_runs": n_runs,
                     "temperatures": temperatures,
                     "n_emails": len(corpus)}}


def _aggregate(
    results: list[dict],
    temperatures: list[float],
    n_runs: int,
) -> dict[str, Any]:
    """Compute corpus-level stats per temperature."""
    per_temp: dict[str, dict] = {}
    for temp in temperatures:
        key = str(temp)
        flip_rates = [
            r["per_temperature"][key]["stats"]["flip_rate"]
            for r in results
        ]
        agreement_rates = [
            r["per_temperature"][key]["stats"]["agreement_rate"]
            for r in results
        ]
        conf_stds = [
            r["per_temperature"][key]["stats"]["confidence_std"]
            for r in results
        ]
        per_temp[key] = {
            "mean_flip_rate": float(np.mean(flip_rates)),
            "mean_agreement_rate": float(np.mean(agreement_rates)),
            "mean_confidence_std": float(np.mean(conf_stds)),
            "pct_fully_stable": float(
                np.mean([1.0 if f == 0.0 else 0.0 for f in flip_rates])
            ),
        }
    # Most unstable cases (highest flip rate, averaged across temps)
    instability_scores = []
    for r in results:
        avg_flip = np.mean([
            r["per_temperature"][str(t)]["stats"]["flip_rate"]
            for t in temperatures
        ])
        instability_scores.append((r["email_id"], float(avg_flip)))
    instability_scores.sort(key=lambda x: x[1], reverse=True)
    return {
        "per_temperature": per_temp,
        "most_unstable": instability_scores[:5],
    }


# ---------------------------------------------------------------------------
# Visualisations
# ---------------------------------------------------------------------------

def _verdict_heatmap(
    results: list[dict],
    temperatures: list[float],
    n_runs: int,
    output_dir: Path,
) -> None:
    """Heatmap: emails x runs, one panel per temperature, colored by verdict."""
    paper_style()
    n_temps = len(temperatures)
    n_emails = len(results)
    fig, axes = plt.subplots(
        1, n_temps,
        figsize=(4 * n_temps, max(4, 0.4 * n_emails)),
        squeeze=False,
    )

    # Build a discrete colormap: 0=accept(green), 1=escalate(yellow),
    # 2=reject(red), 3=error(grey)
    from matplotlib.colors import ListedColormap, BoundaryNorm
    cmap = ListedColormap(["#2ecc71", "#f39c12", "#e74c3c", "#95a5a6"])
    bounds = [-0.5, 0.5, 1.5, 2.5, 3.5]
    norm = BoundaryNorm(bounds, cmap.N)

    for col, temp in enumerate(temperatures):
        ax = axes[0][col]
        key = str(temp)
        # Matrix: rows=emails, cols=runs
        matrix = np.full((n_emails, n_runs), fill_value=3, dtype=int)
        for row, case in enumerate(results):
            runs = case["per_temperature"][key]["runs"]
            for run_idx, run in enumerate(runs):
                matrix[row, run_idx] = VERDICT_CODE.get(
                    run.get("verdict", "error"), 3
                )
        im = ax.imshow(matrix, cmap=cmap, norm=norm,
                       aspect="auto", interpolation="nearest")
        ax.set_title(f"Temperature {temp}", pad=8)
        ax.set_xlabel("Run #")
        if col == 0:
            ax.set_ylabel("Email #")
            ax.set_yticks(range(n_emails))
            ax.set_yticklabels(
                [r["email_id"][:20] for r in results],
                fontsize=7,
            )
        else:
            ax.set_yticks([])
        ax.set_xticks(range(n_runs))
        ax.set_xticklabels([str(i + 1) for i in range(n_runs)], fontsize=8)

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor="#2ecc71", label="accept"),
        Patch(facecolor="#f39c12", label="escalate"),
        Patch(facecolor="#e74c3c", label="reject"),
        Patch(facecolor="#95a5a6", label="error"),
    ]
    fig.legend(handles=legend_elements, loc="lower center",
               ncol=4, fontsize=9, bbox_to_anchor=(0.5, -0.04))

    fig.suptitle("Verdict Stability: Emails x Runs by Temperature",
                 fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    out = output_dir / "verdict_stability.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _flip_rate_bar(
    aggregates: dict,
    temperatures: list[float],
    output_dir: Path,
) -> None:
    """Bar chart: flip rate at each temperature."""
    paper_style()
    fig, ax = plt.subplots(figsize=(6, 4))
    per_temp = aggregates["per_temperature"]
    flip_rates = [per_temp[str(t)]["mean_flip_rate"] for t in temperatures]
    bars = ax.bar(
        [str(t) for t in temperatures],
        flip_rates,
        color=COLORS[:len(temperatures)],
        edgecolor="black",
        linewidth=0.7,
    )
    # Value labels on bars
    for bar, rate in zip(bars, flip_rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.005,
            f"{rate:.1%}",
            ha="center", va="bottom", fontsize=10,
        )
    ax.set_xlabel("Temperature")
    ax.set_ylabel("Mean Flip Rate")
    ax.set_title("Verdict Flip Rate by Temperature")
    ax.set_ylim(0, max(flip_rates or [0.1]) * 1.25 + 0.05)
    ax.yaxis.set_major_formatter(
        matplotlib.ticker.PercentFormatter(xmax=1.0))
    plt.tight_layout()
    out = output_dir / "flip_rate_by_temperature.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _stability_histogram(
    results: list[dict],
    temperatures: list[float],
    output_dir: Path,
) -> None:
    """Histogram: distribution of per-email agreement rates across all temps."""
    paper_style()
    fig, ax = plt.subplots(figsize=(7, 4))
    all_agreement: list[float] = []
    for case in results:
        for temp in temperatures:
            key = str(temp)
            rate = case["per_temperature"][key]["stats"]["agreement_rate"]
            all_agreement.append(rate)

    bins = np.linspace(0, 1, 11)  # 0%, 10%, ..., 100%
    ax.hist(all_agreement, bins=bins, color=COLORS[1],
            edgecolor="black", linewidth=0.7)
    ax.set_xlabel("Agreement Rate (dominant verdict fraction)")
    ax.set_ylabel("Count (email x temperature pairs)")
    ax.set_title("Stability Distribution Across Emails and Temperatures")
    ax.xaxis.set_major_formatter(
        matplotlib.ticker.PercentFormatter(xmax=1.0))
    plt.tight_layout()
    out = output_dir / "stability_distribution.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# LaTeX table
# ---------------------------------------------------------------------------

def _latex_table(
    aggregates: dict,
    temperatures: list[float],
    model: str,
    n_runs: int,
) -> list[str]:
    """Build LaTeX table: per-temperature flip rate and agreement %."""
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{LLM Verdict Reproducibility by Temperature"
        f" ({model}, $n={n_runs}$ runs per email)" + "}",
        r"\label{tab:e1_flip_rate}",
        r"\begin{tabular}{r r r r}",
        r"\hline",
        r"Temperature & Flip Rate & Agreement & Fully Stable \\",
        r"\hline",
    ]
    per_temp = aggregates["per_temperature"]
    for temp in temperatures:
        key = str(temp)
        d = per_temp[key]
        lines.append(
            rf"{temp:.1f} & "
            rf"{d['mean_flip_rate']:.1%} & "
            rf"{d['mean_agreement_rate']:.1%} & "
            rf"{d['pct_fully_stable']:.1%} \\"
        )
    lines += [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment 1 -- LLM verdict reproducibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--runs", type=int, default=10,
        help="Number of LLM calls per email per temperature (default: 10)",
    )
    parser.add_argument(
        "--provider", default="ollama",
        choices=["ollama", "openai", "groq", "together", "anthropic", "nvidia", "deepseek", "mistral_nvidia"],
        help="LLM provider (default: ollama)",
    )
    parser.add_argument(
        "--model", default="gemma3:4b",
        help="Model name for the chosen provider (default: gemma3:4b)",
    )
    parser.add_argument(
        "--temperatures", default="0.0,0.3,0.7,1.0",
        help="Comma-separated list of temperatures to test (default: 0.0,0.3,0.7,1.0)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    temperatures = [float(t.strip()) for t in args.temperatures.split(",")]

    print("=" * 60)
    print("Experiment 1 -- LLM Verdict Reproducibility")
    print("=" * 60)
    print(f"  Provider    : {args.provider}")
    print(f"  Model       : {args.model}")
    print(f"  Runs/email  : {args.runs}")
    print(f"  Temperatures: {temperatures}")

    corpus = load_corpus()
    print(f"  Corpus size : {len(corpus)} emails")
    print("-" * 60)

    output_dir = get_output_dir(EXPERIMENT_NAME)

    # Run the experiment
    experiment_data = run_experiment(
        corpus=corpus,
        provider=args.provider,
        model=args.model,
        temperatures=temperatures,
        n_runs=args.runs,
    )

    # Save raw results
    save_results(experiment_data, output_dir, "results")

    # Print corpus-level summary
    agg = experiment_data["aggregates"]
    print()
    print("Corpus-wide results:")
    print(f"  {'Temp':>6}  {'Flip Rate':>10}  {'Agreement':>10}  {'Fully Stable':>12}")
    print(f"  {'-'*6}  {'-'*10}  {'-'*10}  {'-'*12}")
    for temp in temperatures:
        key = str(temp)
        d = agg["per_temperature"][key]
        print(
            f"  {temp:>6.1f}  "
            f"{d['mean_flip_rate']:>10.1%}  "
            f"{d['mean_agreement_rate']:>10.1%}  "
            f"{d['pct_fully_stable']:>12.1%}"
        )

    print()
    print("Most unstable emails (avg flip rate across temperatures):")
    for email_id, score in agg["most_unstable"]:
        print(f"  {email_id!r:40s}  flip={score:.2f}")

    # Visualisations
    print()
    print("Generating visualisations...")
    _verdict_heatmap(
        experiment_data["results"], temperatures, args.runs, output_dir
    )
    _flip_rate_bar(agg, temperatures, output_dir)
    _stability_histogram(experiment_data["results"], temperatures, output_dir)

    # LaTeX table
    latex_lines = _latex_table(agg, temperatures, args.model, args.runs)
    save_latex(latex_lines, output_dir, "flip_rate_table")

    print()
    print("Experiment 1 complete.")
    print(f"  Output dir: {output_dir}")


if __name__ == "__main__":
    main()
