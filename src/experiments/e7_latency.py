"""e7_latency.py -- Experiment 7: Per-Email Processing Latency

Research Question:
    Is laptop-class hardware (RTX 4060, 16GB VRAM) sufficient for
    real-time email security triage at organizational volumes?

Measures:
  - Total per-email pipeline latency (end-to-end)
  - Per-stage breakdown: rules engine, extraction, LLM inference
  - Throughput in emails/minute
  - Latency distribution (histogram, CDF, percentiles)

Output: data/experiments/e7_latency/
  - latency_distribution.png
  - stage_breakdown.png
  - latency_cdf.png
  - results_<ts>.json
  - latency_table_<ts>.tex
"""
from __future__ import annotations

import argparse
import sys
import time
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

EXPERIMENT_NAME = "e7_latency"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_parsed(case: dict) -> dict:
    """Build a parsed email dict from a corpus case."""
    raw_bytes = case.get("raw_bytes") or case.get("eml")
    if raw_bytes:
        return parse_email(raw_bytes)
    return {
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
        "extraction": {},
    }


def _percentile(data: list[float], p: float) -> float:
    """Compute percentile without scipy."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(sorted_data):
        return sorted_data[f]
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])


def _compute_stats(values: list[float]) -> dict[str, float]:
    """Compute summary statistics for a list of timing values."""
    if not values:
        return {k: 0.0 for k in ("mean", "median", "std", "min", "max", "p95", "p99")}
    arr = np.array(values)
    return {
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "std": float(np.std(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "p95": float(_percentile(values, 95)),
        "p99": float(_percentile(values, 99)),
    }


# ---------------------------------------------------------------------------
# Core experiment
# ---------------------------------------------------------------------------

def run_experiment(
    corpus: list[dict],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Time each email through individual pipeline stages."""
    per_email: list[dict] = []
    total = len(corpus)

    for idx, case in enumerate(corpus):
        email_id = str(case.get("id", case.get("path", f"email_{idx}")))
        expected = case.get("expected", "unknown")
        print(f"  [{idx + 1}/{total}] {email_id[:50]}", end="  ")

        # Parse
        t0 = time.perf_counter()
        parsed = _build_parsed(case)
        t_parse = time.perf_counter() - t0

        # Rules engine
        t0 = time.perf_counter()
        rules_result = run_rules_engine(parsed)
        t_rules = time.perf_counter() - t0
        parsed["analysis"] = rules_result

        # Extraction
        t0 = time.perf_counter()
        ext_result = run_extraction(parsed)
        t_extraction = time.perf_counter() - t0
        parsed["extraction"] = ext_result

        # Check deterministic escalation
        rules_flagged = bool(
            any(d.get("flagged") for d in rules_result.get("details", []))
        )
        ext_flagged = ext_result.get("escalate", False)
        deterministic_escalation = rules_flagged or ext_flagged

        # LLM inference (skip if deterministic already decided)
        t_llm = 0.0
        llm_verdict = None
        if not deterministic_escalation:
            prompt = get_analysis_prompt(parsed, include_signals=True)
            t0 = time.perf_counter()
            try:
                raw = call_model(prompt, provider=provider, model=model, temperature=0.0)
                llm_verdict = "called"
            except Exception:
                llm_verdict = "error"
            t_llm = time.perf_counter() - t0

        t_total = t_parse + t_rules + t_extraction + t_llm

        record = {
            "email_id": email_id,
            "expected": expected,
            "t_parse": round(t_parse, 4),
            "t_rules": round(t_rules, 4),
            "t_extraction": round(t_extraction, 4),
            "t_llm": round(t_llm, 4),
            "t_total": round(t_total, 4),
            "deterministic_escalation": deterministic_escalation,
            "llm_called": not deterministic_escalation,
        }
        per_email.append(record)
        print(f"total={t_total:.2f}s  (rules={t_rules:.2f} ext={t_extraction:.2f} llm={t_llm:.2f})")

    # Aggregate stats
    totals = [r["t_total"] for r in per_email]
    rules_times = [r["t_rules"] for r in per_email]
    ext_times = [r["t_extraction"] for r in per_email]
    llm_times = [r["t_llm"] for r in per_email if r["llm_called"]]
    all_llm_times = [r["t_llm"] for r in per_email]

    total_wall = sum(totals)
    throughput = (len(per_email) / total_wall * 60) if total_wall > 0 else 0

    stats = {
        "total": _compute_stats(totals),
        "rules": _compute_stats(rules_times),
        "extraction": _compute_stats(ext_times),
        "llm_when_called": _compute_stats(llm_times),
        "llm_all": _compute_stats(all_llm_times),
    }

    return {
        "per_email": per_email,
        "stats": stats,
        "summary": {
            "n_emails": len(per_email),
            "n_llm_called": sum(1 for r in per_email if r["llm_called"]),
            "n_deterministic": sum(1 for r in per_email if r["deterministic_escalation"]),
            "total_wall_seconds": round(total_wall, 2),
            "throughput_emails_per_minute": round(throughput, 2),
        },
        "meta": {
            "provider": provider,
            "model": model,
        },
    }


# ---------------------------------------------------------------------------
# Visualizations
# ---------------------------------------------------------------------------

def _plot_latency_distribution(per_email: list[dict], output_dir: Path) -> None:
    """Histogram of total per-email latency."""
    paper_style()
    totals = [r["t_total"] for r in per_email]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(totals, bins=30, color=COLORS[1], edgecolor="black", linewidth=0.6, alpha=0.85)

    mean_val = np.mean(totals)
    p95_val = _percentile(totals, 95)
    ax.axvline(mean_val, color="#e74c3c", linestyle="--", linewidth=1.5, label=f"Mean: {mean_val:.2f}s")
    ax.axvline(p95_val, color="#e67e22", linestyle="--", linewidth=1.5, label=f"P95: {p95_val:.2f}s")

    ax.set_xlabel("Latency (seconds)")
    ax.set_ylabel("Email Count")
    ax.set_title("Per-Email Pipeline Latency Distribution", fontweight="bold")
    ax.legend(fontsize=10)

    plt.tight_layout()
    out = output_dir / "latency_distribution.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _plot_stage_breakdown(stats: dict, output_dir: Path) -> None:
    """Stacked bar showing average time per pipeline stage."""
    paper_style()
    stages = ["Parse", "Rules Engine", "Extraction", "LLM Inference"]
    means = [
        stats["total"]["mean"] - stats["rules"]["mean"] - stats["extraction"]["mean"] - stats["llm_all"]["mean"],
        stats["rules"]["mean"],
        stats["extraction"]["mean"],
        stats["llm_all"]["mean"],
    ]
    # Clamp parse time to 0 if negative due to rounding
    means[0] = max(means[0], 0)

    stage_colors = ["#95a5a6", "#e74c3c", "#e67e22", "#3498db"]

    fig, ax = plt.subplots(figsize=(8, 5))
    bottom = 0
    bars = []
    for i, (stage, mean, color) in enumerate(zip(stages, means, stage_colors)):
        bar = ax.bar("Full Pipeline", mean, bottom=bottom, color=color,
                      edgecolor="black", linewidth=0.5, label=stage)
        if mean > 0.01:
            ax.text(0, bottom + mean / 2, f"{mean:.3f}s\n({mean / stats['total']['mean'] * 100:.0f}%)",
                    ha="center", va="center", fontsize=9, fontweight="bold", color="white")
        bottom += mean
        bars.append(bar)

    ax.set_ylabel("Time (seconds)")
    ax.set_title(f"Average Per-Email Stage Breakdown\n(Total: {stats['total']['mean']:.2f}s)",
                 fontweight="bold")
    ax.legend(loc="upper right", fontsize=9)

    plt.tight_layout()
    out = output_dir / "stage_breakdown.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _plot_latency_cdf(per_email: list[dict], output_dir: Path) -> None:
    """CDF curve of total pipeline latency."""
    paper_style()
    totals = sorted([r["t_total"] for r in per_email])
    cdf = np.arange(1, len(totals) + 1) / len(totals)

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(totals, cdf, color=COLORS[0], linewidth=2)
    ax.fill_between(totals, cdf, alpha=0.15, color=COLORS[0])

    # Mark percentiles
    for pct, color, ls in [(50, "#3498db", ":"), (95, "#e67e22", "--"), (99, "#e74c3c", "--")]:
        val = _percentile(totals, pct)
        ax.axvline(val, color=color, linestyle=ls, linewidth=1.2,
                   label=f"P{pct}: {val:.2f}s")
        ax.axhline(pct / 100, color=color, linestyle=ls, linewidth=0.5, alpha=0.3)

    ax.set_xlabel("Latency (seconds)")
    ax.set_ylabel("Cumulative Probability")
    ax.set_title("Pipeline Latency CDF", fontweight="bold")
    ax.set_ylim(0, 1.02)
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    out = output_dir / "latency_cdf.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# LaTeX table
# ---------------------------------------------------------------------------

def _latex_table(stats: dict, summary: dict, model: str) -> list[str]:
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        rf"\caption{{Per-Email Pipeline Latency ({model})}}",
        r"\label{tab:e7_latency}",
        r"\begin{tabular}{l r r r r r r r}",
        r"\hline",
        r"Stage & Mean & Median & Std & Min & Max & P95 & P99 \\",
        r"\hline",
    ]
    for stage_key, label in [
        ("rules", "Rules Engine"),
        ("extraction", "Extraction"),
        ("llm_when_called", "LLM (when called)"),
        ("total", "Total Pipeline"),
    ]:
        s = stats[stage_key]
        lines.append(
            rf"{label} & {s['mean']:.3f}s & {s['median']:.3f}s & "
            rf"{s['std']:.3f}s & {s['min']:.3f}s & {s['max']:.3f}s & "
            rf"{s['p95']:.3f}s & {s['p99']:.3f}s \\"
        )
    lines += [
        r"\hline",
        rf"\multicolumn{{8}}{{l}}{{\textbf{{Throughput: {summary['throughput_emails_per_minute']:.1f} emails/minute}}}} \\",
        rf"\multicolumn{{8}}{{l}}{{LLM called: {summary['n_llm_called']}/{summary['n_emails']} "
        rf"({summary['n_deterministic']} resolved deterministically)}} \\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment 7 -- Per-email pipeline latency measurement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--provider", default="ollama",
                        choices=["ollama", "openai", "groq", "together", "anthropic",
                                 "nvidia", "deepseek", "mistral_nvidia"],
                        help="LLM provider (default: ollama)")
    parser.add_argument("--model", default="gemma3:4b",
                        help="Model name (default: gemma3:4b)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    print("=" * 60)
    print("Experiment 7 -- Pipeline Latency Measurement")
    print("=" * 60)
    print(f"  Provider : {args.provider}")
    print(f"  Model    : {args.model}")
    print("-" * 60)

    corpus = load_corpus()
    output_dir = get_output_dir(EXPERIMENT_NAME)

    data = run_experiment(corpus, provider=args.provider, model=args.model)

    save_results(data, output_dir, "results")

    # Print summary
    s = data["summary"]
    st = data["stats"]["total"]
    print()
    print(f"  Emails processed   : {s['n_emails']}")
    print(f"  LLM called         : {s['n_llm_called']} ({s['n_deterministic']} deterministic)")
    print(f"  Total wall time    : {s['total_wall_seconds']:.1f}s")
    print(f"  Throughput         : {s['throughput_emails_per_minute']:.1f} emails/min")
    print(f"  Mean latency       : {st['mean']:.3f}s")
    print(f"  Median latency     : {st['median']:.3f}s")
    print(f"  P95 latency        : {st['p95']:.3f}s")
    print(f"  P99 latency        : {st['p99']:.3f}s")

    print()
    print("Generating visualisations...")
    _plot_latency_distribution(data["per_email"], output_dir)
    _plot_stage_breakdown(data["stats"], output_dir)
    _plot_latency_cdf(data["per_email"], output_dir)

    print()
    print("Generating LaTeX table...")
    save_latex(
        _latex_table(data["stats"], data["summary"], args.model),
        output_dir, "latency_table",
    )

    print()
    print("Experiment 7 complete.")
    print(f"  Output dir: {output_dir}")


if __name__ == "__main__":
    main()
