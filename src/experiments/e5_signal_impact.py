"""e5_signal_impact.py -- Experiment 5: Signal Impact on LLM Reliability

Research Question: How does structured deterministic signal enrichment affect
the reliability of LLM-generated security verdicts?

Hypothesis: Signals constrain LLM hallucination and improve both precision
and recall.

Method: Run the corpus through 4 configurations, measuring how adding signals
changes LLM behaviour:
  1. LLM Blind       -- raw email body only
  2. LLM + Headers   -- body + From/To/Subject/Date
  3. LLM + Auth      -- body + headers + SPF/DKIM/DMARC
  4. LLM + All       -- body + headers + auth + extraction flags + rule flags

Output: data/experiments/e5_signal_impact/
  - signal_progression.png        (CORE chart: metrics vs signal level)
  - signal_delta_bars.png         (stacked bar: delta per signal added)
  - per_case_signal_effect.png    (which signal fixed each blind mistake)
  - blind_vs_enriched_confusion.png (side-by-side confusion matrices)
  - results_<ts>.json
  - signal_impact_table_<ts>.tex
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Allow running as standalone script or as module
_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
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
EXPERIMENT_NAME = "e5_signal_impact"

# Ordered list of configurations -- each is a superset of the previous
CONFIG_NAMES = [
    "blind",
    "+headers",
    "+auth",
    "+all",
]

CONFIG_LABELS = {
    "blind":    "LLM Blind",
    "+headers": "LLM + Headers",
    "+auth":    "LLM + Auth",
    "+all":     "LLM + All Signals",
}

# Which metrics to track across configs
METRIC_KEYS = ["accuracy", "precision", "recall", "f1"]
METRIC_LABELS = {
    "accuracy":  "Accuracy",
    "precision": "Precision",
    "recall":    "Recall",
    "f1":        "F1",
}

# Colour per metric (for the progression line chart)
METRIC_COLORS = {
    "accuracy":  COLORS[0],
    "precision": COLORS[1],
    "recall":    COLORS[2],
    "f1":        COLORS[3],
}

# Signal stage colours for delta bar chart
DELTA_COLORS = {
    "+headers": COLORS[1],
    "+auth":    COLORS[2],
    "+all":     COLORS[3],
}


# ---------------------------------------------------------------------------
# Prompt builders -- one per configuration
# ---------------------------------------------------------------------------

def _build_prompt_blind(case: dict, parsed: dict) -> str:
    """Config 1: body text only -- no headers, no signals."""
    body = parsed.get("body_text", "") or ""
    return (
        "You are an email security analyst at a bank. "
        "Analyze this email and respond with a JSON object.\n"
        "Respond ONLY with valid JSON containing these fields:\n"
        '{"verdict": "accepter|rejeter|escalader", "score_risque": 0-100, '
        '"confiance": 0.0-1.0, "raisonnement": "brief explanation"}\n\n'
        "Email body:\n"
        + (body[:3000] if body else "(empty)")
    )


def _build_prompt_headers(case: dict, parsed: dict) -> str:
    """Config 2: body + email headers."""
    body = parsed.get("body_text", "") or ""
    headers = parsed.get("headers", {}) or {}
    from_addr  = headers.get("from",    case.get("from",    "unknown"))
    to_addr    = headers.get("to",      case.get("to",      "unknown"))
    subject    = headers.get("subject", case.get("subject", ""))
    date       = headers.get("date",    case.get("date",    "unknown"))
    return (
        "You are an email security analyst at a bank. "
        "Analyze this email and respond with a JSON object.\n"
        "Respond ONLY with valid JSON containing these fields:\n"
        '{"verdict": "accepter|rejeter|escalader", "score_risque": 0-100, '
        '"confiance": 0.0-1.0, "raisonnement": "brief explanation"}\n\n'
        f"From: {from_addr}\n"
        f"To: {to_addr}\n"
        f"Subject: {subject}\n"
        f"Date: {date}\n\n"
        "Email body:\n"
        + (body[:3000] if body else "(empty)")
    )


def _build_prompt_auth(case: dict, parsed: dict) -> str:
    """Config 3: body + headers + SPF/DKIM/DMARC authentication results."""
    base = _build_prompt_headers(case, parsed)
    auth = parsed.get("auth", {}) or {}
    auth_header = auth.get("auth_header", {}) or {}
    spf   = auth_header.get("spf",   auth.get("spf",   "none"))
    dkim  = auth_header.get("dkim",  auth.get("dkim",  "none"))
    dmarc = auth_header.get("dmarc", auth.get("dmarc", "none"))
    return (
        base
        + f"\n\nAuthentication: SPF={spf}, DKIM={dkim}, DMARC={dmarc}"
    )


def _build_prompt_all(case: dict, parsed: dict) -> str:
    """Config 4: body + headers + auth + extraction flags + rule engine flags."""
    base = _build_prompt_auth(case, parsed)
    extra_parts: list[str] = []

    # Extraction results
    extraction = parsed.get("extraction", {}) or {}
    results = extraction.get("results", []) or []
    if results:
        lines = ["\n\nAttachment analysis:"]
        for r in results:
            flags = r.get("flags", []) or []
            name  = r.get("filename", "unknown")
            if flags:
                lines.append(f"  - {name}: FLAGGED: {', '.join(flags)}")
            else:
                lines.append(f"  - {name}: clean")
        extra_parts.append("".join(lines))

    # Rule engine flags
    analysis = parsed.get("analysis", {}) or {}
    details  = analysis.get("details", []) or []
    flagged  = [d["rule"] for d in details if d.get("flagged")]
    if flagged:
        extra_parts.append(
            f"\n\nRule engine flags: {', '.join(flagged)}"
        )

    return base + "".join(extra_parts)


# Map config name -> prompt builder
_PROMPT_BUILDERS = {
    "blind":    _build_prompt_blind,
    "+headers": _build_prompt_headers,
    "+auth":    _build_prompt_auth,
    "+all":     _build_prompt_all,
}


# ---------------------------------------------------------------------------
# LLM response parsing
# ---------------------------------------------------------------------------

def _extract_json_block(text: str) -> dict:
    """Extract first {...} block from LLM response."""
    match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError("No JSON object found in LLM response")


def _normalise_verdict(raw: str) -> str:
    """Map any verdict variant to canonical three-way string."""
    v = (raw or "").lower().strip()
    if v in ("accepter", "accept", "accepted", "clean", "safe", "benign", "recu"):
        return "accepter"
    if v in ("rejeter", "reject", "rejected", "block"):
        return "rejeter"
    if v in ("escalader", "escalate", "escalate_to_human", "escalade"):
        return "escalader"
    return "escalader"   # fail-safe: unknown -> escalate (never silently accept)


def call_once(prompt: str, provider: str, model: str) -> dict[str, Any]:
    """Single LLM call; returns parsed fields or safe defaults on failure."""
    try:
        raw = call_model(prompt, provider=provider, model=model, temperature=0.0)
        data = _extract_json_block(raw)
        verdict    = _normalise_verdict(str(data.get("verdict", "")))
        confidence = float(data.get("confiance", data.get("confidence", 0.5)))
        score      = int(data.get("score_risque", data.get("risk_score", 50)))
        return {
            "verdict":    verdict,
            "confidence": confidence,
            "score":      score,
            "raw":        raw[:500],
            "error":      False,
        }
    except Exception as exc:
        return {
            "verdict":    "escalader",
            "confidence": 0.0,
            "score":      50,
            "raw":        str(exc)[:300],
            "error":      True,
        }


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------

def _build_parsed(case: dict) -> dict:
    """Return a parsed email dict from a corpus case."""
    raw_bytes = case.get("raw_bytes")
    if raw_bytes:
        parsed = parse_email(raw_bytes)
        # Enrich with rule engine and extraction results
        try:
            parsed["analysis"] = run_rules_engine(parsed)
        except Exception:
            parsed["analysis"] = {}
        try:
            parsed["extraction"] = run_extraction(parsed)
        except Exception:
            parsed["extraction"] = {}
        return parsed

    # Synthetic / dict-based case
    return {
        "body_text":  case.get("body", case.get("text", "")),
        "headers": {
            "from":    case.get("from",    "unknown"),
            "to":      case.get("to",      "unknown"),
            "subject": case.get("subject", ""),
            "date":    case.get("date",    "unknown"),
        },
        "attachments": [],
        "auth":       case.get("auth", {}),
        "analysis":   case.get("analysis", {}),
        "extraction": case.get("extraction", {}),
    }


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_experiment(
    corpus: list[dict],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Run all four signal configurations over the corpus.

    For each email and each config, calls the LLM once (temperature=0).
    Returns structured results ready for metric computation and plotting.
    """
    n_total = len(corpus) * len(CONFIG_NAMES)
    done = 0
    per_case: list[dict] = []

    for case in corpus:
        email_id = str(case.get("id", case.get("path", f"case_{done}")))
        expected = case.get("expected", "unknown")

        parsed = _build_parsed(case)

        config_results: dict[str, dict] = {}
        for cfg in CONFIG_NAMES:
            done += 1
            print(
                f"  [{done:>3}/{n_total}] {email_id[:40]!r:<42} "
                f"config={cfg:<10} ...",
                end=" ",
                flush=True,
            )
            prompt = _PROMPT_BUILDERS[cfg](case, parsed)
            result = call_once(prompt, provider, model)
            config_results[cfg] = result
            binary = classify_verdict(result["verdict"])
            correct = binary == expected
            status = "OK" if correct else "WRONG"
            print(f"verdict={result['verdict']:<10} [{status}]")

        per_case.append({
            "email_id": email_id,
            "expected": expected,
            "configs":  config_results,
        })

    # Aggregate metrics per config
    metrics_per_config: dict[str, dict] = {}
    for cfg in CONFIG_NAMES:
        y_true = [c["expected"] for c in per_case]
        y_pred = [classify_verdict(c["configs"][cfg]["verdict"]) for c in per_case]
        metrics_per_config[cfg] = compute_metrics(y_true, y_pred)

    return {
        "per_case":          per_case,
        "metrics_per_config": metrics_per_config,
        "meta": {
            "provider":  provider,
            "model":     model,
            "n_emails":  len(corpus),
            "configs":   CONFIG_NAMES,
        },
    }


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _identify_blind_errors(per_case: list[dict]) -> list[dict]:
    """Return cases where blind config was wrong."""
    errors = []
    for c in per_case:
        blind_binary = classify_verdict(c["configs"]["blind"]["verdict"])
        if blind_binary != c["expected"]:
            errors.append(c)
    return errors


def _first_fixing_config(case: dict) -> str | None:
    """Return the first config (after blind) that got this case right."""
    expected = case["expected"]
    for cfg in CONFIG_NAMES[1:]:    # skip blind itself
        if classify_verdict(case["configs"][cfg]["verdict"]) == expected:
            return cfg
    return None     # still wrong even with all signals


# ---------------------------------------------------------------------------
# Visualisations
# ---------------------------------------------------------------------------

def _plot_signal_progression(
    metrics_per_config: dict[str, dict],
    output_dir: Path,
) -> None:
    """Line chart: metric values as signals accumulate (CORE chart)."""
    paper_style()
    fig, ax = plt.subplots(figsize=(8, 5))

    x = list(range(len(CONFIG_NAMES)))
    x_labels = [CONFIG_LABELS[c] for c in CONFIG_NAMES]

    for metric in METRIC_KEYS:
        values = [metrics_per_config[cfg][metric] for cfg in CONFIG_NAMES]
        ax.plot(
            x, values,
            marker="o",
            linewidth=2,
            markersize=7,
            color=METRIC_COLORS[metric],
            label=METRIC_LABELS[metric],
        )
        # Annotate final value
        ax.annotate(
            f"{values[-1]:.2f}",
            xy=(x[-1], values[-1]),
            xytext=(4, 2),
            textcoords="offset points",
            fontsize=9,
            color=METRIC_COLORS[metric],
        )

    ax.set_xticks(x)
    ax.set_xticklabels(x_labels, fontsize=10)
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1.0))
    ax.set_title(
        "Signal Enrichment Progression: Metrics vs Signal Level",
        fontweight="bold",
    )
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    plt.tight_layout()

    out = output_dir / "signal_progression.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _plot_signal_delta_bars(
    metrics_per_config: dict[str, dict],
    output_dir: Path,
) -> None:
    """Stacked bar: how much each signal addition improved recall and F1."""
    paper_style()
    metrics_to_show = ["recall", "f1"]
    n_metrics = len(metrics_to_show)
    addition_stages = CONFIG_NAMES[1:]   # [+headers, +auth, +all]
    base_cfg = CONFIG_NAMES[0]           # blind

    fig, axes = plt.subplots(1, n_metrics, figsize=(10, 5), sharey=False)

    for ax_idx, metric in enumerate(metrics_to_show):
        ax = axes[ax_idx]
        baseline = metrics_per_config[base_cfg][metric]
        cumulative_prev = baseline
        bottom = 0.0
        bar_values: list[float]   = []
        bar_colors: list[str]     = []
        bar_labels: list[str]     = []

        for stage in addition_stages:
            current = metrics_per_config[stage][metric]
            delta   = max(current - cumulative_prev, 0.0)
            bar_values.append(delta)
            bar_colors.append(DELTA_COLORS[stage])
            bar_labels.append(CONFIG_LABELS[stage])
            cumulative_prev = current

        # Draw baseline bar
        ax.bar(
            0, baseline, color=COLORS[0], edgecolor="black",
            linewidth=0.7, label="Blind baseline", width=0.5,
        )
        # Draw delta bars stacked on top of baseline
        running_bottom = baseline
        for val, color, label in zip(bar_values, bar_colors, bar_labels):
            if val > 0:
                ax.bar(
                    0, val, bottom=running_bottom,
                    color=color, edgecolor="black", linewidth=0.7,
                    label=label, width=0.5,
                    alpha=0.85,
                )
                ax.text(
                    0, running_bottom + val / 2,
                    f"+{val:.3f}",
                    ha="center", va="center",
                    fontsize=9, color="white", fontweight="bold",
                )
                running_bottom += val

        ax.set_xticks([0])
        ax.set_xticklabels([METRIC_LABELS[metric]])
        ax.set_ylabel("Score")
        ax.set_ylim(0, 1.05)
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1.0))
        ax.set_title(f"Signal Contribution to {METRIC_LABELS[metric]}")
        ax.legend(loc="lower right", fontsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.suptitle(
        "Incremental Signal Contribution (Recall & F1)",
        fontweight="bold", fontsize=14,
    )
    plt.tight_layout()

    out = output_dir / "signal_delta_bars.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _plot_per_case_signal_effect(
    per_case: list[dict],
    output_dir: Path,
) -> None:
    """Bar: for emails that blind got wrong, which signal addition fixed them."""
    paper_style()
    blind_errors = _identify_blind_errors(per_case)
    total_errors = len(blind_errors)

    if total_errors == 0:
        print("  [SKIP] per_case_signal_effect.png -- no blind errors to analyse")
        return

    # Count first-fixing config
    fix_counts: dict[str, int] = {cfg: 0 for cfg in CONFIG_NAMES[1:]}
    fix_counts["none"] = 0

    for case in blind_errors:
        fixer = _first_fixing_config(case)
        if fixer is None:
            fix_counts["none"] += 1
        else:
            fix_counts[fixer] += 1

    labels = list(fix_counts.keys())
    display_labels = [
        CONFIG_LABELS.get(lbl, lbl) if lbl != "none" else "Still Wrong"
        for lbl in labels
    ]
    counts = [fix_counts[lbl] for lbl in labels]
    bar_colors = [
        DELTA_COLORS.get(lbl, "#95a5a6")
        for lbl in labels
    ]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(
        display_labels, counts,
        color=bar_colors, edgecolor="black", linewidth=0.7,
    )
    for bar, count in zip(bars, counts):
        pct = count / total_errors * 100 if total_errors else 0
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.15,
            f"{count} ({pct:.0f}%)",
            ha="center", va="bottom", fontsize=10,
        )

    ax.set_ylabel("Number of Emails Fixed")
    ax.set_title(
        f"Which Signal Fixed LLM-Blind Errors? (n={total_errors} errors)",
        fontweight="bold",
    )
    ax.set_ylim(0, max(counts or [1]) * 1.3)
    plt.tight_layout()

    out = output_dir / "per_case_signal_effect.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


def _plot_confusion_matrices(
    per_case: list[dict],
    output_dir: Path,
) -> None:
    """Side-by-side confusion matrices: blind vs full enrichment."""
    from sklearn.metrics import confusion_matrix as skl_cm

    paper_style()
    labels = ["benign", "malicious"]
    y_true = [c["expected"] for c in per_case]

    configs_to_plot = ["blind", "+all"]
    titles = ["LLM Blind", "LLM + All Signals"]

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))

    for ax, cfg, title in zip(axes, configs_to_plot, titles):
        y_pred = [
            classify_verdict(c["configs"][cfg]["verdict"])
            for c in per_case
        ]
        cm = skl_cm(y_true, y_pred, labels=labels)
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title(title, fontweight="bold", pad=10)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Pred Benign", "Pred Malicious"], fontsize=9)
        ax.set_yticklabels(["True Benign", "True Malicious"], fontsize=9)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")

        thresh = cm.max() / 2.0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(
                    j, i, str(cm[i, j]),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontsize=14, fontweight="bold",
                )
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    fig.suptitle(
        "Confusion Matrices: Blind vs Full Signal Enrichment",
        fontweight="bold", fontsize=14,
    )
    plt.tight_layout()

    out = output_dir / "blind_vs_enriched_confusion.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# LaTeX table
# ---------------------------------------------------------------------------

def _latex_table(
    metrics_per_config: dict[str, dict],
    model: str,
) -> list[str]:
    """Build LaTeX table: config, accuracy, precision, recall, F1, FN, FP, delta-F1."""
    blind_f1 = metrics_per_config["blind"]["f1"]

    lines = [
        r"\begin{table}[h]",
        r"\centering",
        rf"\caption{{Signal Impact on LLM Verdict Reliability ({model})}}",
        r"\label{tab:e5_signal_impact}",
        r"\begin{tabular}{l r r r r r r r}",
        r"\hline",
        r"Configuration & Acc. & Prec. & Recall & F1 & FN & FP & $\Delta$F1 \\",
        r"\hline",
    ]

    for cfg in CONFIG_NAMES:
        m = metrics_per_config[cfg]
        cm = m["confusion_matrix"]
        # confusion_matrix rows: [benign, malicious], cols: [benign, malicious]
        # FN = malicious predicted as benign = cm[1][0]
        # FP = benign predicted as malicious = cm[0][1]
        fn = cm[1][0] if len(cm) > 1 else 0
        fp = cm[0][1] if len(cm) > 0 else 0
        delta_f1 = m["f1"] - blind_f1
        delta_str = rf"+{delta_f1:.3f}" if delta_f1 >= 0 else rf"{delta_f1:.3f}"
        label = CONFIG_LABELS[cfg]
        lines.append(
            rf"{label} & "
            rf"{m['accuracy']:.3f} & "
            rf"{m['precision']:.3f} & "
            rf"{m['recall']:.3f} & "
            rf"{m['f1']:.3f} & "
            rf"{fn} & "
            rf"{fp} & "
            rf"{delta_str} \\"
        )

    lines += [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(metrics_per_config: dict[str, dict]) -> None:
    blind_f1 = metrics_per_config["blind"]["f1"]
    header = (
        f"  {'Configuration':<22} "
        f"{'Accuracy':>9} "
        f"{'Precision':>10} "
        f"{'Recall':>8} "
        f"{'F1':>8} "
        f"{'dF1':>8}"
    )
    sep = "  " + "-" * (len(header) - 2)
    print()
    print("Signal Impact Results:")
    print(header)
    print(sep)
    for cfg in CONFIG_NAMES:
        m = metrics_per_config[cfg]
        delta = m["f1"] - blind_f1
        sign = "+" if delta >= 0 else ""
        print(
            f"  {CONFIG_LABELS[cfg]:<22} "
            f"{m['accuracy']:>9.3f} "
            f"{m['precision']:>10.3f} "
            f"{m['recall']:>8.3f} "
            f"{m['f1']:>8.3f} "
            f"{sign}{delta:>7.3f}"
        )
    print()

    # Key finding
    all_f1    = metrics_per_config["+all"]["f1"]
    total_gain = all_f1 - blind_f1
    print(
        f"  Key finding: signals improved F1 by "
        f"{total_gain:+.3f} "
        f"({blind_f1:.3f} blind -> {all_f1:.3f} enriched)"
    )
    if all_f1 < 1.0:
        print(
            "  Note: even with all signals the model is not perfect "
            "-- this motivates the trust hierarchy (E6)."
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment 5 -- Signal Impact on LLM Reliability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    print("=" * 60)
    print("Experiment 5 -- Signal Impact on LLM Reliability")
    print("=" * 60)
    print(f"  Provider : {args.provider}")
    print(f"  Model    : {args.model}")
    print(f"  Configs  : {' -> '.join(CONFIG_NAMES)}")

    corpus = load_corpus()
    print(f"  Corpus   : {len(corpus)} emails")
    print("-" * 60)

    output_dir = get_output_dir(EXPERIMENT_NAME)

    data = run_experiment(corpus=corpus, provider=args.provider, model=args.model)

    save_results(data, output_dir, "results")

    _print_summary(data["metrics_per_config"])

    print("Generating visualisations...")
    _plot_signal_progression(data["metrics_per_config"], output_dir)
    _plot_signal_delta_bars(data["metrics_per_config"], output_dir)
    _plot_per_case_signal_effect(data["per_case"], output_dir)
    _plot_confusion_matrices(data["per_case"], output_dir)

    latex_lines = _latex_table(data["metrics_per_config"], args.model)
    save_latex(latex_lines, output_dir, "signal_impact_table")

    print()
    print("Experiment 5 complete.")
    print(f"  Output dir: {output_dir}")


if __name__ == "__main__":
    main()
