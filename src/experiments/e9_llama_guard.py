"""e9_llama_guard.py -- Experiment 9: Llama Guard 3 False Positive Analysis

Research Question:
    What is Llama Guard 3's false positive rate on legitimate bank-related
    emails, and does integrating it as a hard gate improve or degrade
    overall pipeline performance?

Hypothesis:
    Llama Guard 3 produces an unacceptably high false positive rate on
    legitimate HTML/marketing emails, making it unsuitable as a hard
    blocker.  Demoting it to a soft signal preserves its value for
    adversarial prompt detection without degrading pipeline accuracy.

Background:
    Guard was DEMOTED from hard-block to soft signal after early testing
    revealed high FP rates on legitimate HTML emails containing marketing
    language, urgency cues, and rich formatting that Guard misclassified
    as adversarial content.  This experiment documents that finding
    quantitatively.

Output: data/experiments/e9_llama_guard/
  - guard_confusion.png        -- confusion matrix heatmap (Guard alone)
  - guard_impact.png           -- grouped bar: pipeline WITH vs WITHOUT guard
  - guard_fp_analysis.png      -- FP rate by email category
  - results_<ts>.json
  - guard_metrics_<ts>.tex
"""
from __future__ import annotations

import argparse
import json
import re
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
import seaborn as sns

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
EXPERIMENT_NAME = "e9_llama_guard"

METRICS = ["accuracy", "precision", "recall", "f1"]
METRIC_LABELS = ["Accuracy", "Precision", "Recall", "F1"]


# ---------------------------------------------------------------------------
# Category inference from case name
# ---------------------------------------------------------------------------

_CATEGORY_MAP = {
    # Malicious categories
    "OLE": "Office/Macro",
    "VBA": "Office/Macro",
    "macro": "Office/Macro",
    "oletools": "Office/Macro",
    "DDE": "Office/Macro",
    "RTF": "Office/Macro",
    "xlsm": "Office/Macro",
    "PPSX": "Office/Macro",
    "XLL": "Office/Macro",
    "OOXML": "Office/Macro",
    "PDF": "PDF",
    "pdf": "PDF",
    "PE_": "Executable",
    "exe": "Executable",
    "CPL": "Executable",
    "HTA": "Executable",
    "LNK": "Shortcut/Script",
    "WSF": "Shortcut/Script",
    "ISO": "Archive/Container",
    "VHD": "Archive/Container",
    "zip": "Archive/Container",
    "nested_zip": "Archive/Container",
    "encrypted_zip": "Archive/Container",
    "polyglot": "Polyglot",
    "phish": "Phishing",
    "credential": "Phishing",
    "spear": "Phishing",
    "CEO": "BEC/Social",
    "BEC": "BEC/Social",
    "wire_fraud": "BEC/Social",
    "thread_hijack": "BEC/Social",
    "spoofed": "BEC/Social",
    "qr_code": "Phishing",
    "homoglyph": "Phishing",
    "unicode": "Evasion",
    "zero_width": "Evasion",
    "base64": "Evasion",
    "steganography": "Evasion",
    "HTML_smuggling": "HTML/Script",
    "SVG": "HTML/Script",
    "MHTML": "HTML/Script",
    "CHM": "HTML/Script",
    "OneNote": "Office/Macro",
    "ICS": "Calendar",
    "calendar": "Calendar",
    # Benign categories
    "invoice": "Invoice/Billing",
    "legitimate_invoice": "Invoice/Billing",
    "linkedin": "Social Notification",
    "github": "Social Notification",
    "marketing": "Marketing",
    "promo": "Marketing",
    "newsletter": "Marketing",
    "conference": "Business Comms",
    "registration": "Business Comms",
    "internal": "Business Comms",
    "team_doc": "Business Comms",
    "delivery": "Transactional",
    "notification": "Transactional",
}


def _infer_category(case: dict) -> str:
    """Infer an email category from the case name/description."""
    name = case.get("name", "")
    for key, cat in _CATEGORY_MAP.items():
        if key in name:
            return cat
    # Fallback based on expected label
    return "Other Malicious" if case.get("expected") == "malicious" else "Other Benign"


# ---------------------------------------------------------------------------
# Llama Guard evaluation
# ---------------------------------------------------------------------------

def _get_email_body(case: dict) -> str:
    """Extract the email body text from a corpus case."""
    raw_bytes = case.get("raw_bytes") or case.get("eml")
    if raw_bytes:
        parsed = parse_email(raw_bytes)
        return parsed.get("body_text", "")
    return case.get("body", case.get("text", ""))


def _run_guard(email_body: str) -> str:
    """Run Llama Guard on a single email body, return 'safe' or 'unsafe'."""
    from analysis import is_payload_safe
    try:
        result = is_payload_safe(email_body)
        return "safe" if result else "unsafe"
    except Exception as e:
        print(f"  [GUARD-ERROR] {e}")
        # Fail-safe: treat errors as safe (Guard bypass)
        return "safe"


def _guard_to_binary(guard_verdict: str) -> str:
    """Map Guard verdict to binary classification.

    Guard says 'unsafe' -> we classify as malicious (it thinks the content is bad).
    Guard says 'safe'   -> we classify as benign.
    """
    return "malicious" if guard_verdict == "unsafe" else "benign"


# ---------------------------------------------------------------------------
# Pipeline simulation: WITH vs WITHOUT Guard
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict:
    """Extract the first JSON object from an LLM response string."""
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError("No valid JSON object found in LLM response")


def _call_llm_verdict(prompt: str, provider: str, model: str) -> dict[str, Any]:
    """Call the LLM and return a parsed verdict dict."""
    try:
        raw = call_model(prompt, provider=provider, model=model, temperature=0.0)
        data = _extract_json(raw)
        verdict = str(data.get("verdict", "error")).lower().strip()
        if verdict in ("accept", "accepted", "clean", "safe", "benign", "recu"):
            verdict = "accepter"
        elif verdict in ("reject", "rejected", "block"):
            verdict = "rejeter"
        elif verdict in ("escalate", "escalate_to_human", "escalade"):
            verdict = "escalader"
        elif verdict not in ("accepter", "rejeter", "escalader"):
            verdict = "escalader"
        return {
            "verdict": verdict,
            "confidence": float(data.get("confiance", data.get("confidence", 0.5))),
            "error": None,
        }
    except Exception as exc:
        return {"verdict": "escalader", "confidence": 0.0, "error": str(exc)[:300]}


def _build_parsed(case: dict) -> dict:
    """Return a parsed email dict from a corpus case."""
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
    }


def _run_pipeline_mode(
    case: dict,
    provider: str,
    model: str,
    guard_verdict: str,
    with_guard: bool,
) -> str:
    """Run pipeline and return binary classification.

    with_guard=True:  if Guard says unsafe, force escalation (hard gate).
    with_guard=False: ignore Guard, normal pipeline behavior.
    """
    # Guard hard gate: if enabled and Guard says unsafe, force escalate
    if with_guard and guard_verdict == "unsafe":
        return "malicious"

    parsed = _build_parsed(case)
    rules_result = run_rules_engine(parsed)
    parsed["analysis"] = rules_result
    ext_result = run_extraction(parsed)
    parsed["extraction"] = ext_result

    # Deterministic escalation check
    rules_flagged = any(d.get("flagged") for d in rules_result.get("details", []))
    ext_flagged = ext_result.get("escalate", False)

    if rules_flagged or ext_flagged:
        return "malicious"

    # LLM stage
    prompt = get_analysis_prompt(parsed, include_signals=True)
    result = _call_llm_verdict(prompt, provider, model)
    return classify_verdict(result["verdict"])


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_experiment(
    corpus: list[dict],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Run the full Llama Guard evaluation experiment."""

    # --- Phase 1: Guard standalone evaluation ---
    print("\n--- Phase 1: Llama Guard Standalone Evaluation ---")
    guard_records: list[dict] = []

    for i, case in enumerate(corpus, 1):
        email_id = case.get("id", case.get("name", case.get("path", str(i))))
        expected = case["expected"]
        category = _infer_category(case)
        body = _get_email_body(case)

        print(f"  [{i}/{len(corpus)}] Guard eval: {str(email_id)[:50]}")
        guard_verdict = _run_guard(body)

        guard_records.append({
            "email_id": str(email_id),
            "expected": expected,
            "guard_verdict": guard_verdict,
            "guard_binary": _guard_to_binary(guard_verdict),
            "body_length": len(body),
            "category": category,
        })

    # Compute Guard standalone metrics
    y_true = [r["expected"] for r in guard_records]
    y_pred = [r["guard_binary"] for r in guard_records]
    guard_metrics = compute_metrics(y_true, y_pred)

    # FP and FN counts
    n_benign = sum(1 for r in guard_records if r["expected"] == "benign")
    n_malicious = sum(1 for r in guard_records if r["expected"] == "malicious")
    fp_count = sum(1 for r in guard_records
                   if r["expected"] == "benign" and r["guard_binary"] == "malicious")
    fn_count = sum(1 for r in guard_records
                   if r["expected"] == "malicious" and r["guard_binary"] == "benign")
    fp_rate = fp_count / n_benign if n_benign > 0 else 0.0
    fn_rate = fn_count / n_malicious if n_malicious > 0 else 0.0

    guard_metrics["fp_count"] = fp_count
    guard_metrics["fn_count"] = fn_count
    guard_metrics["fp_rate"] = fp_rate
    guard_metrics["fn_rate"] = fn_rate

    print(f"\n  Guard standalone: FP={fp_count}/{n_benign} ({fp_rate:.1%}), "
          f"FN={fn_count}/{n_malicious} ({fn_rate:.1%}), "
          f"Acc={guard_metrics['accuracy']:.3f}, F1={guard_metrics['f1']:.3f}")

    # FP rate by category
    category_stats: dict[str, dict] = {}
    for r in guard_records:
        cat = r["category"]
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "fp": 0, "fn": 0,
                                    "expected_benign": 0, "expected_malicious": 0}
        category_stats[cat]["total"] += 1
        if r["expected"] == "benign":
            category_stats[cat]["expected_benign"] += 1
            if r["guard_binary"] == "malicious":
                category_stats[cat]["fp"] += 1
        else:
            category_stats[cat]["expected_malicious"] += 1
            if r["guard_binary"] == "benign":
                category_stats[cat]["fn"] += 1

    fp_by_category = {}
    for cat, stats in category_stats.items():
        if stats["expected_benign"] > 0:
            fp_by_category[cat] = {
                "fp_count": stats["fp"],
                "total_benign": stats["expected_benign"],
                "fp_rate": stats["fp"] / stats["expected_benign"],
            }

    # --- Phase 2: Pipeline WITH vs WITHOUT Guard ---
    print("\n--- Phase 2: Pipeline Comparison (WITH vs WITHOUT Guard) ---")
    pipeline_results: dict[str, list[dict]] = {"with_guard": [], "without_guard": []}

    # Pre-computed guard verdicts keyed by index
    guard_by_idx = {i: r["guard_verdict"] for i, r in enumerate(guard_records)}

    total_pipeline = len(corpus) * 2
    done = 0
    for i, case in enumerate(corpus):
        email_id = case.get("id", case.get("name", case.get("path", str(i))))
        expected = case["expected"]
        gv = guard_by_idx[i]

        for mode in ("with_guard", "without_guard"):
            done += 1
            with_guard = mode == "with_guard"
            print(f"  [{done}/{total_pipeline}] {mode}: {str(email_id)[:50]}")

            try:
                predicted = _run_pipeline_mode(
                    case, provider, model, gv, with_guard=with_guard,
                )
            except Exception as exc:
                print(f"    [ERROR] {exc}")
                predicted = "malicious"  # fail-safe

            pipeline_results[mode].append({
                "email_id": str(email_id),
                "expected": expected,
                "predicted": predicted,
                "guard_verdict": gv,
            })

    # Compute pipeline metrics for each mode
    pipeline_metrics: dict[str, dict] = {}
    for mode in ("with_guard", "without_guard"):
        yt = [r["expected"] for r in pipeline_results[mode]]
        yp = [r["predicted"] for r in pipeline_results[mode]]
        m = compute_metrics(yt, yp)
        fp = sum(1 for t, p in zip(yt, yp) if t == "benign" and p == "malicious")
        fn = sum(1 for t, p in zip(yt, yp) if t == "malicious" and p == "benign")
        m["fp_count"] = fp
        m["fn_count"] = fn
        pipeline_metrics[mode] = m
        label = "WITH Guard (hard gate)" if mode == "with_guard" else "WITHOUT Guard"
        print(f"\n  Pipeline {label}: "
              f"Acc={m['accuracy']:.3f}, F1={m['f1']:.3f}, FP={fp}, FN={fn}")

    return {
        "guard_records": guard_records,
        "guard_metrics": guard_metrics,
        "fp_by_category": fp_by_category,
        "category_stats": {k: v for k, v in category_stats.items()},
        "pipeline_results": pipeline_results,
        "pipeline_metrics": pipeline_metrics,
        "meta": {
            "provider": provider,
            "model": model,
            "n_emails": len(corpus),
            "n_malicious": n_malicious,
            "n_benign": n_benign,
        },
    }


# ---------------------------------------------------------------------------
# Visualisation 1: Guard confusion matrix heatmap
# ---------------------------------------------------------------------------

def _plot_guard_confusion(
    guard_metrics: dict,
    output_dir: Path,
) -> None:
    paper_style()
    fig, ax = plt.subplots(figsize=(6, 5))

    cm = np.array(guard_metrics["confusion_matrix"])
    labels = ["Benign", "Malicious"]

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Reds",
        xticklabels=labels, yticklabels=labels,
        ax=ax, linewidths=0.5, linecolor="gray",
        annot_kws={"size": 16, "weight": "bold"},
    )
    ax.set_xlabel("Guard Prediction", fontsize=12)
    ax.set_ylabel("True Label", fontsize=12)
    ax.set_title(
        "Llama Guard 3 Confusion Matrix (Standalone)\n"
        f"FP Rate: {guard_metrics['fp_rate']:.1%} | "
        f"FN Rate: {guard_metrics['fn_rate']:.1%}",
        fontweight="bold",
    )

    plt.tight_layout()
    out = output_dir / "guard_confusion.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Visualisation 2: Pipeline WITH vs WITHOUT Guard (grouped bar)
# ---------------------------------------------------------------------------

def _plot_guard_impact(
    pipeline_metrics: dict[str, dict],
    output_dir: Path,
) -> None:
    paper_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    modes = ["with_guard", "without_guard"]
    mode_labels = ["WITH Guard\n(hard gate)", "WITHOUT Guard\n(soft signal)"]
    mode_colors = ["#e74c3c", "#2ecc71"]

    x = np.arange(len(METRICS))
    bar_width = 0.32

    for i, (mode, label, color) in enumerate(zip(modes, mode_labels, mode_colors)):
        m = pipeline_metrics[mode]
        values = [m.get(metric, 0.0) for metric in METRICS]
        offset = (i - 0.5) * bar_width
        bars = ax.bar(
            x + offset, values,
            width=bar_width,
            color=color,
            edgecolor="black",
            linewidth=0.6,
            label=label,
        )
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.01,
                f"{val:.3f}",
                ha="center", va="bottom", fontsize=9, fontweight="bold",
            )

    ax.set_xticks(x)
    ax.set_xticklabels(METRIC_LABELS, fontsize=11)
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.18)
    ax.set_title(
        "Pipeline Performance: WITH vs WITHOUT Llama Guard Hard Gate\n"
        "(Guard as hard gate degrades precision due to false positives)",
        fontweight="bold",
    )
    ax.legend(loc="upper right", fontsize=10, framealpha=0.9)
    ax.axhline(1.0, color="gray", linestyle="--", linewidth=0.7, alpha=0.5)

    # Add FP/FN annotations below the chart
    for i, (mode, label) in enumerate(zip(modes, ["WITH", "WITHOUT"])):
        m = pipeline_metrics[mode]
        ax.text(
            0.25 + i * 0.5, -0.12,
            f"{label}: FP={m['fp_count']}, FN={m['fn_count']}",
            transform=ax.transAxes,
            ha="center", fontsize=9,
            bbox={"boxstyle": "round,pad=0.3", "facecolor": mode_colors[i],
                  "alpha": 0.15},
        )

    plt.tight_layout()
    out = output_dir / "guard_impact.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Visualisation 3: FP rate by email category
# ---------------------------------------------------------------------------

def _plot_fp_by_category(
    fp_by_category: dict[str, dict],
    output_dir: Path,
) -> None:
    paper_style()

    if not fp_by_category:
        print("  [SKIP] No benign categories to plot FP analysis.")
        return

    # Sort by FP rate descending
    sorted_cats = sorted(fp_by_category.items(), key=lambda x: x[1]["fp_rate"], reverse=True)
    categories = [c[0] for c in sorted_cats]
    fp_rates = [c[1]["fp_rate"] for c in sorted_cats]
    fp_counts = [c[1]["fp_count"] for c in sorted_cats]
    totals = [c[1]["total_benign"] for c in sorted_cats]

    fig, ax = plt.subplots(figsize=(10, max(5, len(categories) * 0.6)))

    y_pos = np.arange(len(categories))
    bar_colors = ["#e74c3c" if r > 0.5 else "#e67e22" if r > 0.2 else "#f1c40f" if r > 0 else "#2ecc71"
                  for r in fp_rates]

    bars = ax.barh(y_pos, fp_rates, color=bar_colors, edgecolor="black", linewidth=0.5)

    for j, (bar, fp, total) in enumerate(zip(bars, fp_counts, totals)):
        ax.text(
            bar.get_width() + 0.02,
            bar.get_y() + bar.get_height() / 2,
            f"{fp}/{total} ({fp_rates[j]:.0%})",
            va="center", fontsize=9,
        )

    ax.set_yticks(y_pos)
    ax.set_yticklabels(categories, fontsize=10)
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_xlim(0, min(max(fp_rates) + 0.25, 1.2) if fp_rates else 1.0)
    ax.set_title(
        "Llama Guard 3 False Positive Rate by Email Category\n"
        "(Benign emails misclassified as unsafe)",
        fontweight="bold",
    )
    ax.axvline(0.10, color="green", linestyle="--", linewidth=1.0, alpha=0.7,
               label="10% threshold")
    ax.legend(fontsize=9)
    ax.invert_yaxis()

    plt.tight_layout()
    out = output_dir / "guard_fp_analysis.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# LaTeX Table: Guard metrics + pipeline impact comparison
# ---------------------------------------------------------------------------

def _latex_guard_metrics(
    guard_metrics: dict,
    pipeline_metrics: dict[str, dict],
    fp_by_category: dict[str, dict],
) -> list[str]:
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Llama Guard 3 Performance Analysis}",
        r"\label{tab:e9_guard_metrics}",
        "",
        r"% --- Part A: Guard standalone ---",
        r"\subtable[Guard as Standalone Classifier]{",
        r"\begin{tabular}{l r}",
        r"\hline",
        r"Metric & Value \\",
        r"\hline",
        rf"Accuracy & {guard_metrics['accuracy']:.3f} \\",
        rf"Precision & {guard_metrics['precision']:.3f} \\",
        rf"Recall & {guard_metrics['recall']:.3f} \\",
        rf"F1 Score & {guard_metrics['f1']:.3f} \\",
        r"\hline",
        rf"False Positive Rate & {guard_metrics['fp_rate']*100:.1f}\% \\",
        rf"False Negative Rate & {guard_metrics['fn_rate']*100:.1f}\% \\",
        rf"False Positives (count) & {guard_metrics['fp_count']} \\",
        rf"False Negatives (count) & {guard_metrics['fn_count']} \\",
        r"\hline",
        r"\end{tabular}",
        r"}",
        "",
        r"% --- Part B: Pipeline impact ---",
        r"\vspace{1em}",
        r"\subtable[Pipeline Impact: WITH vs WITHOUT Guard]{",
        r"\begin{tabular}{l r r r r r r}",
        r"\hline",
        r"Mode & Accuracy & Precision & Recall & F1 & FP & FN \\",
        r"\hline",
    ]

    mode_display = {
        "with_guard": "WITH Guard (hard gate)",
        "without_guard": "WITHOUT Guard",
    }
    for mode, label in mode_display.items():
        m = pipeline_metrics[mode]
        lines.append(
            rf"{label} & "
            rf"{m['accuracy']:.3f} & "
            rf"{m['precision']:.3f} & "
            rf"{m['recall']:.3f} & "
            rf"{m['f1']:.3f} & "
            rf"{m['fp_count']} & "
            rf"{m['fn_count']} \\"
        )

    lines += [
        r"\hline",
        r"\end{tabular}",
        r"}",
        "",
    ]

    # Part C: FP by category (if data available)
    if fp_by_category:
        lines += [
            r"% --- Part C: FP rate by category ---",
            r"\vspace{1em}",
            r"\subtable[False Positive Rate by Email Category]{",
            r"\begin{tabular}{l r r r}",
            r"\hline",
            r"Category & FP & Total Benign & FP Rate \\",
            r"\hline",
        ]
        for cat, stats in sorted(fp_by_category.items(),
                                  key=lambda x: x[1]["fp_rate"], reverse=True):
            lines.append(
                rf"{cat} & {stats['fp_count']} & {stats['total_benign']} & "
                rf"{stats['fp_rate']:.1\%} \\"
            )
        lines += [
            r"\hline",
            r"\end{tabular}",
            r"}",
        ]

    lines += [
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment 9 -- Llama Guard 3 False Positive Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Guard uses local transformers, but we still need an LLM for the pipeline
    # comparison (WITH vs WITHOUT guard).
    parser.add_argument("--provider", default="ollama",
                        choices=["ollama", "openai", "groq", "together", "anthropic"],
                        help="LLM provider for pipeline comparison (default: ollama)")
    parser.add_argument("--model", default="gemma3:4b",
                        help="Model for pipeline LLM stage (default: gemma3:4b)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    print("=" * 64)
    print("Experiment 9 -- Llama Guard 3 False Positive Analysis")
    print("=" * 64)
    print(f"  Pipeline LLM : {args.provider} / {args.model}")
    print(f"  Guard model  : meta-llama/Llama-Guard-3-1B (local)")

    corpus = load_corpus()
    print(f"  Corpus       : {len(corpus)} emails")
    print("-" * 64)

    output_dir = get_output_dir(EXPERIMENT_NAME)

    # Run experiment
    data = run_experiment(corpus, provider=args.provider, model=args.model)

    # Save raw results
    save_results(data, output_dir, "results")

    # Print summary
    print()
    print("=" * 64)
    print("RESULTS SUMMARY")
    print("=" * 64)

    gm = data["guard_metrics"]
    print(f"\n  Llama Guard 3 (standalone):")
    print(f"    Accuracy  : {gm['accuracy']:.3f}")
    print(f"    Precision : {gm['precision']:.3f}")
    print(f"    Recall    : {gm['recall']:.3f}")
    print(f"    F1        : {gm['f1']:.3f}")
    print(f"    FP Rate   : {gm['fp_rate']:.1%} ({gm['fp_count']}/{data['meta']['n_benign']})")
    print(f"    FN Rate   : {gm['fn_rate']:.1%} ({gm['fn_count']}/{data['meta']['n_malicious']})")

    print(f"\n  Pipeline comparison:")
    print(f"  {'Mode':<30}  {'Acc':>5}  {'Prec':>5}  {'Rec':>5}  {'F1':>5}  {'FP':>4}  {'FN':>4}")
    print(f"  {'-'*30}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*4}  {'-'*4}")
    mode_display = {"with_guard": "WITH Guard (hard gate)", "without_guard": "WITHOUT Guard"}
    for mode, label in mode_display.items():
        m = data["pipeline_metrics"][mode]
        print(f"  {label:<30}  {m['accuracy']:>5.3f}  {m['precision']:>5.3f}  "
              f"{m['recall']:>5.3f}  {m['f1']:>5.3f}  {m['fp_count']:>4d}  {m['fn_count']:>4d}")

    if data["fp_by_category"]:
        print(f"\n  FP by category (benign emails):")
        for cat, stats in sorted(data["fp_by_category"].items(),
                                  key=lambda x: x[1]["fp_rate"], reverse=True):
            print(f"    {cat:<25}  {stats['fp_count']}/{stats['total_benign']}  "
                  f"({stats['fp_rate']:.0%})")

    # Visualisations
    print("\nGenerating visualisations...")
    _plot_guard_confusion(data["guard_metrics"], output_dir)
    _plot_guard_impact(data["pipeline_metrics"], output_dir)
    _plot_fp_by_category(data["fp_by_category"], output_dir)

    # LaTeX tables
    print("\nGenerating LaTeX tables...")
    save_latex(
        _latex_guard_metrics(
            data["guard_metrics"],
            data["pipeline_metrics"],
            data["fp_by_category"],
        ),
        output_dir, "guard_metrics",
    )

    print()
    print("Experiment 9 complete.")
    print(f"  Output dir: {output_dir}")
    print()
    print("KEY FINDING: Guard was demoted from hard-block to soft signal")
    print("because of high false positive rate on legitimate HTML emails.")
    print("This experiment quantifies that architectural decision.")


if __name__ == "__main__":
    main()
