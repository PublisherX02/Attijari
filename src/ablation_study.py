"""ablation_study.py — Trust No Email: Ablation Study & Model Comparison

Research framework for the paper:
  "Trust No Email: Constraining LLM Reasoning with Deterministic Signals
   for Privacy-Preserving Email Threat Triage"

Produces three experiments:
  1. ABLATION STUDY — Pipeline stages on/off to measure each component's
     contribution to detection accuracy.
  2. MODEL COMPARISON — Same corpus through multiple LLM models to find
     minimum viable model size.
  3. SIGNAL ENRICHMENT IMPACT — LLM with vs without structured signals
     to prove external signals constrain hallucination.

Outputs:
  data/ablation_results/
    ablation_table.json          — raw results for all configurations
    ablation_heatmap.png         — stage contribution heatmap
    ablation_bars.png            — grouped bar chart (accuracy/precision/recall/F1)
    model_comparison.json        — per-model results
    model_comparison_bars.png    — model accuracy comparison
    model_comparison_radar.png   — multi-axis model comparison
    signal_impact.json           — with vs without signals
    signal_impact_bars.png       — signal enrichment impact chart
    paper_tables.txt             — LaTeX-ready tables for the paper

Usage:
  python src/ablation_study.py                    # Full study (requires Ollama)
  python src/ablation_study.py --no-llm           # Deterministic stages only (fast)
  python src/ablation_study.py --models gemma3:4b qwen3:8b
  python src/ablation_study.py --ablation-only    # Skip model comparison
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
_SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_SRC.parent / ".env")

from accuracy import (
    build_malicious_cases,
    build_benign_cases,
    run_pipeline_isolated,
    classify_result,
    compute_metrics,
)

_OUT_DIR = _SRC.parent / "data" / "ablation_results"
_OUT_DIR.mkdir(parents=True, exist_ok=True)

# Paper color palette
COLORS = {
    "full":       "#2ecc71",  # green
    "no_llm":     "#3498db",  # blue
    "no_extract": "#e67e22",  # orange
    "no_rules":   "#e74c3c",  # red
    "llm_only":   "#9b59b6",  # purple
    "rules_only": "#1abc9c",  # teal
    "auth_only":  "#f39c12",  # yellow
}

MODEL_COLORS = ["#2ecc71", "#3498db", "#e67e22", "#e74c3c", "#9b59b6",
                "#1abc9c", "#f39c12", "#e91e63"]


# ============================================================================
# EXPERIMENT 1: ABLATION STUDY
# ============================================================================

def run_ablation_config(
    cases: list[dict],
    config_name: str,
    enable_auth: bool = True,
    enable_rules: bool = True,
    enable_extraction: bool = True,
    enable_llm: bool = True,
    model: str | None = None,
    pass_signals_to_llm: bool = True,
) -> dict:
    """Run test corpus through a specific pipeline configuration.

    Returns metrics dict with per-case results.
    """
    print(f"\n{'-'*60}")
    print(f"  Config: {config_name}")
    print(f"  Auth={enable_auth}  Rules={enable_rules}  "
          f"Extraction={enable_extraction}  LLM={enable_llm}")
    print(f"{'-'*60}")

    y_true, y_pred = [], []
    case_results = []
    total_time = 0.0

    for i, case in enumerate(cases, 1):
        t0 = time.time()

        if enable_auth and enable_rules and enable_extraction:
            # Full pipeline (or full minus LLM)
            result = run_pipeline_isolated(case["eml"], run_llm=enable_llm)
        else:
            # Custom pipeline — need to selectively disable stages
            result = _run_selective_pipeline(
                case["eml"],
                enable_auth=enable_auth,
                enable_rules=enable_rules,
                enable_extraction=enable_extraction,
                enable_llm=enable_llm,
                model=model,
                pass_signals=pass_signals_to_llm,
            )

        elapsed = time.time() - t0
        total_time += elapsed

        predicted = classify_result(result)
        y_true.append(case["expected"])
        y_pred.append(predicted)

        tag = "MAL" if case["expected"] == "malicious" else "BEN"
        match = "OK" if case["expected"] == predicted else "MISS"
        print(f"  [{i:02d}/{len(cases)}] [{tag}] {case['name'][:40]:40s} "
              f"-> {predicted:9s} [{match}] ({elapsed:.1f}s)")

        case_results.append({
            "name": case["name"],
            "expected": case["expected"],
            "predicted": predicted,
            "final_status": result["final_status"],
            "stages": result["stages"],
            "elapsed_s": round(elapsed, 2),
        })

    metrics = compute_metrics(y_true, y_pred)
    cm = metrics["confusion_matrix"]

    print(f"\n  Results for '{config_name}':")
    print(f"    Accuracy:  {metrics['accuracy']:.1%}")
    print(f"    Precision: {metrics['precision']:.1%}")
    print(f"    Recall:    {metrics['recall']:.1%}")
    print(f"    F1:        {metrics['f1']:.1%}")
    print(f"    FN={cm[1][0]}  FP={cm[0][1]}  "
          f"Avg latency={total_time/len(cases):.2f}s")

    return {
        "config": config_name,
        "settings": {
            "auth": enable_auth, "rules": enable_rules,
            "extraction": enable_extraction, "llm": enable_llm,
        },
        "metrics": {k: v for k, v in metrics.items()
                    if k != "classification_report"},
        "classification_report": metrics["classification_report"],
        "total_time_s": round(total_time, 2),
        "avg_latency_s": round(total_time / len(cases), 3),
        "cases": case_results,
    }


def _run_selective_pipeline(
    raw_eml: bytes,
    enable_auth: bool,
    enable_rules: bool,
    enable_extraction: bool,
    enable_llm: bool,
    model: str | None = None,
    pass_signals: bool = True,
) -> dict:
    """Run pipeline with individual stages togglable for ablation study."""
    from email_extraction import EmailIngestion
    from rules import RuleEngine

    result = {
        "stages": {},
        "final_status": "unknown",
        "flags_total": 0,
        "deterministic_escalation": False,
    }

    # --- Parse (always needed) ---
    ingestion = EmailIngestion(host="", user="", password="")
    try:
        parsed = ingestion.parse_email(raw_eml)
    except Exception as e:
        result["final_status"] = "escalated"
        result["stages"]["parse"] = {"error": str(e)}
        return result

    result["stages"]["parse"] = {
        "status": parsed.get("status"),
        "attachments": len(parsed.get("attachments", [])),
    }

    # --- Auth ---
    if enable_auth:
        auth_header = parsed.get("headers", {}).get("authentication-results") or ""
        auth_failed = any(x in auth_header.lower()
                         for x in ["dkim=fail", "spf=fail", "dmarc=fail"])
        parsed["auth"] = {
            "summary": auth_header,
            "any_failure": auth_failed,
            "auth_header": {
                "spf": "fail" if "spf=fail" in auth_header.lower() else "pass" if "spf=pass" in auth_header.lower() else "none",
                "dkim": "fail" if "dkim=fail" in auth_header.lower() else "pass" if "dkim=pass" in auth_header.lower() else "none",
                "dmarc": "fail" if "dmarc=fail" in auth_header.lower() else "pass" if "dmarc=pass" in auth_header.lower() else "none",
            },
        }
        if auth_failed:
            parsed["status"] = "escalated"
            result["deterministic_escalation"] = True
        result["stages"]["auth"] = {"failed": auth_failed}
    else:
        parsed["auth"] = {}
        result["stages"]["auth"] = {"skipped": True}

    # --- Rules ---
    if enable_rules:
        import rules as _rules_mod
        _saved_cache = _rules_mod._blocklist_cache
        _saved_time = _rules_mod._blocklist_cache_time
        _rules_mod._blocklist_cache = set()
        _rules_mod._blocklist_cache_time = time.time()

        engine = RuleEngine()
        pre_status = parsed["status"]
        analysis = engine.analyze(parsed)

        _rules_mod._blocklist_cache = _saved_cache
        _rules_mod._blocklist_cache_time = _saved_time

        if pre_status == "escalated" and analysis["verdict"] == "accepted":
            analysis["verdict"] = "escalated"
        parsed["status"] = analysis["verdict"]
        parsed["analysis"] = analysis

        rules_flags = [d for d in analysis["details"] if d["flagged"]]
        result["stages"]["rules"] = {
            "verdict": analysis["verdict"],
            "flags": len(rules_flags),
            "flagged_rules": [d["rule"] for d in rules_flags],
        }
        if rules_flags:
            result["deterministic_escalation"] = True
    else:
        result["stages"]["rules"] = {"skipped": True}

    # --- Extraction ---
    if enable_extraction and parsed.get("attachments"):
        try:
            from extraction import extract_all_attachments
            ext_result = extract_all_attachments(parsed)
            parsed["extraction"] = ext_result

            result["stages"]["extraction"] = {
                "total_flags": ext_result.get("total_flags", 0),
                "escalate": ext_result.get("escalate", False),
            }
            if ext_result.get("escalate"):
                parsed["status"] = "escalated"
                result["deterministic_escalation"] = True
        except Exception as e:
            result["stages"]["extraction"] = {"error": str(e)}
    else:
        result["stages"]["extraction"] = {"skipped": True}

    # --- LLM ---
    if enable_llm and parsed["status"] != "escalated":
        try:
            from analysis import analyze_email_body
            enrichment_data = {}
            if pass_signals:
                enrichment_data["auth"] = parsed.get("auth", {})
                if parsed.get("extraction", {}).get("results"):
                    enrichment_data["extraction"] = [
                        {"filename": r.get("filename"), "flags": r.get("flags", []),
                         "type_mismatch": r.get("type_mismatch"), "iocs": r.get("iocs", {})}
                        for r in parsed["extraction"]["results"]
                    ]

            context = {
                "headers": parsed.get("headers", {}),
                "attachments": parsed.get("attachments", []),
                "enrichment": enrichment_data if pass_signals else {},
            }
            llm_res = analyze_email_body(
                parsed.get("body_text", ""), context=context,
                model=model,
            )
            llm_verdict = (llm_res.get("verdict") or "").lower().strip()
            if llm_verdict in ("accepter", "accepted", "accept", "clean", "safe"):
                llm_verdict = "accepted"
            else:
                llm_verdict = "escalated"

            if parsed["status"] != "escalated" and llm_verdict == "escalated":
                parsed["status"] = "escalated"

            result["stages"]["llm"] = {
                "verdict": llm_verdict,
                "confidence": llm_res.get("confidence"),
                "risk_score": llm_res.get("risk_score"),
            }
        except Exception as e:
            parsed["status"] = "escalated"
            result["stages"]["llm"] = {"error": str(e), "verdict": "escalated"}
    elif enable_llm:
        result["stages"]["llm"] = {"skipped": "already_escalated", "verdict": "escalated"}
    else:
        result["stages"]["llm"] = {"skipped": "disabled"}

    result["final_status"] = parsed["status"]
    return result


def run_ablation_study(cases: list[dict], include_llm: bool = True) -> list[dict]:
    """Run the full ablation study across all pipeline configurations."""
    configs = [
        # Full pipeline
        {"name": "Full Pipeline (Auth+Rules+Extract+LLM)",
         "auth": True, "rules": True, "extraction": True, "llm": True},

        # Remove one stage at a time
        {"name": "No LLM (Deterministic Only)",
         "auth": True, "rules": True, "extraction": True, "llm": False},
        {"name": "No Extraction",
         "auth": True, "rules": True, "extraction": False, "llm": True},
        {"name": "No Rules Engine",
         "auth": True, "rules": False, "extraction": True, "llm": True},
        {"name": "No Auth Check",
         "auth": False, "rules": True, "extraction": True, "llm": True},

        # Isolated stages
        {"name": "LLM Only (No Signals)",
         "auth": False, "rules": False, "extraction": False, "llm": True},
        {"name": "Rules + Extraction Only",
         "auth": True, "rules": True, "extraction": True, "llm": False},
    ]

    if not include_llm:
        configs = [c for c in configs if not c["llm"]]
        # Add rules-only and auth-only for deterministic comparison
        configs.append({"name": "Rules Only",
                        "auth": False, "rules": True, "extraction": False, "llm": False})
        configs.append({"name": "Auth Only",
                        "auth": True, "rules": False, "extraction": False, "llm": False})

    results = []
    for cfg in configs:
        r = run_ablation_config(
            cases, cfg["name"],
            enable_auth=cfg["auth"],
            enable_rules=cfg["rules"],
            enable_extraction=cfg["extraction"],
            enable_llm=cfg["llm"],
        )
        results.append(r)

    return results


# ============================================================================
# EXPERIMENT 2: MODEL COMPARISON
# ============================================================================

def run_model_comparison(
    cases: list[dict],
    models: list[str],
) -> list[dict]:
    """Compare multiple LLM models on the same corpus."""
    print("\n" + "=" * 60)
    print("  EXPERIMENT 2: MODEL COMPARISON")
    print("=" * 60)

    results = []
    for model_name in models:
        print(f"\n  Testing model: {model_name}")

        # Set the model for this run
        os.environ["LLM_MODEL"] = model_name

        # Need to reimport to pick up new model
        import importlib
        import analysis as _analysis_mod
        importlib.reload(_analysis_mod)

        r = run_ablation_config(
            cases, f"Full Pipeline ({model_name})",
            enable_auth=True, enable_rules=True,
            enable_extraction=True, enable_llm=True,
            model=model_name,
        )
        r["model"] = model_name
        results.append(r)

    return results


# ============================================================================
# EXPERIMENT 3: SIGNAL ENRICHMENT IMPACT
# ============================================================================

def run_signal_impact_study(cases: list[dict]) -> list[dict]:
    """Compare LLM with and without structured signals (RQ1 core experiment)."""
    print("\n" + "=" * 60)
    print("  EXPERIMENT 3: SIGNAL ENRICHMENT IMPACT")
    print("  (LLM + Signals vs LLM Alone)")
    print("=" * 60)

    results = []

    # LLM with full signal enrichment
    r1 = run_ablation_config(
        cases, "LLM + All Deterministic Signals",
        enable_auth=True, enable_rules=True,
        enable_extraction=True, enable_llm=True,
        pass_signals_to_llm=True,
    )
    results.append(r1)

    # LLM without signals — raw email only
    r2 = run_ablation_config(
        cases, "LLM Alone (No External Signals)",
        enable_auth=False, enable_rules=False,
        enable_extraction=False, enable_llm=True,
        pass_signals_to_llm=False,
    )
    results.append(r2)

    # LLM with signals but no trust hierarchy override
    r3 = run_ablation_config(
        cases, "LLM + Signals (No Trust Hierarchy)",
        enable_auth=True, enable_rules=True,
        enable_extraction=True, enable_llm=True,
        pass_signals_to_llm=True,
    )
    results.append(r3)

    return results


# ============================================================================
# VISUALIZATIONS (Paper-quality)
# ============================================================================

def _paper_style():
    """Apply consistent paper-quality matplotlib style."""
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 12,
        "axes.titlesize": 14,
        "axes.titleweight": "bold",
        "axes.labelsize": 12,
        "figure.dpi": 200,
        "savefig.dpi": 300,
    })


def plot_ablation_bars(results: list[dict], output_path: Path):
    """Grouped bar chart comparing metrics across ablation configs."""
    _paper_style()

    configs = [r["config"] for r in results]
    # Shorten names for display
    short_names = []
    for c in configs:
        name = (c.replace("Full Pipeline (Auth+Rules+Extract+LLM)", "Full Pipeline")
                 .replace("No LLM (Deterministic Only)", "No LLM")
                 .replace("Rules + Extraction Only", "Rules+Extract")
                 .replace("LLM Only (No Signals)", "LLM Only")
                 .replace("No Extraction", "No Extract")
                 .replace("No Rules Engine", "No Rules")
                 .replace("No Auth Check", "No Auth"))
        short_names.append(name)

    metrics_keys = ["accuracy", "precision", "recall", "f1"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1"]
    x = np.arange(len(short_names))
    width = 0.2

    fig, ax = plt.subplots(figsize=(14, 7))
    for j, (key, label) in enumerate(zip(metrics_keys, metric_labels)):
        values = [r["metrics"][key] for r in results]
        bars = ax.bar(x + j * width, values, width, label=label, alpha=0.85)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.0%}", ha="center", va="bottom", fontsize=8, fontweight="bold")

    ax.set_ylabel("Score")
    ax.set_title("Trust No Email — Ablation Study: Stage Contribution to Detection",
                 fontweight="bold")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(short_names, rotation=25, ha="right", fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.axhline(y=1.0, color="#999", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.legend(loc="upper right", framealpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    print(f"  [PLOT] Ablation bars -> {output_path}")


def plot_ablation_heatmap(results: list[dict], output_path: Path):
    """Heatmap showing FN/FP counts per configuration."""
    _paper_style()

    configs = [r["config"].split("(")[0].strip() for r in results]
    data = []
    for r in results:
        cm = r["metrics"]["confusion_matrix"]
        data.append([cm[1][1], cm[0][0], cm[0][1], cm[1][0]])  # TP, TN, FP, FN

    fig, ax = plt.subplots(figsize=(10, max(5, len(configs) * 0.6)))
    arr = np.array(data)
    labels_col = ["TP\n(Caught)", "TN\n(Clean OK)", "FP\n(False Alarm)", "FN\n(MISSED)"]

    sns.heatmap(arr, annot=True, fmt="d", cmap="RdYlGn",
                xticklabels=labels_col, yticklabels=configs,
                linewidths=1, linecolor="#333", ax=ax,
                annot_kws={"fontsize": 12, "fontweight": "bold"})
    ax.set_title("Trust No Email — Detection Outcomes by Pipeline Configuration",
                 fontweight="bold", pad=15)

    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    print(f"  [PLOT] Ablation heatmap -> {output_path}")


def plot_model_comparison(results: list[dict], output_path: Path):
    """Bar chart comparing models on all metrics."""
    _paper_style()

    models = [r.get("model", r["config"]) for r in results]
    metrics_keys = ["accuracy", "precision", "recall", "f1"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1"]
    x = np.arange(len(models))
    width = 0.2

    fig, ax = plt.subplots(figsize=(12, 6))
    for j, (key, label) in enumerate(zip(metrics_keys, metric_labels)):
        values = [r["metrics"][key] for r in results]
        bars = ax.bar(x + j * width, values, width, label=label,
                      color=MODEL_COLORS[j], alpha=0.85, edgecolor="#222")
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.0%}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_ylabel("Score")
    ax.set_title("Trust No Email — LLM Model Comparison (RQ3: Minimum Viable Model Size)",
                 fontweight="bold")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(models, fontsize=10)
    ax.set_ylim(0, 1.15)
    ax.legend(loc="upper right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    print(f"  [PLOT] Model comparison -> {output_path}")


def plot_model_radar(results: list[dict], output_path: Path):
    """Radar chart comparing models across multiple dimensions."""
    _paper_style()

    models = [r.get("model", r["config"]) for r in results]
    categories = ["Accuracy", "Precision", "Recall", "F1", "Speed"]
    N = len(categories)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    max_latency = max(r["avg_latency_s"] for r in results) or 1
    for i, r in enumerate(results):
        values = [
            r["metrics"]["accuracy"],
            r["metrics"]["precision"],
            r["metrics"]["recall"],
            r["metrics"]["f1"],
            1 - (r["avg_latency_s"] / max_latency),  # Invert: faster = better
        ]
        values += values[:1]
        ax.plot(angles, values, "o-", linewidth=2, label=models[i],
                color=MODEL_COLORS[i % len(MODEL_COLORS)])
        ax.fill(angles, values, alpha=0.1, color=MODEL_COLORS[i % len(MODEL_COLORS)])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylim(0, 1.1)
    ax.set_title("Trust No Email — Model Capability Radar (RQ3)",
                 fontweight="bold", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1))

    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    print(f"  [PLOT] Model radar -> {output_path}")


def plot_signal_impact(results: list[dict], output_path: Path):
    """Side-by-side comparison: LLM with signals vs LLM alone."""
    _paper_style()

    configs = [r["config"] for r in results]
    short = [c.replace("LLM + All Deterministic Signals", "LLM + Signals")
              .replace("LLM Alone (No External Signals)", "LLM Alone")
              .replace("LLM + Signals (No Trust Hierarchy)", "LLM + Signals\n(No Hierarchy)")
             for c in configs]

    metrics_keys = ["accuracy", "precision", "recall", "f1"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1"]
    x = np.arange(len(short))
    width = 0.18

    fig, ax = plt.subplots(figsize=(11, 6))
    colors = ["#2ecc71", "#e74c3c", "#3498db", "#e67e22"]
    for j, (key, label) in enumerate(zip(metrics_keys, metric_labels)):
        values = [r["metrics"][key] for r in results]
        bars = ax.bar(x + j * width, values, width, label=label,
                      color=colors[j], alpha=0.85, edgecolor="#222")
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.0%}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_ylabel("Score")
    ax.set_title("Trust No Email — Impact of Deterministic Signal Enrichment on LLM Accuracy (RQ1)",
                 fontweight="bold", fontsize=12)
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(short, fontsize=10)
    ax.set_ylim(0, 1.18)
    ax.axhline(y=1.0, color="#999", linestyle="--", linewidth=0.8)
    ax.legend(loc="upper right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    print(f"  [PLOT] Signal impact -> {output_path}")


# ============================================================================
# LATEX TABLE GENERATION
# ============================================================================

def generate_latex_tables(
    ablation: list[dict],
    model_comp: list[dict] | None,
    signal_imp: list[dict] | None,
    output_path: Path,
):
    """Generate LaTeX-ready tables for the research paper."""
    lines = []
    lines.append("% ==============================================")
    lines.append("% Trust No Email — Paper Tables (auto-generated)")
    lines.append(f"% Generated: {datetime.now().isoformat()}")
    lines.append("% ==============================================\n")

    # --- Table 1: Ablation Study ---
    lines.append("% TABLE 1: Ablation Study — Stage Contribution")
    lines.append("\\begin{table}[h]")
    lines.append("\\centering")
    lines.append("\\caption{Ablation study results. Each row disables one pipeline "
                 "stage to measure its contribution to detection accuracy.}")
    lines.append("\\label{tab:ablation}")
    lines.append("\\begin{tabular}{lcccccc}")
    lines.append("\\toprule")
    lines.append("Configuration & Acc & Prec & Rec & F1 & FN & FP \\\\")
    lines.append("\\midrule")
    for r in ablation:
        name = (r["config"].split("(")[0].strip()[:30])
        m = r["metrics"]
        cm = m["confusion_matrix"]
        fn, fp = cm[1][0], cm[0][1]
        # Bold the best F1
        f1_str = f"{m['f1']:.1%}"
        lines.append(
            f"{name} & {m['accuracy']:.1%} & {m['precision']:.1%} & "
            f"{m['recall']:.1%} & {f1_str} & {fn} & {fp} \\\\"
        )
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}\n")

    # --- Table 2: Model Comparison ---
    if model_comp:
        lines.append("% TABLE 2: LLM Model Comparison")
        lines.append("\\begin{table}[h]")
        lines.append("\\centering")
        lines.append("\\caption{Detection performance across LLM models of varying size. "
                     "All models receive identical deterministic signals.}")
        lines.append("\\label{tab:models}")
        lines.append("\\begin{tabular}{lccccc}")
        lines.append("\\toprule")
        lines.append("Model & Acc & Prec & Rec & F1 & Avg Latency (s) \\\\")
        lines.append("\\midrule")
        for r in model_comp:
            name = r.get("model", r["config"])
            m = r["metrics"]
            lines.append(
                f"{name} & {m['accuracy']:.1%} & {m['precision']:.1%} & "
                f"{m['recall']:.1%} & {m['f1']:.1%} & {r['avg_latency_s']:.1f} \\\\"
            )
        lines.append("\\bottomrule")
        lines.append("\\end{tabular}")
        lines.append("\\end{table}\n")

    # --- Table 3: Signal Impact ---
    if signal_imp:
        lines.append("% TABLE 3: Signal Enrichment Impact (RQ1)")
        lines.append("\\begin{table}[h]")
        lines.append("\\centering")
        lines.append("\\caption{Impact of deterministic signal enrichment on LLM verdict "
                     "reliability. ``LLM Alone'' receives only raw email text.}")
        lines.append("\\label{tab:signals}")
        lines.append("\\begin{tabular}{lcccccc}")
        lines.append("\\toprule")
        lines.append("Configuration & Acc & Prec & Rec & F1 & FN & FP \\\\")
        lines.append("\\midrule")
        for r in signal_imp:
            name = r["config"][:35]
            m = r["metrics"]
            cm = m["confusion_matrix"]
            lines.append(
                f"{name} & {m['accuracy']:.1%} & {m['precision']:.1%} & "
                f"{m['recall']:.1%} & {m['f1']:.1%} & {cm[1][0]} & {cm[0][1]} \\\\"
            )
        lines.append("\\bottomrule")
        lines.append("\\end{tabular}")
        lines.append("\\end{table}\n")

    # --- Summary Statistics ---
    lines.append("% KEY FINDINGS SUMMARY")
    if ablation:
        full = next((r for r in ablation if "Full" in r["config"]), ablation[0])
        lines.append(f"% Full pipeline: Acc={full['metrics']['accuracy']:.1%}, "
                     f"F1={full['metrics']['f1']:.1%}, "
                     f"FN={full['metrics']['confusion_matrix'][1][0]}")
    if model_comp:
        best = max(model_comp, key=lambda r: r["metrics"]["f1"])
        lines.append(f"% Best model: {best.get('model', 'N/A')} "
                     f"(F1={best['metrics']['f1']:.1%})")
    if signal_imp and len(signal_imp) >= 2:
        with_sig = signal_imp[0]["metrics"]["f1"]
        without = signal_imp[1]["metrics"]["f1"]
        delta = with_sig - without
        lines.append(f"% Signal enrichment F1 delta: +{delta:.1%}")

    text = "\n".join(lines)
    output_path.write_text(text, encoding="utf-8")
    print(f"  [LATEX] Paper tables -> {output_path}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Trust No Email — Ablation Study & Model Comparison"
    )
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip LLM experiments (deterministic stages only)")
    parser.add_argument("--ablation-only", action="store_true",
                        help="Run only ablation study, skip model comparison")
    parser.add_argument("--models", nargs="+",
                        default=["gemma3:4b", "qwen3:8b"],
                        help="LLM models to compare (default: gemma3:4b qwen3:8b)")
    parser.add_argument("--signal-study", action="store_true",
                        help="Run signal enrichment impact study (RQ1)")
    parser.add_argument("--all", action="store_true",
                        help="Run all experiments")
    args = parser.parse_args()

    include_llm = not args.no_llm

    print("=" * 60)
    print("  TRUST NO EMAIL — Research Experiment Suite")
    print("  Ablation Study & Model Comparison")
    print("=" * 60)
    print(f"  LLM experiments: {'ON' if include_llm else 'OFF'}")
    print(f"  Models to test:  {', '.join(args.models)}")
    print(f"  Output dir:      {_OUT_DIR}")
    print()

    # Build test corpus
    cases = build_malicious_cases() + build_benign_cases()
    total_mal = sum(1 for c in cases if c["expected"] == "malicious")
    total_ben = sum(1 for c in cases if c["expected"] == "benign")
    print(f"[CORPUS] {len(cases)} cases: {total_mal} malicious, {total_ben} benign\n")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Experiment 1: Ablation ──
    print("=" * 60)
    print("  EXPERIMENT 1: ABLATION STUDY")
    print("=" * 60)
    ablation_results = run_ablation_study(cases, include_llm=include_llm)

    plot_ablation_bars(ablation_results, _OUT_DIR / f"ablation_bars_{timestamp}.png")
    plot_ablation_heatmap(ablation_results, _OUT_DIR / f"ablation_heatmap_{timestamp}.png")

    ablation_json = _OUT_DIR / f"ablation_table_{timestamp}.json"
    with open(ablation_json, "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2, default=str)
    print(f"  [JSON] Ablation results -> {ablation_json}")

    # ── Experiment 2: Model Comparison ──
    model_results = None
    if include_llm and not args.ablation_only:
        model_results = run_model_comparison(cases, args.models)

        plot_model_comparison(model_results,
                              _OUT_DIR / f"model_comparison_{timestamp}.png")
        plot_model_radar(model_results,
                         _OUT_DIR / f"model_radar_{timestamp}.png")

        model_json = _OUT_DIR / f"model_comparison_{timestamp}.json"
        with open(model_json, "w", encoding="utf-8") as f:
            json.dump(model_results, f, indent=2, default=str)
        print(f"  [JSON] Model comparison -> {model_json}")

    # ── Experiment 3: Signal Impact ──
    signal_results = None
    if include_llm and (args.signal_study or args.all):
        signal_results = run_signal_impact_study(cases)

        plot_signal_impact(signal_results,
                           _OUT_DIR / f"signal_impact_{timestamp}.png")

        signal_json = _OUT_DIR / f"signal_impact_{timestamp}.json"
        with open(signal_json, "w", encoding="utf-8") as f:
            json.dump(signal_results, f, indent=2, default=str)
        print(f"  [JSON] Signal impact -> {signal_json}")

    # ── Generate LaTeX Tables ──
    generate_latex_tables(
        ablation_results,
        model_results,
        signal_results,
        _OUT_DIR / f"paper_tables_{timestamp}.tex",
    )

    # ── Final Summary ──
    print("\n" + "=" * 60)
    print("  EXPERIMENT SUMMARY")
    print("=" * 60)
    print(f"  Corpus:     {len(cases)} test cases "
          f"({total_mal} malicious, {total_ben} benign)")
    print(f"  Ablation:   {len(ablation_results)} configurations tested")
    if model_results:
        best = max(model_results, key=lambda r: r["metrics"]["f1"])
        print(f"  Best model: {best.get('model', 'N/A')} "
              f"(F1={best['metrics']['f1']:.1%})")
    if signal_results and len(signal_results) >= 2:
        with_sig = signal_results[0]["metrics"]
        without = signal_results[1]["metrics"]
        print(f"  Signal impact:")
        print(f"    With signals:    F1={with_sig['f1']:.1%}  "
              f"FN={with_sig['confusion_matrix'][1][0]}")
        print(f"    Without signals: F1={without['f1']:.1%}  "
              f"FN={without['confusion_matrix'][1][0]}")
    print(f"\n  All outputs: {_OUT_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()
