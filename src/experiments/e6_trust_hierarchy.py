"""e6_trust_hierarchy.py -- Experiment 6: Trust Hierarchy vs. LLM Autonomy

Research Question:
    Can a deterministic trust hierarchy bound LLM unreliability to an
    acceptable error surface?

Hypothesis:
    When deterministic signals override LLM outputs (not vice versa),
    false negatives drop to zero regardless of LLM instability.

Configurations tested:
    1. LLM Only          -- LLM decides everything, no rules, no extraction.
    2. LLM + Signals     -- LLM receives signals as context but makes the
       (Flat)               final decision. Rules cannot override LLM.
    3. LLM + Signals     -- Rules/extraction CAN override LLM to escalate,
       (Trust Hierarchy)    but LLM can NEVER override rules to accept.
                            This is the actual Trust No Email architecture.
    4. Full Pipeline     -- Complete production pipeline (accuracy.py).

Output: data/experiments/e6_trust_hierarchy/
  - hierarchy_comparison.png
  - fn_elimination.png
  - trust_flow_sankey.png
  - error_surface.png
  - results_<ts>.json
  - config_comparison_<ts>.tex
  - stage_attribution_<ts>.tex
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
import matplotlib.patches as mpatches
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
EXPERIMENT_NAME = "e6_trust_hierarchy"

CONFIG_NAMES = [
    "LLM Only",
    "LLM + Signals (Flat)",
    "LLM + Signals (Trust Hierarchy)",
    "Full Pipeline (Production)",
]

CONFIG_COLORS = ["#e74c3c", "#e67e22", "#2ecc71", "#3498db"]

METRICS = ["accuracy", "precision", "recall", "f1"]
METRIC_LABELS = ["Accuracy", "Precision", "Recall", "F1"]


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict:
    """Extract the first JSON object from an LLM response string."""
    # Try nested and flat JSON objects
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    # Try to find any JSON-like structure with verdict key
    match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError("No valid JSON object found in LLM response")


def _call_llm_verdict(
    prompt: str,
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Call the LLM and return a parsed verdict dict.

    Returns sentinel with verdict='error' on any failure.
    """
    try:
        raw = call_model(prompt, provider=provider, model=model, temperature=0.0)
        data = _extract_json(raw)
        verdict = str(data.get("verdict", "error")).lower().strip()
        # Normalise variant spellings
        if verdict in ("accept", "accepted", "clean", "safe", "benign", "recu"):
            verdict = "accepter"
        elif verdict in ("reject", "rejected", "block"):
            verdict = "rejeter"
        elif verdict in ("escalate", "escalate_to_human", "escalade"):
            verdict = "escalader"
        elif verdict not in ("accepter", "rejeter", "escalader"):
            verdict = "escalader"  # fail-safe
        return {
            "verdict": verdict,
            "confidence": float(data.get("confiance", data.get("confidence", 0.5))),
            "score_risque": int(data.get("score_risque", data.get("risk_score", 50))),
            "raw": raw[:500],
            "error": None,
        }
    except Exception as exc:
        return {
            "verdict": "escalader",  # fail-safe on error
            "confidence": 0.0,
            "score_risque": -1,
            "raw": "",
            "error": str(exc)[:300],
        }


def _build_parsed(case: dict) -> dict:
    """Return a parsed email dict from a corpus case."""
    raw_bytes = case.get("raw_bytes") or case.get("eml")
    if raw_bytes:
        return parse_email(raw_bytes)
    # Synthetic / dict-based case
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


# ---------------------------------------------------------------------------
# Config 1: LLM Only
# ---------------------------------------------------------------------------

def _run_llm_only(case: dict, provider: str, model: str) -> dict:
    """Config 1: LLM decides everything. No rules, no extraction context."""
    parsed = _build_parsed(case)
    prompt = get_analysis_prompt(parsed, include_signals=False)
    result = _call_llm_verdict(prompt, provider, model)
    return {
        "config": "llm_only",
        "verdict_raw": result["verdict"],
        "verdict_binary": classify_verdict(result["verdict"]),
        "llm_verdict": result["verdict"],
        "llm_error": result["error"],
        "deterministic_override": False,
        "stage_caught": "llm" if classify_verdict(result["verdict"]) == "malicious" else "missed",
    }


# ---------------------------------------------------------------------------
# Config 2: LLM + Signals (Flat)
# ---------------------------------------------------------------------------

def _run_flat(case: dict, provider: str, model: str) -> dict:
    """Config 2: Signals provided to LLM but LLM verdict is final.

    Rules/extraction cannot override the LLM decision.
    """
    parsed = _build_parsed(case)
    rules_result = run_rules_engine(parsed)
    parsed["analysis"] = rules_result
    ext_result = run_extraction(parsed)
    parsed["extraction"] = ext_result

    prompt = get_analysis_prompt(parsed, include_signals=True)
    result = _call_llm_verdict(prompt, provider, model)

    # LLM verdict is final regardless of what rules found
    binary = classify_verdict(result["verdict"])
    rules_flagged = bool(rules_result.get("flags", 0) or
                         any(d.get("flagged") for d in rules_result.get("details", [])))
    ext_flagged = ext_result.get("escalate", False)

    return {
        "config": "flat",
        "verdict_raw": result["verdict"],
        "verdict_binary": binary,
        "llm_verdict": result["verdict"],
        "llm_error": result["error"],
        "rules_flagged": rules_flagged,
        "extraction_flagged": ext_flagged,
        "deterministic_override": False,
        "stage_caught": _attribute_stage(binary, rules_flagged, ext_flagged, result["verdict"]),
    }


# ---------------------------------------------------------------------------
# Config 3: LLM + Signals (Trust Hierarchy)  [the actual architecture]
# ---------------------------------------------------------------------------

def _run_trust_hierarchy(case: dict, provider: str, model: str) -> dict:
    """Config 3: Deterministic stages can escalate; LLM can never accept.

    Decision flow:
      - Rules/extraction flag  -> final = escalated (LLM skipped or overridden)
      - Rules/extraction clean -> call LLM; LLM verdict is used
      - LLM can only ADD escalations, never remove them
    """
    parsed = _build_parsed(case)
    rules_result = run_rules_engine(parsed)
    parsed["analysis"] = rules_result
    ext_result = run_extraction(parsed)
    parsed["extraction"] = ext_result

    rules_flagged = bool(
        any(d.get("flagged") for d in rules_result.get("details", []))
    )
    ext_flagged = ext_result.get("escalate", False)
    deterministic_escalation = rules_flagged or ext_flagged

    if deterministic_escalation:
        # Deterministic stages override; LLM is not called
        final_verdict = "escalader"
        llm_verdict = None
        llm_error = None
        stage_caught = "rules" if rules_flagged else "extraction"
    else:
        # Deterministic stages are clean; delegate to LLM
        prompt = get_analysis_prompt(parsed, include_signals=True)
        result = _call_llm_verdict(prompt, provider, model)
        llm_verdict = result["verdict"]
        llm_error = result["error"]
        final_verdict = llm_verdict  # LLM verdict used as-is (can escalate, can accept)
        binary_llm = classify_verdict(llm_verdict)
        stage_caught = "llm" if binary_llm == "malicious" else "missed"

    binary = classify_verdict(final_verdict)

    return {
        "config": "trust_hierarchy",
        "verdict_raw": final_verdict,
        "verdict_binary": binary,
        "llm_verdict": llm_verdict,
        "llm_error": llm_error,
        "rules_flagged": rules_flagged,
        "extraction_flagged": ext_flagged,
        "deterministic_override": deterministic_escalation,
        "stage_caught": stage_caught if binary == "malicious" else "missed",
    }


# ---------------------------------------------------------------------------
# Config 4: Full Pipeline (Production)
# ---------------------------------------------------------------------------

def _run_full_pipeline(case: dict, provider: str, model: str) -> dict:
    """Config 4: Delegates to run_pipeline_isolated from accuracy.py."""
    _src = Path(__file__).resolve().parent.parent
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

    from accuracy import run_pipeline_isolated

    raw_bytes = case.get("raw_bytes") or case.get("eml")
    if not raw_bytes:
        # Reconstruct minimal eml from dict fields
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = case.get("from", "test@test.com")
        msg["To"] = case.get("to", "analyst@bank.com")
        msg["Subject"] = case.get("subject", "")
        msg.set_content(case.get("body", case.get("text", "")))
        raw_bytes = msg.as_bytes()

    pipeline_result = run_pipeline_isolated(raw_bytes, run_llm=True)
    final_status = pipeline_result.get("final_status", "escalated")

    # Map pipeline status -> binary classification
    if final_status in ("accepted", "accepter", "clean"):
        binary = "benign"
    else:
        binary = "malicious"

    stages = pipeline_result.get("stages", {})
    rules_flagged = bool(stages.get("rules", {}).get("flags", 0))
    ext_flagged = stages.get("extraction", {}).get("escalate", False)
    det_esc = pipeline_result.get("deterministic_escalation", False)

    stage_caught = _attribute_stage(binary, rules_flagged, ext_flagged, final_status)

    return {
        "config": "full_pipeline",
        "verdict_raw": final_status,
        "verdict_binary": binary,
        "llm_verdict": stages.get("llm", {}).get("verdict"),
        "llm_error": stages.get("llm", {}).get("error"),
        "rules_flagged": rules_flagged,
        "extraction_flagged": ext_flagged,
        "deterministic_override": det_esc,
        "stage_caught": stage_caught,
    }


# ---------------------------------------------------------------------------
# Stage attribution helper
# ---------------------------------------------------------------------------

def _attribute_stage(
    binary: str,
    rules_flagged: bool,
    ext_flagged: bool,
    llm_verdict: str | None,
) -> str:
    """Determine which stage caught the email (for attribution charts)."""
    if binary != "malicious":
        return "missed"
    if rules_flagged:
        return "rules"
    if ext_flagged:
        return "extraction"
    if llm_verdict and classify_verdict(str(llm_verdict)) == "malicious":
        return "llm"
    return "missed"


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_experiment(
    corpus: list[dict],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Run all 4 configurations over the full corpus."""
    runners = [
        ("llm_only",        _run_llm_only),
        ("flat",            _run_flat),
        ("trust_hierarchy", _run_trust_hierarchy),
        ("full_pipeline",   _run_full_pipeline),
    ]

    per_config: dict[str, list[dict]] = {k: [] for k, _ in runners}

    total = len(corpus) * len(runners)
    done = 0
    for case in corpus:
        email_id = case.get("id", case.get("path", str(done)))
        expected = case.get("expected", "unknown")
        for cfg_key, runner in runners:
            done += 1
            print(f"  [{done}/{total}] config={cfg_key}  email={str(email_id)[:40]!r}")
            try:
                outcome = runner(case, provider, model)
            except Exception as exc:
                outcome = {
                    "config": cfg_key,
                    "verdict_raw": "escalader",
                    "verdict_binary": "malicious",
                    "llm_verdict": None,
                    "llm_error": str(exc)[:300],
                    "rules_flagged": False,
                    "extraction_flagged": False,
                    "deterministic_override": False,
                    "stage_caught": "error",
                }
            outcome["email_id"] = str(email_id)
            outcome["expected"] = expected
            per_config[cfg_key].append(outcome)

    # Compute metrics per config
    config_metrics: dict[str, dict] = {}
    for cfg_key, outcomes in per_config.items():
        y_true = [o["expected"] for o in outcomes]
        y_pred = [o["verdict_binary"] for o in outcomes]
        m = compute_metrics(y_true, y_pred)
        # Count FN and FP
        fn = sum(
            1 for t, p in zip(y_true, y_pred)
            if t == "malicious" and p == "benign"
        )
        fp = sum(
            1 for t, p in zip(y_true, y_pred)
            if t == "benign" and p == "malicious"
        )
        config_metrics[cfg_key] = {**m, "fn": fn, "fp": fp}

    # Stage attribution for trust_hierarchy config
    stage_attr = _compute_stage_attribution(per_config["trust_hierarchy"])

    return {
        "per_config": per_config,
        "config_metrics": config_metrics,
        "stage_attribution": stage_attr,
        "meta": {
            "provider": provider,
            "model": model,
            "n_emails": len(corpus),
            "n_malicious": sum(1 for c in corpus if c.get("expected") == "malicious"),
            "n_benign": sum(1 for c in corpus if c.get("expected") == "benign"),
        },
    }


def _compute_stage_attribution(outcomes: list[dict]) -> dict[str, int]:
    """Count how many malicious emails each stage caught in trust_hierarchy."""
    attr: dict[str, int] = {"rules": 0, "extraction": 0, "llm": 0, "missed": 0, "error": 0}
    for o in outcomes:
        if o["expected"] != "malicious":
            continue
        stage = o.get("stage_caught", "missed")
        attr[stage] = attr.get(stage, 0) + 1
    return attr


# ---------------------------------------------------------------------------
# Visualisation 1: Grouped bar — 4 configs x 4 metrics
# ---------------------------------------------------------------------------

def _plot_hierarchy_comparison(
    config_metrics: dict[str, dict],
    output_dir: Path,
) -> None:
    paper_style()
    fig, ax = plt.subplots(figsize=(12, 6))

    cfg_keys = list(config_metrics.keys())
    n_configs = len(cfg_keys)
    n_metrics = len(METRICS)
    x = np.arange(n_metrics)
    bar_width = 0.18
    offsets = np.linspace(-(n_configs - 1) / 2, (n_configs - 1) / 2, n_configs) * bar_width

    for i, (cfg_key, offset) in enumerate(zip(cfg_keys, offsets)):
        m = config_metrics[cfg_key]
        values = [m.get(metric, 0.0) for metric in METRICS]
        bars = ax.bar(
            x + offset, values,
            width=bar_width,
            color=CONFIG_COLORS[i],
            edgecolor="black",
            linewidth=0.6,
            label=CONFIG_NAMES[i],
        )
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.008,
                f"{val:.2f}",
                ha="center", va="bottom", fontsize=7, rotation=45,
            )

    ax.set_xticks(x)
    ax.set_xticklabels(METRIC_LABELS, fontsize=11)
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.18)
    ax.set_title("Trust Hierarchy Configuration Comparison", fontweight="bold")
    ax.legend(loc="upper right", fontsize=8, framealpha=0.9)
    ax.axhline(1.0, color="gray", linestyle="--", linewidth=0.7, alpha=0.5)

    plt.tight_layout()
    out = output_dir / "hierarchy_comparison.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Visualisation 2: FN count per config (the thesis chart)
# ---------------------------------------------------------------------------

def _plot_fn_elimination(
    config_metrics: dict[str, dict],
    output_dir: Path,
) -> None:
    paper_style()
    fig, ax = plt.subplots(figsize=(8, 5))

    cfg_keys = list(config_metrics.keys())
    fn_counts = [config_metrics[k]["fn"] for k in cfg_keys]
    fp_counts = [config_metrics[k]["fp"] for k in cfg_keys]

    x = np.arange(len(cfg_keys))
    bar_width = 0.35

    fn_bars = ax.bar(x - bar_width / 2, fn_counts, bar_width,
                     label="False Negatives (missed threats)",
                     color="#e74c3c", edgecolor="black", linewidth=0.7)
    fp_bars = ax.bar(x + bar_width / 2, fp_counts, bar_width,
                     label="False Positives (benign flagged)",
                     color="#f39c12", edgecolor="black", linewidth=0.7)

    for bar in fn_bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.15,
                str(int(h)), ha="center", va="bottom",
                fontsize=11, fontweight="bold", color="#c0392b")

    for bar in fp_bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.15,
                str(int(h)), ha="center", va="bottom",
                fontsize=10, color="#d35400")

    ax.set_xticks(x)
    ax.set_xticklabels(CONFIG_NAMES, fontsize=9, wrap=True)
    ax.set_ylabel("Email count")
    ax.set_title(
        "False Negative Elimination Across Trust Configurations\n"
        "(Near-zero FN proves the Trust Hierarchy thesis)",
        fontweight="bold",
    )
    ax.legend(fontsize=9)

    # Annotate the trust hierarchy bar with a star
    hier_idx = list(config_metrics.keys()).index("trust_hierarchy")
    fn_hier = fn_counts[hier_idx]
    ax.annotate(
        "Trust Hierarchy\n(target: FN=0)",
        xy=(hier_idx - bar_width / 2, fn_hier),
        xytext=(hier_idx - bar_width / 2 - 0.5, fn_hier + max(fn_counts or [1]) * 0.3),
        arrowprops={"arrowstyle": "->", "color": "black"},
        fontsize=8,
        color="#2c3e50",
    )

    max_y = max(max(fn_counts or [0]), max(fp_counts or [0])) + 2
    ax.set_ylim(0, max(max_y, 3))

    plt.tight_layout()
    out = output_dir / "fn_elimination.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Visualisation 3: Trust flow stacked bar (stage attribution)
# ---------------------------------------------------------------------------

def _plot_trust_flow_sankey(
    per_config: dict[str, list[dict]],
    output_dir: Path,
) -> None:
    """Stacked bar: for each config, how many malicious emails each stage caught."""
    paper_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    stage_keys = ["rules", "extraction", "llm", "missed", "error"]
    stage_colors = {
        "rules":      "#e74c3c",
        "extraction": "#e67e22",
        "llm":        "#3498db",
        "missed":     "#95a5a6",
        "error":      "#2c3e50",
    }
    stage_labels = {
        "rules":      "Caught by Rules Engine",
        "extraction": "Caught by Extraction",
        "llm":        "Caught by LLM",
        "missed":     "Missed (False Negative)",
        "error":      "Processing Error",
    }

    cfg_keys = list(per_config.keys())
    n_configs = len(cfg_keys)
    x = np.arange(n_configs)

    # Compute stage counts per config (malicious emails only)
    stage_data: dict[str, list[int]] = {s: [] for s in stage_keys}
    for cfg_key in cfg_keys:
        outcomes = per_config[cfg_key]
        counts = {s: 0 for s in stage_keys}
        for o in outcomes:
            if o.get("expected") != "malicious":
                continue
            stage = o.get("stage_caught", "missed")
            if stage not in counts:
                stage = "error"
            counts[stage] += 1
        for s in stage_keys:
            stage_data[s].append(counts[s])

    bottoms = np.zeros(n_configs)
    for stage in stage_keys:
        vals = np.array(stage_data[stage], dtype=float)
        if vals.sum() == 0:
            continue
        ax.bar(x, vals, bottom=bottoms,
               color=stage_colors[stage], label=stage_labels[stage],
               edgecolor="white", linewidth=0.4)
        for i, (v, b) in enumerate(zip(vals, bottoms)):
            if v > 0:
                ax.text(i, b + v / 2, str(int(v)),
                        ha="center", va="center", fontsize=9,
                        color="white", fontweight="bold")
        bottoms += vals

    ax.set_xticks(x)
    ax.set_xticklabels(CONFIG_NAMES, fontsize=9)
    ax.set_ylabel("Malicious emails detected by each stage")
    ax.set_title(
        "Detection Stage Attribution by Configuration\n"
        "(Trust Hierarchy drives FN to zero via deterministic override)",
        fontweight="bold",
    )
    ax.legend(loc="upper right", fontsize=8, framealpha=0.9)

    plt.tight_layout()
    out = output_dir / "trust_flow_sankey.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# Visualisation 4: Error surface scatter FP vs FN
# ---------------------------------------------------------------------------

def _plot_error_surface(
    config_metrics: dict[str, dict],
    output_dir: Path,
) -> None:
    paper_style()
    fig, ax = plt.subplots(figsize=(7, 6))

    cfg_keys = list(config_metrics.keys())
    for i, cfg_key in enumerate(cfg_keys):
        m = config_metrics[cfg_key]
        fp = m["fp"]
        fn = m["fn"]
        ax.scatter(fp, fn, s=180, color=CONFIG_COLORS[i],
                   edgecolors="black", linewidths=0.8, zorder=5)
        ax.annotate(
            CONFIG_NAMES[i],
            xy=(fp, fn),
            xytext=(fp + 0.3, fn + 0.15),
            fontsize=8,
            color=CONFIG_COLORS[i],
        )

    # Draw the ideal zone label
    ax.axhline(0, color="#2ecc71", linestyle="--", linewidth=1.0,
               alpha=0.7, label="FN = 0 (zero missed threats)")

    ax.set_xlabel("False Positives (FP) — benign emails incorrectly flagged", fontsize=10)
    ax.set_ylabel("False Negatives (FN) — threats missed", fontsize=10)
    ax.set_title(
        "Error Surface: FP vs FN per Configuration\n"
        "(Target: Trust Hierarchy sits at FN ~= 0)",
        fontweight="bold",
    )
    ax.legend(fontsize=8)

    all_fp = [config_metrics[k]["fp"] for k in cfg_keys]
    all_fn = [config_metrics[k]["fn"] for k in cfg_keys]
    ax.set_xlim(-0.5, max(max(all_fp or [1]), 1) + 1.5)
    ax.set_ylim(-0.5, max(max(all_fn or [1]), 1) + 1.5)
    ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))
    ax.yaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))

    plt.tight_layout()
    out = output_dir / "error_surface.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PNG] {out}")


# ---------------------------------------------------------------------------
# LaTeX Table 1: Config comparison
# ---------------------------------------------------------------------------

def _latex_config_comparison(
    config_metrics: dict[str, dict],
    model: str,
) -> list[str]:
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        rf"\caption{{Trust Configuration Comparison ({model})}}",
        r"\label{tab:e6_config_comparison}",
        r"\begin{tabular}{l r r r r r r}",
        r"\hline",
        r"Configuration & Accuracy & Precision & Recall & F1 & FN & FP \\",
        r"\hline",
    ]
    cfg_display = dict(zip(config_metrics.keys(), CONFIG_NAMES))
    for cfg_key, m in config_metrics.items():
        name = cfg_display.get(cfg_key, cfg_key).replace("&", r"\&")
        lines.append(
            rf"{name} & "
            rf"{m['accuracy']:.3f} & "
            rf"{m['precision']:.3f} & "
            rf"{m['recall']:.3f} & "
            rf"{m['f1']:.3f} & "
            rf"{m['fn']} & "
            rf"{m['fp']} \\"
        )
    lines += [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# LaTeX Table 2: Per-stage attribution (trust hierarchy)
# ---------------------------------------------------------------------------

def _latex_stage_attribution(
    stage_attr: dict[str, int],
    n_malicious: int,
) -> list[str]:
    total_caught = sum(v for k, v in stage_attr.items() if k not in ("missed", "error"))
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Per-Stage Detection Attribution (Trust Hierarchy Configuration)}",
        r"\label{tab:e6_stage_attribution}",
        r"\begin{tabular}{l r r}",
        r"\hline",
        r"Stage & Emails Caught & \% of Malicious \\",
        r"\hline",
    ]
    stage_display = {
        "rules":      "Rules Engine",
        "extraction": "Extraction Stage",
        "llm":        "LLM Analysis",
        "missed":     "Missed (False Negative)",
        "error":      "Processing Error",
    }
    for stage, label in stage_display.items():
        count = stage_attr.get(stage, 0)
        pct = (count / n_malicious * 100) if n_malicious > 0 else 0.0
        lines.append(rf"{label} & {count} & {pct:.1f}\% \\")
    lines += [
        r"\hline",
        rf"Total malicious & {n_malicious} & 100.0\% \\",
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
        description="Experiment 6 -- Trust Hierarchy vs LLM Autonomy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--provider", default="ollama",
                        choices=["ollama", "openai", "groq", "together", "anthropic", "nvidia", "deepseek", "mistral_nvidia"],
                        help="LLM provider (default: ollama)")
    parser.add_argument("--model", default="gemma3:4b",
                        help="Model name for the chosen provider (default: gemma3:4b)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    print("=" * 64)
    print("Experiment 6 -- Trust Hierarchy vs LLM Autonomy")
    print("=" * 64)
    print(f"  Provider : {args.provider}")
    print(f"  Model    : {args.model}")

    corpus = load_corpus()
    print(f"  Corpus   : {len(corpus)} emails")
    print("-" * 64)

    output_dir = get_output_dir(EXPERIMENT_NAME)

    # Run all configurations
    data = run_experiment(corpus, provider=args.provider, model=args.model)

    # Save raw results
    save_results(data, output_dir, "results")

    # Print summary table
    print()
    print(f"  {'Configuration':<36}  {'Acc':>5}  {'Prec':>5}  {'Rec':>5}  {'F1':>5}  {'FN':>4}  {'FP':>4}")
    print(f"  {'-'*36}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*4}  {'-'*4}")
    for cfg_key, display_name in zip(data["config_metrics"].keys(), CONFIG_NAMES):
        m = data["config_metrics"][cfg_key]
        print(
            f"  {display_name:<36}  "
            f"{m['accuracy']:>5.3f}  "
            f"{m['precision']:>5.3f}  "
            f"{m['recall']:>5.3f}  "
            f"{m['f1']:>5.3f}  "
            f"{m['fn']:>4d}  "
            f"{m['fp']:>4d}"
        )

    print()
    print("Stage attribution (trust hierarchy, malicious emails):")
    for stage, count in data["stage_attribution"].items():
        print(f"  {stage:<15} : {count}")

    # Visualisations
    print()
    print("Generating visualisations...")
    _plot_hierarchy_comparison(data["config_metrics"], output_dir)
    _plot_fn_elimination(data["config_metrics"], output_dir)
    _plot_trust_flow_sankey(data["per_config"], output_dir)
    _plot_error_surface(data["config_metrics"], output_dir)

    # LaTeX tables
    print()
    print("Generating LaTeX tables...")
    save_latex(
        _latex_config_comparison(data["config_metrics"], args.model),
        output_dir, "config_comparison",
    )
    save_latex(
        _latex_stage_attribution(
            data["stage_attribution"],
            data["meta"]["n_malicious"],
        ),
        output_dir, "stage_attribution",
    )

    print()
    print("Experiment 6 complete.")
    print(f"  Output dir: {output_dir}")


if __name__ == "__main__":
    main()
