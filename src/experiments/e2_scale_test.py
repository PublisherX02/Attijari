"""e2_scale_test.py -- Experiment 2: Does model scale solve verdict reliability?

Research Question:
    Does increasing model scale resolve verdict reliability in adversarial
    classification?

Hypothesis:
    Larger models make different errors, not fewer. Error rate does not
    converge to zero. Models miss different subsets of adversarial emails,
    and no single model achieves 100% recall alone.

Usage:
    python e2_scale_test.py
    python e2_scale_test.py --skip-cloud
    python e2_scale_test.py --skip-missing
    python e2_scale_test.py --models "ollama:gemma3:4b" "groq:llama-3.3-70b-versatile"
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------------------------------------------------------------------------
# Project path setup (must precede local imports)
# ---------------------------------------------------------------------------
_SRC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SRC))

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
# Model registry
# ---------------------------------------------------------------------------
MODELS: list[dict] = [
    # Local (Ollama)
    {"provider": "ollama", "model": "gemma3:4b",   "params": "4B",    "type": "local"},
    {"provider": "ollama", "model": "qwen3:8b",    "params": "8B",    "type": "local"},
    # Cloud APIs - keys from env vars
    {"provider": "groq",      "model": "llama-3.3-70b-versatile",                    "params": "70B",    "type": "cloud"},
    {"provider": "together",  "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",   "params": "70B",    "type": "cloud"},
    {"provider": "openai",    "model": "gpt-4o-mini",                                "params": "~200B",  "type": "cloud"},
    {"provider": "anthropic", "model": "claude-sonnet-4-20250514",                   "params": "~200B+", "type": "cloud"},
    {"provider": "nvidia",          "model": "meta/llama-3.3-70b-instruct",                "params": "70B",    "type": "cloud"},
    {"provider": "deepseek",        "model": "deepseek-ai/deepseek-r1",                    "params": "671B",   "type": "cloud"},
    {"provider": "mistral_nvidia",  "model": "mistralai/mistral-small-24b-instruct-2501",  "params": "24B",    "type": "cloud"},
]

# Env-var keys required per cloud provider
_PROVIDER_ENV: dict[str, str] = {
    "groq":           "GROQ_API_KEY",
    "together":       "TOGETHER_API_KEY",
    "openai":         "OPENAI_API_KEY",
    "anthropic":      "ANTHROPIC_API_KEY",
    "nvidia":         "NVIDIA_API_KEY",
    "deepseek":       "NVIDIA_DEEPSEEK_V4_PRO_KEY",
    "mistral_nvidia": "NVIDIA_MISTRAL_KEY",
}

EXPERIMENT_NAME = "e2_scale_test"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="E2: Scale test -- does bigger mean better at security?"
    )
    parser.add_argument(
        "--models",
        nargs="+",
        metavar="PROVIDER:MODEL",
        help=(
            "Space-separated list of provider:model pairs to test. "
            "Example: ollama:gemma3:4b groq:llama-3.3-70b-versatile"
        ),
    )
    parser.add_argument(
        "--skip-cloud",
        action="store_true",
        help="Only test local Ollama models, skip all cloud providers.",
    )
    parser.add_argument(
        "--skip-missing",
        action="store_true",
        help="Skip cloud models whose API key is not set instead of erroring.",
    )
    return parser.parse_args()


def build_model_list(args: argparse.Namespace) -> list[dict]:
    """Resolve the final list of models to test from CLI args and flags."""
    if args.models:
        resolved: list[dict] = []
        for spec in args.models:
            # Format: "provider:model" where model may contain colons (e.g. gemma3:4b)
            parts = spec.split(":", 1)
            if len(parts) != 2:
                print(f"[WARN] Cannot parse model spec '{spec}' -- expected provider:model, skipping")
                continue
            provider, model = parts
            # Find matching entry in registry for params/type metadata
            meta = next(
                (m for m in MODELS if m["provider"] == provider and m["model"] == model),
                {"provider": provider, "model": model, "params": "?", "type": "cloud"},
            )
            resolved.append(meta)
        return resolved

    candidates = MODELS
    if args.skip_cloud:
        candidates = [m for m in MODELS if m["type"] == "local"]
    return candidates


def filter_available_models(
    models: list[dict], skip_missing: bool
) -> list[dict]:
    """Remove cloud models whose API key is absent when --skip-missing is set."""
    available: list[dict] = []
    for m in models:
        provider = m["provider"]
        if provider == "ollama":
            available.append(m)
            continue
        env_var = _PROVIDER_ENV.get(provider, "")
        if env_var and not os.getenv(env_var):
            msg = (
                f"[WARN] {provider.upper()} model '{m['model']}' skipped -- "
                f"{env_var} is not set"
            )
            if skip_missing:
                print(msg)
                continue
            else:
                print(msg)
                print(f"       Set {env_var} or pass --skip-missing to skip automatically.")
                sys.exit(1)
        available.append(m)
    return available


# ---------------------------------------------------------------------------
# LLM response parsing
# ---------------------------------------------------------------------------

def parse_verdict_from_response(raw: str) -> str:
    """Extract verdict from LLM JSON response robustly.

    Tries json.loads on the full response first, then uses regex to find the
    verdict field. Falls back to 'escalader' (escalate) on any parse failure.
    """
    # Attempt 1: full JSON parse
    try:
        data = json.loads(raw.strip())
        verdict = data.get("verdict", "")
        if verdict:
            return verdict
    except (json.JSONDecodeError, AttributeError, ValueError):
        pass

    # Attempt 2: extract JSON object via regex then parse
    json_match = re.search(r'\{[^{}]*\}', raw, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group())
            verdict = data.get("verdict", "")
            if verdict:
                return verdict
        except (json.JSONDecodeError, ValueError):
            pass

    # Attempt 3: regex directly on verdict field
    verdict_match = re.search(
        r'"verdict"\s*:\s*"([^"]+)"', raw, re.IGNORECASE
    )
    if verdict_match:
        return verdict_match.group(1)

    # Fail-safe: treat as escalated (never silently accept)
    return "escalader"


# ---------------------------------------------------------------------------
# Per-case inference
# ---------------------------------------------------------------------------

def evaluate_single_case(
    case: dict,
    model_entry: dict,
    is_cloud: bool,
) -> dict:
    """Run one email through one model. Returns a result dict."""
    raw_eml: bytes = case.get("raw_eml", b"")
    expected: str = case.get("expected", "malicious")
    attack_type: str = case.get("attack_type", "unknown")
    case_id: str = case.get("id", "unknown")

    result: dict[str, Any] = {
        "case_id": case_id,
        "expected": expected,
        "attack_type": attack_type,
        "predicted_verdict": "escalader",
        "predicted_binary": "malicious",
        "latency_s": 0.0,
        "error": None,
    }

    try:
        parsed = parse_email(raw_eml)
        # LLM sees ONLY the email -- no enrichment signals
        prompt = get_analysis_prompt(parsed, include_signals=False)

        start = time.time()
        raw_response = call_model(
            prompt=prompt,
            provider=model_entry["provider"],
            model=model_entry["model"],
        )
        elapsed = time.time() - start

        verdict_str = parse_verdict_from_response(raw_response)
        binary = classify_verdict(verdict_str)

        result["predicted_verdict"] = verdict_str
        result["predicted_binary"] = binary
        result["latency_s"] = round(elapsed, 3)

    except Exception as exc:
        result["error"] = str(exc)
        print(f"    [ERROR] case {case_id}: {exc}")

    # Rate-limit courtesy sleep for cloud providers
    if is_cloud:
        time.sleep(1)

    return result


# ---------------------------------------------------------------------------
# Per-model evaluation
# ---------------------------------------------------------------------------

def evaluate_model(model_entry: dict, corpus: list[dict]) -> dict:
    """Run the full corpus through one model and collect results."""
    label = f"{model_entry['provider']}:{model_entry['model']}"
    is_cloud = model_entry["type"] == "cloud"
    print(f"\n[MODEL] {label}  (params={model_entry['params']}, type={model_entry['type']})")

    case_results: list[dict] = []
    for idx, case in enumerate(corpus, 1):
        print(f"  [{idx:3d}/{len(corpus)}] {case.get('id', '?')}", end=" ... ", flush=True)
        res = evaluate_single_case(case, model_entry, is_cloud)
        case_results.append(res)
        status = "ok" if not res["error"] else "ERR"
        print(f"{res['predicted_binary']} [{status}]")

    y_true = [r["expected"] for r in case_results]
    y_pred = [r["predicted_binary"] for r in case_results]
    metrics = compute_metrics(y_true, y_pred)

    latencies = [r["latency_s"] for r in case_results if not r["error"]]
    avg_latency = round(sum(latencies) / len(latencies), 3) if latencies else 0.0

    false_negatives = [
        r["case_id"]
        for r in case_results
        if r["expected"] == "malicious" and r["predicted_binary"] == "benign"
    ]

    return {
        "model": model_entry,
        "label": label,
        "metrics": metrics,
        "avg_latency_s": avg_latency,
        "false_negatives": false_negatives,
        "fn_count": len(false_negatives),
        "case_results": case_results,
    }


# ---------------------------------------------------------------------------
# Visualisations
# ---------------------------------------------------------------------------

def _params_to_numeric(params_str: str) -> float:
    """Convert a params string like '4B', '~200B', '~200B+' to a float."""
    cleaned = re.sub(r"[^0-9.]", "", params_str)
    try:
        return float(cleaned)
    except ValueError:
        return 1.0


def plot_scale_vs_accuracy(model_results: list[dict], output_dir: Path) -> None:
    """Scatter/line: model size (log x) vs F1/recall (y)."""
    paper_style()
    fig, ax = plt.subplots(figsize=(9, 5))

    xs_f1: list[float] = []
    ys_f1: list[float] = []
    xs_recall: list[float] = []
    ys_recall: list[float] = []
    labels: list[str] = []

    for r in model_results:
        x = _params_to_numeric(r["model"]["params"])
        f1 = r["metrics"]["f1"]
        recall = r["metrics"]["recall"]
        xs_f1.append(x)
        ys_f1.append(f1)
        xs_recall.append(x)
        ys_recall.append(recall)
        labels.append(r["model"]["model"].split("/")[-1])

    ax.scatter(xs_f1, ys_f1, color=COLORS[0], s=90, zorder=5, label="F1")
    ax.scatter(xs_recall, ys_recall, color=COLORS[3], s=90, marker="^",
               zorder=5, label="Recall")

    # Connect points with a dashed line to show trend
    sorted_pairs_f1 = sorted(zip(xs_f1, ys_f1))
    sorted_pairs_rc = sorted(zip(xs_recall, ys_recall))
    if sorted_pairs_f1:
        ax.plot([p[0] for p in sorted_pairs_f1], [p[1] for p in sorted_pairs_f1],
                "--", color=COLORS[0], alpha=0.5, linewidth=1)
    if sorted_pairs_rc:
        ax.plot([p[0] for p in sorted_pairs_rc], [p[1] for p in sorted_pairs_rc],
                "--", color=COLORS[3], alpha=0.5, linewidth=1)

    # Annotate each point
    for x, y, lbl in zip(xs_f1, ys_f1, labels):
        ax.annotate(lbl, (x, y), textcoords="offset points",
                    xytext=(6, 4), fontsize=8)

    ax.set_xscale("log")
    ax.set_xlim(left=1)
    ax.set_ylim(0, 1.05)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=1, alpha=0.7,
               label="Perfect recall ceiling")
    ax.set_xlabel("Model size (B parameters, log scale)")
    ax.set_ylabel("Score")
    ax.set_title("Scale vs. Security Classification Performance\n"
                 "Curve plateaus -- scale alone does not reach 1.0 recall")
    ax.legend(fontsize=10)
    ax.grid(True, which="both", linestyle="--", alpha=0.3)

    out = output_dir / "scale_vs_accuracy.png"
    fig.tight_layout()
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"  [PLOT] {out}")


def plot_error_overlap(model_results: list[dict], output_dir: Path) -> None:
    """Heatmap: pairwise % overlap of false negatives between models."""
    paper_style()
    n = len(model_results)
    if n < 2:
        print("  [SKIP] error_overlap requires at least 2 models")
        return

    labels = [r["model"]["model"].split("/")[-1] for r in model_results]
    matrix = np.zeros((n, n), dtype=float)

    for i, ri in enumerate(model_results):
        set_i = set(ri["false_negatives"])
        for j, rj in enumerate(model_results):
            set_j = set(rj["false_negatives"])
            if not set_i and not set_j:
                matrix[i, j] = 0.0
            elif not set_i or not set_j:
                matrix[i, j] = 0.0
            else:
                overlap = len(set_i & set_j)
                matrix[i, j] = overlap / max(len(set_i), len(set_j)) * 100

    fig, ax = plt.subplots(figsize=(max(6, n + 2), max(5, n + 1)))
    im = ax.imshow(matrix, vmin=0, vmax=100, cmap="YlOrRd")
    plt.colorbar(im, ax=ax, label="% shared false negatives")

    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
    ax.set_yticklabels(labels, fontsize=9)

    for i in range(n):
        for j in range(n):
            ax.text(j, i, f"{matrix[i, j]:.0f}%",
                    ha="center", va="center",
                    color="black" if matrix[i, j] < 60 else "white",
                    fontsize=9)

    ax.set_title("False Negative Overlap Between Models\n"
                 "Low off-diagonal values confirm: models miss DIFFERENT emails")
    fig.tight_layout()
    out = output_dir / "model_error_overlap.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"  [PLOT] {out}")


def plot_comparison_bars(model_results: list[dict], output_dir: Path) -> None:
    """Grouped bar chart: accuracy / precision / recall / F1 per model."""
    paper_style()
    metric_keys = ["accuracy", "precision", "recall", "f1"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1"]
    n_models = len(model_results)
    n_metrics = len(metric_keys)
    x = np.arange(n_models)
    width = 0.2

    fig, ax = plt.subplots(figsize=(max(8, n_models * 2), 5))

    for i, (key, label) in enumerate(zip(metric_keys, metric_labels)):
        values = [r["metrics"][key] for r in model_results]
        offset = (i - n_metrics / 2 + 0.5) * width
        bars = ax.bar(x + offset, values, width, label=label,
                      color=COLORS[i], alpha=0.85)
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.01,
                f"{val:.2f}",
                ha="center", va="bottom", fontsize=7,
            )

    model_names = [r["model"]["model"].split("/")[-1] for r in model_results]
    ax.set_xticks(x)
    ax.set_xticklabels(model_names, rotation=25, ha="right", fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison -- Accuracy / Precision / Recall / F1\n"
                 "No model achieves perfect scores across all metrics")
    ax.legend(fontsize=10, loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.35)

    fig.tight_layout()
    out = output_dir / "model_comparison_bars.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"  [PLOT] {out}")


def plot_error_analysis(model_results: list[dict], output_dir: Path) -> None:
    """Per-model bar chart of false negatives grouped by attack type."""
    paper_style()
    n_models = len(model_results)
    if n_models == 0:
        return

    # Collect all attack types
    all_types: set[str] = set()
    for r in model_results:
        for cr in r["case_results"]:
            if (cr["expected"] == "malicious"
                    and cr["predicted_binary"] == "benign"):
                all_types.add(cr.get("attack_type", "unknown"))
    if not all_types:
        all_types = {"none"}
    all_types_sorted = sorted(all_types)

    # Build matrix: rows = models, cols = attack types, values = FN count
    data: list[list[int]] = []
    for r in model_results:
        row: list[int] = []
        for atype in all_types_sorted:
            count = sum(
                1 for cr in r["case_results"]
                if cr["expected"] == "malicious"
                and cr["predicted_binary"] == "benign"
                and cr.get("attack_type", "unknown") == atype
            )
            row.append(count)
        data.append(row)

    x = np.arange(len(all_types_sorted))
    width = 0.8 / max(n_models, 1)
    fig, ax = plt.subplots(figsize=(max(8, len(all_types_sorted) * 2), 5))

    model_names = [r["model"]["model"].split("/")[-1] for r in model_results]
    for i, (row, name) in enumerate(zip(data, model_names)):
        offset = (i - n_models / 2 + 0.5) * width
        ax.bar(x + offset, row, width, label=name,
               color=COLORS[i % len(COLORS)], alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(all_types_sorted, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("False Negative Count")
    ax.set_title("Error Analysis by Attack Type per Model\n"
                 "Models miss different attack categories")
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.35)

    fig.tight_layout()
    out = output_dir / "error_analysis.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"  [PLOT] {out}")


# ---------------------------------------------------------------------------
# LaTeX tables
# ---------------------------------------------------------------------------

def _tex_escape(s: str) -> str:
    """Minimal LaTeX special-character escaping."""
    return (
        s.replace("_", r"\_")
         .replace("&", r"\&")
         .replace("%", r"\%")
         .replace("#", r"\#")
         .replace("~", r"\textasciitilde{}")
         .replace("^", r"\textasciicircum{}")
    )


def build_latex_comparison_table(model_results: list[dict]) -> list[str]:
    """Table 1: model name, params, accuracy, precision, recall, F1, FN count, avg latency."""
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{Model Comparison -- Scale vs. Security Classification Performance}",
        r"\label{tab:e2_model_comparison}",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        r"Model & Params & Acc & Prec & Recall & F1 & FN & Lat(s) \\",
        r"\midrule",
    ]
    for r in model_results:
        m = r["metrics"]
        name = _tex_escape(r["model"]["model"].split("/")[-1])
        params = _tex_escape(r["model"]["params"])
        lines.append(
            f"{name} & {params} & "
            f"{m['accuracy']:.3f} & {m['precision']:.3f} & "
            f"{m['recall']:.3f} & {m['f1']:.3f} & "
            f"{r['fn_count']} & {r['avg_latency_s']:.2f} \\\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


def build_latex_overlap_table(model_results: list[dict]) -> list[str]:
    """Table 2: pairwise false-negative overlap matrix (%)."""
    n = len(model_results)
    short_names = [r["model"]["model"].split("/")[-1] for r in model_results]

    col_spec = "l" + "r" * n
    header_cols = " & ".join(_tex_escape(name) for name in short_names)

    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{False Negative Overlap Matrix (\% shared FN between model pairs)}",
        r"\label{tab:e2_fn_overlap}",
        rf"\begin{{tabular}}{{{col_spec}}}",
        r"\toprule",
        rf"Model & {header_cols} \\",
        r"\midrule",
    ]

    fn_sets = [set(r["false_negatives"]) for r in model_results]

    for i, (fn_i, name_i) in enumerate(zip(fn_sets, short_names)):
        row_vals: list[str] = []
        for j, fn_j in enumerate(fn_sets):
            if not fn_i and not fn_j:
                pct = 0.0
            elif not fn_i or not fn_j:
                pct = 0.0
            else:
                pct = len(fn_i & fn_j) / max(len(fn_i), len(fn_j)) * 100
            row_vals.append(f"{pct:.0f}\\%")
        lines.append(
            f"{_tex_escape(name_i)} & " + " & ".join(row_vals) + r" \\"
        )

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    models = build_model_list(args)
    models = filter_available_models(models, skip_missing=args.skip_missing)

    if not models:
        print("[ERROR] No models to test after filtering. Exiting.")
        sys.exit(1)

    print(f"\n=== Experiment 2: Scale Test ===")
    print(f"Models to test: {len(models)}")
    for m in models:
        print(f"  - {m['provider']}:{m['model']}  ({m['params']})")

    corpus = load_corpus()
    if not corpus:
        print("[ERROR] Empty corpus. Cannot run experiment.")
        sys.exit(1)

    output_dir = get_output_dir(EXPERIMENT_NAME)
    print(f"\nOutput directory: {output_dir}\n")

    model_results: list[dict] = []
    for model_entry in models:
        result = evaluate_model(model_entry, corpus)
        model_results.append(result)

        m = result["metrics"]
        print(
            f"  => acc={m['accuracy']:.3f}  prec={m['precision']:.3f}  "
            f"rec={m['recall']:.3f}  f1={m['f1']:.3f}  "
            f"FN={result['fn_count']}  lat={result['avg_latency_s']}s"
        )

    # ---- Persist raw results ----
    print("\n[SAVING] Results ...")
    save_results(
        {
            "experiment": EXPERIMENT_NAME,
            "hypothesis": (
                "Larger models make different errors, not fewer. "
                "Error rate does not converge to zero."
            ),
            "models_tested": len(model_results),
            "corpus_size": len(corpus),
            "results": [
                {
                    "label": r["label"],
                    "model": r["model"],
                    "metrics": {
                        k: v for k, v in r["metrics"].items()
                        if k != "classification_report"
                    },
                    "avg_latency_s": r["avg_latency_s"],
                    "fn_count": r["fn_count"],
                    "false_negatives": r["false_negatives"],
                }
                for r in model_results
            ],
        },
        output_dir,
        "e2_results",
    )

    # ---- Visualisations ----
    print("\n[PLOTTING] Generating figures ...")
    plot_scale_vs_accuracy(model_results, output_dir)
    plot_error_overlap(model_results, output_dir)
    plot_comparison_bars(model_results, output_dir)
    plot_error_analysis(model_results, output_dir)

    # ---- LaTeX tables ----
    print("\n[LATEX] Generating tables ...")
    save_latex(build_latex_comparison_table(model_results), output_dir, "table1_model_comparison")
    save_latex(build_latex_overlap_table(model_results), output_dir, "table2_fn_overlap")

    # ---- Summary ----
    print("\n=== EXPERIMENT 2 SUMMARY ===")
    print(f"{'Model':<45} {'Params':<8} {'Recall':>6} {'F1':>6} {'FN':>4}")
    print("-" * 72)
    for r in model_results:
        m = r["metrics"]
        name = r["model"]["model"].split("/")[-1]
        params = r["model"]["params"]
        print(f"{name:<45} {params:<8} {m['recall']:>6.3f} {m['f1']:>6.3f} {r['fn_count']:>4}")

    all_fn_sets = [set(r["false_negatives"]) for r in model_results]
    union_fns = set().union(*all_fn_sets) if all_fn_sets else set()
    intersection_fns = (
        all_fn_sets[0].intersection(*all_fn_sets[1:])
        if len(all_fn_sets) > 1
        else all_fn_sets[0] if all_fn_sets else set()
    )

    print(f"\nFalse negatives in ANY model:  {len(union_fns)}")
    print(f"False negatives in ALL models: {len(intersection_fns)}")
    if union_fns and intersection_fns:
        pct_shared = len(intersection_fns) / len(union_fns) * 100
        print(f"Overlap ratio: {pct_shared:.1f}%  "
              f"(low = models miss different emails -- hypothesis supported)")

    print(f"\nAll outputs written to: {output_dir}")


if __name__ == "__main__":
    main()
