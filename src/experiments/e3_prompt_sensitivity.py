"""e3_prompt_sensitivity.py -- Experiment 3: Prompt Sensitivity Analysis.

Research Question: How sensitive are LLM security verdicts to prompt formulation?
Hypothesis: Minor prompt changes flip verdicts on 10-30% of edge cases.

Method:
  - Define 6 prompt variants (same semantic intent, different wording/framing)
  - Run each email through each variant
  - Measure agreement rates, flip rates, and which email categories are most sensitive

Output: data/experiments/e3_prompt_sensitivity/
  - sensitivity_heatmap.png
  - variant_agreement.png
  - sensitivity_distribution.png
  - flip_cases.png
  - results_*.json
  - prompt_variants_*.tex
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

# Allow running as standalone script or as module
_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
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
# Prompt variants
# ---------------------------------------------------------------------------

PROMPT_VARIANTS: list[dict] = [
    {
        "name": "baseline",
        "system": (
            "You are an email security analyst at a bank. "
            "Analyze this email and respond with valid JSON."
        ),
        "instruction": (
            'Respond ONLY with JSON: '
            '{"verdict": "accepter|rejeter|escalader", '
            '"score_risque": 0-100, "confiance": 0.0-1.0, '
            '"raisonnement": "brief reason"}'
        ),
    },
    {
        "name": "safety_first",
        "system": (
            "You are a cautious security analyst. "
            "When in doubt, flag the email. Better safe than sorry."
        ),
        "instruction": (
            'Classify this email. Respond ONLY with JSON: '
            '{"verdict": "accepter|rejeter|escalader", '
            '"score_risque": 0-100, "confiance": 0.0-1.0, '
            '"raisonnement": "brief reason"}'
        ),
    },
    {
        "name": "minimal",
        "system": "Analyze this email.",
        "instruction": (
            'JSON response: '
            '{"verdict": "accepter|rejeter|escalader", '
            '"score_risque": 0-100, "confiance": 0.0-1.0, '
            '"raisonnement": "reason"}'
        ),
    },
    {
        "name": "english_verdict",
        "system": "You are an email security analyst at a bank.",
        "instruction": (
            'Respond with JSON: '
            '{"verdict": "accept|reject|escalate", '
            '"risk_score": 0-100, "confidence": 0.0-1.0, '
            '"reasoning": "brief explanation"}'
        ),
    },
    {
        "name": "roleplay_soc",
        "system": (
            "You work in a Security Operations Center (SOC). "
            "You review flagged emails. "
            "Your job is to protect the bank from phishing and malware."
        ),
        "instruction": (
            'Analyze and respond with JSON: '
            '{"verdict": "accepter|rejeter|escalader", '
            '"score_risque": 0-100, "confiance": 0.0-1.0, '
            '"raisonnement": "brief reason"}'
        ),
    },
    {
        "name": "reversed_order",
        "system": "You are an email security analyst at a bank.",
        "instruction": (
            'Respond with JSON: '
            '{"raisonnement": "brief reason", '
            '"confiance": 0.0-1.0, "score_risque": 0-100, '
            '"verdict": "accepter|rejeter|escalader"}'
        ),
    },
]

VARIANT_NAMES = [v["name"] for v in PROMPT_VARIANTS]

# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def build_prompt(variant: dict, email_context: str) -> str:
    """Combine system message, instruction, and email content into a single prompt."""
    return "\n\n".join([
        f"[SYSTEM]\n{variant['system']}",
        f"[EMAIL]\n{email_context}",
        f"[INSTRUCTION]\n{variant['instruction']}",
    ])


# ---------------------------------------------------------------------------
# JSON parsing with regex fallback
# ---------------------------------------------------------------------------

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)
_JSON_OBJECT_RE = re.compile(r"\{[\s\S]*\}", re.IGNORECASE)

_VERDICT_ALIASES: dict[str, str] = {
    # French variants
    "accepter": "accept",
    "rejeter": "reject",
    "escalader": "escalate",
    # English variants
    "accept": "accept",
    "reject": "reject",
    "escalate": "escalate",
    # Free-text synonyms
    "clean": "accept",
    "safe": "accept",
    "benign": "accept",
    "malicious": "reject",
    "phishing": "reject",
    "spam": "reject",
    "block": "reject",
    "flag": "escalate",
    "review": "escalate",
    "unsure": "escalate",
}


def normalize_verdict(raw: str) -> str:
    """Map any verdict string to canonical accept / reject / escalate."""
    v = (raw or "").lower().strip().strip('"').strip("'")
    return _VERDICT_ALIASES.get(v, "escalate")  # fail-safe


def parse_llm_json(raw_text: str) -> Optional[dict]:
    """Extract and parse JSON from LLM output; returns None on failure."""
    candidates: list[str] = []

    # Priority 1: fenced code block
    for m in _JSON_BLOCK_RE.finditer(raw_text):
        candidates.append(m.group(1).strip())

    # Priority 2: bare JSON object anywhere in output
    for m in _JSON_OBJECT_RE.finditer(raw_text):
        candidates.append(m.group(0).strip())

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            # Strip trailing commas and retry
            cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                continue

    return None


def extract_verdict_from_parsed(parsed: Optional[dict]) -> str:
    """Pull the verdict field from parsed JSON, normalising key variants."""
    if not parsed:
        return "escalate"
    # Field name may differ by variant (verdict vs. verdict, etc.)
    raw = (
        parsed.get("verdict")
        or parsed.get("Verdict")
        or "escalate"
    )
    return normalize_verdict(str(raw))


def extract_score_from_parsed(parsed: Optional[dict]) -> int:
    """Pull risk score, handling both French and English field names."""
    if not parsed:
        return 50
    raw = (
        parsed.get("score_risque")
        or parsed.get("risk_score")
        or parsed.get("score")
        or 50
    )
    try:
        return max(0, min(100, int(float(raw))))
    except (TypeError, ValueError):
        return 50


def extract_confidence_from_parsed(parsed: Optional[dict]) -> float:
    """Pull confidence score, handling French and English field names."""
    if not parsed:
        return 0.5
    raw = (
        parsed.get("confiance")
        or parsed.get("confidence")
        or 0.5
    )
    try:
        return max(0.0, min(1.0, float(raw)))
    except (TypeError, ValueError):
        return 0.5


# ---------------------------------------------------------------------------
# Core experiment runner
# ---------------------------------------------------------------------------

def run_single_email(
    case: dict,
    provider: str,
    model: str,
) -> dict:
    """Run all prompt variants against a single email case."""
    raw_eml: bytes = case.get("raw_eml", b"")
    expected: str = case.get("expected", "unknown")
    category: str = case.get("category", "unknown")
    case_id: str = case.get("id", "unknown")

    # Parse email and build context string once (shared across variants)
    try:
        parsed = parse_email(raw_eml)
        email_context = get_analysis_prompt(parsed, include_signals=False)
    except Exception as exc:
        print(f"  [WARN] parse error for {case_id}: {exc}")
        email_context = f"(parse error: {exc})"
        parsed = {}

    variant_results: list[dict] = []

    for variant in PROMPT_VARIANTS:
        prompt = build_prompt(variant, email_context)
        llm_raw = ""
        parsed_json = None
        verdict = "escalate"
        score = 50
        confidence = 0.5
        error = None

        try:
            llm_raw = call_model(prompt, provider=provider, model=model)
            parsed_json = parse_llm_json(llm_raw)
            verdict = extract_verdict_from_parsed(parsed_json)
            score = extract_score_from_parsed(parsed_json)
            confidence = extract_confidence_from_parsed(parsed_json)
        except Exception as exc:
            error = str(exc)
            print(f"  [ERROR] variant={variant['name']} case={case_id}: {exc}")

        variant_results.append({
            "variant": variant["name"],
            "verdict": verdict,
            "score_risque": score,
            "confiance": confidence,
            "binary": classify_verdict(verdict),
            "error": error,
        })

    # Compute per-email stability
    verdicts = [r["verdict"] for r in variant_results]
    binaries = [r["binary"] for r in variant_results]
    unique_verdicts = set(verdicts)
    unique_binaries = set(binaries)
    agreement_rate = verdicts.count(verdicts[0]) / len(verdicts)
    is_stable = len(unique_verdicts) == 1
    binary_stable = len(unique_binaries) == 1

    return {
        "id": case_id,
        "expected": expected,
        "category": category,
        "variants": variant_results,
        "unique_verdicts": list(unique_verdicts),
        "agreement_rate": agreement_rate,
        "is_stable": is_stable,
        "binary_stable": binary_stable,
    }


def run_experiment(
    corpus: list[dict],
    provider: str,
    model: str,
) -> list[dict]:
    """Run all emails through all prompt variants. Returns per-email result dicts."""
    results = []
    n = len(corpus)
    for i, case in enumerate(corpus):
        print(f"  [{i+1}/{n}] {case.get('id', '?')} (expected={case.get('expected', '?')})")
        result = run_single_email(case, provider=provider, model=model)
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_variant_metrics(
    results: list[dict],
    variant_name: str,
) -> dict:
    """Compute accuracy / recall / F1 for a single prompt variant."""
    y_true = [r["expected"] for r in results]
    y_pred = [
        next(v["binary"] for v in r["variants"] if v["variant"] == variant_name)
        for r in results
    ]
    return compute_metrics(y_true, y_pred)


def compute_pairwise_agreement(results: list[dict]) -> np.ndarray:
    """
    Return NxN agreement matrix where entry [i,j] = fraction of emails where
    variant i and variant j produced the same verdict.
    """
    n = len(VARIANT_NAMES)
    matrix = np.zeros((n, n), dtype=float)

    for i, va in enumerate(VARIANT_NAMES):
        for j, vb in enumerate(VARIANT_NAMES):
            agreed = 0
            for r in results:
                vmap = {v["variant"]: v["verdict"] for v in r["variants"]}
                if vmap.get(va) == vmap.get(vb):
                    agreed += 1
            matrix[i, j] = agreed / len(results) if results else 0.0

    return matrix


def compute_agreement_with_baseline(
    results: list[dict],
    variant_name: str,
) -> float:
    """Fraction of emails where this variant agrees with 'baseline' on verdict."""
    agreed = 0
    for r in results:
        vmap = {v["variant"]: v["verdict"] for v in r["variants"]}
        if vmap.get("baseline") == vmap.get(variant_name):
            agreed += 1
    return agreed / len(results) if results else 0.0


# ---------------------------------------------------------------------------
# Visualizations
# ---------------------------------------------------------------------------

VERDICT_COLOR_MAP = {
    "accept": "#2ecc71",
    "reject": "#e74c3c",
    "escalate": "#f39c12",
    "escalade": "#f39c12",
    "error": "#95a5a6",
}


def _verdict_to_numeric(verdict: str) -> int:
    """Map verdict to integer for heatmap coloring."""
    return {"accept": 0, "reject": 2, "escalate": 1}.get(verdict, 1)


def plot_sensitivity_heatmap(results: list[dict], output_dir: Path) -> Path:
    """
    Heatmap: emails (rows) x prompt variants (cols).
    Rows sorted by stability (most stable at top, most sensitive at bottom).
    """
    paper_style()

    sorted_results = sorted(results, key=lambda r: r["agreement_rate"], reverse=True)
    n_emails = len(sorted_results)
    n_variants = len(VARIANT_NAMES)

    matrix = np.zeros((n_emails, n_variants), dtype=float)
    for row_i, r in enumerate(sorted_results):
        vmap = {v["variant"]: v["verdict"] for v in r["variants"]}
        for col_j, vname in enumerate(VARIANT_NAMES):
            matrix[row_i, col_j] = _verdict_to_numeric(vmap.get(vname, "escalate"))

    fig, ax = plt.subplots(figsize=(max(10, n_variants * 1.8), max(6, n_emails * 0.35)))

    # Use a 3-colour discrete colourmap: accept=green, escalate=orange, reject=red
    cmap = matplotlib.colors.ListedColormap(["#2ecc71", "#f39c12", "#e74c3c"])
    bounds = [-0.5, 0.5, 1.5, 2.5]
    norm = matplotlib.colors.BoundaryNorm(bounds, cmap.N)

    im = ax.imshow(matrix, aspect="auto", cmap=cmap, norm=norm,
                   interpolation="nearest")

    ax.set_xticks(range(n_variants))
    ax.set_xticklabels(VARIANT_NAMES, rotation=30, ha="right", fontsize=10)
    ax.set_yticks(range(n_emails))
    ax.set_yticklabels(
        [f"{r['id'][:16]} ({r['agreement_rate']:.0%})" for r in sorted_results],
        fontsize=7,
    )
    ax.set_xlabel("Prompt Variant")
    ax.set_ylabel("Email (sorted by stability)")
    ax.set_title("Prompt Sensitivity Heatmap: Verdict per Email per Variant")

    legend_patches = [
        mpatches.Patch(color="#2ecc71", label="accept"),
        mpatches.Patch(color="#f39c12", label="escalate"),
        mpatches.Patch(color="#e74c3c", label="reject"),
    ]
    ax.legend(handles=legend_patches, loc="upper right",
              bbox_to_anchor=(1.15, 1), fontsize=9)

    plt.tight_layout()
    out = output_dir / "sensitivity_heatmap.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] {out}")
    return out


def plot_variant_agreement(agreement_matrix: np.ndarray, output_dir: Path) -> Path:
    """Pairwise agreement matrix heatmap (like a correlation matrix)."""
    paper_style()

    fig, ax = plt.subplots(figsize=(8, 7))
    sns.heatmap(
        agreement_matrix,
        annot=True,
        fmt=".2f",
        cmap="YlOrRd",
        vmin=0.0,
        vmax=1.0,
        xticklabels=VARIANT_NAMES,
        yticklabels=VARIANT_NAMES,
        ax=ax,
        linewidths=0.5,
    )
    ax.set_title("Pairwise Verdict Agreement Between Prompt Variants")
    ax.set_xlabel("Variant")
    ax.set_ylabel("Variant")
    plt.xticks(rotation=30, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()

    out = output_dir / "variant_agreement.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] {out}")
    return out


def plot_sensitivity_distribution(results: list[dict], output_dir: Path) -> Path:
    """Histogram of email stability: how many emails agree across all variants."""
    paper_style()

    agreement_rates = [r["agreement_rate"] for r in results]
    n_stable = sum(1 for r in results if r["is_stable"])
    n_total = len(results)

    fig, ax = plt.subplots(figsize=(8, 5))
    bins = np.linspace(0, 1, 13)  # 0.0, 0.083, ..., 1.0 in 12 steps
    counts, edges, patches = ax.hist(
        agreement_rates, bins=bins, color=COLORS[1], edgecolor="white", linewidth=0.8
    )

    # Highlight fully stable bar
    for patch, left in zip(patches, edges[:-1]):
        if left >= 0.99:
            patch.set_facecolor(COLORS[0])

    ax.axvline(
        np.mean(agreement_rates), color=COLORS[3], linestyle="--", linewidth=1.5,
        label=f"Mean agreement: {np.mean(agreement_rates):.2f}"
    )
    ax.set_xlabel("Agreement Rate Across All Variants (fraction)")
    ax.set_ylabel("Number of Emails")
    ax.set_title(
        f"Prompt Sensitivity Distribution\n"
        f"{n_stable}/{n_total} emails stable (100% variant agreement)"
    )
    ax.legend(fontsize=10)
    plt.tight_layout()

    out = output_dir / "sensitivity_distribution.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] {out}")
    return out


def plot_flip_cases(results: list[dict], output_dir: Path) -> Path:
    """Bar chart: which email categories are most sensitive to prompt changes."""
    paper_style()

    # Group by category, compute instability rate (< full agreement)
    category_total: dict[str, int] = {}
    category_unstable: dict[str, int] = {}

    for r in results:
        cat = r.get("category", "unknown")
        category_total[cat] = category_total.get(cat, 0) + 1
        if not r["is_stable"]:
            category_unstable[cat] = category_unstable.get(cat, 0) + 1

    categories = sorted(category_total.keys())
    instability_rates = [
        category_unstable.get(c, 0) / category_total[c]
        for c in categories
    ]

    fig, ax = plt.subplots(figsize=(max(8, len(categories) * 1.4), 5))
    bar_colors = [COLORS[3] if r > 0.3 else COLORS[1] for r in instability_rates]
    bars = ax.bar(categories, instability_rates, color=bar_colors, edgecolor="white")

    ax.axhline(0.3, color=COLORS[3], linestyle="--", linewidth=1,
               label="30% instability threshold")
    ax.set_xlabel("Email Category")
    ax.set_ylabel("Instability Rate (fraction of emails with verdict flip)")
    ax.set_title("Prompt Sensitivity by Email Category")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=10)

    for bar, rate, cat in zip(bars, instability_rates, categories):
        count = category_unstable.get(cat, 0)
        total = category_total[cat]
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.02,
            f"{count}/{total}",
            ha="center", va="bottom", fontsize=9,
        )

    plt.xticks(rotation=25, ha="right", fontsize=10)
    plt.tight_layout()

    out = output_dir / "flip_cases.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] {out}")
    return out


# ---------------------------------------------------------------------------
# LaTeX table
# ---------------------------------------------------------------------------

def build_latex_table(
    results: list[dict],
    variant_metrics: dict[str, dict],
    baseline_agreements: dict[str, float],
) -> list[str]:
    """Build LaTeX table comparing prompt variant performance."""
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{Prompt Variant Comparison: Accuracy, Recall, F1, and Agreement with Baseline}",
        r"\label{tab:prompt-sensitivity}",
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Variant & Accuracy & Recall & F1 & Agreement w/ Baseline (\%) \\",
        r"\midrule",
    ]

    for vname in VARIANT_NAMES:
        m = variant_metrics.get(vname, {})
        acc = m.get("accuracy", 0.0)
        rec = m.get("recall", 0.0)
        f1 = m.get("f1", 0.0)
        agr = baseline_agreements.get(vname, 1.0)
        latex_name = vname.replace("_", r"\_")
        agr_pct = f"{agr * 100:.1f}"
        lines.append(
            f"{latex_name} & {acc:.3f} & {rec:.3f} & {f1:.3f} & {agr_pct}\\% \\\\"
        )

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return lines


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def print_summary(results: list[dict], variant_metrics: dict[str, dict]) -> None:
    n = len(results)
    n_stable = sum(1 for r in results if r["is_stable"])
    n_binary_stable = sum(1 for r in results if r["binary_stable"])
    mean_agree = np.mean([r["agreement_rate"] for r in results])

    print()
    print("=" * 60)
    print("EXPERIMENT 3 -- PROMPT SENSITIVITY RESULTS")
    print("=" * 60)
    print(f"Total emails        : {n}")
    print(f"Fully stable        : {n_stable} ({n_stable/n:.1%}) -- same verdict all 6 variants")
    print(f"Binary stable       : {n_binary_stable} ({n_binary_stable/n:.1%}) -- same accept/reject all 6 variants")
    print(f"Mean agreement rate : {mean_agree:.3f}")
    print()
    print(f"{'Variant':<20} {'Accuracy':>10} {'Recall':>10} {'F1':>8}")
    print("-" * 52)
    for vname in VARIANT_NAMES:
        m = variant_metrics.get(vname, {})
        print(
            f"{vname:<20} "
            f"{m.get('accuracy', 0):.3f}      "
            f"{m.get('recall', 0):.3f}      "
            f"{m.get('f1', 0):.3f}"
        )
    print("=" * 60)
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="E3: Prompt Sensitivity Analysis for Trust No Email paper"
    )
    p.add_argument("--provider", default="ollama",
                   choices=["ollama", "openai", "groq", "together", "anthropic", "nvidia", "deepseek", "mistral_nvidia"],
                   help="LLM provider (default: ollama)")
    p.add_argument("--model", default="gemma3:4b",
                   help="Model name (default: gemma3:4b)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    print(f"[E3] Prompt Sensitivity | provider={args.provider} model={args.model}")

    output_dir = get_output_dir("e3_prompt_sensitivity")
    print(f"[E3] Output dir: {output_dir}")

    # Load corpus
    print("[E3] Loading corpus...")
    corpus = load_corpus()

    if not corpus:
        print("[ERROR] Corpus is empty. Cannot run experiment.", file=sys.stderr)
        sys.exit(1)

    # Run experiment
    print(f"[E3] Running {len(corpus)} emails x {len(PROMPT_VARIANTS)} variants...")
    t0 = time.time()
    results = run_experiment(corpus, provider=args.provider, model=args.model)
    elapsed = time.time() - t0
    print(f"[E3] Done in {elapsed:.1f}s")

    # Compute metrics per variant
    variant_metrics: dict[str, dict] = {}
    for vname in VARIANT_NAMES:
        variant_metrics[vname] = compute_variant_metrics(results, vname)

    # Pairwise agreement matrix
    agreement_matrix = compute_pairwise_agreement(results)

    # Agreement with baseline per variant
    baseline_agreements = {
        vname: compute_agreement_with_baseline(results, vname)
        for vname in VARIANT_NAMES
    }

    # Print summary
    print_summary(results, variant_metrics)

    # Save raw results
    payload = {
        "experiment": "e3_prompt_sensitivity",
        "provider": args.provider,
        "model": args.model,
        "n_emails": len(corpus),
        "n_variants": len(PROMPT_VARIANTS),
        "variant_names": VARIANT_NAMES,
        "variant_metrics": variant_metrics,
        "pairwise_agreement": agreement_matrix.tolist(),
        "baseline_agreements": baseline_agreements,
        "per_email": results,
    }
    save_results(payload, output_dir, "results")

    # Visualizations
    print("[E3] Generating plots...")
    plot_sensitivity_heatmap(results, output_dir)
    plot_variant_agreement(agreement_matrix, output_dir)
    plot_sensitivity_distribution(results, output_dir)
    plot_flip_cases(results, output_dir)

    # LaTeX table
    print("[E3] Generating LaTeX table...")
    latex_lines = build_latex_table(results, variant_metrics, baseline_agreements)
    save_latex(latex_lines, output_dir, "prompt_variants")

    print(f"[E3] All outputs written to: {output_dir}")


if __name__ == "__main__":
    main()
