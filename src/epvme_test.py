"""epvme_test.py — Test pipeline against 500 real malicious .eml files from EPVME dataset.

Usage:
    python src/epvme_test.py                # 500 emails, no LLM (fast, rules+extraction only)
    python src/epvme_test.py --with-llm     # include LLM stage (slow, ~2min/email)
    python src/epvme_test.py --count 100    # test fewer emails
"""
from __future__ import annotations

import argparse
import io
import json
import os
import random
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_SRC.parent / ".env")

from accuracy import run_pipeline_isolated, classify_result

_OUT_DIR = _SRC.parent / "data" / "epvme_results"
_OUT_DIR.mkdir(parents=True, exist_ok=True)

EPVME_ZIP = _SRC.parent / "EPVME-Dataset-main.zip"


def load_epvme_emls(count: int = 500, seed: int = 42) -> list[tuple[str, bytes]]:
    """Load `count` .eml files from the nested EPVME zip archive.

    Returns list of (filename, raw_bytes) tuples.
    """
    if not EPVME_ZIP.exists():
        print(f"ERROR: {EPVME_ZIP} not found")
        sys.exit(1)

    # Collect all .eml entries across inner zips
    outer = zipfile.ZipFile(str(EPVME_ZIP))
    inner_zips = sorted([n for n in outer.namelist() if n.endswith(".zip")])

    all_entries: list[tuple[str, str]] = []  # (inner_zip_name, eml_path)
    for iz in inner_zips:
        inner_data = outer.read(iz)
        inner = zipfile.ZipFile(io.BytesIO(inner_data))
        for name in inner.namelist():
            if name.lower().endswith(".eml"):
                all_entries.append((iz, name))
        inner.close()

    print(f"[EPVME] Found {len(all_entries)} total .eml files across {len(inner_zips)} zips")

    # Sample
    rng = random.Random(seed)
    if count < len(all_entries):
        selected = rng.sample(all_entries, count)
    else:
        selected = all_entries

    # Load the selected .eml bytes
    # Group by inner zip to avoid re-reading the same zip multiple times
    by_zip: dict[str, list[str]] = defaultdict(list)
    for iz, eml_path in selected:
        by_zip[iz].append(eml_path)

    results: list[tuple[str, bytes]] = []
    for iz, eml_paths in by_zip.items():
        inner_data = outer.read(iz)
        inner = zipfile.ZipFile(io.BytesIO(inner_data))
        for eml_path in eml_paths:
            raw = inner.read(eml_path)
            results.append((eml_path, raw))
        inner.close()

    outer.close()
    return results


def main():
    parser = argparse.ArgumentParser(description="EPVME dataset pipeline test")
    parser.add_argument("--count", type=int, default=500, help="Number of .eml files to test")
    parser.add_argument("--with-llm", action="store_true", help="Include LLM analysis (slow)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling")
    args = parser.parse_args()

    run_llm = args.with_llm

    print("=" * 60)
    print("  IMANIA — EPVME Dataset Test")
    print("=" * 60)
    print(f"  Sample size:  {args.count}")
    print(f"  LLM analysis: {'ON' if run_llm else 'OFF (rules + extraction only)'}")
    print(f"  Seed:         {args.seed}")
    print()

    # Load emails
    emls = load_epvme_emls(count=args.count, seed=args.seed)
    print(f"[LOADED] {len(emls)} .eml files ready for testing\n")

    # Run pipeline
    results = []
    caught = 0
    missed = 0
    errors = 0
    stage_catches: Counter = Counter()  # which stage first caught it
    rule_hits: Counter = Counter()  # which specific rules fired
    timings: list[float] = []

    for i, (filename, raw_eml) in enumerate(emls, 1):
        short = filename.split("/")[-1][:40]
        if i % 50 == 1 or i == len(emls):
            print(f"[{i:3d}/{len(emls)}] Processing {short}...")

        t0 = time.time()
        try:
            result = run_pipeline_isolated(raw_eml, run_llm=run_llm)
        except Exception as e:
            result = {"final_status": "escalated", "stages": {"error": str(e)},
                      "deterministic_escalation": True}
            errors += 1
        elapsed = time.time() - t0
        timings.append(elapsed)

        predicted = classify_result(result)
        is_caught = predicted == "malicious"

        if is_caught:
            caught += 1
        else:
            missed += 1
            print(f"  *** MISS: {filename} -> {result['final_status']} ***")

        # Track which stage caught it
        if is_caught:
            stages = result.get("stages", {})
            if stages.get("auth", {}).get("failed"):
                stage_catches["auth"] += 1
            elif stages.get("rules", {}).get("flags", 0) > 0:
                stage_catches["rules"] += 1
            elif stages.get("extraction", {}).get("escalate"):
                stage_catches["extraction"] += 1
            elif stages.get("llm", {}).get("verdict") == "escalated":
                stage_catches["llm"] += 1
            else:
                stage_catches["parse_or_other"] += 1

        # Track specific rule hits
        flagged_rules = result.get("stages", {}).get("rules", {}).get("flagged_rules", [])
        for r in flagged_rules:
            rule_hits[r] += 1

        results.append({
            "filename": filename,
            "predicted": predicted,
            "final_status": result["final_status"],
            "deterministic": result.get("deterministic_escalation", False),
            "stages": {k: v for k, v in result.get("stages", {}).items()
                       if k != "extraction"},  # skip bulky extraction details
            "elapsed": elapsed,
        })

    # --- Results ---
    total = len(emls)
    detection_rate = caught / total if total else 0

    print("\n" + "=" * 60)
    print("  RESULTS — EPVME Dataset (all malicious)")
    print("=" * 60)
    print(f"\n  Total tested:     {total}")
    print(f"  Detected (TP):    {caught}  ({caught/total:.1%})")
    print(f"  Missed (FN):      {missed}  ({missed/total:.1%})")
    print(f"  Parse errors:     {errors}")
    print(f"  Detection rate:   {detection_rate:.1%}")
    print(f"\n  Avg latency:      {np.mean(timings):.2f}s")
    print(f"  Median latency:   {np.median(timings):.2f}s")
    print(f"  Max latency:      {np.max(timings):.2f}s")

    print(f"\n  Detection by stage (first stage that caught it):")
    for stage, count in stage_catches.most_common():
        print(f"    {stage:20s}: {count:4d}  ({count/caught:.1%})" if caught else "")

    print(f"\n  Top 15 rules fired:")
    for rule, count in rule_hits.most_common(15):
        print(f"    {rule:40s}: {count:4d}")

    # --- Save results ---
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": {"count": total, "llm": run_llm, "seed": args.seed},
        "summary": {
            "total": total,
            "caught": caught,
            "missed": missed,
            "detection_rate": detection_rate,
            "avg_latency": float(np.mean(timings)),
        },
        "stage_catches": dict(stage_catches),
        "top_rules": dict(rule_hits.most_common(30)),
        "missed_emails": [r for r in results if r["predicted"] == "benign"],
    }
    report_path = _OUT_DIR / "epvme_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report saved: {report_path}")

    # --- Plots ---
    # 1. Stage detection pie chart
    if stage_catches:
        fig, ax = plt.subplots(figsize=(8, 6))
        labels = list(stage_catches.keys())
        sizes = list(stage_catches.values())
        colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6"]
        ax.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors[:len(labels)],
               startangle=140)
        ax.set_title(f"EPVME Detection by Pipeline Stage (n={caught})")
        fig.tight_layout()
        fig.savefig(_OUT_DIR / "epvme_stage_pie.png", dpi=150)
        plt.close(fig)

    # 2. Top rules bar chart
    if rule_hits:
        fig, ax = plt.subplots(figsize=(12, 6))
        top_rules = rule_hits.most_common(15)
        rules_names = [r[0][:35] for r in top_rules]
        rules_counts = [r[1] for r in top_rules]
        bars = ax.barh(range(len(rules_names)), rules_counts, color="#e74c3c")
        ax.set_yticks(range(len(rules_names)))
        ax.set_yticklabels(rules_names, fontsize=9)
        ax.set_xlabel("Emails flagged")
        ax.set_title(f"Top Rules Triggered on EPVME Dataset (n={total})")
        ax.invert_yaxis()
        fig.tight_layout()
        fig.savefig(_OUT_DIR / "epvme_rules_bar.png", dpi=150)
        plt.close(fig)

    # 3. Latency histogram
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(timings, bins=30, color="#3498db", edgecolor="white")
    ax.axvline(np.median(timings), color="#e74c3c", linestyle="--", label=f"Median: {np.median(timings):.2f}s")
    ax.set_xlabel("Processing time (seconds)")
    ax.set_ylabel("Count")
    ax.set_title(f"EPVME Pipeline Latency Distribution (n={total})")
    ax.legend()
    fig.tight_layout()
    fig.savefig(_OUT_DIR / "epvme_latency.png", dpi=150)
    plt.close(fig)

    # 4. Detection gauge
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.barh(["Detected", "Missed"], [caught, missed],
            color=["#2ecc71", "#e74c3c"])
    ax.set_xlabel("Emails")
    ax.set_title(f"EPVME Detection Rate: {detection_rate:.1%}")
    for j, v in enumerate([caught, missed]):
        ax.text(v + 1, j, str(v), va="center", fontweight="bold")
    fig.tight_layout()
    fig.savefig(_OUT_DIR / "epvme_detection.png", dpi=150)
    plt.close(fig)

    print(f"  Plots saved to {_OUT_DIR}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
