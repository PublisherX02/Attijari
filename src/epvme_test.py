"""epvme_test.py — Test pipeline against 500 real malicious .eml files from EPVME dataset.

Usage:
    python src/epvme_test.py                          # 500 emails, no LLM (fast, rules+extraction only)
    python src/epvme_test.py --with-llm               # include LLM stage (slow, ~2min/email)
    python src/epvme_test.py --with-llm --with-detonation  # + sandbox for LLM-unsure attachments
    python src/epvme_test.py --count 100               # test fewer emails
    python src/epvme_test.py --with-llm --no-benign    # EPVME only, skip benign mix (no true F1/precision)

By default a benign case set (accuracy.build_benign_cases — clean invoices,
newsletters, etc.) is run through the same pipeline alongside EPVME so that
precision / F1 / accuracy are computed against real negatives, not just
recall on an all-malicious set. Use --no-benign to skip this and only get
the EPVME detection rate (recall).
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

from accuracy import (
    run_pipeline_isolated, classify_result, build_benign_cases,
    compute_metrics, plot_confusion_matrix, plot_metrics_bar,
)

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
    parser.add_argument("--with-detonation", action="store_true",
                         help="Queue attachments the LLM was unsure about for CAPE sandbox "
                              "detonation, then drain the queue once at the end (requires "
                              "--with-llm and a reachable DB + CAPE instance)")
    parser.add_argument("--no-benign", action="store_true",
                         help="Skip the benign case mix — EPVME-only recall, no true "
                              "precision/F1/accuracy (no negatives to measure false positives)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling")
    args = parser.parse_args()

    run_llm = args.with_llm
    run_detonation = args.with_detonation
    run_benign = not args.no_benign
    if run_detonation and not run_llm:
        print("ERROR: --with-detonation requires --with-llm (the sandbox trigger is LLM-unsure)")
        sys.exit(1)

    db = None
    if run_detonation:
        from database import SessionLocal
        db = SessionLocal()

    print("=" * 60)
    print("  ATTIJARI — EPVME Dataset Test")
    print("=" * 60)
    print(f"  Sample size:  {args.count}")
    print(f"  LLM analysis: {'ON' if run_llm else 'OFF (rules + extraction only)'}")
    print(f"  Detonation:   {'ON (queued + drained at end)' if run_detonation else 'OFF'}")
    print(f"  Benign mix:   {'ON (for precision/F1)' if run_benign else 'OFF (recall only)'}")
    print(f"  Seed:         {args.seed}")
    print()

    # Load emails
    emls = load_epvme_emls(count=args.count, seed=args.seed)
    print(f"[LOADED] {len(emls)} EPVME (malicious) .eml files ready for testing")

    cases: list[tuple[str, str, bytes]] = [("malicious", fn, raw) for fn, raw in emls]
    n_malicious = len(cases)
    n_benign = 0
    if run_benign:
        benign_cases = build_benign_cases()
        cases += [("benign", c["name"], c["eml"]) for c in benign_cases]
        n_benign = len(benign_cases)
        print(f"[LOADED] {n_benign} benign .eml cases mixed in for precision/F1")
    print()

    # Run pipeline
    results = []
    caught = 0            # true positives on the EPVME (malicious) subset only
    missed = 0             # false negatives on the EPVME (malicious) subset only
    errors = 0
    stage_catches: Counter = Counter()  # which stage first caught it (malicious subset)
    rule_hits: Counter = Counter()      # which specific rules fired
    timings: list[float] = []           # pipeline latency, every case, sandbox or not
    timings_no_sandbox: list[float] = []   # pipeline latency, cases that did NOT need the sandbox
    sha_to_result_index: dict[str, int] = {}  # for folding detonation verdicts back in

    total_cases = len(cases)
    for i, (expected, filename, raw_eml) in enumerate(cases, 1):
        short = str(filename).split("/")[-1][:40]
        if i % 50 == 1 or i == total_cases:
            print(f"[{i:3d}/{total_cases}] Processing {short}...")

        t0 = time.time()
        try:
            result = run_pipeline_isolated(raw_eml, run_llm=run_llm,
                                            enable_detonation=run_detonation, db=db)
        except Exception as e:
            result = {"final_status": "escalated", "stages": {"error": str(e)},
                      "deterministic_escalation": True, "detonation_queued": []}
            errors += 1
        elapsed = time.time() - t0
        timings.append(elapsed)

        predicted = classify_result(result)
        queued_shas = result.get("detonation_queued", [])
        if not queued_shas:
            timings_no_sandbox.append(elapsed)

        if expected == "malicious":
            is_caught = predicted == "malicious"
            if is_caught:
                caught += 1
            else:
                missed += 1
                print(f"  *** MISS: {filename} -> {result['final_status']} ***")

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

            flagged_rules = result.get("stages", {}).get("rules", {}).get("flagged_rules", [])
            for r in flagged_rules:
                rule_hits[r] += 1
        elif predicted == "malicious":
            print(f"  *** FALSE POSITIVE: {filename} -> {result['final_status']} ***")

        results.append({
            "filename": filename,
            "expected": expected,
            "predicted": predicted,
            "final_status": result["final_status"],
            "deterministic": result.get("deterministic_escalation", False),
            "stages": {k: v for k, v in result.get("stages", {}).items()
                       if k != "extraction"},  # skip bulky extraction details
            "elapsed": elapsed,
        })
        for sha in queued_shas:
            sha_to_result_index[sha] = len(results) - 1

    # --- Detonation drain (optional) ---
    detonation_summary = None
    timings_with_sandbox: list[float] = []
    sandbox_durations: list[float] = []
    if run_detonation:
        from database import count_queued_detonations, PendingDetonation
        import detonation as detonation_mod

        n_queued = count_queued_detonations(db)
        print(f"\n[DETONATION] {n_queued} sample(s) queued from this run — draining...")
        detonation_summary = {"queued": n_queued, "processed": 0, "escalated": 0,
                               "errors": 0, "flipped_to_malicious": 0}
        drain_t0 = time.time()
        # process_detonation_queue() handles DETONATION_BATCH_SIZE (default 5)
        # per call and its own drain/restore window; loop until the queue —
        # scoped to what we enqueued above — is empty.
        guard = 0
        while count_queued_detonations(db) > 0 and guard < 200:
            summary = detonation_mod.process_detonation_queue()
            detonation_summary["processed"] += summary.get("processed", 0)
            detonation_summary["escalated"] += summary.get("escalated", 0)
            detonation_summary["errors"] += summary.get("errors", 0)
            if summary.get("status") in ("empty", "cape_unavailable"):
                break
            guard += 1
        detonation_summary["elapsed"] = time.time() - drain_t0

        # Fold sandbox verdicts back into the per-email results, and compute
        # per-sample "latency with sandbox" = original pipeline latency +
        # the sample's own time sitting in the sandbox (updated_at is set
        # both when a row flips to 'running' and again when it finishes, so
        # updated_at - created_at approximates queued-to-verdict duration).
        for sha, idx in sha_to_result_index.items():
            row = db.query(PendingDetonation).filter(PendingDetonation.sha256 == sha).first()
            if not row:
                continue
            if row.created_at and row.updated_at:
                duration = (row.updated_at - row.created_at).total_seconds()
                if duration > 0:
                    sandbox_durations.append(duration)
                    timings_with_sandbox.append(results[idx]["elapsed"] + duration)
            if not row.result:
                continue
            if row.result.get("escalate") and results[idx]["predicted"] != "malicious":
                results[idx]["predicted"] = "malicious"
                results[idx]["final_status"] = "escalated"
                results[idx]["stages"]["detonation"] = {
                    "malscore": row.result.get("malscore"),
                    "escalate": True,
                }
                if results[idx]["expected"] == "malicious":
                    stage_catches["detonation"] += 1
                    detonation_summary["flipped_to_malicious"] += 1
                    caught += 1
                    missed -= 1
                print(f"  *** SANDBOX CAUGHT: {results[idx]['filename']} "
                      f"(malscore {row.result.get('malscore')}) ***")

        db.close()

    # --- Classification metrics (accuracy / precision / recall / F1) ---
    metrics = None
    if run_benign:
        y_true = [r["expected"] for r in results]
        y_pred = [r["predicted"] for r in results]
        metrics = compute_metrics(y_true, y_pred)

    # --- Results ---
    total = n_malicious
    detection_rate = caught / total if total else 0
    sandbox_invocations = len(sha_to_result_index)
    sandbox_rate = sandbox_invocations / total_cases if total_cases else 0

    print("\n" + "=" * 60)
    print("  RESULTS — EPVME Dataset (malicious subset)")
    print("=" * 60)
    print(f"\n  Total tested:     {total}")
    print(f"  Detected (TP):    {caught}  ({caught/total:.1%})")
    print(f"  Missed (FN):      {missed}  ({missed/total:.1%})")
    print(f"  Parse errors:     {errors}")
    print(f"  Detection rate:   {detection_rate:.1%}")

    if metrics:
        print(f"\n  Classification metrics (malicious + benign, n={total_cases}):")
        print(f"    Accuracy:   {metrics['accuracy']:.1%}")
        print(f"    Precision:  {metrics['precision']:.1%}")
        print(f"    Recall:     {metrics['recall']:.1%}")
        print(f"    F1 score:   {metrics['f1']:.1%}")

    print(f"\n  Latency — pipeline only (no sandbox), n={len(timings_no_sandbox)}:")
    if timings_no_sandbox:
        print(f"    Avg:    {np.mean(timings_no_sandbox):.2f}s")
        print(f"    Median: {np.median(timings_no_sandbox):.2f}s")
        print(f"    Max:    {np.max(timings_no_sandbox):.2f}s")
    if timings_with_sandbox:
        print(f"\n  Latency — WITH sandbox (pipeline + CAPE), n={len(timings_with_sandbox)}:")
        print(f"    Avg:    {np.mean(timings_with_sandbox):.2f}s")
        print(f"    Median: {np.median(timings_with_sandbox):.2f}s")
        print(f"    Max:    {np.max(timings_with_sandbox):.2f}s")

    print(f"\n  Sandbox invocation rate: {sandbox_invocations}/{total_cases} emails "
          f"({sandbox_rate:.1%}) needed the sandbox")

    print(f"\n  Detection by stage (first stage that caught it):")
    for stage, count in stage_catches.most_common():
        print(f"    {stage:20s}: {count:4d}  ({count/caught:.1%})" if caught else "")

    if detonation_summary:
        print(f"\n  Sandbox (CAPE) detonation:")
        print(f"    Queued:             {detonation_summary['queued']}")
        print(f"    Processed:          {detonation_summary['processed']}")
        print(f"    Escalated by CAPE:  {detonation_summary['escalated']}")
        print(f"    Flipped to caught:  {detonation_summary['flipped_to_malicious']}")
        print(f"    Errors:             {detonation_summary['errors']}")
        print(f"    Drain wall time:    {detonation_summary['elapsed']:.1f}s")

    print(f"\n  Top 15 rules fired:")
    for rule, count in rule_hits.most_common(15):
        print(f"    {rule:40s}: {count:4d}")

    # --- Save results ---
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": {"count": total, "benign_mixed": n_benign, "llm": run_llm,
                   "detonation": run_detonation, "seed": args.seed},
        "detonation_summary": detonation_summary,
        "summary": {
            "total": total,
            "caught": caught,
            "missed": missed,
            "detection_rate": detection_rate,
            "avg_latency": float(np.mean(timings)),
            "avg_latency_no_sandbox": float(np.mean(timings_no_sandbox)) if timings_no_sandbox else None,
            "avg_latency_with_sandbox": float(np.mean(timings_with_sandbox)) if timings_with_sandbox else None,
            "sandbox_invocations": sandbox_invocations,
            "sandbox_rate": sandbox_rate,
        },
        "metrics": {k: v for k, v in (metrics or {}).items() if k != "classification_report"},
        "classification_report": (metrics or {}).get("classification_report"),
        "stage_catches": dict(stage_catches),
        "top_rules": dict(rule_hits.most_common(30)),
        "missed_emails": [r for r in results if r["expected"] == "malicious" and r["predicted"] == "benign"],
        "false_positives": [r for r in results if r["expected"] == "benign" and r["predicted"] == "malicious"],
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

    # 3. Latency histogram (overall, all cases)
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(timings, bins=30, color="#3498db", edgecolor="white")
    ax.axvline(np.median(timings), color="#e74c3c", linestyle="--", label=f"Median: {np.median(timings):.2f}s")
    ax.set_xlabel("Processing time (seconds)")
    ax.set_ylabel("Count")
    ax.set_title(f"EPVME Pipeline Latency Distribution (n={total_cases})")
    ax.legend()
    fig.tight_layout()
    fig.savefig(_OUT_DIR / "epvme_latency.png", dpi=150)
    plt.close(fig)

    # 3b. Latency comparison: without sandbox vs with sandbox
    if timings_with_sandbox:
        fig, ax = plt.subplots(figsize=(8, 5))
        data = [timings_no_sandbox, timings_with_sandbox]
        bp = ax.boxplot(data, labels=["Without sandbox", "With sandbox"],
                         patch_artist=True, widths=0.5)
        for patch, color in zip(bp["boxes"], ["#2ecc71", "#e74c3c"]):
            patch.set_facecolor(color)
            patch.set_alpha(0.6)
        for i, series in enumerate(data, start=1):
            ax.text(i, np.median(series), f" median {np.median(series):.2f}s",
                    va="center", fontsize=9, fontweight="bold")
        ax.set_ylabel("Processing time (seconds)")
        ax.set_title("Pipeline Latency: Without Sandbox vs. With Sandbox")
        fig.tight_layout()
        fig.savefig(_OUT_DIR / "epvme_latency_sandbox_comparison.png", dpi=150)
        plt.close(fig)

    # 3c. Sandbox invocation rate
    fig, ax = plt.subplots(figsize=(6, 6))
    invoked = sandbox_invocations
    not_invoked = total_cases - invoked
    colors = ["#e67e22", "#2ecc71"]
    wedges, _, autotexts = ax.pie(
        [invoked, not_invoked], labels=["Sent to sandbox", "Resolved without sandbox"],
        autopct=lambda p: f"{p:.1f}%\n({int(round(p / 100 * total_cases))})",
        colors=colors, startangle=90,
    )
    ax.set_title(f"How Often the Pipeline Needed the Sandbox (n={total_cases})")
    fig.tight_layout()
    fig.savefig(_OUT_DIR / "epvme_sandbox_rate.png", dpi=150)
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

    # 5. Accuracy / Precision / Recall / F1 bar chart + confusion matrix
    if metrics:
        plot_metrics_bar(metrics, _OUT_DIR / "epvme_metrics_bar.png")
        plot_confusion_matrix(metrics["confusion_matrix"], _OUT_DIR / "epvme_confusion_matrix.png")

    print(f"  Plots saved to {_OUT_DIR}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
