"""corpus_test.py -- Test pipeline against public email corpora.

Downloads and tests:
  1. SpamAssassin public corpus (ham + spam)
  2. Nazario phishing corpus
  3. Existing synthetic corpus (malicious + benign)

Runs each email through run_pipeline_isolated() and reports metrics.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
import urllib.request
from collections import Counter
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path

# Project imports
_SRC = Path(__file__).resolve().parent
_ROOT = _SRC.parent
sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_ROOT / ".env")

from accuracy import run_pipeline_isolated, build_malicious_cases, build_benign_cases

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATA_DIR = _ROOT / "data" / "corpora"
DATA_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_DIR = _ROOT / "data" / "experiments" / "corpus_validation"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# SpamAssassin corpus URLs (Apache mirror)
SA_URLS = {
    "ham":  "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "spam": "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2",
}

# Nazario phishing corpus (GitHub mirror of classic collection)
NAZARIO_URL = "https://monkey.org/~jose/phishing/phishing3.mbox"

MAX_PER_CATEGORY = 50  # limit per category to keep runtime reasonable


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------
def download_file(url: str, dest: Path) -> Path:
    """Download a URL to local path if not already cached."""
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  [CACHED] {dest.name}")
        return dest
    print(f"  [DOWNLOAD] {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        print(f"  [OK] {dest.stat().st_size / 1024:.0f} KB")
    except Exception as e:
        print(f"  [FAIL] {e}")
    return dest


# ---------------------------------------------------------------------------
# Corpus loaders
# ---------------------------------------------------------------------------
def load_spamassassin(category: str, limit: int = MAX_PER_CATEGORY) -> list[dict]:
    """Download and extract SpamAssassin corpus emails."""
    url = SA_URLS[category]
    archive_name = url.split("/")[-1]
    archive_path = DATA_DIR / archive_name
    download_file(url, archive_path)

    if not archive_path.exists() or archive_path.stat().st_size == 0:
        print(f"  [SKIP] Failed to download {category}")
        return []

    expected = "benign" if category == "ham" else "malicious"
    cases = []
    try:
        with tarfile.open(str(archive_path), "r:bz2") as tar:
            members = [m for m in tar.getmembers() if m.isfile() and not m.name.endswith("cmds")]
            for member in members[:limit]:
                try:
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    raw = f.read()
                    # Validate it's parseable
                    BytesParser(policy=policy.default).parsebytes(raw)
                    cases.append({
                        "name": f"SA_{category}_{Path(member.name).name}",
                        "source": "SpamAssassin",
                        "expected": expected,
                        "raw_bytes": raw,
                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"  [ERROR] Extracting {archive_name}: {e}")

    print(f"  [SpamAssassin {category}] Loaded {len(cases)} emails")
    return cases


def load_nazario(limit: int = MAX_PER_CATEGORY) -> list[dict]:
    """Download Nazario phishing mbox into memory and parse.

    Windows has issues reading the file back from disk (OSError 22),
    so we download directly into memory and parse from there.
    """
    cache_path = DATA_DIR / "nazario_emails.json"

    # If we already extracted and cached individual emails, use that
    if cache_path.exists() and cache_path.stat().st_size > 100:
        print(f"  [CACHED] Loading from {cache_path.name}")
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        cases = []
        for i, entry in enumerate(cached[:limit]):
            cases.append({
                "name": f"nazario_phish_{i}",
                "source": "Nazario",
                "expected": "malicious",
                "raw_bytes": entry["raw"].encode("latin-1"),
            })
        print(f"  [Nazario] Loaded {len(cases)} phishing emails (cached)")
        return cases

    # Download into memory (skip disk due to Windows read issues)
    print(f"  [DOWNLOAD] {NAZARIO_URL}")
    try:
        req = urllib.request.Request(NAZARIO_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            raw_data = resp.read()
        print(f"  [OK] {len(raw_data) / 1024 / 1024:.1f} MB in memory")
    except Exception as e:
        print(f"  [FAIL] Download error: {e}")
        return []

    # Parse mbox from memory
    cases = []
    cache_entries = []
    parts = raw_data.split(b"\nFrom ")
    for i, part in enumerate(parts):
        if len(cases) >= limit:
            break
        try:
            if i > 0:
                part = b"From " + part
            lines = part.split(b"\n", 1)
            if len(lines) < 2:
                continue
            email_bytes = lines[1] if lines[0].startswith(b"From ") else part
            if len(email_bytes) < 50:
                continue
            # Validate it's parseable
            BytesParser(policy=policy.default).parsebytes(email_bytes)
            cases.append({
                "name": f"nazario_phish_{len(cases)}",
                "source": "Nazario",
                "expected": "malicious",
                "raw_bytes": email_bytes,
            })
            cache_entries.append({"raw": email_bytes.decode("latin-1")})
        except Exception:
            continue

    # Cache to disk as JSON for future runs
    try:
        cache_path.write_text(
            json.dumps(cache_entries, ensure_ascii=True),
            encoding="utf-8",
        )
        print(f"  [CACHE] Saved {len(cache_entries)} emails to {cache_path.name}")
    except Exception as e:
        print(f"  [WARN] Could not cache: {e}")

    print(f"  [Nazario] Loaded {len(cases)} phishing emails")
    return cases


def load_synthetic() -> list[dict]:
    """Load existing synthetic corpus from accuracy.py."""
    cases = []
    for c in build_malicious_cases():
        cases.append({
            "name": c["name"],
            "source": "Synthetic_Malicious",
            "expected": "malicious",
            "raw_bytes": c["eml"],
        })
    for c in build_benign_cases():
        cases.append({
            "name": c["name"],
            "source": "Synthetic_Benign",
            "expected": "benign",
            "raw_bytes": c["eml"],
        })
    print(f"  [Synthetic] Loaded {len(cases)} emails "
          f"({sum(1 for c in cases if c['expected'] == 'malicious')} mal, "
          f"{sum(1 for c in cases if c['expected'] == 'benign')} ben)")
    return cases


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------
def run_corpus(cases: list[dict], run_llm: bool = True) -> list[dict]:
    """Run each case through the pipeline and collect results."""
    results = []
    total = len(cases)
    for i, case in enumerate(cases):
        name = case["name"]
        expected = case["expected"]
        print(f"  [{i+1}/{total}] {name} (expected={expected})", end="", flush=True)

        t0 = time.time()
        try:
            pipeline_result = run_pipeline_isolated(case["raw_bytes"], run_llm=run_llm)
            status = pipeline_result["final_status"]
            # Map pipeline status to binary
            if status in ("accepted", "recu"):
                predicted = "benign"
            else:
                predicted = "malicious"
            elapsed = time.time() - t0
            correct = predicted == expected
            print(f"  -> {status} ({'OK' if correct else 'WRONG'}) [{elapsed:.1f}s]")
            results.append({
                "name": name,
                "source": case["source"],
                "expected": expected,
                "predicted": predicted,
                "pipeline_status": status,
                "correct": correct,
                "elapsed_s": round(elapsed, 2),
                "deterministic": pipeline_result.get("deterministic_escalation", False),
                "stages": pipeline_result.get("stages", {}),
            })
        except Exception as e:
            elapsed = time.time() - t0
            print(f"  -> ERROR: {e} [{elapsed:.1f}s]")
            # Fail-safe: error = malicious (escalate)
            predicted = "malicious"
            results.append({
                "name": name,
                "source": case["source"],
                "expected": expected,
                "predicted": predicted,
                "pipeline_status": "error",
                "correct": predicted == expected,
                "elapsed_s": round(elapsed, 2),
                "deterministic": False,
                "error": str(e),
            })
    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(results: list[dict]) -> dict:
    """Compute accuracy, precision, recall, F1."""
    y_true = [r["expected"] for r in results]
    y_pred = [r["predicted"] for r in results]

    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report,
    )
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "recall": recall_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "f1": f1_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=["benign", "malicious"]).tolist(),
        "classification_report": classification_report(y_true, y_pred, labels=["benign", "malicious"], zero_division=0),
    }


def print_report(results: list[dict], label: str):
    """Print a summary report for a set of results."""
    print()
    print(f"{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")

    metrics = compute_metrics(results)
    cm = metrics["confusion_matrix"]

    print(f"  Total     : {len(results)}")
    print(f"  Correct   : {sum(r['correct'] for r in results)}")
    print(f"  Wrong     : {sum(not r['correct'] for r in results)}")
    print(f"  Accuracy  : {metrics['accuracy']:.1%}")
    print(f"  Precision : {metrics['precision']:.1%}")
    print(f"  Recall    : {metrics['recall']:.1%}")
    print(f"  F1        : {metrics['f1']:.1%}")
    print(f"  Confusion : TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

    # Errors breakdown
    errors = [r for r in results if not r["correct"]]
    if errors:
        print(f"\n  Misclassified:")
        for r in errors[:10]:
            print(f"    {r['name']}: expected={r['expected']} got={r['predicted']} "
                  f"(status={r['pipeline_status']})")

    # Deterministic vs LLM breakdown
    det_count = sum(1 for r in results if r.get("deterministic"))
    print(f"\n  Deterministic detections: {det_count}/{len(results)}")
    print(f"  LLM-only detections: {sum(1 for r in results if r['predicted']=='malicious' and not r.get('deterministic'))}")

    return metrics


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Test pipeline against public corpora")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM stage (deterministic only)")
    parser.add_argument("--limit", type=int, default=MAX_PER_CATEGORY, help="Max emails per category")
    parser.add_argument("--skip-download", action="store_true", help="Only use synthetic corpus")
    args = parser.parse_args()

    run_llm = not args.no_llm

    print("=" * 60)
    print("  CORPUS VALIDATION TEST")
    print("=" * 60)
    print(f"  LLM enabled : {run_llm}")
    print(f"  Max/category: {args.limit}")
    print()

    # ── Load all corpora ──
    all_cases = []
    all_results_by_source = {}

    # 1. Synthetic (always)
    print("Loading synthetic corpus...")
    synthetic = load_synthetic()
    all_cases.extend(synthetic)

    if not args.skip_download:
        # 2. SpamAssassin ham
        print("\nLoading SpamAssassin ham...")
        sa_ham = load_spamassassin("ham", limit=args.limit)
        all_cases.extend(sa_ham)

        # 3. SpamAssassin spam
        print("\nLoading SpamAssassin spam...")
        sa_spam = load_spamassassin("spam", limit=args.limit)
        all_cases.extend(sa_spam)

        # 4. Nazario phishing
        print("\nLoading Nazario phishing corpus...")
        nazario = load_nazario(limit=args.limit)
        all_cases.extend(nazario)

    print(f"\n{'='*60}")
    print(f"  TOTAL CORPUS: {len(all_cases)} emails")
    sources = Counter(c["source"] for c in all_cases)
    for src, count in sources.items():
        expected_dist = Counter(c["expected"] for c in all_cases if c["source"] == src)
        print(f"    {src}: {count} ({', '.join(f'{k}={v}' for k,v in expected_dist.items())})")
    print(f"{'='*60}\n")

    # ── Run pipeline ──
    print("Running pipeline...")
    results = run_corpus(all_cases, run_llm=run_llm)

    # ── Per-source reports ──
    for source in sources:
        source_results = [r for r in results if r["source"] == source]
        m = print_report(source_results, f"Results: {source}")
        all_results_by_source[source] = {
            "metrics": m,
            "count": len(source_results),
            "correct": sum(r["correct"] for r in source_results),
        }

    # ── Overall report ──
    overall_metrics = print_report(results, "OVERALL RESULTS")

    # ── Save results ──
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = {
        "timestamp": ts,
        "config": {"llm_enabled": run_llm, "limit_per_category": args.limit},
        "corpus_summary": {src: {"count": c, "expected": dict(Counter(
            case["expected"] for case in all_cases if case["source"] == src
        ))} for src, c in sources.items()},
        "overall_metrics": {k: v for k, v in overall_metrics.items() if k != "classification_report"},
        "per_source": {src: d["metrics"]["accuracy"] for src, d in all_results_by_source.items()},
        "per_email": [{k: v for k, v in r.items() if k != "stages"} for r in results],
        "misclassified": [r["name"] for r in results if not r["correct"]],
    }
    out_path = RESULTS_DIR / f"corpus_validation_{ts}.json"
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"\n  Results saved: {out_path}")


if __name__ == "__main__":
    main()
