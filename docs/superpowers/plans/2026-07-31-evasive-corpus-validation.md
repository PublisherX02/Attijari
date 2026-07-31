# Evasive-Corpus Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate the 2026-07-31 evasion-hardening code (`extraction.py`'s encryption detection/OneNote/recursive-archive-YARA, `cape_client.py`'s anti-analysis signature override) against real evasive malware samples, producing detection-rate/precision/recall/F1 statistics grouped by evasion technique.

**Architecture:** A new `malwarebazaar_client.py` (fail-safe REST wrapper, matching `cape_client.py`'s style) downloads tag-filtered, password-protected sample zips. A new `evasive_corpus_test.py` orchestrator (sibling to `epvme_test.py`) wraps each still-encrypted zip as a synthetic `.eml` attachment and runs it through the existing, unmodified `accuracy.run_pipeline_isolated()` — decryption, YARA, and CAPE detonation all happen exactly where they would for a real attachment, inside the already-sandboxed extraction containers and the existing CAPE VM. A manual runbook documents the separate raw-binary track (InQuest/RawMal-TF), run entirely on the CAPE VM, never on this dev machine.

**Tech Stack:** Python 3.12, `requests` (already a dependency), `pytest` + `unittest.mock.monkeypatch` for tests, the existing `accuracy.py`/`secrets_client.py`/`cape_client.py` modules (unmodified).

## Global Constraints

- Zero risk to this Windows dev machine: no live/raw malware binary is ever decrypted or executed on its bare filesystem outside a sandboxed container. (spec, "Guiding constraint")
- MalwareBazaar samples stay ZIP-encrypted (password `infected`) until decrypted by the existing sandboxed extraction path — `malwarebazaar_client.py` itself must never call `zipfile`/extract. (spec, Component 1 + Testing)
- No production code path (`extraction.py`, `cape_client.py`, `detonation_config.py`) is modified by this work — only new files plus two additive lines in `migrate_env_to_vault.py`'s config dict and `.env.example`. (spec, "Data flow & error handling")
- `evasive_corpus_test.py` and the CAPE-VM runbook are exercised manually, not part of the blocking `pytest` suite — same convention as `epvme_test.py`. (spec, Testing)
- Any failure (API down, corrupt download, CAPE unreachable) marks that sample `"error"`, never silently skipped, never counted as `"detected"`. (spec, "Data flow & error handling")

---

### Task 1: MalwareBazaar API key wiring (Vault config)

**Files:**
- Modify: `scripts/migrate_env_to_vault.py:31-37` (`_GROUPS["threat_intel"]` dict)
- Modify: `.env.example` (document the new key)
- Test: none (this task only adds a dict entry and a doc line; `secrets_client.get_api_key()` already reads arbitrary keys from the `threat_intel` group with no code change needed — see Task 2's `get_api_key("malwarebazaar")` call)

**Interfaces:**
- Produces: `secrets_client.get_api_key("malwarebazaar")` returns a non-empty string once `MALWAREBAZAAR_API_KEY` is set in `.env` and migrated, or `""` if unset — this is `get_api_key()`'s existing, unmodified behavior (`src/secrets_client.py:88-90`), consumed by Task 2.

- [ ] **Step 1: Add the new key to the migration script's group dict**

In `scripts/migrate_env_to_vault.py`, change:

```python
    "threat_intel": {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "threatfox": "THREATFOX_AUTH_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "otx": "OTX_API_KEY",
        "dnstwist": "DNSTWIST_API_KEY",
    },
```

to:

```python
    "threat_intel": {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "threatfox": "THREATFOX_AUTH_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "otx": "OTX_API_KEY",
        "dnstwist": "DNSTWIST_API_KEY",
        "malwarebazaar": "MALWAREBAZAAR_API_KEY",
    },
```

- [ ] **Step 2: Document the new env var in `.env.example`**

Find the threat-intel section of `.env.example` (look for `VIRUSTOTAL_API_KEY`/`THREATFOX_AUTH_KEY` — these now live in Vault per the 2026-07-30 secrets-manager migration, so `.env.example` only has a comment pointing at Vault, not real values). Add one line to that same comment block:

```
# MALWAREBAZAAR_API_KEY (abuse.ch Auth-Key, free registration at
# https://bazaar.abuse.ch/account/) now lives in Vault (secret/attijari/threat_intel),
# same as the other threat-intel keys above.
```

- [ ] **Step 3: Verify the dict change doesn't break the existing migration script**

Run: `python -c "import sys; sys.path.insert(0,'scripts'); sys.path.insert(0,'src'); import ast; ast.parse(open('scripts/migrate_env_to_vault.py').read())"`
Expected: no output (valid syntax). This is a config-only change with no test file — the real verification is Task 2's tests exercising `get_api_key("malwarebazaar")` end-to-end via the existing (already-tested) `secrets_client` machinery.

- [ ] **Step 4: Commit**

```bash
git add scripts/migrate_env_to_vault.py .env.example
git commit -m "feat: add MalwareBazaar API key to Vault threat_intel group"
```

---

### Task 2: `malwarebazaar_client.py` — fail-safe REST wrapper

**Files:**
- Create: `src/malwarebazaar_client.py`
- Test: `tests/test_malwarebazaar_client.py`

**Interfaces:**
- Consumes: `secrets_client.get_api_key("malwarebazaar")` (existing, from Task 1's config change — no code change to `secrets_client.py` itself).
- Produces: `malwarebazaar_client.query_by_tag(tag: str, limit: int = 50) -> list[dict]`, `malwarebazaar_client.download_sample(sha256: str, dest_dir: Path) -> Path | None`, both consumed by Task 3's `evasive_corpus_test.py`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_malwarebazaar_client.py`:

```python
"""test_malwarebazaar_client.py — MalwareBazaar API client. Samples must
stay ZIP-encrypted (password 'infected') until the existing sandboxed
extraction path decrypts them — this client must never call zipfile or
extract anything itself."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", content_type="application/json"):
        self.status_code = status_code
        self._json = json_data
        self.content = content
        self.headers = {"content-type": content_type}

    def json(self):
        return self._json


def test_query_by_tag_returns_data_on_success(monkeypatch):
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "test-key")
    fake = _FakeResponse(json_data={
        "query_status": "ok",
        "data": [{"sha256_hash": "a" * 64, "file_name": "invoice.one", "tags": ["onenote"]}],
    })
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        return fake

    monkeypatch.setattr(mb.requests, "post", fake_post)
    result = mb.query_by_tag("onenote", limit=10)
    assert result == [{"sha256_hash": "a" * 64, "file_name": "invoice.one", "tags": ["onenote"]}]
    assert captured["data"]["query"] == "get_taginfo"
    assert captured["data"]["tag"] == "onenote"
    assert captured["data"]["limit"] == "10"
    assert captured["headers"]["Auth-Key"] == "test-key"


def test_query_by_tag_returns_empty_list_on_no_results(monkeypatch):
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "test-key")
    fake = _FakeResponse(json_data={"query_status": "no_results"})
    monkeypatch.setattr(mb.requests, "post", lambda *a, **k: fake)
    assert mb.query_by_tag("nonexistent_tag") == []


def test_query_by_tag_returns_empty_list_on_missing_api_key(monkeypatch):
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "")

    def fail_post(*a, **k):
        raise AssertionError("must not call the API with no key")

    monkeypatch.setattr(mb.requests, "post", fail_post)
    assert mb.query_by_tag("onenote") == []


def test_query_by_tag_returns_empty_list_on_network_error(monkeypatch):
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "test-key")

    def raise_post(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr(mb.requests, "post", raise_post)
    assert mb.query_by_tag("onenote") == []


def test_download_sample_saves_encrypted_bytes_untouched(monkeypatch, tmp_path):
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "test-key")
    fake_zip_bytes = b"PK\x03\x04fake-encrypted-zip-bytes"
    fake = _FakeResponse(content=fake_zip_bytes, content_type="application/zip")
    monkeypatch.setattr(mb.requests, "post", lambda *a, **k: fake)

    result = mb.download_sample("b" * 64, tmp_path)
    assert result == tmp_path / f"{'b' * 64}.zip"
    assert result.read_bytes() == fake_zip_bytes


def test_download_sample_returns_none_on_json_error_body(monkeypatch, tmp_path):
    """Confirmed pattern (same as cape_client.fetch_task_mitmdump): a 200
    response with a JSON error body must not be saved as if it were the
    file — this is the exact bug class that bit fetch_task_mitmdump."""
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "test-key")
    fake = _FakeResponse(
        json_data={"query_status": "file_not_found"},
        content=b'{"query_status": "file_not_found"}',
        content_type="application/json",
    )
    monkeypatch.setattr(mb.requests, "post", lambda *a, **k: fake)
    result = mb.download_sample("c" * 64, tmp_path)
    assert result is None
    assert not (tmp_path / f"{'c' * 64}.zip").exists()


def test_download_sample_returns_none_on_network_error(monkeypatch, tmp_path):
    import malwarebazaar_client as mb
    monkeypatch.setattr(mb, "_api_key", lambda: "test-key")

    def raise_post(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr(mb.requests, "post", raise_post)
    assert mb.download_sample("d" * 64, tmp_path) is None


def test_module_never_imports_zipfile():
    """Structural safety check: this client must never decompress a
    downloaded sample — decryption/extraction happens only inside the
    existing sandboxed extraction path (extraction.py's Docker containers),
    never in this thin API-wrapper module."""
    source = Path(__file__).parent.parent.joinpath("src", "malwarebazaar_client.py").read_text()
    assert "zipfile" not in source
    assert "extractall" not in source
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_malwarebazaar_client.py -v`
Expected: all 8 tests FAIL with `ModuleNotFoundError: No module named 'malwarebazaar_client'`.

- [ ] **Step 3: Write `src/malwarebazaar_client.py`**

```python
"""malwarebazaar_client.py — Thin REST client for the MalwareBazaar API
(abuse.ch). Used only by the evasive-corpus validation harness
(evasive_corpus_test.py), never by the production pipeline.

Samples are returned/saved EXACTLY as MalwareBazaar serves them: ZIP
archives AES-128-encrypted with the industry-standard password "infected"
(inert until deliberately decrypted). This module MUST NEVER extract or
decrypt a downloaded sample — that happens only inside the existing
sandboxed extraction path (extraction.py's network-disabled Docker
containers), matching CLAUDE.md's "zero risk to the host machine"
constraint for this validation work.

Fail-safe: any error (missing API key, network failure, malformed
response) returns an empty result ([] or None) rather than raising — this
is a test-harness convenience client, not a security-critical path, so
callers always get a safe, checkable "nothing here" rather than a crash.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import requests

_API_URL = "https://mb-api.abuse.ch/api/v1/"
_HTTP_TIMEOUT = 30


def _api_key() -> str:
    from secrets_client import get_api_key
    return get_api_key("malwarebazaar")


def query_by_tag(tag: str, limit: int = 50) -> list[dict]:
    """Return sample metadata dicts tagged with `tag` (e.g. "onenote",
    "html-smuggling", "encrypted-zip", "iso", "lnk"), most recent first.
    Returns [] on any failure — no API key configured, network error,
    malformed response, or MalwareBazaar reporting no results."""
    key = _api_key()
    if not key:
        return []
    try:
        r = requests.post(
            _API_URL,
            data={"query": "get_taginfo", "tag": tag, "limit": str(limit)},
            headers={"Auth-Key": key},
            timeout=_HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            return []
        payload = r.json()
        if payload.get("query_status") != "ok":
            return []
        data = payload.get("data")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def download_sample(sha256: str, dest_dir: Path) -> Optional[Path]:
    """Download the still-password-protected zip for `sha256` into
    `dest_dir/<sha256>.zip`, untouched. Returns the saved path, or None on
    any failure (missing key, network error, or MalwareBazaar returning a
    200 + JSON error body instead of the file — same defensive pattern as
    cape_client.fetch_task_mitmdump, which was bitten by exactly this
    shape of response for a different CAPE endpoint)."""
    key = _api_key()
    if not key:
        return None
    try:
        r = requests.post(
            _API_URL,
            data={"query": "get_file", "sha256_hash": sha256},
            headers={"Auth-Key": key},
            timeout=_HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            return None
        ctype = r.headers.get("content-type", "")
        if ctype.split(";")[0].strip().lower() == "application/json":
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_path = dest_dir / f"{sha256}.zip"
        out_path.write_bytes(r.content)
        return out_path
    except Exception:
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_malwarebazaar_client.py -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Run the full existing suite to check for regressions**

Run: `pytest tests/ -q`
Expected: previous passing count (306 passed, 1 skipped as of the last full run) plus these 8 new tests, no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/malwarebazaar_client.py tests/test_malwarebazaar_client.py
git commit -m "feat: add MalwareBazaar API client for evasive-corpus sample acquisition"
```

---

### Task 3: `evasive_corpus_test.py` — pipeline validation orchestrator

**Files:**
- Create: `src/evasive_corpus_test.py`
- Test: none new (this is a manual-run script, same convention as `epvme_test.py` — see "Global Constraints"). Verified by Step 4's manual smoke run against a single real tag, not automated pytest.

**Interfaces:**
- Consumes: `malwarebazaar_client.query_by_tag(tag, limit)` / `malwarebazaar_client.download_sample(sha256, dest_dir)` (Task 2), `accuracy._make_eml(from_addr, to_addr, subject, body, attachments, extra_headers, auth_pass)`, `accuracy.build_benign_cases() -> list[dict]`, `accuracy.run_pipeline_isolated(raw_eml, run_llm, enable_detonation, db)`, `accuracy.classify_result(result) -> str`, `accuracy.compute_metrics(y_true, y_pred) -> dict`, `accuracy.plot_confusion_matrix(cm, output_path)`, `accuracy.plot_metrics_bar(metrics, output_path)` — all existing, unmodified (confirmed signatures in `src/accuracy.py:65-73`, `2533-2534`, `3600-3601`, `3817-3818`, `3827-3828`, `3840`, `3871`). Detonation-drain pattern (`count_queued_detonations`, `PendingDetonation`, `detonation.process_detonation_queue()`) mirrors `epvme_test.py:224-284` exactly — same existing, unmodified functions.
- Produces: `data/evasive_corpus_results/evasive_corpus_report.json` with a `per_technique_breakdown` key (dict of tag -> `{"total": int, "caught": int, "detection_rate": float}`) and, per malicious sample, a `family` field (MalwareBazaar's `signature` metadata field, best-effort, empty string if absent) and a `suspicious_behaviors` field (CAPE's signature-name list when detonation ran) — both consumed by Task 4's Avast-CTU cross-check, which modifies this file's main loop to add the cross-check call.

- [ ] **Step 1: Write `src/evasive_corpus_test.py`**

```python
"""evasive_corpus_test.py — Validate the pipeline's evasion-hardening
logic (encrypted-attachment detection, OneNote escalation, recursive
archive scanning, CAPE anti-sandbox signature override) against real
MalwareBazaar samples, tagged by evasion technique.

Samples stay ZIP-encrypted (password "infected") until the existing
sandboxed extraction path decrypts them — this script never calls
zipfile/extracts anything itself, matching malwarebazaar_client.py's
same constraint. The password is passed only as simulated email body
text, exercising the exact same encrypted-attachment-plus-password-in-body
detection path (extraction.py's _detect_encryption() /
encrypted_with_password_in_body flag) a real attack would trigger.

A benign case mix (accuracy.build_benign_cases(), same set epvme_test.py
uses) is included by default so precision/F1/accuracy are computed against
real negatives — without it every y_true label is "malicious" and
precision/F1 would be trivially meaningless. Use --no-benign to skip this
and get MalwareBazaar-only recall (matches epvme_test.py's own convention).

Usage:
    python src/evasive_corpus_test.py --tags onenote,html-smuggling,encrypted-zip,iso,lnk --limit-per-tag 40
    python src/evasive_corpus_test.py --tags onenote --limit-per-tag 10 --no-detonation
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_SRC.parent / ".env")

import malwarebazaar_client as mb
from accuracy import (
    _make_eml, build_benign_cases, run_pipeline_isolated, classify_result,
    compute_metrics, plot_confusion_matrix, plot_metrics_bar,
)

_OUT_DIR = _SRC.parent / "data" / "evasive_corpus_results"
_OUT_DIR.mkdir(parents=True, exist_ok=True)
_SAMPLES_DIR = _SRC.parent / "data" / "evasive_corpus" / "malwarebazaar"


def _wrap_as_eml(filename: str, zip_bytes: bytes) -> bytes:
    """Wrap a still-encrypted MalwareBazaar sample as a synthetic phishing
    email, with the zip's password in the body — exactly the pattern
    CLAUDE.md rule 8 (encrypted attachment + password in body = automatic
    escalate) is designed to catch."""
    return _make_eml(
        from_addr="invoice@vendor-billing.example",
        to_addr="test@attijari.test",
        subject=f"Secure document: {filename}",
        body=(
            "Please find the attached secure document.\n\n"
            "The archive is password-protected for your security.\n"
            "Password: infected\n"
        ),
        attachments=[(filename, zip_bytes, "application/zip")],
    )


def _acquire_samples(tags: list[str], limit_per_tag: int) -> list[dict]:
    """Returns list of {"tag", "filename", "sha256", "family", "zip_path"}
    for successfully downloaded samples. `family` is MalwareBazaar's
    "signature" metadata field (its own vendor-detection name), best-effort
    — empty string if MalwareBazaar didn't provide one for this sample.
    Any query/download failure for a given sample is skipped here (logged,
    not silent) and simply never appears in the returned list, so it can
    never be counted as caught."""
    acquired = []
    for tag in tags:
        metas = mb.query_by_tag(tag, limit=limit_per_tag)
        print(f"[ACQUIRE] tag={tag!r}: {len(metas)} sample(s) found")
        for meta in metas:
            sha256 = meta.get("sha256_hash")
            filename = meta.get("file_name") or f"{sha256}.bin"
            if not sha256:
                continue
            zip_path = mb.download_sample(sha256, _SAMPLES_DIR)
            if zip_path is None:
                print(f"  [SKIP] {filename} ({sha256[:12]}...) — download failed")
                continue
            acquired.append({
                "tag": tag, "filename": filename, "sha256": sha256,
                "family": meta.get("signature") or "", "zip_path": zip_path,
            })
    return acquired


def main():
    parser = argparse.ArgumentParser(description="Evasive-corpus pipeline validation")
    parser.add_argument("--tags", type=str, required=True,
                         help="Comma-separated MalwareBazaar tags, e.g. "
                              "onenote,html-smuggling,encrypted-zip,iso,lnk")
    parser.add_argument("--limit-per-tag", type=int, default=40,
                         help="Max samples to pull per tag")
    parser.add_argument("--no-detonation", action="store_true",
                         help="Skip CAPE detonation (static analysis only, "
                              "for a fast pass without a reachable CAPE VM)")
    parser.add_argument("--no-benign", action="store_true",
                         help="Skip the benign case mix — MalwareBazaar-only "
                              "recall, no true precision/F1 (matches "
                              "epvme_test.py's --no-benign convention)")
    args = parser.parse_args()

    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    run_detonation = not args.no_detonation
    run_benign = not args.no_benign

    print("=" * 60)
    print("  ATTIJARI — Evasive Corpus Validation (MalwareBazaar)")
    print("=" * 60)
    print(f"  Tags:         {', '.join(tags)}")
    print(f"  Limit/tag:    {args.limit_per_tag}")
    print(f"  Detonation:   {'ON' if run_detonation else 'OFF (static analysis only)'}")
    print(f"  Benign mix:   {'ON (for precision/F1)' if run_benign else 'OFF (recall only)'}")
    print()

    db = None
    if run_detonation:
        from database import SessionLocal
        db = SessionLocal()

    samples = _acquire_samples(tags, args.limit_per_tag)
    n_malicious = len(samples)
    print(f"\n[LOADED] {n_malicious} sample(s) acquired across {len(tags)} tag(s)")

    cases: list[tuple[str, dict | None, bytes]] = [
        ("malicious", s, _wrap_as_eml(s["filename"], s["zip_path"].read_bytes()))
        for s in samples
    ]
    if run_benign:
        benign_cases = build_benign_cases()
        cases += [("benign", None, c["eml"]) for c in benign_cases]
        print(f"[LOADED] {len(benign_cases)} benign .eml cases mixed in for precision/F1")
    print()

    results = []
    per_tag: dict[str, dict[str, int]] = {t: {"total": 0, "caught": 0} for t in tags}
    sha_to_result_index: dict[str, int] = {}
    total_cases = len(cases)

    for i, (expected, sample, raw_eml) in enumerate(cases, 1):
        label = sample["filename"][:40] if sample else "(benign case)"
        print(f"[{i:3d}/{total_cases}] {expected}: {label}...")

        t0 = time.time()
        try:
            result = run_pipeline_isolated(raw_eml, run_llm=True,
                                            enable_detonation=run_detonation, db=db)
        except Exception as e:
            result = {"final_status": "error", "stages": {"error": str(e)},
                      "deterministic_escalation": False, "detonation_queued": []}
        elapsed = time.time() - t0

        predicted = classify_result(result) if result["final_status"] != "error" else "error"
        queued_shas = result.get("detonation_queued", [])

        if sample is not None:
            per_tag[sample["tag"]]["total"] += 1
            if predicted == "malicious":
                per_tag[sample["tag"]]["caught"] += 1

        results.append({
            "tag": sample["tag"] if sample else None,
            "filename": sample["filename"] if sample else label,
            "sha256": sample["sha256"] if sample else None,
            "family": sample["family"] if sample else None,
            "expected": expected,
            "predicted": predicted,
            "final_status": result["final_status"],
            "elapsed": elapsed,
            "suspicious_behaviors": [],
        })
        for sha in queued_shas:
            sha_to_result_index[sha] = len(results) - 1

    # --- Detonation drain (mirrors epvme_test.py's pattern exactly) ---
    if run_detonation and sha_to_result_index:
        from database import count_queued_detonations, PendingDetonation
        import detonation as detonation_mod

        n_queued = count_queued_detonations(db)
        print(f"\n[DETONATION] {n_queued} sample(s) queued from this run — draining...")
        guard = 0
        while count_queued_detonations(db) > 0 and guard < 200:
            summary = detonation_mod.process_detonation_queue()
            if summary.get("status") in ("empty", "cape_unavailable"):
                break
            guard += 1

        for sha, idx in sha_to_result_index.items():
            row = db.query(PendingDetonation).filter(PendingDetonation.sha256 == sha).first()
            if not row or not row.result:
                continue
            results[idx]["suspicious_behaviors"] = row.result.get("suspicious_behaviors", [])
            if row.result.get("escalate") and results[idx]["predicted"] != "malicious":
                results[idx]["predicted"] = "malicious"
                results[idx]["final_status"] = "escalated"
                tag = results[idx]["tag"]
                if tag:
                    per_tag[tag]["caught"] += 1
        db.close()

    y_true = [r["expected"] for r in results if r["predicted"] != "error"]
    y_pred = [r["predicted"] for r in results if r["predicted"] != "error"]
    metrics = compute_metrics(y_true, y_pred) if y_true else None
    per_technique_breakdown = {
        tag: {
            "total": stats["total"],
            "caught": stats["caught"],
            "detection_rate": (stats["caught"] / stats["total"]) if stats["total"] else 0.0,
        }
        for tag, stats in per_tag.items()
    }

    report = {
        "config": {"tags": tags, "limit_per_tag": args.limit_per_tag,
                    "detonation": run_detonation, "benign_mix": run_benign},
        "summary": {"total_malicious": n_malicious,
                    "errors": sum(1 for r in results if r["predicted"] == "error")},
        "metrics": metrics,
        "per_technique_breakdown": per_technique_breakdown,
        "results": results,
    }
    (_OUT_DIR / "evasive_corpus_report.json").write_text(json.dumps(report, indent=2))
    print(f"\n[SAVED] {_OUT_DIR / 'evasive_corpus_report.json'}")

    if metrics:
        plot_metrics_bar(metrics, _OUT_DIR / "evasive_corpus_metrics_bar.png")
        plot_confusion_matrix(metrics["confusion_matrix"], _OUT_DIR / "evasive_corpus_confusion_matrix.png")

    print("\n" + "=" * 60)
    print("  Per-technique detection rate:")
    for tag, stats in per_technique_breakdown.items():
        print(f"    {tag:20s} {stats['caught']:3d}/{stats['total']:3d}  ({stats['detection_rate']:.1%})")
    print("=" * 60)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify the script imports cleanly**

Run: `python -c "import sys; sys.path.insert(0, 'src'); import evasive_corpus_test"`
Expected: no output, no `ImportError` (confirms `_make_eml`, `build_benign_cases`, `run_pipeline_isolated`, `classify_result`, `compute_metrics`, `plot_confusion_matrix`, `plot_metrics_bar` all resolve from `accuracy.py`, and `malwarebazaar_client` resolves from Task 2).

- [ ] **Step 3: Verify `--help` works (argparse wiring)**

Run: `python src/evasive_corpus_test.py --help`
Expected: usage text listing `--tags`, `--limit-per-tag`, `--no-detonation`, `--no-benign`, no traceback.

- [ ] **Step 4: Manual smoke run against a single real tag (requires `MALWAREBAZAAR_API_KEY` set)**

Run: `python src/evasive_corpus_test.py --tags onenote --limit-per-tag 3 --no-detonation`
Expected: prints `[ACQUIRE] tag='onenote': N sample(s) found` with N > 0 (confirms the assumed MalwareBazaar `get_taginfo`/`get_file` request/response shapes from Task 2 are actually correct against the live API — if this step shows 0 samples or an error, stop and check the response shape against MalwareBazaar's current API docs before proceeding, per this project's established practice of confirming against the real instance rather than guessing), then processes each through the pipeline plus the default benign mix, and writes `data/evasive_corpus_results/evasive_corpus_report.json` with a non-empty `per_technique_breakdown.onenote` entry and a non-null `metrics` block.

- [ ] **Step 5: Run the full existing suite to confirm zero regressions**

Run: `pytest tests/ -q`
Expected: same passing count as after Task 2 (this task adds no new automated tests, only a manually-run script — matching `epvme_test.py`'s existing convention).

- [ ] **Step 6: Commit**

```bash
git add src/evasive_corpus_test.py
git commit -m "feat: add evasive-corpus pipeline validation harness (MalwareBazaar track)"
```

---

### Task 4: Avast-CTU cross-check (informational, non-blocking)

**Files:**
- Create: `src/avast_ctu_crosscheck.py`
- Modify: `src/evasive_corpus_test.py` (add `--avast-ctu-dir` CLI arg and wire the cross-check call after the detonation-drain step)
- Test: `tests/test_avast_ctu_crosscheck.py`

**Interfaces:**
- Consumes: each malicious result's `family` and `suspicious_behaviors` fields (produced by Task 3's main loop/drain step).
- Produces: `avast_ctu_crosscheck.find_reference_report(family: str, avast_ctu_dir: Path) -> dict | None`, `avast_ctu_crosscheck.crosscheck_signatures(own_signatures: list[str], reference_report: dict) -> dict` — both consumed only by `evasive_corpus_test.py`'s main loop.

**Note:** the Avast-CTU Public CAPE Dataset itself (13GB of JSON reports) is not downloaded by any code in this plan — that's a manual, one-time step for the user (same reasoning as RawMal-TF's manual access request in Task 5), since automating a 13GB fetch is out of scope here. This task only builds the code that reads whatever local directory of already-downloaded reports the user points it at via `--avast-ctu-dir`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_avast_ctu_crosscheck.py`:

```python
"""test_avast_ctu_crosscheck.py — best-effort comparison between this
project's own CAPE signatures and the Avast-CTU Public CAPE Dataset's
reference reports for the same malware family. Informational only."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import avast_ctu_crosscheck as crosscheck


def test_find_reference_report_matches_by_filename(tmp_path):
    report = {"family": "Emotet", "signatures": [{"name": "antisandbox_sleep"}]}
    (tmp_path / "emotet_report_001.json").write_text(json.dumps(report))
    result = crosscheck.find_reference_report("Emotet", tmp_path)
    assert result == report


def test_find_reference_report_matches_by_family_field(tmp_path):
    report = {"family": "Qakbot", "signatures": []}
    (tmp_path / "sample_042.json").write_text(json.dumps(report))
    result = crosscheck.find_reference_report("qakbot", tmp_path)
    assert result == report


def test_find_reference_report_none_when_no_match(tmp_path):
    (tmp_path / "unrelated.json").write_text(json.dumps({"family": "Trickbot"}))
    assert crosscheck.find_reference_report("Emotet", tmp_path) is None


def test_find_reference_report_none_when_dir_missing(tmp_path):
    assert crosscheck.find_reference_report("Emotet", tmp_path / "does-not-exist") is None


def test_find_reference_report_none_when_family_empty(tmp_path):
    (tmp_path / "emotet.json").write_text(json.dumps({"family": "Emotet"}))
    assert crosscheck.find_reference_report("", tmp_path) is None


def test_find_reference_report_skips_malformed_json(tmp_path):
    (tmp_path / "broken.json").write_text("{not valid json")
    (tmp_path / "emotet_good.json").write_text(json.dumps({"family": "Emotet"}))
    result = crosscheck.find_reference_report("Emotet", tmp_path)
    assert result == {"family": "Emotet"}


def test_crosscheck_signatures_identifies_reference_only_signatures():
    own = ["network_http", "persistence"]
    reference = {"signatures": [
        {"name": "network_http"}, {"name": "antisandbox_sleep"},
    ]}
    result = crosscheck.crosscheck_signatures(own, reference)
    assert result["shared"] == ["network_http"]
    assert result["reference_only"] == ["antisandbox_sleep"]
    assert result["own_only"] == ["persistence"]


def test_crosscheck_signatures_handles_empty_own_list():
    result = crosscheck.crosscheck_signatures([], {"signatures": [{"name": "x"}]})
    assert result["own_only"] == []
    assert result["reference_only"] == ["x"]
    assert result["shared"] == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_avast_ctu_crosscheck.py -v`
Expected: all 8 tests FAIL with `ModuleNotFoundError: No module named 'avast_ctu_crosscheck'`.

- [ ] **Step 3: Write `src/avast_ctu_crosscheck.py`**

```python
"""avast_ctu_crosscheck.py — Best-effort comparison between this project's
own CAPE detonation signatures and the Avast-CTU Public CAPE Dataset's
reference reports for the same malware family.

Informational only: never affects a verdict, only surfaces a gap ("CAPE
caught fewer/different anti-analysis signatures than a reference sandbox
did for the same family") for a human to review in the report.

The Avast-CTU dataset itself (13GB of JSON reports) is not downloaded by
this module — that is a manual, one-time step (see the design spec) since
its size makes it unsuitable for automated per-run fetching. This module
only reads whatever local directory of already-downloaded reports the
caller points it at via `avast_ctu_dir`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def find_reference_report(family: str, avast_ctu_dir: Path) -> Optional[dict]:
    """Best-effort lookup: return the first Avast-CTU JSON report whose
    filename or top-level "family" field matches `family` (case-insensitive
    substring match). Returns None if `family` is empty, the directory
    doesn't exist, or nothing matches — never raises."""
    if not family or not avast_ctu_dir.is_dir():
        return None
    family_lower = family.lower()
    for path in sorted(avast_ctu_dir.glob("*.json")):
        if family_lower in path.stem.lower():
            try:
                return json.loads(path.read_text())
            except Exception:
                continue
    for path in sorted(avast_ctu_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        val = data.get("family")
        if isinstance(val, str) and family_lower in val.lower():
            return data
    return None


def crosscheck_signatures(own_signatures: list[str], reference_report: dict) -> dict:
    """Diff this run's CAPE signature names against the reference report's
    signature names. `reference_only` is the interesting case: something a
    reference sandbox caught for this family that our own CAPE run
    didn't."""
    ref_sigs = reference_report.get("signatures", [])
    ref_names = {
        (s.get("name") or "").lower()
        for s in ref_sigs if isinstance(s, dict) and s.get("name")
    }
    own_names = {s.lower() for s in own_signatures if s}
    return {
        "own_only": sorted(own_names - ref_names),
        "reference_only": sorted(ref_names - own_names),
        "shared": sorted(own_names & ref_names),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_avast_ctu_crosscheck.py -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Wire the cross-check into `evasive_corpus_test.py`**

In `src/evasive_corpus_test.py`, add the import near the top (alongside the existing `import malwarebazaar_client as mb` line):

```python
import avast_ctu_crosscheck
```

Add the CLI arg, alongside the existing `--no-benign` argument:

```python
    parser.add_argument("--avast-ctu-dir", type=str, default=None,
                         help="Local directory of pre-downloaded Avast-CTU "
                              "JSON reports for cross-checking CAPE "
                              "signatures by malware family (optional, "
                              "informational only)")
```

After the detonation-drain block (right before the `y_true = [...]` line), add:

```python
    if args.avast_ctu_dir:
        avast_ctu_dir = Path(args.avast_ctu_dir)
        for r in results:
            if not r.get("family") or not r.get("suspicious_behaviors"):
                continue
            ref = avast_ctu_crosscheck.find_reference_report(r["family"], avast_ctu_dir)
            if ref is not None:
                r["avast_ctu_crosscheck"] = avast_ctu_crosscheck.crosscheck_signatures(
                    r["suspicious_behaviors"], ref
                )
```

- [ ] **Step 6: Run the full existing suite to confirm zero regressions**

Run: `pytest tests/ -q`
Expected: previous passing count plus these 8 new tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add src/avast_ctu_crosscheck.py src/evasive_corpus_test.py tests/test_avast_ctu_crosscheck.py
git commit -m "feat: add Avast-CTU signature cross-check to evasive-corpus harness"
```

---

### Task 5: Manual runbook for the raw-binary track (InQuest / RawMal-TF)

**Files:**
- Create: `docs/evasive-corpus-runbook.md`

**Interfaces:** None — this is a documentation-only task, no code.

- [ ] **Step 1: Write the runbook**

Create `docs/evasive-corpus-runbook.md`:

```markdown
# Evasive-Corpus Runbook — Raw Binary Track (InQuest / RawMal-TF)

**Read this before doing anything below:** InQuest/malware-samples and
RawMal-TF ship raw, unprotected, live malware binaries — not password-zipped
like MalwareBazaar. Every step in this runbook happens on the CAPE VM
(Hyper-V name `moham`, `192.168.100.10`), never on the analyst's Windows
dev machine, per this project's zero-host-risk constraint. If you find
yourself about to `git clone` either repo on your own laptop — stop.

## 1. Connect to the CAPE VM

```bash
ssh <your-user>@192.168.100.10
```

(Console access via Hyper-V Manager also works if SSH isn't configured.)

## 2. Clone the sample repositories — on the VM only

```bash
mkdir -p ~/evasive-corpus-raw && cd ~/evasive-corpus-raw
git clone https://github.com/InQuest/malware-samples.git
# RawMal-TF requires a manual access request per its README — the binaries
# aren't in the git repo itself, only metadata/instructions for requesting
# the dataset. Follow https://github.com/CS-and-AI/RawMal-TF's request
# process from this VM's browser/session, not your own machine.
```

## 3. Submit each sample to CAPE's own local submission tooling

CAPE ships its own submission CLI on the box it's installed on (distinct
from this repo's `cape_client.py`, which talks to CAPE over the network —
here we're already on the box, so use CAPE's local tooling directly, e.g.
`cape-submit` or the equivalent script from your CAPE install; consult
your CAPE install's own docs for the exact command, since this varies by
CAPE version and was not part of this repo's automation).

## 4. Export the resulting JSON reports back to the dev machine

Reports come back over the *existing* CAPE REST API path — the same one
`cape_client.fetch_report()` already uses for production detonation, no
new transfer mechanism:

```bash
# From the dev machine, once you have a task_id from step 3:
python -c "
import sys; sys.path.insert(0, 'src')
import cape_client
report = cape_client.fetch_report(<task_id>)
import json
print(json.dumps(report, indent=2))
" > data/evasive_corpus_results/raw_binary_task_<task_id>.json
```

## 5. Score manually

Compare each report's verdict against RawMal-TF's ground-truth
type/family label (from its accompanying metadata) or InQuest's own
documented classification for that sample. This track is not folded into
`evasive_corpus_report.json`'s automated metrics in this pass — record
findings directly in a session note or the CLAUDE.md build log, same as
other manual validation work in this project.

**The raw binaries themselves stay on the CAPE VM.** Do not copy them to
the dev machine at any point in this process.
```

- [ ] **Step 2: Verify the markdown is valid**

Run: `python -c "print(open('docs/evasive-corpus-runbook.md').read()[:50])"`
Expected: prints the file's first 50 characters with no error (file exists and is readable).

- [ ] **Step 3: Commit**

```bash
git add -f docs/evasive-corpus-runbook.md
git commit -m "docs: add manual runbook for InQuest/RawMal-TF raw-binary sample track"
```

(Note the `-f`: this repo's `docs/` directory is gitignored broadly, but
individual spec/plan/runbook files are force-added — same pattern already
used for every file under `docs/superpowers/`.)

---

### Task 6: CLAUDE.md build log entry

**Files:**
- Modify: `CLAUDE.md` (gitignored, no commit — matches the existing convention documented at the end of every prior build-log task in this project)

- [ ] **Step 1: Append a Build Log entry**

Add to the end of the "## Build Log" section in `CLAUDE.md`:

```markdown
- **2026-07-31 (Evasive-corpus validation)** — Built the harness to
  validate the same day's evasion-hardening code (encrypted-attachment
  detection, OneNote escalation, recursive archive scanning, CAPE
  anti-sandbox override) against real malware, per
  `docs/superpowers/specs/2026-07-31-evasive-corpus-validation-design.md`.
  A parallel research pass had surveyed 5 sample sources and recommended
  building new air-gapped VM infrastructure to handle them safely — turned
  out unnecessary: the project already has exactly that environment (the
  CAPE VM, Hyper-V name `moham`, `192.168.100.10`, with INetSim already
  configured for sinkholed network simulation). Also surfaced along the
  way: `detonation_config.CAPE_VM_NAME` is stale (`"cape-ubuntu"`, doesn't
  match the VM's real name `moham`) — likely why `DETONATION_MANAGE_VM`
  has stayed disabled since 2026-07-19; not fixed here, tracked as a
  follow-up.
  Two tracks: `malwarebazaar_client.py` (new, thin fail-safe REST wrapper
  matching `cape_client.py`'s style) + `evasive_corpus_test.py` (new,
  sibling to `epvme_test.py`) automate the MalwareBazaar path — samples
  stay ZIP-encrypted (password `infected`) end-to-end, decrypted only
  inside the existing sandboxed extraction containers, exercising the
  real `encrypted_with_password_in_body` detection path Task 2 of the
  evasion-hardening work shipped earlier today. `docs/evasive-corpus-runbook.md`
  documents the InQuest/RawMal-TF raw-binary track as a manual procedure
  run entirely on the CAPE VM — those binaries never touch this dev
  machine. `per_technique_breakdown` in the new report gives detection
  rate grouped by MalwareBazaar tag (onenote/html-smuggling/encrypted-zip/
  iso/lnk/etc.), the technique-level answer the user asked for rather
  than just an aggregate. `avast_ctu_crosscheck.py` (Task 4) adds an
  optional, informational-only diff between our own CAPE run's signature
  names and a matching Avast-CTU reference report for the same malware
  family (via `--avast-ctu-dir`, pointed at a manually-downloaded local
  copy of the 13GB dataset — not fetched automatically by any code here).
```

- [ ] **Step 2: Append the real smoke-run numbers as their own paragraph**

Task 3 Step 4 already ran `python src/evasive_corpus_test.py --tags onenote --limit-per-tag 3 --no-detonation` and printed a `[ACQUIRE] tag='onenote': N sample(s) found` line plus a final per-technique detection-rate table, and wrote `data/evasive_corpus_results/evasive_corpus_report.json`. Open that JSON file, read `summary.total_malicious`, `summary.errors`, and `per_technique_breakdown.onenote`, and append one more paragraph to the entry from Step 1 stating those exact numbers, e.g.:

```markdown
  **Smoke-tested against the live API** (Task 3 Step 4): pulled N onenote-
  tagged samples, X/N caught (detection rate Y%), Z errors. Full corpus
  run across all five tags deferred to a follow-up session (this pass
  validates the harness itself works end-to-end, not the full-scale
  detection-rate study).
```

replacing N/X/Y/Z with the actual values read from
`evasive_corpus_report.json` — do not invent numbers or copy this example
verbatim.

- [ ] **Step 3: No commit** — `CLAUDE.md` is gitignored (`.gitignore:8`); leave it updated on disk only, matching every prior build-log entry in this project.

---
