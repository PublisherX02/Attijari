# ImaniIA Hackathon Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand this codebase from the Attijari email-security POC to ImaniIA, a local-first claims-triage copilot, and publish it as a clean, IP-safe public repo at `https://github.com/PublisherX02/Automate-Or-Die.git`, with a working CV damage-assessment step added to the extraction pipeline.

**Architecture:** No pipeline logic changes except one new extraction step. Everything else is (a) mechanical text substitution across tracked product files, (b) a handful of file renames/moves, (c) two IP-protection carve-outs (YARA rules, CV model weights), and (d) a git-mechanics step to publish with fresh history.

**Tech Stack:** Python 3.12, FastAPI/Jinja2 dashboard, pytest, git.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-17-imania-hackathon-rebrand-design.md`
- Product name: **ImaniIA**. Case-variant replacement mapping (apply in this exact order to avoid substring corruption): `ATTIJARI`→`IMANIA`, `Attijari`→`ImaniIA`, `attijari`→`imania`, `TIJARI`→`IMANIA`, `Tijari`→`Imania`, `tijari`→`imania`.
- `docs/superpowers/**` is internal Claude Code process history (specs/plans). It stays in the private `Attijari` repo and is **never added** to the new repo's fresh history — do not scrub it, just exclude it from the file list pushed to the new remote.
- `CLAUDE.md` is gitignored in both repos (never committed) — treat it as a local-only file, not a git scrub target.
- No Pydantic field-name renames in the Verdict schema (`risque_expediteur`, `score_risque`, etc.) — those are consumed by 9 research experiment scripts (`src/experiments/e1..e9`) and renaming them for cosmetic reasons only is out of scope. Rebrand happens at the presentation layer (dashboard templates, docstrings) only.
- Existing test suite must stay green after every task. Baseline: run `pytest -q` before Task 1 and record the pass count; every subsequent task's verification step compares against that baseline.

---

### Task 1: Scripted product-file rebrand pass

**Files:**
- Modify (scrub in place, exact list — all git-tracked, outside `docs/superpowers/`):
  `.env.example`, `.gitattributes`, `docker/build.sh`, `docker/docker-compose.build.yml`,
  `docs/generate_architecture.py`, `grafana/provisioning/dashboards/provider.yml`,
  `nginx.conf`, `promptfoo/prompt_template.txt`, `promptfoo/promptfooconfig.yaml`,
  `src/ThreatFoxAPI.py`, `src/accuracy.py`, `src/api.py`, `src/cape_vm_wrapper.py`,
  `src/dashboard/static/css/dashboard.css`, `src/dashboard/static/js/dashboard.js`,
  `src/dashboard/templates/audit.html`, `src/dashboard/templates/base.html`,
  `src/dashboard/templates/blocklist.html`, `src/dashboard/templates/detail.html`,
  `src/dashboard/templates/health.html`, `src/dashboard/templates/history.html`,
  `src/dashboard/templates/inbox.html`, `src/dashboard/templates/login.html`,
  `src/dashboard/templates/manual_detonation.html`, `src/dashboard/templates/reports.html`,
  `src/dashboard/templates/whitelist.html`, `src/database.py`, `src/detonation.py`,
  `src/detonation_config.py`, `src/dnstwist_check.py`, `src/epvme_test.py`,
  `src/experiments/e4_prompt_injection.py`, `src/extraction.py`, `src/health.py`,
  `src/http_client.py`, `src/logger.py`, `src/metrics.py`, `src/reporting.py`,
  `src/routers/detonation_proxy.py`, `src/routers/emails.py`, `src/routers/users.py`,
  `src/rules.py`, `src/sandbox.py`, `src/scheduler.py`, `src/skills.md`,
  `src/stress_test.py`, `src/tasks/background.py`, `src/whois_check.py`,
  `start.bat`, `start_all.ps1`, `test_architecture.py`, `tests/test_pipeline_e2e.py`
- Create (temporary, scratchpad — not part of the product repo): `scripts/rebrand_scrub.py` written to the scratchpad dir, not committed.

**Interfaces:**
- Produces: a working tree where none of the 52 files above contain any case variant of `attijari`/`tijari`. Task 2 depends on this being true before it does file renames.

- [ ] **Step 1: Record the pytest baseline**

Run: `pytest -q 2>&1 | tail -5`
Record the final summary line (e.g. `46 passed`) — this is the baseline every later task's test run must match or exceed.

- [ ] **Step 2: Write the scrub script**

Write to `C:\Users\moham\AppData\Local\Temp\claude\C--Users-moham-Attijari\662d2b6f-2d1e-4734-83bb-756e5c93871c\scratchpad\rebrand_scrub.py`:

```python
import pathlib

FILES = """.env.example
.gitattributes
docker/build.sh
docker/docker-compose.build.yml
docs/generate_architecture.py
grafana/provisioning/dashboards/provider.yml
nginx.conf
promptfoo/prompt_template.txt
promptfoo/promptfooconfig.yaml
src/ThreatFoxAPI.py
src/accuracy.py
src/api.py
src/cape_vm_wrapper.py
src/dashboard/static/css/dashboard.css
src/dashboard/static/js/dashboard.js
src/dashboard/templates/audit.html
src/dashboard/templates/base.html
src/dashboard/templates/blocklist.html
src/dashboard/templates/detail.html
src/dashboard/templates/health.html
src/dashboard/templates/history.html
src/dashboard/templates/inbox.html
src/dashboard/templates/login.html
src/dashboard/templates/manual_detonation.html
src/dashboard/templates/reports.html
src/dashboard/templates/whitelist.html
src/database.py
src/detonation.py
src/detonation_config.py
src/dnstwist_check.py
src/epvme_test.py
src/experiments/e4_prompt_injection.py
src/extraction.py
src/health.py
src/http_client.py
src/logger.py
src/metrics.py
src/reporting.py
src/routers/detonation_proxy.py
src/routers/emails.py
src/routers/users.py
src/rules.py
src/sandbox.py
src/scheduler.py
src/skills.md
src/stress_test.py
src/tasks/background.py
src/whois_check.py
start.bat
start_all.ps1
test_architecture.py
tests/test_pipeline_e2e.py""".splitlines()

REPLACEMENTS = [
    ("ATTIJARI", "IMANIA"),
    ("Attijari", "ImaniIA"),
    ("attijari", "imania"),
    ("TIJARI", "IMANIA"),
    ("Tijari", "Imania"),
    ("tijari", "imania"),
]

ROOT = pathlib.Path(r"C:\Users\moham\Attijari")
changed = []
for rel in FILES:
    p = ROOT / rel
    text = p.read_text(encoding="utf-8")
    original = text
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    if text != original:
        p.write_text(text, encoding="utf-8")
        changed.append(rel)

print(f"Changed {len(changed)}/{len(FILES)} files")
for f in changed:
    print(" ", f)
```

- [ ] **Step 3: Run the script**

Run: `python "C:\Users\moham\AppData\Local\Temp\claude\C--Users-moham-Attijari\662d2b6f-2d1e-4734-83bb-756e5c93871c\scratchpad\rebrand_scrub.py"`
Expected: prints a changed-file count (most of the 52) and a list.

- [ ] **Step 4: Verify zero remaining matches**

Run: `git grep -i -c -e attijari -e tijari -- . ':!docs/superpowers'`
Expected: no output (exit code 1 / empty — `git grep` returns non-zero when there are no matches).

- [ ] **Step 5: Read a sample of changed files to sanity-check the replacement didn't mangle anything**

Read `src/api.py` and `src/dashboard/templates/base.html` (or use Grep to show 3 lines of context around any remaining "Imania"/"ImaniIA" occurrence) and confirm the substitutions read naturally (e.g. a log message that said `"Attijari email pipeline started"` now reads `"ImaniIA email pipeline started"` and not something grammatically broken).

- [ ] **Step 6: Run the full test suite**

Run: `pytest -q 2>&1 | tail -5`
Expected: same pass count as the Step 1 baseline (renaming strings shouldn't change behavior — if any test asserts on literal "Attijari" text, fix that assertion to the new string and re-run).

- [ ] **Step 7: Commit**

```bash
git add .env.example .gitattributes docker/build.sh docker/docker-compose.build.yml docs/generate_architecture.py grafana/provisioning/dashboards/provider.yml nginx.conf promptfoo/prompt_template.txt promptfoo/promptfooconfig.yaml src/ tests/test_pipeline_e2e.py start.bat start_all.ps1 test_architecture.py
git commit -m "rebrand: replace Attijari/Tijari references with ImaniIA across product files"
```

---

### Task 2: File/directory renames and path-reference updates

**Files:**
- Move: `deploy/attijari/vm_wrapper.py` → `deploy/vm_wrapper.py`
- Move: `docs/attijari-sandbox-setup.md` → `docs/sandbox-setup.md`
- Move: `grafana/provisioning/dashboards/attijari.json` → `grafana/provisioning/dashboards/imania.json`
- Modify (scrub content + any path references to the above): the three moved files themselves, plus any file that references the old paths (search after moving).

**Interfaces:**
- Consumes: Task 1's clean working tree (no lingering "attijari" text to reintroduce via a stale path reference).
- Produces: no file or directory name anywhere in the tree contains "attijari"/"tijari".

- [ ] **Step 1: Move the files**

```bash
git mv deploy/attijari/vm_wrapper.py deploy/vm_wrapper.py
git mv docs/attijari-sandbox-setup.md docs/sandbox-setup.md
git mv grafana/provisioning/dashboards/attijari.json grafana/provisioning/dashboards/imania.json
```

- [ ] **Step 2: Remove the now-empty `deploy/attijari/` directory if `git mv` left it**

Run: `Get-ChildItem deploy/attijari -ErrorAction SilentlyContinue` (PowerShell) — if it lists nothing, the directory is already gone (git doesn't track empty dirs); if files remain, investigate before deleting.

- [ ] **Step 3: Scrub content of the three moved files**

Apply the same `REPLACEMENTS` list from Task 1 Step 2 to `deploy/vm_wrapper.py`, `docs/sandbox-setup.md`, `grafana/provisioning/dashboards/imania.json` (reuse the scratchpad script — add these three paths to `FILES` and rerun, or edit by hand since it's only 3 files).

- [ ] **Step 4: Find and fix any reference to the old paths**

Run: `git grep -n "deploy/attijari\|attijari-sandbox-setup\|dashboards/attijari"`
Expected: no matches. If any file (e.g. a runbook or `docker-compose.yml`) references the old path, update it to the new path.

- [ ] **Step 5: Verify no attijari/tijari text remains anywhere in tracked files outside docs/superpowers**

Run: `git grep -i -c -e attijari -e tijari -- . ':!docs/superpowers'`
Expected: empty output.

- [ ] **Step 6: Run tests**

Run: `pytest -q 2>&1 | tail -5`
Expected: matches Task 1's baseline pass count.

- [ ] **Step 7: Commit**

```bash
git add -A -- deploy/ docs/sandbox-setup.md grafana/
git commit -m "rebrand: rename attijari-specific paths to imania/generic equivalents"
```

---

### Task 3: YARA ruleset IP redaction

**Files:**
- Modify: `.gitignore`
- Create: `data/yara_rules/README.md`
- Create: `data/yara_rules/example.yar`

**Interfaces:**
- Produces: a tracked, public-safe placeholder at `data/yara_rules/example.yar` that demonstrates the mechanism exists without shipping the real ruleset (which stays untracked, per the existing `data/` gitignore rule).

- [ ] **Step 1: Confirm the real ruleset is currently untracked**

Run: `git ls-files data/yara_rules/`
Expected: empty (confirms `data/` gitignore rule already keeps `suspicious.yar` out of git — nothing to remove, just need a public-safe stand-in).

- [ ] **Step 2: Carve out a gitignore exception for the placeholder path**

Edit `.gitignore`, after the existing `data/` line, add:

```
!data/yara_rules/
!data/yara_rules/README.md
!data/yara_rules/example.yar
```

- [ ] **Step 3: Write the placeholder rule**

Create `data/yara_rules/example.yar`:

```
// Redacted: proprietary ruleset, available under license.
// This file demonstrates the YARA detection mechanism used by the
// extraction pipeline (src/extraction.py:_local_yara). The production
// ruleset is trained on proprietary phishing/malware datasets and is
// not included in this public repository.

rule example_placeholder_rule
{
    meta:
        author = "ImaniIA"
        description = "Placeholder — see README.md in this directory"
    strings:
        $suspicious_marker = "THIS_IS_A_PLACEHOLDER_RULE_NOT_PRODUCTION"
    condition:
        $suspicious_marker
}
```

- [ ] **Step 4: Write the README**

Create `data/yara_rules/README.md`:

```markdown
# YARA Rules — Redacted

The production detection ruleset used by ImaniIA's extraction pipeline is
proprietary (trained on licensed phishing/malware datasets) and is not
included in this public repository. `example.yar` is a non-functional
placeholder that demonstrates the mechanism only.

The real ruleset is available under a commercial license — contact the
maintainers.
```

- [ ] **Step 5: Verify the placeholder is tracked and the real rule is not**

Run: `git add data/yara_rules/README.md data/yara_rules/example.yar .gitignore && git status --porcelain data/`
Expected: only `README.md` and `example.yar` show as staged additions; `suspicious.yar` (if present locally) does not appear.

- [ ] **Step 6: Run the YARA extraction test to confirm the pipeline still works with a placeholder-only ruleset**

Run: `pytest -q -k yara 2>&1 | tail -15`
Expected: passes (the extraction code just globs `*.yar`/`*.yara` in the directory — it doesn't care whether the rule is real or a placeholder).

- [ ] **Step 7: Commit**

```bash
git commit -m "chore: add public-safe YARA ruleset placeholder, keep real ruleset out of git"
```

---

### Task 4: CV model weights IP carve-out

**Files:**
- Modify: `.gitignore`
- Modify: `src/detonation_config.py` (or wherever env-var-style config constants live — confirmed location in Task 5)

**Interfaces:**
- Produces: `.gitignore` rule that keeps any committed CV model weight file out of git, while the code path that loads it (Task 5) stays intact and works locally with the real file.

- [ ] **Step 1: Add gitignore rules for common model weight formats**

Edit `.gitignore`, add:

```
# CV model weights — proprietary, not shipped in public repo
*.pt
*.onnx
*.weights
models/
```

- [ ] **Step 2: Verify no weight file is currently tracked**

Run: `git ls-files | Select-String "\.pt$|\.onnx$|\.weights$"` (PowerShell) or `git ls-files | grep -E '\.(pt|onnx|weights)$'` (bash)
Expected: empty (the `.venv` ONNX files seen earlier are inside `.venv/`, already gitignored — confirm this command finds none in tracked product files).

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: gitignore CV model weight files (proprietary, license-only)"
```

---

### Task 5: CV damage-assessment extraction step

**Files:**
- Modify: `src/extraction.py` (add `_local_cv_damage`, wire into `_run_tool` dispatch and the images block of `extract_attachment`)
- Modify: `src/detonation_config.py` (add `CV_DAMAGE_MODEL_PATH` env-var-backed constant, following the existing pattern for other config constants in that file)
- Test: `tests/test_extraction_cv_damage.py` (new)

**Interfaces:**
- Consumes: the existing `_run_tool(tool_name, content, stored_path, filename)` dispatcher pattern and `_local_<tool>(content) -> dict` convention already used by `_local_tesseract`/`_local_yara` (src/extraction.py:235-266).
- Produces: `_local_cv_damage(content: bytes) -> dict` returning `{"tool": "cv_damage", "status": "ok"|"unavailable"|"error", "damage_detected": bool, "damage_classes": list[str], "confidence": float, "severity_estimate": "none"|"minor"|"moderate"|"severe"}` on success. `extract_attachment` stores this under `result["cv_damage_assessment"]` and appends a flag to `result["flags"]` when `damage_detected` is true, for stage-5 LLM consumption as an enrichment signal (same pattern as the existing `tesseract`/`yara` signals — no schema change needed since `flags` is already a free-form list consumed downstream).

- [ ] **Step 1: Write the failing test**

Create `tests/test_extraction_cv_damage.py`:

```python
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_local_cv_damage_unavailable_when_no_model_configured(monkeypatch):
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", None)
    result = extraction._local_cv_damage(b"fake image bytes")
    assert result == {"tool": "cv_damage", "status": "unavailable"}


def test_local_cv_damage_returns_severity_on_detection(monkeypatch, tmp_path):
    fake_model_path = tmp_path / "damage.pt"
    fake_model_path.write_bytes(b"not a real model")
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", str(fake_model_path))

    fake_box = MagicMock()
    fake_box.cls = [MagicMock(item=lambda: 0)]
    fake_box.conf = [MagicMock(item=lambda: 0.87)]
    fake_result = MagicMock()
    fake_result.boxes = [fake_box]
    fake_result.names = {0: "dent"}

    fake_model = MagicMock(return_value=[fake_result])

    with patch.object(extraction, "_load_cv_model", return_value=fake_model):
        result = extraction._local_cv_damage(b"fake image bytes")

    assert result["tool"] == "cv_damage"
    assert result["status"] == "ok"
    assert result["damage_detected"] is True
    assert "dent" in result["damage_classes"]
    assert result["confidence"] == 0.87
    assert result["severity_estimate"] in {"minor", "moderate", "severe"}


def test_local_cv_damage_error_is_fail_safe_not_fail_open(monkeypatch, tmp_path):
    fake_model_path = tmp_path / "damage.pt"
    fake_model_path.write_bytes(b"not a real model")
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", str(fake_model_path))

    with patch.object(extraction, "_load_cv_model", side_effect=RuntimeError("model load failed")):
        result = extraction._local_cv_damage(b"fake image bytes")

    assert result["status"] == "error"
    assert result["damage_detected"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_extraction_cv_damage.py -v`
Expected: FAIL — `AttributeError: module 'extraction' has no attribute '_local_cv_damage'` (and `CV_DAMAGE_MODEL_PATH`, `_load_cv_model`).

- [ ] **Step 3: Add the config constant**

In `src/detonation_config.py`, near the other env-var-backed constants (same pattern as `CAPE_VM_WRAPPER_ENABLED`), add:

```python
CV_DAMAGE_MODEL_PATH = os.environ.get("CV_DAMAGE_MODEL_PATH") or None
```

- [ ] **Step 4: Implement `_local_cv_damage` in `src/extraction.py`**

Add near `_local_tesseract` (after the import of `CV_DAMAGE_MODEL_PATH` from `detonation_config` at the top of the file, alongside the other config imports already present):

```python
_CV_MODEL_CACHE = {}


def _load_cv_model(model_path: str):
    if model_path not in _CV_MODEL_CACHE:
        from ultralytics import YOLO
        _CV_MODEL_CACHE[model_path] = YOLO(model_path)
    return _CV_MODEL_CACHE[model_path]


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.75:
        return "severe"
    if confidence >= 0.45:
        return "moderate"
    return "minor"


def _local_cv_damage(content: bytes) -> dict:
    """Damage assessment on claim photos via a locally-hosted YOLO model.

    Fail-safe: any failure (missing model, load error, inference error)
    returns status != "ok" and damage_detected=False — never fabricates
    a positive/negative damage signal on error.
    """
    if not CV_DAMAGE_MODEL_PATH:
        return {"tool": "cv_damage", "status": "unavailable"}
    try:
        model = _load_cv_model(CV_DAMAGE_MODEL_PATH)
        img = Image.open(_io.BytesIO(content))
        results = model(img)
        classes = []
        confidences = []
        for r in results:
            for box in getattr(r, "boxes", []):
                cls_idx = int(box.cls[0].item())
                classes.append(r.names.get(cls_idx, str(cls_idx)))
                confidences.append(float(box.conf[0].item()))
        damage_detected = len(classes) > 0
        top_confidence = max(confidences) if confidences else 0.0
        return {
            "tool": "cv_damage",
            "status": "ok",
            "damage_detected": damage_detected,
            "damage_classes": classes,
            "confidence": round(top_confidence, 4),
            "severity_estimate": _severity_from_confidence(top_confidence) if damage_detected else "none",
        }
    except Exception as e:
        return {"tool": "cv_damage", "status": "error", "error": str(e), "damage_detected": False}
```

Add the import at the top of `src/extraction.py` alongside the existing `detonation_config` imports:

```python
from detonation_config import CV_DAMAGE_MODEL_PATH
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_extraction_cv_damage.py -v`
Expected: 3 passed.

- [ ] **Step 6: Wire `cv_damage` into the `_run_tool` dispatcher**

In `src/extraction.py`, in `_run_tool` (around line 345), add after the `tesseract` branch:

```python
    elif tool_name == "cv_damage":
        return _local_cv_damage(content)
```

- [ ] **Step 7: Call it from the images block in `extract_attachment`**

In `src/extraction.py`, in the `# 4. Images` block (around line 649-663), after the existing stego-metadata check, add:

```python
        # CV damage assessment — claim photos only, additive signal
        cv_result = _run_tool("cv_damage", content, stored_path, filename)
        result["tools_run"].append(cv_result)
        result["cv_damage_assessment"] = cv_result
        if cv_result.get("damage_detected"):
            result["flags"].append(
                f"cv_damage_detected: {', '.join(cv_result.get('damage_classes', []))} "
                f"(severity={cv_result.get('severity_estimate')}, confidence={cv_result.get('confidence')})"
            )
```

- [ ] **Step 8: Write an integration-level test that a damage-photo attachment surfaces the signal end to end**

Add to `tests/test_extraction_cv_damage.py`:

```python
def test_extract_attachment_includes_cv_damage_assessment(monkeypatch, tmp_path):
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", None)  # unavailable path, deterministic
    fake_image = tmp_path / "claim_photo.png"
    fake_image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)

    attachment = {
        "stored_path": str(fake_image),
        "original_name": "claim_photo.png",
        "declared_type": "image/png",
        "real_type": "image/png",
        "type_mismatch": False,
        "sha256": "deadbeef",
    }
    result = extraction.extract_attachment(attachment)
    assert "cv_damage_assessment" in result
    assert result["cv_damage_assessment"]["status"] == "unavailable"
```

- [ ] **Step 9: Run the full test suite**

Run: `pytest -q 2>&1 | tail -5`
Expected: baseline pass count + 4 new passing (3 unit + 1 integration).

- [ ] **Step 10: Add `CV_DAMAGE_MODEL_PATH` to `.env.example` with a comment**

Append to `.env.example`:

```
# Path to the trained YOLO damage-assessment model weights (.pt file).
# Proprietary — not included in this repo. Leave unset to disable the
# CV damage-assessment extraction step (fails safe to "unavailable").
CV_DAMAGE_MODEL_PATH=
```

- [ ] **Step 11: Commit**

```bash
git add src/extraction.py src/detonation_config.py tests/test_extraction_cv_damage.py .env.example
git commit -m "feat: add CV damage-assessment extraction step for claim photos"
```

---

### Task 6: Claims-domain presentation layer

**Files:**
- Modify: `src/dashboard/templates/detail.html` (verdict card labels)
- Modify: `src/analysis.py` (docstrings/prompt copy describing what each verdict field means, if this file contains the LLM prompt template — confirm location first)

**Interfaces:**
- Consumes: existing `Verdict` Pydantic model field names (unchanged, per Global Constraints) — this task only changes human-facing labels/copy, not field names or types.

- [ ] **Step 1: Locate the verdict card rendering and the LLM prompt copy**

Run: `git grep -n "risque_expediteur\|score_risque\|classification_intention" src/dashboard/templates/detail.html src/analysis.py`
Note the exact line numbers before editing (they'll differ from what's shown here since Task 1's scrub already touched these files).

- [ ] **Step 2: Update dashboard labels to claims-domain language**

In `src/dashboard/templates/detail.html`, wherever a field label is rendered (e.g. a `<label>` or `<th>` next to `{{ verdict.risque_expediteur }}`), change the human-readable label text only — for example `Risque expéditeur` → `Gravité du sinistre`, `Verdict` → `Recommandation`, `Accepter/Rejeter/Escalader` → `Valider/Rejeter/Escalader vers expert`. Do not change the Jinja variable references (`verdict.risque_expediteur` etc. stay as-is).

- [ ] **Step 3: Update the LLM prompt/docstring copy in `src/analysis.py`**

Wherever the prompt template or docstrings describe field semantics in email-security terms (e.g. "assess whether this email is phishing"), reword to claims-triage terms (e.g. "assess the severity and legitimacy of this insurance claim") without changing the Pydantic field names, types, or the retry/escalation control flow.

- [ ] **Step 4: Run the full test suite**

Run: `pytest -q 2>&1 | tail -5`
Expected: matches baseline (copy-only change, no logic touched).

- [ ] **Step 5: Manually verify the dashboard renders correctly**

Start the dashboard (`start.bat` or `uvicorn` per existing docs) and open the detail view for any existing test record; confirm labels read naturally in the claims domain and no Jinja template errors appear in the console.

- [ ] **Step 6: Commit**

```bash
git add src/dashboard/templates/detail.html src/analysis.py
git commit -m "rebrand: relabel dashboard and LLM prompt copy for claims-triage domain"
```

---

### Task 7: Exclude leftover Attijari-branding asset

**Files:**
- Modify: `.gitignore`

**Interfaces:**
- Produces: `src/dashboard/static/img/` (currently untracked, contains the reverted Attijari-rebrand logo per CLAUDE.md's build log) is guaranteed excluded from any future `git add`, including the fresh-history creation in Task 8.

- [ ] **Step 1: Confirm the directory is untracked and what it contains**

Run: `git status --porcelain src/dashboard/static/img/` and `Get-ChildItem src/dashboard/static/img/ -Recurse` (or `ls -la` in bash)
Expected: shows `??` (untracked) status and lists the leftover logo file(s).

- [ ] **Step 2: Add an explicit gitignore rule**

Edit `.gitignore`, add:

```
src/dashboard/static/img/
```

- [ ] **Step 3: Verify it's now ignored**

Run: `git status --porcelain src/dashboard/static/img/`
Expected: empty output (no longer shown as untracked).

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: gitignore leftover branding asset directory"
```

---

### Task 8: Publish fresh history to the new public repo

**Files:** none (git mechanics only)

**Interfaces:** none

- [ ] **Step 1: Final verification pass before creating fresh history**

Run: `git grep -i -c -e attijari -e tijari -- . ':!docs/superpowers'`
Expected: empty. If anything remains, stop and fix it before proceeding — once pushed to the public remote, it's public.

- [ ] **Step 2: Confirm the full test suite is green on `dev`**

Run: `pytest -q 2>&1 | tail -5`
Expected: matches or exceeds the Task 1 baseline.

- [ ] **Step 3: Create an orphan branch for the public export**

```bash
git checkout --orphan imania-public
git rm -r --cached .
```

- [ ] **Step 4: Stage everything except `docs/superpowers/`, which stays internal**

```bash
git add -A -- . ':!docs/superpowers'
git status --porcelain | Select-String "^A" | Measure-Object   # sanity count, PowerShell
```

- [ ] **Step 5: Commit the single fresh-history commit**

```bash
git commit -m "ImaniIA: local-first AI copilot for insurance claims triage"
```

- [ ] **Step 6: Add the new remote and push**

```bash
git remote add imania-public https://github.com/PublisherX02/Automate-Or-Die.git
git push imania-public imania-public:main
```

- [ ] **Step 7: Verify on GitHub**

Fetch the pushed branch's file listing (`gh repo view PublisherX02/Automate-Or-Die --json defaultBranchRef` or open the repo URL) and confirm: single commit, no `docs/superpowers/` directory, no `attijari`/`tijari` string anywhere (spot-check via GitHub's code search or a fresh `git clone` + `git grep`).

- [ ] **Step 8: Switch back to the working branch**

```bash
git checkout dev
```

The `imania-public` branch and `imania-public` remote stay in the local repo for future re-publishing (re-run Steps 3-6 with `git branch -D imania-public` first when the demo needs another push); the original `origin` remote (private `Attijari` repo) is untouched throughout.
