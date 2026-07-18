# CV + LLM Claim Verdict, Urgency Queue & Settlement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the trained car-damage YOLO model (`models/car_damage_yolov8.pt`) to the LLM (structured detections + raw photo via vision), split the LLM's output into a Security Concerns section (unchanged) and a new Verdict section (damage report, urgency, settlement recommendation), add a DB-backed urgency triage queue, and add an assistive/automated settlement recommendation gated behind mandatory human confirmation.

**Architecture:** One `analyze_email_body()` call does extraction + fusion + verdict. The CV model runs as a new extraction-stage tool (`_local_cv_damage`, same pattern as `_local_tesseract`/`_local_yara`) and its structured output is injected into the LLM prompt as grounding context; the LLM also receives the raw photo bytes via Ollama's vision API. A new `ClaimVerdict` Pydantic model validates the LLM's claim-specific output; code (never the LLM) computes `missing_information`, `damage_source`, and the automated/assistive settlement gate. A new `urgency` table persists one row per claim, sorted by a numeric `priority` for the triage queue.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy/PostgreSQL, Pydantic v2, Ollama (`gemma3:4b`, vision-capable), Ultralytics YOLOv8.

## Global Constraints

- No renames to existing `LLMVerdict` field names (`sender_risk`, `intent_classification`, `social_engineering_indicators`, `risk_score`, `confidence`, `verdict`, `reasons`) — additive only.
- Settlement recommendations are procedural text only, never a dollar amount — the system has no policy/coverage/claim-amount data to price against.
- Fail-safe direction: unknown/unparseable urgency defaults to `"high"`, never `"low"`. Any missing required field (`policyholder_name`, `policy_number`, `policy_type`, `incident_description`, or a photo) forces `settlement_type = "assistive"` — never `"automated"`.
- Automated settlement requires ALL of: `severity_estimate == "minor"`, `urgency == "low"`, `confidence >= 0.75`, and zero entries in `missing_information`.
- Every settlement — assistive or automated — requires an explicit human confirmation click before anything is considered final. Nothing settles itself.
- New DB table is created via the existing `Base.metadata.create_all(bind=engine)` in `init_db()` — no manual migration needed (this is a brand-new table, not a column added to an existing one).
- Existing sandbox/detonation subsystem is untouched.

---

### Task 1: Car-damage CV model wired into the extraction stage

**Files:**
- Modify: `requirements.txt`
- Modify: `src/detonation_config.py`
- Modify: `src/extraction.py`
- Test: `tests/test_extraction_cv_damage.py` (already exists, currently failing — this task makes it pass)

**Interfaces:**
- Consumes: `models/car_damage_yolov8.pt` (already present on disk, gitignored).
- Produces: `extraction._local_cv_damage(content: bytes) -> dict` returning `{"tool": "cv_damage", "status": "unavailable"}` when no model configured, `{"tool": "cv_damage", "status": "error", "error": str, "damage_detected": False}` on failure, or `{"tool": "cv_damage", "status": "ok", "damage_detected": bool, "damage_classes": list[str], "confidence": float, "severity_estimate": "none"|"minor"|"moderate"|"severe"}` on success. `extraction._load_cv_model(model_path: str)` (patchable module function). `extraction.CV_DAMAGE_MODEL_PATH` (patchable module attribute). `extract_attachment()` stores the result under `result["cv_damage_assessment"]` — Task 5 reads this key.

- [ ] **Step 1: Confirm the baseline failing state**

Run: `cd "C:\Users\moham\Automate or Die Hackathon" && python -m pytest tests/test_extraction_cv_damage.py -v 2>&1 | tail -20`
Expected: 4 failures (`AttributeError: module 'extraction' has no attribute '_local_cv_damage'` and similar for `_load_cv_model`/`CV_DAMAGE_MODEL_PATH`).

- [ ] **Step 2: Add the `ultralytics` dependency**

In `requirements.txt`, after the `# LLM runtime` block (after the `ollama` line), add:

```
# Computer vision — car-damage assessment (claims-triage extraction step)
ultralytics==8.3.60
```

Run: `pip install ultralytics==8.3.60`
Expected: installs cleanly (torch is already pinned at 2.5.1 via the existing `transformers`/Llama Guard dependency, ultralytics will reuse it).

- [ ] **Step 3: Add the model-path config constant**

In `src/detonation_config.py`, at the end of the file, add:

```python

# --------------------------------------------------------------------------
# Car-damage CV model (claims-triage extraction step)
# --------------------------------------------------------------------------
# Path to the trained YOLOv8 damage-assessment model weights (.pt file).
# Proprietary — gitignored, not shipped in the public repo. Leave unset to
# disable the CV damage-assessment extraction step (fails safe to
# "unavailable", never blocks the pipeline).
CV_DAMAGE_MODEL_PATH = os.getenv("CV_DAMAGE_MODEL_PATH") or str(
    (__import__("pathlib").Path(__file__).resolve().parent.parent / "models" / "car_damage_yolov8.pt")
    if (__import__("pathlib").Path(__file__).resolve().parent.parent / "models" / "car_damage_yolov8.pt").exists()
    else ""
) or None
```

- [ ] **Step 4: Add the CV damage functions to `extraction.py`**

In `src/extraction.py`, add this import near the top, right after the existing `from sandbox import run_tool as _sandbox_run, check_sandbox_status` line (line 38):

```python
from detonation_config import CV_DAMAGE_MODEL_PATH
```

Then, immediately after `_local_tesseract` (after line 244, before `def _local_yara`), add:

```python
_CV_MODEL_CACHE: dict[str, "object"] = {}


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
    """Damage assessment on claim photos via the trained YOLOv8 model.

    Fail-safe: any failure (missing model, load error, inference error)
    returns status != "ok" and damage_detected=False — never fabricates a
    positive/negative damage signal on error.
    """
    if not CV_DAMAGE_MODEL_PATH:
        return {"tool": "cv_damage", "status": "unavailable"}
    try:
        from PIL import Image as _CVImage
        import io as _cv_io

        model = _load_cv_model(CV_DAMAGE_MODEL_PATH)
        img = _CVImage.open(_cv_io.BytesIO(content))
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

- [ ] **Step 5: Wire `cv_damage` into the `_run_tool` dispatcher**

In `src/extraction.py`, in `_run_tool` (the `elif tool_name == "tesseract":` branch, currently at line 345-346), add immediately after it:

```python
    elif tool_name == "cv_damage":
        return _local_cv_damage(content)
```

- [ ] **Step 6: Call it from the images block in `extract_attachment`**

In `src/extraction.py`, in the `# 4. Images` block (currently lines 649-663), after the existing stego-metadata check (after the `for flag in stego_flags:` loop, still inside the `if effective_mime in _IMAGE_MIMES ...:` block), add:

```python

        # CV damage assessment — claim photos only, additive signal, never blocks
        cv_result = _run_tool("cv_damage", content, stored_path, filename)
        result["tools_run"].append(cv_result)
        result["cv_damage_assessment"] = cv_result
        if cv_result.get("damage_detected"):
            result["flags"].append(
                f"cv_damage_detected: {', '.join(cv_result.get('damage_classes', []))} "
                f"(severity={cv_result.get('severity_estimate')}, confidence={cv_result.get('confidence')})"
            )
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_extraction_cv_damage.py -v 2>&1 | tail -20`
Expected: 4 passed.

- [ ] **Step 8: Run the full test suite to check for regressions**

Run: `python -m pytest -q 2>&1 | tail -15`
Expected: same pass count as before this task, plus the 4 newly-passing CV tests (baseline was 55 passed / 5 failed before this task — expect 59 passed / 1 failed, the 1 remaining failure being the pre-existing unrelated CSP nonce test).

- [ ] **Step 9: Commit**

```bash
git add requirements.txt src/detonation_config.py src/extraction.py
git commit -m "feat: wire trained YOLOv8 car-damage model into the extraction stage"
```

---

### Task 2: `ClaimVerdict` schema, prompt extension, and fail-safe fusion logic

**Files:**
- Modify: `src/analysis.py`
- Modify: `src/skills.md`
- Test: `tests/test_analysis_claim_verdict.py` (new)

**Interfaces:**
- Consumes: Task 1's `result["cv_damage_assessment"]` (passed in via the caller's `context["cv_damage"]`, wired in Task 5), and a new `context["claim_photo_present"]: bool` flag (also wired in Task 5).
- Produces: `analysis.ClaimVerdict` Pydantic model. `analyze_email_body(..., image_bytes: Optional[bytes] = None)` — new optional parameter. The function's returned dict gains a `"claim_verdict"` key: `{"policyholder_name": str|None, "policy_number": str|None, "policy_type": str|None, "incident_description": str|None, "damage_classes": list[str], "severity_estimate": "none"|"minor"|"moderate"|"severe", "full_report": str, "urgency": "low"|"medium"|"high"|"critical", "urgency_reasoning": str, "settlement_recommendation": str, "missing_information": list[str], "damage_detected": bool, "damage_source": "cv_model"|"llm_vision"|"both"|"text_only", "settlement_type": "assistive"|"automated"}`. Task 5 reads this key; Task 4's `upsert_urgency` reads it.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_analysis_claim_verdict.py`:

```python
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import analysis


def _llm_json(claim_verdict: dict, **overrides) -> str:
    base = {
        "sender_risk": 5, "intent_classification": "legitimate claim",
        "social_engineering_indicators": [], "risk_score": 5,
        "confidence": 0.9, "verdict": "accepted", "reasons": ["clean"],
        "claim_verdict": claim_verdict,
    }
    base.update(overrides)
    return json.dumps(base)


def test_complete_minor_claim_gets_automated_settlement(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Minor bumper scrape in parking lot",
        "damage_classes": ["scratch"], "severity_estimate": "minor",
        "full_report": "Small scratch on rear bumper, cosmetic only.",
        "urgency": "low", "urgency_reasoning": "Minor cosmetic damage, no injuries.",
        "settlement_recommendation": "Approve for direct repair, no adjuster needed.",
    }
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "I scraped my bumper in a parking lot.",
        context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert cv["missing_information"] == []
    assert cv["settlement_type"] == "automated"
    assert cv["damage_source"] == "text_only"  # no cv_damage context, no image_bytes passed


def test_missing_policy_number_forces_assistive_settlement(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": None,
        "policy_type": "auto", "incident_description": "Minor scrape",
        "damage_classes": ["scratch"], "severity_estimate": "minor",
        "full_report": "Small scratch.", "urgency": "low",
        "urgency_reasoning": "Minor.", "settlement_recommendation": "Approve.",
    }
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "I scraped my bumper.", context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert "policy_number" in cv["missing_information"]
    assert cv["settlement_type"] == "assistive"


def test_missing_photo_is_reported_and_blocks_automation(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Minor scrape",
        "damage_classes": [], "severity_estimate": "minor",
        "full_report": "No photo provided.", "urgency": "low",
        "urgency_reasoning": "Minor per description.", "settlement_recommendation": "Request photos.",
    }
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "I scraped my bumper.", context={"claim_photo_present": False},
    )
    cv = result["claim_verdict"]
    assert "photo" in cv["missing_information"]
    assert cv["settlement_type"] == "assistive"


def test_severe_damage_never_auto_settles_even_if_complete(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Major collision",
        "damage_classes": ["frame_damage", "airbag_deployed"], "severity_estimate": "severe",
        "full_report": "Severe front-end damage.", "urgency": "critical",
        "urgency_reasoning": "Severe structural damage.", "settlement_recommendation": "Send to adjuster immediately.",
    }
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "My car was in a major accident.", context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert cv["settlement_type"] == "assistive"
    assert cv["urgency"] == "critical"


def test_unparseable_urgency_defaults_to_high_not_low(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Some damage",
        "damage_classes": [], "severity_estimate": "minor",
        "full_report": "Report.", "urgency": "not_a_real_level",
        "urgency_reasoning": "n/a", "settlement_recommendation": "n/a",
    }
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "Something happened to my car.", context={"claim_photo_present": True},
    )
    assert result["claim_verdict"]["urgency"] == "high"


def test_cv_damage_context_grounds_damage_source(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Dent on door",
        "damage_classes": ["dent"], "severity_estimate": "minor",
        "full_report": "Dent confirmed.", "urgency": "low",
        "urgency_reasoning": "Minor.", "settlement_recommendation": "Approve.",
    }
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "Dent on my car door.",
        context={
            "claim_photo_present": True,
            "cv_damage": {"tool": "cv_damage", "status": "ok", "damage_detected": True,
                          "damage_classes": ["dent"], "confidence": 0.9, "severity_estimate": "moderate"},
        },
    )
    assert result["claim_verdict"]["damage_source"] == "cv_model"


def test_missing_claim_verdict_key_fails_safe_to_needs_review(monkeypatch):
    # LLM returns a valid security verdict but omits claim_verdict entirely
    payload = json.dumps({
        "sender_risk": 5, "intent_classification": "unknown", "social_engineering_indicators": [],
        "risk_score": 5, "confidence": 0.9, "verdict": "accepted", "reasons": [],
    })
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: payload)
    result = analysis.analyze_email_body(
        "Some claim text.", context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert cv["urgency"] == "high"  # ClaimVerdict() default, never silently low
    assert cv["settlement_type"] == "assistive"
    assert set(["policyholder_name", "policy_number", "policy_type", "incident_description"]) <= set(cv["missing_information"])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_analysis_claim_verdict.py -v 2>&1 | tail -30`
Expected: FAIL — `TypeError: analyze_email_body() got an unexpected keyword argument` or `KeyError: 'claim_verdict'` (the function doesn't know about `claim_verdict` yet).

- [ ] **Step 3: Add the `ClaimVerdict` Pydantic model**

In `src/analysis.py`, immediately after the `LLMVerdict` class (after line 46, before `SKILLS_PATH = ...` on line 48), add:

```python
class ClaimVerdict(BaseModel):
    """LLM-produced claim assessment. This is what the model is asked to
    fill in; analyze_email_body() layers missing_information/damage_source/
    settlement_type on top afterward — those are computed in code, never
    trusted from the model's own self-report."""
    policyholder_name: Optional[str] = Field(default=None, max_length=255)
    policy_number: Optional[str] = Field(default=None, max_length=100)
    policy_type: Optional[str] = Field(default=None, max_length=100)
    incident_description: Optional[str] = Field(default=None, max_length=2000)
    damage_classes: List[str] = Field(default_factory=list)
    severity_estimate: str = Field(default="none")
    full_report: str = Field(default="", max_length=3000)
    urgency: str = Field(default="high")  # fail-safe: unknown -> high, never silently low
    urgency_reasoning: str = Field(default="model output missing or invalid", max_length=1000)
    settlement_recommendation: str = Field(default="", max_length=1000)

    @field_validator("severity_estimate", mode="before")
    @classmethod
    def validate_severity(cls, v):
        allowed = ("none", "minor", "moderate", "severe")
        v = str(v or "none").strip().lower()
        return v if v in allowed else "none"

    @field_validator("urgency", mode="before")
    @classmethod
    def validate_urgency(cls, v):
        allowed = ("low", "medium", "high", "critical")
        v = str(v or "high").strip().lower()
        return v if v in allowed else "high"

    @field_validator("damage_classes", mode="before")
    @classmethod
    def truncate_damage_classes(cls, v):
        if not isinstance(v, list):
            return []
        return [str(c)[:100] for c in v[:20]]

    @field_validator("policyholder_name", "policy_number", "policy_type", "incident_description", mode="before")
    @classmethod
    def blank_to_none(cls, v):
        if v is None:
            return None
        v = str(v).strip()
        return v or None
```

Also add `List` to the existing `from typing import Any, Dict, List, Optional` import at the top (line 8) — check it's already there: it is (`List` is already imported), no change needed there.

- [ ] **Step 4: Extend `analyze_email_body`'s signature and compute the fused claim verdict**

In `src/analysis.py`, change the function signature (line 253) from:

```python
def analyze_email_body(body_text: str, model: Optional[str] = None, skills_path_candidates: Optional[list[str]] = None, context: Optional[dict] = None) -> Dict[str, Any]:
```

to:

```python
def analyze_email_body(body_text: str, model: Optional[str] = None, skills_path_candidates: Optional[list[str]] = None, context: Optional[dict] = None, image_bytes: Optional[bytes] = None) -> Dict[str, Any]:
```

In the same function, after the existing enrichment context loop and before the `# ── DETERMINISTIC SIGNAL SCORING ──` comment (currently line 379), add:

```python
    # CV damage detection — grounding signal for the claim verdict, same
    # pattern as the THREATFOX/ABUSEIPDB context lines above.
    cv_damage_ctx = ctx.get("cv_damage") if isinstance(ctx.get("cv_damage"), dict) else None
    if cv_damage_ctx and cv_damage_ctx.get("status") == "ok":
        if cv_damage_ctx.get("damage_detected"):
            ctx_parts.append(
                f"CV-DAMAGE-DETECTION: classes={', '.join(cv_damage_ctx.get('damage_classes', []))} "
                f"confidence={cv_damage_ctx.get('confidence')} severity={cv_damage_ctx.get('severity_estimate')}"
            )
        else:
            ctx_parts.append("CV-DAMAGE-DETECTION: no damage detected by model")
```

Then, find the two `model_output = _call_ollama_client(model, prompt)` / `_call_ollama_http(model, prompt)` calls (currently lines 457, 459) and change them to pass images through:

```python
    # Call model
    model_output = None
    try:
        try:
            model_output = _call_ollama_client(model, prompt, images=[_b64(image_bytes)] if image_bytes else None)
        except Exception:
            model_output = _call_ollama_http(model, prompt, images=[_b64(image_bytes)] if image_bytes else None)
    except Exception as e:
```

(This anticipates Task 3's `images` parameter on both call functions — Task 3 must land before this line works. If executing tasks out of order, this step will raise `TypeError: unexpected keyword argument 'images'` until Task 3 is done; the two tasks are meant to land together in the same PR.)

Add a small base64 helper right above `analyze_email_body` (before line 253):

```python
def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


```

Finally, replace the function's `return { ... }` statement (currently lines 615-627) with:

```python
    # ── CLAIM VERDICT: validate LLM output, then layer computed (never
    # LLM-trusted) fail-safe fields on top ──
    raw_claim = parsed.get("claim_verdict") if isinstance(parsed.get("claim_verdict"), dict) else {}
    try:
        validated_claim = ClaimVerdict(**raw_claim)
    except Exception:
        validated_claim = ClaimVerdict()  # all fail-safe defaults: urgency=high, everything else empty

    photo_present = bool(ctx.get("claim_photo_present"))
    has_cv_signal = bool(cv_damage_ctx and cv_damage_ctx.get("status") == "ok")
    if image_bytes is not None and has_cv_signal:
        damage_source = "both"
    elif image_bytes is not None:
        damage_source = "llm_vision"
    elif has_cv_signal:
        damage_source = "cv_model"
    else:
        damage_source = "text_only"

    required_fields = {
        "policyholder_name": validated_claim.policyholder_name,
        "policy_number": validated_claim.policy_number,
        "policy_type": validated_claim.policy_type,
        "incident_description": validated_claim.incident_description,
    }
    missing_information = [k for k, v in required_fields.items() if not v]
    if not photo_present:
        missing_information.append("photo")

    damage_detected = bool(
        (has_cv_signal and cv_damage_ctx.get("damage_detected"))
        or validated_claim.damage_classes
    )

    settlement_type = (
        "automated"
        if (
            validated_claim.severity_estimate == "minor"
            and validated_claim.urgency == "low"
            and confidence >= 0.75
            and not missing_information
        )
        else "assistive"
    )

    claim_verdict_out = {
        **validated_claim.model_dump(),
        "missing_information": missing_information,
        "damage_detected": damage_detected,
        "damage_source": damage_source,
        "settlement_type": settlement_type,
    }

    return {
        "verdict": verdict,
        "reasons": reasons,
        "confidence": confidence,
        "risk_score": llm_risk,
        "sender_risk": validated.sender_risk,
        "intent_classification": validated.intent_classification,
        "social_engineering_indicators": validated.social_engineering_indicators,
        "indicators": parsed.get("indicators"),
        "raw_model_output": model_output,
        "signal_score": det_score,
        "signal_breakdown": signal_score_result.breakdown(),
        "claim_verdict": claim_verdict_out,
    }
```

Also update the two early-return fail-safe paths so `claim_verdict` is always present in the returned dict (never a KeyError for callers). Change:

```python
        return {"verdict": "escalated", "reasons": ["analysis_failed:internal_error"], "raw_model_output": None}
```

to:

```python
        return {"verdict": "escalated", "reasons": ["analysis_failed:internal_error"], "raw_model_output": None, "claim_verdict": ClaimVerdict().model_dump() | {"missing_information": ["policyholder_name", "policy_number", "policy_type", "incident_description", "photo"], "damage_detected": False, "damage_source": "text_only", "settlement_type": "assistive"}}
```

and change both:

```python
        return {"verdict": "escalated", "reasons": ["model_output_not_json"], "raw_model_output": model_output}
```

and:

```python
        return {"verdict": "escalated", "reasons": ["model_output_failed_validation"], "raw_model_output": model_output}
```

to the same pattern (swap only the `"reasons"` value to match each site):

```python
        return {"verdict": "escalated", "reasons": ["model_output_not_json"], "raw_model_output": model_output, "claim_verdict": ClaimVerdict().model_dump() | {"missing_information": ["policyholder_name", "policy_number", "policy_type", "incident_description", "photo"], "damage_detected": False, "damage_source": "text_only", "settlement_type": "assistive"}}
```

```python
        return {"verdict": "escalated", "reasons": ["model_output_failed_validation"], "raw_model_output": model_output, "claim_verdict": ClaimVerdict().model_dump() | {"missing_information": ["policyholder_name", "policy_number", "policy_type", "incident_description", "photo"], "damage_detected": False, "damage_source": "text_only", "settlement_type": "assistive"}}
```

- [ ] **Step 5: Extend `skills.md`'s prompt with claims-assessment instructions**

In `src/skills.md`, insert this new section immediately before the `# Output Format` heading (currently line 61):

```markdown
# Claims Assessment (Insurance)

In addition to the security assessment above, extract and assess the insurance claim itself from the email body and any provided photo/CV detections.

Extract from the email text (use null if genuinely not present in the text — never invent a value):
- policyholder_name: the claimant's full name
- policy_number: the insurance policy number
- policy_type: the type of policy (e.g. "auto", "comprehensive", "collision")
- incident_description: a concise description of what happened, in your own words

Damage assessment:
- If a CV-DAMAGE-DETECTION context line is present, treat it as a grounded, verified signal — do not contradict its damage_classes without strong reason from the photo or text.
- If a photo was provided directly to you, describe what you see in full_report — this is the full report on the state of the car the operator reads.
- severity_estimate: "none" | "minor" | "moderate" | "severe" — your best judgment combining the CV detections and/or the photo and/or the text description.
- damage_classes: list of damage types identified (e.g. ["dent", "scratch", "broken headlight"]).

Urgency and settlement:
- urgency: "low" | "medium" | "high" | "critical" — how urgently this claim needs human attention. Base this on severity, any mention of injuries, and any missing or contradictory information. When uncertain, prefer the higher urgency level — never guess low.
- urgency_reasoning: one or two sentences explaining the urgency level.
- settlement_recommendation: a procedural recommendation only (e.g. "approve for direct repair, no adjuster needed", "send to adjuster for in-person inspection", "request additional photos of the damage"). NEVER propose a dollar amount — you have no policy or coverage data to price against.

```

Then replace the strict JSON schema line (currently line 65):

```
{"sender_risk": 0-100, "intent_classification": "string", "social_engineering_indicators": ["string"], "risk_score": 0-100, "confidence": 0.0-1.0, "verdict": "accepted | escalated", "reasons": ["string"]}
```

with:

```
{"sender_risk": 0-100, "intent_classification": "string", "social_engineering_indicators": ["string"], "risk_score": 0-100, "confidence": 0.0-1.0, "verdict": "accepted | escalated", "reasons": ["string"], "claim_verdict": {"policyholder_name": "string or null", "policy_number": "string or null", "policy_type": "string or null", "incident_description": "string or null", "damage_classes": ["string"], "severity_estimate": "none | minor | moderate | severe", "full_report": "string", "urgency": "low | medium | high | critical", "urgency_reasoning": "string", "settlement_recommendation": "string"}}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_analysis_claim_verdict.py -v 2>&1 | tail -30`
Expected: FAIL still on the `images=` keyword until Task 3 lands (see the note in Step 4) — if Task 3 hasn't landed yet, skip to Task 3 now and come back to this step. Once Task 3 is done: 7 passed.

- [ ] **Step 7: Commit**

```bash
git add src/analysis.py src/skills.md tests/test_analysis_claim_verdict.py
git commit -m "feat: add ClaimVerdict schema, prompt extension, and settlement fail-safe gate"
```

---

### Task 3: Vision (image) support in the Ollama call functions

**Files:**
- Modify: `src/analysis.py`

**Interfaces:**
- Produces: `_call_ollama_client(model: str, prompt: str, images: Optional[list[str]] = None) -> str` and `_call_ollama_http(model: str, prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS, images: Optional[list[str]] = None) -> str` — both backward compatible (existing 2-arg callers unaffected).

- [ ] **Step 1: Write the failing test**

Create `tests/test_analysis_vision.py`:

```python
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import analysis


def test_call_ollama_http_includes_images_in_payload():
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"response": "{}"}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        import json as _json
        captured["payload"] = _json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analysis._call_ollama_http("gemma3:4b", "prompt text", images=["ZmFrZWJhc2U2NA=="])

    assert captured["payload"]["images"] == ["ZmFrZWJhc2U2NA=="]


def test_call_ollama_http_omits_images_key_when_none():
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"response": "{}"}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        import json as _json
        captured["payload"] = _json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analysis._call_ollama_http("gemma3:4b", "prompt text")

    assert "images" not in captured["payload"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "C:\Users\moham\Automate or Die Hackathon" && python -m pytest tests/test_analysis_vision.py -v 2>&1 | tail -20`
Expected: FAIL — `TypeError: _call_ollama_http() got an unexpected keyword argument 'images'`.

- [ ] **Step 3: Add the `images` parameter to both call functions**

In `src/analysis.py`, change `_call_ollama_http`'s signature (line 71) from:

```python
def _call_ollama_http(model: str, prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
```

to:

```python
def _call_ollama_http(model: str, prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS, images: Optional[list[str]] = None) -> str:
```

And its payload construction (lines 77-84) from:

```python
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": DEFAULT_TEMPERATURE,
        "stream": False,
        "format": "json",
    }).encode("utf-8")
```

to:

```python
    payload_dict = {
        "model": model,
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": DEFAULT_TEMPERATURE,
        "stream": False,
        "format": "json",
    }
    if images:
        payload_dict["images"] = images
    payload = json.dumps(payload_dict).encode("utf-8")
```

Then change `_call_ollama_client`'s signature (line 113) from:

```python
def _call_ollama_client(model: str, prompt: str) -> str:
```

to:

```python
def _call_ollama_client(model: str, prompt: str, images: Optional[list[str]] = None) -> str:
```

And its `kwargs` construction (line 121) from:

```python
    kwargs = {"model": model, "prompt": prompt, "max_tokens": DEFAULT_MAX_TOKENS, "temperature": DEFAULT_TEMPERATURE, "stream": False, "format": "json"}
```

to:

```python
    kwargs = {"model": model, "prompt": prompt, "max_tokens": DEFAULT_MAX_TOKENS, "temperature": DEFAULT_TEMPERATURE, "stream": False, "format": "json"}
    if images:
        kwargs["images"] = images
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_analysis_vision.py -v 2>&1 | tail -20`
Expected: 2 passed.

- [ ] **Step 5: Go back and finish Task 2's Step 6 now that `images=` is supported**

Run: `python -m pytest tests/test_analysis_claim_verdict.py tests/test_analysis_vision.py -v 2>&1 | tail -40`
Expected: 9 passed total.

- [ ] **Step 6: Commit**

```bash
git add src/analysis.py tests/test_analysis_vision.py
git commit -m "feat: add vision (images) parameter to the Ollama call functions"
```

---

### Task 4: `urgency` table, permission, and DB helper functions

**Files:**
- Modify: `src/database.py`
- Test: `tests/test_urgency_table.py` (new)

**Interfaces:**
- Produces: `database.Urgency` SQLAlchemy model. `database.upsert_urgency(db: Session, email_id: int, claim_verdict: dict) -> Optional[Urgency]`. `database.get_urgency_queue(db: Session, limit: int = 100) -> list[Urgency]` (sorted critical-first). `database.confirm_settlement(db: Session, email_id: int, actor: str) -> Optional[Urgency]`. New permission key `"claims.settle"` in `ALL_PERMISSIONS`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_urgency_table.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import (
    Base, Urgency, Email, SessionLocal, engine,
    upsert_urgency, get_urgency_queue, confirm_settlement,
    ALL_PERMISSIONS,
)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.query(Urgency).delete()
    session.query(Email).delete()
    session.commit()
    session.close()


def _make_email(db, idempotency_key="urgency-test-1"):
    email = Email(idempotency_key=idempotency_key, raw_sha256="a" * 64, status="recu")
    db.add(email)
    db.commit()
    db.refresh(email)
    return email


def test_claims_settle_permission_exists():
    assert "claims.settle" in ALL_PERMISSIONS


def test_upsert_urgency_creates_row_with_correct_priority(db_session):
    email = _make_email(db_session)
    claim_verdict = {
        "urgency": "critical", "urgency_reasoning": "severe damage",
        "missing_information": [], "settlement_type": "assistive",
        "settlement_recommendation": "send to adjuster",
    }
    row = upsert_urgency(db_session, email.id, claim_verdict)
    assert row.level == "critical"
    assert row.priority == 3
    assert row.settlement_confirmed is False


def test_upsert_urgency_updates_existing_row(db_session):
    email = _make_email(db_session)
    upsert_urgency(db_session, email.id, {"urgency": "low"})
    updated = upsert_urgency(db_session, email.id, {"urgency": "high"})
    assert updated.level == "high"
    assert updated.priority == 2
    count = db_session.query(Urgency).filter(Urgency.email_id == email.id).count()
    assert count == 1  # updated, not duplicated


def test_upsert_urgency_returns_none_for_empty_claim_verdict(db_session):
    email = _make_email(db_session)
    assert upsert_urgency(db_session, email.id, {}) is None
    assert upsert_urgency(db_session, email.id, None) is None


def test_get_urgency_queue_sorts_critical_first(db_session):
    e1 = _make_email(db_session, "urgency-low")
    e2 = _make_email(db_session, "urgency-critical")
    e3 = _make_email(db_session, "urgency-medium")
    upsert_urgency(db_session, e1.id, {"urgency": "low"})
    upsert_urgency(db_session, e2.id, {"urgency": "critical"})
    upsert_urgency(db_session, e3.id, {"urgency": "medium"})
    queue = get_urgency_queue(db_session)
    levels = [r.level for r in queue]
    assert levels == ["critical", "medium", "low"]


def test_confirm_settlement_sets_fields(db_session):
    email = _make_email(db_session)
    upsert_urgency(db_session, email.id, {"urgency": "low", "settlement_type": "automated"})
    confirmed = confirm_settlement(db_session, email.id, "alice")
    assert confirmed.settlement_confirmed is True
    assert confirmed.settlement_confirmed_by == "alice"
    assert confirmed.settlement_confirmed_at is not None


def test_confirm_settlement_returns_none_when_no_row(db_session):
    email = _make_email(db_session)
    assert confirm_settlement(db_session, email.id, "alice") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd "C:\Users\moham\Automate or Die Hackathon" && python -m pytest tests/test_urgency_table.py -v 2>&1 | tail -20`
Expected: FAIL — `ImportError: cannot import name 'Urgency' from 'database'`.

- [ ] **Step 3: Add the `Urgency` model**

In `src/database.py`, immediately after the `AuditLog` class (after line 176, before `class AnalystFeedback(Base):`), add:

```python
class Urgency(Base):
    """Per-claim urgency classification and settlement recommendation.

    One row per email/claim. `priority` is a plain int derived from `level`
    so the triage queue sorts with a simple ORDER BY, no enum-sort hacks.
    """

    __tablename__ = "urgency"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, unique=True, index=True)
    level = Column(String(20), nullable=False)              # low/medium/high/critical
    priority = Column(Integer, nullable=False, index=True)   # 0-3, derived from level
    reasoning = Column(Text, nullable=True)
    missing_information = Column(JSONB, nullable=True)
    settlement_type = Column(String(20), nullable=True)      # assistive/automated
    settlement_recommendation = Column(Text, nullable=True)
    settlement_confirmed = Column(Boolean, default=False)
    settlement_confirmed_by = Column(String(255), nullable=True)
    settlement_confirmed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    email = relationship("Email")
```

- [ ] **Step 4: Add the `claims.settle` permission**

In `src/database.py`, in the `ALL_PERMISSIONS` dict (currently lines 291-311), add a new line right after `"detonation.manual": True,` (line 310):

```python
    "claims.settle": True,       # confirm an assistive/automated settlement recommendation
```

Leave `ANALYST_PERMISSIONS` untouched (matches the existing `detonation.manual` pattern — off by default for analyst, admin assigns per-user via the existing permission editor).

- [ ] **Step 5: Add the helper functions**

In `src/database.py`, immediately after `add_audit_entry` (after line 550, before `def is_blocked`), add:

```python
_URGENCY_PRIORITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def upsert_urgency(db: Session, email_id: int, claim_verdict: Optional[dict]) -> Optional["Urgency"]:
    """Create or update the urgency row for a claim from its claim_verdict dict.

    Returns None if claim_verdict is empty/missing — not every processed
    email is a claim with a verdict worth tracking in the triage queue.
    """
    if not claim_verdict:
        return None
    level = claim_verdict.get("urgency", "high")
    priority = _URGENCY_PRIORITY.get(level, 2)
    existing = db.query(Urgency).filter(Urgency.email_id == email_id).first()
    if existing:
        existing.level = level
        existing.priority = priority
        existing.reasoning = claim_verdict.get("urgency_reasoning")
        existing.missing_information = claim_verdict.get("missing_information")
        existing.settlement_type = claim_verdict.get("settlement_type")
        existing.settlement_recommendation = claim_verdict.get("settlement_recommendation")
        db.commit()
        db.refresh(existing)
        return existing
    row = Urgency(
        email_id=email_id,
        level=level,
        priority=priority,
        reasoning=claim_verdict.get("urgency_reasoning"),
        missing_information=claim_verdict.get("missing_information"),
        settlement_type=claim_verdict.get("settlement_type"),
        settlement_recommendation=claim_verdict.get("settlement_recommendation"),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_urgency_queue(db: Session, limit: int = 100) -> list["Urgency"]:
    """Triage queue, critical-first."""
    return (
        db.query(Urgency)
        .order_by(Urgency.priority.desc(), Urgency.created_at.asc())
        .limit(limit)
        .all()
    )


def confirm_settlement(db: Session, email_id: int, actor: str) -> Optional["Urgency"]:
    """Human confirmation of a settlement recommendation (assistive or automated)."""
    row = db.query(Urgency).filter(Urgency.email_id == email_id).first()
    if not row:
        return None
    row.settlement_confirmed = True
    row.settlement_confirmed_by = actor
    row.settlement_confirmed_at = utcnow()
    db.commit()
    db.refresh(row)
    return row
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_urgency_table.py -v 2>&1 | tail -30`
Expected: 7 passed. (`Base.metadata.create_all` in the fixture creates the new `urgency` table on the dev database the first time this runs.)

- [ ] **Step 7: Run the full test suite to check for regressions**

Run: `python -m pytest -q 2>&1 | tail -15`
Expected: prior pass count + 7.

- [ ] **Step 8: Commit**

```bash
git add src/database.py tests/test_urgency_table.py
git commit -m "feat: add urgency table, claims.settle permission, and triage queue helpers"
```

---

### Task 5: Wire the pipeline — pass the photo to the LLM, persist urgency

**Files:**
- Modify: `src/main.py`
- Test: `tests/test_main_claim_pipeline.py` (new)

**Interfaces:**
- Consumes: Task 1's `cv_damage_assessment` (from extraction results), Task 2's `analyze_email_body(..., image_bytes=...)` and `context["cv_damage"]`/`context["claim_photo_present"]`, Task 4's `upsert_urgency`.
- Produces: after `save_email`, an `Urgency` row exists for any email whose LLM analysis produced a `claim_verdict`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_main_claim_pipeline.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from unittest.mock import patch


def test_find_claim_photo_picks_first_image_attachment():
    import main

    attachments = [
        {"original_name": "invoice.pdf", "stored_path": "/tmp/invoice.pdf"},
        {"original_name": "damage.jpg", "stored_path": "/tmp/damage.jpg"},
    ]
    result = main._find_claim_photo(attachments)
    assert result is not None
    assert result["original_name"] == "damage.jpg"


def test_find_claim_photo_returns_none_when_no_image():
    import main

    attachments = [{"original_name": "invoice.pdf", "stored_path": "/tmp/invoice.pdf"}]
    assert main._find_claim_photo(attachments) is None


def test_find_claim_photo_returns_none_for_empty_list():
    import main

    assert main._find_claim_photo([]) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "C:\Users\moham\Automate or Die Hackathon" && python -m pytest tests/test_main_claim_pipeline.py -v 2>&1 | tail -20`
Expected: FAIL — `AttributeError: module 'main' has no attribute '_find_claim_photo'`.

- [ ] **Step 3: Add the `_find_claim_photo` helper**

In `src/main.py`, `Path` is not currently imported (confirmed: no `pathlib` import exists in this file). Change the top of the file (line 1) from:

```python
import os
import sys
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
```

to:

```python
import os
import sys
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

from detonation_config import IMAGE_EXTENSIONS
```

Then, near the top of the file (module level, after the imports, before the first function definition), add:

```python
def _find_claim_photo(attachments: list) -> "dict | None":
    """First image attachment in the list, or None. Used to pick the photo
    passed to the LLM's vision input for claim-photo assessment."""
    for att in attachments or []:
        name = (att.get("original_name") or "").lower()
        if any(name.endswith(ext) for ext in IMAGE_EXTENSIONS):
            return att
    return None
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_main_claim_pipeline.py -v 2>&1 | tail -20`
Expected: 3 passed.

- [ ] **Step 5: Wire the photo + CV context into the LLM call**

In `src/main.py`, in the LLM analysis block (the code around line 671-702 read earlier), change the `context = {...}` construction and the `analyze_email_body(...)` call. Currently:

```python
                        context = {
                            "headers": parsed.get("headers", {}),
                            "attachments": parsed.get("attachments", []),
                            "enrichment": enrichment_data
                        }
                        llm_res = analyze_email_body(llm_input, context=context)
```

Replace with:

```python
                        claim_photo = _find_claim_photo(parsed.get("attachments", []))
                        photo_bytes = None
                        cv_damage_result = None
                        if claim_photo and claim_photo.get("stored_path"):
                            try:
                                photo_bytes = Path(claim_photo["stored_path"]).read_bytes()
                            except Exception:
                                photo_bytes = None
                            for er in (parsed.get("extraction", {}).get("results") or []):
                                if er.get("filename") == claim_photo.get("original_name"):
                                    cv_damage_result = er.get("cv_damage_assessment")
                                    break

                        context = {
                            "headers": parsed.get("headers", {}),
                            "attachments": parsed.get("attachments", []),
                            "enrichment": enrichment_data,
                            "claim_photo_present": claim_photo is not None,
                            "cv_damage": cv_damage_result,
                        }
                        llm_res = analyze_email_body(llm_input, context=context, image_bytes=photo_bytes)
```

- [ ] **Step 6: Persist the urgency row after the email is saved**

In `src/main.py`, find `saved = _save_email(db, email_data)` (currently line 792). Immediately after that line, add:

```python
                    try:
                        from database import upsert_urgency
                        claim_verdict = (parsed.get("llm_analysis") or {}).get("claim_verdict")
                        upsert_urgency(db, saved.id, claim_verdict)
                    except Exception as e:
                        print(f"[URGENCY] Failed to persist urgency row: {e} (verdict/email save unaffected)")
```

- [ ] **Step 7: Run the full test suite**

Run: `python -m pytest -q 2>&1 | tail -15`
Expected: prior pass count + 3, no regressions. (This step only added a pure helper function and two call-site changes gated by existing try/except blocks — the live-Ollama e2e test in `tests/test_pipeline_e2e.py` is unaffected since `image_bytes` defaults to `None` and `context` additions are additive keys.)

- [ ] **Step 8: Commit**

```bash
git add src/main.py tests/test_main_claim_pipeline.py
git commit -m "feat: wire claim photo + CV signal into the LLM call, persist urgency after save"
```

---

### Task 6: Backend API — urgency queue list + settlement confirmation

**Files:**
- Modify: `src/routers/emails.py`
- Test: `tests/test_urgency_api.py` (new)

**Interfaces:**
- Produces: `GET /api/urgency` (permission `emails.view`) → `{"items": [{"email_id", "level", "priority", "reasoning", "missing_information", "settlement_type", "settlement_recommendation", "settlement_confirmed", "subject", "sender", "status"}, ...]}`, sorted critical-first. `POST /api/emails/{email_id}/settlement/confirm` (permission `claims.settle`) → `{"success": true, "email_id": int, "settlement_confirmed": true}`, 404 if no urgency row exists for that email.

**Note on testing convention:** this repo does not use `fastapi.testclient.TestClient` anywhere (confirmed: no test file imports it). The established pattern for permission-gated endpoint functions (see `tests/test_cape_dashboard.py::test_run_window_409_when_window_active` and neighbors) is to call the endpoint function directly — bypassing FastAPI's `Depends()` injection entirely — passing `user=SimpleNamespace(username="...")`, plus a separate lightweight test that just checks the router's `.routes` list for path/permission registration. This task follows that same convention.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_urgency_api.py`:

```python
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import Base, Urgency, Email, SessionLocal, engine, upsert_urgency


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.query(Urgency).delete()
    session.query(Email).delete()
    session.commit()
    session.close()


def test_urgency_routes_registered():
    from routers.emails import emails_router
    paths = {getattr(r, "path", "") for r in emails_router.routes}
    assert "/api/urgency" in paths
    assert "/api/emails/{email_id}/settlement/confirm" in paths


def test_get_urgency_queue_api_returns_sorted_items(db_session):
    from routers.emails import get_urgency_queue_api

    e1 = Email(idempotency_key="api-test-low", raw_sha256="a" * 64, status="recu")
    e2 = Email(idempotency_key="api-test-critical", raw_sha256="b" * 64, status="recu")
    db_session.add_all([e1, e2])
    db_session.commit()
    db_session.refresh(e1)
    db_session.refresh(e2)
    upsert_urgency(db_session, e1.id, {"urgency": "low"})
    upsert_urgency(db_session, e2.id, {"urgency": "critical"})

    out = get_urgency_queue_api(user=SimpleNamespace(username="admin"))
    levels = [i["level"] for i in out["items"] if i["email_id"] in (e1.id, e2.id)]
    assert levels.index("critical") < levels.index("low")


def test_confirm_settlement_api_sets_audit_entry(db_session, monkeypatch):
    from routers.emails import confirm_settlement_api
    import database

    email = Email(idempotency_key="api-test-confirm", raw_sha256="c" * 64, status="recu")
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)
    upsert_urgency(db_session, email.id, {"urgency": "low", "settlement_type": "automated"})

    audits = []
    original_add_audit = database.add_audit_entry
    def _spy_add_audit(db, **kw):
        audits.append(kw)
        return original_add_audit(db, **kw)
    monkeypatch.setattr(database, "add_audit_entry", _spy_add_audit)

    out = confirm_settlement_api(email.id, user=SimpleNamespace(username="admin"))
    assert out["settlement_confirmed"] is True
    assert audits and audits[0]["action"] == "settlement_confirm"
    assert audits[0]["actor"] == "admin"


def test_confirm_settlement_api_404_when_no_urgency_row(db_session):
    from fastapi import HTTPException
    from routers.emails import confirm_settlement_api

    email = Email(idempotency_key="api-test-no-urgency", raw_sha256="d" * 64, status="recu")
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)

    try:
        confirm_settlement_api(email.id, user=SimpleNamespace(username="admin"))
        assert False, "expected HTTPException 404"
    except HTTPException as e:
        assert e.status_code == 404


def test_get_email_api_includes_settlement_confirmed(db_session):
    import asyncio
    from routers.emails import api_get_email

    email = Email(idempotency_key="api-test-detail-urgency", raw_sha256="e" * 64, status="recu")
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)
    upsert_urgency(db_session, email.id, {"urgency": "low", "settlement_type": "assistive"})

    out = asyncio.run(api_get_email(email.id, user=SimpleNamespace(username="admin")))
    assert out["settlement_confirmed"] is False

    from database import confirm_settlement
    confirm_settlement(db_session, email.id, "admin")
    out2 = asyncio.run(api_get_email(email.id, user=SimpleNamespace(username="admin")))
    assert out2["settlement_confirmed"] is True


def test_get_email_api_settlement_confirmed_false_when_no_urgency_row(db_session):
    import asyncio
    from routers.emails import api_get_email

    email = Email(idempotency_key="api-test-detail-no-urgency", raw_sha256="f" * 64, status="recu")
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)

    out = asyncio.run(api_get_email(email.id, user=SimpleNamespace(username="admin")))
    assert out["settlement_confirmed"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "C:\Users\moham\Automate or Die Hackathon" && python -m pytest tests/test_urgency_api.py -v 2>&1 | tail -20`
Expected: FAIL — `ImportError: cannot import name 'get_urgency_queue_api' from 'routers.emails'`.

- [ ] **Step 3: Add the endpoints**

In `src/routers/emails.py`, at the end of the file, add:

```python

@emails_router.get("/api/urgency")
def get_urgency_queue_api(
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    from database import SessionLocal, get_urgency_queue, Email as _Email
    db = SessionLocal()
    try:
        rows = get_urgency_queue(db)
        out = []
        for r in rows:
            email = db.query(_Email).filter(_Email.id == r.email_id).first()
            out.append({
                "email_id": r.email_id,
                "level": r.level,
                "priority": r.priority,
                "reasoning": r.reasoning,
                "missing_information": r.missing_information,
                "settlement_type": r.settlement_type,
                "settlement_recommendation": r.settlement_recommendation,
                "settlement_confirmed": r.settlement_confirmed,
                "subject": email.subject if email else None,
                "sender": email.sender if email else None,
                "status": email.status if email else None,
            })
        return {"items": out}
    finally:
        db.close()


@emails_router.post("/api/emails/{email_id}/settlement/confirm")
def confirm_settlement_api(
    email_id: int,
    user: AuthenticatedUser = Depends(require_permission("claims.settle")),
):
    from database import SessionLocal, confirm_settlement, add_audit_entry
    db = SessionLocal()
    try:
        row = confirm_settlement(db, email_id, user.username)
        if not row:
            raise HTTPException(404, "No urgency/settlement record for this claim")
        add_audit_entry(
            db, action="settlement_confirm", actor=user.username,
            email_id=email_id,
            details={"settlement_type": row.settlement_type, "recommendation": row.settlement_recommendation},
        )
        return {"success": True, "email_id": email_id, "settlement_confirmed": True}
    finally:
        db.close()
```

- [ ] **Step 4: Extend `GET /api/emails/{id}` to include the settlement-confirmed flag**

Task 7's detail-page UI needs to know whether a claim's settlement has already been confirmed (to hide the confirm button), and that flag lives on the `Urgency` row, not `Email`. In `src/routers/emails.py`, in `api_get_email` (the function read above), add this lookup right before the `return {` statement (currently right after the `domain_in_whitelist` line):

```python
        from database import Urgency
        urgency_row = db.query(Urgency).filter(Urgency.email_id == email_id).first()
```

Then add one new key to the returned dict, alongside the existing `"llm_result": email.llm_result,` line:

```python
            "settlement_confirmed": bool(urgency_row.settlement_confirmed) if urgency_row else False,
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_urgency_api.py -v 2>&1 | tail -30`
Expected: 6 passed.

- [ ] **Step 6: Run the full test suite**

Run: `python -m pytest -q 2>&1 | tail -15`
Expected: prior pass count + 6, no regressions.

- [ ] **Step 7: Commit**

```bash
git add src/routers/emails.py tests/test_urgency_api.py
git commit -m "feat: add urgency queue and settlement confirmation API endpoints"
```

---

### Task 7: Detail page UI — two-section verdict card + settlement confirm button

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js`

**Interfaces:**
- Consumes: `e.llm_result` (already returned by `GET /api/emails/{id}`, now containing `sender_risk`/`intent_classification`/`social_engineering_indicators` at the top level and a nested `claim_verdict` object — both from Task 2's `analyze_email_body` return shape). `POST /api/emails/{id}/settlement/confirm` from Task 6.

- [ ] **Step 1: Add a `renderVerdictSections` helper and a settlement-confirm action**

In `src/dashboard/static/js/dashboard.js`, immediately before `async function loadEmailDetail(emailId) {` (currently line 448), add:

```javascript
function renderVerdictSections(e) {
    const llm = e.llm_result;
    if (!llm) return '';

    const securityHtml = `
        <div class="detail-section" style="grid-column: 1 / -1">
            <h3>🔒 Security Concerns</h3>
            <div class="detail-row"><span class="detail-label">Sender Risk</span><span class="detail-value">${parseInt(llm.sender_risk) || 0}/100</span></div>
            <div class="detail-row"><span class="detail-label">Intent</span><span class="detail-value">${esc(llm.intent_classification) || '—'}</span></div>
            ${(llm.social_engineering_indicators || []).length > 0 ? `
                <div class="detail-row"><span class="detail-label">Indicators</span><span class="detail-value">${(llm.social_engineering_indicators || []).map(esc).join(', ')}</span></div>
            ` : ''}
        </div>`;

    const cv = llm.claim_verdict;
    if (!cv) return securityHtml;

    const urgencyColors = { low: '#7f8c8d', medium: '#2980b9', high: '#e67e22', critical: '#e74c3c' };
    const urgencyColor = urgencyColors[cv.urgency] || '#7f8c8d';
    const missing = cv.missing_information || [];

    const verdictHtml = `
        <div class="detail-section" style="grid-column: 1 / -1">
            <h3>🚗 Verdict</h3>
            <div class="detail-row">
                <span class="detail-label">Urgency</span>
                <span class="detail-value"><span class="badge" style="background:${urgencyColor};color:white">${esc(cv.urgency)}</span></span>
            </div>
            <div class="detail-row"><span class="detail-label">Urgency reasoning</span><span class="detail-value">${esc(cv.urgency_reasoning) || '—'}</span></div>
            <div class="detail-row"><span class="detail-label">Severity</span><span class="detail-value">${esc(cv.severity_estimate) || 'none'}</span></div>
            ${(cv.damage_classes || []).length > 0 ? `
                <div class="detail-row"><span class="detail-label">Damage detected</span><span class="detail-value">${(cv.damage_classes || []).map(esc).join(', ')}</span></div>
            ` : ''}
            <div class="detail-row"><span class="detail-label">Damage source</span><span class="detail-value">${esc(cv.damage_source) || '—'}</span></div>
            ${cv.full_report ? `
                <div class="detail-row"><span class="detail-label">Full report</span><span class="detail-value">${esc(cv.full_report)}</span></div>
            ` : ''}
            ${missing.length > 0 ? `
                <div class="detail-row"><span class="detail-label" style="color:var(--color-escalated,#f59e0b)">Missing information</span><span class="detail-value" style="color:var(--color-escalated,#f59e0b)">${missing.map(esc).join(', ')}</span></div>
            ` : ''}
            <div class="detail-row">
                <span class="detail-label">Settlement recommendation</span>
                <span class="detail-value">
                    <span class="badge ${cv.settlement_type === 'automated' ? 'accepted' : 'recu'}" style="margin-right:8px">${esc(cv.settlement_type)}</span>
                    ${esc(cv.settlement_recommendation) || '—'}
                </span>
            </div>
            <div class="action-bar" style="margin-top:12px">
                ${userCan('claims.settle') && !e.settlement_confirmed ? `
                    <button class="btn btn-primary btn-sm" data-action="confirm-settlement" data-id="${parseInt(e.id)}">✓ Confirm settlement</button>
                ` : e.settlement_confirmed ? `<span style="color:var(--text-muted);font-size:0.85rem">Settlement confirmed</span>` : ''}
            </div>
        </div>`;

    return securityHtml + verdictHtml;
}

async function confirmSettlement(emailId) {
    try {
        await API.post(`/api/emails/${emailId}/settlement/confirm`);
        showToast('Settlement confirmed', 'success');
        loadEmailDetail(emailId);
    } catch (err) {
        showToast(`Confirm failed: ${err.message}`, 'error');
    }
}
```

- [ ] **Step 2: Splice the new sections into `loadEmailDetail`'s rendering**

In `src/dashboard/static/js/dashboard.js`, in `loadEmailDetail` (the `container.innerHTML = \`...\`` template currently at lines 516-569), find:

```javascript
            ${e.llm_reasoning ? `
                <div class="reasoning-card">
                    <h3>🤖 LLM Reasoning</h3>
                    <div class="reasoning-text">${esc(e.llm_reasoning)}</div>
                </div>
            ` : ''}
```

and replace it with:

```javascript
            <div class="detail-grid">
                ${renderVerdictSections(e)}
            </div>

            ${e.llm_reasoning ? `
                <div class="reasoning-card">
                    <h3>🤖 LLM Reasoning</h3>
                    <div class="reasoning-text">${esc(e.llm_reasoning)}</div>
                </div>
            ` : ''}
```

- [ ] **Step 3: Register the new action**

In `src/dashboard/static/js/dashboard.js`, near the other `registerAction(...)` calls (after `registerAction('open-override-modal', ...)`, currently line 1288), add:

```javascript
registerAction('confirm-settlement', (el) => confirmSettlement(parseInt(el.dataset.id)));
```

- [ ] **Step 4: Manually verify in the browser**

Run the dashboard (`start.bat` or the project's normal dev-server command), log in, open an email detail page for a record that has an `llm_result.claim_verdict` (any claim processed after Task 5 landed — for a quick check without waiting on a live pipeline run, you can also manually set one row's `llm_result` via `psql` to include a `claim_verdict` object matching Task 2's shape). Confirm: the Security Concerns and Verdict sections render as two separate cards, the urgency badge shows the right color, and — if logged in as a user with `claims.settle` — the confirm button appears and clicking it shows a success toast and makes the button disappear on reload.

- [ ] **Step 5: Commit**

```bash
git add src/dashboard/static/js/dashboard.js
git commit -m "feat: render two-section verdict card and settlement confirmation on the detail page"
```

---

### Task 8: Urgency Queue dashboard page

**Files:**
- Create: `src/dashboard/templates/urgency_queue.html`
- Modify: `src/dashboard/templates/base.html`
- Modify: `src/routers/dashboard.py`
- Modify: `src/dashboard/static/js/dashboard.js`

**Interfaces:**
- Consumes: `GET /api/urgency` from Task 6.
- Produces: a new page at `/urgency-queue`, nav-linked, visible to users with `emails.view`.

- [ ] **Step 1: Add the page route**

In `src/routers/dashboard.py`, after `dashboard_manual_detonation` (after line 103), add:

```python

@dashboard_router.get("/urgency-queue", response_class=HTMLResponse)
async def dashboard_urgency_queue(request: Request):
    ctx = _ctx(request, "urgency_queue")
    if not _has_perm(ctx, "emails.view"):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "urgency_queue.html", ctx)
```

- [ ] **Step 2: Add the nav link**

In `src/dashboard/templates/base.html`, immediately after the Inbox Queue nav link's closing `{% endif %}` (currently line 34, right after the `</a>` for `/`), add:

```html
                {% if role == 'admin' or permissions.get('emails.view', False) %}
                <a href="/urgency-queue" class="nav-link {% if active_page == 'urgency_queue' %}active{% endif %}">
                    <span class="nav-icon">🚨</span>
                    <span>Urgency Queue</span>
                </a>
                {% endif %}
```

- [ ] **Step 3: Create the template**

Create `src/dashboard/templates/urgency_queue.html`:

```html
{% extends "base.html" %}
{% block title %}Urgency Queue — ImaniIA{% endblock %}

{% block content %}
<div class="page-header">
    <div>
        <h2>Urgency Queue</h2>
        <p class="page-subtitle">Claims sorted critical-first</p>
    </div>
</div>

<div class="table-container">
    <table>
        <thead>
            <tr>
                <th>Urgency</th>
                <th>Subject</th>
                <th>Sender</th>
                <th>Missing Info</th>
                <th>Settlement</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="urgency-table-body">
            <tr><td colspan="6" class="loading-overlay"><div class="spinner"></div> Loading…</td></tr>
        </tbody>
    </table>
</div>
{% endblock %}

{% block scripts %}
<script nonce="{{ csp_nonce }}">document.addEventListener('DOMContentLoaded', () => loadUrgencyQueue());</script>
{% endblock %}
```

- [ ] **Step 4: Add `loadUrgencyQueue()` to dashboard.js**

In `src/dashboard/static/js/dashboard.js`, near `loadEmailDetail` (add it right before that function, before line 448), add:

```javascript
const urgencyColorsMap = { low: '#7f8c8d', medium: '#2980b9', high: '#e67e22', critical: '#e74c3c' };

async function loadUrgencyQueue() {
    const tbody = document.getElementById('urgency-table-body');
    if (!tbody) return;
    try {
        const data = await API.get('/api/urgency');
        const items = data.items || [];
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No claims in the urgency queue.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(i => `
            <tr data-action="open-email" data-id="${parseInt(i.email_id)}" style="cursor:pointer">
                <td><span class="badge" style="background:${urgencyColorsMap[i.level] || '#7f8c8d'};color:white">${esc(i.level)}</span></td>
                <td>${esc(truncate(i.subject, 60)) || '—'}</td>
                <td>${esc(i.sender) || '—'}</td>
                <td>${(i.missing_information || []).length > 0 ? esc((i.missing_information || []).join(', ')) : '—'}</td>
                <td>
                    <span class="badge ${i.settlement_type === 'automated' ? 'accepted' : 'recu'}">${esc(i.settlement_type) || '—'}</span>
                    ${i.settlement_confirmed ? ' <span style="color:var(--text-muted);font-size:0.75rem">confirmed</span>' : ''}
                </td>
                <td data-action="noop"><a href="/email/${parseInt(i.email_id)}" class="btn btn-outline btn-sm">View</a></td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Error: ${esc(err.message)}</td></tr>`;
    }
}
```

- [ ] **Step 5: Manually verify in the browser**

Log in, click "Urgency Queue" in the nav, confirm the page loads, shows claims sorted critical-first (or the empty state if none exist yet), and clicking "View" navigates to that email's detail page.

- [ ] **Step 6: Commit**

```bash
git add src/routers/dashboard.py src/dashboard/templates/base.html src/dashboard/templates/urgency_queue.html src/dashboard/static/js/dashboard.js
git commit -m "feat: add Urgency Queue dashboard page"
```

---

### Task 9: Full-suite verification and wrap-up

**Files:** none (verification only)

- [ ] **Step 1: Run the entire test suite**

Run: `cd "C:\Users\moham\Automate or Die Hackathon" && python -m pytest -q 2>&1 | tail -20`
Expected: 84 passed, 1 failed. Baseline was 55 passed / 5 failed. Task 1 turns the 4 already-written CV-damage failures into passes (59/1). Tasks 2-6 add 7+2+7+3+6 = 25 new passing tests (84/1). The 1 remaining failure is the pre-existing, unrelated CSP nonce test (`test_csp_script_src_is_nonce_based_not_unsafe_inline`) — out of scope for this plan, verified in Step 2 below to be the same failure as before this plan started.

- [ ] **Step 2: If the CSP test is the only failure, confirm it's the known pre-existing one**

Run: `python -m pytest tests/test_csp_no_inline_handlers.py -v 2>&1 | tail -15`
Expected: same failure message seen before this plan started (`script-src still contains 'unsafe-inline'`) — confirms nothing in this plan touched CSP.

- [ ] **Step 3: Manual end-to-end smoke test**

Start the dashboard, submit a test claim email with a car-damage photo attachment through the normal ingestion path (or `python src/manual_detonation.py`-adjacent test flow / existing test fixtures under `data/samples/` if present), and confirm: the detail page shows both verdict sections, the urgency queue lists the claim at the right priority, and confirming settlement moves `settlement_confirmed` to true and appears in the audit log (`/audit` page).

- [ ] **Step 4: Update CLAUDE.md's build log**

Add an entry to the `## Build Log` section of `CLAUDE.md` (this file is gitignored per the rebrand plan's constraints — edit it locally, do not `git add` it) summarizing what shipped: CV model wiring, two-section verdict, urgency table + queue page, settlement confirmation gate, and the pre-existing CSP test status.
