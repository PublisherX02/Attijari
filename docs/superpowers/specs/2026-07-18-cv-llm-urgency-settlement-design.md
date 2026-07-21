# CV + LLM Claim Verdict, Urgency Queue & Settlement — Design

**Date:** 2026-07-18
**Context:** "Automate Or Die" hackathon (ImaniIA), building on the rebrand landed earlier today (`2026-07-17-imania-hackathon-rebrand-design.md` / `-rebrand.md`)
**Depends on:** the rebrand's Task 5 stub (`_local_cv_damage`, `CV_DAMAGE_MODEL_PATH`, `tests/test_extraction_cv_damage.py`) — already present but unimplemented; a real trained model already exists at `models/car_damage_yolov8.pt` (52MB YOLOv8, gitignored).

## Goal

Wire the car-damage CV model to the LLM so a claim photo gets assessed two ways — the deterministic detector and the LLM's own vision read — fused into one report. Split the LLM's structured output into two named sections (`Security Concerns`, already exists; `Verdict`, new — damage report + claim decision + settlement recommendation). Add a DB-backed urgency classification with a sorted triage queue. Add an assistive-or-automated settlement recommendation that always requires human confirmation, with automation gated to only the clearest minor cases.

## Non-goals

- No dollar-amount settlement figures — the system has no policy/coverage/claim-amount data to price against. Settlement is a procedural recommendation ("approve for direct repair" / "send to adjuster" / "request more photos"), not a payout number.
- No renames to existing `Verdict` Pydantic field names (`risque_expediteur`, `score_risque`, etc.) — per the rebrand plan's Global Constraints, these are consumed by `src/experiments/e1..e9`. New fields are additive, nested under a new sub-model.
- No new claim-intake UI/form. All required fields (name, policy number, policy type, description) are expected to already be present in the inbound email body/subject text and are extracted by the LLM, not entered separately.
- No changes to the existing sandbox/detonation security layer — untouched.

## Architecture

Single LLM call does extraction + fusion; the CV model grounds it rather than replacing it.

```text
Extraction stage (existing, src/extraction.py, images block)
    │
    ├─ _local_cv_damage(content) → runs models/car_damage_yolov8.pt (already
    │    stubbed by the rebrand plan's Task 5, just needs the real YOLO call
    │    filled in — the fail-safe unavailable/error contract is unchanged)
    │    → { damage_detected, damage_classes, confidence, severity_estimate }
    │    → stored in result["cv_damage_assessment"], same as today
    │
    ▼
Stage 5 — LLM analysis (src/analysis.py, analyze_email_body)
    │
    ├─ Prompt gains a new structured-signals block, same pattern as the
    │   existing tesseract/yara signal injection: the CV model's detections
    │   are serialized into the prompt as text context ("A deterministic
    │   damage detector found: dent (0.87), scratch (0.62)...").
    │
    ├─ NEW: if a qualifying image attachment exists, its bytes are also
    │   passed to Ollama via the `images` parameter (gemma3:4b is vision-
    │   capable) — the LLM sees the actual photo, not just the CV summary.
    │
    ├─ NEW: the same call extracts claim intake fields (policyholder name,
    │   policy number, policy type, incident description) from the email
    │   body/subject text as part of its structured output. One LLM call
    │   handles extraction + fusion + verdict — no separate parsing step.
    │
    └─ Output: FullVerdict { security_concerns, claim_verdict } — see schema below.
    │
    ▼
Persistence: emails.llm_result (JSONB, unchanged column) stores the full
FullVerdict. A NEW urgency table gets one row per claim, populated from
claim_verdict.urgency / .settlement_* — see below.
    │
    ▼
Dashboard: existing detail page renders both sections; NEW Urgency Queue
page lists claims sorted critical-first; settlement recommendation gets a
confirm button (human-in-the-loop, same pattern as existing accept/reject).
```

Why ground the LLM with a deterministic detector instead of only using
vision: a YOLO detection is reproducible and auditable (fixed classes,
confidence scores, no prompt sensitivity) — same reasoning as why OCR/YARA
are separate deterministic extraction steps rather than asking the LLM to
read text or match patterns itself. The LLM still sees the photo directly
(per your requirement) but its damage-class claims are checked against, not
solely sourced from, an ungrounded vision call.

## Schema

### Pydantic (`src/analysis.py` or wherever `Verdict` currently lives)

```python
class SecurityConcerns(BaseModel):
    # unchanged — exactly today's fields, renamed to nothing
    risque_expediteur: int
    classification_intention: str
    indices_ingenierie_sociale: list[str]
    resume_piece_jointe: str
    confiance: float

class ClaimVerdict(BaseModel):
    # claim intake, extracted from email text
    policyholder_name: Optional[str]
    policy_number: Optional[str]
    policy_type: Optional[str]
    incident_description: Optional[str]
    missing_information: list[str]        # e.g. ["policy_number", "photo"]

    # damage assessment
    damage_detected: bool
    damage_classes: list[str]
    damage_source: Literal['cv_model', 'llm_vision', 'both', 'text_only']
    severity_estimate: Literal['none', 'minor', 'moderate', 'severe']
    full_report: str                      # the "full report on the state of the car"

    # urgency
    urgency: Literal['low', 'medium', 'high', 'critical']
    urgency_reasoning: str

    # settlement
    settlement_type: Literal['assistive', 'automated']
    settlement_recommendation: str        # procedural action, never a $ amount

    # decision
    verdict: Literal['accepter', 'rejeter', 'escalader']
    raisonnement: str

class FullVerdict(BaseModel):
    security_concerns: SecurityConcerns
    claim_verdict: ClaimVerdict
    score_risque: int                     # kept top-level, unchanged, for sort/back-compat
```

`emails.llm_result` (existing JSONB column) stores `FullVerdict.model_dump()` as-is — no migration needed there.

### New `urgency` table (`src/database.py`, same pattern as `Blocklist`/`AuditLog`)

```python
class Urgency(Base):
    __tablename__ = "urgency"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, unique=True, index=True)
    level = Column(String(20), nullable=False)              # low/medium/high/critical
    priority = Column(Integer, nullable=False, index=True)   # 0-3, derived from level, for ORDER BY
    reasoning = Column(Text, nullable=True)
    missing_information = Column(JSONB, nullable=True)
    settlement_type = Column(String(20), nullable=True)      # assistive/automated
    settlement_recommendation = Column(Text, nullable=True)
    settlement_confirmed = Column(Boolean, default=False)
    settlement_confirmed_by = Column(String(255), nullable=True)
    settlement_confirmed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
```

`priority` is a plain int (critical=3, high=2, medium=1, low=0) so the queue is `ORDER BY priority DESC, created_at ASC` — no string-enum sort hacks.

## Fail-safe rules (extends the project's existing "never fail-open" list)

1. **Missing required fields** (any of policyholder_name / policy_number / policy_type / incident_description / a qualifying photo) → `missing_information` populated, `verdict` forced to `escalader`, `settlement_type` forced to `assistive`. Never auto-settles on incomplete intake.
2. **CV model unavailable/error** (matches the existing Task 5 contract) → `damage_source` falls back to `llm_vision` if a photo exists, or `text_only` if not. Never blocks the pipeline — same `status: unavailable|error` pattern as `_local_tesseract`/`_local_yara`.
3. **No image attachment at all** → `damage_source: text_only`, LLM gives a best-effort severity/urgency from the description alone, but since "photo" is a required field this always lands in the missing-information fail-safe above (rule 1) — so text-only claims are always forced to escalate/assistive, never auto-settled.
4. **Automated settlement gate** — `settlement_type = automated` only when ALL hold: `severity_estimate == 'minor'`, `urgency == 'low'`, `confiance >= 0.75`, and `missing_information` is empty. Any doubt on any axis → `assistive`.
5. **Human confirmation is mandatory regardless of settlement_type** — automated only means the LLM proposes a specific ready-to-execute action; it still requires an operator click to confirm, exactly like existing reject-requires-confirmation. Nothing settles itself.
6. **LLM call/vision failure or invalid output after 2 retries** → existing escalate-on-invalid-output rule applies unchanged; no new bypass.

## Dashboard changes

- **Detail page** (`detail.html`): verdict card splits into two clearly-labeled sections, "Security Concerns" (existing fields, unchanged rendering) and "Verdict" (new — damage report, severity/urgency badges, settlement recommendation + confirm button).
- **New Urgency Queue page** (nav entry next to Inbox, same list/row pattern as `inbox.html`): claims sorted critical-first via the `urgency` table's `priority`, each row shows level badge + one-line reasoning + link to detail page.
- **Settlement confirm**: `POST /api/claims/{email_id}/settlement/confirm` (permission-gated like the existing detonation retry endpoint), sets `settlement_confirmed`, `settlement_confirmed_by`, `settlement_confirmed_at`, audit-logged via the existing `add_audit_entry` pattern.

## Testingc

- Fill in `tests/test_extraction_cv_damage.py`'s currently-failing tests (real `_local_cv_damage` implementation against `models/car_damage_yolov8.pt`).
- New: `ClaimVerdict` fail-safe tests — missing-field forces escalate/assistive; CV-unavailable falls back to llm_vision/text_only; automated-settlement gate only fires when all four conditions hold.
- New: `urgency` table tests — row created/updated alongside verdict persistence, `priority` correctly derived from `level`, queue query sorts critical-first.
- New: settlement confirm endpoint test — permission-gated, audit-logged, sets confirmation fields.

## Open items for the implementation plan

- Exact prompt template changes to `src/analysis.py` (where the current single-purpose email-security prompt lives) — the implementation plan should read the current prompt in full before rewriting it, since it's doing double duty now (security signals + claim extraction + damage fusion) and needs to stay within the model's context/instruction-following limits.
- Confirm `ollama` client/HTTP call path support for the `images` parameter in this codebase's current Ollama client version (`_call_ollama_client` vs `_call_ollama_http` in `src/analysis.py`) — may need a small helper change to pass image bytes through.
