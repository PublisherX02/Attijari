# ImaniIA — Hackathon Rebrand Design

**Date:** 2026-07-17
**Context:** "Automate Or Die" hackathon, subject: Intelligent Claims Automation
**Deadline:** 1-2 days

## Product identity

**ImaniIA** — a local-first, human-in-the-loop AI copilot for insurance claims intake and triage. Rebrand of the existing email-security-triage POC: same 5-stage deterministic pipeline, same fail-safe/human-confirmation constraints, relabeled for the insurance claims domain.

Positioning against "any PDF extractor + API call" competitors: local data residency (no claim document content ever leaves the machine — medical records, ID copies, police reports stay local), a security layer that detonates suspicious attachments in an isolated sandbox before extraction, and a mandatory-human-confirmation settlement flow (an insurer cannot let an LLM auto-approve a payout — this is a compliance feature, not a limitation).

## Architecture (reused, relabeled)

```
Claim document upload
    ↓
[1] INGESTION — parse, archive, hash idempotency  (unchanged)
    ↓
[2] RULES ENGINE — extension policy, known-bad hashes, header/file anomalies
    │        → evident threat → human review queue
    ↓
[3] ISOLATED EXTRACTION (no network) — MarkItDown/oletools/PyMuPDF/OCR
    │        → ambiguous/suspicious → CAPE SANDBOX DETONATION (kept as-is:
    │          drain-window, manual "See in VM" trigger, VNC live view,
    │          fail-safe escalate on timeout/crash)
    │        + NEW: CV damage assessment on claim photos (trained model)
    ↓
[4] SIGNAL ENRICHMENT — repurposed: policy DB, claim history, prior-claim dedup
    ↓
[5] LOCAL LLM ANALYSIS — case summarization + severity/priority + settlement recommendation
    ↓
HUMAN REVIEW (dashboard) — adjuster confirms; blocklist/quarantine/audit trail all kept
```

All existing security machinery is kept, only relabeled: `PendingDetonation`, `cape_client.py`, `detonation.py`, manual-detonation page, amber suspension banner, blocklist/whitelist/audit pages. E.g. "sender blocklist" → "known-fraud document/sender blocklist", "email quarantine" → "claim quarantine".

## Verdict schema (renamed, same shape/constraints)

- `risque_expediteur` → `gravite_sinistre`
- `verdict: accepter/rejeter/escalader` → `recommandation: valider/rejeter/escalader_vers_expert`
- Same fail-safe rules apply: low confidence → forced escalation; rules engine not overridable by LLM; invalid LLM output after 2 retries → escalate; encrypted-attachment-with-password pattern → automatic escalate.

## Mapping to hackathon subject bullet points

| Bullet | Mapping |
|---|---|
| Intelligent document extraction & case summarization | Near-direct reuse of MarkItDown/oletools/PyMuPDF/OCR + stage 5 LLM summarization |
| Claim severity prediction & prioritization | Reuse of `score_risque`-style scoring, rules-engine-not-overridable pattern |
| Assisted/automated settlement recommendation | Reuse of accept/reject/escalate + mandatory human confirmation |
| Automated damage assessment (computer vision) | NEW: trained model plugged in as an extraction-stage step on claim photos, produces a severity signal consumed by stage 5 |
| 24/7 FNOL chatbot (AR/FR) | Out of scope for this pass — noted as roadmap, not attempted in 1-2 days |

## IP protection for the public repo

The repo will be pushed publicly to `https://github.com/PublisherX02/Automate-Or-Die.git` — product is intended to be sold, so proprietary detection assets are stubbed, not present in real form:

- `data/yara_rules/suspicious.yar` → replaced with a single placeholder rule containing a comment: `// Redacted: proprietary ruleset, available under license`. Real ruleset stays only in the private `Attijari` repo/local machine.
- Trained CV damage-assessment model weights → excluded via `.gitignore`, README notes "model available under license/NDA"; code path to load/run it stays intact so it still works locally during the demo with the real (untracked) weights file.

## Rebrand & scrub mechanics

61 files currently reference "Attijari"/"Tijari" (repo-wide grep, 2026-07-17). Plan:
- Global text replace: bank name → domain-neutral terms, varying by context (code identifiers vs. UI copy vs. docs).
- Delete/genericize bank-specific artifacts with no claims-domain equivalent: `deploy/attijari/` → `deploy/`, `docs/attijari-sandbox-setup.md` → `docs/sandbox-setup.md`, `grafana/provisioning/dashboards/attijari.json` → renamed.
- `CLAUDE.md` rewritten for the new domain/name. The existing Build Log (real engineering history, Attijari-specific) moves to `docs/archive/attijari-build-log.md` rather than being deleted, since the new public CLAUDE.md must not reference a real bank.
- `.env.example` scrubbed of bank-specific values/comments.
- `src/dashboard/static/img/` (currently untracked, contains the reverted Attijari-rebrand logo work) — excluded, not carried into the new repo.

## Repo mechanics

- Scrub/rebrand happens first, entirely in the current working tree.
- Once clean, create a fresh history (orphan branch or fresh `git init`) from the scrubbed tree — no commit in the new repo's history ever mentions Attijari, even transiently.
- Add `https://github.com/PublisherX02/Automate-Or-Die.git` as the new repo's remote, push.
- The current `Attijari` repo/remote is left untouched — stays the private/internal one.

## Demo scope (1-2 days)

- **Day 1:** rebrand/scrub pass, relabel verdict schema and dashboard copy to claims domain, stand up the new repo with fresh scrubbed history.
- **Day 2:** wire the CV model in as a new extraction-stage step for photo attachments (produces a damage severity signal consumed by stage 5 same as any other enrichment signal); rehearse demo flow: upload a claim (docs + photos) → rules → extraction/CV → LLM verdict card → adjuster approves/escalates in dashboard, with the sandbox/VM security layer visibly available.

## Testing

Existing test suite (46/46 green pre-rebrand) gets updated in lockstep with renames — no logic changes expected from the rebrand itself, so tests should stay green throughout except where new assertions are needed for renamed fields/new CV step. New CV integration step gets its own test coverage (mocked model inference, signal shape validation, fail-safe-on-model-error path).
