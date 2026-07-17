# ImaniIA

**Local-first, human-in-the-loop AI copilot for insurance claims triage.**

Built for the *Automate Or Die* hackathon — subject: Intelligent Claims Automation.

## Why local-first

Claim documents (medical records, ID copies, police reports, repair invoices)
are sensitive. ImaniIA never sends document content to a third-party API —
everything runs on local infrastructure (local LLM via Ollama, local
extraction pipeline, local isolated sandbox for suspicious attachments). Only
non-content metadata (file hashes, IPs, domains) can leave the machine, and
only to reputation lookups.

Every rejection or settlement recommendation requires human adjuster
confirmation — the system proposes, the adjuster decides. Nothing pays out
autonomously.

## Pipeline

```
Claim document upload
    |
[1] INGESTION        parse, archive, hash idempotency
    |
[2] RULES ENGINE      policy validity, duplicate-claim, known-fraud blocklist
    |
[3] ISOLATED EXTRACTION (no network)
    |   MarkItDown / oletools / PyMuPDF / OCR
    |   + CV damage assessment on claim photos (trained model)
    |   suspicious files -> CAPE sandbox detonation (isolated VM, live view)
    |
[4] SIGNAL ENRICHMENT  policy lookups, claim history, document authenticity
    |
[5] LOCAL LLM ANALYSIS severity scoring + fraud risk + settlement recommendation
    |
HUMAN REVIEW (dashboard) -- adjuster confirms; nothing auto-settles
```

## Mapping to the hackathon subject

| Subject bullet point | This project |
|---|---|
| Intelligent document extraction & case summarization | Stage 3 (MarkItDown/oletools/PyMuPDF/OCR) + stage 5 LLM summary |
| Claim severity prediction & prioritization | Stage 5 deterministic + LLM risk scoring |
| Assisted/automated settlement recommendation | Stage 5 recommendation + mandatory human confirmation |
| Automated damage assessment (computer vision) | Stage 3 CV extraction step on claim photos |
| 24/7 FNOL chatbot (AR/FR) | Roadmap — not implemented in this pass |

## What's redacted in this public repo

This product is intended to be sold commercially, so two proprietary assets
are stubbed rather than shipped in full:

- **YARA detection ruleset** (`data/yara_rules/`) — real ruleset is trained on
  licensed phishing/malware datasets; only a non-functional placeholder rule
  is included here. See `data/yara_rules/README.md`.
- **CV damage-assessment model weights** — proprietary, gitignored (`*.pt`).
  The extraction code path (`src/extraction.py:_local_cv_damage`) is fully
  present and works locally once `CV_DAMAGE_MODEL_PATH` points at a real
  weights file; it fails safe to `"unavailable"` when unset.

## Running locally

```bash
cp .env.example .env    # fill in your values
pip install -r requirements.txt
python src/main.py      # pipeline
python src/api.py       # dashboard (or use start.bat / start_all.ps1)
```

See `docs/sandbox-setup.md` for the optional CAPE detonation sandbox setup.
