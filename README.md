# ImaniIA

**Local-first, human-in-the-loop AI copilot for insurance claims triage.**

Built for the *Automate Or Die* hackathon — subject: Intelligent Claims Automation.

ImaniIA ingests incoming insurance claims (email + documents + photos), runs them through a deterministic security/extraction pipeline, assesses fraud risk and vehicle/property damage with a local LLM and a trained computer-vision model, classifies urgency, and proposes a settlement — but **nothing ever pays out without a human adjuster clicking confirm.**

---

## Table of contents

- [Why local-first](#why-local-first)
- [Key features](#key-features)
- [Architecture](#architecture)
- [Mapping to the hackathon subject](#mapping-to-the-hackathon-subject)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running it](#running-it)
- [Sample / synthetic data](#sample--synthetic-data)
- [Testing](#testing)
- [Docker](#docker)
- [What's redacted in this public repo](#whats-redacted-in-this-public-repo)
- [Troubleshooting](#troubleshooting)

---

## Why local-first

Claim documents (medical records, ID copies, police reports, repair invoices, damage photos) are sensitive. ImaniIA never sends document content to a third-party API — everything runs on local infrastructure:

- **Local LLM** via Ollama (default: `gemma3:4b`, vision-capable)
- **Local computer-vision model** (trained YOLOv8) for damage assessment
- **Local, network-isolated extraction pipeline** (containerized where Docker is available)
- **Local, network-isolated sandbox** (CAPEv2) for detonating suspicious attachments

Only non-content metadata (SHA-256 hashes, IP addresses, domain names) is ever sent off-machine, and only to reputation lookups (VirusTotal, AbuseIPDB, ThreatFox, AlienVault OTX). File content is never uploaded anywhere.

Every rejection and every settlement recommendation — assistive or automated — requires explicit human adjuster confirmation. The system proposes; the adjuster decides. Nothing pays out autonomously.

## Key features

- **5-stage deterministic pipeline**: ingestion → rules engine → isolated extraction → signal enrichment → local LLM analysis, with fail-safe defaults at every stage (a crash or timeout escalates to a human, never silently accepts).
- **CV + LLM damage assessment**: a trained YOLOv8 model detects and classifies vehicle damage from claim photos; its structured output is fed to the LLM as grounding context, and the LLM also receives the raw photo directly (vision) for a combined report.
- **Two-section verdict**: *Security Concerns* (fraud/social-engineering signals — is this claim itself suspicious?) and *Verdict* (damage report, severity, urgency, settlement recommendation) — genuinely orthogonal axes, both shown to the adjuster.
- **Urgency triage queue**: every claim gets a `low`/`medium`/`high`/`critical` urgency classification with reasoning, sorted critical-first in a dedicated dashboard page.
- **Assistive/automated settlement gate**: the LLM proposes a *procedural* recommendation (never a dollar amount — there's no policy/pricing data to base one on). Automated settlement only fires when severity is minor, urgency is low, confidence is high, and nothing required is missing; otherwise it's assistive. Either way, an adjuster must click confirm.
- **Sandbox detonation**: attachments that survive static analysis inconclusively get detonated in an isolated CAPEv2 VM, with a live view available in the dashboard.
- **RBAC dashboard**: role-based permissions (admin/analyst/viewer) with a granular per-permission editor, full audit log, and action history.

## Architecture

```text
Claim submission (email + attachments)
    |
    v
[1] INGESTION — parse, archive raw original, SHA-256 idempotency
    |
    v
[2] RULES ENGINE — policy validity, duplicate-claim match, known-fraud blocklist,
    |               extension policy, header anomalies
    |               -> evident cases -> human review queue
    v
[3] ISOLATED EXTRACTION — no network access
    |   python-magic, MarkItDown, oletools, pdfid, PyMuPDF, Tesseract (OCR), YARA
    |   + CV damage assessment on claim photos (trained YOLOv8 model)
    |   -> ambiguous/suspicious files -> CAPE sandbox detonation (isolated VM)
    v
[4] SIGNAL ENRICHMENT
    |   Local: policy status, claim history, document authenticity signals
    |   API (metadata only): VirusTotal (hash), AbuseIPDB (IP), ThreatFox, OTX
    v
[5] LOCAL LLM ANALYSIS
    |   Receives: claim text + CV damage signal + claim photo (vision) + all
    |   structured signals. Returns a Pydantic-validated verdict:
    |     - Security Concerns: sender risk, fraud indicators
    |     - Verdict: damage report, severity, urgency, settlement recommendation
    v
HUMAN REVIEW (dashboard) — adjuster confirms or overrides
    |
    +-- Approve claim -> notify claimant
    +-- Escalate/reject (after human confirmation) -> quarantine + blocklist cascade
    +-- Confirm settlement (assistive or automated) -> logged, audited
```

## Mapping to the hackathon subject

| Subject bullet point | This project |
|---|---|
| Intelligent document extraction & case summarization | Stage 3 (MarkItDown/oletools/PyMuPDF/OCR) + stage 5 LLM summary |
| Claim severity prediction & prioritization | Stage 5 deterministic + LLM risk scoring, urgency triage queue |
| Assisted/automated settlement recommendation | Stage 5 recommendation + mandatory human confirmation gate |
| Automated damage assessment (computer vision) | Stage 3 CV extraction step (trained YOLOv8) fused with LLM vision |
| 24/7 FNOL chatbot (AR/FR) | Roadmap — not implemented in this pass |

## Tech stack

| Component | Tool |
|---|---|
| Language | Python 3.12 |
| Web framework | FastAPI + Jinja2 |
| Database | PostgreSQL (SQLAlchemy 2.0) |
| Schemas | Pydantic v2 (strict LLM-output validation) |
| Email parsing | `email` module, `imaplib` |
| File type detection | `python-magic-bin` (Windows) / `python-magic` |
| Text extraction | MarkItDown |
| Office inspection | `oletools` |
| PDF inspection | `pdfid`, PyMuPDF |
| OCR | Tesseract |
| Signature matching | YARA |
| Computer vision | Ultralytics YOLOv8 |
| LLM runtime | Ollama (`gemma3:4b` by default — vision-capable) |
| Prompt-injection guard | Llama Guard 3 (1B) via `transformers` |
| Detonation sandbox | CAPEv2 (separate VM) |
| Frontend | Server-rendered Jinja2 + vanilla JS (CSP-strict, no inline handlers) |
| Auth | JWT + TOTP 2FA, bcrypt |
| Containerization | Docker (per-tool isolated extraction containers) + docker-compose |

## Project structure

```text
.
├── .env.example              # template — copy to .env and fill in
├── requirements.txt           # Python dependencies
├── docker-compose.yml         # app + postgres + nginx
├── docker/                    # per-tool isolated extraction Dockerfiles
├── start.bat / start_all.ps1  # Windows convenience launchers
├── scripts/
│   └── generate_sample_claims.py   # synthetic claim-email + photo generator
├── src/
│   ├── main.py                # pipeline entrypoint (--serve / --daemon / --migrate)
│   ├── api.py                 # FastAPI app
│   ├── api_core.py            # auth/permission dependencies
│   ├── database.py            # SQLAlchemy models, RBAC, DB helpers
│   ├── analysis.py            # LLM call + ClaimVerdict fusion logic
│   ├── extraction.py          # Stage 3 isolated extraction (incl. CV damage model)
│   ├── rules.py                # Stage 2 rules engine
│   ├── skills.md               # the actual LLM system prompt
│   ├── detonation.py / detonation_config.py / cape_client.py   # sandbox subsystem
│   ├── routers/                # FastAPI routers (emails, users, dashboard, detonation)
│   └── dashboard/               # Jinja2 templates + static JS/CSS
├── tests/                      # pytest suite (unit + integration)
├── data/
│   ├── samples/                # example/synthetic data (see below)
│   └── yara_rules/             # placeholder ruleset (real one is redacted)
└── docs/                       # setup runbooks, design specs, implementation plans
```

## Installation

**Prerequisites:**

- Python 3.12
- PostgreSQL 14+ (local install or via `docker-compose`)
- [Ollama](https://ollama.com) with a vision-capable model pulled (default `gemma3:4b`)
- Tesseract OCR (system install — e.g. `choco install tesseract` on Windows, `apt install tesseract-ocr` on Debian/Ubuntu)
- Docker (optional but recommended — isolated per-tool extraction containers; the pipeline falls back to local execution if Docker isn't available)

**Steps:**

```bash
git clone https://github.com/PublisherX02/Automate-Or-Die.git
cd Automate-Or-Die

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

# Pull the default LLM model
ollama pull gemma3:4b

# Set up the database (adjust credentials to match your .env)
createdb imania_db   # or: psql -c "CREATE DATABASE imania_db;"

cp .env.example .env
# edit .env — see Configuration below
```

On first run, `init_db()` creates every table automatically (`Base.metadata.create_all`) — no manual migration step needed for a fresh database. A default admin user is created on first run; credentials are written to a local file and printed to the console (see console output on first launch), and MFA (TOTP) setup is required immediately.

## Configuration

Copy `.env.example` to `.env` and fill in the values relevant to what you want to run. Nothing in `.env` is committed — `.gitignore` blocks it explicitly.

The file is organized into sections; you don't need every value to get the core pipeline + dashboard running. Minimum to boot the dashboard and process a claim locally:

| Variable | Required for | Notes |
|---|---|---|
| `DATABASE_URL` | Everything | `postgresql://user:pass@host:5432/dbname` |
| `VAULT_ENCRYPTION_KEY` | Everything | Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `JWT_SECRET` | Dashboard login | Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"`. **Must differ from `VAULT_ENCRYPTION_KEY`.** |
| `LLM_MODEL` | Stage 5 analysis | Defaults to `gemma3:4b` if unset |
| `CV_DAMAGE_MODEL_PATH` | CV damage assessment | Optional — proprietary trained weights, not included; the step fails safe to `"unavailable"` when unset |
| `IMAP_HOST` / `IMAP_USER` / `IMAP_PASSWORD` | Live email ingestion | Not needed if you're only feeding it sample `.eml` files |

Everything else (threat-intel API keys, SMTP/Slack/Teams reporting, the CAPE detonation sandbox block) is optional and each subsystem degrades gracefully — a missing API key just means that particular enrichment signal is skipped, never a crash.

The detonation sandbox (CAPEv2) is the most involved optional piece — it requires a separate VM. See `docs/sandbox-setup.md` for the full runbook; until it's configured, `CAPE_VM_WRAPPER_ENABLED=0` keeps that subsystem inert and the rest of the pipeline works normally.

## Running it

```bash
# Run the pipeline once (polls IMAP if configured, processes and exits)
python src/main.py

# Run the dashboard (FastAPI + background IMAP polling)
python src/main.py --serve
# -> http://localhost:8000

# Run just the background polling daemon (no dashboard)
python src/main.py --daemon
```

On Windows, `start.bat` / `start_all.ps1` wrap the same commands with venv activation and a bit of process cleanup.

Once the dashboard is running, log in (default admin credentials are printed on first-run — see the `[ISO 27001] ADMIN CREATED` console block), set up TOTP 2FA, and you'll land on the Inbox Queue. The Urgency Queue (sidebar) shows claims sorted critical-first once any have been processed.

## Sample / synthetic data

No live IMAP inbox needed to see the pipeline work. `scripts/generate_sample_claims.py` generates four fully-synthetic `.eml` claim emails (no real names, no real data) — a clean minor claim, a clean severe claim, a claim missing required fields, and a staged/fraud-flagged claim — each with a small placeholder "damage photo" drawn with PIL, into `data/samples/synthetic_claims/`. A set is already committed there; re-run the script any time to regenerate:

```bash
python scripts/generate_sample_claims.py
```

Feed one through the real ingestion parser directly (no dashboard needed):

```bash
python -c "
import sys; sys.path.insert(0, 'src')
from email_extraction import EmailIngestion
raw = open('data/samples/synthetic_claims/01_legitimate_minor_claim.eml', 'rb').read()
ing = EmailIngestion(host='unused', user='unused', password='unused')
result = ing.parse_email(raw)
print(result['status'], result['headers']['subject'])
"
```

## Testing

```bash
pytest -q
```

The suite covers, among others: the rules engine, the extraction pipeline (including the CV damage-assessment model, mocked at the model-load boundary), the `ClaimVerdict` fail-safe fusion logic (missing-field handling, the automated-settlement gate, urgency defaulting), the urgency table and triage-queue sort order, the settlement-confirmation API, RBAC permission checks, and the detonation-sandbox state machine.

One pre-existing, environment-dependent test is worth knowing about: `tests/test_architecture.py` can trigger a native crash loading the real Llama-Guard-3-1B model under memory pressure (a `transformers`/`torch` issue on this class of machine, unrelated to this project's code). If you hit it, run the rest of the suite with `pytest -q --deselect tests/test_architecture.py`.

## Docker

```bash
docker-compose up
```

Brings up the app (FastAPI + background polling), PostgreSQL, and nginx (rate-limited reverse proxy) together. The extraction pipeline additionally uses **per-tool** isolated containers (see `docker/`) when Docker is available — each extraction tool (oletools, pdfid, pymupdf, yara, tesseract, markitdown, magic, ioc_finder) runs with `--network=none --read-only --cap-drop=ALL --no-new-privileges` and hard CPU/memory/PID limits, regardless of whether you're running the main app via Docker or locally. If Docker isn't available at all, extraction falls back to direct local execution automatically.

## What's redacted in this public repo

This product is intended to be sold commercially, so two proprietary assets are stubbed rather than shipped in full:

- **YARA detection ruleset** (`data/yara_rules/`) — the real ruleset is trained on licensed phishing/malware datasets; only a non-functional placeholder rule is included here. See `data/yara_rules/README.md`.
- **CV damage-assessment model weights** — proprietary, gitignored (`*.pt`, `models/`). The extraction code path (`src/extraction.py:_local_cv_damage`) is fully present and works locally once `CV_DAMAGE_MODEL_PATH` points at a real weights file; it fails safe to `"unavailable"` when unset, so the rest of the pipeline (including the LLM's own vision-based damage read) still works without it.

## Troubleshooting

- **"DATABASE_URL is not set"** — the app refuses to start without one; set it in `.env`.
- **Dashboard login works but 2FA setup seems stuck** — check the console output from the first run for the printed admin credentials/TOTP QR data; it's only shown once.
- **CV damage assessment always returns `"unavailable"`** — expected without a real `CV_DAMAGE_MODEL_PATH` weights file (proprietary, not shipped). Every other part of the pipeline, including the LLM's own vision-based read of the photo, still works.
- **Detonation sandbox does nothing** — expected until `docs/sandbox-setup.md`'s runbook is executed against a real CAPEv2 VM and `CAPE_VM_WRAPPER_ENABLED=1` is set; this is an optional subsystem.
- **`tests/test_architecture.py` crashes the whole test run** — see [Testing](#testing) above; deselect it and file it separately.
