# Project Proposal: Imani AI
**The End-to-End Local AI Engine for Secure Claims Automation**

Target: Sector 1 — Insurance & Banking | Theme 1: Intelligent Claims Automation

## 1. Problem Statement

The insurance sector aims to automate 50% of claims-related activities by 2030 to cut processing costs by 25–30%. However, achieving full automation creates a massive "Intake Vulnerability."

When insurers automate the ingestion of First Notification of Loss (FNOL) emails, they blindly pull in unstructured attachments — such as PDFs (police reports) and image files (car damage). This exposes their internal networks to Business Email Compromise (BEC) and zero-day ransomware. In 2023 alone, BEC accounted for over $2.9 billion in financial losses globally.

**The Pain Point:** Conventional defenses (Secure Email Gateways) are structurally blind to zero-payload, text-based attacks, while standard automation tools are blind to malware.

**Concrete Example:** If a claimant emails a weaponized PDF disguised as a medical invoice, or an attacker uses hidden prompt-injection text to manipulate the AI, a blind automation tool will ingest the threat, potentially triggering a multi-million-dinar ransomware breach. You cannot automate claims if the automation pipeline itself is a security liability.

## 2. Your Solution

Imani AI is a fully localized, zero-trust claims automation pipeline. It securely ingests the FNOL, extracts the data, assesses physical damage, and summarizes the case for the adjuster — all while running completely on-premises, with every settlement decision confirmed by a human adjuster before it takes effect.

**Value Proposition:** Achieve full claims-ingestion automation without opening the door to cyber threats, while keeping all sensitive customer data strictly within the insurer's local network — and keeping a human in the loop for every payout decision.

**High-Level Architecture (The Intake Flow):**

```
[Incoming Claim Email/Document]
       │
       ▼
[Stage 1: Rules Engine] ──(evident threat: known-bad hash/blocklist)──> [Human Review Queue]
   (deterministic, not overridable by the AI)
       │
       ▼ (clean or ambiguous)
[Stage 2: Isolated Extraction — no network access]
   MarkItDown / oletools / pdfid / PyMuPDF / Tesseract OCR / YARA
   + CV damage assessment (YOLOv8 object detection) on claim photos
       │
       ├─(static analysis inconclusive AND AI confidence low)──▶ [Zero-Trust Sandbox Detonation]
       │                                                          (network-isolated VM, memory-gated,
       │                                                           triggered only when needed — not
       │                                                           run on every file)
       ▼
[Stage 3: Local LLM Analysis] ───▶ Severity, fraud risk & case summary
       │
       ▼
[Adjuster Review Dashboard] ───▶ Human confirms accept / reject / escalate.
                                  Nothing settles autonomously.
```

## 3. Innovation

Current automation solutions rely heavily on commercial cloud APIs, which violate the strict data sovereignty regulations of financial institutions.

Imani AI is an entirely air-gapped, on-premises architecture. Our unique approach merges a deterministic trust hierarchy (rules engine + CAPEv2 malware sandboxing) with probabilistic AI (a quantized local LLM and YOLOv8-based computer vision). Static, deterministic checks run first and can never be overridden by the AI; the network-isolated sandbox is reserved for the subset of files that static analysis and the LLM can't confidently clear, so we're not burning sandbox cycles on every attachment. This bounded, tiered architecture provides state-of-the-art automation with zero data leakage and strong resistance to adversarial prompt-injection attacks, while a human adjuster always makes the final call.

## 4. Quantified Impact

- **100% Local Processing Cost:** 0 TND spent on external API calls. By running the AI, CV, and OCR models locally, the marginal compute cost per claim is zero.
- **Estimated Ingestion Time Saved:** Automating the extraction of policy numbers, invoice totals, and damage summaries removes the manual data-entry bottleneck for claims adjusters ahead of their review.
- **Live Prototype Validation Plan:** We are running the pipeline end-to-end against a mixed batch of benign claims (documents + photos), simulated malicious payloads, and text-based prompt-injection attempts, to confirm in the live demo that: (a) benign claims are correctly extracted and summarized, (b) malicious payloads are isolated by the sandbox before reaching the extraction/LLM stage, and (c) prompt-injection attempts are flagged rather than followed. Exact pass-rate figures will be presented from that live run rather than asserted in advance.

## 5. Feasibility

This project is highly feasible because it leverages highly optimized, open-source orchestration tools built to run on constrained environments.

**Resources Needed:** A single consumer-grade workstation, Docker, Ollama, and local open-weights models (Gemma 3 4B, Tesseract). A GPU accelerates inference but is not required — the pipeline runs on CPU-only Ollama inference at this volume.

**Hackathon Build Plan:**
This submission builds on our existing local-security R&D (an email-triage pipeline with the same rules-engine → isolated-extraction → sandbox → local-LLM → human-review architecture, developed prior to this event) rather than starting from a blank repository. During the hackathon window we:
- Rebranded and re-scoped the pipeline from email-security triage to insurance claims triage (verdict schema, dashboard, LLM prompt, all rewritten for the claims domain).
- Integrated a real trained YOLOv8 vehicle-damage-detection model as a new computer-vision extraction step, verified against a live sample photo.
- Diagnosed and fixed a live sandbox-connectivity gap (firewall rules) and a WebSocket relay bug so the detonation VM's live view actually renders in the dashboard.
- Redacted proprietary detection assets (the YARA ruleset, the CV model weights) from the public repository while keeping the mechanism demonstrable, since this product is intended to be sold commercially.

## 6. Originality

**Ingenious Low-Cost Approach:** We are democratizing enterprise-grade automation. Instead of requiring a massive, expensive server rack, our system uses a quantized local LLM and lightweight OCR/CV models to run sophisticated semantic analysis on a single workstation.

**Clever Repurposing:** We are taking a malware-analysis sandboxing technique and repurposing it as a standard business intake gateway for insurance claims — detonating suspicious attachments in an isolated VM before any AI model ever touches them.

## 7. Target Audience and Use Cases

**Who:** Claims Adjusters, Underwriters, and IT Security teams within Tunisian banks and insurance providers.

**Context:** Used during the First Notification of Loss (FNOL) phase, specifically when customers submit evidence (photos, PDFs, documents) via email or a claims portal.

**How Often:** 24/7 continuous operation, acting as the automated, frontline gateway for every digital claim submitted to the institution.

## 8. Competitive Differentiation

**Cloud AI Wrappers (e.g., OpenAI / Azure APIs):** While fast, these tools force insurers to send highly sensitive local banking/medical data to foreign servers, violating data residency laws, and are vulnerable to prompt-injection attacks. Imani AI is fully local and keeps a deterministic layer the AI cannot override.

**Legacy Secure Email Gateways (SEGs):** Traditional security tools are good at stopping known malware but are blind to text-based social engineering and cannot read, assess, or summarize claims data. Imani AI bridges the gap, offering both security and intelligent workflow automation.

**Manual Human Processing:** Highly secure but slow, unscalable, and expensive. Imani AI automates the repetitive extraction and summarization while retaining human-level security checks and final human sign-off on every settlement decision.
