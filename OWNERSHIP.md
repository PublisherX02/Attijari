# Ownership & Authorship Statement

**Project:** Tijari Bank AI Email Security Triage POC (this repository)
**Author:** Mohamed Mouelhi
**Contact:** mohamedmouelhi2005@gmail.com
**Statement date:** 2026-08-06

## Statement

I, Mohamed Mouelhi, am the sole author and architect of this project — its
design, its cahier des charges, and its implementation — from initial
conception through the current state of this repository. This document is a
factual record of that authorship, created before any handoff of this project
to a third party, for my own protection.

## Evidence of sole authorship

This repository's git history is the primary evidence and should be treated
as authoritative over this document if the two ever disagree:

- **246 commits**, spanning 2026-06-18 through 2026-08-05.
- Every human-authored commit carries the identity
  `mohamedmouelhi2005@gmail.com` (as git usernames `DOOM007` and
  `PublisherX02` — the same person, same email, across the full history).
  No other individual appears as an author anywhere in this history.
- The only non-human entry is a single automated `copilot-swe-agent[bot]`
  commit — tooling output, not a human contributor.
- Cumulative history: ~1,338 file changes, ~241,000 lines inserted, ~8,450
  lines deleted across the project's life — consistent with sole ownership
  of a large, continuously-developed system, not a handoff of someone else's
  partial work.
- Run `git log --format='%an <%ae> %ad' --date=short` in this repository at
  any time to reproduce this evidence independently.

## Scope of the work

This repository is not a single script or prototype — it is a five-stage
pipeline (ingestion, rules engine, isolated extraction, signal enrichment,
local-LLM analysis) plus a review dashboard, built and hardened over
~7 weeks, including (non-exhaustive, see `CLAUDE.md`'s build log for full
detail with dates):

- The original architecture and the cahier des charges itself, which I
  authored — Aziz's role was to *approve* it, not to write it.
- The inbound SMTP ingestion redesign, POP3/IMAP mailbox abstraction, and
  outbound relay system.
- Redis-backed externalization of rate limiting, TOTP replay protection,
  the detonation window lock, and the pipeline scan lock (ARCH-1).
- The Kubernetes deployment manifests and the Docker-to-K8s sandbox
  backend abstraction (`sandbox_k8s.py`).
- The RQ-based real job queue replacing the original poll loop.
- The CI security gate suite (secret scanning, SAST, dependency audit,
  container/IaC scanning, API fuzzing, an LLM adversarial regression
  suite, license/coverage gates).
- The HashiCorp Vault secrets-manager integration.
- The evasion-hardening pass (YARA entropy/structural rules, ISO/7z/LNK
  extraction, encrypted-attachment detection, recursive archive scanning)
  validated against real malware corpora (MalwareBazaar, InQuest).
- The CAPE sandbox integration and the live hypervisor/network-isolation
  hardening on the detonation VM.

## On the role of others

Per this project's own internal documentation (`CLAUDE.md`, "Key people"):

- **Aziz** — manager, *approved* the cahier des charges.
- **Encadrant** — listed as project owner and responsible signatory.

Approval and formal signatory status are administrative roles, not
authorship. Neither is recorded anywhere in this repository's history as
having authored, committed, or technically contributed to any part of the
implementation.

## Reservation of rights

Handoff of a working demonstration or of this codebase to Tijari Bank, to my
encadrant, or to any other party does not, by itself, constitute a transfer,
assignment, or waiver of my authorship or ownership rights in this work. Any
such transfer requires a separate, explicit, written agreement specifying
scope, compensation, and licensing terms, which does not yet exist as of the
date of this statement.

## Provenance fingerprint

A verifiable, non-public fingerprint tying this statement to me personally
is recorded separately — see `scripts/generate_provenance_fingerprint.py`
and its output below. The fingerprint is derived from information only I
possess; anyone can verify it matches once I disclose the inputs, but no one
can forge it in advance without those inputs.

```text
PROVENANCE_FINGERPRINT_SHA256 = 54e0ba4eeb642dd105f1f912c9bdc0216284ad596a76b89c050d67be6d01b58d
GENERATED: 2026-08-06
```

---
*This file is a personal record, not a legal instrument. It does not
constitute legal advice. If ownership of this project is disputed, consult
a lawyer before relying on this document alone.*
