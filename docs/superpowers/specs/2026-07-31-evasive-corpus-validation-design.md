# Evasive-Corpus Validation Design

## Context

The 2026-07-31 evasion-hardening work (`docs/superpowers/specs/2026-07-31-evasion-hardening-design.md`)
shipped new detection logic — structural encrypted-attachment detection,
OneNote escalation, recursive archive YARA scanning, CAPE anti-sandbox
signature override, container-timeout fail-safe — validated only by
synthetic unit tests (hand-built fixtures in `tests/` and `accuracy.py`).
None of it has been checked against *real* evasive malware. A separate
research pass produced a report surveying five candidate sample sources
(MalwareBazaar, InQuest/malware-samples, Avast-CTU Public CAPE Dataset,
RawMal-TF, Malware-Traffic-Analysis.net) for this purpose.

The report's own OpSec guidance (air-gapped VM, no EDR, DNS sinkhole) at
first looked like it required building new isolated infrastructure. It
doesn't: the project already has exactly this environment. The CAPE VM
(Hyper-V name `moham`, reachable at `192.168.100.10` per
[[project_detonation_cape]]) already runs CAPEv2 with INetSim configured
for realistic-but-sinkholed network simulation. `moham`'s host-level NIC
is bridged to the real network (for CAPE's own management/updates), but
the detonation guest (`cuckoo2`) talks only through CAPE's INetSim-backed
internal network — the OpSec goal is already met by existing
infrastructure, not something this design needs to build.

**Goal (from the user):** both validate that CAPE's own sandbox isn't
trivially evaded, and run the evasive corpus end-to-end through the full
email pipeline, producing detection-rate/precision/recall/F1 statistics
in the same spirit as the existing EPVME report.

**Guiding constraint (explicit, non-negotiable):** zero risk to this
Windows dev machine. No live/raw malware binary is ever decrypted or
executed on its bare filesystem. Anything requiring that lands on the
CAPE VM directly.

## Scope for this pass

All five sources are in scope, split into two tracks by trust/handling
requirements:

- **Automated track:** MalwareBazaar (API-scriptable, samples ship
  AES-128-encrypted in a ZIP with the industry-standard password
  `infected` — inert until deliberately decrypted) + Avast-CTU Public CAPE
  Dataset (JSON telemetry only, zero infection risk, no binaries at all).
- **Manual track:** InQuest/malware-samples and RawMal-TF (raw, unprotected
  live binaries) — handled entirely on the CAPE VM per a written runbook,
  not scripted from this repo. Malware-Traffic-Analysis.net (PCAP +
  dropped-file scenarios) is deferred — same manual-track handling
  requirements as InQuest/RawMal-TF, but not built out in this pass;
  noted as a follow-up once the manual runbook is proven out.

## Architecture

```text
This dev machine (Windows)
  malwarebazaar_client.py --query_by_tag()--> MalwareBazaar API
                          --download_sample()--> data/evasive_corpus/malwarebazaar/<sha256>.zip
                              (password-protected zip saved as-is; never extracted here)

  evasive_corpus_test.py
    for each downloaded zip:
      - wrap as an .eml attachment via accuracy._make_eml(), body text
        containing "password: infected" (exercises the real
        encrypted_with_password_in_body + _detect_encryption() path,
        same as a real attacker's password-protected payload)
      - call accuracy.run_pipeline_isolated(raw_eml, run_llm=True,
        enable_detonation=True) — UNCHANGED, exercises rules -> sandboxed
        extraction (decryption/YARA/oletools happen inside the existing
        network-disabled, non-privileged Docker containers) -> LLM ->
        CAPE detonation via the existing cape_client, reaching moham
        exactly like production
    score with accuracy.classify_result() / compute_metrics(), same
    shape as epvme_report.json -> data/evasive_corpus_results/

  Avast-CTU cross-check (informational, non-blocking):
    for any malware family name your own CAPE run's signatures match,
    load the corresponding Avast-CTU JSON report and diff behavior/
    signature summaries — flags if CAPE's own sandbox missed something
    a reference sandbox caught for the same family.

CAPE VM "moham" (192.168.100.10)
  docs/evasive-corpus-runbook.md (manual):
    - git clone InQuest/malware-samples and RawMal-TF directly on moham
      over SSH/console (never on the dev machine)
    - submit via CAPE's existing submission tooling, running locally there
    - export only the resulting JSON reports back to this machine
      (over the existing CAPE REST API path — no new transfer mechanism)
    - raw binaries never leave moham
```

## Components

1. **`src/malwarebazaar_client.py`** (new) — thin, fail-safe wrapper
   matching `cape_client.py`'s style:
   - `query_by_tag(tag: str, limit: int = 50) -> list[dict]` — POSTs to
     `https://mb-api.abuse.ch/api/v1/` with `query=get_taginfo`, header
     `Auth-Key: <MALWAREBAZAAR_API_KEY>`. Returns `[]` on any error
     (network, malformed response, missing key) — never raises to the
     caller, consistent with the project's fail-safe philosophy for
     optional/enrichment integrations.
   - `download_sample(sha256: str, dest_dir: Path) -> Path | None` —
     POSTs `query=get_file&sha256_hash=<sha256>`, saves the raw response
     bytes (the encrypted zip, untouched) to
     `data/evasive_corpus/malwarebazaar/<sha256>.zip`. Never calls
     `zipfile`/extracts. Returns `None` on any failure.
   - API key: `MALWAREBAZAAR_API_KEY`, sourced via
     `secrets_client.get_api_key("malwarebazaar")` — extends the existing
     `threat_intel` Vault group (`virustotal`/`threatfox`/`abuseipdb`/`otx`/
     `dnstwist`) with one more optional key, no new Vault path needed.

2. **`src/evasive_corpus_test.py`** (new, sibling to `epvme_test.py`) —
   orchestrator script, not part of the automated pytest suite (same
   reasoning as `epvme_test.py`: depends on live network access and a
   reachable CAPE VM). CLI:

   ```bash
   python src/evasive_corpus_test.py --tags onenote,html-smuggling,encrypted-zip,iso,lnk --limit-per-tag 40
   python src/evasive_corpus_test.py --tags onenote --limit-per-tag 10 --no-detonation  # fast, static-only pass
   python src/evasive_corpus_test.py --avast-ctu-crosscheck data/avast_ctu/  # cross-check step
   ```

   Reuses `accuracy.run_pipeline_isolated`, `classify_result`,
   `compute_metrics`, `plot_confusion_matrix`, `plot_metrics_bar` as-is —
   no changes to shared scoring code. Writes
   `data/evasive_corpus_results/evasive_corpus_report.json` + the same
   chart set as `epvme_report.json`, plus one new
   `per_technique_breakdown` field (detection rate grouped by the
   MalwareBazaar tag that produced each sample — the report's key ask:
   "how good is our system" needs the technique-level answer, not just
   an aggregate).

3. **`docs/evasive-corpus-runbook.md`** (new) — manual procedure for the
   InQuest/RawMal-TF track. Documents: SSH into `moham`, `git clone` each
   repo into a scratch directory on the VM (never on the dev machine),
   submit samples via CAPE's own existing submission path (same
   `tasks/create/file/` endpoint `cape_client.py` already uses, just
   invoked locally on the VM rather than over the network), pull the
   resulting JSON reports back via the existing CAPE REST API
   (`cape_client.fetch_report`) exactly as production does today — no new
   transfer mechanism. Scoring for this track is manual (compare against
   RawMal-TF's ground-truth family/type labels) rather than folded into
   `evasive_corpus_report.json` in this pass.

## Data flow & error handling

Every failure mode (MalwareBazaar API down, corrupt/truncated download,
CAPE submission error, CAPE VM unreachable) marks that sample `"error"` in
the harness's per-sample results — never silently skipped, never counted
as `"detected"`. This mirrors CLAUDE.md's "fail-safe, never fail-open":
the harness's job is to measure the pipeline honestly, so an error must
show up as a visible gap in the report, not get absorbed into either
metric bucket. No production code path (`extraction.py`, `cape_client.py`,
`detonation_config.py`) is modified by this work — the harness calls
existing, already-shipped functions unchanged.

**Known related bug, out of scope for this pass:** `detonation_config.py`'s
`CAPE_VM_NAME` is set to `"cape-ubuntu"`, but the VM's actual Hyper-V name
is `"moham"` — this is why `DETONATION_MANAGE_VM` has stayed disabled
since 2026-07-19 (lifecycle management targets a VM name that doesn't
exist). Not fixed here since it's orthogonal to sample validation and
`DETONATION_MANAGE_VM=0` already sidesteps it; flagged for a future
session.

## Testing

- `tests/test_malwarebazaar_client.py` (new): mocked HTTP only, zero real
  API calls in CI/automated runs. Verifies tag-query URL/body
  construction, and — the one safety-critical assertion — that
  `download_sample()` never calls `zipfile.ZipFile`/`extractall` on the
  response bytes under any code path (grep-style structural check plus a
  behavioral test with a mocked malicious-looking zip response).
- `evasive_corpus_test.py` and the CAPE-VM runbook are exercised manually,
  matching `epvme_test.py`'s existing convention — both depend on live
  external state (network, a reachable CAPE VM) that doesn't belong in
  the blocking test suite.

## Explicitly deferred (not this pass)

- Malware-Traffic-Analysis.net integration (same manual-track handling as
  InQuest/RawMal-TF; revisit once that runbook is proven out).
- Folding the manual InQuest/RawMal-TF track's results into the same
  `evasive_corpus_report.json` scoring format as the automated track.
- Fixing `CAPE_VM_NAME`/re-enabling `DETONATION_MANAGE_VM` (noted above,
  tracked as a follow-up).
