# Evasion Hardening: YARA, Extraction, CAPE — Design

Date: 2026-07-31
Status: Approved for planning

## Context

An internal red-team test is expected "next week" that will send evasive
viruses/attachments through the pipeline. This spec hardens the three
pipeline stages that handle attachments end-to-end:

```
Attachment → [1] YARA scan (static) → [2] Extraction
             (oletools/pdfid/archives/OneNote) → [3] CAPE detonation
             (dynamic, only if LLM unsure)
```

Preceded by two research passes (see conversation) covering:
- The current codebase's actual YARA/extraction/CAPE implementation
  (`src/extraction.py`, `src/sandbox.py`, `src/cape_client.py`,
  `src/detonation_config.py`, `data/yara_rules/suspicious.yar`).
- Current (2025-2026) phishing/evasive-attachment tactics: string-encoding
  evasion of static signatures, password-protected archive/document
  phishing, polyglot files, OneNote (.one) delivery, sandbox anti-analysis
  techniques, and CAPE's own countermeasures/submission options.

**Key finding driving priority:** CAPE's current escalation logic is
malscore-only (`cape_client.py:185-186` — `escalate = malscore >=
CAPE_MALSCORE_ESCALATE`). A sample that detects the sandbox and stays
dormant produces a low malscore even though CAPE's own anti-sandbox/anti-VM
signatures fired — those signatures are folded into a flat list that only
sets `suspicious`, never `escalate`. This is the most consequential gap for
an evasive-malware test specifically, since "detect and go dormant" is
exactly what evasive malware does.

## Non-goals

- Full polyglot-file structural detection (current research: this is still
  an open ML research problem — PolyConv, 2025 — not a solved
  signature-matching problem). The new `pe`-module/entropy rules raise the
  bar but don't claim to catch every polyglot.
- A production-grade Vault-style secrets change, K8s manifest change, or
  any work from the separate secrets-manager track (already shipped
  2026-07-30, unrelated).
- Standing up a full evasive-malware benchmark dataset in this pass — the
  external dataset search is a parallel, non-blocking effort (see below).

## Architecture / stage-by-stage design

### 1. YARA hardening

**New file:** `data/yara_rules/evasion.yar` — kept separate from
`data/yara_rules/suspicious.yar` so the new, higher-maintenance detection
logic (entropy, PE structure, encoded-string variants) doesn't risk
destabilizing the existing 14 plaintext-string rules already in production.

- **Entropy rule**: uses YARA's `math` module, `math.entropy(0,
  filesize)` over the whole file, flagging 7.0-8.0 as likely
  packed/encrypted (compressed media can also read high entropy — this is
  a `suspicious`-tier signal, not an auto-escalate on its own, combined
  with other signals downstream in extraction).
- **PE-structural rule**: uses the `pe` module — suspicious import
  combination (`VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`
  present with a low total import count, a classic process-injection
  signature) OR a known packer section name (`UPX0`, `UPX1`, `.aspack`,
  `.themida`).
- **Encoded-string variants**: `xor`, `base64`, and `base64wide` YARA
  string modifiers applied to the existing high-value keyword sets
  (PowerShell invocation strings, VBA auto-exec/shell strings) so an
  attacker who XORs or base64-encodes those strings to dodge the plaintext
  rules in `suspicious.yar` still gets caught.

**Compile-once caching**: both YARA call sites
(`src/extraction.py:_local_yara`, `docker/scripts/yara_scan.py`)
currently call `yara.compile(filepath=...)` fresh on every single scan.
Switch to compiling once (module-level, at first use, cached for the
process lifetime) — matters more once rule count grows with `evasion.yar`
added. Rule *content* changes still require a process restart to pick up,
consistent with how Docker image rebuilds already work for the sandboxed
tools.

### 2. Extraction hardening

**Password-protection detection** (`src/extraction.py`) — replaces
"heuristic only" with a real structural check:
- ZIP: read each entry's local file header General Purpose Bit Flag; bit 0
  set means the entry is encrypted. `zipfile.ZipInfo.flag_bits & 0x1`.
- OOXML (docx/xlsx/pptx, which are zip containers): a password-protected
  OOXML file is actually CFBF/OLE (not a zip) containing
  `EncryptedPackage`/`EncryptionInfo` streams — detect via `oletools`'
  `olefile.isOleFile()` + stream name check, distinct from a normal OOXML
  zip.
- When either signal fires **and** the email body contains a
  password-hint pattern (existing check, `extraction.py:762-772`), this is
  now a *confirmed* password-protected-attachment-with-password-in-body
  case per CLAUDE.md rule #8 (automatic escalate), not a guess from MIME
  type alone.

**OneNote (`.one`) handling**: add `.one` to the attachment-type dispatch.
No mature open-source OneNote parser exists for safely inspecting embedded
objects — matching the existing `SANDBOX_REQUIRED_TOOLS` fail-safe pattern
(`extraction.py:327-343`), a `.one` attachment with no available parser
tool escalates rather than passing through unexamined. If a working
extraction path is found during implementation, this upgrades to
extract-and-scan; if not, the escalate-on-unparseable behavior is the
correct fallback, not a placeholder.

**Recursive archive scanning**: currently the archive-bomb heuristic
(`extraction.py:558-622`) checks nesting depth and compression ratio but
never actually scans nested content. Add one level of recursive extraction
(bounded by the existing depth/bomb limits) — nested files get YARA +
`python-magic` run against them, not just filename/ratio checks. Full
unbounded recursion is explicitly out of scope (bomb-safety already caps
this at 2 levels); this makes the one level that's already inspected for
safety also get *scanned*, not just size-checked.

**Container-timeout fail-safe fix**: `sandbox.py`'s Docker timeout path
(`TimeoutExpired` → `status=error, error="timeout_killed_after_Ns"`) does
not set `fallback=True`, so `_run_tool()`'s escalate-on-required-tool-
failure logic (`extraction.py:371-372`) doesn't reliably trigger for a
`SANDBOX_REQUIRED_TOOLS` timeout. Fix: a timeout for a required tool sets
`escalate=True`/`suspicious=True` explicitly in the result dict returned
from `_run_tool_docker`, closing this fail-open gap.

### 3. CAPE hardening

**Signature-category escalation override** (`src/cape_client.py`,
`parse_report()`): a new `ANTI_ANALYSIS_SIGNATURE_PATTERNS` list (substring
match against signature name/description, case-insensitive) —
`antisandbox`, `antivm`, `antidbg`, `stalling`, `sandbox_evasion`,
`anti_vm`, `vmdetect`. If any collected `sig_names` entry matches any
pattern, `escalate=True` is forced regardless of `malscore`. This directly
closes the "dormant evasive malware scores low, never escalates" gap
identified as the top-priority finding.

**Submission-side anti-evasion options**: CAPE has debugger/tracing
options (`bp0`-`bp3`, `count`, `depth`) and the web UI defaults to a
human-interaction-emulation toggle per current docs — but
`cape_client.submit_file()` (`cape_client.py:79-113`) passes no `options=`
string at all today. Exact option key names must be verified against the
**live** CAPE instance's actual API/config before shipping (research
found conflicting/unconfirmed exact syntax across docs versions) — this
follows the project's established practice (see the 2026-07-27 CAPE-proxy
build log entries) of confirming against the real instance rather than
guessing from docs. If verification isn't possible before the implementation
session ends, this sub-item is documented as a follow-up rather than
guessed at.

## Testing strategy

- **Unit tests with deterministic fixtures**, built directly regardless of
  the external dataset search: a zip with the encryption bit set (safe,
  synthetic), a synthetic buffer with known high Shannon entropy, a
  synthetic small PE-like structure with the suspicious import pattern (or
  a mocked `pe` module result if constructing a real PE is impractical), a
  mocked CAPE report JSON carrying an `antisandbox_sleep`-style signature
  name at a low malscore.
- **EPVME 5k-subset run**: separate, already-existing regression check
  (`src/epvme_test.py`) plus the user's professor deliverable — confirmed
  via research that EPVME is almost entirely attachment-free, so it
  validates no regressions in the rules/LLM layer but does **not**
  meaningfully exercise this spec's new YARA/extraction/CAPE logic. Not a
  substitute for the fixtures above.
- **External evasive-attachment dataset**: parallel, non-blocking effort —
  the user is dispatching their own research agent to find a suitable
  labeled dataset (request already handed off). Once available, run it as
  an additional empirical validation pass; implementation does not wait on
  it.

## Error handling

Consistent with CLAUDE.md's fail-safe principle (never fail-open): any
exception in the new entropy/PE-module/archive-recursion/OneNote/
password-detection logic is caught, logged, and the attachment is marked
`suspicious=True` (escalate depending on which check) rather than the
exception propagating or the attachment silently passing through
unexamined.

## Rollout order

1. YARA: `evasion.yar` + compile-once caching + unit tests.
2. Extraction: password-protection detection + container-timeout fix
   (self-contained, no CAPE dependency).
3. Extraction: OneNote handling.
4. Extraction: recursive archive scanning.
5. CAPE: signature-category escalation override (highest-priority finding,
   but implemented after the extraction items above since it depends on
   `cape_client.py`'s existing structure, not on them).
6. CAPE: submission-side anti-evasion options (pending live-instance
   verification).
7. Full existing suite re-run after every step; EPVME 5k run once the
   whole pass is complete (regression + professor deliverable).
