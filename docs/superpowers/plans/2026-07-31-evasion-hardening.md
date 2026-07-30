# Evasion Hardening (YARA / Extraction / CAPE) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the pipeline's YARA rules, isolated extraction layer, and CAPE detonation logic against evasive attachments, ahead of an internal red-team test.

**Architecture:** Three independent-but-sequenced fixes layered onto the existing sandbox-first, fail-closed pipeline (`src/extraction.py` → `src/sandbox.py` → `src/cape_client.py`). No existing behavior is removed — every change adds a new detection signal or closes a fail-safe gap on top of what's already there.

**Tech Stack:** `yara-python==4.5.4` (already pinned), `olefile` (new explicit dependency, already present transitively via `oletools==0.60.2` — pin it directly).

## Global Constraints

- Fail-safe, never fail-open (CLAUDE.md): any new check that errors (corrupt file, parse exception) logs and treats the attachment as suspicious/escalates rather than crashing or silently passing through.
- Rules engine / deterministic signals are not overridable by the LLM (CLAUDE.md) — none of these changes touch that invariant; they only add more deterministic signals into the existing `escalate`/`suspicious` flow.
- `SANDBOX_REQUIRED_TOOLS` fail-safe pattern (`src/extraction.py:56`, `_sandbox_required_failsafe` at `extraction.py:327-343`): a tool with no available sandbox image escalates rather than parsing unsandboxed. Reused as-is for OneNote (Task 4) — no new Docker image is built.
- CAPE submission-option changes (Task 7) must not be enabled by default without live-instance verification — this project's established practice (see the 2026-07-27 CAPE-proxy build log entries) is to confirm against the real instance rather than guess from docs. CAPE is unreachable from this dev machine (confirmed via `cape_client.is_available()` returning `False`), so Task 7 ships as disabled-by-default scaffolding, not a guessed, enabled config.
- Existing YARA rules (`data/yara_rules/suspicious.yar`) are untouched — new rules go in a separate file (`data/yara_rules/evasion.yar`) so a bug in the new, higher-maintenance detection logic can't destabilize the 14 rules already in production.
- Test convention: this project's extraction/sandbox tests (`tests/test_extraction_sandbox_failsafe.py`) use `sys.path.insert(0, str(Path(__file__).parent.parent / "src"))` + module-level `import extraction`, plain `test_*` functions (no classes/fixtures beyond built-in `monkeypatch`/`tmp_path`), and the "assert this must never be called" idiom via `monkeypatch.setattr(extraction, "_local_x", lambda *a, **k: (_ for _ in ()).throw(AssertionError(...)))`. CAPE tests (`tests/test_detonation.py`) use `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))`, local imports inside each test function, and a small `_FakeResponse` class for HTTP mocking. Match these exactly.

---

### Task 1: YARA `evasion.yar` + compile-once caching

**Files:**
- Create: `data/yara_rules/evasion.yar`
- Modify: `src/extraction.py:266-284` (`_local_yara`), add new module-level cache
- Test: `tests/test_yara_evasion.py`

**Interfaces:**
- Produces: `_get_compiled_yara_rulesets() -> dict[str, "yara.Rules | Exception"]` (module-level cache in `extraction.py`), consumed only by `_local_yara()` itself.
- No other task depends on this one — YARA rules run before extraction/CAPE regardless of these changes.

- [ ] **Step 1: Write the failing tests**

```python
"""test_yara_evasion.py — new evasion.yar rules (entropy, PE structure,
encoded-string variants) and compile-once caching in _local_yara()."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_evasion_yar_compiles():
    import yara
    rule_path = Path(__file__).parent.parent / "data" / "yara_rules" / "evasion.yar"
    rules = yara.compile(filepath=str(rule_path))
    assert rules is not None


def test_high_entropy_rule_matches_random_bytes():
    import os as _os
    extraction._yara_compiled_cache = None
    random_bytes = _os.urandom(2048)  # high entropy by construction
    result = extraction._local_yara(random_bytes)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "high_entropy_payload" in matched


def test_high_entropy_rule_does_not_match_plain_text():
    extraction._yara_compiled_cache = None
    plain = b"Dear customer, please find attached your invoice. " * 40
    result = extraction._local_yara(plain)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "high_entropy_payload" not in matched


def test_encoded_powershell_rule_matches_base64_variant():
    import base64
    extraction._yara_compiled_cache = None
    encoded = base64.b64encode(b"padding header bytes powershell -enc payload continues here")
    result = extraction._local_yara(encoded)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "suspicious_powershell_encoded" in matched


def test_pe_structural_rules_do_not_false_positive_on_random_bytes():
    # Positive-case verification of the PE-structural rules (suspicious
    # imports, packer section names) requires a real, well-formed PE with
    # a specific import table / section layout — impractical to construct
    # byte-for-byte in a unit test. This test covers the negative case
    # (no false positives on non-PE data); positive-case verification
    # happens against the external evasive-sample dataset once available
    # (see docs/superpowers/specs/2026-07-31-evasion-hardening-design.md).
    extraction._yara_compiled_cache = None
    result = extraction._local_yara(b"not a PE file, just some bytes " * 20)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "suspicious_pe_imports" not in matched
    assert "packer_section_names" not in matched


def test_local_yara_compiles_rules_only_once_per_file(monkeypatch):
    extraction._yara_compiled_cache = None
    real_compile = extraction.yara.compile
    calls = {"count": 0}

    def _counting_compile(*a, **k):
        calls["count"] += 1
        return real_compile(*a, **k)

    monkeypatch.setattr(extraction.yara, "compile", _counting_compile)
    try:
        extraction._local_yara(b"first scan")
        extraction._local_yara(b"second scan")
        extraction._local_yara(b"third scan")
        num_rule_files = len(
            list(extraction.YARA_RULES_DIR.glob("*.yar")) + list(extraction.YARA_RULES_DIR.glob("*.yara"))
        )
        assert calls["count"] == num_rule_files
    finally:
        extraction._yara_compiled_cache = None  # don't leak into other test files
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_yara_evasion.py -v`
Expected: FAIL — `evasion.yar` doesn't exist yet (first test fails with a file-not-found/compile error), and `_yara_compiled_cache` doesn't exist as an attribute on `extraction` yet.

- [ ] **Step 3: Write `data/yara_rules/evasion.yar`**

```yara
import "math"
import "pe"

rule high_entropy_payload {
    meta:
        description = "Detects high-entropy regions suggesting packed/encrypted payload"
        severity = "medium"
    condition:
        filesize > 256 and math.entropy(0, filesize) >= 7.0
}

rule suspicious_pe_imports {
    meta:
        description = "Detects PE files importing the classic process-injection API combination (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)"
        severity = "high"
    condition:
        pe.is_pe
        and pe.imports("kernel32.dll", "VirtualAlloc")
        and pe.imports("kernel32.dll", "WriteProcessMemory")
        and pe.imports("kernel32.dll", "CreateRemoteThread")
}

rule packer_section_names {
    meta:
        description = "Detects known packer section names (UPX, ASPack, Themida)"
        severity = "high"
    condition:
        pe.is_pe and for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == "UPX0" or pe.sections[i].name == "UPX1" or
            pe.sections[i].name == ".aspack" or pe.sections[i].name == ".themida"
        )
}

rule suspicious_powershell_encoded {
    meta:
        description = "Detects XOR/base64-encoded PowerShell/VBA keywords that evade plaintext string rules"
        severity = "high"
    strings:
        $ps1_xor = "powershell" ascii xor
        $ps1_b64 = "powershell" ascii base64 base64wide
        $iex_xor = "Invoke-Expression" ascii xor
        $iex_b64 = "Invoke-Expression" ascii base64 base64wide
        $auto_xor = "AutoOpen" ascii xor
        $auto_b64 = "AutoOpen" ascii base64 base64wide
    condition:
        any of them
}
```

- [ ] **Step 4: Edit `src/extraction.py` — add compile-once caching**

Replace `_local_yara()` at `extraction.py:266-284`:

```python
_yara_compiled_cache: dict | None = None


def _get_compiled_yara_rulesets() -> dict:
    """Compile each rule file once and cache for the process lifetime.
    Per-file (not combined) so one broken rule file doesn't prevent the
    others from matching — same isolation the old per-scan-compile loop had,
    just cached instead of recompiled on every single attachment."""
    global _yara_compiled_cache
    if _yara_compiled_cache is None:
        _yara_compiled_cache = {}
        rule_files = list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))
        for rf in rule_files:
            try:
                _yara_compiled_cache[rf.name] = yara.compile(filepath=str(rf))
            except Exception as e:
                _yara_compiled_cache[rf.name] = e
    return _yara_compiled_cache


def _local_yara(content: bytes) -> dict:
    if not _HAS_YARA:
        return {"tool": "yara", "status": "unavailable"}
    try:
        rulesets = _get_compiled_yara_rulesets()
        if not rulesets:
            return {"tool": "yara", "status": "ok", "matches": [], "suspicious": False}
        all_matches = []
        for rf_name, compiled in rulesets.items():
            if isinstance(compiled, Exception):
                all_matches.append({"error": f"{rf_name}: {compiled}"})
                continue
            try:
                for m in compiled.match(data=content):
                    all_matches.append({"rule": m.rule, "meta": m.meta, "tags": m.tags, "rule_file": rf_name})
            except Exception as e:
                all_matches.append({"error": f"{rf_name}: {e}"})
        return {"tool": "yara", "status": "ok", "matches": all_matches,
                "suspicious": any("rule" in m for m in all_matches)}
    except Exception as e:
        return {"tool": "yara", "status": "error", "error": str(e)}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_yara_evasion.py -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Run the full existing suite to check for regressions**

Run: `pytest tests/ -v -k "extraction or yara"`
Expected: no new failures (existing YARA-adjacent tests in `test_extraction_sandbox_failsafe.py` still pass — that file's `test_low_risk_tools_still_run_local` monkeypatches `extraction._local_yara` directly, unaffected by the internal caching change).

- [ ] **Step 7: Commit**

```bash
git add data/yara_rules/evasion.yar src/extraction.py tests/test_yara_evasion.py
git commit -m "feat: add evasion-resistant YARA rules (entropy, PE structure, encoded strings) with compile-once caching"
```

---

### Task 2: Extraction — real password-protection detection

**Files:**
- Modify: `requirements.txt` (add `olefile` explicit pin)
- Modify: `src/extraction.py` (add `_detect_encryption()`, guarded `olefile` import, integrate into step 8 at `extraction.py:762-772`)
- Test: `tests/test_extraction_encryption_detection.py`

**Interfaces:**
- Produces: `_detect_encryption(content: bytes, filename: str) -> dict` (`{"encrypted": bool, "method": str | None}`), consumed by `extract_attachment()`'s step 8 password-hint check.

- [ ] **Step 1: Add `olefile` to requirements.txt**

`olefile==0.47` is already installed transitively via `oletools==0.60.2` (confirmed: `pip show olefile` reports `0.47`). Pin it explicitly since our own code now imports it directly, not just `oletools` internally.

Edit `requirements.txt`, insert after the `oletools==0.60.2` line:
```
oletools==0.60.2
olefile==0.47
```

Run: `pip install olefile==0.47` (already satisfied, confirms no version conflict).

- [ ] **Step 2: Write the failing tests**

```python
"""test_extraction_encryption_detection.py — real structural detection of
password-protected ZIP/OOXML attachments, replacing the MIME/extension-only
heuristic."""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def _make_zip_with_encryption_flag() -> bytes:
    """Python's zipfile can READ encrypted entries (pwd=) but cannot WRITE
    one natively — build a normal zip, then patch the General Purpose Bit
    Flag (bit 0 = encrypted) directly in both the local file header and the
    central directory record, exactly as a real encrypted zip has it set."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", "hello")
    raw = bytearray(buf.getvalue())
    raw[6] |= 0x01  # local file header GP flag, offset 6-7 from file start
    cd_sig = raw.find(b"PK\x01\x02")
    raw[cd_sig + 8] |= 0x01  # central directory record GP flag
    return bytes(raw)


def test_detect_encryption_zip_flag_set():
    content = _make_zip_with_encryption_flag()
    result = extraction._detect_encryption(content, "secret.zip")
    assert result["encrypted"] is True
    assert result["method"] == "zip_encryption_flag"


def test_detect_encryption_plain_zip_not_flagged():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("data.txt", "hello")
    result = extraction._detect_encryption(buf.getvalue(), "plain.zip")
    assert result["encrypted"] is False
    assert result["method"] is None


def test_detect_encryption_ooxml_encrypted_package(monkeypatch):
    import olefile

    class _FakeOle:
        def exists(self, name):
            return name == "EncryptedPackage"

        def close(self):
            pass

    monkeypatch.setattr(olefile, "isOleFile", lambda buf: True)
    monkeypatch.setattr(olefile, "OleFileIO", lambda buf: _FakeOle())
    result = extraction._detect_encryption(b"\xd0\xcf\x11\xe0fakecfb", "secret.docx")
    assert result["encrypted"] is True
    assert result["method"] == "ooxml_encrypted_package"


def test_detect_encryption_plain_ooxml_not_flagged(monkeypatch):
    import olefile
    monkeypatch.setattr(olefile, "isOleFile", lambda buf: False)
    result = extraction._detect_encryption(b"PK\x03\x04plainooxml", "invoice.docx")
    assert result["encrypted"] is False


def test_extract_attachment_confirmed_encrypted_plus_password_body_escalates(tmp_path):
    content = _make_zip_with_encryption_flag()
    f = tmp_path / "invoice.zip"
    f.write_bytes(content)
    att = {"stored_path": str(f), "original_name": "invoice.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "b" * 64}
    res = extraction.extract_attachment(att, body_text="see attached, password: 1234")
    assert res["escalate"] is True
    assert any("encrypted_with_password_in_body" in fl for fl in res["flags"])
    assert any("attachment_encrypted" in fl for fl in res["flags"])
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_extraction_encryption_detection.py -v`
Expected: FAIL — `extraction._detect_encryption` doesn't exist yet.

- [ ] **Step 4: Add guarded `olefile` import to `src/extraction.py`**

Insert after the existing `_HAS_YARA` guarded-import block (after `extraction.py:126`, before the `_HAS_IOC_FINDER` block):

```python
try:
    import olefile
    _HAS_OLEFILE = True
except ImportError:
    _HAS_OLEFILE = False
```

- [ ] **Step 5: Add `_detect_encryption()` to `src/extraction.py`**

Insert immediately before `_check_image_stego_metadata()` (before `extraction.py:475`):

```python
def _detect_encryption(content: bytes, filename: str) -> dict:
    """Structurally detect whether a ZIP-based or OOXML/OLE attachment is
    password-protected, replacing the old MIME/extension-only guess.

    RAR/7z are not structurally verified here (no parser library in
    requirements.txt) — callers should still combine this with the
    extension/MIME heuristic for those formats, same as before.
    """
    fname_lower = filename.lower()

    if fname_lower.endswith((".zip", ".docx", ".xlsx", ".pptx", ".docm",
                              ".xlsm", ".pptm", ".ppsx", ".ppsm")):
        try:
            import zipfile as _zf
            import io as _io
            buf = _io.BytesIO(content)
            if _zf.is_zipfile(buf):
                buf.seek(0)
                with _zf.ZipFile(buf, "r") as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            return {"encrypted": True, "method": "zip_encryption_flag"}
        except Exception:
            pass

    if _HAS_OLEFILE and fname_lower.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                                               ".docm", ".xlsm", ".pptm", ".ppsx", ".ppsm")):
        try:
            import io as _io
            buf = _io.BytesIO(content)
            if olefile.isOleFile(buf):
                buf.seek(0)
                ole = olefile.OleFileIO(buf)
                try:
                    if ole.exists("EncryptedPackage") or ole.exists("EncryptionInfo"):
                        return {"encrypted": True, "method": "ooxml_encrypted_package"}
                finally:
                    ole.close()
        except Exception:
            pass

    return {"encrypted": False, "method": None}
```

- [ ] **Step 6: Integrate into `extract_attachment()`'s step 8**

Replace `extraction.py:762-772`:
```python
    # 8. CRITICAL: encrypted attachment + password in body = auto escalate
    if body_text:
        body_lower = body_text.lower()
        password_hints = ["password", "mot de passe", "mdp", "pwd", "pass:"]
        has_pw = any(hint in body_lower for hint in password_hints)
        is_encrypted = (effective_mime in _ARCHIVE_MIMES or
                        filename.lower().endswith((".zip", ".rar", ".7z", ".enc")))
        if has_pw and is_encrypted:
            result["suspicious"] = True
            result["escalate"] = True
            result["flags"].append("encrypted_with_password_in_body: automatic escalation per security policy")
```
with:
```python
    # 8. CRITICAL: encrypted attachment + password in body = auto escalate
    encryption_check = _detect_encryption(content, filename)
    if encryption_check["encrypted"]:
        result["flags"].append(f"attachment_encrypted: {encryption_check['method']}")
    if body_text:
        body_lower = body_text.lower()
        password_hints = ["password", "mot de passe", "mdp", "pwd", "pass:"]
        has_pw = any(hint in body_lower for hint in password_hints)
        is_encrypted = (encryption_check["encrypted"] or effective_mime in _ARCHIVE_MIMES or
                        filename.lower().endswith((".zip", ".rar", ".7z", ".enc")))
        if has_pw and is_encrypted:
            result["suspicious"] = True
            result["escalate"] = True
            result["flags"].append("encrypted_with_password_in_body: automatic escalation per security policy")
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_extraction_encryption_detection.py -v`
Expected: PASS (6 tests).

- [ ] **Step 8: Run the full existing suite**

Run: `pytest tests/ -v -k extraction`
Expected: no new failures.

- [ ] **Step 9: Commit**

```bash
git add requirements.txt src/extraction.py tests/test_extraction_encryption_detection.py
git commit -m "feat: real structural password-protection detection (zip flag + OOXML EncryptedPackage)"
```

---

### Task 3: Extraction — container-timeout fail-safe fix

**Files:**
- Modify: `src/extraction.py` (add timeout-escalation loop after the existing SEC-H1 loop at `extraction.py:735-745`)
- Test: `tests/test_extraction_timeout_failsafe.py`

**Interfaces:**
- None new — this is a closed-loop fix inside `extract_attachment()`, reusing the existing `SANDBOX_REQUIRED_TOOLS` constant and `result["tools_run"]` list.

- [ ] **Step 1: Write the failing test**

```python
"""test_extraction_timeout_failsafe.py — a sandboxed-tool container timeout
for a SANDBOX_REQUIRED_TOOLS tool must escalate the whole attachment
(CLAUDE.md: "Crash or timeout -> escalate, never accept"). Closes a gap
where sandbox.py's TimeoutExpired handler doesn't set fallback=True, so
_run_tool()'s existing escalate-on-required-tool-failure branch never
triggers for a timeout specifically."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_container_timeout_for_required_tool_escalates(monkeypatch, tmp_path):
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: True)

    def _fake_sandbox_run(tool_name, stored_path, env=None):
        if tool_name == "oletools":
            return {"tool": "oletools", "status": "error", "error": "timeout_killed_after_45s"}
        return {"tool": tool_name, "status": "ok"}

    monkeypatch.setattr(extraction, "_sandbox_run", _fake_sandbox_run)

    f = tmp_path / "invoice.docm"
    f.write_bytes(b"\xd0\xcf\x11\xe0payload")
    att = {"stored_path": str(f), "original_name": "invoice.docm",
           "declared_type": "application/vnd.ms-word.document.macroEnabled.12",
           "real_type": "application/vnd.ms-word.document.macroEnabled.12", "sha256": "e" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("sandbox_timeout_for_oletools" in fl for fl in res["flags"])


def test_container_timeout_for_non_required_tool_does_not_force_escalate(monkeypatch, tmp_path):
    # yara isn't in SANDBOX_REQUIRED_TOOLS — a timeout there is unusual but
    # shouldn't be force-escalated by this specific fail-safe (yara already
    # runs locally as a fallback in practice; this just confirms the new
    # loop is scoped to SANDBOX_REQUIRED_TOOLS only, not every tool).
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: True)

    def _fake_sandbox_run(tool_name, stored_path, env=None):
        if tool_name == "yara":
            return {"tool": "yara", "status": "error", "error": "timeout_killed_after_45s"}
        return {"tool": tool_name, "status": "ok"}

    monkeypatch.setattr(extraction, "_sandbox_run", _fake_sandbox_run)

    f = tmp_path / "note.txt"
    f.write_bytes(b"hello")
    att = {"stored_path": str(f), "original_name": "note.txt",
           "declared_type": "text/plain", "real_type": "text/plain", "sha256": "c" * 64}
    res = extraction.extract_attachment(att)
    assert not any("sandbox_timeout_for_yara" in fl for fl in res["flags"])
```

- [ ] **Step 2: Run tests to verify the first fails**

Run: `pytest tests/test_extraction_timeout_failsafe.py -v`
Expected: `test_container_timeout_for_required_tool_escalates` FAILS (`res["escalate"]` is `False` — the gap being fixed). `test_container_timeout_for_non_required_tool_does_not_force_escalate` PASSES already (nothing to fix there, it documents the scope boundary).

- [ ] **Step 3: Add the timeout-escalation loop to `src/extraction.py`**

Insert immediately after the existing SEC-H1 propagation loop (after `extraction.py:745`, before the `# 7b. DETONATION CANDIDATE` comment at line 747):

```python
    # 7c. Sandboxed-tool timeout fail-safe — a container timeout for a
    # SANDBOX_REQUIRED_TOOLS tool must escalate (CLAUDE.md: "Crash or
    # timeout -> escalate, never accept"), same principle as the SEC-H1
    # loop above. sandbox.py's TimeoutExpired handler doesn't set
    # fallback=True, so _run_tool()'s escalate-on-required-tool-failure
    # branch (extraction.py:367) doesn't reliably trigger for a timeout —
    # this loop closes that gap independently of which call site consumed
    # the tool's result.
    for _tr in result["tools_run"]:
        _tr_tool = _tr.get("tool")
        _tr_err = _tr.get("error", "")
        if (_tr_tool in SANDBOX_REQUIRED_TOOLS and isinstance(_tr_err, str)
                and _tr_err.startswith("timeout_killed_after_")):
            result["suspicious"] = True
            result["escalate"] = True
            _flag = f"sandbox_timeout_for_{_tr_tool}: container exceeded time limit — escalating (fail-safe)"
            if _flag not in result["flags"]:
                result["flags"].append(_flag)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_extraction_timeout_failsafe.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v -k extraction`
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add src/extraction.py tests/test_extraction_timeout_failsafe.py
git commit -m "fix: sandboxed-tool container timeout now escalates required-tool attachments (fail-safe gap)"
```

---

### Task 4: Extraction — OneNote (`.one`) handling

**Files:**
- Modify: `src/extraction.py` (`SANDBOX_REQUIRED_TOOLS` at `extraction.py:56`, new `_ONENOTE_MIMES` constant, new dispatch block, exclude `.one` from the MarkItDown catch-all at `extraction.py:715`)
- Test: `tests/test_extraction_onenote.py`

**Interfaces:**
- None new — reuses the existing `_run_tool()`/`_sandbox_required_failsafe()` machinery. No Docker image is built for `"onenote"`, so `_can_sandbox("onenote")` is always `False`, and `_run_tool("onenote", ...)` always returns the fail-safe escalation dict.

- [ ] **Step 1: Write the failing test**

```python
"""test_extraction_onenote.py — OneNote (.one) attachments have no mature
open-source parser available; matching the SANDBOX_REQUIRED_TOOLS fail-safe
pattern, they escalate rather than pass through unexamined. A major
2024-2025 initial-access vector (embedded .vbs/.hta/.exe behind a fake
"click to view" button)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_onenote_attachment_escalates_no_parser(tmp_path):
    f = tmp_path / "invoice.one"
    f.write_bytes(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4dfakeonenotebytes")
    att = {"stored_path": str(f), "original_name": "invoice.one",
           "declared_type": "application/onenote",
           "real_type": "application/onenote", "sha256": "f" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("sandbox_unavailable_for_onenote" in fl for fl in res["flags"])


def test_onenote_by_extension_alone_also_escalates(tmp_path):
    # declared/real type unknown, only the .one extension is present.
    f = tmp_path / "unknown.one"
    f.write_bytes(b"randombytes")
    att = {"stored_path": str(f), "original_name": "unknown.one",
           "declared_type": "application/octet-stream",
           "real_type": "application/octet-stream", "sha256": "1" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_extraction_onenote.py -v`
Expected: FAIL — `.one` currently falls only into the MarkItDown catch-all, which doesn't escalate.

- [ ] **Step 3: Edit `src/extraction.py`**

Add `.one` to the SANDBOX_REQUIRED_TOOLS set at `extraction.py:56`:
```python
SANDBOX_REQUIRED_TOOLS = {"oletools", "pdfid", "pymupdf", "markitdown", "onenote"}
```

Add `_ONENOTE_MIMES` near the other MIME-set constants (after `_ARCHIVE_MIMES` at `extraction.py:433-434`):
```python
_ONENOTE_MIMES = {"application/onenote", "application/msonenote"}
```

Add a new dispatch block in `extract_attachment()`, immediately after the OOXML DDE block and before the PDF block (after `extraction.py:671`, before `# 3. PDF`):
```python
    # 2c. OneNote (.one) — no mature open-source parser exists; treat as
    # requiring isolated analysis we can't provide, matching the
    # SANDBOX_REQUIRED_TOOLS fail-safe pattern (escalate rather than pass
    # through unexamined). A major 2024-2025 initial-access vector
    # (embedded .vbs/.hta/.exe behind a fake "click to view" button).
    if effective_mime in _ONENOTE_MIMES or filename.lower().endswith(".one"):
        one_result = _run_tool("onenote", content, stored_path, filename)
        result["tools_run"].append(one_result)
        # _run_tool always returns sandbox_required_unavailable=True here
        # (no "onenote" Docker image is ever built) — the SEC-H1 loop
        # below picks this up and escalates automatically.
```

Exclude `.one` from the MarkItDown catch-all at `extraction.py:715`:
```python
    if effective_mime not in _IMAGE_MIMES and effective_mime not in _ARCHIVE_MIMES:
```
becomes:
```python
    if (effective_mime not in _IMAGE_MIMES and effective_mime not in _ARCHIVE_MIMES
            and effective_mime not in _ONENOTE_MIMES and not filename.lower().endswith(".one")):
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_extraction_onenote.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v -k extraction`
Expected: no new failures, including `test_all_required_parsers_are_gated` in `test_extraction_sandbox_failsafe.py` (it iterates an explicit tuple `("oletools", "pdfid", "pymupdf", "markitdown")`, unaffected by adding `"onenote"` to the set).

- [ ] **Step 6: Commit**

```bash
git add src/extraction.py tests/test_extraction_onenote.py
git commit -m "feat: OneNote (.one) attachments escalate via SANDBOX_REQUIRED_TOOLS fail-safe (no parser available)"
```

---

### Task 5: Extraction — recursive archive scanning

**Files:**
- Modify: `src/extraction.py` (extend the archive-bomb block at `extraction.py:558-622` with a member-content YARA scan)
- Test: `tests/test_extraction_recursive_archive_scan.py`

**Interfaces:**
- Consumes: `_local_yara()` (Task 1) — called directly on nested member bytes, not through `_run_tool()`, matching the existing policy that YARA is byte-level pattern matching allowed to run locally regardless of sandbox availability.

- [ ] **Step 1: Write the failing test**

```python
"""test_extraction_recursive_archive_scan.py — the existing archive-bomb
check only inspects nesting depth/compression ratio/filenames; it never
scans the actual decompressed bytes. This adds a bounded first-level scan
of archive member content with YARA."""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_recursive_archive_scan_catches_yara_match_in_nested_file(tmp_path):
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("payload.txt", "powershell -enc AAAA")
    f = tmp_path / "archive.zip"
    f.write_bytes(inner_buf.getvalue())
    att = {"stored_path": str(f), "original_name": "archive.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "a" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("archive_member_yara_match" in fl for fl in res["flags"])


def test_recursive_archive_scan_clean_archive_not_flagged(tmp_path):
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("readme.txt", "just a normal invoice attachment, nothing suspicious here")
    f = tmp_path / "clean.zip"
    f.write_bytes(inner_buf.getvalue())
    att = {"stored_path": str(f), "original_name": "clean.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "d" * 64}
    res = extraction.extract_attachment(att)
    assert not any("archive_member_yara_match" in fl for fl in res["flags"])
```

- [ ] **Step 2: Run tests to verify the first fails**

Run: `pytest tests/test_extraction_recursive_archive_scan.py -v`
Expected: `test_recursive_archive_scan_catches_yara_match_in_nested_file` FAILS (nested content is never scanned today). The clean-archive test already passes (nothing to flag).

- [ ] **Step 3: Extend the archive-bomb block in `src/extraction.py`**

Insert immediately after the existing archive-bomb block's closing (`extraction.py:622`, after the `except Exception: pass  # archive check is best-effort` line), as a new self-contained block that re-checks the same `effective_mime in _ARCHIVE_MIMES or ...` condition (simpler to insert as its own unit than nesting inside the existing block's try/except structure):

```python
    # 1c. Recursive scan: actually run YARA against archive member content —
    # the bomb-check above only inspects ratios/nesting/filenames, never the
    # decompressed bytes themselves. Bounded to the first 20 members and
    # 10 MB per member (bomb-check above already caps overall risk via the
    # ratio/nesting checks); uses _local_yara directly (not the sandbox)
    # since YARA is already in the non-required-sandbox category.
    if effective_mime in _ARCHIVE_MIMES or filename.lower().endswith((".zip", ".rar", ".7z", ".gz")):
        try:
            import zipfile as _zf
            import io as _io
            zf_buf = _io.BytesIO(content)
            if _zf.is_zipfile(zf_buf):
                zf_buf.seek(0)
                with _zf.ZipFile(zf_buf, "r") as zf:
                    for member in zf.infolist()[:20]:
                        if member.file_size == 0 or member.file_size > 10 * 1024 * 1024:
                            continue
                        try:
                            member_bytes = zf.read(member.filename)
                        except RuntimeError:
                            continue  # encrypted member, can't read without password
                        member_yara = _local_yara(member_bytes)
                        if member_yara.get("suspicious"):
                            result["suspicious"] = True
                            result["escalate"] = True
                            m_matches = [m.get("rule", "?") for m in member_yara.get("matches", []) if "rule" in m]
                            result["flags"].append(
                                f"archive_member_yara_match: {member.filename} matched {', '.join(m_matches)}"
                            )
        except Exception:
            pass  # best-effort, consistent with the bomb-check block above
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_extraction_recursive_archive_scan.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v -k extraction`
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add src/extraction.py tests/test_extraction_recursive_archive_scan.py
git commit -m "feat: scan archive member content with YARA (bounded first-level recursion)"
```

---

### Task 6: CAPE — signature-category escalation override

**Files:**
- Modify: `src/detonation_config.py` (new `ANTI_ANALYSIS_SIGNATURE_PATTERNS` constant)
- Modify: `src/cape_client.py` (import the constant, use it in `parse_report()`)
- Test: append to `tests/test_detonation.py` (matches existing `parse_report()` test style exactly)

**Interfaces:**
- Produces: `detonation_config.ANTI_ANALYSIS_SIGNATURE_PATTERNS: tuple[str, ...]`, consumed only by `cape_client.parse_report()`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_detonation.py`, after `test_parse_report_suspicious_by_signature` (after line 67):

```python
def test_parse_report_forces_escalate_on_antisandbox_signature():
    from cape_client import parse_report
    # Low malscore (below CAPE_MALSCORE_ESCALATE) but an anti-sandbox
    # signature fired — must still escalate. This is the core evasion-
    # hardening fix: a sample that detects the sandbox and goes dormant
    # would otherwise score low and never escalate.
    report = {
        "info": {"score": 1.2, "category": "file"},
        "signatures": [{"name": "antisandbox_sleep", "description": "Detects sleep-based sandbox evasion"}],
    }
    r = parse_report(report, task_id=55)
    assert r["escalate"] is True
    assert r["suspicious"] is True


def test_parse_report_does_not_escalate_on_unrelated_low_score_signature():
    from cape_client import parse_report
    report = {
        "info": {"score": 1.0},
        "signatures": [{"name": "network_http", "description": "Performs an HTTP request"}],
    }
    r = parse_report(report, task_id=56)
    assert r["escalate"] is False
    assert r["suspicious"] is True  # bool(sig_names) still makes it suspicious — existing behavior


def test_parse_report_escalates_on_antivm_description_even_if_name_generic():
    from cape_client import parse_report
    # The pattern match is against BOTH name and description text (whichever
    # ends up in sig_names — parse_report prefers description over name).
    report = {
        "info": {"score": 0.8},
        "signatures": [{"name": "sig_042", "description": "Checks for VM-specific registry keys (antivm)"}],
    }
    r = parse_report(report, task_id=57)
    assert r["escalate"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_detonation.py -v -k antisandbox or antivm`
Expected: FAIL — no signature-category override exists yet, so `escalate` stays `False` for a malscore of 1.2/0.8.

- [ ] **Step 3: Add the constant to `src/detonation_config.py`**

Insert after the existing verdict-mapping block (after `detonation_config.py:69`, before the `# Which file types are worth detonating` comment):

```python
# --------------------------------------------------------------------------
# Evasion hardening: signature-category escalation override
# --------------------------------------------------------------------------
# CAPE's malscore can stay low for a sample that detects the sandbox and
# goes dormant — but CAPE still logs an anti-sandbox/anti-VM/anti-debug
# signature when that happens. Any signature name/description matching one
# of these substrings (case-insensitive) forces escalation regardless of
# malscore, closing that blind spot.
ANTI_ANALYSIS_SIGNATURE_PATTERNS = (
    "antisandbox", "anti-sandbox", "anti_sandbox",
    "antivm", "anti-vm", "anti_vm",
    "antidebug", "anti-debug", "anti_debug",
    "antiemulation", "anti-emulation", "anti_emulation",
    "stalling", "sandbox_evasion", "sandbox evasion", "vmdetect",
)
```

- [ ] **Step 4: Wire it into `src/cape_client.py`**

Edit the import block at `cape_client.py:19-25`:
```python
from detonation_config import (
    CAPE_API_URL, CAPE_API_TOKEN, CAPE_VERIFY_TLS,
    CAPE_HTTP_TIMEOUT, CAPE_POLL_INTERVAL, CAPE_TOTAL_TIMEOUT,
    CAPE_ANALYSIS_TIMEOUT, CAPE_READY_TIMEOUT, CAPE_ENFORCE_TIMEOUT,
    CAPE_MALSCORE_ESCALATE, CAPE_MALSCORE_SUSPICIOUS,
    CAPE_VM_WRAPPER_ENABLED, IMAGE_EXTENSIONS,
    ANTI_ANALYSIS_SIGNATURE_PATTERNS,
)
```

Edit `parse_report()` at `cape_client.py:185-186`:
```python
    escalate = malscore >= CAPE_MALSCORE_ESCALATE
    suspicious = malscore >= CAPE_MALSCORE_SUSPICIOUS or bool(sig_names)
```
becomes:
```python
    escalate = malscore >= CAPE_MALSCORE_ESCALATE
    suspicious = malscore >= CAPE_MALSCORE_SUSPICIOUS or bool(sig_names)

    # Evasion hardening: a sample that detects the sandbox and goes dormant
    # can score low on malscore, but CAPE still logs the anti-sandbox/anti-VM
    # signature when that happens — force escalate regardless of malscore.
    anti_analysis_hit = any(
        pattern in name.lower()
        for name in sig_names
        for pattern in ANTI_ANALYSIS_SIGNATURE_PATTERNS
    )
    if anti_analysis_hit:
        escalate = True
        suspicious = True
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_detonation.py -v`
Expected: PASS (all tests in the file, including the 3 new ones).

- [ ] **Step 6: Run the full existing suite**

Run: `pytest tests/ -v -k detonation`
Expected: no new failures.

- [ ] **Step 7: Commit**

```bash
git add src/detonation_config.py src/cape_client.py tests/test_detonation.py
git commit -m "feat: CAPE signature-category override forces escalate on anti-sandbox/anti-VM signatures regardless of malscore"
```

---

### Task 7: CAPE — submission-side anti-evasion options (scaffolding, disabled by default)

**Files:**
- Modify: `src/detonation_config.py` (new `CAPE_ANTI_EVASION_OPTIONS_ENABLED`/`CAPE_ANTI_EVASION_OPTIONS` env-driven config)
- Modify: `src/cape_client.py` (`submit_file()` at `cape_client.py:79-113`)
- Modify: `.env.example` (document the new toggle)
- Test: append to `tests/test_detonation.py`

**Interfaces:**
- Produces: `detonation_config.CAPE_ANTI_EVASION_OPTIONS_ENABLED: bool`, `detonation_config.CAPE_ANTI_EVASION_OPTIONS: str`, consumed only by `cape_client.submit_file()`.

- [ ] **Step 1: Confirm CAPE is still unreachable from this dev machine**

Run: `python -c "import sys; sys.path.insert(0,'src'); import cape_client; print(cape_client.is_available())"`
Expected: `False` (already confirmed during planning — CAPE runs on a separate VM not reachable from this dev box). If this now prints `True`, STOP and consult the live instance's `docs/book/src/usage/submit.rst` or web UI submission form for the exact current option key names before proceeding with Step 3 below — do not guess.

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_detonation.py`:

```python
def test_submit_file_sends_no_options_by_default(monkeypatch, tmp_path):
    import cape_client
    monkeypatch.setattr(cape_client, "CAPE_ANTI_EVASION_OPTIONS_ENABLED", False)
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZfake")
    captured = {}

    def fake_post(url, headers=None, files=None, data=None, timeout=None, verify=None):
        captured["data"] = data
        return _FakeResponse(json_data={"data": {"task_id": 1}})

    monkeypatch.setattr(cape_client.requests, "post", fake_post)
    cape_client.submit_file(str(f), "x.exe")
    assert "options" not in captured["data"]


def test_submit_file_sends_options_when_enabled(monkeypatch, tmp_path):
    import cape_client
    monkeypatch.setattr(cape_client, "CAPE_ANTI_EVASION_OPTIONS_ENABLED", True)
    monkeypatch.setattr(cape_client, "CAPE_ANTI_EVASION_OPTIONS", "human=1")
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZfake")
    captured = {}

    def fake_post(url, headers=None, files=None, data=None, timeout=None, verify=None):
        captured["data"] = data
        return _FakeResponse(json_data={"data": {"task_id": 1}})

    monkeypatch.setattr(cape_client.requests, "post", fake_post)
    cape_client.submit_file(str(f), "x.exe")
    assert captured["data"]["options"] == "human=1"
```

(These use the existing `_FakeResponse` class already defined in `tests/test_detonation.py` at lines 89-97 — no new mock class needed.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_detonation.py -v -k anti_evasion_options`
Expected: FAIL — `CAPE_ANTI_EVASION_OPTIONS_ENABLED` doesn't exist as an attribute on `cape_client` yet.

- [ ] **Step 4: Add config to `src/detonation_config.py`**

Insert after the `ANTI_ANALYSIS_SIGNATURE_PATTERNS` block added in Task 6:

```python
# --------------------------------------------------------------------------
# Evasion hardening: submission-side anti-evasion options
# --------------------------------------------------------------------------
# CAPE has debugger/tracing options (bp0-bp3, count, depth) and a
# human-interaction-emulation toggle per current docs, but the exact
# option key names must be confirmed against the LIVE CAPE instance before
# enabling — docs found during the 2026-07-31 evasion-hardening research
# were inconsistent across versions, and CAPE is not reachable from this
# dev machine to verify directly. Disabled by default (no extra options
# sent, unchanged behavior) until verified live, matching this project's
# established practice of confirming against the real instance rather than
# guessing (see the 2026-07-27 CAPE-proxy build log entries).
CAPE_ANTI_EVASION_OPTIONS_ENABLED = os.getenv("CAPE_ANTI_EVASION_OPTIONS_ENABLED", "0") != "0"
# Raw CAPE "options" submission string (CAPE's own semicolon-separated
# key=value format), only sent when the toggle above is on.
CAPE_ANTI_EVASION_OPTIONS = os.getenv("CAPE_ANTI_EVASION_OPTIONS", "")
```

- [ ] **Step 5: Wire it into `src/cape_client.py`**

Add to the import block (extending the one edited in Task 6):
```python
from detonation_config import (
    CAPE_API_URL, CAPE_API_TOKEN, CAPE_VERIFY_TLS,
    CAPE_HTTP_TIMEOUT, CAPE_POLL_INTERVAL, CAPE_TOTAL_TIMEOUT,
    CAPE_ANALYSIS_TIMEOUT, CAPE_READY_TIMEOUT, CAPE_ENFORCE_TIMEOUT,
    CAPE_MALSCORE_ESCALATE, CAPE_MALSCORE_SUSPICIOUS,
    CAPE_VM_WRAPPER_ENABLED, IMAGE_EXTENSIONS,
    ANTI_ANALYSIS_SIGNATURE_PATTERNS,
    CAPE_ANTI_EVASION_OPTIONS_ENABLED, CAPE_ANTI_EVASION_OPTIONS,
)
```

Edit `submit_file()` at `cape_client.py:93-95`:
```python
            ext = os.path.splitext(filename or "")[1].lower()
            if ext in IMAGE_EXTENSIONS:
                data["package"] = "image"
```
becomes:
```python
            ext = os.path.splitext(filename or "")[1].lower()
            if ext in IMAGE_EXTENSIONS:
                data["package"] = "image"
            if CAPE_ANTI_EVASION_OPTIONS_ENABLED and CAPE_ANTI_EVASION_OPTIONS:
                data["options"] = CAPE_ANTI_EVASION_OPTIONS
```

- [ ] **Step 6: Document in `.env.example`**

Add near the existing CAPE detonation section (after the `CAPE_MALSCORE_SUSPICIOUS` line):
```
# Evasion hardening: submission-side anti-evasion options (disabled by
# default — exact CAPE option key names must be verified against the live
# CAPE instance before enabling; see the 2026-07-31 evasion-hardening
# build log entry).
CAPE_ANTI_EVASION_OPTIONS_ENABLED=0
CAPE_ANTI_EVASION_OPTIONS=
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_detonation.py -v`
Expected: PASS (all tests, including the 2 new ones).

- [ ] **Step 8: Run the full existing suite**

Run: `pytest tests/ -v -k detonation`
Expected: no new failures.

- [ ] **Step 9: Commit**

```bash
git add src/detonation_config.py src/cape_client.py tests/test_detonation.py .env.example
git commit -m "feat: add disabled-by-default CAPE anti-evasion submission-options scaffolding (pending live-instance verification)"
```

---

### Task 8: CLAUDE.md build log entry

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Append a new Build Log entry**

Add to the end of the "## Build Log" section in `CLAUDE.md`, after the 2026-07-30 secrets-manager entry:

```markdown
- **2026-07-31 (Evasion hardening)** — Hardened YARA rules, the isolated
  extraction layer, and CAPE detonation logic against evasive attachments
  ahead of an internal red-team test (spec:
  `docs/superpowers/specs/2026-07-31-evasion-hardening-design.md`, plan:
  `docs/superpowers/plans/2026-07-31-evasion-hardening.md`). Preceded by
  two research passes: current codebase architecture, and 2025-2026
  phishing/evasive-attachment tactics.
  **Top finding:** CAPE's escalation logic was malscore-only — a sample
  that detects the sandbox and goes dormant produced a low malscore even
  though CAPE's own anti-sandbox/anti-VM signatures fired. Fixed with a
  new `ANTI_ANALYSIS_SIGNATURE_PATTERNS` check in `cape_client.parse_report()`
  that forces `escalate=True` on any anti-sandbox/anti-VM/anti-debug
  signature name/description match, regardless of malscore.
  Other changes: `data/yara_rules/evasion.yar` (entropy check via YARA's
  `math` module, `pe`-module structural rules for process-injection
  imports/packer sections, `xor`/`base64`/`base64wide` variants of
  high-value keywords) plus compile-once caching in `_local_yara()`
  (previously recompiled every scan); real structural password-protection
  detection (`_detect_encryption()` — ZIP encryption flag bit, OOXML
  `EncryptedPackage`/`EncryptionInfo` streams via `olefile`, now pinned
  explicitly) replacing the old MIME/extension-only heuristic; OneNote
  (`.one`) attachments now escalate via the existing `SANDBOX_REQUIRED_TOOLS`
  fail-safe pattern (no mature open-source parser exists, so no new Docker
  image was needed — reused the existing "no sandbox available →
  escalate" machinery as-is); recursive archive scanning (YARA now runs
  against the first 20 archive-member files' decompressed bytes, not just
  filename/ratio bomb-checks); and a container-timeout fail-safe fix
  (`sandbox.py`'s `TimeoutExpired` handler didn't set `fallback=True`, so
  a `SANDBOX_REQUIRED_TOOLS` tool timing out never reliably escalated —
  closed with a dedicated timeout-detection loop in `extract_attachment()`).
  **Known limitation, not solved here:** CAPE submission-side anti-evasion
  options (`CAPE_ANTI_EVASION_OPTIONS_ENABLED`/`CAPE_ANTI_EVASION_OPTIONS`)
  shipped as scaffolding, disabled by default — CAPE is not reachable from
  this dev machine, so the exact option key names (debugger/tracing
  options, human-interaction-emulation toggle) could not be verified
  against the live instance. Enable only after confirming against the real
  CAPE instance's submission form/docs, matching this project's
  established practice (see the 2026-07-27 CAPE-proxy build log entries).
  **Also deferred (parallel, non-blocking effort):** the user is
  dispatching a separate research agent to find a labeled dataset of
  evasive-attachment samples (password-protected archives, polyglots,
  OneNote payloads, sandbox-evasive malware) to empirically validate this
  hardening — EPVME (49k emails) was confirmed almost entirely
  attachment-free during research, so it validates the rules/LLM layer
  (and doubles as the user's professor deliverable) but not this spec's
  new detection logic specifically.
```

- [ ] **Step 2: No commit** — `CLAUDE.md` is gitignored with zero git history in this repo (confirmed during the secrets-manager session), matching established local-only convention. Leave it updated on disk.

---

### Task 9: Full regression suite + EPVME run

**Files:** None modified — verification only.

- [ ] **Step 1: Run the full test suite with coverage**

Run: `pytest tests/ --cov=src --cov-report=term -v`
Expected: all tests pass (baseline was 284 passed, 1 skipped as of the secrets-manager session; expect that plus this plan's ~20 new tests, all passing), coverage at or above the existing floor.

- [ ] **Step 2: Manual smoke test — confirm the new rules/logic actually load**

Run:
```bash
python -c "
import sys; sys.path.insert(0, 'src')
import extraction
print('YARA rule files:', [f.name for f in extraction.YARA_RULES_DIR.glob('*.yar')])
result = extraction._local_yara(b'test')
print('YARA scan status:', result['status'])
import cape_client
print('ANTI_ANALYSIS_SIGNATURE_PATTERNS loaded:', len(__import__('detonation_config').ANTI_ANALYSIS_SIGNATURE_PATTERNS), 'patterns')
"
```
Expected: `evasion.yar` and `suspicious.yar` both listed, YARA scan status `ok`, pattern count printed with no import errors.

- [ ] **Step 3: Run the EPVME 5k-sample regression + professor deliverable**

Run: `python src/epvme_test.py --count 5000 --with-llm`

(Add `--with-detonation` only if a live CAPE instance is reachable at run time — per Task 7's confirmed-unreachable state during planning, expect to omit it unless that's changed by the time this step runs.)

Expected: completes and writes results to `data/epvme_results/` (matching the existing 500-sample run's output format — `epvme_report.json` + chart PNGs). This is a regression check on the rules/LLM layer (EPVME is confirmed attachment-sparse, so it does not exercise this plan's new YARA/extraction/CAPE logic) and the user's professor deliverable — report the resulting detection rate/precision/recall/F1 back to the user once complete.

- [ ] **Step 4: Report results to the user**

Summarize: full suite pass/fail counts, EPVME 5k detection metrics, and a reminder that empirical validation of the new evasion-hardening logic specifically is still pending the external dataset (parallel effort, not blocking).
