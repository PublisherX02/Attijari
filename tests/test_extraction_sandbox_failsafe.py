"""SEC-H1 regression: complex-format parsers must never run unsandboxed.

When Docker is unavailable, oletools / pdfid / pymupdf / markitdown must NOT
fall back to in-process host parsing of attacker-controlled files — the
attachment escalates instead (fail-safe). magic / yara / tesseract stay
allowed to run locally.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def _no_sandbox(monkeypatch):
    """Force the 'Docker unavailable' condition."""
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: False)
    monkeypatch.setattr(extraction, "_allow_unsandboxed", lambda: False)


def test_oletools_escalates_instead_of_local_parse(monkeypatch):
    _no_sandbox(monkeypatch)
    # If the local parser is ever called, fail loudly — it must not be.
    monkeypatch.setattr(extraction, "_local_oletools",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local oletools ran unsandboxed!")))
    res = extraction._run_tool("oletools", b"\xd0\xcf\x11\xe0macro", "/tmp/x.doc", "x.doc")
    assert res["escalate"] is True
    assert res["suspicious"] is True
    assert res["sandbox_required_unavailable"] is True
    assert res.get("sandboxed") is False


def test_all_required_parsers_are_gated(monkeypatch):
    _no_sandbox(monkeypatch)
    for tool in ("oletools", "pdfid", "pymupdf", "markitdown"):
        res = extraction._run_tool(tool, b"data", "/tmp/x.bin", "x.bin")
        assert res["escalate"] is True, f"{tool} should escalate when unsandboxed"
        assert res["sandbox_required_unavailable"] is True, f"{tool} not gated"


def test_low_risk_tools_still_run_local(monkeypatch):
    # yara is byte-level pattern matching, allowed to run local when Docker down.
    _no_sandbox(monkeypatch)
    ran = {"yara": False}

    def _fake_yara(content):
        ran["yara"] = True
        return {"tool": "yara", "status": "ok", "matches": [], "suspicious": False}

    monkeypatch.setattr(extraction, "_local_yara", _fake_yara)
    res = extraction._run_tool("yara", b"data", "/tmp/x.bin", "x.bin")
    assert ran["yara"] is True
    assert not res.get("sandbox_required_unavailable")


def test_escape_hatch_allows_local_when_explicitly_enabled(monkeypatch):
    # EXTRACTION_ALLOW_UNSANDBOXED=1 restores old dev behaviour.
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: False)
    monkeypatch.setattr(extraction, "_allow_unsandboxed", lambda: True)
    ran = {"ole": False}

    def _fake_ole(content, filename):
        ran["ole"] = True
        return {"tool": "oletools", "status": "ok", "suspicious": False, "macros": []}

    monkeypatch.setattr(extraction, "_local_oletools", _fake_ole)
    res = extraction._run_tool("oletools", b"data", "/tmp/x.doc", "x.doc")
    assert ran["ole"] is True
    assert not res.get("sandbox_required_unavailable")


def test_extract_attachment_escalates_office_doc_when_no_sandbox(monkeypatch, tmp_path):
    # End-to-end at the attachment level: a .docm with the sandbox down must
    # escalate and must never invoke the local Office parser.
    _no_sandbox(monkeypatch)
    monkeypatch.setattr(extraction, "_local_oletools",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local oletools ran!")))
    monkeypatch.setattr(extraction, "_local_markitdown",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local markitdown ran!")))

    f = tmp_path / "invoice.docm"
    f.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1payload")
    att = {"stored_path": str(f), "original_name": "invoice.docm",
           "declared_type": "application/vnd.ms-word.document.macroEnabled.12",
           "real_type": "application/vnd.ms-word.document.macroEnabled.12", "sha256": "d" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("sandbox_unavailable_for_" in fl for fl in res["flags"])
