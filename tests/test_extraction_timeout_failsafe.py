"""test_extraction_timeout_failsafe.py — a sandboxed-tool container timeout
for a SANDBOX_REQUIRED_TOOLS tool must escalate the whole attachment
("Crash or timeout -> escalate, never accept"). Closes a gap
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
