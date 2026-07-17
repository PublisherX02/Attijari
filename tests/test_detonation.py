"""Tests for the CAPE-based, memory-gated detonation subsystem.

These cover the host-side logic that runs WITHOUT a live CAPE box:
  - config surface
  - file-type gating
  - CAPE report → pipeline-verdict mapping
  - the global pause flag
  - fail-safe behavior when CAPE is unreachable
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_config_has_required_fields():
    import detonation_config as cfg
    assert cfg.CAPE_API_URL
    assert cfg.CAPE_MALSCORE_ESCALATE >= cfg.CAPE_MALSCORE_SUSPICIOUS
    assert cfg.DETONATION_CYCLE_TIMEOUT > 0
    assert ".exe" in cfg.SUPPORTED_EXTENSIONS
    assert ".pdf" in cfg.SUPPORTED_EXTENSIONS


def test_should_detonate_extension():
    from detonation import should_detonate
    assert should_detonate("invoice.docm") is True
    assert should_detonate("malware.exe") is True
    assert should_detonate("readme.txt") is False
    assert should_detonate("photo.jpg") is True  # CAPE image package, added 2026-07-16
    assert should_detonate("report.pdf") is True
    assert should_detonate("script.ps1") is True
    assert should_detonate("data.csv") is False


def test_parse_report_malicious():
    from cape_client import parse_report
    report = {
        "info": {"score": 8.0, "category": "file"},
        "signatures": [{"name": "ransomware", "description": "encrypts files"}],
        "behavior": {"processes": [1, 2, 3]},
        "network": {"hosts": ["1.2.3.4"]},
    }
    r = parse_report(report, task_id=42)
    assert r["escalate"] is True
    assert r["suspicious"] is True
    assert r["risk_score"] == 80
    assert r["cape_task_id"] == 42
    assert "encrypts files" in r["suspicious_behaviors"]
    assert r["processes_spawned"] == 3


def test_parse_report_clean():
    from cape_client import parse_report
    r = parse_report({"info": {"score": 0.5}}, task_id=7)
    assert r["escalate"] is False
    assert r["suspicious"] is False
    assert r["risk_score"] == 5


def test_parse_report_suspicious_by_signature():
    from cape_client import parse_report
    # low score but a signature fired → suspicious, not escalate
    r = parse_report({"info": {"score": 3.5}, "signatures": [{"name": "persistence"}]}, task_id=9)
    assert r["suspicious"] is True
    assert r["escalate"] is False


def test_pause_flag_lifecycle():
    import detonation_state as st
    assert st.is_active() is False
    st.begin("test")
    assert st.is_active() is True
    assert st.status()["reason"] == "test"
    st.end()
    assert st.is_active() is False


def test_detonate_failsafe_on_submit_error(monkeypatch):
    import cape_client
    # Simulate CAPE refusing the submission → must fail SAFE (escalate).
    monkeypatch.setattr(cape_client, "submit_file", lambda *a, **k: None)
    r = cape_client.detonate("/nonexistent/path", "x.exe")
    assert r["escalate"] is True
    assert r["suspicious"] is True
    assert r["status"] == "error"
