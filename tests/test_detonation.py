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


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", content_type="application/json"):
        self.status_code = status_code
        self._json = json_data
        self.content = content
        self.headers = {"content-type": content_type}

    def json(self):
        return self._json


def test_list_machines_returns_data_on_success(monkeypatch):
    import cape_client
    fake = _FakeResponse(json_data={"error": False, "data": [{"name": "cuckoo2", "platform": "windows"}]})
    monkeypatch.setattr(cape_client.requests, "get", lambda *a, **k: fake)
    machines = cape_client.list_machines()
    assert machines == [{"name": "cuckoo2", "platform": "windows"}]


def test_list_machines_none_when_api_disabled(monkeypatch):
    """CAPE's machines/list returns HTTP 200 with an error body when the
    feature is disabled in api.conf (confirmed live) — not a 403/404."""
    import cape_client
    fake = _FakeResponse(json_data={"error": True, "error_value": "Machine list API is disabled"})
    monkeypatch.setattr(cape_client.requests, "get", lambda *a, **k: fake)
    assert cape_client.list_machines() is None


def test_view_machine_builds_correct_path(monkeypatch):
    import cape_client
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        return _FakeResponse(json_data={"error": False, "data": {"name": "cuckoo2"}})

    monkeypatch.setattr(cape_client.requests, "get", fake_get)
    result = cape_client.view_machine("cuckoo2")
    assert result == {"name": "cuckoo2"}
    assert seen["url"].endswith("/machines/view/cuckoo2/")


def test_list_tasks_builds_limit_offset_path(monkeypatch):
    """Confirmed live against a real CAPE instance: tasks/list/<limit>/ and
    tasks/list/<limit>/<offset>/ are real path segments (a plain count-based
    page size), not a "last N days" filter — a bare ?days= query param had
    no effect on the response at all."""
    import cape_client
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        return _FakeResponse(json_data={"error": False, "data": []})

    monkeypatch.setattr(cape_client.requests, "get", fake_get)
    cape_client.list_tasks()
    assert seen["url"].endswith("/tasks/list/")
    cape_client.list_tasks(limit=7)
    assert seen["url"].endswith("/tasks/list/7/")
    cape_client.list_tasks(limit=50, offset=10)
    assert seen["url"].endswith("/tasks/list/50/10/")


def test_fetch_task_mitmdump_returns_bytes_on_success(monkeypatch):
    import cape_client
    fake = _FakeResponse(content=b"binary-har-data", content_type="application/octet-stream")
    monkeypatch.setattr(cape_client.requests, "get", lambda *a, **k: fake)
    assert cape_client.fetch_task_mitmdump(41) == b"binary-har-data"


def test_fetch_task_mitmdump_none_when_api_disabled(monkeypatch):
    """Confirmed live: disabled mitmdump API returns 200 + JSON error body,
    not a non-200 — must not be handed back as if it were the file."""
    import cape_client
    fake = _FakeResponse(
        json_data={"error": True, "error_value": "Mitmdump HAR download API is disabled"},
        content=b'{"error": true, "error_value": "Mitmdump HAR download API is disabled"}',
        content_type="application/json",
    )
    monkeypatch.setattr(cape_client.requests, "get", lambda *a, **k: fake)
    assert cape_client.fetch_task_mitmdump(41) is None
