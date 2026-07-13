"""Tests for the CAPE sandbox <-> dashboard integration layer.

Hermetic host-side tests (no DB, no network, no live CAPE):
  - config surface for the wrapper / websockify / web-report plumbing
  - cape_vm_wrapper client fail-safe behavior
  - cuckoo2 pre-flight recovery logic
  - report-proxy URL allowlist + HTML rewriting
  - /raw content-type sniffing (magic bytes, never declared type)
  - VNC relay token check
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_config_has_wrapper_fields():
    import detonation_config as cfg
    assert isinstance(cfg.CAPE_VM_WRAPPER_ENABLED, bool)
    assert cfg.CAPE_VM_WRAPPER_URL.startswith("http")
    assert not cfg.CAPE_VM_WRAPPER_URL.endswith("/")
    assert cfg.CAPE_VM_WRAPPER_TIMEOUT > 0
    assert cfg.WEBSOCKIFY_URL.startswith("ws")
    # CAPE_WEB_URL is the Django UI base: API URL without the /apiv2 suffix
    assert not cfg.CAPE_WEB_URL.endswith("/apiv2")
    assert not cfg.CAPE_WEB_URL.endswith("/")


def test_wrapper_client_disabled_returns_none(monkeypatch):
    import cape_vm_wrapper
    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", False)
    assert cape_vm_wrapper.cuckoo2_state() is None
    assert cape_vm_wrapper.reset_cuckoo2() is False


def test_wrapper_client_state_ok(monkeypatch):
    import cape_vm_wrapper

    class FakeResp:
        status_code = 200
        def json(self):
            return {"cuckoo2": "shut off"}

    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper.requests, "get", lambda *a, **kw: FakeResp())
    assert cape_vm_wrapper.cuckoo2_state() == "shut off"


def test_wrapper_client_never_raises(monkeypatch):
    import cape_vm_wrapper

    def boom(*a, **kw):
        raise ConnectionError("wrapper down")

    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper.requests, "get", boom)
    monkeypatch.setattr(cape_vm_wrapper.requests, "post", boom)
    assert cape_vm_wrapper.cuckoo2_state() is None
    assert cape_vm_wrapper.reset_cuckoo2() is False


def test_wrapper_client_reset_ok(monkeypatch):
    import cape_vm_wrapper

    class FakeResp:
        status_code = 200

    captured = {}

    def fake_post(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResp()

    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_TOKEN", "sekret")
    monkeypatch.setattr(cape_vm_wrapper.requests, "post", fake_post)
    assert cape_vm_wrapper.reset_cuckoo2() is True
    assert captured["url"].endswith("/vm/reset")
    assert captured["headers"]["Authorization"] == "Bearer sekret"


def test_preflight_resets_stuck_cuckoo2(monkeypatch):
    import detonation
    import detonation_config as cfg
    import cape_vm_wrapper
    import cape_client

    calls = []
    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "cuckoo2_state", lambda: "running")
    monkeypatch.setattr(cape_vm_wrapper, "reset_cuckoo2",
                        lambda: calls.append("reset") or True)
    monkeypatch.setattr(cape_client, "wait_until_ready",
                        lambda t: calls.append("wait") or True)
    detonation._preflight_cuckoo2()
    assert calls == ["reset", "wait"]


def test_preflight_noop_when_cuckoo2_off(monkeypatch):
    import detonation
    import detonation_config as cfg
    import cape_vm_wrapper

    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "cuckoo2_state", lambda: "shut off")
    monkeypatch.setattr(cape_vm_wrapper, "reset_cuckoo2",
                        lambda: (_ for _ in ()).throw(AssertionError("must not reset")))
    detonation._preflight_cuckoo2()  # must not raise, must not reset


def test_preflight_never_raises_when_wrapper_down(monkeypatch):
    import detonation
    import detonation_config as cfg
    import cape_vm_wrapper

    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "cuckoo2_state",
                        lambda: (_ for _ in ()).throw(RuntimeError("down")))
    detonation._preflight_cuckoo2()  # swallowed — window must proceed


def test_sniff_media_type_magic_bytes():
    # JWT_SECRET must exist before any api_core import chain
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _sniff_media_type
    assert _sniff_media_type(b"%PDF-1.7 blah") == ("application/pdf", True)
    assert _sniff_media_type(b"\x89PNG\r\n\x1a\nxxxx") == ("image/png", True)
    assert _sniff_media_type(b"\xff\xd8\xff\xe0rest") == ("image/jpeg", True)
    assert _sniff_media_type(b"GIF89a....") == ("image/gif", True)
    # a docm renamed to .pdf still gets octet-stream: magic bytes win (rule 7)
    assert _sniff_media_type(b"PK\x03\x04word/") == ("application/octet-stream", False)
    assert _sniff_media_type(b"") == ("application/octet-stream", False)


def test_report_proxy_upstream_path_allowlist():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _upstream_path
    assert _upstream_path(42, "") == "analysis/42/"
    assert _upstream_path(42, "analysis/42/") == "analysis/42/"
    assert _upstream_path(42, "static/css/style.css") == "static/css/style.css"
    # never proxy CAPE admin or arbitrary paths
    assert _upstream_path(42, "admin/") is None
    assert _upstream_path(42, "apiv2/tasks/list/") is None
    assert _upstream_path(42, "static/../admin/") is None


def test_report_proxy_rewrites_root_relative_refs():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _rewrite_report_html
    html = (
        '<link href="/static/css/a.css"><script src="/static/js/b.js"></script>'
        '<a href="/analysis/42/network/">net</a>'
        '<a href="https://example.com/x">ext</a>'
        '<a href="//cdn.example.com/y">proto-rel</a>'
        '<style>.x{background:url(/static/img/z.png)}</style>'
    )
    out = _rewrite_report_html(html, 42)
    assert 'href="/api/detonation/report/42/static/css/a.css"' in out
    assert 'src="/api/detonation/report/42/static/js/b.js"' in out
    assert 'href="/api/detonation/report/42/analysis/42/network/"' in out
    # absolute and protocol-relative URLs untouched
    assert 'href="https://example.com/x"' in out
    assert 'href="//cdn.example.com/y"' in out
    assert 'url(/api/detonation/report/42/static/img/z.png)' in out


def test_parse_report_includes_proxied_web_report_url():
    from cape_client import parse_report
    r = parse_report({"info": {"score": 2.0}}, task_id=123)
    assert r["web_report_url"] == "/api/detonation/report/123/"


def test_preflight_disabled_is_noop(monkeypatch):
    import detonation
    import detonation_config as cfg
    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", False)
    detonation._preflight_cuckoo2()  # no wrapper import side effects required
