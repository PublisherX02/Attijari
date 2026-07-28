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
    """Prefixes verified against a live CAPE report page (task 56, attijari,
    2026-07-27): every root-relative link CAPE itself emits — report tabs,
    nav bar Submit/Search/Pending, Statistics, Compare, dropped/static file
    downloads, the JSON export link, and the nav bar's own "API" link — falls
    under one of these namespaces. The proxy only ever forwards GET (see the
    router's @get decorator), so allow-listing apiv2/ here can't be used to
    trigger CAPE's mutating actions (those are POSTs)."""
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _upstream_path
    assert _upstream_path(42, "") == "analysis/42/"
    assert _upstream_path(42, "analysis/42/") == "analysis/42/"
    assert _upstream_path(42, "static/css/style.css") == "static/css/style.css"
    # real tab/link targets seen on a live report
    assert _upstream_path(42, "analysis/load_files/42/behavior/") == "analysis/load_files/42/behavior/"
    assert _upstream_path(42, "analysis/load_files/42/network/") == "analysis/load_files/42/network/"
    assert _upstream_path(42, "analysis/42/pcapstream/1/") == "analysis/42/pcapstream/1/"
    assert _upstream_path(42, "apiv2/") == "apiv2/"
    assert _upstream_path(42, "filereport/42/json/") == "filereport/42/json/"
    assert _upstream_path(42, "submit/resubmit/42/abc/") == "submit/resubmit/42/abc/"
    assert _upstream_path(42, "compare/42/") == "compare/42/"
    assert _upstream_path(42, "statistics/7/") == "statistics/7/"
    assert _upstream_path(42, "file/staticzip/42/abc/") == "file/staticzip/42/abc/"
    # never proxy CAPE admin or arbitrary paths
    assert _upstream_path(42, "admin/") is None
    assert _upstream_path(42, "static/../admin/") is None
    assert _upstream_path(42, "../../etc/passwd") is None


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


def test_report_proxy_tags_inline_scripts_with_csp_nonce():
    """The dashboard's CSP is nonce-only, no 'unsafe-inline' (api.py's
    security_and_metrics_middleware). CAPE ships its tabajax tab-switching
    logic as inline <script> blocks with no nonce, which the browser
    silently drops — the click still moves the URL (plain <a href="#...">)
    but nothing runs to actually load the tab content. Confirmed live: the
    real report HTML has 4 inline <script>/<script type='...'> blocks, none
    carrying a nonce, alongside <script src=...> tags that don't need one
    (same-origin, already covered by script-src 'self')."""
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _rewrite_report_html
    html = (
        '<script src="/static/js/jquery.js"></script>'
        "<script>$('[data-bs-toggle=\"tabajax\"]').click(function(){});</script>"
        "<script type='text/javascript'>var x = 1;</script>"
    )
    out = _rewrite_report_html(html, 42, nonce="abc123")
    assert '<script src="/api/detonation/report/42/static/js/jquery.js"></script>' in out
    assert 'src=' not in out.split('<script nonce="abc123">')[1].split('</script>')[0]
    assert '<script nonce="abc123">' in out
    assert "<script nonce=\"abc123\" type='text/javascript'>" in out
    # without a nonce (e.g. never expected to happen, but keep it inert) inline
    # scripts pass through unmodified rather than raising
    out_no_nonce = _rewrite_report_html(html, 42)
    assert 'nonce=' not in out_no_nonce


def test_report_proxy_forwards_x_requested_with_to_upstream():
    """CAPE 403s the behavior/network tabajax partials without this header
    (confirmed live: identical request with vs. without X-Requested-With
    gave 200 vs. 403 from the real CAPE instance) — the proxy must forward
    whatever the browser's jQuery `.load()` call sent, and nothing else."""
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _upstream_headers

    class FakeRequest:
        def __init__(self, headers):
            self.headers = headers

    assert _upstream_headers(FakeRequest({"x-requested-with": "XMLHttpRequest"})) == {
        "X-Requested-With": "XMLHttpRequest"
    }
    assert _upstream_headers(FakeRequest({})) == {}
    # never forward cookies/auth — the proxy uses its own CAPE credentials
    assert _upstream_headers(FakeRequest({"cookie": "sessionid=abc"})) == {}


def test_report_proxy_rewrites_data_url_attrs_and_inline_js_literals():
    """The actual bug: CAPE's behavior/network tabs load via jQuery
    `data-url="/analysis/..."` (not href/src/action), and the PCAP viewer
    fires `$.get("/analysis/56/pcapstream/"+n)` from inline <script> — both
    are plain quoted root-relative strings, not HTML attributes the old
    href=/src=/action=-only regex recognized."""
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _rewrite_report_html
    html = (
        '<a data-bs-toggle="tabajax" data-url="/analysis/load_files/42/behavior/">Behavior</a>'
        '<script>$.get("/analysis/42/pcapstream/"+choice+"/", cb);</script>'
        '<a href="/apiv2/">API</a>'
    )
    out = _rewrite_report_html(html, 42)
    assert 'data-url="/api/detonation/report/42/analysis/load_files/42/behavior/"' in out
    assert '$.get("/api/detonation/report/42/analysis/42/pcapstream/"+choice+"/", cb);' in out
    assert 'href="/api/detonation/report/42/apiv2/"' in out


def test_parse_report_includes_proxied_web_report_url():
    from cape_client import parse_report
    r = parse_report({"info": {"score": 2.0}}, task_id=123)
    assert r["web_report_url"] == "/api/detonation/report/123/"


def test_preflight_disabled_is_noop(monkeypatch):
    import detonation
    import detonation_config as cfg
    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", False)
    detonation._preflight_cuckoo2()  # no wrapper import side effects required


def test_ws_token_ok_accepts_valid_rejects_garbage():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone
    from api_core import JWT_SECRET, ALGORITHM
    from routers.detonation_proxy import _ws_token_ok

    good = pyjwt.encode(
        {"sub": "analyst", "purpose": "ws",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        JWT_SECRET, algorithm=ALGORITHM)
    assert _ws_token_ok(good) is True
    assert _ws_token_ok(None) is False
    assert _ws_token_ok("") is False
    assert _ws_token_ok("not-a-jwt") is False

    expired = pyjwt.encode(
        {"sub": "analyst",
         "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
        JWT_SECRET, algorithm=ALGORITHM)
    assert _ws_token_ok(expired) is False


def test_ws_token_ok_rejects_revoked():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone
    from api_core import JWT_SECRET, ALGORITHM, revoke_token
    from routers.detonation_proxy import _ws_token_ok

    tok = pyjwt.encode(
        {"sub": "analyst",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        JWT_SECRET, algorithm=ALGORITHM)
    revoke_token(tok)
    assert _ws_token_ok(tok) is False


# ---------------------------------------------------------------------------
# Manual VM control — atomic window acquisition (try_begin)
# ---------------------------------------------------------------------------

class _DummyDB:
    def close(self):
        pass


def test_try_begin_claims_and_refuses_when_active():
    import detonation_state as ds
    ds.end()
    assert ds.try_begin("t1") is True
    assert ds.is_active() is True
    assert ds.try_begin("t2") is False          # already held
    ds.end()
    assert ds.try_begin("t3") is True           # reusable after end()
    ds.end()


def test_detonation_lock_is_cross_thread_mutex():
    # An asyncio.Lock here would only synchronize coroutines on one event
    # loop and silently reopen the poller-vs-endpoint race. Must be a raw
    # OS mutex.
    import _thread
    import detonation_state as ds
    assert isinstance(ds._lock, _thread.LockType)


def test_try_begin_race_exactly_one_winner():
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import detonation_state as ds
    ds.end()
    n = 16
    barrier = threading.Barrier(n)

    def claim(_):
        barrier.wait()                          # all threads fire together
        return ds.try_begin("race")

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(claim, range(n)))
    ds.end()
    assert results.count(True) == 1
    assert results.count(False) == n - 1


def test_process_queue_already_running_when_window_held(monkeypatch):
    import database
    import detonation
    import detonation_state as ds
    monkeypatch.setattr(database, "SessionLocal", lambda: _DummyDB())
    monkeypatch.setattr(database, "count_queued_detonations", lambda db: 1)
    ds.end()
    assert ds.try_begin("held-by-test")
    try:
        out = detonation.process_detonation_queue()
        assert out == {"processed": 0, "status": "already_running"}
    finally:
        ds.end()


# ---------------------------------------------------------------------------
# Manual VM control — run-window endpoint
# ---------------------------------------------------------------------------

def test_run_window_409_when_window_active():
    from types import SimpleNamespace
    from fastapi import HTTPException
    import detonation_state as ds
    from routers.detonation_proxy import api_detonation_run_window
    ds.end()
    assert ds.try_begin("held-by-test")
    try:
        try:
            api_detonation_run_window(user=SimpleNamespace(username="op"))
            assert False, "expected HTTPException 409"
        except HTTPException as e:
            assert e.status_code == 409
    finally:
        ds.end()


def test_run_window_empty_queue_is_noop(monkeypatch):
    from types import SimpleNamespace
    import database
    import detonation_state as ds
    from routers.detonation_proxy import api_detonation_run_window
    ds.end()
    monkeypatch.setattr(database, "SessionLocal", lambda: _DummyDB())
    monkeypatch.setattr(database, "count_queued_detonations", lambda db: 0)
    out = api_detonation_run_window(user=SimpleNamespace(username="op"))
    assert out == {"status": "empty"}
    assert ds.is_active() is False              # nothing was drained/started


def test_run_window_starts_thread_and_writes_audit(monkeypatch):
    import threading
    from types import SimpleNamespace
    import database
    import detonation
    import detonation_state as ds
    from routers.detonation_proxy import api_detonation_run_window
    ds.end()
    audits = []
    ran = threading.Event()
    monkeypatch.setattr(database, "SessionLocal", lambda: _DummyDB())
    monkeypatch.setattr(database, "count_queued_detonations", lambda db: 2)
    monkeypatch.setattr(database, "add_audit_entry",
                        lambda db, **kw: audits.append(kw))
    monkeypatch.setattr(detonation, "process_detonation_queue",
                        lambda: (ran.set(), {"status": "ok"})[1])
    out = api_detonation_run_window(user=SimpleNamespace(username="op"))
    assert out == {"status": "started"}
    assert ran.wait(5), "process_detonation_queue never ran in the thread"
    assert audits and audits[0]["action"] == "detonation_window_manual"
    assert audits[0]["actor"] == "op"
    assert audits[0]["details"]["queued"] == 2


def test_run_window_route_registered_with_scan_permission():
    from routers.detonation_proxy import detonation_proxy_router
    match = [r for r in detonation_proxy_router.routes
             if getattr(r, "path", "") == "/api/detonation/run-window"]
    assert match, "run-window route not registered"


def test_vm_info_reports_available_and_disabled_sections(monkeypatch):
    """Machines/primary-VM/tasks sections must be independently reported —
    e.g. machines disabled on this CAPE instance must not blank out tasks
    that ARE available, and vice versa."""
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from types import SimpleNamespace
    import cape_client
    from routers.detonation_proxy import api_detonation_vm_info

    monkeypatch.setattr(cape_client, "list_machines", lambda: None)  # disabled
    monkeypatch.setattr(cape_client, "view_machine", lambda name: {"name": name, "platform": "windows"})
    monkeypatch.setattr(cape_client, "list_tasks", lambda limit=None, offset=None: [{"id": 41, "status": "reported"}])

    out = api_detonation_vm_info(user=SimpleNamespace(username="op"))
    assert out["machines"] == {"available": False, "data": []}
    assert out["primary_machine"]["available"] is True
    assert out["primary_machine"]["data"]["platform"] == "windows"
    assert out["recent_tasks"] == {"available": True, "data": [{"id": 41, "status": "reported"}]}


def test_primary_machine_name_prefers_machines_list(monkeypatch):
    """Must never use det_cfg.CAPE_VM_NAME — that's the outer Hyper-V VM
    ("cape-ubuntu") hosting CAPE itself, not the CAPE-registered detonation
    guest. This was a real bug caught before shipping: the machines list (or
    the most recent task's "machine" field) names the actual guest."""
    from routers.detonation_proxy import _primary_machine_name
    assert _primary_machine_name([{"name": "cuckoo2"}], None) == "cuckoo2"


def test_primary_machine_name_falls_back_to_recent_task():
    from routers.detonation_proxy import _primary_machine_name
    # machines list disabled (None) or empty — fall back to the most recent task
    assert _primary_machine_name(None, [{"id": 41, "machine": "cuckoo2"}]) == "cuckoo2"
    assert _primary_machine_name([], [{"id": 41, "machine": "cuckoo2"}]) == "cuckoo2"


def test_primary_machine_name_last_resort_default():
    from routers.detonation_proxy import _primary_machine_name
    assert _primary_machine_name(None, None) == "cuckoo2"
    assert _primary_machine_name([], []) == "cuckoo2"


def test_vm_info_uses_derived_machine_name_not_cape_vm_name(monkeypatch):
    """Regression test for the det_cfg.CAPE_VM_NAME bug: view_machine() must
    be called with the name derived from real CAPE data, not the Hyper-V
    wrapper VM's name."""
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from types import SimpleNamespace
    import cape_client
    import detonation_config as det_cfg
    from routers.detonation_proxy import api_detonation_vm_info

    seen = {}
    monkeypatch.setattr(cape_client, "list_machines", lambda: None)  # disabled
    monkeypatch.setattr(cape_client, "view_machine", lambda name: seen.setdefault("name", name) or None)
    monkeypatch.setattr(cape_client, "list_tasks", lambda limit=None, offset=None: [{"id": 41, "machine": "cuckoo2"}])

    out = api_detonation_vm_info(user=SimpleNamespace(username="op"))
    assert seen["name"] == "cuckoo2"
    assert seen["name"] != det_cfg.CAPE_VM_NAME
    assert out["primary_machine"]["name"] == "cuckoo2"


def test_task_mitmdump_404_when_unavailable(monkeypatch):
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from types import SimpleNamespace
    import cape_client
    from fastapi import HTTPException
    from routers.detonation_proxy import api_detonation_task_mitmdump

    monkeypatch.setattr(cape_client, "fetch_task_mitmdump", lambda task_id: None)
    try:
        api_detonation_task_mitmdump(task_id=41, user=SimpleNamespace(username="op"))
        assert False, "expected HTTPException"
    except HTTPException as e:
        assert e.status_code == 404


def test_task_mitmdump_returns_file_response_when_available(monkeypatch):
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from types import SimpleNamespace
    import cape_client
    from routers.detonation_proxy import api_detonation_task_mitmdump

    monkeypatch.setattr(cape_client, "fetch_task_mitmdump", lambda task_id: b"binary-data")
    resp = api_detonation_task_mitmdump(task_id=41, user=SimpleNamespace(username="op"))
    assert resp.body == b"binary-data"
    assert "task-41-mitmdump.bin" in resp.headers["content-disposition"]
