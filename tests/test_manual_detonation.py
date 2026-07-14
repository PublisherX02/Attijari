"""Tests for the Manual Detonation page — operator-driven arbitrary-file detonation.

Hermetic host-side tests (no live DB, network, or CAPE): pure-logic functions
and monkeypatched collaborators, matching tests/test_detonation.py and
tests/test_cape_dashboard.py.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# Task 1 — CAPE_DETONABLE_EXTENSIONS
# ---------------------------------------------------------------------------

def test_cape_detonable_extensions_present():
    import detonation_config as cfg
    ext = cfg.CAPE_DETONABLE_EXTENSIONS
    # CAPE-supported types are accepted
    for e in (".exe", ".dll", ".docx", ".xlsx", ".pdf", ".js", ".msg", ".eml", ".iso", ".vhd", ".one", ".hwp"):
        assert e in ext, f"{e} should be detonable"
    # Non-detonable types are absent
    for e in (".txt", ".png", ".mp3", ".csv"):
        assert e not in ext
    # All entries are lowercase and dot-prefixed
    assert all(x.startswith(".") and x == x.lower() for x in ext)


# ---------------------------------------------------------------------------
# Task 2 — detonation.manual permission
# ---------------------------------------------------------------------------

def test_detonation_manual_permission_registered():
    import database as db
    assert "detonation.manual" in db.ALL_PERMISSIONS
    # Off by default for non-admin roles — admin must grant it explicitly
    assert "detonation.manual" not in db.ANALYST_PERMISSIONS
    assert "detonation.manual" not in db.VIEWER_PERMISSIONS


def test_detonation_manual_permission_enforced():
    import database as db

    class U:
        def __init__(self, role, perms):
            self.role = role
            self.permissions = perms

    assert db.user_has_permission(U("admin", {}), "detonation.manual") is True
    assert db.user_has_permission(U("analyst", {}), "detonation.manual") is False
    assert db.user_has_permission(U("analyst", {"detonation.manual": True}), "detonation.manual") is True


# ---------------------------------------------------------------------------
# Task 3 — PendingDetonation columns + enqueue signature
# ---------------------------------------------------------------------------

def test_enqueue_detonation_signature():
    import inspect, database as db
    sig = inspect.signature(db.enqueue_detonation)
    for p in ("created_by", "priority", "status"):
        assert p in sig.parameters, f"enqueue_detonation missing {p}"
    assert sig.parameters["priority"].default is False
    assert sig.parameters["status"].default == "queued"


def test_pending_detonation_has_manual_columns():
    import database as db
    cols = db.PendingDetonation.__table__.columns.keys()
    assert "created_by" in cols
    assert "priority" in cols


# ---------------------------------------------------------------------------
# Task 4 — DB helpers: promote_deferred_detonations
# ---------------------------------------------------------------------------

def test_promote_deferred_detonations_flips_status():
    import database as db

    class Row:
        def __init__(self, status):
            self.status = status

    rows = [Row("deferred"), Row("deferred")]

    class FakeQuery:
        def filter(self, *a, **k): return self
        def all(self): return rows

    class FakeDB:
        def __init__(self): self.committed = False
        def query(self, *a, **k): return FakeQuery()
        def commit(self): self.committed = True

    fake = FakeDB()
    n = db.promote_deferred_detonations(fake)
    assert n == 2
    assert all(r.status == "ready" for r in rows)
    assert fake.committed is True


# ---------------------------------------------------------------------------
# Task 5 — upload validation + safe storage
# ---------------------------------------------------------------------------

def test_validate_upload():
    import manual_detonation as m
    assert m.validate_upload(1000, "invoice.pdf") is None
    assert m.validate_upload(1000, "malware.exe") is None
    # unsupported extension
    assert "cannot detonate" in (m.validate_upload(1000, "notes.txt") or "").lower()
    assert "cannot detonate" in (m.validate_upload(1000, "photo.png") or "").lower()
    # oversized
    assert "too large" in (m.validate_upload(m.MAX_UPLOAD_BYTES + 1, "big.exe") or "").lower()
    # empty
    assert m.validate_upload(0, "x.exe") is not None
    # double extension resolves to the REAL last extension (.exe -> supported)
    assert m.validate_upload(1000, "invoice.pdf.exe") is None


def test_store_upload_uses_internal_id(tmp_path, monkeypatch):
    import manual_detonation as m
    import hashlib
    monkeypatch.setattr(m, "MANUAL_UPLOAD_DIR", str(tmp_path))
    content = b"MZ fake exe bytes"
    path, sha = m.store_upload(content, "../../evil name.exe")
    assert sha == hashlib.sha256(content).hexdigest()
    # stored under the sandbox dir, filename does NOT contain attacker path
    assert str(tmp_path) in os.path.realpath(path)
    assert "evil name" not in os.path.basename(path)
    assert ".." not in os.path.basename(path)
    with open(path, "rb") as fh:
        assert fh.read() == content


# ---------------------------------------------------------------------------
# Task 6 — upload orchestration (Branch A/B) + confirm
# ---------------------------------------------------------------------------

def _install_fakes(monkeypatch):
    """Wire manual_detonation to in-memory fakes; return (module, state)."""
    import manual_detonation as m
    state = {"enqueued": [], "audits": [], "window_started": 0, "active": False, "rows": {}}

    class FakeRow:
        _seq = 0
        def __init__(self, **kw):
            FakeRow._seq += 1
            self.id = FakeRow._seq
            self.__dict__.update(kw)

    def fake_enqueue(db, sha256, stored_path, filename=None, email_id=None,
                     idempotency_key=None, reason=None, created_by=None,
                     priority=False, status="queued"):
        row = FakeRow(sha256=sha256, stored_path=stored_path, filename=filename,
                      email_id=email_id, created_by=created_by, priority=priority,
                      status=status)
        state["enqueued"].append(row)
        state["rows"][row.id] = row
        return row

    def fake_audit(db, action, actor, email_id=None, details=None):
        state["audits"].append({"action": action, "actor": actor, "details": details})

    class FakeDB:
        def close(self): pass
        def commit(self): pass

    monkeypatch.setattr(m, "SessionLocal", lambda: FakeDB())
    monkeypatch.setattr(m, "enqueue_detonation", fake_enqueue)
    monkeypatch.setattr(m, "add_audit_entry", fake_audit)
    monkeypatch.setattr(m, "get_pending_detonation", lambda db, pid: state["rows"].get(pid))
    monkeypatch.setattr(m, "_start_window", lambda: state.__setitem__("window_started", state["window_started"] + 1))
    monkeypatch.setattr(m, "_window_active", lambda: state["active"])
    monkeypatch.setattr(m, "store_upload", lambda content, name: ("/tmp/x.exe", "a" * 64))
    return m, state


def test_handle_upload_branch_now(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    out = m.handle_upload(b"MZ...", "sample.exe", "now", "alice")
    assert out["status"] == "queued"
    assert out["window"] == "started"
    row = state["enqueued"][0]
    assert row.email_id is None and row.priority is False and row.status == "queued"
    assert row.created_by == "alice"
    assert state["window_started"] == 1
    assert state["audits"][0]["action"] == "detonation_manual_upload"
    assert state["audits"][0]["details"]["branch"] == "now"


def test_handle_upload_branch_now_window_active(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    state["active"] = True
    out = m.handle_upload(b"MZ...", "sample.exe", "now", "alice")
    assert out["status"] == "queued"
    assert out["window"] == "active"
    assert state["window_started"] == 0  # not started again


def test_handle_upload_branch_queue(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    out = m.handle_upload(b"MZ...", "sample.exe", "queue", "bob")
    assert out["status"] == "deferred"
    row = state["enqueued"][0]
    assert row.status == "deferred" and row.priority is True
    assert state["window_started"] == 0


def test_handle_upload_rejects_bad_type(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    out = m.handle_upload(b"hi", "notes.txt", "now", "alice")
    assert "error" in out and "cannot detonate" in out["error"].lower()
    assert state["enqueued"] == []


def test_confirm_ready_promotes_and_starts(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    m.handle_upload(b"MZ...", "sample.exe", "queue", "bob")
    row = state["enqueued"][0]
    row.status = "ready"
    out = m.confirm_ready(row.id, "bob")
    assert out["status"] == "queued"
    assert row.status == "queued"
    assert state["window_started"] == 1


def test_confirm_ready_rejects_non_ready(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    m.handle_upload(b"MZ...", "sample.exe", "now", "alice")
    row = state["enqueued"][0]  # status "queued", not "ready"
    out = m.confirm_ready(row.id, "alice")
    assert "error" in out
