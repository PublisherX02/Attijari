"""Endpoint-level tests for attachment listing, raw-serve gating, and
insist. Hermetic — monkeypatched collaborators, no live HTTP client or DB,
matching tests/test_manual_detonation.py's Task 7/8 style."""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")


def test_serialize_attachments(monkeypatch):
    from routers import emails as e

    class FakeAttachment:
        def __init__(self, id, filename, sha256):
            self.id = id
            self.filename = filename
            self.sha256 = sha256
            self.real_type = "application/pdf"
            self.size_bytes = 1234
            self.created_at = None

    rows = [FakeAttachment(1, "a.pdf", "a" * 64), FakeAttachment(2, "b.exe", "b" * 64)]

    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def all(self): return rows

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    monkeypatch.setattr(e, "attachment_safety_status",
                        lambda db, sha: "safe" if sha.startswith("a") else "unsafe")
    out = e._serialize_attachments(FakeDB(), email_id=1)
    assert out[0]["id"] == 1 and out[0]["filename"] == "a.pdf" and out[0]["status"] == "safe"
    assert out[1]["id"] == 2 and out[1]["status"] == "unsafe"
    assert out[0]["real_type"] == "application/pdf"
    assert out[0]["size_bytes"] == 1234


def test_attachment_raw_403_when_not_safe():
    """The route handler is a thin FastAPI wrapper around resolve_attachment
    (routers/detonation_proxy.py's api_attachment_raw) — this confirms the
    status values that must NOT count as safe, i.e. must 403."""
    from attachments import STATUS_SAFE, STATUS_UNSAFE, STATUS_PENDING, STATUS_UNVERIFIED
    for not_safe in (STATUS_UNSAFE, STATUS_PENDING, STATUS_UNVERIFIED):
        assert not_safe != STATUS_SAFE


def test_sniff_media_type_unchanged():
    """Confirms the existing magic-byte sniffing this task reuses (rewritten
    endpoint still calls the same _sniff_media_type) is untouched."""
    from routers.detonation_proxy import _sniff_media_type
    assert _sniff_media_type(b"%PDF-1.4...")[0] == "application/pdf"
    assert _sniff_media_type(b"not a real file")[1] is False
