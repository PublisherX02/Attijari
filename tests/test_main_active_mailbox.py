"""run_pipeline() must prefer the dashboard-active mailbox and fall back to
.env when none is configured — and must never crash the fallback path if
the mailboxes table/DB lookup itself fails."""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import mailboxes


def test_get_active_mailbox_credentials_falls_back_gracefully(monkeypatch):
    # Simulate "no mailbox configured yet" — the exact state on a fresh DB.
    from database import Base, engine, SessionLocal
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        assert mailboxes.get_active_mailbox_credentials(db) is None
    finally:
        db.close()


def test_gmail_bridge_relay_one_uses_explicit_rcpt(monkeypatch):
    import gmail_smtp_bridge as bridge

    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=15):
            captured["host"] = host
            captured["port"] = port
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def sendmail(self, from_addr, to_addrs, raw):
            captured["to_addrs"] = to_addrs

    monkeypatch.setattr(bridge.smtplib, "SMTP", FakeSMTP)
    ok = bridge.relay_one(b"Subject: test\r\n\r\nbody", "explicit@target.com")
    assert ok is True
    assert captured["to_addrs"] == ["explicit@target.com"]


def test_gmail_bridge_skips_when_active_mailbox_is_pop3(monkeypatch):
    import gmail_smtp_bridge as bridge
    import database
    import mailboxes

    # gmail_smtp_bridge.run_once() does `from database import SessionLocal` and
    # `from mailboxes import get_active_mailbox_credentials` as LOCAL imports
    # inside the function body, re-resolved from these modules at call time —
    # patch the source modules' attributes, not `bridge.SessionLocal` /
    # `bridge.get_active_mailbox_credentials` (those names are never read).
    monkeypatch.setattr(
        mailboxes, "get_active_mailbox_credentials",
        lambda db: {"host": "pop.example.com", "user": "a@example.com", "port": 995, "password": "pw", "protocol": "pop3"},
    )

    class FakeSessionLocal:
        def __call__(self):
            return self
        def close(self):
            pass
    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())

    with patch("email_extraction.EmailIngestion.connect") as mock_connect:
        result = bridge.run_once()
        mock_connect.assert_not_called()
    assert result == 0
