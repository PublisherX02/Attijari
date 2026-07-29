"""pop3_smtp_bridge mirrors gmail_smtp_bridge but only acts when the active
mailbox's protocol is 'pop3' — never double-relays a mailbox both bridges
could otherwise see."""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import database
import mailboxes

# pop3_smtp_bridge.run_once() does `from database import SessionLocal` and
# `from mailboxes import get_active_mailbox_credentials` as LOCAL imports
# inside the function body, re-resolved from these modules at call time —
# every test below patches database.SessionLocal / mailboxes.get_active_mailbox_credentials
# directly, never `bridge.SessionLocal` / `bridge.get_active_mailbox_credentials`
# (those attributes are never read by the function).


class FakeSessionLocal:
    def __call__(self):
        return self
    def close(self):
        pass


def test_skips_when_no_active_mailbox(monkeypatch):
    import pop3_smtp_bridge as bridge

    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())
    monkeypatch.setattr(mailboxes, "get_active_mailbox_credentials", lambda db: None)

    assert bridge.run_once() == 0


def test_skips_when_active_mailbox_is_imap(monkeypatch):
    import pop3_smtp_bridge as bridge

    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())
    monkeypatch.setattr(
        mailboxes, "get_active_mailbox_credentials",
        lambda db: {"host": "imap.gmail.com", "user": "a@gmail.com", "port": 993, "password": "pw", "protocol": "imap"},
    )

    with patch("pop3_smtp_bridge.Pop3Ingestion") as mock_pop3:
        result = bridge.run_once()
        mock_pop3.assert_not_called()
    assert result == 0


def test_relays_pop3_mailbox_mail(monkeypatch):
    import pop3_smtp_bridge as bridge

    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())
    monkeypatch.setattr(
        mailboxes, "get_active_mailbox_credentials",
        lambda db: {"host": "pop.example.com", "user": "a@example.com", "port": 995, "password": "pw", "protocol": "pop3"},
    )

    fake_ingestion = MagicMock()
    fake_ingestion.fetch_recent.return_value = [b"Subject: t\r\n\r\nbody"]
    monkeypatch.setattr(bridge, "Pop3Ingestion", lambda **kwargs: fake_ingestion)

    with patch.object(bridge, "relay_one", return_value=True) as mock_relay:
        relayed = bridge.run_once()
        mock_relay.assert_called_once()
    assert relayed == 1
    fake_ingestion.connect.assert_called_once()
    fake_ingestion.disconnect.assert_called_once()
