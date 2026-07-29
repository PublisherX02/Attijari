"""Pop3Ingestion mirrors EmailIngestion's interface (connect/disconnect/fetch_recent)
but over POP3 instead of IMAP — for mailboxes that don't offer IMAP."""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from email_extraction import Pop3Ingestion, CONNECT_TIMEOUT


def _raw_message(subject: str, date: datetime) -> bytes:
    date_str = date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    return f"Subject: {subject}\r\nDate: {date_str}\r\n\r\nbody".encode()


def test_connect_uses_pop3_ssl_with_explicit_context():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw", port=995)
    with patch("email_extraction.poplib.POP3_SSL") as mock_pop3_ssl:
        mock_conn = MagicMock()
        mock_pop3_ssl.return_value = mock_conn
        ing.connect()
        _, kwargs = mock_pop3_ssl.call_args
        assert mock_pop3_ssl.call_args[0][0] == "pop.example.com"
        assert kwargs.get("context") is not None
        mock_conn.user.assert_called_once_with("a@example.com")
        mock_conn.pass_.assert_called_once_with("pw")


def test_connect_passes_connect_timeout_to_pop3_ssl():
    """Finding 3: an unresponsive POP3 host must not hang the executor
    thread forever — POP3_SSL needs an explicit timeout, matching
    EmailIngestion.connect()'s pattern for IMAP4_SSL."""
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw", port=995)
    with patch("email_extraction.poplib.POP3_SSL") as mock_pop3_ssl:
        mock_conn = MagicMock()
        mock_pop3_ssl.return_value = mock_conn
        ing.connect()
        _, kwargs = mock_pop3_ssl.call_args
        assert kwargs.get("timeout") == CONNECT_TIMEOUT


def test_disconnect_calls_quit():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw")
    ing.conn = MagicMock()
    ing.disconnect()
    ing.conn.quit.assert_called_once()


def test_connect_failure_propagates():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="wrong")
    with patch("email_extraction.poplib.POP3_SSL") as mock_pop3_ssl:
        mock_conn = MagicMock()
        mock_conn.pass_.side_effect = Exception("-ERR authentication failed")
        mock_pop3_ssl.return_value = mock_conn
        try:
            ing.connect()
            assert False, "expected exception"
        except Exception as e:
            assert "authentication failed" in str(e)


def test_fetch_recent_filters_by_date_and_limit():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw")
    ing.conn = MagicMock()
    now = datetime.now(timezone.utc)
    messages = {
        1: _raw_message("old", now - timedelta(days=30)),
        2: _raw_message("recent-1", now - timedelta(days=1)),
        3: _raw_message("recent-2", now - timedelta(hours=2)),
    }
    ing.conn.list.return_value = (b"+OK", [f"{i} 100".encode() for i in messages], 0)
    ing.conn.retr.side_effect = lambda i: (b"+OK", [line.encode() for line in messages[i].decode().splitlines()], len(messages[i]))

    result = ing.fetch_recent(since_days=7, limit=50)
    assert len(result) == 2
    assert all(b"recent" in r for r in result)


def test_fetch_recent_respects_limit():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw")
    ing.conn = MagicMock()
    now = datetime.now(timezone.utc)
    messages = {i: _raw_message(f"msg{i}", now - timedelta(minutes=i)) for i in range(1, 6)}
    ing.conn.list.return_value = (b"+OK", [f"{i} 100".encode() for i in messages], 0)
    ing.conn.retr.side_effect = lambda i: (b"+OK", [line.encode() for line in messages[i].decode().splitlines()], len(messages[i]))

    result = ing.fetch_recent(since_days=7, limit=2)
    assert len(result) == 2
