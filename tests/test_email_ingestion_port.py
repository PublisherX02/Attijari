import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_extraction import EmailIngestion


def test_connect_uses_custom_port():
    ingestion = EmailIngestion(host="imap.example.com", user="u", password="p", port=1993)
    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()
        mock_imap.return_value = mock_conn
        ingestion.connect()
        args, kwargs = mock_imap.call_args
        assert args[0] == "imap.example.com"
        assert kwargs.get("port", args[1] if len(args) > 1 else None) == 1993


def test_connect_defaults_to_993():
    ingestion = EmailIngestion(host="imap.gmail.com", user="u", password="p")
    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()
        mock_imap.return_value = mock_conn
        ingestion.connect()
        args, kwargs = mock_imap.call_args
        assert kwargs.get("port", args[1] if len(args) > 1 else None) == 993
