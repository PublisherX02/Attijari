"""run_pipeline(single_file=...) reads exactly one file directly, bypassing
fetch_pending_smtp(limit=50) entirely — the only sanctioned change to this
830-line function. Everything downstream of the raw_emails assignment is
NOT re-tested here; this project's existing pipeline tests already cover
run_pipeline()'s internals and are unaffected since this change is purely
additive (single_file=None preserves today's exact behavior)."""
import os
import sys
from pathlib import Path
from unittest.mock import patch, sentinel

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")


def test_single_file_mode_reads_exactly_that_file(tmp_path, monkeypatch):
    import main

    fake_email_bytes = b"Subject: test\r\nFrom: a@example.com\r\n\r\nbody"
    target = tmp_path / "abc123.eml"
    target.write_bytes(fake_email_bytes)

    # Patch archive_raw to prove that raw_emails contains the exact file content
    # and to short-circuit the loop before expensive pipeline operations run.
    with patch("email_extraction.EmailIngestion.fetch_pending_smtp") as mock_fetch, \
         patch("email_extraction.EmailIngestion.archive_raw",
               side_effect=KeyboardInterrupt("stop-here-probe")) as mock_archive, \
         patch("main._ollama_reachable", return_value=True):
        try:
            main.run_pipeline(single_file=str(target))
        except KeyboardInterrupt as e:
            assert "stop-here-probe" in str(e)
        else:
            assert False, "expected the probe patch to interrupt run_pipeline before completion"

    # Verify fetch_pending_smtp was never called in single_file mode
    mock_fetch.assert_not_called()
    # Verify archive_raw was called with exactly the file content
    mock_archive.assert_called_once()
    assert mock_archive.call_args[0][0] == fake_email_bytes


def test_default_mode_still_calls_fetch_pending_smtp(monkeypatch):
    import main

    sentinel_email = sentinel.EMAIL
    with patch("email_extraction.EmailIngestion.fetch_pending_smtp",
               return_value=[sentinel_email]) as mock_fetch, \
         patch("email_extraction.EmailIngestion.archive_raw",
               side_effect=KeyboardInterrupt("stop-here-probe")) as mock_archive, \
         patch("main._ollama_reachable", return_value=True):
        try:
            main.run_pipeline()  # single_file=None, today's default behavior
        except KeyboardInterrupt as e:
            assert "stop-here-probe" in str(e)
        else:
            assert False, "expected the probe patch to interrupt run_pipeline before completion"

    # Verify fetch_pending_smtp was called with the right batch size
    mock_fetch.assert_called_once_with(limit=50)
    # Verify archive_raw was called with the sentinel email
    mock_archive.assert_called_once()
    assert mock_archive.call_args[0][0] == sentinel_email
