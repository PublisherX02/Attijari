"""handle_DATA enqueues one pipeline job immediately after writing the
.eml file, using pipeline_jobs' shared enqueue helper (so dedup behavior
matches the sweep in Task 4 exactly)."""
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()


def test_handle_data_enqueues_after_writing_file(tmp_path):
    from smtp_receiver import PendingMailHandler

    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=10_000_000)
    envelope = MagicMock()
    envelope.content = b"Subject: test\r\n\r\nbody"

    with patch("smtp_receiver.enqueue_pipeline_job") as mock_enqueue:
        result = asyncio.run(handler.handle_DATA(server=None, session=None, envelope=envelope))

    assert result == "250 Message accepted for delivery"
    mock_enqueue.assert_called_once()
    enqueued_path = mock_enqueue.call_args[0][0]
    assert enqueued_path.endswith(".eml")
    assert Path(enqueued_path).exists()


def test_handle_data_does_not_enqueue_when_size_exceeded(tmp_path):
    from smtp_receiver import PendingMailHandler

    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=5)
    envelope = MagicMock()
    envelope.content = b"way more than 5 bytes"

    with patch("smtp_receiver.enqueue_pipeline_job") as mock_enqueue:
        result = asyncio.run(handler.handle_DATA(server=None, session=None, envelope=envelope))

    assert "552" in result
    mock_enqueue.assert_not_called()
