"""The safety-net sweep: scans data/smtp_pending/*.eml and enqueues each
via pipeline_jobs.enqueue_pipeline_job — using the SAME dedup key function
(job_id_for_file) the SMTP receiver's own enqueue call uses (Task 3), so a
file already enqueued by handle_DATA is a harmless no-op here, not a
duplicate job."""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")


def test_sweep_enqueues_every_eml_file_found(tmp_path, monkeypatch):
    import api
    (tmp_path / "aaa.eml").write_bytes(b"one")
    (tmp_path / "bbb.eml").write_bytes(b"two")
    (tmp_path / "not-an-email.txt").write_bytes(b"ignored")

    monkeypatch.setattr(api, "_SWEEP_DIR", tmp_path)
    with patch("api.enqueue_pipeline_job", return_value=True) as mock_enqueue:
        count = api._sweep_pending_directory()

    assert count == 2
    enqueued_paths = {call.args[0] for call in mock_enqueue.call_args_list}
    assert enqueued_paths == {str(tmp_path / "aaa.eml"), str(tmp_path / "bbb.eml")}


def test_sweep_handles_missing_directory_gracefully(tmp_path, monkeypatch):
    import api
    missing = tmp_path / "does-not-exist"
    monkeypatch.setattr(api, "_SWEEP_DIR", missing)
    count = api._sweep_pending_directory()  # must not raise
    assert count == 0
