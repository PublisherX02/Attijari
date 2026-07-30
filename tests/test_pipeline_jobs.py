"""pipeline_jobs.py: the RQ wiring around run_pipeline(single_file=...).
Uses a real local Redis/Memurai connection (this project's existing test
convention for Redis-backed code, e.g. ARCH-1's tests) — never starts a
real rq worker process; process_email_file() is called directly to verify
job behavior, and enqueue_pipeline_job()/on_pipeline_job_failure() are
tested against the real queue's state."""
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

# Must be set before pipeline_jobs is first imported anywhere in this test
# session — QUEUE_NAME is read at module-import time — so tests never touch
# the real production "attijari-pipeline" queue (a live app/worker sharing
# the same Redis instance could have genuinely pending jobs there).
os.environ.setdefault("RQ_QUEUE_NAME", "attijari-pipeline-test")

import redis_client


def _clean_queue():
    import pipeline_jobs
    q = pipeline_jobs.get_pipeline_queue()
    q.empty()
    return q


def test_job_id_for_file_is_deterministic_and_based_on_filename():
    import pipeline_jobs
    # Filenames are already {sha256}.eml (src/smtp_receiver.py) — the job id
    # must be derived from that stem, not recomputed from file content (the
    # sweep in Task 4 only has a Path, re-hashing every file's content on
    # every 5-minute sweep would be wasteful and is unnecessary: the
    # filename already IS the content hash).
    assert pipeline_jobs.job_id_for_file("/x/y/abc123.eml") == "pipeline-abc123"
    assert pipeline_jobs.job_id_for_file("/x/y/abc123.eml") == pipeline_jobs.job_id_for_file("/z/abc123.eml")


def test_enqueue_pipeline_job_returns_true_then_false_on_repeat():
    _clean_queue()
    import pipeline_jobs
    first = pipeline_jobs.enqueue_pipeline_job("/tmp/dedup-test-abc.eml")
    second = pipeline_jobs.enqueue_pipeline_job("/tmp/dedup-test-abc.eml")
    assert first is True
    assert second is False
    _clean_queue()


def test_process_email_file_calls_run_pipeline_single_file():
    import pipeline_jobs
    with patch("pipeline_jobs.run_pipeline") as mock_run:
        pipeline_jobs.process_email_file("/tmp/some-file.eml")
    mock_run.assert_called_once_with(single_file="/tmp/some-file.eml")


def test_process_email_file_moves_file_to_processed_on_success(tmp_path):
    import pipeline_jobs
    src = tmp_path / "abc123.eml"
    src.write_bytes(b"raw email content")

    with patch("pipeline_jobs.run_pipeline") as mock_run:
        pipeline_jobs.process_email_file(str(src))

    mock_run.assert_called_once_with(single_file=str(src))
    assert not src.exists()
    dest = tmp_path / "processed" / "abc123.eml"
    assert dest.exists()
    assert dest.read_bytes() == b"raw email content"


def test_process_email_file_leaves_file_in_place_on_run_pipeline_failure(tmp_path):
    import pipeline_jobs
    src = tmp_path / "def456.eml"
    src.write_bytes(b"raw email content")

    with patch("pipeline_jobs.run_pipeline", side_effect=RuntimeError("boom")):
        try:
            pipeline_jobs.process_email_file(str(src))
        except RuntimeError:
            pass
        else:
            assert False, "expected run_pipeline's RuntimeError to propagate"

    assert src.exists()
    assert not (tmp_path / "processed" / "def456.eml").exists()


def test_process_email_file_publishes_refresh_signal_on_success(tmp_path):
    import pipeline_jobs
    src = tmp_path / "refresh789.eml"
    src.write_bytes(b"raw email content")

    pubsub = redis_client.get_client().pubsub()
    pubsub.subscribe("attijari:pipeline:refresh")
    pubsub.get_message(timeout=2)  # discard the subscribe-confirmation message

    with patch("pipeline_jobs.run_pipeline"):
        pipeline_jobs.process_email_file(str(src))

    message = None
    for _ in range(10):
        message = pubsub.get_message(timeout=1)
        if message and message.get("type") == "message":
            break
    pubsub.close()

    assert message is not None, "expected a message on attijari:pipeline:refresh"
    assert message["data"] == str(src)


def test_on_failure_marks_matching_email_escalated(monkeypatch):
    import pipeline_jobs
    fake_job = MagicMock()
    fake_job.args = ("/tmp/deadbeef.eml",)

    fake_email = MagicMock()
    fake_email.status = "pending"
    fake_db = MagicMock()
    fake_db.query.return_value.filter.return_value.first.return_value = fake_email

    with patch("pipeline_jobs.SessionLocal", return_value=fake_db):
        pipeline_jobs.on_pipeline_job_failure(fake_job, None, ValueError, ValueError("boom"), None)

    assert fake_email.status == "escalated"
    fake_db.commit.assert_called_once()
    fake_db.close.assert_called_once()


def test_on_failure_does_not_raise_when_no_matching_email_found():
    import pipeline_jobs
    fake_job = MagicMock()
    fake_job.args = ("/tmp/nonexistent.eml",)

    fake_db = MagicMock()
    fake_db.query.return_value.filter.return_value.first.return_value = None

    with patch("pipeline_jobs.SessionLocal", return_value=fake_db):
        pipeline_jobs.on_pipeline_job_failure(fake_job, None, ValueError, ValueError("boom"), None)  # must not raise

    fake_db.close.assert_called_once()


def test_on_failure_does_not_raise_when_db_unreachable():
    import pipeline_jobs
    with patch("pipeline_jobs.SessionLocal", side_effect=Exception("db down")):
        pipeline_jobs.on_pipeline_job_failure(MagicMock(args=("/tmp/x.eml",)), None, ValueError, ValueError("boom"), None)  # must not raise


def test_on_failure_does_not_raise_when_db_close_raises():
    # The finally: db.close() block is the last line of defense — if close()
    # itself raises (e.g. a dropped connection), it must be swallowed too,
    # not propagate out of a function whose entire contract is "never raise".
    import pipeline_jobs
    fake_job = MagicMock()
    fake_job.args = ("/tmp/deadbeef.eml",)

    fake_email = MagicMock()
    fake_email.status = "pending"
    fake_db = MagicMock()
    fake_db.query.return_value.filter.return_value.first.return_value = fake_email
    fake_db.close.side_effect = Exception("close failed")

    with patch("pipeline_jobs.SessionLocal", return_value=fake_db):
        pipeline_jobs.on_pipeline_job_failure(fake_job, None, ValueError, ValueError("boom"), None)  # must not raise

    assert fake_email.status == "escalated"
    fake_db.commit.assert_called_once()
    fake_db.close.assert_called_once()
