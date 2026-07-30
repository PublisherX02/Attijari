"""pipeline_jobs.py — RQ wiring for the per-email job queue (2026-07-30,
replaces the old poll-and-batch-process loop). run_pipeline() itself
(src/main.py) is unmodified except for the single_file parameter added
alongside this module — see docs/superpowers/specs/2026-07-30-job-queue-design.md
for why that function is not otherwise refactored.

job_id_for_file() is the ONE place the dedup key is computed — both enqueue
call sites (smtp_receiver.py's handle_DATA, and the periodic sweep in
api.py) import it from here rather than each computing their own, so they
can never drift into using different keys for the same file.
"""
from __future__ import annotations

from pathlib import Path

from rq import Queue, Retry
from rq.exceptions import DuplicateJobError

from redis_client import get_client
from main import run_pipeline
from database import SessionLocal, Email

QUEUE_NAME = "attijari-pipeline"


def job_id_for_file(file_path: str) -> str:
    """Derived from the filename's stem — src/smtp_receiver.py already
    names files {sha256}.eml, so the filename itself is the content hash;
    no need to re-read and re-hash the file just to compute a dedup key."""
    stem = Path(file_path).stem
    return f"pipeline-{stem}"


def get_pipeline_queue() -> Queue:
    return Queue(QUEUE_NAME, connection=get_client())


def enqueue_pipeline_job(file_path: str) -> bool:
    """Enqueue one pipeline job for file_path. Returns True if newly
    enqueued, False if a job with this file's dedup key was already queued
    (or running/finished and still tracked) — NOT an error, just a no-op,
    since a duplicate enqueue of an already-handled file is harmless (the
    pipeline's own DB-idempotency check inside run_pipeline() treats a
    re-processed already-done file as a cache hit)."""
    queue = get_pipeline_queue()
    job_id = job_id_for_file(file_path)
    try:
        queue.enqueue(
            process_email_file,
            file_path,
            job_id=job_id,
            unique=True,
            retry=Retry(max=3, interval=[30, 120, 300]),
            on_failure=on_pipeline_job_failure,
        )
        return True
    except DuplicateJobError:
        return False


def process_email_file(file_path: str) -> None:
    """RQ job entrypoint — one email, via run_pipeline()'s single_file mode."""
    run_pipeline(single_file=file_path)


def on_pipeline_job_failure(job, connection, type, value, traceback) -> None:
    """Runs after RQ's retries (see enqueue_pipeline_job's Retry policy) are
    exhausted. Marks the matching DB record escalated if one exists and the
    DB is reachable; NEVER raises, NEVER deletes the raw file — the file on
    disk is the last-resort durability guarantee regardless of what happens
    here. Matches the pipeline's own existing "fail-safe, never fail-open"
    philosophy: a job that could not complete becomes an escalation for a
    human, not a silent drop."""
    file_path = job.args[0] if job.args else None
    if not file_path:
        return

    sha = Path(file_path).stem
    try:
        db = SessionLocal()
    except Exception as e:
        print(f"[PIPELINE-JOB] Redis job {job} failed permanently; DB unreachable to escalate ({e}); file left on disk: {file_path}")
        return

    try:
        email = db.query(Email).filter(Email.raw_sha256 == sha).first()
        if email is None:
            print(f"[PIPELINE-JOB] Job for {file_path} failed permanently with no matching DB record "
                  f"(crash before any record was saved) — file left on disk, no DB update possible: {value}")
            return
        email.status = "escalated"
        db.commit()
        print(f"[PIPELINE-JOB] Job for {file_path} failed permanently after retries — "
              f"marked email id={email.id} escalated. Error: {value}")
    except Exception as e:
        print(f"[PIPELINE-JOB] Failed to mark email escalated after job failure for {file_path}: {e}")
    finally:
        try:
            db.close()
        except Exception:
            pass
