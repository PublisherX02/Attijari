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

import os
from pathlib import Path

from rq import Queue, Retry
from rq.exceptions import DuplicateJobError

from redis_client import get_client
from main import run_pipeline
from database import SessionLocal, Email

# Overridable via RQ_QUEUE_NAME so the test suite can point at a dedicated
# queue instead of the real production "attijari-pipeline" queue — running
# tests against the real queue name while the real app/worker is live could
# wipe genuinely pending email-processing jobs (q.empty() in tests). Read at
# import time, so any override must be set before pipeline_jobs is first
# imported in a process (see tests/test_pipeline_jobs.py).
QUEUE_NAME = os.getenv("RQ_QUEUE_NAME", "attijari-pipeline")


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
    """RQ job entrypoint — one email, via run_pipeline()'s single_file mode.
    On success, moves the file out of the sweep's search path (a `processed/`
    subdirectory) so the safety-net sweep never re-finds and re-enqueues an
    already-handled file indefinitely — files are still never deleted
    (matching this project's existing "never delete smtp_pending files"
    convention), just relocated. On failure (this function raising), the
    file is deliberately left in place — on_pipeline_job_failure's contract
    already guarantees it's never deleted, and leaving it in the original
    (swept) location means a retried/re-swept attempt can still find it.

    Also publishes on the "attijari:pipeline:refresh" Redis Pub/Sub channel
    after a successful run, so the app process's WebSocket-connected
    dashboard clients get a live refresh — this job runs in a separate RQ
    worker process with no access to the app process's in-memory
    ws_manager, so Redis (already shared infrastructure between app and
    worker) is the cross-process signal. See api.py's
    _pipeline_refresh_listener for the subscriber side."""
    run_pipeline(single_file=file_path)

    src = Path(file_path)
    processed_dir = src.parent / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    dest = processed_dir / src.name
    try:
        src.rename(dest)
    except OSError as e:
        print(f"[PIPELINE-JOB] Could not move {file_path} to processed/ after success (non-fatal): {e}")

    try:
        get_client().publish("attijari:pipeline:refresh", file_path)
    except Exception as e:
        print(f"[PIPELINE-JOB] Could not publish refresh signal for {file_path} (non-fatal): {e}")


def on_pipeline_job_failure(job, connection, type, value, traceback) -> None:
    """RQ calls this callback on EVERY failed attempt, not just the final
    one — RQ's exception handler invokes on_failure BEFORE it decides
    whether Job.retry() has more attempts left (verified against rq==2.10.0
    source). With enqueue_pipeline_job's Retry(max=3, ...) actually retrying
    (this requires the worker to run with --with-scheduler; see
    worker-deployment.yaml), a single underlying failure can therefore fire
    this callback up to 4 times (three retried attempts plus the final,
    truly-exhausted one) before the job is done retrying.

    This is intentional, not a bug: marking the matching DB record
    escalated is idempotent (setting the same status repeatedly is
    harmless), and firing early is actually SAFER for this project's
    fail-safe philosophy — a human analyst sees the escalation sooner
    rather than only after the last retry. NEVER raises, NEVER deletes the
    raw file — the file on disk is the last-resort durability guarantee
    regardless of what happens here or how many times it runs."""
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
