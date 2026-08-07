"""resume_and_report.py — resumes the atomic-red-team batch from durable
state (DB rows + .eml files on disk), not the in-memory Redis queue, since
a full machine stop/restart between now and when the user returns could
lose whatever was still queued. Re-enqueuing an already-processed file is
a safe no-op (pipeline_jobs.enqueue_pipeline_job's own RQ unique-job-id
guarantee, plus run_pipeline()'s own DB idempotency check as a second
layer) -- so this script can be re-run any number of times safely.

Invoked by resume_and_report.bat, which starts the full stack (app,
worker, Vault, Memurai, Ollama) via the existing start.bat FIRST, then
hands off here once port 8000 is confirmed listening.
"""
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PENDING_DIR = PROJECT_ROOT / "data" / "smtp_pending"
REPORT_HTML = PROJECT_ROOT / "docs" / "atomic-red-team-report.html"
QUEUE_POLL_INTERVAL_S = 30
QUEUE_POLL_LOG_EVERY = 4  # log progress every N polls (every 2 min at 30s interval)


def _wait_for_port(host: str, port: int, timeout_s: int = 120) -> bool:
    import socket
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(2)
    return False


def _reenqueue_pending() -> int:
    """Mirrors api.py's own _sweep_pending_directory() safety-net logic --
    every .eml still sitting in data/smtp_pending/ (root, not processed/)
    gets (re-)enqueued. Idempotent: a file whose job already ran to
    completion moved to processed/ and won't be found here; a file whose
    job is still genuinely queued/running gets a harmless duplicate
    enqueue attempt that RQ's own unique-job-id check turns into a no-op."""
    from pipeline_jobs import enqueue_pipeline_job

    count = 0
    if not PENDING_DIR.is_dir():
        return 0
    for path in sorted(PENDING_DIR.glob("*.eml")):
        enqueue_pipeline_job(str(path))
        count += 1
    return count


def _queue_depth() -> int:
    import redis
    r = redis.Redis(host="localhost", port=6379, decode_responses=False)
    return r.llen(b"rq:queue:attijari-pipeline")


def main():
    print("=" * 60)
    print("  Resuming Attijari + atomic-red-team batch")
    print("=" * 60)

    print("[1/4] Waiting for the app (port 8000) to come up...")
    if not _wait_for_port("127.0.0.1", 8000, timeout_s=180):
        print("[ERROR] App did not come up on port 8000 within 3 minutes.")
        print("        Check that start.bat launched cleanly (Vault/Memurai/Ollama), then re-run this script.")
        sys.exit(1)
    print("      App is up.")

    print("[2/4] Re-enqueuing any not-yet-processed files (safe no-op for anything already done)...")
    n = _reenqueue_pending()
    print(f"      Re-enqueued {n} file(s) still sitting in data/smtp_pending/.")

    print("[3/4] Waiting for the queue to drain (this can take a while -- ~1-2 min per email observed)...")
    polls = 0
    while True:
        try:
            depth = _queue_depth()
        except Exception as e:
            print(f"      [WARN] Could not read queue depth ({e}), retrying...")
            time.sleep(QUEUE_POLL_INTERVAL_S)
            continue
        if depth == 0:
            print("      Queue drained.")
            break
        polls += 1
        if polls % QUEUE_POLL_LOG_EVERY == 0:
            print(f"      ...{depth} still queued")
        time.sleep(QUEUE_POLL_INTERVAL_S)

    print("      Waiting 30s for the last in-flight job to finish committing to the DB...")
    time.sleep(30)

    print("[4/4] Generating the final report...")
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "generate_atomic_report.py")],
        cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        print("[ERROR] Report generation failed -- see output above.")
        sys.exit(1)

    print()
    print("=" * 60)
    print(f"  DONE. Report: {REPORT_HTML}")
    print("=" * 60)
    if REPORT_HTML.exists():
        webbrowser.open(REPORT_HTML.as_uri())


if __name__ == "__main__":
    main()
