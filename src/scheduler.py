"""scheduler.py — Automated background scheduler for the ImaniIA pipeline.

Uses APScheduler to run:
  1. IMAP poll: every 60s (configurable via POLL_INTERVAL_SECONDS)
  2. Threat feed update: daily at 03:00 (configurable via FEED_UPDATE_CRON)
  3. Admin report: daily at 08:00 (configurable via REPORT_CRON)

Start with:  python src/scheduler.py
Or via main: python src/main.py --daemon
"""
from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

# Ensure src/ on path
_SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC_DIR))

load_dotenv()

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from logger import get_logger

logger = get_logger("scheduler")

# Configuration from environment
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
FEED_UPDATE_CRON = os.getenv("FEED_UPDATE_CRON", "0 3 * * *")
REPORT_CRON = os.getenv("REPORT_CRON", "0 8 * * *")


def _run_pipeline_job():
    """Job: Run one pipeline iteration (IMAP poll + analysis)."""
    try:
        from metrics import scheduler_last_run, pipeline_duration_seconds
        t0 = time.time()

        # Import here to avoid circular imports at module level
        from main import run_pipeline
        run_pipeline()

        elapsed = time.time() - t0
        pipeline_duration_seconds.observe(elapsed)
        scheduler_last_run.set(time.time())
        logger.info(f"Pipeline job completed in {elapsed:.1f}s")
    except Exception as e:
        logger.error(f"Pipeline job failed: {e}")


def _update_feeds_job():
    """Job: Download fresh threat feed files."""
    try:
        from threat_feeds import update_feeds
        logger.info("Updating threat feeds...")
        update_feeds()
        logger.info("Threat feeds updated.")
    except Exception as e:
        logger.error(f"Feed update job failed: {e}")


def _generate_report_job():
    """Job: Generate and deliver the daily admin report."""
    try:
        from reporting import generate_and_deliver
        logger.info("Generating daily report...")
        report = generate_and_deliver("daily")
        total = report.get("counts", {}).get("total", 0)
        delivered = report.get("delivered_via", [])
        logger.info(f"Report generated: {total} emails, delivered via {delivered}")
    except Exception as e:
        logger.error(f"Report job failed: {e}")


def create_scheduler() -> BackgroundScheduler:
    """Create and configure the background scheduler with all jobs."""
    scheduler = BackgroundScheduler(
        job_defaults={
            "coalesce": True,      # merge missed runs into one
            "max_instances": 1,    # prevent overlapping runs
            "misfire_grace_time": 60,
        }
    )

    # Job 1: IMAP poll every N seconds
    scheduler.add_job(
        _run_pipeline_job,
        trigger=IntervalTrigger(seconds=POLL_INTERVAL),
        id="imap_poll",
        name="IMAP Poll & Analysis",
        replace_existing=True,
    )

    # Job 2: Threat feed update (daily at 03:00 by default)
    cron_parts = FEED_UPDATE_CRON.split()
    if len(cron_parts) == 5:
        scheduler.add_job(
            _update_feeds_job,
            trigger=CronTrigger(
                minute=cron_parts[0], hour=cron_parts[1],
                day=cron_parts[2], month=cron_parts[3],
                day_of_week=cron_parts[4],
            ),
            id="feed_update",
            name="Threat Feed Update",
            replace_existing=True,
        )

    # Job 3: Daily admin report (daily at 08:00 by default)
    report_parts = REPORT_CRON.split()
    if len(report_parts) == 5:
        scheduler.add_job(
            _generate_report_job,
            trigger=CronTrigger(
                minute=report_parts[0], hour=report_parts[1],
                day=report_parts[2], month=report_parts[3],
                day_of_week=report_parts[4],
            ),
            id="daily_report",
            name="Daily Admin Report",
            replace_existing=True,
        )

    return scheduler


def start_daemon():
    """Start the scheduler as a foreground daemon process."""
    logger.info("=" * 50)
    logger.info("[SCHEDULER] Starting ImaniIA background scheduler")
    logger.info(f"  IMAP poll interval: {POLL_INTERVAL}s")
    logger.info(f"  Feed update cron:   {FEED_UPDATE_CRON}")
    logger.info(f"  Report cron:        {REPORT_CRON}")
    logger.info("=" * 50)

    scheduler = create_scheduler()
    scheduler.start()

    # Graceful shutdown
    def _shutdown(signum, frame):
        logger.info("[SCHEDULER] Shutting down...")
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Print registered jobs
    jobs = scheduler.get_jobs()
    for job in jobs:
        logger.info(f"  Registered: {job.name} (next run: {job.next_run_time})")

    # Block forever — scheduler runs in background thread
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        logger.info("[SCHEDULER] Shutting down...")
        scheduler.shutdown(wait=False)


if __name__ == "__main__":
    start_daemon()
