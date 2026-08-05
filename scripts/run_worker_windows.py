"""run_worker_windows.py — Windows-safe RQ worker launcher for the
"attijari-pipeline" queue.

Plain `rq worker` is not usable on Windows for this project, in two
independent ways discovered live while debugging a stalled pipeline:

  1. RQ's default Worker forks a child process per job (os.fork()), which
     does not exist on Windows at all -- crashes on the very first job.
     Fixed by using SimpleWorker, which runs jobs in-process instead.

  2. Independent of the worker class actually running jobs,
     rq.registry.BaseRegistry hardcodes UnixSignalDeathPenalty (built on
     signal.SIGALRM, also POSIX-only) for the periodic registry-cleanup
     maintenance task. Every job enqueued by pipeline_jobs.py carries an
     on_failure callback (used to mark the matching email "escalated"),
     so ANY job left in the StartedJobRegistry by an interrupted/crashed
     worker run (including the fork crash above) makes the *next*
     worker's routine cleanup try to run that callback under a death
     penalty timeout -- and immediately crash with
     "AttributeError: module 'signal' has no attribute 'SIGALRM'".
     SimpleWorker.death_penalty_class is already the timer-based
     (threading, not signal) TimerDeathPenalty, but BaseRegistry's own
     hardcoded default is separate and does not follow it -- must be
     monkeypatched explicitly.

Deliberately does NOT reuse src/redis_client.py's shared get_client() --
that connection is constructed with decode_responses=True (correct for
the plain-string security state it's actually meant for: rate limits,
TOTP replay, the detonation-window lock), but RQ stores job payloads as
pickled binary and needs a raw bytes connection; forcing utf-8 decoding
on that data raises UnicodeDecodeError the moment RQ reads a job hash
back (confirmed live while writing this script). A dedicated
decode_responses=False connection is used here instead, pointed at the
same REDIS_URL and the same pipeline_jobs.QUEUE_NAME so it talks to the
identical queue the app enqueues onto.

Run with: python scripts/run_worker_windows.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import redis
import rq.registry
from rq import Queue
from rq.timeouts import TimerDeathPenalty
from rq.worker import SimpleWorker

rq.registry.BaseRegistry.death_penalty_class = TimerDeathPenalty

from pipeline_jobs import QUEUE_NAME  # noqa: E402  (after path setup)

if __name__ == "__main__":
    redis_url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    connection = redis.Redis.from_url(redis_url)  # decode_responses=False (default)
    queue = Queue(QUEUE_NAME, connection=connection)
    worker = SimpleWorker([queue], connection=connection)
    worker.work(with_scheduler=True)
