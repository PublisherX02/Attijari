"""detonation_state.py — Global "detonation in progress" flag.

While a drained detonation window is active, the pipeline is torn down (Ollama
models unloaded, Docker stopped) to free RAM for the CAPE Ubuntu VM. The
background poller, the scheduler, and the manual /api/scan endpoint must all
refuse to start a new pipeline run during that window — otherwise they'd reload
the models and blow the memory budget on a 16 GB machine.

This is an in-process flag (the pipeline runs single-process, workers=1). It is
watchdog-guarded in detonation.py: it always clears, even on crash, so the
system can never get stuck "paused" (fail-safe, never fail-open).
"""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_active = False
_since = 0.0
_reason = ""


def begin(reason: str = "") -> None:
    global _active, _since, _reason
    with _lock:
        _active = True
        _since = time.time()
        _reason = reason


def end() -> None:
    global _active, _reason
    with _lock:
        _active = False
        _reason = ""


def is_active() -> bool:
    with _lock:
        return _active


def status() -> dict:
    with _lock:
        return {
            "active": _active,
            "reason": _reason,
            "elapsed_s": round(time.time() - _since, 1) if _active else 0,
        }
