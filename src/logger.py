"""logger.py — Structured audit logging for compliance.

Two log streams:
  1. Console: human-readable for operator (via print() in pipeline)
  2. Audit file: machine-readable JSON lines for the compliance trail

The audit file (data/audit.log) contains one JSON object per line with:
  - ts: ISO-8601 timestamp
  - event: event type (e.g. "verdict", "enrichment_hit", "blocklist_add")
  - email_id: idempotency key or Message-ID
  - module: which pipeline stage produced this event
  - data: event-specific payload
"""
import json
import logging
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure data directory exists
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _PROJECT_ROOT / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)

_LOG_FILE = _DATA_DIR / "audit.log"

# Scoped to the "attijari" logger tree only -- NOT logging.basicConfig(),
# which configures the ROOT logger and therefore also captures every
# third-party library's own logger (rq, aiosmtpd's "mail.log",
# checkdmarc.*, ...). Those libraries already print their own console
# output through their own handlers, so hijacking root as well produced
# every one of their messages TWICE: once from their own handler, once
# re-echoed through our JSON formatter (confirmed live: 136 duplicate
# "rq.worker" JSON lines in one worker run alone). Attaching our handlers
# to "attijari" specifically, with propagate=False, keeps our own JSON
# console/file output while leaving third-party loggers alone.
_formatter = logging.Formatter(
    '{"ts":"%(asctime)s", "level":"%(levelname)s", "module":"%(name)s", "msg":"%(message)s"}'
)
_file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(_formatter)
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_formatter)

logger = logging.getLogger("attijari")
logger.setLevel(logging.INFO)
logger.propagate = False
logger.addHandler(_file_handler)
logger.addHandler(_stream_handler)

# --- Known-noisy, non-actionable third-party log/warning sources -----------
# Each of these is a real, previously-confirmed source of console clutter
# with zero diagnostic value in this environment -- not a blanket "silence
# everything" pass. Other messages from these same libraries still surface
# normally.

# aiosmtpd logs every SMTP protocol line (EHLO/MAIL FROM/RCPT TO/DATA/QUIT,
# "Peer: ...", "handling connection", "connection lost") at INFO under the
# logger name "mail.log" -- routine chatter on every single delivered
# email. Real problems (oversized message, malformed command) still surface
# at WARNING+.
logging.getLogger("mail.log").setLevel(logging.WARNING)


class _DropExactMessage(logging.Filter):
    """Drops only log records whose message exactly matches a known,
    permanently non-actionable one -- e.g. checkdmarc's Windows-only "TLS
    testing isn't supported" notice, which fires on nearly every email's
    DKIM/SPF/DMARC check and can never be resolved on this platform.
    Deliberately message-scoped rather than a logger-level cutoff, so any
    other (genuinely actionable) warning from the same logger still shows."""

    def __init__(self, message: str):
        super().__init__()
        self._message = message

    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage() != self._message


logging.getLogger("checkdmarc.smtp").addFilter(
    _DropExactMessage("Testing TLS is not supported on Windows")
)

# pydub emits this RuntimeWarning (via warnings.warn, not logging) every
# time its ffmpeg/avconv probe runs and finds neither on PATH -- a
# transitive MarkItDown dependency for audio transcription this project
# never uses (email/attachment text extraction only, no audio attack
# surface in scope). Installing ffmpeg would only silence a warning about
# a feature we don't use.
warnings.filterwarnings(
    "ignore",
    message=r"Couldn't find ffmpeg or avconv.*",
    category=RuntimeWarning,
)


def get_logger(module_name: str) -> logging.Logger:
    """Get a configured logger for a specific module."""
    return logging.getLogger(f"attijari.{module_name}")


# ---------------------------------------------------------------------------
# Structured audit trail — JSON lines appended to data/audit.log
# ---------------------------------------------------------------------------
_audit_logger = logging.getLogger("attijari.audit")
_audit_handler = logging.FileHandler(_DATA_DIR / "audit_events.jsonl", encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False  # don't duplicate to console


def audit_event(event: str, module: str, email_id: str | None = None,
                data: dict[str, Any] | None = None):
    """Write a structured audit event as a JSON line.

    Args:
        event: event type — "rules_verdict", "enrichment_hit", "llm_verdict",
               "blocklist_cascade", "extraction_flag", "final_verdict", etc.
        module: pipeline stage — "rules", "extraction", "threatfox", "virustotal",
                "abuseipdb", "otx", "dnstwist", "whois", "llm", "pipeline"
        email_id: idempotency key or Message-ID for correlation
        data: event-specific payload (must be JSON-serializable)
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "module": module,
        "email_id": email_id,
    }
    if data:
        record["data"] = data
    try:
        _audit_logger.info(json.dumps(record, default=str, ensure_ascii=False))
    except Exception:
        pass  # audit logging must never crash the pipeline
