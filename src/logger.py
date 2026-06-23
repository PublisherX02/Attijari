"""logger.py — Structured audit logging for compliance.

Two log streams:
  1. Console: human-readable for operator (via print() in pipeline)
  2. Audit file: machine-readable JSON lines for SOC compliance trail

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure data directory exists
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _PROJECT_ROOT / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)

_LOG_FILE = _DATA_DIR / "audit.log"

logging.basicConfig(
    format='{"ts":"%(asctime)s", "level":"%(levelname)s", "module":"%(name)s", "msg":"%(message)s"}',
    level=logging.INFO,
    handlers=[
        logging.FileHandler(_LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("tijari")


def get_logger(module_name: str) -> logging.Logger:
    """Get a configured logger for a specific module."""
    return logging.getLogger(f"tijari.{module_name}")


# ---------------------------------------------------------------------------
# Structured audit trail — JSON lines appended to data/audit.log
# ---------------------------------------------------------------------------
_audit_logger = logging.getLogger("tijari.audit")
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
