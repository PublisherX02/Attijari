"""logger.py — Structured audit logging for compliance.

Replaces standard print() with JSON-formatted logs containing:
- timestamp
- log level
- module name
- message

Logs are written to both standard output and an audit trail file (data/audit.log).
"""
import logging
import os
from pathlib import Path

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
