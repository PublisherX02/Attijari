"""alerts.py — Lightweight alerting for critical security events.

Logs alerts to DB (alert table) and optionally sends to webhook.
No external dependencies — uses stdlib urllib for webhooks.
"""
from __future__ import annotations

import json
import os
from enum import Enum
from typing import Optional


class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


def send_alert(
    level: AlertLevel,
    title: str,
    details: Optional[dict] = None,
    source: str = "system",
) -> None:
    """Log a security alert to console, DB, and optional webhook.

    Never raises — any failure is printed and swallowed so the pipeline
    continues (fail-safe: alerting must not become a failure mode).
    """
    print(f"[ALERT-{level.value.upper()}] {title}")
    _save_to_db(level, title, details, source)
    _post_webhook(level, title, details, source)


# ---------------------------------------------------------------------------
# Internal helpers (kept private — callers use send_alert only)
# ---------------------------------------------------------------------------

def _save_to_db(
    level: AlertLevel,
    title: str,
    details: Optional[dict],
    source: str,
) -> None:
    try:
        from database import SessionLocal, Alert
        db = SessionLocal()
        try:
            alert = Alert(level=level.value, title=title, details=details, source=source)
            db.add(alert)
            db.commit()
        finally:
            db.close()
    except Exception as e:
        print(f"[ALERT] DB save failed: {e}")


def _post_webhook(
    level: AlertLevel,
    title: str,
    details: Optional[dict],
    source: str,
) -> None:
    url = os.getenv("ALERT_WEBHOOK_URL")
    if not url:
        return
    try:
        from urllib.request import urlopen, Request as UrlRequest
        from urllib.error import URLError
        payload = json.dumps({
            "level": level.value,
            "title": title,
            "details": details or {},
            "source": source,
        }).encode("utf-8")
        req = UrlRequest(url, data=payload, headers={"Content-Type": "application/json"})
        urlopen(req, timeout=5)
    except Exception as e:
        print(f"[ALERT] Webhook delivery failed: {e}")
