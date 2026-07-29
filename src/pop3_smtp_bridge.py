"""pop3_smtp_bridge.py — relays mail from a POP3-only active mailbox into the
local inbound SMTP receiver. Structural mirror of gmail_smtp_bridge.py, but
guards the opposite way: only acts when the active mailbox's protocol is
'pop3'. gmail_smtp_bridge.py carries the matching guard so exactly one
bridge ever acts on the active mailbox at a time.
"""
from __future__ import annotations

import os
import time

from email_extraction import Pop3Ingestion
from gmail_smtp_bridge import relay_one, SMTP_TARGET_HOST, SMTP_TARGET_PORT

POP3_BRIDGE_INTERVAL = int(os.getenv("POP3_BRIDGE_INTERVAL_SECONDS", "60"))


def run_once() -> int:
    """Fetch recent mail from the active mailbox over POP3 and relay it into
    the SMTP receiver. Returns count relayed. No-op unless the active
    mailbox's protocol is 'pop3'."""
    from database import SessionLocal
    from mailboxes import get_active_mailbox_credentials

    db = SessionLocal()
    try:
        active = get_active_mailbox_credentials(db)
    except Exception as e:
        print(f"[POP3-BRIDGE] Failed to load active mailbox: {e}")
        active = None
    finally:
        db.close()

    if not active or active.get("protocol") != "pop3":
        return 0

    host, user, password, port = active["host"], active["user"], active["password"], active["port"]
    rcpt_to = os.getenv("GMAIL_BRIDGE_RCPT_TO") or user

    ingestion = Pop3Ingestion(host=host, user=user, password=password, port=port)
    try:
        ingestion.connect()
    except Exception as e:
        print(f"[POP3-BRIDGE] POP3 connect failed: {e}")
        return 0

    try:
        raw_emails = ingestion.fetch_recent(since_days=7, limit=50)
    finally:
        try:
            ingestion.disconnect()
        except Exception:
            pass

    relayed = sum(1 for raw in raw_emails if relay_one(raw, rcpt_to))
    if relayed:
        print(f"[POP3-BRIDGE] Relayed {relayed}/{len(raw_emails)} message(s) into the SMTP receiver")
    return relayed


def run_forever() -> None:
    print(f"[POP3-BRIDGE] Polling every {POP3_BRIDGE_INTERVAL}s -> {SMTP_TARGET_HOST}:{SMTP_TARGET_PORT}")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[POP3-BRIDGE] Tick error: {e}")
        time.sleep(POP3_BRIDGE_INTERVAL)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    run_forever()
