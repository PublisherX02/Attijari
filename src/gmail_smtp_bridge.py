"""gmail_smtp_bridge.py — relays real mail into the local inbound SMTP receiver.

Context: the 2026-07-24 change (see
docs/superpowers/specs/2026-07-24-smtp-ingestion-design.md) replaced IMAP
polling with src/smtp_receiver.py as the pipeline's ONLY ingestion source.
That spec deliberately simulates "the internet" locally — it expects a test
client (swaks/smtplib) to deliver mail, not real mail. That broke the
personal-mailbox demo described in CLAUDE.md, since nothing bridged the two.

This module IS that test client: it polls the active mailbox over IMAP
(reusing EmailIngestion, the same class the pipeline used before SMTP
ingestion replaced it) and re-delivers each message via SMTP to our own
receiver. run_pipeline() in main.py is untouched — it still only reads from
data/smtp_pending/; this just keeps that directory fed with real mail.

Which mailbox is "active" comes from the dashboard-managed mailbox_accounts
table (2026-07-29, see
docs/superpowers/specs/2026-07-29-dashboard-mailbox-accounts-design.md) —
falls back to the legacy IMAP_HOST/IMAP_USER/IMAP_PASSWORD env vars if no
mailbox has been added/activated yet, so today's Gmail setup keeps working
unmodified until it's adopted into the dashboard.

Safe to poll repeatedly: fetch_recent() uses BODY.PEEK[] (never marks
anything read on the source mailbox), and the SMTP receiver dedupes accepted
messages by content SHA-256, so re-relaying an already-seen message is a
no-op.
"""
from __future__ import annotations

import os
import smtplib
import time
from email import policy
from email.parser import BytesParser

from email_extraction import EmailIngestion

GMAIL_BRIDGE_INTERVAL = int(os.getenv("GMAIL_BRIDGE_INTERVAL_SECONDS", "60"))
SMTP_TARGET_HOST = os.getenv("SMTP_INBOUND_LISTEN_HOST", "127.0.0.1")
SMTP_TARGET_PORT = int(os.getenv("SMTP_INBOUND_LISTEN_PORT", "2525"))


def _extract_from(raw: bytes) -> str:
    """Best-effort envelope-from for the relay hop; the receiver only checks RCPT TO."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        addr = msg.get("From") or ""
        if "<" in addr and ">" in addr:
            return addr[addr.index("<") + 1: addr.index(">")]
        return addr or "mail-bridge@localhost"
    except Exception:
        return "mail-bridge@localhost"


def relay_one(raw: bytes, rcpt_to: str) -> bool:
    """Deliver one raw message to the local inbound SMTP receiver. True on success."""
    try:
        with smtplib.SMTP(SMTP_TARGET_HOST, SMTP_TARGET_PORT, timeout=15) as smtp:
            smtp.sendmail(_extract_from(raw), [rcpt_to], raw)
        return True
    except Exception as e:
        print(f"[MAIL-BRIDGE] Relay failed: {e}")
        return False


def run_once() -> int:
    """Fetch recent mail from the active mailbox and relay it into the SMTP receiver.
    Returns count relayed."""
    from database import SessionLocal
    from mailboxes import get_active_mailbox_credentials

    db = SessionLocal()
    try:
        active = get_active_mailbox_credentials(db)
    except Exception as e:
        print(f"[MAIL-BRIDGE] Failed to load active mailbox, falling back to .env: {e}")
        active = None
    finally:
        db.close()

    if active:
        host, user, password, port = active["host"], active["user"], active["password"], active["port"]
    else:
        host = os.getenv("IMAP_HOST")
        user = os.getenv("IMAP_USER")
        password = os.getenv("IMAP_PASSWORD")
        port = 993

    rcpt_to = os.getenv("GMAIL_BRIDGE_RCPT_TO") or user or ""
    if not rcpt_to:
        print("[MAIL-BRIDGE] No recipient configured "
              "(set GMAIL_BRIDGE_RCPT_TO, or configure/activate a mailbox in the dashboard) — skipping")
        return 0

    ingestion = EmailIngestion(host=host, user=user, password=password, port=port)
    try:
        ingestion.connect()
    except Exception as e:
        print(f"[MAIL-BRIDGE] IMAP connect failed: {e}")
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
        print(f"[MAIL-BRIDGE] Relayed {relayed}/{len(raw_emails)} message(s) into the SMTP receiver")
    return relayed


def run_forever() -> None:
    print(f"[MAIL-BRIDGE] Polling every {GMAIL_BRIDGE_INTERVAL}s -> {SMTP_TARGET_HOST}:{SMTP_TARGET_PORT}")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[MAIL-BRIDGE] Tick error: {e}")
        time.sleep(GMAIL_BRIDGE_INTERVAL)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    run_forever()
