"""gmail_smtp_bridge.py — relays real Gmail mail into the local inbound SMTP receiver.

Context: the 2026-07-24 change (see
docs/superpowers/specs/2026-07-24-smtp-ingestion-design.md) replaced IMAP
polling with src/smtp_receiver.py as the pipeline's ONLY ingestion source.
That spec deliberately simulates "the internet" locally — it expects a test
client (swaks/smtplib) to deliver mail, not real Gmail. That broke the
personal-Gmail demo described in CLAUDE.md, since nothing bridged the two.

This module IS that test client: it polls Mohamed's Gmail over IMAP (reusing
EmailIngestion, the same class the pipeline used before SMTP ingestion
replaced it) and re-delivers each message via SMTP to our own receiver.
run_pipeline() in main.py is untouched — it still only reads from
data/smtp_pending/; this just keeps that directory fed with real mail.

Safe to poll repeatedly: fetch_recent() uses BODY.PEEK[] (never marks
anything read on Gmail), and the SMTP receiver dedupes accepted messages by
content SHA-256, so re-relaying an already-seen message is a no-op.
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
# Must resolve to an address SMTP_INBOUND_ACCEPTED_DOMAINS allows (or that
# list must be empty). Falls back to the Gmail account itself.
BRIDGE_RCPT_TO = os.getenv("GMAIL_BRIDGE_RCPT_TO") or os.getenv("IMAP_USER", "")


def _extract_from(raw: bytes) -> str:
    """Best-effort envelope-from for the relay hop; the receiver only checks RCPT TO."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        addr = msg.get("From") or ""
        if "<" in addr and ">" in addr:
            return addr[addr.index("<") + 1: addr.index(">")]
        return addr or "gmail-bridge@localhost"
    except Exception:
        return "gmail-bridge@localhost"


def relay_one(raw: bytes) -> bool:
    """Deliver one raw message to the local inbound SMTP receiver. True on success."""
    try:
        with smtplib.SMTP(SMTP_TARGET_HOST, SMTP_TARGET_PORT, timeout=15) as smtp:
            smtp.sendmail(_extract_from(raw), [BRIDGE_RCPT_TO], raw)
        return True
    except Exception as e:
        print(f"[GMAIL-BRIDGE] Relay failed: {e}")
        return False


def run_once() -> int:
    """Fetch recent Gmail mail and relay it into the SMTP receiver. Returns count relayed."""
    if not BRIDGE_RCPT_TO:
        print("[GMAIL-BRIDGE] No recipient configured "
              "(set GMAIL_BRIDGE_RCPT_TO or IMAP_USER) — skipping")
        return 0

    ingestion = EmailIngestion(
        host=os.getenv("IMAP_HOST"),
        user=os.getenv("IMAP_USER"),
        password=os.getenv("IMAP_PASSWORD"),
    )
    try:
        ingestion.connect()
    except Exception as e:
        print(f"[GMAIL-BRIDGE] IMAP connect failed: {e}")
        return 0

    try:
        raw_emails = ingestion.fetch_recent(since_days=7, limit=50)
    finally:
        try:
            ingestion.disconnect()
        except Exception:
            pass

    relayed = sum(1 for raw in raw_emails if relay_one(raw))
    if relayed:
        print(f"[GMAIL-BRIDGE] Relayed {relayed}/{len(raw_emails)} "
              f"Gmail message(s) into the SMTP receiver")
    return relayed


def run_forever() -> None:
    print(f"[GMAIL-BRIDGE] Polling Gmail every {GMAIL_BRIDGE_INTERVAL}s -> "
          f"{SMTP_TARGET_HOST}:{SMTP_TARGET_PORT} (rcpt={BRIDGE_RCPT_TO or 'UNSET'})")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[GMAIL-BRIDGE] Tick error: {e}")
        time.sleep(GMAIL_BRIDGE_INTERVAL)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    run_forever()
