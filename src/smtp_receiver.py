"""Inbound SMTP receiver — accepts mail fast, hands off to the pipeline later.

Replaces Gmail IMAP polling as the source of new mail (see
docs/superpowers/specs/2026-07-24-smtp-ingestion-design.md). Accepts a
message (size + recipient-domain checks only) and writes it to
data/smtp_pending/ for main.py's existing pipeline to pick up on its next
tick — no rules/extraction/enrichment/LLM work happens inside the SMTP
transaction itself.
"""
import hashlib
import os
from pathlib import Path

from aiosmtpd.controller import Controller

from pipeline_jobs import enqueue_pipeline_job

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
PENDING_DIR = _PROJECT_ROOT / "data" / "smtp_pending"


class PendingMailHandler:
    """aiosmtpd message handler: validate fast, persist, return."""

    def __init__(self, pending_dir: Path, accepted_domains: set[str], max_size: int):
        self.pending_dir = pending_dir
        self.accepted_domains = accepted_domains
        self.max_size = max_size

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if self.accepted_domains:
            domain = address.split("@")[-1].lower() if "@" in address else ""
            if domain not in self.accepted_domains:
                return f"550 not accepting mail for {address!r}"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        data = envelope.content
        if len(data) > self.max_size:
            return f"552 Message exceeds size limit of {self.max_size} bytes"

        self.pending_dir.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256(data).hexdigest()
        path = self.pending_dir / f"{sha}.eml"
        if not path.exists():
            path.write_bytes(data)
        enqueue_pipeline_job(str(path))
        return "250 Message accepted for delivery"


def _accepted_domains_from_env() -> set[str]:
    raw = os.getenv("SMTP_INBOUND_ACCEPTED_DOMAINS", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def build_controller() -> Controller:
    """Construct (but do not start) the inbound SMTP Controller from env config."""
    host = os.getenv("SMTP_INBOUND_LISTEN_HOST", "127.0.0.1")
    port = int(os.getenv("SMTP_INBOUND_LISTEN_PORT", "2525"))
    max_size = int(os.getenv("SMTP_INBOUND_MAX_MESSAGE_SIZE", str(25 * 1024 * 1024)))
    handler = PendingMailHandler(
        pending_dir=PENDING_DIR,
        accepted_domains=_accepted_domains_from_env(),
        max_size=max_size,
    )
    return Controller(handler, hostname=host, port=port, data_size_limit=max_size)
