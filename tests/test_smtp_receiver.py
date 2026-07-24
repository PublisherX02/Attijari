import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.smtp_receiver import PendingMailHandler


class _FakeSession:
    pass


class _FakeEnvelope:
    def __init__(self):
        self.rcpt_tos = []
        self.content = b""


@pytest.mark.asyncio
async def test_handle_rcpt_accepts_matching_domain(tmp_path):
    handler = PendingMailHandler(
        pending_dir=tmp_path, accepted_domains={"attijaribank.com"}, max_size=1000
    )
    envelope = _FakeEnvelope()
    status = await handler.handle_RCPT(
        None, _FakeSession(), envelope, "analyst@attijaribank.com", []
    )
    assert status == "250 OK"
    assert envelope.rcpt_tos == ["analyst@attijaribank.com"]


@pytest.mark.asyncio
async def test_handle_rcpt_rejects_other_domain(tmp_path):
    handler = PendingMailHandler(
        pending_dir=tmp_path, accepted_domains={"attijaribank.com"}, max_size=1000
    )
    envelope = _FakeEnvelope()
    status = await handler.handle_RCPT(
        None, _FakeSession(), envelope, "someone@gmail.com", []
    )
    assert status.startswith("550")
    assert envelope.rcpt_tos == []


@pytest.mark.asyncio
async def test_handle_rcpt_accepts_any_domain_when_unrestricted(tmp_path):
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1000)
    envelope = _FakeEnvelope()
    status = await handler.handle_RCPT(None, _FakeSession(), envelope, "x@anything.test", [])
    assert status == "250 OK"


@pytest.mark.asyncio
async def test_handle_data_writes_pending_file(tmp_path):
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1000)
    envelope = _FakeEnvelope()
    envelope.content = b"Subject: test\r\n\r\nbody\r\n"
    status = await handler.handle_DATA(None, _FakeSession(), envelope)
    assert status == "250 Message accepted for delivery"
    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 1
    assert files[0].read_bytes() == envelope.content


@pytest.mark.asyncio
async def test_handle_data_rejects_oversized_message(tmp_path):
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=10)
    envelope = _FakeEnvelope()
    envelope.content = b"x" * 100
    status = await handler.handle_DATA(None, _FakeSession(), envelope)
    assert status.startswith("552")
    assert list(tmp_path.glob("*.eml")) == []


def test_end_to_end_delivery_via_real_controller(tmp_path):
    """Integration test: real Controller on an ephemeral port, real smtplib client."""
    from src.smtp_receiver import PendingMailHandler
    from aiosmtpd.controller import Controller

    # aiosmtpd's Controller uses a real "wake up the server" connect() to
    # its configured port to confirm readiness; on Windows this fails with
    # port=0 (ephemeral), so a fixed test-only port is used instead.
    port = 20025
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1_000_000)
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        msg = EmailMessage()
        msg["From"] = "attacker@example.com"
        msg["To"] = "analyst@attijaribank.com"
        msg["Subject"] = "test delivery"
        msg.set_content("hello from the integration test")

        with smtplib.SMTP("127.0.0.1", port, timeout=5) as client:
            client.send_message(msg)
    finally:
        controller.stop()

    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 1
    assert b"hello from the integration test" in files[0].read_bytes()
