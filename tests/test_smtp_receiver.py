import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

import pytest
from limits.storage import MemoryStorage

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.smtp_receiver import PendingMailHandler
from src.smtp_rate_limit import SmtpRateLimiter


class _FakeSession:
    pass


class _FakeEnvelope:
    def __init__(self):
        self.rcpt_tos = []
        self.content = b""
        self.mail_from = None
        self.mail_options = []


@pytest.mark.asyncio
async def test_handle_mail_accepts_sender_under_limit(tmp_path):
    handler = PendingMailHandler(
        pending_dir=tmp_path,
        accepted_domains=set(),
        max_size=1000,
        rate_limiter=SmtpRateLimiter(storage=MemoryStorage()),
    )
    envelope = _FakeEnvelope()
    status = await handler.handle_MAIL(
        None, _FakeSession(), envelope, "sender@example.com", []
    )
    assert status == "250 OK"
    assert envelope.mail_from == "sender@example.com"


@pytest.mark.asyncio
async def test_handle_mail_rejects_sender_over_limit(tmp_path):
    limiter = SmtpRateLimiter(storage=MemoryStorage())
    handler = PendingMailHandler(
        pending_dir=tmp_path, accepted_domains=set(), max_size=1000, rate_limiter=limiter
    )
    envelope = _FakeEnvelope()
    for _ in range(20):
        status = await handler.handle_MAIL(
            None, _FakeSession(), envelope, "flooder@example.com", []
        )
        assert status == "250 OK"
        envelope.mail_from = None  # reset, mirroring a fresh transaction per message
    status = await handler.handle_MAIL(
        None, _FakeSession(), envelope, "flooder@example.com", []
    )
    assert status.startswith("450")
    assert envelope.mail_from is None


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


@pytest.mark.asyncio
async def test_handle_data_is_noop_for_already_processed_file(tmp_path):
    # A source that re-delivers unread mail on every poll (gmail_smtp_bridge.py,
    # every 60s, forever) must not resurrect and re-enqueue a message whose
    # file was already moved to processed/ by a successful pipeline run --
    # otherwise every already-analyzed email gets silently re-queued forever
    # for as long as it stays in the bridge's fetch window, even after the
    # source message is deleted.
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1000)
    content = b"Subject: already handled\r\n\r\nbody\r\n"
    import hashlib
    sha = hashlib.sha256(content).hexdigest()
    processed_dir = tmp_path / "processed"
    processed_dir.mkdir()
    (processed_dir / f"{sha}.eml").write_bytes(content)

    envelope = _FakeEnvelope()
    envelope.content = content
    with patch("src.smtp_receiver.enqueue_pipeline_job") as mock_enqueue:
        status = await handler.handle_DATA(None, _FakeSession(), envelope)

    assert status == "250 Message accepted for delivery"
    mock_enqueue.assert_not_called()
    # must not resurrect the file in the top-level pending dir either
    assert not (tmp_path / f"{sha}.eml").exists()


@pytest.mark.asyncio
async def test_handle_data_still_enqueues_when_not_yet_processed(tmp_path):
    # Sanity check the fix doesn't over-broaden: a genuinely new (or still
    # pending/failed, never-moved-to-processed/) message must still enqueue.
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1000)
    envelope = _FakeEnvelope()
    envelope.content = b"Subject: brand new\r\n\r\nbody\r\n"
    with patch("src.smtp_receiver.enqueue_pipeline_job") as mock_enqueue:
        status = await handler.handle_DATA(None, _FakeSession(), envelope)

    assert status == "250 Message accepted for delivery"
    mock_enqueue.assert_called_once()
    assert len(list(tmp_path.glob("*.eml"))) == 1


def test_end_to_end_delivery_via_real_controller(tmp_path):
    """Integration test: real Controller on an ephemeral port, real smtplib client.

    enqueue_pipeline_job is patched out here: it always targets the real,
    global "attijari-pipeline" Redis queue regardless of this test's
    isolated tmp_path pending_dir, so an unpatched call here would enqueue
    a real job (pointing at a file this test's tmp_path fixture deletes
    afterward) into the actual production queue a live worker consumes —
    confirmed live 2026-08-03 (real DB rows and a real processing delay
    resulted from exactly this before the patch was added). Enqueue
    behavior itself is already covered by test_smtp_receiver_enqueues.py's
    mocked tests.
    """
    from src.smtp_receiver import PendingMailHandler
    from aiosmtpd.controller import Controller

    with patch("src.smtp_receiver.enqueue_pipeline_job"):
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


def test_end_to_end_rate_limit_rejects_flood_via_real_controller(tmp_path):
    """Integration test: a real controller genuinely returns 450 over SMTP wire once the sender's quota is spent.

    enqueue_pipeline_job is patched out — see the comment on
    test_end_to_end_delivery_via_real_controller above for why: it always
    targets the real production Redis queue regardless of this test's
    isolated tmp_path, which previously let 20 real "flooder@example.com"
    jobs land in the live database.
    """
    from aiosmtpd.controller import Controller

    port = 20026
    handler = PendingMailHandler(
        pending_dir=tmp_path,
        accepted_domains=set(),
        max_size=1_000_000,
        rate_limiter=SmtpRateLimiter(storage=MemoryStorage()),
    )
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        with patch("src.smtp_receiver.enqueue_pipeline_job"):
            with smtplib.SMTP("127.0.0.1", port, timeout=5) as client:
                for i in range(20):
                    msg = EmailMessage()
                    msg["From"] = "flooder@example.com"
                    msg["To"] = "analyst@attijaribank.com"
                    msg["Subject"] = f"flood {i}"
                    msg.set_content(f"flood body {i}")
                    client.send_message(msg)

                msg = EmailMessage()
                msg["From"] = "flooder@example.com"
                msg["To"] = "analyst@attijaribank.com"
                msg["Subject"] = "flood 21"
                msg.set_content("flood body 21")
                with pytest.raises(smtplib.SMTPSenderRefused) as exc_info:
                    client.send_message(msg)
                assert exc_info.value.smtp_code == 450
    finally:
        controller.stop()

    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 20
