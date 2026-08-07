"""test_rules_engine_not_llm_overridable.py — CLAUDE.md critical design rule
2: "Rules engine rejections are NOT overridable by the LLM. The LLM can
escalate a clean-looking email, but can never clear something the rules
flagged." An explicit code comment in main.py only documents the guard for
the prior-status=="escalated" case (line ~322); there was no equivalent
comment or dedicated test for the more common "proposed_reject" case (a
rules-engine hard-evidence flag, e.g. a blocked attachment extension).
Verified structurally in main.py: the entire LLM-verdict-application block
(lines ~757-777) has no code path that ever assigns
parsed["status"] = "accepted" -- only "escalated" assignments exist there --
but this test proves it behaviorally with a forced LLM mock, not just by
reading the code, since a source-level guarantee that was never actually
exercised is exactly the class of bug this project has hit before (the
nested-email fix existing in source but not being live at test time).
"""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest


def _build_blocked_extension_email() -> bytes:
    return (
        b"From: colleague@trusted-partner.tld\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: TEST-RULE2-PYTEST-FORCED\r\n"
        b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n"
        b"--b\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Hi, please find the script attached.\r\n"
        b"--b\r\n"
        b'Content-Type: text/x-python; name="report.py"\r\n'
        b'Content-Disposition: attachment; filename="report.py"\r\n\r\n'
        b"print('hello')\r\n"
        b"--b--\r\n"
    )


@pytest.fixture
def _cleanup_test_email():
    yield
    from database import SessionLocal, Email, Attachment, AuditLog, AnalystFeedback, PendingDetonation
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.subject == "TEST-RULE2-PYTEST-FORCED").first()
        if email:
            db.query(AuditLog).filter(AuditLog.email_id == email.id).delete()
            db.query(AnalystFeedback).filter(AnalystFeedback.email_id == email.id).delete()
            db.query(PendingDetonation).filter(PendingDetonation.email_id == email.id).delete()
            db.query(Attachment).filter(Attachment.email_id == email.id).delete()
            db.query(Email).filter(Email.id == email.id).delete()
            db.commit()
    finally:
        db.close()


def test_proposed_reject_survives_explicit_llm_accepted_verdict(tmp_path, _cleanup_test_email):
    import main

    path = tmp_path / "forced_test.eml"
    path.write_bytes(_build_blocked_extension_email())

    with patch("main.analyze_email_body", return_value={
        "verdict": "accepted", "confidence": 0.95, "risk_score": 5,
        "reasons": ["forced test: LLM says accepted despite rules-engine hard flag"],
    }):
        main.run_pipeline(single_file=str(path))

    from database import SessionLocal, Email
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.subject == "TEST-RULE2-PYTEST-FORCED").order_by(Email.id.desc()).first()
        assert email is not None, "pipeline did not persist an Email row for the test file"
        assert email.rules_result.get("verdict") == "proposed_reject", (
            "test setup invalid: expected the .py attachment to trigger a rules-engine "
            "proposed_reject, got " + repr(email.rules_result.get("verdict"))
        )
        assert email.status != "accepted", (
            "RULE 2 VIOLATED: rules-engine proposed_reject was overridden by an explicit "
            "LLM 'accepted' verdict"
        )
    finally:
        db.close()
