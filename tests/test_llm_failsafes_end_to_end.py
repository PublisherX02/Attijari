"""test_llm_failsafes_end_to_end.py — CLAUDE.md critical design rules 1 and
3, verified through the FULL run_pipeline(), not just analyze_email_body()
in isolation. test_llm_adversarial_regression.py already proves the
function-level invariants (low confidence forces escalation, a crashed
Ollama call returns escalated) -- but a function-level guarantee that was
never exercised end-to-end is exactly the class of bug this project hit
earlier the same day (the nested-email fix existed correctly in source but
wasn't live at the actual test time). These two tests send a genuinely
clean email (no rules-engine hard/soft flags at all) through
main.run_pipeline() with the low-level Ollama call functions mocked, and
confirm the final DB-persisted status is escalated, not accepted or a crash.

Rule 1: "Fail-safe, never fail-open... LLM error... defaults to
escalate-to-human... NEVER to accept."
Rule 3: "Low confidence -> forced escalation regardless of verdict."
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


def _build_clean_email(subject: str) -> bytes:
    # No attachment, no Authentication-Results header (verify_sender_authentication
    # bypasses the strict DMARC check when no gateway header is present -- "for
    # local testing"), plain benign body: nothing here should trip any
    # rules-engine hard or soft flag, isolating the LLM-stage fail-safes.
    return (
        f"From: colleague@trusted-partner.tld\r\n"
        f"To: victim@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"Hi, just checking in about next week's meeting. See you then.\r\n"
    ).encode()


@pytest.fixture
def _cleanup(request):
    subjects = []

    def _register(subject):
        subjects.append(subject)

    yield _register

    from database import SessionLocal, Email, Attachment, AuditLog, AnalystFeedback, PendingDetonation
    db = SessionLocal()
    try:
        for subject in subjects:
            email = db.query(Email).filter(Email.subject == subject).first()
            if email:
                db.query(AuditLog).filter(AuditLog.email_id == email.id).delete()
                db.query(AnalystFeedback).filter(AnalystFeedback.email_id == email.id).delete()
                db.query(PendingDetonation).filter(PendingDetonation.email_id == email.id).delete()
                db.query(Attachment).filter(Attachment.email_id == email.id).delete()
                db.query(Email).filter(Email.id == email.id).delete()
        db.commit()
    finally:
        db.close()


def test_low_confidence_forces_escalation_end_to_end(tmp_path, _cleanup):
    import main
    import analysis

    subject = "TEST-RULE3-PYTEST-FORCED"
    _cleanup(subject)
    path = tmp_path / "rule3_test.eml"
    path.write_bytes(_build_clean_email(subject))

    low_confidence_json = (
        '{"verdict": "accepted", "confidence": 0.2, "risk_score": 5, '
        '"sender_risk": 5, "intent_classification": "benign"}'
    )
    with patch.object(analysis, "is_payload_safe", return_value=True), \
         patch.object(analysis, "_call_ollama_client", return_value=low_confidence_json):
        main.run_pipeline(single_file=str(path))

    from database import SessionLocal, Email
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.subject == subject).order_by(Email.id.desc()).first()
        assert email is not None, "pipeline did not persist an Email row for the test file"
        assert email.rules_result.get("verdict") == "accepted", (
            "test setup invalid: expected a clean rules-engine pass to isolate "
            "the LLM-stage fail-safe, got " + repr(email.rules_result.get("verdict"))
        )
        assert email.llm_result.get("raw_model_output") is not None or email.llm_result.get("verdict") == "escalated", (
            "expected the LLM stage to have actually run"
        )
        assert email.status == "escalated", (
            f"RULE 3 VIOLATED: low-confidence (0.2) 'accepted' LLM verdict on a rules-clean "
            f"email did not force escalation end-to-end; final status was {email.status!r}"
        )
    finally:
        db.close()


def test_llm_outage_fails_safe_to_escalated_end_to_end(tmp_path, _cleanup):
    import main
    import analysis

    subject = "TEST-RULE1-PYTEST-FORCED"
    _cleanup(subject)
    path = tmp_path / "rule1_test.eml"
    path.write_bytes(_build_clean_email(subject))

    def _raise(*a, **k):
        raise RuntimeError("simulated Ollama outage")

    with patch.object(analysis, "is_payload_safe", return_value=True), \
         patch.object(analysis, "_call_ollama_client", side_effect=_raise), \
         patch.object(analysis, "_call_ollama_http", side_effect=_raise):
        main.run_pipeline(single_file=str(path))

    from database import SessionLocal, Email
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.subject == subject).order_by(Email.id.desc()).first()
        assert email is not None, "pipeline did not persist an Email row for the test file"
        assert email.rules_result.get("verdict") == "accepted", (
            "test setup invalid: expected a clean rules-engine pass to isolate "
            "the LLM-outage fail-safe, got " + repr(email.rules_result.get("verdict"))
        )
        assert email.status == "escalated", (
            f"RULE 1 VIOLATED: a completely unreachable LLM (both Ollama call paths "
            f"raising) did not fail safe to escalated end-to-end; final status was "
            f"{email.status!r} -- the pipeline must never treat an LLM outage as an "
            f"implicit accept, and must not crash the whole run either"
        )
    finally:
        db.close()
