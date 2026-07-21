"""SEC-H3: JWT revocation is durable (DB-backed), not in-memory.

A revoked/logged-out token must stay revoked across process restarts and be
visible to every worker — the old in-memory set reset on restart, silently
reviving revoked tokens.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# api_core refuses to import without a signing key — provide one for the test.
if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import jwt as pyjwt
import pytest
from database import (
    Base, RevokedToken, SessionLocal, engine, utcnow,
    add_revoked_token, is_jti_revoked,
)
import api_core


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    jtis = []
    session.info["jtis"] = jtis
    yield session
    session.rollback()
    session.query(RevokedToken).filter(RevokedToken.jti.in_(jtis)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _mk_token(jti="j-abc", with_jti=True, hours=8):
    payload = {"sub": "alice", "role": "analyst",
               "exp": datetime.now(timezone.utc) + timedelta(hours=hours)}
    if with_jti:
        payload["jti"] = jti
    return pyjwt.encode(payload, api_core.JWT_SECRET, algorithm=api_core.ALGORITHM)


def test_add_and_check_revoked(db_session):
    jti = "revoke-me-1"
    db_session.info["jtis"].append(jti)
    add_revoked_token(db_session, jti, utcnow() + timedelta(hours=8))
    assert is_jti_revoked(db_session, jti) is True
    assert is_jti_revoked(db_session, "never-added") is False


def test_expired_revocation_is_not_active(db_session):
    jti = "expired-1"
    db_session.info["jtis"].append(jti)
    # Insert directly with a past expiry (add_revoked_token would purge it).
    db_session.add(RevokedToken(jti=jti, expires_at=utcnow() - timedelta(minutes=1)))
    db_session.commit()
    assert is_jti_revoked(db_session, jti) is False


def test_add_purges_expired_rows(db_session):
    old = "old-expired"
    db_session.add(RevokedToken(jti=old, expires_at=utcnow() - timedelta(hours=1)))
    db_session.commit()
    fresh = "fresh-1"
    db_session.info["jtis"].append(fresh)
    add_revoked_token(db_session, fresh, utcnow() + timedelta(hours=8))
    # The expired row should have been swept on insert.
    assert db_session.query(RevokedToken).filter(RevokedToken.jti == old).first() is None


def test_revoke_token_end_to_end(db_session):
    token = _mk_token(jti="e2e-1")
    db_session.info["jtis"].append("e2e-1")
    assert api_core.is_token_revoked(token) is False
    api_core.revoke_token(token)
    assert api_core.is_token_revoked(token) is True


def test_durable_reads_from_db_not_memory(db_session):
    # There is no in-memory set anymore: is_token_revoked answers purely from
    # the DB, so a token revoked "in another process" is seen here too.
    token = _mk_token(jti="durable-1")
    db_session.info["jtis"].append("durable-1")
    add_revoked_token(db_session, "durable-1", utcnow() + timedelta(hours=8))
    assert api_core.is_token_revoked(token) is True


def test_legacy_token_without_jti_is_revocable(db_session):
    import hashlib
    token = _mk_token(with_jti=False)
    db_session.info["jtis"].append(hashlib.sha256(token.encode()).hexdigest())
    api_core.revoke_token(token)
    assert api_core.is_token_revoked(token) is True


def test_unrelated_token_not_revoked(db_session):
    revoked = _mk_token(jti="r-1")
    other = _mk_token(jti="r-2")
    db_session.info["jtis"].append("r-1")
    api_core.revoke_token(revoked)
    assert api_core.is_token_revoked(other) is False
