"""Router-level tests: call the endpoint functions directly with a fake
AuthenticatedUser, mirroring the codebase's existing pattern of testing
FastAPI handlers as plain async functions rather than spinning up a TestClient."""
import asyncio
import os
import random
import sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest
from starlette.requests import Request
from database import Base, MailboxAccount, SessionLocal, engine
from routers import mailboxes as mailboxes_router_mod
import mailboxes as mailboxes_service

ADMIN = SimpleNamespace(username="admin", role="admin", user_id=1)


def _fake_request() -> Request:
    """Minimal Starlette Request satisfying @_limiter.limit(...) — a random
    client IP per call so tests don't share a rate-limit bucket and trip
    each other up within the same test-session minute."""
    ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    scope = {
        "type": "http", "method": "POST", "path": "/", "headers": [],
        "client": (ip, 12345), "server": ("127.0.0.1", 8000),
        "scheme": "http", "query_string": b"", "app": None,
    }
    return Request(scope)


@pytest.fixture
def db_cleanup():
    Base.metadata.create_all(bind=engine)
    ids = []
    yield ids
    session = SessionLocal()
    session.query(MailboxAccount).filter(MailboxAccount.id.in_(ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def test_add_endpoint_rejects_bad_password(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-fail@gmail.com", provider="gmail", password="wrong",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(False, "AUTHENTICATIONFAILED")):
        with pytest.raises(Exception) as exc_info:
            asyncio.run(mailboxes_router_mod.api_add_mailbox(_fake_request(), body, ADMIN))
    assert "AUTHENTICATIONFAILED" in str(exc_info.value)


def test_add_then_list_then_activate(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-ok@gmail.com", provider="gmail", password="right",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(_fake_request(), body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    assert result["success"] is True
    assert "password" not in result["mailbox"]

    listing = asyncio.run(mailboxes_router_mod.api_list_mailboxes(ADMIN))
    assert any(m["email"] == "router-ok@gmail.com" for m in listing["mailboxes"])

    activated = asyncio.run(mailboxes_router_mod.api_activate_mailbox(result["mailbox"]["id"], ADMIN))
    assert activated["mailbox"]["is_active"] is True


def test_deactivate_endpoint_clears_active_flag(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-deact@gmail.com", provider="gmail", password="right",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(_fake_request(), body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    asyncio.run(mailboxes_router_mod.api_activate_mailbox(result["mailbox"]["id"], ADMIN))

    outcome = asyncio.run(mailboxes_router_mod.api_deactivate_mailbox(ADMIN))
    assert outcome["success"] is True

    listing = asyncio.run(mailboxes_router_mod.api_list_mailboxes(ADMIN))
    row = next(m for m in listing["mailboxes"] if m["id"] == result["mailbox"]["id"])
    assert row["is_active"] is False

    # now deletable, since nothing is active anymore
    deleted = asyncio.run(mailboxes_router_mod.api_delete_mailbox(result["mailbox"]["id"], ADMIN))
    db_cleanup.remove(result["mailbox"]["id"])
    assert deleted["success"] is True


def test_delete_active_mailbox_rejected(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-del@gmail.com", provider="gmail", password="right",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(_fake_request(), body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    asyncio.run(mailboxes_router_mod.api_activate_mailbox(result["mailbox"]["id"], ADMIN))

    with pytest.raises(Exception) as exc_info:
        asyncio.run(mailboxes_router_mod.api_delete_mailbox(result["mailbox"]["id"], ADMIN))
    assert exc_info.value.status_code == 400
