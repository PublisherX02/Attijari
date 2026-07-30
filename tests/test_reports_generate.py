"""Regression test for the "Generate Report Now" dashboard button.

Bug: the button called GET /api/stats (a no-op stats refresh, discarded)
instead of anything that actually produced a report, so /api/reports
stayed permanently empty ("No reports generated yet" forever). Fixed by
adding POST /api/reports/generate, which calls the same
reporting.generate_and_deliver() the scheduler already uses.
"""
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest

from routers import emails as emails_router_mod

ADMIN = SimpleNamespace(username="admin", role="admin", user_id=1)


@pytest.mark.asyncio
async def test_generate_report_calls_generate_and_deliver_and_reports_channels():
    fake_report = {"delivered_via": ["dashboard", "smtp"]}
    with patch("reporting.generate_and_deliver", return_value=fake_report) as mock_gen:
        result = await emails_router_mod.api_generate_report(period="daily", user=ADMIN)
    mock_gen.assert_called_once_with("daily")
    assert result == {"delivered_via": ["dashboard", "smtp"], "period": "daily"}


@pytest.mark.asyncio
async def test_generate_report_defaults_delivered_via_to_empty_list():
    with patch("reporting.generate_and_deliver", return_value={}):
        result = await emails_router_mod.api_generate_report(period="weekly", user=ADMIN)
    assert result == {"delivered_via": [], "period": "weekly"}
