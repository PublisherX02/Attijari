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

import json

import pytest
from fastapi import HTTPException

from database import Report, SessionLocal
from routers import emails as emails_router_mod

ADMIN = SimpleNamespace(username="admin", role="admin", user_id=1)


@pytest.fixture
def sample_report():
    db = SessionLocal()
    try:
        from datetime import datetime, timezone
        row = Report(
            report_type="daily",
            period_start=datetime(2026, 7, 29, tzinfo=timezone.utc),
            period_end=datetime(2026, 7, 30, tzinfo=timezone.utc),
            data={"counts": {"total": 3}, "details": []},
            delivered_via=["dashboard"],
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        report_id = row.id
    finally:
        db.close()
    yield report_id
    db = SessionLocal()
    try:
        db.query(Report).filter(Report.id == report_id).delete()
        db.commit()
    finally:
        db.close()


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


@pytest.mark.asyncio
async def test_download_report_returns_json_attachment(sample_report):
    response = await emails_router_mod.api_download_report(sample_report, user=ADMIN)
    assert response.media_type == "application/json"
    assert "attachment" in response.headers["content-disposition"]
    body = json.loads(response.body)
    assert body["report_type"] == "daily"
    assert body["data"]["counts"]["total"] == 3


@pytest.mark.asyncio
async def test_download_report_404_for_missing_id():
    with pytest.raises(HTTPException) as exc_info:
        await emails_router_mod.api_download_report(999999999, user=ADMIN)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_send_report_returns_501_not_configured(sample_report):
    with pytest.raises(HTTPException) as exc_info:
        await emails_router_mod.api_send_report(sample_report, user=ADMIN)
    assert exc_info.value.status_code == 501
    assert "not configured" in exc_info.value.detail.lower() or "coming" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_send_report_404_for_missing_id():
    with pytest.raises(HTTPException) as exc_info:
        await emails_router_mod.api_send_report(999999999, user=ADMIN)
    assert exc_info.value.status_code == 404
