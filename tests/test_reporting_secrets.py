"""test_reporting_secrets.py — confirms reporting.py's env-based SMTP/webhook
fallbacks resolve via secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_smtp_fallback_creds_from_vault():
    import secrets_client
    import reporting
    creds = secrets_client.get_smtp_creds()
    user, password = reporting._smtp_fallback_creds()
    assert user == creds["user"]
    assert password == creds["password"]


def test_slack_webhook_fallback_from_vault():
    import secrets_client
    import reporting
    assert reporting._slack_webhook_fallback() == secrets_client.get_webhook_url("slack")


def test_teams_webhook_fallback_from_vault():
    import secrets_client
    import reporting
    assert reporting._teams_webhook_fallback() == secrets_client.get_webhook_url("teams")
