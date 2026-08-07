"""test_migrate_env_to_vault.py — writes into the real local dev-mode Vault
(this project's test convention — no fakes). Uses a root-token client to
write (same as vault_bootstrap.py) since migration is an operator action,
not something the read-only attijari-app AppRole can do.

Snapshots and restores the production paths it touches: database.py,
api_core.py, etc. read these same paths from the same real Vault instance,
so leaving synthetic test values in place would corrupt the live app config
for every test that runs afterward in the same session."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_migrate_writes_all_groups_and_reports_removable_vars():
    import migrate_env_to_vault
    import secrets_client
    from test_secrets_client import _snapshot, _restore

    paths = ["database", "jwt", "vault_encryption_key", "threat_intel", "smtp", "webhooks", "cape"]
    snapshot = _snapshot(paths)
    try:
        env_vars = {
            "DATABASE_URL": "postgresql://u:p@host/db",
            "JWT_SECRET": "jwt-value",
            "VAULT_ENCRYPTION_KEY": "fernet-value",
            "VIRUSTOTAL_API_KEY": "vt-value",
            "THREATFOX_AUTH_KEY": "tf-value",
            "ABUSEIPDB_API_KEY": "ab-value",
            "OTX_API_KEY": "otx-value",
            "DNSTWIST_API_KEY": "{}",
            "SMTP_USER": "smtp-user-value",
            "SMTP_PASSWORD": "smtp-pass-value",
            "SLACK_WEBHOOK_URL": "https://slack/x",
            "TEAMS_WEBHOOK_URL": "https://teams/y",
            "CAPE_API_TOKEN": "cape-value",
            "CAPE_VM_WRAPPER_TOKEN": "wrapper-value",
            "DASHBOARD_HOST": "127.0.0.1",  # non-secret, must NOT be reported as migrated
        }

        removable = migrate_env_to_vault.migrate(
            env_vars, os.environ["VAULT_ADDR"], os.environ["VAULT_TOKEN"]
        )

        secrets_client._cache.clear()
        assert secrets_client.get_database_url() == "postgresql://u:p@host/db"
        assert secrets_client.get_jwt_secret() == "jwt-value"
        assert secrets_client.get_vault_encryption_key() == "fernet-value"
        assert secrets_client.get_api_key("virustotal") == "vt-value"
        assert secrets_client.get_cape_token("api_token") == "cape-value"

        assert "DATABASE_URL" in removable
        assert "CAPE_VM_WRAPPER_TOKEN" in removable
        assert "DASHBOARD_HOST" not in removable
    finally:
        _restore(snapshot)
        secrets_client._cache.clear()
