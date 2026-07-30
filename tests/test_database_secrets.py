"""test_database_secrets.py — confirms database.py reads DATABASE_URL via
secrets_client, not os.getenv, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_database_url_matches_vault_value():
    import secrets_client
    import database

    assert database.DATABASE_URL == secrets_client.get_database_url()
