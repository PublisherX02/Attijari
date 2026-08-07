"""test_api_core_secrets.py — confirms api_core.py reads JWT_SECRET via
secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_jwt_secret_matches_vault_fallback_chain():
    import secrets_client
    import api_core

    try:
        expected = secrets_client.get_jwt_secret()
    except RuntimeError:
        expected = secrets_client.get_vault_encryption_key()
    assert api_core.JWT_SECRET == expected
