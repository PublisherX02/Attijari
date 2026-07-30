"""test_vault.py — src/vault.py's Fernet key now comes from HashiCorp Vault
via secrets_client, not directly from an environment variable. Runs against
the real local dev-mode Vault (this project's test convention — no fakes)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_get_fernet_uses_secrets_client_vault_encryption_key():
    import secrets_client
    import vault

    fernet = vault._get_fernet()
    token = fernet.encrypt(b"hello")
    assert fernet.decrypt(token) == b"hello"

    # Confirm it's built from the same key secrets_client resolves, not a
    # stale os.getenv read.
    from cryptography.fernet import Fernet
    expected_fernet = Fernet(secrets_client.get_vault_encryption_key().encode())
    assert expected_fernet.decrypt(token) == b"hello"


def test_encrypt_and_decrypt_field_round_trip():
    import vault
    token = vault.encrypt_field("a-totp-seed")
    assert token is not None
    assert vault.decrypt_field(token) == "a-totp-seed"
