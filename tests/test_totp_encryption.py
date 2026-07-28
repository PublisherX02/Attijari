"""SEC-H2: TOTP secrets are encrypted at rest.

A DB dump must never reveal a usable MFA seed. These test the vault field
helpers and the end-to-end property that an encrypted-then-decrypted seed
still verifies a real TOTP code, and that legacy plaintext rows keep working.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Ensure a vault key exists even if .env isn't loaded in the test env.
if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pyotp
import vault


def test_encrypt_decrypt_roundtrip():
    seed = pyotp.random_base32()
    token = vault.encrypt_field(seed)
    assert token != seed                       # not stored in the clear
    assert not token.startswith(seed[:8])      # ciphertext, not the seed
    assert vault.decrypt_field(token) == seed  # recoverable


def test_decrypt_passes_through_legacy_plaintext():
    # Pre-SEC-H2 rows hold a raw base32 seed; decrypt_field must return it
    # unchanged so login keeps working before the migration runs.
    legacy = pyotp.random_base32()
    assert vault.decrypt_field(legacy) == legacy


def test_is_encrypted_field_distinguishes():
    seed = pyotp.random_base32()
    assert vault.is_encrypted_field(seed) is False
    assert vault.is_encrypted_field(vault.encrypt_field(seed)) is True
    assert vault.is_encrypted_field(None) is False


def test_none_is_handled():
    assert vault.encrypt_field(None) is None
    assert vault.decrypt_field(None) is None


def test_encrypted_seed_still_verifies_a_live_totp_code():
    # The property that matters at login: store encrypted, decrypt, verify.
    seed = pyotp.random_base32()
    stored = vault.encrypt_field(seed)             # what lands in the DB
    code = pyotp.TOTP(seed).now()                  # what the user's app shows
    recovered = vault.decrypt_field(stored)        # what login reads back
    assert pyotp.TOTP(recovered).verify(code, valid_window=1)


def test_encrypted_token_fits_column_width():
    # totp_secret column is VARCHAR(255); the encrypted seed must fit.
    for _ in range(20):
        token = vault.encrypt_field(pyotp.random_base32())
        assert len(token) <= 255


def test_ciphertext_is_unique_per_call():
    # Fernet embeds an IV+timestamp, so the same seed encrypts differently
    # each time — no static fingerprint of a shared seed across users.
    seed = pyotp.random_base32()
    assert vault.encrypt_field(seed) != vault.encrypt_field(seed)
