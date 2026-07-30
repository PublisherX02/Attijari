"""test_detonation_config_secrets.py — confirms detonation_config.py reads
CAPE tokens via secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_cape_tokens_match_vault_values():
    import secrets_client
    import detonation_config

    assert detonation_config.CAPE_API_TOKEN == secrets_client.get_cape_token("api_token")
    assert detonation_config.CAPE_VM_WRAPPER_TOKEN == secrets_client.get_cape_token("vm_wrapper_token")
