"""test_vault_bootstrap.py — bootstrap runs against a real local dev-mode
Vault (this project's test convention — no fakes, see test_redis_client.py).
Requires VAULT_ADDR/VAULT_TOKEN pointed at a running dev-mode server."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))


def test_bootstrap_is_idempotent():
    import vault_bootstrap

    vault_addr = os.environ["VAULT_ADDR"]
    root_token = os.environ["VAULT_TOKEN"]

    first = vault_bootstrap.bootstrap(vault_addr, root_token)
    second = vault_bootstrap.bootstrap(vault_addr, root_token)

    # role_id is stable across re-runs; secret_id is freshly generated each
    # time (by design — generate_secret_id always mints a new one), so only
    # role_id is asserted equal.
    assert first["role_id"] == second["role_id"]
    assert first["secret_id"] != ""
    assert second["secret_id"] != ""
