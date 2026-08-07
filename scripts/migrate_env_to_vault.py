"""migrate_env_to_vault.py — one-time migration of .env secrets into Vault.

Reads the current .env, writes each secret group into its Vault KV path,
and prints which .env lines are now redundant. Never deletes anything from
.env — that is a manual step after the operator verifies the app boots
correctly against Vault.

Writes with a root/write-capable Vault token (VAULT_TOKEN), not the app's
own read-only AppRole session — the same elevated-credential pattern as
vault_bootstrap.py, since migration is an operator action.

Run with VAULT_ADDR and VAULT_TOKEN set (see docs/vault-dev-setup.md):

    python scripts/migrate_env_to_vault.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import hvac
from dotenv import dotenv_values

_GROUPS = {
    "database": {"url": "DATABASE_URL"},
    "jwt": {"secret": "JWT_SECRET"},
    "vault_encryption_key": {"key": "VAULT_ENCRYPTION_KEY"},
    "threat_intel": {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "threatfox": "THREATFOX_AUTH_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "otx": "OTX_API_KEY",
        "dnstwist": "DNSTWIST_API_KEY",
    },
    "smtp": {"user": "SMTP_USER", "password": "SMTP_PASSWORD"},
    "webhooks": {"slack": "SLACK_WEBHOOK_URL", "teams": "TEAMS_WEBHOOK_URL"},
    "cape": {"api_token": "CAPE_API_TOKEN", "vm_wrapper_token": "CAPE_VM_WRAPPER_TOKEN"},
}


def migrate(env_vars: dict, vault_addr: str, root_token: str) -> list[str]:
    client = hvac.Client(url=vault_addr, token=root_token)
    if not client.is_authenticated():
        raise RuntimeError(f"Could not authenticate to Vault at {vault_addr} with the given token.")

    removable = []

    for vault_path, key_mapping in _GROUPS.items():
        secret_body = {}
        for vault_key, env_name in key_mapping.items():
            value = env_vars.get(env_name)
            if value:
                secret_body[vault_key] = value
                removable.append(env_name)
        if secret_body:
            client.secrets.kv.v2.create_or_update_secret(
                path=f"attijari/{vault_path}", secret=secret_body
            )

    return removable


if __name__ == "__main__":
    vault_addr = os.environ.get("VAULT_ADDR")
    root_token = os.environ.get("VAULT_TOKEN")
    if not vault_addr or not root_token:
        print("Set VAULT_ADDR and VAULT_TOKEN before running this script.", file=sys.stderr)
        sys.exit(1)

    project_root = Path(__file__).parent.parent
    env_vars = dotenv_values(project_root / ".env")
    removable = migrate(env_vars, vault_addr, root_token)
    print("Migrated the following groups into Vault: database, jwt, vault_encryption_key,")
    print("threat_intel, smtp, webhooks, cape (only groups with at least one non-empty value).")
    print()
    print("These .env lines are now redundant and safe to delete manually, once you've")
    print("confirmed the app boots correctly against Vault:")
    for name in removable:
        print(f"  {name}")
