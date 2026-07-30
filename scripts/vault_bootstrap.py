"""vault_bootstrap.py — one-time (idempotent) Vault setup for this project.

Mounts the KV v2 secrets engine at secret/, creates the attijari-app AppRole
with a read-only policy scoped to secret/data/attijari/*, and generates a
role_id/secret_id pair for the app to authenticate with.

Run with VAULT_ADDR and VAULT_TOKEN (a token with admin rights, e.g. the
dev-mode root token) set in the environment:

    python scripts/vault_bootstrap.py
"""
from __future__ import annotations

import os
import sys

import hvac

POLICY_NAME = "attijari-app-policy"
ROLE_NAME = "attijari-app"

POLICY_HCL = """
path "secret/data/attijari/*" {
  capabilities = ["read"]
}
"""


def bootstrap(vault_addr: str, root_token: str) -> dict:
    client = hvac.Client(url=vault_addr, token=root_token)
    if not client.is_authenticated():
        raise RuntimeError(f"Could not authenticate to Vault at {vault_addr} with the given token.")

    # KV v2 mount (idempotent: skip if already mounted at secret/)
    mounts = client.sys.list_mounted_secrets_engines()
    if "secret/" not in mounts:
        client.sys.enable_secrets_engine(backend_type="kv", path="secret", options={"version": "2"})

    # Read-only policy (idempotent: overwriting with the same HCL is safe)
    client.sys.create_or_update_policy(name=POLICY_NAME, policy=POLICY_HCL)

    # AppRole auth method (idempotent: skip if already enabled)
    auth_methods = client.sys.list_auth_methods()
    if "approle/" not in auth_methods:
        client.sys.enable_auth_method("approle")

    # AppRole role bound to the read-only policy
    client.auth.approle.create_or_update_approle(
        role_name=ROLE_NAME,
        token_policies=[POLICY_NAME],
        token_ttl="15m",
        token_max_ttl="1h",
    )

    role_id = client.auth.approle.read_role_id(ROLE_NAME)["data"]["role_id"]
    secret_id_response = client.auth.approle.generate_secret_id(ROLE_NAME)
    secret_id = secret_id_response["data"]["secret_id"]

    return {"role_id": role_id, "secret_id": secret_id}


if __name__ == "__main__":
    vault_addr = os.environ.get("VAULT_ADDR")
    root_token = os.environ.get("VAULT_TOKEN")
    if not vault_addr or not root_token:
        print("Set VAULT_ADDR and VAULT_TOKEN before running this script.", file=sys.stderr)
        sys.exit(1)

    creds = bootstrap(vault_addr, root_token)
    print(f"VAULT_ROLE_ID={creds['role_id']}")
    print(f"VAULT_SECRET_ID={creds['secret_id']}")
    print("Copy the two lines above into your .env (or the bank VM's secret provisioning step).")
