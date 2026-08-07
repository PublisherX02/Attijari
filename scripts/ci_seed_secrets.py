"""ci_seed_secrets.py — CI-only helper that seeds the ephemeral Vault dev
service container (secops.yml's test/api-fuzz jobs) with throwaway secrets,
via migrate_env_to_vault.migrate(). Never used outside CI.

Reads its input from CI_* env vars (set in the workflow's step env: block)
rather than a heredoc, since an embedded Python heredoc inside a YAML
block scalar inherits that block's indentation on every line, which is a
Python IndentationError at the top level.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import migrate_env_to_vault  # noqa: E402


def main() -> None:
    vault_addr = os.environ["VAULT_ADDR"]
    vault_token = os.environ["VAULT_TOKEN"]
    env_vars = {
        "DATABASE_URL": os.environ.get("CI_DATABASE_URL", ""),
        "JWT_SECRET": os.environ.get("CI_JWT_SECRET", ""),
        "VAULT_ENCRYPTION_KEY": os.environ.get("CI_VAULT_ENCRYPTION_KEY", ""),
        "VIRUSTOTAL_API_KEY": os.environ.get("CI_VIRUSTOTAL_API_KEY", ""),
        "THREATFOX_AUTH_KEY": os.environ.get("CI_THREATFOX_AUTH_KEY", ""),
    }
    migrate_env_to_vault.migrate(env_vars, vault_addr, vault_token)


if __name__ == "__main__":
    main()
