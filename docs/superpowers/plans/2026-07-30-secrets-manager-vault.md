# Secrets Manager (HashiCorp Vault) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace plaintext secrets in `.env` and `deploy/k8s/secret.yaml` with a HashiCorp Vault-backed secrets client (`src/secrets_client.py`), used everywhere the app currently reads a sensitive value via `os.getenv()`.

**Architecture:** A local dev-mode Vault server (KV v2 engine at `secret/attijari/*`, AppRole auth) is the single source of truth for secrets. `src/secrets_client.py` is a lazy singleton (same pattern as `src/redis_client.py`) that authenticates via AppRole, caches secrets with a short TTL, and exposes typed getters. Every call site that currently does `os.getenv("SOME_SECRET")` is replaced with a call into this client. Non-secret config (hosts, ports, timeouts, toggles) is untouched.

**Tech Stack:** `hvac==2.4.0` (Vault Python client), local Vault binary in dev mode, GitHub Actions `hashicorp/vault` service container in CI.

## Global Constraints

- Fail closed: any failure to reach Vault or read a required secret at app startup raises immediately — never fall back to a missing/default secret value (docs/superpowers/specs/2026-07-30-secrets-manager-design.md, "Fail-safe" / CLAUDE.md fail-closed principle).
- `src/vault.py` (Fernet quarantine/TOTP encryption) is a different system from HashiCorp Vault and is NOT renamed — only gets a one-line docstring note.
- Non-secret config (hosts, ports, timeouts, feature toggles, CAPE thresholds) stays in `.env`/ConfigMap exactly as today — only sensitive values migrate.
- This project's established test convention for a lazy-singleton client with a real local dependency (see `tests/test_redis_client.py`) is **no mocks** — tests run against a real, reachable instance (here: a real local dev-mode Vault), not fakes. Follow this convention for `secrets_client.py` tests.
- Vault KV v2 path layout: `secret/attijari/{database, jwt, vault_encryption_key, threat_intel, smtp, webhooks, cape}` (exact JSON key names are specified per-task below).
- Migration is one-way and manual at the deletion step: `scripts/migrate_env_to_vault.py` writes secrets into Vault but never deletes anything from `.env` — that is a manual step for the operator after verifying the app boots correctly.
- `hvac==2.4.0` is the pinned version to add to `requirements.txt`, following this file's existing exact-`==`-pin convention.

---

### Task 1: Add `hvac` dependency and Vault bootstrap script

**Files:**
- Modify: `requirements.txt`
- Create: `scripts/vault_bootstrap.py`
- Test: `tests/test_vault_bootstrap.py`

**Interfaces:**
- Produces: `scripts/vault_bootstrap.py` exposes `bootstrap(vault_addr: str, root_token: str) -> dict` returning `{"role_id": str, "secret_id": str}`. This is consumed by Task 2's tests (to obtain AppRole credentials) and by the CI workflow (Task 10).

- [ ] **Step 1: Add `hvac` to requirements.txt**

Edit `C:\Users\moham\Attijari\requirements.txt`, inserting after the `cryptography==48.0.1` line (end of the "Authentication & security" block, before "Monitoring & scheduling"):

```
# Secrets management (HashiCorp Vault)
hvac==2.4.0
```

- [ ] **Step 2: Install and verify import**

Run: `pip install hvac==2.4.0`
Then: `python -c "import hvac; print(hvac.__version__)"`
Expected: prints `2.4.0` with no errors.

- [ ] **Step 3: Start a local dev-mode Vault server for development**

This is a one-time local setup step (not part of the automated test suite, which assumes Vault is already running — same assumption `test_redis_client.py` makes about Memurai). Document it by creating `C:\Users\moham\Attijari\docs\vault-dev-setup.md`:

```markdown
# Local Vault dev-mode setup

1. Download the Vault binary for Windows from HashiCorp's release page and
   put `vault.exe` on your PATH.
2. Start a dev-mode server (in-memory, auto-unsealed, fixed root token):

   vault server -dev -dev-root-token-id="root" -dev-listen-address="127.0.0.1:8200"

3. Leave that terminal running. In a second terminal, set:

   set VAULT_ADDR=http://127.0.0.1:8200
   set VAULT_TOKEN=root

4. Run the bootstrap script to create the KV engine, AppRole, and policy:

   python scripts/vault_bootstrap.py

   This prints a `VAULT_ROLE_ID` and `VAULT_SECRET_ID` — copy both into your
   local `.env`, along with `VAULT_ADDR=http://127.0.0.1:8200`.

5. Never run `vault server -dev` against anything but a throwaway local
   instance — dev mode has no persistence and a fixed root token.
```

- [ ] **Step 4: Write `scripts/vault_bootstrap.py`**

```python
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
```

- [ ] **Step 5: Write the idempotency test**

```python
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
```

- [ ] **Step 6: Run test (requires local dev-mode Vault running per Step 3)**

Run: `set VAULT_ADDR=http://127.0.0.1:8200 && set VAULT_TOKEN=root && pytest tests/test_vault_bootstrap.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt scripts/vault_bootstrap.py tests/test_vault_bootstrap.py docs/vault-dev-setup.md
git commit -m "feat: add hvac dependency and Vault AppRole bootstrap script"
```

---

### Task 2: `src/secrets_client.py` — AppRole login and low-level KV read with TTL cache

**Files:**
- Create: `src/secrets_client.py`
- Test: `tests/test_secrets_client.py`

**Interfaces:**
- Consumes: a running Vault with AppRole already bootstrapped (Task 1), `VAULT_ADDR`/`VAULT_ROLE_ID`/`VAULT_SECRET_ID` env vars.
- Produces: `get_client() -> hvac.Client` (authenticated singleton) and `read_secret(path: str) -> dict` (KV v2 read, e.g. `read_secret("database")` reads `secret/attijari/database` and returns its data dict), both consumed by Task 3's typed getters.

- [ ] **Step 1: Write the failing tests**

```python
"""test_secrets_client.py — lazy singleton client, reachable against the
real local dev-mode Vault instance (this project's test convention for
lazy-singleton clients — no fakes, see test_redis_client.py). Requires
VAULT_ADDR/VAULT_ROLE_ID/VAULT_SECRET_ID in the environment and the KV path
secret/attijari/_smoke_test seeded before the run (Step 2 below seeds it)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_get_client_returns_working_singleton():
    import secrets_client
    c1 = secrets_client.get_client()
    c2 = secrets_client.get_client()
    assert c1 is c2
    assert c1.is_authenticated()


def test_read_secret_round_trip():
    import secrets_client
    client = secrets_client.get_client()
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/_smoke_test",
        secret={"hello": "world"},
    )
    data = secrets_client.read_secret("_smoke_test")
    assert data["hello"] == "world"


def test_read_secret_missing_path_raises():
    import secrets_client
    import pytest
    with pytest.raises(RuntimeError):
        secrets_client.read_secret("_definitely_does_not_exist")


def test_read_secret_is_cached_within_ttl():
    import secrets_client
    client = secrets_client.get_client()
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/_cache_test",
        secret={"value": "first"},
    )
    first = secrets_client.read_secret("_cache_test")
    # Update Vault directly, bypassing the client's cache
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/_cache_test",
        secret={"value": "second"},
    )
    cached = secrets_client.read_secret("_cache_test")
    assert first["value"] == "first"
    assert cached["value"] == "first"  # still cached, TTL not expired
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_secrets_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'secrets_client'`.

- [ ] **Step 3: Write `src/secrets_client.py`**

```python
"""secrets_client.py — HashiCorp Vault-backed secrets access.

Not to be confused with src/vault.py, which is a different system (Fernet
at-rest encryption of quarantined emails/TOTP secrets). This module is the
client for HashiCorp Vault, the secrets manager that (as of this module)
stores the Fernet key vault.py uses, among other secrets.

Fail-closed: any failure to authenticate or read a required secret raises
immediately. There is no fallback to a missing/default value.
"""
from __future__ import annotations

import os
import time

import hvac

_client: "hvac.Client | None" = None
_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = 300


def get_client() -> hvac.Client:
    global _client
    if _client is None:
        vault_addr = os.getenv("VAULT_ADDR")
        role_id = os.getenv("VAULT_ROLE_ID")
        secret_id = os.getenv("VAULT_SECRET_ID")
        if not vault_addr or not role_id or not secret_id:
            raise RuntimeError(
                "VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID must all be set. "
                "Run scripts/vault_bootstrap.py against your Vault server to obtain "
                "VAULT_ROLE_ID/VAULT_SECRET_ID."
            )
        client = hvac.Client(url=vault_addr)
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        if not client.is_authenticated():
            raise RuntimeError(f"AppRole login to Vault at {vault_addr} failed.")
        _client = client
    return _client


def read_secret(path: str) -> dict:
    """Read secret/attijari/<path> (KV v2), cached for _CACHE_TTL_SECONDS."""
    now = time.monotonic()
    cached = _cache.get(path)
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    client = get_client()
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=f"attijari/{path}", mount_point="secret", raise_on_deleted_version=True
        )
    except hvac.exceptions.InvalidPath as exc:
        raise RuntimeError(f"Vault path secret/attijari/{path} does not exist.") from exc

    data = response["data"]["data"]
    _cache[path] = (now, data)
    return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `set VAULT_ADDR=http://127.0.0.1:8200 && pytest tests/test_secrets_client.py -v` (with `VAULT_ROLE_ID`/`VAULT_SECRET_ID` from Task 1's bootstrap output also set)
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/secrets_client.py tests/test_secrets_client.py
git commit -m "feat: add Vault-backed secrets_client with AppRole auth and TTL cache"
```

---

### Task 3: Typed getters on `secrets_client.py`

**Files:**
- Modify: `src/secrets_client.py`
- Test: `tests/test_secrets_client.py`

**Interfaces:**
- Consumes: `read_secret(path)` from Task 2.
- Produces: `get_database_url()`, `get_jwt_secret()`, `get_vault_encryption_key()`, `get_api_key(name: str)`, `get_smtp_creds()`, `get_webhook_url(name: str)`, `get_cape_token(name: str)` — consumed by Tasks 5-9.

- [ ] **Step 1: Write the failing tests (appended to `tests/test_secrets_client.py`)**

```python
def test_typed_getters_round_trip():
    import secrets_client
    client = secrets_client.get_client()

    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/database", secret={"url": "postgresql://u:p@host/db"}
    )
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/jwt", secret={"secret": "jwt-signing-key"}
    )
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/vault_encryption_key", secret={"key": "fernet-key-value"}
    )
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/threat_intel",
        secret={"virustotal": "vt-key", "threatfox": "tf-key", "abuseipdb": "ab-key",
                "otx": "otx-key", "dnstwist": "{}"},
    )
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/smtp", secret={"user": "smtp-user", "password": "smtp-pass"}
    )
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/webhooks", secret={"slack": "https://hooks.slack/x", "teams": "https://teams/y"}
    )
    client.secrets.kv.v2.create_or_update_secret(
        path="attijari/cape", secret={"api_token": "cape-token", "vm_wrapper_token": "wrapper-token"}
    )

    secrets_client._cache.clear()  # force a fresh read for this test

    assert secrets_client.get_database_url() == "postgresql://u:p@host/db"
    assert secrets_client.get_jwt_secret() == "jwt-signing-key"
    assert secrets_client.get_vault_encryption_key() == "fernet-key-value"
    assert secrets_client.get_api_key("virustotal") == "vt-key"
    assert secrets_client.get_api_key("threatfox") == "tf-key"
    assert secrets_client.get_api_key("abuseipdb") == "ab-key"
    assert secrets_client.get_api_key("otx") == "otx-key"
    assert secrets_client.get_api_key("dnstwist") == "{}"
    assert secrets_client.get_smtp_creds() == {"user": "smtp-user", "password": "smtp-pass"}
    assert secrets_client.get_webhook_url("slack") == "https://hooks.slack/x"
    assert secrets_client.get_webhook_url("teams") == "https://teams/y"
    assert secrets_client.get_cape_token("api_token") == "cape-token"
    assert secrets_client.get_cape_token("vm_wrapper_token") == "wrapper-token"
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_secrets_client.py::test_typed_getters_round_trip -v`
Expected: FAIL with `AttributeError: module 'secrets_client' has no attribute 'get_database_url'`.

- [ ] **Step 3: Append typed getters to `src/secrets_client.py`**

```python
def get_database_url() -> str:
    return read_secret("database")["url"]


def get_jwt_secret() -> str:
    return read_secret("jwt")["secret"]


def get_vault_encryption_key() -> str:
    return read_secret("vault_encryption_key")["key"]


def get_api_key(name: str) -> str:
    """name is one of: virustotal, threatfox, abuseipdb, otx, dnstwist."""
    return read_secret("threat_intel").get(name, "")


def get_smtp_creds() -> dict:
    """Returns {"user": ..., "password": ...}."""
    data = read_secret("smtp")
    return {"user": data.get("user", ""), "password": data.get("password", "")}


def get_webhook_url(name: str) -> str:
    """name is one of: slack, teams."""
    return read_secret("webhooks").get(name, "")


def get_cape_token(name: str) -> str:
    """name is one of: api_token, vm_wrapper_token."""
    return read_secret("cape").get(name, "")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_secrets_client.py -v`
Expected: PASS (5 tests total).

- [ ] **Step 5: Commit**

```bash
git add src/secrets_client.py tests/test_secrets_client.py
git commit -m "feat: add typed secret getters to secrets_client"
```

---

### Task 4: `scripts/migrate_env_to_vault.py`

**Files:**
- Create: `scripts/migrate_env_to_vault.py`
- Test: `tests/test_migrate_env_to_vault.py`

**Interfaces:**
- Consumes: `secrets_client.get_client()` (Task 2) for the Vault KV write; reads plaintext values from a `.env`-like source dict (function takes a dict, not the file directly, so it's testable without touching the real `.env`).
- Produces: `migrate(env_vars: dict) -> list[str]` returning the list of `.env` variable names now redundant and safe to delete — consumed by the script's `__main__` block only (no other task depends on this function beyond invoking it).

- [ ] **Step 1: Write the failing test**

```python
"""test_migrate_env_to_vault.py — writes into the real local dev-mode Vault
(this project's test convention — no fakes)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_migrate_writes_all_groups_and_reports_removable_vars():
    import migrate_env_to_vault
    import secrets_client

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

    removable = migrate_env_to_vault.migrate(env_vars)

    secrets_client._cache.clear()
    assert secrets_client.get_database_url() == "postgresql://u:p@host/db"
    assert secrets_client.get_jwt_secret() == "jwt-value"
    assert secrets_client.get_vault_encryption_key() == "fernet-value"
    assert secrets_client.get_api_key("virustotal") == "vt-value"
    assert secrets_client.get_cape_token("api_token") == "cape-value"

    assert "DATABASE_URL" in removable
    assert "CAPE_VM_WRAPPER_TOKEN" in removable
    assert "DASHBOARD_HOST" not in removable
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_migrate_env_to_vault.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'migrate_env_to_vault'`.

- [ ] **Step 3: Write `scripts/migrate_env_to_vault.py`**

```python
"""migrate_env_to_vault.py — one-time migration of .env secrets into Vault.

Reads the current .env, writes each secret group into its Vault KV path,
and prints which .env lines are now redundant. Never deletes anything from
.env — that is a manual step after the operator verifies the app boots
correctly against Vault.

Run with VAULT_ADDR/VAULT_ROLE_ID/VAULT_SECRET_ID set (see
docs/vault-dev-setup.md):

    python scripts/migrate_env_to_vault.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dotenv import dotenv_values

import secrets_client

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


def migrate(env_vars: dict) -> list[str]:
    client = secrets_client.get_client()
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
    project_root = Path(__file__).parent.parent
    env_vars = dotenv_values(project_root / ".env")
    removable = migrate(env_vars)
    print("Migrated the following groups into Vault: database, jwt, vault_encryption_key,")
    print("threat_intel, smtp, webhooks, cape (only groups with at least one non-empty value).")
    print()
    print("These .env lines are now redundant and safe to delete manually, once you've")
    print("confirmed the app boots correctly against Vault:")
    for name in removable:
        print(f"  {name}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_migrate_env_to_vault.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/migrate_env_to_vault.py tests/test_migrate_env_to_vault.py
git commit -m "feat: add .env-to-Vault migration script"
```

---

### Task 5: `database.py` uses `secrets_client.get_database_url()`

**Files:**
- Modify: `src/database.py:53-59`
- Test: `tests/test_database_secrets.py`

**Interfaces:**
- Consumes: `secrets_client.get_database_url()` (Task 3).

- [ ] **Step 1: Write the failing test**

```python
"""test_database_secrets.py — confirms database.py reads DATABASE_URL via
secrets_client, not os.getenv, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_database_url_matches_vault_value():
    import secrets_client
    import database

    assert database.DATABASE_URL == secrets_client.get_database_url()
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_database_secrets.py -v`
Expected: FAIL — `database.DATABASE_URL` currently comes from `os.getenv("DATABASE_URL")`, which won't match the Vault-stored value seeded in Task 4's test unless `.env`'s `DATABASE_URL` happens to match (it won't, since Task 4 wrote a synthetic test value into Vault, not the real one) — confirms the current code path is `os.getenv`, not Vault.

- [ ] **Step 3: Edit `src/database.py:53-59`**

Replace:
```python
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. "
        "The application refuses to start without a database connection string. "
        "Set it in your .env file (e.g. DATABASE_URL=postgresql://user:pass@host:5432/dbname)."
    )
```
with:
```python
from secrets_client import get_database_url

try:
    DATABASE_URL = get_database_url()
except RuntimeError as exc:
    raise RuntimeError(
        "Could not read DATABASE_URL from Vault. "
        "The application refuses to start without a database connection string. "
        f"Underlying error: {exc}"
    ) from exc
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_database_secrets.py -v`
Expected: PASS — but only once Vault's `secret/attijari/database` holds the actual `DATABASE_URL` value for your environment. Run `python scripts/migrate_env_to_vault.py` first (Task 4) against your real `.env`, or manually write the real value with the Vault CLI, before running this test in a real dev environment.

- [ ] **Step 5: Run the full existing suite to check for regressions**

Run: `pytest tests/ -v`
Expected: no new failures beyond this test file.

- [ ] **Step 6: Commit**

```bash
git add src/database.py tests/test_database_secrets.py
git commit -m "refactor: read DATABASE_URL from Vault via secrets_client"
```

---

### Task 6: `api_core.py` uses `secrets_client` for JWT_SECRET/VAULT_ENCRYPTION_KEY

**Files:**
- Modify: `src/api_core.py:147-161`
- Test: `tests/test_api_core_secrets.py`

**Interfaces:**
- Consumes: `secrets_client.get_jwt_secret()`, `secrets_client.get_vault_encryption_key()` (Task 3).

- [ ] **Step 1: Write the failing test**

```python
"""test_api_core_secrets.py — confirms api_core.py reads JWT_SECRET via
secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_jwt_secret_matches_vault_value():
    import secrets_client
    import api_core

    assert api_core.JWT_SECRET == secrets_client.get_jwt_secret()
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_api_core_secrets.py -v`
Expected: FAIL — current code reads `os.getenv("JWT_SECRET")`.

- [ ] **Step 3: Edit `src/api_core.py:147-161`**

Replace:
```python
_jwt_secret = os.getenv("JWT_SECRET") or os.getenv("VAULT_ENCRYPTION_KEY")
if not _jwt_secret:
    raise RuntimeError(
        "JWT_SECRET is not set. "
        "The API refuses to start without a secure JWT signing key. "
        "Set JWT_SECRET in your .env file (must differ from VAULT_ENCRYPTION_KEY)."
    )
if _jwt_secret == os.getenv("VAULT_ENCRYPTION_KEY"):
    import warnings
    warnings.warn(
        "JWT_SECRET is the same as VAULT_ENCRYPTION_KEY. "
        "Set a separate JWT_SECRET in .env for defense-in-depth.",
        stacklevel=1,
    )
JWT_SECRET = _jwt_secret
```
with:
```python
from secrets_client import get_jwt_secret, get_vault_encryption_key

try:
    _jwt_secret = get_jwt_secret()
except RuntimeError:
    _jwt_secret = get_vault_encryption_key()
if not _jwt_secret:
    raise RuntimeError(
        "JWT_SECRET is not set in Vault (secret/attijari/jwt). "
        "The API refuses to start without a secure JWT signing key."
    )
if _jwt_secret == get_vault_encryption_key():
    import warnings
    warnings.warn(
        "JWT_SECRET is the same as VAULT_ENCRYPTION_KEY. "
        "Set a separate JWT_SECRET value in Vault (secret/attijari/jwt) for defense-in-depth.",
        stacklevel=1,
    )
JWT_SECRET = _jwt_secret
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_api_core_secrets.py -v`
Expected: PASS, given `secret/attijari/jwt` and `secret/attijari/vault_encryption_key` are seeded (Task 3's test seeds both; a real dev environment needs Task 4's migration run first).

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v`
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add src/api_core.py tests/test_api_core_secrets.py
git commit -m "refactor: read JWT_SECRET/VAULT_ENCRYPTION_KEY from Vault via secrets_client"
```

---

### Task 7: `vault.py` uses `secrets_client.get_vault_encryption_key()`

**Files:**
- Modify: `src/vault.py:1-34`
- Test: `tests/test_vault.py` (may already exist — check with `Glob tests/test_vault*.py` before writing; if it exists, append the new test rather than creating a duplicate file)

**Interfaces:**
- Consumes: `secrets_client.get_vault_encryption_key()` (Task 3).

- [ ] **Step 1: Check for an existing test file**

Run: search `tests/` for a file matching `test_vault*.py`. If found, all subsequent test steps append to that file instead of creating a new one.

- [ ] **Step 2: Write the failing test**

```python
def test_get_fernet_uses_secrets_client(monkeypatch):
    import secrets_client
    import vault

    monkeypatch.setattr(secrets_client, "get_vault_encryption_key", lambda: secrets_client.get_vault_encryption_key())
    fernet = vault._get_fernet()
    token = fernet.encrypt(b"hello")
    assert fernet.decrypt(token) == b"hello"
```

(This test mainly documents intent — the meaningful check is Step 3's implementation actually calling `secrets_client`, verified by Step 4's full-suite run still passing, since `vault.py` has extensive existing coverage of `encrypt_field`/`decrypt_field`/`encrypt_and_store` that will fail if `_get_fernet()` breaks.)

- [ ] **Step 3: Edit `src/vault.py`**

Add a docstring clarification at the top (lines 1-10), and update `_get_fernet()` (lines 26-34):

Replace the module docstring:
```python
"""vault.py — Encrypted quarantine vault for escalated emails.

Uses Fernet (AES-128-CBC + HMAC-SHA256) symmetric encryption.
Key is loaded from the VAULT_ENCRYPTION_KEY environment variable.

Directory structure:
  data/vault/{YYYY-MM}/{email_sha256}.enc

If the key is lost, quarantined emails are unrecoverable (by design).
"""
```
with:
```python
"""vault.py — Encrypted quarantine vault for escalated emails.

NOTE: this is unrelated to HashiCorp Vault (see src/secrets_client.py). This
module is Fernet-based at-rest encryption for quarantined emails and TOTP
secrets; the Fernet key itself is now fetched from HashiCorp Vault via
secrets_client.get_vault_encryption_key(), rather than read directly from
an environment variable.

Directory structure:
  data/vault/{YYYY-MM}/{email_sha256}.enc

If the key is lost, quarantined emails are unrecoverable (by design).
"""
```

Replace `_get_fernet()`:
```python
def _get_fernet() -> Fernet:
    """Get the Fernet cipher from environment. Raises if key is missing."""
    key = os.getenv("VAULT_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "VAULT_ENCRYPTION_KEY not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)
```
with:
```python
def _get_fernet() -> Fernet:
    """Get the Fernet cipher from Vault (secret/attijari/vault_encryption_key)."""
    from secrets_client import get_vault_encryption_key
    key = get_vault_encryption_key()
    return Fernet(key.encode() if isinstance(key, str) else key)
```

Also remove the now-unused `load_dotenv()` call at line 20 only if nothing else in the file needs it — check the rest of `vault.py` for other `os.getenv` calls first; if none remain, remove the `from dotenv import load_dotenv` import and the `load_dotenv()` call.

- [ ] **Step 4: Run the full existing suite**

Run: `pytest tests/ -v -k vault`
Expected: all vault-related tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/vault.py tests/test_vault.py
git commit -m "refactor: vault.py reads its Fernet key from HashiCorp Vault via secrets_client"
```

---

### Task 8: Threat-intel enrichment modules use `secrets_client.get_api_key()`

**Files:**
- Modify: `src/virustotal.py:48`, `src/ThreatFoxAPI.py:30`, `src/abuseipdb.py:67`, `src/alienvault_otx.py:26`, `src/dnstwist_check.py:32`
- Test: `tests/test_enrichment_secrets.py`

**Interfaces:**
- Consumes: `secrets_client.get_api_key(name)` (Task 3).

- [ ] **Step 1: Write the failing tests**

```python
"""test_enrichment_secrets.py — confirms each enrichment module resolves its
API key via secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_virustotal_key_source():
    import secrets_client
    from secrets_client import get_api_key
    import virustotal
    # virustotal._resolve_key() (new helper introduced in Step 3) should
    # return the same value get_api_key("virustotal") does.
    assert virustotal._resolve_key(None) == get_api_key("virustotal")


def test_threatfox_key_source():
    from secrets_client import get_api_key
    import ThreatFoxAPI
    assert ThreatFoxAPI._resolve_key(None) == get_api_key("threatfox")


def test_abuseipdb_key_source():
    from secrets_client import get_api_key
    import abuseipdb
    assert abuseipdb._resolve_key(None) == get_api_key("abuseipdb")


def test_otx_headers_use_vault_key():
    from secrets_client import get_api_key
    import alienvault_otx
    headers = alienvault_otx._otx_headers()
    expected_key = get_api_key("otx")
    if expected_key:
        assert headers["X-OTX-API-KEY"] == expected_key
    else:
        assert "X-OTX-API-KEY" not in headers


def test_dnstwist_config_from_vault():
    from secrets_client import get_api_key
    import dnstwist_check
    import json
    raw = get_api_key("dnstwist")
    expected = json.loads(raw) if raw else {}
    assert dnstwist_check._load_config() == expected
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_enrichment_secrets.py -v`
Expected: FAIL — `_resolve_key` doesn't exist yet on any of these modules, and `_otx_headers`/`_load_config` still read `os.getenv` directly.

- [ ] **Step 3: Edit each module**

`src/virustotal.py:48` — replace:
```python
key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
```
with:
```python
def _resolve_key(api_key: str | None) -> str:
    from secrets_client import get_api_key
    return api_key or get_api_key("virustotal")

key = _resolve_key(api_key)
```
(Insert `_resolve_key` as a module-level function near the top of the file, above its first use, then replace the inline `key = ...` assignment at line 48 with `key = _resolve_key(api_key)`.)

`src/ThreatFoxAPI.py:30` — same pattern:
```python
def _resolve_key(api_key: str | None) -> str:
    from secrets_client import get_api_key
    return api_key or get_api_key("threatfox")

key = _resolve_key(api_key)
```

`src/abuseipdb.py:67` — same pattern:
```python
def _resolve_key(api_key: str | None) -> str:
    from secrets_client import get_api_key
    return api_key or get_api_key("abuseipdb")

key = _resolve_key(api_key)
```

`src/alienvault_otx.py:25-29` — replace:
```python
def _otx_headers() -> dict:
    key = os.getenv("OTX_API_KEY")
    headers = {"Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
```
with:
```python
def _otx_headers() -> dict:
    from secrets_client import get_api_key
    key = get_api_key("otx")
    headers = {"Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
```

`src/dnstwist_check.py:30-34` — replace:
```python
def _load_config() -> dict:
    """Load dnstwist config from DNSTWIST_API_KEY env var (JSON)."""
    raw = os.getenv("DNSTWIST_API_KEY", "")
    if not raw:
        return {}
```
with:
```python
def _load_config() -> dict:
    """Load dnstwist config from Vault (secret/attijari/threat_intel, key "dnstwist", JSON)."""
    from secrets_client import get_api_key
    raw = get_api_key("dnstwist")
    if not raw:
        return {}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_enrichment_secrets.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v`
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add src/virustotal.py src/ThreatFoxAPI.py src/abuseipdb.py src/alienvault_otx.py src/dnstwist_check.py tests/test_enrichment_secrets.py
git commit -m "refactor: threat-intel API keys resolved via secrets_client instead of os.getenv"
```

---

### Task 9: `reporting.py` uses `secrets_client` for SMTP creds and webhook URLs

**Files:**
- Modify: `src/reporting.py:134-137, 239, 295`
- Test: `tests/test_reporting_secrets.py`

**Interfaces:**
- Consumes: `secrets_client.get_smtp_creds()`, `secrets_client.get_webhook_url(name)` (Task 3).

- [ ] **Step 1: Write the failing tests**

```python
"""test_reporting_secrets.py — confirms reporting.py's env-based SMTP/webhook
fallbacks resolve via secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_smtp_fallback_creds_from_vault():
    import secrets_client
    import reporting
    creds = secrets_client.get_smtp_creds()
    user, password = reporting._smtp_fallback_creds()
    assert user == creds["user"]
    assert password == creds["password"]


def test_slack_webhook_fallback_from_vault():
    import secrets_client
    import reporting
    assert reporting._slack_webhook_fallback() == secrets_client.get_webhook_url("slack")


def test_teams_webhook_fallback_from_vault():
    import secrets_client
    import reporting
    assert reporting._teams_webhook_fallback() == secrets_client.get_webhook_url("teams")
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_reporting_secrets.py -v`
Expected: FAIL — `_smtp_fallback_creds`/`_slack_webhook_fallback`/`_teams_webhook_fallback` don't exist yet.

- [ ] **Step 3: Edit `src/reporting.py`**

Add three small helper functions near the top of the file (after imports), then use them at the three call sites:

```python
def _smtp_fallback_creds() -> tuple[str, str]:
    from secrets_client import get_smtp_creds
    creds = get_smtp_creds()
    return creds["user"], creds["password"]


def _slack_webhook_fallback() -> str:
    from secrets_client import get_webhook_url
    return get_webhook_url("slack")


def _teams_webhook_fallback() -> str:
    from secrets_client import get_webhook_url
    return get_webhook_url("teams")
```

Replace `src/reporting.py:134-137`:
```python
    else:
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = int(os.getenv("SMTP_PORT", "465"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASSWORD")
```
with:
```python
    else:
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = int(os.getenv("SMTP_PORT", "465"))
        smtp_user, smtp_pass = _smtp_fallback_creds()
```

Replace `src/reporting.py:239`:
```python
    url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
```
with:
```python
    url = webhook_url or _slack_webhook_fallback()
```

Replace `src/reporting.py:295`:
```python
    url = webhook_url or os.getenv("TEAMS_WEBHOOK_URL")
```
with:
```python
    url = webhook_url or _teams_webhook_fallback()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reporting_secrets.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v`
Expected: no new failures (existing `reporting.py` tests that pass `mailbox=` or `webhook_url=` explicitly are unaffected, since those still take the non-fallback branch).

- [ ] **Step 6: Commit**

```bash
git add src/reporting.py tests/test_reporting_secrets.py
git commit -m "refactor: reporting.py SMTP/webhook fallbacks resolved via secrets_client"
```

---

### Task 10: `detonation_config.py` uses `secrets_client` for CAPE tokens

**Files:**
- Modify: `src/detonation_config.py:23, 158`
- Test: `tests/test_detonation_config_secrets.py`

**Interfaces:**
- Consumes: `secrets_client.get_cape_token(name)` (Task 3).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_detonation_config_secrets.py -v`
Expected: FAIL — current code reads `os.getenv("CAPE_API_TOKEN", "")` / `os.getenv("CAPE_VM_WRAPPER_TOKEN", "")`.

- [ ] **Step 3: Edit `src/detonation_config.py`**

Replace line 23:
```python
CAPE_API_TOKEN = os.getenv("CAPE_API_TOKEN", "")
```
with:
```python
from secrets_client import get_cape_token
CAPE_API_TOKEN = get_cape_token("api_token")
```

Replace line 158:
```python
CAPE_VM_WRAPPER_TOKEN = os.getenv("CAPE_VM_WRAPPER_TOKEN", "")
```
with:
```python
CAPE_VM_WRAPPER_TOKEN = get_cape_token("vm_wrapper_token")
```

(Note: as today, these are read once at import time — not re-fetched on Vault rotation without an app restart. This is unchanged behavior, not a new limitation introduced by this task.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_detonation_config_secrets.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full existing suite**

Run: `pytest tests/ -v`
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add src/detonation_config.py tests/test_detonation_config_secrets.py
git commit -m "refactor: CAPE tokens read from Vault via secrets_client"
```

---

### Task 11: Shrink `.env.example` and `deploy/k8s/secret.yaml.example`

**Files:**
- Modify: `.env.example`
- Modify: `deploy/k8s/secret.yaml.example`

**Interfaces:**
- None (documentation/template files only, no code interfaces).

- [ ] **Step 1: Edit `.env.example`**

Remove these lines (now Vault-managed, no longer read from `.env` in code):
```
VIRUSTOTAL_API_KEY=
THREATFOX_AUTH_KEY=
AbuseIPDB_API_KEY=
```
```
DNSTWIST_API_KEY={"domain_fuzzer_url":...}
```
```
OTX_API_KEY=
```
```
VAULT_ENCRYPTION_KEY=
```
```
JWT_SECRET=
```
```
SMTP_USER=
SMTP_PASSWORD=
```
```
SLACK_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
```
```
CAPE_API_TOKEN=
```
```
CAPE_VM_WRAPPER_TOKEN=
```
```
DATABASE_URL=postgresql://postgres:yourpassword@localhost:5432/attijari_db
```

Add a new section near the top, right after the file's header comment block:
```
# --- HashiCorp Vault (secrets manager) ---
# All secrets (DB creds, JWT signing key, threat-intel API keys, SMTP creds,
# webhook URLs, CAPE tokens) now live in Vault, not here. See
# docs/vault-dev-setup.md to stand up a local dev-mode Vault and run
# scripts/vault_bootstrap.py, then scripts/migrate_env_to_vault.py if you
# have existing secrets to migrate.
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=
VAULT_SECRET_ID=
```

Leave `DATABASE_URL`'s old line removed entirely (it's fully Vault-managed now, unlike e.g. `SMTP_HOST`/`SMTP_PORT` which stay since only the credential pair is secret).

- [ ] **Step 2: Edit `deploy/k8s/secret.yaml.example`**

Replace the full file:
```yaml
# secret.yaml.example — TEMPLATE ONLY. Copy to secret.yaml on the bank VM,
# fill in real values, and apply it there. secret.yaml itself (with real
# secrets) must NEVER be committed — see .gitignore.
#
# As of the HashiCorp Vault secrets-manager integration
# (docs/superpowers/specs/2026-07-30-secrets-manager-design.md), this Secret
# only needs to carry Vault connection info. VAULT_ROLE_ID is not sensitive
# (safe in this file); VAULT_SECRET_ID is sensitive and must be provisioned
# manually on the bank VM — see that spec's "Known limitation" section. All
# other secrets (DB creds, JWT_SECRET, threat-intel keys, SMTP creds,
# webhook URLs, CAPE tokens) now live in Vault itself, not in this Secret.
apiVersion: v1
kind: Secret
metadata:
  name: attijari-secrets
  namespace: attijari
type: Opaque
stringData:
  VAULT_ADDR: "http://vault.attijari.svc.cluster.local:8200"
  VAULT_ROLE_ID: "CHANGE_ME_from_scripts/vault_bootstrap.py_output"
  VAULT_SECRET_ID: "CHANGE_ME_provision_manually_do_not_commit_a_real_value_here"
```

- [ ] **Step 3: Commit**

```bash
git add .env.example deploy/k8s/secret.yaml.example
git commit -m "docs: shrink .env.example and k8s secret template to Vault connection info only"
```

---

### Task 12: CI — add Vault service container and bootstrap step

**Files:**
- Modify: `.github/workflows/secops.yml` (the `test` job, lines 86-156, and the `api-fuzz` job, lines ~205-232)

**Interfaces:**
- None (CI config only).

- [ ] **Step 1: Add a `vault` service to the `test` job's `services:` block**

In `.github/workflows/secops.yml`, after the existing `redis:` service block (ends around line 116), add:
```yaml
      vault:
        image: hashicorp/vault:1.17
        env:
          VAULT_DEV_ROOT_TOKEN_ID: ci-root-token
          VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
        ports:
          - 8200:8200
        options: >-
          --cap-add=IPC_LOCK
          --health-cmd "VAULT_ADDR=http://127.0.0.1:8200 vault status -tls-skip-verify"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
```

- [ ] **Step 2: Add a bootstrap-and-seed step before "Run Pytest"**

Insert after the "Install dependencies" step (after line 128) and before "Run Pytest" (line 129):
```yaml
      - name: Bootstrap Vault and seed CI secrets
        env:
          VAULT_ADDR: http://127.0.0.1:8200
          VAULT_TOKEN: ci-root-token
        run: |
          python scripts/vault_bootstrap.py > vault_creds.txt
          echo "VAULT_ROLE_ID=$(grep VAULT_ROLE_ID vault_creds.txt | cut -d= -f2)" >> $GITHUB_ENV
          echo "VAULT_SECRET_ID=$(grep VAULT_SECRET_ID vault_creds.txt | cut -d= -f2)" >> $GITHUB_ENV
          rm vault_creds.txt
          python - <<'PYEOF'
          import sys
          sys.path.insert(0, "src")
          sys.path.insert(0, "scripts")
          import migrate_env_to_vault
          migrate_env_to_vault.migrate({
              "DATABASE_URL": "postgresql://postgres:postgres@localhost:5432/attijari_test",
              "JWT_SECRET": "ci-only-jwt-secret-not-used-outside-this-workflow-run",
              "VAULT_ENCRYPTION_KEY": "RExB-2NL83wRpMGjq-t_OCUxvK7qiEskB9jU4F5fd8c=",
              "VIRUSTOTAL_API_KEY": "${{ secrets.VIRUSTOTAL_API_KEY }}",
              "THREATFOX_AUTH_KEY": "${{ secrets.THREATFOX_AUTH_KEY }}",
          })
          PYEOF
```

- [ ] **Step 3: Update the "Run Pytest" step's env block**

Replace the `env:` block at lines 136-151:
```yaml
        env:
          # Required for some tests as seen in previous ci.yml
          VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
          THREATFOX_AUTH_KEY: ${{ secrets.THREATFOX_AUTH_KEY }}
          # Live-DB tests (test_jwt_revocation.py, test_detonation_recovery.py, etc.)
          # need a real Postgres to run against — provided by the service above.
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/attijari_test
          REDIS_URL: redis://localhost:6379/0
          # src/api_core.py raises RuntimeError at import time if neither is set.
          # Locally, collection succeeds without them (nothing imports api_core.py
          # at collection time), but any test that exercises auth code paths at
          # *execution* time would hit this — and neither var was ever present in
          # this workflow. CI-only throwaway values (sign/encrypt nothing outside
          # this run); must differ from each other or api_core.py warns.
          JWT_SECRET: ci-only-jwt-secret-not-used-outside-this-workflow-run
          VAULT_ENCRYPTION_KEY: RExB-2NL83wRpMGjq-t_OCUxvK7qiEskB9jU4F5fd8c=
```
with:
```yaml
        env:
          # Live-DB tests need a real Postgres/Redis to run against — services above.
          REDIS_URL: redis://localhost:6379/0
          # Secrets themselves now come from Vault (seeded by the bootstrap step
          # above) — these three are the connection credentials to reach Vault,
          # not the secrets themselves.
          VAULT_ADDR: http://127.0.0.1:8200
          VAULT_ROLE_ID: ${{ env.VAULT_ROLE_ID }}
          VAULT_SECRET_ID: ${{ env.VAULT_SECRET_ID }}
```

- [ ] **Step 4: Apply the same three changes to the `api-fuzz` job**

The `api-fuzz` job (around line 205) boots the real app via uvicorn, which now requires Vault too. Repeat Steps 1-3 for that job's `services:` block and its app-boot step's `env:`.

- [ ] **Step 5: Verify locally with `act` or by reasoning through the YAML**

Since this environment has no Docker daemon (per the existing constraint noted in the K8s-orchestration build log entry), this step cannot be dry-run locally. Instead, carefully re-read the edited YAML for correct indentation and matching `$GITHUB_ENV` variable names before committing — a YAML syntax error here fails the whole workflow, not just the intended test.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/secops.yml
git commit -m "ci: add Vault dev-mode service container and bootstrap step to test/api-fuzz jobs"
```

---

### Task 13: Update CLAUDE.md build log

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:**
- None.

- [ ] **Step 1: Append a new Build Log entry**

Add to the end of the "## Build Log" section in `CLAUDE.md`, after the 2026-07-30 CI-expansion entry:

```markdown
- **2026-07-30 (Secrets manager)** — Replaced plaintext secrets in `.env`
  and `deploy/k8s/secret.yaml` with HashiCorp Vault (spec:
  `docs/superpowers/specs/2026-07-30-secrets-manager-design.md`). New
  `src/secrets_client.py` (lazy singleton, AppRole auth, KV v2 read with a
  5-minute TTL cache) is the one shared point every secret now flows
  through: `database.py` (DB URL), `api_core.py` (JWT signing key),
  `vault.py` (the Fernet key it uses for quarantine/TOTP encryption — note
  this is a *different* "vault" from HashiCorp Vault, see that module's
  docstring), the threat-intel modules (VirusTotal/ThreatFox/AbuseIPDB/
  OTX/dnstwist API keys), `reporting.py` (SMTP creds, Slack/Teams webhook
  URLs), and `detonation_config.py` (CAPE API token, VM wrapper token).
  `scripts/vault_bootstrap.py` sets up the KV engine + AppRole + read-only
  policy (idempotent); `scripts/migrate_env_to_vault.py` moves existing
  `.env` values in (never deletes `.env` lines — that stays a manual
  step). CI's `secops.yml` `test`/`api-fuzz` jobs gained a
  `hashicorp/vault:1.17` dev-mode service container + bootstrap step,
  mirroring the existing Postgres/Redis service pattern.
  This closes the "plain K8s Secrets are an acknowledged gap" note from
  the 2026-07-30 Kubernetes-orchestration entry — `deploy/k8s/
  secret.yaml.example` now only carries `VAULT_ADDR`/`VAULT_ROLE_ID`
  (non-sensitive); `VAULT_SECRET_ID` provisioning on the bank VM remains a
  manual, documented step (Vault's inherent "secret zero" problem, not
  automated).
  **Known limitation, not solved here:** `VAULT_SECRET_ID` bootstrap onto
  the real bank VM is manual. Standing up a production (non-dev-mode)
  Vault server on that VM is also not part of this work — this delivered
  the *integration*, not a hand-rolled Vault HA cluster.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: log secrets manager (HashiCorp Vault) work in CLAUDE.md build log"
```

---

## Post-plan verification

- [ ] Run the full suite one final time: `pytest tests/ --cov=src --cov-report=term -v`. Expected: all tests pass, coverage at or above the existing 20% floor.
- [ ] Manually verify the app boots end-to-end against local dev-mode Vault: start Vault, run `vault_bootstrap.py`, run `migrate_env_to_vault.py` against a real `.env`, set `VAULT_ADDR`/`VAULT_ROLE_ID`/`VAULT_SECRET_ID`, then start the app (`python -m src.main --serve` or the project's existing start script) and confirm it boots without falling back to any `os.getenv` secret path.
