# Secrets Manager (HashiCorp Vault) — Design

Date: 2026-07-30
Status: Approved for planning

## Context

Secrets currently live in two places:
- A plaintext local `.env` file (dev machine).
- A gitignored `deploy/k8s/secret.yaml` (K8s), which is a **plain base64
  Kubernetes Secret** — flagged as an acknowledged gap in the
  2026-07-30 Kubernetes-orchestration build log entry, pending "the
  secrets-manager initiative."

This is the next item in the stated roadmap order (ARCH-1 → K8s → job
queue → CI security gates → **secrets manager**). It is independent of,
and not time-critical relative to, the separate evasion-hardening work
(YARA/extraction/CAPE) requested for next week's adversarial test —
that is a separate, parallel track.

**Naming clarification (important):** `src/vault.py` already exists and
does something unrelated — Fernet (AES) at-rest encryption of quarantined
emails and TOTP secrets, keyed by `VAULT_ENCRYPTION_KEY`. This design
introduces **HashiCorp Vault**, a secrets manager, which will itself
become the place `VAULT_ENCRYPTION_KEY` is *stored*. The two "vaults" are
different systems. `src/vault.py` is not renamed (avoid unnecessary
churn across its callers); it gets a one-line docstring note pointing at
the new module to prevent future confusion.

## Goals

- Remove plaintext secrets from `.env` and from the K8s Secret manifest.
- One consistent secrets-access path for the whole app instead of
  scattered `os.getenv()` calls for sensitive values.
- Same integration code path on this local Windows dev machine and later
  on the bank VM — no dev-only shortcut that goes untested until deploy.
- Fail closed: if the secrets backend is unreachable, the app refuses to
  start rather than silently falling back to a missing/default secret.

## Non-goals

- Standing up a production-grade, highly-available Vault cluster. The
  bank-VM Vault instance is a single server, consistent with the
  project's existing "single VM, no cloud managed services" posture
  (same posture as Postgres/Redis in the K8s design). HA Vault is a
  possible future item, not in scope here.
- Automating `VAULT_SECRET_ID` provisioning on the bank VM. That
  bootstrap step is manual and documented, not automated (see
  "Known limitation" below).
- Migrating non-secret config (hosts, ports, timeouts, feature toggles).
  Those stay in `.env`/ConfigMap exactly as today.

## Architecture

```
                    ┌─────────────────────────┐
                    │   Vault server           │
                    │   (dev-mode locally;     │
                    │   real server on bank VM)│
                    │                          │
                    │  KV v2 @ secret/attijari/│
                    │   - database             │
                    │   - jwt                  │
                    │   - vault_encryption_key │
                    │   - threat_intel         │
                    │   - smtp                 │
                    │   - webhooks             │
                    │   - cape                 │
                    │   - nvidia               │
                    └───────────▲──────────────┘
                                │ AppRole (role_id + secret_id)
                                │
                    ┌───────────┴──────────────┐
                    │  src/secrets_client.py    │
                    │  lazy singleton, TTL cache│
                    │  get_database_url()       │
                    │  get_jwt_secret()         │
                    │  get_vault_encryption_key()│
                    │  get_api_key(name)        │
                    │  get_smtp_creds()         │
                    │  get_webhook_url(name)    │
                    │  get_cape_token(name)     │
                    └───────────┬──────────────┘
                                │
        ┌───────────┬──────────┼───────────┬──────────────┐
        ▼           ▼          ▼           ▼              ▼
   database.py  api_core.py  vault.py   enrichment/    reporting.py
                                          (VT/AbuseIPDB/  cape_client.py
                                           ThreatFox/OTX)  detonation_config
```

## Components

### Vault server

- **Local dev**: `vault server -dev` (in-memory, auto-unsealed, fixed
  root token for dev convenience). Documented as dev-only — never used
  for a real deployment.
- **Bank VM (future)**: a real Vault server process (file or Raft
  storage backend), manually unsealed per Vault's standard operational
  model. Stood up when the bank VM exists; this design only requires
  that `VAULT_ADDR` point at it.

### Secrets engine & layout

- KV v2 engine mounted at `secret/`.
- One path per logical group under `secret/attijari/`, matching today's
  `.env` groupings (see diagram). Each path holds a small JSON object
  (e.g. `secret/attijari/threat_intel` → `{virustotal, threatfox,
  abuseipdb, otx, dnstwist}`).

### Auth: AppRole

- One Vault role, `attijari-app`, with a policy granting `read` on
  `secret/data/attijari/*` (KV v2 data path) — no write, no other paths.
- `role_id`: not sensitive, can sit in `.env`/ConfigMap alongside
  `VAULT_ADDR`.
- `secret_id`: sensitive, rotatable. **Known limitation**: something has
  to deliver this credential to the app initially — Vault's "secret
  zero" problem. For local dev, it's generated once via `vault write
  auth/approle/role/attijari-app/secret-id` and placed in `.env` as
  `VAULT_SECRET_ID`. For the bank VM, provisioning is a manual,
  documented step (e.g., an operator pastes it into a K8s Secret created
  out-of-band) — not automated by this design.

### `src/secrets_client.py`

- Lazy singleton (same pattern as `src/redis_client.py`).
- Authenticates via AppRole using `hvac` on first access.
- Caches fetched secrets in memory with a short TTL (default 5 minutes)
  so rotations propagate without an app restart, without hitting Vault
  on every call.
- Typed getters mirror today's env-var groups: `get_database_url()`,
  `get_jwt_secret()`, `get_vault_encryption_key()`, `get_api_key(name)`
  (threat-intel keys), `get_smtp_creds()`, `get_webhook_url(name)`,
  `get_cape_token(name)`.
- **Fail-closed**: any failure to authenticate or read a required secret
  at startup raises immediately — the app does not boot. This matches
  the existing behavior in `api_core.py` (already raises if
  `JWT_SECRET`/`VAULT_ENCRYPTION_KEY` is missing) and CLAUDE.md's
  fail-closed principle for infra failures.

### Call-site changes

Replace direct `os.getenv()` reads of *secret* values with
`secrets_client.get_*()` in:
- `database.py` (DB connection string)
- `api_core.py` (JWT signing secret)
- `vault.py` (the Fernet `VAULT_ENCRYPTION_KEY` itself — read via
  `secrets_client.get_vault_encryption_key()` instead of `os.getenv`)
- `enrichment/` modules (VirusTotal, AbuseIPDB, ThreatFox, OTX, dnstwist
  API keys)
- `reporting.py` (SMTP user/password, Slack/Teams webhook URLs)
- `cape_client.py` / detonation config (CAPE API token, VM wrapper token)
- `pop3_smtp_bridge.py` / `gmail_smtp_bridge.py` where they read mailbox
  or SMTP secrets directly

Non-secret config (hosts, ports, timeouts, feature toggles, CAPE
malscore thresholds, etc.) is untouched — still plain `.env`/ConfigMap.

### Migration script

`scripts/migrate_env_to_vault.py`:
- Reads the current `.env`.
- Writes each secret group to its Vault KV path.
- Prints a checklist of which `.env` lines are now redundant and safe to
  delete.
- **Never auto-deletes anything from `.env`** — deletion is a manual
  step after the operator confirms the app boots correctly against
  Vault.

### K8s changes

- `deploy/k8s/secret.yaml.example` shrinks to just `VAULT_ADDR` and
  `VAULT_ROLE_ID` (both non-sensitive).
- `VAULT_SECRET_ID` bootstrap on the bank VM is called out explicitly in
  a comment/doc as a manual step, not automated here.
- This directly closes the "plain K8s Secrets are an acknowledged gap"
  note from the 2026-07-30 Kubernetes-orchestration build log entry.

## Error handling

- Vault unreachable at startup → app raises, refuses to boot (fail
  closed — consistent with existing `JWT_SECRET`/`VAULT_ENCRYPTION_KEY`
  checks).
- Vault reachable but a specific path/key missing → same: raise with a
  clear message naming the missing path, not a silent `None`.
- Cached secret + Vault goes down *after* startup → cached value keeps
  serving until TTL expiry; if refresh then fails, the last-known-good
  cached value is kept and a warning is logged (avoids an unnecessary
  outage from a transient Vault blip) rather than crashing an
  already-running app.

## Testing

- Unit tests mock `hvac.Client` (matching the existing mocking style
  used for Redis/K8s clients elsewhere in the suite).
- One live integration test runs against the local dev-mode Vault
  server, skipped gracefully if `VAULT_ADDR` is unreachable — same
  pattern as the existing Postgres/Redis-dependent tests.
- Full existing suite (257 passed, 1 skipped as of the last build-log
  entry) must stay green after the `os.getenv()` → `secrets_client`
  call-site migration.

## Rollout order

1. Stand up local dev-mode Vault; write `secrets_client.py` + unit
   tests.
2. Migration script; move all current `.env` secrets into Vault KV.
3. Update call sites group by group (DB → JWT/vault key → threat-intel
   → SMTP/webhooks → CAPE), running the full suite after each group.
4. Shrink `.env.example` and `deploy/k8s/secret.yaml.example` to
   non-secret values + `VAULT_ADDR`/`VAULT_ROLE_ID`.
5. Update the Production Deployment Backlog in CLAUDE.md: mark the
   secrets-manager item done, add "stand up real Vault server on bank
   VM + provision `VAULT_SECRET_ID`" as a bank-VM-only manual
   prerequisite (mirroring how other bank-VM-only steps are already
   tracked there).
