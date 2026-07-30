# Local Vault dev-mode setup

1. Install the Vault binary. On Windows, `winget install HashiCorp.Vault`
   works; otherwise download it from HashiCorp's release page and put
   `vault.exe` on your PATH.
2. Start a dev-mode server (in-memory, auto-unsealed, fixed root token):

   ```
   vault server -dev -dev-root-token-id="root" -dev-listen-address="127.0.0.1:8200"
   ```

3. Leave that terminal running. In a second terminal, set:

   ```
   set VAULT_ADDR=http://127.0.0.1:8200
   set VAULT_TOKEN=root
   ```

4. Run the bootstrap script to create the KV engine, AppRole, and policy:

   ```
   python scripts/vault_bootstrap.py
   ```

   This prints a `VAULT_ROLE_ID` and `VAULT_SECRET_ID` — copy both into your
   local `.env`, along with `VAULT_ADDR=http://127.0.0.1:8200`.

5. Never run `vault server -dev` against anything but a throwaway local
   instance — dev mode has no persistence and a fixed root token.
