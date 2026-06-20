## Day 1:
-preparing the workspace 
-Research to build the architecture of the Agentic AI system
-added VirusTotal API KEY to .env

Must do Tomorrow:
    -Read and configure AbuserIPDB API key

## Day 2:
- Fixed bugs in `email_extraction.py` (the main email ingestion script):
  - The script wasn't running at all because of a typo in the main guard
  - An important function (`extract_attachment`) was unreachable due to bad indentation
  - Fixed several typos in method names and dictionary keys
  - Added the missing `idempotency_key()` method
  - Removed a duplicated loop that would process emails twice

- Added progress logging so we can see where the script is at each step:
  - Each stage prints a tag like `[CONNECT]`, `[FETCH]`, `[PARSE]`, `[ARCHIVE]`
  - Added timeout checkpoints — if any step takes too long the pipeline stops cleanly instead of hanging

- Added an idempotency system so emails are not reprocessed on re-run:
  - A ledger file (`data/processed_ledger.json`) keeps track of what was already processed
  - Already-seen emails show their cached result directly instead of being re-parsed
  - The idempotency key combines both Message-ID and the raw email hash to prevent spoofing

- Security hardening:
  - Default email status is now `"recu"` (received/parsed only) — not `"accepted"`
  - `"accepted"` will only be set later after the full analysis chain passes
  - Parse errors set the status to `"escalated"`
  - Added size limits: max 25 MB per email, max 10 MB per attachment, max 20 attachments

- Limited email fetch to the 5 most recent unread emails (was loading the entire inbox)

- Installed Google API packages (`google-api-python-client`, `google-auth-httplib2`, `google-auth-oauthlib`)

Must do next:
    - Read and configure AbuserIPDB API key
    - Build the analysis chain that promotes emails from "recu" to "accepted"