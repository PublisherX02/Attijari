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


## Day 3:
- Architecture Problem
  To establish the connectuion and the autonomation of the tool when receiving emails automatically we need to decide on two architectures each one having their own weak sides
  - # Plan1:
    - Each administrative pc has a built in copie of this tool with no privileges ".exe". and in the .env keys we have the IMAP of the user Outlook email and the IMAP creditentials of the SecOps engineers to send reports and confirmation.
    - Pros: less risk while manipulating source code/noc hange to the system architecture
    - Cons: each new acc created, new pc configured needs to receive a new update version of the system since pcs only receive .eve file with no edit rights

  - # Plan2:
    - One copie of the triage tool hosted in one of the servers connected to all administrative pcs and Secops engineers via IMAP creditentials.
    - Pros: Easier configuration 
    - Cons: repetitive source code manipulation can cause unexpected problems/.env becomes unreadable/email_triage. py needs a whole architecture change to fetch all the emails from each user/multiple servers needed for peak hours and API antispam prevention
#
- Completed the rules layer + passing checks with flying colors 
- needs to work on autonomating the scanning tests each time a new email is received

#
- Problem: LLM (Ollama) instability — frequent timeouts and streaming/NDJSON formats made parsing unreliable; wrong `rules.py` version appeared earlier due to import path confusion.

- What we faced:
  - Ollama often returned NDJSON/events or timed out, causing parse failures and accidental escalations.
  - Pipeline sometimes imported the wrong rules module (duplicate files/paths).
  - MAX_ATTACHMENT_SIZE and MAX_ATTACHMENT_COUNT were defined but not enforced in earlier parse flow.

- What we changed:
  - Enforced MAX_ATTACHMENT_COUNT before extracting attachments and made _extract_attachment reject oversized files (max size enforced).
  - Rewrote/verified src/rules.py to use deterministic lists (BLOCKED_EXTENSIONS, BLOCKLIST_DOMAINS, BLOCKED_HASHES) and added a `phishy_body` heuristic.
  - Added robust LLM helper (src/analysis.py): prefers non-streaming calls, reconstructs NDJSON when needed, extracts balanced JSON blocks, and loads a hardened skills.md system prompt.
  - Hardened LLM calls with retries, backoff, increased timeouts; changed failure semantics so analysis returns "unavailable" instead of auto-escalating on transient failures.
  - Persisted compact LLM summary (verdict + reasons) into the processed ledger for auditing.
  - Fixed import/path issues by using correct module locations and adjusted main.py to pass headers+attachments as context to the LLM.

- What still not working / open items:
  - Ollama endpoint still occasionally slow or non-responsive; need to check local Ollama daemon health or use a hosted fallback.
  - Full raw LLM outputs are not fully persisted (only compact summary saved) — limits offline analysis/auditability.
  - Model tuning (temperature, stop tokens) in skills.md could be improved to force single-blob JSON output.
  - Consider async queueing for LLM calls to avoid blocking ingestion during analysis.

- Next actions (recommended):
  1. Store full raw LLM responses for failed calls in data/ for offline debugging.
  2. Add quick healthcheck + restart for Ollama or fallback to remote model.
  3. Add unit tests for NDJSON -> JSON parsing and for attachment size/count enforcement.
  4. Consider changing LLM failure policy only after operator review (now returns "unavailable").

  ## Day4:
- Fixed LLM bugs and inconsistency.
- Created a skills.md file in order to improve the LLM response and analysis paying extra precaution to details citing his role patterns of suspicious social engineering and AI generated text meant for fishing attacks. Thios solution raises to avoid the extra work of fine-tunning a model since there is no real data available to adapt it to real life cases.
- Fixed LLM delayed time response as it was a resource problem which raised couple of concerns:
  - If the LLM will be hosted in a CPU server, the response time for the analysis for a single email can take up to 3-4 minutes depending on various variables. This won't be that big of a problem since the bank system receives in average 120 emails per today (average an email in 6 minute). But it needs to be discussed a limit of productivity and rapidity  to deliver response.
  - The skills.md needs to be changed regulary in order to stay up to new fishing methods and develop it's capabilities not only in social engineeringa dn AI detection but also the psychology to detect the fishing intent.


