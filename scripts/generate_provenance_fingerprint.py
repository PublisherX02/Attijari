"""generate_provenance_fingerprint.py — one-time authorship fingerprint generator.

Run this locally. It never sends anything anywhere and the passphrase you
enter is never written to disk or printed back — only the resulting SHA-256
hash is shown. Paste that hash into OWNERSHIP.md as PROVENANCE_FINGERPRINT_SHA256.

The point: the hash is derived from a passphrase only you know, combined with
your name/email and today's date. Anyone can independently recompute it and
confirm it matches *once you choose to reveal the passphrase* (e.g. in a
dispute), but nobody can forge a matching hash in advance without knowing
that passphrase first. That makes it a lightweight, verifiable-after-the-fact
authorship marker, distinct from (and weaker than) the git history itself,
which remains the primary evidence in OWNERSHIP.md.

Usage:
    python scripts/generate_provenance_fingerprint.py
"""
from __future__ import annotations

import getpass
import hashlib
from datetime import date, timezone, datetime


def main() -> None:
    print("Provenance fingerprint generator — nothing here is saved or transmitted.\n")
    full_name = input("Full legal name: ").strip()
    email = input("Email: ").strip()
    passphrase = getpass.getpass("Private passphrase (won't echo, choose something only you'd know): ")

    if not full_name or not email or not passphrase:
        print("All three fields are required. Nothing was written.")
        return

    today = date.today().isoformat()
    material = f"{full_name}|{email}|{today}|{passphrase}".encode("utf-8")
    fingerprint = hashlib.sha256(material).hexdigest()

    print("\n--- Paste this into OWNERSHIP.md ---")
    print(f"PROVENANCE_FINGERPRINT_SHA256 = {fingerprint}")
    print(f"GENERATED: {today}")
    print("-------------------------------------")
    print(
        "\nKeep the passphrase itself private and offline (not in this repo, "
        "not in chat history) until/unless you need to prove authorship by "
        "revealing it and letting someone else recompute this same hash."
    )


if __name__ == "__main__":
    main()
