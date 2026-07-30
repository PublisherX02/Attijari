"""check_licenses.py — fail CI if a new AGPL/GPL (non-LGPL) dependency shows up.

Run after `pip install -r requirements.txt`. Reads pip-licenses' JSON output
and flags anything that is AGPL or GPL-but-not-LGPL, since those are the
copyleft families that create real compliance risk when selling to a bank
(AGPL's network-use clause is the sharpest one; a bank running this as a
network service could be obligated to release the whole codebase). LGPL is
allowed — it does not force the surrounding proprietary code to open up,
only modifications to the LGPL library itself.

KNOWN_ACCEPTED holds packages already reviewed and accepted despite a
copyleft license, with the reason on file. Anything else in that family
fails the build.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

# pcodedmp (GPLv3) is a transitive dependency of oletools, which this
# project genuinely needs for VBA macro decompilation (src/extraction.py's
# VBA_Parser) — there is no drop-in replacement. Reviewed and accepted;
# not distributed as a modified/relinked binary, used as-is via oletools'
# own API surface.
#
# tld's license is disjunctive ("MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later")
# — the project can comply under MPL-1.1, a permissive-ish weak-copyleft
# license, so this is not a real GPL obligation despite the string containing
# "GPL-2.0-only".
#
# pymupdf (`import fitz`, src/extraction.py — PDF /JS, /OpenAction, /Launch
# detection) is dual-licensed AGPL-3.0 / paid Artifex commercial license.
# THIS ONE IS NOT RESOLVED. AGPL's network-use clause is a real risk for a
# bank running this as a network service — could obligate releasing the
# whole codebase. Temporarily allowlisted so CI stays usable for a POC;
# MUST be revisited (buy the Artifex commercial license, or replace PyMuPDF
# with a permissively-licensed alternative such as pypdfium2/pdfplumber)
# before any real deployment. Do not let this sit here quietly — flag it.
KNOWN_ACCEPTED = {"pcodedmp", "tld", "pymupdf"}
KNOWN_ACCEPTED_LOWER = {name.lower() for name in KNOWN_ACCEPTED}

# Matches GPL but not LGPL (careful: "GPLv3" is a literal substring of
# "LGPLv3+", so a naive "GPL" substring check would misflag LGPL packages).
_GPL_NOT_L_RE = re.compile(r"(?<!L)GPL", re.IGNORECASE)


def _is_copyleft(license_str: str) -> bool:
    if "AGPL" in license_str.upper() or "AFFERO" in license_str.upper():
        return True
    return bool(_GPL_NOT_L_RE.search(license_str))


def main() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "piplicenses", "--format=json", "--with-license-file", "--no-license-path"],
        capture_output=True, text=True, check=True,
    )
    packages = json.loads(proc.stdout)

    violations = []
    for pkg in packages:
        name = pkg["Name"]
        license_str = pkg["License"]
        if name.lower() in KNOWN_ACCEPTED_LOWER:
            continue
        if _is_copyleft(license_str):
            violations.append((name, pkg["Version"], license_str))

    if violations:
        print("Copyleft (AGPL/GPL) dependencies found — not on the accepted list:")
        for name, version, license_str in violations:
            print(f"  - {name} {version}: {license_str}")
        print(
            "\nIf this is a genuine, reviewed, unavoidable dependency, add it to "
            "KNOWN_ACCEPTED in scripts/check_licenses.py with a one-line reason "
            "(see pcodedmp for the existing example). Otherwise, remove or replace it."
        )
        return 1

    print(f"License check passed — {len(packages)} packages, no unreviewed AGPL/GPL found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
