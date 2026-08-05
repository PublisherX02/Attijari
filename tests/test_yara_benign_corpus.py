"""CI gate: the full YARA ruleset must show zero matches against the
benign email corpus. A new or edited rule that trips on realistic clean
mail fails this test, not a production email.
"""
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from accuracy import build_benign_cases
from extraction import _local_yara


def _scannable_blobs(raw_eml: bytes) -> list[tuple[str, bytes]]:
    """Extract exactly what production YARA-scans: decoded attachment
    bytes and body text — never raw base64-encoded MIME bytes, which
    would never match a plain-text string rule and would be meaningless
    false confidence."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_eml)
    blobs = []
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        content = body.get_content()
        if isinstance(content, str):
            blobs.append(("body", content.encode("utf-8", errors="replace")))
    for part in msg.iter_attachments():
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if payload:
            blobs.append((part.get_filename() or "attachment", payload))
    return blobs


def test_no_yara_rule_matches_any_benign_case():
    failures = []
    for case in build_benign_cases():
        for blob_name, blob in _scannable_blobs(case["eml"]):
            result = _local_yara(blob)
            for match in result.get("matches", []):
                if "rule" in match:
                    failures.append(
                        f"case={case['name']!r} blob={blob_name!r} rule={match['rule']!r}"
                    )
    assert failures == [], (
        "YARA rule(s) matched benign mail — false positive(s) found:\n"
        + "\n".join(failures)
    )
