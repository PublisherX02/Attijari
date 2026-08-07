"""test_rules_unrecognized_attachment_type.py — default-deny for attachment
types: BLOCKED_EXTENSIONS only ever covered known-DANGEROUS extensions,
leaving a third category completely unexamined by the rules engine --
formats nobody ever vetted at all (not known-safe, not known-dangerous).
Those previously fell straight through to MarkItDown's generic text
extraction, which produces confident-looking "clean" output for a format
it was never actually tested against. This rule flags anything outside
both the dangerous list and a positive allowlist of formats the extraction
stage has real, verified handling for -- proposed_reject, same as an
explicitly blocked extension, but still requiring human confirmation
before anything is actually rejected.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def _email_with_attachment(filename: str) -> dict:
    return {
        "headers": {"from": "sender@example.com", "to": "victim@example.com",
                     "subject": "x", "message-id": "<x@x>"},
        "attachments": [{"original_name": filename, "sha256": "a" * 64}],
        "body_text": "", "body_html": "",
    }


def test_unusual_extension_flagged_and_proposed_reject():
    parsed = _email_with_attachment("data.xyz123")
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "unrecognized_attachment_type")
    assert d["flagged"] is True
    assert res["verdict"] == "proposed_reject"


def test_no_extension_at_all_flagged():
    parsed = _email_with_attachment("README")
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "unrecognized_attachment_type")
    assert d["flagged"] is True
    assert "(no extension)" in d["reason"]


def test_known_safe_extensions_not_flagged():
    for filename in ("invoice.pdf", "report.docx", "photo.jpg", "archive.zip",
                       "notes.txt", "data.csv", "memo.rtf", "slides.pptx"):
        parsed = _email_with_attachment(filename)
        res = rules.RuleEngine().analyze(parsed)
        d = next(x for x in res["details"] if x["rule"] == "unrecognized_attachment_type")
        assert d["flagged"] is False, f"{filename} was incorrectly flagged as unrecognized"


def test_blocked_extension_not_double_flagged_by_this_rule():
    # .exe is already caught by Rule 2 (blocked_extension) -- this rule
    # should stay quiet for it rather than raising a second, redundant flag.
    parsed = _email_with_attachment("tool.exe")
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "unrecognized_attachment_type")
    assert d["flagged"] is False
    d_blocked = next(x for x in res["details"] if x["rule"] == "blocked_extension")
    assert d_blocked["flagged"] is True
    assert res["verdict"] == "proposed_reject"


def test_no_attachment_at_all_not_flagged():
    parsed = {
        "headers": {"from": "a@b.tld", "to": "v@e.com", "subject": "x", "message-id": "<x@x>"},
        "attachments": [], "body_text": "", "body_html": "",
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "unrecognized_attachment_type")
    assert d["flagged"] is False
    assert res["verdict"] == "accepted"


def test_disk_image_and_archive_extensions_recognized_not_unknown():
    # .rar/.vhd/.vhdx/.cab hit their own "no parser available" escalation
    # INSIDE the archive tool -- but the format itself is a recognized,
    # deliberately-handled one, not an unknown type, so this rule must not
    # also flag them (avoids double-counting the same fact two ways).
    for filename in ("data.rar", "disk.vhd", "disk.vhdx", "update.cab", "shortcut.lnk", "image.iso"):
        parsed = _email_with_attachment(filename)
        res = rules.RuleEngine().analyze(parsed)
        d = next(x for x in res["details"] if x["rule"] == "unrecognized_attachment_type")
        assert d["flagged"] is False, f"{filename} was incorrectly flagged as unrecognized"
