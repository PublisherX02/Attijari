"""test_extraction_nested_email.py — an email attached inside another email
(message/rfc822, or a raw .eml dropped in as a generic file) has no deep-scan
path: this pipeline's rules/URL/sender-domain checks only ever run against
the *outer* email's own headers/body, never recurse into a nested message.
A malicious link or spoofed sender living only inside the attached email is
therefore invisible to every existing check. Two things must hold:

1. email_extraction.py must not crash trying to hash the nested message as
   if it were raw bytes (part.get_content() returns an EmailMessage object
   for message/rfc822, not bytes/str) -- it must store/hash/name it like any
   other attachment instead of losing the real filename to a generic
   "parse_failed" error.
2. extraction.py must then deliberately escalate it, matching the
   OneNote/RAR "no parser available" fail-safe pattern, rather than letting
   MarkItDown's generic text extraction create false confidence that the
   nested content was actually examined.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email.message import EmailMessage
from email import policy

import extraction
from email_extraction import EmailIngestion


def _build_forwarded_phishing_email() -> bytes:
    inner = EmailMessage()
    inner["From"] = "phisher@evil-lookalike.tld"
    inner["To"] = "victim@example.com"
    inner["Subject"] = "URGENT: verify your account"
    inner.set_content("Click here: http://totally-legit-paypal.security-verify.tld/login")

    outer = EmailMessage(policy=policy.default)
    outer["From"] = "Alex Hunter <halex5307@gmail.com>"
    outer["To"] = "mohamedmouelhi2005@gmail.com"
    outer["Subject"] = "Fwd: check this out"
    outer.set_content("See attached email")
    outer.add_attachment(inner.as_bytes(), maintype="message", subtype="rfc822",
                          filename="forwarded.eml")
    return outer.as_bytes()


def test_nested_email_attachment_is_captured_not_crashed():
    ing = EmailIngestion(host="x", user="x", password="x")
    result = ing.parse_email(_build_forwarded_phishing_email())

    assert result["parse_errors"] == []
    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["original_name"] == "forwarded.eml"
    assert att["declared_type"] == "message/rfc822"
    assert len(att["sha256"]) == 64


def test_nested_email_attachment_escalates_via_extraction(tmp_path):
    f = tmp_path / "forwarded.eml"
    f.write_bytes(b"From: phisher@evil.tld\r\nSubject: test\r\n\r\nbody")
    att = {"stored_path": str(f), "original_name": "forwarded.eml",
           "declared_type": "message/rfc822", "real_type": "message/rfc822",
           "sha256": "a" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("nested_email_attachment" in fl for fl in res["flags"])


def test_eml_by_extension_alone_also_escalates(tmp_path):
    # declared/real type unknown (e.g. sent as application/octet-stream),
    # only the .eml extension is present -- must still escalate.
    f = tmp_path / "forwarded_message.eml"
    f.write_bytes(b"From: phisher@evil.tld\r\nSubject: test\r\n\r\nbody")
    att = {"stored_path": str(f), "original_name": "forwarded_message.eml",
           "declared_type": "application/octet-stream",
           "real_type": "application/octet-stream", "sha256": "b" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("nested_email_attachment" in fl for fl in res["flags"])


def test_full_pipeline_escalates_email_with_nested_phishing_attachment():
    ing = EmailIngestion(host="x", user="x", password="x")
    parsed = ing.parse_email(_build_forwarded_phishing_email())
    assert parsed["status"] != "escalated"  # not escalated at parse time

    ext = extraction.extract_all_attachments(parsed)
    assert ext["escalate"] is True
