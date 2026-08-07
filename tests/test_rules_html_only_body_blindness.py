"""test_rules_html_only_body_blindness.py — phishy_body (Rule 4),
vishing_callback (Rule 12), and thread_hijack_bec's financial-keyword check
all built their phrase-matching text from `body_text` alone, defined before
`combined_body_lower` (body_text + body_html) existed anywhere in this file
-- Rules 25/27/27b were fixed later to combine both, but the fix was never
backported to these three. An HTML-only email (no text/plain part at all --
the common real-world case for phishing kits, which rarely bother with a
plain-text alternative) made `body` an empty string, silently blinding all
three rules to content that would be caught instantly if the identical
wording appeared in body_text instead. Confirmed live before this fix with
word-for-word identical urgency+credential-targeting content.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def test_phishy_body_fires_on_html_only_email():
    parsed = {
        "headers": {"from": "a@b.tld", "to": "v@e.com", "subject": "Account Alert",
                     "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": "<p>Your account will be suspended. Click here to verify your account immediately.</p>",
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "phishy_body")
    assert d["flagged"] is True


def test_phishy_body_still_fires_on_text_only_email():
    # Regression guard: the fix must not have broken the original path.
    parsed = {
        "headers": {"from": "a@b.tld", "to": "v@e.com", "subject": "Account Alert",
                     "message-id": "<x@x>"},
        "attachments": [],
        "body_text": "Your account will be suspended. Click here to verify your account immediately.",
        "body_html": "",
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "phishy_body")
    assert d["flagged"] is True


def test_phishy_body_not_flagged_on_benign_html_only_email():
    parsed = {
        "headers": {"from": "a@b.tld", "to": "v@e.com", "subject": "Newsletter",
                     "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": "<p>Here is our monthly newsletter with product updates.</p>",
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "phishy_body")
    assert d["flagged"] is False


def test_vishing_callback_fires_on_html_only_email():
    parsed = {
        "headers": {"from": "ext@vendor.tld", "to": "v@e.com", "subject": "x",
                     "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": ("<p>Your subscription was renewed for $49.99. If you do not "
                      "recognize this charge, call 555-123-4567 to cancel.</p>"),
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "vishing_callback")
    assert d["flagged"] is True


def test_bec_financial_keywords_fire_on_html_only_email():
    parsed = {
        "headers": {"from": "ext@vendor.tld", "to": "v@e.com",
                     "subject": "Changement de coordonnees bancaires",
                     "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": "<p>Merci de mettre a jour nos coordonnees bancaires (nouveau RIB) pour le prochain virement.</p>",
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "thread_hijack_bec")
    assert d["flagged"] is True
