"""test_rules_masked_link.py — "hidden URL" phishing: a link whose displayed
text names one domain but whose actual href points somewhere else entirely,
e.g. <a href="http://evil.tld/x">https://paypal.com/login</a>. Before this,
nothing in the pipeline compared displayed link text to the real href
target — URL extraction elsewhere treats HTML source as flat regex-matched
text, so it happens to catch both strings as separate body_urls entries,
but never links "claims to be X" to "actually goes to Y"."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def test_masked_link_detected():
    html = ('<html><body>Click <a href="http://evil-lookalike.tld/login">'
            'https://www.paypal.com/login</a> now</body></html>')
    mismatches = rules._find_href_text_mismatches(html)
    assert len(mismatches) == 1
    assert mismatches[0]["displayed_domain"] == "paypal.com"
    assert mismatches[0]["actual_host"] == "evil-lookalike.tld"


def test_matching_link_text_and_href_not_flagged():
    html = ('<html><body><a href="https://www.paypal.com/login">'
            'https://www.paypal.com/login</a></body></html>')
    assert rules._find_href_text_mismatches(html) == []


def test_generic_link_text_not_flagged():
    # "here" doesn't name a domain -- nothing to compare against, so this
    # must not be flagged (would otherwise false-positive on nearly every
    # legitimate email that uses "click here" style link text).
    html = '<html><body><a href="http://evil-lookalike.tld/login">here</a></body></html>'
    assert rules._find_href_text_mismatches(html) == []


def test_safe_link_proxy_excluded():
    # Microsoft Safe Links / Proofpoint / Mimecast legitimately show the
    # original destination as link text while routing the real href through
    # their own scanning domain -- that's the proxy working as designed.
    html = ('<html><body><a href="https://safelinks.protection.outlook.com/?url=xyz">'
            'https://paypal.com/login</a></body></html>')
    assert rules._find_href_text_mismatches(html) == []


def test_mailto_link_not_flagged():
    # A mailto: link displaying an email address (e.g. "user@gmail.com")
    # would otherwise false-positive: the text-domain regex matches
    # "gmail.com" inside the address with no real href host to compare.
    html = '<html><body><a href="mailto:user@gmail.com">user@gmail.com</a></body></html>'
    assert rules._find_href_text_mismatches(html) == []


def test_no_html_body_returns_empty():
    assert rules._find_href_text_mismatches("") == []
    assert rules._find_href_text_mismatches(None) == []


def test_multi_label_tld_same_domain_not_flagged():
    # last-two-labels alone would reduce "paypal.co.uk" to "co.uk" and
    # incorrectly treat any two .co.uk links as a mismatch.
    html = ('<a href="https://www.paypal.co.uk/login">'
            'https://www.paypal.co.uk/login</a>')
    assert rules._find_href_text_mismatches(html) == []


def test_multi_label_tld_genuine_mismatch_still_caught():
    html = ('<a href="http://evil.tld/login">'
            'https://www.paypal.co.uk/login</a>')
    mismatches = rules._find_href_text_mismatches(html)
    assert len(mismatches) == 1
    assert mismatches[0]["actual_host"] == "evil.tld"


def test_masked_link_is_hard_evidence_end_to_end():
    parsed = {
        "headers": {"from": "Alex Hunter <alex@example.com>", "to": "victim@example.com",
                    "subject": "test", "message-id": "<x@x>"},
        "attachments": [],
        "body_text": "",
        "body_html": ('<html><body>Click <a href="http://evil-lookalike.tld/login">'
                       'https://www.paypal.com/login</a></body></html>'),
    }
    engine = rules.RuleEngine()
    res = engine.analyze(parsed)
    assert res["verdict"] == "proposed_reject"
    masked = [d for d in res["details"] if d["rule"] == "masked_link_mismatch"]
    assert masked and masked[0]["flagged"] is True
