"""test_rules_hidden_json_redirect.py — a redirect hidden in a <meta
http-equiv="refresh"> tag needs no JavaScript, no <script> tag, no HTML
event-handler attribute, and no <a href> at all -- so it was invisible to
every rule that checks for those things (html_smuggling's own sibling
patterns, text_body_script_payload, xss_header_injection) AND invisible to
the two rules purpose-built for hidden/masked links
(_find_hidden_destination_links, _find_href_text_mismatches), both of which
bail out immediately unless the HTML contains an "<a" tag. Confirmed live
before this fix: a neutral-worded email whose only payload is a
meta-refresh to a phishing lookalike domain returned "accepted" with zero
rules flagged.

Also covers the two related, already-working paths this session confirmed
by direct testing (not assumed): a redirect URL sitting in a <script
type="application/json"> blob (no <a> tag, no visible button) IS already
caught, but via html_smuggling's pre-existing "<script" pattern rather than
any URL-aware rule; and a bare HTML event-handler attribute (onerror=)
driving the same kind of redirect without any <script> tag IS already
caught via xss_header_injection's event-handler pattern list.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def _email(body_html: str) -> dict:
    return {
        "headers": {"from": "sender@example.com", "to": "victim@example.com",
                     "subject": "Votre dossier", "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": body_html,
    }


def test_meta_refresh_redirect_is_flagged_http_equiv_first():
    parsed = _email(
        '<p>Bonjour, merci de consulter le document ci-joint.</p>'
        '<meta http-equiv="refresh" content="0;url=http://totally-legit-paypal.security-verify.tld/login">'
    )
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "html_smuggling"]
    assert flagged and flagged[0]["flagged"] is True
    assert "meta-refresh-redirect" in flagged[0]["reason"]
    assert "totally-legit-paypal.security-verify.tld" in flagged[0]["reason"]
    assert res["verdict"] == "proposed_reject"


def test_meta_refresh_redirect_is_flagged_content_attribute_first():
    # Attribute order in the raw HTML must not matter.
    parsed = _email(
        '<p>Bonjour.</p>'
        '<meta content="0;url=http://evil-lookalike.tld/x" http-equiv="refresh">'
    )
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "html_smuggling"]
    assert flagged and flagged[0]["flagged"] is True
    assert "evil-lookalike.tld" in flagged[0]["reason"]


def test_meta_refresh_with_neutral_wording_no_longer_sails_through_clean():
    # The exact regression this fix closes: no reward-lure vocabulary, no
    # urgency language -- before the fix this returned "accepted" with
    # zero rules flagged.
    parsed = _email(
        '<p>Bonjour, merci de consulter le document ci-joint concernant votre dossier.</p>'
        '<meta http-equiv="refresh" content="0;url=http://totally-legit-paypal.security-verify.tld/login">'
    )
    res = rules.RuleEngine().analyze(parsed)
    assert res["verdict"] != "accepted"


def test_benign_html_without_meta_refresh_not_flagged():
    parsed = _email("<p>Bonjour, voici la facture du mois.</p>")
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "html_smuggling"]
    assert flagged and flagged[0]["flagged"] is False


def test_ordinary_meta_tags_not_falsely_flagged():
    # A bare <meta charset=...> / viewport tag must never trip this --
    # only http-equiv=refresh specifically.
    parsed = _email(
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width">'
        '<p>Bonjour, voici la facture du mois.</p>'
    )
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "html_smuggling"]
    assert flagged and flagged[0]["flagged"] is False


def test_json_redirect_inside_script_tag_already_caught_via_script_pattern():
    parsed = _email(
        '<p>Felicitations! Vous avez gagne une reduction de 33%.</p>'
        '<script type="application/json" id="cfg">'
        '{"target": "http://totally-legit-paypal.security-verify.tld/login"}'
        '</script>'
        '<script>var c=JSON.parse(document.getElementById("cfg").textContent);'
        'window.location.href=c.target;</script>'
    )
    res = rules.RuleEngine().analyze(parsed)
    flagged_rules = {d["rule"] for d in res["details"] if d["flagged"]}
    assert "html_smuggling" in flagged_rules
    assert res["verdict"] == "proposed_reject"


def test_event_handler_redirect_without_script_tag_already_caught():
    parsed = _email(
        '<p>Felicitations! Vous avez gagne une reduction de 33%.</p>'
        '<img src="x" data-cfg=\'{"target":"http://totally-legit-paypal.security-verify.tld/login"}\' '
        'onerror="window.location=JSON.parse(this.getAttribute(&quot;data-cfg&quot;)).target">'
    )
    res = rules.RuleEngine().analyze(parsed)
    flagged_rules = {d["rule"] for d in res["details"] if d["flagged"]}
    assert "xss_header_injection" in flagged_rules
    assert res["verdict"] == "proposed_reject"


def test_json_url_extracted_into_body_urls_regardless_of_wrapping_tag():
    # extract_signals' raw regex scan sees any http(s):// substring in
    # body_html regardless of whether it's inside an <a>, a <script>-JSON
    # blob, or plain text -- this feeds feed_malicious_url/dnstwist even
    # for links this file's dedicated hidden-link rules can't see.
    body_html = (
        '<script type="application/json">'
        '{"target": "http://totally-legit-paypal.security-verify.tld/login"}'
        '</script>'
    )
    parsed = _email(body_html)
    signals = rules.extract_signals(parsed)
    assert "http://totally-legit-paypal.security-verify.tld/login" in signals["body_urls"]
