"""test_rules_hidden_url_tactic.py — the "hidden URL" phishing tactic where
a link's destination is never disclosed to the reader at all (generic
"click here"/"lien" text, no domain claim) paired with a lure/urgency
signal already present on the same email.

Distinct from masked_link_mismatch (tests/test_rules_masked_link.py), which
requires the text to make a FALSE domain claim. This rule covers the case
where no claim is made at all -- found while investigating a real test
email ("vous avez gagné une réduction... [lien]") where the link text was
just "lien" (French for "link"), so masked_link_mismatch correctly didn't
fire, but nothing else named the concealment tactic itself either.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def test_generic_link_text_alone_not_flagged():
    # A bare "click here" is completely ordinary in legitimate marketing.
    html = '<a href="http://example-shop.com/deal">click here</a>'
    hidden = rules._find_hidden_destination_links(html)
    assert len(hidden) == 1  # detected structurally...
    parsed = {
        "headers": {"from": "a@example.com", "to": "b@example.com",
                    "subject": "", "message-id": "<x@x>"},
        "attachments": [], "body_text": "Check out our new spring sale.",
        "body_html": html,
    }
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "hidden_url_phishing_tactic"]
    assert flagged and flagged[0]["flagged"] is False  # ...but not treated as phishing alone


def test_opaque_link_plus_reward_lure_is_hard_evidence():
    # Reproduces the real "La Gargoulette" test email: opaque "lien" text,
    # no domain claim, paired with reward-lure vocabulary.
    parsed = {
        "headers": {"from": "Alex Hunter <halex5307@gmail.com>",
                    "to": "victim@example.com", "subject": "", "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": (
            "<p>Vous avez gagné une réduction de 33% avec notre partenaire.</p>"
            "<p>Cliquez sur le lien ci-dessous :</p>"
            '<p><a href="http://lagargoulette.com/?rid=bJnotte">lien</a></p>'
            "<p>Le bon d’achat est valable jusqu’au 31 décembre.</p>"
        ),
    }
    res = rules.RuleEngine().analyze(parsed)
    assert res["verdict"] == "proposed_reject"
    flagged = [d for d in res["details"] if d["rule"] == "hidden_url_phishing_tactic"]
    assert flagged and flagged[0]["flagged"] is True
    assert "hidden URL" in flagged[0]["reason"]
    assert "lagargoulette.com" in flagged[0]["reason"]


def test_domain_disclosing_link_not_double_counted():
    # If the text already names a (possibly lying) domain, that's
    # masked_link_mismatch's job, not this rule's -- must not double-flag.
    html = ('<a href="http://evil.tld/login">'
            'https://www.attijaribank.com.tn/moncompte</a>')
    assert rules._find_hidden_destination_links(html) == []


def test_opaque_link_without_lure_not_flagged():
    parsed = {
        "headers": {"from": "a@example.com", "to": "b@example.com",
                    "subject": "", "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": '<p>See the report</p><a href="http://example.com/report">here</a>',
    }
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "hidden_url_phishing_tactic"]
    assert flagged and flagged[0]["flagged"] is False
