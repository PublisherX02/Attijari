"""test_rules_brand_impersonation.py — one of the single most common
real-world phishing tactics: the From display name claims a well-known
brand ("PayPal Support", "Microsoft Security Team") while the actual
sender address belongs to an unrelated domain. Distinct from
internal_domain_spoof (Rule 13), which only checks claims of this bank's
own internal domain.

Legitimate-pattern cases are drawn from real senders already present in
this project's own production database (Facebook notification emails via
facebookmail.com, Meta security emails via account.meta.com) rather than
invented -- verifying this rule doesn't flag traffic this pipeline
actually receives.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def _check(from_header: str):
    parsed = {
        "headers": {"from": from_header, "to": "victim@example.com",
                     "subject": "x", "message-id": "<x@x>"},
        "attachments": [], "body_text": "", "body_html": "",
    }
    res = rules.RuleEngine().analyze(parsed)
    return next(x for x in res["details"] if x["rule"] == "brand_impersonation_display_name")


def test_paypal_impersonation_from_unrelated_domain_flagged():
    d = _check("PayPal Support <random123@totally-unrelated-domain.tld>")
    assert d["flagged"] is True
    assert "paypal" in d["reason"]


def test_microsoft_impersonation_flagged():
    d = _check("Microsoft Security Team <attacker@evil.tld>")
    assert d["flagged"] is True


def test_dhl_impersonation_flagged():
    d = _check("DHL Delivery <noreply@dhl-tracking-secure.tld>")
    assert d["flagged"] is True


def test_real_facebook_notification_pattern_not_flagged():
    # Real pattern from this project's own DB, not invented.
    d = _check("Ahmed sur Facebook <close_friend_updates@facebookmail.com>")
    assert d["flagged"] is False


def test_real_facebook_priority_subdomain_not_flagged():
    d = _check("Facebook <notification@priority.facebookmail.com>")
    assert d["flagged"] is False


def test_real_meta_security_subdomain_not_flagged():
    d = _check("Meta Account Security <security@account.meta.com>")
    assert d["flagged"] is False


def test_genuine_paypal_sender_not_flagged():
    d = _check("PayPal <service@paypal.com>")
    assert d["flagged"] is False


def test_no_brand_mention_not_flagged():
    d = _check("John Smith <john.smith@example.com>")
    assert d["flagged"] is False
