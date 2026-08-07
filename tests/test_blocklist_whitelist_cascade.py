"""test_blocklist_whitelist_cascade.py — CLAUDE.md: "Whitelist override
always wins" and "never auto-block shared infrastructure IPs (Gmail,
Outlook relays)". Zero existing test coverage for either claim before this
file — both are explicit, non-negotiable statements in CLAUDE.md's
cascading-blocklist section, verified here against the real DB (matching
this project's established pattern for blocklist/whitelist tests) rather
than assumed correct from a code read.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

import rules
from database import (
    SessionLocal, Blocklist, Whitelist, add_blocklist_entry,
    is_whitelisted,
)


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _cleanup_blocklist_whitelist():
    yield
    db = SessionLocal()
    try:
        db.query(Blocklist).filter(Blocklist.value.like("%.pytest-cascade-test.tld")).delete(synchronize_session=False)
        db.query(Whitelist).filter(Whitelist.value.like("%.pytest-cascade-test.tld")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    rules._blocklist_cache_time = 0.0  # force a fresh reload next call


def test_whitelisted_domain_overrides_existing_domain_block_at_rules_engine(db):
    domain = "evil.pytest-cascade-test.tld"
    add_blocklist_entry(db, "domain", domain, source="manual")
    rules._blocklist_cache_time = 0.0

    parsed_blocked = {
        "headers": {"from": f"someone@{domain}", "to": "v@e.com", "subject": "x", "message-id": "<x@x>"},
        "attachments": [], "body_text": "", "body_html": "",
    }
    res = rules.RuleEngine().analyze(parsed_blocked)
    d = next(x for x in res["details"] if x["rule"] == "blocklist_domain")
    assert d["flagged"] is True, "blocklist_domain must fire before whitelisting"

    db.add(Whitelist(indicator_type="domain", value=domain, active=True))
    db.commit()
    rules._blocklist_cache_time = 0.0

    res2 = rules.RuleEngine().analyze(parsed_blocked)
    d2 = next(x for x in res2["details"] if x["rule"] == "blocklist_domain")
    assert d2["flagged"] is False, "whitelist override must win for a domain-level block"
    assert "whitelisted override" in d2["reason"]


def test_whitelisting_domain_does_not_override_a_specific_sender_block(db):
    # CLAUDE.md's intent is "don't block ALL of gmail.com for one scammer's
    # address" -- the inverse must also hold: whitelisting a shared domain
    # must not silently clear an individually-confirmed-malicious sender
    # address on that same domain.
    domain = "shared.pytest-cascade-test.tld"
    sender = f"scammer@{domain}"
    add_blocklist_entry(db, "email", sender, source="manual")
    db.add(Whitelist(indicator_type="domain", value=domain, active=True))
    db.commit()
    rules._blocklist_cache_time = 0.0

    parsed = {
        "headers": {"from": sender, "to": "v@e.com", "subject": "x", "message-id": "<x@x>"},
        "attachments": [], "body_text": "", "body_html": "",
    }
    res = rules.RuleEngine().analyze(parsed)
    d = next(x for x in res["details"] if x["rule"] == "blocklist_domain")
    assert d["flagged"] is True, "a whitelisted domain must not clear a specifically-blocked sender address"


def test_add_blocklist_entry_refuses_a_whitelisted_indicator(db):
    domain = "preemptive.pytest-cascade-test.tld"
    db.add(Whitelist(indicator_type="domain", value=domain, active=True))
    db.commit()

    added = add_blocklist_entry(db, "domain", domain, source="cascade")
    assert added is False, "whitelist must win even at add-time, not just at rules-engine evaluation time"

    still_blocked = db.query(Blocklist).filter(Blocklist.value == domain, Blocklist.active == True).first()
    assert still_blocked is None


def test_cascade_blocklist_skips_shared_infrastructure_ip():
    from rules import cascade_blocklist, is_shared_infrastructure_ip

    gmail_ip = "74.125.20.1"  # Google/Gmail relay range
    real_malicious_ip = "203.0.113.77"  # TEST-NET-3, not a shared-infra prefix
    assert is_shared_infrastructure_ip(gmail_ip) is True
    assert is_shared_infrastructure_ip(real_malicious_ip) is False

    cascade_blocklist(
        sender_email="attacker@pytest-cascade-test.tld",
        sender_domain=None,
        ips=[gmail_ip, real_malicious_ip],
        hashes=None,
    )

    db = SessionLocal()
    try:
        gmail_entry = db.query(Blocklist).filter(Blocklist.value == gmail_ip).first()
        assert gmail_entry is None, "a shared-infrastructure IP (Gmail relay) must never be auto-blocked"
        real_entry = db.query(Blocklist).filter(Blocklist.value == real_malicious_ip).first()
        assert real_entry is not None, "a genuinely non-shared malicious IP must still be blocked"
        db.query(Blocklist).filter(Blocklist.value == real_malicious_ip).delete()
        db.query(Blocklist).filter(Blocklist.value == "attacker@pytest-cascade-test.tld").delete()
        db.commit()
    finally:
        db.close()
