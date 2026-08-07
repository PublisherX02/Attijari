"""test_rules_reward_lure.py — reward/prize/lottery-lure phishing ("vous
avez gagné une réduction de 33%... cliquez sur le lien") is a distinct
social-engineering family that phishy_body's urgency+targeting phrase
pairing was never designed to catch (there's no threat of account
suspension, and "claim your discount" isn't credential/wire-transfer
targeting language).

Also covers the accent-normalization bug found while building this: every
French phrase list in rules.py is written in plain ASCII ("compte a ete
suspendu"), which never matches real accented French text ("compte a été
suspendu") or typographic curly apostrophes ("d’achat") without first
stripping diacritics and normalizing quotes -- a real, previously-silent
gap affecting every existing French phrase rule, not just this new one.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def test_normalize_strips_accents_and_curly_quotes():
    assert rules._normalize_for_phrase_match("gagné") == "gagne"
    assert rules._normalize_for_phrase_match("d’achat") == "d'achat"
    assert rules._normalize_for_phrase_match("étudiant") == "etudiant"


def test_reward_lure_requires_two_hits():
    parsed = {
        "headers": {"from": "a@example.com", "to": "b@example.com",
                    "subject": "", "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": "<p>Vous avez gagné un prix incroyable.</p>",
    }
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "reward_lure_phishing"]
    assert flagged and flagged[0]["flagged"] is False


def test_reward_lure_two_hits_with_real_accented_french_is_hard_evidence():
    # Reproduces the real email that motivated this rule: accented French
    # ("gagné") plus a curly-apostrophe contraction ("d’achat") -- both
    # must survive normalization for the phrase match to fire at all.
    parsed = {
        "headers": {"from": "Alex Hunter <halex5307@gmail.com>",
                    "to": "victim@example.com", "subject": "", "message-id": "<x@x>"},
        "attachments": [], "body_text": "",
        "body_html": (
            "<p>Vous avez gagné une réduction de 33% avec notre partenaire.</p>"
            "<p>Le bon d’achat est valable jusqu’au 31 décembre.</p>"
        ),
    }
    res = rules.RuleEngine().analyze(parsed)
    assert res["verdict"] == "proposed_reject"
    flagged = [d for d in res["details"] if d["rule"] == "reward_lure_phishing"]
    assert flagged and flagged[0]["flagged"] is True


def test_single_generic_word_not_flagged():
    # A lone "reduction"/"discount" mention is common in legitimate
    # marketing and must not trip this alone.
    parsed = {
        "headers": {"from": "a@example.com", "to": "b@example.com",
                    "subject": "", "message-id": "<x@x>"},
        "attachments": [], "body_text": "Profitez de notre reduction de printemps.",
        "body_html": "",
    }
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "reward_lure_phishing"]
    assert flagged and flagged[0]["flagged"] is False
