import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import analysis


def _llm_json(claim_verdict: dict, **overrides) -> str:
    base = {
        "sender_risk": 5, "intent_classification": "legitimate claim",
        "social_engineering_indicators": [], "risk_score": 5,
        "confidence": 0.9, "verdict": "accepted", "reasons": ["clean"],
        "claim_verdict": claim_verdict,
    }
    base.update(overrides)
    return json.dumps(base)


def test_complete_minor_claim_gets_automated_settlement(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Minor bumper scrape in parking lot",
        "damage_classes": ["scratch"], "severity_estimate": "minor",
        "full_report": "Small scratch on rear bumper, cosmetic only.",
        "urgency": "low", "urgency_reasoning": "Minor cosmetic damage, no injuries.",
        "settlement_recommendation": "Approve for direct repair, no adjuster needed.",
    }
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "I scraped my bumper in a parking lot.",
        context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert cv["missing_information"] == []
    assert cv["settlement_type"] == "automated"
    assert cv["damage_source"] == "text_only"  # no cv_damage context, no image_bytes passed


def test_missing_policy_number_forces_assistive_settlement(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": None,
        "policy_type": "auto", "incident_description": "Minor scrape",
        "damage_classes": ["scratch"], "severity_estimate": "minor",
        "full_report": "Small scratch.", "urgency": "low",
        "urgency_reasoning": "Minor.", "settlement_recommendation": "Approve.",
    }
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "I scraped my bumper.", context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert "policy_number" in cv["missing_information"]
    assert cv["settlement_type"] == "assistive"


def test_missing_photo_is_reported_and_blocks_automation(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Minor scrape",
        "damage_classes": [], "severity_estimate": "minor",
        "full_report": "No photo provided.", "urgency": "low",
        "urgency_reasoning": "Minor per description.", "settlement_recommendation": "Request photos.",
    }
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "I scraped my bumper.", context={"claim_photo_present": False},
    )
    cv = result["claim_verdict"]
    assert "photo" in cv["missing_information"]
    assert cv["settlement_type"] == "assistive"


def test_severe_damage_never_auto_settles_even_if_complete(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Major collision",
        "damage_classes": ["frame_damage", "airbag_deployed"], "severity_estimate": "severe",
        "full_report": "Severe front-end damage.", "urgency": "critical",
        "urgency_reasoning": "Severe structural damage.", "settlement_recommendation": "Send to adjuster immediately.",
    }
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "My car was in a major accident.", context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert cv["settlement_type"] == "assistive"
    assert cv["urgency"] == "critical"


def test_unparseable_urgency_defaults_to_high_not_low(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Some damage",
        "damage_classes": [], "severity_estimate": "minor",
        "full_report": "Report.", "urgency": "not_a_real_level",
        "urgency_reasoning": "n/a", "settlement_recommendation": "n/a",
    }
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "Something happened to my car.", context={"claim_photo_present": True},
    )
    assert result["claim_verdict"]["urgency"] == "high"


def test_cv_damage_context_grounds_damage_source(monkeypatch):
    claim = {
        "policyholder_name": "Jane Doe", "policy_number": "POL-123",
        "policy_type": "auto", "incident_description": "Dent on door",
        "damage_classes": ["dent"], "severity_estimate": "minor",
        "full_report": "Dent confirmed.", "urgency": "low",
        "urgency_reasoning": "Minor.", "settlement_recommendation": "Approve.",
    }
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: _llm_json(claim))
    result = analysis.analyze_email_body(
        "Dent on my car door.",
        context={
            "claim_photo_present": True,
            "cv_damage": {"tool": "cv_damage", "status": "ok", "damage_detected": True,
                          "damage_classes": ["dent"], "confidence": 0.9, "severity_estimate": "moderate"},
        },
    )
    assert result["claim_verdict"]["damage_source"] == "cv_model"


def test_missing_claim_verdict_key_fails_safe_to_needs_review(monkeypatch):
    # LLM returns a valid security verdict but omits claim_verdict entirely
    payload = json.dumps({
        "sender_risk": 5, "intent_classification": "unknown", "social_engineering_indicators": [],
        "risk_score": 5, "confidence": 0.9, "verdict": "accepted", "reasons": [],
    })
    monkeypatch.setattr(analysis, "is_payload_safe", lambda body: True)
    monkeypatch.setattr(analysis, "_call_ollama_client", lambda model, prompt, **kw: payload)
    result = analysis.analyze_email_body(
        "Some claim text.", context={"claim_photo_present": True},
    )
    cv = result["claim_verdict"]
    assert cv["urgency"] == "high"  # ClaimVerdict() default, never silently low
    assert cv["settlement_type"] == "assistive"
    assert set(["policyholder_name", "policy_number", "policy_type", "incident_description"]) <= set(cv["missing_information"])
