import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _FakeEmail:
    def __init__(self, status="pending_detonation"):
        self.id = 1
        self.status = status
        self.enrichment_result = {
            "body_text": "Bonjour, voici la facture jointe.",
            "headers": {"from": "a@b.com", "subject": "Facture"},
            "attachments_meta": [],
        }
        self.llm_result = {"verdict": "accepted", "confidence": 0.8}


class _FakeDB:
    def commit(self): pass


def test_cape_confirmed_malicious_pins_escalated_even_if_llm_says_accepted(monkeypatch):
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 8.5, "escalate": True, "suspicious": True,
                   "suspicious_behaviors": ["ransomware"], "cape_task_id": 42}

    def fake_analyze(body_text, model=None, skills_path_candidates=None, context=None):
        # LLM (wrongly) says accepted even though context carries the CAPE report
        assert "detonation" in (context.get("enrichment") or {})
        return {"verdict": "accepted", "confidence": 0.9, "risk_score": 10, "reasons": ["looks fine"]}

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    detonation._second_pass_verdict(_FakeDB(), email, cape_result)

    assert email.status == "escalated"
    assert email.llm_result.get("sandbox_confirmed_malicious") is True


def test_cape_clean_result_lets_llm_verdict_stand(monkeypatch):
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 0.5, "escalate": False, "suspicious": False, "cape_task_id": 43}

    def fake_analyze(body_text, model=None, skills_path_candidates=None, context=None):
        return {"verdict": "accepted", "confidence": 0.95, "risk_score": 5, "reasons": ["clean"]}

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    detonation._second_pass_verdict(_FakeDB(), email, cape_result)

    assert email.status == "accepted"


def test_second_pass_never_sets_quarantined(monkeypatch):
    """Even a maximally-malicious CAPE result must land on 'escalated', not
    'quarantined' — all rejections require human confirmation."""
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 10.0, "escalate": True, "suspicious": True, "cape_task_id": 44}

    def fake_analyze(body_text, model=None, skills_path_candidates=None, context=None):
        return {"verdict": "escalated", "confidence": 0.99, "risk_score": 99, "reasons": ["ransomware"]}

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    detonation._second_pass_verdict(_FakeDB(), email, cape_result)

    assert email.status == "escalated"
    assert email.status != "quarantined"


def test_second_pass_llm_crash_fails_safe_to_escalated(monkeypatch):
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 1.0, "escalate": False, "suspicious": False, "cape_task_id": 45}

    def fake_analyze(*a, **k):
        raise RuntimeError("ollama down")

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    detonation._second_pass_verdict(_FakeDB(), email, cape_result)

    assert email.status == "escalated"
