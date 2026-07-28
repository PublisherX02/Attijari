import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _install_fake_enqueue(monkeypatch):
    calls = []

    def fake_enqueue(db, sha256, stored_path, filename=None, email_id=None,
                     idempotency_key=None, reason=None, created_by=None,
                     priority=False, status="queued"):
        calls.append({"sha256": sha256, "filename": filename, "reason": reason})
        return None

    monkeypatch.setattr("database.enqueue_detonation", fake_enqueue)
    return calls


def test_clean_looking_attachment_still_enqueues(monkeypatch):
    """Today's gate requires llm_unsure or static_suspicious. The new gate
    must enqueue ANY detonation_candidate, even a confident-clean one."""
    import main
    calls = _install_fake_enqueue(monkeypatch)
    parsed = {
        "llm_analysis": {"confidence": 0.99},  # LLM very sure -> old gate would skip
        "extraction": {"results": [
            {"detonation_candidate": True, "suspicious": False,
             "sha256": "a" * 64, "filename": "invoice.pdf"},
        ]},
        "attachments": [{"sha256": "a" * 64, "stored_path": "/tmp/invoice.pdf"}],
        "idempotency_key": "key1",
    }
    main._maybe_enqueue_detonation(db=object(), parsed=parsed, email_id=1,
                                    deterministic_escalation=False)
    assert len(calls) == 1
    assert calls[0]["sha256"] == "a" * 64


def test_deterministically_escalated_email_never_enqueues(monkeypatch):
    import main
    calls = _install_fake_enqueue(monkeypatch)
    parsed = {
        "extraction": {"results": [
            {"detonation_candidate": True, "sha256": "b" * 64, "filename": "x.exe"},
        ]},
        "attachments": [{"sha256": "b" * 64, "stored_path": "/tmp/x.exe"}],
        "idempotency_key": "key2",
    }
    main._maybe_enqueue_detonation(db=object(), parsed=parsed, email_id=2,
                                    deterministic_escalation=True)
    assert calls == []


def test_non_candidate_attachment_never_enqueues(monkeypatch):
    """detonation_candidate is already False for rules-engine-rejected
    attachments (extraction.py:753-758) — confirms the gate still respects it."""
    import main
    calls = _install_fake_enqueue(monkeypatch)
    parsed = {
        "extraction": {"results": [
            {"detonation_candidate": False, "sha256": "c" * 64, "filename": "y.exe"},
        ]},
        "attachments": [{"sha256": "c" * 64, "stored_path": "/tmp/y.exe"}],
        "idempotency_key": "key3",
    }
    main._maybe_enqueue_detonation(db=object(), parsed=parsed, email_id=3,
                                    deterministic_escalation=False)
    assert calls == []
