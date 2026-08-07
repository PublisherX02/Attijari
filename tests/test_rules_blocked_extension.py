"""test_rules_blocked_extension.py — BLOCKED_EXTENSIONS previously covered
Windows-native executables/scripts (.exe/.js/.vbs/.scr/.bat/.ps1/.jar/.msi/
.cmd/.com) but not interpreter scripts like .py, despite being the same
"runs arbitrary code on open" risk class. A tutor/evaluator testing this
pipeline asked directly what happens when a .py file is sent -- before this
fix, the answer was: nothing, it passed straight through to markitdown's
plain-text extraction with no escalation. Also covers .vbe/.jse/.wsf/.hta,
which extraction.py's _SCRIPT_EXTS already escalated but the earlier
rules-engine stage never blocked, so the two layers disagreed on the same
attachment.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rules


def _email_with_attachment(filename: str) -> dict:
    return {
        "headers": {"from": "sender@example.com", "to": "victim@example.com",
                     "subject": "please review", "message-id": "<x@x>"},
        "attachments": [{"original_name": filename, "sha256": "a" * 64}],
        "body_text": "See attached.",
        "body_html": "",
    }


def test_py_attachment_is_blocked_extension_hard_evidence():
    parsed = _email_with_attachment("invoice.py")
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "blocked_extension"]
    assert flagged and flagged[0]["flagged"] is True
    assert res["verdict"] == "proposed_reject"


def test_pyw_sh_rb_pl_php_are_all_blocked():
    for filename in ("script.pyw", "run.sh", "tool.rb", "script.pl", "shell.php"):
        parsed = _email_with_attachment(filename)
        res = rules.RuleEngine().analyze(parsed)
        flagged = [d for d in res["details"] if d["rule"] == "blocked_extension"]
        assert flagged and flagged[0]["flagged"] is True, f"{filename} was not blocked"


def test_vbe_jse_wsf_hta_now_blocked_at_rules_stage_too():
    # Previously only extraction.py's _SCRIPT_EXTS caught these -- confirm
    # the rules engine (which runs first, per CLAUDE.md's stage ordering)
    # now agrees rather than letting them through as "accepted" only to be
    # escalated later by a different layer.
    for filename in ("payload.vbe", "payload.jse", "payload.wsf", "payload.hta"):
        parsed = _email_with_attachment(filename)
        res = rules.RuleEngine().analyze(parsed)
        flagged = [d for d in res["details"] if d["rule"] == "blocked_extension"]
        assert flagged and flagged[0]["flagged"] is True, f"{filename} was not blocked"


def test_benign_docx_not_blocked():
    parsed = _email_with_attachment("report.docx")
    res = rules.RuleEngine().analyze(parsed)
    flagged = [d for d in res["details"] if d["rule"] == "blocked_extension"]
    assert flagged and flagged[0]["flagged"] is False
