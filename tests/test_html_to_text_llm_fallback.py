"""test_html_to_text_llm_fallback.py — main.py's LLM analysis step built its
prompt input from `parsed.get("body_text") or ""` with no fallback -- an
HTML-only email (no text/plain part at all, the common case for real
phishing kits, which rarely bother with a plain-text alternative) meant the
LLM received a literally empty prompt, unable to reason about content at
all beyond structured signals. The deterministic phrase-matching rules in
rules.py (fixed separately, same session) only catch *known* phrases; the
LLM's holistic/creative-language judgment covered zero content for any such
email before this fix. New `email_extraction.html_to_text()` (stdlib-only,
no new dependency) strips tags/script/style and keeps visible text as a
fallback.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from email_extraction import html_to_text


def test_strips_tags_keeps_visible_text():
    result = html_to_text("<p>Your account will be <b>suspended</b>. Click here.</p>")
    assert "Your account will be" in result
    assert "suspended" in result
    assert "<p>" not in result and "<b>" not in result


def test_excludes_script_and_style_content():
    result = html_to_text(
        '<div><style>.x{color:red}</style><script>alert(document.cookie)</script>Hello world</div>'
    )
    assert "Hello world" in result
    assert "alert" not in result
    assert "color:red" not in result


def test_empty_and_none_input_returns_empty_string():
    assert html_to_text("") == ""
    assert html_to_text(None) == ""


def test_malformed_html_does_not_raise():
    # Unclosed tags, stray angle brackets -- must degrade gracefully, never crash.
    result = html_to_text("<p>unclosed <b>tag content < 5 chars")
    assert isinstance(result, str)


def test_anchor_link_text_preserved():
    result = html_to_text('<a href="http://evil.tld/x">Click here to verify</a>')
    assert "Click here to verify" in result
