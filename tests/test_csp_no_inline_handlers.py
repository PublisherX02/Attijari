"""
Regression test for the Jul 10 incident: a CSP script-src change that silently
disabled every inline onclick/onchange handler in the dashboard for 3 days
because the app wasn't restarted. This test makes two independent guarantees
so the class of bug can't recur silently:
  1. No dashboard source file re-introduces an inline event-handler attribute.
  2. The CSP header's script-src directive is nonce-based, not unsafe-inline.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = REPO_ROOT / "src" / "dashboard"

INLINE_HANDLER_RE = re.compile(r'\bon(?:click|change|keydown|keyup|keypress|submit|input)\s*=\s*["\']')


def _dashboard_source_files():
    files = list((DASHBOARD_DIR / "templates").glob("*.html"))
    files += list((DASHBOARD_DIR / "static" / "js").glob("*.js"))
    return files


def test_no_inline_event_handler_attributes_remain():
    offenders = []
    for path in _dashboard_source_files():
        text = path.read_text(encoding="utf-8")
        for match in INLINE_HANDLER_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_no}")
    assert not offenders, f"Inline event-handler attributes found: {offenders}"


def test_csp_script_src_is_nonce_based_not_unsafe_inline():
    api_source = (REPO_ROOT / "src" / "api.py").read_text(encoding="utf-8")
    match = re.search(r'script-src[^;]*', api_source)
    assert match, "Could not find a script-src directive in src/api.py"
    directive = match.group(0)
    assert "'unsafe-inline'" not in directive, (
        "script-src still contains 'unsafe-inline' — nonce-based CSP was not applied "
        "(or was silently reverted, as happened on Jul 10)."
    )
    assert "nonce-" in directive, "script-src does not reference the per-request nonce"
