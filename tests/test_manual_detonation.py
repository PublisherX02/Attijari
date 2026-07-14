"""Tests for the Manual Detonation page — operator-driven arbitrary-file detonation.

Hermetic host-side tests (no live DB, network, or CAPE): pure-logic functions
and monkeypatched collaborators, matching tests/test_detonation.py and
tests/test_cape_dashboard.py.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# Task 1 — CAPE_DETONABLE_EXTENSIONS
# ---------------------------------------------------------------------------

def test_cape_detonable_extensions_present():
    import detonation_config as cfg
    ext = cfg.CAPE_DETONABLE_EXTENSIONS
    # CAPE-supported types are accepted
    for e in (".exe", ".dll", ".docx", ".xlsx", ".pdf", ".js", ".msg", ".eml", ".iso", ".vhd", ".one", ".hwp"):
        assert e in ext, f"{e} should be detonable"
    # Non-detonable types are absent
    for e in (".txt", ".png", ".mp3", ".csv"):
        assert e not in ext
    # All entries are lowercase and dot-prefixed
    assert all(x.startswith(".") and x == x.lower() for x in ext)
