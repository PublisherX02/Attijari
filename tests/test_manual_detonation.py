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


# ---------------------------------------------------------------------------
# Task 2 — detonation.manual permission
# ---------------------------------------------------------------------------

def test_detonation_manual_permission_registered():
    import database as db
    assert "detonation.manual" in db.ALL_PERMISSIONS
    # Off by default for non-admin roles — admin must grant it explicitly
    assert "detonation.manual" not in db.ANALYST_PERMISSIONS
    assert "detonation.manual" not in db.VIEWER_PERMISSIONS


def test_detonation_manual_permission_enforced():
    import database as db

    class U:
        def __init__(self, role, perms):
            self.role = role
            self.permissions = perms

    assert db.user_has_permission(U("admin", {}), "detonation.manual") is True
    assert db.user_has_permission(U("analyst", {}), "detonation.manual") is False
    assert db.user_has_permission(U("analyst", {"detonation.manual": True}), "detonation.manual") is True
