"""Tests for the Insurance Operator role — read-only like viewer, but scoped
to claim/insurance data with none of the cybersecurity-only surfaces
(blocklist, whitelist, security alerts, audit/action history).
"""
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_insurance_operator_registered_in_role_defaults():
    import database as db
    assert "insurance_operator" in db.ROLE_DEFAULTS
    perms = db.ROLE_DEFAULTS["insurance_operator"]
    assert perms is db.INSURANCE_OPERATOR_PERMISSIONS


def test_insurance_operator_has_no_cybersecurity_permissions():
    import database as db
    perms = db.INSURANCE_OPERATOR_PERMISSIONS
    for cyber_perm in ("blocklist.view", "blocklist.manage", "whitelist.view",
                        "whitelist.manage", "alerts.view", "alerts.acknowledge",
                        "audit.view"):
        assert cyber_perm not in perms, f"{cyber_perm} is a cybersecurity permission, must not be granted"


def test_insurance_operator_can_view_claims():
    import database as db
    perms = db.INSURANCE_OPERATOR_PERMISSIONS
    assert perms.get("emails.view") is True


def test_insurance_operator_is_read_only_like_viewer():
    """'nearly the same privileges as a viewer' — no release/quarantine/override
    action permissions, matching the viewer's read-only power level."""
    import database as db
    perms = db.INSURANCE_OPERATOR_PERMISSIONS
    for action_perm in ("emails.release", "emails.quarantine", "emails.override",
                          "emails.revert", "emails.bulk", "emails.scan",
                          "users.manage", "detonation.manual"):
        assert action_perm not in perms


def test_insurance_operator_permission_enforced():
    import database as db

    class U:
        def __init__(self, role, perms):
            self.role = role
            self.permissions = perms

    u = U("insurance_operator", db.INSURANCE_OPERATOR_PERMISSIONS)
    assert db.user_has_permission(u, "emails.view") is True
    assert db.user_has_permission(u, "blocklist.view") is False
    assert db.user_has_permission(u, "audit.view") is False


def test_create_user_request_accepts_insurance_operator_role():
    from routers.users import CreateUserRequest
    req = CreateUserRequest(username="ins_op1", password="password123", role="insurance_operator")
    assert req.role == "insurance_operator"


def test_update_user_request_accepts_insurance_operator_role():
    from routers.users import UpdateUserRequest
    req = UpdateUserRequest(role="insurance_operator")
    assert req.role == "insurance_operator"
