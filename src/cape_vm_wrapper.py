"""cape_vm_wrapper.py — HTTP client for the imania VM wrapper service.

The wrapper is a tiny authenticated HTTP service running ON the imania VM
(source: deploy/vm_wrapper.py). It exposes the cuckoo2 guest's
libvirt state and a destroy+restart-CAPE recovery action. The host never
shells into imania over SSH; this client is the only control path.

Fail-safe contract: every function swallows errors and returns None/False.
The caller must treat "wrapper unreachable" as "log and proceed" — a failed
submission escalates the queued emails to a human anyway (never fail-open,
never block the drain window on the wrapper).
"""
from __future__ import annotations

from typing import Optional

import requests

from detonation_config import (
    CAPE_VM_WRAPPER_ENABLED, CAPE_VM_WRAPPER_URL,
    CAPE_VM_WRAPPER_TOKEN, CAPE_VM_WRAPPER_TIMEOUT,
)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {CAPE_VM_WRAPPER_TOKEN}"}


def cuckoo2_state() -> Optional[str]:
    """Return `virsh domstate` of cuckoo2 ('running', 'shut off', ...) or None."""
    if not CAPE_VM_WRAPPER_ENABLED:
        return None
    try:
        r = requests.get(
            f"{CAPE_VM_WRAPPER_URL}/vm/status",
            headers=_headers(), timeout=CAPE_VM_WRAPPER_TIMEOUT,
        )
        if r.status_code != 200:
            return None
        payload = r.json() or {}
        return payload.get("cuckoo2")
    except Exception:
        return None


def reset_cuckoo2() -> bool:
    """`virsh destroy cuckoo2` + `systemctl restart cape.service`. True on success."""
    if not CAPE_VM_WRAPPER_ENABLED:
        return False
    try:
        r = requests.post(
            f"{CAPE_VM_WRAPPER_URL}/vm/reset",
            headers=_headers(), timeout=CAPE_VM_WRAPPER_TIMEOUT * 3,
        )
        return r.status_code == 200
    except Exception:
        return False
