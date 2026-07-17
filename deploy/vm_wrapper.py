#!/usr/bin/env python3
"""vm_wrapper.py — minimal VM recovery wrapper for the attijari CAPE box.

Runs ON attijari (same operational pattern as cape.service). Exposes exactly
two actions over authenticated HTTP so the dashboard host never needs SSH:

    GET  /vm/status  -> {"cuckoo2": "<virsh domstate output>"}
    POST /vm/reset   -> virsh destroy cuckoo2 + systemctl restart cape.service

Auth: Authorization: Bearer $VM_WRAPPER_TOKEN (from the environment; the
service refuses every request when the token is unset — fail closed).

virsh/systemctl run via sudo with the tightly scoped sudoers entry shipped in
vm-wrapper-sudoers. Bind address must be the INTERNAL interface only (the
systemd unit sets VM_WRAPPER_BIND=192.168.100.10); default is loopback.
"""
import os
import subprocess
from functools import wraps

from flask import Flask, jsonify, request

TOKEN = os.environ.get("VM_WRAPPER_TOKEN", "")
# NOTE: if you change VM_WRAPPER_DOMAIN, /etc/sudoers.d/vm-wrapper must be
# updated in the same breath — it whitelists the exact command text
# ("virsh destroy cuckoo2"), so a renamed domain makes sudo prompt and fail.
DOMAIN = os.environ.get("VM_WRAPPER_DOMAIN", "cuckoo2")
BIND = os.environ.get("VM_WRAPPER_BIND", "127.0.0.1")
PORT = int(os.environ.get("VM_WRAPPER_PORT", "8090"))

app = Flask(__name__)


def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not TOKEN or auth != f"Bearer {TOKEN}":
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def _run(cmd, timeout=60):
    # A hung command must surface as clean JSON, never Flask's HTML 500 page.
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout: {' '.join(cmd)} exceeded {timeout}s"
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


@app.get("/vm/status")
@require_token
def vm_status():
    code, out, err = _run(["sudo", "virsh", "domstate", DOMAIN])
    if code != 0:
        return jsonify({"error": err or "virsh domstate failed"}), 500
    return jsonify({DOMAIN: out})


@app.post("/vm/reset")
@require_token
def vm_reset():
    detail = {}
    # 'domain is not running' from destroy is fine — the goal is "not running".
    code, out, err = _run(["sudo", "virsh", "destroy", DOMAIN], timeout=60)
    detail["virsh_destroy"] = {"code": code, "out": out, "err": err}
    code2, out2, err2 = _run(["sudo", "systemctl", "restart", "cape.service"],
                             timeout=120)
    detail["cape_restart"] = {"code": code2, "out": out2, "err": err2}
    ok = code2 == 0
    return jsonify({"success": ok, "detail": detail}), (200 if ok else 500)


if __name__ == "__main__":
    app.run(host=BIND, port=PORT)
