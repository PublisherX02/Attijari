"""cape_client.py — Thin REST client for a CAPEv2 sandbox.

Talks to CAPE's apiv2 over HTTP. The host never runs the guest directly; it
just submits a sample, polls the task, and pulls the report. All email content
stays inside the isolated CAPE VM — only the file bytes are sent to the
local CAPE instance (not any external service), consistent with CLAUDE.md.

Uses the project's shared TLS-verified HTTP session (http_client) so we don't
re-implement certificate handling.
"""
from __future__ import annotations

import os
import time
from typing import Any, Optional

import requests

from detonation_config import (
    CAPE_API_URL, CAPE_API_TOKEN, CAPE_VERIFY_TLS,
    CAPE_HTTP_TIMEOUT, CAPE_POLL_INTERVAL, CAPE_TOTAL_TIMEOUT,
    CAPE_ANALYSIS_TIMEOUT, CAPE_READY_TIMEOUT, CAPE_ENFORCE_TIMEOUT,
    CAPE_MALSCORE_ESCALATE, CAPE_MALSCORE_SUSPICIOUS,
    CAPE_VM_WRAPPER_ENABLED, IMAGE_EXTENSIONS,
)


def _headers() -> dict[str, str]:
    h = {"Accept": "application/json"}
    if CAPE_API_TOKEN:
        h["Authorization"] = f"Token {CAPE_API_TOKEN}"
    return h


def is_available() -> bool:
    """Return True if the CAPE API answers. Cheap reachability probe."""
    try:
        r = requests.get(
            f"{CAPE_API_URL}/cuckoo/status/",
            headers=_headers(), timeout=CAPE_HTTP_TIMEOUT, verify=CAPE_VERIFY_TLS,
        )
        return r.status_code == 200
    except Exception:
        return False


def wait_until_ready(timeout: int) -> bool:
    """Poll the CAPE status endpoint until it responds or timeout elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_available():
            return True
        time.sleep(5)
    return False


def _preflight_cuckoo2() -> None:
    """Recover cuckoo2 if a previous run left it powered on before this
    submission — CAPE refuses 'tasks/create/file' unless the VM is found
    powered off. Wrapper disabled/unreachable -> log and proceed: a failed
    submission below still escalates the email safely (fail-safe, never
    fail-open); never block submission on the wrapper.
    """
    if not CAPE_VM_WRAPPER_ENABLED:
        return
    try:
        import cape_vm_wrapper
        state = cape_vm_wrapper.cuckoo2_state()
        if state == "running":
            print("[CAPE] cuckoo2 left running — destroy + CAPE restart via wrapper before submit")
            if cape_vm_wrapper.reset_cuckoo2():
                wait_until_ready(CAPE_READY_TIMEOUT)
            else:
                print("[CAPE] cuckoo2 reset failed — proceeding anyway (fail-safe)")
    except Exception as e:
        print(f"[CAPE] cuckoo2 pre-flight skipped: {e}")


def submit_file(file_path: str, filename: str) -> Optional[int]:
    """Submit a sample for analysis. Returns the CAPE task id, or None on error."""
    _preflight_cuckoo2()
    try:
        with open(file_path, "rb") as fh:
            files = {"file": (filename, fh)}
            data = {
                "timeout": CAPE_ANALYSIS_TIMEOUT,
                # enforce_timeout=False lets CAPE end the analysis as soon as
                # monitored activity stops instead of always burning the full
                # ceiling — same max depth, less wasted wall-clock time.
                "enforce_timeout": CAPE_ENFORCE_TIMEOUT,
                # keep it lean: no extra options that spawn more guests
            }
            ext = os.path.splitext(filename or "")[1].lower()
            if ext in IMAGE_EXTENSIONS:
                data["package"] = "image"
            r = requests.post(
                f"{CAPE_API_URL}/tasks/create/file/",
                headers=_headers(), files=files, data=data,
                timeout=CAPE_HTTP_TIMEOUT, verify=CAPE_VERIFY_TLS,
            )
        if r.status_code not in (200, 201):
            return None
        payload = r.json()
        # CAPE returns {"error": false, "data": {"task_ids": [N]}} or {"task_id": N}
        data = payload.get("data", payload)
        if isinstance(data, dict):
            if data.get("task_ids"):
                return int(data["task_ids"][0])
            if data.get("task_id"):
                return int(data["task_id"])
        return None
    except Exception:
        return None


def _task_status(task_id: int) -> Optional[str]:
    try:
        r = requests.get(
            f"{CAPE_API_URL}/tasks/status/{task_id}/",
            headers=_headers(), timeout=CAPE_HTTP_TIMEOUT, verify=CAPE_VERIFY_TLS,
        )
        if r.status_code != 200:
            return None
        payload = r.json()
        data = payload.get("data", payload)
        if isinstance(data, dict):
            return data.get("status")
        if isinstance(data, str):
            return data
        return None
    except Exception:
        return None


def wait_for_report(task_id: int) -> bool:
    """Block until the task reaches a terminal state. True if reported OK."""
    deadline = time.time() + CAPE_TOTAL_TIMEOUT
    while time.time() < deadline:
        status = _task_status(task_id)
        if status in ("reported", "completed"):
            return True
        if status in ("failed_analysis", "failed_processing", "failed"):
            return False
        time.sleep(CAPE_POLL_INTERVAL)
    return False  # timed out


def fetch_report(task_id: int) -> Optional[dict[str, Any]]:
    """Fetch the concise report for a finished task."""
    for view in ("report/{}/json", "report/{}"):
        try:
            r = requests.get(
                f"{CAPE_API_URL}/tasks/get/{view.format(task_id)}/",
                headers=_headers(), timeout=CAPE_HTTP_TIMEOUT * 2, verify=CAPE_VERIFY_TLS,
            )
            if r.status_code == 200:
                payload = r.json()
                return payload.get("data", payload)
        except Exception:
            continue
    return None


def parse_report(report: dict[str, Any], task_id: int) -> dict[str, Any]:
    """Map a CAPE report into the pipeline's detonation-result format."""
    info = report.get("info", {}) if isinstance(report, dict) else {}
    malscore = info.get("score")
    if malscore is None:
        malscore = report.get("malscore", 0) if isinstance(report, dict) else 0
    try:
        malscore = float(malscore)
    except (TypeError, ValueError):
        malscore = 0.0

    signatures = report.get("signatures", []) if isinstance(report, dict) else []
    sig_names = []
    for s in signatures:
        if isinstance(s, dict) and s.get("name"):
            sig_names.append(s.get("description") or s.get("name"))

    behavior = report.get("behavior", {}) if isinstance(report, dict) else {}
    processes = behavior.get("processes", []) if isinstance(behavior, dict) else []
    network = report.get("network", {}) if isinstance(report, dict) else {}

    escalate = malscore >= CAPE_MALSCORE_ESCALATE
    suspicious = malscore >= CAPE_MALSCORE_SUSPICIOUS or bool(sig_names)

    return {
        "tool": "detonation",
        "detonated": True,
        "status": "ok",
        "cape_task_id": task_id,
        # Dashboard-proxied path (the browser can never reach CAPE directly)
        "web_report_url": f"/api/detonation/report/{task_id}/",
        "malscore": malscore,
        "risk_score": int(min(malscore * 10, 100)),   # 0–10 → 0–100
        "suspicious": suspicious,
        "escalate": escalate,
        "suspicious_behaviors": sig_names[:30],
        "processes_spawned": len(processes) if isinstance(processes, list) else 0,
        "network_hosts": len(network.get("hosts", [])) if isinstance(network, dict) else 0,
        "summary": info.get("category", ""),
    }


def _get_json(path: str) -> Optional[Any]:
    """GET a CAPE apiv2 JSON endpoint. Returns None on transport failure,
    non-200, or a CAPE-level `{"error": true, ...}` response (several apiv2
    endpoints return 200 with an error body when the feature is disabled in
    CAPE's own api.conf — confirmed live: machines/list, machines/view, and
    tasks/get/mitmdump all do this on this deployment rather than 403/404)."""
    try:
        r = requests.get(
            f"{CAPE_API_URL}/{path}",
            headers=_headers(), timeout=CAPE_HTTP_TIMEOUT, verify=CAPE_VERIFY_TLS,
        )
        if r.status_code != 200:
            return None
        payload = r.json()
        if isinstance(payload, dict) and payload.get("error"):
            return None
        return payload.get("data", payload) if isinstance(payload, dict) else payload
    except Exception:
        return None


def list_machines() -> Optional[list[dict]]:
    """List CAPE's registered analysis VMs. None if unavailable OR if the
    machines-list API is disabled on this CAPE instance (its own config
    choice, not a client-side restriction)."""
    return _get_json("machines/list/")


def view_machine(name: str) -> Optional[dict]:
    """Detail view for one analysis VM (state, platform, tags, ...)."""
    return _get_json(f"machines/view/{name}/")


def list_tasks(limit: Optional[int] = None, offset: Optional[int] = None) -> Optional[list[dict]]:
    """Most recent CAPE tasks, newest first. `limit`/`offset` map onto CAPE's
    own `tasks/list/<limit>/<offset>/` path segments (confirmed live — CAPE
    paginates by count, there is no server-side "last N days" filter)."""
    path = "tasks/list/"
    if limit is not None:
        path += f"{int(limit)}/"
        if offset is not None:
            path += f"{int(offset)}/"
    return _get_json(path)


def fetch_task_mitmdump(task_id: int) -> Optional[bytes]:
    """Raw mitmdump/HAR capture for a task's decrypted TLS traffic, if CAPE's
    mitmdump download API is enabled for this deployment (it returns a 200
    JSON `{"error": true, ...}` body instead of the file when disabled — we
    treat that the same as unavailable rather than returning the error JSON
    as if it were file content)."""
    try:
        r = requests.get(
            f"{CAPE_API_URL}/tasks/get/mitmdump/{int(task_id)}/",
            headers=_headers(), timeout=CAPE_HTTP_TIMEOUT * 2, verify=CAPE_VERIFY_TLS,
        )
        if r.status_code != 200:
            return None
        ctype = r.headers.get("content-type", "")
        if ctype.split(";")[0].strip().lower() == "application/json":
            return None
        return r.content
    except Exception:
        return None


def detonate(file_path: str, filename: str) -> dict[str, Any]:
    """Full single-sample cycle: submit → wait → fetch → parse.

    Fail-safe: any error returns suspicious=True so the email still reaches a
    human analyst rather than being silently accepted.
    """
    task_id = submit_file(file_path, filename)
    if task_id is None:
        return {"tool": "detonation", "detonated": False, "status": "error",
                "error": "cape_submit_failed", "suspicious": True, "escalate": True}

    if not wait_for_report(task_id):
        return {"tool": "detonation", "detonated": True, "status": "error",
                "error": "cape_analysis_timeout_or_failed", "cape_task_id": task_id,
                "suspicious": True, "escalate": True}

    report = fetch_report(task_id)
    if report is None:
        return {"tool": "detonation", "detonated": True, "status": "error",
                "error": "cape_report_unavailable", "cape_task_id": task_id,
                "suspicious": True, "escalate": True}

    return parse_report(report, task_id)
