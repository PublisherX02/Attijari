"""detonation.py — Memory-gated CAPE detonation orchestrator (host side).

Design (see detonation_config.py):
  - Detonation is RARE: only inconclusive-static + unsure-LLM samples are queued.
  - Detonation runs in a DRAINED window so the CAPE Ubuntu VM never competes for
    RAM with Ollama / Llama Guard / Docker on one 16 GB machine:

        1. Set the global "detonation active" flag (poller/scheduler/scan pause).
        2. Unload Ollama models (keep_alive=0) and release the Llama Guard model.
        3. Stop Docker (frees the WSL2 backend).
        4. Resume the CAPE Ubuntu VM (Hyper-V Save-state → Start) and wait for API.
        5. Submit each queued sample to CAPE, poll, fetch + parse the report,
           update the email record.
        6. Suspend the VM, restart Docker, clear the flag.

  A watchdog guarantees step 6's teardown ALWAYS runs — even on crash or
  timeout — so the pipeline can never be left permanently paused
  (fail-safe, never fail-open).

CAPE install/config lives on a separate Ubuntu VM; this module only speaks to it
over the REST API (see cape_client.py).
"""
from __future__ import annotations

import os
import subprocess
import time
from typing import Any

import detonation_config as cfg
import detonation_state as state
import cape_client
from analysis import analyze_email_body


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, timeout: int = 60) -> bool:
    """Run a host shell command. Returns True on exit 0. Never raises."""
    if not cmd:
        return True
    try:
        # shell=True is intentional: cmd comes from trusted operator config
        # (detonation_config / env), never from user input.
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)  # nosec B602
        if r.returncode != 0:
            print(f"[DETONATION] cmd failed ({r.returncode}): {cmd}\n  {r.stderr.strip()[:300]}")
        return r.returncode == 0
    except Exception as e:
        print(f"[DETONATION] cmd error: {cmd} — {e}")
        return False


def should_detonate(filename: str) -> bool:
    ext = os.path.splitext(filename or "")[1].lower()
    return ext in cfg.SUPPORTED_EXTENSIONS


def is_available() -> bool:
    """Cheap check used by main.py at startup for operator visibility."""
    return cape_client.is_available()


# ---------------------------------------------------------------------------
# Resource management (drain / restore)
# ---------------------------------------------------------------------------

def _unload_ollama() -> None:
    """Unload every currently-loaded Ollama model via keep_alive=0."""
    if not cfg.DETONATION_UNLOAD_OLLAMA:
        return
    try:
        import requests
        r = requests.get(f"{cfg.OLLAMA_BASE_URL}/api/ps", timeout=10)
        models = [m.get("name") or m.get("model") for m in r.json().get("models", [])] if r.ok else []
        for m in filter(None, models):
            try:
                requests.post(
                    f"{cfg.OLLAMA_BASE_URL}/api/generate",
                    json={"model": m, "keep_alive": 0}, timeout=15,
                )
                print(f"[DETONATION] Unloaded Ollama model: {m}")
            except Exception as e:
                print(f"[DETONATION] Could not unload {m}: {e}")
    except Exception as e:
        print(f"[DETONATION] Ollama unload skipped: {e}")


def _free_guard() -> None:
    if not cfg.DETONATION_FREE_GUARD:
        return
    try:
        from analysis import free_guard_model
        free_guard_model()
    except Exception as e:
        print(f"[DETONATION] Guard release skipped: {e}")


def _stop_docker() -> None:
    if cfg.DETONATION_STOP_DOCKER and cfg.DOCKER_STOP_CMD:
        print("[DETONATION] Stopping Docker/WSL2 backend...")
        _run(cfg.DOCKER_STOP_CMD, timeout=120)


def _start_docker() -> None:
    if not (cfg.DETONATION_STOP_DOCKER and cfg.DOCKER_START_CMD):
        return
    print("[DETONATION] Restarting Docker...")
    # Launch Docker Desktop detached; then wait for the daemon to answer.
    try:
        subprocess.Popen(cfg.DOCKER_START_CMD, shell=True)  # nosec B602 — trusted config command
    except Exception as e:
        print(f"[DETONATION] Docker start failed to launch: {e}")
        return
    deadline = time.time() + cfg.DOCKER_READY_TIMEOUT
    while time.time() < deadline:
        try:
            r = subprocess.run(["docker", "info"], capture_output=True, timeout=8)
            if r.returncode == 0:
                print("[DETONATION] Docker is back up")
                return
        except Exception:
            pass
        time.sleep(5)
    print("[DETONATION] WARNING: Docker did not confirm ready within timeout")


def _preflight_cuckoo2() -> None:
    """Recover cuckoo2 if a previous run left it powered on.

    Runs after the imania VM is up and CAPE answers, before submitting the
    batch — prevents CAPE's 'Trying to start a virtual machine that has not
    been turned off' failure. Wrapper disabled/unreachable → log and proceed:
    a failed submission escalates safely; never block the drain window.
    """
    if not cfg.CAPE_VM_WRAPPER_ENABLED:
        return
    try:
        import cape_vm_wrapper
        st = cape_vm_wrapper.cuckoo2_state()
        print(f"[DETONATION] cuckoo2 pre-flight state: {st}")
        if st == "running":
            print("[DETONATION] cuckoo2 left running — destroy + CAPE restart via wrapper")
            if cape_vm_wrapper.reset_cuckoo2():
                if not cape_client.wait_until_ready(cfg.CAPE_READY_TIMEOUT):
                    print("[DETONATION] CAPE not ready after cuckoo2 reset — proceeding (fail-safe)")
            else:
                print("[DETONATION] cuckoo2 reset failed — proceeding (fail-safe)")
    except Exception as e:
        print(f"[DETONATION] cuckoo2 pre-flight skipped: {e}")


def _resume_vm() -> bool:
    if not cfg.DETONATION_MANAGE_VM:
        ok = cape_client.is_available()
        if ok:
            _preflight_cuckoo2()
        return ok
    print(f"[DETONATION] Resuming CAPE VM '{cfg.CAPE_VM_NAME}'...")
    if not _run(cfg.VM_RESUME_CMD, timeout=120):
        print(f"[DETONATION] VM resume command failed — '{cfg.CAPE_VM_NAME}' was likely never started "
              f"(check Hyper-V permissions for the account running this process)")
    if not cape_client.wait_until_ready(cfg.CAPE_READY_TIMEOUT):
        print("[DETONATION] CAPE API did not become ready after VM resume")
        return False
    print("[DETONATION] CAPE API ready")
    _preflight_cuckoo2()
    return True


def _suspend_vm() -> None:
    if cfg.DETONATION_MANAGE_VM and cfg.VM_SUSPEND_CMD:
        print(f"[DETONATION] Suspending CAPE VM '{cfg.CAPE_VM_NAME}' to free RAM...")
        _run(cfg.VM_SUSPEND_CMD, timeout=120)


def _drain() -> None:
    """Free host memory before detonation."""
    _unload_ollama()
    _free_guard()
    _stop_docker()


def _restore() -> None:
    """Always-runs teardown: suspend VM, bring Docker back. Ollama reloads lazily."""
    try:
        _suspend_vm()
    finally:
        _start_docker()


# ---------------------------------------------------------------------------
# Queue processing
# ---------------------------------------------------------------------------

def _process_one(row) -> dict[str, Any]:
    """Detonate a single queued sample and return the parsed result."""
    fname = row.filename or "sample.bin"
    path = row.stored_path
    if not path or not os.path.exists(path):
        return {"tool": "detonation", "detonated": False, "status": "error",
                "error": "stored_file_missing", "suspicious": True, "escalate": True}
    print(f"[DETONATION] Detonating {fname} (sha {row.sha256[:12]}...) via CAPE")
    return cape_client.detonate(path, fname)


def _second_pass_verdict(db, email, result: dict) -> None:
    """Re-run LLM analysis with the CAPE report folded in. Sets email.status
    to 'accepted' or 'escalated' ONLY — never 'quarantined'/'released'
    (CLAUDE.md: all rejections require human confirmation; those two
    statuses are analyst-only actions on an already-escalated email).
    A CAPE-confirmed-malicious result always pins the verdict to
    'escalated', matching the existing rule that deterministic signals
    can't be overridden by the LLM."""
    enr = email.enrichment_result or {}
    body_text = enr.get("body_text") or ""
    context = {
        "headers": enr.get("headers") or {},
        "attachments": enr.get("attachments_meta") or [],
        "enrichment": {"detonation": result},
    }

    try:
        llm_res = analyze_email_body(body_text, context=context)
        raw_verdict = (llm_res.get("verdict") or "").lower().strip()
        llm_says_accepted = raw_verdict in ("accepter", "accepted", "accept", "clean", "safe")
    except Exception as e:
        print(f"[DETONATION] Second-pass LLM analysis failed: {e} -> ESCALATED (fail-safe)")
        llm_says_accepted = False
        llm_res = {"verdict": "escalated", "reasons": [f"second_pass_error: {e}"]}

    cape_malicious = bool(result.get("escalate")) or (
        result.get("malscore") is not None and result["malscore"] >= cfg.CAPE_MALSCORE_ESCALATE
    )

    if cape_malicious or not llm_says_accepted:
        email.status = "escalated"
        if cape_malicious:
            llm_res["sandbox_confirmed_malicious"] = True
    else:
        email.status = "accepted"

    email.llm_result = llm_res
    db.commit()


def _apply_result_to_email(db, row, result: dict[str, Any]) -> None:
    """Fold the detonation verdict back into the email record + audit log."""
    from database import Email, add_audit_entry
    if not row.email_id:
        return
    email = db.query(Email).filter(Email.id == row.email_id).first()
    if not email:
        return

    enrichment = dict(email.enrichment_result or {})
    enrichment["detonation"] = result
    email.enrichment_result = enrichment
    try:
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(email, "enrichment_result")
    except Exception:
        pass

    if result.get("escalate") and email.status not in ("quarantined", "released"):
        email.status = "escalated"
    db.commit()

    if email.status == "pending_detonation":
        try:
            _second_pass_verdict(db, email, result)
        except Exception as e:
            # Fail-safe: never leave an email stuck on pending_detonation.
            email.status = "escalated"
            db.commit()
            print(f"[DETONATION] Second-pass verdict crashed: {e} -> ESCALATED (fail-safe)")

    try:
        add_audit_entry(
            db, action="detonation_complete", actor="system", email_id=row.email_id,
            details={
                "sha256": row.sha256,
                "malscore": result.get("malscore"),
                "risk_score": result.get("risk_score"),
                "escalate": result.get("escalate"),
                "cape_task_id": result.get("cape_task_id"),
                "behaviors": result.get("suspicious_behaviors", [])[:10],
            },
        )
    except Exception:
        pass


def process_detonation_queue() -> dict[str, Any]:
    """Drain the queue in one memory-freed window. Safe no-op if nothing queued.

    Returns a summary dict. Guaranteed to restore the pipeline via the watchdog
    pattern (try/finally) regardless of how any single detonation fails.
    """
    from database import (
        SessionLocal, get_queued_detonations, count_queued_detonations,
        recover_stale_running_detonations,
    )

    db = SessionLocal()
    try:
        # A 'running' row can only legitimately stay that way for one drain
        # cycle; anything older survived a crashed/restarted server process
        # and would otherwise block re-queueing the same file forever
        # (enqueue_detonation de-dupes on queued/running). Opportunistic
        # cleanup — must never break the drain, so a failure here is swallowed.
        try:
            recover_stale_running_detonations(db, cfg.DETONATION_CYCLE_TIMEOUT + 300)
        except Exception as _rec_err:
            print(f"[DETONATION] stale-row recovery skipped: {_rec_err}")
        if count_queued_detonations(db) == 0:
            return {"processed": 0, "status": "empty"}
    finally:
        db.close()

    if not state.try_begin("processing detonation queue"):
        return {"processed": 0, "status": "already_running"}

    summary = {"processed": 0, "escalated": 0, "errors": 0, "status": "ok"}
    cycle_deadline = time.time() + cfg.DETONATION_CYCLE_TIMEOUT
    print("[DETONATION] === Entering drained detonation window ===")

    try:
        _drain()
        if not _resume_vm():
            summary["status"] = "cape_unavailable"
            # Fail-safe: escalate everything still queued so nothing is silently accepted.
            _escalate_all_queued("cape_unavailable")
            return summary

        # One item at a time, re-querying the queue before each pick, so a
        # priority row inserted while something else is detonating (the
        # analyst's "insist" action, or a fresh always-on enqueue) is picked
        # up right after the CURRENT item finishes — never interrupting it.
        # The VM stays resumed across the whole run; only an empty queue that
        # stays empty for DETONATION_IDLE_TIMEOUT_SECONDS closes the window.
        last_activity = time.time()
        while True:
            if time.time() > cycle_deadline:
                print("[DETONATION] Cycle timeout — stopping window early")
                summary["status"] = "cycle_timeout"
                break

            db = SessionLocal()
            try:
                rows = get_queued_detonations(db, limit=1)
                row = rows[0] if rows else None

                if row is None:
                    idle_for = time.time() - last_activity
                    if idle_for > cfg.DETONATION_IDLE_TIMEOUT_SECONDS:
                        print(f"[DETONATION] Queue empty for {idle_for:.0f}s — closing window")
                        break
                    db.close()
                    time.sleep(cfg.DETONATION_IDLE_POLL_SECONDS)
                    continue

                row.status = "running"
                row.attempts = (row.attempts or 0) + 1
                db.commit()

                try:
                    result = _process_one(row)
                except Exception as e:
                    result = {"tool": "detonation", "detonated": False, "status": "error",
                              "error": f"orchestrator_crash: {e}", "suspicious": True, "escalate": True}

                row.result = result
                row.status = "error" if result.get("status") == "error" else "done"
                db.commit()

                _apply_result_to_email(db, row, result)

                summary["processed"] += 1
                if result.get("escalate"):
                    summary["escalated"] += 1
                if result.get("status") == "error":
                    summary["errors"] += 1
            finally:
                db.close()

            last_activity = time.time()

        return summary

    except Exception as e:
        print(f"[DETONATION] Window crashed: {e}")
        summary["status"] = f"crash: {e}"
        return summary
    finally:
        _restore()
        state.end()
        print(f"[DETONATION] === Detonation window closed: {summary} ===")


def _escalate_all_queued(reason: str) -> None:
    """Fail-safe: when CAPE is unreachable, escalate every queued email so a
    human still reviews it, and drop the samples from the queue."""
    from database import SessionLocal, PendingDetonation, Email, add_audit_entry
    db = SessionLocal()
    try:
        rows = db.query(PendingDetonation).filter(PendingDetonation.status == "queued").all()
        for row in rows:
            row.status = "error"
            row.result = {"status": "error", "error": reason, "escalate": True}
            if row.email_id:
                email = db.query(Email).filter(Email.id == row.email_id).first()
                if email and email.status not in ("quarantined", "released"):
                    email.status = "escalated"
        db.commit()
        if rows:
            add_audit_entry(db, action="detonation_unavailable", actor="system",
                            details={"reason": reason, "escalated_count": len(rows)})
            print(f"[DETONATION] CAPE unavailable — escalated {len(rows)} queued email(s) for review")
    except Exception as e:
        print(f"[DETONATION] Fail-safe escalation error: {e}")
    finally:
        db.close()
