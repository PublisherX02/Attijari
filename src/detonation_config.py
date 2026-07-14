"""detonation_config.py — CAPEv2 detonation sandbox configuration.

The detonation subsystem is DEFERRED / MEMORY-GATED:
  - Files are sent to CAPE only when static analysis (YARA / oletools / pdfid /
    extraction) was inconclusive AND the LLM was unsure (low confidence).
  - Detonation runs in a *drained* window: Ollama models + Llama Guard are
    unloaded and Docker is stopped first, so the CAPE Ubuntu VM never competes
    for RAM with the rest of the pipeline on a single 16 GB machine.

CAPE itself runs on a separate Ubuntu VM (KVM guest). The host only talks to it
over the CAPE REST API. All values are overridable via environment variables.
"""
from __future__ import annotations

import os

# --------------------------------------------------------------------------
# CAPE REST API (Ubuntu VM)
# --------------------------------------------------------------------------
# Base URL of the CAPE apiv2 endpoint, e.g. http://192.168.56.10:8000/apiv2
CAPE_API_URL = os.getenv("CAPE_API_URL", "http://127.0.0.1:8000/apiv2").rstrip("/")
# Token issued by CAPE (web UI → API tokens). Sent as `Authorization: Token <t>`.
CAPE_API_TOKEN = os.getenv("CAPE_API_TOKEN", "")
# Verify TLS if CAPE is served over https (set to "0" for self-signed lab certs).
CAPE_VERIFY_TLS = os.getenv("CAPE_VERIFY_TLS", "1") != "0"

# --------------------------------------------------------------------------
# Timeouts (seconds)
# --------------------------------------------------------------------------
CAPE_ANALYSIS_TIMEOUT = int(os.getenv("CAPE_ANALYSIS_TIMEOUT", "180"))   # in-guest run time
CAPE_POLL_INTERVAL = int(os.getenv("CAPE_POLL_INTERVAL", "10"))          # how often to poll task status
CAPE_TOTAL_TIMEOUT = int(os.getenv("CAPE_TOTAL_TIMEOUT", "600"))         # give up on one sample after this
CAPE_HTTP_TIMEOUT = int(os.getenv("CAPE_HTTP_TIMEOUT", "30"))            # per HTTP request

# Hard ceiling on one full drain→detonate→restore cycle. The watchdog restores
# the pipeline no matter what once this elapses (fail-safe, never fail-open).
DETONATION_CYCLE_TIMEOUT = int(os.getenv("DETONATION_CYCLE_TIMEOUT", "1800"))  # 30 min

# Max samples to process in one drained window before restoring the pipeline,
# so ingestion is never starved for too long when the queue is large.
DETONATION_BATCH_SIZE = int(os.getenv("DETONATION_BATCH_SIZE", "5"))

# --------------------------------------------------------------------------
# Verdict mapping (CAPE malscore is 0–10)
# --------------------------------------------------------------------------
# malscore >= this  → treat as malicious → escalate the email
CAPE_MALSCORE_ESCALATE = float(os.getenv("CAPE_MALSCORE_ESCALATE", "6.0"))
# malscore >= this  → mark suspicious (surfaced to analyst, not auto-escalated)
CAPE_MALSCORE_SUSPICIOUS = float(os.getenv("CAPE_MALSCORE_SUSPICIOUS", "3.0"))

# --------------------------------------------------------------------------
# Which file types are worth detonating
# --------------------------------------------------------------------------
SUPPORTED_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".msi", ".msp",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".ppsx", ".ppsm", ".rtf",
    ".pdf",
    ".zip", ".rar", ".7z",
    ".lnk", ".jar",
}

# --------------------------------------------------------------------------
# Manual-detonation page: the FULL set CAPEv2 can detonate (broader than the
# curated auto-detonate SUPPORTED_EXTENSIONS above). Derived from CAPEv2's
# analysis-package extension map (docs usage/packages.html). Operators may
# submit any of these; CAPE aborts anything it can't handle, so we reject
# unsupported types up front. Override via env (comma-separated) to match the
# specific CAPE guest's installed packages.
# --------------------------------------------------------------------------
_DEFAULT_CAPE_DETONABLE = {
    ".mdb", ".accdb", ".class", ".iso", ".vhd", ".chm", ".url", ".cpl", ".dll",
    ".doc", ".docm", ".docx", ".eml", ".exe", ".hta", ".hwp", ".jar",
    ".js", ".jse", ".lnk", ".mht", ".build", ".msg", ".msi", ".nsis", ".one",
    ".pdf", ".ppt", ".pptm", ".pptx", ".ps1", ".pub", ".pubx", ".py", ".rar",
    ".reg", ".scr", ".sct", ".swf", ".vbs", ".vbe", ".wsf",
    ".xls", ".xlsm", ".xlsx", ".xslt", ".xps", ".zip",
}
_env_ext = os.getenv("CAPE_DETONABLE_EXTENSIONS", "").strip()
CAPE_DETONABLE_EXTENSIONS = (
    {e if e.startswith(".") else "." + e for e in
     (x.strip().lower() for x in _env_ext.split(",")) if e}
    if _env_ext else _DEFAULT_CAPE_DETONABLE
)

# --------------------------------------------------------------------------
# Resource management — commands run on the WINDOWS HOST to free memory
# before detonation and restore afterwards. Each is a shell command string;
# set to "" to disable that step. Tune these to YOUR exact setup.
# --------------------------------------------------------------------------

# Toggle whole steps
DETONATION_UNLOAD_OLLAMA = os.getenv("DETONATION_UNLOAD_OLLAMA", "1") != "0"
DETONATION_FREE_GUARD = os.getenv("DETONATION_FREE_GUARD", "1") != "0"
DETONATION_STOP_DOCKER = os.getenv("DETONATION_STOP_DOCKER", "1") != "0"
DETONATION_MANAGE_VM = os.getenv("DETONATION_MANAGE_VM", "1") != "0"

# Ollama endpoint (used to list + unload loaded models via keep_alive=0)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

# Docker: stopping the WSL2 backend is what actually frees the ~2 GB `vmmem`.
# NOTE: `wsl --shutdown` stops ALL WSL2 distros (including Docker Desktop's).
DOCKER_STOP_CMD = os.getenv("DOCKER_STOP_CMD", "wsl --shutdown")
# Restart Docker Desktop after detonation (adjust path if installed elsewhere).
DOCKER_START_CMD = os.getenv(
    "DOCKER_START_CMD",
    r'"C:\Program Files\Docker\Docker\Docker Desktop.exe"',
)
# How long to wait for `docker info` to succeed again after restart.
DOCKER_READY_TIMEOUT = int(os.getenv("DOCKER_READY_TIMEOUT", "120"))

# CAPE Ubuntu VM lifecycle. Defaults are Hyper-V (recommended when WSL2 is in
# use). For VirtualBox, override with e.g.
#   VM_RESUME_CMD="VBoxManage controlvm cape-ubuntu resume || VBoxManage startvm cape-ubuntu --type headless"
#   VM_SUSPEND_CMD="VBoxManage controlvm cape-ubuntu savestate"
CAPE_VM_NAME = os.getenv("CAPE_VM_NAME", "cape-ubuntu")
VM_RESUME_CMD = os.getenv("VM_RESUME_CMD", f'powershell -NoProfile -Command "Start-VM -Name \'{CAPE_VM_NAME}\'"')
VM_SUSPEND_CMD = os.getenv("VM_SUSPEND_CMD", f'powershell -NoProfile -Command "Save-VM -Name \'{CAPE_VM_NAME}\'"')
# Wait for the CAPE API to answer after the VM resumes.
CAPE_READY_TIMEOUT = int(os.getenv("CAPE_READY_TIMEOUT", "180"))

# --------------------------------------------------------------------------
# Dashboard integration: attijari VM wrapper, websockify, CAPE web UI
# --------------------------------------------------------------------------
# Tiny authenticated HTTP service running ON the attijari VM (source in
# deploy/attijari/). Used ONLY to recover a cuckoo2 guest left stuck
# "running" (destroy + restart cape.service). Disabled by default until the
# runbook (docs/attijari-sandbox-setup.md) has been executed.
CAPE_VM_WRAPPER_ENABLED = os.getenv("CAPE_VM_WRAPPER_ENABLED", "0") != "0"
CAPE_VM_WRAPPER_URL = os.getenv("CAPE_VM_WRAPPER_URL", "http://192.168.100.10:8090").rstrip("/")
CAPE_VM_WRAPPER_TOKEN = os.getenv("CAPE_VM_WRAPPER_TOKEN", "")
CAPE_VM_WRAPPER_TIMEOUT = int(os.getenv("CAPE_VM_WRAPPER_TIMEOUT", "20"))

# websockify endpoint on attijari fronting cuckoo2's fixed VNC port. The
# dashboard's /ws/vnc relay is the only consumer; the browser never sees this.
WEBSOCKIFY_URL = os.getenv("WEBSOCKIFY_URL", "ws://192.168.100.10:6080")

# CAPE's Django web UI base (report pages, /analysis/<id>/). Defaults to the
# API host without the /apiv2 suffix.
CAPE_WEB_URL = os.getenv(
    "CAPE_WEB_URL",
    CAPE_API_URL[: -len("/apiv2")] if CAPE_API_URL.endswith("/apiv2") else CAPE_API_URL,
).rstrip("/")
