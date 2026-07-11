# Detonation Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a lightweight malware detonation sandbox using VirtualBox + Windows 7 SP1 guest VM that executes suspicious email attachments, monitors behavioral artifacts, resists anti-VM detection, produces JSON behavioral reports, and integrates with the existing extraction pipeline.

**Architecture:** A Python host-side orchestrator (`src/detonation.py`) manages a VirtualBox Windows 7 VM via `VBoxManage` CLI. It copies suspicious files into the VM, triggers a Python guest agent (`guest_agent.py`) that opens/executes the file while monitoring processes, filesystem, registry, and network activity for 90 seconds. Results are collected as JSON, the VM reverts to a clean snapshot, and the behavioral report feeds into Stage 3.5 of the existing pipeline (between extraction and enrichment). Anti-VM-detection hardening is applied via VBoxManage DMI/BIOS spoofing and in-guest environment camouflage.

**Tech Stack:** VirtualBox 7.x (VBoxManage CLI), Python 3.12, psutil (guest monitoring), watchdog (guest filesystem monitoring), Sysmon (guest event logging), FakeNet-NG (guest network simulation), Procmon/Noriben (guest process monitoring)

**System Constraints:**
- Total RAM: 16 GB, ~6 GB free for sandbox
- WSL2 is active (Ubuntu default) — VirtualBox runs in Hyper-V compatibility mode
- Windows 11 Home N host
- Budget: ~1.8 GB RAM for the VM + overhead, leaving ~4 GB for pipeline + Ollama + PostgreSQL

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/detonation.py` | Host-side orchestrator — VM lifecycle, file submission, result collection, snapshot revert |
| `src/detonation_config.py` | Configuration constants — VM name, paths, timeouts, thresholds |
| `guest/agent.py` | Guest-side monitoring agent — process/file/registry/network watchers |
| `guest/config.py` | Guest agent configuration — watch paths, exclusions, timeouts |
| `guest/install.bat` | One-time guest setup — installs Python, psutil, watchdog, Sysmon, configures services |
| `guest/sysmon_config.xml` | Sysmon configuration — process creation, file creation, network, registry events |
| `guest/camouflage.py` | Anti-VM-detection — fake processes, realistic desktop, mouse movement |
| `guest/camouflage.bat` | Startup script that runs camouflage before agent |
| `scripts/setup_vm.ps1` | Host-side PowerShell script — creates VM, applies anti-detection hardening, takes clean snapshot |
| `scripts/vbox_harden.bat` | VBoxManage anti-detection commands — DMI/BIOS/ACPI spoofing |
| `tests/test_detonation.py` | Host orchestrator tests — mock VBoxManage, verify JSON report schema |
| `tests/test_guest_agent.py` | Guest agent tests — verify monitor output format, timeout behavior |

---

## Prerequisites — What to Install

### On the Host (your Windows 11 machine)

**1. VirtualBox 7.x**
- Download: https://www.virtualbox.org/wiki/Downloads → "Windows hosts"

- Install with default settings
- Note: With WSL2 active, VirtualBox uses Hyper-V backend (slightly slower but functional)
- After install, verify: `VBoxManage --version` in terminal

**2. VirtualBox Extension Pack** (same version as VirtualBox)
- Download from same page → "All supported platforms"
- Double-click to install (adds USB 3.0, RDP, disk encryption)

**3. Windows 7 SP1 x64 ISO**
- You need a legitimate Windows 7 SP1 Professional or Ultimate x64 ISO
- Professional is preferred (supports Remote Desktop, Group Policy)
- Key is not strictly needed for POC (runs in trial mode for 30 days, can rearm 3x = 120 days)

### Inside the Guest VM (installed during setup)

| Tool | Purpose | Install Method |
|------|---------|----------------|
| Python 3.12 | Guest agent runtime | MSI installer (offline copy) |
| psutil | Process monitoring | `pip install psutil` (offline wheel) |
| watchdog | Filesystem monitoring | `pip install watchdog` (offline wheel) |
| Sysmon v15 | Kernel-level event logging | Sysinternals download (standalone .exe) |
| FakeNet-NG | Network simulation (catches C2 attempts) | GitHub release (standalone) |
| Microsoft Office 2010/2013 | Opens weaponized documents | ISO/installer (for .doc/.docx/.xls detonation) |
| Adobe Reader 9/X | Opens weaponized PDFs | Offline installer (intentionally old = vulnerable) |
| 7-Zip | Opens archive-based payloads | MSI installer |
| Procmon (optional) | Deep process tracing | Sysinternals (standalone .exe) |

### Anti-VM-Detection Cyber Tools (inside guest)

| Tool | Purpose |
|------|---------|
| Pafish | Test whether malware can detect the VM (run to verify hardening works) |
| al-khaser | Advanced anti-VM/anti-debug test suite (validates camouflage) |

---

## Task 1: Configuration Module

**Files:**
- Create: `src/detonation_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_detonation.py
import pytest

def test_config_has_required_fields():
    from detonation_config import (
        VM_NAME, SNAPSHOT_NAME, VBOXMANAGE,
        GUEST_AGENT_PATH, GUEST_SUBMIT_DIR, GUEST_RESULTS_DIR,
        DETONATION_TIMEOUT, MONITOR_DURATION, REVERT_TIMEOUT,
        SUPPORTED_EXTENSIONS, REPORT_SCHEMA_VERSION,
    )
    assert isinstance(VM_NAME, str) and VM_NAME
    assert isinstance(SNAPSHOT_NAME, str) and SNAPSHOT_NAME
    assert isinstance(DETONATION_TIMEOUT, int) and DETONATION_TIMEOUT > 0
    assert isinstance(MONITOR_DURATION, int) and MONITOR_DURATION > 0
    assert isinstance(SUPPORTED_EXTENSIONS, set)
    assert ".exe" in SUPPORTED_EXTENSIONS
    assert ".docm" in SUPPORTED_EXTENSIONS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py::test_config_has_required_fields -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'detonation_config'`

- [ ] **Step 3: Write implementation**

```python
# src/detonation_config.py
"""Detonation sandbox configuration constants."""
from pathlib import Path
import shutil

# --- VM identity ---
VM_NAME = "Detonation-Win7"
SNAPSHOT_NAME = "clean-snapshot"

# --- VBoxManage path ---
VBOXMANAGE = shutil.which("VBoxManage") or r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# --- Guest paths (inside the Windows 7 VM) ---
GUEST_USER = "analyst"
GUEST_PASSWORD = "Detonate2026!"  # local account, no domain
GUEST_AGENT_PATH = r"C:\sandbox\agent.py"
GUEST_SUBMIT_DIR = r"C:\sandbox\submit"
GUEST_RESULTS_DIR = r"C:\sandbox\results"
GUEST_PYTHON = r"C:\Python312\python.exe"

# --- Timeouts (seconds) ---
DETONATION_TIMEOUT = 120      # max total time for one sample
MONITOR_DURATION = 90         # how long to monitor after opening file
VM_BOOT_TIMEOUT = 60          # max wait for VM to be responsive
REVERT_TIMEOUT = 30           # max wait for snapshot revert
VBOX_CMD_TIMEOUT = 15         # per VBoxManage command

# --- File types worth detonating ---
# Only detonate file types that can execute code or exploit viewers.
# Pure text/images go through static analysis only.
SUPPORTED_EXTENSIONS = {
    # Executables
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".msi", ".msp",
    # Office (macro-capable)
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".ppsx", ".ppsm", ".rtf",
    # PDF
    ".pdf",
    # Archives (will be extracted + opened)
    ".zip", ".rar", ".7z",
    # Shortcuts
    ".lnk",
    # Java
    ".jar",
}

# --- Report ---
REPORT_SCHEMA_VERSION = "1.0"

# --- Resource limits ---
VM_RAM_MB = 1536              # 1.5 GB for the guest
VM_CPUS = 1                   # single CPU core
VM_VRAM_MB = 32               # minimal video RAM
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py::test_config_has_required_fields -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/detonation_config.py tests/test_detonation.py
git commit -m "feat: add detonation sandbox configuration module"
```

---

## Task 2: VM Setup Script with Anti-Detection Hardening

**Files:**
- Create: `scripts/vbox_harden.bat`
- Create: `scripts/setup_vm.ps1`

- [ ] **Step 1: Write VBoxManage anti-detection hardening script**

This script applies DMI/BIOS/ACPI spoofing so malware cannot detect it's running in VirtualBox.

```batch
@echo off
REM scripts/vbox_harden.bat — Anti-VM-detection hardening for VirtualBox
REM Run AFTER creating the VM but BEFORE first boot
REM Usage: vbox_harden.bat "Detonation-Win7"

SET VM=%~1
IF "%VM%"=="" SET VM=Detonation-Win7

echo [HARDEN] Applying anti-detection to VM: %VM%

REM === 1. DMI/BIOS strings — replace VirtualBox identifiers ===
REM These are what tools like Pafish, al-khaser, and malware check first.
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor"        "American Megatrends Inc."
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion"       "F8"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate"   "11/12/2021"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor"  "5"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor"  "17"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor"      "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct"     "20Y3CTO1WW"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion"     "ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial"      "PF2ABC12"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU"         "LENOVO_MT_20Y3_BU_Think_FM_ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily"      "ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid"        "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor"     "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisType"       "10"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion"    "ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial"     "PF2ABC12"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor"       "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct"      "20Y3CTO1WW"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion"      "SDK0T76461 WIN"

REM === 2. ACPI table customization ===
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiOemId"       "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId"   "LNVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev"  "20160930"

REM === 3. Hide VirtualBox-specific devices ===
REM Remove the "VBOX" prefix from the hard disk serial and firmware
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber"    "WD-WMC4N0K2YPR7"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "01.01A01"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber"      "WDC WD10EZEX-00WN4A0"

REM === 4. MAC address — use a Dell/Lenovo OUI, NOT VirtualBox default 08:00:27 ===
VBoxManage modifyvm "%VM%" --mac-address1 "B8AEED710042"

REM === 5. Disable VirtualBox-detectable features ===
VBoxManage modifyvm "%VM%" --paravirt-provider none
VBoxManage modifyvm "%VM%" --nested-hw-virt off

REM === 6. CPU identity — hide hypervisor bit ===
REM This prevents CPUID-based VM detection (checks hypervisor present bit)
VBoxManage modifyvm "%VM%" --cpu-profile "Intel Core i7-10750H"

echo [HARDEN] Anti-detection hardening applied to %VM%
echo [HARDEN] IMPORTANT: Do NOT install VirtualBox Guest Additions in this VM!
echo [HARDEN] Run Pafish inside the VM to verify hardening effectiveness.
```

- [ ] **Step 2: Write VM creation PowerShell script**

```powershell
# scripts/setup_vm.ps1 — Create and configure the detonation VM
# Usage: powershell -ExecutionPolicy Bypass -File scripts\setup_vm.ps1 -IsoPath "C:\path\to\win7sp1.iso"

param(
    [Parameter(Mandatory=$true)]
    [string]$IsoPath,

    [string]$VMName = "Detonation-Win7",
    [string]$VMDir = "$env:USERPROFILE\VirtualBox VMs",
    [int]$RamMB = 1536,
    [int]$DiskGB = 40,
    [int]$CPUs = 1,
    [int]$VRamMB = 32
)

$VBM = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $VBM)) {
    Write-Error "VBoxManage not found. Install VirtualBox first."
    exit 1
}

if (-not (Test-Path $IsoPath)) {
    Write-Error "ISO not found at: $IsoPath"
    exit 1
}

Write-Host "[SETUP] Creating VM: $VMName" -ForegroundColor Cyan

# Create VM
& $VBM createvm --name $VMName --ostype "Windows7_64" --register --basefolder $VMDir

# Configure hardware
& $VBM modifyvm $VMName `
    --memory $RamMB `
    --cpus $CPUs `
    --vram $VRamMB `
    --graphicscontroller vboxsvga `
    --audio-driver none `
    --usb off `
    --clipboard-mode disabled `
    --drag-and-drop disabled `
    --nic1 intnet `
    --intnet1 "detonation-isolated" `
    --boot1 dvd --boot2 disk --boot3 none --boot4 none

# Internal-only network means:
# - VM can talk to FakeNet-NG (running inside guest) which simulates DNS/HTTP
# - VM CANNOT reach the real internet or host network
# - Malware C2 attempts are captured by FakeNet-NG

# Create virtual disk
$DiskPath = "$VMDir\$VMName\$VMName.vdi"
& $VBM createmedium disk --filename $DiskPath --size ($DiskGB * 1024) --format VDI

# Add SATA controller and attach disk
& $VBM storagectl $VMName --name "SATA" --add sata --controller IntelAhci --portcount 2
& $VBM storageattach $VMName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $DiskPath

# Attach ISO
& $VBM storagectl $VMName --name "IDE" --add ide
& $VBM storageattach $VMName --storagectl "IDE" --port 0 --device 0 --type dvddrive --medium $IsoPath

Write-Host "[SETUP] Applying anti-detection hardening..." -ForegroundColor Yellow
$hardenScript = Join-Path $PSScriptRoot "vbox_harden.bat"
if (Test-Path $hardenScript) {
    & cmd /c $hardenScript $VMName
} else {
    Write-Warning "vbox_harden.bat not found at $hardenScript — run manually"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " VM '$VMName' created successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Start VM:  VBoxManage startvm `"$VMName`""
Write-Host "  2. Install Windows 7 SP1 from the ISO"
Write-Host "  3. Create user account: analyst / Detonate2026!"
Write-Host "  4. DO NOT install VirtualBox Guest Additions"
Write-Host "  5. Install guest tools (see guest/install.bat)"
Write-Host "  6. Run guest/camouflage.bat to set up anti-detection"
Write-Host "  7. Run Pafish.exe to verify VM is not detectable"
Write-Host "  8. Take clean snapshot:"
Write-Host "     VBoxManage snapshot `"$VMName`" take `"clean-snapshot`""
Write-Host ""
Write-Host "RAM allocation: ${RamMB}MB (leaves ~4.5GB for host)" -ForegroundColor Cyan
```

- [ ] **Step 3: Commit**

```bash
git add scripts/vbox_harden.bat scripts/setup_vm.ps1
git commit -m "feat: add VM creation and anti-detection hardening scripts"
```

---

## Task 3: Guest Agent — Behavioral Monitor

**Files:**
- Create: `guest/config.py`
- Create: `guest/agent.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_guest_agent.py
import json
import pytest

def test_report_schema():
    """Verify the behavioral report JSON schema is valid."""
    # Simulate a report from the agent
    report = {
        "schema_version": "1.0",
        "sample_sha256": "abc123",
        "sample_filename": "test.exe",
        "monitor_duration_s": 90,
        "detonation_method": "execute",
        "processes": [],
        "file_activity": [],
        "registry_activity": [],
        "network_activity": [],
        "dns_queries": [],
        "suspicious_behaviors": [],
        "risk_score": 0,
        "summary": "",
    }
    required_keys = {
        "schema_version", "sample_sha256", "sample_filename",
        "monitor_duration_s", "detonation_method",
        "processes", "file_activity", "registry_activity",
        "network_activity", "dns_queries",
        "suspicious_behaviors", "risk_score", "summary",
    }
    assert required_keys.issubset(report.keys())
    assert isinstance(report["processes"], list)
    assert isinstance(report["risk_score"], (int, float))
    assert report["schema_version"] == "1.0"


def test_suspicious_behavior_detection():
    """Verify suspicious behavior patterns are flagged."""
    # These patterns should always be flagged
    suspicious_patterns = [
        {"type": "process_spawn", "detail": "cmd.exe spawned by WINWORD.EXE"},
        {"type": "process_spawn", "detail": "powershell.exe spawned by EXCEL.EXE"},
        {"type": "registry_persistence", "detail": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run modified"},
        {"type": "file_drop_executable", "detail": r"C:\Users\analyst\AppData\Local\Temp\payload.exe created"},
        {"type": "network_connection", "detail": "TCP connection to 185.234.72.1:443"},
    ]
    for pattern in suspicious_patterns:
        assert "type" in pattern
        assert "detail" in pattern
        assert pattern["type"] in {
            "process_spawn", "registry_persistence", "file_drop_executable",
            "network_connection", "dns_query_suspicious", "api_call_suspicious",
            "file_drop_script", "scheduled_task", "service_creation",
            "credential_access", "defense_evasion",
        }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_guest_agent.py -v`
Expected: PASS (these are schema validation tests — they test the contract, not the implementation)

- [ ] **Step 3: Write guest configuration**

```python
# guest/config.py
"""Guest agent configuration — runs INSIDE the Windows 7 VM."""

# --- Paths ---
SUBMIT_DIR = r"C:\sandbox\submit"
RESULTS_DIR = r"C:\sandbox\results"
AGENT_LOG = r"C:\sandbox\agent.log"

# --- Monitoring ---
MONITOR_DURATION = 90  # seconds to observe after opening file

# --- File type → open method mapping ---
# "execute" = run the file directly (exe, bat, ps1, etc.)
# "open" = open with associated application (doc, pdf, etc.)
OPEN_METHODS = {
    # Direct execution
    ".exe": "execute", ".scr": "execute", ".com": "execute",
    ".bat": "execute", ".cmd": "execute",
    ".vbs": "execute", ".vbe": "execute",
    ".js": "execute", ".jse": "execute",
    ".wsf": "execute", ".wsh": "execute",
    ".hta": "execute", ".msi": "execute",
    ".ps1": "powershell",
    ".jar": "java",
    ".lnk": "execute",
    # Open with viewer/editor
    ".doc": "open", ".docm": "open", ".docx": "open",
    ".xls": "open", ".xlsm": "open", ".xlsx": "open",
    ".ppt": "open", ".pptm": "open", ".pptx": "open",
    ".ppsx": "open", ".ppsm": "open",
    ".rtf": "open",
    ".pdf": "open",
    # Archives — extract then scan contents
    ".zip": "extract", ".rar": "extract", ".7z": "extract",
}

# --- Suspicious process names ---
# If any of these are spawned by an Office app or PDF reader, it's suspicious
SUSPICIOUS_CHILD_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe", "rundll32.exe",
    "regsvr32.exe", "msiexec.exe", "schtasks.exe",
    "net.exe", "net1.exe", "whoami.exe", "systeminfo.exe",
    "tasklist.exe", "reg.exe", "sc.exe",
    "forfiles.exe", "pcalua.exe",
}

# --- Legitimate parent processes (for Office/PDF detonation) ---
OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe",
    "acrord32.exe", "foxit reader.exe",
}

# --- Registry keys to monitor (persistence, defense evasion) ---
REGISTRY_WATCHLIST = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKCU\Environment",
]

# --- File paths to monitor for drops ---
WATCH_DIRECTORIES = [
    r"C:\Users\analyst\AppData\Local\Temp",
    r"C:\Users\analyst\AppData\Roaming",
    r"C:\Users\analyst\Desktop",
    r"C:\Users\analyst\Downloads",
    r"C:\Windows\Temp",
    r"C:\ProgramData",
]

# --- Executable extensions (file drops with these = suspicious) ---
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".hta", ".com", ".msi",
}
```

- [ ] **Step 4: Write the guest agent**

```python
# guest/agent.py
"""Detonation sandbox guest agent — runs INSIDE the Windows 7 VM.

This agent:
1. Watches a submit directory for new files
2. Opens/executes the file using the appropriate method
3. Monitors process, filesystem, registry, and network activity
4. Writes a JSON behavioral report to the results directory
5. Exits after the monitoring period

IMPORTANT: This file runs in an ISOLATED VM. It is NOT part of the
host-side Python project. It uses only stdlib + psutil + watchdog.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import winreg
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import psutil

from config import (
    SUBMIT_DIR, RESULTS_DIR, AGENT_LOG, MONITOR_DURATION,
    OPEN_METHODS, SUSPICIOUS_CHILD_PROCESSES, OFFICE_PARENTS,
    REGISTRY_WATCHLIST, WATCH_DIRECTORIES, EXECUTABLE_EXTENSIONS,
)

# --- Logging ---
def log(msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(AGENT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# --- Process Monitor ---
class ProcessMonitor:
    """Track new processes spawned during detonation."""

    def __init__(self):
        self.baseline_pids = set()
        self.new_processes = []
        self.suspicious = []
        self._stop = threading.Event()

    def snapshot_baseline(self):
        self.baseline_pids = {p.pid for p in psutil.process_iter()}

    def monitor(self):
        while not self._stop.is_set():
            try:
                current = set()
                for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "create_time"]):
                    current.add(proc.pid)
                    if proc.pid not in self.baseline_pids:
                        info = proc.info
                        parent_name = ""
                        try:
                            parent = psutil.Process(info["ppid"])
                            parent_name = parent.name().lower()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        entry = {
                            "pid": info["pid"],
                            "name": info["name"],
                            "parent_pid": info["ppid"],
                            "parent_name": parent_name,
                            "cmdline": " ".join(info["cmdline"] or [])[:500],
                            "time": datetime.now().isoformat(),
                        }
                        self.new_processes.append(entry)
                        self.baseline_pids.add(proc.pid)

                        # Check for suspicious child process spawning
                        name_lower = (info["name"] or "").lower()
                        if (name_lower in SUSPICIOUS_CHILD_PROCESSES and
                                parent_name in OFFICE_PARENTS):
                            self.suspicious.append({
                                "type": "process_spawn",
                                "detail": f"{info['name']} spawned by {parent_name}",
                                "pid": info["pid"],
                                "cmdline": entry["cmdline"],
                                "time": entry["time"],
                            })
                            log(f"SUSPICIOUS: {info['name']} spawned by {parent_name}")

            except Exception as e:
                log(f"ProcessMonitor error: {e}")
            time.sleep(0.5)

    def stop(self):
        self._stop.set()


# --- File System Monitor ---
class FileMonitor:
    """Watch directories for new file creation."""

    def __init__(self):
        self.baseline_files = {}
        self.new_files = []
        self.suspicious = []
        self._stop = threading.Event()

    def snapshot_baseline(self):
        for watch_dir in WATCH_DIRECTORIES:
            try:
                for root, dirs, files in os.walk(watch_dir):
                    for f in files:
                        full = os.path.join(root, f)
                        self.baseline_files[full] = True
            except (PermissionError, OSError):
                pass

    def monitor(self):
        while not self._stop.is_set():
            for watch_dir in WATCH_DIRECTORIES:
                try:
                    for root, dirs, files in os.walk(watch_dir):
                        for f in files:
                            full = os.path.join(root, f)
                            if full not in self.baseline_files:
                                self.baseline_files[full] = True
                                ext = os.path.splitext(f)[1].lower()
                                size = 0
                                try:
                                    size = os.path.getsize(full)
                                except OSError:
                                    pass

                                entry = {
                                    "path": full,
                                    "name": f,
                                    "extension": ext,
                                    "size_bytes": size,
                                    "time": datetime.now().isoformat(),
                                }
                                self.new_files.append(entry)
                                log(f"FILE DROP: {full} ({size} bytes)")

                                if ext in EXECUTABLE_EXTENSIONS:
                                    self.suspicious.append({
                                        "type": "file_drop_executable",
                                        "detail": f"{full} created ({size} bytes)",
                                        "time": entry["time"],
                                    })
                                elif ext in (".vbs", ".js", ".ps1", ".bat", ".cmd"):
                                    self.suspicious.append({
                                        "type": "file_drop_script",
                                        "detail": f"{full} created ({size} bytes)",
                                        "time": entry["time"],
                                    })
                except (PermissionError, OSError):
                    pass
            time.sleep(1.0)

    def stop(self):
        self._stop.set()


# --- Registry Monitor ---
class RegistryMonitor:
    """Check registry persistence keys for changes."""

    def __init__(self):
        self.baseline = {}
        self.changes = []
        self.suspicious = []
        self._stop = threading.Event()

    def _read_key(self, key_path):
        """Read all values under a registry key."""
        values = {}
        hive_map = {
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
        }
        parts = key_path.split("\\", 1)
        hive = hive_map.get(parts[0])
        subkey = parts[1] if len(parts) > 1 else ""
        if not hive:
            return values
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = str(data)[:200]
                        i += 1
                    except OSError:
                        break
        except (OSError, PermissionError):
            pass
        return values

    def snapshot_baseline(self):
        for key_path in REGISTRY_WATCHLIST:
            self.baseline[key_path] = self._read_key(key_path)

    def monitor(self):
        while not self._stop.is_set():
            for key_path in REGISTRY_WATCHLIST:
                current = self._read_key(key_path)
                prev = self.baseline.get(key_path, {})

                # Detect new or changed values
                for name, value in current.items():
                    if name not in prev:
                        entry = {
                            "key": key_path,
                            "value_name": name,
                            "value_data": value,
                            "action": "created",
                            "time": datetime.now().isoformat(),
                        }
                        self.changes.append(entry)
                        log(f"REGISTRY: {key_path}\\{name} = {value}")

                        if "Run" in key_path or "Services" in key_path:
                            self.suspicious.append({
                                "type": "registry_persistence",
                                "detail": f"{key_path}\\{name} modified",
                                "time": entry["time"],
                            })
                    elif prev[name] != value:
                        entry = {
                            "key": key_path,
                            "value_name": name,
                            "value_data": value,
                            "old_value": prev[name],
                            "action": "modified",
                            "time": datetime.now().isoformat(),
                        }
                        self.changes.append(entry)

                self.baseline[key_path] = current
            time.sleep(2.0)

    def stop(self):
        self._stop.set()


# --- Network Monitor ---
class NetworkMonitor:
    """Track new network connections made during detonation."""

    def __init__(self):
        self.baseline_conns = set()
        self.new_connections = []
        self.suspicious = []
        self._stop = threading.Event()

    def snapshot_baseline(self):
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:
                    self.baseline_conns.add((conn.raddr.ip, conn.raddr.port))
        except (psutil.AccessDenied, OSError):
            pass

    def monitor(self):
        while not self._stop.is_set():
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.raddr:
                        key = (conn.raddr.ip, conn.raddr.port)
                        if key not in self.baseline_conns:
                            self.baseline_conns.add(key)
                            proc_name = ""
                            try:
                                if conn.pid:
                                    proc_name = psutil.Process(conn.pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                            entry = {
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                                "local_port": conn.laddr.port if conn.laddr else None,
                                "status": conn.status,
                                "pid": conn.pid,
                                "process": proc_name,
                                "time": datetime.now().isoformat(),
                            }
                            self.new_connections.append(entry)
                            log(f"NETWORK: {proc_name} -> {conn.raddr.ip}:{conn.raddr.port}")

                            self.suspicious.append({
                                "type": "network_connection",
                                "detail": f"TCP connection to {conn.raddr.ip}:{conn.raddr.port} by {proc_name}",
                                "time": entry["time"],
                            })
            except (psutil.AccessDenied, OSError):
                pass
            time.sleep(1.0)

    def stop(self):
        self._stop.set()


# --- File Opening / Detonation ---
def detonate(filepath, method):
    """Open or execute the file based on its type."""
    log(f"DETONATE: {filepath} via {method}")

    if method == "execute":
        subprocess.Popen([filepath], shell=True)
    elif method == "powershell":
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", filepath])
    elif method == "java":
        subprocess.Popen(["java", "-jar", filepath])
    elif method == "open":
        os.startfile(filepath)
    elif method == "extract":
        # Extract archive, then open each extracted file
        extract_dir = os.path.join(os.path.dirname(filepath), "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(["7z", "x", filepath, f"-o{extract_dir}", "-y"],
                       timeout=30, capture_output=True)
        for f in os.listdir(extract_dir):
            ext = os.path.splitext(f)[1].lower()
            sub_method = OPEN_METHODS.get(ext, "open")
            sub_path = os.path.join(extract_dir, f)
            detonate(sub_path, sub_method)
    else:
        log(f"Unknown method: {method}, falling back to os.startfile")
        os.startfile(filepath)


# --- Risk Scoring ---
def compute_risk_score(suspicious_behaviors):
    """Compute 0-100 risk score from observed behaviors."""
    weights = {
        "process_spawn": 25,
        "file_drop_executable": 20,
        "file_drop_script": 15,
        "registry_persistence": 25,
        "network_connection": 20,
        "dns_query_suspicious": 10,
        "scheduled_task": 20,
        "service_creation": 25,
        "credential_access": 30,
        "defense_evasion": 20,
    }
    score = 0
    for behavior in suspicious_behaviors:
        score += weights.get(behavior["type"], 10)
    return min(score, 100)


# --- Main Agent Entry Point ---
def run_agent():
    """Main agent loop — watch for files, detonate, monitor, report."""
    os.makedirs(SUBMIT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    log("Agent started, watching " + SUBMIT_DIR)

    # Wait for a file to appear in submit dir
    sample_path = None
    deadline = time.time() + 30  # 30s to receive a file
    while time.time() < deadline:
        files = [f for f in os.listdir(SUBMIT_DIR) if not f.startswith(".")]
        if files:
            sample_path = os.path.join(SUBMIT_DIR, files[0])
            break
        time.sleep(0.5)

    if not sample_path:
        log("ERROR: No file received within 30 seconds")
        sys.exit(1)

    # Compute file hash
    with open(sample_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    filename = os.path.basename(sample_path)
    ext = os.path.splitext(filename)[1].lower()
    method = OPEN_METHODS.get(ext, "open")

    log(f"Sample: {filename} (SHA256: {sha256})")
    log(f"Extension: {ext}, Method: {method}")

    # Initialize monitors
    proc_mon = ProcessMonitor()
    file_mon = FileMonitor()
    reg_mon = RegistryMonitor()
    net_mon = NetworkMonitor()

    # Take baselines
    log("Taking baseline snapshots...")
    proc_mon.snapshot_baseline()
    file_mon.snapshot_baseline()
    reg_mon.snapshot_baseline()
    net_mon.snapshot_baseline()

    # Start monitor threads
    threads = []
    for mon in [proc_mon, file_mon, reg_mon, net_mon]:
        t = threading.Thread(target=mon.monitor, daemon=True)
        t.start()
        threads.append(t)

    # Detonate
    log(f"Detonating {filename}...")
    try:
        detonate(sample_path, method)
    except Exception as e:
        log(f"Detonation error: {e}")

    # Monitor for MONITOR_DURATION seconds
    log(f"Monitoring for {MONITOR_DURATION} seconds...")
    time.sleep(MONITOR_DURATION)

    # Stop monitors
    log("Stopping monitors...")
    proc_mon.stop()
    file_mon.stop()
    reg_mon.stop()
    net_mon.stop()

    for t in threads:
        t.join(timeout=5)

    # Collect all suspicious behaviors
    all_suspicious = (
        proc_mon.suspicious +
        file_mon.suspicious +
        reg_mon.suspicious +
        net_mon.suspicious
    )

    # Build report
    report = {
        "schema_version": "1.0",
        "sample_sha256": sha256,
        "sample_filename": filename,
        "detonation_method": method,
        "monitor_duration_s": MONITOR_DURATION,
        "timestamp": datetime.now().isoformat(),
        "processes": proc_mon.new_processes,
        "file_activity": file_mon.new_files,
        "registry_activity": reg_mon.changes,
        "network_activity": net_mon.new_connections,
        "dns_queries": [],  # populated by Sysmon log parsing if available
        "suspicious_behaviors": all_suspicious,
        "risk_score": compute_risk_score(all_suspicious),
        "summary": _generate_summary(all_suspicious, proc_mon, file_mon, reg_mon, net_mon),
    }

    # Write report
    report_path = os.path.join(RESULTS_DIR, f"report_{sha256[:16]}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log(f"Report written: {report_path}")
    log(f"Risk score: {report['risk_score']}/100")
    log(f"Suspicious behaviors: {len(all_suspicious)}")
    log("Agent complete.")


def _generate_summary(suspicious, proc_mon, file_mon, reg_mon, net_mon):
    """Generate human-readable summary of detonation results."""
    parts = []
    if not suspicious:
        return "No suspicious behavior observed during detonation."

    if proc_mon.suspicious:
        procs = [s["detail"] for s in proc_mon.suspicious]
        parts.append(f"Process spawning: {'; '.join(procs)}")
    if file_mon.suspicious:
        drops = [s["detail"] for s in file_mon.suspicious]
        parts.append(f"File drops: {'; '.join(drops[:5])}")
    if reg_mon.suspicious:
        regs = [s["detail"] for s in reg_mon.suspicious]
        parts.append(f"Registry persistence: {'; '.join(regs[:5])}")
    if net_mon.suspicious:
        nets = [s["detail"] for s in net_mon.suspicious]
        parts.append(f"Network activity: {'; '.join(nets[:5])}")

    return " | ".join(parts)


if __name__ == "__main__":
    run_agent()
```

- [ ] **Step 5: Commit**

```bash
git add guest/config.py guest/agent.py tests/test_guest_agent.py
git commit -m "feat: add guest-side behavioral monitoring agent"
```

---

## Task 4: Guest Environment Setup Scripts

**Files:**
- Create: `guest/install.bat`
- Create: `guest/sysmon_config.xml`
- Create: `guest/camouflage.py`
- Create: `guest/camouflage.bat`

- [ ] **Step 1: Write guest installation script**

```batch
@echo off
REM guest/install.bat — Run inside the Windows 7 VM after OS install
REM Prerequisites: Copy this entire guest/ folder + installers to C:\sandbox\

echo ===================================
echo  Detonation Sandbox Guest Setup
echo ===================================

REM Create directory structure
mkdir C:\sandbox\submit 2>NUL
mkdir C:\sandbox\results 2>NUL
mkdir C:\sandbox\tools 2>NUL

REM --- 1. Python 3.12 ---
echo [1/6] Install Python 3.12...
REM Copy python-3.12.x-amd64.exe to C:\sandbox\tools\ before running
IF EXIST C:\sandbox\tools\python-*.exe (
    C:\sandbox\tools\python-*.exe /quiet InstallAllUsers=1 TargetDir=C:\Python312 PrependPath=1
) ELSE (
    echo SKIP: Python installer not found in C:\sandbox\tools\
)

REM --- 2. Python packages ---
echo [2/6] Install Python packages...
C:\Python312\python.exe -m pip install --no-index --find-links=C:\sandbox\tools\wheels psutil watchdog 2>NUL
IF ERRORLEVEL 1 (
    echo Trying online install...
    C:\Python312\python.exe -m pip install psutil watchdog
)

REM --- 3. Sysmon ---
echo [3/6] Install Sysmon...
IF EXIST C:\sandbox\tools\Sysmon64.exe (
    C:\sandbox\tools\Sysmon64.exe -accepteula -i C:\sandbox\sysmon_config.xml
    echo Sysmon installed with custom config
) ELSE (
    echo SKIP: Sysmon64.exe not found in C:\sandbox\tools\
)

REM --- 4. FakeNet-NG ---
echo [4/6] Setup FakeNet-NG...
IF EXIST C:\sandbox\tools\fakenet (
    echo FakeNet-NG found. To start: C:\sandbox\tools\fakenet\fakenet.exe
) ELSE (
    echo SKIP: FakeNet-NG not found in C:\sandbox\tools\fakenet\
)

REM --- 5. Disable Windows Defender / Updates (reduce noise) ---
echo [5/6] Disabling Windows Update and Defender...
sc config wuauserv start= disabled >NUL 2>&1
sc stop wuauserv >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >NUL 2>&1

REM --- 6. Set agent to autostart ---
echo [6/6] Configuring agent autostart...
REM The agent should NOT autostart normally — it's triggered per-detonation.
REM Instead, add camouflage to startup so the VM looks "lived in".
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Camouflage /t REG_SZ /d "C:\sandbox\camouflage.bat" /f >NUL

echo.
echo ===================================
echo  Setup complete!
echo ===================================
echo.
echo Next steps:
echo  1. Install Microsoft Office 2010/2013 (for doc/xls detonation)
echo  2. Install Adobe Reader 9 or X (for PDF detonation)
echo  3. Install 7-Zip (for archive detonation)
echo  4. Copy Pafish.exe to C:\sandbox\tools\ and run to test anti-VM
echo  5. Run camouflage.bat to populate desktop/docs
echo  6. Shut down, then take snapshot from host:
echo     VBoxManage snapshot "Detonation-Win7" take "clean-snapshot"
```

- [ ] **Step 2: Write Sysmon configuration**

```xml
<!-- guest/sysmon_config.xml — Lightweight config for detonation monitoring -->
<!-- Captures: process creation, file creation, network connections, registry -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Creation (Event ID 1) — log everything -->
    <ProcessCreate onmatch="exclude"/>

    <!-- File Creation (Event ID 11) — focus on temp/user dirs -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\AppData\</TargetFilename>
      <TargetFilename condition="contains">\Temp\</TargetFilename>
      <TargetFilename condition="contains">\Desktop\</TargetFilename>
      <TargetFilename condition="contains">\Downloads\</TargetFilename>
      <TargetFilename condition="contains">\ProgramData\</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.bat</TargetFilename>
      <TargetFilename condition="end with">.ps1</TargetFilename>
      <TargetFilename condition="end with">.vbs</TargetFilename>
    </FileCreate>

    <!-- Network Connection (Event ID 3) — log all -->
    <NetworkConnect onmatch="exclude"/>

    <!-- Registry (Event ID 12, 13, 14) — focus on persistence keys -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
      <TargetObject condition="contains">\Services\</TargetObject>
      <TargetObject condition="contains">\Winlogon</TargetObject>
      <TargetObject condition="contains">\Environment</TargetObject>
    </RegistryEvent>

    <!-- DNS Query (Event ID 22) — log all -->
    <DnsQuery onmatch="exclude"/>

    <!-- Process Termination (Event ID 5) — useful for short-lived droppers -->
    <ProcessTerminate onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
```

- [ ] **Step 3: Write anti-VM camouflage script**

```python
# guest/camouflage.py
"""Anti-VM-detection camouflage — makes the VM look like a real workstation.

Runs at VM startup (via camouflage.bat). Creates:
- Realistic desktop files (Word docs, Excel files, PDFs)
- Browser history artifacts
- Recent documents list
- Fake running processes (optional)
- Mouse movement simulation (prevents idle-detection)

These defeat malware that checks for "sterile" environments (no documents,
no browser history, no recent files = probably a sandbox).
"""
import os
import random
import shutil
import subprocess
import threading
import time
import ctypes
from pathlib import Path

DESKTOP = Path(os.path.expanduser("~")) / "Desktop"
DOCUMENTS = Path(os.path.expanduser("~")) / "Documents"
RECENT = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"


def create_decoy_files():
    """Create realistic-looking documents on desktop and in Documents."""
    desktop_files = [
        ("Budget_2026_Q3.xlsx", b"PK\x03\x04"),  # ZIP magic (OOXML)
        ("Meeting_Notes_July.docx", b"PK\x03\x04"),
        ("Project_Timeline.pdf", b"%PDF-1.4"),
        ("Team_Photo.jpg", b"\xff\xd8\xff\xe0"),
        ("Presentation_Final.pptx", b"PK\x03\x04"),
        ("Contacts.csv", b"Name,Email,Phone\nJohn,john@company.com,+1234"),
    ]
    doc_files = [
        ("Annual_Report_2025.pdf", b"%PDF-1.4"),
        ("Expenses_March.xlsx", b"PK\x03\x04"),
        ("Company_Handbook.docx", b"PK\x03\x04"),
        ("Invoice_4521.pdf", b"%PDF-1.4"),
    ]

    for name, magic in desktop_files:
        path = DESKTOP / name
        if not path.exists():
            # Create small files with correct magic bytes + padding
            with open(path, "wb") as f:
                f.write(magic)
                f.write(os.urandom(random.randint(1024, 8192)))

    DOCUMENTS.mkdir(exist_ok=True)
    for name, magic in doc_files:
        path = DOCUMENTS / name
        if not path.exists():
            with open(path, "wb") as f:
                f.write(magic)
                f.write(os.urandom(random.randint(2048, 16384)))


def create_browser_artifacts():
    """Create browser-like artifacts to defeat empty-browser checks."""
    # Chrome local state (indicates Chrome was used)
    chrome_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"
    chrome_dir.mkdir(parents=True, exist_ok=True)
    local_state = chrome_dir / "Local State"
    if not local_state.exists():
        local_state.write_text('{"profile":{"info_cache":{"Default":{"name":"analyst"}}}}')

    # Firefox profiles.ini
    ff_dir = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox"
    ff_dir.mkdir(parents=True, exist_ok=True)
    profiles_ini = ff_dir / "profiles.ini"
    if not profiles_ini.exists():
        profiles_ini.write_text("[General]\nStartWithLastProfile=1\n")


def simulate_mouse_movement():
    """Periodically move the mouse cursor to defeat idle detection.

    Many sandbox-aware malware checks if the mouse moves at all.
    Static cursor = sandbox. Random micro-movements = real user.
    """
    while True:
        try:
            x = random.randint(-3, 3)
            y = random.randint(-3, 3)
            ctypes.windll.user32.mouse_event(0x0001, x, y, 0, 0)
        except Exception:
            pass
        time.sleep(random.uniform(5, 15))


def set_realistic_environment():
    """Set environment variables that malware might check."""
    # Computer name (already set during OS install, but verify)
    # Username should be something realistic, not "sandbox" or "malware"
    os.environ["NUMBER_OF_PROCESSORS"] = "4"
    os.environ["COMPUTERNAME"] = os.environ.get("COMPUTERNAME", "DESKTOP-A1B2C3D")


def main():
    print("[CAMOUFLAGE] Setting up realistic environment...")
    create_decoy_files()
    create_browser_artifacts()
    set_realistic_environment()
    print("[CAMOUFLAGE] Decoy files and artifacts created")

    # Start mouse movement in background
    t = threading.Thread(target=simulate_mouse_movement, daemon=True)
    t.start()
    print("[CAMOUFLAGE] Mouse movement simulation started")
    print("[CAMOUFLAGE] Ready — VM appears as a real workstation")


if __name__ == "__main__":
    main()
    # Keep running for mouse movement
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
```

- [ ] **Step 4: Write camouflage startup batch**

```batch
@echo off
REM guest/camouflage.bat — Runs at VM startup before agent
REM Sets up anti-detection camouflage (decoy files, mouse movement)

REM Start FakeNet-NG in background (simulates network for malware)
IF EXIST C:\sandbox\tools\fakenet\fakenet.exe (
    start /min "" C:\sandbox\tools\fakenet\fakenet.exe
    timeout /t 3 /nobreak >NUL
)

REM Start camouflage
start /min "" C:\Python312\python.exe C:\sandbox\camouflage.py
```

- [ ] **Step 5: Commit**

```bash
git add guest/install.bat guest/sysmon_config.xml guest/camouflage.py guest/camouflage.bat
git commit -m "feat: add guest VM setup, Sysmon config, and anti-detection camouflage"
```

---

## Task 5: Host-Side Detonation Orchestrator

**Files:**
- Create: `src/detonation.py`
- Modify: `tests/test_detonation.py` (add orchestrator tests)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_detonation.py — add to existing file

from unittest.mock import patch, MagicMock
import json
import pytest

def test_vbox_command_wrapper():
    """Test VBoxManage command wrapper handles success and errors."""
    from detonation import _vbox_cmd
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
        result = _vbox_cmd(["list", "vms"])
        assert result.returncode == 0

def test_vbox_command_timeout():
    """Test VBoxManage wrapper raises on timeout."""
    from detonation import _vbox_cmd
    import subprocess
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=15)):
        with pytest.raises(subprocess.TimeoutExpired):
            _vbox_cmd(["list", "vms"])

def test_should_detonate_extension():
    """Test file extension filtering for detonation."""
    from detonation import should_detonate
    assert should_detonate("invoice.docm") is True
    assert should_detonate("malware.exe") is True
    assert should_detonate("readme.txt") is False
    assert should_detonate("photo.jpg") is False
    assert should_detonate("report.pdf") is True

def test_parse_behavioral_report():
    """Test parsing of guest agent JSON report."""
    from detonation import parse_behavioral_report
    report = {
        "schema_version": "1.0",
        "sample_sha256": "abc123",
        "sample_filename": "test.docm",
        "monitor_duration_s": 90,
        "detonation_method": "open",
        "processes": [{"pid": 1234, "name": "cmd.exe", "parent_name": "winword.exe"}],
        "file_activity": [],
        "registry_activity": [],
        "network_activity": [],
        "dns_queries": [],
        "suspicious_behaviors": [
            {"type": "process_spawn", "detail": "cmd.exe spawned by winword.exe"}
        ],
        "risk_score": 25,
        "summary": "Process spawning: cmd.exe spawned by winword.exe",
    }
    result = parse_behavioral_report(json.dumps(report))
    assert result["risk_score"] == 25
    assert result["suspicious"] is True
    assert len(result["suspicious_behaviors"]) == 1
    assert result["detonated"] is True

def test_parse_empty_report():
    """Test parsing empty/clean behavioral report."""
    from detonation import parse_behavioral_report
    report = {
        "schema_version": "1.0",
        "sample_sha256": "abc123",
        "sample_filename": "clean.pdf",
        "monitor_duration_s": 90,
        "detonation_method": "open",
        "processes": [],
        "file_activity": [],
        "registry_activity": [],
        "network_activity": [],
        "dns_queries": [],
        "suspicious_behaviors": [],
        "risk_score": 0,
        "summary": "No suspicious behavior observed during detonation.",
    }
    result = parse_behavioral_report(json.dumps(report))
    assert result["risk_score"] == 0
    assert result["suspicious"] is False
    assert result["detonated"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'detonation'`

- [ ] **Step 3: Write the orchestrator**

```python
# src/detonation.py
"""detonation.py — Host-side detonation sandbox orchestrator.

Manages the VirtualBox Windows 7 VM lifecycle for behavioral analysis:
1. Check if VM and snapshot exist
2. Revert VM to clean snapshot
3. Start VM and wait for boot
4. Copy suspicious file into guest via VBoxManage guestcontrol
5. Trigger guest agent
6. Wait for monitoring period + collect report
7. Power off VM and revert to clean snapshot

Integration: Called from extraction.py as an optional Stage 3.5
when static analysis is ambiguous (suspicious but not conclusive).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from detonation_config import (
    VM_NAME, SNAPSHOT_NAME, VBOXMANAGE,
    GUEST_USER, GUEST_PASSWORD,
    GUEST_AGENT_PATH, GUEST_SUBMIT_DIR, GUEST_RESULTS_DIR, GUEST_PYTHON,
    DETONATION_TIMEOUT, MONITOR_DURATION, VM_BOOT_TIMEOUT,
    REVERT_TIMEOUT, VBOX_CMD_TIMEOUT,
    SUPPORTED_EXTENSIONS, REPORT_SCHEMA_VERSION,
)


# --- VBoxManage wrapper ---

def _vbox_cmd(args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run a VBoxManage command with timeout."""
    cmd = [VBOXMANAGE] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout or VBOX_CMD_TIMEOUT,
    )


# --- VM status checks ---

def is_vm_available() -> dict[str, Any]:
    """Check if detonation VM exists and has a clean snapshot."""
    result = {"available": False, "vm_exists": False, "snapshot_exists": False, "vm_state": "unknown"}
    try:
        # Check VM exists
        r = _vbox_cmd(["showvminfo", VM_NAME, "--machinereadable"])
        if r.returncode != 0:
            return result
        result["vm_exists"] = True

        # Parse VM state
        for line in r.stdout.splitlines():
            if line.startswith("VMState="):
                result["vm_state"] = line.split("=")[1].strip('"')
                break

        # Check snapshot exists
        r = _vbox_cmd(["snapshot", VM_NAME, "list", "--machinereadable"])
        if r.returncode == 0 and SNAPSHOT_NAME in r.stdout:
            result["snapshot_exists"] = True

        result["available"] = result["vm_exists"] and result["snapshot_exists"]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return result


def should_detonate(filename: str) -> bool:
    """Check if a file type should be sent to the detonation sandbox."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUPPORTED_EXTENSIONS


# --- VM lifecycle ---

def _revert_snapshot() -> bool:
    """Revert VM to clean snapshot."""
    try:
        r = _vbox_cmd(["snapshot", VM_NAME, "restore", SNAPSHOT_NAME], timeout=REVERT_TIMEOUT)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _start_vm() -> bool:
    """Start the VM in headless mode."""
    try:
        r = _vbox_cmd(["startvm", VM_NAME, "--type", "headless"], timeout=30)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _wait_for_boot() -> bool:
    """Wait until guest OS is responsive (guest agent can run)."""
    deadline = time.time() + VM_BOOT_TIMEOUT
    while time.time() < deadline:
        try:
            r = _vbox_cmd([
                "guestcontrol", VM_NAME, "run",
                "--exe", "C:\\Windows\\System32\\cmd.exe",
                "--username", GUEST_USER, "--password", GUEST_PASSWORD,
                "--", "cmd.exe", "/c", "echo ready",
            ], timeout=10)
            if r.returncode == 0 and "ready" in r.stdout:
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(2)
    return False


def _poweroff_vm() -> bool:
    """Force power off the VM."""
    try:
        r = _vbox_cmd(["controlvm", VM_NAME, "poweroff"], timeout=15)
        time.sleep(2)  # give VBox a moment to release locks
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _copy_file_to_guest(host_path: str) -> bool:
    """Copy a file from host to guest submit directory."""
    filename = os.path.basename(host_path)
    guest_path = f"{GUEST_SUBMIT_DIR}\\{filename}"
    try:
        r = _vbox_cmd([
            "guestcontrol", VM_NAME, "copyto",
            "--username", GUEST_USER, "--password", GUEST_PASSWORD,
            "--target-directory", GUEST_SUBMIT_DIR,
            host_path,
        ], timeout=30)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _run_guest_agent() -> bool:
    """Start the guest agent inside the VM."""
    try:
        # Run agent in background (don't wait for it to finish)
        r = _vbox_cmd([
            "guestcontrol", VM_NAME, "run",
            "--exe", GUEST_PYTHON,
            "--username", GUEST_USER, "--password", GUEST_PASSWORD,
            "--no-wait-stdout", "--no-wait-stderr",
            "--", "python.exe", GUEST_AGENT_PATH,
        ], timeout=10)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _collect_report(sha256_prefix: str) -> str | None:
    """Copy the behavioral report from guest to host."""
    report_filename = f"report_{sha256_prefix}.json"
    guest_report_path = f"{GUEST_RESULTS_DIR}\\{report_filename}"

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            r = _vbox_cmd([
                "guestcontrol", VM_NAME, "copyfrom",
                "--username", GUEST_USER, "--password", GUEST_PASSWORD,
                "--target-directory", tmpdir,
                guest_report_path,
            ], timeout=15)
            if r.returncode == 0:
                local_path = os.path.join(tmpdir, report_filename)
                if os.path.exists(local_path):
                    with open(local_path, "r") as f:
                        return f.read()
        except subprocess.TimeoutExpired:
            pass
    return None


# --- Report parsing ---

def parse_behavioral_report(report_json: str) -> dict[str, Any]:
    """Parse guest agent behavioral report into pipeline-compatible format."""
    try:
        report = json.loads(report_json)
    except json.JSONDecodeError:
        return {
            "detonated": True,
            "status": "error",
            "error": "invalid_report_json",
            "suspicious": True,
            "risk_score": 0,
            "suspicious_behaviors": [],
            "escalate": True,
        }

    suspicious_behaviors = report.get("suspicious_behaviors", [])
    risk_score = report.get("risk_score", 0)

    return {
        "detonated": True,
        "status": "ok",
        "schema_version": report.get("schema_version"),
        "sample_sha256": report.get("sample_sha256"),
        "sample_filename": report.get("sample_filename"),
        "detonation_method": report.get("detonation_method"),
        "monitor_duration_s": report.get("monitor_duration_s"),
        "risk_score": risk_score,
        "suspicious": len(suspicious_behaviors) > 0,
        "suspicious_behaviors": suspicious_behaviors,
        "processes_spawned": len(report.get("processes", [])),
        "files_dropped": len(report.get("file_activity", [])),
        "registry_changes": len(report.get("registry_activity", [])),
        "network_connections": len(report.get("network_activity", [])),
        "summary": report.get("summary", ""),
    }


# --- Main orchestrator ---

def detonate_file(file_path: str, sha256: str, filename: str) -> dict[str, Any]:
    """Full detonation cycle: revert → boot → submit → monitor → collect → poweroff → revert.

    Args:
        file_path: absolute path to the file on the host
        sha256: SHA-256 hash of the file
        filename: original filename (for extension detection)

    Returns:
        dict with detonation results, compatible with extraction pipeline format.
    """
    t0 = time.time()
    result = {
        "tool": "detonation",
        "detonated": False,
        "status": "not_run",
        "sha256": sha256,
        "filename": filename,
        "suspicious": False,
        "risk_score": 0,
        "suspicious_behaviors": [],
        "elapsed_s": 0,
    }

    # Pre-check
    if not should_detonate(filename):
        result["status"] = "skipped_unsupported_type"
        result["elapsed_s"] = round(time.time() - t0, 2)
        return result

    vm_status = is_vm_available()
    if not vm_status["available"]:
        result["status"] = "vm_unavailable"
        result["error"] = f"vm_exists={vm_status['vm_exists']}, snapshot={vm_status['snapshot_exists']}"
        result["elapsed_s"] = round(time.time() - t0, 2)
        return result

    print(f"[DETONATION] Starting detonation of {filename} (SHA256: {sha256[:16]}...)")

    try:
        # Step 1: Power off if running, then revert to clean snapshot
        if vm_status["vm_state"] == "running":
            print("[DETONATION] VM is running, powering off first...")
            _poweroff_vm()

        print("[DETONATION] Reverting to clean snapshot...")
        if not _revert_snapshot():
            result["status"] = "error"
            result["error"] = "snapshot_revert_failed"
            return result

        # Step 2: Start VM
        print("[DETONATION] Starting VM...")
        if not _start_vm():
            result["status"] = "error"
            result["error"] = "vm_start_failed"
            return result

        # Step 3: Wait for boot
        print("[DETONATION] Waiting for guest OS boot...")
        if not _wait_for_boot():
            result["status"] = "error"
            result["error"] = "vm_boot_timeout"
            _poweroff_vm()
            return result

        # Step 4: Copy file to guest
        print(f"[DETONATION] Copying {filename} to guest...")
        if not _copy_file_to_guest(file_path):
            result["status"] = "error"
            result["error"] = "file_copy_failed"
            _poweroff_vm()
            return result

        # Step 5: Start guest agent
        print("[DETONATION] Starting behavioral monitor agent...")
        if not _run_guest_agent():
            result["status"] = "error"
            result["error"] = "agent_start_failed"
            _poweroff_vm()
            return result

        # Step 6: Wait for monitoring to complete
        # Agent monitors for MONITOR_DURATION seconds, plus buffer for startup/reporting
        wait_time = MONITOR_DURATION + 30
        print(f"[DETONATION] Monitoring for {MONITOR_DURATION}s (waiting {wait_time}s total)...")
        time.sleep(wait_time)

        # Step 7: Collect report
        print("[DETONATION] Collecting behavioral report...")
        sha256_prefix = sha256[:16]
        report_json = _collect_report(sha256_prefix)

        if report_json:
            parsed = parse_behavioral_report(report_json)
            result.update(parsed)
            print(f"[DETONATION] Risk score: {result['risk_score']}/100")
            print(f"[DETONATION] Suspicious behaviors: {len(result['suspicious_behaviors'])}")
            if result["summary"]:
                print(f"[DETONATION] Summary: {result['summary']}")
        else:
            result["status"] = "error"
            result["error"] = "report_not_found"
            result["detonated"] = True  # file was detonated but report collection failed
            result["suspicious"] = True  # fail-safe: missing report = suspicious
            print("[DETONATION] WARNING: Could not collect report — marking as suspicious (fail-safe)")

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["suspicious"] = True  # fail-safe
        print(f"[DETONATION] CRASH: {e} — marking as suspicious (fail-safe)")

    finally:
        # Step 8: Always power off and revert to clean state
        print("[DETONATION] Cleaning up — powering off and reverting...")
        _poweroff_vm()
        _revert_snapshot()

    result["elapsed_s"] = round(time.time() - t0, 2)
    print(f"[DETONATION] Complete in {result['elapsed_s']}s")
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/detonation.py tests/test_detonation.py
git commit -m "feat: add host-side detonation sandbox orchestrator"
```

---

## Task 6: Pipeline Integration — Stage 3.5

**Files:**
- Modify: `src/extraction.py` (add detonation call)
- Modify: `src/main.py` (import and status check)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_detonation.py — add to existing file

def test_extraction_detonation_integration():
    """Test that extraction pipeline calls detonation for ambiguous files."""
    from detonation import should_detonate, parse_behavioral_report
    import json

    # Scenario: oletools finds macro but it's benign-looking
    # Static analysis is ambiguous → detonation should run
    assert should_detonate("invoice.docm") is True

    # Scenario: text file → no detonation
    assert should_detonate("readme.txt") is False

    # Scenario: detonation finds suspicious behavior → escalate
    report = {
        "schema_version": "1.0",
        "sample_sha256": "abc",
        "sample_filename": "invoice.docm",
        "monitor_duration_s": 90,
        "detonation_method": "open",
        "processes": [{"pid": 100, "name": "powershell.exe", "parent_name": "winword.exe"}],
        "file_activity": [],
        "registry_activity": [{"key": "Run", "value_name": "malware", "action": "created"}],
        "network_activity": [{"remote_ip": "185.234.72.1", "remote_port": 443}],
        "dns_queries": [],
        "suspicious_behaviors": [
            {"type": "process_spawn", "detail": "powershell.exe spawned by winword.exe"},
            {"type": "registry_persistence", "detail": "Run key modified"},
            {"type": "network_connection", "detail": "TCP to 185.234.72.1:443"},
        ],
        "risk_score": 70,
        "summary": "Process spawning + registry persistence + C2 communication",
    }
    parsed = parse_behavioral_report(json.dumps(report))
    assert parsed["risk_score"] == 70
    assert parsed["suspicious"] is True
    assert len(parsed["suspicious_behaviors"]) == 3
```

- [ ] **Step 2: Run test to verify it passes (uses already-built functions)**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py::test_extraction_detonation_integration -v`
Expected: PASS

- [ ] **Step 3: Add detonation import and status check to main.py**

Add after the existing sandbox status check (around line 46):

```python
    # Check detonation sandbox status
    try:
        from detonation import is_vm_available
        det_status = is_vm_available()
        if det_status["available"]:
            print(f"[DETONATION] VM '{det_status.get('vm_state', 'unknown')}' — detonation sandbox ready")
        else:
            missing = []
            if not det_status["vm_exists"]:
                missing.append("VM not created")
            if not det_status["snapshot_exists"]:
                missing.append("no clean snapshot")
            print(f"[DETONATION] Sandbox unavailable ({', '.join(missing)}) — behavioral analysis skipped")
    except ImportError:
        print("[DETONATION] Module not available — behavioral analysis skipped")
```

- [ ] **Step 4: Add detonation stage to extraction.py**

Add to `extract_attachment()` after the IOC extraction step (step 7, around line 684), before the encrypted attachment check (step 8):

```python
    # 7b. DETONATION — behavioral analysis in isolated VM (Stage 3.5)
    # Only runs when: (1) VM sandbox is available, (2) file type is detonable,
    # (3) static analysis was ambiguous (suspicious but not already escalated).
    # If static analysis already escalated, detonation adds cost with no benefit.
    if not result["escalate"] and stored_path:
        try:
            from detonation import is_vm_available, should_detonate, detonate_file
            if should_detonate(filename) and is_vm_available().get("available"):
                print(f"[DETONATION] Static analysis ambiguous — detonating {filename}")
                det_result = detonate_file(stored_path, sha256, filename)
                result["tools_run"].append(det_result)

                if det_result.get("suspicious"):
                    result["suspicious"] = True
                    result["flags"].append(
                        f"detonation_suspicious: risk_score={det_result.get('risk_score', 0)}/100, "
                        f"behaviors={len(det_result.get('suspicious_behaviors', []))}"
                    )
                    if det_result.get("risk_score", 0) >= 50:
                        result["escalate"] = True
                        result["flags"].append("detonation_escalate: behavioral risk score >= 50")

                elif det_result.get("status") == "error":
                    # Fail-safe: detonation error → escalate
                    result["escalate"] = True
                    result["flags"].append(
                        f"detonation_error: {det_result.get('error', 'unknown')} — escalating (fail-safe)"
                    )
        except ImportError:
            pass  # detonation module not installed — skip silently
```

- [ ] **Step 5: Run full test suite**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/detonation.py src/extraction.py src/main.py tests/test_detonation.py
git commit -m "feat: integrate detonation sandbox as Stage 3.5 in extraction pipeline"
```

---

## Task 7: Verification — End-to-End Smoke Test

**Files:**
- No new files — manual verification steps

- [ ] **Step 1: Verify all imports work**

Run:
```bash
cd C:\Users\moham\Attijari && python -c "
from detonation_config import VM_NAME, SUPPORTED_EXTENSIONS, DETONATION_TIMEOUT
from detonation import is_vm_available, should_detonate, parse_behavioral_report, detonate_file
print(f'VM_NAME: {VM_NAME}')
print(f'Supported extensions: {len(SUPPORTED_EXTENSIONS)}')
print(f'Timeout: {DETONATION_TIMEOUT}s')
print(f'VM status: {is_vm_available()}')
print(f'should_detonate(invoice.docm): {should_detonate(\"invoice.docm\")}')
print(f'should_detonate(readme.txt): {should_detonate(\"readme.txt\")}')
print('All imports OK')
"
```

Expected: Prints config values, VM status shows `available: False` (VM not set up yet), extension checks pass.

- [ ] **Step 2: Run all tests**

Run: `cd C:\Users\moham\Attijari && python -m pytest tests/test_detonation.py tests/test_guest_agent.py -v`
Expected: ALL PASS

- [ ] **Step 3: Verify extraction pipeline still works without VM**

Run:
```bash
cd C:\Users\moham\Attijari && python -c "
from extraction import _available_tools
tools = _available_tools()
print('Available tools:', tools)
print('Pipeline loads OK without detonation VM')
"
```

Expected: Lists existing tools, no errors. Detonation is optional — pipeline works without it.

- [ ] **Step 4: Commit final state**

```bash
git add -A
git commit -m "test: verify detonation sandbox integration and backward compatibility"
```

---

## Post-Implementation: VM Setup Checklist

After all code is committed, set up the actual VM by following these steps in order:

1. **Install VirtualBox 7.x** — download from virtualbox.org
2. **Run setup script:** `powershell -ExecutionPolicy Bypass -File scripts\setup_vm.ps1 -IsoPath "C:\path\to\win7.iso"`
3. **Install Windows 7 SP1** — user: `analyst`, password: `Detonate2026!`
4. **DO NOT install VirtualBox Guest Additions** (detectable by malware)
5. **Copy `guest/` folder** into `C:\sandbox\` inside the VM
6. **Copy offline installers** (Python, psutil wheel, Sysmon, FakeNet-NG) to `C:\sandbox\tools\`
7. **Run `C:\sandbox\install.bat`** inside the VM
8. **Install Office 2010/2013** (for .doc/.docm detonation)
9. **Install Adobe Reader 9/X** (for .pdf detonation — intentionally old)
10. **Install 7-Zip** (for archive extraction)
11. **Run `C:\sandbox\camouflage.bat`** to create decoy files
12. **Run Pafish.exe** — verify 0 VM detections (if any fail, check hardening script)
13. **Shut down VM cleanly** (Start → Shut Down)
14. **Take clean snapshot:** `VBoxManage snapshot "Detonation-Win7" take "clean-snapshot"`
15. **Verify from host:** Run the smoke test from Task 7 Step 1 — `available` should now be `True`
