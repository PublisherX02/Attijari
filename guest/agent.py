"""Detonation sandbox guest agent — runs INSIDE the Windows 7 VM.

This agent:
1. Watches a submit directory for new files
2. Opens/executes the file using the appropriate method
3. Monitors process, filesystem, registry, and network activity
4. Writes a JSON behavioral report to the results directory
5. Exits after the monitoring period

IMPORTANT: This file runs in an ISOLATED VM with Python 3.7.
It is NOT part of the host-side Python project.
It uses only stdlib + psutil + watchdog.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import winreg
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
    line = "[{}] {}".format(ts, msg)
    print(line)
    try:
        with open(AGENT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# --- Process Monitor ---
class ProcessMonitor:
    def __init__(self):
        self.baseline_pids = set()
        self.new_processes = []
        self.suspicious = []
        self._stop = threading.Event()

    def snapshot_baseline(self):
        self.baseline_pids = set(p.pid for p in psutil.process_iter())

    def monitor(self):
        while not self._stop.is_set():
            try:
                for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "create_time"]):
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

                        name_lower = (info["name"] or "").lower()
                        if (name_lower in SUSPICIOUS_CHILD_PROCESSES and
                                parent_name in OFFICE_PARENTS):
                            self.suspicious.append({
                                "type": "process_spawn",
                                "detail": "{} spawned by {}".format(info["name"], parent_name),
                                "pid": info["pid"],
                                "cmdline": entry["cmdline"],
                                "time": entry["time"],
                            })
                            log("SUSPICIOUS: {} spawned by {}".format(info["name"], parent_name))

            except Exception as e:
                log("ProcessMonitor error: {}".format(e))
            time.sleep(0.5)

    def stop(self):
        self._stop.set()


# --- File System Monitor ---
class FileMonitor:
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
                                log("FILE DROP: {} ({} bytes)".format(full, size))

                                if ext in EXECUTABLE_EXTENSIONS:
                                    self.suspicious.append({
                                        "type": "file_drop_executable",
                                        "detail": "{} created ({} bytes)".format(full, size),
                                        "time": entry["time"],
                                    })
                                elif ext in (".vbs", ".js", ".ps1", ".bat", ".cmd"):
                                    self.suspicious.append({
                                        "type": "file_drop_script",
                                        "detail": "{} created ({} bytes)".format(full, size),
                                        "time": entry["time"],
                                    })
                except (PermissionError, OSError):
                    pass
            time.sleep(1.0)

    def stop(self):
        self._stop.set()


# --- Registry Monitor ---
class RegistryMonitor:
    def __init__(self):
        self.baseline = {}
        self.changes = []
        self.suspicious = []
        self._stop = threading.Event()

    def _read_key(self, key_path):
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
                        log("REGISTRY: {}\\{} = {}".format(key_path, name, value))

                        if "Run" in key_path or "Services" in key_path:
                            self.suspicious.append({
                                "type": "registry_persistence",
                                "detail": "{}\\{} modified".format(key_path, name),
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
                            log("NETWORK: {} -> {}:{}".format(proc_name, conn.raddr.ip, conn.raddr.port))

                            self.suspicious.append({
                                "type": "network_connection",
                                "detail": "TCP connection to {}:{} by {}".format(
                                    conn.raddr.ip, conn.raddr.port, proc_name),
                                "time": entry["time"],
                            })
            except (psutil.AccessDenied, OSError):
                pass
            time.sleep(1.0)

    def stop(self):
        self._stop.set()


# --- File Opening / Detonation ---
def detonate(filepath, method):
    log("DETONATE: {} via {}".format(filepath, method))

    if method == "execute":
        subprocess.Popen([filepath], shell=True)
    elif method == "powershell":
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", filepath])
    elif method == "java":
        subprocess.Popen(["java", "-jar", filepath])
    elif method == "open":
        os.startfile(filepath)
    elif method == "extract":
        extract_dir = os.path.join(os.path.dirname(filepath), "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(["7z", "x", filepath, "-o{}".format(extract_dir), "-y"],
                       timeout=30, capture_output=True)
        for f in os.listdir(extract_dir):
            ext = os.path.splitext(f)[1].lower()
            sub_method = OPEN_METHODS.get(ext, "open")
            sub_path = os.path.join(extract_dir, f)
            detonate(sub_path, sub_method)
    else:
        log("Unknown method: {}, falling back to os.startfile".format(method))
        os.startfile(filepath)


# --- Risk Scoring ---
def compute_risk_score(suspicious_behaviors):
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
    os.makedirs(SUBMIT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    log("Agent started, watching " + SUBMIT_DIR)

    sample_path = None
    deadline = time.time() + 30
    while time.time() < deadline:
        files = [f for f in os.listdir(SUBMIT_DIR) if not f.startswith(".")]
        if files:
            sample_path = os.path.join(SUBMIT_DIR, files[0])
            break
        time.sleep(0.5)

    if not sample_path:
        log("ERROR: No file received within 30 seconds")
        sys.exit(1)

    with open(sample_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    filename = os.path.basename(sample_path)
    ext = os.path.splitext(filename)[1].lower()
    method = OPEN_METHODS.get(ext, "open")

    log("Sample: {} (SHA256: {})".format(filename, sha256))
    log("Extension: {}, Method: {}".format(ext, method))

    proc_mon = ProcessMonitor()
    file_mon = FileMonitor()
    reg_mon = RegistryMonitor()
    net_mon = NetworkMonitor()

    log("Taking baseline snapshots...")
    proc_mon.snapshot_baseline()
    file_mon.snapshot_baseline()
    reg_mon.snapshot_baseline()
    net_mon.snapshot_baseline()

    threads = []
    for mon in [proc_mon, file_mon, reg_mon, net_mon]:
        t = threading.Thread(target=mon.monitor, daemon=True)
        t.start()
        threads.append(t)

    log("Detonating {}...".format(filename))
    try:
        detonate(sample_path, method)
    except Exception as e:
        log("Detonation error: {}".format(e))

    log("Monitoring for {} seconds...".format(MONITOR_DURATION))
    time.sleep(MONITOR_DURATION)

    log("Stopping monitors...")
    proc_mon.stop()
    file_mon.stop()
    reg_mon.stop()
    net_mon.stop()

    for t in threads:
        t.join(timeout=5)

    all_suspicious = (
        proc_mon.suspicious +
        file_mon.suspicious +
        reg_mon.suspicious +
        net_mon.suspicious
    )

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
        "dns_queries": [],
        "suspicious_behaviors": all_suspicious,
        "risk_score": compute_risk_score(all_suspicious),
        "summary": _generate_summary(all_suspicious, proc_mon, file_mon, reg_mon, net_mon),
    }

    report_path = os.path.join(RESULTS_DIR, "report_{}.json".format(sha256[:16]))
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log("Report written: {}".format(report_path))
    log("Risk score: {}/100".format(report["risk_score"]))
    log("Suspicious behaviors: {}".format(len(all_suspicious)))
    log("Agent complete.")


def _generate_summary(suspicious, proc_mon, file_mon, reg_mon, net_mon):
    if not suspicious:
        return "No suspicious behavior observed during detonation."

    parts = []
    if proc_mon.suspicious:
        procs = [s["detail"] for s in proc_mon.suspicious]
        parts.append("Process spawning: {}".format("; ".join(procs)))
    if file_mon.suspicious:
        drops = [s["detail"] for s in file_mon.suspicious]
        parts.append("File drops: {}".format("; ".join(drops[:5])))
    if reg_mon.suspicious:
        regs = [s["detail"] for s in reg_mon.suspicious]
        parts.append("Registry persistence: {}".format("; ".join(regs[:5])))
    if net_mon.suspicious:
        nets = [s["detail"] for s in net_mon.suspicious]
        parts.append("Network activity: {}".format("; ".join(nets[:5])))

    return " | ".join(parts)


if __name__ == "__main__":
    run_agent()
