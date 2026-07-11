"""Guest agent configuration — runs INSIDE the Windows 7 VM."""

# --- Paths ---
SUBMIT_DIR = r"C:\sandbox\submit"
RESULTS_DIR = r"C:\sandbox\results"
AGENT_LOG = r"C:\sandbox\agent.log"

# --- Monitoring ---
MONITOR_DURATION = 90  # seconds to observe after opening file

# --- File type -> open method mapping ---
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
    # Archives
    ".zip": "extract", ".rar": "extract", ".7z": "extract",
}

# --- Suspicious process names ---
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
