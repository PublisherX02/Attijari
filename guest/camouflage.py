"""Anti-VM-detection camouflage — makes the VM look like a real workstation.

Compatible with Python 3.7 on Windows 7.
"""
import os
import random
import threading
import time
import ctypes
from pathlib import Path

DESKTOP = Path(os.path.expanduser("~")) / "Desktop"
DOCUMENTS = Path(os.path.expanduser("~")) / "Documents"


def create_decoy_files():
    desktop_files = [
        ("Budget_2026_Q3.xlsx", b"PK\x03\x04"),
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
            with open(str(path), "wb") as f:
                f.write(magic)
                f.write(os.urandom(random.randint(1024, 8192)))

    DOCUMENTS.mkdir(exist_ok=True)
    for name, magic in doc_files:
        path = DOCUMENTS / name
        if not path.exists():
            with open(str(path), "wb") as f:
                f.write(magic)
                f.write(os.urandom(random.randint(2048, 16384)))


def create_browser_artifacts():
    chrome_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"
    chrome_dir.mkdir(parents=True, exist_ok=True)
    local_state = chrome_dir / "Local State"
    if not local_state.exists():
        with open(str(local_state), "w") as f:
            f.write('{"profile":{"info_cache":{"Default":{"name":"analyst"}}}}')

    ff_dir = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox"
    ff_dir.mkdir(parents=True, exist_ok=True)
    profiles_ini = ff_dir / "profiles.ini"
    if not profiles_ini.exists():
        with open(str(profiles_ini), "w") as f:
            f.write("[General]\nStartWithLastProfile=1\n")


def simulate_mouse_movement():
    while True:
        try:
            x = random.randint(-3, 3)
            y = random.randint(-3, 3)
            ctypes.windll.user32.mouse_event(0x0001, x, y, 0, 0)
        except Exception:
            pass
        time.sleep(random.uniform(5, 15))


def main():
    print("[CAMOUFLAGE] Setting up realistic environment...")
    create_decoy_files()
    create_browser_artifacts()
    os.environ["NUMBER_OF_PROCESSORS"] = "4"
    print("[CAMOUFLAGE] Decoy files and artifacts created")

    t = threading.Thread(target=simulate_mouse_movement, daemon=True)
    t.start()
    print("[CAMOUFLAGE] Mouse movement simulation started")
    print("[CAMOUFLAGE] Ready")


if __name__ == "__main__":
    main()
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
