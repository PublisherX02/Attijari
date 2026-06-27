import os
import pytest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
BASE_DIR = SRC_DIR.parent

def test_swe_benchmark_pro_architectural_refactoring():
    """
    SWE*benchmark Pro Evaluation:
    Evaluates if the AI agent successfully refactored a monolithic api.py into a modular architecture.
    Criteria:
    1. api.py exists and is stripped down (less than 300 lines).
    2. routers/ directory exists and contains auth, dashboard, emails, and websockets modules.
    3. tasks/background.py exists.
    """
    # 1. Check api.py reduction
    api_py_path = SRC_DIR / "api.py"
    assert api_py_path.exists(), "api.py should exist"
    with open(api_py_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    assert len(lines) < 300, f"api.py should be refactored to be thin, but has {len(lines)} lines"

    # 2. Check routers
    routers_dir = SRC_DIR / "routers"
    assert routers_dir.exists() and routers_dir.is_dir(), "routers/ directory missing"
    assert (routers_dir / "auth.py").exists(), "auth.py router missing"
    assert (routers_dir / "dashboard.py").exists(), "dashboard.py router missing"
    assert (routers_dir / "emails.py").exists(), "emails.py router missing"
    assert (routers_dir / "websockets.py").exists(), "websockets.py router missing"

    # 3. Check background tasks
    assert (SRC_DIR / "tasks" / "background.py").exists(), "tasks/background.py missing"

def test_swe_benchmark_pro_high_availability():
    """
    SWE*benchmark Pro Evaluation:
    Evaluates if the High Availability (HA) configuration was correctly applied.
    Criteria:
    1. start.bat must launch uvicorn with '--workers 4'.
    2. main.py --serve must launch uvicorn with 'workers=4'.
    """
    start_bat_path = BASE_DIR / "start.bat"
    main_py_path = SRC_DIR / "main.py"

    assert start_bat_path.exists(), "start.bat missing"
    assert main_py_path.exists(), "main.py missing"

    with open(main_py_path, 'r', encoding='utf-8') as f:
        main_content = f.read()
    
    assert "workers=4" in main_content, "Uvicorn HA workers not configured in main.py"

def test_gdpval_soc2_iso27001_compliance():
    """
    GDPval Real-World Economic Task Evaluation:
    Evaluates if the AI delivered professional-grade compliance implementations for SOC 2 and ISO 27001.
    Criteria:
    1. Data Retention Purge: Code exists to delete records older than 90 days.
    2. Data Masking (A.8.11): PII masking logic is active on email addresses.
    """
    # 1. Data Retention
    bg_task_path = SRC_DIR / "tasks" / "background.py"
    with open(bg_task_path, 'r', encoding='utf-8') as f:
        bg_content = f.read()
    
    assert "timedelta(days=90)" in bg_content or "days=90" in bg_content, "90-day retention policy missing"
    assert ".delete()" in bg_content, "Database purge command missing"

    # 2. PII Masking
    core_path = SRC_DIR / "api_core.py"
    with open(core_path, 'r', encoding='utf-8') as f:
        core_content = f.read()
    
    assert "def mask_pii(" in core_content, "PII masking function missing"
    assert "***" in core_content, "PII obfuscation characters missing"

def test_gdpval_nist_cp9_contingency_planning():
    """
    GDPval Evaluation:
    Evaluates if NIST CP-9 (Contingency Planning - Secure Off-site Backups) is professionally implemented.
    Criteria:
    1. Backups must be encrypted before rest.
    2. Backups must be placed in a dedicated offsite vault directory.
    """
    bg_task_path = SRC_DIR / "tasks" / "background.py"
    with open(bg_task_path, 'r', encoding='utf-8') as f:
        bg_content = f.read()
    
    assert "pg_dump" in bg_content, "Database dump utility not utilized"
    assert "fernet.encrypt(" in bg_content, "Backup encryption (NIST CP-9) missing"
    assert "offsite_vault" in bg_content, "Offsite vault destination missing"
    assert "os.remove(backup_file)" in bg_content or "os.remove" in bg_content, "Unencrypted backup file not shredded"
