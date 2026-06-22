import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from dotenv import load_dotenv

import ThreatFoxAPI
import virustotal
import abuseipdb
import alienvault_otx
import dnstwist_check
import analysis
import threat_feeds
import sandbox
import email_extraction
import rules

def print_result(name, result, error=None):
    if error:
        print(f"[FAIL] {name}: {error}")
    else:
        print(f"[OK]   {name}")

def test_all():
    load_dotenv()
    print("=== Architecture Component Test ===")
    
    # 1. Threat Feeds
    try:
        feeds = threat_feeds.get_feeds()
        print_result("ThreatFeeds (Local)", None)
    except Exception as e:
        print_result("ThreatFeeds (Local)", None, str(e))

    # 2. ThreatFox
    try:
        dummy_hash = "d41d8cd98f00b204e9800998ecf8427e" * 2 # valid 64 char
        res = ThreatFoxAPI.check_threatfox(dummy_hash)
        if "error" in res and res["error"] == "missing_api_key":
            print_result("ThreatFox API", None, "SKIPPED (Missing API Key)")
        else:
            print_result("ThreatFox API", res)
    except Exception as e:
        print_result("ThreatFox API", None, str(e))

    # 3. VirusTotal
    try:
        res = virustotal.check_hash(dummy_hash)
        if "error" in res and res["error"] == "missing_api_key":
            print_result("VirusTotal API", None, "SKIPPED (Missing API Key)")
        else:
            print_result("VirusTotal API", res)
    except Exception as e:
        print_result("VirusTotal API", None, str(e))

    # 4. AbuseIPDB
    try:
        res = abuseipdb.check_ip("8.8.8.8")
        if "error" in res and res["error"] == "missing_api_key":
            print_result("AbuseIPDB API", None, "SKIPPED (Missing API Key)")
        else:
            print_result("AbuseIPDB API", res)
    except Exception as e:
        print_result("AbuseIPDB API", None, str(e))

    # 5. AlienVault OTX
    try:
        res = alienvault_otx.check_ip("8.8.8.8")
        if "error" in res and res["error"] == "missing_api_key":
            print_result("AlienVault OTX", None, "SKIPPED (Missing API Key)")
        else:
            print_result("AlienVault OTX", res)
    except Exception as e:
        print_result("AlienVault OTX", None, str(e))

    # 6. dnstwist
    try:
        res = dnstwist_check.is_typosquat("attijaribank.com")
        print_result("dnstwist", res)
    except Exception as e:
        print_result("dnstwist", None, str(e))

    # 7. Sandbox (Docker check)
    try:
        import subprocess
        res = subprocess.run(["docker", "info"], capture_output=True, text=True)
        if res.returncode == 0:
            print_result("Docker Sandbox Engine", "Available")
        else:
            print_result("Docker Sandbox Engine", None, "Docker not running")
    except Exception as e:
        print_result("Docker Sandbox Engine", None, f"Docker check failed: {e}")

    # 8. Ollama LLM
    try:
        print("Testing Ollama LLM...")
        res = analysis.analyze_email_body("Please click here to update your password.", context={})
        verdict = res.get("verdict", "").lower()
        if verdict in ("escalated", "rejeter", "escalader"):
            print_result("Ollama LLM", res)
        else:
            print_result("Ollama LLM", None, f"Unexpected or failed verdict: {res}")
    except Exception as e:
        print_result("Ollama LLM", None, str(e))

if __name__ == "__main__":
    test_all()
