import sys
import os
import time

# Ensure src/ is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dotenv import load_dotenv

def print_result(name: str, success: bool, message: str = ""):
    status = "[\033[92mOK\033[0m]" if success else "[\033[91mFAIL\033[0m]"
    print(f"{status} {name:<25} {message}")

def test_database():
    try:
        from database import init_db, SessionLocal
        init_db()
        db = SessionLocal()
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db.close()
        print_result("Database", True, "Successfully connected and executed query")
    except Exception as e:
        print_result("Database", False, str(e))

def test_dashboard_api():
    try:
        from fastapi.testclient import TestClient
        from api import app
        client = TestClient(app)
        
        # Test health endpoint
        res1 = client.get("/api/health")
        if res1.status_code != 200:
            print_result("Dashboard API", False, f"/api/health returned {res1.status_code}")
            return
            
        # Test stats endpoint (uses DB)
        res2 = client.get("/api/stats")
        if res2.status_code != 200:
            print_result("Dashboard API", False, f"/api/stats returned {res2.status_code}")
            return
            
        # Test emails endpoint (uses DB)
        res3 = client.get("/api/emails")
        if res3.status_code != 200:
            print_result("Dashboard API", False, f"/api/emails returned {res3.status_code}")
            return
            
        print_result("Dashboard API", True, "Successfully queried localhost API endpoints")
    except Exception as e:
        print_result("Dashboard API", False, str(e))

def test_imap():
    try:
        from email_extraction import EmailIngestion
        ingestion = EmailIngestion(
            host=os.getenv("IMAP_HOST"),
            user=os.getenv("IMAP_USER"),
            password=os.getenv("IMAP_PASSWORD"),
        )
        ingestion.connect()
        ingestion.disconnect()
        print_result("IMAP Ingestion", True, "Successfully connected to IMAP server")
    except Exception as e:
        print_result("IMAP Ingestion", False, str(e))

def test_sandbox():
    try:
        from sandbox import check_sandbox_status
        status = check_sandbox_status()
        if status.get("docker_available"):
            print_result("Sandbox (Docker)", True, f"Docker is available. Images: {status.get('images')}")
        else:
            print_result("Sandbox (Docker)", False, "Docker daemon is not running")
    except Exception as e:
        print_result("Sandbox (Docker)", False, str(e))

def test_threatfox():
    try:
        from ThreatFoxAPI import check_threatfox
        res = check_threatfox("8.8.8.8", indicator_type="ip")
        if "error" in res:
            print_result("ThreatFox API", False, res["error"])
        else:
            print_result("ThreatFox API", True, "Successfully reached ThreatFox")
    except Exception as e:
        print_result("ThreatFox API", False, str(e))

def test_virustotal():
    try:
        from virustotal import check_hash
        # Use EICAR hash or empty sha256 to test connection safely
        dummy_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" # EICAR hash
        res = check_hash(dummy_sha)
        if "error" in res:
            print_result("VirusTotal API", False, res["error"])
        else:
            print_result("VirusTotal API", True, f"Successfully reached VT (detections: {res.get('detection_count', 'unknown')})")
    except Exception as e:
        print_result("VirusTotal API", False, str(e))

def test_abuseipdb():
    try:
        from abuseipdb import check_ip
        res = check_ip("8.8.8.8")
        if "error" in res:
            print_result("AbuseIPDB API", False, res["error"])
        else:
            print_result("AbuseIPDB API", True, f"Successfully reached AbuseIPDB (score: {res.get('abuse_score', 'unknown')})")
    except Exception as e:
        print_result("AbuseIPDB API", False, str(e))

def test_otx():
    try:
        from alienvault_otx import check_ip
        res = check_ip("8.8.8.8")
        if "error" in res:
            print_result("AlienVault OTX", False, res["error"])
        else:
            print_result("AlienVault OTX", True, f"Successfully reached OTX (pulse count: {res.get('pulse_count', 'unknown')})")
    except Exception as e:
        print_result("AlienVault OTX", False, str(e))

def test_dnstwist():
    try:
        from dnstwist_check import is_typosquat
        # Using a clearly safe/legitimate domain to verify it doesn't crash
        res = is_typosquat("google.com")
        print_result("DNSTwist", True, f"Execution successful (typosquat={res.get('is_typosquat')})")
    except Exception as e:
        print_result("DNSTwist", False, str(e))

def test_whois():
    try:
        from whois_check import check_domain_age
        res = check_domain_age("google.com")
        if "error" in res:
            print_result("WHOIS/RDAP", False, res["error"])
        else:
            print_result("WHOIS/RDAP", True, f"Successfully resolved domain age: {res.get('domain_age_days', 'unknown')} days")
    except Exception as e:
        print_result("WHOIS/RDAP", False, str(e))

def test_llm():
    try:
        from analysis import analyze_email_body
        res = analyze_email_body("Hello, this is a test email.", context={})
        if res.get("verdict"):
            print_result("LLM (Ollama)", True, f"Successfully generated verdict: {res['verdict']}")
        else:
            print_result("LLM (Ollama)", False, "Received empty or invalid response from LLM")
    except Exception as e:
        print_result("LLM (Ollama)", False, str(e))

def main():
    os.system('color') # Enable ansi escape characters in windows
    print("==================================================")
    print("Starting Comprehensive Component Diagnostics...")
    print("==================================================\n")
    
    load_dotenv()
    
    print("--- 1. Infrastructure & API ---")
    test_database()
    test_dashboard_api()
    test_imap()
    test_sandbox()
    
    print("\n--- 2. Enrichment APIs ---")
    test_threatfox()
    test_virustotal()
    test_abuseipdb()
    test_otx()
    
    print("\n--- 3. Context & Domain ---")
    test_dnstwist()
    test_whois()
    
    print("\n--- 4. Machine Learning ---")
    test_llm()
    
    print("\n==================================================")
    print("Diagnostics Completed.")
    print("==================================================")

if __name__ == "__main__":
    main()
