"""enrichment.py — Stage 4: Signal Enrichment Orchestration

Runs all external metadata lookups and returns a unified result.
Each enrichment source can escalate the email to proposed_reject.

Sources:
  - ThreatFox (abuse.ch): IP/domain/hash C2 lookup
  - VirusTotal: SHA-256 hash reputation (NEVER upload files)
  - AbuseIPDB: IP abuse confidence score
  - AlienVault OTX: campaign context for IPs/domains/hashes
  - dnstwist: typosquat detection on sender domain
  - WHOIS/RDAP: domain age check

CLAUDE.md compliance:
  - Only metadata (hashes, IPs, domains) is sent externally
  - Never send email content to any external service
  - Shared infrastructure IPs (Gmail, Outlook) are filtered out
"""
from __future__ import annotations

from email.utils import parseaddr
from typing import Any

import time as _time

from ThreatFoxAPI import check_threatfox
from abuseipdb import check_ip as check_abuseipdb
from virustotal import check_hash as check_virustotal
from alienvault_otx import (
    check_ip as check_otx_ip,
    check_domain as check_otx_domain,
    check_hash as check_otx_hash,
)
from dnstwist_check import is_typosquat
from whois_check import check_domain_age
from validators import is_valid_domain, is_valid_sha256, extract_ips_from_text, is_shared_infrastructure_ip
from health import record_success, record_failure


def run_enrichment(parsed: dict) -> dict:
    """Run all enrichment sources against a parsed email.

    Args:
        parsed: parsed email dict with headers, attachments, extraction results, etc.

    Returns:
        dict with:
          - status: "proposed_reject" if any deterministic hit, else None
          - threatfox, virustotal, abuseipdb, otx, dnstwist, whois: per-source results
          - all_ips: validated IPs found (for cascading blocklist)
          - sender_domain: validated sender domain (or None)
          - details: list of flagged rule-like entries for analysis
    """
    result = {
        "status": None,
        "threatfox": [],
        "virustotal": [],
        "abuseipdb": [],
        "otx": [],
        "dnstwist": {},
        "whois": {},
        "all_ips": [],
        "sender_domain": None,
        "details": [],
    }

    def _set_reject(source: str, reason: str):
        result["status"] = "proposed_reject"
        print(f"[{source}] {reason}")

    # --- Validate sender domain once ---
    sender_raw = parsed.get("headers", {}).get("from")
    sender_addr = parseaddr(sender_raw)[1] if sender_raw else ""
    sender_domain = None
    if sender_addr and "@" in sender_addr:
        dom = sender_addr.split("@")[-1].strip().lower()
        if is_valid_domain(dom):
            sender_domain = dom
        else:
            print(f"[VALIDATION] Sender domain '{dom}' failed validation — skipping external API lookups for domain")
    result["sender_domain"] = sender_domain

    # === ThreatFox ===
    threat_results = []
    found_count = 0
    errors = []
    try:
        for att in parsed.get("attachments", []):
            sha = att.get("sha256") or att.get("sha")
            if sha and is_valid_sha256(sha):
                print(f"[THREATFOX] Querying hash for attachment {att.get('original_name')}: {sha}")
                t0 = _time.time()
                try:
                    res = check_threatfox(sha, indicator_type="hash")
                    record_success("threatfox", _time.time() - t0)
                except Exception as e:
                    record_failure("threatfox", str(e), _time.time() - t0)
                    raise
                threat_results.append(res)
                if res.get("found"):
                    found_count += 1
                    _set_reject("THREATFOX", f"Attachment {att.get('original_name')} ({sha[:12]}...) flagged")
                if res.get("error"):
                    errors.append(res["error"])
                    record_failure("threatfox", res["error"])

        if sender_domain:
            print(f"[THREATFOX] Querying domain: {sender_domain}")
            t0 = _time.time()
            try:
                res = check_threatfox(sender_domain, indicator_type="domain")
                record_success("threatfox", _time.time() - t0)
            except Exception as e:
                record_failure("threatfox", str(e), _time.time() - t0)
                raise
            threat_results.append(res)
            if res.get("found"):
                found_count += 1
                _set_reject("THREATFOX", f"Sender domain {sender_domain} flagged")
            if res.get("error"):
                errors.append(res["error"])
                record_failure("threatfox", res["error"])

        raw_sha = parsed.get("raw_sha256")
        if raw_sha and is_valid_sha256(raw_sha):
            print(f"[THREATFOX] Querying raw email SHA256: {raw_sha}")
            t0 = _time.time()
            try:
                res = check_threatfox(raw_sha, indicator_type="hash")
                record_success("threatfox", _time.time() - t0)
            except Exception as e:
                record_failure("threatfox", str(e), _time.time() - t0)
                raise
            threat_results.append(res)
            if res.get("found"):
                found_count += 1
                _set_reject("THREATFOX", f"Raw email hash {raw_sha[:12]}... flagged")
            if res.get("error"):
                errors.append(res["error"])
                record_failure("threatfox", res["error"])
    except Exception as e:
        errors.append(str(e))
        print(f"[THREATFOX] Lookup failed: {e}")

    if threat_results:
        print(f"[THREATFOX] Checked {len(threat_results)} indicator(s), matches: {found_count}")
        for r in threat_results:
            ind = r.get("indicator") or r.get("search_term") or r.get("hash") or r.get("ioc")
            itype = r.get("indicator_type") or "unknown"
            if r.get("found"):
                print(f"  - {itype}: {ind} -> FOUND")
            elif r.get("error"):
                print(f"  - {itype}: {ind} -> ERROR: {r.get('error')}")
            else:
                print(f"  - {itype}: {ind} -> not found")
    else:
        print("[THREATFOX] No indicators checked")
    if errors:
        print(f"[THREATFOX] Errors: {errors}")

    result["threatfox"] = threat_results
    if found_count > 0:
        result["details"].append({"rule": "threatfox", "flagged": True,
                                  "reason": f"ThreatFox match count={found_count}"})

    # === VirusTotal ===
    vt_results = []
    try:
        for att in parsed.get("attachments", []):
            sha = att.get("sha256")
            if sha and is_valid_sha256(sha):
                print(f"[VIRUSTOTAL] Querying hash: {att.get('original_name')} ({sha[:12]}...)")
                t0 = _time.time()
                try:
                    vt_res = check_virustotal(sha)
                    record_success("virustotal", _time.time() - t0)
                except Exception as e:
                    record_failure("virustotal", str(e), _time.time() - t0)
                    raise
                vt_results.append(vt_res)
                if vt_res.get("detected"):
                    names = ", ".join(vt_res.get("malware_names", [])[:3]) or "unknown"
                    _set_reject("VIRUSTOTAL",
                                f"DETECTED: {vt_res['detection_count']}/{vt_res.get('total_engines', 0)} engines — {names}")
                elif vt_res.get("error"):
                    print(f"[VIRUSTOTAL] ERROR: {vt_res['error']}")
                    record_failure("virustotal", vt_res["error"])
                elif vt_res.get("note") == "hash_not_found_in_vt":
                    print(f"[VIRUSTOTAL] Hash not in database (first seen)")
                else:
                    print(f"[VIRUSTOTAL] Clean ({vt_res.get('detection_count', 0)}/{vt_res.get('total_engines', 0)})")
    except Exception as e:
        print(f"[VIRUSTOTAL] Lookup failed: {e}")
    result["virustotal"] = vt_results

    # === AbuseIPDB ===
    abuseipdb_results = []
    all_ips: list[str] = []
    try:
        received_raw = parsed.get("headers", {}).get("received") or ""
        if isinstance(received_raw, list):
            received_raw = " ".join(str(r) for r in received_raw)
        header_ips = extract_ips_from_text(str(received_raw))

        ext_ips = []
        for ext_res in parsed.get("extraction", {}).get("results", []):
            for v4 in ext_res.get("iocs", {}).get("ipv4s", []):
                ext_ips.append(v4)
            for v6 in ext_res.get("iocs", {}).get("ipv6s", []):
                ext_ips.append(v6)

        all_ips = list(set(header_ips + [ip for ip in ext_ips if ip.strip()]))
        all_ips = [ip for ip in all_ips if ip]

        # Filter shared infrastructure IPs (CLAUDE.md)
        infra_ips = [ip for ip in all_ips if is_shared_infrastructure_ip(ip)]
        if infra_ips:
            print(f"[INFRA] Skipping {len(infra_ips)} shared infrastructure IP(s): {', '.join(infra_ips[:3])}")
        all_ips = [ip for ip in all_ips if not is_shared_infrastructure_ip(ip)]

        if all_ips:
            print(f"[ABUSEIPDB] Checking {len(all_ips)} IP(s)...")
            for ip in all_ips[:10]:
                t0 = _time.time()
                try:
                    res = check_abuseipdb(ip)
                    record_success("abuseipdb", _time.time() - t0)
                except Exception as e:
                    record_failure("abuseipdb", str(e), _time.time() - t0)
                    raise
                abuseipdb_results.append(res)
                if res.get("skipped"):
                    continue
                score = res.get("abuse_score", 0)
                if res.get("is_malicious"):
                    _set_reject("ABUSEIPDB",
                                f"{ip} -> MALICIOUS (score={score}, reports={res.get('total_reports')}, "
                                f"isp={res.get('isp')}, country={res.get('country_code')})")
                elif res.get("error"):
                    print(f"[ABUSEIPDB] {ip} -> ERROR: {res['error']}")
                    record_failure("abuseipdb", res["error"])
                else:
                    print(f"[ABUSEIPDB] {ip} -> clean (score={score})")
        else:
            print("[ABUSEIPDB] No IPs to check")
    except Exception as e:
        print(f"[ABUSEIPDB] Lookup failed: {e}")
    result["abuseipdb"] = abuseipdb_results
    result["all_ips"] = all_ips

    # === AlienVault OTX ===
    otx_results = []
    try:
        if sender_domain:
            print(f"[OTX] Querying domain: {sender_domain}")
            t0 = _time.time()
            try:
                otx_dom = check_otx_domain(sender_domain)
                record_success("otx", _time.time() - t0)
            except Exception as e:
                record_failure("otx", str(e), _time.time() - t0)
                raise
            otx_results.append(otx_dom)
            if otx_dom.get("found"):
                pulses = otx_dom.get("pulse_count", 0)
                tags = ", ".join(otx_dom.get("tags", [])[:5]) or "none"
                _set_reject("OTX", f"Domain {sender_domain} FLAGGED — {pulses} pulse(s), tags: {tags}")
            elif otx_dom.get("error"):
                print(f"[OTX] Domain {sender_domain} -> ERROR: {otx_dom['error']}")
                record_failure("otx", otx_dom["error"])
            else:
                print(f"[OTX] Domain {sender_domain} -> clean")

        for ip in all_ips[:10]:
            print(f"[OTX] Querying IP: {ip}")
            t0 = _time.time()
            try:
                otx_ip = check_otx_ip(ip)
                record_success("otx", _time.time() - t0)
            except Exception as e:
                record_failure("otx", str(e), _time.time() - t0)
                raise
            otx_results.append(otx_ip)
            if otx_ip.get("found"):
                pulses = otx_ip.get("pulse_count", 0)
                families = ", ".join(otx_ip.get("malware_families", [])) or "none"
                _set_reject("OTX", f"IP {ip} FLAGGED — {pulses} pulse(s), malware: {families}")
            elif otx_ip.get("error"):
                print(f"[OTX] IP {ip} -> ERROR: {otx_ip['error']}")
                record_failure("otx", otx_ip["error"])
            else:
                print(f"[OTX] IP {ip} -> clean")

        for att in parsed.get("attachments", []):
            sha = att.get("sha256")
            if sha and is_valid_sha256(sha):
                print(f"[OTX] Querying hash: {att.get('original_name')} ({sha[:12]}...)")
                t0 = _time.time()
                try:
                    otx_h = check_otx_hash(sha)
                    record_success("otx", _time.time() - t0)
                except Exception as e:
                    record_failure("otx", str(e), _time.time() - t0)
                    raise
                otx_results.append(otx_h)
                if otx_h.get("found"):
                    families = ", ".join(otx_h.get("malware_families", [])) or "unknown"
                    _set_reject("OTX", f"Hash FLAGGED — {otx_h.get('pulse_count', 0)} pulse(s), malware: {families}")
                elif otx_h.get("error"):
                    print(f"[OTX] Hash -> ERROR: {otx_h['error']}")
                    record_failure("otx", otx_h["error"])
                else:
                    print(f"[OTX] Hash -> clean")
    except Exception as e:
        print(f"[OTX] Lookup failed: {e}")

    otx_hits = sum(1 for r in otx_results if r.get("found"))
    if otx_hits > 0:
        result["details"].append({"rule": "otx", "flagged": True,
                                  "reason": f"AlienVault OTX match count={otx_hits}"})
    print(f"[OTX] Checked {len(otx_results)} indicator(s), matches: {otx_hits}")
    result["otx"] = otx_results

    # === dnstwist ===
    dnstwist_result = {}
    try:
        if sender_domain:
            print(f"[DNSTWIST] Checking if {sender_domain} is a typosquat...")
            t0 = _time.time()
            try:
                dnstwist_result = is_typosquat(sender_domain)
                record_success("dnstwist", _time.time() - t0)
            except Exception as e:
                record_failure("dnstwist", str(e), _time.time() - t0)
                raise
            if dnstwist_result.get("is_typosquat"):
                _set_reject("DNSTWIST",
                            f"TYPOSQUAT DETECTED — {sender_domain} impersonates {dnstwist_result['impersonates']}")
            else:
                print(f"[DNSTWIST] {sender_domain} -> not a typosquat")
        else:
            print("[DNSTWIST] No valid sender domain to check")
    except Exception as e:
        print(f"[DNSTWIST] Check failed: {e}")

    if dnstwist_result.get("is_typosquat"):
        result["details"].append({"rule": "dnstwist", "flagged": True,
                                  "reason": f"Typosquat of {dnstwist_result['impersonates']}"})
    result["dnstwist"] = dnstwist_result

    # === WHOIS ===
    whois_result = {}
    try:
        if sender_domain:
            print(f"[WHOIS] Checking domain age: {sender_domain}")
            t0 = _time.time()
            try:
                whois_result = check_domain_age(sender_domain)
                record_success("whois", _time.time() - t0)
            except Exception as e:
                record_failure("whois", str(e), _time.time() - t0)
                raise
            age = whois_result.get("domain_age_days")
            if whois_result.get("is_new_domain"):
                _set_reject("WHOIS", f"NEW DOMAIN — {sender_domain} registered {age} day(s) ago")
            elif age is not None:
                print(f"[WHOIS] {sender_domain} -> {age} day(s) old (OK)")
            elif whois_result.get("error"):
                print(f"[WHOIS] {sender_domain} -> ERROR: {whois_result['error']}")
                record_failure("whois", whois_result["error"])
            else:

                
                
                print(f"[WHOIS] {sender_domain} -> age unknown")
        else:
            print("[WHOIS] No valid sender domain to check")
    except Exception as e:
        print(f"[WHOIS] Check failed: {e}")

    if whois_result.get("is_new_domain"):
        result["details"].append({"rule": "whois_new_domain", "flagged": True,
                                  "reason": f"Domain registered {whois_result.get('domain_age_days', '?')} days ago"})
    result["whois"] = whois_result

    return result
