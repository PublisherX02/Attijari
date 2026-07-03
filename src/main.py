import os
import sys
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from dotenv import load_dotenv

from email_extraction import EmailIngestion, TimeoutError, verify_sender_authentication
from rules import RuleEngine, add_to_blocklist
from analysis import analyze_email_body
from logger import get_logger
from ThreatFoxAPI import check_threatfox
from abuseipdb import check_ip as check_abuseipdb
from virustotal import check_hash as check_virustotal
from dkim_verify import verify_all as verify_email_auth
from extraction import extract_all_attachments
from threat_feeds import get_feeds
from sandbox import check_sandbox_status
from alienvault_otx import check_ip as check_otx_ip, check_domain as check_otx_domain, check_hash as check_otx_hash
from dnstwist_check import is_typosquat
from whois_check import check_domain_age
from validators import is_valid_domain, is_valid_sha256, extract_ips_from_text


def run_pipeline():
    load_dotenv()
    logger = get_logger("pipeline")

    logger.info("=" * 50)
    logger.info("[START] Email Ingestion & Analysis Pipeline")
    logger.info("=" * 50)
    t_start = time.time()

    # Initialize threat feeds (OpenPhish + URLhaus)
    feeds = get_feeds()

    # Check sandbox status
    sandbox = check_sandbox_status()
    if sandbox["docker_available"]:
        built = sum(1 for v in sandbox["images"].values() if v)
        total = len(sandbox["images"])
        print(f"[SANDBOX] Docker OK — {built}/{total} extraction containers built")
    else:
        print("[SANDBOX] Docker unavailable — extraction tools run locally (less isolated)")

    # Initialize database session
    db = None
    try:
        from database import SessionLocal, init_db, save_email, get_cached_email, add_audit_entry
        init_db()
        db = SessionLocal()
        print("[DB] PostgreSQL connected")
    except Exception as e:
        print(f"[DB] PostgreSQL unavailable ({e}) — using JSON ledger fallback")
        db = None

    ingestion = EmailIngestion(
        host=os.getenv("IMAP_HOST"),
        user=os.getenv("IMAP_USER"),
        password=os.getenv("IMAP_PASSWORD"),
    )
    engine = RuleEngine()

    try:
        ingestion.connect()
        raw_emails = ingestion.fetch_recent(since_days=7, limit=50)

        cached = 0
        for i, raw in enumerate(raw_emails, 1):
            print(f"\n--- Email {i}/{len(raw_emails)} ---")

            # archive raw BEFORE parsing — crash-safe
            ingestion.archive_raw(raw)

            # check idempotency cache
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            message_id = msg.get("Message-ID")
            idem_key = ingestion.idempotency_key(raw, str(message_id) if message_id else None)

            # Check DB cache first, then fall back to JSON
            # encode-safe helper for Windows cp1252 console
            def _safe(s): return str(s).encode("ascii", "replace").decode("ascii") if s else ""

            if db:
                cached_email = get_cached_email(db, idem_key)
                if cached_email and cached_email.llm_result:
                    print(f"[CACHED] Already processed:")
                    print(f"  De:     {_safe(cached_email.sender)}")
                    print(f"  Sujet:  {_safe(cached_email.subject)}")
                    print(f"  Statut: {cached_email.status}")
                    cached += 1
                    continue
            else:
                prev = ingestion.get_cached_result(raw, str(message_id) if message_id else None)
                if prev:
                    print(f"[CACHED] Already processed:")
                    print(f"  De:     {_safe(prev.get('from'))}")
                    print(f"  Sujet:  {_safe(prev.get('subject'))}")
                    print(f"  PJ:     {prev.get('attachments')}")
                    print(f"  Statut: {prev['status']}")
                    if prev.get("parse_errors"):
                        print(f"  Erreurs: {prev['parse_errors']}")
                    cached += 1
                    continue

            # parse
            parsed = ingestion.parse_email(raw)
            
            # Protocol Authentication (SPF/DMARC)
            # DMARC failure is a strong signal but NOT auto-quarantine — many legitimate
            # senders have misconfigured auth (forwarded mail, mailing lists, new domains).
            # Escalate so the full pipeline still runs and the analyst gets full context.
            if not verify_sender_authentication(raw):
                print("[AUTH] Protocol Authentication (DMARC) Failed — escalating for full analysis.")
                parsed["status"] = "escalated"
                parsed["dmarc_failed"] = True

            # --- Parse original email Date header ---
            _email_date = None
            try:
                from email.utils import parsedate_to_datetime
                _date_hdr = parsed.get("headers", {}).get("date")
                if _date_hdr:
                    _email_date = parsedate_to_datetime(_date_hdr)
            except Exception:
                pass  # unparseable date — leave as None

            # --- Save as "pending" immediately so the dashboard shows it ---
            _sender_raw_early = parsed.get("headers", {}).get("from", "")
            _, _sender_addr_early = parseaddr(_sender_raw_early)
            _sender_domain_early = None
            if _sender_addr_early and "@" in _sender_addr_early:
                _sender_domain_early = _sender_addr_early.split("@")[-1].strip().lower()

            pending_record = None
            if db:
                try:
                    from database import save_email as _save_pending
                    pending_data = {
                        "idempotency_key": parsed["idempotency_key"],
                        "message_id": parsed["headers"].get("message-id"),
                        "raw_sha256": parsed.get("raw_sha256", ""),
                        "sender": _sender_raw_early,
                        "sender_domain": _sender_domain_early,
                        "subject": parsed["headers"].get("subject"),
                        "attachment_count": len(parsed["attachments"]),
                        "status": parsed.get("status", "pending"),
                        "email_date": _email_date,
                    }
                    pending_record = _save_pending(db, pending_data)
                    print(f"[DB] Email #{pending_record.id} saved as PENDING")
                    # Dashboard refresh is handled by the background poll loop
                    # No need for an internal HTTP notify call
                    pass
                except Exception as e:
                    print(f"[DB] Pending save failed ({e}) — continuing pipeline")

            # DKIM / SPF / DMARC authentication
            try:
                sender = parsed.get("headers", {}).get("from") or ""
                _, addr = parseaddr(sender)
                sender_domain = addr.split("@")[-1].strip().lower() if "@" in addr else None
                auth_header = parsed.get("headers", {}).get("authentication-results")

                print(f"[AUTH] Verifying DKIM/SPF/DMARC for {sender_domain or 'unknown'}...")
                auth_result = verify_email_auth(raw, sender_domain=sender_domain, auth_header=auth_header)
                parsed["auth"] = auth_result

                if auth_result.get("any_failure"):
                    print(f"[AUTH] FAILURES: {auth_result['summary']}")
                else:
                    print(f"[AUTH] All checks passed")

                # Log individual results
                dkim_r = auth_result.get("dkim", {})
                if dkim_r.get("status") == "ok":
                    print(f"  [{'ok' if dkim_r['valid'] else '!!'}] DKIM: {dkim_r.get('details', 'unknown')}")
                ah = auth_result.get("auth_header", {})
                if ah.get("spf") != "none":
                    flag = "ok" if ah["spf"] == "pass" else "!!"
                    print(f"  [{flag}] SPF (header): {ah['spf']}")
                if ah.get("dmarc") != "none":
                    flag = "ok" if ah["dmarc"] == "pass" else "!!"
                    print(f"  [{flag}] DMARC (header): {ah['dmarc']}")
            except Exception as e:
                print(f"[AUTH] Verification failed: {e}")
                parsed["auth"] = {"error": str(e), "any_failure": False}

            # Track whether escalation comes from deterministic signals (rules/enrichment)
            # vs LLM-only. Blocklist cascade should ONLY fire on deterministic hits.
            _deterministic_escalation = parsed["status"] == "escalated"  # from parse errors

            # analyze via rules engine
            if parsed["status"] not in ["quarantined", "blocked"]:
                _pre_rules_status = parsed["status"]
                analysis = engine.analyze(parsed)
                # Rules can escalate but NEVER downgrade an existing escalation
                if _pre_rules_status == "escalated" and analysis["verdict"] == "accepted":
                    analysis["verdict"] = "escalated"
                parsed["status"] = analysis["verdict"]
                parsed["analysis"] = analysis
                print(f"[RULES] {analysis['rules_run']} rules, {analysis['flags']} flag(s) -> {analysis['verdict'].upper()}")
                if analysis.get("flags", 0) > 0:
                    _deterministic_escalation = True
                if _pre_rules_status == "escalated":
                    _deterministic_escalation = True  # prior signal (DMARC/parse) is deterministic
                for detail in analysis["details"]:
                    flag_marker = "!!" if detail["flagged"] else "ok"
                    print(f"  [{flag_marker}] {detail['rule']}: {detail['reason']}")

                # Auto-quarantine: blocklisted sender already confirmed malicious by analyst.
                # No need to re-analyze or wait for review — go straight to quarantine + spam.
                _blocklist_hit = any(
                    d["flagged"] and d["rule"] == "blocklist_domain"
                    for d in analysis.get("details", [])
                )
                if _blocklist_hit:
                    parsed["status"] = "quarantined"
                    parsed["auto_quarantine_reason"] = "blocklisted_sender"
                    print("[AUTO-QUARANTINE] Sender on blocklist (analyst-confirmed) — skipping pipeline, moving to spam")
                    try:
                        from alerts import send_alert, AlertLevel
                        send_alert(
                            AlertLevel.INFO,
                            "Auto-quarantined blocklisted sender",
                            {
                                "sender": parsed.get("headers", {}).get("from", ""),
                                "subject": parsed.get("headers", {}).get("subject", ""),
                                "idempotency_key": parsed.get("idempotency_key"),
                            },
                        )
                    except Exception:
                        pass
                    from routing import _imap_move_to_spam
                    _msg_id = parsed.get("headers", {}).get("message-id", "")
                    if _msg_id:
                        _imap_move_to_spam(_msg_id)
                    # Save to DB and skip remaining pipeline
                    _auto_q_sender = parsed.get("headers", {}).get("from", "")
                    _, _auto_q_addr = parseaddr(_auto_q_sender)
                    _auto_q_domain = None
                    if _auto_q_addr and "@" in _auto_q_addr:
                        _auto_q_domain = _auto_q_addr.split("@")[-1].strip().lower()

                    if db:
                        try:
                            save_email(db, {
                                "idempotency_key": parsed["idempotency_key"],
                                "message_id": parsed["headers"].get("message-id"),
                                "raw_sha256": parsed.get("raw_sha256", ""),
                                "sender": _auto_q_sender,
                                "sender_domain": _auto_q_domain,
                                "subject": parsed["headers"].get("subject"),
                                "attachment_count": len(parsed["attachments"]),
                                "status": "quarantined",
                                "email_date": _email_date,
                                "rules_result": parsed.get("analysis"),
                                "llm_result": None,
                                "llm_reasoning": "Auto-quarantined: sender on analyst-confirmed blocklist",
                                "parse_errors": parsed.get("parse_errors"),
                            })
                            print(f"[DB] Auto-quarantined email from {_auto_q_addr}")
                            # Audit trail
                            try:
                                add_audit_entry(db, action="auto_quarantine", actor="system",
                                    details={"reason": "blocklisted_sender", "sender": _auto_q_addr,
                                             "domain": _auto_q_domain})
                            except Exception:
                                pass
                        except Exception as e:
                            print(f"[DB] Auto-quarantine save failed: {e}")
                    print(f"  De:     {_safe(parsed['headers']['from'])}")
                    print(f"  Sujet:  {_safe(parsed['headers']['subject'])}")
                    print(f"  Statut: quarantined (auto)")
                    continue  # skip extraction/enrichment/LLM

                # Stage 3: Isolated extraction — security analysis of all attachments
                if parsed.get("attachments") and parsed["status"] != "escalated":
                    print(f"[EXTRACTION] Running isolated security extraction on {len(parsed['attachments'])} attachment(s)...")
                    extraction_results = extract_all_attachments(parsed)
                    parsed["extraction"] = extraction_results

                    if extraction_results.get("escalate"):
                        parsed["status"] = "escalated"
                        _deterministic_escalation = True
                        print(f"[EXTRACTION] Deterministic escalation — attachment(s) flagged by extraction tools")
                    elif extraction_results.get("total_flags", 0) > 0:
                        print(f"[EXTRACTION] {extraction_results['total_flags']} flag(s) found — continuing to enrichment")
                    # Cross-check extracted IOCs against threat feeds
                    for ext_res in extraction_results.get("results", []):
                        iocs = ext_res.get("iocs", {})
                        if iocs:
                            feed_match = feeds.check_all(
                                urls=iocs.get("urls"),
                                domains=iocs.get("domains"),
                                ips=iocs.get("ipv4s"),
                            )
                            if feed_match.get("total_matches", 0) > 0:
                                parsed["status"] = "escalated"
                                print(f"[FEEDS] Extracted IOCs match threat feeds: "
                                      f"{feed_match['total_matches']} hit(s) in {ext_res['filename']}")
                elif parsed.get("attachments"):
                    print(f"[EXTRACTION] Skipped — already ESCALATED from rules")

                # --- Extract and validate sender domain once for all enrichment ---
                _sender_raw = parsed.get("headers", {}).get("from")
                _sender_addr = parseaddr(_sender_raw)[1] if _sender_raw else ""
                sender_domain = None
                if _sender_addr and "@" in _sender_addr:
                    _dom = _sender_addr.split("@")[-1].strip().lower()
                    if is_valid_domain(_dom):
                        sender_domain = _dom
                    else:
                        print(f"[VALIDATION] Sender domain '{_dom}' failed validation — skipping external API lookups for domain")

                # Enrichment: ThreatFox runs before LLM and can short-circuit to a deterministic reject
                # Track pre-enrichment status so we only skip LLM when enrichment itself
                # found a threat signal — NOT when status was already escalated from AUTH/rules.
                _pre_enrichment_status = parsed.get("status")

                # ThreatFox API: check attachments, sender domain, and raw email hash
                threat_results = []
                found_count = 0
                errors = []
                try:
                    # check attachment hashes (validate SHA-256 format first)
                    for att in parsed.get("attachments", []):
                        sha = att.get("sha256") or att.get("sha")
                        if sha and is_valid_sha256(sha):
                            print(f"[THREATFOX] Querying hash for attachment {att.get('original_name')}: {sha}")
                            res = check_threatfox(sha, indicator_type="hash")
                            threat_results.append(res)
                            if res.get("found"):
                                found_count += 1
                                parsed["status"] = "escalated"  # deterministic short-circuit
                                print(f"[THREATFOX] Attachment {att.get('original_name')} ({sha[:12]}...) flagged")
                            if res.get("error"):
                                errors.append(res.get("error"))

                    # check sender domain (pre-validated above)
                    if sender_domain:
                        print(f"[THREATFOX] Querying domain: {sender_domain}")
                        res = check_threatfox(sender_domain, indicator_type="domain")
                        threat_results.append(res)
                        if res.get("found"):
                            found_count += 1
                            parsed["status"] = "escalated"
                            print(f"[THREATFOX] Sender domain {sender_domain} flagged")
                        if res.get("error"):
                            errors.append(res.get("error"))

                    # check raw email hash (sha256 of the whole email)
                    raw_sha = parsed.get("raw_sha256")
                    if raw_sha and is_valid_sha256(raw_sha):
                        print(f"[THREATFOX] Querying raw email SHA256: {raw_sha}")
                        res = check_threatfox(raw_sha, indicator_type="hash")
                        threat_results.append(res)
                        if res.get("found"):
                            found_count += 1
                            parsed["status"] = "escalated"
                            print(f"[THREATFOX] Raw email hash {raw_sha[:12]}... flagged")
                        if res.get("error"):
                            errors.append(res.get("error"))

                except Exception as e:
                    err = str(e)
                    errors.append(err)
                    print(f"[THREATFOX] Lookup failed: {err}")

                # attach ThreatFox results into analysis so LLM sees them when called
                parsed.setdefault("analysis", {})["threatfox"] = threat_results
                # If ThreatFox produced matches, add a deterministic detail entry so rules-treated equally
                if found_count > 0:
                    detail = {"rule": "threatfox", "flagged": True, "reason": f"ThreatFox match count={found_count}"}
                    parsed.setdefault("analysis", {}).setdefault("details", []).append(detail)

                # always print ThreatFox summary for operator visibility
                if threat_results:
                    print(f"[THREATFOX] Checked {len(threat_results)} indicator(s), matches: {found_count}")
                    for r in threat_results:
                        ind = r.get("indicator") or r.get("search_term") or r.get("hash") or r.get("ioc")
                        itype = r.get("indicator_type") or r.get("ioc_type") or r.get("type") or "unknown"
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

                # Enrichment: VirusTotal — SHA-256 hash lookup (NEVER upload files)
                vt_results = []
                try:
                    for att in parsed.get("attachments", []):
                        sha = att.get("sha256")
                        if sha and is_valid_sha256(sha):
                            print(f"[VIRUSTOTAL] Querying hash: {att.get('original_name')} ({sha[:12]}...)")
                            vt_res = check_virustotal(sha)
                            vt_results.append(vt_res)
                            if vt_res.get("detected"):
                                parsed["status"] = "escalated"
                                names = ", ".join(vt_res.get("malware_names", [])[:3]) or "unknown"
                                print(f"[VIRUSTOTAL] DETECTED: {vt_res['detection_count']}/{vt_res.get('total_engines',0)} "
                                      f"engines — {names}")
                            elif vt_res.get("error"):
                                print(f"[VIRUSTOTAL] ERROR: {vt_res['error']}")
                            elif vt_res.get("note") == "hash_not_found_in_vt":
                                print(f"[VIRUSTOTAL] Hash not in database (first seen)")
                            else:
                                print(f"[VIRUSTOTAL] Clean ({vt_res.get('detection_count', 0)}/{vt_res.get('total_engines', 0)})")
                except Exception as e:
                    print(f"[VIRUSTOTAL] Lookup failed: {e}")

                parsed.setdefault("analysis", {})["virustotal"] = vt_results

                # Enrichment: AbuseIPDB — check IPs from Received headers
                abuseipdb_results = []
                all_ips = []  # initialized here so OTX block can safely reference it
                try:
                    received_raw = parsed.get("headers", {}).get("received") or ""
                    if isinstance(received_raw, list):
                        received_raw = " ".join(str(r) for r in received_raw)
                    # Extract + validate IPs (IPv4 + IPv6, filters private/loopback/reserved)
                    header_ips = extract_ips_from_text(str(received_raw))
                    # also grab IPs from body if extraction found them
                    ext_ips = []
                    for ext_res in parsed.get("extraction", {}).get("results", []):
                        for v4 in ext_res.get("iocs", {}).get("ipv4s", []):
                            ext_ips.append(v4)
                        for v6 in ext_res.get("iocs", {}).get("ipv6s", []):
                            ext_ips.append(v6)
                    # Merge and re-validate all
                    all_ips = list(set(header_ips + [ip for ip in ext_ips if ip.strip()]))
                    all_ips = [ip for ip in all_ips if ip]  # remove empty strings

                    if all_ips:
                        print(f"[ABUSEIPDB] Checking {len(all_ips)} IP(s)...")
                        for ip in all_ips[:10]:  # cap to avoid rate limits
                            res = check_abuseipdb(ip)
                            abuseipdb_results.append(res)
                            if res.get("skipped"):
                                continue
                            score = res.get("abuse_score", 0)
                            if res.get("is_malicious"):
                                parsed["status"] = "escalated"
                                print(f"[ABUSEIPDB] {ip} -> MALICIOUS (score={score}, "
                                      f"reports={res.get('total_reports')}, "
                                      f"isp={res.get('isp')}, country={res.get('country_code')})")
                            elif res.get("error"):
                                print(f"[ABUSEIPDB] {ip} -> ERROR: {res['error']}")
                            else:
                                print(f"[ABUSEIPDB] {ip} -> clean (score={score})")
                    else:
                        print("[ABUSEIPDB] No IPs to check")
                except Exception as e:
                    print(f"[ABUSEIPDB] Lookup failed: {e}")

                parsed.setdefault("analysis", {})["abuseipdb"] = abuseipdb_results

                # Enrichment: AlienVault OTX — CONTEXTUAL intel for the LLM
                # OTX pulses indicate the indicator appeared in threat research, NOT
                # that it is necessarily malicious. Popular legitimate domains routinely
                # show up in OTX.  Results are passed to the LLM but do NOT auto-escalate.
                otx_results = []
                try:
                    if sender_domain:
                        print(f"[OTX] Querying domain: {sender_domain}")
                        otx_dom = check_otx_domain(sender_domain)
                        otx_results.append(otx_dom)
                        if otx_dom.get("found"):
                            pulses = otx_dom.get("pulse_count", 0)
                            tags = ", ".join(otx_dom.get("tags", [])[:5]) or "none"
                            print(f"[OTX] Domain {sender_domain} — {pulses} pulse(s), tags: {tags}")
                        elif otx_dom.get("error"):
                            print(f"[OTX] Domain {sender_domain} -> ERROR: {otx_dom['error']}")
                        else:
                            print(f"[OTX] Domain {sender_domain} -> clean")

                    for ip in all_ips[:10]:
                        print(f"[OTX] Querying IP: {ip}")
                        otx_ip = check_otx_ip(ip)
                        otx_results.append(otx_ip)
                        if otx_ip.get("found"):
                            pulses = otx_ip.get("pulse_count", 0)
                            families = ", ".join(otx_ip.get("malware_families", [])) or "none"
                            print(f"[OTX] IP {ip} — {pulses} pulse(s), malware: {families}")
                        elif otx_ip.get("error"):
                            print(f"[OTX] IP {ip} -> ERROR: {otx_ip['error']}")
                        else:
                            print(f"[OTX] IP {ip} -> clean")

                    for att in parsed.get("attachments", []):
                        sha = att.get("sha256")
                        if sha and is_valid_sha256(sha):
                            print(f"[OTX] Querying hash: {att.get('original_name')} ({sha[:12]}...)")
                            otx_h = check_otx_hash(sha)
                            otx_results.append(otx_h)
                            if otx_h.get("found"):
                                families = ", ".join(otx_h.get("malware_families", [])) or "unknown"
                                print(f"[OTX] Hash — {otx_h.get('pulse_count', 0)} pulse(s), malware: {families}")
                            elif otx_h.get("error"):
                                print(f"[OTX] Hash -> ERROR: {otx_h['error']}")
                            else:
                                print(f"[OTX] Hash -> clean")

                except Exception as e:
                    print(f"[OTX] Lookup failed: {e}")

                parsed.setdefault("analysis", {})["otx"] = otx_results
                otx_hits = sum(1 for r in otx_results if r.get("found"))
                # OTX hits are contextual — logged for LLM but NOT flagged as deterministic
                print(f"[OTX] Checked {len(otx_results)} indicator(s), context hits: {otx_hits}")

                # Enrichment: dnstwist — typosquat detection on sender domain
                dnstwist_result = {}
                try:
                    if sender_domain:
                        print(f"[DNSTWIST] Checking if {sender_domain} is a typosquat...")
                        dnstwist_result = is_typosquat(sender_domain)
                        if dnstwist_result.get("is_typosquat"):
                            parsed["status"] = "escalated"
                            print(f"[DNSTWIST] TYPOSQUAT DETECTED — {sender_domain} impersonates {dnstwist_result['impersonates']}")
                        else:
                            print(f"[DNSTWIST] {sender_domain} -> not a typosquat")
                    else:
                        print("[DNSTWIST] No valid sender domain to check")
                except Exception as e:
                    print(f"[DNSTWIST] Check failed: {e}")

                parsed.setdefault("analysis", {})["dnstwist"] = dnstwist_result
                if dnstwist_result.get("is_typosquat"):
                    detail = {"rule": "dnstwist", "flagged": True,
                              "reason": f"Typosquat of {dnstwist_result['impersonates']}"}
                    parsed.setdefault("analysis", {}).setdefault("details", []).append(detail)

                # Enrichment: WHOIS/RDAP — domain age check (new domain = strong signal)
                whois_result = {}
                try:
                    if sender_domain:
                        print(f"[WHOIS] Checking domain age: {sender_domain}")
                        whois_result = check_domain_age(sender_domain)
                        age = whois_result.get("domain_age_days")
                        if whois_result.get("is_new_domain"):
                            parsed["status"] = "escalated"
                            print(f"[WHOIS] NEW DOMAIN — {sender_domain} registered {age} day(s) ago")
                        elif age is not None:
                            print(f"[WHOIS] {sender_domain} -> {age} day(s) old (OK)")
                        elif whois_result.get("error"):
                            print(f"[WHOIS] {sender_domain} -> ERROR: {whois_result['error']}")
                        else:
                            print(f"[WHOIS] {sender_domain} -> age unknown")
                    else:
                        print("[WHOIS] No valid sender domain to check")
                except Exception as e:
                    print(f"[WHOIS] Check failed: {e}")

                parsed.setdefault("analysis", {})["whois"] = whois_result
                if whois_result.get("is_new_domain"):
                    detail = {"rule": "whois_new_domain", "flagged": True,
                              "reason": f"Domain registered {whois_result.get('domain_age_days', '?')} days ago"}
                    parsed.setdefault("analysis", {}).setdefault("details", []).append(detail)

                # Only skip LLM if enrichment itself escalated the email (not prior AUTH/rules).
                # AUTH failures (DMARC misconfiguration) need LLM reasoning for the analyst.
                _enrichment_escalated = (
                    parsed.get("status") == "escalated"
                    and _pre_enrichment_status != "escalated"
                )
                if _enrichment_escalated:
                    _deterministic_escalation = True
                    print("[ENRICHMENT] Deterministic match -> skipping LLM and proposing reject/escalation")
                else:
                    # LLM analysis (Ollama)
                    try:
                        llm_input = parsed.get("body_text") or ""
                        # Build enrichment context with all signals for LLM
                        enrichment_data = {
                            "threatfox": threat_results,
                            "virustotal": vt_results,
                            "abuseipdb": abuseipdb_results,
                            "otx": otx_results,
                            "dnstwist": dnstwist_result,
                            "whois": whois_result,
                            "auth": parsed.get("auth", {}),
                        }
                        ext = parsed.get("extraction", {})
                        if ext.get("results"):
                            extraction_summary = []
                            for er in ext["results"]:
                                extraction_summary.append({
                                    "filename": er.get("filename"),
                                    "real_type": er.get("real_type"),
                                    "type_mismatch": er.get("type_mismatch"),
                                    "flags": er.get("flags", []),
                                    "iocs": er.get("iocs", {}),
                                    "suspicious": er.get("suspicious"),
                                })
                            enrichment_data["extraction"] = extraction_summary
                        context = {
                            "headers": parsed.get("headers", {}),
                            "attachments": parsed.get("attachments", []),
                            "enrichment": enrichment_data
                        }
                        llm_res = analyze_email_body(llm_input, context=context)
                        parsed["llm_analysis"] = llm_res
                        raw_llm_verdict = (llm_res.get("verdict") or "").lower().strip()

                        # Normalize French and English LLM outputs to pipeline statuses
                        llm_verdict = ""
                        if raw_llm_verdict in ("accepter", "accepted", "accept", "clean", "safe"):
                            llm_verdict = "accepted"
                        elif raw_llm_verdict in ("rejeter", "escalader", "escalated", "reject", "malicious", "phishing"):
                            llm_verdict = "escalated"

                        # Fail-safe: unknown or missing verdict → escalate
                        if not llm_verdict:
                            parsed["status"] = "escalated"
                            print(f"[LLM] Invalid/unknown verdict '{raw_llm_verdict}' -> ESCALATED (fail-safe)")
                        else:
                            print(f"[LLM] Model verdict: {llm_verdict.upper()}")
                            if llm_res.get("reasons"):
                                print(f"  Reasons: {llm_res.get('reasons')}")
                            # LLM can escalate but NEVER override a rules-engine escalation
                            if parsed["status"] != "escalated" and llm_verdict == "escalated":
                                parsed["status"] = "escalated"
                                print(f"[LLM] Model flagged -> ESCALATED")
                    except Exception as e:
                        # Fail-safe: LLM crash → escalate, never silently accept
                        parsed["status"] = "escalated"
                        print(f"[LLM] Analysis failed: {e} -> ESCALATED (fail-safe)")
                        try:
                            from alerts import send_alert, AlertLevel
                            send_alert(
                                AlertLevel.WARNING,
                                "LLM analysis failed",
                                {
                                    "error": str(e),
                                    "sender": parsed.get("headers", {}).get("from", ""),
                                    "subject": parsed.get("headers", {}).get("subject", ""),
                                    "idempotency_key": parsed.get("idempotency_key"),
                                },
                            )
                        except Exception:
                            pass
            else:
                print(f"[RULES] Skipped — email already ESCALATED from parse errors")

            # Blocklist cascade is DEFERRED to analyst action (quarantine button).
            # CLAUDE.md: "All rejections must be confirmed by a human analyst."
            # The pipeline proposes verdicts; only analyst confirmation triggers blocklist.
            if parsed["status"] == "escalated":
                if _deterministic_escalation:
                    print(f"[VERDICT] ESCALATED (deterministic) — awaiting analyst review")
                else:
                    print(f"[VERDICT] ESCALATED (LLM-only) — awaiting analyst review")

            # --- Save final results to database (primary) or JSON ledger (fallback) ---
            _sender_raw = parsed.get("headers", {}).get("from", "")
            _, _sender_addr = parseaddr(_sender_raw)
            _sender_domain = None
            if _sender_addr and "@" in _sender_addr:
                _sender_domain = _sender_addr.split("@")[-1].strip().lower()

            if db:
                try:
                    from database import save_email as _save_email
                    llm_raw_reasons = (parsed.get("llm_analysis") or {}).get("raisonnement") or (parsed.get("llm_analysis") or {}).get("reasons")
                    if isinstance(llm_raw_reasons, list):
                        llm_raw_reasons = "\n".join(f"• {r}" for r in llm_raw_reasons)

                    email_data = {
                        "idempotency_key": parsed["idempotency_key"],
                        "message_id": parsed["headers"].get("message-id"),
                        "raw_sha256": parsed.get("raw_sha256", ""),
                        "sender": _sender_raw,
                        "sender_domain": _sender_domain,
                        "subject": parsed["headers"].get("subject"),
                        "attachment_count": len(parsed["attachments"]),
                        "status": parsed["status"],
                        "email_date": _email_date,
                        "rules_result": parsed.get("analysis"),
                        "enrichment_result": {
                            "threatfox": parsed.get("analysis", {}).get("threatfox"),
                            "virustotal": parsed.get("analysis", {}).get("virustotal"),
                            "abuseipdb": parsed.get("analysis", {}).get("abuseipdb"),
                            "otx": parsed.get("analysis", {}).get("otx"),
                            "dnstwist": parsed.get("analysis", {}).get("dnstwist"),
                            "whois": parsed.get("analysis", {}).get("whois"),
                            "auth": parsed.get("auth"),
                        },
                        "llm_result": parsed.get("llm_analysis"),
                        "llm_reasoning": llm_raw_reasons,
                        "parse_errors": parsed.get("parse_errors"),
                    }
                    saved = _save_email(db, email_data)

                    # Track metrics
                    try:
                        from metrics import emails_processed_total
                        emails_processed_total.labels(status=parsed["status"]).inc()
                    except Exception:
                        pass

                    print(f"[DB] Updated email #{saved.id} -> {parsed['status'].upper()}")

                    # Dashboard refresh is handled by the background poll loop
                    pass
                except Exception as e:
                    print(f"[DB] Save failed ({e}) — falling back to JSON ledger")
                    ingestion.mark_processed(parsed["idempotency_key"], parsed)
            else:
                # JSON fallback
                ingestion.mark_processed(parsed["idempotency_key"], parsed)

            # summary (encode-safe for Windows cp1252 console)
            def _safe(s): return str(s).encode("ascii", "replace").decode("ascii") if s else ""
            print(f"  De:     {_safe(parsed['headers']['from'])}")
            print(f"  Sujet:  {_safe(parsed['headers']['subject'])}")
            print(f"  PJ:     {len(parsed['attachments'])}")
            print(f"  Statut: {parsed['status']}")
            if parsed["parse_errors"]:
                print(f"  Erreurs: {parsed['parse_errors']}")

        if cached:
            print(f"\n[INFO] {cached} email(s) loaded from cache")

        ingestion.disconnect()

    except TimeoutError as e:
        logger.error(f"[ABORT] {e}")
        logger.error("Pipeline stopped — check network or server")
    except Exception as e:
        import traceback
        logger.error(f"Unhandled {type(e).__name__} in pipeline: {e}")
        traceback.print_exc()
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    elapsed = time.time() - t_start
    logger.info(f"=== Pipeline Finished in {elapsed:.1f}s ===")


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--daemon" in args:
        # Start background scheduler (polls IMAP every 60s)
        from scheduler import start_daemon
        start_daemon()

    elif "--serve" in args:
        # Start the FastAPI dashboard server (background polling handled inside api.py)
        import uvicorn
        port = int(os.getenv("DASHBOARD_PORT", "8000"))
        host = os.getenv("DASHBOARD_HOST", "0.0.0.0")
        print(f"[SERVE] Starting dashboard on http://{host}:{port}")
        uvicorn.run("api:app", host=host, port=port, reload=False, workers=1)

    elif "--migrate" in args:
        # Run data migration from JSON to PostgreSQL
        from migrate_data import main as migrate_main
        migrate_main()

    else:
        # Default: run pipeline once
        run_pipeline()