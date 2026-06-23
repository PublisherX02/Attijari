import os
import sys
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from dotenv import load_dotenv

from email_extraction import EmailIngestion, TimeoutError
from rules import RuleEngine, add_to_blocklist, cascade_blocklist
from analysis import analyze_email_body
from logger import get_logger, audit_event
from dkim_verify import verify_all as verify_email_auth
from extraction import extract_all_attachments
from threat_feeds import get_feeds
from sandbox import check_sandbox_status
from url_utils import normalize_url


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
        raw_emails = ingestion.fetch_unread()

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
            if db:
                cached_email = get_cached_email(db, idem_key)
                if cached_email:
                    print(f"[CACHED] Already processed:")
                    print(f"  De:     {cached_email.sender}")
                    print(f"  Sujet:  {cached_email.subject}")
                    print(f"  Statut: {cached_email.status}")
                    cached += 1
                    continue
            else:
                prev = ingestion.get_cached_result(raw, str(message_id) if message_id else None)
                if prev:
                    print(f"[CACHED] Already processed:")
                    print(f"  De:     {prev.get('from')}")
                    print(f"  Sujet:  {prev.get('subject')}")
                    print(f"  PJ:     {prev.get('attachments')}")
                    print(f"  Statut: {prev['status']}")
                    if prev.get("parse_errors"):
                        print(f"  Erreurs: {prev['parse_errors']}")
                    cached += 1
                    continue

            # parse
            parsed = ingestion.parse_email(raw)

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

            # Initialize enrichment variables (needed for blocklist section even if skipped)
            all_ips = []
            threat_results = []
            vt_results = []
            abuseipdb_results = []
            otx_results = []
            dnstwist_result = {}
            whois_result = {}
            sender_domain = None

            # analyze via rules engine
            if parsed["status"] != "escalated":
                analysis = engine.analyze(parsed)
                parsed["status"] = analysis["verdict"]
                parsed["analysis"] = analysis
                print(f"[RULES] {analysis['rules_run']} rules, {analysis['flags']} flag(s) -> {analysis['verdict'].upper()}")
                audit_event("rules_verdict", "rules", idem_key, {
                    "verdict": analysis["verdict"], "flags": analysis["flags"],
                    "hard_flags": analysis.get("hard_flags", 0),
                    "flagged_rules": [d["rule"] for d in analysis["details"] if d["flagged"]],
                })
                for detail in analysis["details"]:
                    flag_marker = "!!" if detail["flagged"] else "ok"
                    print(f"  [{flag_marker}] {detail['rule']}: {detail['reason']}")

                # Stage 3: Isolated extraction — security analysis of all attachments
                if parsed.get("attachments") and parsed["status"] not in ("escalated", "proposed_reject"):
                    print(f"[EXTRACTION] Running isolated security extraction on {len(parsed['attachments'])} attachment(s)...")
                    extraction_results = extract_all_attachments(parsed)
                    parsed["extraction"] = extraction_results

                    if extraction_results.get("escalate"):
                        parsed["status"] = "proposed_reject"
                        print(f"[EXTRACTION] Deterministic flags — attachment(s) flagged by extraction tools -> PROPOSED_REJECT")
                    elif extraction_results.get("total_flags", 0) > 0:
                        parsed["extraction_has_flags"] = True
                        print(f"[EXTRACTION] {extraction_results['total_flags']} flag(s) found — continuing to enrichment")
                    # Cross-check extracted IOCs against threat feeds
                    for ext_res in extraction_results.get("results", []):
                        iocs = ext_res.get("iocs", {})
                        if iocs:
                            # Normalize IOC URLs before feed check (Fix #4)
                            raw_urls = iocs.get("urls") or []
                            normalized_urls = [normalize_url(u) for u in raw_urls]
                            feed_match = feeds.check_all(
                                urls=normalized_urls,
                                domains=iocs.get("domains"),
                                ips=iocs.get("ipv4s"),
                            )
                            if feed_match.get("total_matches", 0) > 0:
                                parsed["status"] = "proposed_reject"
                                print(f"[FEEDS] Extracted IOCs match threat feeds: "
                                      f"{feed_match['total_matches']} hit(s) in {ext_res['filename']} -> PROPOSED_REJECT")
                elif parsed.get("attachments"):
                    print(f"[EXTRACTION] Skipped — already {parsed['status'].upper()} from rules")

                # --- Stage 4: Signal Enrichment (all external API lookups) ---
                from enrichment import run_enrichment
                enr = run_enrichment(parsed)

                # Apply enrichment results to parsed email
                sender_domain = enr["sender_domain"]
                all_ips = enr["all_ips"]
                threat_results = enr["threatfox"]
                vt_results = enr["virustotal"]
                abuseipdb_results = enr["abuseipdb"]
                otx_results = enr["otx"]
                dnstwist_result = enr["dnstwist"]
                whois_result = enr["whois"]

                # Store enrichment results in analysis for LLM context
                analysis = parsed.setdefault("analysis", {})
                analysis["threatfox"] = threat_results
                analysis["virustotal"] = vt_results
                analysis["abuseipdb"] = abuseipdb_results
                analysis["otx"] = otx_results
                analysis["dnstwist"] = dnstwist_result
                analysis["whois"] = whois_result
                for detail in enr["details"]:
                    analysis.setdefault("details", []).append(detail)

                # Upgrade status if enrichment found deterministic hits
                if enr["status"] == "proposed_reject":
                    parsed["status"] = "proposed_reject"

                # If any deterministic source matched, skip LLM — hard evidence trumps LLM opinion
                if parsed.get("status") == "proposed_reject":
                    print("[ENRICHMENT] Deterministic match -> skipping LLM, proposed rejection for human review")
                elif parsed.get("status") == "escalated":
                    print("[ENRICHMENT] Heuristic match -> skipping LLM, escalated for human review")
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
                            parsed["parse_errors"].append(f"fail-safe: invalid verdict '{raw_llm_verdict}'")
                            print(f"[LLM] Invalid/unknown verdict '{raw_llm_verdict}' -> ESCALATED (fail-safe)")
                            audit_event("llm_failsafe", "llm", idem_key, {
                                "raw_verdict": raw_llm_verdict, "reason": "invalid_verdict"})
                        else:
                            print(f"[LLM] Model verdict: {llm_verdict.upper()}")
                            if llm_res.get("confidence") is not None:
                                print(f"  Confidence: {llm_res['confidence']:.2f}")
                            if llm_res.get("reasons"):
                                print(f"  Reasons: {llm_res.get('reasons')}")

                            # Fix #3: Extraction flags must block LLM acceptance
                            if llm_verdict == "accepted" and parsed.get("extraction_has_flags"):
                                llm_verdict = "escalated"
                                print(f"[LLM] Overridden — extraction found flags, cannot accept")

                            audit_event("llm_verdict", "llm", idem_key, {
                                "verdict": llm_verdict,
                                "confidence": llm_res.get("confidence"),
                                "risk_score": llm_res.get("risk_score"),
                                "reasons": llm_res.get("reasons"),
                            })

                            # LLM can escalate but NEVER override a rules-engine or enrichment decision
                            if parsed["status"] not in ("escalated", "proposed_reject") and llm_verdict == "escalated":
                                parsed["status"] = "escalated"
                                print(f"[LLM] Model flagged -> ESCALATED")
                    except Exception as e:
                        # Fail-safe: LLM crash → escalate, never silently accept
                        parsed["status"] = "escalated"
                        parsed["parse_errors"].append(f"fail-safe: LLM analysis failed ({e})")
                        print(f"[LLM] Analysis failed: {e} -> ESCALATED (fail-safe)")
            else:
                print(f"[RULES] Skipped — email already ESCALATED from parse errors")

            # Cascading Blocklist — ONLY on deterministic enrichment matches
            # CLAUDE.md: "All rejections require human confirmation"
            # Escalation alone is NOT confirmation — only auto-blocklist when
            # a deterministic signal (rules engine, ThreatFox, VirusTotal, OTX,
            # dnstwist, AbuseIPDB) triggered the escalation, not LLM-only verdicts.
            # CLAUDE.md cascading blocklist: proposed_reject = deterministic evidence
            # Block sender email + domain + associated IPs + file hashes
            # escalated (LLM-only or heuristic) = needs human confirmation first
            if parsed["status"] == "proposed_reject":
                _, sender_email = parseaddr(parsed["headers"].get("from", ""))
                _cascade_domain = None
                if sender_email and "@" in sender_email:
                    _cascade_domain = sender_email.split("@")[-1].strip().lower()

                # Collect all IPs seen in this email
                _cascade_ips = list(set(all_ips)) if all_ips else []

                # Collect all attachment hashes
                _cascade_hashes = [
                    att.get("sha256") for att in parsed.get("attachments", [])
                    if att.get("sha256")
                ]

                cascade_blocklist(
                    sender_email=sender_email,
                    sender_domain=_cascade_domain,
                    ips=_cascade_ips,
                    hashes=_cascade_hashes,
                )
            elif parsed["status"] == "escalated":
                print(f"[BLOCKLIST] Skipped — escalation is heuristic/LLM-only, awaiting human confirmation")

            # --- Save to database (primary) or JSON ledger (fallback) ---
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

                    print(f"[DB] Saved email #{saved.id}")
                    
                    try:
                        import requests
                        requests.post("http://localhost:8000/api/internal/notify", timeout=2)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[DB] Save failed ({e}) — falling back to JSON ledger")
                    ingestion.mark_processed(parsed["idempotency_key"], parsed)
            else:
                # JSON fallback
                ingestion.mark_processed(parsed["idempotency_key"], parsed)

            # summary
            print(f"  De:     {parsed['headers']['from']}")
            print(f"  Sujet:  {parsed['headers']['subject']}")
            print(f"  PJ:     {len(parsed['attachments'])}")
            print(f"  Statut: {parsed['status']}")
            if parsed["parse_errors"]:
                print(f"  Erreurs: {parsed['parse_errors']}")

            # Structured audit trail — final decision record
            audit_event("final_verdict", "pipeline", idem_key, {
                "status": parsed["status"],
                "sender": parsed["headers"].get("from"),
                "subject": parsed["headers"].get("subject"),
                "attachments": len(parsed["attachments"]),
                "rules_flags": parsed.get("analysis", {}).get("flags", 0),
                "llm_confidence": (parsed.get("llm_analysis") or {}).get("confidence"),
                "parse_errors": parsed.get("parse_errors") or [],
            })

            if i < len(raw_emails):
                print(f"[COOLDOWN] Waiting 2 seconds to respect API limits...")
                import time
                time.sleep(2.0)

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
        # Start the FastAPI dashboard server
        import uvicorn
        port = int(os.getenv("DASHBOARD_PORT", "8000"))
        host = os.getenv("DASHBOARD_HOST", "0.0.0.0")
        print(f"[SERVE] Starting dashboard on http://{host}:{port}")
        uvicorn.run("api:app", host=host, port=port, reload=True)

    elif "--migrate" in args:
        # Run data migration from JSON to PostgreSQL
        from migrate_data import main as migrate_main
        migrate_main()

    else:
        # Default: run pipeline once
        run_pipeline()



#needs to add a function if an email is flagged as "escalate" the sender email and domaon must be bloecked