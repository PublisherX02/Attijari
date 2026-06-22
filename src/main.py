import os
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from dotenv import load_dotenv

from email_extraction import EmailIngestion, TimeoutError
from rules import RuleEngine
from analysis import analyze_email_body
from rules import BLOCKED_SENDER
from ThreatFoxAPI import check_threatfox


def run_pipeline():
    load_dotenv()

    print("=" * 50)
    print("[START] Email Ingestion & Analysis Pipeline")
    print("=" * 50)
    t_start = time.time()

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

            # analyze via rules engine
            if parsed["status"] != "escalated":
                analysis = engine.analyze(parsed)
                parsed["status"] = analysis["verdict"]
                parsed["analysis"] = analysis
                print(f"[RULES] {analysis['rules_run']} rules, {analysis['flags']} flag(s) -> {analysis['verdict'].upper()}")
                for detail in analysis["details"]:
                    flag_marker = "!!" if detail["flagged"] else "ok"
                    print(f"  [{flag_marker}] {detail['rule']}: {detail['reason']}")

                # Enrichment: ThreatFox runs before LLM and can short-circuit to a deterministic reject
                # ThreatFox API: check attachments, sender domain, and raw email hash
                threat_results = []
                found_count = 0
                errors = []
                try:
                    # check attachment hashes
                    for att in parsed.get("attachments", []):
                        sha = att.get("sha256") or att.get("sha")
                        if sha:
                            print(f"[THREATFOX] Querying hash for attachment {att.get('original_name')}: {sha}")
                            res = check_threatfox(sha, indicator_type="hash")
                            threat_results.append(res)
                            if res.get("found"):
                                found_count += 1
                                parsed["status"] = "escalated"  # deterministic short-circuit
                                print(f"[THREATFOX] Attachment {att.get('original_name')} ({sha[:12]}...) flagged")
                            if res.get("error"):
                                errors.append(res.get("error"))

                    # check sender domain (use parseaddr to extract clean address)
                    sender = parsed.get("headers", {}).get("from")
                    addr = parseaddr(sender)[1] if sender else ""
                    if addr and "@" in addr:
                        domain = addr.split("@")[-1].strip().lower()
                        print(f"[THREATFOX] Querying domain: {domain}")
                        res = check_threatfox(domain, indicator_type="domain")
                        threat_results.append(res)
                        if res.get("found"):
                            found_count += 1
                            parsed["status"] = "escalated"
                            print(f"[THREATFOX] Sender domain {domain} flagged")
                        if res.get("error"):
                            errors.append(res.get("error"))

                    # check raw email hash (sha256 of the whole email)
                    raw_sha = parsed.get("raw_sha256")
                    if raw_sha:
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
                        itype = r.get("indicator_type") or r.get("ioc_type") or r.get("ioc_type") or "unknown"
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

                # If ThreatFox matched, skip LLM (deterministic signal)
                if parsed.get("status") == "escalated":
                    print("[THREATFOX] Deterministic match -> skipping LLM and proposing reject/escalation")
                else:
                    # LLM analysis (Ollama)
                    VALID_LLM_VERDICTS = {"accepted", "escalated"}
                    try:
                        llm_input = parsed.get("body_text") or ""
                        # include threatfox summary in context for the LLM
                        context = {
                            "headers": parsed.get("headers", {}),
                            "attachments": parsed.get("attachments", []),
                            "enrichment": {"threatfox": threat_results}
                        }
                        llm_res = analyze_email_body(llm_input, context=context)
                        parsed["llm_analysis"] = llm_res
                        llm_verdict = (llm_res.get("verdict") or "").lower().strip()

                        # Fail-safe: unknown or missing verdict → escalate
                        if llm_verdict not in VALID_LLM_VERDICTS:
                            parsed["status"] = "escalated"
                            print(f"[LLM] Invalid/unknown verdict '{llm_verdict}' -> ESCALATED (fail-safe)")
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
            else:
                print(f"[RULES] Skipped — email already ESCALATED from parse errors")

            # record to ledger
            ingestion.mark_processed(parsed["idempotency_key"], parsed)

            # summary
            print(f"  De:     {parsed['headers']['from']}")
            print(f"  Sujet:  {parsed['headers']['subject']}")
            print(f"  PJ:     {len(parsed['attachments'])}")
            print(f"  Statut: {parsed['status']}")
            if parsed["parse_errors"]:
                print(f"  Erreurs: {parsed['parse_errors']}")

        if cached:
            print(f"\n[INFO] {cached} email(s) loaded from cache")

        ingestion.disconnect()

    except TimeoutError as e:
        print(f"\n[ABORT] {e}")
        print("[ABORT] Pipeline stopped — check network or server")
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")

    elapsed = time.time() - t_start
    print(f"\n{'=' * 50}")
    print(f"[DONE] Finished in {elapsed:.1f}s")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    run_pipeline()



#needs to add a function if an email is flagged as "escalate" the sender email and domaon must be bloecked