import os
import time
from email import policy
from email.parser import BytesParser

from dotenv import load_dotenv

from email_extraction import EmailIngestion, TimeoutError
from rules import RuleEngine


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
