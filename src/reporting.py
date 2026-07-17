"""reporting.py — Admin Reporting Module.

Generates structured triage summaries and delivers via:
  - SMTP email (HTML formatted)
  - Slack webhook (Block Kit JSON)
  - Microsoft Teams webhook (Adaptive Card JSON)
  - Dashboard storage (PostgreSQL reports table)
"""
from __future__ import annotations

import json
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

from database import SessionLocal, Email, Report, add_audit_entry
from http_client import get_session


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(period: str = "daily") -> dict:
    """Generate a structured triage report for the given period.

    Args:
        period: 'hourly', 'daily', or 'weekly'

    Returns:
        dict with counts, details, and top threats.
    """
    now = datetime.now(timezone.utc)
    if period == "hourly":
        start = now - timedelta(hours=1)
    elif period == "weekly":
        start = now - timedelta(weeks=1)
    else:
        start = now - timedelta(days=1)

    db = SessionLocal()
    try:
        emails = db.query(Email).filter(
            Email.created_at >= start,
            Email.created_at <= now,
        ).order_by(Email.created_at.desc()).all()

        # Count by status
        counts = {"total": 0, "accepted": 0, "escalated": 0,
                  "quarantined": 0, "released": 0, "recu": 0}
        details = []
        threat_senders = {}

        for e in emails:
            counts["total"] += 1
            counts[e.status] = counts.get(e.status, 0) + 1

            detail = {
                "id": e.id,
                "sender": e.sender,
                "subject": e.subject,
                "status": e.status,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "llm_reasoning": e.llm_reasoning,
                "analyst_action": e.analyst_action,
            }
            details.append(detail)

            # Track threat senders
            if e.status in ("escalated", "quarantined") and e.sender_domain:
                threat_senders[e.sender_domain] = threat_senders.get(e.sender_domain, 0) + 1

        # Sort top threats by frequency
        top_threats = sorted(
            [{"domain": d, "count": c} for d, c in threat_senders.items()],
            key=lambda x: x["count"], reverse=True,
        )[:10]

        report = {
            "period": period,
            "period_start": start.isoformat(),
            "period_end": now.isoformat(),
            "counts": counts,
            "top_threats": top_threats,
            "details": details,
            "generated_at": now.isoformat(),
        }

        return report
    finally:
        db.close()


def store_report(report: dict) -> int:
    """Store a generated report in the database for dashboard access."""
    db = SessionLocal()
    try:
        r = Report(
            report_type=report["period"],
            period_start=datetime.fromisoformat(report["period_start"]),
            period_end=datetime.fromisoformat(report["period_end"]),
            data=report,
        )
        db.add(r)
        db.commit()
        db.refresh(r)
        print(f"[REPORT] Stored report #{r.id} ({report['period']})")
        return r.id
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SMTP delivery
# ---------------------------------------------------------------------------

def send_smtp_report(report: dict, recipients: Optional[list[str]] = None) -> bool:
    """Send the report as an HTML email via SMTP."""
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")

    if not all([smtp_host, smtp_user, smtp_pass]):
        print("[REPORT] SMTP not configured — skipping email delivery.")
        return False

    if not recipients:
        recip_str = os.getenv("REPORT_RECIPIENTS", "")
        recipients = [r.strip() for r in recip_str.split(",") if r.strip()]
    if not recipients:
        print("[REPORT] No recipients configured — skipping email delivery.")
        return False

    counts = report["counts"]
    subject = (
        f"[ImaniIA] {report['period'].title()} Report — "
        f"{counts['total']} emails: {counts['accepted']} Accepted, "
        f"{counts['escalated']} Escalated, {counts['quarantined']} Quarantined"
    )

    html = _format_html_report(report)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[REPORT] Email sent to {', '.join(recipients)}")
        return True
    except Exception as e:
        print(f"[REPORT] SMTP delivery failed: {e}")
        return False


def _format_html_report(report: dict) -> str:
    """Format the report as a styled HTML email."""
    counts = report["counts"]
    top_threats = report.get("top_threats", [])
    details = report.get("details", [])

    threat_rows = ""
    for t in top_threats:
        threat_rows += f"<tr><td>{t['domain']}</td><td>{t['count']}</td></tr>"

    detail_rows = ""
    for d in details[:25]:  # Limit to 25 most recent
        status_color = {
            "accepted": "#22c55e", "released": "#3b82f6",
            "escalated": "#f59e0b", "quarantined": "#ef4444",
        }.get(d["status"], "#6b7280")

        detail_rows += (
            f"<tr>"
            f"<td>{d.get('sender', 'N/A')}</td>"
            f"<td>{d.get('subject', 'N/A')[:60]}</td>"
            f"<td><span style='color:{status_color};font-weight:bold'>{d['status'].upper()}</span></td>"
            f"<td>{d.get('created_at', '')[:19] if d.get('created_at') else ''}</td>"
            f"</tr>"
        )

    return f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1a1a2e; padding: 20px;">
        <h2 style="color: #0f3460;">ImaniIA — {report['period'].title()} Report</h2>
        <p>Period: {report['period_start'][:16]} → {report['period_end'][:16]} UTC</p>

        <table style="border-collapse:collapse; margin:16px 0;">
            <tr>
                <td style="padding:8px 16px; background:#22c55e; color:white; border-radius:4px 0 0 4px;"><b>{counts['accepted']}</b> Accepted</td>
                <td style="padding:8px 16px; background:#f59e0b; color:white;"><b>{counts['escalated']}</b> Escalated</td>
                <td style="padding:8px 16px; background:#ef4444; color:white;"><b>{counts['quarantined']}</b> Quarantined</td>
                <td style="padding:8px 16px; background:#3b82f6; color:white; border-radius:0 4px 4px 0;"><b>{counts['released']}</b> Released</td>
            </tr>
        </table>

        {"<h3>Top Threat Domains</h3><table border='1' cellpadding='6' style='border-collapse:collapse;'><tr><th>Domain</th><th>Count</th></tr>" + threat_rows + "</table>" if threat_rows else ""}

        <h3>Recent Emails ({counts['total']} total)</h3>
        <table border='1' cellpadding='6' style='border-collapse:collapse; font-size:13px;'>
            <tr style='background:#f1f5f9;'><th>Sender</th><th>Subject</th><th>Status</th><th>Time</th></tr>
            {detail_rows}
        </table>

        <p style="color:#6b7280; font-size:12px; margin-top:20px;">
            Generated by ImaniIA Claims Triage System at {report['generated_at'][:19]} UTC
        </p>
    </body>
    </html>
    """


# ---------------------------------------------------------------------------
# Slack delivery
# ---------------------------------------------------------------------------

def send_slack_report(report: dict, webhook_url: Optional[str] = None) -> bool:
    """Send the report to Slack via incoming webhook."""
    url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        print("[REPORT] Slack webhook not configured — skipping.")
        return False

    counts = report["counts"]
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"📊 ImaniIA {report['period'].title()} Report"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*✅ Accepted:* {counts['accepted']}"},
                {"type": "mrkdwn", "text": f"*⚠️ Escalated:* {counts['escalated']}"},
                {"type": "mrkdwn", "text": f"*🔴 Quarantined:* {counts['quarantined']}"},
                {"type": "mrkdwn", "text": f"*🔵 Released:* {counts['released']}"},
            ]
        },
        {"type": "divider"},
    ]

    # Add top threats
    if report.get("top_threats"):
        threats_text = "\n".join(
            f"• `{t['domain']}` — {t['count']} email(s)"
            for t in report["top_threats"][:5]
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Threat Domains:*\n{threats_text}"}
        })

    payload = {"blocks": blocks}

    try:
        session = get_session()
        resp = session.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            print("[REPORT] Slack notification sent.")
            return True
        else:
            print(f"[REPORT] Slack webhook returned {resp.status_code}")
            return False
    except Exception as e:
        print(f"[REPORT] Slack delivery failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Microsoft Teams delivery
# ---------------------------------------------------------------------------

def send_teams_report(report: dict, webhook_url: Optional[str] = None) -> bool:
    """Send the report to Microsoft Teams via incoming webhook (Adaptive Card)."""
    url = webhook_url or os.getenv("TEAMS_WEBHOOK_URL")
    if not url:
        print("[REPORT] Teams webhook not configured — skipping.")
        return False

    counts = report["counts"]
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"📊 ImaniIA {report['period'].title()} Report",
                        "size": "Large",
                        "weight": "Bolder",
                    },
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {"type": "Column", "items": [
                                {"type": "TextBlock", "text": f"✅ {counts['accepted']}", "weight": "Bolder", "color": "Good"},
                                {"type": "TextBlock", "text": "Accepted", "size": "Small"},
                            ]},
                            {"type": "Column", "items": [
                                {"type": "TextBlock", "text": f"⚠️ {counts['escalated']}", "weight": "Bolder", "color": "Warning"},
                                {"type": "TextBlock", "text": "Escalated", "size": "Small"},
                            ]},
                            {"type": "Column", "items": [
                                {"type": "TextBlock", "text": f"🔴 {counts['quarantined']}", "weight": "Bolder", "color": "Attention"},
                                {"type": "TextBlock", "text": "Quarantined", "size": "Small"},
                            ]},
                            {"type": "Column", "items": [
                                {"type": "TextBlock", "text": f"🔵 {counts['released']}", "weight": "Bolder", "color": "Accent"},
                                {"type": "TextBlock", "text": "Released", "size": "Small"},
                            ]},
                        ],
                    },
                ],
            },
        }],
    }

    try:
        session = get_session()
        resp = session.post(url, json=card, timeout=10)
        if resp.status_code in (200, 202):
            print("[REPORT] Teams notification sent.")
            return True
        else:
            print(f"[REPORT] Teams webhook returned {resp.status_code}")
            return False
    except Exception as e:
        print(f"[REPORT] Teams delivery failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Unified delivery
# ---------------------------------------------------------------------------

def generate_and_deliver(period: str = "daily") -> dict:
    """Generate report and deliver via all configured channels."""
    report = generate_report(period)

    delivered = []

    # Always store in DB
    try:
        store_report(report)
        delivered.append("dashboard")
    except Exception as e:
        print(f"[REPORT] DB store failed: {e}")

    # SMTP
    if send_smtp_report(report):
        delivered.append("smtp")

    # Slack
    if send_slack_report(report):
        delivered.append("slack")

    # Teams
    if send_teams_report(report):
        delivered.append("teams")

    report["delivered_via"] = delivered
    print(f"[REPORT] Delivered via: {', '.join(delivered) if delivered else 'none'}")
    return report
