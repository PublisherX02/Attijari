"""generate_atomic_report.py — builds a self-contained HTML report (table +
charts) of the atomic-red-team batch test: for each of the 164 real
attack-technique samples, what MITRE technique it represents and exactly
what detection mechanism caught it (or didn't). Reads from durable state
only (the DB + data/atomic_batch/manifest.json), so it can be re-run any
number of times, including after a full restart.
"""
import json
import re
import sys
from collections import Counter, defaultdict
from html import escape
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

MANIFEST_PATH = PROJECT_ROOT / "data" / "atomic_batch" / "manifest.json"
OUTPUT_PATH = PROJECT_ROOT / "docs" / "atomic-red-team-report.html"

from database import SessionLocal, Email  # noqa: E402


def _primary_detection(rules_result: dict, enrichment_result: dict, llm_result: dict) -> tuple[str, str]:
    """Returns (layer_label, detail) -- the FIRST deterministic layer that
    actually fired, in the same precedence the pipeline itself uses
    (rules engine first, then extraction/YARA, then LLM last)."""
    rules_result = rules_result or {}
    enrichment_result = enrichment_result or {}
    llm_result = llm_result or {}

    hard_flags = [d for d in (rules_result.get("details") or []) if d.get("flagged")]
    if hard_flags:
        names = ", ".join(sorted({d["rule"] for d in hard_flags}))
        return ("Rules Engine", names)

    attachments_meta = enrichment_result.get("attachments_meta") or []
    all_flags: list[str] = []
    for a in attachments_meta:
        all_flags.extend(a.get("extraction_flags") or [])

    def _has(prefix):
        return [f for f in all_flags if prefix in f]

    if _has("qr_code_url_found"):
        return ("QR Code Decode", _has("qr_code_url_found")[0])
    if _has("executable_disguised_as_document"):
        return ("Magic-Byte Verification", _has("executable_disguised_as_document")[0])
    if _has("lnk_command") or _has("archive_dangerous_content"):
        m = _has("lnk_command") or _has("archive_dangerous_content")
        return ("Archive/LNK Analysis", m[0][:160])
    if _has("yara_match"):
        return ("YARA", _has("yara_match")[0])
    if _has("oletools_suspicious"):
        return ("OLE/Macro Analysis", _has("oletools_suspicious")[0])
    if _has("no_parser_available_for_format"):
        return ("Fail-Safe (No Parser)", _has("no_parser_available_for_format")[0][:160])
    if _has("nested_email_attachment"):
        return ("Nested-Email Fail-Safe", "always-escalate by design")
    if _has("type_mismatch"):
        return ("Type-Mismatch Detection", _has("type_mismatch")[0])
    if any("sandbox_error" in f for f in all_flags):
        sb = [f for f in all_flags if "sandbox_error" in f]
        return ("Sandbox Fail-Safe", sb[0][:160])

    vt_hits = [v for v in (enrichment_result.get("virustotal") or []) if v.get("detected")]
    if vt_hits:
        return ("VirusTotal", f"{vt_hits[0].get('detection_count', '?')} engine(s)")

    if llm_result.get("verdict") == "escalated":
        reasons = llm_result.get("reasons") or []
        return ("LLM Analysis (only)", (reasons[0] if reasons else "")[:160])

    return ("Not Detected", "")


def main():
    if not MANIFEST_PATH.exists():
        print(f"[ERROR] Manifest not found at {MANIFEST_PATH}")
        sys.exit(1)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    print(f"Loaded manifest: {len(manifest)} samples")

    db = SessionLocal()
    try:
        shas = list(manifest.keys())
        rows = db.query(Email).filter(Email.raw_sha256.in_(shas)).all()
        by_sha = {r.raw_sha256: r for r in rows}
    finally:
        db.close()

    print(f"Matched {len(by_sha)}/{len(manifest)} samples to DB rows")

    results = []
    for sha, meta in manifest.items():
        row = by_sha.get(sha)
        technique_full = meta["technique_id"]
        technique_base = re.match(r"(T\d{4})", technique_full)
        technique_base = technique_base.group(1) if technique_base else technique_full
        if row is None:
            results.append({
                "technique": technique_full, "technique_base": technique_base,
                "display_name": meta["display_name"], "filename": meta["filename"],
                "status": "not processed", "layer": "N/A", "detail": "",
                "size": meta.get("size_bytes", 0),
            })
            continue
        layer, detail = _primary_detection(row.rules_result, row.enrichment_result, row.llm_result)
        results.append({
            "technique": technique_full, "technique_base": technique_base,
            "display_name": meta["display_name"], "filename": meta["filename"],
            "status": row.status, "layer": layer, "detail": detail,
            "size": meta.get("size_bytes", 0),
        })

    total = len(results)
    processed = [r for r in results if r["status"] != "not processed"]
    detected = [r for r in processed if r["status"] in ("escalated", "quarantined", "proposed_reject")]
    accepted = [r for r in processed if r["status"] == "accepted"]
    not_processed = [r for r in results if r["status"] == "not processed"]

    layer_counts = Counter(r["layer"] for r in processed)
    technique_counts = defaultdict(lambda: {"total": 0, "detected": 0})
    for r in results:
        technique_counts[r["technique_base"]]["total"] += 1
        if r["status"] in ("escalated", "quarantined", "proposed_reject"):
            technique_counts[r["technique_base"]]["detected"] += 1

    print(f"Total: {total}, Processed: {len(processed)}, Detected: {len(detected)}, "
          f"Accepted (missed): {len(accepted)}, Not yet processed: {len(not_processed)}")

    html = _build_html(results, total, processed, detected, accepted, not_processed,
                        layer_counts, technique_counts)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(html, encoding="utf-8")
    print(f"Report written to {OUTPUT_PATH}")


def _bar_chart_svg(counter: dict, title: str, width: int = 720) -> str:
    if not counter:
        return "<p class='muted'>No data yet.</p>"
    items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
    max_val = max(v for _, v in items) or 1
    row_h = 32
    label_w = 220
    chart_w = width - label_w - 60
    height = row_h * len(items) + 20
    bars = []
    for i, (label, val) in enumerate(items):
        y = i * row_h + 10
        bar_w = max(2, (val / max_val) * chart_w)
        bars.append(f"""
        <text x="{label_w - 10}" y="{y + row_h/2 + 5}" text-anchor="end" class="bar-label">{escape(str(label))}</text>
        <rect x="{label_w}" y="{y + 4}" width="{bar_w:.1f}" height="{row_h - 10}" rx="4" class="bar"/>
        <text x="{label_w + bar_w + 8}" y="{y + row_h/2 + 5}" class="bar-value">{val}</text>
        """)
    return f"""
    <h3>{escape(title)}</h3>
    <svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="{escape(title)}">
      {''.join(bars)}
    </svg>
    """


def _build_html(results, total, processed, detected, accepted, not_processed,
                 layer_counts, technique_counts) -> str:
    detection_rate = (len(detected) / len(processed) * 100) if processed else 0

    rows_html = []
    for r in sorted(results, key=lambda r: (r["technique_base"], r["technique"])):
        status_class = {
            "escalated": "status-escalated", "quarantined": "status-escalated",
            "proposed_reject": "status-escalated", "accepted": "status-accepted",
            "not processed": "status-pending",
        }.get(r["status"], "status-pending")
        rows_html.append(f"""
        <tr>
          <td class="mono">{escape(r['technique'])}</td>
          <td>{escape(r['display_name'])}</td>
          <td class="mono">{escape(r['filename'])}</td>
          <td><span class="badge {status_class}">{escape(r['status'])}</span></td>
          <td>{escape(r['layer'])}</td>
          <td class="detail">{escape(r['detail'])}</td>
        </tr>
        """)

    technique_rows = []
    for tech, c in sorted(technique_counts.items()):
        rate = (c["detected"] / c["total"] * 100) if c["total"] else 0
        technique_rows.append((tech, c["total"], c["detected"], rate))

    layer_chart = _bar_chart_svg(dict(layer_counts), "Detection mechanism breakdown")
    technique_chart = _bar_chart_svg(
        {t: c["detected"] for t, c, *_ in [(t, cc) for t, cc in technique_counts.items()]},
        "Detections by MITRE technique"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>atomic-red-team pipeline validation report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #0b0f14; --panel: #121821; --border: #232c38; --text: #e6edf3;
    --muted: #8b98a5; --accent: #4f8cff; --good: #3fb950; --bad: #f85149;
    --warn: #d29922;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg: #f6f8fa; --panel: #ffffff; --border: #d0d7de; --text: #1f2328;
      --muted: #57606a; --accent: #0969da; --good: #1a7f37; --bad: #cf222e;
      --warn: #9a6700;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 24px 64px; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif; line-height: 1.5;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 4px; }}
  .subtitle {{ color: var(--muted); margin-top: 0; margin-bottom: 28px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 32px; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }}
  .stat .n {{ font-size: 1.8rem; font-weight: 700; }}
  .stat .l {{ color: var(--muted); font-size: 0.85rem; }}
  .stat.good .n {{ color: var(--good); }}
  .stat.bad .n {{ color: var(--bad); }}
  section {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 24px; overflow-x: auto; }}
  h3 {{ margin-top: 0; font-size: 1.1rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.88rem; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 600; position: sticky; top: 0; background: var(--panel); }}
  .mono {{ font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 0.85em; }}
  .detail {{ color: var(--muted); max-width: 420px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }}
  .status-escalated {{ background: rgba(63,185,80,0.15); color: var(--good); }}
  .status-accepted {{ background: rgba(248,81,73,0.15); color: var(--bad); }}
  .status-pending {{ background: rgba(210,153,34,0.15); color: var(--warn); }}
  .bar {{ fill: var(--accent); }}
  .bar-label {{ fill: var(--text); font-size: 12px; }}
  .bar-value {{ fill: var(--muted); font-size: 12px; }}
  .muted {{ color: var(--muted); }}
  .table-scroll {{ max-height: 640px; overflow-y: auto; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>atomic-red-team pipeline validation report</h1>
  <p class="subtitle">{total} real attack-technique samples from RedCanary's atomic-red-team, run through the full live pipeline. Detection layer shown is the first deterministic mechanism that actually fired, in pipeline precedence order.</p>

  <div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">Total samples</div></div>
    <div class="stat"><div class="n">{len(processed)}</div><div class="l">Processed</div></div>
    <div class="stat good"><div class="n">{len(detected)}</div><div class="l">Detected / escalated</div></div>
    <div class="stat {'bad' if accepted else 'good'}"><div class="n">{len(accepted)}</div><div class="l">Accepted (missed)</div></div>
    <div class="stat"><div class="n">{len(not_processed)}</div><div class="l">Not yet processed</div></div>
    <div class="stat"><div class="n">{detection_rate:.1f}%</div><div class="l">Detection rate</div></div>
  </div>

  <section>{layer_chart}</section>
  <section>{technique_chart}</section>

  <section>
    <h3>Full results ({total} samples)</h3>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Technique</th><th>Name</th><th>Sample file</th><th>Status</th><th>Detected by</th><th>Detail</th></tr></thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
    </div>
  </section>
</div>
</body>
</html>
"""


if __name__ == "__main__":
    main()
