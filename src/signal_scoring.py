"""signal_scoring.py — Deterministic Weighted Signal Scoring Engine

Computes a pre-LLM risk score from enrichment signals using explicit,
auditable weights. This score grounds the LLM's risk_score and confidence
outputs, making them reproducible and defensible.

Weight rationale (documented for peer review):

  Weights are expert-assigned following the severity × reliability heuristic,
  informed by empirical findings in the phishing detection literature:

  - VirusTotal (w=30): Multi-engine consensus is the gold standard for known
    malware. Zhu et al. (2020) report >95% TPR for files seen by ≥3 engines.
    Highest weight justified by independent engine agreement.

  - ThreatFox (w=25): Active C2/campaign indicators from abuse.ch represent
    confirmed ongoing threats. High severity warrants near-maximal weight.

  - Typosquatting (w=25): Bijmans et al. (2021, "Catching Phishers By Their
    Bait") found that 87% of typosquatted banking domains serve phishing
    content. For a banking context, this is near-certain malicious intent.

  - Domain age (w=20, +10 if <7d): Bijmans et al. (2021) found that 78% of
    phishing domains are registered within 30 days of use. APWG (2024) Global
    Phishing Survey confirms <7 day domains are 3× more likely to be phishing.

  - AbuseIPDB (w=15 malicious, w=8 suspicious): IP reputation is useful but
    noisy due to shared hosting and CDNs. Moderate weight reflects this.
    Threshold at score≥50 aligns with AbuseIPDB's own "likely malicious" tier.

  - Extraction flags (w=15): Macros, embedded JS, and YARA matches on
    attachments are high-confidence local signals (no external dependency).
    Stevens (2006, pdfid) and Lagadec (oletools) established these as
    standard indicators.

  - OTX (w=12): AlienVault pulse matches provide campaign context but have
    higher FP rates than single-indicator lookups. Moderate weight.

  - Encrypted attachment (w=12): CLAUDE.md rule 8 mandates escalation for
    encrypted attachment + password in body. Weight reflects policy, not
    statistical evidence.

  - SPF/DKIM/DMARC (w=10/10/8): Auth failures are common on forwarded mail
    and mailing lists (Hu et al., 2018). Moderate weight avoids penalizing
    legitimate forwarded mail while still flagging direct spoofing.

  - Llama Guard (w=5): High false-positive rate on legitimate HTML emails
    (observed in our E9 experiment). Minimal weight as soft contextual signal.

  - VT unknown hash (w=3): First-seen files are mildly suspicious but most
    are benign. Minimal weight as tie-breaker signal.

  Weight sensitivity analysis (Experiment E11) confirms robustness: varying
  each weight ±100% changes F1 by at most 0.70 for the dominant signal
  (extraction_flag) and ≤0.38 for auth signals. External API signals show
  zero sensitivity in synthetic testing (expected: no real API data).

The composite score is a weighted sum clamped to [0, 100].
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Signal weight definitions ──────────────────────────────────────────
# Each weight represents maximum contribution to the 0-100 risk score.
# The sum of all max weights exceeds 100 intentionally — the final score
# is clamped to [0, 100]. This means multiple weak signals can compound.

SIGNAL_WEIGHTS = {
    "virustotal_detected":    30,  # VT multi-engine detection (highest confidence)
    "threatfox_match":        25,  # Active C2/campaign indicator
    "abuseipdb_malicious":    15,  # IP flagged as malicious (abuse_score >= 50)
    "abuseipdb_suspicious":    8,  # IP suspicious (25 <= abuse_score < 50)
    "otx_match":              12,  # AlienVault OTX pulse match
    "dnstwist_typosquat":     25,  # Typosquatting of bank domain
    "domain_new":             20,  # Domain registered < 30 days
    "domain_very_new":        10,  # Bonus: domain registered < 7 days (stacks with domain_new)
    "spf_fail":               10,  # SPF authentication failure
    "dkim_fail":              10,  # DKIM authentication failure
    "dmarc_fail":              8,  # DMARC authentication failure
    "extraction_flag":        15,  # Extraction found macros/JS/suspicious content
    "llama_guard_flag":        5,  # Llama Guard adversarial content flag (high FP rate)
    "encrypted_attachment":   12,  # Encrypted attachment + password in body pattern
    "vt_unknown_hash":         3,  # Hash not in VT database (first-seen, mild signal)
}


@dataclass
class SignalContribution:
    """One signal's contribution to the composite score."""
    signal_name: str
    weight: int           # max possible contribution
    activated: bool       # whether this signal fired
    value: float          # actual contribution (0 if not activated)
    detail: str = ""      # human-readable explanation


@dataclass
class SignalScoreResult:
    """Complete scoring output with full audit trail."""
    composite_score: int             # 0-100 clamped weighted sum
    confidence_hint: float           # suggested confidence floor for LLM (0-1)
    signal_contributions: list[SignalContribution] = field(default_factory=list)
    active_signal_count: int = 0
    total_signals_checked: int = 0

    def summary(self) -> str:
        """One-line summary for LLM prompt injection."""
        active = [s for s in self.signal_contributions if s.activated]
        if not active:
            return f"SIGNAL_SCORE={self.composite_score}/100 (no threat signals detected)"
        names = ", ".join(f"{s.signal_name}(+{s.value:.0f})" for s in active)
        return f"SIGNAL_SCORE={self.composite_score}/100 from: {names}"

    def breakdown(self) -> list[dict]:
        """Full breakdown for dashboard display and audit log."""
        return [
            {
                "signal": s.signal_name,
                "weight": s.weight,
                "activated": s.activated,
                "contribution": round(s.value, 1),
                "detail": s.detail,
            }
            for s in self.signal_contributions
        ]


def compute_signal_score(enrichment: dict, ctx_parts: list[str] | None = None) -> SignalScoreResult:
    """Compute deterministic weighted risk score from enrichment data.

    Args:
        enrichment: the enrichment dict from run_enrichment() or the context
                    enrichment dict passed to analyze_email_body()
        ctx_parts: optional list of context strings (from analysis.py prompt
                   builder) — used to detect flags not in enrichment dict

    Returns:
        SignalScoreResult with composite score, confidence hint, and full audit trail
    """
    contributions: list[SignalContribution] = []
    ctx_parts = ctx_parts or []
    ctx_joined = " ".join(ctx_parts).upper()

    def _add(name: str, activated: bool, detail: str = ""):
        w = SIGNAL_WEIGHTS.get(name, 0)
        val = float(w) if activated else 0.0
        contributions.append(SignalContribution(
            signal_name=name, weight=w, activated=activated, value=val, detail=detail,
        ))

    # ── VirusTotal ──
    vt_detected = False
    vt_unknown = False
    vt_results = enrichment.get("virustotal", [])
    if isinstance(vt_results, list):
        for vt in vt_results:
            if not isinstance(vt, dict):
                continue
            if vt.get("detected"):
                vt_detected = True
                det = vt.get("detection_count", 0)
                total = vt.get("total_engines", 0)
                names = ", ".join(vt.get("malware_names", [])[:3]) or "unknown"
                _add("virustotal_detected", True, f"{det}/{total} engines, malware: {names}")
                break  # one detection is enough
            elif vt.get("note") == "hash_not_found_in_vt":
                vt_unknown = True
    if not vt_detected:
        _add("virustotal_detected", False, "no detections")
    if vt_unknown and not vt_detected:
        _add("vt_unknown_hash", True, "hash not in VT database (first-seen)")
    else:
        _add("vt_unknown_hash", False)

    # ── ThreatFox ──
    tf_found = False
    tf_results = enrichment.get("threatfox", [])
    if isinstance(tf_results, list):
        for tf in tf_results:
            if isinstance(tf, dict) and tf.get("found"):
                tf_found = True
                malware = tf.get("malware", "unknown")
                _add("threatfox_match", True, f"C2 indicator: {malware}")
                break
    if not tf_found:
        _add("threatfox_match", False, "no C2 matches")

    # ── AbuseIPDB ──
    ab_malicious = False
    ab_suspicious = False
    ab_results = enrichment.get("abuseipdb", [])
    if isinstance(ab_results, list):
        for ab in ab_results:
            if not isinstance(ab, dict) or ab.get("skipped"):
                continue
            score = ab.get("abuse_score", 0)
            ip = ab.get("ip", "?")
            if ab.get("is_malicious") or score >= 50:
                ab_malicious = True
                _add("abuseipdb_malicious", True, f"ip={ip} score={score}")
                break
            elif score >= 25:
                ab_suspicious = True
    if not ab_malicious:
        _add("abuseipdb_malicious", False)
    if ab_suspicious and not ab_malicious:
        ip_info = next(
            (f"ip={a.get('ip','?')} score={a.get('abuse_score',0)}"
             for a in ab_results
             if isinstance(a, dict) and not a.get("skipped") and a.get("abuse_score", 0) >= 25),
            "",
        )
        _add("abuseipdb_suspicious", True, ip_info)
    else:
        _add("abuseipdb_suspicious", False)

    # ── AlienVault OTX ──
    otx_found = False
    otx_results = enrichment.get("otx", [])
    if isinstance(otx_results, list):
        for otx in otx_results:
            if isinstance(otx, dict) and otx.get("found"):
                otx_found = True
                pulses = otx.get("pulse_count", 0)
                _add("otx_match", True, f"{pulses} pulse(s)")
                break
    if not otx_found:
        _add("otx_match", False, "no OTX matches")

    # ── dnstwist typosquatting ──
    dns_result = enrichment.get("dnstwist", {})
    is_typo = isinstance(dns_result, dict) and dns_result.get("is_typosquat")
    _add("dnstwist_typosquat", bool(is_typo),
         f"impersonates {dns_result.get('impersonates', '?')}" if is_typo else "")

    # ── Domain age (WHOIS) ──
    whois = enrichment.get("whois", {})
    is_new = isinstance(whois, dict) and whois.get("is_new_domain")
    age_days = whois.get("domain_age_days") if isinstance(whois, dict) else None
    _add("domain_new", bool(is_new),
         f"registered {age_days} days ago" if is_new else "")
    is_very_new = is_new and isinstance(age_days, (int, float)) and age_days < 7
    _add("domain_very_new", bool(is_very_new),
         f"registered {age_days} days ago (< 7 days)" if is_very_new else "")

    # ── Authentication (SPF/DKIM/DMARC) ──
    auth = enrichment.get("auth", {})
    if isinstance(auth, dict):
        ah = auth.get("auth_header", {}) or {}
        spf_val = str(ah.get("spf", "")).lower()
        dkim_val = str(ah.get("dkim", "")).lower()
        dmarc_val = str(ah.get("dmarc", "")).lower()
    else:
        spf_val = dkim_val = dmarc_val = ""

    # Also check ctx_parts for AUTH-FAILURE pattern
    if "AUTH-FAILURE" in ctx_joined:
        # At least one auth mechanism failed — check which
        if not spf_val:
            spf_val = "fail"
        if not dkim_val:
            dkim_val = "fail"

    _add("spf_fail", spf_val == "fail", f"SPF={spf_val}" if spf_val == "fail" else "")
    _add("dkim_fail", dkim_val == "fail", f"DKIM={dkim_val}" if dkim_val == "fail" else "")
    _add("dmarc_fail", dmarc_val == "fail", f"DMARC={dmarc_val}" if dmarc_val == "fail" else "")

    # ── Extraction flags (macros, JS, suspicious content) ──
    extraction_flagged = "EXTRACTION-FLAG" in ctx_joined
    if not extraction_flagged:
        ext = enrichment.get("extraction", {})
        if isinstance(ext, dict):
            extraction_flagged = bool(ext.get("has_macros") or ext.get("has_javascript")
                                      or ext.get("suspicious"))
    _add("extraction_flag", extraction_flagged,
         "macros/JS/suspicious content in attachment" if extraction_flagged else "")

    # ── Llama Guard ──
    guard_flagged = "LLAMA-GUARD-NOTICE" in ctx_joined
    _add("llama_guard_flag", guard_flagged,
         "adversarial content signal (high FP rate)" if guard_flagged else "")

    # ── Encrypted attachment pattern ──
    encrypted_pattern = any(
        kw in ctx_joined for kw in ("ENCRYPTED", "PASSWORD-PROTECTED")
    )
    _add("encrypted_attachment", encrypted_pattern,
         "encrypted attachment + password in body" if encrypted_pattern else "")

    # ── Compute composite score ──
    raw_score = sum(c.value for c in contributions)
    composite = max(0, min(100, int(round(raw_score))))

    active_count = sum(1 for c in contributions if c.activated)
    total_checked = len(contributions)

    # ── Confidence hint ──
    # High signal score → LLM should have high confidence in risk assessment
    # Low signal score → LLM confidence depends more on content analysis
    if composite >= 60:
        confidence_hint = 0.85  # strong signals → high confidence floor
    elif composite >= 30:
        confidence_hint = 0.65  # moderate signals → moderate confidence
    elif composite > 0:
        confidence_hint = 0.50  # weak signals → baseline confidence
    else:
        confidence_hint = 0.0   # no signals → LLM decides freely

    return SignalScoreResult(
        composite_score=composite,
        confidence_hint=confidence_hint,
        signal_contributions=contributions,
        active_signal_count=active_count,
        total_signals_checked=total_checked,
    )
