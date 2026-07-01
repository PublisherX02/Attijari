"""shared.py -- Common utilities for Trust No Email research experiments.

Provides:
  - Test corpus loading (malicious + benign)
  - Metrics computation
  - Paper-quality plot styling
  - LLM invocation helpers (local Ollama + cloud APIs)
  - Result persistence (JSON + LaTeX)
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
_SRC = Path(__file__).resolve().parent.parent
_ROOT = _SRC.parent
sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_ROOT / ".env")

from accuracy import build_malicious_cases, build_benign_cases
from email_extraction import EmailIngestion
from rules import RuleEngine

# ---------------------------------------------------------------------------
# Output directories
# ---------------------------------------------------------------------------
EXPERIMENTS_DIR = _ROOT / "data" / "experiments"
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)


def get_output_dir(experiment_name: str) -> Path:
    d = EXPERIMENTS_DIR / experiment_name
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------
def load_corpus() -> list[dict]:
    """Load the full test corpus (malicious + benign)."""
    cases = build_malicious_cases() + build_benign_cases()
    print(f"[CORPUS] {len(cases)} cases: "
          f"{sum(1 for c in cases if c['expected'] == 'malicious')} malicious, "
          f"{sum(1 for c in cases if c['expected'] == 'benign')} benign")
    return cases


def load_malicious_only() -> list[dict]:
    return [c for c in load_corpus() if c["expected"] == "malicious"]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    labels = ["benign", "malicious"]
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "recall": recall_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "f1": f1_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(y_true, y_pred, labels=labels, zero_division=0),
    }


def classify_verdict(verdict: str) -> str:
    """Map any verdict string to binary classification."""
    v = (verdict or "").lower().strip()
    if v in ("accepter", "accepted", "accept", "clean", "safe", "benign", "recu"):
        return "benign"
    return "malicious"  # fail-safe: unknown = malicious


# ---------------------------------------------------------------------------
# LLM Invocation — Multi-provider
# ---------------------------------------------------------------------------

def call_ollama(prompt: str, model: str = "gemma3:4b", temperature: float = 0.0) -> str:
    """Call local Ollama model."""
    import requests
    resp = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": prompt, "stream": False,
              "options": {"temperature": temperature, "num_predict": 2048}},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("response", "")


def call_openai_compatible(
    prompt: str,
    model: str,
    api_key: str,
    base_url: str = "https://api.openai.com/v1",
    temperature: float = 0.0,
) -> str:
    """Call OpenAI-compatible API (OpenAI, Groq, Together, etc.)."""
    import requests
    resp = requests.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": 2048,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def call_anthropic(prompt: str, model: str = "claude-sonnet-4-20250514",
                   api_key: str = "", temperature: float = 0.0) -> str:
    """Call Anthropic Claude API."""
    import requests
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 2048,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


# Provider registry
PROVIDERS = {
    "ollama": call_ollama,
    "openai": lambda prompt, model, **kw: call_openai_compatible(
        prompt, model, api_key=os.getenv("OPENAI_API_KEY", ""), **kw),
    "groq": lambda prompt, model, **kw: call_openai_compatible(
        prompt, model, api_key=os.getenv("GROQ_API_KEY", ""),
        base_url="https://api.groq.com/openai/v1", **kw),
    "together": lambda prompt, model, **kw: call_openai_compatible(
        prompt, model, api_key=os.getenv("TOGETHER_API_KEY", ""),
        base_url="https://api.together.xyz/v1", **kw),
    "anthropic": lambda prompt, model, **kw: call_anthropic(
        prompt, model, api_key=os.getenv("ANTHROPIC_API_KEY", ""), **kw),
    "nvidia": lambda prompt, model, **kw: call_openai_compatible(
        prompt, model, api_key=os.getenv("NVIDIA_API_KEY", ""),
        base_url="https://integrate.api.nvidia.com/v1", **kw),
    "deepseek": lambda prompt, model, **kw: call_openai_compatible(
        prompt, model, api_key=os.getenv("NVIDIA_DEEPSEEK_V4_PRO_KEY", ""),
        base_url="https://integrate.api.nvidia.com/v1", **kw),
    "mistral_nvidia": lambda prompt, model, **kw: call_openai_compatible(
        prompt, model, api_key=os.getenv("NVIDIA_MISTRAL_KEY", ""),
        base_url="https://integrate.api.nvidia.com/v1", **kw),
}


def call_model(prompt: str, provider: str, model: str,
               temperature: float = 0.0) -> str:
    """Universal model caller."""
    fn = PROVIDERS.get(provider)
    if not fn:
        raise ValueError(f"Unknown provider: {provider}. "
                         f"Available: {list(PROVIDERS.keys())}")
    if provider == "ollama":
        return fn(prompt, model=model, temperature=temperature)
    return fn(prompt, model, temperature=temperature)


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------

def parse_email(raw_eml: bytes) -> dict:
    """Parse raw .eml bytes into structured data."""
    ingestion = EmailIngestion(host="", user="", password="")
    return ingestion.parse_email(raw_eml)


def run_rules_engine(parsed: dict) -> dict:
    """Run rules engine with isolated blocklist."""
    import rules as _rules_mod
    saved_cache = _rules_mod._blocklist_cache
    saved_time = _rules_mod._blocklist_cache_time
    _rules_mod._blocklist_cache = set()
    _rules_mod._blocklist_cache_time = time.time()

    engine = RuleEngine()
    analysis = engine.analyze(parsed)

    _rules_mod._blocklist_cache = saved_cache
    _rules_mod._blocklist_cache_time = saved_time
    return analysis


def run_extraction(parsed: dict) -> dict:
    """Run file extraction/analysis on attachments."""
    if not parsed.get("attachments"):
        return {"results": [], "total_flags": 0, "escalate": False}
    from extraction import extract_all_attachments
    return extract_all_attachments(parsed)


def get_analysis_prompt(parsed: dict, include_signals: bool = True) -> str:
    """Build the LLM analysis prompt from parsed email data."""
    from analysis import analyze_email_body
    # We need the prompt but not the actual LLM call, so we extract it
    body = parsed.get("body_text", "")
    headers = parsed.get("headers", {})

    prompt_parts = [
        "You are an email security analyst at a bank. Analyze this email and respond with a JSON object.",
        "Respond ONLY with valid JSON containing these fields:",
        '{"verdict": "accepter|rejeter|escalader", "score_risque": 0-100, '
        '"confiance": 0.0-1.0, "raisonnement": "brief explanation"}',
        "",
        f"From: {headers.get('from', 'unknown')}",
        f"To: {headers.get('to', 'unknown')}",
        f"Subject: {headers.get('subject', 'no subject')}",
        f"Date: {headers.get('date', 'unknown')}",
        "",
        "Email body:",
        body[:3000] if body else "(empty)",
    ]

    if include_signals:
        auth = parsed.get("auth", {})
        if auth:
            prompt_parts.append(f"\nAuthentication: SPF={auth.get('auth_header', {}).get('spf', 'none')}, "
                                f"DKIM={auth.get('auth_header', {}).get('dkim', 'none')}, "
                                f"DMARC={auth.get('auth_header', {}).get('dmarc', 'none')}")

        extraction = parsed.get("extraction", {})
        if extraction and extraction.get("results"):
            prompt_parts.append("\nAttachment analysis:")
            for r in extraction["results"]:
                flags = r.get("flags", [])
                prompt_parts.append(f"  - {r.get('filename', 'unknown')}: "
                                    f"{'FLAGGED: ' + ', '.join(flags) if flags else 'clean'}")

        rules = parsed.get("analysis", {})
        if rules:
            flagged = [d["rule"] for d in rules.get("details", []) if d.get("flagged")]
            if flagged:
                prompt_parts.append(f"\nRule engine flags: {', '.join(flagged)}")

    return "\n".join(prompt_parts)


# ---------------------------------------------------------------------------
# Plot styling
# ---------------------------------------------------------------------------
def paper_style():
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 12,
        "axes.titlesize": 14,
        "axes.titleweight": "bold",
        "axes.labelsize": 12,
        "figure.dpi": 200,
        "savefig.dpi": 300,
    })


COLORS = ["#2ecc71", "#3498db", "#e67e22", "#e74c3c", "#9b59b6",
          "#1abc9c", "#f39c12", "#e91e63", "#00bcd4", "#795548"]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def save_results(data: Any, output_dir: Path, name: str) -> Path:
    """Save results as JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"{name}_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  [JSON] {path}")
    return path


def save_latex(lines: list[str], output_dir: Path, name: str) -> Path:
    """Save LaTeX table."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"{name}_{ts}.tex"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [LATEX] {path}")
    return path
