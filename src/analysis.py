from __future__ import annotations
import json
import os
from typing import Any, Dict, Optional

SKILLS_PATHS = [
    os.path.join(os.path.dirname(__file__), "skills.md"),
    os.path.join(os.path.dirname(__file__), "..", "skills.md"),
    os.path.join(os.getcwd(), "skills.md"),
]

DEFAULT_MODEL = "gemma3:4b"
OLLAMA_HTTP_URL = "http://localhost:11434/api/generate"


def _load_skills_prompt(path_candidates: list[str] = SKILLS_PATHS) -> str:
    for p in path_candidates:
        try:
            p = os.path.abspath(p)
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as fh:
                    return fh.read()
        except Exception:
            continue
    return ""  # empty system prompt if not found


def _call_ollama_http(model: str, prompt: str, max_tokens: int = 1024) -> str:
    # Uses stdlib to avoid external dependency
    try:
        from urllib import request, parse
    except Exception as e:
        raise RuntimeError(f"urllib unavailable: {e}")

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "max_tokens": max_tokens,
    }).encode("utf-8")

    req = request.Request(OLLAMA_HTTP_URL, data=payload, headers={"Content-Type": "application/json"})
    with request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def _call_ollama_client(model: str, prompt: str) -> str:
    # Best-effort: support ollama python package if installed.
    try:
        import ollama
    except Exception as e:
        raise RuntimeError("ollama python client not available") from e

    client = ollama.Ollama()
    # The exact client API may vary; use generate or create if present
    if hasattr(client, "generate"):
        return client.generate(model=model, prompt=prompt)
    if hasattr(client, "create"):
        return client.create(model=model, prompt=prompt)
    raise RuntimeError("Unsupported ollama client API")


def analyze_email_body(body_text: str, model: Optional[str] = None, skills_path_candidates: Optional[list[str]] = None) -> Dict[str, Any]:

    #Returns a dict with keys: verdict (accepted|escalated), reasons (list), raw_model_output.
    
    model = model or DEFAULT_MODEL
    skills = _load_skills_prompt(skills_path_candidates or SKILLS_PATHS)

    # Build a deterministic instruction asking for strict JSON output
    prompt = (
        "SYSTEM:\n" + skills + "\n\n" +
        "USER:\n" +
        "You are a security analysis assistant. Analyze the following email body and return ONLY valid JSON with keys:\n"
        "  - verdict: 'accepted' or 'escalated'\n"
        "  - reasons: array of short strings explaining flags\n"
        "  - indicators: optional object with discovered IOCs or patterns\n\n"
        "Respond with compact JSON only. Now analyze this text:\n\n" + body_text
    )

    # Try python ollama client first
    model_output = None
    try:
        model_output = _call_ollama_client(model, prompt)
    except Exception:
        try:
            model_output = _call_ollama_http(model, prompt)
        except Exception as e:
            return {"verdict": "accepted", "reasons": [f"analysis_failed:{e}"], "raw_model_output": None}

    # Try to extract JSON from model_output
    parsed = None
    try:
        # Some Ollama outputs may wrap JSON; attempt to find first '{'...
        first = model_output.find("{")
        if first != -1:
            candidate = model_output[first:]
            parsed = json.loads(candidate)
        else:
            parsed = json.loads(model_output)
    except Exception:
        # Fallback: return raw output as reason
        return {"verdict": "accepted", "reasons": ["model_output_not_json"], "raw_model_output": model_output}

    # Normalize verdict
    verdict = parsed.get("verdict", "accepted")
    reasons = parsed.get("reasons", []) or []

    return {"verdict": verdict, "reasons": reasons, "indicators": parsed.get("indicators"), "raw_model_output": model_output}


if __name__ == "__main__":
    # quick CLI for local testing
    import sys
    text = sys.stdin.read() if not sys.stdin.isatty() else ""
    if not text:
        print("Usage: echo 'email body' | python src/analysis.py")
        raise SystemExit(1)
    out = analyze_email_body(text)
    print(json.dumps(out, indent=2))
