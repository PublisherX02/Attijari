"""analysis.py

Loads system prompt from skills.md and analyzes an email body with Ollama (gemma3:4b).
Tries Python ollama client if available, falls back to Ollama HTTP API at localhost:11434.
"""
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
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.0
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
            "temperature": DEFAULT_TEMPERATURE,
            "stream": False,
            "stop": ["```"]
        }).encode("utf-8")

        req = request.Request(OLLAMA_HTTP_URL, data=payload, headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8")


def _call_ollama_client(model: str, prompt: str) -> str:
    # Best-effort: support ollama python package if installed.
    try:
        import ollama
    except Exception as e:
        raise RuntimeError("ollama python client not available") from e

    client = ollama.Ollama()
        # Try non-streaming deterministic generation where possible
        kwargs = {"model": model, "prompt": prompt, "max_tokens": DEFAULT_MAX_TOKENS, "temperature": DEFAULT_TEMPERATURE, "stream": False}
        if hasattr(client, "generate"):
            try:
                return client.generate(**kwargs)
            except TypeError:
                # older client may not accept kwargs
                return client.generate(model=model, prompt=prompt)
        if hasattr(client, "create"):
            try:
                return client.create(**kwargs)
            except TypeError:
                return client.create(model=model, prompt=prompt)
        # Last attempt
        try:
            return client.generate(model=model, prompt=prompt)
        except Exception:
            raise RuntimeError("Unsupported ollama client API")


def analyze_email_body(body_text: str, model: Optional[str] = None, skills_path_candidates: Optional[list[str]] = None, context: Optional[dict] = None) -> Dict[str, Any]:
    """Analyze an email body with the assigned Ollama model.

    context: optional dict with keys 'headers' (dict) and 'attachments' (list).

    Returns a dict with keys: verdict (accepted|escalated), reasons (list), indicators (dict), raw_model_output
    """
    model = model or DEFAULT_MODEL
    skills = _load_skills_prompt(skills_path_candidates or SKILLS_PATHS)

    # Build a deterministic instruction asking for strict JSON output
    # Include brief context (headers + attachment filenames) if provided to help detection
    ctx = context or {}
    ctx_parts = []
    hdrs = ctx.get('headers') if isinstance(ctx.get('headers'), dict) else None
    if hdrs:
        for k in ('from', 'message-id', 'authentication-results', 'subject'):
            v = hdrs.get(k)
            if v:
                ctx_parts.append(f"{k}: {v}")
    atts = ctx.get('attachments') if isinstance(ctx.get('attachments'), list) else None
    if atts:
        names = [a.get('original_name') for a in atts if isinstance(a, dict) and a.get('original_name')]
        if names:
            ctx_parts.append("attachments: " + ", ".join(names))
    context_note = "\nCONTEXT:\n" + "\n".join(ctx_parts) + "\n\n" if ctx_parts else ""

    prompt = (
        "SYSTEM:\n" + skills + "\n\n" +
        "USER:\n" +
        "You are a security analysis assistant. Analyze the following email and return ONLY valid compact JSON with keys:\n"
        "  - verdict: 'accepted' or 'escalated'\n"
        "  - reasons: array of short strings explaining flags\n"
        "  - indicators: optional object with discovered IOCs or patterns\n\n"
        "Do NOT stream events or prefix the JSON with explanation. Return a single JSON blob only.\n\n"
        "" + context_note + "Now analyze this text:\n\n" + (body_text or "")
    )

    # Try python ollama client first
    model_output = None
    try:
        model_output = _call_ollama_client(model, prompt)
    except Exception:
        try:
            model_output = _call_ollama_http(model, prompt)
        except Exception as e:
            return {"verdict": "escalated", "reasons": [f"analysis_failed:{e}"], "raw_model_output": None}

    # Try to extract JSON from model_output (robust for streaming/event-wrapped Ollama outputs)
    parsed = None
    try:
        def _find_json_with_key(s: str, key: str) -> str | None:
            i = s.find(f'"{key}"')
            if i == -1:
                return None
            # find the opening brace before the key
            start = s.rfind('{', 0, i)
            if start == -1:
                return None
            # balance braces forward to find the matching closing brace
            depth = 0
            for j in range(start, len(s)):
                if s[j] == '{':
                    depth += 1
                elif s[j] == '}':
                    depth -= 1
                    if depth == 0:
                        return s[start:j+1]
            return None

        candidate = _find_json_with_key(model_output, 'verdict')
        if not candidate:
            # fallback: scan each balanced JSON block and look for 'verdict'
            candidate = None
            starts = [idx for idx, ch in enumerate(model_output) if ch == '{']
            for st in starts:
                depth = 0
                for j in range(st, len(model_output)):
                    if model_output[j] == '{':
                        depth += 1
                    elif model_output[j] == '}':
                        depth -= 1
                        if depth == 0:
                            block = model_output[st:j+1]
                            try:
                                obj = json.loads(block)
                                if isinstance(obj, dict) and 'verdict' in obj:
                                    candidate = block
                                    break
                            except Exception:
                                pass
                            break
                if candidate:
                    break

        if candidate:
            parsed = json.loads(candidate)
        else:
            # If the API returned streaming event objects (NDJSON), reconstruct the response
            reconstructed = []
            for line in model_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    # some event formats use 'response' or 'text'
                    if isinstance(ev, dict) and 'response' in ev and isinstance(ev['response'], str):
                        reconstructed.append(ev['response'])
                    elif isinstance(ev, dict) and 'text' in ev and isinstance(ev['text'], str):
                        reconstructed.append(ev['text'])
                except Exception:
                    # not a JSON event line; skip
                    continue
            joined = ''.join(reconstructed)
            # try to find JSON in reconstructed text
            cand2 = None
            # flexible search for the 'verdict' key in the reconstructed stream
            key_idx = joined.find('"verdict"')
            if key_idx == -1:
                key_idx = joined.find('"verdict')
            if key_idx == -1:
                key_idx = joined.find('verdict')

            if key_idx != -1:
                start = joined.rfind('{', 0, key_idx)
                if start != -1:
                    depth = 0
                    for j in range(start, len(joined)):
                        if joined[j] == '{':
                            depth += 1
                        elif joined[j] == '}':
                            depth -= 1
                            if depth == 0:
                                cand2 = joined[start:j+1]
                                break
            if cand2:
                parsed = json.loads(cand2)
            else:
                # last resort: attempt to parse the entire output as JSON
                parsed = json.loads(model_output)
    except Exception:
        # Fallback: return raw output as reason and escalate for manual review
        return {"verdict": "escalated", "reasons": ["model_output_not_json"], "raw_model_output": model_output}

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
