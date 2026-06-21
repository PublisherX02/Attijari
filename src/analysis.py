"""analysis.py

Robust Ollama analysis helper.
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


def _call_ollama_http(model: str, prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
    try:
        from urllib import request
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
    try:
        import ollama
    except Exception as e:
        raise RuntimeError("ollama python client not available") from e

    client = ollama.Ollama()
    kwargs = {"model": model, "prompt": prompt, "max_tokens": DEFAULT_MAX_TOKENS, "temperature": DEFAULT_TEMPERATURE, "stream": False}
    if hasattr(client, "generate"):
        try:
            return client.generate(**kwargs)
        except TypeError:
            return client.generate(model=model, prompt=prompt)
    if hasattr(client, "create"):
        try:
            return client.create(**kwargs)
        except TypeError:
            return client.create(model=model, prompt=prompt)
    # final attempt
    try:
        return client.generate(model=model, prompt=prompt)
    except Exception:
        raise RuntimeError("Unsupported ollama client API")


def analyze_email_body(body_text: str, model: Optional[str] = None, skills_path_candidates: Optional[list[str]] = None, context: Optional[dict] = None) -> Dict[str, Any]:
    """Analyze email body text with Ollama and return structured verdict.

    context: optional dict with 'headers' and 'attachments' to aid the model.
    """
    model = model or DEFAULT_MODEL
    skills = _load_skills_prompt(skills_path_candidates or SKILLS_PATHS)

    # Build context note
    ctx = context or {}
    ctx_parts = []
    hdrs = ctx.get("headers") if isinstance(ctx.get("headers"), dict) else None
    if hdrs:
        for k in ("from", "message-id", "authentication-results", "subject"):
            v = hdrs.get(k)
            if v:
                ctx_parts.append(f"{k}: {v}")
    atts = ctx.get("attachments") if isinstance(ctx.get("attachments"), list) else None
    if atts:
        names = [a.get("original_name") for a in atts if isinstance(a, dict) and a.get("original_name")]
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
        "Do NOT stream events or provide any prose. Return a single JSON blob only.\n\n"
        + context_note + "Now analyze this text:\n\n" + (body_text or "")
    )

    # Call model
    model_output = None
    try:
        try:
            model_output = _call_ollama_client(model, prompt)
        except Exception:
            model_output = _call_ollama_http(model, prompt)
    except Exception as e:
        # escalate if analysis failed
        return {"verdict": "escalated", "reasons": [f"analysis_failed:{e}"], "raw_model_output": None}

    # Robust JSON extraction: look for 'verdict' key in balanced JSON block, else NDJSON reconstruction
    parsed = None
    try:
        def _find_json_with_key(s: str, key: str) -> Optional[str]:
            i = s.find(f'"{key}"')
            if i == -1:
                return None
            start = s.rfind('{', 0, i)
            if start == -1:
                return None
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
            # scan balanced blocks
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
            # NDJSON-style reconstruction
            reconstructed = []
            for line in model_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict) and 'response' in ev and isinstance(ev['response'], str):
                        reconstructed.append(ev['response'])
                    elif isinstance(ev, dict) and 'text' in ev and isinstance(ev['text'], str):
                        reconstructed.append(ev['text'])
                except Exception:
                    continue
            joined = ''.join(reconstructed)
            cand2 = None
            key_idx = joined.find('"verdict"')
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
                parsed = json.loads(model_output)
    except Exception:
        return {"verdict": "escalated", "reasons": ["model_output_not_json"], "raw_model_output": model_output}

    verdict = parsed.get("verdict", "accepted")
    reasons = parsed.get("reasons", []) or []
    return {"verdict": verdict, "reasons": reasons, "indicators": parsed.get("indicators"), "raw_model_output": model_output}


if __name__ == "__main__":
    import sys
    text = sys.stdin.read() if not sys.stdin.isatty() else ""
    if not text:
        print("Usage: echo 'email body' | python src/analysis.py")
        raise SystemExit(1)
    out = analyze_email_body(text)
    print(json.dumps(out, indent=2))
