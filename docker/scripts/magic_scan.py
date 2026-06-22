"""Sandboxed magic-byte file type detection."""
import json
import sys

try:
    import magic
    content = open("/work/input", "rb").read()
    mime = magic.from_buffer(content, mime=True)
    desc = magic.from_buffer(content)
    json.dump({"tool": "magic", "status": "ok", "mime": mime, "description": desc}, sys.stdout)
except Exception as e:
    json.dump({"tool": "magic", "status": "error", "error": str(e)}, sys.stdout)
