"""Sandboxed text extraction via MarkItDown.
WARNING: does NOT detect macros/JS — complementary tool only.
"""
import json
import sys
import os

try:
    from markitdown import MarkItDown

    ext = os.environ.get("FILE_EXT", ".bin")
    # MarkItDown needs a file with proper extension
    src = "/work/input"
    dst = f"/tmp/file{ext}"
    with open(src, "rb") as f_in, open(dst, "wb") as f_out:
        f_out.write(f_in.read())

    md = MarkItDown()
    result = md.convert(dst)
    text = result.text_content if hasattr(result, "text_content") else str(result)

    json.dump({
        "tool": "markitdown",
        "status": "ok",
        "text": text[:10000],
        "text_length": len(text),
    }, sys.stdout)
except Exception as e:
    json.dump({"tool": "markitdown", "status": "error", "error": str(e)}, sys.stdout)
