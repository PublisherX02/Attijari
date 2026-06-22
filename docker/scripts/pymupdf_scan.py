"""Sandboxed PDF text + structure extraction."""
import json
import sys

try:
    import fitz

    doc = fitz.open("/work/input")
    text_parts = []
    links = []
    for page in doc:
        text_parts.append(page.get_text())
        for link in page.get_links():
            uri = link.get("uri")
            if uri:
                links.append(uri)
    doc.close()

    full_text = "\n".join(text_parts)
    json.dump({
        "tool": "pymupdf",
        "status": "ok",
        "page_count": doc.page_count if hasattr(doc, 'page_count') else len(text_parts),
        "text": full_text[:10000],
        "links": links[:100],
        "text_length": len(full_text),
    }, sys.stdout)
except Exception as e:
    json.dump({"tool": "pymupdf", "status": "error", "error": str(e)}, sys.stdout)
