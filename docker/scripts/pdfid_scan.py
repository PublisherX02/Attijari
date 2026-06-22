"""Sandboxed PDF keyword detection."""
import json
import sys

try:
    from pdfid import pdfid

    result = {"tool": "pdfid", "status": "ok", "keywords": {}, "suspicious": False}
    dangerous = {"/JS", "/JavaScript", "/OpenAction", "/Launch", "/AA",
                 "/RichMedia", "/EmbeddedFile", "/XFA", "/AcroForm"}

    xmldoc = pdfid.PDFiD("/work/input")
    for kw in xmldoc.keywords:
        count = kw.count + kw.hexcodecount
        if count > 0:
            result["keywords"][kw.name] = count
            if kw.name in dangerous:
                result["suspicious"] = True

    json.dump(result, sys.stdout)
except Exception as e:
    json.dump({"tool": "pdfid", "status": "error", "error": str(e)}, sys.stdout)
