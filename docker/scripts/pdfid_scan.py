"""Sandboxed PDF keyword detection."""
import json
import sys

try:
    from pdfid import pdfid

    result = {"tool": "pdfid", "status": "ok", "keywords": {}, "suspicious": False}
    dangerous = {"/JS", "/JavaScript", "/OpenAction", "/Launch", "/AA",
                 "/RichMedia", "/EmbeddedFile", "/XFA", "/AcroForm"}

    # PDFiD() returns an xml.dom.minidom.Document, not an object with a
    # .keywords attribute (confirmed 2026-08-05 against the installed
    # pdfid==0.2.7 package). Each <Keyword Name="..." Count="..."
    # HexcodeCount="..."/> element is one row.
    xmldoc = pdfid.PDFiD("/work/input")
    for kw in xmldoc.getElementsByTagName("Keyword"):
        name = kw.getAttribute("Name")
        count = int(kw.getAttribute("Count") or 0) + int(kw.getAttribute("HexcodeCount") or 0)
        if count > 0:
            result["keywords"][name] = count
            if name in dangerous:
                result["suspicious"] = True

    json.dump(result, sys.stdout)
except Exception as e:
    json.dump({"tool": "pdfid", "status": "error", "error": str(e)}, sys.stdout)
