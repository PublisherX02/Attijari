"""test_extraction_local_pdfid.py — regression test for a real bug found
2026-08-05: _local_pdfid assumed pdfid.PDFiD() returns an object with a
.keywords attribute (an older/different pdfid API). The installed
pdfid==0.2.7 package's PDFiD() actually returns an xml.dom.minidom.Document
(confirmed via doc.toxml()), so every real call raised
AttributeError: 'Document' object has no attribute 'keywords' -- silently
caught by _local_pdfid's except clause and reported as status="error",
which then escalated every PDF attachment via the SANDBOX_REQUIRED_TOOLS
hard-crash fail-safe (extraction.py section 7d), regardless of actual PDF
content. Never caught before because EXTRACTION_ALLOW_UNSANDBOXED was never
enabled in this environment until 2026-08-05, so _local_pdfid had never
actually run against a real file outside a mock."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction

# A syntactically valid, minimal PDF (real xref table) with no dangerous
# keywords -- pdfid should parse this cleanly and report suspicious=False.
_BENIGN_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
    b"xref\n0 4\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"0000000115 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\n"
    b"startxref\n178\n%%EOF"
)


def test_local_pdfid_parses_benign_pdf_without_error():
    if not extraction._HAS_PDFID:
        return  # pdfid not installed in this environment -- nothing to regress
    res = extraction._local_pdfid(_BENIGN_PDF)
    assert res["status"] == "ok", res
    assert res["suspicious"] is False


def test_local_pdfid_flags_dangerous_keyword():
    if not extraction._HAS_PDFID:
        return
    malicious_pdf = _BENIGN_PDF.replace(b"/Type/Catalog", b"/Type/Catalog/OpenAction 5 0 R/JS")
    res = extraction._local_pdfid(malicious_pdf)
    assert res["status"] == "ok", res
    assert res["suspicious"] is True
