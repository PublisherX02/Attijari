"""extraction.py — Stage 3: Isolated Security Extraction

Architecture: SANDBOX-FIRST with local fallback
  1. If Docker is available and images are built → run each tool in its own
     isolated container (no network, no privileges, capped CPU/RAM/PIDs)
  2. If Docker is unavailable → fall back to direct local execution
  3. Tesseract always runs locally when installed (user has it on host)

Tools per container:
  - magic        : real file type via magic bytes
  - oletools     : VBA macros, OLE objects (Office files)
  - pdfid        : suspicious PDF keywords (/JS, /OpenAction, /Launch)
  - pymupdf      : PDF text + structure extraction
  - tesseract    : OCR text from images (local — installed on host)
  - yara         : pattern-based malware signatures
  - ioc_finder   : IOC extraction (IPs, domains, URLs, hashes)
  - markitdown   : readable text extraction (complementary only)

Container security (enforced by sandbox.py):
  --network=none, --read-only, --cap-drop=ALL, --no-new-privileges,
  --cpus=0.5, --memory=256m, --pids-limit=50, --tmpfs /tmp:noexec:50m

CRITICAL DESIGN RULES (from CLAUDE.md):
  - MarkItDown alone is NEVER sufficient — always run oletools/pdfid too
  - Declared file type lies — python-magic verifies via magic bytes
  - File names are hostile — only internal IDs used as paths
  - Encrypted attachment + password in body = automatic escalate
  - Any extraction failure = escalate, never accept
"""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any

from sandbox import run_tool as _sandbox_run, check_sandbox_status

# ---------- safe base paths ----------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
YARA_RULES_DIR = _PROJECT_ROOT / "data" / "yara_rules"
EXTRACTION_TIMEOUT = 60  # seconds per attachment

# ---------- SEC-H1: mandatory isolation for complex-format parsers ----------
# These tools parse attacker-controlled complex/active content (Office VBA,
# PDF objects, arbitrary MarkItDown formats) where a parser exploit runs with
# our privileges. They MUST run inside the sandbox container. If the sandbox
# is unavailable, we escalate the attachment (fail-safe) rather than parse it
# unsandboxed on the host — the same rule the pipeline applies to timeouts and
# crashes (CLAUDE.md: the extraction environment must be isolated).
#
# magic / yara / tesseract / ioc_finder are intentionally NOT here: they are
# byte-level type sniffing, pattern matching, OCR, and text regexing — a far
# smaller parser-exploit surface — and tesseract is host-local by design.
SANDBOX_REQUIRED_TOOLS = {"oletools", "pdfid", "pymupdf", "markitdown", "onenote"}

# Escape hatch for local dev ONLY: set EXTRACTION_ALLOW_UNSANDBOXED=1 to permit
# the old behaviour of running the parsers above locally when Docker is down.
# Default is secure (fail-safe). Never enable this where real mail is processed.
def _allow_unsandboxed() -> bool:
    return os.getenv("EXTRACTION_ALLOW_UNSANDBOXED", "0") == "1"

# ---------- Check sandbox status once at import ----------
_sandbox_status = None

def _get_sandbox():
    global _sandbox_status
    if _sandbox_status is None:
        _sandbox_status = check_sandbox_status()
        if _sandbox_status["docker_available"]:
            built = [t for t, ok in _sandbox_status["images"].items() if ok]
            missing = [t for t, ok in _sandbox_status["images"].items() if not ok]
            print(f"[SANDBOX] Docker OK — images built: {', '.join(built) or 'none'}")
            if missing:
                print(f"[SANDBOX] Images NOT built (will use local fallback): {', '.join(missing)}")
        else:
            print("[SANDBOX] Docker unavailable — all tools run locally")
    return _sandbox_status


def _can_sandbox(tool: str) -> bool:
    """Check if a tool can run in sandbox mode."""
    s = _get_sandbox()
    return s["docker_available"] and s["images"].get(tool, False)


# ---------- local fallback imports (each independently optional) ----------
try:
    import magic
    _HAS_MAGIC = True
except ImportError:
    _HAS_MAGIC = False

try:
    from oletools.olevba import VBA_Parser
    from oletools import oleid
    _HAS_OLETOOLS = True
except ImportError:
    _HAS_OLETOOLS = False

try:
    from pdfid import pdfid as _pdfid_module
    _HAS_PDFID = True
except ImportError:
    _HAS_PDFID = False

try:
    import fitz  # PyMuPDF
    _HAS_PYMUPDF = True
except ImportError:
    _HAS_PYMUPDF = False

try:
    import pytesseract
    from PIL import Image
    import io as _io
    _HAS_TESSERACT = True
except ImportError:
    _HAS_TESSERACT = False

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

try:
    import olefile
    _HAS_OLEFILE = True
except ImportError:
    _HAS_OLEFILE = False

try:
    from ioc_finder import ioc_finder
    _HAS_IOC_FINDER = True
except ImportError:
    _HAS_IOC_FINDER = False

try:
    from markitdown import MarkItDown
    _HAS_MARKITDOWN = True
except ImportError:
    _HAS_MARKITDOWN = False


def _available_tools() -> dict[str, str]:
    """Returns tool → mode: 'sandbox', 'local', or 'unavailable'."""
    tools = {}
    local_map = {
        "magic": _HAS_MAGIC, "oletools": _HAS_OLETOOLS,
        "pdfid": _HAS_PDFID, "pymupdf": _HAS_PYMUPDF,
        "tesseract": _HAS_TESSERACT, "yara": _HAS_YARA,
        "ioc_finder": _HAS_IOC_FINDER, "markitdown": _HAS_MARKITDOWN,
    }
    for name, has_local in local_map.items():
        if _can_sandbox(name):
            tools[name] = "sandbox"
        elif has_local:
            tools[name] = "local"
        else:
            tools[name] = "unavailable"
    return tools


# =====================================================================
# Local fallback tool functions (used when Docker is unavailable)
# =====================================================================

def _local_detect_type(content: bytes) -> dict:
    if not _HAS_MAGIC:
        return {"tool": "magic", "status": "unavailable"}
    try:
        mime = magic.from_buffer(content, mime=True)
        desc = magic.from_buffer(content)
        return {"tool": "magic", "status": "ok", "mime": mime, "description": desc}
    except Exception as e:
        return {"tool": "magic", "status": "error", "error": str(e)}


def _local_oletools(content: bytes, filename: str) -> dict:
    if not _HAS_OLETOOLS:
        return {"tool": "oletools", "status": "unavailable"}
    try:
        result = {"tool": "oletools", "status": "ok", "macros": [], "ole_indicators": [], "suspicious": False}
        try:
            oid = oleid.OleID(data=content)
            for ind in oid.check():
                entry = {"name": ind.name, "value": str(ind.value)}
                if hasattr(ind, "risk"):
                    entry["risk"] = str(ind.risk)
                    if str(ind.risk).lower() in ("high", "medium"):
                        result["suspicious"] = True
                result["ole_indicators"].append(entry)
        except Exception as e:
            result["ole_indicators"].append({"error": str(e)})
        try:
            vba = VBA_Parser(filename, data=content)
            if vba.detect_vba_macros():
                result["suspicious"] = True
                for vba_type, stream, sub, code in vba.extract_macros():
                    result["macros"].append({
                        "type": str(vba_type), "stream": str(stream),
                        "name": str(sub), "code_preview": (code[:500] if code else ""),
                    })
            vba.close()
        except Exception as e:
            result["macros"].append({"error": str(e)})
        return result
    except Exception as e:
        return {"tool": "oletools", "status": "error", "error": str(e)}


def _local_pdfid(content: bytes) -> dict:
    if not _HAS_PDFID:
        return {"tool": "pdfid", "status": "unavailable"}
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            result = {"tool": "pdfid", "status": "ok", "keywords": {}, "suspicious": False}
            dangerous = {"/JS", "/JavaScript", "/OpenAction", "/Launch", "/AA",
                         "/RichMedia", "/EmbeddedFile", "/XFA", "/AcroForm"}
            xmldoc = _pdfid_module.PDFiD(tmp_path)
            for kw in xmldoc.keywords:
                count = kw.count + kw.hexcodecount
                if count > 0:
                    result["keywords"][kw.name] = count
                    if kw.name in dangerous:
                        result["suspicious"] = True
            return result
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        return {"tool": "pdfid", "status": "error", "error": str(e)}


def _local_pymupdf(content: bytes) -> dict:
    if not _HAS_PYMUPDF:
        return {"tool": "pymupdf", "status": "unavailable"}
    try:
        doc = fitz.open(stream=content, filetype="pdf")
        text_parts, links = [], []
        page_count = doc.page_count
        for page in doc:
            text_parts.append(page.get_text())
            for link in page.get_links():
                uri = link.get("uri")
                if uri:
                    links.append(uri)
        doc.close()
        full_text = "\n".join(text_parts)
        return {"tool": "pymupdf", "status": "ok", "page_count": page_count,
                "text": full_text[:10000], "links": links[:100], "text_length": len(full_text)}
    except Exception as e:
        return {"tool": "pymupdf", "status": "error", "error": str(e)}


def _local_tesseract(content: bytes) -> dict:
    """Tesseract OCR — always runs locally (installed on host)."""
    if not _HAS_TESSERACT:
        return {"tool": "tesseract", "status": "unavailable"}
    try:
        img = Image.open(_io.BytesIO(content))
        text = pytesseract.image_to_string(img, lang="fra+eng+ara")
        return {"tool": "tesseract", "status": "ok", "text": text[:5000], "text_length": len(text)}
    except Exception as e:
        return {"tool": "tesseract", "status": "error", "error": str(e)}


_yara_compiled_cache: dict | None = None


def _get_compiled_yara_rulesets() -> dict:
    """Compile each rule file once and cache for the process lifetime.
    Per-file (not combined) so one broken rule file doesn't prevent the
    others from matching — same isolation the old per-scan-compile loop had,
    just cached instead of recompiled on every single attachment."""
    global _yara_compiled_cache
    if _yara_compiled_cache is None:
        _yara_compiled_cache = {}
        rule_files = list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))
        for rf in rule_files:
            try:
                _yara_compiled_cache[rf.name] = yara.compile(filepath=str(rf))
            except Exception as e:
                _yara_compiled_cache[rf.name] = e
    return _yara_compiled_cache


def _local_yara(content: bytes) -> dict:
    if not _HAS_YARA:
        return {"tool": "yara", "status": "unavailable"}
    try:
        rulesets = _get_compiled_yara_rulesets()
        if not rulesets:
            return {"tool": "yara", "status": "ok", "matches": [], "suspicious": False}
        all_matches = []
        for rf_name, compiled in rulesets.items():
            if isinstance(compiled, Exception):
                all_matches.append({"error": f"{rf_name}: {compiled}"})
                continue
            try:
                for m in compiled.match(data=content):
                    all_matches.append({"rule": m.rule, "meta": m.meta, "tags": m.tags, "rule_file": rf_name})
            except Exception as e:
                all_matches.append({"error": f"{rf_name}: {e}"})
        return {"tool": "yara", "status": "ok", "matches": all_matches,
                "suspicious": any("rule" in m for m in all_matches)}
    except Exception as e:
        return {"tool": "yara", "status": "error", "error": str(e)}


def _local_iocs(text: str) -> dict:
    if not _HAS_IOC_FINDER:
        return {"tool": "ioc_finder", "status": "unavailable"}
    if not text or not text.strip():
        return {"tool": "ioc_finder", "status": "ok", "iocs": {}}
    try:
        iocs = ioc_finder.parse_iocs(text)
        filtered = {}
        for key in ("ipv4s", "ipv6s", "domains", "urls", "email_addresses",
                     "md5s", "sha256s", "sha1s", "bitcoin_addresses"):
            vals = iocs.get(key, [])
            if vals:
                filtered[key] = vals[:50]
        return {"tool": "ioc_finder", "status": "ok", "iocs": filtered}
    except Exception as e:
        return {"tool": "ioc_finder", "status": "error", "error": str(e)}


def _local_markitdown(content: bytes, filename: str) -> dict:
    if not _HAS_MARKITDOWN:
        return {"tool": "markitdown", "status": "unavailable"}
    try:
        with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1] or ".bin", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            md = MarkItDown()
            result = md.convert(tmp_path)
            text = result.text_content if hasattr(result, "text_content") else str(result)
            return {"tool": "markitdown", "status": "ok", "text": text[:10000], "text_length": len(text)}
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        return {"tool": "markitdown", "status": "error", "error": str(e)}


# =====================================================================
# Unified tool dispatcher: sandbox first, local fallback
# =====================================================================

def _sandbox_required_failsafe(tool_name: str, why: str) -> dict:
    """SEC-H1 fail-safe result for a tool that MUST be sandboxed but can't be.

    Never parses the file locally. Marked suspicious+escalate so the attachment
    is routed to a human instead of silently passing without isolated analysis.
    """
    print(f"[EXTRACTION] {tool_name} requires the sandbox but it is unavailable "
          f"({why}) — escalating, NOT parsing unsandboxed (SEC-H1 fail-safe)")
    return {
        "tool": tool_name,
        "status": "error",
        "error": f"sandbox_required_but_unavailable:{why}",
        "sandbox_required_unavailable": True,
        "suspicious": True,
        "escalate": True,
        "sandboxed": False,
    }


def _run_tool(tool_name: str, content: bytes, stored_path: str,
              filename: str = "file.bin") -> dict:
    """Run a tool via sandbox if available, else local fallback.

    For SANDBOX_REQUIRED_TOOLS, "no sandbox" means escalate, never local —
    unless EXTRACTION_ALLOW_UNSANDBOXED=1 (dev only).
    """
    requires_sandbox = tool_name in SANDBOX_REQUIRED_TOOLS and not _allow_unsandboxed()

    # Try sandbox first
    if _can_sandbox(tool_name):
        env = {}
        if tool_name == "oletools":
            env["ORIGINAL_NAME"] = filename
        if tool_name == "markitdown":
            _, ext = os.path.splitext(filename)
            env["FILE_EXT"] = ext or ".bin"

        result = _sandbox_run(tool_name, stored_path, env=env)

        # If sandbox succeeded, return result
        if result.get("status") != "error" or not result.get("fallback"):
            return result
        # Sandbox failed with fallback flag. For isolation-required tools we do
        # NOT drop to unsandboxed local parsing — escalate instead (SEC-H1).
        if requires_sandbox:
            return _sandbox_required_failsafe(tool_name, "sandbox_run_failed")
        print(f"[EXTRACTION] Sandbox failed for {tool_name}, falling back to local")
    elif requires_sandbox:
        # Sandbox not available at all and this tool must be isolated.
        return _sandbox_required_failsafe(tool_name, "sandbox_unavailable")

    # Local fallback (only non-required tools, or EXTRACTION_ALLOW_UNSANDBOXED=1)
    if tool_name == "magic":
        return _local_detect_type(content)
    elif tool_name == "oletools":
        return _local_oletools(content, filename)
    elif tool_name == "pdfid":
        return _local_pdfid(content)
    elif tool_name == "pymupdf":
        return _local_pymupdf(content)
    elif tool_name == "yara":
        return _local_yara(content)
    elif tool_name == "ioc_finder":
        # ioc_finder gets text, not bytes — handled specially in orchestrator
        return {"tool": "ioc_finder", "status": "unavailable", "note": "use _run_ioc_text"}
    elif tool_name == "markitdown":
        return _local_markitdown(content, filename)
    elif tool_name == "tesseract":
        return _local_tesseract(content)
    else:
        return {"tool": tool_name, "status": "unavailable"}


def _run_ioc_text(text: str, stored_path: str | None = None) -> dict:
    """Run IOC extraction on text (not binary)."""
    if _can_sandbox("ioc_finder") and stored_path:
        # Write text to temp file for sandbox
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        try:
            result = _sandbox_run("ioc_finder", tmp_path)
            if result.get("status") != "error" or not result.get("fallback"):
                return result
        finally:
            os.unlink(tmp_path)
    return _local_iocs(text)


# =====================================================================
# MIME dispatch tables
# =====================================================================

_OFFICE_MIMES = {
    "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
}
_RTF_MIMES = {"text/rtf", "application/rtf"}
_PDF_MIMES = {"application/pdf"}
_IMAGE_MIMES = {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/tiff", "image/webp"}
_ARCHIVE_MIMES = {"application/zip", "application/x-rar-compressed", "application/x-7z-compressed",
                   "application/gzip", "application/x-tar"}
_ONENOTE_MIMES = {"application/onenote", "application/msonenote"}


# =====================================================================
# PDF URL phishing detection helper
# =====================================================================

def _check_pdf_urls_for_phishing(urls: list[str]) -> list[str]:
    """Check extracted PDF URLs for phishing patterns."""
    from urllib.parse import urlparse
    flags = []
    # Bank domain patterns for typosquat detection
    _BANK_KEYWORDS = ("attijari", "attijar", "wafabank", "wafa")
    # Phishing path keywords
    _PHISH_PATHS = ("login", "verify", "confirm", "secure", "account", "auth",
                    "signin", "session", "credential", "password", "update")
    # Suspicious TLDs / test domains
    _EVIL_SUFFIXES = (".evil.test", ".evil.com", ".test", ".tk", ".ml", ".ga", ".cf")

    for url in urls[:50]:  # cap
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            # 1. Typosquat of bank domain
            if any(kw in host for kw in _BANK_KEYWORDS) and "attijaribank.com.tn" not in host:
                flags.append(f"pdf_phishing_url: typosquat of bank domain in {host}")
            # 2. Login/verify path on non-bank domain
            if any(p in path for p in _PHISH_PATHS) and "attijaribank.com.tn" not in host:
                if not any(legit in host for legit in (
                    "google.com", "microsoft.com", "linkedin.com", "github.com",
                    "apple.com", "adobe.com", "sharepoint.com")):
                    flags.append(f"pdf_phishing_url: suspicious login path in {url[:120]}")
            # 3. Known evil/test TLDs
            if any(host.endswith(s) for s in _EVIL_SUFFIXES):
                flags.append(f"pdf_phishing_url: evil/test domain {host}")
        except Exception:
            continue
    return flags


def _detect_encryption(content: bytes, filename: str) -> dict:
    """Structurally detect whether a ZIP-based or OOXML/OLE attachment is
    password-protected, replacing the old MIME/extension-only guess.

    RAR/7z are not structurally verified here (no parser library in
    requirements.txt) — callers should still combine this with the
    extension/MIME heuristic for those formats, same as before.
    """
    fname_lower = filename.lower()

    if fname_lower.endswith((".zip", ".docx", ".xlsx", ".pptx", ".docm",
                              ".xlsm", ".pptm", ".ppsx", ".ppsm")):
        try:
            import zipfile as _zf
            import io as _io
            buf = _io.BytesIO(content)
            if _zf.is_zipfile(buf):
                buf.seek(0)
                with _zf.ZipFile(buf, "r") as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            return {"encrypted": True, "method": "zip_encryption_flag"}
        except Exception:
            pass

    if _HAS_OLEFILE and fname_lower.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                                               ".docm", ".xlsm", ".pptm", ".ppsx", ".ppsm")):
        try:
            import io as _io
            buf = _io.BytesIO(content)
            if olefile.isOleFile(buf):
                buf.seek(0)
                ole = olefile.OleFileIO(buf)
                try:
                    if ole.exists("EncryptedPackage") or ole.exists("EncryptionInfo"):
                        return {"encrypted": True, "method": "ooxml_encrypted_package"}
                finally:
                    ole.close()
        except Exception:
            pass

    return {"encrypted": False, "method": None}


def _check_image_stego_metadata(content: bytes, filename: str) -> list[str]:
    """Check image metadata for steganography tool signatures."""
    flags = []
    # Very rudimentary check on raw bytes for stego signatures (often left in tEXt/EXIF chunks)
    stego_keywords = (
        b"SteganoEncoder", b"steghide", b"OpenStego", 
        b"Stegosuite", b"SilentEye", b"payload embedded"
    )
    # Check first 8KB (headers/metadata)
    chunk = content[:8192].lower()
    for kw in stego_keywords:
        if kw.lower() in chunk:
            flags.append(f"image_stego_metadata: signature '{kw.decode(errors='ignore')}' found")
    return flags


# =====================================================================
# Main extraction orchestrator
# =====================================================================

def extract_attachment(attachment: dict, body_text: str | None = None) -> dict:
    """Run all applicable security tools on a single attachment.

    Sandbox-first: each tool runs in its own Docker container when available.
    Falls back to local execution when Docker/images are unavailable.
    """
    t0 = time.time()
    stored_path = attachment.get("stored_path")
    filename = attachment.get("original_name", "unnamed")
    declared_type = attachment.get("declared_type", "unknown")
    real_type = attachment.get("real_type")
    type_mismatch = attachment.get("type_mismatch", False)
    sha256 = attachment.get("sha256", "")

    result = {
        "sha256": sha256,
        "filename": filename,
        "declared_type": declared_type,
        "real_type": real_type,
        "type_mismatch": type_mismatch,
        "tools_run": [],
        "flags": [],
        "extracted_text": "",
        "iocs": {},
        "suspicious": False,
        "escalate": False,
    }

    # Read content
    try:
        content = Path(stored_path).read_bytes()
    except Exception as e:
        result["flags"].append(f"cannot_read_file: {e}")
        result["escalate"] = True
        return result

    effective_mime = real_type or declared_type

    # If magic wasn't run at ingestion, run it now
    if not real_type:
        magic_result = _run_tool("magic", content, stored_path, filename)
        result["tools_run"].append(magic_result)
        if magic_result.get("status") == "ok":
            effective_mime = magic_result["mime"]
            result["real_type"] = effective_mime
            if declared_type not in ("unknown", "application/octet-stream") and effective_mime != declared_type:
                result["type_mismatch"] = True
                result["flags"].append(f"type_mismatch: declared={declared_type} real={effective_mime}")

    if type_mismatch:
        result["flags"].append(f"type_mismatch: declared={declared_type} real={real_type}")

    text_parts = []

    # 1. YARA — always runs
    yara_result = _run_tool("yara", content, stored_path, filename)
    result["tools_run"].append(yara_result)
    if yara_result.get("suspicious"):
        result["suspicious"] = True
        result["escalate"] = True
        matches = [m.get("rule", "?") for m in yara_result.get("matches", []) if "rule" in m]
        result["flags"].append(f"yara_match: {', '.join(matches)}")

    # 1b. Archive bomb detection — nested ZIPs and high compression ratios
    # ZIP bombs overwhelm extraction with decompression work. The test corpus
    # zip bomb is too small to hit the 60s timeout, so detect structurally.
    if effective_mime in _ARCHIVE_MIMES or filename.lower().endswith((".zip", ".rar", ".7z", ".gz")):
        try:
            import zipfile as _zf
            import io as _io
            zf_buf = _io.BytesIO(content)
            if _zf.is_zipfile(zf_buf):
                zf_buf.seek(0)
                with _zf.ZipFile(zf_buf, "r") as zf:
                    # Check compression ratio (decompressed / compressed)
                    total_compressed = sum(i.compress_size for i in zf.infolist() if i.compress_size > 0)
                    total_decompressed = sum(i.file_size for i in zf.infolist())
                    ratio = total_decompressed / total_compressed if total_compressed > 0 else 0

                    # Check nesting: any member is itself a ZIP?
                    nesting_depth = 0
                    for member in zf.infolist():
                        if member.file_size > 0:
                            try:
                                inner = zf.read(member.filename)
                                inner_buf = _io.BytesIO(inner)
                                if _zf.is_zipfile(inner_buf):
                                    nesting_depth += 1
                                    # Check second level
                                    inner_buf.seek(0)
                                    with _zf.ZipFile(inner_buf, "r") as zf2:
                                        for m2 in zf2.infolist():
                                            try:
                                                inner2 = zf2.read(m2.filename)
                                                if _zf.is_zipfile(_io.BytesIO(inner2)):
                                                    nesting_depth += 1
                                                    break
                                            except Exception:
                                                pass
                                    break  # found nested ZIP, stop scanning
                            except Exception:
                                pass

                    # Check for dangerous file extensions inside the archive
                    _DANGEROUS_EXTS = (".js", ".vbs", ".exe", ".scr", ".bat",
                                       ".ps1", ".hta", ".cmd", ".com", ".msi",
                                       ".jar", ".wsf", ".lnk")
                    dangerous_files = [
                        m.filename for m in zf.infolist()
                        if any(m.filename.lower().endswith(ext) for ext in _DANGEROUS_EXTS)
                    ]

                    if nesting_depth >= 1 or ratio > 50:
                        result["suspicious"] = True
                        result["escalate"] = True
                        result["flags"].append(
                            f"archive_bomb_suspected: nesting_depth={nesting_depth} "
                            f"compression_ratio={ratio:.0f}x — possible zip bomb"
                        )
                    if dangerous_files:
                        result["suspicious"] = True
                        result["escalate"] = True
                        names = ", ".join(dangerous_files[:5])
                        result["flags"].append(
                            f"archive_dangerous_content: executable file(s) inside archive: {names}"
                        )
        except Exception:
            pass  # archive check is best-effort

    # 2. Office files + RTF — oletools
    if effective_mime in _OFFICE_MIMES or effective_mime in _RTF_MIMES or filename.lower().endswith(
            (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pptm",
             ".ppsx", ".ppsm", ".docm", ".xlsm", ".rtf")):
        ole_result = _run_tool("oletools", content, stored_path, filename)
        result["tools_run"].append(ole_result)
        if ole_result.get("suspicious"):
            result["suspicious"] = True
            result["escalate"] = True
            result["flags"].append("oletools_suspicious: macros or OLE indicators detected")
            for macro in ole_result.get("macros", []):
                if macro.get("code_preview"):
                    text_parts.append(macro["code_preview"])

    # 2b. OOXML DDE detection — oletools catches VBA but NOT DDE fields.
    # DDE (Dynamic Data Exchange) executes commands without macro warnings.
    # Scan ZIP-based OOXML for DDEAUTO/DDE instrText fields.
    if filename.lower().endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
        try:
            import zipfile as _zf
            import io as _io
            zf_buf = _io.BytesIO(content)
            if _zf.is_zipfile(zf_buf):
                zf_buf.seek(0)
                with _zf.ZipFile(zf_buf, "r") as zf:
                    _DDE_PATTERNS = (b"DDEAUTO", b"DDE ", b"instrText", b"fldChar")
                    _DDE_DANGEROUS = (b"cmd", b"powershell", b"mshta", b"wscript",
                                      b"cscript", b"certutil", b"bitsadmin",
                                      b"rundll32", b"regsvr32", b"msiexec",
                                      b"forfiles", b"pcalua", b"mshtml")
                    for name in zf.namelist():
                        if name.endswith(".xml") or name.endswith(".rels"):
                            try:
                                xml_content = zf.read(name)
                                has_dde = any(p in xml_content for p in _DDE_PATTERNS)
                                has_dangerous = any(p in xml_content.lower() for p in _DDE_DANGEROUS)
                                if has_dde and has_dangerous:
                                    result["suspicious"] = True
                                    result["escalate"] = True
                                    result["flags"].append(
                                        f"dde_field_detected: DDE command execution in {name} "
                                        f"— no macro warning shown to user"
                                    )
                                    break
                            except Exception:
                                pass
        except Exception:
            pass  # DDE check is best-effort; other tools still run

    # 2c. OneNote (.one) — no mature open-source parser exists; treat as
    # requiring isolated analysis we can't provide, matching the
    # SANDBOX_REQUIRED_TOOLS fail-safe pattern (escalate rather than pass
    # through unexamined). A major 2024-2025 initial-access vector
    # (embedded .vbs/.hta/.exe behind a fake "click to view" button).
    if effective_mime in _ONENOTE_MIMES or filename.lower().endswith(".one"):
        one_result = _run_tool("onenote", content, stored_path, filename)
        result["tools_run"].append(one_result)
        # _run_tool always returns sandbox_required_unavailable=True here
        # (no "onenote" Docker image is ever built) — the SEC-H1 loop
        # below picks this up and escalates automatically.

    # 3. PDF — pdfid + pymupdf
    if effective_mime in _PDF_MIMES or filename.lower().endswith(".pdf"):
        pid_result = _run_tool("pdfid", content, stored_path, filename)
        result["tools_run"].append(pid_result)
        if pid_result.get("suspicious"):
            result["suspicious"] = True
            result["escalate"] = True
            bad_keys = [k for k, v in pid_result.get("keywords", {}).items()
                        if k in {"/JS", "/JavaScript", "/OpenAction", "/Launch", "/AA"} and v > 0]
            result["flags"].append(f"pdfid_suspicious: {', '.join(bad_keys)}")

        pdf_result = _run_tool("pymupdf", content, stored_path, filename)
        result["tools_run"].append(pdf_result)
        if pdf_result.get("text"):
            text_parts.append(pdf_result["text"])
        if pdf_result.get("links"):
            result["flags"].append(f"pdf_links_found: {len(pdf_result['links'])}")
            # Check PDF URLs for phishing patterns
            phish_flags = _check_pdf_urls_for_phishing(pdf_result["links"])
            if phish_flags:
                result["suspicious"] = True
                result["escalate"] = True
                for pf in phish_flags:
                    result["flags"].append(pf)

    # 4. Images — Tesseract OCR (always local — host has Tesseract v5.5)
    if effective_mime in _IMAGE_MIMES or filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp")):
        ocr_result = _run_tool("tesseract", content, stored_path, filename)
        result["tools_run"].append(ocr_result)
        if ocr_result.get("text"):
            text_parts.append(ocr_result["text"])
        
        # Check image metadata for stego signatures
        stego_flags = _check_image_stego_metadata(content, filename)
        if stego_flags:
            result["suspicious"] = True
            result["escalate"] = True
            for flag in stego_flags:
                result["flags"].append(flag)

    # 5. MarkItDown — text extraction (complementary, NEVER standalone)
    if (effective_mime not in _IMAGE_MIMES and effective_mime not in _ARCHIVE_MIMES
            and effective_mime not in _ONENOTE_MIMES and not filename.lower().endswith(".one")):
        md_result = _run_tool("markitdown", content, stored_path, filename)
        result["tools_run"].append(md_result)
        if md_result.get("text"):
            text_parts.append(md_result["text"])

    # 6. Combine extracted text
    all_text = "\n".join(text_parts)
    result["extracted_text"] = all_text[:15000]

    # 7. IOC extraction on combined text
    if all_text.strip():
        ioc_result = _run_ioc_text(all_text, stored_path)
        result["tools_run"].append(ioc_result)
        result["iocs"] = ioc_result.get("iocs", {})
        if ioc_result.get("iocs"):
            total_iocs = sum(len(v) for v in ioc_result["iocs"].values())
            if total_iocs > 0:
                result["flags"].append(f"iocs_extracted: {total_iocs} indicators found")

    # 7a. SEC-H1 fail-safe propagation — any isolation-required tool that could
    # not run sandboxed escalates the whole attachment, regardless of which
    # call site consumed its result (pymupdf/markitdown don't check suspicious).
    for _tr in result["tools_run"]:
        if _tr.get("sandbox_required_unavailable"):
            result["suspicious"] = True
            result["escalate"] = True
            _flag = (f"sandbox_unavailable_for_{_tr.get('tool')}: file needs isolated "
                     f"analysis but no container was available — escalating (never parsed unsandboxed)")
            if _flag not in result["flags"]:
                result["flags"].append(_flag)

    # 7c. Sandboxed-tool timeout fail-safe — a container timeout for a
    # SANDBOX_REQUIRED_TOOLS tool must escalate (CLAUDE.md: "Crash or
    # timeout -> escalate, never accept"), same principle as the SEC-H1
    # loop above. sandbox.py's TimeoutExpired handler doesn't set
    # fallback=True, so _run_tool()'s escalate-on-required-tool-failure
    # branch doesn't reliably trigger for a timeout — this loop closes
    # that gap independently of which call site consumed the tool's result.
    for _tr in result["tools_run"]:
        _tr_tool = _tr.get("tool")
        _tr_err = _tr.get("error", "")
        if (_tr_tool in SANDBOX_REQUIRED_TOOLS and isinstance(_tr_err, str)
                and _tr_err.startswith("timeout_killed_after_")):
            result["suspicious"] = True
            result["escalate"] = True
            _flag = f"sandbox_timeout_for_{_tr_tool}: container exceeded time limit — escalating (fail-safe)"
            if _flag not in result["flags"]:
                result["flags"].append(_flag)

    # 7b. DETONATION CANDIDATE (Stage 3.5) — DEFERRED, not run inline.
    # Detonation is memory-gated and runs later in a drained window (see
    # detonation.py). Here we only MARK a file as a candidate when static
    # analysis was inconclusive (not escalated) but the file type is detonable.
    # main.py decides whether to actually enqueue it, combining this marker
    # with the LLM's confidence.
    result["detonation_candidate"] = False
    if not result["escalate"] and stored_path:
        try:
            from detonation import should_detonate
            if should_detonate(filename):
                result["detonation_candidate"] = True
        except ImportError:
            pass

    # 8. CRITICAL: encrypted attachment + password in body = auto escalate
    encryption_check = _detect_encryption(content, filename)
    if encryption_check["encrypted"]:
        result["flags"].append(f"attachment_encrypted: {encryption_check['method']}")
    if body_text:
        body_lower = body_text.lower()
        password_hints = ["password", "mot de passe", "mdp", "pwd", "pass:"]
        has_pw = any(hint in body_lower for hint in password_hints)
        is_encrypted = (encryption_check["encrypted"] or effective_mime in _ARCHIVE_MIMES or
                        filename.lower().endswith((".zip", ".rar", ".7z", ".enc")))
        if has_pw and is_encrypted:
            result["suspicious"] = True
            result["escalate"] = True
            result["flags"].append("encrypted_with_password_in_body: automatic escalation per security policy")

    elapsed = time.time() - t0
    result["extraction_time_s"] = round(elapsed, 2)
    if elapsed > EXTRACTION_TIMEOUT:
        result["flags"].append(f"extraction_timeout: {elapsed:.1f}s > {EXTRACTION_TIMEOUT}s")
        result["escalate"] = True

    return result


def extract_all_attachments(parsed_email: dict) -> dict:
    """Run extraction on all attachments in a parsed email."""
    attachments = parsed_email.get("attachments", [])
    body_text = parsed_email.get("body_text")
    available = _available_tools()

    sandbox_tools = [t for t, m in available.items() if m == "sandbox"]
    local_tools = [t for t, m in available.items() if m == "local"]
    missing_tools = [t for t, m in available.items() if m == "unavailable"]

    if sandbox_tools:
        print(f"[EXTRACTION] Sandboxed: {', '.join(sandbox_tools)}")
    if local_tools:
        print(f"[EXTRACTION] Local fallback: {', '.join(local_tools)}")
    if missing_tools:
        print(f"[EXTRACTION] Unavailable: {', '.join(missing_tools)}")

    if not attachments:
        print("[EXTRACTION] No attachments to analyze")
        return {"results": [], "total_flags": 0, "escalate": False, "tools": available}

    results = []
    total_flags = 0
    any_escalate = False

    for i, att in enumerate(attachments, 1):
        name = att.get("original_name", "unnamed")
        print(f"[EXTRACTION] Analyzing {i}/{len(attachments)}: {name}")

        try:
            ext_result = extract_attachment(att, body_text=body_text)
            results.append(ext_result)

            n_flags = len(ext_result.get("flags", []))
            total_flags += n_flags
            tools_run = [t.get("tool", "?") for t in ext_result.get("tools_run", [])]
            sandboxed = [t.get("tool") for t in ext_result.get("tools_run", []) if t.get("sandboxed")]

            if ext_result.get("escalate"):
                any_escalate = True
                print(f"[EXTRACTION]   ESCALATE: {', '.join(ext_result['flags'])}")
            elif ext_result.get("suspicious"):
                print(f"[EXTRACTION]   SUSPICIOUS: {', '.join(ext_result['flags'])}")
            else:
                print(f"[EXTRACTION]   CLEAN ({n_flags} flag(s))")

            mode = f"sandboxed={len(sandboxed)}/{len(tools_run)}" if sandboxed else "all-local"
            print(f"[EXTRACTION]   Tools: {', '.join(tools_run)} [{mode}] ({ext_result.get('extraction_time_s', 0)}s)")

        except Exception as e:
            error_result = {
                "sha256": att.get("sha256", ""), "filename": name,
                "flags": [f"extraction_crash: {e}"],
                "escalate": True, "suspicious": True, "tools_run": [],
            }
            results.append(error_result)
            any_escalate = True
            total_flags += 1
            print(f"[EXTRACTION]   CRASH: {e} -> ESCALATE (fail-safe)")

    print(f"[EXTRACTION] Done: {len(results)} attachment(s), {total_flags} flag(s), escalate={any_escalate}")

    return {
        "results": results,
        "total_flags": total_flags,
        "escalate": any_escalate,
        "tools": available,
    }
