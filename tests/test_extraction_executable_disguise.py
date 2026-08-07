"""test_extraction_executable_disguise.py — CLAUDE.md rule 7's canonical
example: a genuine executable renamed to look like a document
("invoice.pdf"). The existing `type_mismatch` flag never independently
forced escalation -- it was purely descriptive metadata, relying entirely
on YARA/oletools happening to also catch the same file for an unrelated
reason. Confirmed live with a real PE (T1036.003.exe from atomic-red-team)
renamed to invoice.pdf/resume.docx/vacation_photo.jpg: escalation happened
only via yara_match:suspicious_exe_in_document, never via type_mismatch
itself.

First fix attempt compared real_type against a fixed set of MIME strings
(application/x-dosexec etc.) and still missed real detections: the
sandboxed Docker "magic" tool and the local ingestion-time python-magic
call report the identical PE file as two DIFFERENT MIME strings
(application/vnd.microsoft.portable-executable vs application/x-dosexec)
depending on which libmagic database/wrapper ran. Fixed by checking the
raw content's own magic-byte signature (MZ/ELF/Mach-O) directly instead,
which has no such version-drift problem.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction

# A minimal, syntactically valid PE header (MZ + enough of the DOS stub to
# be unambiguous) -- doesn't need to be a runnable executable, just needs
# to start with the real magic bytes this check keys on.
_MINIMAL_PE = b"MZ" + b"\x90\x00" * 30 + b"\x00" * 400
_MINIMAL_ELF = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 400
_REAL_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"


def _attachment(tmp_path, filename: str, content: bytes) -> dict:
    f = tmp_path / filename
    f.write_bytes(content)
    return {"stored_path": str(f), "original_name": filename,
            "declared_type": "application/octet-stream", "real_type": None,
            "sha256": "a" * 64}


def test_pe_disguised_as_pdf_escalates_via_new_flag(tmp_path):
    att = _attachment(tmp_path, "invoice.pdf", _MINIMAL_PE)
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("executable_disguised_as_document" in fl for fl in res["flags"])


def test_pe_disguised_as_docx_escalates(tmp_path):
    att = _attachment(tmp_path, "resume.docx", _MINIMAL_PE)
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("executable_disguised_as_document" in fl for fl in res["flags"])


def test_elf_disguised_as_jpg_escalates(tmp_path):
    att = _attachment(tmp_path, "vacation_photo.jpg", _MINIMAL_ELF)
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("executable_disguised_as_document" in fl for fl in res["flags"])


def test_real_benign_pdf_not_flagged(tmp_path):
    att = _attachment(tmp_path, "real.pdf", _REAL_PDF)
    res = extraction.extract_attachment(att)
    assert not any("executable_disguised_as_document" in fl for fl in res["flags"])


def test_honestly_named_exe_does_not_double_flag(tmp_path):
    # rules.py's BLOCKED_EXTENSIONS already hard-blocks an honest .exe at
    # the earlier rules-engine stage -- this new check is specifically for
    # the disguise case and should stay quiet when the filename already
    # tells the truth, to avoid a redundant/confusing second flag.
    att = _attachment(tmp_path, "tool.exe", _MINIMAL_PE)
    res = extraction.extract_attachment(att)
    assert not any("executable_disguised_as_document" in fl for fl in res["flags"])


def test_disguise_check_is_gated_on_raw_bytes_not_mime_string_reporting():
    # Regression guard for the exact bug this fix went through: verifies
    # the check works from content signature directly, independent of
    # whatever string a magic-byte library happens to report.
    assert extraction._content_is_executable(_MINIMAL_PE) is True
    assert extraction._content_is_executable(_MINIMAL_ELF) is True
    assert extraction._content_is_executable(_REAL_PDF) is False
