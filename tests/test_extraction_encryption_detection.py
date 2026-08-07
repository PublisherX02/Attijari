"""test_extraction_encryption_detection.py — real structural detection of
password-protected ZIP/OOXML attachments, replacing the MIME/extension-only
heuristic."""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def _make_zip_with_encryption_flag() -> bytes:
    """Python's zipfile can READ encrypted entries (pwd=) but cannot WRITE
    one natively — build a normal zip, then patch the General Purpose Bit
    Flag (bit 0 = encrypted) directly in both the local file header and the
    central directory record, exactly as a real encrypted zip has it set."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", "hello")
    raw = bytearray(buf.getvalue())
    raw[6] |= 0x01  # local file header GP flag, offset 6-7 from file start
    cd_sig = raw.find(b"PK\x01\x02")
    raw[cd_sig + 8] |= 0x01  # central directory record GP flag
    return bytes(raw)


def test_detect_encryption_zip_flag_set():
    content = _make_zip_with_encryption_flag()
    result = extraction._detect_encryption(content, "secret.zip")
    assert result["encrypted"] is True
    assert result["method"] == "zip_encryption_flag"


def test_detect_encryption_plain_zip_not_flagged():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("data.txt", "hello")
    result = extraction._detect_encryption(buf.getvalue(), "plain.zip")
    assert result["encrypted"] is False
    assert result["method"] is None


_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def test_detect_encryption_ooxml_encrypted_package(monkeypatch):
    import olefile

    class _FakeOle:
        def exists(self, name):
            return name == "EncryptedPackage"

        def close(self):
            pass

    monkeypatch.setattr(olefile, "isOleFile", lambda buf: True)
    monkeypatch.setattr(olefile, "OleFileIO", lambda buf: _FakeOle())
    result = extraction._detect_encryption(_OLE_MAGIC + b"fakecfb", "secret.docx")
    assert result["encrypted"] is True
    assert result["method"] == "ooxml_encrypted_package"


def test_detect_encryption_plain_ooxml_not_flagged(monkeypatch):
    import olefile
    monkeypatch.setattr(olefile, "isOleFile", lambda buf: False)
    result = extraction._detect_encryption(b"PK\x03\x04plainooxml", "invoice.docx")
    assert result["encrypted"] is False


def test_detect_encryption_gated_on_content_signature_not_filename():
    # The real bug this fix closes: a genuinely encrypted zip renamed to a
    # completely unrelated extension must still be detected -- the old
    # implementation gated on `filename.endswith((".zip", ".docx", ...))`
    # and silently returned "not encrypted" without ever looking at the
    # bytes for any other extension, evadable by a plain rename.
    content = _make_zip_with_encryption_flag()
    for fname in ("photo.jpg", "report.pdf", "attachment", "notes.txt"):
        result = extraction._detect_encryption(content, fname)
        assert result["encrypted"] is True, f"renamed to {fname} evaded detection"
        assert result["method"] == "zip_encryption_flag"


def test_detect_encryption_ooxml_gated_on_content_signature_not_filename(monkeypatch):
    # Same evasion, but for the OLE/CFB family: an encrypted Office document
    # renamed away from .docx/.xlsx/etc previously bypassed BOTH this
    # function's own extension gate AND extract_attachment()'s
    # `effective_mime in _ARCHIVE_MIMES` fallback, since OLE/CFB (what an
    # encrypted Office file physically is) was never in that MIME set.
    import olefile

    class _FakeOle:
        def exists(self, name):
            return name == "EncryptedPackage"

        def close(self):
            pass

    monkeypatch.setattr(olefile, "isOleFile", lambda buf: True)
    monkeypatch.setattr(olefile, "OleFileIO", lambda buf: _FakeOle())
    content = _OLE_MAGIC + b"fakecfb"
    for fname in ("photo.jpg", "report.pdf", "attachment"):
        result = extraction._detect_encryption(content, fname)
        assert result["encrypted"] is True, f"renamed to {fname} evaded detection"
        assert result["method"] == "ooxml_encrypted_package"


def test_extract_attachment_confirmed_encrypted_plus_password_body_escalates(tmp_path):
    content = _make_zip_with_encryption_flag()
    f = tmp_path / "invoice.zip"
    f.write_bytes(content)
    att = {"stored_path": str(f), "original_name": "invoice.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "b" * 64}
    res = extraction.extract_attachment(att, body_text="see attached, password: 1234")
    assert res["escalate"] is True
    assert any("encrypted_with_password_in_body" in fl for fl in res["flags"])
    assert any("attachment_encrypted" in fl for fl in res["flags"])


def test_extract_attachment_renamed_encrypted_zip_still_escalates(tmp_path):
    # CLAUDE.md rule 8: "must never pass silently" -- a real encrypted zip
    # renamed to look like an image must still trip this, not rely on the
    # filename saying .zip.
    content = _make_zip_with_encryption_flag()
    f = tmp_path / "photo.jpg"
    f.write_bytes(content)
    att = {"stored_path": str(f), "original_name": "photo.jpg",
           "declared_type": "image/jpeg", "real_type": None, "sha256": "d" * 64}
    res = extraction.extract_attachment(att, body_text="see attached photo, password: Summer2026!")
    assert res["escalate"] is True
    assert any("encrypted_with_password_in_body" in fl for fl in res["flags"])
    assert any("attachment_encrypted" in fl for fl in res["flags"])
