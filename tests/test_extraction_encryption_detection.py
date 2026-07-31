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


def test_detect_encryption_ooxml_encrypted_package(monkeypatch):
    import olefile

    class _FakeOle:
        def exists(self, name):
            return name == "EncryptedPackage"

        def close(self):
            pass

    monkeypatch.setattr(olefile, "isOleFile", lambda buf: True)
    monkeypatch.setattr(olefile, "OleFileIO", lambda buf: _FakeOle())
    result = extraction._detect_encryption(b"\xd0\xcf\x11\xe0fakecfb", "secret.docx")
    assert result["encrypted"] is True
    assert result["method"] == "ooxml_encrypted_package"


def test_detect_encryption_plain_ooxml_not_flagged(monkeypatch):
    import olefile
    monkeypatch.setattr(olefile, "isOleFile", lambda buf: False)
    result = extraction._detect_encryption(b"PK\x03\x04plainooxml", "invoice.docx")
    assert result["encrypted"] is False


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
