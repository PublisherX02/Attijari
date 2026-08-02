"""test_extraction_recursive_archive_scan.py — the existing archive-bomb
check only inspects nesting depth/compression ratio/filenames; it never
scans the actual decompressed bytes. This adds a bounded first-level scan
of archive member content with YARA.

2026-08-02: archive scanning moved behind SANDBOX_REQUIRED_TOOLS (a
decompression bomb or a bug in py7zr/pycdlib's C-extension codecs
previously ran unsandboxed in the main pipeline process). These tests use
the EXTRACTION_ALLOW_UNSANDBOXED escape hatch (via monkeypatching
_allow_unsandboxed, matching test_extraction_sandbox_failsafe.py's own
convention) to exercise the real _local_archive_scan logic directly;
test_extraction_archive_sandbox_failsafe.py covers the "Docker down -> must
escalate, never parse unsandboxed" side."""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def _allow_local(monkeypatch):
    monkeypatch.setattr(extraction, "_can_sandbox", lambda tool: False)
    monkeypatch.setattr(extraction, "_allow_unsandboxed", lambda: True)


def test_recursive_archive_scan_catches_yara_match_in_nested_file(tmp_path, monkeypatch):
    _allow_local(monkeypatch)
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("payload.txt", "powershell -enc AAAA")
    f = tmp_path / "archive.zip"
    f.write_bytes(inner_buf.getvalue())
    att = {"stored_path": str(f), "original_name": "archive.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "a" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("archive_member_yara_match" in fl for fl in res["flags"])


def test_recursive_archive_scan_clean_archive_not_flagged(tmp_path, monkeypatch):
    _allow_local(monkeypatch)
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("readme.txt", "just a normal invoice attachment, nothing suspicious here")
    f = tmp_path / "clean.zip"
    f.write_bytes(inner_buf.getvalue())
    att = {"stored_path": str(f), "original_name": "clean.zip",
           "declared_type": "application/zip", "real_type": "application/zip", "sha256": "d" * 64}
    res = extraction.extract_attachment(att)
    assert not any("archive_member_yara_match" in fl for fl in res["flags"])
