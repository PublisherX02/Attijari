"""test_extraction_onenote.py — OneNote (.one) attachments have no mature
open-source parser available; matching the SANDBOX_REQUIRED_TOOLS fail-safe
pattern, they escalate rather than pass through unexamined. A major
2024-2025 initial-access vector (embedded .vbs/.hta/.exe behind a fake
"click to view" button)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_onenote_attachment_escalates_no_parser(tmp_path):
    f = tmp_path / "invoice.one"
    f.write_bytes(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4dfakeonenotebytes")
    att = {"stored_path": str(f), "original_name": "invoice.one",
           "declared_type": "application/onenote",
           "real_type": "application/onenote", "sha256": "f" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
    assert any("sandbox_unavailable_for_onenote" in fl for fl in res["flags"])


def test_onenote_by_extension_alone_also_escalates(tmp_path):
    # declared/real type unknown, only the .one extension is present.
    f = tmp_path / "unknown.one"
    f.write_bytes(b"randombytes")
    att = {"stored_path": str(f), "original_name": "unknown.one",
           "declared_type": "application/octet-stream",
           "real_type": "application/octet-stream", "sha256": "1" * 64}
    res = extraction.extract_attachment(att)
    assert res["escalate"] is True
