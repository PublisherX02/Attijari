"""test_archive_scan_yara_caching.py — docker/scripts/archive_scan.py's
_local_yara() recompiled every .yar/.yara file from scratch on every single
call, unlike extraction.py's copy of the same function (cached since
2026-07-31) -- a real performance regression in a sandboxed hot path, since
one archive scan can call this once per member across up to
_MAX_NESTED_ARCHIVE_DEPTH levels of nesting. Fixed to compile once per
container-invocation and reuse; this test proves the caching actually
happens (yara.compile called once across multiple _local_yara() calls) and
that the match/suspicious result shape is unchanged.
"""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "docker" / "scripts"))

import archive_scan


def setup_function(_):
    # Module-level cache persists across tests in the same process --
    # reset it so each test starts clean.
    archive_scan._yara_compiled_cache = None


def test_yara_compile_called_once_across_multiple_scans():
    mock_compiled = MagicMock()
    mock_compiled.match.return_value = []

    with patch("glob.glob", side_effect=lambda p: ["fake/rules/test.yar"] if p.endswith(".yar") else []), \
         patch("yara.compile", return_value=mock_compiled) as mock_compile:
        archive_scan._local_yara(b"content1")
        archive_scan._local_yara(b"content2")
        archive_scan._local_yara(b"content3")
        assert mock_compile.call_count == 1, (
            f"expected yara.compile to run once and be cached, ran {mock_compile.call_count} times"
        )


def test_match_result_shape_unchanged():
    fake_match = MagicMock()
    fake_match.rule = "test_rule_name"
    mock_compiled = MagicMock()
    mock_compiled.match.return_value = [fake_match]

    with patch("glob.glob", side_effect=lambda p: ["fake/rules/test.yar"] if p.endswith(".yar") else []), \
         patch("yara.compile", return_value=mock_compiled):
        result = archive_scan._local_yara(b"malicious content")
        assert result == {"suspicious": True, "matches": [{"rule": "test_rule_name"}]}


def test_no_rule_files_returns_clean_not_suspicious():
    with patch("glob.glob", return_value=[]):
        result = archive_scan._local_yara(b"anything")
        assert result == {"suspicious": False, "matches": []}


def test_yara_import_error_degrades_to_not_suspicious():
    archive_scan._yara_compiled_cache = None
    with patch("glob.glob", side_effect=lambda p: ["fake/rules/test.yar"] if p.endswith(".yar") else []), \
         patch("yara.compile", side_effect=ImportError("no yara")):
        result = archive_scan._local_yara(b"anything")
        assert result == {"suspicious": False, "matches": []}
