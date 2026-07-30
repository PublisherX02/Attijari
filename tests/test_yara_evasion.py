"""test_yara_evasion.py — new evasion.yar rules (entropy, PE structure,
encoded-string variants) and compile-once caching in _local_yara()."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction


def test_evasion_yar_compiles():
    import yara
    rule_path = Path(__file__).parent.parent / "data" / "yara_rules" / "evasion.yar"
    rules = yara.compile(filepath=str(rule_path))
    assert rules is not None


def test_high_entropy_rule_matches_random_bytes():
    import os as _os
    extraction._yara_compiled_cache = None
    random_bytes = _os.urandom(2048)  # high entropy by construction
    result = extraction._local_yara(random_bytes)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "high_entropy_payload" in matched


def test_high_entropy_rule_does_not_match_plain_text():
    extraction._yara_compiled_cache = None
    plain = b"Dear customer, please find attached your invoice. " * 40
    result = extraction._local_yara(plain)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "high_entropy_payload" not in matched


def test_encoded_powershell_rule_matches_base64_variant():
    import base64
    extraction._yara_compiled_cache = None
    encoded = base64.b64encode(b"padding header bytes powershell -enc payload continues here")
    result = extraction._local_yara(encoded)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "suspicious_powershell_encoded" in matched


def test_pe_structural_rules_do_not_false_positive_on_random_bytes():
    # Positive-case verification of the PE-structural rules (suspicious
    # imports, packer section names) requires a real, well-formed PE with
    # a specific import table / section layout — impractical to construct
    # byte-for-byte in a unit test. This test covers the negative case
    # (no false positives on non-PE data); positive-case verification
    # happens against the external evasive-sample dataset once available
    # (see docs/superpowers/specs/2026-07-31-evasion-hardening-design.md).
    extraction._yara_compiled_cache = None
    result = extraction._local_yara(b"not a PE file, just some bytes " * 20)
    matched = [m["rule"] for m in result["matches"] if "rule" in m]
    assert "suspicious_pe_imports" not in matched
    assert "packer_section_names" not in matched


def test_local_yara_compiles_rules_only_once_per_file(monkeypatch):
    extraction._yara_compiled_cache = None
    real_compile = extraction.yara.compile
    calls = {"count": 0}

    def _counting_compile(*a, **k):
        calls["count"] += 1
        return real_compile(*a, **k)

    monkeypatch.setattr(extraction.yara, "compile", _counting_compile)
    try:
        extraction._local_yara(b"first scan")
        extraction._local_yara(b"second scan")
        extraction._local_yara(b"third scan")
        num_rule_files = len(
            list(extraction.YARA_RULES_DIR.glob("*.yar")) + list(extraction.YARA_RULES_DIR.glob("*.yara"))
        )
        assert calls["count"] == num_rule_files
    finally:
        extraction._yara_compiled_cache = None  # don't leak into other test files
