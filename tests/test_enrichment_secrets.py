"""test_enrichment_secrets.py — confirms each enrichment module resolves its
API key via secrets_client, against the real local dev-mode Vault."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_virustotal_key_source():
    from secrets_client import get_api_key
    import virustotal
    assert virustotal._resolve_key(None) == get_api_key("virustotal")


def test_threatfox_key_source():
    from secrets_client import get_api_key
    import ThreatFoxAPI
    assert ThreatFoxAPI._resolve_key(None) == get_api_key("threatfox")


def test_abuseipdb_key_source():
    from secrets_client import get_api_key
    import abuseipdb
    assert abuseipdb._resolve_key(None) == get_api_key("abuseipdb")


def test_otx_headers_use_vault_key():
    from secrets_client import get_api_key
    import alienvault_otx
    headers = alienvault_otx._otx_headers()
    expected_key = get_api_key("otx")
    if expected_key:
        assert headers["X-OTX-API-KEY"] == expected_key
    else:
        assert "X-OTX-API-KEY" not in headers


def test_dnstwist_config_from_vault():
    from secrets_client import get_api_key
    import dnstwist_check
    import json
    raw = get_api_key("dnstwist")
    expected = json.loads(raw) if raw else {}
    assert dnstwist_check._load_config() == expected
