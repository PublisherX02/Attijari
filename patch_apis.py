import re

# Patch ThreatFox
with open('src/ThreatFoxAPI.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '    if not indicator:\n        return',
    '    from api_cache import api_cache\n    cache_key = f"threatfox_{indicator_type}_{indicator}"\n    cached = api_cache.get_cached(cache_key)\n    if cached:\n        return cached\n    api_cache.enforce_rate_limit("threatfox", 10)\n\n    if not indicator:\n        return'
)

text = text.replace(
    '            return {\n                "source": "threatfox",\n                "indicator": indicator,\n                "indicator_type": indicator_type,\n                "found": found,\n                "status_code": status,\n                "raw": data,\n            }',
    '            res = {\n                "source": "threatfox",\n                "indicator": indicator,\n                "indicator_type": indicator_type,\n                "found": found,\n                "status_code": status,\n                "raw": data,\n            }\n            api_cache.set_cache(cache_key, res, 86400)\n            return res'
)

with open('src/ThreatFoxAPI.py', 'w', encoding='utf-8') as f:
    f.write(text)


# Patch VirusTotal
with open('src/virustotal.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '    key = api_key or os.getenv("VIRUSTOTAL_API_KEY")',
    '    from api_cache import api_cache\n    cache_key = f"vt_{sha256}"\n    cached = api_cache.get_cached(cache_key)\n    if cached:\n        return cached\n\n    key = api_key or os.getenv("VIRUSTOTAL_API_KEY")'
)

text = text.replace(
    '            return {\n                "source": "virustotal",\n                "sha256": sha256,\n                "detected": detection_count >= DETECTION_THRESHOLD,',
    '            res = {\n                "source": "virustotal",\n                "sha256": sha256,\n                "detected": detection_count >= DETECTION_THRESHOLD,'
)
text = text.replace(
    '                "type_description": data.get("type_description"),\n            }',
    '                "type_description": data.get("type_description"),\n            }\n            api_cache.set_cache(cache_key, res, 86400)\n            return res'
)

with open('src/virustotal.py', 'w', encoding='utf-8') as f:
    f.write(text)

# Patch AbuseIPDB
with open('src/abuseipdb.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '    if not ip or not _is_valid_public_ip(ip):',
    '    from api_cache import api_cache\n    cache_key = f"abuseipdb_{ip}"\n    cached = api_cache.get_cached(cache_key)\n    if cached:\n        return cached\n    api_cache.enforce_rate_limit("abuseipdb", 10)\n\n    if not ip or not _is_valid_public_ip(ip):'
)

text = text.replace(
    '            return {\n                "source": "abuseipdb",\n                "ip": ip,\n                "is_malicious": abuse_score >= MALICIOUS_THRESHOLD,',
    '            res = {\n                "source": "abuseipdb",\n                "ip": ip,\n                "is_malicious": abuse_score >= MALICIOUS_THRESHOLD,'
)
text = text.replace(
    '                "total_reports": data.get("totalReports", 0),\n            }',
    '                "total_reports": data.get("totalReports", 0),\n            }\n            api_cache.set_cache(cache_key, res, 86400)\n            return res'
)

with open('src/abuseipdb.py', 'w', encoding='utf-8') as f:
    f.write(text)

# Patch AlienVault OTX
with open('src/alienvault_otx.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '    if not indicator:',
    '    from api_cache import api_cache\n    cache_key = f"otx_{indicator_type}_{indicator}"\n    cached = api_cache.get_cached(cache_key)\n    if cached:\n        return cached\n    api_cache.enforce_rate_limit("otx", 20)\n\n    if not indicator:'
)

text = text.replace(
    '            return {\n                "source": "otx",\n                "indicator": indicator,\n                "indicator_type": indicator_type,\n                "found": pulse_count > 0,',
    '            res = {\n                "source": "otx",\n                "indicator": indicator,\n                "indicator_type": indicator_type,\n                "found": pulse_count > 0,'
)
text = text.replace(
    '                "malware_families": malware_families,\n            }',
    '                "malware_families": malware_families,\n            }\n            api_cache.set_cache(cache_key, res, 86400)\n            return res'
)

with open('src/alienvault_otx.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patching complete!")
