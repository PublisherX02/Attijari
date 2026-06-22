import os
import requests
from dotenv import load_dotenv

load_dotenv()


def check_threatfox(indicator: str, indicator_type: str = "hash", api_key: str | None = None) -> dict:
    """
    Query ThreatFox for an indicator (hash/domain/ip).
    Returns dict: {'source':'threatfox','indicator':..., 'indicator_type':..., 'found': bool, 'raw': ...}
    """
    if not indicator:
        return {"source": "threatfox", "indicator": indicator, "indicator_type": indicator_type, "found": False, "error": "empty indicator"}

    key = api_key or os.getenv("THREATFOX_AUTH_KEY")
    url = "https://threatfox.abuse.ch/api/v1/"
    # ThreatFox expects form data; use a general query field 'search_ioc'/'ioc' as a best-effort payload
    payload = {"query": "search_ioc", "ioc": indicator}
    headers = {"User-Agent": "tijari-ai/1.0"}
    if key:
        headers["API-Key"] = key

    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            data = {"text": resp.text}
        # heuristic: if 'data' in json and length>0 -> found
        found = False
        if isinstance(data, dict) and data.get("data"):
            if isinstance(data["data"], list) and len(data["data"]) > 0:
                found = True
        return {"source": "threatfox", "indicator": indicator, "indicator_type": indicator_type, "found": found, "raw": data}
    except Exception as e:
        return {"source": "threatfox", "indicator": indicator, "indicator_type": indicator_type, "found": False, "error": str(e)}

