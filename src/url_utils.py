"""url_utils.py — Utilities for URL normalization and defanging."""
import urllib.parse
import re

def normalize_url(url: str) -> str:
    """Normalize a URL for threat feed lookups by stripping tracking parameters,
    decoding percent-encodings, and standardizing case.
    """
    try:
        # 1. Decode percent-encoded characters (e.g., %20 -> space)
        url = urllib.parse.unquote(url.strip())
        
        # 2. Parse the URL
        parsed = urllib.parse.urlparse(url)
        
        # 3. Normalize scheme and netloc to lowercase
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # 4. Strip tracking query parameters (e.g., utm_source, ref)
        if parsed.query:
            query_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            # Remove common tracking parameters
            tracking_params = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "source", "click_id"}
            filtered_query = {k: v for k, v in query_dict.items() if k.lower() not in tracking_params}
            # Reconstruct query string
            query = urllib.parse.urlencode(filtered_query, doseq=True)
        else:
            query = ""
            
        # Reconstruct normalized URL
        normalized = urllib.parse.urlunparse((scheme, netloc, parsed.path, parsed.params, query, parsed.fragment))
        return normalized
    except Exception:
        return url.strip()

def defang_url(url: str) -> str:
    """Defang a URL for safe printing/logging (e.g., http -> hxxp, . -> [.])."""
    defanged = re.sub(r'^https?://', 'hxxp://', url, flags=re.IGNORECASE)
    defanged = defanged.replace('.', '[.]')
    return defanged
