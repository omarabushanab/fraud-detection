import hashlib
from urllib.parse import urlparse

def normalize_uri(url: str) -> str:
    url = url.strip().lower()
    parsed = urlparse(url)

    # domain-level normalization (important!)
    return parsed.netloc

def uri_cache_key(url: str) -> str:
    normalized = normalize_uri(url)
    digest = hashlib.sha256(normalized.encode()).hexdigest()
    return f"uri:{digest}"
