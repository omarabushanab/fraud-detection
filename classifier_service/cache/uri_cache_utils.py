import hashlib
from urllib.parse import urlparse

def normalize_uri(url: str) -> str:
    url = url.strip().lower()
    parsed = urlparse(url)

    # domain-level normalization (important!)
    return parsed.netloc

def uri_cache_key(url: str) -> str:
    url = url.strip().lower()

    # Ensure scheme exists
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    # Canonical form
    canonical = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    # Hash to keep key short + safe
    digest = hashlib.sha256(canonical.encode()).hexdigest()

    return f"uri:{digest}"

