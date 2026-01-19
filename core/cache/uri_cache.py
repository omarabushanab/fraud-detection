import json
from datetime import datetime
from core.cache.redis_client import redis_client
from core.cache.uri_cache_utils import uri_cache_key

PHISH_TTL = 24 * 60 * 60       # 24 hours
BENIGN_TTL = 7 * 24 * 60 * 60 # 7 days

def get_cached_uri(url):
    key = uri_cache_key(url)
    value = redis_client.get(key)

    if value is None:
        return None

    return json.loads(value)

def cache_uri_result(url, result):
    key = uri_cache_key(url)

    ttl = PHISH_TTL if result["prediction"] == "PHISHING" else BENIGN_TTL

    payload = {
        **result,
        "cached_at": datetime.utcnow().isoformat()
    }

    redis_client.setex(
        key,
        ttl,
        json.dumps(payload)
    )
