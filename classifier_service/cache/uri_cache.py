import json
from datetime import datetime
from cache.redis_client import get_redis_client
from cache.uri_cache_utils import uri_cache_key

PHISH_TTL = 60       # 24 hours
BENIGN_TTL = 60 # 7 days

def get_cached_uri(url):
    r = get_redis_client()
    if r is None:
        return None

    try:
        key = uri_cache_key(url)
        value = r.get(key)

        if value is None:
            return None

        return json.loads(value)

    except Exception as e:
        print(f"[WARN] Redis get failed: {e}")
        return None


def cache_uri_result(url, result):
    r = get_redis_client()
    if r is None:
        return

    try:
        key = uri_cache_key(url)
        ttl = PHISH_TTL if result["prediction"] == "PHISHING" else BENIGN_TTL

        payload = {
            **result,
            "cached_at": datetime.utcnow().isoformat()
        }

        r.setex(
            key,
            ttl,
            json.dumps(payload)
        )

    except Exception as e:
        print(f"[WARN] Redis set failed: {e}")
