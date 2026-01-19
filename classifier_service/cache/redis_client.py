import os
import time
import redis
from urllib.parse import urlparse

_redis_client = None

def get_redis_client(retries=5, delay=1):
    global _redis_client

    if _redis_client is not None:
        return _redis_client

    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        print("[WARN] REDIS_URL not set — caching disabled", flush=True)
        return None

    parsed = urlparse(redis_url)

    for attempt in range(1, retries + 1):
        try:
            client = redis.Redis(
                host=parsed.hostname,
                port=parsed.port,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                retry_on_timeout=True,
            )

            client.ping()
            print("[INFO] Connected to Redis", flush=True)
            _redis_client = client
            return _redis_client

        except redis.exceptions.RedisError as e:
            print(
                f"[WARN] Redis not ready "
                f"(attempt {attempt}/{retries}): {e}",
                flush=True
            )
            time.sleep(delay)

    print("[WARN] Redis unavailable — caching disabled", flush=True)
    return None
