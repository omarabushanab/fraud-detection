import re
import math
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "secure", "account", "verify",
    "update", "free", "bonus", "bank", "signin"
]

IP_REGEX = re.compile(r"\d+\.\d+\.\d+\.\d+")

def shannon_entropy(s):
    if not s:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""

    features = {
        # Lengths
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),

        # Counts
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": len(re.findall(r"[^a-zA-Z0-9]", url)),

        # Ratios
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),

        # Structure
        "num_subdomains": host.count("."),
        "has_ip": int(bool(IP_REGEX.search(url))),
        "has_at": int("@" in url),
        "https": int(parsed.scheme == "https"),

        # Entropy
        "url_entropy": shannon_entropy(url),
        "host_entropy": shannon_entropy(host),
    }

    for word in SUSPICIOUS_WORDS:
        features[f"has_{word}"] = int(word in url.lower())

    return features
