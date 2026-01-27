import os
import requests

GSB_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_google_safe_browsing(url):
    payload = {
        "client": {
            "clientId": "fraud-detection",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    resp = requests.post(
        f"{GSB_ENDPOINT}?key={GSB_API_KEY}",
        json=payload,
        timeout=5
    )

    if resp.status_code != 200:
        return "UNKNOWN"

    data = resp.json()
    return "MALICIOUS" if "matches" in data else "CLEAN"